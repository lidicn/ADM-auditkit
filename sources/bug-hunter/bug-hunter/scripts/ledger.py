#!/usr/bin/env python3
"""跨轮账本 —— 让工作流记住前几轮查过什么。

为什么必须有这一层（第六轮的教训）：
  流水线此前无状态，每轮跑完都是一份孤立报告。结果是：
    · 无法区分「本轮新发现」与「六轮前就已知」
    · 已修的缺陷会反复出现在候选池里，稀释新信号
    · S2 地图反复指向读烂的文件（dialog.py 已读 6 次仍排第一）

  账本按「文件:行号:标题指纹」去重，三态：
    NEW      本轮首次出现
    KNOWN    此前已记录（不重复计入新缺陷）
    RESOLVED 此前记录过、本轮扫不到了 —— 说明已被修复，或检测器回归了
"""
from __future__ import annotations

import hashlib
import json
import os
import time


def _fp(loc: str, title: str) -> str:
    """指纹：文件+行号区间+标题关键词。刻意不含完整标题，
    因为标题措辞会随报告迭代变化，行号才是稳定锚点。"""
    f = loc.split(":")[0] if loc else ""
    ln = loc.split(":")[1] if ":" in loc else "0"
    key = f"{f}#{int(ln)//1}#{title[:24]}"
    return hashlib.md5(key.encode()).hexdigest()[:10]


def load(path: str) -> dict:
    if not os.path.exists(path):
        return {"rounds": [], "items": {}}
    try:
        return json.load(open(path, encoding="utf-8"))
    except Exception:
        return {"rounds": [], "items": {}}


def diff(ledger: dict, findings: list, round_name: str, mode: str = "full"):
    """把本轮 findings 与账本比对，返回 (new, known, resolved, updated_ledger)。"""
    items = ledger.setdefault("items", {})
    seen = set()
    new, known = [], []

    for f in findings:
        fp = _fp(f.loc, f.title)
        seen.add(fp)
        rec = {"fp": fp, "title": f.title, "loc": f.loc,
               "stage": f.stage, "severity": f.severity,
               "first": round_name, "last": round_name}
        if fp in items:
            items[fp]["last"] = round_name
            known.append(f)
        else:
            items[fp] = rec
            new.append(f)

    # 上轮有、本轮没有 → RESOLVED
    # RESOLVED 只在「同一扫描模式」下才计算。
    # 反例（实测踩过）：上一轮跑全量扫描（vulture/ruff/invariants 全部），
    # 这一轮跑 --fast（只跑 Phase A/B 的 4 条规则），findings 集合天然不同，
    # 于是历史条目大量「消失」→ 刷出上百条假 RESOLVED。
    # 模式不同时，差异来自检测器而非代码，不能当成「缺陷已修复」。
    prev = ledger["rounds"][-1] if ledger.get("rounds") else None
    resolved = []
    if prev and prev.get("mode") == mode:
        prev_last = prev["name"]
        for fp, rec in items.items():
            if rec.get("last") == prev_last and fp not in seen:
                resolved.append(rec)

    ledger.setdefault("rounds", []).append(
        {"name": round_name, "ts": time.strftime("%Y-%m-%d %H:%M"),
         "mode": mode, "new": len(new), "known": len(known),
         "resolved": len(resolved)})
    return new, known, resolved, ledger


def save(ledger: dict, path: str):
    os.makedirs(os.path.dirname(os.path.abspath(path)) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(ledger, fh, ensure_ascii=False, indent=2)


def print_diff(new, known, resolved, verbose=True):
    if not verbose:
        return
    print("─" * 72)
    print("Stage 5  跨轮账本（NEW / KNOWN / RESOLVED）")
    print("─" * 72)
    print(f"  NEW      {len(new):>4} 条   ← 本轮首次出现，是真正的增量")
    print(f"  KNOWN    {len(known):>4} 条   ← 此前已记录，不计入增量")
    print(f"  RESOLVED {len(resolved):>4} 条   ← 上轮有、本轮消失")
    print()
    if new:
        print("  本轮新增：")
        for f in new[:10]:
            print(f"    [{f.severity}] {f.title}")
            print(f"           {f.loc}")
        if len(new) > 10:
            print(f"    ... 另 {len(new)-10} 条")
    if resolved:
        print("  已消失（可能被修复，也可能是检测器回归 —— 必须人工确认）：")
        for r in resolved[:5]:
            print(f"    {r['title'][:56]}")
            print(f"           {r['loc']}")
    print()


# ───────────────── 审计覆盖度 ─────────────────

# 已读文件清单的**唯一数据源**在 stage2_rank.READ_FILES。
# 这里曾另存一份 COVERAGE_DEFAULT（21 条），与那份（19 条）不一致，
# 导致 --fast 模式报 9.5%、全量模式报另一数字 —— 同一份事实两个口径。
# 已在第十轮统一：任何地方要读已读清单，一律 from stage2_rank import READ_FILES。


READ_STATE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "read_state.json")


def _load_extra():
    if os.path.exists(READ_STATE):
        try:
            return set(json.load(open(READ_STATE, encoding="utf-8")))
        except Exception:
            return set()
    return set()


def read_files():
    """已读文件集合（唯一来源）= 代码内基线 + 持久化增量。

    ⚠ 上一版 mark_read 只改内存 set，进程退出即丢：
       R10 标记 10 个（19→28），R11 重跑又回到 19。
       覆盖度是审计进度的核心指标，不能每轮从零开始。
    """
    from stage2_rank import READ_FILES
    return set(READ_FILES) | _load_extra()


def mark_read(path: str):
    """把文件标记为已读并持久化。"""
    cur = _load_extra()
    cur.add(path)
    os.makedirs(os.path.dirname(os.path.abspath(READ_STATE)), exist_ok=True)
    with open(READ_STATE, "w", encoding="utf-8") as fh:
        json.dump(sorted(cur), fh, ensure_ascii=False, indent=2)


def coverage(rows, read_set=None):
    """(已读文件数, 总文件数, 已读覆盖的行数占比估算)。"""
    read = read_files() if read_set is None else read_set
    tot = len(rows)
    got = sum(1 for r in rows if r["file"] in read)
    return got, tot, (got / tot * 100 if tot else 0.0)


# ───────────────── 分档调度：把剩余工作量切成人能消化的批次 ─────────────────

def buckets(repo, read_set=None):
    """把未读文件按规模分档。

    为什么要分档：不同规模的文件需要不同的审计强度。
      XL(>=600) / L(300-599)：精读 —— 逐行看，配合行为实验
      M(150-299)：半精读 —— 看结构 + 关键路径，3-5 个/轮
      S(<150)   ：批量扫 —— 机器扫 + 人工抽查，15-20 个/轮
    不分的后果：要么大文件读不透，要么小文件浪费精读预算。
    """
    import os
    read = read_files() if read_set is None else read_set
    out = {"XL": [], "L": [], "M": [], "S": []}
    base = os.path.join(os.path.abspath(repo), "butler")
    for d, dirs, fs in os.walk(base):
        dirs[:] = [x for x in dirs if x != "__pycache__"]
        for f in fs:
            if not f.endswith(".py"):
                continue
            p = os.path.join(d, f)
            rel = os.path.relpath(p, os.path.abspath(repo))
            if rel in read:
                continue
            n = len(open(p, encoding="utf-8").read().splitlines())
            k = "XL" if n >= 600 else "L" if n >= 300 else "M" if n >= 150 else "S"
            out[k].append((rel, n))
    for k in out:
        out[k].sort(key=lambda x: -x[1])
    return out


def estimate_rounds(repo, per_round_lines=2000):
    """估算把剩余工作量读完需要多少轮。

    per_round_lines 是实测产能：第九轮精读 1701 行 + 若干核查；
    第八轮精读 640 行 + 做挂死实验。取 2000 行/轮为保守值。
    """
    b = buckets(repo)
    total_lines = sum(n for k in b for _, n in b[k])
    # 小文件不按行数计：它们模板化程度高，按个数折算（每个 60 行等效）
    eff = sum(n for k in ("XL", "L", "M") for _, n in b[k]) + len(b["S"]) * 60
    rounds = max(1, round(eff / per_round_lines))
    detail = {k: (len(v), sum(n for _, n in v)) for k, v in b.items()}
    return rounds, total_lines, eff, detail


def print_plan(repo, current_round=9):
    r, tot, eff, d = estimate_rounds(repo)
    print("─" * 72)
    print("剩余工作量与轮次估算")
    print("─" * 72)
    print(f"  {'档':<5}{'文件数':>7}{'行数':>9}   审计强度")
    print("  " + "-" * 46)
    mode = {"XL": "精读（1-2 个/轮）", "L": "精读（2-3 个/轮）",
            "M": "半精读（4-6 个/轮）", "S": "批量扫+抽查（15-20 个/轮）"}
    for k in ("XL", "L", "M", "S"):
        c, n = d[k]
        print(f"  {k:<5}{c:>7}{n:>9}   {mode[k]}")
    print()
    print(f"  未读合计 {sum(c for c, _ in d.values())} 文件 / {tot} 行")
    print(f"  等效工作量 {eff} 行（小文件按 60 行/个折算）")
    print(f"  按 2000 行/轮 → 约需 {r} 轮")
    print(f"  预计收官：R{current_round + r}")
    print()
    print("  ⚠ 这是**产能估算**，不是缺陷预测。产出递减已在 R6-R9 实证")
    print("    （14→4→3→2→1→0），后期轮次大概率零新增。")
    print()
