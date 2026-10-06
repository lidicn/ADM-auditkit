#!/usr/bin/env python3
"""发现-bug 工作流 —— 主入口

    python3 pipeline.py <repo> [--root butler] [--stages 0,1,2,3] [--json out.json]

六阶段：
  S0 环境体检   工具可用性 → 缺失即降级 + 标红（绝不伪装成「无问题」）
  S1 候选生成   vulture / ruff / radon / 自写AST规则 → 候选池
  S2 优先级排序 复杂度 × 枢纽度 × 历史缺陷密度 → 「下一轮读什么」
  S3 不变量断言 属性证伪（唯一能发现未预料形状的一层）
  S4 行为验证   对接既有 audit_helpers 场景注册表（19 正测 + 9 反测）
  S5 报告       汇总 + exit code

设计纪律（五轮审计的血泪）：
  1. 工具缺失 ≠ 无问题。沙箱重置过 3 次，每次工具全丢；若那时流水线
     照常输出「0 缺陷」，等于把缺陷洗白。故体检缺失必须显式降级 + exit≠0。
  2. ERROR ≠ REFUTED。用例自身失败（依赖/桩件）不能解读为「缺陷不存在」。
  3. 反测不许假通过。曾因 `or True` 让反测无条件通过，比没有反测更危险。
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

from core import probe, print_health, missing, FOUND  # noqa: E402
import stage1_scan  # noqa: E402
import stage2_rank  # noqa: E402
import invariants  # noqa: E402
import ledger  # noqa: E402
import fast_core  # noqa: E402
import property_tests  # noqa: E402
import codemap  # noqa: E402
import mutation  # noqa: E402

G, Y, R, C, D = "\033[92m", "\033[93m", "\033[91m", "\033[36m", "\033[0m"
BOLD = "\033[1m"


def banner():
    print()
    print("=" * 72)
    print(f"{BOLD}发现-bug 工作流{D}  ——  静态扫描 → 优先级 → 不变量 → 行为验证")
    print("=" * 72)
    print()


def stage4_verify(repo):
    """对接既有套件。不存在则跳过（不报错，因为它是可选增强）。"""
    helper = os.path.join(repo, "tests", "audit_helpers.py")
    if not os.path.exists(helper):
        return None, "未找到 tests/audit_helpers.py —— 跳过"
    try:
        r = subprocess.run(
            [sys.executable, "-m", "pytest", "tests/test_audit_findings.py",
             "-q", "--no-header", "-p", "no:cacheprovider"],
            capture_output=True, text=True, cwd=repo, timeout=900)
    except Exception as e:
        return None, f"pytest 不可用: {e}"
    tail = (r.stdout or "").strip().splitlines()[-1] if r.stdout.strip() else ""
    return {"rc": r.returncode, "summary": tail}, None


KNOWN_DEFECTS = {
    # 五轮已实锤的缺陷落点（文件名 → 条数），用于 S2 加权
    "butler/core/dialog.py": 4,
    "butler/tts/queue.py": 3,
    "butler/tts/adapter.py": 1,
    "butler/tts/manager.py": 1,
    "butler/triggers/engine.py": 1,
    "butler/api/config_routes.py": 1,
    "butler/store/db.py": 1,
    "butler/af_bridge.py": 2,
    "butler/app.py": 1,
    "butler/core/dedup.py": 1,
    "butler/integrations/ha.py": 1,
    "butler/integrations/docker_tools.py": 1,
}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("repo")
    ap.add_argument("--root", default="butler")
    ap.add_argument("--stages", default="0,1,2,3,4")
    ap.add_argument("--json", default=None)
    ap.add_argument("--top", type=int, default=15)
    ap.add_argument("--round", default="R7")
    ap.add_argument("--fast", action="store_true",
                    help="快速模式：Phase A 廉价预筛全仓 + Phase B 只精扫 core（默认 20 个文件）")
    ap.add_argument("--focus", type=int, default=30,
                    help="Phase B 精扫文件数。实测：30→58%召回，80→88%召回，耗时均约1.3s")
    ap.add_argument("--unread", action="store_true", help="core 只在未读文件里选")
    ap.add_argument("--batch", choices=["XL", "L", "M", "S"], default=None,
                    help="批量模式：按规模档位取未读文件，输出本轮该审的批次")
    ap.add_argument("--per-round", type=int, default=2000,
                    help="每轮产能（行数），用于批次切分")
    ap.add_argument("--mutate", nargs="*", default=None,
                    help="变异测试：指定源文件（相对 repo），存活=测试盲区")
    ap.add_argument("--codemap", action="store_true",
                    help="输出代码图谱：god node（爆炸半径）/ 循环依赖 / 零入度模块")
    ap.add_argument("--property", action="store_true",
                    help="跑 hypothesis 属性测试层（第十二轮新增：随机输入打边界）")
    ap.add_argument("--mark-read", nargs="*", default=None,
                    help="把指定文件标记为已读，推进覆盖度")
    ap.add_argument("--ledger", default=os.path.join(HERE, "..", "findings_ledger.json"))
    a = ap.parse_args()
    repo = os.path.abspath(a.repo)
    stages = set(a.stages.split(","))

    banner()

    # ── S0 ──
    health = probe(repo)
    miss = missing(health)
    if "0" in stages:
        print_health(health)
    if miss:
        print(f"{Y}⚠ {len(miss)} 个工具不可用：{', '.join(miss)}{D}")
        print(f"{Y}  已启用降级方案，报告可信度下降 —— 不得据此判定项目健康。{D}")
        print()

    # ── 覆盖度维护 ──
    if a.mark_read:
        for f in a.mark_read:
            ledger.mark_read(f)
        print(f"已标记 {len(a.mark_read)} 个文件为已读")
        print()

    # ── 批量模式：输出本轮该审的批次 ──
    if a.batch:
        b = ledger.buckets(repo)
        want = b[a.batch]
        quota = a.per_round
        # 配额是"软上限"：至少取 1 个文件，否则 XL 档（单文件 1168 行）
        # 在 quota=2000 下会只取到第一个就因超配额停止，批次太小。
        picked, used = [], 0
        for rel, n in want:
            if picked and used + n > quota * 1.3:
                break
            picked.append((rel, n))
            used += n
        print("─" * 72)
        print(f"本轮批次（{a.batch} 档，配额 {quota} 行）")
        print("─" * 72)
        for rel, n in picked:
            print(f"  {n:>5} 行  {rel}")
        print(f"  合计 {len(picked)} 文件 / {used} 行")
        print()
        print(f"  该档剩余 {len(want) - len(picked)} 个文件")
        print()

    # ── S1 ──
    findings, meta = ([], {})
    if "1" in stages:
        if a.fast:
            from stage2_rank import READ_FILES
            findings, fc = fast_core.run(
                repo, a.root, focus=a.focus, unread_only=a.unread,
                read_files=READ_FILES, verbose=True)
            meta["fast_core"] = fc
            meta["cc_rows"] = []
        else:
            findings, meta = stage1_scan.run(repo, a.root)

    # ── S2 ──
    rows = []
    if "2" in stages:
        rows = stage2_rank.rank(repo, findings, meta.get("cc_rows", []), KNOWN_DEFECTS)
        stage2_rank.print_map(rows, a.top)

    # ── S3m 变异测试（回答「这些测试有多少真在测东西」）──
    if a.mutate:
        print("─" * 72)
        print("Stage 3m 变异测试（存活 = 测试盲区）")
        print("─" * 72)
        mres = mutation.run(a.mutate, repo=repo)
        for r in mres:
            if r["survived"]:
                for ln, desc, code in r["survivors"]:
                    findings.append(Finding(
                        f"M-{r['file'].split('/')[-1]}:L{ln}",
                        f"测试盲区：{desc} 变异存活（无人发现）",
                        "mutation", severity="P2",
                        loc=f"{r['file']}:{ln}",
                        evidence=code))
        print()

    # ── S0b 代码图谱（决定「下一步看哪里」，不产生缺陷，产生优先级）──
    if a.codemap:
        print("─" * 72)
        print("Stage 0b 代码图谱（god node = 爆炸半径）")
        print("─" * 72)
        cm = codemap.run(repo, verbose=True)
        # 循环依赖的结论必须复核：depcycle 曾把类型注解误判成导入，
        # 报 6 条循环全为假阳性。故这里用自写 AST，并可选做真 import 复核。
        if cm["cycles"]:
            mods = sorted({m for c in cm["cycles"] for m in c})
            ver = codemap.verify_importable(repo, mods[:12])
            bad = [m for m, (okk, _) in ver.items() if not okk]
            print(f"  循环依赖实证复核：{len(mods)} 个模块，import 失败 {len(bad)} 个")
            if not bad:
                print("  ⚠ 全部可 import → 非启动期硬循环，可能是延迟导入或误报")
            print()

    # ── S3p 属性测试（hypothesis：随机输入打边界，唯一能自己找反例的层）──
    if a.property:
        print("─" * 72)
        print("Stage 3p 属性测试（hypothesis —— 随机输入，反例即缺陷）")
        print("─" * 72)
        pres = property_tests.run(verbose=True)
        bad = [r for r in pres if not r[1]]
        print(f"  用例 {len(pres)} 条，发现反例 {len(bad)} 条")
        print()
        findings += [
            Finding(f"P{len(findings)+1:02d}", f"属性反例：{nm}", "property",
                    severity="P1", loc="(hypothesis)", evidence=err)
            for nm, _, err, _ in bad
        ]

    # ── S3 ──
    inv = {}
    if "3" in stages:
        inv = invariants.run(repo, a.root)
        all_inv = [f for k in ("async_pure", "durable", "failure", "side_effect")
                   for f in inv.get(k, [])]
        if all_inv:
            print("  不变量违背明细（前 12）：")
            for f in all_inv[:12]:
                col = R if f.severity == "P0" else Y
                print(f"    {col}[{f.severity}]{D} {f.title}")
                print(f"           {f.loc}")
            if len(all_inv) > 12:
                print(f"    ... 另 {len(all_inv)-12} 条")
            print()

    # ── S4 ──
    s4 = None
    if "4" in stages:
        print("─" * 72)
        print("Stage 4  行为验证（对接既有套件）")
        print("─" * 72)
        s4, err = stage4_verify(repo)
        if err:
            print(f"  ⚠ {err}")
        else:
            ok = s4["rc"] == 0
            print(f"  {'✓' if ok else '✗'} {s4['summary']}")
            print("  正测全绿 = 缺陷仍在；转红 = 已修复，该删正测")
        print()

    # ── S5 跨轮账本 ──
    all_f = list(findings) + [f for k in ("async_pure", "durable", "failure",
                  "side_effect", "contract", "degrade") for f in inv.get(k, [])]
    # 关键：只有真正跑过扫描（S1/S3）才写账本。
    # 否则单独跑 --stages 5 时候选池为空，会把所有历史条目误判成 RESOLVED
    # —— 实测就出现过「172 条 RESOLVED」的假信号。
    scanned = bool({"1", "3"} & stages) and bool(all_f)
    if not scanned:
        print("─" * 72)
        print("Stage 5  跨轮账本 —— 本轮未跑扫描，跳过（避免误判 RESOLVED）")
        print("─" * 72)
        print()
        new_f, known_f, resolved_f = [], [], []
    else:
        lg = ledger.load(a.ledger)
        mode = "fast" if a.fast else "full"
        new_f, known_f, resolved_f, lg = ledger.diff(lg, all_f, a.round, mode)
        ledger.save(lg, a.ledger)
    if scanned:
        ledger.print_diff(new_f, known_f, resolved_f)
    # 覆盖度分母必须是全仓唯一枚举，不能既从 buckets 又从 walk 拼
    # （上一版拼出 421 个 = 220+201，重复计数）
    import os as _os
    crows = []
    for d, _dirs, fs in _os.walk(_os.path.join(repo, "butler")):
        _dirs[:] = [x for x in _dirs if x != "__pycache__"]
        for f in fs:
            if f.endswith(".py"):
                crows.append({"file": _os.path.relpath(_os.path.join(d, f), repo)})
    got, tot, pct = ledger.coverage(crows)
    if tot:
        ledger.print_plan(repo)
    print(f"  审计覆盖度：{got}/{tot} 个文件（{pct:.1f}%）—— 未读文件在 S2 地图中标 ★")
    print()

    # ── S6 汇总 ──
    print("=" * 72)
    print(f"{BOLD}汇总{D}")
    print("=" * 72)
    n1 = len(findings)
    n3 = sum(len(inv.get(k, [])) for k in
             ("async_pure", "durable", "failure", "side_effect", "contract", "degrade"))
    n_pass, n_exc, _ = inv.get("except_pass", (0, 0, []))
    print(f"  S1 候选池        {n1} 条")
    print(f"  S3 不变量违背    {n3} 条")
    print(f"  S3 静默 except   {n_pass}/{n_exc} ({n_pass/max(1,n_exc)*100:.0f}%)")
    print(f"  S2 待读文件      {len(rows)} 个（地图见上）")
    print()
    if rows:
        top = rows[0]
        print(f"{C}  下一轮建议先读：{top['file']}{D}")
        print(f"{C}    CC和={top['cc_sum']} CC峰={top['cc_max']} 枢纽={top['hub']} "
              f"候选={top['cands']} 已知缺陷={top['known']}{D}")
    print()

    if a.json:
        out = {
            "repo": repo, "missing_tools": miss,
            "s1": [f.as_dict() for f in findings],
            "s2": rows[:a.top],
            "s3": {k: ([f.as_dict() for f in v] if isinstance(v, list) else list(v))
                   for k, v in inv.items()},
            "s4": s4,
        }
        with open(a.json, "w", encoding="utf-8") as fh:
            json.dump(out, fh, ensure_ascii=False, indent=2)
        print(f"  已写出 {a.json}")

    # exit code：工具缺失或行为验证失败 → 非 0
    if miss:
        print(f"{Y}exit 2（工具缺失，结论需谨慎）{D}")
        return 2
    if s4 and s4["rc"] != 0:
        print(f"{Y}exit 1（行为验证未全绿）{D}")
        return 1
    print(f"{G}exit 0{D}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
