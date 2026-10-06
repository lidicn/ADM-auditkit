#!/usr/bin/env python3
"""召回验证 —— 用**真实缺陷台账**检验工作流是否真的有效。

自检套件（selftest）用的是合成样本，能证明"规则没坏"，但证明不了
"规则在真实代码上找得到真缺陷"。这两件事的差距很大：
  - 合成样本是我按规则的判据写的，天然会被命中
  - 真实代码的缺陷长什么样、我的规则认不认，只有实测才知道

所以本模块做**金标准召回验证**：
  1. 从缺陷台账（baseline/bugs.json）取每个缺陷的**指纹正则 + 所属文件**
  2. 在源码里定位指纹命中的真实行号
  3. 到工作流产出的 findings 里查：该行号（容差 ±3 行）有没有被任何分析器命中
  4. 输出召回率 + 未召回清单

**未召回不等于规则没用**，要分三类：
  - `no_rule_covers`：没有任何规则设计来抓这类问题（真缺口，最该补）
  - `rule_exists_but_missed`：有对应规则但没命中该行（规则判据过窄）
  - `recalled`：召回成功

用法: recall.py <repo_root> <findings_dir> <bugs.json> [--tol 3]
"""
from __future__ import annotations

import ast

import json
import re
import sys
from collections import defaultdict
from pathlib import Path

TOL = 3

# 规则 → 它想抓的问题类型。用于把"未召回"归类为
# 「无规则覆盖」还是「有规则但漏了」。
RULE_FAMILY = {
    "AFS-01": "异常静默", "AFS-02": "批量部分失败", "AFS-03": "非原子写",
    "AFS-04": "无保护读取", "AFS-05": "墙上时钟超时", "AFS-07": "锁下IO",
    "ERR-05": "异常静默", "ERRH-02": "降级伪装成功", "ERRH-03": "降级路径无保护",
    "ERRH-05": "无清理", "ERRH-06": "错误未分类",
    "TX-01": "多写无事务", "TX-03": "先写后校验", "TX-04": "先删后写",
    "TX-05": "内存磁盘顺序", "TX-06": "镜像失同步",
    "RMW-01": "读写不一致", "RMW-02": "全量覆盖无锁",
    "SNG-01": "懒初始化单例", "SNG-03": "单例回退新建",
    "OBS-02": "无界累加", "OBS-04": "有界丢弃", "OBS-06": "失败不记账",
    "AUTH-04": "凭证只增不减", "AUTH-05": "锁内落盘",
    "CONC-08": "锁覆盖不全", "CONC-09": "锁下磁盘IO",
    "IN-01": "直接下标", "IN-02": "不安全转型", "IN-03": "路径拼接",
    "IN-07": "无界切片",
    "RSC-01": "组合爆炸", "RSC-02": "递归无预算", "RSC-03": "无界读",
    "RSC-05": "上限不一致",
    "SER-01": "单向序列化", "SER-02": "键漂移", "SER-05": "default=str",
    "CFG-01": "配置无结构校验", "CFG-02": "版本未校验", "CFG-07": "必填混用",
    "DEAD-01": "不可达语句", "DEAD-03": "死API", "DEAD-04": "常量漂移",
    "TIME-02": "墙上时钟超时", "NUM-01": "除零", "NUM-02": "空序列极值",
    "RES-02": "句柄未关闭", "PAT-04": "模块级env解析", "PAT-07": "实例无界容器",
    "GEN-01": "硬编码凭据", "GEN-02": "SQL拼接", "GEN-03": "动态求值",
    "GEN-04": "TLS关闭", "GEN-06": "日志泄露凭据",
}


def _norm(p: str) -> str:
    return p.replace("\\", "/").lstrip("./")


def locate(root: Path, rel_file: str, patterns: list[str]) -> list[int]:
    """在源码里定位缺陷指纹的真实行号。"""
    # 台账里的路径可能有前缀（src/src/autoforge/...），做尾部匹配
    candidates = []
    base = _norm(rel_file)
    for i in range(len(base.split("/"))):
        tail = "/".join(base.split("/")[i:])
        c = root / tail
        if c.is_file():
            candidates.append(c)
    if not candidates:
        # 再按文件名找
        name = Path(base).name
        candidates = list(root.rglob(name))[:3]
    if not candidates:
        # 缺陷可能位于**主包之外的目录**（如项目自建的 scripts/check_*.py，
        # AF BUG-05/21 即在此）。此时 root 是包根，够不到 ——
        # 向上回溯到仓库根再找，保证台账里的缺陷都能定位到实体文件。
        ups = []
        cur = root
        for _ in range(4):
            cur = cur.parent
            ups.append(cur)
        for up in ups:
            for i in range(len(base.split("/"))):
                tail = "/".join(base.split("/")[i:])
                c = up / tail
                if c.is_file():
                    candidates.append(c)
            if candidates:
                break
        if not candidates:
            for up in ups:
                hits = list(up.rglob(Path(base).name))[:3]
                if hits:
                    candidates = hits
                    break
    lines = []
    for c in candidates:
        try:
            text = c.read_text(errors="ignore")
        except OSError:
            continue
        for pat in patterns:
            try:
                # 首版只有 re.S 没有 re.M → `^`/`$` 退化成"整个文件首尾"，
                # 所有带行首锚点的指纹都定位不到（BUG-04 即此）。
                rx = re.compile(pat, re.M | re.S)
            except re.error:
                continue
            for m in rx.finditer(text):
                lineno = text[:m.start()].count("\n") + 1
                # 命中文件可能在 root 之外（项目自建 scripts/ 目录），
                # 此时 relative_to 会抛 ValueError → 退化为文件名
                try:
                    rel = str(c.relative_to(root))
                except ValueError:
                    rel = c.name
                lines.append((rel, lineno))
        if lines:
            break
    return lines


def load_findings(fdir: Path) -> dict[str, list[int]]:
    """file -> [命中行号...]"""
    out = defaultdict(list)
    for j in fdir.rglob("*.json"):
        try:
            d = json.loads(j.read_text())
        except Exception:
            continue
        items = d.get("findings", []) if isinstance(d, dict) else (d if isinstance(d, list) else [])
        for f in items:
            fn = _norm(str(f.get("file", "")))
            ln = f.get("line")
            if isinstance(ln, int):
                out[fn].append(ln)
    return out


def scope_of(root: Path, rel: str, ln: int) -> tuple[int, int] | None:
    """返回缺陷行所在**顶层作用域**（class/def）的起止行。

    为什么要这个：台账记的是字段声明行（如 af_intervention.py:143），
    而规则报的是类定义行（132）。两者相差十几行，按行号容差会误判为
    "未召回"——实际是同一个缺陷，只是报告粒度不同。
    按作用域判定可消除这类误判。
    """
    f = root / rel
    if not f.is_file():
        return None
    try:
        tree = ast.parse(f.read_text(errors="ignore"))
    except SyntaxError:
        return None
    best = None
    for n in tree.body:
        if isinstance(n, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            end = getattr(n, "end_lineno", None) or n.lineno
            if n.lineno <= ln <= end:
                best = (n.lineno, end)
    return best


def matched_lines(findings: dict[str, list[int]], rel: str, ln: int, tol: int,
                  scope: tuple[int, int] | None = None) -> bool:
    """findings 里是否有覆盖 rel:ln±tol 的命中（路径尾部匹配）。"""
    want = _norm(rel)
    for fn, lns in findings.items():
        # 尾部匹配，兼容 findings 用相对包根、台账用相对仓库根
        if fn == want or fn.endswith("/" + want) or want.endswith("/" + fn) \
                or Path(fn).name == Path(want).name:
            for x in lns:
                if abs(x - ln) <= tol:
                    return True
                # 同一顶层作用域内也算召回（粒度差异）
                if scope and scope[0] <= x <= scope[1]:
                    return True
    return False


def classify(rule_ids: set[str], bug_id: str) -> str:
    """未召回时归类：有没有规则是设计来抓这类问题的。"""
    # 简易映射：缺陷 → 期望命中的规则族
    expect = {
        "BUG-01": "无界累加", "BUG-02": "配置无结构校验",
        "BUG-03": "非原子写", "BUG-04": "异常静默",
        "BUG-05": "非原子写", "BUG-06": "组合爆炸",
        "BUG-07": "异常静默", "BUG-08": "读写不一致",
        "BUG-09": "墙上时钟超时", "BUG-10": "模块级env解析",
        "BUG-11": "先删后写", "BUG-12": "内存磁盘顺序",
        "BUG-13": "降级路径无保护", "BUG-14": "无界累加",
        "BUG-15": "配置无结构校验", "BUG-16": "死API",
        "BUG-17": "配置无结构校验", "BUG-18": "无界累加",
        "BUG-19": "凭证只增不减", "BUG-20": "读写不一致",
        "BUG-21": "无界累加",
    }
    fam = expect.get(bug_id)
    if fam is None:
        return "unknown"
    # 是否存在该族规则（用规则前缀反查）
    has = any(RULE_FAMILY.get(r.split("-")[0] + "-" + r.split("-")[1] if r.count("-") >= 1 else r) == fam
              or fam in str(RULE_FAMILY.values())
              for r in rule_ids)
    return "rule_exists_but_missed" if has else "no_rule_covers"


def main() -> int:
    root = Path(sys.argv[1] if len(sys.argv) > 1 else ".").resolve()
    fdir = Path(sys.argv[2] if len(sys.argv) > 2 else ".")
    bugs_f = Path(sys.argv[3] if len(sys.argv) > 3 else "baseline/bugs.json")
    tol = TOL
    if "--tol" in sys.argv:
        tol = int(sys.argv[sys.argv.index("--tol") + 1])

    bugs = json.loads(bugs_f.read_text()).get("bugs", [])
    findings = load_findings(fdir)
    rule_ids = set()
    for j in fdir.rglob("*.json"):
        try:
            d = json.loads(j.read_text())
        except Exception:
            continue
        items = d.get("findings", []) if isinstance(d, dict) else (d if isinstance(d, list) else [])
    for f in items:
            rule_ids.add(str(f.get("rule", "")))

    rows = []
    for b in bugs:
        locs = locate(root, b.get("file", ""), b.get("patterns", []))
        if not locs:
            rows.append({"id": b["id"], "severity": b.get("severity"),
                         "status": "locate_failed",
                         "note": "指纹在源码里定位不到（缺陷可能已修或指纹失效）"})
            continue
        rel, ln = locs[0]
        scope = scope_of(root, rel, ln)
        hit = matched_lines(findings, rel, ln, tol, scope)
        rows.append({
            "id": b["id"], "severity": b.get("severity"),
            "status": "recalled" if hit else "missed",
            "loc": f"{rel}:{ln}",
            "scope": f"{scope[0]}-{scope[1]}" if scope else None,
            "kind": None if hit else classify(rule_ids, b["id"]),
            "title": b.get("title", "")[:60],
        })

    rec = [r for r in rows if r["status"] == "recalled"]
    miss = [r for r in rows if r["status"] == "missed"]
    bad = [r for r in rows if r["status"] == "locate_failed"]
    rate = len(rec) / max(len(rows), 1)

    out = {
        "total_bugs": len(rows),
        "recalled": len(rec),
        "missed": len(miss),
        "locate_failed": len(bad),
        "recall_rate": round(rate, 3),
        "tolerance_lines": tol,
        "rows": rows,
    }
    print(json.dumps(out, ensure_ascii=False, indent=2))
    return 0 if rate >= 0.5 else 1


if __name__ == "__main__":
    raise SystemExit(main())
