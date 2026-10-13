#!/usr/bin/env python3
"""hit-set diff —— 规则命中集版本回归。

P0-2：共享判据变更联动验证。改 _common.py 或规则后，不用整轮重跑 553 条，
直接对比两轮的命中集，分钟级验证召回/精确率变化。

用法：
  python engine/hit_set_diff.py <project> <round_a> <round_b>
  python engine/hit_set_diff.py AutoForge 5 6

输出：
  - 各规则 added/removed 数量
  - 新增命中详情（rule, file, line）
  - 移除命中详情
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from collections import defaultdict

ROOT = Path(__file__).resolve().parents[1]
PROJECTS_DIR = ROOT / "projects"


def load_findings(project: str, round_num: int) -> list[dict]:
    """加载某轮的 all-findings.json。"""
    f = PROJECTS_DIR / project / f"round-{round_num:03d}" / "all-findings.json"
    if not f.exists():
        # 尝试 findings 目录
        findings_dir = PROJECTS_DIR / project / f"round-{round_num:03d}" / "findings"
        if findings_dir.exists():
            all_findings = []
            for jf in findings_dir.glob("*.json"):
                data = json.loads(jf.read_text(encoding="utf-8"))
                if isinstance(data, list):
                    all_findings.extend(data)
                elif isinstance(data, dict) and "findings" in data:
                    all_findings.extend(data["findings"])
            return all_findings
        print(f"错误: 找不到 {f}", file=sys.stderr)
        sys.exit(1)
    data = json.loads(f.read_text(encoding="utf-8"))
    if isinstance(data, list):
        return data
    return data.get("findings", [])


def finding_key(f: dict) -> tuple:
    """命中的唯一键：(rule, file, line)。"""
    return (f.get("rule", ""), f.get("file", ""), f.get("line", 0))


def site_key(f: dict) -> tuple:
    """站点级键：(file, line) —— 忽略 rule。
    AF-GAP-110：键级（rule,file,line）差集会被行号漂移 / rule 改名放大
    （实测键级 775 差 vs rule 级净额 +25，差 30 倍）。站点级回答
    "这处代码有没有被任何规则命中"，对 rule 改名不敏感。"""
    return (f.get("file", ""), f.get("line", 0))


def rule_net(findings: list[dict]) -> dict:
    """rule 级净额：每规则命中条数（不去重）。"""
    c = defaultdict(int)
    for f in findings:
        c[f.get("rule", "unknown")] += 1
    return dict(c)


def rule_names(findings: list[dict]) -> set:
    return {f.get("rule", "unknown") for f in findings}


def unregistered_rules(findings: list[dict]) -> list:
    """AF-GAP-108 / 召回护栏：findings 里未登记进 RULE_FAMILY 的 rule 名。
    这些 rule 的"未召回"无法被 recall.py 归到"有规则但漏了"，归类失真。
    注意：RULE_FAMILY 用**族号**（AFS-04）做 key，而 findings 的 rule 是
    **全名**（AFS-04-unguarded-load）——按全名精确匹配会全量误报，必须按
    族号前缀匹配（这本身就是 AF-GAP-108"rule 编号口径不一"的实例）。"""
    try:
        if str(ROOT) not in sys.path:
            sys.path.insert(0, str(ROOT))
        from core.recall import RULE_FAMILY
        known = set(RULE_FAMILY)
    except Exception:
        return []
    out = []
    for r in rule_names(findings):
        if r in known or any(r.startswith(k + "-") for k in known):
            continue
        out.append(r)
    return sorted(out)


def main() -> int:
    if len(sys.argv) != 4:
        print("用法: python engine/hit_set_diff.py <project> <round_a> <round_b>")
        print("示例: python engine/hit_set_diff.py AutoForge 5 6")
        return 2

    project = sys.argv[1]
    round_a = int(sys.argv[2])
    round_b = int(sys.argv[3])

    findings_a = load_findings(project, round_a)
    findings_b = load_findings(project, round_b)

    keys_a = {finding_key(f): f for f in findings_a}
    keys_b = {finding_key(f): f for f in findings_b}

    added = {k: v for k, v in keys_b.items() if k not in keys_a}
    removed = {k: v for k, v in keys_a.items() if k not in keys_b}

    print(f"=== 命中集 diff: {project} round-{round_a:03d} → round-{round_b:03d} ===")
    print(f"round-{round_a:03d}: {len(findings_a)} 条")
    print(f"round-{round_b:03d}: {len(findings_b)} 条")
    print(f"新增: {len(added)} 条")
    print(f"移除: {len(removed)} 条")
    print()

    # 按规则分组
    added_by_rule = defaultdict(list)
    for k, v in added.items():
        added_by_rule[v.get("rule", "unknown")].append(v)
    removed_by_rule = defaultdict(list)
    for k, v in removed.items():
        removed_by_rule[v.get("rule", "unknown")].append(v)

    print("--- 按规则统计 ---")
    all_rules = set(added_by_rule.keys()) | set(removed_by_rule.keys())
    for rule in sorted(all_rules):
        a = len(added_by_rule.get(rule, []))
        r = len(removed_by_rule.get(rule, []))
        print(f"  {rule}: +{a} -{r}")
    print()

    # ── 口径分层（AF-GAP-110：键级差 ≠ 工作量）────────────────────────
    # 键级精确差会被行号漂移 / rule 改名放大；站点级与 rule 级净额回答"净变化"。
    sites_a = {site_key(f) for f in findings_a}
    sites_b = {site_key(f) for f in findings_b}
    site_added = sites_b - sites_a
    site_removed = sites_a - sites_b
    rna, rnb = rule_net(findings_a), rule_net(findings_b)
    print("--- 口径分层（键级差会被行号漂移/改名放大，别当工作量）---")
    print(f"  键级（rule,file,line）: +{len(added)} -{len(removed)}  ← 漂移敏感")
    print(f"  站点级（file,line 去重，忽略 rule）: +{len(site_added)} -{len(site_removed)}"
          f"  净 {len(sites_b) - len(sites_a):+d}")
    rule_changed = {r for r in set(rna) | set(rnb) if rna.get(r, 0) != rnb.get(r, 0)}
    print(f"  rule 级净额: {len(rule_changed)} 个规则命中数变化，"
          f"总净 {sum(rnb.values()) - sum(rna.values()):+d} 条")
    # AF-GAP-108：rule 编号跨版本不稳定（改名伪装成增/删）
    rn_added = rule_names(findings_b) - rule_names(findings_a)
    rn_removed = rule_names(findings_a) - rule_names(findings_b)
    if rn_added or rn_removed:
        print(f"  [rule 稳定性] 新增 rule 名 {sorted(rn_added)} / 消失 rule 名 "
              f"{sorted(rn_removed)} —— 可能是改名而非增删，核对 RULE_FAMILY")
    unreg = unregistered_rules(findings_b)
    if unreg:
        print(f"  [召回护栏] 未登记 RULE_FAMILY 的 rule: {unreg} —— 其未召回归类会失真")
    print()

    if added:
        print("--- 新增命中详情 ---")
        for rule in sorted(added_by_rule.keys()):
            print(f"\n  [{rule}]")
            for f in added_by_rule[rule][:10]:
                print(f"    {f.get('file', '')}:{f.get('line', '')} - {f.get('message', '')[:60]}")
            if len(added_by_rule[rule]) > 10:
                print(f"    ... 还有 {len(added_by_rule[rule]) - 10} 条")
        print()

    if removed:
        print("--- 移除命中详情 ---")
        for rule in sorted(removed_by_rule.keys()):
            print(f"\n  [{rule}]")
            for f in removed_by_rule[rule][:10]:
                print(f"    {f.get('file', '')}:{f.get('line', '')} - {f.get('message', '')[:60]}")
            if len(removed_by_rule[rule]) > 10:
                print(f"    ... 还有 {len(removed_by_rule[rule]) - 10} 条")

    return 0


if __name__ == "__main__":
    sys.exit(main())
