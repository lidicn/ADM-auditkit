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
