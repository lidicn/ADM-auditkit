#!/usr/bin/env python3
"""reconcile —— 手猎结论 vs 工具结论对账。

P1（建议书）：价值在「对账」，不在「手动」。
如果第一轮只手动、后面只自动、中间不对账，得到的是两堆互不相干的东西。
真正产经验的是那道落差：

  手动找到 3 个 / 工具报 0 个   → 工具漏了，为什么？   ← 最强信号（可能是规则失效）
  工具找到 5 个 / 手动漏了 5 个 → 我的盲区在哪？       ← 次强信号（人的注意力盲区）
  两者都没找到                  → 真盲区             ← 需人工确认

用法：
  auditkit reconcile <project> --round N
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from collections import defaultdict

ROOT = Path(__file__).resolve().parents[1]
PROJECTS_DIR = ROOT / "projects"


def load_scout_hypotheses(project: str) -> list[dict]:
    """从 scout/hypotheses.md 解析已确证的假设。"""
    f = PROJECTS_DIR / project / "scout" / "hypotheses.md"
    if not f.exists():
        return []
    text = f.read_text(encoding="utf-8")
    hypotheses = []
    # 简单解析：## 假设 N：标题，然后找状态和确证证据
    sections = re.split(r"^## 假设 ", text, flags=re.M)
    for sec in sections[1:]:
        title = sec.split("\n")[0].strip()
        status_match = re.search(r"\*\*状态\*\*[：:]\s*(.+)", sec)
        evidence_match = re.search(r"\*\*确证证据\*\*[：:]\s*(.+)", sec)
        status = status_match.group(1).strip() if status_match else "待验证"
        evidence = evidence_match.group(1).strip() if evidence_match else ""
        hypotheses.append({
            "title": title,
            "status": status,
            "evidence": evidence,
        })
    return hypotheses


def load_round_findings(project: str, round_num: int) -> list[dict]:
    """加载某轮的 findings。"""
    f = PROJECTS_DIR / project / f"round-{round_num:03d}" / "all-findings.json"
    if not f.exists():
        return []
    data = json.loads(f.read_text(encoding="utf-8"))
    if isinstance(data, list):
        return data
    return data.get("findings", [])


def extract_file_from_evidence(evidence: str) -> str | None:
    """从确证证据中提取文件路径（简单匹配 file:line 格式）。"""
    m = re.search(r"([\w./-]+\.\w+):(\d+)", evidence)
    if m:
        return m.group(1)
    return None


def cmd_reconcile(project: str, round_num: int) -> int:
    print(f"=== 对账: {project} 手猎 vs round-{round_num:03d} ===")
    print()

    hypotheses = load_scout_hypotheses(project)
    findings = load_round_findings(project, round_num)

    print(f"手猎假设: {len(hypotheses)} 条")
    print(f"工具命中: {len(findings)} 条")
    print()

    # 已确证的假设
    confirmed = [h for h in hypotheses if "确证" in h.get("status", "")]
    print(f"已确证假设: {len(confirmed)} 条")
    print()

    # 分类对账
    tool_missed = []  # 手动确证但工具没报
    human_missed = []  # 工具报了但手动没确证（需要人工确认是否真盲区）
    both_found = []    # 两者都找到了

    findings_by_file = defaultdict(list)
    for f in findings:
        findings_by_file[f.get("file", "")].append(f)

    for h in confirmed:
        evidence_file = extract_file_from_evidence(h.get("evidence", ""))
        if evidence_file:
            # 检查工具是否在该文件有命中
            tool_hits = [f for f in findings
                         if evidence_file in f.get("file", "") or f.get("file", "") in evidence_file]
            if tool_hits:
                both_found.append((h, tool_hits))
            else:
                tool_missed.append(h)
        else:
            # 无法提取文件，标记为需人工确认
            tool_missed.append(h)

    print("--- 对账结果 ---")
    print(f"  两者都找到: {len(both_found)} 条")
    print(f"  工具漏报（手动确证但工具 0 命中）: {len(tool_missed)} 条")
    print(f"  工具命中总数: {len(findings)} 条（需人工确认是否为手动盲区）")
    print()

    if tool_missed:
        print("--- 工具漏报详情（最强信号：可能是规则失效）---")
        for h in tool_missed:
            print(f"  [{h['status']}] {h['title']}")
            print(f"    证据: {h.get('evidence', '')}")
            print(f"    → 建议：检查是否有对应规则，或规则是否失效（0 命中）")
        print()

    if both_found:
        print("--- 两者都找到 ---")
        for h, hits in both_found:
            print(f"  [{h['status']}] {h['title']}")
            print(f"    工具命中 {len(hits)} 条:")
            for f in hits[:3]:
                print(f"      {f.get('rule', '')} {f.get('file', '')}:{f.get('line', '')}")
        print()

    print("--- 下一步 ---")
    print("  1. 工具漏报 → 写新规则或修复失效规则")
    print("  2. 手动盲区 → 补充手猎假设")
    print("  3. 共同盲区 → 需人工深入分析")
    print()
    print("对账产出应反哺：rules/（新规则）、PITFALLS.md（工具失效教训）、projects/<name>/adapter/（方言）")

    return 0


def main() -> int:
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    project = sys.argv[1]
    round_num = 1
    i = 2
    while i < len(sys.argv):
        if sys.argv[i] == "--round" and i + 1 < len(sys.argv):
            round_num = int(sys.argv[i + 1])
            i += 2
        else:
            i += 1
    return cmd_reconcile(project, round_num)


if __name__ == "__main__":
    sys.exit(main())
