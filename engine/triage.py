#!/usr/bin/env python3
"""triage —— 裁决落盘。

P1-1：人工裁决不落盘，下轮重报。canary:103、flock:132 这类"语义不成立"的 FP，
这次裁了，下个 agent 还得重裁。

裁决按 (rule, file, line) 写进 projects/<name>/triage.json；
后续轮次自动标"已裁决"，只增量报新命中。

用法：
  auditkit triage accept <project> --rule R --file F --line L --reason "..."
  auditkit triage reject <project> --rule R --file F --line L --reason "..."
  auditkit triage list <project>
  auditkit triage apply <project> --round N  # 标记某轮中已裁决的命中
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from datetime import datetime

ROOT = Path(__file__).resolve().parents[1]
PROJECTS_DIR = ROOT / "projects"


def triage_path(project: str) -> Path:
    return PROJECTS_DIR / project / "triage.json"


def bugs_path(project: str) -> Path:
    return PROJECTS_DIR / project / "bugs.json"


def load_bugs(project: str) -> dict:
    f = bugs_path(project)
    if not f.exists():
        return {"version": 1, "project": project, "bugs": []}
    return json.loads(f.read_text(encoding="utf-8"))


def save_bugs(project: str, data: dict) -> None:
    f = bugs_path(project)
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def load_triage(project: str) -> dict:
    f = triage_path(project)
    if not f.exists():
        return {"version": 1, "project": project, "rulings": {}}
    return json.loads(f.read_text(encoding="utf-8"))


def save_triage(project: str, data: dict) -> None:
    f = triage_path(project)
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def ruling_key(rule: str, file: str, line: int) -> str:
    return f"{rule}|{file}|{line}"


def add_ruling(project: str, verdict: str, rule: str, file: str, line: int, reason: str) -> None:
    data = load_triage(project)
    key = ruling_key(rule, file, line)
    data["rulings"][key] = {
        "verdict": verdict,  # "accept" = 已知未修（真bug）, "reject" = 不采纳（误报）
        "rule": rule,
        "file": file,
        "line": line,
        "reason": reason,
        "timestamp": datetime.now().isoformat(),
    }
    save_triage(project, data)
    print(f"已记录裁决: [{verdict}] {rule} {file}:{line}")
    print(f"  原因: {reason}")

    # P1-2：accept 裁决自动写入 bugs.json 缺陷台账
    if verdict == "accept":
        bugs = load_bugs(project)
        # 检查是否已存在
        exists = any(b["rule"] == rule and b["file"] == file and b["line"] == line
                     for b in bugs["bugs"])
        if not exists:
            bugs["bugs"].append({
                "id": f"{project}-{len(bugs['bugs']) + 1:03d}",
                "rule": rule,
                "file": file,
                "line": line,
                "severity": "medium",
                "status": "open",  # open / fixed / wontfix
                "reason": reason,
                "discovered_round": None,
                "fixed_round": None,
                "created_at": datetime.now().isoformat(),
            })
            save_bugs(project, bugs)
            print(f"  已写入缺陷台账: {bugs_path(project)}")
        else:
            print(f"  缺陷台账中已存在，跳过")


def list_rulings(project: str) -> None:
    data = load_triage(project)
    rulings = data.get("rulings", {})
    if not rulings:
        print(f"项目 {project} 暂无裁决记录")
        return
    print(f"项目 {project} 裁决记录（共 {len(rulings)} 条）:")
    for key, r in sorted(rulings.items()):
        print(f"  [{r['verdict']}] {r['rule']} {r['file']}:{r['line']}")
        print(f"    原因: {r.get('reason', '')}")
        print(f"    时间: {r.get('timestamp', '')}")


def apply_to_round(project: str, round_num: int) -> None:
    """标记某轮中已裁决的命中，输出增量（未裁决的新命中）。"""
    data = load_triage(project)
    rulings = data.get("rulings", {})

    findings_file = PROJECTS_DIR / project / f"round-{round_num:03d}" / "all-findings.json"
    if not findings_file.exists():
        print(f"错误: 找不到 {findings_file}", file=sys.stderr)
        sys.exit(1)

    findings = json.loads(findings_file.read_text(encoding="utf-8"))
    if isinstance(findings, dict):
        findings = findings.get("findings", [])

    adjudicated = 0
    new_findings = []
    for f in findings:
        key = ruling_key(f.get("rule", ""), f.get("file", ""), f.get("line", 0))
        if key in rulings:
            adjudicated += 1
            f["adjudicated"] = rulings[key]["verdict"]
            f["adjudicated_reason"] = rulings[key].get("reason", "")
        else:
            new_findings.append(f)

    print(f"=== 轮次 {project} round-{round_num:03d} 裁决应用 ===")
    print(f"总命中: {len(findings)}")
    print(f"已裁决: {adjudicated}")
    print(f"新命中（未裁决）: {len(new_findings)}")
    print()

    # 输出新命中按规则分组
    from collections import Counter
    by_rule = Counter(f.get("rule", "") for f in new_findings)
    print("新命中按规则:")
    for rule, count in by_rule.most_common():
        print(f"  {rule}: {count}")

    # 保存带裁决标记的 findings
    out_file = PROJECTS_DIR / project / f"round-{round_num:03d}" / "findings-adjudicated.json"
    out_file.write_text(json.dumps(findings, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"\n已保存带裁决标记的 findings: {out_file}")


def main() -> int:
    if len(sys.argv) < 2:
        print(__doc__)
        return 2

    cmd = sys.argv[1]

    if cmd == "accept" or cmd == "reject":
        # 解析参数
        project = sys.argv[2] if len(sys.argv) > 2 else None
        if not project:
            print(f"错误: triage {cmd} 需要 <project>")
            return 2
        # 简单解析 --rule --file --line --reason
        args = {}
        i = 3
        while i < len(sys.argv):
            if sys.argv[i] == "--rule" and i + 1 < len(sys.argv):
                args["rule"] = sys.argv[i + 1]
                i += 2
            elif sys.argv[i] == "--file" and i + 1 < len(sys.argv):
                args["file"] = sys.argv[i + 1]
                i += 2
            elif sys.argv[i] == "--line" and i + 1 < len(sys.argv):
                args["line"] = int(sys.argv[i + 1])
                i += 2
            elif sys.argv[i] == "--reason" and i + 1 < len(sys.argv):
                args["reason"] = sys.argv[i + 1]
                i += 2
            else:
                i += 1
        if not all(k in args for k in ("rule", "file", "line")):
            print(f"错误: triage {cmd} 需要 --rule --file --line")
            return 2
        add_ruling(project, cmd, args["rule"], args["file"], args["line"],
                   args.get("reason", ""))
        return 0

    elif cmd == "list":
        project = sys.argv[2] if len(sys.argv) > 2 else None
        if not project:
            print("错误: triage list 需要 <project>")
            return 2
        list_rulings(project)
        return 0

    elif cmd == "bugs":
        # P1-2：查看缺陷台账
        project = sys.argv[2] if len(sys.argv) > 2 else None
        if not project:
            print("错误: triage bugs 需要 <project>")
            return 2
        bugs = load_bugs(project)
        bug_list = bugs.get("bugs", [])
        if not bug_list:
            print(f"项目 {project} 暂无缺陷台账记录")
            return 0
        print(f"项目 {project} 缺陷台账（共 {len(bug_list)} 条）:")
        for b in bug_list:
            print(f"  [{b['status']}] {b['id']} {b['rule']} {b['file']}:{b['line']}")
            print(f"    原因: {b.get('reason', '')}")
        return 0

    elif cmd == "apply":
        project = sys.argv[2] if len(sys.argv) > 2 else None
        round_num = None
        i = 3
        while i < len(sys.argv):
            if sys.argv[i] == "--round" and i + 1 < len(sys.argv):
                round_num = int(sys.argv[i + 1])
                i += 2
            else:
                i += 1
        if not project or not round_num:
            print("错误: triage apply 需要 <project> --round N")
            return 2
        apply_to_round(project, round_num)
        return 0

    print(f"未知 triage 子命令: {cmd}")
    return 2


if __name__ == "__main__":
    sys.exit(main())
