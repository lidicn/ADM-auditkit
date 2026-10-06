#!/usr/bin/env python3
"""Agent/Skill 配置面扫描（agentic 专属面）。

扫描对象：SKILL.md、CLAUDE.md、AGENTS.md、.claude/**、*.mcp.json、prompts/**、commands/**
检测项：越权工具声明、危险命令模板、敏感路径读写、外传通道、隐藏字符、指令覆盖话术
产出：skill-scan.json（含 findings，severity 分级）
"""
import json
import re
import sys
from pathlib import Path

TARGET_GLOBS = ["**/SKILL.md", "**/CLAUDE.md", "**/AGENTS.md", "**/.claude/**/*.md",
                "**/*.mcp.json", "**/commands/**/*.md", "**/prompts/**/*"]

RULES = [
    ("AF-SKILL-001", "critical", r"curl[^|\n]*\|\s*(sudo\s+)?(ba|z)?sh", "远程脚本直执行（下载即执行）"),
    ("AF-SKILL-002", "critical", r"(sudo\s+|\brm\s+-rf\s+[~/$])", "提权或递归删除命令模板"),
    ("AF-SKILL-003", "high", r"(\.ssh|\.aws|\.gnupg|\.kube|id_rsa|\.npmrc|\.netrc|credentials\.json)", "读写凭据/密钥类敏感路径"),
    ("AF-SKILL-004", "high", r"(\.claude/settings|\.claude\.json|CLAUDE\.md|\.cursorrules|\.mcp\.json)", "改写 agent 自身配置（可持久化植入）"),
    ("AF-SKILL-005", "high", r"(ignore\s+(all\s+)?previous\s+instructions|disregard\s+.*(rule|policy)|override\s+safety|--dangerously|--no-verify|--yolo)", "指令覆盖/绕过安全开关话术"),
    ("AF-SKILL-006", "high", r"(base64\s+-d|eval\s*\(|atob\(|exec\(|os\.system\()", "编码/动态执行绕过"),
    ("AF-SKILL-007", "medium", r"https?://(?!github\.com|docs\.|www\.w3\.org|schema\.|pypi\.org|npmjs\.com)[^\s\"')]+", "外联到非白名单域名（数据外传通道）"),
    ("AF-SKILL-008", "medium", r"(api[_-]?key|token|password|secret)\s*[:=]\s*['\"]?[A-Za-z0-9_\-]{8,}", "疑似硬编码凭据"),
    ("AF-SKILL-009", "medium", r"(POST|PUT|fetch\()\s*.*https?://", "向外发送数据"),
    ("AF-SKILL-010", "low", r"[\u200b-\u200f\u202a-\u202e\u2060\ufeff]", "零宽/双向控制字符（隐藏指令）"),
    ("AF-SKILL-011", "info", r"allowed-tools\s*[:=].*(Bash|Write|Edit|NotebookEdit)", "声明了高权限工具，需核对最小权限"),
]


def iter_targets(root: Path):
    seen = set()
    for g in TARGET_GLOBS:
        for p in root.glob(g):
            if p.is_file() and p not in seen and ".git" not in p.parts:
                seen.add(p)
                yield p


def main() -> int:
    root = Path(sys.argv[1] if len(sys.argv) > 1 else "/data/workspace/audit/src")
    outdir = Path(sys.argv[2] if len(sys.argv) > 2 else "/data/workspace/audit/rounds/round-001/skill")
    outdir.mkdir(parents=True, exist_ok=True)

    findings = []
    scanned = []
    for p in iter_targets(root):
        try:
            txt = p.read_text(errors="ignore")
        except Exception:  # noqa: BLE001
            continue
        scanned.append(str(p.relative_to(root)))
        for rid, sev, pat, msg in RULES:
            for m in re.finditer(pat, txt, re.I):
                line = txt[: m.start()].count("\n") + 1
                findings.append({
                    "rule": rid, "severity": sev, "file": str(p.relative_to(root)),
                    "line": line, "message": msg, "snippet": m.group(0)[:160],
                })
        # 未声明 allowed-tools 的 SKILL.md
        if p.name == "SKILL.md" and not re.search(r"allowed-tools", txt, re.I):
            findings.append({"rule": "AF-SKILL-012", "severity": "info", "file": str(p.relative_to(root)),
                             "line": 1, "message": "SKILL.md 未声明 allowed-tools（无法静态约束工具权限）",
                             "snippet": ""})

    out = {"scanned_files": scanned, "findings": findings,
           "counts": {s: sum(1 for f in findings if f["severity"] == s)
                      for s in ["critical", "high", "medium", "low", "info"]}}
    (outdir / "skill-scan.json").write_text(json.dumps(out, ensure_ascii=False, indent=2))
    print(json.dumps({"scanned": len(scanned), **out["counts"]}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
