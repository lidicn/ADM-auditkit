#!/usr/bin/env python3
"""core/report.py —— 把 round 产物生成人类可读 markdown 摘要。

auditkit 的 round 只产出 JSON（summary.json + findings/*.json），开发者难直接读。
本模块把这些 JSON 转成 markdown 摘要：命中数 / 严重度分布 / Top 缺陷列表 / 零覆盖盲区。

投递：cmd_round 末尾调用 generate_report()，生成 report.md 落到 round 目录；
宿主机侧 scripts/deliver_report.sh 再把它拷到目标项目 doc/审计报告/。

用法（被 cmd_round 调）：
  from core.report import generate_report
  generate_report(round_dir, project_name, profile)
"""
from __future__ import annotations

import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _load_findings(round_dir: Path) -> list[dict]:
    """收集 round 目录下所有 findings JSON，合并成一条列表。"""
    findings_dir = round_dir / "findings"
    all_f: list[dict] = []
    if findings_dir.is_dir():
        for jf in sorted(findings_dir.glob("*.json")):
            try:
                d = json.loads(jf.read_text(encoding="utf-8-sig"))
            except Exception:
                continue
            all_f.extend(d.get("findings", []))
    # 兜底：all-findings.json
    af = round_dir / "all-findings.json"
    if af.exists() and not all_f:
        try:
            all_f = json.loads(af.read_text(encoding="utf-8-sig")).get("findings", [])
        except Exception:
            pass
    return all_f


def _sev_sort(f: dict) -> tuple:
    return (SEV_ORDER.get(f.get("severity", "medium"), 2), f.get("file", ""), f.get("line", 0))


def generate_report(round_dir: Path, project: str, profile: dict | None = None) -> Path:
    """生成 report.md，返回其路径。

    Args:
        round_dir: round-NNN 目录（含 findings/ summary.json profile.json）
        project: 项目名
        profile: 画像 dict（可选，用于报告头部）
    """
    summary = {}
    sf = round_dir / "summary.json"
    if sf.exists():
        try:
            summary = json.loads(sf.read_text(encoding="utf-8-sig")).get("summary", {})
        except Exception:
            pass

    findings = _load_findings(round_dir)

    # 严重度分布
    sev_counts = Counter(f.get("severity", "medium") for f in findings)
    # 规则分布
    rule_counts = Counter(f.get("rule", "?") for f in findings)
    # 文件分布（Top 10）
    file_counts = Counter(f.get("file", "?") for f in findings)

    lines: list[str] = []
    lines.append(f"# {project} 审计报告 · {round_dir.name}")
    lines.append("")
    lines.append(f"> 由 auditkit 自动生成。本报告是**机器候选**，非确证缺陷——")
    lines.append(f> 候选不实测不升级为缺陷（proposal-1 方法论）。")
    lines.append("")

    # 头部：画像摘要
    if profile:
        lang = profile.get("languages", {})
        lines.append("## 画像")
        lines.append("")
        lines.append(f"- 主语言: {lang.get('primary', '?')}  文件数: {lang.get('files', '?')}  行数: {lang.get('lines', '?')}")
        fw = profile.get("frameworks", [])
        if fw:
            lines.append(f"- 框架: {', '.join(fw)}")
        lines.append("")

    # 汇总
    lines.append("## 汇总")
    lines.append("")
    lines.append(f"| 指标 | 值 |")
    lines.append(f"|---|---|")
    lines.append(f"| 命中总数 | **{len(findings)}** |")
    sev_row = " · ".join(f"{s} {sev_counts.get(s, 0)}" for s in
                         ("critical", "high", "medium", "low") if sev_counts.get(s))
    lines.append(f"| 严重度分布 | {sev_row or '无'} |")
    lines.append(f"| 规则数 | {len(rule_counts)} |")
    at = summary.get("analyzers_total", "?")
    ao = summary.get("analyzers_ok", "?")
    lines.append(f"| 分析器 | {ao}/{at} ok |")
    lines.append(f"| 引擎 active 规则 | {summary.get('engine', {}).get('active_rules', '?')} |")
    lines.append("")

    # 零覆盖盲区（proposal-3 ⑥：未覆盖面显式 FAIL）
    zero_hit = summary.get("zero_hit", [])
    if zero_hit:
        lines.append("## ⚠ 零覆盖盲区（规则在该项目 0 命中）")
        lines.append("")
        lines.append("> 零命中 ≠ 干净。可能是规则不适用，也可能是规则静默失效（PITFALLS N1）。需人工确认。")
        lines.append("")
        for z in zero_hit:
            lines.append(f"- `{z}`")
        lines.append("")

    # Top 规则
    lines.append("## 命中规则 Top 15")
    lines.append("")
    lines.append("| 规则 | 命中数 |")
    lines.append("|---|---|")
    for rule, cnt in rule_counts.most_common(15):
        lines.append(f"| `{rule}` | {cnt} |")
    lines.append("")

    # Top 文件
    if file_counts:
        lines.append("## 命中文件 Top 10")
        lines.append("")
        lines.append("| 文件 | 命中数 |")
        lines.append("|---|---|")
        for fpath, cnt in file_counts.most_common(10):
            # 脱敏：去掉 /targets/ 前缀
            short = fpath.replace("/targets/", "") if "/targets/" in fpath else fpath
            lines.append(f"| `{short}` | {cnt} |")
        lines.append("")

    # 缺陷明细（high + critical 优先，最多 50 条）
    high_f = [f for f in findings if f.get("severity") in ("critical", "high")]
    high_f.sort(key=_sev_sort)
    if high_f:
        lines.append(f"## 高危缺陷明细（critical + high，共 {len(high_f)} 条，列前 50）")
        lines.append("")
        for f in high_f[:50]:
            short = f.get("file", "?").replace("/targets/", "") if "/targets/" in f.get("file", "") else f.get("file", "?")
            lines.append(f"### {f.get('rule', '?')} · `{f.get('severity', '?')}`")
            lines.append(f"**{f.get('title', '')}**")
            lines.append(f"- 位置: `{short}:{f.get('line', '?')}`")
            msg = f.get("message", "")
            if msg:
                lines.append(f"- 说明: {msg}")
            snip = f.get("snippet", "")
            if snip:
                lines.append(f"- 代码:")
                lines.append(f"  ```")
                for sl in snip.splitlines()[:5]:
                    lines.append(f"  {sl}")
                lines.append(f"  ```")
            lines.append("")

    if len(high_f) > 50:
        lines.append(f"> 还有 {len(high_f) - 50} 条高危未列出，见 `findings/` 原始 JSON。")
        lines.append("")

    lines.append("---")
    lines.append("")
    lines.append("## 关于本报告")
    lines.append("")
    lines.append("- 本报告由 auditkit 静态分析自动生成，是**候选命中**，不是确证缺陷。")
    lines.append("- 静态命中有假阳性（详见 PITFALLS.md），需人工 triage + 实测确证。")
    lines.append("- 原始数据: `findings/*.json` / `all-findings.json` / `summary.json`")
    lines.append("")

    report_path = round_dir / "report.md"
    report_path.write_text("\n".join(lines), encoding="utf-8")
    return report_path


def main() -> int:
    import sys
    if len(sys.argv) < 3:
        print("用法: report.py <round_dir> <project>")
        return 2
    round_dir = Path(sys.argv[1])
    project = sys.argv[2]
    profile = {}
    pf = round_dir / "profile.json"
    if pf.exists():
        try:
            profile = json.loads(pf.read_text(encoding="utf-8-sig"))
        except Exception:
            pass
    p = generate_report(round_dir, project, profile)
    print(f"报告已生成: {p}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
