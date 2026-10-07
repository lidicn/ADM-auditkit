#!/usr/bin/env python3
"""engine/runner.py —— 新引擎的轮次运行器（Phase 2）。

替代 core/registry.py 的 subprocess 调用，直接在 Python 内运行：
  1. L3 规则（rules/generic + rules/project）
  2. 旧分析器（可选，通过 StaticAstMode.run_legacy → AnalyzerBridge → legacy/registry.py）
  3. 跨语言通用层（generic_text.py，保持原 subprocess 方式）

输出格式与 registry.py 完全兼容：
  findings/<analyzer>.json   旧分析器 findings（按分析器名分组）
  findings/engine_rules.json 新规则 findings
  findings/generic_text.json 跨语言 findings
  summary.json                汇总统计（兼容 registry.py 格式）
  all-findings.json           全部 findings
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
CORE = ROOT / "core"

from .base import Finding  # noqa: E402
from .loader import load_rules  # noqa: E402
from .profile import as_profile  # noqa: E402
from .static_ast_mode import StaticAstMode  # noqa: E402


def finding_to_legacy_dict(f: Finding) -> dict:
    """把 Finding 转换成旧分析器 JSON 格式（rule/message/snippet 字段名）。"""
    return {
        "rule": f.rule_id,
        "file": f.file,
        "line": f.line,
        "severity": f.severity,
        "title": f.title,
        "message": f.detail,
        "snippet": f.evidence,
    }


def run_generic_text(repo_root: Path) -> list[Finding]:
    """运行跨语言通用层（保持原 subprocess 方式）。"""
    gt = CORE / "lang" / "generic_text.py"
    if not gt.exists():
        return []
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        cmd = [sys.executable, str(gt), str(repo_root), str(td)]
        try:
            p = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        except subprocess.TimeoutExpired:
            return []
        if p.returncode != 0:
            return []
        findings = []
        for j in Path(td).rglob("*.json"):
            try:
                d = json.loads(j.read_text())
            except Exception:
                continue
            findings += [Finding.from_dict(x) for x in d.get("findings", [])]
        return findings


def run_round(repo_path: Path, outdir: Path, profile_path: Path | None = None,
              extra_roots: list[Path] | None = None,
              include_legacy: bool = False) -> dict:
    """执行一轮审计，写入兼容格式的产物。

    Args:
        repo_path: 仓库根目录
        outdir: 产物输出目录（findings/ 会创建在这里）
        profile_path: 画像 JSON 路径（可选）
        extra_roots: 附加扫描根（可选）
        include_legacy: 是否同时运行 legacy/ 下的旧分析器（默认 False，只跑 rules/ 新规则）

    Returns:
        summary dict（兼容 registry.py 的 summary 格式）
    """
    outdir.mkdir(parents=True, exist_ok=True)
    findings_dir = outdir / "findings"
    findings_dir.mkdir(parents=True, exist_ok=True)

    # 1) 加载画像
    profile = None
    if profile_path and profile_path.exists():
        try:
            profile = json.loads(profile_path.read_text())
        except Exception:
            profile = None
    prof = as_profile(profile)

    # 2) 加载规则
    rules_report = load_rules()
    active_rules = list(rules_report.registry)

    # 构造 adapter 传递 extra_roots
    class _SimpleAdapter:
        def __init__(self, extra):
            self._extra = extra or []
        def extra_roots(self, repo):
            return [str(r) for r in self._extra]
        def focus(self):
            return []
        def focus_rules(self):
            return []
        def profile(self):
            return None
    adapter = _SimpleAdapter(extra_roots)

    # 3) 运行新规则（逐文件逐规则）
    mode = StaticAstMode(include_legacy=False)
    new_rule_findings: list[Finding] = []
    for path in mode.iter_sources(str(repo_path), prof, adapter):
        try:
            src = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        from .base import parse_unit
        try:
            tree = parse_unit(src, str(path))
        except Exception:
            continue
        for rule in active_rules:
            try:
                out = rule.run(tree, prof, adapter) or []
            except Exception as e:
                mode.diagnostics.append(f"规则 {rule.id} 在 {path} 异常: {e}")
                continue
            new_rule_findings += [f for f in out if isinstance(f, Finding)]

    # 4) 运行 legacy 旧分析器（可选，默认关闭；逐个脚本，按脚本名分组）
    legacy_by_analyzer: dict[str, list[Finding]] = {}
    if include_legacy:
        bridge = mode.bridge
        try:
            scripts = bridge.analyzer_scripts()
        except Exception as e:
            mode.diagnostics.append(f"legacy 分析器不可用: {e}")
            scripts = []
        roots = mode.scope_roots(str(repo_path), prof, adapter) or [repo_path]
        for script in scripts:
            analyzer_name = script.stem
            for root in roots:
                try:
                    fs = bridge.run_script(script, root)
                    legacy_by_analyzer.setdefault(analyzer_name, []).extend(fs)
                except Exception as e:
                    mode.diagnostics.append(f"{analyzer_name} @ {root} 失败: {e}")

    # 5) 运行跨语言通用层
    gt_findings = run_generic_text(repo_path)

    # 6) 合并所有 findings
    all_findings = new_rule_findings[:]
    for fs in legacy_by_analyzer.values():
        all_findings += fs
    all_findings += gt_findings

    # 7) 按分析器/规则分组写 JSON（与 registry.py 输出格式完全兼容）
    for analyzer, findings in legacy_by_analyzer.items():
        if findings:
            (findings_dir / f"{analyzer}.json").write_text(
                json.dumps({"findings": [finding_to_legacy_dict(f) for f in findings]},
                           ensure_ascii=False, indent=2))

    # 新规则 findings
    if new_rule_findings:
        (findings_dir / "engine_rules.json").write_text(
            json.dumps({"findings": [finding_to_legacy_dict(f) for f in new_rule_findings]},
                       ensure_ascii=False, indent=2))

    # 跨语言 findings
    if gt_findings:
        (findings_dir / "generic_text.json").write_text(
            json.dumps({"findings": [finding_to_legacy_dict(f) for f in gt_findings]},
                       ensure_ascii=False, indent=2))

    # 7) 统计
    counts: dict[str, int] = {}
    for f in all_findings:
        counts[f.rule_id] = counts.get(f.rule_id, 0) + 1

    results = {}
    for analyzer, findings in legacy_by_analyzer.items():
        results[analyzer] = {"status": "ok", "counts": {}}
        for f in findings:
            r = f.rule_id
            results[analyzer]["counts"][r] = results[analyzer]["counts"].get(r, 0) + 1
    if new_rule_findings:
        results["engine_rules"] = {"status": "ok", "counts": {}}
        for f in new_rule_findings:
            results["engine_rules"]["counts"][f.rule_id] = \
                results["engine_rules"]["counts"].get(f.rule_id, 0) + 1
    if gt_findings:
        results["generic_text"] = {"status": "ok", "counts": {}}

    applicable = [k for k, v in results.items() if v.get("status") == "ok"]
    zero_hit = [k for k in applicable if not results[k].get("counts")]

    summary = {
        "repo": str(repo_path),
        "languages": {},
        "tools": {},
        "analyzers_total": len(results),
        "analyzers_ok": len(applicable),
        "not_applicable": [],
        "failed": [],
        "zero_hit": zero_hit,
        "total_findings": len(all_findings),
        "engine": {
            "active_rules": len(active_rules),
            "broken_rules": len(rules_report.broken),
            "legacy_analyzers": len(legacy_by_analyzer),
            "diagnostics": mode.diagnostics[:50],
        },
    }

    (outdir / "summary.json").write_text(
        json.dumps({"summary": summary, "results": results}, ensure_ascii=False, indent=2))
    (outdir / "all-findings.json").write_text(
        json.dumps({"findings": [finding_to_legacy_dict(f) for f in all_findings]},
                   ensure_ascii=False, indent=2))

    return summary
