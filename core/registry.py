#!/usr/bin/env python3
"""分析器分派与能力探测 —— 解决 AF 工作流的两处硬伤。

硬伤一：**阶段 FAIL 但照样跑完**。AF 的编排里 P2 semgrep、P3 detect-secrets、
P4 graph 长期 FAIL（沙箱装不好 semgrep），日志刷屏却不影响退出码。
读者分不清"真失败"和"这个工具本来就没有"。

硬伤二：**0 命中没有解释**。扫完一堆 0，不知道是代码干净还是规则不适用。

本模块统一处理：
  1. 开工前探测每个分析器/外部工具**是否可用**，不可用标 unavailable（不算失败）
  2. 跑完统计每个分析器的命中数与**适用语言覆盖率**
  3. 输出 capability 矩阵，让"0 命中"总有解释：
       - unavailable → 工具缺失，本项无结论
       - not_applicable → 项目无该语言代码
       - clean → 适用且 0 命中（这才是真干净）

用法: registry.py <repo_root> <outdir> [--profile <profile.json>]
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
ANALYZERS = HERE / "analyzers"
LANG = HERE / "lang"

# 分析器 → 适用语言。Python AST 分析器只对 python 生效。
ANALYZER_LANGS = {p.stem: "python" for p in sorted(ANALYZERS.glob("*_defects.py"))}
ANALYZER_LANGS["pattern_propagation"] = "python"

EXTRA_ARGS = {"testgap_defects": None}  # 需要第三个参数，运行时填


def probe_tools() -> dict:
    """外部工具可用性探测 —— 缺失不算失败，只标 unavailable。"""
    checks = {
        "semgrep": ["semgrep", "--version"],
        "detect-secrets": ["detect-secrets", "--version"],
        "pip-audit": ["pip-audit", "--version"],
        "git": ["git", "--version"],
        "pytest": ["python3", "-m", "pytest", "--version"],
        "network": None,
    }
    out = {}
    for name, cmd in checks.items():
        if cmd is None:
            out[name] = {"available": None, "note": "需运行时判断"}
            continue
        try:
            p = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            out[name] = {"available": p.returncode == 0,
                         "detail": (p.stdout or p.stderr).strip()[:80]}
        except (OSError, subprocess.TimeoutExpired) as e:
            out[name] = {"available": False, "detail": str(e)[:80]}
    return out


def run_analyzer(script: Path, target: Path, extra: list[str] | None = None) -> dict:
    with tempfile.TemporaryDirectory() as td:
        cmd = [sys.executable, str(script), str(target), str(td)]
        if extra:
            cmd += extra
        try:
            p = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        except subprocess.TimeoutExpired:
            return {"status": "timeout", "findings": [], "counts": {}}
        if p.returncode != 0:
            return {"status": "error", "stderr": p.stderr[-300:],
                    "findings": [], "counts": {}}
        findings = []
        for j in Path(td).rglob("*.json"):
            try:
                d = json.loads(j.read_text())
            except Exception:
                continue
            findings += d.get("findings", [])
        counts = {}
        for f in findings:
            counts[f.get("rule", "?")] = counts.get(f.get("rule", "?"), 0) + 1
        # 保存明细
        outdir = Path(td)
        return {"status": "ok", "findings": findings, "counts": counts}


def main() -> int:
    argv = sys.argv[1:]
    extra_roots = []
    while "--extra-root" in argv:
        i = argv.index("--extra-root")
        extra_roots.append(Path(argv[i + 1]).resolve())
        argv = argv[:i] + argv[i + 2:]
    root = Path(argv[0] if argv else ".").resolve()
    outdir = Path(argv[1] if len(argv) > 1 else ".")
    outdir.mkdir(parents=True, exist_ok=True)

    prof_path = None
    if "--profile" in sys.argv:
        prof_path = Path(sys.argv[sys.argv.index("--profile") + 1])
    profile = None
    if prof_path and prof_path.exists():
        try:
            profile = json.loads(prof_path.read_text())
        except Exception as e:
            print(f"[warn] 画像解析失败（{e}）→ 按全语言处理")
            profile = None

    has_python = True if profile is None else profile.get("has_python", True)
    langs = {} if profile is None else profile.get("languages", {}).get("files", {})

    sys.path.insert(0, str(HERE))
    tools = probe_tools()

    results = {}
    all_findings = []

    # 1) Python AST 分析器
    for script in sorted(ANALYZERS.glob("*.py")):
        if script.name.startswith("_"):
            continue
        name = script.stem
        if not has_python:
            results[name] = {"status": "not_applicable",
                             "reason": "项目无 Python 代码", "counts": {}}
            continue
        extra = None
        if name == "testgap_defects":
            extra = [str(root / "tests") if (root / "tests").exists() else str(root)]
        r = run_analyzer(script, root, extra)
        all_r = [r]
        # 附加扫描根：项目自建的门禁/CI 脚本目录（如 scripts/check_*.py）。
        # 这些文件也是产品代码，且常藏着"门禁自身有缺陷"（AF BUG-05/21 即在此），
        # 只扫主包会漏掉整类。
        for er in extra_roots:
            if er.is_dir():
                all_r.append(run_analyzer(script, er, extra))
        merged_counts = {}
        merged_findings = []
        for rr in all_r:
            for k, v in rr.get("counts", {}).items():
                merged_counts[k] = merged_counts.get(k, 0) + v
            merged_findings += rr.get("findings", [])
        r = {"status": "ok" if any(x.get("status") == "ok" for x in all_r) else "error",
             "counts": merged_counts, "findings": merged_findings}
        results[name] = {"status": r["status"], "counts": r.get("counts", {})}
        if r.get("stderr"):
            results[name]["stderr"] = r["stderr"]
        all_findings += r.get("findings", [])
        # 明细落盘
        (outdir / f"{name}.json").write_text(
            json.dumps({"findings": r.get("findings", [])}, ensure_ascii=False, indent=2))

    # 2) 跨语言通用层
    gt = LANG / "generic_text.py"
    if gt.exists():
        # 跨语言文件（Dockerfile / compose yaml / 部署 shell / 前端 TS）
        # 几乎总在**主包之外**。只扫主包 → generic_text 恒为 0，
        # 而这个 0 会被误读成"没有跨语言风险"。故扫仓库根。
        gt_root = Path(os.environ.get("AUDITKIT_REPO_ROOT") or root)
        r = run_analyzer(gt, gt_root)
        results["generic_text"] = {"status": r["status"], "counts": r.get("counts", {})}
        all_findings += r.get("findings", [])
        (outdir / "generic_text.json").write_text(
            json.dumps({"findings": r.get("findings", [])}, ensure_ascii=False, indent=2))

    # 3) 汇总与覆盖率声明
    applicable = [k for k, v in results.items() if v["status"] == "ok"]
    zero_hit_clean = [k for k in applicable if not results[k]["counts"]]
    summary = {
        "repo": str(root),
        "languages": langs,
        "tools": tools,
        "analyzers_total": len(results),
        "analyzers_ok": len(applicable),
        "not_applicable": [k for k, v in results.items() if v["status"] == "not_applicable"],
        "failed": [k for k, v in results.items() if v["status"] in ("error", "timeout")],
        "zero_hit": zero_hit_clean,
        "total_findings": len(all_findings),
    }
    (outdir / "summary.json").write_text(
        json.dumps({"summary": summary, "results": results}, ensure_ascii=False, indent=2))
    (outdir / "all-findings.json").write_text(
        json.dumps({"findings": all_findings}, ensure_ascii=False, indent=2))

    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
