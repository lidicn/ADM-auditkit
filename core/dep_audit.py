#!/usr/bin/env python3
"""依赖与供应链审计（离线优先）。

产出：
  deps/requirements.synth.txt  —— 由 pyproject 全 extras 合成的依赖清单
  deps/pip-audit.json          —— pip-audit 结果（有网时）
  deps/supply-chain.json       —— 私有 wheel / CI 供应链风险清单（自研规则）
"""
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

try:
    import tomllib  # py3.11+
except ModuleNotFoundError:  # pragma: no cover
    try:
        import tomli as tomllib  # type: ignore
    except ModuleNotFoundError:
        tomllib = None


CI_RISK_PATTERNS = [
    (r"uses:\s*[^@\s]+@(?![0-9a-f]{40}\b)(v?\d[\w.\-]*)", "medium", "CI action 未按 SHA 钉死（可被 tag 移动投毒）"),
    (r"on:\s*pull_request_target", "high", "workflow 使用 pull_request_target（fork PR 可获写权限/密钥）"),
    (r"curl[^|\n]*\|\s*(sudo\s+)?(ba)?sh", "critical", "CI 或脚本中出现 curl|sh 远程执行"),
    (r"pip\s+install\s+[^\s]+(?<!\.whl)\s*$", "low", "pip install 未锁版本/未校验哈希"),
    (r"--index-url|--extra-index-url", "medium", "使用第三方/私有 index（依赖混淆风险）"),
    (r"secrets\.\w+\s+in\s+run:", "low", "密钥进入 run 脚本，可能被 echo 到日志"),
]


def pyproject_deps(root: Path) -> dict:
    out = {"core": [], "extras": {}, "private_wheels": []}
    pp = root / "pyproject.toml"
    if not pp.exists() or tomllib is None:
        # 正则兜底
        txt = pp.read_text() if pp.exists() else ""
        out["core"] = re.findall(r"^\s*\"([a-zA-Z0-9_.\-]+[<>=!~\[].*?)\"", txt, re.M)
        return out
    data = tomllib.loads(pp.read_text())
    proj = data.get("project", {})
    out["core"] = list(proj.get("dependencies", []))
    for name, deps in (proj.get("optional-dependencies") or {}).items():
        out["extras"][name] = list(deps)
    return out


def private_wheels(root: Path) -> list:
    res = []
    for whl in root.rglob("*.whl"):
        h = hashlib.sha256(whl.read_bytes()).hexdigest()
        res.append({
            "path": str(whl.relative_to(root)),
            "sha256": h,
            "size": whl.stat().st_size,
            "risk": "私有 wheel 不在公共索引，无法用 pip-audit/OSV 匹配 CVE；需人工核对来源与构建产物完整性",
        })
    return res


def ci_findings(root: Path) -> list:
    findings = []
    for wf in (root / ".github" / "workflows").rglob("*.y*ml") if (root / ".github").exists() else []:
        txt = wf.read_text(errors="ignore")
        for pat, sev, msg in CI_RISK_PATTERNS:
            for m in re.finditer(pat, txt, re.M):
                line = txt[: m.start()].count("\n") + 1
                findings.append({
                    "file": str(wf.relative_to(root)), "line": line, "severity": sev,
                    "rule": "af-supply-chain-ci", "message": msg,
                    "snippet": m.group(0)[:120],
                })
    return findings


def main() -> int:
    root = Path(sys.argv[1] if len(sys.argv) > 1 else "/data/workspace/audit/src")
    outdir = Path(sys.argv[2] if len(sys.argv) > 2 else "/data/workspace/audit/rounds/round-001/deps")
    outdir.mkdir(parents=True, exist_ok=True)

    deps = pyproject_deps(root)
    lines = []
    lines += deps["core"]
    for v in deps["extras"].values():
        lines += v
    req = outdir / "requirements.synth.txt"
    req.write_text("\n".join(sorted(set(lines))) + "\n")

    pa = {"status": "skipped", "reason": ""}
    try:
        r = subprocess.run(
            ["pip-audit", "-r", str(req), "-f", "json", "-o", str(outdir / "pip-audit.json")],
            capture_output=True, text=True, timeout=600,
        )
        pa["status"] = "ok" if r.returncode in (0, 1) else "error"
        pa["returncode"] = r.returncode
        pa["stderr"] = r.stderr[-800:]
        if (outdir / "pip-audit.json").exists():
            pa["summary"] = json.loads((outdir / "pip-audit.json").read_text())
    except Exception as e:  # noqa: BLE001
        pa = {"status": "error", "reason": str(e)}

    report = {
        "pyproject": deps,
        "private_wheels": private_wheels(root),
        "ci_supply_chain": ci_findings(root),
        "pip_audit": pa if pa.get("status") != "ok" else {"status": "ok", "returncode": pa["returncode"]},
    }
    (outdir / "supply-chain.json").write_text(json.dumps(report, ensure_ascii=False, indent=2))
    print(json.dumps({
        "requirements": len(set(lines)),
        "private_wheels": len(report["private_wheels"]),
        "ci_findings": len(report["ci_supply_chain"]),
        "pip_audit": report["pip_audit"]["status"],
    }, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
