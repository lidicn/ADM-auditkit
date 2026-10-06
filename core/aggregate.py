#!/usr/bin/env python3
"""聚合层：合并各阶段 SARIF/JSON → 统一 findings → 与基线 diff → Markdown 报告。

输入目录：<round>/{sast,secrets,deps,skill,graph}
输出：<round>/findings.json（统一清单）、<round>/report.md、<round>/baseline-diff.json
"""
import json
import sys
from pathlib import Path

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "error": 0, "warning": 2}


def sarif_findings(p: Path) -> list:
    if not p.exists():
        return []
    try:
        data = json.loads(p.read_text())
    except Exception:  # noqa: BLE001
        return []
    out = []
    for run in data.get("runs", []):
        rules = {r["id"]: r for r in run.get("tool", {}).get("driver", {}).get("rules", [])}
        for res in run.get("results", []):
            rid = res.get("ruleId", "?")
            sev = res.get("level") or rules.get(rid, {}).get("defaultConfiguration", {}).get("level") or "warning"
            locs = res.get("locations") or []
            path = line = 0
            if locs:
                pl = locs[0].get("physicalLocation", {})
                path = pl.get("artifactLocation", {}).get("uri", "?")
                line = pl.get("region", {}).get("startLine", 0)
            msg = (res.get("message", {}) or {}).get("text", "")
            out.append({"rule": rid, "severity": sev.lower(), "file": path, "line": line,
                        "message": msg.strip()[:400], "tool": "semgrep"})
    return out


def json_findings(p: Path, keys: dict) -> list:
    if not p.exists():
        return []
    data = json.loads(p.read_text())
    items = data.get("findings") or data.get("results") or []
    out = []
    for it in items:
        out.append({"rule": it.get(keys.get("rule", "rule"), "?"),
                    "severity": str(it.get(keys.get("severity", "severity"), "info")).lower(),
                    "file": it.get(keys.get("file", "file"), "?"),
                    "line": it.get(keys.get("line", "line"), 0),
                    "message": it.get(keys.get("message", "message"), "")[:400],
                    "tool": keys.get("tool", "custom")})
    return out


def key(f: dict) -> str:
    return f"{f['tool']}|{f['rule']}|{f['file']}|{f['line']}"


def main() -> int:
    rdir = Path(sys.argv[1] if len(sys.argv) > 1 else "/data/workspace/audit/rounds/round-001")
    baseline = Path(sys.argv[2] if len(sys.argv) > 2 else "/data/workspace/audit/baseline/findings.json")

    f = []
    f += sarif_findings(rdir / "sast" / "semgrep.sarif")
    f += json_findings(rdir / "skill" / "skill-scan.json", {"tool": "skill-scan"})
    f += json_findings(rdir / "deps" / "supply-chain.json", {"rule": "rule", "tool": "supply-chain"})
    f += json_findings(rdir / "secrets" / "detect-secrets.json", {"rule": "type", "tool": "detect-secrets",
                                                                  "severity": "severity"})
    f += json_findings(rdir / "graph" / "risk-paths.json", {"tool": "graph"})

    f.sort(key=lambda x: SEV_ORDER.get(x["severity"], 9))
    (rdir / "findings.json").write_text(json.dumps(f, ensure_ascii=False, indent=2))

    prev = json.loads(baseline.read_text()) if baseline.exists() else []
    prev_keys = {key(x) for x in prev}
    cur_keys = {key(x) for x in f}
    diff = {
        "new": [x for x in f if key(x) not in prev_keys],
        "fixed": [x for x in prev if key(x) not in cur_keys],
        "persistent": [x for x in f if key(x) in prev_keys],
    }
    (rdir / "baseline-diff.json").write_text(json.dumps(diff, ensure_ascii=False, indent=2))
    baseline.parent.mkdir(parents=True, exist_ok=True)
    baseline.write_text(json.dumps(f, ensure_ascii=False, indent=2))

    counts = {}
    for x in f:
        counts[x["severity"]] = counts.get(x["severity"], 0) + 1
    by_rule = {}
    for x in f:
        by_rule[x["rule"]] = by_rule.get(x["rule"], 0) + 1

    lines = [f"# AutoForge 审计 — {rdir.name}", "",
             f"统一发现总数：**{len(f)}** ｜ 新增 {len(diff['new'])} ｜ 修复 {len(diff['fixed'])} ｜ 遗留 {len(diff['persistent'])}", "",
             "## 按严重度", ""]
    for s in ["critical", "error", "high", "warning", "medium", "low", "info"]:
        if counts.get(s):
            lines.append(f"- {s}: {counts[s]}")
    lines += ["", "## 按规则 Top", ""]
    for r, c in sorted(by_rule.items(), key=lambda kv: -kv[1])[:15]:
        lines.append(f"- `{r}`: {c}")
    lines += ["", "## 新增发现（相对基线）", ""]
    for x in diff["new"][:30]:
        lines.append(f"- **[{x['severity']}]** `{x['rule']}` {x['file']}:{x['line']} — {x['message'][:160]}")
    if not diff["new"]:
        lines.append("- 无")
    (rdir / "report.md").write_text("\n".join(lines) + "\n")

    print(json.dumps({"total": len(f), "new": len(diff["new"]), "fixed": len(diff["fixed"]),
                      "counts": counts}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
