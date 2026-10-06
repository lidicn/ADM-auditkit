#!/usr/bin/env python3
"""把图谱可达性路径（paths.json）转成可聚合 findings。

判级：sink 类别 × 入口是否不可信 × 跳数。跳数越少越值得人工核验（攻击面越短）。
"""
import json
import sys
from pathlib import Path

SINK_SEV = {"exec": "high", "ha_action": "high", "secret": "high", "deserialize": "medium",
            "file_write": "medium", "network_out": "medium", "mqtt": "medium", "db": "low",
            "file_read": "low"}


def main() -> int:
    gdir = Path(sys.argv[1] if len(sys.argv) > 1 else "/data/workspace/audit/rounds/round-001/graph")
    p = gdir / "paths.json"
    if not p.exists():
        (gdir / "risk-paths.json").write_text('{"findings": []}')
        print(0)
        return 0
    paths = json.loads(p.read_text())
    findings = []
    for it in paths:
        sink = str(it.get("sink", "")).replace("SINK::", "")
        hops = int(it.get("hops", 99))
        if hops > 6:            # 过长路径对人工核验价值低
            continue
        sev = SINK_SEV.get(sink, "low")
        if hops <= 2 and sev == "medium":
            sev = "high"
        chain = " → ".join(it.get("path", []))
        findings.append({
            "rule": f"AF-GRAPH-{sink}",
            "severity": sev,
            "file": it.get("entry", "?"),
            "line": 0,
            "message": f"不可信入口可达 sink[{sink}]，{hops} 跳：{chain}",
            "tool": "graph",
        })
    (gdir / "risk-paths.json").write_text(json.dumps({"findings": findings}, ensure_ascii=False, indent=2))
    print(len(findings))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
