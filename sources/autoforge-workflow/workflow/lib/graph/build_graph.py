#!/usr/bin/env python3
"""图谱化审计：把 AutoForge 源码变成「入口 → 信任边界 → sink」可达性图。

图层：
  1) 模块依赖图（import 边）
  2) 能力图（模块 → sink：进程/文件/网络/HA/MQTT/DB）
  3) 数据流可达性（外部入口 → sink 的最短路径，即审计主线）

产出：graph.json / graph.graphml / graph.svg / paths.json
"""
import ast
import json
import re
import sys
from collections import defaultdict
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import networkx as nx  # noqa: E402

SINKS = {
    "exec": r"(subprocess\.(run|Popen|call|check_output)|os\.system|os\.exec|eval|exec\()",
    "file_write": r"(open\(.*['\"][wa]|os\.remove|os\.rename|shutil\.(rmtree|move|copy)|\.write_text|\.write_bytes|Path\(.*\)\.write)",
    "file_read": r"(open\(.*['\"]r|\.read_text|json\.load|yaml\.safe_load)",
    "network_out": r"(requests\.(get|post|put|delete)|httpx\.(get|post)|urllib\.request|socket\.|websocket)",
    "ha_action": r"(call_service|async_call|hass\.services|service_call|state_set)",
    "mqtt": r"(mqtt|publish\(|subscribe\()",
    "db": r"(\.execute\(|\.commit\(|sqlite3|INSERT INTO|UPDATE )",
    "secret": r"(os\.environ|getenv|keyring|token|secret|password)",
    "deserialize": r"(pickle\.load|yaml\.load\(|marshal\.load)",
}
ENTRY_HINT = re.compile(r"(nl|mcp|api|cli|adapter|bridge|executor|service|gate|apply|parser|spec)", re.I)
UNTRUSTED_HINT = re.compile(r"(nl|mcp|api|bridge|adapter|webhook|stdin|argv|env|request|payload|tool_result|model|llm)", re.I)


def module_name(root: Path, f: Path) -> str:
    rel = f.relative_to(root).with_suffix("")
    return str(rel).replace("/", ".").replace(".__init__", "")


def scan(root: Path) -> dict:
    files = sorted(root.rglob("*.py"))
    mods = {}
    for f in files:
        if any(p in {"tests", "test", ".venv"} for p in f.parts):
            pass
        try:
            tree = ast.parse(f.read_text(errors="ignore"))
        except SyntaxError:
            continue
        mods[module_name(root, f)] = (f, tree)
    return mods


def build(root: Path):
    G = nx.DiGraph()
    mods = scan(root)
    local_prefixes = set()
    for m in mods:
        parts = m.split(".")
        local_prefixes.add(parts[0])

    sink_nodes = {}
    for s in SINKS:
        sink_nodes[s] = f"SINK::{s}"
        G.add_node(sink_nodes[s], kind="sink", sink=s)

    env_node = "ENTRY::env"
    G.add_node(env_node, kind="entry", untrusted=True)

    for m, (f, tree) in mods.items():
        rel = str(f.relative_to(root))
        is_entry = bool(ENTRY_HINT.search(rel))
        G.add_node(m, kind="module", path=rel,
                   entry=is_entry, untrusted=bool(UNTRUSTED_HINT.search(rel)))
        src = f.read_text(errors="ignore")

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for a in node.names:
                    if a.name.split(".")[0] in local_prefixes:
                        G.add_edge(m, a.name, kind="import")
            elif isinstance(node, ast.ImportFrom):
                if node.module and node.module.split(".")[0] in local_prefixes:
                    G.add_edge(m, node.module, kind="import")

        for s, pat in SINKS.items():
            hits = len(re.findall(pat, src))
            if hits:
                G.add_edge(m, sink_nodes[s], kind="capability", weight=hits)
        if re.search(r"os\.environ|getenv", src):
            G.add_edge(env_node, m, kind="dataflow")

    return G, mods


def paths_to_sinks(G: nx.DiGraph) -> list:
    entries = [n for n, d in G.nodes(data=True) if d.get("entry") or d.get("untrusted")]
    sinks = [n for n, d in G.nodes(data=True) if d.get("kind") == "sink"]
    out = []
    for e in entries:
        for s in sinks:
            try:
                p = nx.shortest_path(G, e, s)
            except (nx.NetworkXNoPath, nx.NodeNotFound):
                continue
            if len(p) > 1:
                out.append({"entry": e, "sink": s, "hops": len(p) - 1, "path": p})
    out.sort(key=lambda x: (x["hops"], x["entry"]))
    return out


def render(G: nx.DiGraph, out_png: Path):
    keep = [n for n, d in G.nodes(data=True)
            if d.get("kind") in ("sink", "entry") or G.out_degree(n) > 0 or G.in_degree(n) > 0]
    H = G.subgraph(keep)
    pos = nx.spring_layout(H, seed=7, k=0.9)
    colors = {"module": "#9ecae1", "sink": "#e6550d", "entry": "#31a354"}
    node_colors = [colors.get(H.nodes[n].get("kind"), "#999") for n in H]
    sizes = [220 if H.nodes[n].get("kind") != "module" else 60 for n in H]
    plt.figure(figsize=(16, 12))
    nx.draw_networkx_nodes(H, pos, node_color=node_colors, node_size=sizes, alpha=0.85)
    nx.draw_networkx_edges(H, pos, alpha=0.25, arrows=True, arrowsize=8)
    labels = {n: (n.split(".")[-1] if H.nodes[n].get("kind") == "module" else n.split("::")[-1]) for n in H}
    nx.draw_networkx_labels(H, pos, labels=labels, font_size=6)
    plt.title("AutoForge trust-boundary graph (entry -> module -> sink)", fontsize=12)
    plt.axis("off")
    plt.tight_layout()
    plt.savefig(out_png, dpi=130)


def main() -> int:
    root = Path(sys.argv[1] if len(sys.argv) > 1 else "/data/workspace/audit/src")
    outdir = Path(sys.argv[2] if len(sys.argv) > 2 else "/data/workspace/audit/rounds/round-001/graph")
    outdir.mkdir(parents=True, exist_ok=True)

    src_root = root if (root / "src").exists() is False else root
    G, mods = build(src_root)
    paths = paths_to_sinks(G)

    (outdir / "paths.json").write_text(json.dumps(paths[:200], ensure_ascii=False, indent=2))
    data = {"nodes": [{"id": n, **d} for n, d in G.nodes(data=True)],
            "edges": [{"source": u, "target": v, **d} for u, v, d in G.edges(data=True)]}
    (outdir / "graph.json").write_text(json.dumps(data, ensure_ascii=False, indent=2))
    nx.write_graphml(G, str(outdir / "graph.graphml"))
    try:
        render(G, outdir / "graph.png")
    except Exception as e:  # noqa: BLE001
        print(f"[graph] 渲染失败：{e}", file=sys.stderr)

    print(json.dumps({
        "modules": len(mods), "nodes": G.number_of_nodes(), "edges": G.number_of_edges(),
        "entry_to_sink_paths": len(paths),
        "shortest_3": [f"{p['entry']} -> {p['sink']} ({p['hops']}hops)" for p in paths[:3]],
    }, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
