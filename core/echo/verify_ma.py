#!/usr/bin/env python3
"""Echo 有效性验证器 —— 用 memory-agent 第五期 42 条真缺陷做 ground truth。

这是 Echo 相对"空想工具"的最大优势：它有已知阳性样本。
判据：静默/断链类缺陷应被 Echo 命中；非沉默类（崩溃面/语义分裂）属设计边界。
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

# 第五期确证缺陷（file, func, id, 类别）
#   silent = 沉默/断链类（Echo 应命中）
#   crash  = 崩溃面（外抛，Echo 设计边界）
#   sem    = 语义/口径分裂（Echo 设计边界）
KNOWN = [
    ("ha_client.py", "get_history", "MA52", "silent"),
    ("store.py", "insert_events", "MA54", "silent"),
    ("insights_legacy.py", "water_purifier_usage", "MA55", "silent"),
    ("store.py", "merge_member_appearance", "MA58", "silent"),
    ("mcp_server.py", "save_skill", "MA59", "silent"),
    ("nr_routes.py", "analyze_water_purifier", "MA63", "silent"),
    ("insights/service.py", "_device_usage_one", "MA66", "silent"),
    ("ha_db.py", "get_history", "MA72", "silent"),
    ("poller.py", "_fetch_history", "MA74", "silent"),
    ("store.py", "_rebuild_agent_memory_fts", "MA75", "silent"),
    ("runtime.py", "_build_ha_db", "MA76", "silent"),
    ("mqtt_bridge.py", "advertise", "MA77", "silent"),
    ("insights/repository.py", "activity_rules", "MA78", "crash"),
    ("activity_inference.py", "current_behaviors", "MA79", "silent"),
    ("ha_db.py", "detect_schema", "MA83", "silent"),
    ("llm_client.py", "stream_chat", "MA85", "silent"),
    ("vision_service.py", "vlm_analyze", "MA86", "silent"),
    ("runtime.py", "_periodic_activity_inference", "MA87", "silent"),
    ("runtime.py", "_periodic_mqtt_presence", "MA88", "silent"),
    ("agent_memory.py", "conflict_scan", "MA89", "silent"),
]


def find_hits(chains, f, fn):
    out = []
    for c in chains:
        e = c["exit"]
        if e["file"].endswith(f) and (fn in e["func"] or e["func"].endswith(fn)):
            out.append(c)
            continue
        for s in c["path"]:
            if s["file"].endswith(f) and (fn in s["func"] or s["func"].endswith(fn)):
                out.append(c)
                break
    return out


def main() -> int:
    src = Path(sys.argv[1] if len(sys.argv) > 1 else "/data/workspace/echo_ma_src.json")
    res = json.loads(src.read_text(encoding="utf-8"))
    chains = res["chains"]

    print(f"Echo 产出：{res['stats']['silent_exits']} 沉默出口 → "
          f"{res['stats']['broken_chains']} 断链\n")
    print(f"{'ID':6s} {'目标':40s} {'命中':5s} {'类别':7s} 形态")
    print("-" * 82)

    stat = {"silent": [0, 0], "crash": [0, 0], "sem": [0, 0]}
    missed_silent = []
    for f, fn, i, cat in KNOWN:
        h = find_hits(chains, f, fn)
        stat[cat][1] += 1
        if h:
            stat[cat][0] += 1
        elif cat == "silent":
            missed_silent.append((i, f, fn))
        kind = h[0]["exit"]["kind"] if h else "-"
        print(f"{i:6s} {f}:{fn:33s} {'YES' if h else ' . ':5s} {cat:7s} {kind}")

    print("-" * 82)
    for cat, label in (("silent", "沉默/断链类（应命中）"),
                       ("crash", "崩溃面（设计边界）"),
                       ("sem", "语义分裂（设计边界）")):
        hit, tot = stat[cat]
        if tot:
            print(f"{label:22s} {hit}/{tot}")

    if missed_silent:
        print(f"\n[未命中的沉默类] {', '.join(m[0] for m in missed_silent)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
