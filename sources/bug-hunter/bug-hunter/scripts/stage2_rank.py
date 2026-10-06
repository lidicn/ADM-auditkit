#!/usr/bin/env python3
"""Stage 2 —— 优先级排序：把候选池收敛成「下一轮该读什么」。

排序依据（来自第五轮 V19 的交叉验证结论）：
  复杂度 × 枢纽度 × 历史缺陷密度 —— 三者相乘。

  复杂度：CC 越高越可能藏缺陷（on_wakeup CC63 里挖出 3 个，dispatch_tool CC93 未读）
  枢纽度：被依赖越多，改动 blast radius 越大（logging_setup 153 / runtime 47）
  历史密度：同文件已有实锤缺陷的，再加成（缺陷有聚集性）

产出一张「审计优先级地图」——这是本工作流最有复用价值的资产，
因为它把「下一轮从哪读」从拍脑袋变成可计算。
"""
from __future__ import annotations

import ast
import collections
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from stage1_scan import _py_files  # noqa: E402


def hub_scores(repo, root="butler"):
    """模块被依赖次数（枢纽度）。

    key 统一为「相对 repo 的文件路径」如 `butler/core/dialog.py`，
    与 rank() 里 findings/CC 的文件口径一致 —— 上一版这里用点号分隔的
    模块名，导致 key 永远匹配不上，枢纽度全 0（静默失效，很难察觉）。
    """
    repo = os.path.abspath(repo)
    dep = collections.Counter()
    for p in _py_files(repo, root):
        rel = os.path.relpath(p, repo)
        try:
            t = ast.parse(open(p, encoding="utf-8").read())
        except Exception:
            continue
        seen = set()
        for n in ast.walk(t):
            mods = []
            if isinstance(n, ast.ImportFrom) and n.module:
                mods = [n.module]
            elif isinstance(n, ast.Import):
                mods = [a.name for a in n.names]
            for m in mods:
                if not m.startswith("butler"):
                    continue
                # 但ler.xxx.yyy → 候选：butler/xxx/yyy.py 或 butler/xxx.py(子符号)
                parts = m.split(".")
                cands = []
                if len(parts) >= 2:
                    cands.append(os.path.join(*parts) + ".py")
                if len(parts) >= 3:
                    cands.append(os.path.join(*parts[:-1]) + ".py")
                hit = None
                for c in cands:
                    if os.path.exists(os.path.join(repo, c)) and c != rel:
                        hit = c
                        break
                if hit and hit not in seen:
                    seen.add(hit)
                    dep[hit] += 1
    return dep


def file_cc(cc_rows):
    """每个文件的 CC 总和 + 最高值。"""
    tot, mx = collections.Counter(), collections.Counter()
    for r in cc_rows:
        tot[r["file"]] += r["cc"]
        mx[r["file"]] = max(mx[r["file"]], r["cc"])
    return tot, mx


# 六轮审计中我逐行读过 / 做过行为实验的文件（覆盖率 10.1%）
# 未读文件在排序中加成 —— 知识盲区风险高于已知区域的残留风险
READ_FILES = {
    "butler/core/dialog.py", "butler/tts/queue.py", "butler/tts/adapter.py",
    "butler/tts/manager.py", "butler/tts/singleton.py", "butler/tts/helper.py",
    "butler/triggers/engine.py", "butler/api/config_routes.py", "butler/store/db.py",
    "butler/af_bridge.py", "butler/core/dedup.py", "butler/integrations/llm.py",
    "butler/core/wakeup.py", "butler/devices.py", "butler/triggers/registry.py",
    "butler/core/state.py", "butler/integrations/ha.py",
    "butler/integrations/docker_tools.py", "butler/app.py",
}


def rank(repo, findings, cc_rows, known_defect_files=None, read_files=None):
    """返回排序后的文件级优先级列表。

    read_files：已读文件集合。未读的高复杂度文件加成 —— 理由见下方注释。
    """
    known = known_defect_files or {}
    read = READ_FILES if read_files is None else read_files
    dep = hub_scores(repo)
    tot, mx = file_cc(cc_rows)

    # 候选命中数（按文件）
    hit = collections.Counter()
    hit_sev = collections.defaultdict(collections.Counter)
    for f in findings:
        if f.loc:
            fl = f.loc.split(":")[0]
            hit[fl] += 1
            hit_sev[fl][f.severity] += 1

    files = set(tot) | set(hit) | set(x.split(":")[0] for x in
                                      (v for v in [dep] for v in v))
    rows = []
    for f in files:
        c_tot, c_max = tot.get(f, 0), mx.get(f, 0)
        d = dep.get(f, 0)
        h = hit.get(f, 0)
        k = known.get(f, 0)
        # 评分：复杂度(对数压缩) × 枢纽(对数) + 候选命中 + 历史加成×2
        import math
        # 未读加成：同样复杂度下，没读过的文件更可能藏着没发现的缺陷。
        # 这不是猜测——audit 经验是「读过的文件缺陷已被挖出，未读的仍是黑箱」。
        unread = 0.0 if f in read else 4.0
        score = (math.log1p(c_tot) * 3 + math.log1p(c_max) * 2
                 + math.log1p(d) * 1.5
                 + h * 1.0
                 + k * 2.5
                 + unread)
        rows.append({"file": f, "cc_sum": c_tot, "cc_max": c_max,
                     "hub": d, "cands": h, "known": k, "score": round(score, 2),
                     "read": "是" if f in read else "否",
                     "sev": dict(hit_sev.get(f, {}))})
    rows.sort(key=lambda x: -x["score"])
    return rows


def print_map(rows, top=15):
    print("─" * 72)
    print("Stage 2  优先级地图（下一轮该读什么）")
    print("─" * 72)
    print(f"  {'文件':<40}{'CC和':>6}{'CC峰':>6}{'枢纽':>5}{'候选':>5}{'已知':>5}{'读过':>5}{'分':>7}")
    print("  " + "-" * 79)
    for r in rows[:top]:
        mark = "  " if r["read"] == "是" else "★ "
        print(f"  {mark}{r['file'][:37]:<38}{r['cc_sum']:>6}{r['cc_max']:>6}"
              f"{r['hub']:>5}{r['cands']:>5}{r['known']:>5}{r['read']:>6}{r['score']:>7}")
    print()
    print("  读法：分越高越该优先读。★ = 未读（加成 4 分）。")
    print("        '已知'列是我已实锤的缺陷数，参与加权是因为缺陷有聚集性。")
    print()
