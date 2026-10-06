#!/usr/bin/env python3
"""已知缺陷回归检查 —— 改判据后跑这个，命中率不得下降。

用法：python3 auditkit/regression/check_regression.py [--summary PATH]
"""
import json, sys, pathlib

REPO = "/data/workspace/audit/doubao-butler-main"
SUMMARY = "/data/workspace/audit/out/audit_summary.json"
FIX = pathlib.Path(__file__).parent / "fixtures.json"

def load_stage_items(summary, stage):
    """取该阶段的 findings。

    第二十轮：各阶段返回结构不统一 —— 有的在 items，有的在 lan_high，
    lifecycle 一条 item 只到文件级（无行号）。统一在这里做归一化，
    避免"明明命中却因字段名不同而报未命中"。
    """
    d = summary.get(stage)
    if not d:
        return []
    if isinstance(d, list):
        return d
    out = []
    for key in ("items", "lan_high", "lan_urls", "findings", "hard"):
        v = d.get(key)
        if isinstance(v, list):
            out += v
    if not out:
        # 兜底：所有 list 值拼起来
        for v in d.values():
            if isinstance(v, list):
                out += [x for x in v if isinstance(x, dict)]
    return out

def _blob(it):
    """把 item 的所有值拼成一个可检索的 blob。

    第二十轮：原实现只认 item['file'] + item['line']，导致 multisource
    （结构是 {"a": "butler/schema.py:31 _EVENTS", "b": "..."}）100% 失配
    —— 明明命中却报未命中，回归结果反向误导。改为全字段 blob 匹配。"""
    parts = []
    def walk(o):
        if isinstance(o, dict):
            for v in o.values():
                walk(v)
        elif isinstance(o, list):
            for v in o:
                walk(v)
        elif o is not None:
            parts.append(str(o))
    walk(it)
    return " \n ".join(parts)


def item_matches(it, case, tol=3):
    blob = _blob(it)
    tail = case["file"].split("/")[-1]
    full = case["file"]
    # 1) 文件名必须出现（尾名或全路径）
    if tail not in blob and full not in blob:
        return False
    if case["line"] == 0:
        return True
    # 2) 行号：优先结构化字段；否则在 blob 里找 "文件名:行号" 模式
    for key in ("line", "lineno", "line_no", "start_line"):
        if key in it and isinstance(it[key], int):
            return abs(it[key] - case["line"]) <= tol
    import re as _re
    for m in _re.finditer(r"""\b(\d{1,5})\b""", blob):
        pass
    # 找 "xxx.py:31" 形式
    pat = _re.escape(tail) + r""":(\d+)"""
    for m in _re.finditer(pat, blob):
        if abs(int(m.group(1)) - case["line"]) <= tol:
            return True
    pat2 = _re.escape(full) + r""":(\d+)"""
    for m in _re.finditer(pat2, blob):
        if abs(int(m.group(1)) - case["line"]) <= tol:
            return True
    # 3) 退化：整个 blob 里出现过该行号（宽松）
    return False

def main():
    summary = json.load(open(SUMMARY))
    cases = json.load(open(FIX))["cases"]
    by_stage = {}
    for c in cases:
        by_stage.setdefault(c["stage"], []).append(c)
    total = hit = 0
    miss_report = []
    print(f"{'阶段':<16}{'命中/总数':<12}状态")
    print("-"*48)
    for stage, cs in sorted(by_stage.items()):
        items = load_stage_items(summary, stage)
        # dupfiles 的 items 结构特殊
        if stage == "dupfiles" and not items:
            items = summary.get("dupfiles", {}).get("items", [])
        h = 0
        for c in cs:
            total += 1
            ok = any(item_matches(it, c) for it in items)
            if ok:
                h += 1; hit += 1
            else:
                miss_report.append(c)
        flag = "✅" if h == len(cs) else ("⚠️" if h else "❌")
        print(f"{stage:<16}{h}/{len(cs):<12}{flag}")
    print("-"*48)
    print(f"总计 {hit}/{total}  ({hit/total*100:.0f}%)")
    if miss_report:
        print("\n未命中：")
        for c in miss_report:
            print(f"  [{c['sev']}] {c['id']} {c['file']}:{c['line']}  {c['desc']}")
    return 0 if hit == total else 1

if __name__ == "__main__":
    sys.exit(main())
