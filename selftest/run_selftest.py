#!/usr/bin/env python3
"""分析器自检套件 runner —— 防止"规则静默失效"（PITFALLS N1 类事故）。

第十六轮的教训：分析器首版在真实代码上报 0，差点写出"此处无缺陷"的假结论；
实际是遍历节点类型与取值函数不匹配导致规则全部跳过。第十五轮同样靠合成
样例自检才证明 0 是真实结果而非漏检。

本套件把"每轮临时手写自检"固化成**可重复执行**的门禁：

  1. 每个分析器跑 `cases/dirty.py`（塞满已知缺陷）
     → 必须**至少命中 1 条**；0 命中 = 红警（规则可能已失效）
  2. 每个分析器跑 `cases/clean.py`（全是正确写法）
     → 与 golden 快照比对；命中数显著增加 = 红警（规则变宽，假阳性回归）
  3. 命中快照写入 `selftest/golden.json`；本次结果与快照不同的条目全部列出

用法:
  run_selftest.py                 # 跑全部，比对 golden
  run_selftest.py --update        # 重新生成 golden 快照
  run_selftest.py --analyzer X    # 只跑指定分析器
"""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent
LIB = Path(__import__("os").environ.get("AUDITKIT_ANALYZERS")
           or (ROOT.parent / "legacy" / "analyzers"))
if not LIB.exists():                       # 兼容 AF 原布局
    LIB = ROOT.parent / "workflow" / "lib"
CASES = ROOT / "cases"
GOLDEN = ROOT / "golden.json"
PY = sys.executable

# 分析器 → (脚本名, 额外参数)
ANALYZERS = [
    ("ast_defects", []),
    ("state_defects", []),
    ("concurrency_defects", []),
    ("boundary_defects", []),
    ("controlflow_defects", []),
    ("deadcode_defects", []),
    ("time_numeric_defects", []),
    ("input_defects", []),
    ("consistency_defects", []),
    ("serialization_defects", []),
    ("errorhandling_defects", []),
    ("observability_defects", []),
    ("config_compat_defects", []),
    ("api_contract_defects", []),
    ("semantic_defects", []),
    ("resource_defects", []),
    ("pattern_propagation", []),
    ("auth_defects", []),
    ("rmw_consistency", []),
    # testgap 需要第三个参数（tests 目录）
    ("testgap_defects", [str(CASES)]),
    ("generic_text", []),
]

#: 不在 legacy/analyzers 下的分析器 → 显式路径
EXTRA_SCRIPTS = {
    "generic_text": ROOT.parent / "core" / "lang" / "generic_text.py",
}


def run(analyzer: str, case: Path, extra: list[str]):
    """跑单个分析器，返回 (命中规则计数 dict, ok, stderr, warn_count)。

    warn_count = stderr 里 [warn] 出现次数（解析失败被显式记录，非静默）。
    proposal-2 建议 7：三态诊断要能区分"分析器坏了"vs"文件没读进来"vs"真没缺陷"。
    """
    script = EXTRA_SCRIPTS.get(analyzer) or (LIB / f"{analyzer}.py")
    if not script.exists():
        return {}, False, f"分析器不存在: {script}", 0
    with tempfile.TemporaryDirectory() as td:
        cmd = [PY, str(script), str(case), str(td)] + extra
        try:
            p = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
        except subprocess.TimeoutExpired:
            return {}, False, "超时", 0
        if p.returncode != 0:
            return {}, False, f"exit={p.returncode}: {p.stderr[-300:]}", 0
        # 收集产物里的 findings
        counts: Counter = Counter()
        for j in Path(td).rglob("*.json"):
            try:
                d = json.loads(j.read_text())
            except Exception:
                continue
            for f in d.get("findings", []):
                counts[f.get("rule", "?")] += 1
        stderr = p.stderr[-300:] if p.stderr else ""
        warn_count = stderr.count("[warn]")
        return dict(counts), True, stderr, warn_count


def main() -> int:
    args = [a for a in sys.argv[1:]]
    update = "--update" in args
    only = None
    if "--analyzer" in args:
        i = args.index("--analyzer")
        only = args[i + 1] if i + 1 < len(args) else None

    result = {}
    failures = []
    for name, extra in ANALYZERS:
        if only and name != only:
            continue
        script = EXTRA_SCRIPTS.get(name) or (LIB / f"{name}.py")
        if not script.exists():
            failures.append(f"[skip] {name}: 脚本缺失")
            continue

        # dirty：必须至少命中 1 条
        dcnt, dok, derr, dwarn = run(name, CASES / "dirty", extra)
        # clean：与 golden 比对
        ccnt, cok, cerr, cwarn = run(name, CASES / "clean", extra)

        # 三态诊断（proposal-2 建议 7）：
        #   tools_missing   分析器自身崩了（非 0 退出/超时/脚本缺）
        #   ok_but_no_hit   跑了但 0 命中（规则可能失效，或文件没读进来——看 warn_count）
        #   ok              正常命中
        if not dok:
            failures.append(f"[FAIL] {name} 在 dirty 样本上运行失败: {derr}")
            result[name] = {"dirty": dcnt, "clean": {}, "status": "tools_missing",
                            "clean_raw": {}, "clean_allowed": []}
            continue
        if not cok:
            failures.append(f"[FAIL] {name} 在 clean 样本上运行失败: {cerr}")
            result[name] = {"dirty": dcnt, "clean": {}, "status": "tools_missing",
                            "clean_raw": {}, "clean_allowed": []}
            continue
        # clean 白名单：某些规则在 clean 样本上命中属**已知良性**，
        # 已逐条人工核验并记入 expect.json（附理由），不再算作失败。
        allow = set()
        ef = ROOT / "expect.json"
        if ef.exists():
            try:
                allow_data = json.loads(ef.read_text()).get("allow_on_clean", [])
                # expect.json 的 allow_on_clean 可能是 dict（规则→理由）或 list
                allow = set(allow_data.keys() if isinstance(allow_data, dict) else allow_data)
            except Exception:
                allow = set()
        ccnt_eff = {k: v for k, v in ccnt.items() if k not in allow}

        n_dirty = sum(dcnt.values())
        # 三态判定
        if n_dirty > 0:
            status = "ok"
        elif dwarn > 0:
            status = "ok_but_no_hit"   # 跑了但有文件没读进来（[warn]），疑似静默失效
        else:
            status = "ok_but_no_hit"   # 0 命中且无 warn，规则可能失效（PITFALLS N1）

        result[name] = {"dirty": dcnt, "clean": ccnt_eff,
                        "clean_raw": ccnt,
                        "clean_allowed": sorted(set(ccnt) - set(ccnt_eff)),
                        "status": status,
                        "warn_count": dwarn + cwarn}

        if n_dirty == 0:
            hint = f"，{dwarn} 个 [warn]（文件可能没读进来）" if dwarn else "，无 [warn]（规则可能失效）"
            failures.append(
                f"[FAIL] {name} 在 dirty（已知缺陷样本）上 **0 命中**{hint} —— "
                f"PITFALLS N1（status={status}）")
        if dwarn > 0:
            failures.append(f"[FAIL] {name} 运行时 {dwarn} 个 [warn]: {derr[:200]}")

    # 与 golden 比对
    drift = []
    if GOLDEN.exists() and not update:
        try:
            golden = json.loads(GOLDEN.read_text())
        except Exception:
            golden = {}
        for name, cur in result.items():
            old = golden.get(name, {})
            for phase in ("dirty", "clean"):
                o, c = old.get(phase, {}), cur.get(phase, {})
                # 新增/消失的规则
                new = set(c) - set(o)
                gone = set(o) - set(c)
                for r in sorted(new):
                    drift.append(f"[+{phase}] {name}: 新命中 {r} ×{c[r]}")
                for r in sorted(gone):
                    if o[r] > 0:
                        drift.append(
                            f"[-{phase}] {name}: **{r} 消失**（原 ×{o[r]}）—— 规则可能失效")

    if update:
        GOLDEN.write_text(json.dumps(result, ensure_ascii=False, indent=2))
        print(json.dumps({"updated": True, "analyzers": len(result)},
                         ensure_ascii=False, indent=2))
        return 0

    ok = not failures
    statuses = {k: v.get("status", "?") for k, v in result.items()}
    print(json.dumps({
        "ok": ok,
        "analyzers": len(result),
        "statuses": statuses,
        "dirty_hits": {k: sum(v["dirty"].values()) for k, v in result.items()},
        "clean_hits": {k: sum(v["clean"].values()) for k, v in result.items()},
        "failures": failures,
        "drift": drift,
    }, ensure_ascii=False, indent=2))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
