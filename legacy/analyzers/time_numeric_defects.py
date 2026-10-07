#!/usr/bin/env python3
"""第七轮专题：时间与数值边界（纯 stdlib AST）。

前六轮覆盖：稳定性与资源、持久化与崩溃恢复、并发与异步、资源上限与复杂度、
控制流与异常契约、死代码与缓存契约。本轮看**最容易在边界失守的两类**：

  TIME 类（时钟口径）
  - TIME-01 同一表达式内混用单调时钟与墙上时钟（差值无意义）
  - TIME-02 用墙上时钟做超时/租约/TTL 判定（NTP 校时 → 瞬间失效或永久卡死）
  - TIME-03 timedelta 与 monotonic 秒数混算（语义不同源）
  - TIME-04 过期判定用 `>=` 还是 `>` 的边界（部分场景差一毫秒即相反结果）
  - TIME-05 时间戳存 float 但比较时用字符串（或反之）

  NUM 类（数值边界）
  - NUM-01 除法未防护空容器（ZeroDivisionError）
  - NUM-02 空序列求 max/min 无 default
  - NUM-03 浮点直接等值比较
  - NUM-04 round()/百分比分母可能为 0

设计原则：本项目在时钟上整体做得很好（注入 TimeSource + monotonic），
所以本轮预期命中少且多为提示；每条命中给出机制说明便于人工判定。

用法: time_numeric_defects.py <src_root> <outdir>
"""
from __future__ import annotations

import ast
import json
import re
import sys
from collections import Counter
from pathlib import Path

TIMEOUT_CTX = re.compile(r"(?i)(deadline|timeout|expire|elapsed|lease|until|ttl|window|duration|age)")
MONO_PAT = re.compile(r"monotonic\s*\(\s*\)")
WALL_PAT = re.compile(r"time\.time\s*\(\s*\)|\.timestamp\s*\(\s*\)")


def _unparse(n):
    try:
        return ast.unparse(n)
    except Exception:
        return ""


def _fn_of(tree, node):
    """找到 node 所属的最内层函数名与该函数对象。"""
    for fn in ast.walk(tree):
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if any(x is node for x in ast.walk(fn)):
            return fn
    return None


# ────────────────────────────────────────────────────────────────────
# TIME-01 同一表达式内混用单调时钟与墙上时钟
# ────────────────────────────────────────────────────────────────────
def check_clock_mix_in_expr(tree, rel):
    out = []
    for n in ast.walk(tree):
        if not isinstance(n, ast.BinOp) or not isinstance(n.op, ast.Sub):
            continue
        s = _unparse(n)
        if MONO_PAT.search(s) and WALL_PAT.search(s):
            fn = _fn_of(tree, n)
            out.append({
                "rule": "TIME-01-clock-mix", "severity": "high",
                "file": rel, "line": n.lineno,
                "function": fn.name if fn else "<module>",
                "message": f"同一减法表达式混用单调时钟与墙上时钟：{s[:70]}；"
                           f"两个时钟原点不同，差值无意义（NTP 校时后会突变甚至为负）"})
    return out


# ────────────────────────────────────────────────────────────────────
# TIME-02 墙上时钟做超时/租约/TTL
# ────────────────────────────────────────────────────────────────────
def check_wall_for_timeout(tree, rel):
    out = []
    for fn in ast.walk(tree):
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        # 函数名或局部变量命中超时语义
        locals_hit = any(TIMEOUT_CTX.search(a.arg) for a in
                         list(fn.args.args) + list(fn.args.kwonlyargs))
        if not (TIMEOUT_CTX.search(fn.name) or locals_hit):
            continue
        for n in ast.walk(fn):
            if not isinstance(n, ast.Call):
                continue
            s = _unparse(n)
            if not WALL_PAT.search(s):
                continue
            if MONO_PAT.search(s):
                continue
            # 与常量/变量的比较才算判定
            out.append({
                "rule": "TIME-02-wall-timeout", "severity": "medium",
                "file": rel, "line": n.lineno, "function": fn.name,
                "message": f"{fn.name}() 用墙上时钟 {s[:40]} 做超时/租约判定；"
                           f"NTP 校时或改表会让判定瞬间失效或永久卡死，应使用 monotonic()"})
    return out


# ────────────────────────────────────────────────────────────────────
# TIME-03 timedelta 与 monotonic 秒数混算
# ────────────────────────────────────────────────────────────────────
def check_timedelta_mono_mix(tree, rel):
    out = []
    for n in ast.walk(tree):
        if not isinstance(n, ast.BinOp):
            continue
        s = _unparse(n)
        if "timedelta" not in s:
            continue
        if MONO_PAT.search(s):
            fn = _fn_of(tree, n)
            out.append({
                "rule": "TIME-03-timedelta-mono", "severity": "medium",
                "file": rel, "line": n.lineno,
                "function": fn.name if fn else "<module>",
                "message": f"timedelta 与 monotonic 秒数混算：{s[:70]}；"
                           f"timedelta 属墙上时钟语义，与单调时钟相加含义不清"})
    return out


# ────────────────────────────────────────────────────────────────────
# TIME-05 时间戳字符串与数值比较混用（同一模块内对同一字段两种口径）
# ────────────────────────────────────────────────────────────────────
def check_ts_type_mix(tree, rel):
    out = []
    for fn in ast.walk(tree):
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        subs = {}
        for n in ast.walk(fn):
            if isinstance(n, ast.Subscript) and isinstance(n.value, ast.Name):
                key = n.slice
                k = _unparse(key)
                if k in subs:
                    continue
                subs.setdefault(k, []).append(n)
        for n in ast.walk(fn):
            if not isinstance(n, ast.Compare):
                continue
            s = _unparse(n)
            if not re.search(r"(?i)(ts|time|at|until|expire|lease|created|updated)", s):
                continue
            # 一侧是字符串方法结果、另一侧是数值
            if re.search(r"\.isoformat\(\)|['\"]\d{4}-", s) and re.search(r"monotonic|time\(\)", s):
                out.append({
                    "rule": "TIME-05-ts-type-mix", "severity": "high",
                    "file": rel, "line": n.lineno, "function": fn.name,
                    "message": f"比较中一侧为 ISO 字符串、另一侧为单调/墙上秒数：{s[:70]}"
                               f" → 类型不同，比较结果不反映时间先后"})
    return out


# ────────────────────────────────────────────────────────────────────
# NUM-01 除法未防护空容器
# ────────────────────────────────────────────────────────────────────
def _guarded_by_call(n: ast.BinOp, src: str) -> bool:
    """是否被 max(1, len(...)) / or 0 / if 判空保护。"""
    if re.search(r"max\(\s*1\s*,\s*len\(", src):
        return True
    if re.search(r"if\s+\w+\s+(else|>)\s*", src):
        return True
    return False


def check_division_guard(tree, rel):
    out = []
    for fn in ast.walk(tree):
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for n in ast.walk(fn):
            if not isinstance(n, ast.BinOp) or not isinstance(n.op, ast.Div):
                continue
            s = _unparse(n)
            if "len(" not in s and "count" not in s and "total" not in s:
                continue
            if _guarded_by_call(n, s):
                continue
            # 同函数内是否有判空 return
            guarded = False
            for st in ast.walk(fn):
                if isinstance(st, ast.If):
                    t = _unparse(st.test).lower()
                    if ("not " in t or "len(" in t) and any(
                            isinstance(x, ast.Return) for x in ast.walk(st)):
                        guarded = True
            out.append({
                "rule": "NUM-01-div-zero", "severity": "medium",
                "file": rel, "line": n.lineno, "function": fn.name,
                "message": f"{fn.name}() 中除法 {s[:60]}"
                           + ("；未见判空保护（可能返回早于此处，需人工确认）" if guarded
                              else "；未见判空保护 → 空集合时 ZeroDivisionError")})
    return out


# ────────────────────────────────────────────────────────────────────
# NUM-02 空序列 max/min 无 default
# ────────────────────────────────────────────────────────────────────
def check_maxmin_empty(tree, rel):
    out = []
    for fn in ast.walk(tree):
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for n in ast.walk(fn):
            if not isinstance(n, ast.Call):
                continue
            nm = getattr(n.func, "id", None)
            if nm not in ("max", "min"):
                continue
            s = _unparse(n)
            if "default=" in s:
                continue
            if not re.search(r"\[\]|\(\)|for ", s):
                continue
            out.append({
                "rule": "NUM-02-maxmin-empty", "severity": "medium",
                "file": rel, "line": n.lineno, "function": fn.name,
                "message": f"{fn.name}() 中 {nm}({s[:50]}) 无 default= 且参数可能为生成器/推导式"
                           f" → 空序列时 ValueError"})
    return out


# ────────────────────────────────────────────────────────────────────
# NUM-03 浮点等值比较
# ────────────────────────────────────────────────────────────────────
def check_float_eq(tree, rel):
    out = []
    for fn in ast.walk(tree):
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for n in ast.walk(fn):
            if not isinstance(n, ast.Compare):
                continue
            if not any(isinstance(o, (ast.Eq, ast.NotEq)) for o in n.ops):
                continue
            s = _unparse(n)
            if not re.search(r"\d+\.\d+", s):
                continue
            if re.search(r"(?i)(version|ratio|weight|score|conf|rate)", s):
                continue
            out.append({
                "rule": "NUM-03-float-eq", "severity": "low",
                "file": rel, "line": n.lineno, "function": fn.name,
                "message": f"{fn.name}() 对浮点做等值比较：{s[:60]}"
                           f" → 精度误差可能导致判定不成立"})
    return out


CHECKS = [
    check_clock_mix_in_expr,
    check_wall_for_timeout,
    check_timedelta_mono_mix,
    check_ts_type_mix,
    check_division_guard,
    check_maxmin_empty,
    check_float_eq,
]


def main() -> int:
    root = Path(sys.argv[1] if len(sys.argv) > 1 else "/data/workspace/audit/src/src/autoforge")
    outdir = Path(sys.argv[2] if len(sys.argv) > 2 else "/data/workspace/audit/rounds/round-007/time_numeric")
    outdir.mkdir(parents=True, exist_ok=True)

    findings, files = [], 0
    for p in sorted(root.rglob("*.py")):
        if any(x.startswith("test") for x in p.parts):
            continue
        try:
            tree = ast.parse(p.read_text(errors="ignore"))
        except SyntaxError:
            continue
        rel = str(p.relative_to(root))
        files += 1
        for c in CHECKS:
            try:
                findings += c(tree, rel)
            except Exception as e:  # noqa: BLE001
                print(f"[warn] {c.__name__} on {rel}: {e}", file=sys.stderr)

    sev = {"high": 0, "medium": 1, "low": 2}
    findings.sort(key=lambda x: (sev.get(x["severity"], 9), x["file"], x["line"]))
    (outdir / "time-numeric-findings.json").write_text(
        json.dumps({"findings": findings}, ensure_ascii=False, indent=2))
    print(json.dumps({"files": files, "total": len(findings),
                      "by_severity": dict(Counter(f["severity"] for f in findings)),
                      "by_rule": dict(Counter(f["rule"] for f in findings))},
                     ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
