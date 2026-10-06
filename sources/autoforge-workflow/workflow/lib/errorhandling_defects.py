#!/usr/bin/env python3
"""第十一轮专题：错误处理与降级路径正确性（纯 stdlib AST）。

前十轮覆盖：稳定性、持久化、并发、复杂度、控制流、死代码/缓存、时间数值、
输入边界、事务边界、序列化。本轮看**出错之后能不能正确恢复**：

  ERRH-01 重试计数语义错误（off-by-one / 成功也重试 / 最后一次仍 sleep）
  ERRH-02 降级返回「伪装成功」的值（返回 0/空容器/True 掩盖真实失败）
  ERRH-03 降级路径本身无错处理（fallback 里再抛，或 fallback 结果未校验）
  ERRH-04 熔断半开态探测无并发限制（多个请求同时探测）
  ERRH-05 超时未设置 / 超时后未清理资源
  ERRH-06 错误分类把「暂时性错误」当「永久性错误」处理（或反之）

设计原则：本类问题误报率高；命中必须给「机制说明」，且一律人工核验。
规则只做定位，不做判定。

用法: errorhandling_defects.py <src_root> <outdir>
"""
from __future__ import annotations

import ast
import json
import re
import sys
from collections import Counter
from pathlib import Path

SLEEP_HINT = ("sleep", "wait", "delay")
TRANSIENT = ("timeout", "Timeout", "Connection", "Temporary", "Busy", "Throttl", "Rate")
PERMANENT = ("NotFound", "Permission", "Validation", "Syntax", "Value")


def _chain(n: ast.Call) -> str:
    if isinstance(n.func, ast.Name):
        return n.func.id
    if isinstance(n.func, ast.Attribute):
        parts = []
        cur = n.func
        while isinstance(cur, ast.Attribute):
            parts.append(cur.attr)
            cur = cur.value
        if isinstance(cur, ast.Name):
            parts.append(cur.id)
            return ".".join(reversed(parts))
        # 接收者不是简单 Name（如 `(p / "x.json").write_text(...)`、数组下标、
        # 函数调用结果）→ 首版直接返回 ""，整条调用被丢弃（PITFALLS N7）。
        # 改为保留已收集的属性链，至少能匹配方法名。
        if parts:
            return ".".join(reversed(parts))
    return ""


def _fn_src(fn) -> str:
    try:
        return ast.unparse(fn)
    except Exception:
        return ""


# ────────────────────────────────────────────────────────────────────
# ERRH-01 重试循环语义
# ────────────────────────────────────────────────────────────────────
def check_retry_semantics(tree, rel):
    out = []
    for fn in ast.walk(tree):
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        name_l = fn.name.lower()
        src = _fn_src(fn)
        if not re.search(r"retr(y|ies)|attempt|backoff|max_retries", name_l + src):
            continue
        # 找 for attempt in range(N) 结构
        for n in ast.walk(fn):
            if not isinstance(n, ast.For):
                continue
            it = ast.unparse(n.iter)
            if "range(" not in it:
                continue
            body_src = ast.unparse(ast.Module(body=n.body, type_ignores=[]))
            has_break = "break" in body_src
            has_return = re.search(r"^\s*return\b", body_src, re.M) is not None
            has_sleep = any(k in body_src for k in SLEEP_HINT)
            has_raise = "raise" in body_src
            # 成功退出条件：break/return 存在
            if not (has_break or has_return):
                out.append({
                    "rule": "ERRH-01-retry-no-exit", "severity": "medium",
                    "file": rel, "line": n.lineno, "function": fn.name,
                    "message": f"{fn.name}() 的重试循环 `for ... in {it}` 无 break/return 退出；"
                               f"成功也会继续重试 N 次（浪费，且可能重复副作用）"})
            # 最后一次仍 sleep（无意义的尾部等待）
            if has_sleep:
                last = n.body[-1] if n.body else None
                ls = ast.unparse(last) if last is not None else ""
                if any(k in ls for k in SLEEP_HINT) and not re.search(
                        r"if\b", ast.unparse(n.body[-2]) if len(n.body) >= 2 else ""):
                    out.append({
                        "rule": "ERRH-01-tail-sleep", "severity": "low",
                        "file": rel, "line": getattr(last, "lineno", n.lineno),
                        "function": fn.name,
                        "message": f"{fn.name}() 重试循环末尾无条件 sleep："
                                   f"最后一次重试后仍等待，白白增加延迟"})
            # 全部失败后是否 raise/返回失败
            tail_src = ast.unparse(ast.Module(body=fn.body[fn.body.index(n):], type_ignores=[])) \
                if n in fn.body else ""
            if not has_raise and tail_src and not re.search(r"return\s+(False|None)\b", tail_src):
                out.append({
                    "rule": "ERRH-01-retry-swallows", "severity": "medium",
                    "file": rel, "line": n.lineno, "function": fn.name,
                    "message": f"{fn.name}() 重试耗尽后既未 raise 也未返回失败标志；"
                               f"调用方无法区分「成功」与「重试全败」"})
    return out


# ────────────────────────────────────────────────────────────────────
# ERRH-02 降级返回「伪装成功」的值
# ────────────────────────────────────────────────────────────────────
FAKE_OK = {"0", "0.0", "0.0,", "True", "''", '""', "{}", "[]", "None"}


def check_fake_success(tree, rel):
    out = []
    for fn in ast.walk(tree):
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for n in ast.walk(fn):
            if not isinstance(n, ast.Try) or not n.handlers:
                continue
            for h in n.handlers:
                # except 块里直接 return 常量
                for st in h.body:
                    if not isinstance(st, ast.Return) or st.value is None:
                        continue
                    v = ast.unparse(st.value)
                    if v in FAKE_OK or re.match(r"^(0(\.0+)?|True|None|\{\}|\[\])$", v):
                        # 是否有日志（有日志说明是有意降级）
                        hsrc = ast.unparse(ast.Module(body=h.body, type_ignores=[]))
                        logged = any(k in hsrc for k in ("logger", "log.", "warn", "error", "audit"))
                        out.append({
                            "rule": "ERRH-02-fake-success",
                            "severity": "low" if logged else "medium",
                            "file": rel, "line": st.lineno, "function": fn.name,
                            "message": f"{fn.name}() 在 except 中 return {v}"
                                       + ("（有日志，属有意降级）" if logged
                                          else "，且无日志：调用方会把它当正常结果，失败不可观测")})
    return out


# ────────────────────────────────────────────────────────────────────
# ERRH-03 降级路径无保护
# ────────────────────────────────────────────────────────────────────
def check_unprotected_fallback(tree, rel):
    out = []
    for fn in ast.walk(tree):
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for n in ast.walk(fn):
            if not isinstance(n, ast.Try) or not n.handlers:
                continue
            for h in n.handlers:
                # except 内部的调用是否再被 try 包裹
                inner_calls = [c for c in ast.walk(ast.Module(body=h.body, type_ignores=[]))
                               if isinstance(c, ast.Call)]
                if not inner_calls:
                    continue
                inner_try = any(isinstance(t, ast.Try)
                                for t in ast.walk(ast.Module(body=h.body, type_ignores=[])))
                risky = [c for c in inner_calls
                         if re.search(r"(?i)(fallback|degrade|default|last_resort|safe_)",
                                      _chain(c))]
                if risky and not inner_try:
                    out.append({
                        "rule": "ERRH-03-unprotected-fallback", "severity": "medium",
                        "file": rel, "line": h.lineno, "function": fn.name,
                        "message": (f"{fn.name}() 在 except 中调用降级入口 "
                                    f"{_chain(risky[0])}() 但无内层 try；"
                                    f"降级路径自身失败会让原异常被替换成新异常，掩盖真因")})
    return out


# ────────────────────────────────────────────────────────────────────
# ERRH-04 熔断半开态并发探测
# ────────────────────────────────────────────────────────────────────
def check_halfopen_concurrency(tree, rel):
    out = []
    src_txt = ast.unparse(tree)
    if not re.search(r"(?i)half_?open|halfopen", src_txt):
        return out
    for fn in ast.walk(tree):
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        s = _fn_src(fn)
        if not re.search(r"(?i)half_?open", s):
            continue
        has_lock = any(k in s for k in ("with self._lock", "_lock.acquire", "Lock("))
        has_probe_guard = re.search(r"(?i)(probe|trial|allow_one|single|permit)", s) is not None
        if not (has_lock or has_probe_guard):
            out.append({
                "rule": "ERRH-04-halfopen-concurrency", "severity": "medium",
                "file": rel, "line": fn.lineno, "function": fn.name,
                "message": f"{fn.name}() 处理熔断半开态，但未见锁或单探测许可；"
                           f"多请求会同时穿透探测，熔断失去保护作用"})
    return out


# ────────────────────────────────────────────────────────────────────
# ERRH-05 超时后未清理 / 无超时
# ────────────────────────────────────────────────────────────────────
# 只认真正的网络客户端入口；`.get(`/`.post(` 会命中 dict.get 与 FastAPI 装饰器 → 623 条全误报
NET_CALL = re.compile(
    r"(?i)(urlopen|requests\.(get|post|put|delete|request)|httpx\.(get|post|request|Client|AsyncClient)"
    r"|aiohttp\.ClientSession|socket\.socket|socket\.create_connection"
    r"|\.urlopen\(|(?<!_)session\.(get|post)\()")
# 处于 HTTP 服务端/客户端同一模块时，timeout 也可能出现在别处；要求 timeout 关键字或变量
TIMEOUT_HINT = re.compile(r"(?i)\btimeout\b")


def check_timeout_cleanup(tree, rel):
    out = []
    for fn in ast.walk(tree):
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        src = _fn_src(fn)
        if not NET_CALL.search(src):
            continue
        has_timeout = TIMEOUT_HINT.search(src) is not None
        has_finally = any(isinstance(t, ast.Try) and t.finalbody for t in ast.walk(fn))
        has_ctx = "with " in src
        if not has_timeout:
            out.append({
                "rule": "ERRH-05-no-timeout", "severity": "high",
                "file": rel, "line": fn.lineno, "function": fn.name,
                "message": f"{fn.name}() 含网络调用但未见 timeout 参数；"
                           f"远端不响应会永久挂起调用方（有界失败原则）"})
        elif not (has_finally or has_ctx):
            out.append({
                "rule": "ERRH-05-no-cleanup", "severity": "medium",
                "file": rel, "line": fn.lineno, "function": fn.name,
                "message": f"{fn.name}() 有网络调用且设了 timeout，但无 finally/with 清理；"
                           f"超时后连接/句柄可能泄漏"})
    return out


# ────────────────────────────────────────────────────────────────────
# ERRH-06 错误分类：暂时性被当永久性（或反之）
# ────────────────────────────────────────────────────────────────────
def check_error_classification(tree, rel):
    out = []
    for fn in ast.walk(tree):
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for n in ast.walk(fn):
            if not isinstance(n, ast.Try):
                continue
            names = []
            for h in n.handlers:
                t = h.type
                if isinstance(t, ast.Name):
                    names.append(t.id)
                elif isinstance(t, ast.Tuple):
                    names += [e.id for e in t.elts if isinstance(e, ast.Name)]
                elif isinstance(t, ast.Attribute):
                    names.append(t.attr)
            if not names:
                continue
            transient = [x for x in names if any(k in x for k in TRANSIENT)]
            permanent = [x for x in names if any(k in x for k in PERMANENT)]
            if transient and permanent:
                # 同一 try 把两类放一起，需人工看处理是否相同
                bodies = [ast.unparse(ast.Module(body=h.body, type_ignores=[]))
                          for h in n.handlers]
                same = all(b == bodies[0] for b in bodies[1:])
                if same:
                    out.append({
                        "rule": "ERRH-06-error-classification", "severity": "medium",
                        "file": rel, "line": n.lineno, "function": fn.name,
                        "message": (f"{fn.name}() 把暂时性错误（{transient}）与永久性错误"
                                    f"（{permanent}）用**完全相同**的方式处理；"
                                    f"重试对永久性错误无效、放弃对暂时性错误可惜")})
    return out


CHECKS = [
    check_retry_semantics,
    check_fake_success,
    check_unprotected_fallback,
    check_halfopen_concurrency,
    check_timeout_cleanup,
    check_error_classification,
]


def main() -> int:
    root = Path(sys.argv[1] if len(sys.argv) > 1 else "/data/workspace/audit/src/src/autoforge")
    outdir = Path(sys.argv[2] if len(sys.argv) > 2 else "/data/workspace/audit/rounds/round-011/errorhandling")
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
    (outdir / "errorhandling-findings.json").write_text(
        json.dumps({"findings": findings}, ensure_ascii=False, indent=2))
    print(json.dumps({"files": files, "total": len(findings),
                      "by_severity": dict(Counter(f["severity"] for f in findings)),
                      "by_rule": dict(Counter(f["rule"] for f in findings))},
                     ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
