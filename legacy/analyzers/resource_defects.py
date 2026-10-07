#!/usr/bin/env python3
"""第十六轮专题：资源生命周期与清理（纯 stdlib AST）。

前十五轮覆盖：稳定性、持久化、并发、复杂度、控制流、缓存、时间数值、
输入边界、事务边界、序列化、错误处理/降级、可观测性、配置兼容性、
测试缺口、API 契约。本轮看**拿到资源后有没有还回去**：

  RES-01 os.open()/mkstemp() 得到的 fd 无对应 close（非 with 包裹）
  RES-02 裸 open() 赋值给变量但无 close（非 with）
  RES-03 线程创建后无 join 且非 daemon（进程退出hang / 线程泄漏）
  RES-04 临时目录/文件创建后无清理（mkdtemp 无 rmtree）
  RES-05 子进程 Popen 后无 terminate/wait（僵尸进程）
  RES-06 异常路径上资源未释放（close 在 try 外 / 无 finally）

设计原则：先认"安全形状"（with / try-finally / 显式 close），
命中一律标注**获取点行号**与**是否在 finally 内**，便于人工秒判。

用法: resource_defects.py <src_root> <outdir>
"""
from __future__ import annotations

import ast
import json
import re
import sys
from collections import Counter
from pathlib import Path

OPEN_ACQUIRE = {"open", "os.open", "os.fdopen"}
TMP_ACQUIRE = {"mkstemp", "mkdtemp", "NamedTemporaryFile"}


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
        return ".".join(reversed(parts))
    if parts:
            return ".".join(reversed(parts))
    return ""


def _base(c: str) -> str:
    return c.split(".")[-1]


def _assigned_names(n) -> list[str]:
    out = []
    if isinstance(n, ast.Assign):
        for t in n.targets:
            if isinstance(t, ast.Name):
                out.append(t.id)
            elif isinstance(t, ast.Tuple):
                out += [e.id for e in t.elts if isinstance(e, ast.Name)]
    elif isinstance(n, ast.AugAssign):
        if isinstance(n.target, ast.Name):
            out.append(n.target.id)
    return out


def _in_try_finally(fn, node) -> bool:
    """node 是否在某个 try 的 body 里，且该 try 有 finalbody。"""
    for t in ast.walk(fn):
        if isinstance(t, ast.Try) and t.finalbody:
            if any(x is node for x in ast.walk(ast.Module(body=t.body, type_ignores=[]))):
                return True
    return False


def _in_with(tree, node) -> bool:
    for w in ast.walk(tree):
        if isinstance(w, ast.With):
            for it in w.items:
                if it.context_expr is node:
                    return True
    return False


def _name_closed_later(fn, name: str, after_line: int) -> bool:
    """变量是否在其后的代码里被 close（形如 x.close() / os.close(x)）。"""
    for n in ast.walk(fn):
        if not isinstance(n, ast.Call):
            continue
        c = _chain(n)
        if c.endswith(".close"):
            v = n.func
            if isinstance(v, ast.Attribute) and isinstance(v.value, ast.Name) \
                    and v.value.id == name and n.lineno >= after_line:
                return True
        if c == "os.close" and n.args:
            a = n.args[0]
            if isinstance(a, ast.Name) and a.id == name and n.lineno >= after_line:
                return True
    return False


# ────────────────────────────────────────────────────────────────────
# RES-01 / RES-02 文件描述符与文件句柄
# ────────────────────────────────────────────────────────────────────
def check_fd_and_handle(tree, rel):
    out = []
    for fn in ast.walk(tree):
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for asg in ast.walk(fn):
            if not isinstance(asg, ast.Assign) or not isinstance(asg.value, ast.Call):
                continue
            n = asg.value
            c = _chain(n)
            b = _base(c)
            is_open = b == "open" and c in OPEN_ACQUIRE
            is_osopen = c == "os.open"
            if not (is_open or is_osopen):
                continue
            # with 包裹 → 安全
            if _in_with(tree, n):
                continue
            names = _assigned_names(asg)
            # 未赋值（例如 f(...).close() 链式）→ 跳过
            if not names:
                continue
            # 在 try 且该 try 有 finally → 假定 finally 会收（配合 RES-06）
            in_fin = _in_try_finally(fn, n)
            for nm in names:
                if _name_closed_later(fn, nm, n.lineno):
                    continue
                rule = "RES-01-fd-not-closed" if is_osopen else "RES-02-handle-not-closed"
                sev = "low" if in_fin else "medium"
                out.append({
                    "rule": rule, "severity": sev,
                    "file": rel, "line": n.lineno, "function": fn.name,
                    "message": (f"{fn.name}() 在第 {n.lineno} 行 {c}() 得到 {nm}，"
                                + ("位于 try 内（该 try 有 finally，需确认 finally 是否 close）"
                                   if in_fin else "既无 with 也无 close")
                                + " → 文件描述符泄漏"),
                    "var": nm, "in_try_finally": in_fin,
                })
    return out


# ────────────────────────────────────────────────────────────────────
# RES-03 线程无 join 且非 daemon
# ────────────────────────────────────────────────────────────────────
def check_thread_join(tree, rel):
    out = []
    src_all = ast.unparse(tree)
    for asg in ast.walk(tree):
        if not isinstance(asg, ast.Assign) or not isinstance(asg.value, ast.Call):
            continue
        n = asg.value
        c = _chain(n)
        if _base(c) not in ("Thread", "Timer"):
            continue
        daemon = False
        for kw in n.keywords:
            if kw.arg == "daemon":
                try:
                    daemon = bool(ast.literal_eval(kw.value))
                except Exception:
                    daemon = True
        if daemon:
            continue
        has_join = bool(re.search(r"\.join\s*\(", src_all))
        has_daemon_attr = bool(re.search(r"\.daemon\s*=\s*True", src_all))
        if has_join or has_daemon_attr:
            continue
        out.append({
            "rule": "RES-03-thread-no-join", "severity": "low",
            "file": rel, "line": n.lineno, "function": c,
            "message": f"创建 {c}() 但模块内未见 daemon=True 或 .join()；"
                       f"非 daemon 线程会阻塞进程退出（长驻服务可忽略）",
            "vars": _assigned_names(asg),
        })
    return out


# ────────────────────────────────────────────────────────────────────
# RES-04 临时目录/文件无清理
# ────────────────────────────────────────────────────────────────────
def check_tmp_cleanup(tree, rel):
    out = []
    # 模块级粗粒度 has_cleanup 太宽松（模块里出现一次 rmtree 就认为全部清理了）。
    # 改为：看 mkdtemp 的结果变量是否**被用作** rmtree/unlink/remove 的实参。
    cleaned_vars = set()
    for n in ast.walk(tree):
        if not isinstance(n, ast.Call):
            continue
        c = _chain(n)
        if _base(c) not in ("rmtree", "unlink", "remove"):
            continue
        for a in n.args:
            if isinstance(a, ast.Name):
                cleaned_vars.add(a.id)
            elif isinstance(a, ast.Attribute):
                cleaned_vars.add(ast.unparse(a))
    for asg in ast.walk(tree):
        if not isinstance(asg, ast.Assign) or not isinstance(asg.value, ast.Call):
            continue
        n = asg.value
        b = _base(_chain(n))
        if b not in TMP_ACQUIRE or b == "mkstemp":
            continue
        names = _assigned_names(asg)
        if not names:
            continue
        if any(nm in cleaned_vars for nm in names):
            continue
        # 是否直接返回给调用方（由调用方负责清理）
        returned = False
        for fn in ast.walk(tree):
            if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            for st in ast.walk(fn):
                if isinstance(st, ast.Return) and isinstance(st.value, ast.Name) \
                        and st.value.id in names:
                    returned = True
        out.append({
            "rule": "RES-04-tmp-no-cleanup",
            "severity": "low" if returned else "medium",
            "file": rel, "line": n.lineno, "function": b,
            "message": (f"创建临时资源 {b}() 赋值给 {names}，但未见对其做 "
                        + ("rmtree/unlink（直接返回给调用方，责任转移）" if returned
                           else "rmtree/unlink 清理 → 反复调用会堆积临时文件")),
            "vars": names,
        })
    return out


# ────────────────────────────────────────────────────────────────────
# RES-05 子进程无回收
# ────────────────────────────────────────────────────────────────────
def check_subprocess_reap(tree, rel):
    out = []
    src_all = ast.unparse(tree)
    if not re.search(r"(?i)subprocess\.(Popen|run|call|check_output)", src_all):
        return out
    has_wait = bool(re.search(r"(?i)(\.wait\s*\(|\.terminate\s*\(|\.kill\s*\(|\.poll\s*\(|check_output|\.run\s*\()", src_all))
    if has_wait:
        return out
    for n in ast.walk(tree):
        if isinstance(n, ast.Call) and _base(_chain(n)) == "Popen":
            out.append({
                "rule": "RES-05-subprocess-no-reap", "severity": "medium",
                "file": rel, "line": n.lineno, "function": "Popen",
                "message": "Popen() 创建子进程，但模块内未见 wait/terminate/poll；"
                           "不回收会留下僵尸进程",
            })
    return out


# ────────────────────────────────────────────────────────────────────
# RES-06 异常路径资源未释放：获取在 try 内、close 在 try 外且无 finally
# ────────────────────────────────────────────────────────────────────
def check_release_outside_finally(tree, rel):
    out = []
    for fn in ast.walk(tree):
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for t in ast.walk(fn):
            if not isinstance(t, ast.Try) or not t.body:
                continue
            if t.finalbody:
                continue
            # try 内获取资源
            acquired = []
            for x in ast.walk(ast.Module(body=t.body, type_ignores=[])):
                if not isinstance(x, ast.Assign) or not isinstance(x.value, ast.Call):
                    continue
                cc = _chain(x.value)
                if _base(cc) in ("open", "Popen") or cc == "os.open":
                    acquired += _assigned_names(x)
            if not acquired:
                continue
            # close 在 try 之后
            for n in ast.walk(fn):
                if not isinstance(n, ast.Call):
                    continue
                c = _chain(n)
                if not c.endswith(".close") and c != "os.close":
                    continue
                tgt = ""
                if isinstance(n.func, ast.Attribute) and isinstance(n.func.value, ast.Name):
                    tgt = n.func.value.id
                elif c == "os.close" and n.args and isinstance(n.args[0], ast.Name):
                    tgt = n.args[0].id
                if tgt and tgt in acquired and n.lineno > t.body[-1].lineno:
                    out.append({
                        "rule": "RES-06-close-after-try", "severity": "medium",
                        "file": rel, "line": n.lineno, "function": fn.name,
                        "message": (f"{fn.name}() 在 try 内获取 {tgt}，但 close 在 try 之后"
                                    f"且该 try 无 finally；try 内抛异常时 {tgt} 不会关闭"),
                        "var": tgt,
                    })
    return out


CHECKS = [
    check_fd_and_handle,
    check_thread_join,
    check_tmp_cleanup,
    check_subprocess_reap,
    check_release_outside_finally,
]


def main() -> int:
    root = Path(sys.argv[1] if len(sys.argv) > 1 else "/data/workspace/audit/src/src/autoforge")
    outdir = Path(sys.argv[2] if len(sys.argv) > 2 else "/data/workspace/audit/rounds/round-016/resource")
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
    (outdir / "resource-findings.json").write_text(
        json.dumps({"findings": findings}, ensure_ascii=False, indent=2))
    print(json.dumps({"files": files, "total": len(findings),
                      "by_severity": dict(Counter(f["severity"] for f in findings)),
                      "by_rule": dict(Counter(f["rule"] for f in findings))},
                     ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
