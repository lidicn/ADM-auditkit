#!/usr/bin/env python3
"""第五轮专题：控制流完整性与异常契约（纯 stdlib AST）。

前四轮覆盖：资源泄漏/除零/索引/竞态、持久化/崩溃恢复、并发/异步、资源上限与复杂度。
本轮只看**控制流与异常语义**这类会让「fail-closed 契约悄悄失效」的问题：
  - finally 里的 return/break/continue（吞异常、跳清理）
  - except 顺序遮蔽（父类在前 → 子类分支永不执行）
  - except 捕获未定义的异常名（拼写错误 → 该分支永不生效）
  - assert 做运行时校验（python -O 下被移除 → 校验静默消失）
  - except 块完全静默（只有 pass）
  - 绕过状态机迁移表直接赋值

设计原则：每条命中都必须给出「为什么会真的失效」的机制。命中后一律人工核验。

用法: controlflow_defects.py <src_root> <outdir>
"""
from __future__ import annotations

import ast
import builtins
import json
import re
import sys
from pathlib import Path

BUILTIN_EXC = {n for n in dir(builtins) if n.endswith(("Error", "Exception", "Warning",
                                                       "Exit", "Interrupt", "Iteration",
                                                       "Timeout", "Stop"))}
BUILTIN_EXC |= {"Exception", "BaseException", "KeyboardInterrupt", "SystemExit",
                "GeneratorExit", "StopIteration", "StopAsyncIteration"}

# 常见父子关系（用于 except 顺序遮蔽判定）
PARENT_OF = {
    "Exception": BUILTIN_EXC,          # Exception 遮蔽一切
    "BaseException": BUILTIN_EXC | {"Exception"},
    "OSError": {"FileNotFoundError", "PermissionError", "BlockingIOError", "InterruptedError",
                "NotADirectoryError", "IsADirectoryError", "FileExistsError", "TimeoutError",
                "ConnectionError", "BrokenPipeError", "ChildProcessError", "ProcessLookupError"},
    "LookupError": {"KeyError", "IndexError"},
    "ArithmeticError": {"ZeroDivisionError", "OverflowError", "FloatingPointError"},
    "ValueError": {"JSONDecodeError", "UnicodeDecodeError", "UnicodeError"},
    "RuntimeError": {"RecursionError", "NotImplementedError"},
    "ConnectionError": {"BrokenPipeError", "ConnectionRefusedError", "ConnectionResetError"},
    "UnicodeError": {"UnicodeDecodeError", "UnicodeEncodeError", "UnicodeTranslateError"},
}


def _exc_names(handler: ast.ExceptHandler) -> list[str]:
    """返回 handler 捕获的异常名，Attribute 保留完整点路径（如 urllib.error.HTTPError）。

    首版对 Attribute 只取 attr，把 `json.JSONDecodeError` 变成裸 `JSONDecodeError`
    丢进「未定义」判定 —— ERR-03 的 10 条命中全是这么来的假阳性。
    """
    def _one(e):
        if isinstance(e, ast.Name):
            return e.id
        if isinstance(e, ast.Attribute):
            parts = []
            cur = e
            while isinstance(cur, ast.Attribute):
                parts.append(cur.attr)
                cur = cur.value
            if isinstance(cur, ast.Name):
                parts.append(cur.id)
                return ".".join(reversed(parts))
            return parts[-1]
        return None

    t = handler.type
    if t is None:
        return []
    if isinstance(t, ast.Tuple):
        return [x for x in (_one(e) for e in t.elts) if x]
    x = _one(t)
    return [x] if x else []


def _base_name(nm: str) -> str:
    """点路径取最后一段，用于父子关系判定。"""
    return nm.split(".")[-1]


# ────────────────────────────────────────────────────────────────────
# ERR-01 finally 中的 return / break / continue
# ────────────────────────────────────────────────────────────────────
def _handler_in_finally(fn, handler) -> bool:
    """该 except handler 是否位于某个 try 的 finalbody 内。

    `finally:` 里的 `except OSError: pass` 通常是**清理失败**（删临时文件/解锁），
    吞掉是正确取舍——清理失败不该影响主流程。首版未排除 → clean 样本上
    atomic_write/replace_file 两条误报（PITFALLS 新增条目 P14）。
    """
    for t in ast.walk(fn):
        if isinstance(t, ast.Try) and t.finalbody:
            for x in ast.walk(ast.Module(body=t.finalbody, type_ignores=[])):
                if x is handler:
                    return True
            # finalbody 内的嵌套 try/except
            for x in ast.walk(ast.Module(body=t.finalbody, type_ignores=[])):
                if isinstance(x, ast.Try):
                    for h in x.handlers:
                        if h is handler:
                            return True
    return False


CLEANUP_CALL = re.compile(r"(?i)(unlink|rmtree|\bremove\b|\.close\s*\(|release|unlock|cleanup|dispose|shutdown)")


def _try_body_is_cleanup(tr) -> bool:
    """该 try 的 body 是否**只**做清理类调用。

    除 finally 外还有一种正确形态：函数末尾的独立 try 里只做「删备份/关句柄」，
    失败则 pass（备份删不掉不影响主流程）。PITFALLS P14 补记。
    """
    calls = [n for n in ast.walk(ast.Module(body=tr.body, type_ignores=[]))
             if isinstance(n, ast.Call)]
    if not calls:
        return False
    return all(CLEANUP_CALL.search(ast.unparse(n)) for n in calls)


def check_finally_control(tree, rel):
    out = []
    for n in ast.walk(tree):
        if not isinstance(n, ast.Try) or not n.finalbody:
            continue
        for st in n.finalbody:
            if isinstance(st, ast.Return):
                out.append({
                    "rule": "ERR-01-finally-return", "severity": "high",
                    "file": rel, "line": st.lineno, "function": "<try>",
                    "message": "finally 中有 return：会吞掉 try/except 中正在传播的异常，"
                               "且跳过先前 except 的清理语义，失败被伪装成成功"})
            elif isinstance(st, ast.Break):
                out.append({
                    "rule": "ERR-01-finally-break", "severity": "medium",
                    "file": rel, "line": st.lineno, "function": "<try>",
                    "message": "finally 中有 break：会吞掉异常并改变外层循环的控制流"})
            elif isinstance(st, ast.Continue):
                out.append({
                    "rule": "ERR-01-finally-continue", "severity": "medium",
                    "file": rel, "line": st.lineno, "function": "<try>",
                    "message": "finally 中有 continue：会吞掉异常并跳到下一轮"})
    return out


# ────────────────────────────────────────────────────────────────────
# ERR-02 except 顺序遮蔽
# ────────────────────────────────────────────────────────────────────
def check_except_shadowing(tree, rel):
    out = []
    for n in ast.walk(tree):
        if not isinstance(n, ast.Try) or len(n.handlers) < 2:
            continue
        seen_broad = None
        for h in n.handlers:
            names = _exc_names(h)
            if not names:          # 裸 except: 遮蔽其后一切
                if h is not n.handlers[-1]:
                    out.append({
                        "rule": "ERR-02-except-shadow", "severity": "high",
                        "file": rel, "line": h.lineno, "function": "<try>",
                        "message": "裸 except: 后面还有 except 分支 → 后面的分支永不可达"})
                continue
            if seen_broad:
                for nm in names:
                    children = PARENT_OF.get(seen_broad, set())
                    if nm in children or seen_broad in ("Exception", "BaseException"):
                        out.append({
                            "rule": "ERR-02-except-shadow", "severity": "high",
                            "file": rel, "line": h.lineno, "function": "<try>",
                            "message": f"except {seen_broad} 在前，except {nm} 在后 → "
                                       f"{nm} 分支永不执行（被父类捕获）"})
            for nm in names:
                base = _base_name(nm)
                if base in PARENT_OF and base not in ("Exception", "BaseException"):
                    seen_broad = base
    return out


# ────────────────────────────────────────────────────────────────────
# ERR-03 except 捕获了项目中不存在的异常名（拼写错误 → 永不生效）
# ────────────────────────────────────────────────────────────────────
def _defined_exceptions(root: Path) -> set[str]:
    names = set()
    for p in root.rglob("*.py"):
        try:
            t = ast.parse(p.read_text(errors="ignore"))
        except SyntaxError:
            continue
        for n in ast.walk(t):
            if isinstance(n, ast.ClassDef):
                bases = []
                for b in n.bases:
                    if isinstance(b, ast.Name):
                        bases.append(b.id)
                    elif isinstance(b, ast.Attribute):
                        bases.append(b.attr)
                if any(b in BUILTIN_EXC or b.endswith(("Error", "Exception"))
                       for b in bases) or n.name.endswith(("Error", "Exception")):
                    names.add(n.name)
    return names


def _imported_names(tree: ast.Module) -> set[str]:
    """模块内所有可引用的名字：import X / from X import Y as Z / 模块级赋值名。

    ERR-03 首版 11 条命中**全是误报**——`from json import JSONDecodeError`、
    `from urllib.error import HTTPError, URLError`、`from homesdk.config import
    MissingEnv` 这些导入名没有被计入已知集合。补上后才能真正判「名字不存在」。
    """
    names: set[str] = set()
    for n in ast.walk(tree):
        if isinstance(n, ast.Import):
            for a in n.names:
                names.add(a.asname or a.name.split(".")[0])
        elif isinstance(n, ast.ImportFrom):
            for a in n.names:
                if a.name != "*":
                    names.add(a.asname or a.name)
    for n in tree.body:
        if isinstance(n, ast.Assign):
            for t in n.targets:
                if isinstance(t, ast.Name):
                    names.add(t.id)
        elif isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            names.add(n.name)
    return names


def check_undefined_except(tree, rel, known: set[str], imported: set[str]):
    out = []
    for n in ast.walk(tree):
        if not isinstance(n, ast.Try):
            continue
        for h in n.handlers:
            for nm in _exc_names(h):
                if nm in BUILTIN_EXC or nm in known or nm in imported:
                    continue
                # 带点的（json.JSONDecodeError / _mqtt.MqttUnavailable）静态判不了，跳过
                if "." in nm:
                    continue
                out.append({
                    "rule": "ERR-03-undefined-except", "severity": "high",
                    "file": rel, "line": h.lineno, "function": "<try>",
                    "message": f"except {nm}：该异常名在本仓库、内建异常与本模块导入名中均未出现 → "
                               f"若拼写错误，此处会抛 NameError 而非捕获"})
    return out


# ────────────────────────────────────────────────────────────────────
# ERR-04 assert 用于运行时输入校验（python -O 下被移除）
# ────────────────────────────────────────────────────────────────────
def check_assert_validation(tree, rel):
    out = []
    for fn in ast.walk(tree):
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for n in ast.walk(fn):
            if not isinstance(n, ast.Assert):
                continue
            test = ast.unparse(n.test).lower()
            # 排除纯自检/调试型 assert（self._x is not None 之类）
            looks_like_validation = any(
                k in test for k in ("isinstance", "not none", "!= none", "in ", "len(",
                                    ">= 0", "> 0", "startswith", "tzinfo"))
            if not looks_like_validation:
                continue
            out.append({
                "rule": "ERR-04-assert-validation", "severity": "medium",
                "file": rel, "line": n.lineno, "function": fn.name,
                "message": f"{fn.name}() 用 assert 做校验（{ast.unparse(n.test)[:50]}）；"
                           f"python -O / PYTHONOPTIMIZE 下 assert 被移除，校验静默消失。"
                           f"若这是运行时契约，应改为 raise"})
    return out


# ────────────────────────────────────────────────────────────────────
# ERR-05 except 块完全静默（只有 pass）
# ────────────────────────────────────────────────────────────────────
def check_silent_except(tree, rel):
    out = []
    for fn in ast.walk(tree):
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for n in ast.walk(fn):
            if not isinstance(n, ast.Try):
                continue
            for h in n.handlers:
                if len(h.body) != 1 or not isinstance(h.body[0], ast.Pass):
                    continue
                if _handler_in_finally(fn, h):
                    continue      # finally 内的清理失败，吞掉是正确取舍
                if _try_body_is_cleanup(n):
                    continue      # try 内只做清理（删备份/关句柄），失败不影响主流程
                names = _exc_names(h) or ["<裸 except>"]
                out.append({
                    "rule": "ERR-05-silent-except", "severity": "medium",
                    "file": rel, "line": h.lineno, "function": fn.name,
                    "message": f"{fn.name}() 捕获 {', '.join(names)} 后仅 pass："
                               f"无日志、无返回、无重抛，故障完全不可观测"})
    return out


# ────────────────────────────────────────────────────────────────────
# ERR-06 绕过状态机迁移表直接赋值
#   条件：模块定义了 _ALLOWED 迁移表（dict[str, set]），却在其他函数里
#         直接给状态字段赋值，未走校验函数
# ────────────────────────────────────────────────────────────────────
def check_state_machine_bypass(tree, rel):
    out = []
    has_table = any(isinstance(n, ast.Assign) and any(
        isinstance(t, ast.Name) and t.id == "_ALLOWED" for t in n.targets)
        for n in tree.body)
    if not has_table:
        return out
    guard_names = {n.name for n in ast.walk(tree)
                   if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
                   and (n.name.startswith("_transition") or n.name.startswith("transition"))}
    for fn in ast.walk(tree):
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if fn.name in guard_names:
            continue
        for n in ast.walk(fn):
            if isinstance(n, ast.Assign):
                for t in n.targets:
                    if isinstance(t, ast.Attribute) and t.attr == "state" \
                            and isinstance(t.value, ast.Attribute):
                        out.append({
                            "rule": "ERR-06-state-machine-bypass", "severity": "high",
                            "file": rel, "line": n.lineno, "function": fn.name,
                            "message": f"{fn.name}() 直接给 .state 赋值，绕过 _ALLOWED 迁移表校验"
                                       f"（{', '.join(sorted(guard_names)) or '未见守卫函数'}）"})
    return out


def main() -> int:
    root = Path(sys.argv[1] if len(sys.argv) > 1 else "/data/workspace/audit/src/src/autoforge")
    outdir = Path(sys.argv[2] if len(sys.argv) > 2 else "/data/workspace/audit/rounds/round-005/controlflow")
    outdir.mkdir(parents=True, exist_ok=True)

    known = _defined_exceptions(root)
    findings, files = [], 0
    for p in sorted(root.rglob("*.py")):
        if any(part.startswith("test") for part in p.parts):
            continue
        try:
            tree = ast.parse(p.read_text(errors="ignore"))
        except SyntaxError:
            continue
        rel = str(p.relative_to(root))
        files += 1
        imported = _imported_names(tree)
        findings += check_finally_control(tree, rel)
        findings += check_except_shadowing(tree, rel)
        findings += check_undefined_except(tree, rel, known, imported)
        findings += check_assert_validation(tree, rel)
        findings += check_silent_except(tree, rel)
        findings += check_state_machine_bypass(tree, rel)

    sev = {"high": 0, "medium": 1, "low": 2}
    findings.sort(key=lambda x: (sev.get(x["severity"], 9), x["file"], x["line"]))
    (outdir / "controlflow-findings.json").write_text(
        json.dumps({"findings": findings}, ensure_ascii=False, indent=2))
    from collections import Counter
    print(json.dumps({"files": files, "total": len(findings),
                      "by_severity": dict(Counter(f["severity"] for f in findings)),
                      "by_rule": dict(Counter(f["rule"] for f in findings))},
                     ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
