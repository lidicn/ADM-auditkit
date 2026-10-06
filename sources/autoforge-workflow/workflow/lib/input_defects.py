#!/usr/bin/env python3
"""第八轮专题：外部输入健壮性与信任边界（纯 stdlib AST）。

前七轮覆盖：稳定性、持久化、并发、复杂度、控制流、死代码/缓存、时间/数值。
本轮看**数据从外部进来之后有没有被正确对待**：

  IN-01  外部 JSON 解析后直接下标取值（缺字段 → KeyError 穿出）
  IN-02  类型转换无保护（int()/float() 直接作用于外部值）
  IN-03  路径由外部输入拼接（遍历风险）
  IN-04  写端点无鉴权依赖（HTTP 层）
  IN-05  外部字符串直接进 os.system/subprocess/eval（命令注入）
  IN-06  外部值不做范围校验就写入状态（越界/污染）
  IN-07  外部输入驱动循环/切片无上限（DoS）

设计原则：本类问题在**本地工具类**场景多为可接受的 fail-fast（CLI 抛栈即可），
所以每条都标注 `surface`：http / mcp / cli / lib，只对 http/mcp 面升格。

用法: input_defects.py <src_root> <outdir>
"""
from __future__ import annotations

import ast
import json
import re
import sys
from collections import Counter
from pathlib import Path

HTTP_HINT = ("af_api.py", "af_mcp.py")
CLI_HINT = ("af_cli.py",)
DANGEROUS = {"system", "popen", "check_output", "check_call", "run", "eval", "exec"}


def _surface(rel: str) -> str:
    if any(h in rel for h in HTTP_HINT):
        return "http"
    if any(h in rel for h in CLI_HINT):
        return "cli"
    return "lib"


def _call_chain(n: ast.Call):
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
    return ""


# ────────────────────────────────────────────────────────────────────
# IN-01 解析后直接下标取值
# ────────────────────────────────────────────────────────────────────
def check_direct_index_on_parsed(tree, rel):
    out = []
    surf = _surface(rel)
    for fn in ast.walk(tree):
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        # 找 json.loads/load 赋值的变量名
        parsed_vars = set()
        for n in ast.walk(fn):
            if isinstance(n, ast.Assign) and isinstance(n.value, ast.Call):
                c = _call_chain(n.value)
                if c in ("json.loads", "json.load"):
                    for t in n.targets:
                        if isinstance(t, ast.Name):
                            parsed_vars.add(t.id)
            if isinstance(n, ast.Call) and _call_chain(n) in ("json.loads", "json.load"):
                if isinstance(n.func, ast.Attribute) and isinstance(n.func.value, ast.Name):
                    pass
        if not parsed_vars:
            continue
        for n in ast.walk(fn):
            if not isinstance(n, ast.Subscript):
                continue
            if not isinstance(n.value, ast.Name) or n.value.id not in parsed_vars:
                continue
            # 是否被 try 包裹
            guarded = False
            for t in ast.walk(fn):
                if isinstance(t, ast.Try) and any(x is n for x in ast.walk(t)):
                    guarded = True
            if guarded:
                continue
            key = ast.unparse(n.slice)
            if key in ("0", "-1") and surf == "lib":
                continue
            out.append({
                "rule": "IN-01-direct-index", "severity": "high" if surf == "http" else "medium",
                "file": rel, "line": n.lineno, "function": fn.name, "surface": surf,
                "message": f"{fn.name}() 对解析结果 {n.value.id}[{key}] 直接下标取值且无 try；"
                           f"外部 JSON 缺该字段时 KeyError 穿出"})
    return out


# ────────────────────────────────────────────────────────────────────
# IN-02 类型转换无保护
# ────────────────────────────────────────────────────────────────────
def check_unsafe_cast(tree, rel):
    out = []
    surf = _surface(rel)
    for fn in ast.walk(tree):
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for n in ast.walk(fn):
            if not isinstance(n, ast.Call):
                continue
            c = _call_chain(n)
            if c not in ("int", "float"):
                continue
            if not n.args:
                continue
            arg = ast.unparse(n.args[0])
            # 外部来源特征：来自 dict.get / 下标 / 参数
            external = bool(re.search(r"\.get\(|\[[\"']|payload|body|data|raw|env|request", arg))
            if not external:
                continue
            guarded = any(isinstance(t, ast.Try) and any(x is n for x in ast.walk(t))
                          for t in ast.walk(fn))
            if guarded:
                continue
            out.append({
                "rule": "IN-02-unsafe-cast", "severity": "high" if surf == "http" else "medium",
                "file": rel, "line": n.lineno, "function": fn.name, "surface": surf,
                "message": f"{fn.name}() 对外部值 {c}({arg[:40]}) 直接转换且无 try；"
                           f"脏数据 → ValueError 穿出"})
    return out


# ────────────────────────────────────────────────────────────────────
# IN-03 路径由外部拼接
# ────────────────────────────────────────────────────────────────────
def check_path_traversal(tree, rel):
    out = []
    surf = _surface(rel)
    for fn in ast.walk(tree):
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for n in ast.walk(fn):
            if not isinstance(n, ast.Call):
                continue
            c = _call_chain(n)
            if c not in ("os.path.join", "Path"):
                continue
            for a in n.args:
                s = ast.unparse(a)
                if re.search(r"(?i)(name|path|id|file|dir|key)\b", s) and \
                        not s.startswith(('"', "'")) and "[" not in s:
                    out.append({
                        "rule": "IN-03-path-join", "severity": "medium" if surf == "http" else "low",
                        "file": rel, "line": n.lineno, "function": fn.name, "surface": surf,
                        "message": f"{fn.name}() 用变量 {s[:40]} 拼路径；"
                                   f"若该值来自外部且未校验 `..`/斜杠 → 路径遍历"})
                    break
    return out


# ────────────────────────────────────────────────────────────────────
# IN-05 外部值进危险调用
# ────────────────────────────────────────────────────────────────────
def check_dangerous_call(tree, rel):
    out = []
    for fn in ast.walk(tree):
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for n in ast.walk(fn):
            if not isinstance(n, ast.Call):
                continue
            c = _call_chain(n)
            base = c.split(".")[-1]
            if base not in DANGEROUS:
                continue
            if base in ("run",) and "subprocess" not in c:
                continue
            if base in ("eval", "exec") and len(n.args) == 0:
                continue
            args = [ast.unparse(a) for a in n.args]
            external = any(re.search(r"(?i)(payload|body|data|raw|user|input|spec|name|cmd)", a)
                           for a in args)
            out.append({
                "rule": "IN-05-dangerous-call",
                "severity": "high" if external else "medium",
                "file": rel, "line": n.lineno, "function": fn.name,
                "surface": _surface(rel),
                "message": f"{fn.name}() 调用 {c}()"
                           + ("，参数疑似含外部输入 → 命令注入面" if external
                              else "（参数未识别为外部输入，需人工确认）")})
    return out


# ────────────────────────────────────────────────────────────────────
# IN-07 外部值驱动切片/循环无上限
# ────────────────────────────────────────────────────────────────────
def check_unbounded_slice(tree, rel):
    out = []
    surf = _surface(rel)
    for fn in ast.walk(tree):
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for n in ast.walk(fn):
            if not isinstance(n, ast.Subscript) or not isinstance(n.slice, ast.Slice):
                continue
            for part in (n.slice.lower, n.slice.upper, n.slice.step):
                if part is None:
                    continue
                s = ast.unparse(part)
                if re.search(r"\.get\(|\[[\"']|payload|body|limit|count|n\b", s) and \
                        not re.match(r"^-?\d+$", s):
                    out.append({
                        "rule": "IN-07-unbounded-slice", "severity": "low",
                        "file": rel, "line": n.lineno, "function": fn.name, "surface": surf,
                        "message": f"{fn.name}() 切片边界来自外部值 {s[:40]}；"
                                   f"未校验上限时超大数据会一次性载入"})
                    break
    return out


CHECKS = [
    check_direct_index_on_parsed,
    check_unsafe_cast,
    check_path_traversal,
    check_dangerous_call,
    check_unbounded_slice,
]


def main() -> int:
    root = Path(sys.argv[1] if len(sys.argv) > 1 else "/data/workspace/audit/src/src/autoforge")
    outdir = Path(sys.argv[2] if len(sys.argv) > 2 else "/data/workspace/audit/rounds/round-008/input")
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
    (outdir / "input-findings.json").write_text(
        json.dumps({"findings": findings}, ensure_ascii=False, indent=2))
    print(json.dumps({"files": files, "total": len(findings),
                      "by_severity": dict(Counter(f["severity"] for f in findings)),
                      "by_rule": dict(Counter(f["rule"] for f in findings)),
                      "by_surface": dict(Counter(f.get("surface", "?") for f in findings))},
                     ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
