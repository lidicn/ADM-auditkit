#!/usr/bin/env python3
"""第四轮专题：资源上限与复杂度失控（纯 stdlib AST）。

前面三轮分别覆盖了：资源泄漏/除零/索引/竞态、持久化/崩溃恢复、并发/异步。
本轮只看一类此前未碰的：**计算资源的上限缺失导致挂起或 OOM**——
组合爆炸、无预算递归、无界读取、ReDoS。

设计原则：本类问题误报率高，所以每条命中都带「机制说明 + 该模块是否已有同类上限」
（RSC-05 不一致信号），便于人工快速判定。

用法: boundary_defects.py <src_root> <outdir>
"""
from __future__ import annotations

import ast
import json
import re
import sys
from pathlib import Path

BUDGET_WORDS = ("depth", "budget", "limit", "max_", "cap", "count", "deadline", "_n", "level")
NESTED_QUANT = re.compile(r"\((?:[^\\)]|\\.)*[\+\*]\)\s*[\+\*]")
CARTESIAN_HINT = ("|", "&", "product", "combinations", "permutations")


def _name(node) -> str | None:
    if isinstance(node.func, ast.Name):
        return node.func.id
    if isinstance(node.func, ast.Attribute):
        return node.func.attr
    return None


GUARD_WORDS = ("visited", "seen", "onstack", "on_stack", "gray", "black", "white",
               "memo", "done", "trail", "path")


def _fn_has_budget(fn: ast.FunctionDef) -> bool:
    """函数是否带深度/预算/上限形参、计数器递增，或环检测集合。

    RSC-02 首版 114 条命中几乎全是误报：图遍历的 dfs 用 visited/onstack 集合做
    环检测、递归下降解析器用 depth 形参，都被当成"无预算递归"。这里补上两类
    守卫信号的识别，否则该规则对本项目没有区分度。
    """
    args = fn.args
    names = [a.arg for a in (list(args.posonlyargs) + list(args.args) + list(args.kwonlyargs))]
    if any(any(w in n.lower() for w in BUDGET_WORDS + GUARD_WORDS) for n in names):
        return True
    src = ast.unparse(fn)
    low = src.lower()
    # 环检测：局部集合 + add/discard/in 判定
    has_set = any(w in low for w in GUARD_WORDS)
    if has_set and any(op in src for op in (".add(", ".discard(", " in ", "not in ")):
        return True
    for n in ast.walk(fn):
        if isinstance(n, ast.AugAssign) and isinstance(n.op, ast.Add):
            tgt = n.target
            if isinstance(tgt, ast.Name) and any(w in tgt.id.lower()
                                                 for w in ("depth", "nodes", "count", "steps", "i", "n")):
                return True
        # 提前返回守卫：if 条件里出现深度/上限比较
        if isinstance(n, ast.If):
            t = ast.unparse(n.test).lower()
            if any(w in t for w in ("depth", "limit", "max", "budget", ">=", ">")) and \
               any(isinstance(s, ast.Return) for s in ast.walk(n)):
                return True
    return False


def _module_limits(tree: ast.Module) -> list[str]:
    out = []
    for n in tree.body:
        if isinstance(n, ast.Assign):
            for t in n.targets:
                if isinstance(t, ast.Name) and re.match(r"^(MAX|LIMIT|CAP)_", t.id):
                    out.append(t.id)
    return out


def _self_recursive(fn) -> bool:
    """只认两种真自递归：模块级函数按名调用自身，或方法 `self.同名()`。

    首版用 `_name()` 取 Attribute 的 attr 名匹配，导致 `def pop()` 里的
    `self._store.pop()` 被判成递归——这是 RSC-02 绝大部分假阳性的来源。
    """
    for n in ast.walk(fn):
        if not isinstance(n, ast.Call):
            continue
        f = n.func
        if isinstance(f, ast.Name) and f.id == fn.name:
            return True
        if isinstance(f, ast.Attribute) and f.attr == fn.name \
                and isinstance(f.value, ast.Name) and f.value.id == "self":
            return True
    return False


# ────────────────────────────────────────────────────────────────────
# RSC-01 组合爆炸：循环中用「双层 for 推导式」做笛卡尔积，且无任何上限
# ────────────────────────────────────────────────────────────────────
def check_cartesian(tree, rel):
    out = []
    mod_limits = _module_limits(tree)
    for fn in ast.walk(tree):
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for n in ast.walk(fn):
            if isinstance(n, (ast.ListComp, ast.SetComp, ast.GeneratorExp)) and len(n.generators) >= 2:
                # 两个生成器 → 笛卡尔积；检查是否有 break/上限保护
                guarded = _fn_has_budget(fn) or bool(mod_limits)
                # 是否在循环体内（被反复放大）
                in_loop = False
                for lp in ast.walk(fn):
                    if isinstance(lp, (ast.For, ast.While)) and any(x is n for x in ast.walk(lp)):
                        in_loop = True
                sev = "high" if (in_loop and not guarded) else "medium"
                out.append({
                    "rule": "RSC-01-combinatorial",
                    "severity": sev,
                    "file": rel, "line": n.lineno, "function": fn.name,
                    "message": (f"{fn.name}() 用双层推导式做笛卡尔积"
                                + ("，且位于循环体内（每轮再放大）" if in_loop else "")
                                + ("；函数无预算参数、模块无上限常量 → 结果规模随输入指数增长"
                                   if not guarded else "；但函数/模块存在上限信号，需人工确认是否覆盖此处")),
                    "module_limits": mod_limits,
                })
    return out


# ────────────────────────────────────────────────────────────────────
# RSC-02 无预算递归
# ────────────────────────────────────────────────────────────────────
def check_recursion_no_budget(tree, rel):
    out = []
    mod_limits = _module_limits(tree)
    for fn in ast.walk(tree):
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if not _self_recursive(fn):
            continue
        if _fn_has_budget(fn):
            continue
        # 是否有 visited/seen 集合（图遍历的环防护）
        src = ast.unparse(fn)
        has_visited = any(w in src for w in ("visited", "seen", "color", "onstack", "memo", "cache"))
        if has_visited:
            continue
        out.append({
            "rule": "RSC-02-recursion-no-budget",
            "severity": "high" if not mod_limits else "medium",
            "file": rel, "line": fn.lineno, "function": fn.name,
            "message": (f"{fn.name}() 自递归，无深度/预算形参、无计数器、无 visited 集合；"
                        f"输入深度不受控时会 RecursionError 或栈溢出"
                        + ("（模块已有 MAX_* 上限常量但未用于此函数 → 内部不一致）" if mod_limits else "")),
            "module_limits": mod_limits,
        })
    return out


# ────────────────────────────────────────────────────────────────────
# RSC-03 无界读取：一次性把整个文件/序列读进内存且无 limit
# ────────────────────────────────────────────────────────────────────
UNBOUNDED_READERS = {"readlines", "splitlines", "read"}


def check_unbounded_read(tree, rel):
    out = []
    for fn in ast.walk(tree):
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if _fn_has_budget(fn):
            continue
        for n in ast.walk(fn):
            if not isinstance(n, ast.Call):
                continue
            nm = _name(n)
            if nm not in UNBOUNDED_READERS:
                continue
            # 后接切片则视为有界
            parent = None
            for anc in ast.walk(fn):
                for ch in ast.iter_child_nodes(anc):
                    if ch is n:
                        parent = anc
            if isinstance(parent, ast.Subscript):
                continue
            out.append({
                "rule": "RSC-03-unbounded-read",
                "severity": "medium",
                "file": rel, "line": n.lineno, "function": fn.name,
                "message": (f"{fn.name}() 调用 {nm}() 一次性载入全部内容且无 limit/切片；"
                            f"大文件直接占满内存"),
            })
    return out


# ────────────────────────────────────────────────────────────────────
# RSC-04 ReDoS：正则含嵌套量词
# ────────────────────────────────────────────────────────────────────
def check_redos(tree, rel):
    out = []
    for n in ast.walk(tree):
        if not isinstance(n, ast.Constant) or not isinstance(n.value, str):
            continue
        if not NESTED_QUANT.search(n.value):
            continue
        # 是否用于 re.* 调用
        used = False
        for c in ast.walk(tree):
            if isinstance(c, ast.Call) and c.args and any(a is n for a in c.args):
                nm = _name(c) or ""
                if nm in ("match", "search", "findall", "finditer", "sub", "subn", "split", "fullmatch"):
                    used = True
        out.append({
            "rule": "RSC-04-redos",
            "severity": "medium" if used else "low",
            "file": rel, "line": getattr(n, "lineno", 0), "function": "<module>",
            "message": (f"正则字面量含嵌套量词（灾难性回溯风险）：{n.value[:70]!r}"
                        + ("" if used else "；未确认直接用于 re.*，需人工核对")),
        })
    return out


# ────────────────────────────────────────────────────────────────────
# RSC-05 同模块不一致：模块为求值设了上限，但归一化/转换路径没有
# ────────────────────────────────────────────────────────────────────
def check_limit_inconsistency(tree, rel):
    out = []
    limits = _module_limits(tree)
    if not limits:
        return out
    for fn in ast.walk(tree):
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if not _self_recursive(fn):
            continue
        if _fn_has_budget(fn):
            continue
        out.append({
            "rule": "RSC-05-limit-inconsistency",
            "severity": "high",
            "file": rel, "line": fn.lineno, "function": fn.name,
            "message": (f"模块已定义上限常量 {limits}，但递归函数 {fn.name}() 未使用任何上限"
                        f" → 同一份数据走「有上限」路径安全、走此路径失控"),
            "module_limits": limits,
        })
    return out


CHECKS = [
    check_cartesian,
    check_recursion_no_budget,
    check_unbounded_read,
    check_redos,
    check_limit_inconsistency,
]


def main() -> int:
    root = Path(sys.argv[1] if len(sys.argv) > 1 else "/data/workspace/audit/src/src/autoforge")
    outdir = Path(sys.argv[2] if len(sys.argv) > 2 else "/data/workspace/audit/rounds/round-004/boundary")
    outdir.mkdir(parents=True, exist_ok=True)

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
        for c in CHECKS:
            try:
                findings += c(tree, rel)
            except Exception as e:  # noqa: BLE001
                print(f"[warn] {c.__name__} on {rel}: {e}", file=sys.stderr)

    sev = {"high": 0, "medium": 1, "low": 2}
    findings.sort(key=lambda x: (sev.get(x["severity"], 9), x["file"], x["line"]))
    (outdir / "boundary-findings.json").write_text(
        json.dumps({"findings": findings}, ensure_ascii=False, indent=2))
    from collections import Counter
    print(json.dumps({"files": files, "total": len(findings),
                      "by_severity": dict(Counter(f["severity"] for f in findings)),
                      "by_rule": dict(Counter(f["rule"] for f in findings))},
                     ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
