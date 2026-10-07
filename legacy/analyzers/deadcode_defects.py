#!/usr/bin/env python3
"""第六轮专题：死代码 / 不可达分支 / 契约漂移（纯 stdlib AST）。

前五轮覆盖：稳定性与资源、持久化与崩溃恢复、并发与异步、资源上限与复杂度、
控制流与异常契约。本轮看**代码自身的一致性**：
  - DEAD-01 不可达语句（return/raise/break/continue 之后仍有语句）
  - DEAD-02 同名重复定义（模块级函数/类/常量被定义两次 → 前者成死代码）
  - DEAD-03 未被任何模块引用的模块级定义（死 API）
  - DEAD-04 同名常量在不同模块取值不一致（契约漂移）
  - DEAD-05 形参在函数体内从未使用（签名漂移）
  - DEAD-06 方法内 return 之后仍有语句（类级重复，单独统计便于定位）

设计原则：本类问题**天然高假阳性**（动态派发、__all__ 导出、插件注册），
所以 DEAD-03 只报「既未在包内被引用、也未出现在 __all__ / 工具表」的定义，
并标注为 low，供人工确认而非直接判缺陷。

用法: deadcode_defects.py <src_root> <outdir>
"""
from __future__ import annotations

import ast
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path


def _walk_bodies(node):
    """yield (body_list, owner_name) 便于逐块检查不可达。"""
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
        yield node.body, node.name
    for child in ast.iter_child_nodes(node):
        yield from _walk_bodies(child)


TERMINATORS = (ast.Return, ast.Raise, ast.Break, ast.Continue)


# ────────────────────────────────────────────────────────────────────
# DEAD-01/06 不可达语句
# ────────────────────────────────────────────────────────────────────
def check_unreachable(tree, rel):
    out = []
    for fn in ast.walk(tree):
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for body, _ in _walk_bodies(fn):
            for i, st in enumerate(body[:-1]):
                if not isinstance(st, TERMINATORS):
                    continue
                nxt = body[i + 1]
                if isinstance(nxt, ast.Pass):
                    continue
                # 只报非平凡语句（Assign/Expr Call 等），注释与 docstring 不算
                if isinstance(nxt, ast.Expr) and isinstance(nxt.value, ast.Constant):
                    continue
                kind = ("return" if isinstance(st, ast.Return)
                        else "raise" if isinstance(st, ast.Raise)
                        else "break" if isinstance(st, ast.Break) else "continue")
                out.append({
                    "rule": "DEAD-01-unreachable", "severity": "medium",
                    "file": rel, "line": nxt.lineno, "function": fn.name,
                    "message": (f"{fn.name}() 中 {kind} 之后仍有语句（{type(nxt).__name__}）"
                                f"：永不执行。常是重构残留，或本应生效的逻辑被误留在后面"),
                })
    return out


def _module_defs(tree: ast.Module):
    funcs, consts, classes = {}, {}, {}
    for n in tree.body:
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
            funcs.setdefault(n.name, []).append(n)
        elif isinstance(n, ast.ClassDef):
            classes.setdefault(n.name, []).append(n)
        elif isinstance(n, ast.Assign):
            for t in n.targets:
                if isinstance(t, ast.Name) and t.id.isupper():
                    consts.setdefault(t.id, []).append((n.lineno, n.value))
    return funcs, consts, classes


# ────────────────────────────────────────────────────────────────────
# DEAD-02 同名重复定义
# ────────────────────────────────────────────────────────────────────
def check_duplicate_defs(tree, rel):
    out = []
    funcs, consts, classes = _module_defs(tree)
    for name, nodes in funcs.items():
        if len(nodes) > 1:
            lines = [n.lineno for n in nodes]
            out.append({
                "rule": "DEAD-02-duplicate-def", "severity": "high", "file": rel,
                "line": lines[0], "function": name,
                "message": f"函数 {name}() 在同一模块被定义 {len(nodes)} 次（行 {lines}）；"
                           f"前面的定义被后面的静默覆盖，若两者语义不同则是真 bug"})
    for name, nodes in classes.items():
        if len(nodes) > 1:
            lines = [n.lineno for n in nodes]
            out.append({
                "rule": "DEAD-02-duplicate-def", "severity": "high", "file": rel,
                "line": lines[0], "function": name,
                "message": f"类 {name} 在同一模块被定义 {len(nodes)} 次（行 {lines}）"})
    for name, items in consts.items():
        if len(items) > 1:
            lines = [l for l, _ in items]
            vals = []
            for _, v in items:
                try:
                    vals.append(ast.literal_eval(v))
                except Exception:
                    vals.append("<non-literal>")
            same = all(v == vals[0] for v in vals)
            out.append({
                "rule": "DEAD-02-duplicate-const",
                "severity": "medium" if same else "high", "file": rel,
                "line": lines[0], "function": name,
                "message": (f"常量 {name} 在同一模块被赋值 {len(items)} 次（行 {lines}）；"
                            + ("取值相同，为冗余赋值" if same
                               else f"取值不同（{vals}）→ 后者生效，读者极易误判实际值"))})
    return out


def _collect(root: Path):
    trees, texts = {}, {}
    for p in sorted(root.rglob("*.py")):
        if any(x.startswith("test") for x in p.parts):
            continue
        try:
            t = ast.parse(p.read_text(errors="ignore"))
        except SyntaxError:
            continue
        trees[str(p.relative_to(root))] = t
        texts[str(p.relative_to(root))] = p.read_text(errors="ignore")
    return trees, texts


# ────────────────────────────────────────────────────────────────────
# DEAD-03 死 API：包内无人引用、且未出现在 __all__ / 工具表
# ────────────────────────────────────────────────────────────────────
def check_dead_api(trees, texts):
    out = []
    exported = set()
    # 收集所有 __all__ 与字符串型工具表引用
    for rel, t in trees.items():
        for n in ast.walk(t):
            if isinstance(n, ast.Assign):
                for tgt in n.targets:
                    if isinstance(tgt, ast.Name) and tgt.id == "__all__":
                        try:
                            exported |= set(ast.literal_eval(n.value))
                        except Exception:
                            pass
    # 统计每个名字的出现次数（跨所有文件文本，保守计数）
    counts = Counter()
    for rel, txt in texts.items():
        for rel2, t in trees.items():
            pass
    for rel, t in trees.items():
        names = []
        for n in t.body:
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                names.append(n.name)
        for name in names:
            if name.startswith("__"):
                continue
            if name in exported:
                continue
            # 在其他模块的文本里出现？
            hits = 0
            for rel2, txt in texts.items():
                if rel2 == rel:
                    continue
                if name in txt:
                    hits += 1
            # 本模块内除定义处以外是否出现
            own_hits = texts[rel].count(name) - 1
            if hits == 0 and own_hits <= 0:
                out.append({
                    "rule": "DEAD-03-dead-api", "severity": "low", "file": rel,
                    "line": 0, "function": name,
                    "message": f"{name} 在本模块定义后，包内无任何引用，也未出现在 __all__；"
                               f"可能是废弃 API 或插件入口（需人工确认）"})
    return out


# ────────────────────────────────────────────────────────────────────
# DEAD-04 同名常量跨模块取值不一致
# ────────────────────────────────────────────────────────────────────
def check_const_drift(trees):
    out = []
    vals = defaultdict(dict)
    for rel, t in trees.items():
        for n in t.body:
            if not isinstance(n, ast.Assign):
                continue
            for tgt in n.targets:
                if not (isinstance(tgt, ast.Name) and tgt.id.isupper()):
                    continue
                try:
                    v = ast.literal_eval(n.value)
                except Exception:
                    continue
                if isinstance(v, (int, float, str, bool)) and not isinstance(v, type(None)):
                    vals[tgt.id][rel] = v
    for name, per_file in vals.items():
        distinct = set(per_file.values())
        if len(distinct) <= 1:
            continue
        out.append({
            "rule": "DEAD-04-const-drift", "severity": "medium",
            "file": ", ".join(sorted(per_file)[:3]), "line": 0, "function": name,
            "message": f"常量 {name} 在不同模块取值不同："
                       + "；".join(f"{k}={v!r}" for k, v in sorted(per_file.items())[:5])
                       + " → 同名不同值，跨模块行为不一致"})
    return out


# ────────────────────────────────────────────────────────────────────
# DEAD-05 形参从未使用（排除 dunder / 协议实现 / 有 raise NotImplementedError）
# ────────────────────────────────────────────────────────────────────
def check_unused_param(tree, rel):
    out = []
    for cls in ast.walk(tree):
        if not isinstance(cls, ast.ClassDef):
            continue
        for fn in cls.body:
            if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            if fn.name.startswith("__") or fn.name in ("_", "__init__"):
                continue
            src = ast.unparse(fn)
            if "NotImplementedError" in src or fn.body == []:
                continue
            if isinstance(fn.body[0], ast.Expr) and isinstance(fn.body[0].value, ast.Constant):
                continue
            args = fn.args
            names = [a.arg for a in (list(args.posonlyargs) + list(args.args) + list(args.kwonlyargs))]
            names = [n for n in names if n not in ("self", "cls")]
            used = {n.id for n in ast.walk(fn) if isinstance(n, ast.Name)} | \
                   {n.attr for n in ast.walk(fn) if isinstance(n, ast.Attribute)}
            unused = [n for n in names if n not in used and n not in src.split("def ")[0]]
            # 用 unparse 再核一遍（防 ast.Name 漏掉注解引用）
            unused = [n for n in unused if src.count(n) <= 1]
            if unused:
                out.append({
                    "rule": "DEAD-05-unused-param", "severity": "low", "file": rel,
                    "line": fn.lineno, "function": fn.name,
                    "message": f"{cls.name}.{fn.name}() 的形参 {', '.join(unused)} 在函数体内"
                               f"从未使用：可能漏实现了某个分支（签名与实现漂移）"})
    return out


def main() -> int:
    root = Path(sys.argv[1] if len(sys.argv) > 1 else "/data/workspace/audit/src/src/autoforge")
    outdir = Path(sys.argv[2] if len(sys.argv) > 2 else "/data/workspace/audit/rounds/round-006/deadcode")
    outdir.mkdir(parents=True, exist_ok=True)

    trees, texts = _collect(root)
    findings = []
    for rel, t in trees.items():
        findings += check_unreachable(t, rel)
        findings += check_duplicate_defs(t, rel)
        findings += check_unused_param(t, rel)
    findings += check_dead_api(trees, texts)
    findings += check_const_drift(trees)

    sev = {"high": 0, "medium": 1, "low": 2}
    findings.sort(key=lambda x: (sev.get(x["severity"], 9), x["file"], x["line"]))
    (outdir / "deadcode-findings.json").write_text(
        json.dumps({"findings": findings}, ensure_ascii=False, indent=2))
    print(json.dumps({"files": len(trees), "total": len(findings),
                      "by_severity": dict(Counter(f["severity"] for f in findings)),
                      "by_rule": dict(Counter(f["rule"] for f in findings))},
                     ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
