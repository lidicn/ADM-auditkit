#!/usr/bin/env python3
"""engine/helpers.py —— 通用 AST 原语（去项目化）。

来源：元宝 v2 贡献包（AutoForge 20 轮 + memory-agent 20 轮审计沉淀，共 176 条 lessons）。
本文件把那些"用错一次就得出错误结论"的原语集中到一处，供所有 L3 规则 import。

**每条原语都对应一次真实事故**，改动前请先读对应的 lesson。

与 v2 包的差异：
  - 不包含 Finding 类（使用 engine.base.Finding）
  - 不包含 Dimension 基类（使用 engine.base.BaseRule）
  - 其余原语函数完整保留
"""
from __future__ import annotations

import ast
import pathlib
import re
from typing import Any, Iterator

# ── 1. unparse：判定 / 展示 / 区间 ─────────────────────────────────────


def full_unparse(node: ast.AST) -> str:
    """**存在性判定用**：完整源码，不截断。

    事故（lesson 64 / SC-01）：用截断版 unparse 判"函数体内是否含 X"，
    实测漏检率 **79%**（28 个带闸函数只认出 6 个），且**无任何报错**。
    """
    try:
        return ast.unparse(node)
    except Exception:
        return ""


def code_unparse(node: ast.AST) -> str:
    """**顺序/区间判定用**：剥离 docstring 后再 unparse。

    事故（lesson 167）：docstring 里的字样被当成第一处命中，
    把 `body[a.end():b.start()]` 的区间带偏 ⇒ 判据 0 命中。

    分级：存在性判据 docstring 污染假阳性率 0%（可用 full_unparse）；
    **顺序/区间判据必须用本函数。**
    """
    try:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef,
                             ast.ClassDef, ast.Module)):
            parts = []
            for child in node.body:
                if (isinstance(child, ast.Expr)
                        and isinstance(child.value, ast.Constant)
                        and isinstance(child.value.value, str)):
                    continue
                parts.append(ast.unparse(child))
            return "\n".join(parts)
        return ast.unparse(node)
    except Exception:
        return ""


def brief(node: ast.AST, limit: int = 120) -> str:
    """**展示用**：截断。禁止用于任何判定（lesson 64）。"""
    try:
        return ast.unparse(node)[:limit]
    except Exception:
        return ""


# ── 2. 遍历：作用域感知 vs 穿透 ──────────────────────────────────────

_SCOPE_NODES = (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)


def own_walk(node: ast.AST) -> Iterator[ast.AST]:
    """作用域感知遍历：遇到新的函数/类/Lambda **停止下钻**。

    事故（AutoForge 第二轮）：`ast.walk` 穿透嵌套函数，把内层闭包的 return
    误报成外层缺陷，627 条命中里 620 条是误报。
    """
    stack = list(getattr(node, "body", [node]))
    while stack:
        cur = stack.pop(0)  # FIFO：保持源码顺序（lesson 7：LIFO 会打乱顺序）
        yield cur
        if isinstance(cur, _SCOPE_NODES):
            continue  # 不下钻子作用域
        stack[:0] = list(ast.iter_child_nodes(cur))


def all_walk(node: ast.AST) -> Iterator[ast.AST]:
    """穿透遍历（找所有函数定义时用）。判定前请优先试 own_walk。"""
    return ast.walk(node)


# ── 3. 调用名解析 ────────────────────────────────────────────────────


def call_name(node: ast.AST) -> str:
    """取调用的**末段**名字：`a.b.c()` → `c`。

    注意 lesson 4 / SC-04：`json.dump` 会被 `json.dumps` 的子串匹配命中，
    所以凡匹配调用名一律用本函数取末段后**全等比较**，不要用 `in`。
    """
    if not isinstance(node, ast.Call):
        return ""
    f = node.func
    if isinstance(f, ast.Attribute):
        return f.attr
    if isinstance(f, ast.Name):
        return f.id
    return ""


def call_full(node: ast.AST) -> str:
    """取调用全名：`a.b.c()` → `a.b.c`。"""
    try:
        return ast.unparse(node.func)
    except Exception:
        return ""


def calls_in(node: ast.AST, name: str) -> bool:
    """作用域内是否调用了 `name`（末段全等，非子串）。"""
    for n in own_walk(node):
        if isinstance(n, ast.Call) and call_name(n) == name:
            return True
    return False


# ── 4. 跨函数展开 ────────────────────────────────────────────────────


class CallGraph:
    """函数索引 + 跨函数展开。

    事故（lesson 44 / 51 / 65）：只认直接调用会漏掉 helper 封装的形态，
    以及"闸在被调用方"的情况——闸的检测必须做传递闭包。
    """

    def __init__(self, files: list[tuple[Any, ast.AST]]) -> None:
        self.index: dict[str, ast.AST] = {}
        for _p, tree in files:
            for fn in ast.walk(tree):
                if isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    self.index.setdefault(fn.name, fn)

    def resolve(self, call: ast.AST) -> list[ast.AST]:
        return [self.index[call_name(call)]] if call_name(call) in self.index else []

    def body_contains(self, node: ast.AST, pred, depth: int = 2) -> bool:
        """在自身 + 被调用方（depth 层）内查找谓词。"""
        try:
            if pred(full_unparse(node)):
                return True
        except Exception:
            pass
        if depth <= 0:
            return False
        for n in own_walk(node):
            if isinstance(n, ast.Call):
                for tgt in self.resolve(n):
                    if self.body_contains(tgt, pred, depth - 1):
                        return True
        return False


# ── 5. 留痕四叉判定 ──────────────────────────────────────────────────

_TRACE_PAT = re.compile(
    r"(logger\.|logging\.|print\(|_log\.|warnings?\.warn|"
    r"raise\s+\w+|"
    r"\w*(?:_counter|_count|fail(?:ed)?_count)\s*(\+=|=)|"
    r"\w*(?:errors?|problems?|unreadable|skipped|dropped)\s*\.append\()"
)


def has_trace(node: ast.AST) -> tuple[bool, str]:
    """异常/失败是否被"留痕"。**必须认四叉**（lesson 40 / 47 / 160）：

        ① 日志（logger/print/warn）
        ② raise
        ③ 计数（counter += 1）
        ④ **状态标志置位 / 记账列表 append**（比日志更强）

    只认 ① 会误判：AutoForge `af_auth._load_revoked_file` 用毒化标志
    （比日志强得多）、memory-agent `af_insight_queue._load` 用记账列表，
    连续两轮把它们误判成"无留痕"。
    """
    m = _TRACE_PAT.search(full_unparse(node))
    return (bool(m), m.group(0) if m else "")


def handlers_of(node: ast.AST) -> list[ast.ExceptHandler]:
    """取作用域内（不穿透嵌套函数）的 except handler。"""
    return [n for n in own_walk(node) if isinstance(n, ast.ExceptHandler)]


# ── 6. 文件加载与路径脱敏 ────────────────────────────────────────────


def load_files(root, exclude: tuple[str, ...] = ("__pycache__", ".git", "node_modules")):
    """加载源码 → [(path, tree)]。跳过不可解析文件（不静默，返回时过滤）。

    lesson 38 / SC-02：解析失败必须被看见——auditkit 的 selftest 曾全红，
    根因是样本带 BOM 抛 SyntaxError 被 20 个分析器的 except 静默吞掉。
    """
    out, skipped = [], []
    for p in sorted(pathlib.Path(root).rglob("*.py")):
        if any(x in str(p) for x in exclude):
            continue
        try:
            out.append((p, ast.parse(p.read_text(encoding="utf-8-sig", errors="ignore"))))
        except (SyntaxError, UnicodeDecodeError) as exc:
            skipped.append((p, str(exc)[:60]))
    return out, skipped


def rel_path(p, root=None) -> str:
    """相对化路径（报告脱敏，禁止硬编码绝对路径前缀）。"""
    sp = str(pathlib.Path(p))
    if root:
        sr = str(pathlib.Path(root))
        if sp.startswith(sr):
            return sp[len(sr):].lstrip("/")
    try:
        return str(pathlib.Path(sp).relative_to(pathlib.Path.cwd()))
    except ValueError:
        return sp


# ── 7. 严重度排序 ────────────────────────────────────────────────────

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


# ── 8. 函数遍历 ──────────────────────────────────────────────────────

def iter_funcs(files):
    """遍历 (path, fn, full_body)。"""
    for path, tree in files:
        for fn in ast.walk(tree):
            if isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
                yield path, fn, full_unparse(fn)
