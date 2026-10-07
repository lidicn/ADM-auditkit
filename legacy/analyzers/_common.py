#!/usr/bin/env python3
"""共享 AST 辅助 —— 一处修，处处生效。

**为什么要有这个模块**：AF 二十轮里 `_chain()` 被复制进 10 个分析器，
同一个缺陷（BinOp receiver 返回空串）因此复制了 10 份；容器识别逻辑
同样散落各处且形态各异。PITFALLS N7 记过这个教训：
> 跨文件复制的 helper，一处有缺陷等于处处有缺陷。

本模块收录**所有分析器共用**的判据，新增规则请先来这里找现成的。

收录内容：
  - `_chain()`           调用链还原（含 BinOp/下标/调用结果 receiver）
  - `container_inits()`  容器字段识别，**覆盖全部四种声明形态**
  - `has_removal_path()` 容器是否有删除路径（区分"累加型"与"映射型"）
  - `is_bounded()`       容器是否有界化
"""
from __future__ import annotations

import ast
import re

CONTAINER_FUNCS = {"dict", "list", "deque", "set", "defaultdict", "OrderedDict",
                   "field", "defaultdict"}
CONTAINER_TYPES = {"list[", "dict[", "set[", "List[", "Dict[", "Set[",
                   "tuple[", "Tuple[", "deque[", "frozenset["}

#: 有界化证据：deque(maxlen=)、类内 max_* 字段、尾部裁剪
BOUNDED_RE = re.compile(
    r"(?i)(deque\s*\(\s*[^)]*maxlen|maxlen\s*=|\bmax_\w+\s*[:=]|"
    r"\b\w+\s*=\s*\w+\[-|del\s+\w+\s*\[\s*:|\.trim\s*\(|\.popleft\s*\()")

REMOVAL_RE = re.compile(
    r"(?i)(self\.\w+\.(pop|popitem|clear|remove|discard)\b|del\s+self\.\w+\s*\[)")


def _chain(n: ast.Call) -> str:
    """还原调用名，如 `os.replace(...)` → `os.replace`。

    首版在 receiver 不是简单 Name 时返回 `""`（`(p/"x").write_text()`、
    `arr[0].save()` 全被丢弃）→ 10 个分析器集体漏检。
    现改为**保留已收集的属性链**，至少能匹配方法名（PITFALLS N7）。
    """
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
        if parts:
            return ".".join(reversed(parts))
    return ""


def _is_empty_container(node: ast.AST) -> bool:
    """该初值表达式是否产生一个**空容器**。

    覆盖三种写法：
      - 字面量：`[]` `{}` `set()`
      - 构造函数无参：`list()` `dict()` `deque()` `defaultdict()`
      - dataclass：`field(default_factory=list)` —— `field` 不在容器函数表里时
        **整个 dataclass 字段品类静默漏检**（AF BUG-21 的同形问题，PITFALLS N8）
    """
    if isinstance(node, (ast.List, ast.Dict, ast.Set, ast.ListComp, ast.DictComp)):
        return True
    if isinstance(node, ast.Call):
        name = _chain(node)
        base = name.split(".")[-1]
        if base in CONTAINER_FUNCS:
            return True
        # field(default_factory=list/dict/deque)
        if base == "field":
            for kw in node.keywords:
                if kw.arg == "default_factory":
                    return _is_empty_container(kw.value)
    return False


def container_inits(scope: ast.AST) -> dict[str, int]:
    """收集作用域内所有**容器字段/变量** → {名字: 行号}。

    这是全工作流最容易漏的一处，历史上漏过三种形态：
      1. `self.X = []`                        (Assign + Attribute)
      2. `self.X: list[str] = []`             (AnnAssign + Attribute) ← BUG-01 的写法
      3. `X: list[str] = field(default=...)`  (AnnAssign + Name, dataclass)
      4. `X = []`                             (Assign + Name, 模块级)
    前三种各自在不同分析器里漏过，现在统一收口。
    """
    out: dict[str, int] = {}
    for n in ast.walk(scope):
        # ── AnnAssign（带注解）──
        if isinstance(n, ast.AnnAssign):
            tgt = n.target
            # 2) self.X: list[str] = []
            if isinstance(tgt, ast.Attribute) and isinstance(tgt.value, ast.Name) \
                    and tgt.value.id == "self":
                ann = ast.unparse(n.annotation) if n.annotation else ""
                if any(t in ann for t in CONTAINER_TYPES):
                    out.setdefault(tgt.attr, n.lineno)
                    continue
                if n.value is not None and _is_empty_container(n.value):
                    out.setdefault(tgt.attr, n.lineno)
                continue
            # 3) dataclass 字段：X: list[str] = field(...)
            if isinstance(tgt, ast.Name):
                ann = ast.unparse(n.annotation) if n.annotation else ""
                if any(t in ann for t in CONTAINER_TYPES):
                    out.setdefault(tgt.id, n.lineno)
        # ── Assign（无注解）──
        elif isinstance(n, ast.Assign):
            if n.value is not None and _is_empty_container(n.value):
                for t in n.targets:
                    if isinstance(t, ast.Attribute) and isinstance(t.value, ast.Name) \
                            and t.value.id == "self":
                        out.setdefault(t.attr, n.lineno)
                    elif isinstance(t, ast.Name):
                        out.setdefault(t.id, n.lineno)
    return out


def has_removal_path(scope_src: str, name: str) -> bool:
    """该**具体容器**是否有删除路径。

    有进有出的容器（如 code store 的 create/consume）不是"单调累加"，
    报它属于假阳性。判据必须**按容器名**，不能按类 ——
    早期版本用类级判定，导致同类中真正无界的容器被连坐跳过
    （AF BUG-18 的 records 就是这样被漏掉的）。
    """
    if not name:
        return False
    return bool(re.search(
        rf"(?i)self\.{re.escape(name)}\.(pop|popitem|clear|remove|discard)\b"
        rf"|del\s+self\.{re.escape(name)}\s*\[", scope_src))


def is_bounded(scope_src: str, name: str) -> bool:
    """该容器是否有界化证据（deque(maxlen) / max_* / 尾部裁剪 / trim）。"""
    if not name:
        return False
    pats = [
        rf"self\.{re.escape(name)}\s*=\s*deque\([^)]*maxlen",
        rf"self\.{re.escape(name)}\s*=\s*self\.{re.escape(name)}\[-",
        rf"del\s+self\.{re.escape(name)}\s*\[\s*:",
        rf"while\s+len\(\s*self\.{re.escape(name)}\s*\)\s*>",
        rf"if\s+len\(\s*self\.{re.escape(name)}\s*\)\s*>",
        rf"self\.{re.escape(name)}\.popleft\s*\(",
        rf"\bmax_\w*{re.escape(name)}\b",
    ]
    return any(re.search(p, scope_src, re.I) for p in pats)
