#!/usr/bin/env python3
"""示例规则 —— 把既有分析器能力改造成规则插件（示范迁移路径）。

迁移三步（本文件就是模板）：
  1. **不复制** legacy/analyzers 的逻辑：用 importlib 包装 legacy/analyzers/_common.py
     的共享判据（container_inits / has_removal_path / is_bounded）。
  2. 把「分析器脚本 + 目录扫描」收缩成 run(tree, profile, adapter) -> list[Finding]：
     只处理一棵 AST，文件遍历交给 L1 引擎（engine/static_ast_mode.py）。
  3. 自带 dirty/clean 样本：加载期自动验证，dirty 必命中、clean 必不命中。

v1.0.1：配套 legacy/_common.is_bounded 修复（注解赋值 `self.X: deque[T] =
deque(maxlen=)` 此前漏判，AutoForge round-005 把 af_bus.emitted（已有界）误报），
新增 clean 样本 bounded-deque-annotated 锁住该形态。
"""
from __future__ import annotations

import ast
import importlib.util
import re
from pathlib import Path

from engine.base import BaseRule, Finding, node_source

_GROWTH_RE = r"self\.{name}\.(append|extend|add|insert|update|setdefault)\b"

# 整体替换型容器：有 reset/clear 调用，说明是整体替换而非单调累加
_RESET_RE = r"self\.{name}\.(reset|clear)\b"

# v1.0.2（2026-10-12 memory-agent round-003 收敛）：周期方法开头的**赋值重置**
# （`self.X = []` / `{}` / `set()`）同样是"有进有出"的形态——
# identity.py:428 `self._needs_review = []` 每轮 reconcile 重置，
# 旧判据只认 reset/clear 调用，把这类误报成无界累加。
#
# 关键陷阱：`self.X = []` 在 `__init__` 里是**容器初始化**、在业务方法里才是
# **周期重置**，源码形状完全相同、语义相反。所以必须按 AST 判所在函数，
# 不能用正则（第一版用正则，dirty 样本的 __init__ 初始化被误杀 → 规则 broken）。
_INIT_METHODS = ("__init__", "__new__", "__post_init__")
_EMPTY_LITERALS = (ast.List, ast.Dict, ast.Set)


def _is_empty_literal(node: ast.AST) -> bool:
    if isinstance(node, _EMPTY_LITERALS):
        return True
    if isinstance(node, ast.Call):
        return getattr(node.func, "id", "") in ("list", "dict", "set")
    return False


def _has_assign_reset(cls_node: ast.ClassDef, name: str) -> bool:
    """非初始化方法里是否出现 `self.<name> = []` 这类整体赋值重置。"""
    for fn in ast.walk(cls_node):
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if fn.name in _INIT_METHODS:
            continue
        for sub in ast.walk(fn):
            if not isinstance(sub, ast.Assign):
                continue
            if not _is_empty_literal(sub.value):
                continue
            for target in sub.targets:
                if (isinstance(target, ast.Attribute) and target.attr == name
                        and isinstance(target.value, ast.Name)
                        and target.value.id == "self"):
                    return True
    return False


def _load_common():
    """包装 legacy/analyzers/_common.py —— 复用判据，零复制。"""
    path = Path(__file__).resolve().parents[2] / "legacy" / "analyzers" / "_common.py"
    if not path.exists():
        raise RuntimeError(f"缺少共享判据模块: {path}")
    spec = importlib.util.spec_from_file_location("auditkit_core_analyzers_common", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


try:
    _COMMON = _load_common()
    _COMMON_ERROR = ""
except Exception as _e:            # 缺 core 时降级为可诊断失败（自检会把它标 broken）
    _COMMON = None
    _COMMON_ERROR = f"{type(_e).__name__}: {_e}"


class UnboundedContainerRule(BaseRule):
    """类内容器只进不出且无界化证据 → 长时间运行会无界增长。"""

    id = "py.unbounded_container"
    name = "无界累加容器"
    description = "容器字段只进不出（无 pop/clear/del）且无 maxlen/max_* 等界化证据"
    applies_to = []
    mode = "static_ast"
    severity = "high"
    status = "active"
    version = "1.0.2"
    tests = {
        "dirty": [
            {"name": "append-no-removal", "code": (
                "class Store:\n"
                "    def __init__(self):\n"
                "        self.records = []\n"
                "    def add(self, x):\n"
                "        self.records.append(x)\n")},
        ],
        "clean": [
            {"name": "bounded-deque", "code": (
                "from collections import deque\n"
                "class Store:\n"
                "    def __init__(self):\n"
                "        self.records = deque(maxlen=100)\n"
                "    def add(self, x):\n"
                "        self.records.append(x)\n")},
            {"name": "bounded-deque-annotated", "code": (
                "from collections import deque\n"
                "class Bus:\n"
                "    def __init__(self):\n"
                "        self.emitted: deque[Event] = deque(maxlen=1000)\n"
                "    def add(self, x):\n"
                "        self.emitted.append(x)\n")},
            {"name": "has-removal-path", "code": (
                "class Store:\n"
                "    def __init__(self):\n"
                "        self.records = []\n"
                "    def add(self, x):\n"
                "        self.records.append(x)\n"
                "    def take(self):\n"
                "        return self.records.pop()\n")},
            {"name": "reset-by-assignment", "code": (
                "class Reconciler:\n"
                "    def __init__(self):\n"
                "        self.needs_review = []\n"
                "    def reconcile(self):\n"
                "        self.needs_review = []\n"
                "        return {}\n"
                "    def collect(self, x):\n"
                "        self.needs_review.append(x)\n")},
        ],
    }

    def run(self, tree, profile, adapter) -> list:
        if _COMMON is None:
            raise RuntimeError(f"规则依赖缺失（core/analyzers/_common.py）: {_COMMON_ERROR}")
        out = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.ClassDef):
                continue
            scope_src = node_source(tree, node) or ""
            for name, lineno in _COMMON.container_inits(node).items():
                if _COMMON.has_removal_path(scope_src, name):
                    continue                      # 有进有出，不是单调累加
                if _COMMON.is_bounded(scope_src, name):
                    continue                      # 已有界化证据
                # 整体替换型容器：有 reset/clear 调用，说明是整体替换而非单调累加
                if re.search(_RESET_RE.format(name=re.escape(name)), scope_src, re.I):
                    continue
                # v1.0.2：周期方法开头的赋值重置（self.X = []）同属"有进有出"
                # （AST 按所在函数判定，__init__ 里的同名赋值是初始化不算重置）
                if _has_assign_reset(node, name):
                    continue
                if not re.search(_GROWTH_RE.format(name=re.escape(name)), scope_src, re.I):
                    continue                      # 没有增长动作，不报
                # P2-2：生命周期启发式——Builder/Factory 类通常按调用构建即弃，
                # 与进程级单例同 severity 报出会稀释信号。降级为 low。
                severity = self.severity
                class_name = node.name.lower()
                if any(k in class_name for k in ("builder", "factory", "temp", "tmp")):
                    severity = "low"
                out.append(Finding(
                    rule_id=self.id,
                    file=str(getattr(tree, "path", "<memory>")),
                    line=int(lineno),
                    severity=severity,
                    title=self.name,
                    detail=(f"{node.name}.self.{name} 只进不出：无 pop/clear/del，"
                            f"也无 maxlen/max_* 界化证据"),
                    evidence=scope_src.splitlines()[0][:200] if scope_src else "",
                ))
        return out
