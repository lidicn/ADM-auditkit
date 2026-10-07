#!/usr/bin/env python3
"""示例规则 —— 把既有分析器能力改造成规则插件（示范迁移路径）。

迁移三步（本文件就是模板）：
  1. **不复制** core/analyzers 的逻辑：用 importlib 包装 core/analyzers/_common.py
     的共享判据（container_inits / has_removal_path / is_bounded）。
  2. 把「分析器脚本 + 目录扫描」收缩成 run(tree, profile, adapter) -> list[Finding]：
     只处理一棵 AST，文件遍历交给 L1 引擎（engine/static_ast_mode.py）。
  3. 自带 dirty/clean 样本：加载期自动验证，dirty 必命中、clean 必不命中。
"""
from __future__ import annotations

import ast
import importlib.util
import re
from pathlib import Path

from engine.base import BaseRule, Finding, node_source

_GROWTH_RE = r"self\.{name}\.(append|extend|add|insert|update|setdefault)\b"


def _load_common():
    """包装 core/analyzers/_common.py —— 复用判据，零复制。"""
    path = Path(__file__).resolve().parents[2] / "core" / "analyzers" / "_common.py"
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
    version = "1.0.0"
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
            {"name": "has-removal-path", "code": (
                "class Store:\n"
                "    def __init__(self):\n"
                "        self.records = []\n"
                "    def add(self, x):\n"
                "        self.records.append(x)\n"
                "    def take(self):\n"
                "        return self.records.pop()\n")},
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
                if not re.search(_GROWTH_RE.format(name=re.escape(name)), scope_src, re.I):
                    continue                      # 没有增长动作，不报
                out.append(Finding(
                    rule_id=self.id,
                    file=str(getattr(tree, "path", "<memory>")),
                    line=int(lineno),
                    severity=self.severity,
                    title=self.name,
                    detail=(f"{node.name}.self.{name} 只进不出：无 pop/clear/del，"
                            f"也无 maxlen/max_* 界化证据"),
                    evidence=scope_src.splitlines()[0][:200] if scope_src else "",
                ))
        return out
