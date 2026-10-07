#!/usr/bin/env python3
"""engine —— L1 多模式引擎 + L3 契约层。

对外只导出契约类型；加载器（engine.loader）与模式实现（engine.static_ast_mode）
按需 import，避免无谓的加载开销。
"""
from .base import (
    BaseAdapter, BaseAuditMode, BaseRule, Finding, ModeUnavailable, NullAdapter,
    ProjectAdapter, RuleError, RuleRegistry, RuleValidationError, DEFAULT_ACTIVE_STATUS,
)
from .profile import Gates, Languages, ProjectProfile

__all__ = [
    "BaseAdapter", "BaseAuditMode", "BaseRule", "Finding", "ModeUnavailable",
    "NullAdapter", "ProjectAdapter", "RuleError", "RuleRegistry", "RuleValidationError",
    "DEFAULT_ACTIVE_STATUS", "Gates", "Languages", "ProjectProfile",
]
