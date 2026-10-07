#!/usr/bin/env python3
"""L1 引擎契约层 —— BaseRule / BaseAuditMode / Finding / RuleRegistry。

这是四层架构里**唯一定义接口**的模块：

    L0 基础设施   core/* + selftest/*（现有，不动）
    L1 多模式引擎 engine/（本模块定契约；static_ast_mode.py 是 Phase 1 唯一实现）
    L2 项目适配   projects/<name>/adapter/（声明式 focus.yaml + profile_cache.json）
    L3 规则层     rules/generic/ + rules/project/<name>/（YAML + Python 双形态）

三条铁律：
  1. 本模块项目无关、规则无关：不 import core/*，不认识任何具体项目。
  2. 注册期 fail-closed（校验不过不进注册表）；执行期 fail-open（单文件/单规则
     异常不中断整轮）。两个语义分属 loader / mode，互不混淆。
  3. 规则的唯一出口是 Finding；规则只看一棵 AST（tree）+ 画像（profile）+ 适配（adapter）。
"""
from __future__ import annotations

import ast
import re
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

#: 8 种审计模式（Phase 1 只实现 static_ast，其余留接口）
VALID_MODES = (
    "static_ast", "cross_lang_text", "graph_reachability", "contract_verify",
    "dynamic_injection", "mutation_test", "dep_supply_chain", "config_audit",
)
VALID_SEVERITIES = ("critical", "high", "medium", "low")
VALID_STATUS = ("draft", "testing", "active", "deprecated", "broken")
#: 默认参与审计的状态（draft 未定稿、deprecated 已退役、broken 自检失败）
DEFAULT_ACTIVE_STATUS = ("active", "testing")
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.\-]*$")


class RuleError(Exception):
    """规则层错误基类。"""


class RuleValidationError(RuleError):
    """注册期校验失败（fail-closed：这类规则不进注册表）。"""


class ModeUnavailable(RuleError):
    """该审计模式 Phase 1 尚未实现。"""


def normalize_severity(value) -> str:
    """宽容归一：未知严重度回落 medium（用于接收旧 findings）。"""
    v = str(value or "").strip().lower()
    return v if v in VALID_SEVERITIES else "medium"


def at_or_above(severity, floor) -> bool:
    """severity 是否达到/超过 floor（critical 最高）。floor=None 表示不过滤。"""
    if floor is None:
        return True
    s = SEVERITY_ORDER.get(normalize_severity(severity))
    f = SEVERITY_ORDER.get(normalize_severity(floor))
    if s is None or f is None:
        return True
    return s <= f


@dataclass
class Finding:
    """单条发现 —— 规则层 → 引擎 → 报告 的唯一数据形态。"""

    rule_id: str
    file: str
    line: int
    severity: str
    title: str
    detail: str
    evidence: str = ""

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: Mapping[str, Any] | None) -> "Finding":
        """兼容旧分析器 JSON 的字段命名差异（rule/rule_id、path/file、message/detail…）。"""
        d = d or {}
        return cls(
            rule_id=str(d.get("rule_id") or d.get("rule") or "?"),
            file=str(d.get("file") or d.get("path") or ""),
            line=int(d.get("line") or 0),
            severity=normalize_severity(d.get("severity")),
            title=str(d.get("title") or d.get("name") or ""),
            detail=str(d.get("detail") or d.get("message") or ""),
            evidence=str(d.get("evidence") or d.get("snippet") or ""),
        )


class BaseRule:
    """L3 规则插件基类。子类**必须**实现 run()，否则注册报错（验收 5）。

    属性契约（§0）：
        id / name / applies_to / mode / severity / status / version / tests
    契约方法：
        run(tree, profile, adapter) -> list[Finding]
    """

    #: 中间抽象层置 True 可跳过收集；具体规则保持 False
    abstract: bool = False

    id: str = ""
    name: str = ""
    description: str = ""
    applies_to: list = []          # 空列表 = 所有项目
    mode: str = "static_ast"
    severity: str = "medium"
    status: str = "draft"
    version: str = "0.0.0"
    tests: dict = {}               # {"dirty": [{"name","code"}], "clean": [...]}

    def run(self, tree, profile, adapter) -> list:
        raise NotImplementedError(f"{type(self).__name__} 未实现 run()")


def implements_run(cls) -> bool:
    """是否真正实现了 run（排除 BaseRule.run 自身与非子类）。"""
    return (isinstance(cls, type) and issubclass(cls, BaseRule)
            and getattr(cls, "run", None) is not BaseRule.run)


def validate_rule_meta(rule) -> None:
    """注册期元数据校验（fail-closed）。"""
    if not isinstance(rule, BaseRule):
        raise RuleValidationError(f"不是 BaseRule 实例: {type(rule).__name__}")
    rid = getattr(rule, "id", "")
    if not isinstance(rid, str) or not ID_RE.match(rid or ""):
        raise RuleValidationError(f"规则 id 非法: {rid!r}（需匹配 {ID_RE.pattern}）")
    if not str(getattr(rule, "name", "") or "").strip():
        raise RuleValidationError(f"{rid}: name 不能为空")
    if getattr(rule, "mode", "") not in VALID_MODES:
        raise RuleValidationError(f"{rid}: mode 非法 {getattr(rule, 'mode', '')!r}，可选 {VALID_MODES}")
    if getattr(rule, "severity", "") not in VALID_SEVERITIES:
        raise RuleValidationError(f"{rid}: severity 非法 {getattr(rule, 'severity', '')!r}，可选 {VALID_SEVERITIES}")
    if getattr(rule, "status", "") not in VALID_STATUS:
        raise RuleValidationError(f"{rid}: status 非法 {getattr(rule, 'status', '')!r}，可选 {VALID_STATUS}")
    if not isinstance(getattr(rule, "version", ""), str) or not str(rule.version).strip():
        raise RuleValidationError(f"{rid}: version 不能为空")
    applies = getattr(rule, "applies_to", None)
    if not isinstance(applies, (list, tuple)) or any(not isinstance(a, str) for a in applies):
        raise RuleValidationError(f"{rid}: applies_to 必须是字符串列表（空列表=所有项目）")
    if not implements_run(type(rule)):
        raise RuleValidationError(f"{rid}: 未实现 run()（BaseRule 子类必须实现 run）")


def rule_summary(rule) -> dict:
    """CLI `auditkit rules list` 的行数据。"""
    return {
        "id": getattr(rule, "id", ""),
        "name": getattr(rule, "name", ""),
        "mode": getattr(rule, "mode", ""),
        "applies_to": list(getattr(rule, "applies_to", []) or []),
        "status": getattr(rule, "status", ""),
        "severity": getattr(rule, "severity", ""),
        "version": getattr(rule, "version", ""),
    }


# ── AST 便利函数（引擎层公共件；legacy/analyzers/_common.py 保持不动）────────
def call_chain(node: ast.Call) -> str:
    """还原调用链：`os.replace(...)` → `os.replace`；`(p/"x").write_text()` → `write_text`。

    与 legacy/analyzers/_common._chain 语义一致（保留已收集的属性链，不返回空串）。
    两份并存是 §2.2 约束的结果：core/* 不许改；Phase 2 把 core 侧改为复用本函数。
    """
    func = getattr(node, "func", None)
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        parts = []
        cur = func
        while isinstance(cur, ast.Attribute):
            parts.append(cur.attr)
            cur = cur.value
        if isinstance(cur, ast.Name):
            parts.append(cur.id)
        return ".".join(reversed(parts))
    return ""


def attach_unit(tree, source: str, path: str):
    """把 source/path 附着到 AST 根节点（供 regex 匹配与 evidence 取行）。"""
    try:
        tree.source = source
        tree.path = path
    except Exception:  # 极端实现不支持属性附着时静默降级
        pass
    return tree


def parse_unit(source: str, path: str = "<memory>") -> ast.Module:
    """解析并附着 source/path —— loader 自检与 mode 执行都走这里。"""
    tree = ast.parse(source, filename=path)
    return attach_unit(tree, source, path)


def source_line(tree, lineno: int) -> str:
    src = getattr(tree, "source", "") or ""
    lines = src.splitlines()
    if 0 < lineno <= len(lines):
        return lines[lineno - 1]
    return ""


def node_source(tree, node) -> str:
    """取节点源码片段；无 source 时用 ast.unparse 兜底。"""
    src = getattr(tree, "source", "") or ""
    if src:
        try:
            seg = ast.get_source_segment(src, node)
            if seg:
                return seg
        except Exception:
            pass
    try:
        return ast.unparse(node)          # Python ≥ 3.9
    except Exception:
        return ""


# ── L2 适配（engine 提供类型，数据在 projects/<name>/adapter/）────────────
class BaseAdapter:
    """项目适配基类：画像缓存、关注点、专属工具配置的访问入口。"""

    project: str = ""
    focus: list = []

    def extra_roots(self, repo_path) -> list:
        return []

    def is_focus(self, item) -> bool:
        return item in (self.focus or [])

    def severity_floor(self):
        return None

    def profile(self):
        return None


class NullAdapter(BaseAdapter):
    """无项目上下文时的默认适配（规则自检、临时目录扫描都用它）。"""

    project = ""


class ProjectAdapter(BaseAdapter):
    """由 loader.load_adapter 从 focus.yaml + profile_cache.json 构造。"""

    def __init__(self, project: str, focus=(), focus_rules=(), extra_roots=(),
                 severity_floor=None, tools=None, profile=None, root=None):
        self.project = project
        self.focus = list(focus or [])
        self.focus_rules = list(focus_rules or [])
        self._extra_roots = [str(x) for x in (extra_roots or [])]
        self._severity_floor = severity_floor
        self.tools = dict(tools or {})
        self._profile = profile
        self.root = Path(root) if root else None

    def extra_roots(self, repo_path) -> list:
        base = Path(repo_path)
        out = []
        for rel in self._extra_roots:
            p = Path(rel)
            out.append(p if p.is_absolute() else base / p)
        return out

    def is_focus(self, item) -> bool:
        return item in self.focus or item in self.focus_rules

    def severity_floor(self):
        return self._severity_floor

    def profile(self):
        return self._profile


class BaseAuditMode:
    """L1 审计模式基类（8 种之一）。Phase 1 只有 static_ast 有实现。"""

    name: str = ""

    def applies_to(self, profile) -> bool:
        """该模式是否适用于此画像。"""
        return True

    def run(self, repo_path, profile, adapter, rules) -> list:
        raise NotImplementedError(f"模式 {self.name or type(self).__name__} 未实现")


class RuleRegistry:
    """规则注册表：唯一 id、元数据合法、按项目/模式/状态筛选。"""

    def __init__(self, rules: Iterable[BaseRule] | None = None):
        self._rules: dict = {}
        for r in (rules or []):
            self.register(r)

    def register(self, rule, *, replace: bool = False) -> BaseRule:
        validate_rule_meta(rule)                      # 未实现 run() 在这里报错
        rid = rule.id
        if rid in self._rules and not replace:
            raise RuleValidationError(
                f"规则 id 重复: {rid}（已注册 {type(self._rules[rid]).__name__}）")
        self._rules[rid] = rule
        return rule

    def register_class(self, cls, *, replace: bool = False) -> BaseRule:
        if not isinstance(cls, type) or not issubclass(cls, BaseRule):
            raise RuleValidationError(f"不是 BaseRule 子类: {cls!r}")
        if not implements_run(cls):
            raise RuleValidationError(f"{getattr(cls, '__name__', cls)} 未实现 run()，拒绝注册")
        return self.register(cls(), replace=replace)

    def get(self, rule_id: str, default=None):
        return self._rules.get(rule_id, default)

    def remove(self, rule_id: str) -> None:
        self._rules.pop(rule_id, None)

    def ids(self) -> list:
        return list(self._rules)

    def select(self, project=None, mode=None, statuses=DEFAULT_ACTIVE_STATUS) -> list:
        """按 applies_to / mode / status 筛选。

        applies_to == [] 表示所有项目（§0 契约）；statuses=None 表示不过滤状态。
        """
        out = []
        for r in self._rules.values():
            if statuses is not None and r.status not in statuses:
                continue
            if mode is not None and r.mode != mode:
                continue
            if project is not None and r.applies_to and project not in r.applies_to:
                continue
            out.append(r)
        return out

    def __contains__(self, rule_id) -> bool:
        return rule_id in self._rules

    def __len__(self) -> int:
        return len(self._rules)

    def __iter__(self):
        return iter(self._rules.values())
