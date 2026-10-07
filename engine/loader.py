#!/usr/bin/env python3
"""L3 规则加载器 —— 扫描 rules/，把 YAML 声明式 + Python 插件式归一成 BaseRule。

目录约定：
    rules/generic/              通用规则（所有项目）
    rules/project/<project>/    项目专属规则（applies_to 指向该项目）
两种形态：
    *.py    插件式：BaseRule 子类，实现 run(tree, profile, adapter)
    *.yaml  声明式：id/name/description/applies_to/mode/severity/match/tests
加载即自检（验收 6）：
    dirty 样本必须命中、clean 样本必须不命中；任一不过 → status="broken"
    且不进注册表（不参与审计），但保留在 report.broken 供人工查看原因。
"""
from __future__ import annotations

import ast
import importlib
import importlib.util
import re
import sys
import types
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Sequence

from .base import (
    BaseRule, Finding, NullAdapter, ProjectAdapter, RuleError, RuleRegistry,
    RuleValidationError, VALID_MODES, DEFAULT_ACTIVE_STATUS, implements_run,
    validate_rule_meta, normalize_severity, parse_unit, source_line, call_chain,
)
from .profile import ProjectProfile, as_profile

RULES_DIR_NAME = "rules"


# ── 路径与发现 ──────────────────────────────────────────────────────────
def default_rules_root() -> Path:
    return Path(__file__).resolve().parents[1] / RULES_DIR_NAME


def default_projects_root() -> Path:
    return Path(__file__).resolve().parents[1] / "projects"


def _ensure_sys_path() -> None:
    root = str(Path(__file__).resolve().parents[1])
    if root not in sys.path:
        sys.path.insert(0, root)


def is_rule_file(path) -> bool:
    p = Path(path)
    if p.suffix == ".py":
        return p.name == "__init__.py" or not p.name.startswith("_")
    return p.suffix in (".yaml", ".yml")


def discover_rule_files(roots: Sequence) -> list:
    """递归发现规则文件（generic + project/<name> 一并覆盖，验收 7）。"""
    seen, out = set(), []
    for root in roots:
        root = Path(root)
        if not root.exists():
            continue
        for p in sorted(root.rglob("*")):
            if not p.is_file() or not is_rule_file(p):
                continue
            if "__pycache__" in p.parts:
                continue
            key = str(p.resolve())
            if key in seen:
                continue
            seen.add(key)
            out.append(p)
    return out


def _as_roots(roots) -> list:
    if roots is None:
        return [default_rules_root()]
    if isinstance(roots, (str, Path)):
        return [Path(roots)]
    return [Path(r) for r in roots]


# ── 结果类型 ────────────────────────────────────────────────────────────
@dataclass
class RuleFailure:
    """source = 规则 id 或文件路径；kind 见各调用点。"""
    source: str
    kind: str
    message: str


@dataclass
class SampleResult:
    """单个 dirty/clean 样本的自检结果（`auditkit rules test` 直接打印）。"""
    kind: str          # "dirty" | "clean"
    name: str
    hits: int
    ok: bool
    message: str = ""
    fail_kind: str = ""   # no_tests / empty_sample / dirty_miss / clean_hit / exception


@dataclass
class LoadReport:
    registry: RuleRegistry = field(default_factory=RuleRegistry)
    broken: dict = field(default_factory=dict)      # rule_id -> BaseRule（status=broken）
    failures: dict = field(default_factory=dict)    # rule_id -> [RuleFailure]
    skipped: list = field(default_factory=list)     # 文件级跳过（import/empty/no_yaml…）

    def get(self, rule_id):
        return self.registry.get(rule_id) or self.broken.get(rule_id)

    def active_ids(self) -> list:
        return sorted(self.registry.ids())

    def rules_for(self, project=None, mode=None, statuses=DEFAULT_ACTIVE_STATUS) -> list:
        return self.registry.select(project=project, mode=mode, statuses=statuses)

    def summary(self) -> dict:
        return {
            "loaded": self.active_ids(),
            "broken": sorted(self.broken),
            "failures": {k: [{"kind": f.kind, "message": f.message} for f in v]
                         for k, v in self.failures.items()},
            "skipped": [{"source": f.source, "kind": f.kind, "message": f.message}
                        for f in self.skipped],
            "counts": {"loaded": len(self.registry), "broken": len(self.broken),
                       "skipped": len(self.skipped)},
        }


# ── Python 插件式 ──────────────────────────────────────────────────────
_MOD_SEQ = 0


def load_py_module(path) -> types.ModuleType:
    global _MOD_SEQ
    _MOD_SEQ += 1
    path = Path(path)
    name = f"auditkit_rules_{_MOD_SEQ}_{path.stem}"
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ImportError(f"无法加载 {path}")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    try:
        spec.loader.exec_module(mod)
    except Exception:
        sys.modules.pop(name, None)
        raise
    return mod


def collect_rule_classes(module) -> list:
    """收集本文件定义的具体规则类（跳过抽象层与被 import 进来的类）。"""
    out = []
    for obj in vars(module).values():
        if not isinstance(obj, type) or not issubclass(obj, BaseRule):
            continue
        if obj is BaseRule or getattr(obj, "abstract", False):
            continue
        if getattr(obj, "__module__", "") != module.__name__:
            continue
        out.append(obj)
    return out


# ── YAML 声明式 ────────────────────────────────────────────────────────
class YamlRule(BaseRule):
    """YAML 声明式规则的运行形态（由 parse_yaml_rule 构造）。

    match 语义（§7-1）：
        match: {call: [eval, exec]}        # 单条件组，组内多判据 AND，判据内多模式 OR
        match: [{call: [...]}, {regex: ...}]  # 列表 = 组间 OR
    支持判据：call / attr / name / type / regex（regex 编译期校验）。
    """

    def __init__(self, id, name, description="", applies_to=None, mode="static_ast",
                 severity="medium", status="active", version="1.0.0", match=None,
                 tests=None, origin=""):
        self.id = str(id)
        self.name = str(name)
        self.description = str(description or "")
        self.applies_to = [str(a) for a in (applies_to or [])]
        self.mode = str(mode)
        self.severity = str(severity)
        self.status = str(status)
        self.version = str(version)
        self.tests = dict(tests or {})
        self.origin = str(origin)
        self._groups = _compile_match(match, self.origin)

    def run(self, tree, profile, adapter) -> list:
        src = getattr(tree, "source", "") or _unparse(tree)
        path = getattr(tree, "path", "<memory>")
        out, seen = [], set()
        for gi, group in enumerate(self._groups):
            crits = group["criteria"]
            if all(c["kind"] == "regex" for c in crits):        # 纯正则：按行扫
                for lineno, line in enumerate(src.splitlines(), 1):
                    if any(rx.search(line) for c in crits for rx in c["rx"]):
                        self._emit(out, seen, path, lineno, line, group, gi)
                continue
            for node in ast.walk(tree):                          # 节点型：按 AST 扫
                lineno = getattr(node, "lineno", None)
                if not lineno:
                    continue
                if not all(_criterion_matches(node, c, src) for c in crits):
                    continue
                self._emit(out, seen, path, lineno, source_line(tree, lineno), group, gi)
        return out

    def _emit(self, out, seen, path, lineno, line, group, gi):
        key = (lineno, gi)
        if key in seen:
            return
        seen.add(key)
        desc = _group_desc(group)
        detail = f"{self.description}（命中 {desc}）".strip()
        out.append(Finding(
            rule_id=self.id, file=str(path), line=int(lineno),
            severity=self.severity, title=self.name, detail=detail,
            evidence=str(line or "").strip()[:200],
        ))


def _unparse(tree) -> str:
    try:
        return ast.unparse(tree)
    except Exception:
        return ""


def _compile_match(match, origin: str) -> list:
    if match is None:
        raise RuleValidationError(f"{origin}: 缺少 match")
    groups = match if isinstance(match, list) else [match]
    out = []
    for g in groups:
        if not isinstance(g, dict) or not g:
            raise RuleValidationError(f"{origin}: match 必须是非空映射或映射列表")
        crits = []
        for key, val in g.items():
            kind = str(key).lower()
            if kind not in ("call", "attr", "name", "type", "regex"):
                raise RuleValidationError(f"{origin}: 未知 match 键 {key!r}（可选 call/attr/name/type/regex）")
            pats = val if isinstance(val, list) else [val]
            pats = [str(p) for p in pats]
            if not pats or not all(pats):
                raise RuleValidationError(f"{origin}: match.{kind} 不能为空")
            crit = {"kind": kind, "patterns": pats}
            if kind == "regex":
                try:
                    crit["rx"] = [re.compile(p) for p in pats]
                except re.error as e:
                    raise RuleValidationError(f"{origin}: match.regex 非法正则: {e}")
            crits.append(crit)
        out.append({"criteria": crits})
    return out


def _name_match(value: str, pattern: str) -> bool:
    return value == pattern or value.endswith("." + pattern)


def _criterion_matches(node, crit, src: str) -> bool:
    kind = crit["kind"]
    pats = crit["patterns"]
    if kind == "call":
        if not isinstance(node, ast.Call):
            return False
        chain = call_chain(node)
        return any(_name_match(chain, p) for p in pats)
    if kind == "attr":
        if not isinstance(node, ast.Attribute):
            return False
        return any(_name_match(node.attr, p) for p in pats)
    if kind == "name":
        if not isinstance(node, ast.Name):
            return False
        return any(node.id == p or node.id.endswith("." + p) for p in pats)
    if kind == "type":
        return type(node).__name__ in pats
    if kind == "regex":
        line = _line_of(src, getattr(node, "lineno", 0))
        return any(rx.search(line) for rx in crit["rx"])
    return False


def _line_of(src: str, lineno: int) -> str:
    lines = src.splitlines()
    return lines[lineno - 1] if 0 < lineno <= len(lines) else ""


def _group_desc(group) -> str:
    parts = []
    for c in group["criteria"]:
        parts.append(f"{c['kind']}={{{'|'.join(c['patterns'])}}}")
    return " 且 ".join(parts)


def parse_yaml_rule(doc, origin: str = "<memory>") -> YamlRule:
    """把一份 YAML 规则文档解析成 YamlRule（schema 校验 fail-closed）。"""
    if not isinstance(doc, dict):
        raise RuleValidationError(f"{origin}: 规则文档必须是映射")
    for key in ("id", "name", "match"):
        if not doc.get(key):
            raise RuleValidationError(f"{origin}: 缺少必填字段 {key}")
    tests = doc.get("tests") or {}
    if not isinstance(tests, dict):
        raise RuleValidationError(f"{origin}: tests 必须是映射")
    applies = doc.get("applies_to") or []
    if isinstance(applies, str):
        applies = [applies]
    rule = YamlRule(
        id=str(doc["id"]),
        name=str(doc["name"]),
        description=str(doc.get("description") or ""),
        applies_to=[str(a) for a in applies],
        mode=str(doc.get("mode") or "static_ast"),
        severity=str(doc.get("severity") or "medium"),
        status=str(doc.get("status") or "active"),
        version=str(doc.get("version") or "1.0.0"),
        match=doc["match"],
        tests=tests,
        origin=origin,
    )
    validate_rule_meta(rule)
    return rule


def _yaml_module():
    try:
        import yaml  # type: ignore
        return yaml
    except Exception:
        return None


# ── 加载期自检（dirty 必命中 / clean 必不命中）──────────────────────────
_EMPTY_PROFILE = ProjectProfile.empty()
_NULL_ADAPTER = NullAdapter()


def _sample_parts(item, index: int):
    if isinstance(item, str):
        return (f"sample-{index}", item)
    if isinstance(item, dict):
        return (str(item.get("name") or f"sample-{index}"), str(item.get("code") or ""))
    return (f"sample-{index}", str(item or ""))


def run_rule_tests(rule) -> list:
    """执行规则自带 dirty/clean 样本，返回逐样本结果（验收 6/10）。"""
    tests = getattr(rule, "tests", None)
    tests = tests if isinstance(tests, dict) else {}
    results = []
    for kind in ("dirty", "clean"):
        items = tests.get(kind) or []
        if not items:
            results.append(SampleResult(kind, "<missing>", 0, False,
                                        f"缺少 {kind} 测试样本", "no_tests"))
            continue
        for i, item in enumerate(items):
            name, code = _sample_parts(item, i)
            if not code.strip():
                results.append(SampleResult(kind, name, 0, False, "样本代码为空", "empty_sample"))
                continue
            try:
                tree = parse_unit(code, f"<rule-test:{getattr(rule, 'id', '?')}:{kind}:{name}>")
                found = rule.run(tree, _EMPTY_PROFILE, _NULL_ADAPTER) or []
            except Exception as e:
                results.append(SampleResult(kind, name, 0, False,
                                            f"运行异常: {type(e).__name__}: {e}", "exception"))
                continue
            hits = len(found)
            if kind == "dirty":
                ok = hits > 0
                results.append(SampleResult(kind, name, hits, ok,
                                            "" if ok else "dirty 样本未命中（规则可能失效）",
                                            "" if ok else "dirty_miss"))
            else:
                ok = hits == 0
                results.append(SampleResult(kind, name, hits, ok,
                                            "" if ok else f"clean 样本误报 {hits} 条",
                                            "" if ok else "clean_hit"))
    return results


# ── 摄取与加载 ─────────────────────────────────────────────────────────
def _mark_broken(rule, report, kind: str, message: str) -> None:
    rid = getattr(rule, "id", "") or type(rule).__name__
    try:
        rule.status = "broken"
    except Exception:
        pass
    report.broken[rid] = rule
    report.failures.setdefault(rid, []).append(RuleFailure(rid, kind, message))


def _ingest_rule(rule, report: LoadReport, *, validate: bool = True) -> None:
    rid = getattr(rule, "id", "") or type(rule).__name__
    try:
        validate_rule_meta(rule)
    except RuleValidationError as e:
        _mark_broken(rule, report, "meta", str(e))
        return
    if validate:
        results = run_rule_tests(rule)
        rule.test_results = results
        bad = [r for r in results if not r.ok]
        if bad:
            for r in bad:
                report.failures.setdefault(rid, []).append(RuleFailure(rid, r.fail_kind, r.message))
            _mark_broken(rule, report, "selftest", f"{len(bad)} 个样本自检未通过")
            return
    try:
        report.registry.register(rule, replace=False)
    except RuleValidationError as e:
        _mark_broken(rule, report, "duplicate_id", str(e))


def _ingest_class(cls, report: LoadReport, *, validate: bool = True) -> None:
    rid = getattr(cls, "id", "") or cls.__name__
    if not implements_run(cls):
        report.failures.setdefault(rid, []).append(
            RuleFailure(rid, "missing_run", f"{cls.__name__} 未实现 run()（BaseRule 子类必须实现 run）"))
        try:
            rule = cls()
            _mark_broken(rule, report, "missing_run", f"{cls.__name__} 未实现 run()")
        except Exception:
            report.broken.setdefault(rid, cls)
        return
    try:
        rule = cls()
    except Exception as e:
        report.failures.setdefault(rid, []).append(
            RuleFailure(rid, "init", f"{cls.__name__} 构造失败: {type(e).__name__}: {e}"))
        return
    _ingest_rule(rule, report, validate=validate)


def load_python_file(path, report: LoadReport, *, validate: bool = True) -> None:
    path = Path(path)
    try:
        module = load_py_module(path)
    except Exception as e:
        report.skipped.append(RuleFailure(str(path), "import", f"{type(e).__name__}: {e}"))
        return
    classes = collect_rule_classes(module)
    if not classes:
        report.skipped.append(RuleFailure(str(path), "empty", "文件中没有 BaseRule 子类"))
        return
    for cls in classes:
        _ingest_class(cls, report, validate=validate)


def load_yaml_file(path, report: LoadReport, *, validate: bool = True) -> None:
    path = Path(path)
    y = _yaml_module()
    if y is None:
        report.skipped.append(RuleFailure(str(path), "no_yaml", "缺少 pyyaml，YAML 规则不可用"))
        return
    try:
        docs = list(y.safe_load_all(path.read_text(encoding="utf-8")))
    except Exception as e:
        report.skipped.append(RuleFailure(str(path), "yaml_parse", f"{type(e).__name__}: {e}"))
        return
    for doc in docs:
        if doc is None:
            continue
        try:
            rule = parse_yaml_rule(doc, origin=str(path))
        except RuleValidationError as e:
            src = str(doc.get("id")) if isinstance(doc, dict) and doc.get("id") else str(path)
            report.failures.setdefault(src, []).append(RuleFailure(src, "yaml_schema", str(e)))
            report.broken[src] = doc
            continue
        _ingest_rule(rule, report, validate=validate)


def load_rules(roots=None, *, validate: bool = True) -> LoadReport:
    """扫描规则目录并加载（验收 6/7/8 的统一入口）。

    >>> report = load_rules()                      # 默认 <repo>/rules
    >>> report.rules_for(project="AutoForge")      # 按 applies_to 过滤
    """
    _ensure_sys_path()
    report = LoadReport()
    for root in _as_roots(roots):
        if not root.exists():
            report.skipped.append(RuleFailure(str(root), "missing_root", "规则目录不存在"))
            continue
        for path in discover_rule_files([root]):
            if path.suffix in (".yaml", ".yml"):
                load_yaml_file(path, report, validate=validate)
            else:
                load_python_file(path, report, validate=validate)
    return report


def test_rule_by_id(rule_id: str, roots=None):
    """单独跑某规则的 dirty/clean 自检（`auditkit rules test <id>`）。"""
    report = load_rules(roots, validate=False)
    rule = report.registry.get(rule_id) or report.broken.get(rule_id)
    if rule is None:
        raise KeyError(rule_id)
    return rule, run_rule_tests(rule)


def load_adapter(project_name: str, projects_root=None) -> ProjectAdapter:
    """读 L2 适配（focus.yaml + profile_cache.json）；目录缺失时返回空适配（fail-open）。"""
    root = Path(projects_root) if projects_root else default_projects_root()
    adir = root / project_name / "adapter"
    focus, profile = {}, None
    focus_path = adir / "focus.yaml"
    if focus_path.exists():
        y = _yaml_module()
        if y is None:
            raise RuleError("缺少 pyyaml，无法读取 focus.yaml")
        try:
            focus = y.safe_load(focus_path.read_text(encoding="utf-8")) or {}
        except Exception as e:
            raise RuleError(f"focus.yaml 解析失败: {e}")
    cache_path = adir / "profile_cache.json"
    if cache_path.exists():
        try:
            profile = ProjectProfile.load(cache_path, name=project_name)
        except Exception as e:
            raise RuleError(f"profile_cache.json 解析失败: {e}")
    return ProjectAdapter(
        project=project_name,
        focus=focus.get("focus") or [],
        focus_rules=focus.get("focus_rules") or [],
        extra_roots=focus.get("extra_roots") or [],
        severity_floor=focus.get("severity_floor"),
        tools=focus.get("tools") or {},
        profile=profile,
        root=adir,
    )
