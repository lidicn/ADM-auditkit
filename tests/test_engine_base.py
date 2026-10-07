#!/usr/bin/env python3
"""engine/base.py + engine/profile.py + static_ast_mode 的契约单测。"""
from __future__ import annotations

import json
import sys
import tempfile
import types
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from engine.base import (  # noqa: E402
    DEFAULT_ACTIVE_STATUS, BaseAuditMode, BaseRule, Finding, ModeUnavailable,
    NullAdapter, ProjectAdapter, RuleError, RuleRegistry, RuleValidationError,
    at_or_above, call_chain, implements_run, node_source, normalize_severity,
    parse_unit, rule_summary, source_line, validate_rule_meta,
)
from engine.profile import DEFAULT_SKIP_DIRS, Gates, Languages, ProjectProfile, as_profile  # noqa: E402


def _raises(exc, fn, *a, **kw):
    try:
        fn(*a, **kw)
    except exc as e:
        return e
    raise AssertionError(f"{exc.__name__} 未被抛出")


class _RuleOk(BaseRule):
    id, name = "test.ok", "测试规则"
    description = "仅用于单测"
    applies_to = []
    mode = "static_ast"
    severity = "low"
    status = "active"
    version = "1.0.0"

    def run(self, tree, profile, adapter):
        return []


class _RuleNoRun(BaseRule):
    id, name = "test.norun", "缺 run"
    mode, severity, status, version = "static_ast", "low", "active", "1.0.0"


class _RuleAF(BaseRule):
    id, name = "test.af", "仅 AF"
    applies_to = ["AutoForge"]
    mode, severity, status, version = "static_ast", "low", "active", "1.0.0"

    def run(self, tree, profile, adapter):
        return []


class _RuleOtherMode(_RuleOk):
    id = "test.other_mode"
    mode = "cross_lang_text"


class _RuleDraft(_RuleOk):
    id, status = "test.draft", "draft"


class _RuleBroken(_RuleOk):
    id, status = "test.broken", "broken"


# ── Finding ───────────────────────────────────────────────────────────
def test_finding_to_dict_roundtrip():
    f = Finding("r1", "a.py", 3, "high", "标题", "详情", "证据")
    d = f.to_dict()
    assert set(d) == {"rule_id", "file", "line", "severity", "title", "detail", "evidence"}
    f2 = Finding.from_dict(d)
    assert (f2.rule_id, f2.file, f2.line, f2.severity, f2.title, f2.detail, f2.evidence) == \
           ("r1", "a.py", 3, "high", "标题", "详情", "证据")


def test_finding_from_legacy_dict_keys():
    f = Finding.from_dict({"rule": "old.1", "path": "x/y.py", "line": "7",
                           "severity": "HIGH", "name": "旧标题", "message": "旧详情",
                           "snippet": "旧证据"})
    assert f.rule_id == "old.1" and f.file == "x/y.py" and f.line == 7
    assert f.severity == "high" and f.title == "旧标题" and f.detail == "旧详情"
    assert f.evidence == "旧证据"


def test_normalize_severity_and_at_or_above():
    assert normalize_severity("CRITICAL") == "critical"
    assert normalize_severity("weird") == "medium"
    assert at_or_above("critical", "medium") is True
    assert at_or_above("low", "medium") is False
    assert at_or_above("low", None) is True


# ── RuleRegistry / 校验 ────────────────────────────────────────────────
def test_registry_rejects_rule_without_run():
    reg = RuleRegistry()
    e = _raises(RuleValidationError, reg.register, _RuleNoRun())
    assert "run" in str(e)


def test_registry_rejects_empty_id():
    class _R(_RuleOk):
        id = ""
    e = _raises(RuleValidationError, RuleRegistry().register, _R())
    assert "id" in str(e)


def test_registry_rejects_unknown_mode():
    class _R(_RuleOk):
        id, mode = "test.badmode", "no_such_mode"
    assert "mode" in str(_raises(RuleValidationError, RuleRegistry().register, _R()))


def test_registry_rejects_unknown_severity():
    class _R(_RuleOk):
        id, severity = "test.badsev", "fatal"
    assert "severity" in str(_raises(RuleValidationError, RuleRegistry().register, _R()))


def test_registry_rejects_unknown_status():
    class _R(_RuleOk):
        id, status = "test.badstatus", "wip"
    assert "status" in str(_raises(RuleValidationError, RuleRegistry().register, _R()))


def test_registry_rejects_non_rule_object():
    assert "BaseRule" in str(_raises(RuleValidationError, RuleRegistry().register, object()))


def test_register_class_requires_run():
    reg = RuleRegistry()
    e = _raises(RuleValidationError, reg.register_class, _RuleNoRun)
    assert "run" in str(e)
    assert reg.register_class(_RuleOk) is not None and len(reg) == 1


def test_registry_register_get_len_iter():
    reg = RuleRegistry([_RuleOk()])
    assert len(reg) == 1 and "test.ok" in reg
    assert reg.get("test.ok").id == "test.ok" and reg.get("nope") is None
    assert [r.id for r in reg] == ["test.ok"] and reg.ids() == ["test.ok"]
    reg.remove("test.ok")
    assert len(reg) == 0


def test_registry_duplicate_id_rejected_replace_allowed():
    reg = RuleRegistry([_RuleOk()])

    class _Dup(_RuleOk):
        pass
    assert "重复" in str(_raises(RuleValidationError, reg.register, _Dup()))
    assert reg.register(_Dup(), replace=True) is not None and len(reg) == 1


def test_registry_select_applies_to_empty_means_all():
    reg = RuleRegistry([_RuleOk()])          # applies_to == []
    assert len(reg.select(project="AutoForge")) == 1
    assert len(reg.select(project="whatever")) == 1


def test_registry_select_applies_to_specific_project():
    reg = RuleRegistry([_RuleAF(), _RuleOk()])
    got = {r.id for r in reg.select(project="AutoForge")}
    assert got == {"test.af", "test.ok"}
    got = {r.id for r in reg.select(project="doubao-butler")}
    assert got == {"test.ok"}


def test_registry_select_by_mode():
    reg = RuleRegistry([_RuleOk(), _RuleOtherMode()])
    assert {r.id for r in reg.select(mode="static_ast")} == {"test.ok"}
    assert {r.id for r in reg.select(mode="cross_lang_text")} == {"test.other_mode"}


def test_registry_select_by_status_excludes_draft_broken():
    reg = RuleRegistry([_RuleOk(), _RuleDraft(), _RuleBroken()])
    assert {r.id for r in reg.select()} == {"test.ok"}
    assert set(DEFAULT_ACTIVE_STATUS) == {"active", "testing"}
    assert len(reg.select(statuses=None)) == 3


def test_validate_rule_meta_accepts_valid_rule():
    validate_rule_meta(_RuleOk())            # 不抛即通过
    s = rule_summary(_RuleOk())
    assert s == {"id": "test.ok", "name": "测试规则", "mode": "static_ast",
                 "applies_to": [], "status": "active", "severity": "low",
                 "version": "1.0.0"}


def test_implements_run_detection():
    assert implements_run(_RuleOk) is True
    assert implements_run(_RuleNoRun) is False
    assert implements_run(BaseRule) is False
    assert implements_run("not a class") is False


def test_rule_summary_fields():
    s = rule_summary(_RuleAF())
    assert s["applies_to"] == ["AutoForge"] and s["id"] == "test.af"


# ── BaseAuditMode / AST 便利函数 ──────────────────────────────────────
def test_base_audit_mode_default_contract():
    m = BaseAuditMode()
    assert m.applies_to(None) is True
    assert "未实现" in str(_raises(NotImplementedError, m.run, ".", None, None, []))


def test_call_chain_variants():
    tree = parse_unit("os.replace(a, b)\n(p / 'x').write_text(t)\narr[0].save()\nfoo()\n")
    calls = [n for n in __import__("ast").walk(tree) if isinstance(n, __import__("ast").Call)]
    chains = sorted(call_chain(c) for c in calls)
    assert chains == ["foo", "os.replace", "save", "write_text"]


def test_parse_unit_attaches_source_and_path():
    t = parse_unit("x = 1\n", "a.py")
    assert getattr(t, "source") == "x = 1\n" and getattr(t, "path") == "a.py"
    assert source_line(t, 1) == "x = 1" and source_line(t, 9) == ""


def test_node_source_and_source_line():
    import ast
    t = parse_unit("def f():\n    return g(1)\n", "b.py")
    call = [n for n in ast.walk(t) if isinstance(n, ast.Call)][0]
    assert node_source(t, call) == "g(1)"
    t2 = parse_unit("x = 1\n", "c.py")
    assert node_source(t2, t2.body[0]) == "x = 1"


# ── Adapter ───────────────────────────────────────────────────────────
def test_null_adapter_defaults():
    a = NullAdapter()
    assert a.project == "" and a.extra_roots(".") == [] and a.is_focus("x") is False
    assert a.severity_floor() is None and a.profile() is None


def test_project_adapter_extra_roots_and_focus():
    with tempfile.TemporaryDirectory() as td:
        repo = Path(td)
        (repo / "scripts").mkdir()
        ad = ProjectAdapter("AutoForge", focus=["a"], focus_rules=["r1"],
                            extra_roots=["scripts", "missing"], severity_floor="medium",
                            root=repo / "adapter")
        assert [p.name for p in ad.extra_roots(repo)] == ["scripts", "missing"]
        assert ad.is_focus("a") and ad.is_focus("r1") and not ad.is_focus("b")
        assert ad.severity_floor() == "medium"
        abs_ad = ProjectAdapter("x", extra_roots=[str(repo / "scripts")])
        assert abs_ad.extra_roots(repo)[0].is_absolute()


# ── Profile ───────────────────────────────────────────────────────────
def test_languages_file_count_int_or_dict():
    assert Languages.from_dict({"files": 12}).file_count() == 12
    assert Languages.from_dict({"files": {"python": 3, "ts": 2}}).file_count() == 5
    assert Languages().file_count() == 0


def test_profile_from_dict_keeps_unknown_keys():
    p = ProjectProfile.from_dict({"languages": {"primary": "python"}, "weird": 1})
    assert p.raw == {"weird": 1} and p.primary_language == "python"
    assert p.to_dict()["weird"] == 1


def test_profile_python_root_prefers_python_packages():
    with tempfile.TemporaryDirectory() as td:
        repo = Path(td)
        (repo / "src" / "pkg").mkdir(parents=True)
        (repo / "src" / "top").mkdir(parents=True)
        p = ProjectProfile.from_dict({"python_packages": [{"path": "src/pkg"}]})
        assert p.python_root(repo).name == "pkg"


def test_profile_python_root_layout_fallback():
    with tempfile.TemporaryDirectory() as td:
        repo = Path(td)
        (repo / "app").mkdir()
        p = ProjectProfile.empty()
        assert p.python_root(repo).name == "app"
        (repo / "app").rmdir()
        assert p.python_root(repo) == repo


def test_profile_extra_gate_roots():
    with tempfile.TemporaryDirectory() as td:
        repo = Path(td)
        (repo / "tools").mkdir()
        (repo / "scripts").mkdir()
        p = ProjectProfile.from_dict({"gates": {
            "self_check_scripts": ["tools/check_x.py"],
            "ci": [{"path": "scripts"}, {"path": "other"}]}})
        got = sorted(x.name for x in p.extra_gate_roots(repo))
        assert got == ["scripts", "tools"]


def test_profile_empty_and_json_roundtrip():
    p = ProjectProfile.empty("X", "/tmp/x")
    d = json.loads(json.dumps(p.to_dict(), ensure_ascii=False))
    q = as_profile(d)
    assert q.name == "X" and q.repo_root == "/tmp/x" and q.has_python is True
    assert isinstance(q.gates, Gates) and isinstance(q.languages, Languages)
    assert as_profile(None).name == "" and as_profile(p) is p


# ── StaticAstMode / AnalyzerBridge（验收 12）──────────────────────────
def test_static_ast_mode_runs_rules_over_repo():
    from engine.loader import YamlRule
    from engine.static_ast_mode import StaticAstMode
    with tempfile.TemporaryDirectory() as td:
        repo = Path(td)
        (repo / "src").mkdir()
        (repo / "src" / "app.py").write_text("def f(x):\n    return eval(x)\n", encoding="utf-8")
        rule = YamlRule(id="t.eval", name="eval", match={"call": ["eval"]},
                        tests={"dirty": [{"code": "eval(x)"}], "clean": [{"code": "y=1"}]})
        mode = StaticAstMode(include_legacy=False)
        got = mode.run(repo, ProjectProfile.empty(), NullAdapter(), [rule])
        assert len(got) == 1 and got[0].rule_id == "t.eval" and got[0].line == 2
        assert got[0].file.endswith("app.py") and mode.diagnostics == []


def test_static_ast_mode_skips_bad_syntax_file():
    from engine.loader import YamlRule
    from engine.static_ast_mode import StaticAstMode
    with tempfile.TemporaryDirectory() as td:
        repo = Path(td)
        (repo / "broken.py").write_text("def f(:\n", encoding="utf-8")
        rule = YamlRule(id="t.any", name="any", match={"type": ["Module"]},
                        tests={"dirty": [{"code": "x=1"}], "clean": [{"code": ""}]})
        rule.tests = {"dirty": [{"name": "d", "code": "x = 1"}], "clean": [{"name": "c", "code": ""}]}
        mode = StaticAstMode(include_legacy=False)
        assert mode.run(repo, ProjectProfile.empty(), NullAdapter(), [rule]) == []
        assert any("语法错误" in d for d in mode.diagnostics)


def test_static_ast_mode_scope_includes_adapter_extra_roots():
    from engine.static_ast_mode import StaticAstMode
    with tempfile.TemporaryDirectory() as td:
        repo = Path(td)
        (repo / "src").mkdir()
        (repo / "scripts").mkdir()
        ad = ProjectAdapter("X", extra_roots=["scripts"])
        mode = StaticAstMode(include_legacy=False)
        roots = [p.name for p in mode.scope_roots(repo, ProjectProfile.empty(), ad)]
        assert "src" in roots and "scripts" in roots


def test_analyzer_bridge_maps_legacy_findings():
    from engine.static_ast_mode import AnalyzerBridge
    bridge = AnalyzerBridge(core_dir=Path(tempfile.gettempdir()))
    bridge._mod = types.SimpleNamespace(
        run_analyzer=lambda s, t, extra=None: {"findings": [
            {"rule": "legacy.r", "path": "a.py", "line": 5, "severity": "HIGH",
             "name": "旧标题", "message": "旧详情", "snippet": "旧证据"}]})
    got = bridge.run_script(Path("x.py"), Path("."))
    assert len(got) == 1 and isinstance(got[0], Finding)
    assert got[0].rule_id == "legacy.r" and got[0].file == "a.py" and got[0].line == 5
    assert got[0].severity == "high" and got[0].evidence == "旧证据"


def test_analyzer_bridge_missing_core_raises():
    from engine.static_ast_mode import AnalyzerBridge
    bridge = AnalyzerBridge(core_dir=Path(tempfile.mkdtemp()) / "nope")
    assert bridge.analyzer_scripts() == []
    assert "未找到" in str(_raises(FileNotFoundError, bridge.registry_module))


def test_get_mode_registry():
    from engine.static_ast_mode import PHASE2_MODES, StaticAstMode, get_mode
    assert isinstance(get_mode("static_ast"), StaticAstMode)
    for name in PHASE2_MODES:
        assert "Phase 2" in str(_raises(ModeUnavailable, get_mode, name))
    assert "未知" in str(_raises(ModeUnavailable, get_mode, "nope"))
