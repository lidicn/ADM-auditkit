#!/usr/bin/env python3
"""engine/loader.py 单测：发现、双形态、自检、applies_to、CLI 子命令。"""
from __future__ import annotations

import argparse
import contextlib
import importlib.util
import io
import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from engine import loader  # noqa: E402
from engine.base import RuleValidationError  # noqa: E402


def _raises(exc, fn, *a, **kw):
    try:
        fn(*a, **kw)
    except exc as e:
        return e
    raise AssertionError(f"{exc.__name__} 未被抛出")


GOOD_RULE = '''
from engine.base import BaseRule, Finding

class TmpGoodRule(BaseRule):
    id = "tmp.good"
    name = "临时规则"
    description = "命中 eval 调用"
    applies_to = []
    mode = "static_ast"
    severity = "high"
    status = "active"
    version = "1.0.0"
    tests = {
        "dirty": [{"name": "d1", "code": "def f(x):\\n    return eval(x)\\n"}],
        "clean": [{"name": "c1", "code": "def f(x):\\n    return x\\n"}],
    }

    def run(self, tree, profile, adapter):
        import ast
        out = []
        for n in ast.walk(tree):
            if isinstance(n, ast.Call) and getattr(n.func, "id", "") == "eval":
                out.append(Finding(self.id, getattr(tree, "path", ""), n.lineno,
                                   self.severity, self.name, "eval", "eval"))
        return out
'''

NORUN_RULE = '''
from engine.base import BaseRule

class TmpNoRunRule(BaseRule):
    id = "tmp.norun"
    name = "缺 run"
    mode, severity, status, version = "static_ast", "low", "active", "1.0.0"
    tests = {"dirty": [{"name": "d", "code": "x = 1"}], "clean": [{"name": "c", "code": "x = 2"}]}
'''

NOTESTS_RULE = '''
from engine.base import BaseRule

class TmpNoTestsRule(BaseRule):
    id = "tmp.notests"
    name = "无样本"
    mode, severity, status, version = "static_ast", "low", "active", "1.0.0"
    tests = {}
    def run(self, tree, profile, adapter):
        return []
'''

ALWAYS_EMPTY = '''
from engine.base import BaseRule

class TmpAlwaysEmptyRule(BaseRule):
    id = "tmp.always_empty"
    name = "永不命中"
    mode, severity, status, version = "static_ast", "low", "active", "1.0.0"
    tests = {"dirty": [{"name": "d", "code": "eval(x)"}], "clean": [{"name": "c", "code": "y=1"}]}
    def run(self, tree, profile, adapter):
        return []
'''

ALWAYS_HIT = '''
from engine.base import BaseRule, Finding

class TmpAlwaysHitRule(BaseRule):
    id = "tmp.always_hit"
    name = "总是命中"
    mode, severity, status, version = "static_ast", "low", "active", "1.0.0"
    tests = {"dirty": [{"name": "d", "code": "eval(x)"}], "clean": [{"name": "c", "code": "y=1"}]}
    def run(self, tree, profile, adapter):
        return [Finding(self.id, getattr(tree, "path", ""), 1, "low", self.name, "always", "")]
'''

RAISING_RULE = '''
from engine.base import BaseRule

class TmpRaisingRule(BaseRule):
    id = "tmp.raising"
    name = "运行即异常"
    mode, severity, status, version = "static_ast", "low", "active", "1.0.0"
    tests = {"dirty": [{"name": "d", "code": "eval(x)"}], "clean": [{"name": "c", "code": "y=1"}]}
    def run(self, tree, profile, adapter):
        raise RuntimeError("boom")
'''

ABSTRACT_RULE = '''
from engine.base import BaseRule

class TmpAbstractRule(BaseRule):
    abstract = True
    id = "tmp.abstract"
    name = "抽象层"
    def run(self, tree, profile, adapter):
        return []
'''

AF_RULE = '''
from engine.base import BaseRule

class TmpAfRule(BaseRule):
    id = "tmp.af"
    name = "仅 AF"
    applies_to = ["AutoForge"]
    mode, severity, status, version = "static_ast", "low", "active", "1.0.0"
    tests = {"dirty": [{"name": "d", "code": "eval(x)"}], "clean": [{"name": "c", "code": "y=1"}]}
    def run(self, tree, profile, adapter):
        import ast
        return [F for F in []] or ([1] if any(isinstance(n, __import__("ast").Call)
                for n in __import__("ast").walk(tree)) else [])
'''

DUP_A = GOOD_RULE.replace("tmp.good", "tmp.dup").replace("TmpGoodRule", "TmpDupA")
DUP_B = GOOD_RULE.replace("tmp.good", "tmp.dup").replace("TmpGoodRule", "TmpDupB")

YAML_RULE = """
id: tmp.yaml
name: YAML 临时规则
applies_to: []
mode: static_ast
severity: medium
status: active
version: "1.0.0"
match:
  call: [eval]
tests:
  dirty:
    - name: d
      code: |
        def f(x):
            return eval(x)
  clean:
    - name: c
      code: |
        def f(x):
            return x
"""


def _write(root: Path, rel: str, text: str) -> Path:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")
    return p


def _tmp_tree() -> Path:
    d = Path(tempfile.mkdtemp())
    return d


# ── 发现 ──────────────────────────────────────────────────────────────
def test_is_rule_file_filters_private_files():
    assert loader.is_rule_file(Path("a.py")) and loader.is_rule_file(Path("__init__.py"))
    assert loader.is_rule_file(Path("r.yaml")) and loader.is_rule_file(Path("r.yml"))
    assert not loader.is_rule_file(Path("_helper.py")) and not loader.is_rule_file(Path("r.txt"))


def test_discover_rule_files_finds_py_and_yaml():
    root = _tmp_tree()
    _write(root, "generic/a.py", GOOD_RULE)
    _write(root, "generic/_skip.py", GOOD_RULE)
    _write(root, "generic/r.yaml", YAML_RULE)
    _write(root, "project/demo/__init__.py", AF_RULE)
    found = [p.name for p in loader.discover_rule_files([root])]
    assert sorted(found) == ["__init__.py", "a.py", "r.yaml"]


# ── Python 插件式 ─────────────────────────────────────────────────────
def test_load_python_rule_ok_and_registered():
    root = _tmp_tree()
    _write(root, "generic/a.py", GOOD_RULE)
    report = loader.load_rules([root])
    rule = report.registry.get("tmp.good")
    assert rule is not None and rule.status == "active"
    assert rule.test_results and all(r.ok for r in rule.test_results)


def test_load_python_rule_missing_run_marked_broken():
    root = _tmp_tree()
    _write(root, "generic/a.py", NORUN_RULE)
    report = loader.load_rules([root])
    assert report.registry.get("tmp.norun") is None
    assert "tmp.norun" in report.broken
    kinds = [f.kind for f in report.failures["tmp.norun"]]
    assert "missing_run" in kinds


def test_load_python_rule_without_tests_marked_broken():
    root = _tmp_tree()
    _write(root, "generic/a.py", NOTESTS_RULE)
    report = loader.load_rules([root])
    assert report.registry.get("tmp.notests") is None
    kinds = [f.kind for f in report.failures["tmp.notests"]]
    assert "no_tests" in kinds


def test_load_python_rule_dirty_miss_marked_broken():
    root = _tmp_tree()
    _write(root, "generic/a.py", ALWAYS_EMPTY)
    report = loader.load_rules([root])
    assert report.registry.get("tmp.always_empty") is None
    kinds = [f.kind for f in report.failures["tmp.always_empty"]]
    assert "dirty_miss" in kinds and "selftest" in kinds


def test_load_python_rule_clean_hit_marked_broken():
    root = _tmp_tree()
    _write(root, "generic/a.py", ALWAYS_HIT)
    report = loader.load_rules([root])
    assert report.registry.get("tmp.always_hit") is None
    kinds = [f.kind for f in report.failures["tmp.always_hit"]]
    assert "clean_hit" in kinds


def test_load_python_rule_exception_marked_broken():
    root = _tmp_tree()
    _write(root, "generic/a.py", RAISING_RULE)
    report = loader.load_rules([root])
    kinds = [f.kind for f in report.failures["tmp.raising"]]
    assert "exception" in kinds and report.registry.get("tmp.raising") is None


def test_load_discovers_generic_and_project_rule_dirs():
    root = _tmp_tree()
    _write(root, "generic/a.py", GOOD_RULE)
    _write(root, "project/demo/__init__.py", AF_RULE)
    report = loader.load_rules([root])
    assert {"tmp.good", "tmp.af"} <= set(report.registry.ids())


def test_applies_to_filtering_via_rules_for():
    root = _tmp_tree()
    _write(root, "generic/a.py", GOOD_RULE)          # applies_to = []
    _write(root, "project/demo/__init__.py", AF_RULE)  # applies_to = ["AutoForge"]
    report = loader.load_rules([root])
    assert {r.id for r in report.rules_for(project="AutoForge")} == {"tmp.good", "tmp.af"}
    assert {r.id for r in report.rules_for(project="doubao-butler")} == {"tmp.good"}
    assert {r.id for r in report.rules_for(mode="static_ast")} == {"tmp.good", "tmp.af"}
    assert report.rules_for(mode="cross_lang_text") == []


def test_duplicate_rule_id_second_marked_broken():
    root = _tmp_tree()
    _write(root, "generic/a.py", DUP_A)
    _write(root, "generic/b.py", DUP_B)
    report = loader.load_rules([root])
    assert report.registry.get("tmp.dup") is not None          # 先到者保留
    kinds = [f.kind for f in report.failures.get("tmp.dup", [])]
    assert "duplicate_id" in kinds


def test_abstract_rule_class_skipped():
    root = _tmp_tree()
    _write(root, "generic/a.py", ABSTRACT_RULE)
    report = loader.load_rules([root])
    assert report.registry.ids() == [] and report.broken == {}
    assert any(f.kind == "empty" for f in report.skipped)


def test_rule_file_import_error_recorded_as_skipped():
    root = _tmp_tree()
    _write(root, "generic/a.py", "import nonexistent_module_xyz\n")
    report = loader.load_rules([root])
    assert any(f.kind == "import" for f in report.skipped)
    assert report.registry.ids() == []


def test_mixed_yaml_and_python_rules_loaded():
    root = _tmp_tree()
    _write(root, "generic/a.py", GOOD_RULE)
    _write(root, "generic/r.yaml", YAML_RULE)
    report = loader.load_rules([root])
    assert {"tmp.good", "tmp.yaml"} <= set(report.registry.ids())
    assert report.summary()["counts"]["loaded"] == 2


def test_missing_rules_root_recorded():
    report = loader.load_rules([Path(tempfile.mkdtemp()) / "nope"])
    assert any(f.kind == "missing_root" for f in report.skipped)


def test_run_rule_tests_result_shape_and_fail_kinds():
    root = _tmp_tree()
    _write(root, "generic/a.py", ALWAYS_HIT)
    report = loader.load_rules([root], validate=False)
    rule = report.registry.get("tmp.always_hit")
    results = loader.run_rule_tests(rule)
    assert [(r.kind, r.name, r.ok) for r in results] == [
        ("dirty", "d", True), ("clean", "c", False)]
    assert results[1].fail_kind == "clean_hit" and results[1].hits == 1


def test_test_rule_by_id_missing_raises_keyerror():
    _raises(KeyError, loader.test_rule_by_id, "no.such.rule", [Path(tempfile.mkdtemp())])


def test_loader_reports_missing_pyyaml():
    old = loader._yaml_module
    loader._yaml_module = lambda: None
    try:
        root = _tmp_tree()
        _write(root, "generic/r.yaml", YAML_RULE)
        report = loader.load_rules([root])
    finally:
        loader._yaml_module = old
    assert any(f.kind == "no_yaml" for f in report.skipped)
    assert report.registry.ids() == []


# ── 真实规则树（验收 13）──────────────────────────────────────────────
def test_real_rules_tree_example_rule_validates():
    report = loader.load_rules([ROOT / "rules"])
    rule = report.get("py.unbounded_container")
    assert rule is not None, report.summary()
    core_common = ROOT / "core" / "analyzers" / "_common.py"
    if core_common.exists():
        assert rule.status in ("active", "testing")
        assert all(r.ok for r in getattr(rule, "test_results", []))
    else:
        assert rule.status == "broken"
        msgs = " ".join(f.message for f in report.failures.get("py.unbounded_container", []))
        assert "_common" in msgs
    if loader._yaml_module() is not None:
        y = report.registry.get("py.dynamic_code_exec")
        assert y is not None and y.status == "active"
    # 项目规则：AutoForge 命中 applies_to 定向
    af = report.get("af.mcp_tool_no_timeout")
    assert af is not None and af.applies_to == ["AutoForge"]


# ── L2 adapter ────────────────────────────────────────────────────────
def test_load_adapter_reads_focus_and_profile_cache():
    root = _tmp_tree()
    _write(root, "AutoForge/adapter/focus.yaml",
           "project: AutoForge\nfocus: [a]\nfocus_rules: [r1]\nextra_roots: [scripts]\n"
           "severity_floor: medium\ntools: {semgrep: optional}\n")
    _write(root, "AutoForge/adapter/profile_cache.json",
           json.dumps({"languages": {"primary": "python", "files": {"python": 2}, "lines": 10},
                       "has_python": True, "frameworks": ["fastapi"]}))
    ad = loader.load_adapter("AutoForge", projects_root=root)
    assert ad.project == "AutoForge" and ad.focus == ["a"] and ad.focus_rules == ["r1"]
    assert [p.name for p in ad.extra_roots("/repo")] == ["scripts"]
    assert ad.severity_floor() == "medium" and ad.tools == {"semgrep": "optional"}
    assert ad.profile().primary_language == "python" and ad.profile().file_count() == 2


def test_load_adapter_missing_dir_returns_empty_adapter():
    ad = loader.load_adapter("nope", projects_root=Path(tempfile.mkdtemp()))
    assert ad.project == "nope" and ad.focus == [] and ad.profile() is None


# ── CLI（验收 9/10）───────────────────────────────────────────────────
def _auditkit_module():
    from importlib.machinery import SourceFileLoader
    loader = SourceFileLoader("auditkit_under_test", str(ROOT / "auditkit"))
    spec = importlib.util.spec_from_loader("auditkit_under_test", loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


def test_cli_rules_list_subcommand():
    mod = _auditkit_module()
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        rc = mod.cmd_rules(argparse.Namespace(rules_cmd="list", project=None, all=True, json=True))
    rows = json.loads(buf.getvalue())
    assert rc == 0 and isinstance(rows, list) and rows
    for key in ("id", "name", "mode", "applies_to", "status"):
        assert key in rows[0]
    ids = {r["id"] for r in rows}
    assert "py.dynamic_code_exec" in ids or "py.unbounded_container" in ids


def test_cli_rules_test_subcommand():
    mod = _auditkit_module()
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        rc = mod.cmd_rules(argparse.Namespace(rules_cmd="test", rule_id="py.dynamic_code_exec",
                                             json=False))
    out = buf.getvalue()
    assert rc == 0 and "PASS" in out and "dirty" in out and "clean" in out


def test_cli_rules_test_unknown_id_returns_2():
    mod = _auditkit_module()
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        rc = mod.cmd_rules(argparse.Namespace(rules_cmd="test", rule_id="no.such.id", json=False))
    assert rc == 2 and "未找到规则" in buf.getvalue()
