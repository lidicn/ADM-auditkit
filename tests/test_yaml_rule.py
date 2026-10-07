#!/usr/bin/env python3
"""YAML 声明式规则单测：schema、match 语义、dirty/clean 自检、broken 标记。"""
from __future__ import annotations

import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from engine import loader  # noqa: E402
from engine.base import RuleValidationError  # noqa: E402
from engine.profile import ProjectProfile  # noqa: E402
from engine.base import NullAdapter  # noqa: E402


def _raises(exc, fn, *a, **kw):
    try:
        fn(*a, **kw)
    except exc as e:
        return e
    raise AssertionError(f"{exc.__name__} 未被抛出")


MINIMAL = {
    "id": "y.min", "name": "最小规则", "match": {"call": ["eval"]},
    "tests": {"dirty": [{"name": "d", "code": "eval(x)"}],
              "clean": [{"name": "c", "code": "y=1"}]},
}


def _rule(doc=None, **over):
    d = dict(doc or MINIMAL)
    d.update(over)
    return loader.parse_yaml_rule(d, origin="<test>")


def _run(rule, code, path="<test>"):
    from engine.base import parse_unit
    return rule.run(parse_unit(code, path), ProjectProfile.empty(), NullAdapter())


# ── schema ────────────────────────────────────────────────────────────
def test_parse_yaml_rule_minimal_fields():
    r = _rule()
    assert (r.id, r.name, r.mode, r.severity) == ("y.min", "最小规则", "static_ast", "medium")
    assert r.status == "active" and r.version == "1.0.0" and r.applies_to == []


def test_parse_yaml_rule_defaults():
    r = _rule(description="d", applies_to=None, version=None, status=None, severity=None)
    assert r.description == "d" and r.version == "1.0.0" and r.status == "active"
    assert r.severity == "medium" and r.origin == "<test>"


def test_parse_yaml_rule_rejects_missing_id():
    d = dict(MINIMAL); d.pop("id")
    assert "id" in str(_raises(RuleValidationError, loader.parse_yaml_rule, d))


def test_parse_yaml_rule_rejects_missing_name():
    d = dict(MINIMAL); d.pop("name")
    assert "name" in str(_raises(RuleValidationError, loader.parse_yaml_rule, d))


def test_parse_yaml_rule_rejects_missing_match():
    d = dict(MINIMAL); d.pop("match")
    assert "match" in str(_raises(RuleValidationError, loader.parse_yaml_rule, d))


def test_parse_yaml_rule_rejects_unknown_mode():
    e = _raises(RuleValidationError, _rule, mode="no_such_mode")
    # parse 阶段存疑则注册/自检阶段必拦
    if not isinstance(e, RuleValidationError):
        raise AssertionError
    assert "mode" in str(e)


def test_parse_yaml_rule_rejects_unknown_severity():
    e = _raises(RuleValidationError, _rule, severity="fatal")
    assert "severity" in str(e)


def test_parse_yaml_rule_rejects_unknown_match_key():
    assert "match" in str(_raises(RuleValidationError, _rule, match={"bogus": ["x"]}))


def test_parse_yaml_rule_rejects_invalid_regex():
    e = _raises(RuleValidationError, _rule, match={"regex": ["("]})
    assert "regex" in str(e)


def test_parse_yaml_rule_applies_to_string_or_list():
    assert _rule(applies_to="solo").applies_to == ["solo"]
    assert _rule(applies_to=["a", "b"]).applies_to == ["a", "b"]


# ── 运行语义 ──────────────────────────────────────────────────────────
def test_yaml_rule_dirty_hit_fields():
    r = _rule(severity="high", description="危险调用")
    got = _run(r, "def f(x):\n    return eval(x)\n", "pkg/a.py")
    assert len(got) == 1
    f = got[0]
    assert (f.rule_id, f.file, f.line, f.severity, f.title) == ("y.min", "pkg/a.py", 2, "high", "最小规则")
    assert "危险调用" in f.detail and "eval(x)" in f.evidence


def test_yaml_rule_clean_code_no_findings():
    r = _rule()
    assert _run(r, "def f(x):\n    return x + 1\n") == []


def test_yaml_rule_call_list_is_or():
    r = _rule(match={"call": ["eval", "exec"]})
    assert len(_run(r, "exec(src)")) == 1 and len(_run(r, "eval(src)")) == 1
    assert _run(r, "safe(src)") == []


def test_yaml_rule_call_matches_method_tail():
    r = _rule(match={"call": ["call_tool"]})
    assert len(_run(r, "session.call_tool('x')")) == 1
    assert len(_run(r, "(p / 'y').call_tool('x')")) == 1
    assert _run(r, "call_toolish('x')") == []


def test_yaml_rule_attr_match():
    r = _rule(match={"attr": ["dangerous"]})
    assert len(_run(r, "obj.dangerous()")) == 1
    assert _run(r, "obj.safe()") == []


def test_yaml_rule_name_match():
    r = _rule(match={"name": ["secret_key"]})
    assert len(_run(r, "secret_key = get()")) == 1
    assert _run(r, "other = get()") == []


def test_yaml_rule_type_match():
    r = _rule(match={"type": ["JoinedStr"]})
    assert len(_run(r, 'x = f"{y}"')) == 1
    assert _run(r, 'x = "y"') == []


def test_yaml_rule_regex_only_scans_lines():
    r = _rule(match={"regex": ["TODO\\s*HACK"]})
    got = _run(r, "# TODO HACK\nx = 1\n# TODO   HACK here\n")
    assert [f.line for f in got] == [1, 3]
    assert all(f.evidence.startswith("#") for f in got)


def test_yaml_rule_group_and_semantics():
    r = _rule(match={"call": ["eval"], "regex": ["dangerous"]})
    assert len(_run(r, "y = dangerous(eval(x))")) == 1
    assert _run(r, "y = eval(x)") == []      # 无 regex 线索 ⇒ 组内 AND 不成立


def test_yaml_rule_test_samples_accept_plain_strings():
    r = _rule(tests={"dirty": ["eval(x)"], "clean": ["y = 1"]})
    results = loader.run_rule_tests(r)
    assert [x.ok for x in results] == [True, True]
    assert results[0].name == "sample-0"


# ── 文件级加载 + 自检标记 ─────────────────────────────────────────────
def _yaml_file(tmp: Path, text: str) -> Path:
    p = tmp / "r.yaml"
    p.write_text(text, encoding="utf-8")
    return p


def test_yaml_file_end_to_end_active_rule():
    tmp = Path(tempfile.mkdtemp())
    _yaml_file(tmp, """
id: y.file
name: 文件级规则
applies_to: [demo]
mode: static_ast
severity: low
status: active
version: "2.0.0"
match: {call: [eval]}
tests:
  dirty: [{name: d, code: "eval(x)"}]
  clean: [{name: c, code: "y=1"}]
""")
    report = loader.load_rules([tmp])
    rule = report.registry.get("y.file")
    assert rule is not None and rule.status == "active" and rule.applies_to == ["demo"]
    assert report.rules_for(project="demo")[0].id == "y.file"
    assert report.rules_for(project="other") == []


def test_yaml_file_missing_tests_marked_broken():
    tmp = Path(tempfile.mkdtemp())
    _yaml_file(tmp, "id: y.notests\nname: 无样本\nmatch: {call: [eval]}\n")
    report = loader.load_rules([tmp])
    assert report.registry.get("y.notests") is None
    assert "no_tests" in [f.kind for f in report.failures["y.notests"]]
    assert report.broken["y.notests"].status == "broken"


def test_yaml_file_dirty_miss_marked_broken():
    tmp = Path(tempfile.mkdtemp())
    _yaml_file(tmp, """
id: y.miss
name: 不命中
match: {call: [eval]}
tests:
  dirty: [{name: d, code: "y = 1"}]
  clean: [{name: c, code: "z = 2"}]
""")
    report = loader.load_rules([tmp])
    assert report.registry.get("y.miss") is None
    assert "dirty_miss" in [f.kind for f in report.failures["y.miss"]]


def test_yaml_file_clean_hit_marked_broken():
    tmp = Path(tempfile.mkdtemp())
    _yaml_file(tmp, """
id: y.fp
name: 误报
match: {call: [eval]}
tests:
  dirty: [{name: d, code: "eval(x)"}]
  clean: [{name: c, code: "eval(y)"}]
""")
    report = loader.load_rules([tmp])
    assert report.registry.get("y.fp") is None
    assert "clean_hit" in [f.kind for f in report.failures["y.fp"]]
    assert report.broken["y.fp"].status == "broken"
