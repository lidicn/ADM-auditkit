"""py.bool_literal_string —— bool("false")/bool("true") 字面量读反用户意图。

来源：doubao-butler 第五期 DB139（round-150，high）：`butler/bus/inbox.py:236`
    `bool("false") == True`，**「不要覆盖静默」被读成「要」**——用户显式关闭被
    反转成开启。同族 DB120/123/137：`bool(d.get(k, True))` 对显式 `null` 得 False
    （与主动禁用不可区分）。

【缺陷形态】`bool(<非空字符串字面量>)` 恒为 True（Python truthiness：非空字符串
    即真），与字面量**语义**相反。`bool("false")` 本意是"false"，运行时却是 True。
    这是"形状像布尔、实为字符串"的典型读反。
    - 空串 `bool("")` 是 False（正确表达 false）→ **不报**；
    - 任意非布尔意图字符串 `bool("hello")` 罕见 → **不报**（避免误报）；
    - 只报"人类显然想表达布尔"的字面量集。

【判据】只判可机械坐实的形态：`bool()` 唯一实参是字符串常量，且其
    `strip().lower()` 属布尔意图集 {true,false,yes,no,on,off,0,1}。极窄、低误报。
    `bool(d.get(k, D))` 的 truthiness 陷阱（有害与否取决于默认值 D，见 PITFALLS
    通则 E"形态无罪，默认值才决定后果"）由 triage 跟进，本规则不收——否则会把
    无害的 D=False 一并误报。
"""
from __future__ import annotations

import ast

from engine.base import BaseRule, Finding, node_source

# 人类显然想表达布尔、却写成字符串常量的字面量集（lower 后匹配）
_BOOL_INTENT = {"true", "false", "yes", "no", "on", "off", "0", "1"}


class BoolLiteralStringRule(BaseRule):
    id = "py.bool_literal_string"
    name = "bool(布尔字符串字面量) 恒真读反语义"
    description = (
        'bool("false")/bool("true") 等：非空字符串恒为 True，与字面量语义相反，'
        "用户显式关闭被读成开启（如「不要覆盖静默」→「要」）"
    )
    applies_to = []
    mode = "static_ast"
    severity = "medium"
    status = "active"
    version = "1.0.0"
    intent = "discovery"

    tests = {
        "dirty": [
            {"name": "bool-false-string",
             "code": "def set_overwrite(d):\n"
                     "    overwrite = bool('false')\n"
                     "    return overwrite\n"},
            {"name": "bool-true-string",
             "code": "def flag():\n"
                     "    return bool('true')\n"},
            {"name": "bool-no-string",
             "code": "def enabled(d):\n"
                     "    return bool('no')\n"},
            {"name": "bool-zero-string",
             "code": "def on():\n"
                     "    return bool('0')\n"},
        ],
        "clean": [
            {"name": "empty-string-is-false",
             "code": "def f():\n    return bool('')\n"},
            {"name": "arbitrary-string",
             "code": "def f():\n    return bool('hello')\n"},
            {"name": "variable",
             "code": "def f(x):\n    return bool(x)\n"},
            {"name": "coerced-int",
             "code": "def f(s):\n    return bool(int(s))\n"},
            {"name": "real-bool-call",
             "code": "def f(d):\n    return bool(d.get('on'))\n"},
        ],
    }

    def run(self, tree, profile=None, adapter=None) -> list[Finding]:
        out = []
        for n in ast.walk(tree):
            if not isinstance(n, ast.Call):
                continue
            f = n.func
            if not (isinstance(f, ast.Name) and f.id == "bool"):
                continue
            if not n.args or n.keywords:
                continue
            a = n.args[0]
            if not (isinstance(a, ast.Constant) and isinstance(a.value, str)):
                continue
            if a.value.strip().lower() not in _BOOL_INTENT:
                continue
            out.append(Finding(
                rule_id=self.id, file=str(getattr(tree, "path", "<memory>")),
                line=int(getattr(n, "lineno", 0)), severity=self.severity,
                title=self.name,
                detail=(f"bool({a.value!r}) 非空字符串恒为 True，与字面量语义相反；"
                        f"若本意是布尔应写作 True/False 或显式解析字符串（读反用户意图）"),
                evidence=node_source(tree, n.lineno)[:200],
            ))
        return out
