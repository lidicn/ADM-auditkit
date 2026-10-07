"""py.json_parse_unguarded —— 循环内裸 JSON 解析。

来源：memory-agent MA-01/02/03（确证 High）。
    `for r in rows: json.loads(r["tags_json"])` 无 try ⇒
    一条脏数据不是被跳过，而是炸掉整个循环，用户看到的是"功能整个没了"。

判据：JSON 解析调用未被 try 包裹，且位于循环体内。
    循环外未保护的解析不报——那是单点失败，噪音过高（见 §9.3）。
"""
from __future__ import annotations

import ast

from engine.base import BaseRule, Finding, node_source
from engine.helpers import own_walk, call_name

_PARSE_CALLS = {"loads", "load", "safe_json_loads"}


class JsonParseUnguardedRule(BaseRule):
    id = "py.json_parse_unguarded"
    name = "循环内裸 JSON 解析"
    description = "循环体内 JSON 解析未受保护：一条脏数据会让整批处理失败，而非跳过该条"
    applies_to = []
    mode = "static_ast"
    severity = "high"
    status = "active"
    version = "1.0.0"

    tests = {
        "dirty": [
            {"name": "loop-unguarded",
             "code": "def list_rules(rows):\n"
                     "    out = []\n"
                     "    for r in rows:\n"
                     "        out.append(json.loads(r['tags_json']))\n"
                     "    return out"},
            {"name": "while-unguarded",
             "code": "def drain(fh):\n"
                     "    out = []\n"
                     "    while True:\n"
                     "        line = fh.readline()\n"
                     "        if not line:\n"
                     "            break\n"
                     "        out.append(json.loads(line))\n"
                     "    return out"},
        ],
        "clean": [
            {"name": "loop-guarded",
             "code": "def list_rules(rows):\n"
                     "    out = []\n"
                     "    for r in rows:\n"
                     "        try:\n"
                     "            out.append(json.loads(r['tags_json']))\n"
                     "        except ValueError:\n"
                     "            continue\n"
                     "    return out"},
            {"name": "guarded-not-in-loop",
             "code": "def load_one(path):\n"
                     "    try:\n"
                     "        return json.loads(Path(path).read_text())\n"
                     "    except ValueError:\n"
                     "        return {}"},
        ],
    }

    def run(self, tree, profile=None, adapter=None) -> list[Finding]:
        out = []
        for fn in own_walk(tree):
            if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            loops = [n for n in own_walk(fn) if isinstance(n, (ast.For, ast.While))]
            if not loops:
                continue
            for call in own_walk(fn):
                if not isinstance(call, ast.Call) or call_name(call) not in _PARSE_CALLS:
                    continue
                if self._in_try(fn, call):
                    continue
                if not any(any(x is call for x in ast.walk(lo)) for lo in loops):
                    continue
                out.append(Finding(
                    rule_id=self.id, file=str(tree.path), line=call.lineno,
                    severity=self.severity, title=self.name,
                    detail=f"`{fn.name}` 循环内 JSON 解析未受保护：一条脏数据将中断整批",
                    evidence=node_source(tree, call.lineno)[:200],
                ))
        return out

    @staticmethod
    def _in_try(fn, target) -> bool:
        for t in own_walk(fn):
            if isinstance(t, ast.Try) and any(x is target for x in ast.walk(t)):
                return True
        return False
