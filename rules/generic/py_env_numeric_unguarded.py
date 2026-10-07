"""py.env_numeric_unguarded —— 环境变量裸数值转换。

来源：AutoForge R9-01 / R9-02（均确证）。
    R9-02（High）：`AUTOFORGE_BLAST_RADIUS` 配负数 ⇒ `if limit > 0` 不成立
                   ⇒ 护栏静默失效（fail-open），服务照常启动。
    R9-01（Med） ：6 处裸 int/os.getenv，配成 "abc" 服务直接起不来。

判据：表达式同时含 ①数值转换 int()/float() ②os.getenv/environ，
      且不含任何 ③try/except/clamp/max/min/lo=/hi= 兜底。

clean 样本：`_env_number(...)` 类集中 helper（带解析兜底+上下界+warning）⇒ 不命中。
"""
from __future__ import annotations

import ast
import re

from engine.base import BaseRule, Finding, node_source
from engine.helpers import all_walk

_CAST = re.compile(r"\b(int|float)\s*\(")
_ENV = re.compile(r"(os\.getenv|os\.environ|environ\.get|getenv)")
_GUARD = re.compile(r"(try|except|clamp|max\(|min\(|lo\s*=|hi\s*=|fallback|default)")


class EnvNumericUnguardedRule(BaseRule):
    id = "py.env_numeric_unguarded"
    name = "环境变量裸数值转换"
    description = "int()/float() 直接作用于 os.getenv 且无解析兜底与上下界"
    applies_to = []
    mode = "static_ast"
    severity = "medium"
    status = "active"
    version = "1.0.0"

    tests = {
        "dirty": [
            {"name": "module-level-bare-int",
             "code": "import os\nSESSION_TTL_S = int(os.getenv('SESSION_TTL_S', '1800'))"},
            {"name": "in-function-bare-int",
             "code": "def build():\n    limit = int(os.getenv('BLAST_RADIUS', '8'))\n    return limit"},
        ],
        "clean": [
            {"name": "central-helper-with-bounds",
             "code": "def _env_number(name, default, lo=1, hi=100):\n"
                     "    try:\n"
                     "        n = int(os.getenv(name, str(default)))\n"
                     "    except (TypeError, ValueError):\n"
                     "        return default\n"
                     "    return max(lo, min(n, hi))"},
            {"name": "clamped-inline",
             "code": "def build():\n"
                     "    limit = int(os.getenv('BLAST_RADIUS', '8') or 8)\n"
                     "    return max(1, min(limit, 500))"},
        ],
    }

    @staticmethod
    def _clamped_later(tree_ast, name: str) -> bool:
        for node in ast.walk(tree_ast):
            if isinstance(node, ast.Call) and ast.unparse(node.func) in ("max", "min"):
                try:
                    if re.search(rf"\b{name}\b", ast.unparse(node)):
                        return True
                except Exception:
                    continue
        return False

    def run(self, tree, profile=None, adapter=None) -> list[Finding]:
        out = []
        scopes = list(all_walk(tree))
        for n in scopes:
            if isinstance(n, (ast.Assign, ast.AnnAssign)):
                val = n.value
                if val is None:
                    continue
                try:
                    expr = ast.unparse(val)
                except Exception:
                    continue
                if not (_CAST.search(expr) and _ENV.search(expr)):
                    continue
                if _GUARD.search(expr):
                    continue
                # 变量在后续语句里被 clamp ⇒ 已受控（clean/clamped-inline）
                tgt = n.targets[0] if isinstance(n, ast.Assign) else n.target
                tname = getattr(tgt, "id", None) or getattr(tgt, "attr", None)
                if tname and self._clamped_later(tree, tname):
                    continue
                out.append(Finding(
                    rule_id=self.id, file=str(tree.path), line=n.lineno,
                    severity=self.severity, title=self.name,
                    detail="环境变量裸数值转换：配错即崩或静默失效",
                    evidence=node_source(tree, n.lineno)[:200],
                ))
        return out
