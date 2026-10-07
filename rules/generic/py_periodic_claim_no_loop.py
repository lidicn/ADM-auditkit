"""py.periodic_claim_no_loop —— 声称"周期/定时"的函数不在周期循环内。

来源：memory-agent MA-35（确证 High）。
    purge_old / purge_idempotency / purge_mcp_audit 三个清理函数
    **实现完全正确**，但调用点只在 startup ⇒ 声明 90 天保留期，实测 456 天（5.1×）。

核心认识（lesson 163）：**实现正确 ≠ 策略生效**。机制 = 函数 + 触发器，
而触发器不在写这个函数的人的视野里。

判据：
    ① docstring 含"周期任务/定时/定期/每日/periodically"
    ② 函数自身不是周期宿主（无 while True + sleep）
单文件判据只出"候选"，真实判定需跨文件查调用点——故本规则标 medium，
并在 detail 明确写出"须跨文件确认调用点"。
"""
from __future__ import annotations

import ast
import re

from engine.base import BaseRule, Finding, node_source
from engine.helpers import all_walk, full_unparse

_CLAIM = re.compile(r"(周期任务|定时|定期|每日|periodically|scheduled|定时跑)")
_HOST = re.compile(r"while\s+True")
_SLEEP = re.compile(r"(asyncio\.sleep|time\.sleep|\.sleep\()")


class PeriodicClaimNoLoopRule(BaseRule):
    id = "py.periodic_claim_no_loop"
    name = "声称周期执行但自身不在循环内"
    description = "docstring 声明周期/定时，但函数内无循环——须跨文件确认是否存在周期调用点"
    applies_to = []
    mode = "static_ast"
    severity = "medium"
    status = "active"
    version = "1.0.0"

    tests = {
        "dirty": [
            {"name": "claim-periodic-no-loop",
             "code": 'def purge_old(conn, days):\n'
                     '    """按保留期清理（周期任务，定时跑）。"""\n'
                     '    conn.execute("DELETE FROM events WHERE day < ?", (days,))'},
        ],
        "clean": [
            {"name": "is-periodic-host",
             "code": 'async def periodic_cleanup(store, interval=86400):\n'
                     '    """周期清理。"""\n'
                     '    while True:\n'
                     '        await asyncio.sleep(interval)\n'
                     '        await store.purge_old(90)'},
            {"name": "no-periodic-claim",
             "code": 'def purge_old(conn, days):\n'
                     '    """按保留期清理。"""\n'
                     '    conn.execute("DELETE FROM events WHERE day < ?", (days,))'},
        ],
    }

    def run(self, tree, profile=None, adapter=None) -> list[Finding]:
        out = []
        for fn in all_walk(tree):
            if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            doc = ast.get_docstring(fn) or ""
            if not _CLAIM.search(doc):
                continue
            body = full_unparse(fn)
            if _HOST.search(body) and _SLEEP.search(body):
                continue  # 自身即周期宿主
            out.append(Finding(
                rule_id=self.id, file=str(tree.path), line=fn.lineno,
                severity=self.severity, title=self.name,
                detail=f"`{fn.name}` 声明周期执行但自身无循环，须跨文件确认调用点是否在 while True 内",
                evidence=node_source(tree, fn.lineno)[:200],
            ))
        return out
