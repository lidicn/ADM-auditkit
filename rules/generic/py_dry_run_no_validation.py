"""py.dry_run_no_validation —— dry_run 假绿。

来源：memory-agent MA-28（确证 High）。
    声明「dry_run=true：只校验参数，不写入」，实现却在**任何校验之前**
    就 `return {"ok": True, "message": "参数校验通过"}` ⇒ 校验一行都没跑。

判据：
    ① docstring 含 dry_run / 只校验 类声明
    ② 存在 `if dry_run:` 分支
    ③ 该分支**之前**没有任何校验动作（raise / return error / 判空）
    ④ 该分支直接返回含 ok 的 dict

判据 ③ 是关键：校验写在分支**之前**是正确实现（clean 样本），不构成缺陷。
"""
from __future__ import annotations

import ast
import re

from engine.base import BaseRule, Finding, node_source
from engine.helpers import all_walk, code_unparse

_CLAIM = re.compile(r"(dry[_ ]?run|只校验|不写入)")
_VALIDATE = re.compile(r"(raise|assert\s|\bvalidate|_check|error\s*[:=]|ok\s*[:=]\s*False|"
                       r"not\s+\w+\s*:|if\s+not\s)")


class DryRunNoValidationRule(BaseRule):
    id = "py.dry_run_no_validation"
    name = "dry_run 假绿（声明只校验但未校验）"
    description = "dry_run 分支在未做任何校验的情况下直接返回成功，调用方会误判参数合法"
    applies_to = []
    mode = "static_ast"
    severity = "high"
    status = "active"
    version = "1.0.0"

    tests = {
        "dirty": [
            {"name": "return-ok-before-validate",
             "code": 'def teach(dry_run, entity_id):\n'
                     '    """dry_run=true：只校验参数，不写入。"""\n'
                     '    if dry_run:\n'
                     '        return {"ok": True, "dry_run": True, "message": "参数校验通过，未写入"}\n'
                     '    if not entity_id:\n'
                     '        return {"ok": False, "error": "entity_id 不能为空"}\n'
                     '    return {"ok": True}'},
        ],
        "clean": [
            {"name": "validate-before-dry-run",
             "code": 'def teach(dry_run, entity_id):\n'
                     '    """dry_run=true：只校验参数，不写入。"""\n'
                     '    if not entity_id:\n'
                     '        return {"ok": False, "error": "entity_id 不能为空"}\n'
                     '    if dry_run:\n'
                     '        return {"ok": True, "dry_run": True, "dispatched": False}\n'
                     '    return {"ok": True}'},
            {"name": "no-dry-run-claim",
             "code": 'def teach(entity_id):\n'
                     '    """写入一条信号。"""\n'
                     '    if not entity_id:\n'
                     '        return {"ok": False, "error": "empty"}\n'
                     '    return {"ok": True}'},
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
            for node in fn.body:
                if not isinstance(node, ast.If):
                    continue
                try:
                    cond = ast.unparse(node.test)
                except Exception:
                    continue
                if "dry_run" not in cond:
                    continue
                pre = "\n".join(ast.unparse(x) for x in fn.body[:fn.body.index(node)])
                if _VALIDATE.search(pre):
                    continue  # 校验在分支之前 ⇒ 契约成立
                body = "\n".join(ast.unparse(x) for x in node.body)
                if re.search(r"""["']ok["']\s*[:=]\s*True""", body) and "return" in body:
                    out.append(Finding(
                        rule_id=self.id, file=str(tree.path), line=node.lineno,
                        severity=self.severity, title=self.name,
                        detail=f"`{fn.name}` 的 dry_run 分支在校验前返回成功",
                        evidence=node_source(tree, node.lineno)[:200],
                    ))
        return out
