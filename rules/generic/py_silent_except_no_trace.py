"""py.silent_except_no_trace —— except 吞掉失败且不留任何痕迹。

来源：AutoForge R6-02 / R10-01、memory-agent MA-15/16（均确证）。
    MA-15：预检失败返回 None = "覆盖良好"，与**真的覆盖良好**逐字节相同。

判据（四叉留痕，lesson 40/47——这是最容易误判的一族）：
    留痕 = ①日志 ②raise ③计数 ④状态标志置位 / 记账列表 append
    **四叉均无**才判缺陷。只认 ① 会误判（毒化标志、记账列表都比日志强）。

排除项（均为假阳性来源）：
    · `except asyncio.CancelledError` —— 关停语义 ≠ 容错语义（lesson 141）
    · 极短 handler（pass 类由其他规则处理）
"""
from __future__ import annotations

import ast
import re

from engine.base import BaseRule, Finding, node_source
from engine.helpers import all_walk, own_walk, has_trace

# lesson 40：状态标志置位（毒化标志）比日志更强，必须与日志同等对待。
# 若 engine.helpers.has_trace 后续把这一叉并入四叉，可删除本地补充。
_POISON = re.compile(
    r"(\b\w*(?:POISON|POISONED|poisoned|broken|degraded|stale|dirty)\w*\s*=\s*True|"
    r"\b\w+\.append\(|\b\w*(?:_ok|ok)\w*\s*=\s*False)")


class SilentExceptNoTraceRule(BaseRule):
    id = "py.silent_except_no_trace"
    name = "静默吞掉异常"
    description = "except 分支吞掉失败，且日志/raise/计数/状态标志四叉留痕均无"
    applies_to = []
    mode = "static_ast"
    severity = "low"
    status = "active"
    version = "1.0.0"

    tests = {
        "dirty": [
            {"name": "bare-silent-return",
             "code": "def check():\n"
                     "    try:\n"
                     "        return load()\n"
                     "    except Exception:\n"
                     "        return None"},
        ],
        "clean": [
            {"name": "logged",
             "code": "import logging\n"
                     "def check():\n"
                     "    try:\n"
                     "        return load()\n"
                     "    except Exception as exc:\n"
                     "        logging.warning('load failed: %s', exc)\n"
                     "        return None"},
            {"name": "poison-flag-stronger-than-log",
             "code": "def load_revoked():\n"
                     "    global POISONED\n"
                     "    try:\n"
                     "        return json.loads(open('p').read())\n"
                     "    except Exception:\n"
                     "        POISONED = True\n"
                     "        return None"},
            {"name": "cancelled-is-shutdown-semantics",
             "code": "async def gen():\n"
                     "    try:\n"
                     "        await work()\n"
                     "    except asyncio.CancelledError:\n"
                     "        return"},
        ],
    }

    def run(self, tree, profile=None, adapter=None) -> list[Finding]:
        out = []
        for scope in all_walk(tree):
            if not isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            for h in own_walk(scope):
                if not isinstance(h, ast.ExceptHandler):
                    continue
                if h.type is not None:
                    try:
                        if "CancelledError" in ast.unparse(h.type):
                            continue  # 关停语义 ≠ 容错语义
                    except Exception:
                        pass
                try:
                    hb = ast.unparse(h)
                except Exception:
                    continue
                if len(hb.strip()) < 8:
                    continue
                if has_trace(h)[0]:
                    continue
                if _POISON.search(hb):
                    continue  # 状态标志置位 = 留痕（比日志更强，lesson 40）
                out.append(Finding(
                    rule_id=self.id, file=str(tree.path), line=h.lineno,
                    severity=self.severity, title=self.name,
                    detail=f"`{scope.name}` 的 except 分支吞掉失败且无留痕",
                    evidence=node_source(tree, h.lineno)[:200],
                ))
        return out
