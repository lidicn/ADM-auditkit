"""py.except_return_failopen —— 异常分支返回"放行"。

来源：memory-agent MA-04/14/16（坏时间窗 → return True ⇒ 约束失效）、
      AutoForge R13-01（策略文件损坏 → 保护整段消失，fail-open）。

判据：except 体内 `return True` / `return 1`（调用点读作"通过/命中"），且**无留痕**。
    有留痕的不报（可观测 ⇒ 可排查，见 engine.helpers.has_trace 的留痕四叉）。
    返回 None/{}/[] 不报——语义取决于调用点，自动判方向必然误报。
"""
from __future__ import annotations

import ast

from engine.base import BaseRule, Finding, node_source
from engine.helpers import own_walk, all_walk, has_trace

_FAIL_OPEN = {"True": "放行 / 命中 / 通过", "1": "成功"}


class ExceptReturnFailopenRule(BaseRule):
    id = "py.except_return_failopen"
    name = "异常分支返回放行值"
    description = "except 后返回 True/1，且无日志等留痕：失败被读成成功，护栏静默消失"
    applies_to = []
    mode = "static_ast"
    severity = "high"
    status = "active"
    version = "1.0.0"

    tests = {
        "dirty": [
            {"name": "bad-window-returns-true",
             "code": "def in_window(spec, hour):\n"
                     "    try:\n"
                     "        lo, hi = spec.split('-')\n"
                     "        return int(lo) <= hour <= int(hi)\n"
                     "    except Exception:\n"
                     "        return True"},
            {"name": "acl-load-returns-true",
             "code": "def allowed(path):\n"
                     "    try:\n"
                     "        return json.loads(open(path).read())\n"
                     "    except (OSError, ValueError):\n"
                     "        return True"},
        ],
        "clean": [
            {"name": "returns-none-with-log",
             "code": "def in_window(spec, hour):\n"
                     "    try:\n"
                     "        lo, hi = spec.split('-')\n"
                     "        return int(lo) <= hour <= int(hi)\n"
                     "    except Exception:\n"
                     "        logger.warning('坏时间窗 %r（不命中）', spec)\n"
                     "        return None"},
            {"name": "fail-closed-returns-false",
             "code": "def allowed(path):\n"
                     "    try:\n"
                     "        return json.loads(open(path).read())\n"
                     "    except (OSError, ValueError):\n"
                     "        return False"},
        ],
    }

    def run(self, tree, profile=None, adapter=None) -> list[Finding]:
        out = []
        # own_walk 遇 FunctionDef 会停止下钻（设计如此），须先取函数再进内部
        scopes = [n for n in all_walk(tree)
                  if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]
        for scope in scopes:
            for h in own_walk(scope):
                if not isinstance(h, ast.ExceptHandler):
                    continue
                if h.type is not None and "CancelledError" in ast.unparse(h.type):
                    continue  # 关停语义 ≠ 容错语义
                if has_trace(h)[0]:
                    continue
                for node in ast.walk(h):
                    if not isinstance(node, ast.Return) or node.value is None:
                        continue
                    try:
                        val = ast.unparse(node.value)
                    except Exception:
                        continue
                    if val in _FAIL_OPEN:
                        out.append(Finding(
                            rule_id=self.id, file=str(tree.path), line=node.lineno,
                            severity=self.severity, title=self.name,
                            detail=f"except 返回 `{val}`（语义：{_FAIL_OPEN[val]}）且无留痕 ⇒ fail-open",
                            evidence=node_source(tree, node.lineno)[:200],
                        ))
        return out
