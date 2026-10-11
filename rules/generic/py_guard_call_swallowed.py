"""py.guard_call_swallowed —— 护栏调用被纯 pass 的 except 静默吞掉。

来源：memory-agent 第三期第十九轮确证缺陷 M23（high）——护栏 `mark()` 置位失败
被 `except Exception: pass` 吞掉，破坏性覆盖（M6）在"已修复"代码里静默复发：
盘上旧数据全丢、日志零输出。形态可怕之处在于**读代码时它看起来有防护**——
有 try、有护栏调用、有 except，唯独 except 里什么都不做。

历史（本规则自身的坑）：v1.0.0 为 YAML（draft），match 用
`call: [mark, ...]` + `type: [Pass]` AND。但引擎 matcher 要求**同一节点**同时满足
两判据——Call 节点永远不可能是 Pass 节点，规则必然 0 命中（注册期 3/3 dirty
miss → broken，fail-closed）。判据本质是**上下文**（护栏 call 位于某 try 体内，
该 try 的 handler 是纯 pass），YAML 五判据表达不了（gap-6 criterion-locality）。
v1.1.0 改写为 Python 插件：直接分析 Try/ExceptHandler 结构，问题根除。

判据（两条同时满足才报）：
    ① 存在 ExceptHandler，其 body 全部语句都是 pass（护栏失败无声无息）
    ② 所属 try 的体内（不穿透嵌套函数/类/lambda —— PITFALLS P1）调用了护栏类 API
  报在护栏调用行，detail 标注被吞的异常类型。

护栏 API 集合沿用原 YAML 的 assumptions.guard_api，并补上遗漏的 `check_and_recover`
（该名在 assumptions 里有、match 里没有 —— 本已静默漏检）。
clean 形态：handler 有日志/raise ⇒ 不报；try 体内无护栏调用 ⇒ 不报。
"""
from __future__ import annotations

import ast

from engine.base import BaseRule, Finding, node_source
from engine.helpers import all_walk, call_name

#: 护栏类 API（置位 / 隔离 / 出站校验 / 自检恢复）。随项目演进可扩充。
_GUARDS = {
    "mark", "mark_poisoned", "guard", "barrier", "quarantine", "cycle_safe",
    "safe_json_dumps", "validate_outbound_url", "validate_url",
    "assert_safe_outbound", "check_and_recover",
}

_SCOPE = (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)


def _guard_calls_in(stmts) -> list[ast.Call]:
    """在语句子树里找护栏调用；遇嵌套作用域停止下钻（PITFALLS P1）。"""
    out: list[ast.Call] = []
    stack = list(stmts)
    while stack:
        cur = stack.pop(0)
        if isinstance(cur, ast.Call) and call_name(cur) in _GUARDS:
            out.append(cur)
            continue
        if isinstance(cur, _SCOPE):
            continue
        stack[:0] = list(ast.iter_child_nodes(cur))
    return out


class GuardSwallowedRule(BaseRule):
    id = "py.guard_call_swallowed"
    name = "护栏调用被纯 pass 吞掉"
    description = ("护栏类 API（置位/隔离/出站校验等）在 try 里调用，但 except 分支只有 pass："
                   "护栏自身失败时无声无息，防护形同虚设（fail-silent）")
    applies_to = []
    mode = "static_ast"
    severity = "high"
    status = "active"
    version = "1.1.0"

    tests = {
        # 沿用原 YAML 的 7 条样本（v1.0.0 自测曾 7/7，仅 matcher 语义变更导致失效）
        "dirty": [
            {"name": "guard-swallowed-by-pass",
             "code": "def _load_users(self):\n"
                     "    try:\n"
                     "        return json.loads(p.read_text())\n"
                     "    except Exception as exc:\n"
                     "        try:\n"
                     "            from .state_poison import mark\n"
                     "            mark(self.users_file, exc)\n"
                     "        except Exception:\n"
                     "            pass\n"
                     "        return {}"},
            {"name": "quarantine-swallowed",
             "code": "def save(path, data):\n"
                     "    try:\n"
                     "        barrier(path)\n"
                     "    except Exception:\n"
                     "        pass\n"
                     "    write_json(path, data)"},
            {"name": "validate-url-swallowed",
             "code": "def fetch(url):\n"
                     "    try:\n"
                     "        validate_outbound_url(url)\n"
                     "    except Exception:\n"
                     "        pass\n"
                     "    return httpx.get(url)"},
        ],
        "clean": [
            {"name": "guard-with-logging",
             "code": "def _load_users(self):\n"
                     "    try:\n"
                     "        return json.loads(p.read_text())\n"
                     "    except Exception as exc:\n"
                     "        try:\n"
                     "            from .state_poison import mark\n"
                     "            mark(self.users_file, exc)\n"
                     "        except Exception as _me:\n"
                     "            _LOG.error('置位失败（写侧护栏可能未生效）: %s', _me)\n"
                     "        return {}"},
            {"name": "guard-reraise",
             "code": "def save(path, data):\n"
                     "    try:\n"
                     "        barrier(path)\n"
                     "    except Exception as exc:\n"
                     "        raise RuntimeError(f'护栏失败: {exc}')\n"
                     "    write_json(path, data)"},
            {"name": "no-guard-at-all",
             "code": "def helper(items):\n"
                     "    for x in items:\n"
                     "        if not x:\n"
                     "            pass\n"
                     "    return len(items)"},
            {"name": "pass-in-unrelated-branch",
             "code": "def poll():\n"
                     "    while True:\n"
                     "        try:\n"
                     "            item = queue.get_nowait()\n"
                     "        except Empty:\n"
                     "            pass\n"
                     "        else:\n"
                     "            handle(item)"},
        ],
    }

    def run(self, tree, profile=None, adapter=None) -> list[Finding]:
        out: list[Finding] = []
        for node in all_walk(tree):
            if not isinstance(node, ast.Try):
                continue
            swallowed = [h for h in node.handlers
                         if h.body and all(isinstance(s, ast.Pass) for s in h.body)]
            if not swallowed:
                continue
            kinds = " / ".join(
                ast.unparse(h.type) if h.type is not None else "bare except"
                for h in swallowed)
            for call in _guard_calls_in(node.body):
                out.append(Finding(
                    rule_id=self.id, file=str(tree.path), line=call.lineno,
                    severity=self.severity, title=self.name,
                    detail=(f"护栏 `{call_name(call)}()` 的失败会被 `except {kinds}: pass` "
                            f"静默吞掉——护栏失效时既不留痕也不中止，防护形同虚设"),
                    evidence=node_source(tree, call)[:200],
                ))
        return out
