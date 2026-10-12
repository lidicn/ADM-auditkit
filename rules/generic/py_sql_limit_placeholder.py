"""py.sql_limit_placeholder —— SQL LIMIT 占位符下推且绑定值未见钳制（v2 函数级）。

来源：memory-agent MA-07 / MA-09（确证 High）：
    SQLite 中 `LIMIT -1` = **无上限**（lesson 81）；`?limit=abc` → 路由 500。

为什么从 YAML 正则升级为 Python 插件（v1.1.0 → v2.0.0）：
    v1 正则只认「LIMIT ?」形状，无法判断绑定值是否已钳制。
    memory-agent round-003 实测 **32/32 全部假阳性**——该项目所有
    `LIMIT ?` 都配了 `clamp_limit(limit, 50, 500)` 或
    `max(1, min(int(limit or 100), 1000))`，正则把正确用法也报了。
    100% 噪音率意味着 v1 除了「这里用了参数化」以外不提供任何信息。

v2 判据（函数级，三步全部满足才报）：
  1. execute/executescript 的 SQL 字面量含 `LIMIT ?`；
  2. 绑定参数（调用的第二个位置参数）里出现裸 Name；
  3. 该 Name 在同一函数内**没有**被 clamp_limit/max/min 系调用包裹
     （即调用点未见钳制）。
`int(limit)` 这类纯 cast 不算钳制——int() 不设上界，负值照样穿透。
"""
from __future__ import annotations

import ast

from engine.base import BaseRule, Finding, node_source

_CLAMP_FUNCS = {"clamp_limit", "clamp", "max", "min"}
_EXECUTE_TAILS = {"execute", "executescript", "executemany", "raw"}


def _tail(node: ast.AST) -> str:
    """取调用链末段名。"""
    if isinstance(node, ast.Attribute):
        return node.attr
    if isinstance(node, ast.Name):
        return node.id
    return ""


def _sql_literals(node: ast.AST) -> list[str]:
    """收集调用参数里的字符串字面量（含 BinOp 拼接与 f-string 的常量部分）。"""
    out: list[str] = []
    for sub in ast.walk(node):
        if isinstance(sub, ast.Constant) and isinstance(sub.value, str):
            out.append(sub.value)
    return out


def _clamped_names(fn: ast.AST) -> set[str]:
    """函数内被 clamp_limit/clamp/max/min 包裹过的名字 = 已有钳制基础设施。"""
    names: set[str] = set()
    for sub in ast.walk(fn):
        if not isinstance(sub, ast.Call):
            continue
        if _tail(sub.func) in _CLAMP_FUNCS:
            for arg in sub.args:
                for n in ast.walk(arg):
                    if isinstance(n, ast.Name):
                        names.add(n.id)
    return names


def _bound_names(call: ast.Call) -> set[str]:
    """execute(...) 第二个位置参数（绑定元组/列表）里的裸 Name。

    注意：必须**跳过 Call 的 func 位**——`(clamp_limit(limit, 50, 500),)` 里
    `clamp_limit` 是 Name 节点但它是被调函数名，不是绑定值。
    （v2.0.0 首版用 ast.walk 把它也收进来，导致两条 clean 全误报。）
    """
    if len(call.args) < 2:
        return set()
    names: set[str] = set()

    def visit(node: ast.AST) -> None:
        if isinstance(node, ast.Call):
            for arg in node.args:
                visit(arg)
            for kw in node.keywords:
                visit(kw.value)
            return
        if isinstance(node, ast.Name):
            names.add(node.id)
            return
        for child in ast.iter_child_nodes(node):
            visit(child)

    visit(call.args[1])
    return names


class SqlLimitPlaceholderRule(BaseRule):
    id = "py.sql_limit_placeholder"
    name = "SQL LIMIT 占位符下推且未见钳制"
    description = (
        "SQL 含 LIMIT ? 且绑定值是未经 max/min/clamp 钳制的裸形参："
        "SQLite 中负值 = 无上限，非数字直接抛错"
    )
    applies_to = []
    mode = "static_ast"
    severity = "medium"
    status = "active"
    version = "2.0.0"
    intent = "discovery"
    tests = {
        "dirty": [
            {"name": "limit-placeholder", "code": (
                "def query_events(conn, limit):\n"
                "    return conn.execute(\"SELECT * FROM events LIMIT ?\", (limit,))\n")},
            {"name": "limit-placeholder-offset", "code": (
                "def page(conn, limit, offset):\n"
                "    return conn.execute(\"SELECT * FROM t LIMIT ? OFFSET ?\", (limit, offset))\n")},
            {"name": "cast-is-not-clamp", "code": (
                "def page(conn, limit):\n"
                "    return conn.execute(\"SELECT * FROM t LIMIT ?\", [int(limit)])\n")},
        ],
        "clean": [
            {"name": "clamp-limit-helper", "code": (
                "def page(conn, limit):\n"
                "    return conn.execute(\"SELECT * FROM t LIMIT ?\",\n"
                "                        (clamp_limit(limit, 50, 500),))\n")},
            {"name": "min-max-clamp", "code": (
                "def page(conn, limit):\n"
                "    return conn.execute(\"SELECT * FROM t LIMIT ?\",\n"
                "                        (max(1, min(int(limit or 100), 1000)),))\n")},
            {"name": "literal-limit", "code": (
                "def query_recent(conn):\n"
                "    return conn.execute(\"SELECT * FROM events LIMIT 100\")\n")},
            {"name": "constant-binding", "code": (
                "def page(conn):\n"
                "    return conn.execute(\"SELECT * FROM events LIMIT ?\", (100,))\n")},
            {"name": "parameterized-where-not-limit", "code": (
                "def by_day(conn, day):\n"
                "    return conn.execute(\"SELECT * FROM events WHERE day = ?\", (day,))\n")},
        ],
    }

    def run(self, tree, profile=None, adapter=None) -> list:
        out = []
        funcs = [n for n in ast.walk(tree)
                 if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]
        for fn in funcs:
            clamped = _clamped_names(fn)
            for sub in ast.walk(fn):
                if not isinstance(sub, ast.Call):
                    continue
                if _tail(sub.func) not in _EXECUTE_TAILS:
                    continue
                if not any("limit ?" in s.lower() for s in _sql_literals(sub)):
                    continue
                unclamped = _bound_names(sub) - clamped
                if not unclamped:
                    continue
                names = ", ".join(sorted(unclamped))
                out.append(Finding(
                    rule_id=self.id,
                    file=str(getattr(tree, "path", "<memory>")),
                    line=sub.lineno,
                    severity=self.severity,
                    title=self.name,
                    detail=(f"LIMIT 绑定值 {names} 未经钳制直达 SQL；"
                            "SQLite 负值=无上限，非数字抛错"),
                    evidence=node_source(tree, sub.lineno)[:200],
                ))
        return out
