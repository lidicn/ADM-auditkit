"""py.import_time_env_int —— 模块导入期把环境变量裸转数字。

来源：memory-agent round-003（2026-10-12）确证族 D1（6 处站点）：
    store.py:52/55、rule_lifecycle.py:72/74、mcp_server.py:289
    `_X = int(os.getenv("MA_X_MAX", "2000"))` 在**模块导入期**执行。

两个独立失效路径（本规则一条同时覆盖）：
  1. 响亮失效：env 写成非数字 → import 期 ValueError → 进程起不来。
     对常驻容器就是启动失败循环（崩溃→重建 churn）。
  2. 静默失效：传 0/负值不报错但语义反转——护栏上限被关或变成无界
     （与 AutoForge R9-01/02「负数 ⇒ 护栏静默失效」同族）。

**修复状态**：memory-agent 已于 2026-10-12 落地修复——新增 `env_cfg.py`
（`env_int(name, default, lo, hi)` / `env_float`，畸形与越界值回落默认值而不崩进程），
store.py / rule_lifecycle.py / mcp_server.py 共 6 处全部改接。
故本规则 intent=**regression**：0 命中是修复生效的证据，不是规则失效；
一旦有人新写裸 `int(os.getenv(...))` 会立即回归报警。
"""
from __future__ import annotations

import ast

from engine.base import BaseRule, Finding, node_source

_ENV_FUNCS = ("os.getenv", "os.environ.get")
_NUM_CASTS = ("int", "float")


def _dotted(node: ast.AST) -> str:
    """取调用的点分名（Name/Attribute 链），非链返回 \"\"。"""
    parts: list[str] = []
    cur = node
    while isinstance(cur, ast.Attribute):
        parts.append(cur.attr)
        cur = cur.value
    if isinstance(cur, ast.Name):
        parts.append(cur.id)
        return ".".join(reversed(parts))
    return ""


def _has_env_call(node: ast.AST) -> bool:
    for sub in ast.walk(node):
        if isinstance(sub, ast.Call) and _dotted(sub.func) in _ENV_FUNCS:
            return True
    return False


class ImportTimeEnvIntRule(BaseRule):
    id = "py.import_time_env_int"
    name = "导入期环境变量裸转数值"
    description = (
        "模块级 `int(os.getenv(...))`：导入期执行，坏配置直接杀死进程，"
        "0/负值则让护栏静默失效；应收口到带钳位与降级的 env_int()"
    )
    applies_to = []
    mode = "static_ast"
    severity = "medium"
    status = "active"
    version = "1.0.0"
    intent = "regression"
    tests = {
        "dirty": [
            {"name": "module-level-int-getenv", "code": (
                "import os\n"
                "_VOICE_CACHE_MAX = int(os.getenv(\"MA_VOICE_CACHE_MAX\", \"2000\"))\n")},
            {"name": "module-level-float-environ", "code": (
                "import os\n"
                "DRY_RUN_DAYS = float(os.environ.get(\"MA_RULE_DRY_RUN_DAYS\", \"3\"))\n")},
            {"name": "annotated-assign", "code": (
                "import os\n"
                "MIN_EVIDENCE: int = int(os.getenv(\"MA_RULE_MIN_EVIDENCE\", \"3\"))\n")},
        ],
        "clean": [
            {"name": "inside-function", "code": (
                "import os\n"
                "def _cfg():\n"
                "    return int(os.getenv(\"MA_X\", \"1\"))\n")},
            {"name": "no-numeric-cast", "code": (
                "import os\n"
                "SECRET_DIR = os.getenv(\"MA_SECRET_DIR\", \"/run/secrets\")\n")},
            {"name": "cast-without-env", "code": (
                "N = int(\"5\")\n")},
            {"name": "guarded-with-fallback", "code": (
                "import os\n"
                "try:\n"
                "    MAX = int(os.getenv(\"MA_MAX\", \"100\"))\n"
                "except ValueError:\n"
                "    MAX = 100\n")},
        ],
    }

    def run(self, tree, profile=None, adapter=None) -> list:
        out = []
        guarded: set[int] = set()
        for node in tree.body:  # 顶层 Try 内的赋值视为「有降级」，不报
            if isinstance(node, ast.Try):
                for sub in node.body:
                    guarded.add(id(sub))
        for node in tree.body:
            if not isinstance(node, (ast.Assign, ast.AnnAssign)):
                continue
            if id(node) in guarded:
                continue
            value = node.value
            if not isinstance(value, ast.Call):
                continue
            if _dotted(value.func) not in _NUM_CASTS:
                continue
            if not _has_env_call(value):
                continue
            out.append(Finding(
                rule_id=self.id,
                file=str(getattr(tree, "path", "<memory>")),
                line=node.lineno,
                severity=self.severity,
                title=self.name,
                detail=("导入期裸转数值：env 非数字→import 期 ValueError→进程起不来；"
                        "0/负值→护栏静默失效。应收口到带钳位/降级的 env_int()"),
                evidence=node_source(tree, node.lineno)[:200],
            ))
        return out
