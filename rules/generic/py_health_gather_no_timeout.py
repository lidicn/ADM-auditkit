"""py.health_gather_no_timeout —— 存活判据用 gather 却不设总超时。

来源：memory-agent round-003（2026-10-12）结构性风险 D3：
    runtime.py:1048 `asyncio.gather(...)` 驱动 /health，无 asyncio.wait_for。
    叠加 store 全局 RLock 无获取超时、purge 的 VACUUM 持锁、chroma 查询
    默认 60s 超时 ⇒ /health 可被拖数十秒 ⇒ 存活探针误杀 ⇒ 容器重启。

为什么这是独立缺陷类：单个慢调用都有各自的超时（甚至"足够长"），
但**没有总超时的 gather 让 health 的耗时 = 最慢那个子系统**。
探针的超时阈值通常远小于子系统超时之和——链条在接缝处断裂。

判据（为保精度做三重收窄）：
  1. 函数名含 health/ready/status/ping/probe 之一（存活判据启发式）；
  2. 函数体内有 `asyncio.gather(` 调用；
  3. 同一函数内**没有** `asyncio.wait_for(`。

**修复状态**：memory-agent `runtime.py:health()` 已于 2026-10-12 加上
`asyncio.wait_for` 总超时。故本规则 intent=**regression**：0 命中是修复生效的
证据；项目里其他 health/status 类函数若漏加 wait_for 仍会命中（本轮另在
vision_service.py 发现一处），回归护栏与新发现两用。
"""
from __future__ import annotations

import ast

from engine.base import BaseRule, Finding, node_source

_NAME_HINTS = ("health", "ready", "status", "ping", "probe")


def _dotted(node: ast.AST) -> str:
    parts: list[str] = []
    cur = node
    while isinstance(cur, ast.Attribute):
        parts.append(cur.attr)
        cur = cur.value
    if isinstance(cur, ast.Name):
        parts.append(cur.id)
        return ".".join(reversed(parts))
    return ""


def _iter_own(node: ast.AST):
    """遍历函数自身语句，不下钻进嵌套 def/class。"""
    for child in ast.iter_child_nodes(node):
        if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        yield child
        yield from _iter_own(child)


class HealthGatherNoTimeoutRule(BaseRule):
    id = "py.health_gather_no_timeout"
    name = "存活判据 gather 无总超时"
    description = (
        "health/ready 类函数用 asyncio.gather 汇聚子系统探测，"
        "却没有 asyncio.wait_for 总超时——耗时被最慢子系统决定，"
        "可拖垮存活探针引发误杀重启"
    )
    applies_to = []
    mode = "static_ast"
    severity = "medium"
    status = "active"
    version = "1.0.0"
    intent = "regression"
    tests = {
        "dirty": [
            {"name": "health-gather-no-timeout", "code": (
                "import asyncio\n"
                "async def health(self):\n"
                "    ha = asyncio.to_thread(self.ha.get_status)\n"
                "    store = asyncio.to_thread(self.store.stats)\n"
                "    return await asyncio.gather(ha, store, return_exceptions=True)\n")},
            {"name": "ready-probe-gather", "code": (
                "import asyncio\n"
                "async def ready():\n"
                "    a = ping_a()\n"
                "    b = ping_b()\n"
                "    return await asyncio.gather(a, b)\n")},
        ],
        "clean": [
            {"name": "health-with-wait-for", "code": (
                "import asyncio\n"
                "async def health(self):\n"
                "    tasks = [ping_a(), ping_b()]\n"
                "    return await asyncio.wait_for(asyncio.gather(*tasks), timeout=5)\n")},
            {"name": "non-health-gather-ok", "code": (
                "import asyncio\n"
                "async def fetch_all(self):\n"
                "    return await asyncio.gather(self.a(), self.b())\n")},
            {"name": "health-without-gather", "code": (
                "async def health(self):\n"
                "    return {\"ok\": True}\n")},
        ],
    }

    def run(self, tree, profile=None, adapter=None) -> list:
        out = []
        for fn in ast.walk(tree):
            if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            name = fn.name.lower()
            if not any(h in name for h in _NAME_HINTS):
                continue
            has_gather = has_wait_for = False
            gather_line = 0
            for sub in _iter_own(fn):
                if not isinstance(sub, ast.Call):
                    continue
                dotted = _dotted(sub.func)
                if dotted == "asyncio.gather":
                    has_gather = True
                    gather_line = sub.lineno
                elif dotted == "asyncio.wait_for":
                    has_wait_for = True
            if has_gather and not has_wait_for:
                out.append(Finding(
                    rule_id=self.id,
                    file=str(getattr(tree, "path", "<memory>")),
                    line=gather_line,
                    severity=self.severity,
                    title=self.name,
                    detail=(f"{fn.name}() 用 asyncio.gather 汇聚探测但无 wait_for 总超时；"
                            "health 耗时=最慢子系统，可拖垮存活探针"),
                    evidence=node_source(tree, gather_line)[:200],
                ))
        return out
