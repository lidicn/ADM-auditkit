#!/usr/bin/env python3
"""AutoForge 项目专属规则（L3）。只对 applies_to=["AutoForge"] 生效。"""
from __future__ import annotations

import ast

from engine.base import BaseRule, Finding, call_chain

MATCH_TAILS = ("call_tool", "run_tool", "invoke_tool")
TIMEOUT_KEYS = ("timeout", "timeout_s", "timeout_seconds", "request_timeout")


class AFMcpToolTimeoutRule(BaseRule):
    """MCP/工具调用未设超时 —— 沙箱里外部调用挂死会拖垮整轮工作流。"""

    id = "af.mcp_tool_no_timeout"
    name = "MCP 工具调用未设超时"
    description = "工具调用未传 timeout 参数，外部调用可能无限期挂起"
    applies_to = ["AutoForge"]
    mode = "static_ast"
    severity = "high"
    status = "active"
    version = "1.0.0"
    tests = {
        "dirty": [{"name": "no-timeout", "code": (
            "def tool(req):\n"
            "    return session.call_tool('read', req)\n")}],
        "clean": [{"name": "with-timeout", "code": (
            "def tool(req):\n"
            "    return session.call_tool('read', req, timeout=30)\n")}],
    }

    def run(self, tree, profile, adapter) -> list:
        out = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            chain = call_chain(node)
            if chain.split(".")[-1] not in MATCH_TAILS:
                continue
            if any((kw.arg or "") in TIMEOUT_KEYS for kw in node.keywords):
                continue
            out.append(Finding(
                rule_id=self.id,
                file=str(getattr(tree, "path", "<memory>")),
                line=int(getattr(node, "lineno", 0)),
                severity=self.severity,
                title=self.name,
                detail=f"调用 {chain or '<call>'} 未传 timeout 参数",
                evidence=(getattr(tree, "source", "") or "").splitlines()[
                    getattr(node, "lineno", 1) - 1][:200] if getattr(tree, "source", "") else "",
            ))
        return out
