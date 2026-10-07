#!/usr/bin/env python3
"""memory-agent 项目专属规则（L3）。applies_to=["memory-agent"]。

已知栈：Chainlit + LangGraph + Qdrant + PostgreSQL + embedding-service
（以 profile 探测为准，见 config/projects.yaml 的 note）。
"""
from __future__ import annotations

import ast

from engine.base import BaseRule, Finding, call_chain, source_line

MATCH_TAILS = ("create", "invoke", "ainvoke")
CHAIN_HINTS = ("completions", "chat", "embeddings")
TIMEOUT_KEYS = ("timeout", "timeout_s", "timeout_seconds", "request_timeout")


class MAExternalCallTimeoutRule(BaseRule):
    """外部 LLM/向量端点调用未设超时 —— 无降级路径时整条 LangGraph 链会卡死。"""

    id = "ma.llm_call_no_timeout"
    name = "外部模型/向量端点调用未设超时"
    description = "对 LLM 或 embedding 端点的调用未传 timeout，故障时会无限期等待"
    applies_to = ["memory-agent"]
    mode = "static_ast"
    severity = "high"
    status = "testing"
    version = "1.0.0"
    tests = {
        "dirty": [
            {"name": "completions-no-timeout", "code": (
                "def ask(client, msgs):\n"
                "    return client.chat.completions.create(model='m', messages=msgs)\n")},
            {"name": "graph-invoke-no-timeout", "code": (
                "def run(graph, state):\n"
                "    return graph.invoke(state)\n")},
        ],
        "clean": [
            {"name": "completions-with-timeout", "code": (
                "def ask(client, msgs):\n"
                "    return client.chat.completions.create(model='m', messages=msgs, timeout=20)\n")},
            {"name": "local-create", "code": (
                "def build(factory):\n"
                "    return factory.create()\n")},
        ],
    }

    def run(self, tree, profile, adapter) -> list:
        out = []
        src = getattr(tree, "source", "")
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            chain = call_chain(node)
            tail = chain.split(".")[-1]
            if tail not in MATCH_TAILS:
                continue
            if tail not in ("invoke", "ainvoke") and not any(h in chain for h in CHAIN_HINTS):
                continue
            if any((kw.arg or "") in TIMEOUT_KEYS for kw in node.keywords):
                continue
            line = int(getattr(node, "lineno", 0))
            out.append(Finding(
                rule_id=self.id,
                file=str(getattr(tree, "path", "<memory>")),
                line=line,
                severity=self.severity,
                title=self.name,
                detail=f"调用 {chain or '<call>'} 未传 timeout 参数",
                evidence=source_line(tree, line).strip()[:200],
            ))
        return out
