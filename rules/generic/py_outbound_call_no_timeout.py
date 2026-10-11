"""py.outbound_call_no_timeout —— 外部阻塞调用未设超时。

来源：AutoForge 20261011 审计。项目自声明焦点规则 af.mcp_tool_no_timeout
只认 call_tool/run_tool/invoke_tool，而该仓库真实出站调用词汇是
urlopen / opener.open / subprocess.run / Popen / requests.* —— 规则词汇与
代码词汇不匹配，焦点规则 0 命中（属"不适用"，非静默失效）。本规则覆盖
真实词汇，跨项目通用。

criterion-locality：只覆盖**可凭调用链名判定**的目标（urlopen/subprocess/
requests/socket）。`x.wait()`/`x.join()` 类型不可静态判定（可能是 queue 或
已设超时的进程），按判据局部性**不纳入**，避免假阳性。

为什么重要：无 timeout 的外部调用在沙箱/CI 里挂死会拖垮整轮工作流。
"""
from __future__ import annotations

import ast

from engine.base import BaseRule, Finding, call_chain

URL_TAILS = ("urlopen", "urlretrieve")
SUBPROC_TAILS = ("run", "Popen", "call", "check_output", "check_call")
HTTP_TAILS = ("get", "post", "put", "delete", "patch", "head", "request")
TIMEOUT_KEYS = ("timeout", "timeout_s", "timeout_seconds", "request_timeout")


class OutboundCallNoTimeoutRule(BaseRule):
    id = "py.outbound_call_no_timeout"
    name = "外部阻塞调用未设超时"
    description = "urlopen/subprocess/requests/socket 等外部调用未传 timeout，可能无限期挂起"
    applies_to = []
    mode = "static_ast"
    severity = "medium"
    status = "active"
    version = "1.1.0"

    tests = {
        "dirty": [
            {"name": "urlopen", "code": "def f(u):\n    return urllib.request.urlopen(u)\n"},
            {"name": "subprocess", "code": "def f(cmd):\n    return subprocess.run(cmd)\n"},
            {"name": "requests", "code": "def f(u):\n    return requests.get(u)\n"},
            {"name": "popen", "code": "def f(cmd):\n    return subprocess.Popen(cmd)\n"},
        ],
        "clean": [
            {"name": "urlopen-ok", "code": "def f(u):\n    return urllib.request.urlopen(u, timeout=30)\n"},
            {"name": "subprocess-ok", "code": "def f(cmd):\n    return subprocess.run(cmd, timeout=10)\n"},
            {"name": "requests-ok", "code": "def f(u):\n    return requests.get(u, timeout=5)\n"},
            {"name": "plain-call", "code": "def f(x):\n    return obj.run(x)\n"},
            {"name": "queue-join", "code": "def f(q):\n    return q.join()\n"},
        ],
    }

    def _has_timeout(self, node: ast.Call) -> bool:
        return any((kw.arg or "") in TIMEOUT_KEYS for kw in node.keywords)

    def _is_target(self, chain: str) -> bool:
        if not chain:
            return False
        tail = chain.split(".")[-1]
        low = chain.lower()

        # 排除 dict/映射访问（.get() 是内存操作，不是外部调用）
        if tail == "get":
            return False

        # Popen 构造器本身非阻塞，timeout 只适用于 .wait()/.communicate()
        if tail == "popen":
            return False

        if tail in URL_TAILS:
            return True
        if tail in SUBPROC_TAILS and "subprocess" in low:
            return True
        if tail in HTTP_TAILS and ("requests" in low or low.startswith("session.")):
            return True
        if tail == "create_connection" and "socket" in low:
            return True
        return False

    def run(self, tree, profile, adapter) -> list:
        out = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            chain = call_chain(node)
            if not self._is_target(chain):
                continue
            if self._has_timeout(node):
                continue
            out.append(Finding(
                rule_id=self.id,
                file=str(getattr(tree, "path", "<memory>")),
                line=int(getattr(node, "lineno", 0)),
                severity=self.severity,
                title=self.name,
                detail=f"调用 {chain or '<call>'} 未传 timeout，外部调用可能无限期挂起",
                evidence="",
            ))
        return out
