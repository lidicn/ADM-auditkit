#!/usr/bin/env python3
"""规则：出站调用显式关闭超时（timeout=None）。

**来源**：2026-10-12 十项目批量审计（R1 基线轮）。排查 `py.outbound_call_no_timeout`
时发现该规则用「是否出现 timeout 关键字」判定（`_has_timeout`），于是
`timeout=None` 这种**显式拆掉护栏**的写法会被当成「已设超时」放行——
比"忘记设"更恶劣，却恰好落在既有规则的盲区里。本规则补这个洞，
与 `py.outbound_call_no_timeout`**互不重叠**（后者管"没传"，本规则管"传了但关掉"）。

**为什么是缺陷**：`urlopen(u, timeout=None)`、`requests.get(u, timeout=None)`、
`httpx.Client(timeout=None)` 都是"无限期等待"。写这种代码通常是为了调试时
绕开超时，然后忘了删；在常驻服务里表现为偶发永久挂起，且**没有任何日志**。

**判据局部性**：只判 timeout 关键字的值是字面量 None。不判数值是否过小
（那是容量问题不是挂死问题），不判重试/熔断。

**AST 契约提醒（踩坑记录）**：`engine.base.parse_unit` 返回的是**附着了
source/path 的 ast.Module**，不是包装对象——**没有 `.ast` 属性**。
必须用 `getattr(tree, "ast", tree)` 兼容，否则 AttributeError 会把规则变成静默失效。
（`docs/RULE_AUTHORING_GUIDE.md` §7 写的是 `tree.ast`，与实现不符，已另立提案。）
"""
from __future__ import annotations

import ast

from engine.base import BaseRule, Finding, node_source, call_chain

_TARGET_TAILS = {
    "urlopen", "urlretrieve", "get", "post", "put", "patch", "delete",
    "head", "options", "request", "run", "call", "check_output", "check_call",
    "stream", "send",
}
_HTTPX_CLIENT = {"Client", "AsyncClient"}


class HttpTimeoutDisabledRule(BaseRule):
    id = "py.http_timeout_disabled"
    name = "出站调用显式关闭超时"
    description = (
        "HTTP/子进程出站调用传了 timeout=None——显式关闭超时护栏，"
        "对端不响应时无限期挂起且无日志；比'忘记设超时'更隐蔽。"
    )
    applies_to: list[str] = []
    mode = "static_ast"
    severity = "high"
    status = "active"
    version = "1.0.0"
    intent = "discovery"

    tests = {
        "dirty": [
            {"name": "requests-timeout-none",
             "code": "import requests\n\ndef f(u):\n    return requests.get(u, timeout=None)\n"},
            {"name": "urlopen-timeout-none",
             "code": "import urllib.request\n\ndef f(u):\n    return urllib.request.urlopen(u, timeout=None)\n"},
        ],
        "clean": [
            {"name": "requests-with-real-timeout",
             "code": "import requests\n\ndef f(u):\n    return requests.get(u, timeout=10)\n"},
            {"name": "dict-get-unrelated",
             "code": "def f(c):\n    return c.get(\"k\", None)\n"},
        ],
    }

    def run(self, tree, profile=None, adapter=None) -> list[Finding]:
        # AST 契约：parse_unit 返回 ast.Module（附着 source/path），没有 .ast 属性。
        root = getattr(tree, "ast", tree)
        out: list[Finding] = []
        for node in ast.walk(root):
            if not isinstance(node, ast.Call):
                continue
            chain = call_chain(node)
            if not chain:
                continue
            tail = chain.split(".")[-1]
            if tail not in _TARGET_TAILS and tail not in _HTTPX_CLIENT:
                continue
            # 排除内存操作：dict.get 的第二参数是 default 不是 timeout
            if tail == "get" and "requests" not in chain.lower() \
                    and not chain.lower().startswith(("session.", "httpx.", "client.", "http")):
                continue
            for kw in node.keywords:
                if kw.arg == "timeout" and isinstance(kw.value, ast.Constant) \
                        and kw.value.value is None:
                    out.append(Finding(
                        rule_id=self.id,
                        file=str(getattr(tree, "path", "<memory>")),
                        line=int(getattr(node, "lineno", 0)),
                        severity=self.severity,
                        title=self.name,
                        detail=f"`{chain}(timeout=None)` 显式关闭超时，对端不响应将无限期挂起",
                        evidence=node_source(tree, node)[:200],
                    ))
                    break
        return out
