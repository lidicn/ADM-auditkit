"""ma.acp_entry_no_owner_check —— ACP 会话入口未做属主校验。

来源：memory-agent MA-36（确证 **Critical**）
    acp_server.py 中 `M_SESSION_HISTORY` / `M_SESSION_DELETE` / `M_CANCEL`
    三个入口都调了 `check_owner`，唯独 `M_PROMPT`（:416）没有——
    而 M_PROMPT 恰恰是**能力最强**的（会真起 DebugRun 执行指令）。

    实测：B 用 A 的 sessionId 调 M_PROMPT ⇒ 直接放行，
    读到 A 的会话历史（LLM 请求含 A 的卡号），并把 B 的指令写回 A 的会话。

判据（lesson 168 + 174，两步走，缺一步就全是假阳性）：
    ① **先定模块边界**：只在该模块**已定义属主校验 helper** 时才谈对等
       （全仓扫会把"从未设计过"的地方判成"漏做了"，假阳性 21→3）
    ② 在该模块内按**资源 ID 形参分组**，找出"接受资源 ID 却不调 helper"的入口

clean 样本：所有入口都校验，或模块内根本没有属主设计 ⇒ 不命中。
"""
from __future__ import annotations

import ast
import re

from engine.base import BaseRule, Finding, node_source
from engine.helpers import all_walk, code_unparse

_OWNER_FN = re.compile(r"(check_owner|assert_owner|_owner_check|verify_owner)", re.I)
_OWNER_CALL = re.compile(r"(check_owner|assert_owner|verify_owner)", re.I)
_RES_PARAM = re.compile(r"^(sid|session_id|sessionId|owner_id|resource_id|conversation_id)$", re.I)
_CREATE = re.compile(r"^(new_|create_|make_|register|bind)", re.I)


class AcpEntryNoOwnerCheckRule(BaseRule):
    id = "ma.acp_entry_no_owner_check"
    name = "ACP 会话入口未做属主校验"
    description = "同模块已有属主校验 helper，但该入口接受资源 ID 却未调用 ⇒ 跨主体读写"
    applies_to = ["memory-agent"]
    mode = "static_ast"
    severity = "critical"
    status = "active"
    version = "1.0.0"

    tests = {
        "dirty": [
            {"name": "prompt-missing-owner-check",
             "code": "OWNERS = {}\n"
                     "def check_owner(sid, owner_token):\n"
                     "    if not owner_token:\n"
                     "        return False\n"
                     "    return OWNERS.get(sid) == owner_token\n"
                     "def session_history(sid, caller):\n"
                     "    if not check_owner(sid, caller):\n"
                     "        return {'ok': False}\n"
                     "    return {'ok': True}\n"
                     "def do_prompt(sid, caller):\n"
                     "    return {'ok': True, 'session_id': sid}"},
        ],
        "clean": [
            {"name": "all-entries-checked",
             "code": "OWNERS = {}\n"
                     "def check_owner(sid, owner_token):\n"
                     "    return bool(owner_token) and OWNERS.get(sid) == owner_token\n"
                     "def session_history(sid, caller):\n"
                     "    if not check_owner(sid, caller):\n"
                     "        return {'ok': False}\n"
                     "    return {'ok': True}\n"
                     "def do_prompt(sid, caller):\n"
                     "    if not check_owner(sid, caller):\n"
                     "        return {'ok': False, 'error': 'denied'}\n"
                     "    return {'ok': True}"},
            {"name": "no-owner-design-in-module",
             "code": "def do_prompt(sid, caller):\n"
                     "    return {'ok': True, 'session_id': sid}\n"
                     "def helper(sid):\n"
                     "    return sid"},
        ],
    }

    def run(self, tree, profile=None, adapter=None) -> list[Finding]:
        fns = [f for f in all_walk(tree)
               if isinstance(f, (ast.FunctionDef, ast.AsyncFunctionDef))]
        if not any(_OWNER_FN.search(f.name) for f in fns):
            return []  # 该模块无属主设计 ⇒ 不适用（lesson 168）
        entries = []
        for f in fns:
            if _OWNER_FN.search(f.name) or _CREATE.search(f.name):
                continue
            args = [a.arg for a in f.args.args] + [a.arg for a in f.args.kwonlyargs]
            if not any(_RES_PARAM.search(a) for a in args):
                continue
            try:
                entries.append((f, code_unparse(f)))
            except Exception:
                continue
        guarded = [f for f, b in entries if _OWNER_CALL.search(b)]
        if not guarded:
            return []  # 没有任何入口做校验 ⇒ 不是"漏一个"
        out = []
        for f, b in entries:
            if _OWNER_CALL.search(b):
                continue
            out.append(Finding(
                rule_id=self.id, file=str(tree.path), line=f.lineno,
                severity=self.severity, title=self.name,
                detail=(f"`{f.name}` 接受资源 ID 但未调用属主校验；"
                        f"同模块 {len(guarded)} 个入口做了（"
                        + ", ".join(sorted({g.name for g in guarded})[:3]) + "）"),
                evidence=node_source(tree, f.lineno)[:200],
            ))
        return out
