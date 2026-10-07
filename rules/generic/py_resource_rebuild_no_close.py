"""py.resource_rebuild_no_close —— 重建资源对象但不关闭旧实例。

来源：memory-agent MA-25（确证 High）。
    `Router.reconfigure` 整表重建 providers，旧 AsyncClient 从不 close()；
    实测 50 次配置保存 → 150 个未关闭连接。
    **同一函数内 ha_db 那支却正确关了旧连接**（这就是对照证据）。

判据：
    ① 类里定义了 close/aclose/shutdown 的可关闭类型（本文件内取）
    ② `self.X = <构造>` 形式的重建赋值
    ③ 该函数内没有任何 close 调用

注意：全局 shutdown 正确 ≠ 热更新路径正确（lesson 125）——shutdown
      只在进程退出跑一次，而 reconfigure 是运行期反复执行。
"""
from __future__ import annotations

import ast
import re

from engine.base import BaseRule, Finding, node_source
from engine.helpers import all_walk, code_unparse

_CLOSE_CALL = re.compile(r"(\.close\(\)|\.aclose\(\)|\.shutdown\(\)|\.release\(\))")
_RES_NAMES = ("clients", "providers", "pool", "pools", "conns", "connections",
              "handlers", "sessions", "engines", "adapters")


class ResourceRebuildNoCloseRule(BaseRule):
    id = "py.resource_rebuild_no_close"
    name = "重建资源但未关闭旧实例"
    description = "对 self.<资源> 整表重建，旧对象从不 close ⇒ 连接池/句柄泄漏"
    applies_to = []
    mode = "static_ast"
    severity = "medium"
    status = "active"
    version = "1.0.0"

    tests = {
        "dirty": [
            {"name": "rebuild-dict-no-close",
             "code": "class Router:\n"
                     "    def __init__(self):\n"
                     "        self.clients = {}\n"
                     "    def reconfigure(self, cfg):\n"
                     "        self.clients = {k: mk(cfg, k) for k in ('a', 'b')}"},
        ],
        "clean": [
            {"name": "close-old-before-rebuild",
             "code": "class Pool:\n"
                     "    def __init__(self):\n"
                     "        self.clients = {}\n"
                     "    def reconfigure(self, cfg):\n"
                     "        new = build(cfg)\n"
                     "        for old in self.clients.values():\n"
                     "            old.close()\n"
                     "        self.clients = new"},
            {"name": "no-rebuild-at-all",
             "code": "class Pool:\n"
                     "    def __init__(self):\n"
                     "        self.name = 'x'\n"
                     "    def ping(self):\n"
                     "        return self.name"},
        ],
    }

    def run(self, tree, profile=None, adapter=None) -> list[Finding]:
        closable = set()
        for cls in all_walk(tree):
            if not isinstance(cls, ast.ClassDef):
                continue
            for f in ast.walk(cls):
                if isinstance(f, (ast.FunctionDef, ast.AsyncFunctionDef)) and \
                        re.match(r"(a?close|shutdown|stop|release)", f.name):
                    closable.add(cls.name)
        out = []
        for fn in all_walk(tree):
            if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            try:
                code = code_unparse(fn)
            except Exception:
                continue
            if fn.name in ("__init__", "__new__", "setup", "setUp"):
                continue  # 首次初始化不是"重建"
            if _CLOSE_CALL.search(code):
                continue  # 已有关闭动作
            names = sorted(closable) + list(_RES_NAMES)
            pat = rf"self\.({'|'.join(names)})\s*=\s*"
            for m in re.finditer(pat, code):
                rhs = code[m.end():m.end() + 30].strip()
                if rhs.startswith(("{}", "[", "None", "''", '""')):
                    continue  # 赋空值不是重建
                out.append(Finding(
                    rule_id=self.id, file=str(tree.path), line=fn.lineno,
                    severity=self.severity, title=self.name,
                    detail=f"`{fn.name}` 重建 `self.{m.group(1)}` 但未见关闭旧实例",
                    evidence=node_source(tree, fn.lineno)[:200],
                ))
                break
        return out
