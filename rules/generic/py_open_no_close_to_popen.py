"""py.open_no_close_to_popen —— open() 不用 with 传 Popen stdout/stderr 后父进程不关闭句柄。

来源：DeskPilot 跨项目审计 round-008（2026-10-12）。
    - backend/service.py:173-174  out_log = open(log_dir / "gateway.out.log", "a")
      err_log = open(...)  传给 Popen(stdout=out_log, stderr=err_log)，父进程永不 close
    - backend/core/supervisor.py:98-99  完全相同的模式，在 _monitor_loop 重启循环中反复泄漏

判据：
    ① 存在 open(...) 赋值给某变量 V（Assign，非 with 语句内）
    ② 同一作用域内存在 subprocess.Popen(...) 调用
    ③ 该 Popen 的 stdout= 或 stderr= 实参引用了 V（同名字面匹配）

PITFALLS 通则：Popen 子进程继承 fd 后父进程应立即 close（子进程已拿到 fd）。
不用 with 传给 Popen 的 open() 句柄，父进程永不关闭 ⇒ 每次重启泄漏 2 句柄，
频繁重启后耗尽 FD（Windows 默认上限 512/16384）。_stop_gateway 只 kill 进程不关句柄。

不报的情况（clean）：
    - open() 在 with 语句内（with-statement 的 context manager 负责 close）
    - open() 返回值赋给变量后被显式 .close()
    - open() 用于普通文件读写（不传给 Popen）
"""
from __future__ import annotations

import ast

from engine.base import BaseRule, Finding, node_source
from engine.helpers import all_walk


def _callee_name(call: ast.Call) -> str:
    f = call.func
    if isinstance(f, ast.Name):
        return f.id
    if isinstance(f, ast.Attribute):
        return f.attr
    return ""


def _is_with_target(node: ast.AST, name: str) -> bool:
    """name 是否是 with 语句的 as 目标（被 with 管理）。"""
    # 向上找父节点链
    parent = getattr(node, "parent", None)
    while parent is not None:
        if isinstance(parent, ast.With):
            for item in parent.items:
                tgt = item.optional_vars
                if isinstance(tgt, ast.Name) and tgt.id == name:
                    return True
        parent = getattr(parent, "parent", None)
    return False


def _is_closed_later(fn: ast.AST, var_name: str) -> bool:
    """函数体内是否有 var_name.close() 调用。"""
    for node in ast.walk(fn):
        if isinstance(node, ast.Call):
            f = node.func
            if isinstance(f, ast.Attribute) and f.attr == "close":
                if isinstance(f.value, ast.Name) and f.value.id == var_name:
                    return True
    return False


class OpenNoCloseToPopenRule(BaseRule):
    id = "py.open_no_close_to_popen"
    name = "open() 不用 with 传 Popen stdout/stderr 后父进程不关句柄"
    description = (
        "open() 不用 with 语句，返回的句柄传给 subprocess.Popen 的 stdout/stderr，"
        "父进程永不 close。Popen 子进程继承 fd 后父进程应立即 close，"
        "否则每次进程重启泄漏句柄，频繁重启后耗尽 FD。"
        "来源：DeskPilot service.py:173 + supervisor.py:98。"
    )
    applies_to = []
    mode = "static_ast"
    severity = "high"
    status = "active"
    version = "1.0.0"
    intent = "discovery"

    tests = {
        "dirty": [
            {"name": "open-to-popen-stdout-no-close",
             "code": "import subprocess\n"
                     "def start():\n"
                     "    out_log = open('log.out', 'a')\n"
                     "    err_log = open('log.err', 'a')\n"
                     "    p = subprocess.Popen(['cmd'], stdout=out_log, stderr=err_log)\n"
                     "    return p\n"},
            {"name": "open-to-popen-stderr-only",
             "code": "import subprocess\n"
                     "def start():\n"
                     "    log = open('log.out', 'a')\n"
                     "    subprocess.Popen(['cmd'], stderr=log)\n"},
        ],
        "clean": [
            {"name": "with-statement-manages-handle",
             "code": "import subprocess\n"
                     "def start():\n"
                     "    with open('log.out', 'a') as out_log:\n"
                     "        p = subprocess.Popen(['cmd'], stdout=out_log)\n"
                     "    return p\n"},
            {"name": "explicit-close-after-popen",
             "code": "import subprocess\n"
                     "def start():\n"
                     "    out_log = open('log.out', 'a')\n"
                     "    p = subprocess.Popen(['cmd'], stdout=out_log)\n"
                     "    out_log.close()\n"
                     "    return p\n"},
            {"name": "open-for-normal-read",
             "code": "def read_config():\n"
                     "    f = open('config.json')\n"
                     "    data = f.read()\n"
                     "    f.close()\n"
                     "    return data\n"},
            {"name": "popen-without-file-stdout",
             "code": "import subprocess\n"
                     "def start():\n"
                     "    p = subprocess.Popen(['cmd'], stdout=subprocess.PIPE)\n"
                     "    return p\n"},
        ],
    }

    def run(self, tree, profile=None, adapter=None) -> list[Finding]:
        out = []
        # 建 parent 索引
        for parent in ast.walk(tree):
            for child in ast.iter_child_nodes(parent):
                child.parent = parent

        for fn in all_walk(tree):
            if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            # 收集本函数内 open() 赋值给变量 V 的映射（V 名 → Assign 行号）
            open_assigns: dict[str, int] = {}
            for node in ast.walk(fn):
                if isinstance(node, ast.Assign):
                    for tgt in node.targets:
                        if isinstance(tgt, ast.Name):
                            val = node.value
                            if isinstance(val, ast.Call):
                                if _callee_name(val) == "open":
                                    # 检查不是在 with 内（with 内的 as 目标由 context manager 管）
                                    if not _is_with_target(node, tgt.id):
                                        open_assigns[tgt.id] = node.lineno
            if not open_assigns:
                continue
            # 查本函数内 Popen 调用的 stdout=/stderr= 是否引用了 open 变量
            for node in ast.walk(fn):
                if not isinstance(node, ast.Call):
                    continue
                if _callee_name(node) != "Popen":
                    continue
                for kw in node.keywords:
                    if kw.arg in ("stdout", "stderr"):
                        if isinstance(kw.value, ast.Name) and kw.value.id in open_assigns:
                            var = kw.value.id
                            # 判据：未被 with 管理 + 未被显式 close
                            if _is_closed_later(fn, var):
                                continue
                            out.append(Finding(
                                rule_id=self.id,
                                file=str(getattr(tree, "path", "")),
                                line=open_assigns[var],
                                severity=self.severity,
                                title=self.name,
                                detail=(
                                    f"open() 赋值给 `{var}` 不用 with，传给 subprocess.Popen "
                                    f"的 {kw.arg}= 后父进程不 close。子进程继承 fd 后父进程应立即 close，"
                                    f"否则每次进程重启泄漏句柄，频繁重启后耗尽 FD。"
                                ),
                                evidence=node_source(tree, open_assigns[var])[:200],
                            ))
        return out
