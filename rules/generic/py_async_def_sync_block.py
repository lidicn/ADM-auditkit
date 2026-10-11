"""py.async_def_sync_block —— async def 内同步阻塞调用卡死事件循环。

来源：DeskPilot 跨项目审计 round-008（2026-10-12）。
    两个独立触发路径，同一缺陷类：
    - backend/desktop_agent.py:655  async def exec_tool 同步调 _invoke_desktop
      （ctypes 桌面操作 + subprocess + time.sleep ~7s）⇒ /health 挂起 30s+
      agent_watcher 误判崩溃并重启（critical）
    - backend/api/v1/ws.py:175  async def _broadcast_loop 同步调 collect_status()
      （psutil.cpu_percent(interval=0.1) 阻塞 100ms + COM/pycaw + ctypes EnumWindows）
      每个 WS 推送周期阻塞事件循环 100ms+，连接时所有 HTTP/WS 停摆（high）

判据（组内 AND，组间 OR）：
    ① 函数是 async def（ast.AsyncFunctionDef）
    ② 函数体内直接出现同步阻塞调用，且该调用**未**被 asyncio.to_thread/run_in_executor 包装
    阻塞调用集合（call 末段名或 attr 名）：
        - time.sleep
        - psutil.cpu_percent / cpu_times_percent / virtual_memory（带 interval=）
        - subprocess.Popen / subprocess.run / subprocess.call / subprocess.check_output / .communicate
        - ctypes 调用（windll / cdll / ctypes.windll / ctypes.cdll）
        - win32com / Dispatch / CoInitialize
        - requests.get / requests.post / requests.request（同步 HTTP）
    ③ 排除：调用出现在 asyncio.to_thread(...)/loop.run_in_executor(...) 的实参内（已被正确包装）

PITFALLS 通则：async def 体内凡同步阻塞调用必须 asyncio.to_thread 包装，
否则单线程事件循环被阻塞期间所有并发请求/协程停摆。
本规则只报「裸调用」，不报已被 to_thread 包装的（clean 样本）。

已知局限：ctypes 调用若经中间变量赋值（`user32 = ctypes.windll.user32` 后
`user32.GetForegroundWindow()`），receiver 是 Name(user32)，静态分析无法追踪
变量来源，规则不报。dirty 样本用直链 `ctypes.windll.user32.X()` 形态。
"""
from __future__ import annotations

import ast

from engine.base import BaseRule, Finding, node_source
from engine.helpers import all_walk

# 同步阻塞调用：call 末段名
_BLOCKING_CALLS = {
    "sleep",
    "cpu_percent", "cpu_times_percent", "virtual_memory",
    "Popen", "run", "call", "check_output", "check_call", "communicate",
    "Dispatch", "CoInitialize",
    "get", "post", "request",  # requests.* 同步 HTTP
}

# ctypes 模块前缀（receiver 是 windll/cdll/ctypes.windll/ctypes.cdll）
_CTYPES_ATTRS = {"windll", "cdll", "oledll", "WinDLL", "CDLL"}


def _is_in_to_thread(node: ast.AST) -> bool:
    """判断 node 是否在 asyncio.to_thread(...) 或 loop.run_in_executor(...) 的实参内。"""
    parent = getattr(node, "parent", None)
    cur = node
    # 向上找最近的 Call
    while cur is not None:
        cur = getattr(cur, "parent", None)
        if isinstance(cur, ast.Call):
            callee = _callee_name(cur)
            if callee in ("to_thread", "run_in_executor"):
                # node 在该 Call 的 args 内即为已被包装
                if any(a is node for a in cur.args):
                    return True
                # 递归：node 可能是 args 内的子表达式
                return _expr_contains(cur, node)
    return False


def _expr_contains(container: ast.AST, target: ast.AST) -> bool:
    """target 是否在 container 的 AST 子树内。"""
    for child in ast.walk(container):
        if child is target:
            return True
    return False


def _callee_name(call: ast.Call) -> str:
    """取调用末段名：asyncio.to_thread → to_thread；foo.bar() → bar。"""
    f = call.func
    if isinstance(f, ast.Name):
        return f.id
    if isinstance(f, ast.Attribute):
        return f.attr
    return ""


def _is_ctypes_call(call: ast.Call) -> bool:
    """receiver 链含 ctypes.windll / ctypes.cdll / 裸 windll / 裸 cdll 等。

    ctypes.windll.user32.GetForegroundWindow() 的 func 是 Attribute(GetForegroundWindow)，
    其 receiver 是 Attribute(user32, value=Attribute(windll, value=Name(ctypes)))。
    沿 receiver 链向下找是否有 ctypes.windll 这种组合。
    """
    f = call.func
    if not isinstance(f, ast.Attribute):
        return False
    # 沿 receiver 链收集所有 attr 和最底 Name.id
    chain_attrs = []
    recv = f.value
    while isinstance(recv, ast.Attribute):
        chain_attrs.append(recv.attr)
        recv = recv.value
    if isinstance(recv, ast.Name):
        chain_attrs.append(recv.id)
    # 链里同时出现 ctypes 且其后跟 windll/cdll/...（任意 ctypes.* 前缀即算）
    if "ctypes" in chain_attrs:
        for a in _CTYPES_ATTRS:
            if a in chain_attrs:
                return True
    # 裸 windll.X() / 裸 cdll.X()（无 ctypes 前缀但首段是 windll/cdll）
    if chain_attrs and chain_attrs[-1] in _CTYPES_ATTRS:
        return True
    return False


class AsyncDefSyncBlockRule(BaseRule):
    id = "py.async_def_sync_block"
    name = "async def 内同步阻塞调用卡死事件循环"
    description = (
        "async def 函数体内直接调用同步阻塞操作（time.sleep / psutil 采集 / subprocess / "
        "ctypes / win32com / 同步 HTTP），未用 asyncio.to_thread 包装。"
        "单线程事件循环被阻塞期间所有并发请求/协程停摆，是 FastAPI/asyncio 最常见稳定性陷阱。"
        "来源：DeskPilot desktop_agent.py:655（critical）+ ws.py:175（high）。"
    )
    applies_to = []
    mode = "static_ast"
    severity = "high"
    status = "active"
    version = "1.0.0"
    intent = "discovery"

    tests = {
        "dirty": [
            {"name": "async-def-time-sleep",
             "code": "import asyncio, time\n"
                     "async def poll():\n"
                     "    time.sleep(7)\n"
                     "    return 'done'\n"},
            {"name": "async-def-subprocess-popen",
             "code": "import subprocess\n"
                     "async def run_cmd(cmd):\n"
                     "    p = subprocess.Popen(cmd)\n"
                     "    p.communicate()\n"
                     "    return p.returncode\n"},
            {"name": "async-def-psutil-interval",
             "code": "import psutil\n"
                     "async def collect_status():\n"
                     "    cpu = psutil.cpu_percent(interval=0.1)\n"
                     "    return cpu\n"},
            {"name": "async-def-ctypes",
             "code": "import ctypes\n"
                     "async def get_foreground():\n"
                     "    hwnd = ctypes.windll.user32.GetForegroundWindow()\n"
                     "    return hwnd\n"},
        ],
        "clean": [
            {"name": "wrapped-in-to-thread",
             "code": "import asyncio, time\n"
                     "async def poll():\n"
                     "    await asyncio.to_thread(time.sleep, 7)\n"
                     "    return 'done'\n"},
            {"name": "wrapped-in-run_in_executor",
             "code": "import asyncio, subprocess\n"
                     "async def run_cmd(loop, cmd):\n"
                     "    return await loop.run_in_executor(None, subprocess.run, cmd)\n"},
            {"name": "sync-def-not-flagged",
             "code": "import time\n"
                     "def poll():\n"
                     "    time.sleep(7)\n"
                     "    return 'done'\n"},
            {"name": "async-def-await-async-call",
             "code": "import asyncio\n"
                     "async def fetch(session):\n"
                     "    return await session.get('http://x')\n"},
        ],
    }

    def run(self, tree, profile=None, adapter=None) -> list[Finding]:
        out = []
        # 先建 parent 索引（用于判断是否在 to_thread 内）
        for parent in ast.walk(tree):
            for child in ast.iter_child_nodes(parent):
                child.parent = parent

        for fn in all_walk(tree):
            if not isinstance(fn, ast.AsyncFunctionDef):
                continue
            for node in ast.walk(fn):
                if not isinstance(node, ast.Call):
                    continue
                callee = _callee_name(node)
                # 判据②：是否阻塞调用
                blocking = False
                reason = ""
                if callee in _BLOCKING_CALLS:
                    # requests.get/post/request 末段名 get/post/request 过宽，
                    # 只在 receiver 名为 requests/httpx 同步客户端时才算
                    if callee in ("get", "post", "request"):
                        recv = node.func.value if isinstance(node.func, ast.Attribute) else None
                        recv_name = ""
                        if isinstance(recv, ast.Name):
                            recv_name = recv.id
                        elif isinstance(recv, ast.Attribute):
                            recv_name = recv.attr
                        if recv_name in ("requests",):
                            blocking = True
                            reason = f"async def 内同步 HTTP requests.{callee}()"
                        elif recv_name in ("httpx",) and callee in ("get", "post", "request"):
                            # httpx.Client（同步）才报，httpx.AsyncClient 不报（但静态难分，保守报）
                            blocking = True
                            reason = f"async def 内同步 HTTP httpx.{callee}()"
                    else:
                        blocking = True
                        reason = f"async def 内同步阻塞调用 {callee}()"
                elif _is_ctypes_call(node):
                    blocking = True
                    reason = "async def 内 ctypes 同步调用"
                if not blocking:
                    continue
                # 判据③：是否已被 to_thread/run_in_executor 包装
                if _is_in_to_thread(node):
                    continue
                out.append(Finding(
                    rule_id=self.id,
                    file=str(getattr(tree, "path", "")),
                    line=node.lineno,
                    severity=self.severity,
                    title=self.name,
                    detail=reason + "；未用 asyncio.to_thread/run_in_executor 包装，阻塞事件循环。",
                    evidence=node_source(tree, node.lineno)[:200],
                ))
        return out
