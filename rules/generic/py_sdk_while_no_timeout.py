"""py.sdk_while_no_timeout —— while True 循环调 C SDK 无总超时守卫。

来源：DeskPilot 跨项目审计 round-008（2026-10-12）。
    讯飞 SDK（xfyun_msc.py）三个循环路径，全部 while True 仅靠 SDK 返回状态码退出：
    - xfyun_msc.py:179-191  QTTSAudioGet 合成循环，synth_status==DATA_END 或 err!=0 才退
      SDK 异常时永不变 DATA_END，线程池 worker 永久占用，池耗尽后全请求无响应（high）
    - xfyun_msc.py:276-283  QISRGetResult IAT 识别循环，同上
    - voice_iat.py:136-147  feed_audio 内 while True 调 QISRGetResult，status!=0 才 break

判据：
    ① 存在 while True / while 1 循环（条件为常量真）
    ② 循环体内调用了 C SDK / 外部库 的「轮询取数据」函数（call 末段名匹配）
    ③ 循环体或函数内**没有**总超时守卫：
       - 无 time.time() 起始时间 + 循环内 break-on-elapsed
       - 无 time.monotonic() 同上
       - 无 max_iter / 最大迭代计数器
       - 无 asyncio.wait_for / asyncio.timeout 包装（若是 async）

    SDK 轮询函数集合（可扩展）：
        QTTSAudioGet / QISRGetResult / QTTSSessionEnd / QISRSSessionEnd
        MSPGetQzrState / MSPGetList
        （讯飞 MSC 系列：QTTS*/QISR*/MSP*）

PITFALLS 通则：C SDK 的状态机不可信——SDK 卡死时返回值永不变，
while True 循环必须在外层加总超时/最大迭代守卫，而非依赖 SDK 自身正确性。
与 py.outbound_call_no_timeout 不同：那条查单次调用无 timeout，本条查循环依赖 SDK 返回值退出。

注意：本规则是**信号型**规则——SDK 函数名匹配即可报，因为 C SDK 循环无超时是高危模式，
宁可多报（人工 triage 排除非 SDK 的通用 while True）。severity=high 但 status=testing，
需要端到端验证噪音后再转 active。
"""
from __future__ import annotations

import ast
import re

from engine.base import BaseRule, Finding, node_source
from engine.helpers import all_walk

# C SDK 轮询取数据函数（讯飞 MSC 系列为主，可扩展）
_SDK_POLL_CALLS = {
    "QTTSAudioGet", "QISRGetResult",
    "QTTSSessionEnd", "QISRSSessionEnd",
    "MSPGetQzrState", "MSPGetList",
    "QTTSGetParam", "QISRGetParam",
}

# 超时守卫信号：函数/循环内出现这些即认为有总超时
_TIMEOUT_GUARD_CALLS = {"time", "monotonic", "perf_counter", "wait_for", "timeout"}
_TIMEOUT_GUARD_REGEX = re.compile(
    r"(time\.time\(\)|time\.monotonic\(\)|time\.perf_counter\(\)|"
    r"max_iter|MAX_ITER|deadline|elapsed|asyncio\.wait_for|asyncio\.timeout)"
)


def _callee_name(call: ast.Call) -> str:
    f = call.func
    if isinstance(f, ast.Name):
        return f.id
    if isinstance(f, ast.Attribute):
        return f.attr
    return ""


def _is_const_true(node: ast.AST) -> bool:
    """while 条件是否是常量 True（True 字面量 / 1 / 非 0 数字）。"""
    if isinstance(node, ast.Constant):
        return node.value is True or node.value == 1
    return False


def _has_timeout_guard(fn: ast.AST, loop: ast.While) -> bool:
    """函数体 + 循环体源码是否含超时守卫信号。

    PITFALLS P1：all_walk=ast.walk 会下降进嵌套函数，故 fn 可能是内层 def。
    asyncio.wait_for / asyncio.timeout 常包装在内层 def 的外层 enclosing 函数，
    故需沿 parent 链向上找所有 enclosing 函数一并检查。
    """
    try:
        fn_src = ast.unparse(fn)
        loop_src = ast.unparse(loop)
    except Exception:
        return False
    if _TIMEOUT_GUARD_REGEX.search(fn_src) or _TIMEOUT_GUARD_REGEX.search(loop_src):
        return True
    # 沿 parent 链向上找 enclosing async def / def，检查其源码
    cur = getattr(fn, "parent", None)
    while cur is not None:
        if isinstance(cur, (ast.FunctionDef, ast.AsyncFunctionDef)):
            try:
                outer_src = ast.unparse(cur)
            except Exception:
                outer_src = ""
            if _TIMEOUT_GUARD_REGEX.search(outer_src):
                return True
        cur = getattr(cur, "parent", None)
    return False


class SdkWhileNoTimeoutRule(BaseRule):
    id = "py.sdk_while_no_timeout"
    name = "while True 循环调 C SDK 无总超时守卫"
    description = (
        "while True 循环调用 C SDK（讯飞 MSC 等）的轮询取数据函数，仅靠 SDK 返回状态码退出，"
        "无总超时/最大迭代守卫。SDK 状态机卡死时循环永久挂起，线程/协程被永久占用。"
        "应在循环外加总超时守卫，而非依赖 SDK 自身正确性。"
        "来源：DeskPilot xfyun_msc.py:179/276 + voice_iat.py:136。"
    )
    applies_to = []
    mode = "static_ast"
    severity = "high"
    status = "testing"  # 信号型，需端到端验证噪音后转 active
    version = "1.0.0"
    intent = "discovery"

    tests = {
        "dirty": [
            {"name": "qts-audio-get-while-true",
             "code": "from msc import QTTSAudioGet, DATA_END\n"
                     "def synth(text):\n"
                     "    out = b''\n"
                     "    while True:\n"
                     "        audio, status = QTTSAudioGet(text)\n"
                     "        out += audio\n"
                     "        if status == DATA_END:\n"
                     "            break\n"
                     "    return out\n"},
            {"name": "qisr-get-result-while-1",
             "code": "from msc import QISRGetResult, _MSP_REC_STATUS_SUCCESS\n"
                     "def recognize():\n"
                     "    text = ''\n"
                     "    while 1:\n"
                     "        chunk, status = QISRGetResult()\n"
                     "        text += chunk\n"
                     "        if status != _MSP_REC_STATUS_SUCCESS:\n"
                     "            break\n"
                     "    return text\n"},
        ],
        "clean": [
            {"name": "while-true-with-deadline",
             "code": "import time\n"
                     "from msc import QTTSAudioGet, DATA_END\n"
                     "def synth(text):\n"
                     "    out = b''\n"
                     "    deadline = time.monotonic() + 30\n"
                     "    while True:\n"
                     "        audio, status = QTTSAudioGet(text)\n"
                     "        out += audio\n"
                     "        if status == DATA_END:\n"
                     "            break\n"
                     "        if time.monotonic() > deadline:\n"
                     "            break\n"
                     "    return out\n"},
            {"name": "while-true-with-max-iter",
             "code": "from msc import QISRGetResult, SUCCESS\n"
                     "def recognize():\n"
                     "    text = ''\n"
                     "    max_iter = 1000\n"
                     "    for _ in range(max_iter):\n"
                     "        chunk, status = QISRGetResult()\n"
                     "        text += chunk\n"
                     "        if status != SUCCESS:\n"
                     "            break\n"
                     "    return text\n"},
            {"name": "while-true-non-sdk-call",
             "code": "def drain(q):\n"
                     "    out = []\n"
                     "    while True:\n"
                     "        item = q.get()\n"
                     "        if item is None:\n"
                     "            break\n"
                     "        out.append(item)\n"
                     "    return out\n"},
            {"name": "async-wait-for-wraps",
             "code": "import asyncio\n"
                     "from msc import QTTSAudioGet, DATA_END\n"
                     "async def synth(text):\n"
                     "    async def _loop():\n"
                     "        while True:\n"
                     "            audio, status = QTTSAudioGet(text)\n"
                     "            if status == DATA_END:\n"
                     "                break\n"
                     "    return await asyncio.wait_for(_loop(), timeout=30)\n"},
        ],
    }

    def run(self, tree, profile=None, adapter=None) -> list[Finding]:
        out = []
        # 建 parent 索引（_has_timeout_guard 沿 parent 链找外层 enclosing 函数）
        for parent in ast.walk(tree):
            for child in ast.iter_child_nodes(parent):
                child.parent = parent
        for fn in all_walk(tree):
            if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            for node in ast.walk(fn):
                if not isinstance(node, ast.While):
                    continue
                if not _is_const_true(node.test):
                    continue
                # 循环体内是否调用了 SDK 轮询函数
                sdk_calls = []
                for child in ast.walk(node):
                    if isinstance(child, ast.Call):
                        if _callee_name(child) in _SDK_POLL_CALLS:
                            sdk_calls.append(child)
                if not sdk_calls:
                    continue
                # 是否有超时守卫
                if _has_timeout_guard(fn, node):
                    continue
                call = sdk_calls[0]
                out.append(Finding(
                    rule_id=self.id,
                    file=str(getattr(tree, "path", "")),
                    line=node.lineno,
                    severity=self.severity,
                    title=self.name,
                    detail=(
                        f"while True 循环调用 C SDK { _callee_name(call) }()，"
                        f"仅靠 SDK 返回状态码退出，无总超时/最大迭代守卫。"
                        f"SDK 卡死时循环永久挂起，线程/协程被永久占用。"
                    ),
                    evidence=node_source(tree, node.lineno)[:200],
                ))
        return out
