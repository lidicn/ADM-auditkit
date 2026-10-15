"""py.print_trace_not_logger —— 失败留痕走 print，未进日志系统。

来源：memory-agent 第五期（MA49/MA63/MA69/MA75/MA77/MA79/MA85/MA88/MA89 + MA-GAP-017），
    全仓量化 243 处 print 留痕（库模块 227、CLI/脚本 16 合理不计）。典型 MA75：
    相隔 4 行，unicode61 分支已 logger.error，全失败分支仍 print。

量化背书（doubao-butler 第五期 GDAL-BUG-020，2026-10-15）：盲抽池判据把所有 except
    一律标"静默"，892 个站点里 46.4% 实际有 logger/print 留痕——"只认有无 except、
    不认留痕通道质量"的粗糙判据假阳性近半。本条判"print 弱留痕"正是对该量化的回应。

与 py.silent_except_no_trace 的分工：
    那条判"四叉留痕均无"（logger/print/warn/raise/计数/记账 都算留痕）；
    本条判**留痕通道质量**——handler 用了 print 但没用 logger/warn。
    print 不进日志系统、部署默认档（root logger WARNING）不可观测、
    与"没匹配上/成功"逐字同形。故 print 是"弱留痕"，库模块应升级为 logger。

排除项（均有更强的留痕或不同语义）：
    · handler 已用 logger/logging/_log/warn（强通道）→ 不报
    · handler 有 raise（fail-loud，print 只是辅助）→ 不报
    · handler 有记账/计数/毒化标志（比 print 强）→ 不报
    · asyncio.CancelledError（关停语义）→ 不报
    · CLI/脚本入口的 print 合理 —— 静态难判，故 severity=info 作人工清单，不派单
"""
from __future__ import annotations

import ast
import re

from engine.base import BaseRule, Finding, node_source
from engine.helpers import all_walk, own_walk

_LOG_RE = re.compile(r"logger\.|logging\.|_log\.|warnings?\.warn")
_RAISE_RE = re.compile(r"\braise\b")
# 复用 silent_except 的记账/毒化补充（比 print 强，lesson 40）
_POISON = re.compile(
    r"(\b\w*(?:POISON|POISONED|poisoned|broken|degraded|stale|dirty)\w*\s*=\s*True|"
    r"\b\w+\.append\(|\b\w*(?:_ok|ok)\w*\s*=\s*False)")


class PrintTraceNotLoggerRule(BaseRule):
    id = "py.print_trace_not_logger"
    name = "失败留痕走 print 不走日志"
    description = "except/失败路径用 print 留痕，未进日志系统（部署档不可观测、与成功同形）"
    applies_to = []
    mode = "static_ast"
    severity = "low"
    status = "active"
    version = "1.0.0"

    tests = {
        "dirty": [
            {"name": "print-only-trace",
             "code": "def load():\n"
                     "    try:\n"
                     "        return read()\n"
                     "    except Exception as e:\n"
                     "        print('load failed', e)\n"
                     "        return None"},
            {"name": "print-fstring-trace",
             "code": "def load(p):\n"
                     "    try:\n"
                     "        return read(p)\n"
                     "    except Exception as e:\n"
                     "        print(f'load {p} failed: {e}')\n"
                     "        return {}"},
        ],
        "clean": [
            {"name": "logger-trace",
             "code": "import logging\n"
                     "def load():\n"
                     "    try:\n"
                     "        return read()\n"
                     "    except Exception as e:\n"
                     "        logging.warning('load failed: %s', e)\n"
                     "        return None"},
            {"name": "logger-attr-trace",
             "code": "def load():\n"
                     "    try:\n"
                     "        return read()\n"
                     "    except Exception as e:\n"
                     "        logger.error('load failed: %s', e)\n"
                     "        return None"},
            {"name": "raise-fail-loud",
             "code": "def load():\n"
                     "    try:\n"
                     "        return read()\n"
                     "    except Exception as e:\n"
                     "        print('load failed', e)\n"
                     "        raise"},
            {"name": "poison-flag",
             "code": "def load():\n"
                     "    try:\n"
                     "        return read()\n"
                     "    except Exception:\n"
                     "        print('load failed')\n"
                     "        POISONED = True\n"
                     "        return None"},
            {"name": "cancelled-shutdown",
             "code": "async def gen():\n"
                     "    try:\n"
                     "        await work()\n"
                     "    except asyncio.CancelledError:\n"
                     "        print('cancelled')\n"
                     "        return"},
        ],
    }

    def run(self, tree, profile=None, adapter=None) -> list[Finding]:
        out = []
        for scope in all_walk(tree):
            if not isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            for h in own_walk(scope):
                if not isinstance(h, ast.ExceptHandler):
                    continue
                if h.type is not None:
                    try:
                        if "CancelledError" in ast.unparse(h.type):
                            continue  # 关停语义 ≠ 容错语义
                    except Exception:
                        pass
                try:
                    hb = ast.unparse(h)
                except Exception:
                    continue
                if len(hb.strip()) < 8:
                    continue
                if "print(" not in hb:
                    continue
                if _LOG_RE.search(hb):
                    continue          # 已走 logger/warn（强通道）
                if _RAISE_RE.search(hb):
                    continue          # fail-loud，print 只是辅助
                if _POISON.search(hb):
                    continue          # 记账/毒化比 print 强
                out.append(Finding(
                    rule_id=self.id, file=str(getattr(tree, "path", "<memory>")),
                    line=h.lineno, severity=self.severity, title=self.name,
                    detail=(f"`{scope.name}` 的 except 用 print 留痕、未进日志系统；"
                            f"库模块应升级为 logger（CLI 脚本可接受）"),
                    evidence=node_source(tree, h.lineno)[:200],
                ))
        return out
