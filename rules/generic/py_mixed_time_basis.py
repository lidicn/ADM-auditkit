#!/usr/bin/env python3
"""规则：同一文件内时间基准混用（naive 本地时间 与 带时区时间 并存）。

**来源**：2026-10-12 十项目批量审计（R1 基线轮）跨项目时间口径排查确证（G1/G2/G3）。
- memory-agent 对外发 MQTT 用 `now_local(tz_offset_hours).isoformat()`（无时区后缀的
  本地串，如 `vision_service.py:1137`、`mqtt_bridge.py:345`）；
- AutoForge 一律 `datetime.now(timezone.utc)`（`af_store.py:104`、`af_time.py:285`）；
- doubao-butler 大量裸 `datetime.now()`（`triggers/engine.py:167,264,325`、
  `tools/schedule.py:25,119`、`core/cron_task.py:89,359`）。

**为什么是缺陷（且是跨项目缺陷）**：容器默认 UTC。管家写库用容器本地时间（UTC），
MA 读同一份数据按 +08:00 本地时间解释 → **跨项目边界处所有"今天/今晚/跨午夜"判定
整体错位 8 小时**：夜间会话被截断到前一天、日环比窗口重叠或漏一天、定时提醒提前/延后
8 小时。这种错误**不抛异常、不产生告警**，只表现为"数据看起来不太对"，是最难发现的
一类稳定性/功能性缺陷。

单看任一项目都"没有 bug"——缺陷只存在于**两个项目的口径差异**里。这正是纯单仓
静态分析会漏掉、必须显式建模的缺陷类。本规则把它下沉到"同文件混用"这一可机械
判定的前兆形态上。

**判据局部性**：只判"同一文件里 naive 与 aware 两种取时方式并存"，不判定哪种是对的。
命中不等于缺陷，但命中文件是跨项目时间对齐时必须逐个人工确认的对象。
"""
from __future__ import annotations

import ast

from engine.base import BaseRule, Finding, source_line
from engine.helpers import call_full

_AWARE_MARKERS = {"astimezone", "utcnow", "timezone.utc", "ZoneInfo", "tzinfo",
                  "tz_convert", "tz_localize", "house_tz", "tz_offset"}


class MixedTimeBasisRule(BaseRule):
    id = "py.mixed_time_basis"
    name = "同一文件内时间基准混用"
    description = (
        "naive 取时（datetime.now() 无参 / utcnow()）与 aware 取时（带 tz 参数、"
        "astimezone、ZoneInfo、tz_offset）在同一文件并存。跨项目边界上本地时间与 UTC "
        "混用会让'今天/跨午夜'判定整体错位，且不抛异常、无告警。"
    )
    applies_to: list[str] = []
    mode = "static_ast"
    severity = "medium"
    status = "active"
    version = "1.0.0"
    intent = "discovery"

    tests = {
        "dirty": [
            {"name": "naive-and-aware-in-one-file",
             "code": (
                 "from datetime import datetime, timezone\n"
                 "import time\n"
                 "\n"
                 "def a():\n"
                 "    return datetime.now()\n"
                 "\n"
                 "def b():\n"
                 "    return datetime.now(timezone.utc)\n"
             )},
            {"name": "naive-and-astimezone",
             "code": (
                 "from datetime import datetime\n"
                 "\n"
                 "def a():\n"
                 "    return datetime.now()\n"
                 "\n"
                 "def b(t):\n"
                 "    return datetime.now().astimezone()\n"
             )},
        ],
        "clean": [
            {"name": "only-naive",
             "code": "from datetime import datetime\n\ndef a():\n    return datetime.now()\n"},
            {"name": "only-aware",
             "code": (
                 "from datetime import datetime, timezone\n"
                 "\n"
                 "def a():\n"
                 "    return datetime.now(timezone.utc)\n"
             )},
            {"name": "no-datetime-at-all",
             "code": "import time\n\ndef a():\n    return time.time()\n"},
        ],
    }

    def run(self, tree, profile=None, adapter=None) -> list[Finding]:
        # AST 契约：parse_unit 返回 ast.Module（附着 source/path），没有 .ast 属性。
        root = getattr(tree, "ast", tree)
        source = getattr(tree, "source", "") or ""
        nodes = list(ast.walk(root))

        naive_line = None
        aware_line = None

        for node in nodes:
            if isinstance(node, ast.Call):
                full = call_full(node)
                if full in ("datetime.now", "datetime.utcnow"):
                    has_tz_arg = bool(node.args) or any(k.arg in ("tz", "tzinfo") for k in node.keywords)
                    if has_tz_arg:
                        aware_line = aware_line if aware_line is not None else node.lineno
                    else:
                        naive_line = naive_line if naive_line is not None else node.lineno
                elif full == "datetime.now().astimezone":
                    aware_line = aware_line if aware_line is not None else node.lineno

        # 兜底：源码里出现 tz 相关字面量也算 aware 证据（覆盖 now_local(...) 等封装）
        if aware_line is None:
            for marker in _AWARE_MARKERS:
                if marker in source:
                    aware_line = -1
                    break

        if naive_line is None or aware_line is None:
            return []

        return [Finding(
            rule_id=self.id,
            file=str(tree.path),
            line=naive_line,
            severity=self.severity,
            title=self.name,
            detail=(f"第 {naive_line} 行为 naive 取时（无时区），同文件第 {aware_line} 行"
                    f"存在带时区取时 —— 时间基准混用，跨项目边界易错位"),
            evidence=source_line(tree, naive_line)[:200],
        )]
