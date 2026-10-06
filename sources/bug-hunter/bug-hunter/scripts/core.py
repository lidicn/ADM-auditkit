#!/usr/bin/env python3
"""发现-bug 工作流内核：环境体检 + 统一结果模型 + 工具降级。

设计要点（来自五轮审计的真实教训）：
  · 工具缺失不得伪装成「无问题」——沙箱重置过 3 次，每次工具全丢。
    若那时流水线照常输出「0 缺陷」，等于把缺陷洗白。故：缺失必须显式降级 +
    在报告顶部标红，且 exit code 非 0。
  · 三态：FOUND / REFUTED / ERROR。ERROR 与 REFUTED 语义完全不同，
    混为一谈是前几轮最大的方法论坑。
"""
from __future__ import annotations

import importlib.metadata as md
import os
import subprocess
import sys

# ───────────────────────── 结果模型 ─────────────────────────

FOUND, REFUTED, ERROR, SKIPPED = "FOUND", "REFUTED", "ERROR", "SKIPPED"


class Finding:
    """一条候选/实锤。stage 标记它是在哪一层被发现的。"""

    __slots__ = ("id", "title", "stage", "state", "severity", "loc", "evidence", "detail")

    def __init__(self, id, title, stage, state=FOUND, severity="P2",
                 loc="", evidence="", detail=None):
        self.id, self.title, self.stage = id, title, stage
        self.state, self.severity = state, severity
        self.loc, self.evidence = loc, evidence
        self.detail = detail or []

    def as_dict(self):
        return {k: getattr(self, k) for k in self.__slots__}


# ───────────────────────── 环境体检 ─────────────────────────

# tool: (import名, 是否必需, 缺失时的替代方案)
TOOLS = {
    "vulture":  ("vulture", False, "自写 AST：未使用符号 + 不可达代码"),
    "radon":    ("radon",   False, "自写 AST：圈复杂度近似（分支计数）"),
    "ruff":     ("ruff",    False, "自写 AST：F821 未定义名（pyflakes 级）"),
    "pytest":   ("pytest",  True,  "无替代 —— 行为验证层无法运行"),
}


def probe(repo: str) -> dict:
    """体检。返回 {tool: (可用, 版本或原因, 替代方案)}。"""
    out = {}
    for name, (imp, required, fallback) in TOOLS.items():
        try:
            v = md.version(imp)
            out[name] = (True, v, fallback)
        except Exception:
            out[name] = (False, "未安装", fallback)
    # python 版本
    out["python"] = (True, ".".join(map(str, sys.version_info[:3])), "")
    # 项目结构
    out["_repo"] = (os.path.isdir(repo), repo, "")
    return out


def missing(health: dict) -> list[str]:
    return [k for k, v in health.items() if not k.startswith("_") and not v[0]]


def print_health(health: dict):
    print("─" * 72)
    print("Stage 0  环境体检")
    print("─" * 72)
    for k, v in health.items():
        if k.startswith("_"):
            continue
        ok, ver, fb = v
        mark = "✓" if ok else "✗"
        print(f"  {mark} {k:<10} {ver}")
        if not ok:
            print(f"      降级 → {fb}")
    print()
