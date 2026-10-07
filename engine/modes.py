#!/usr/bin/env python3
"""engine/modes.py —— L1 多模式引擎：8 种审计模式实现。

Phase 3 固化所有模式的接口和注册，让元宝写规则时有明确的 mode 可选。

模式清单：
  static_ast         静态AST分析（已在 static_ast_mode.py 实现）
  cross_lang_text    跨语言文本分析（包装 core/lang/generic_text.py）
  graph_reachability 图谱可达性分析（包装 core/graph/）
  contract_verify    契约验证（从 docstring 提取不变式并验证）
  dynamic_injection  动态注入（失败注入/超时模拟/并发压测）
  mutation_test      变异测试（注入缺陷验证规则有效性）
  dep_supply_chain   依赖供应链（CVE/许可证/版本比对，包装 core/dep_audit.py）
  config_audit       配置面审计（env/docker-compose/部署配置）

设计原则：
  - 每种模式继承 BaseAuditMode，实现 applies_to() 和 run()
  - 有现有 core/ 实现的模式做包装（零代码复制）
  - 骨架模式的 run() 返回空列表并记录 diagnostics，不抛异常
  - 规则通过 mode 字段选择适用的模式
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from .base import BaseAuditMode, Finding
from .profile import as_profile

ROOT = Path(__file__).resolve().parents[1]
CORE = ROOT / "core"


# ── 1. cross_lang_text ──────────────────────────────────────────────────
class CrossLangTextMode(BaseAuditMode):
    """跨语言文本分析：Dockerfile / yaml / shell / TS / JS 等非 Python 文件。

    包装 core/lang/generic_text.py（subprocess 方式，零代码复制）。
    """
    name = "cross_lang_text"

    def applies_to(self, profile) -> bool:
        prof = as_profile(profile)
        langs = getattr(prof, "languages", None)
        if langs is None:
            return True
        # 只要有非 Python 语言就适用
        files = getattr(langs, "files", {}) or {}
        return any(k != "python" and v > 0 for k, v in files.items())

    def run(self, repo_path, profile, adapter, rules) -> list:
        gt = CORE / "lang" / "generic_text.py"
        if not gt.exists():
            self._diag = f"{self.name}: generic_text.py 不存在，跳过"
            return []
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            cmd = [sys.executable, str(gt), str(repo_path), str(td)]
            try:
                p = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
            except subprocess.TimeoutExpired:
                self._diag = f"{self.name}: 超时"
                return []
            if p.returncode != 0:
                self._diag = f"{self.name}: 退出码 {p.returncode}"
                return []
            findings = []
            for j in Path(td).rglob("*.json"):
                try:
                    d = json.loads(j.read_text())
                except Exception:
                    continue
                findings += [Finding.from_dict(x) for x in d.get("findings", [])]
            return findings


# ── 2. graph_reachability ───────────────────────────────────────────────
class GraphReachabilityMode(BaseAuditMode):
    """图谱可达性分析：调用图/数据流图，反向找闸绕过、入口汇聚。

    包装 core/graph/build_graph.py + paths_to_findings.py（subprocess 方式）。
    """
    name = "graph_reachability"

    def applies_to(self, profile) -> bool:
        prof = as_profile(profile)
        return bool(getattr(prof, "has_python", True))

    def run(self, repo_path, profile, adapter, rules) -> list:
        build = CORE / "graph" / "build_graph.py"
        paths = CORE / "graph" / "paths_to_findings.py"
        if not build.exists() or not paths.exists():
            self._diag = f"{self.name}: graph 模块不存在，跳过"
            return []
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            # 第一步：构建图谱
            cmd1 = [sys.executable, str(build), str(repo_path), str(td / "graph.json")]
            try:
                p1 = subprocess.run(cmd1, capture_output=True, text=True, timeout=300)
            except subprocess.TimeoutExpired:
                self._diag = f"{self.name}: 图谱构建超时"
                return []
            if p1.returncode != 0 or not (td / "graph.json").exists():
                self._diag = f"{self.name}: 图谱构建失败"
                return []
            # 第二步：可达性分析
            cmd2 = [sys.executable, str(paths), str(td / "graph.json"), str(td / "findings")]
            try:
                p2 = subprocess.run(cmd2, capture_output=True, text=True, timeout=300)
            except subprocess.TimeoutExpired:
                self._diag = f"{self.name}: 可达性分析超时"
                return []
            findings = []
            for j in (td / "findings").rglob("*.json") if (td / "findings").exists() else []:
                try:
                    d = json.loads(j.read_text())
                except Exception:
                    continue
                findings += [Finding.from_dict(x) for x in d.get("findings", [])]
            return findings


# ── 3. contract_verify（骨架）───────────────────────────────────────────
class ContractVerifyMode(BaseAuditMode):
    """契约验证：从 docstring/注释提取不变式声明并验证。

    骨架已注册，待实现。元宝可在此模式下写契约验证规则。
    """
    name = "contract_verify"

    def applies_to(self, profile) -> bool:
        prof = as_profile(profile)
        return bool(getattr(prof, "has_python", True))

    def run(self, repo_path, profile, adapter, rules) -> list:
        self._diag = f"{self.name}: 模式骨架已注册，待实现（可从 docstring 提取不变式并验证）"
        return []


# ── 4. dynamic_injection（骨架）─────────────────────────────────────────
class DynamicInjectionMode(BaseAuditMode):
    """动态注入：失败注入/超时模拟/并发压测，验证 fail-open/fail-closed。

    骨架已注册，待实现。需要运行时环境（容器/沙箱）支持。
    """
    name = "dynamic_injection"

    def applies_to(self, profile) -> bool:
        # 动态注入需要可运行环境，默认不自动启用
        return False

    def run(self, repo_path, profile, adapter, rules) -> list:
        self._diag = f"{self.name}: 模式骨架已注册，待实现（需要可运行环境支持失败注入/超时模拟）"
        return []


# ── 5. mutation_test（骨架）─────────────────────────────────────────────
class MutationTestMode(BaseAuditMode):
    """变异测试：注入已知缺陷，验证规则能不能抓到（规则有效性验证）。

    骨架已注册，待实现。方法论参考 contrib 包的 lesson 20/46。
    """
    name = "mutation_test"

    def applies_to(self, profile) -> bool:
        prof = as_profile(profile)
        return bool(getattr(prof, "has_python", True))

    def run(self, repo_path, profile, adapter, rules) -> list:
        self._diag = f"{self.name}: 模式骨架已注册，待实现（注入缺陷验证规则有效性，防止规则静默失效）"
        return []


# ── 6. dep_supply_chain ─────────────────────────────────────────────────
class DepSupplyChainMode(BaseAuditMode):
    """依赖供应链：CVE/许可证/版本比对。

    包装 core/dep_audit.py（subprocess 方式）。
    """
    name = "dep_supply_chain"

    def applies_to(self, profile) -> bool:
        # 几乎所有项目都有依赖
        return True

    def run(self, repo_path, profile, adapter, rules) -> list:
        dep = CORE / "dep_audit.py"
        if not dep.exists():
            self._diag = f"{self.name}: dep_audit.py 不存在，跳过"
            return []
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            cmd = [sys.executable, str(dep), str(repo_path), str(td)]
            try:
                p = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            except subprocess.TimeoutExpired:
                self._diag = f"{self.name}: 超时"
                return []
            if p.returncode != 0:
                self._diag = f"{self.name}: 退出码 {p.returncode}"
                return []
            findings = []
            for j in Path(td).rglob("*.json"):
                try:
                    d = json.loads(j.read_text())
                except Exception:
                    continue
                findings += [Finding.from_dict(x) for x in d.get("findings", [])]
            return findings


# ── 7. config_audit（骨架）──────────────────────────────────────────────
class ConfigAuditMode(BaseAuditMode):
    """配置面审计：env / docker-compose / 部署配置 / 特权容器 / 网络配置。

    骨架已注册，待实现。对多容器项目（如 memory-agent）尤其重要。
    """
    name = "config_audit"

    def applies_to(self, profile) -> bool:
        # 检查是否有 docker-compose / Dockerfile / k8s 配置
        repo = Path(repo_path)
        config_files = list(repo.rglob("docker-compose*.y*ml")) + \
                       list(repo.rglob("Dockerfile")) + \
                       list(repo.rglob("*.env")) + \
                       list(repo.rglob("values.yaml"))
        return len(config_files) > 0

    def run(self, repo_path, profile, adapter, rules) -> list:
        self._diag = f"{self.name}: 模式骨架已注册，待实现（env/docker-compose/特权容器/网络配置审计）"
        return []


# ── 模式注册表 ──────────────────────────────────────────────────────────
ALL_MODES = {
    "cross_lang_text": CrossLangTextMode,
    "graph_reachability": GraphReachabilityMode,
    "contract_verify": ContractVerifyMode,
    "dynamic_injection": DynamicInjectionMode,
    "mutation_test": MutationTestMode,
    "dep_supply_chain": DepSupplyChainMode,
    "config_audit": ConfigAuditMode,
}


def get_mode(name: str) -> BaseAuditMode:
    """获取模式实例。static_ast 在 static_ast_mode.py 注册。"""
    from .static_ast_mode import MODES as STATIC_MODES
    if name in STATIC_MODES:
        return STATIC_MODES[name]()
    if name in ALL_MODES:
        return ALL_MODES[name]()
    raise ValueError(f"未知审计模式: {name}（可选 {list(STATIC_MODES) + list(ALL_MODES)}）")


def all_mode_names() -> list[str]:
    """返回所有已注册的模式名。"""
    from .static_ast_mode import MODES as STATIC_MODES
    return list(STATIC_MODES) + list(ALL_MODES)
