#!/usr/bin/env python3
"""static_ast —— 8 种审计模式中的第 1 种（Phase 1 唯一实现）。

职责：
  1. 收集作用域内 .py 文件（包根 + adapter 附加扫描根 + 画像门禁目录）
  2. 解析 AST，逐文件逐规则执行 L3 规则（mode == "static_ast"）
  3. AnalyzerBridge **import 包装** legacy/registry.py 的既有分析器能力，
     把旧 findings 归一成 Finding —— 不复制任何 legacy/analyzers 代码（验收 12）

失败语义（本模式内）：
  - 单文件语法错误 → 跳过该文件，计入 diagnostics（fail-open）
  - 单规则运行异常 → 跳过该规则该文件，计入 diagnostics（fail-open）
  - 旧分析器缺失/失败 → 计入 diagnostics，unavailable ≠ 失败（对齐 registry.py 语义）
"""
from __future__ import annotations

import importlib.util
from pathlib import Path

from .base import BaseAuditMode, BaseRule, Finding, ModeUnavailable, RuleError
from .profile import DEFAULT_SKIP_DIRS, as_profile


class AnalyzerBridge:
    """legacy/registry.py 的 import 包装：复用 run_analyzer / probe_tools。"""

    def __init__(self, core_dir=None):
        self.legacy_dir = Path(core_dir) if core_dir else Path(__file__).resolve().parents[1] / "legacy"
        self._mod = None

    def registry_module(self):
        if self._mod is None:
            path = self.legacy_dir / "registry.py"
            if not path.exists():
                raise FileNotFoundError(f"未找到 legacy 分析器注册表: {path}")
            spec = importlib.util.spec_from_file_location("auditkit_legacy_registry", path)
            if spec is None or spec.loader is None:
                raise ImportError(f"无法加载 {path}")
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            self._mod = mod
        return self._mod

    def analyzer_scripts(self) -> list:
        adir = self.legacy_dir / "analyzers"
        return sorted(p for p in adir.glob("*.py") if not p.name.startswith("_"))

    def probe(self) -> dict:
        return self.registry_module().probe_tools()

    def run_script(self, script, target, extra=None) -> list:
        res = self.registry_module().run_analyzer(Path(script), Path(target),
                                                  list(extra) if extra else None)
        return [Finding.from_dict(d) for d in (res.get("findings") or [])]


class StaticAstMode(BaseAuditMode):
    name = "static_ast"

    def __init__(self, include_legacy: bool = True, bridge=None, max_file_bytes: int = 2_000_000):
        self.include_legacy = include_legacy
        self.bridge = bridge or AnalyzerBridge()
        self.max_file_bytes = max_file_bytes
        self.diagnostics: list = []

    def applies_to(self, profile) -> bool:
        return bool(getattr(as_profile(profile), "has_python", True))

    def scope_roots(self, repo_path, profile, adapter) -> list:
        prof = as_profile(profile)
        roots = [Path(prof.python_root(repo_path))]
        try:
            roots += [Path(r) for r in (adapter.extra_roots(repo_path) or [])]
        except Exception as e:
            self.diagnostics.append(f"adapter.extra_roots 失败: {e}")
        try:
            roots += [Path(r) for r in prof.extra_gate_roots(repo_path)]
        except Exception as e:
            self.diagnostics.append(f"profile.extra_gate_roots 失败: {e}")
        out, seen = [], set()
        for r in roots:
            try:
                key = str(r.resolve())
            except Exception:
                key = str(r)
            if r.is_dir() and key not in seen:
                seen.add(key)
                out.append(r)
        return out or [Path(repo_path)]

    def iter_sources(self, repo_path, profile, adapter):
        for root in self.scope_roots(repo_path, profile, adapter):
            for p in sorted(root.rglob("*.py")):
                if any(part in DEFAULT_SKIP_DIRS for part in p.parts):
                    continue
                try:
                    if p.stat().st_size > self.max_file_bytes:
                        self.diagnostics.append(f"skip {p}: 超过 {self.max_file_bytes} 字节")
                        continue
                except OSError as e:
                    self.diagnostics.append(f"skip {p}: {e}")
                    continue
                yield p

    def run(self, repo_path, profile, adapter, rules) -> list:
        prof = as_profile(profile)
        wanted = [r for r in (rules or []) if getattr(r, "mode", "") == self.name]
        findings: list = []
        for path in self.iter_sources(repo_path, prof, adapter):
            try:
                src = path.read_text(encoding="utf-8", errors="replace")
            except OSError as e:
                self.diagnostics.append(f"读取失败 {path}: {e}")
                continue
            from .base import parse_unit
            try:
                tree = parse_unit(src, str(path))
            except SyntaxError as e:
                self.diagnostics.append(f"语法错误跳过 {path}: {e}")
                continue
            except Exception as e:
                self.diagnostics.append(f"解析失败跳过 {path}: {type(e).__name__}: {e}")
                continue
            for rule in wanted:
                try:
                    out = rule.run(tree, prof, adapter) or []
                except Exception as e:
                    self.diagnostics.append(f"规则 {getattr(rule, 'id', '?')} 在 {path} 异常: {e}")
                    continue
                findings += [f for f in out if isinstance(f, Finding)]
        if self.include_legacy:
            findings += self.run_legacy(repo_path, prof, adapter)
        return findings

    def run_legacy(self, repo_path, profile, adapter) -> list:
        """包装既有分析器（legacy/registry.run_analyzer），零代码复制。"""
        out: list = []
        try:
            scripts = self.bridge.analyzer_scripts()
        except Exception as e:
            self.diagnostics.append(f"既有分析器不可用: {e}")
            return out
        if not scripts:
            self.diagnostics.append("既有分析器不可用: legacy/analyzers 为空")
            return out
        roots = self.scope_roots(repo_path, profile, adapter) or [Path(repo_path)]
        for script in scripts:
            for root in roots:
                try:
                    out += self.bridge.run_script(script, root)
                except Exception as e:
                    self.diagnostics.append(f"{script.name} @ {root} 失败: {type(e).__name__}: {e}")
        return out


#: 其余 7 种模式：Phase 1 只留接口（名字 + 明确的未实现错误）
PHASE2_MODES = (
    "cross_lang_text", "graph_reachability", "contract_verify", "dynamic_injection",
    "mutation_test", "dep_supply_chain", "config_audit",
)
MODES = {StaticAstMode.name: StaticAstMode}


def get_mode(name: str) -> BaseAuditMode:
    if name in MODES:
        return MODES[name]()
    if name in PHASE2_MODES:
        raise ModeUnavailable(f"模式 {name} 计划 Phase 2 实现")
    raise ModeUnavailable(f"未知审计模式: {name}（可选 {tuple(MODES) + PHASE2_MODES}）")
