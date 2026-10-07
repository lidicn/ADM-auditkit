#!/usr/bin/env python3
"""项目画像数据类 —— 从现有 core/profile.py **只抽接口**，不改其代码。

core/profile.py 是探测脚本（输出 JSON）；本模块把它的输出形态固化成数据类，
供 L1 引擎与 L3 规则消费。两个口径差异在此兼容（见 §7）：
  - `languages.files` 在 auditkit 里被当文件数打印、在 registry.py 里被当映射
    → Languages 同时容忍 int / dict，`file_count()` 自适应。
  - 包根判定 / 附加扫描根判定在 auditkit 里是内联逻辑 → 这里各复刻一份纯函数，
    Phase 2 再收口到本模块（Phase 1 不动 auditkit 的既有逻辑）。
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

DEFAULT_SKIP_DIRS = (
    ".git", "__pycache__", "node_modules", ".venv", "venv", "dist", "build",
    "vendor", "target", "site-packages", ".tox", ".mypy_cache", ".pytest_cache",
)


@dataclass
class Languages:
    primary: str = ""
    files: dict = field(default_factory=dict)   # 语言 → 文件数（registry.py 口径）
    lines: int = 0
    files_total: int = 0                        # `languages.files` 是 int 时的口径

    def file_count(self) -> int:
        if self.files_total:
            return self.files_total
        try:
            return sum(int(v) for v in (self.files or {}).values())
        except Exception:
            return 0

    @classmethod
    def from_dict(cls, d) -> "Languages":
        d = d if isinstance(d, dict) else {}
        files = d.get("files")
        # lines 可能是 int（总行数）或 dict（按语言分行数）
        lines_val = d.get("lines")
        if isinstance(lines_val, dict):
            try:
                lines_total = sum(int(v) for v in lines_val.values())
            except (TypeError, ValueError):
                lines_total = 0
        elif isinstance(lines_val, (int, float, str)) and lines_val != "":
            try:
                lines_total = int(lines_val)
            except (TypeError, ValueError):
                lines_total = 0
        else:
            lines_total = 0
        return cls(
            primary=str(d.get("primary") or ""),
            files=dict(files) if isinstance(files, dict) else {},
            lines=lines_total,
            files_total=int(files) if isinstance(files, int) else 0,
        )

    def to_dict(self) -> dict:
        return {"primary": self.primary, "files": dict(self.files), "lines": self.lines}


@dataclass
class Gates:
    """项目自建门禁（auditkit 用它决定附加扫描根）。"""

    self_check_scripts: list = field(default_factory=list)
    ci: list = field(default_factory=list)

    @classmethod
    def from_dict(cls, d) -> "Gates":
        d = d if isinstance(d, dict) else {}
        ci = []
        for c in (d.get("ci") or []):
            ci.append({"path": str(c)} if isinstance(c, str) else dict(c))
        return cls(self_check_scripts=[str(s) for s in (d.get("self_check_scripts") or [])], ci=ci)

    def to_dict(self) -> dict:
        return {"self_check_scripts": list(self.self_check_scripts), "ci": list(self.ci)}


@dataclass
class ProjectProfile:
    name: str = ""
    repo_root: str = ""
    languages: Languages = field(default_factory=Languages)
    frameworks: list = field(default_factory=list)
    has_python: bool = True
    python_packages: list = field(default_factory=list)   # [{"path": "src/xx", ...}]
    gates: Gates = field(default_factory=Gates)
    raw: dict = field(default_factory=dict)               # 未建模的键原样保留

    # ── 构造 ──────────────────────────────────────────────────────────
    @classmethod
    def empty(cls, name: str = "", repo_root: str = "") -> "ProjectProfile":
        return cls(name=name, repo_root=repo_root)

    @classmethod
    def from_dict(cls, d, name: str = "", repo_root: str = "") -> "ProjectProfile":
        d = dict(d or {})
        known = {"languages", "frameworks", "has_python", "python_packages", "gates"}
        return cls(
            name=name or str(d.get("name") or ""),
            repo_root=repo_root or str(d.get("repo_root") or d.get("repo") or ""),
            languages=Languages.from_dict(d.get("languages")),
            frameworks=[str(f) for f in (d.get("frameworks") or [])],
            has_python=bool(d.get("has_python", True)),
            python_packages=[dict(p) for p in (d.get("python_packages") or []) if isinstance(p, dict)],
            gates=Gates.from_dict(d.get("gates")),
            raw={k: v for k, v in d.items() if k not in known},
        )

    @classmethod
    def load(cls, path, name: str = "") -> "ProjectProfile":
        import json
        p = Path(path)
        return cls.from_dict(json.loads(p.read_text(encoding="utf-8")), name=name)

    def to_dict(self) -> dict:
        out = {
            "name": self.name,
            "repo_root": self.repo_root,
            "languages": self.languages.to_dict(),
            "frameworks": list(self.frameworks),
            "has_python": self.has_python,
            "python_packages": list(self.python_packages),
            "gates": self.gates.to_dict(),
        }
        out.update(self.raw)
        return out

    # ── 查询 ──────────────────────────────────────────────────────────
    @property
    def primary_language(self) -> str:
        return self.languages.primary

    def file_count(self) -> int:
        return self.languages.file_count()

    def python_root(self, repo_path) -> Path:
        """包根判定（复刻 auditkit cmd_round 的语言无关逻辑）。"""
        path = Path(repo_path)
        pkgs = self.python_packages or []
        if pkgs:
            cand = path / str(pkgs[0].get("path") or "")
            if cand.is_dir():
                return cand
        for cand_name in ("src", path.name, "app", "lib"):
            c = path / cand_name
            if c.is_dir():
                return c
        return path

    def extra_gate_roots(self, repo_path) -> list:
        """附加扫描根（复刻 auditkit 的 --extra-root 判定）。"""
        base = Path(repo_path)
        out = []
        for s in self.gates.self_check_scripts:
            d = base / Path(str(s)).parent
            if d.is_dir():
                out.append(d)
        for c in self.gates.ci:
            d = base / str(c.get("path") or "")
            if d.is_dir() and d.name == "scripts":
                out.append(d)
        return out


def as_profile(profile) -> ProjectProfile:
    """把 dict / None / ProjectProfile 归一成 ProjectProfile。"""
    if isinstance(profile, ProjectProfile):
        return profile
    if isinstance(profile, dict):
        return ProjectProfile.from_dict(profile)
    return ProjectProfile.empty()
