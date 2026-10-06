#!/usr/bin/env python3
"""项目画像探测 —— 决定"这个项目该跑哪些分析器"。

AF 二十轮的第一处硬伤：工作流里到处硬编码 `src/src/autoforge`，
换项目就要改一堆路径。更要命的是**分析器全是 Python AST**，
拿去扫一个 TS/Go 项目会全部 0 命中 —— 而 0 命中在静态分析里是最危险的
信号（PITFALLS N1：可能只是规则不适用，不是代码干净）。

所以开工第一件事不是扫，是**先回答"这是个什么项目"**：
  - 主语言是什么？占比多少？
  - 有没有 Python 包？入口在哪？
  - 什么框架（FastAPI / Chainlit / LangGraph / CLI ...）？
  - 测试在哪？有没有门禁脚本？

画像决定分析器分派，并把"不适用"显式记下来 —— 这样报告里的
"Python AST 分析器 0 命中"就有了解释：要么项目没 Python 代码（不适用），
要么有但真干净。

用法: profile.py <repo_root> [--json]
"""
from __future__ import annotations

import ast
import json
import os
import re
import sys
from collections import Counter
from pathlib import Path

# 语言 → 扩展名
LANGS = {
    "python": {".py"},
    "typescript": {".ts", ".tsx"},
    "javascript": {".js", ".jsx", ".mjs", ".cjs"},
    "go": {".go"},
    "rust": {".rs"},
    "java": {".java"},
    "shell": {".sh", ".bash"},
    "yaml": {".yml", ".yaml"},
    "sql": {".sql"},
}

# 框架指纹：文件名/依赖/import 三选一命中即算
FRAMEWORKS = {
    "fastapi": [r"\bfastapi\b", r"from fastapi", r"FastAPI\("],
    "flask": [r"\bflask\b", r"from flask"],
    "django": [r"\bdjango\b", r"DJANGO_SETTINGS"],
    "chainlit": [r"\bchainlit\b", r"import chainlit"],
    "langgraph": [r"\blanggraph\b", r"StateGraph\("],
    "langchain": [r"\blangchain\b"],
    "celery": [r"\bcelery\b"],
    "pytest": [r"\bpytest\b", r"import pytest"],
    "pytorch": [r"\btorch\b"],
    "huggingface": [r"\btransformers\b", r"\bdatasets\b"],
    "vllm": [r"\bvllm\b"],
    "litellm": [r"\blitellm\b"],
    "qdrant": [r"\bqdrant\b"],
    "postgres": [r"\bpostgres\b", r"\bpsycopg\b", r"asyncpg"],
    "redis": [r"\bredis\b"],
    "mqtt": [r"\bpaho\b", r"\bmqtt\b"],
    "homeassistant": [r"\bhomeassistant\b", r"\bhass\b", r"hass\.states"],
    "sqlite": [r"\bsqlite3\b", r"\.db\b"],
    "docker": [r"docker-compose", r"Dockerfile", r"FROM python:"],
    "openai": [r"\bopenai\b", r"OPENAI_API_KEY", r"openai-compatible", r"chat/completions"],
}

SKIP_DIRS = {
    ".git", "__pycache__", "node_modules", ".venv", "venv", "dist", "build",
    ".mypy_cache", ".pytest_cache", ".ruff_cache", "site-packages", ".tox",
    "egg-info", ".idea", ".vscode", "vendor", "target",
}


def walk_files(root: Path):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fn in filenames:
            yield Path(dirpath) / fn


def detect_languages(root: Path) -> dict:
    counts = Counter()
    lines = Counter()
    for f in walk_files(root):
        ext = f.suffix.lower()
        for lang, exts in LANGS.items():
            if ext in exts:
                counts[lang] += 1
                try:
                    lines[lang] += sum(1 for _ in f.open("r", errors="ignore"))
                except OSError:
                    pass
                break
    total_files = sum(counts.values()) or 1
    return {
        "files": dict(counts),
        "lines": dict(lines),
        "primary": counts.most_common(1)[0][0] if counts else "unknown",
        "share": {k: round(v / total_files, 3) for k, v in counts.most_common()},
    }


def detect_frameworks(root: Path, langs: dict) -> list[str]:
    """读依赖清单 + 少量源码头部，匹配框架指纹。"""
    hits = set()
    # 1) 依赖清单（最可靠）
    dep_files = [
        "pyproject.toml", "requirements.txt", "requirements-dev.txt",
        "setup.py", "setup.cfg", "Pipfile", "environment.yml",
        "package.json", "go.mod", "Cargo.toml",
    ]
    blob = []
    for name in dep_files:
        p = root / name
        if p.is_file():
            try:
                blob.append(p.read_text(errors="ignore"))
            except OSError:
                pass
    # 2) 源码（抽样，避免大仓库读爆）
    src_blob = []
    n = 0
    for f in walk_files(root):
        if f.suffix.lower() in LANGS["python"] | LANGS["typescript"] | LANGS["javascript"]:
            try:
                src_blob.append(f.read_text(errors="ignore")[:4000])
            except OSError:
                pass
            n += 1
            if n > 120:
                break
    text = "\n".join(blob) + "\n".join(src_blob)
    for fw, pats in FRAMEWORKS.items():
        for pat in pats:
            if re.search(pat, text, re.IGNORECASE):
                hits.add(fw)
                break
    return sorted(hits)


def detect_python_packages(root: Path) -> list[dict]:
    """找 Python 源码根（含 __init__.py 的目录），返回包路径与模块数。"""
    out = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        if "__init__.py" in filenames:
            n_py = sum(1 for f in Path(dirpath).glob("*.py"))
            out.append({
                "path": str(Path(dirpath).relative_to(root)),
                "modules": n_py,
            })
    out.sort(key=lambda x: -x["modules"])
    return out[:8]


def detect_tests(root: Path) -> dict:
    pats = ["tests", "test", "testing", "spec", "__tests__"]
    found = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        base = Path(dirpath).name
        if base in pats:
            n = sum(1 for f in Path(dirpath).rglob("*")
                    if f.suffix.lower() in LANGS["python"] | LANGS["typescript"] | LANGS["javascript"])
            found.append({"path": str(Path(dirpath).relative_to(root)), "files": n})
    return {"dirs": found[:6], "has_pytest": any(
        (root / n).exists() for n in ("pytest.ini", "conftest.py", "tox.ini"))
        or bool(list(root.rglob("conftest.py"))[:1])}


def detect_gates(root: Path) -> dict:
    """项目自建的门禁/CI 脚本 —— 这些是审计的额外抓手（见 AF BUG-21）。"""
    ci = []
    for cand in [".github/workflows", ".gitlab-ci.yml", "gates.sh", "scripts"]:
        p = root / cand
        if p.exists():
            if p.is_dir():
                ci.append({"path": cand, "count": len(list(p.rglob("*")))})
            else:
                ci.append({"path": cand, "count": 1})
    checks = sorted(str(p.relative_to(root)) for p in root.rglob("check_*.py"))
    return {"ci": ci, "self_check_scripts": checks[:20]}


def detect_entrypoints(root: Path) -> list[str]:
    cands = []
    for name in ("pyproject.toml", "package.json", "setup.py", "Dockerfile",
                 "docker-compose.yml", "docker-compose.yaml", "main.py", "app.py",
                 "cli.py", "__main__.py"):
        if (root / name).exists():
            cands.append(name)
    return cands


def profile(root: Path) -> dict:
    langs = detect_languages(root)
    return {
        "root": str(root),
        "languages": langs,
        "frameworks": detect_frameworks(root, langs),
        "python_packages": detect_python_packages(root),
        "tests": detect_tests(root),
        "gates": detect_gates(root),
        "entrypoints": detect_entrypoints(root),
        "has_python": langs["files"].get("python", 0) > 0,
    }


def main() -> int:
    root = Path(sys.argv[1] if len(sys.argv) > 1 else ".")
    p = profile(root)
    if "--json" in sys.argv:
        print(json.dumps(p, ensure_ascii=False, indent=2))
        return 0
    print(f"项目画像: {root}")
    print(f"  主语言     : {p['languages']['primary']}   "
          f"文件数 {p['languages']['files']}")
    print(f"  代码行数   : {p['languages']['lines']}")
    print(f"  框架       : {', '.join(p['frameworks']) or '（未识别）'}")
    print(f"  Python 包  : {[(x['path'], x['modules']) for x in p['python_packages'][:4]]}")
    print(f"  测试       : {p['tests']['dirs']}  pytest={p['tests']['has_pytest']}")
    print(f"  自建门禁   : {len(p['gates']['self_check_scripts'])} 个 check_*.py, "
          f"CI={[c['path'] for c in p['gates']['ci']]}")
    print(f"  入口       : {p['entrypoints']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
