#!/usr/bin/env python3
"""第十三轮专题：配置传播、默认值与版本演进兼容性（纯 stdlib AST）。

前十二轮覆盖：稳定性、持久化、并发、复杂度、控制流、死代码/缓存、时间数值、
输入边界、事务边界、序列化、错误处理/降级、可观测性。本轮看**配置与数据格式
在演进过程中有没有走样**：

  CFG-01 配置文件读取后不做结构校验（顶层是 dict 就信，字段类型不查）
  CFG-02 声明了版本常量但读取时不比对（旧/新格式被静默接受）
  CFG-03 环境变量覆盖配置后不做范围校验（越界值放行）
  CFG-04 迁移/兼容读取无异常保护
  CFG-05 同名配置不同来源取值不同（env vs 文件 vs 默认 三源漂移）
  CFG-06 已废弃配置项仍被读取（deprecated 但未移除，语义可能与新项冲突）
  CFG-07 数据类字段有默认值但反序列化时缺失即构造失败（向后不兼容）

设计原则：本类问题误报率高（很多"不校验"是对内部数据的合理信任）。
命中一律标注 surface（external=落盘文件/env、internal=内存结构）便于人工判定。

用法: config_compat_defects.py <src_root> <outdir>
"""
from __future__ import annotations

import ast
import json
import re
import sys
from collections import Counter
from pathlib import Path

VERSION_HINT = re.compile(r"(?i)(version|schema|format|revision)")
CHECK_HINT = re.compile(r"(?i)(==|!=|>=|<=|<|>|in\s*\(|isinstance|validate|check|assert)")


def _chain(n: ast.Call) -> str:
    if isinstance(n.func, ast.Name):
        return n.func.id
    if isinstance(n.func, ast.Attribute):
        parts = []
        cur = n.func
        while isinstance(cur, ast.Attribute):
            parts.append(cur.attr)
            cur = cur.value
        if isinstance(cur, ast.Name):
            parts.append(cur.id)
            return ".".join(reversed(parts))
        # 接收者不是简单 Name（如 `(p / "x.json").write_text(...)`、数组下标、
        # 函数调用结果）→ 首版直接返回 ""，整条调用被丢弃（PITFALLS N7）。
        # 改为保留已收集的属性链，至少能匹配方法名。
        if parts:
            return ".".join(reversed(parts))
    return ""


def _fn_src(fn) -> str:
    try:
        return ast.unparse(fn)
    except Exception:
        return ""


def _enclosing_try(fn, node):
    for t in ast.walk(fn):
        if isinstance(t, ast.Try) and any(x is node for x in ast.walk(t)):
            return t
    return None


# ────────────────────────────────────────────────────────────────────
# CFG-01 配置文件读取后不做结构校验
# ────────────────────────────────────────────────────────────────────
def check_config_struct_validation(tree, rel):
    out = []
    for fn in ast.walk(tree):
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for n in ast.walk(fn):
            if not isinstance(n, ast.Call):
                continue
            c = _chain(n)
            if c not in ("json.load", "json.loads"):
                continue
            # 赋给变量的解析结果
            tgt = None
            for a in ast.walk(fn):
                if isinstance(a, ast.Assign) and a.value is n and \
                        isinstance(a.targets[0], ast.Name):
                    tgt = a.targets[0].id
                    break
            if not tgt:
                continue
            src = _fn_src(fn)
            # 是否有 isinstance / .get( 保护 / setdefault 之外的类型检查
            guarded = bool(re.search(rf"isinstance\(\s*{re.escape(tgt)}", src))
            if guarded:
                continue
            # 后续是否直接用下标取值
            uses_sub = bool(re.search(rf"{re.escape(tgt)}\s*\[", src))
            uses_get = bool(re.search(rf"{re.escape(tgt)}\.get\(", src))
            if not (uses_sub or uses_get):
                continue
            out.append({
                "rule": "CFG-01-config-no-struct-check", "severity": "low",
                "file": rel, "line": n.lineno, "function": fn.name, "surface": "external",
                "message": f"{fn.name}() 解析配置到 {tgt} 后直接用下标/get 取值，"
                           f"未见 isinstance({tgt}, dict) 校验；若文件内容类型不符会 TypeError"})
    return out


# ────────────────────────────────────────────────────────────────────
# CFG-02 声明版本常量但读取时不比对
# ────────────────────────────────────────────────────────────────────
def check_version_not_checked(tree, rel):
    out = []
    src_all = ast.unparse(tree)
    # 模块级版本常量
    consts = {}
    for n in tree.body:
        if isinstance(n, ast.Assign):
            for t in n.targets:
                if isinstance(t, ast.Name) and VERSION_HINT.search(t.id):
                    try:
                        consts[t.id] = ast.literal_eval(n.value)
                    except Exception:
                        pass
    if not consts:
        return out
    for name, val in consts.items():
        # 该常量是否只用于 setdefault/赋值，从未参与比较
        writes = len(re.findall(rf"{re.escape(name)}", src_all))
        # 常量可能出现在比较符**右侧**（`payload.get("version") != MODEL_VERSION`）。
        # 首版只匹配了左侧，把 af_predict 的 `!= MODEL_VERSION` 判成"从不比较"（假阳性）。
        cmp = r"(?:==|!=|>=|<=|<|>)"
        compares = (len(re.findall(rf"{re.escape(name)}\s*{cmp}", src_all))
                    + len(re.findall(rf"{cmp}\s*{re.escape(name)}\b", src_all)))
        if writes >= 2 and compares == 0:
            out.append({
                "rule": "CFG-02-version-not-checked", "severity": "low",
                "file": rel, "line": 0, "function": "<module>", "surface": "external",
                "message": f"版本常量 {name}={val!r} 出现 {writes} 次，但**从未参与比较**；"
                           f"读取旧/新格式文件时版本差异被静默忽略（setdefault 只补不校验）"})
    return out


# ────────────────────────────────────────────────────────────────────
# CFG-03 环境变量覆盖配置后无范围校验
# ────────────────────────────────────────────────────────────────────
RANGE_HINT = re.compile(r"(?i)(min|max|lo|hi|clamp|bound|limit|range)")


def check_env_override_range(tree, rel):
    out = []
    for fn in ast.walk(tree):
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        fname = fn.name.lower()
        if not re.search(r"(?i)(from_env|load_config|_env|settings)", fname):
            continue
        src = _fn_src(fn)
        if "setattr(" not in src:
            continue
        for n in ast.walk(fn):
            if not isinstance(n, ast.Call):
                continue
            c = _chain(n)
            if c != "setattr":
                continue
            # 第三个参数是 float/int 转换
            if len(n.args) < 3:
                continue
            v = ast.unparse(n.args[2])
            if not re.search(r"^(float|int)\(", v):
                continue
            if RANGE_HINT.search(src):
                continue
            out.append({
                "rule": "CFG-03-env-override-no-range", "severity": "low",
                "file": rel, "line": n.lineno, "function": fn.name, "surface": "external",
                "message": f"{fn.name}() 用 env 覆盖配置 `setattr(..., {v[:40]})`，"
                           f"函数内未见范围校验；负数/超大值会被直接采用"})
    return out


# ────────────────────────────────────────────────────────────────────
# CFG-04 迁移/兼容读取无异常保护
# ────────────────────────────────────────────────────────────────────
def check_migration_unprotected(tree, rel):
    out = []
    for fn in ast.walk(tree):
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if not re.search(r"(?i)(migrate|legacy|compat|upgrade)", fn.name):
            continue
        src = _fn_src(fn)
        has_try = any(isinstance(t, ast.Try) for t in ast.walk(fn))
        reads_file = bool(re.search(r"(?i)(open\(|read_text|json\.load)", src))
        if reads_file and not has_try:
            out.append({
                "rule": "CFG-04-migration-unprotected", "severity": "medium",
                "file": rel, "line": fn.lineno, "function": fn.name, "surface": "external",
                "message": f"{fn.name}() 读文件做迁移但无 try；旧档损坏会让整个加载路径抛异常"})
    return out


# ────────────────────────────────────────────────────────────────────
# CFG-05 同名配置三源漂移（env / 文件 / 默认）
# ────────────────────────────────────────────────────────────────────
def _module_defaults(tree):
    """模块级 os.getenv(name, default) → {name: default}。"""
    d = {}
    for n in ast.walk(tree):
        if isinstance(n, ast.Call) and _chain(n) in ("os.getenv", "getenv"):
            if len(n.args) >= 2:
                try:
                    key = ast.literal_eval(n.args[0])
                    val = ast.literal_eval(n.args[1])
                    if isinstance(key, str):
                        d.setdefault(key, set()).add(val)
                except Exception:
                    pass
    return d


def check_env_default_drift(tree, rel):
    out = []
    d = _module_defaults(tree)
    for k, vals in d.items():
        if len(vals) > 1:
            out.append({
                "rule": "CFG-05-env-default-drift", "severity": "medium",
                "file": rel, "line": 0, "function": "<module>", "surface": "external",
                "message": f"环境变量 {k} 在同一模块内出现多个不同默认值 {sorted(map(repr, vals))}"
                           f" → 不同代码路径拿到不同的“默认”，行为不一致"})
    return out


# ────────────────────────────────────────────────────────────────────
# CFG-06 已废弃配置项仍被读取
# ────────────────────────────────────────────────────────────────────
def check_deprecated_env(tree, rel):
    out = []
    src_all = ast.unparse(tree)
    for n in ast.walk(tree):
        if not isinstance(n, ast.Call):
            continue
        c = _chain(n)
        if c not in ("os.getenv", "getenv", "os.environ.get"):
            continue
        if not n.args:
            continue
        try:
            key = ast.literal_eval(n.args[0])
        except Exception:
            continue
        if not isinstance(key, str):
            continue
        # 该 key 附近是否出现 deprecated/废弃/legacy
        ctx = src_all[max(0, src_all.find(key) - 400): src_all.find(key) + 400]
        if re.search(r"(?i)(deprecat|废弃|已废弃|obsolete|DEPRECATED)", ctx):
            out.append({
                "rule": "CFG-06-deprecated-env", "severity": "low",
                "file": rel, "line": n.lineno, "function": "<module>", "surface": "external",
                "message": f"环境变量 {key} 被标注为废弃但仍被读取；"
                           f"若与新配置项并存且语义冲突，行为取决于读取顺序"})
    return out


# ────────────────────────────────────────────────────────────────────
# CFG-07 反序列化缺失必需字段
# ────────────────────────────────────────────────────────────────────
def check_required_field_backcompat(tree, rel):
    out = []
    for cls in ast.walk(tree):
        if not isinstance(cls, ast.ClassDef):
            continue
        methods = {m.name for m in cls.body
                   if isinstance(m, (ast.FunctionDef, ast.AsyncFunctionDef))}
        if "from_dict" not in methods:
            continue
        fd = next(m for m in cls.body if getattr(m, "name", None) == "from_dict")
        src = _fn_src(fd)
        # 必需字段（无默认值的 AnnAssign）
        required = []
        for n in cls.body:
            if isinstance(n, ast.AnnAssign) and isinstance(n.target, ast.Name) \
                    and n.value is None:
                required.append(n.target.id)
        if not required:
            continue
        # from_dict 里对必需字段用 data["k"] 还是 data.get("k")
        hard = [f for f in required if re.search(rf"data\s*\[\s*[\"']{re.escape(f)}[\"']\s*\]", src)]
        soft = [f for f in required
                if re.search(rf"\.get\(\s*[\"']{re.escape(f)}[\"']", src)
                and f not in hard]
        if hard and re.search(r"data\.(get|setdefault)", src):
            out.append({
                "rule": "CFG-07-required-field-mixed", "severity": "low",
                "file": rel, "line": fd.lineno, "class": cls.name, "function": "from_dict",
                "surface": "external",
                "message": f"{cls.name}.from_dict() 对必需字段混用硬取 {hard[:4]} 与 "
                           f".get() {soft[:4]}；老档缺字段时前者 KeyError、后者静默取默认"
                           f" → 向后兼容行为不一致"})
    return out


CHECKS = [
    check_config_struct_validation,
    check_version_not_checked,
    check_env_override_range,
    check_migration_unprotected,
    check_env_default_drift,
    check_deprecated_env,
    check_required_field_backcompat,
]


def main() -> int:
    root = Path(sys.argv[1] if len(sys.argv) > 1 else "/data/workspace/audit/src/src/autoforge")
    outdir = Path(sys.argv[2] if len(sys.argv) > 2 else "/data/workspace/audit/rounds/round-013/config")
    outdir.mkdir(parents=True, exist_ok=True)

    findings, files = [], 0
    for p in sorted(root.rglob("*.py")):
        if any(x.startswith("test") for x in p.parts):
            continue
        try:
            tree = ast.parse(p.read_text(errors="ignore"))
        except SyntaxError:
            continue
        rel = str(p.relative_to(root))
        files += 1
        for c in CHECKS:
            try:
                findings += c(tree, rel)
            except Exception as e:  # noqa: BLE001
                print(f"[warn] {c.__name__} on {rel}: {e}", file=sys.stderr)

    sev = {"high": 0, "medium": 1, "low": 2}
    findings.sort(key=lambda x: (sev.get(x["severity"], 9), x["file"], x["line"]))
    (outdir / "config-findings.json").write_text(
        json.dumps({"findings": findings}, ensure_ascii=False, indent=2))
    print(json.dumps({"files": files, "total": len(findings),
                      "by_severity": dict(Counter(f["severity"] for f in findings)),
                      "by_rule": dict(Counter(f["rule"] for f in findings))},
                     ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
