#!/usr/bin/env python3
"""第十九轮专题：读写一致性与单例生命周期契约（纯 stdlib AST）。

前十八轮覆盖稳定性、持久化、并发、复杂度、控制流、缓存、时间数值、输入边界、
事务边界、序列化、错误处理/降级、可观测性、配置兼容性、测试缺口、API 契约、
资源生命周期、模式泛化/语义、鉴权。本轮看**状态在多个实例/多个进程间是否一致**：

  RMW-01 read-modify-write 不一致：同类中有的写盘方法先 _load()，有的不
         （写前不重读 ⇒ 用陈旧内存快照全量覆盖，抹掉其他实例/进程的写入）
  RMW-02 全量覆盖写（_persist 写整个容器）但未持锁/未重读
  SNG-01 模块级懒初始化单例：`if X is None: X = T()` 无锁
  SNG-02 单例无 reset 手段（测试无法隔离）
  SNG-03 单例的构造参数来源与调用方不一致（`or` fallback 到每次新建）
  SNG-04 跨模块单例路径不一致（root vs store.root）

设计原则：RMW 类问题**必须实测**才能确证（静态只能给候选）。
命中一律输出「写盘方法清单 + 是否重读」的对照表，便于人工判定。

用法: rmw_consistency.py <src_root> <outdir>
"""
from __future__ import annotations

import ast
import json
import re
import sys
from collections import Counter
from pathlib import Path

PERSIST_HINT = re.compile(r"(?i)(_persist|_save|save_all|write_all|flush_all|_rewrite)")
LOAD_HINT = re.compile(r"(?i)(_load|_reload|_refresh|read_all)")


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
        return ".".join(reversed(parts))
    if parts:
            return ".".join(reversed(parts))
    return ""


def _fn_src(fn) -> str:
    try:
        return ast.unparse(fn)
    except Exception:
        return ""


def _methods(cls) -> dict:
    return {m.name: m for m in cls.body
            if isinstance(m, (ast.FunctionDef, ast.AsyncFunctionDef))}


# ────────────────────────────────────────────────────────────────────
# RMW-01 read-modify-write 不一致
# ────────────────────────────────────────────────────────────────────
def check_rmw_inconsistency(tree, rel):
    out = []
    for cls in ast.walk(tree):
        if not isinstance(cls, ast.ClassDef):
            continue
        ms = _methods(cls)
        # 需要有"全量写"与"全量读"两个助手
        writers = [n for n in ms if PERSIST_HINT.search(n)]
        readers = [n for n in ms if LOAD_HINT.search(n)]
        if not writers or not readers:
            continue
        # 统计各公开方法的 写盘 / 重读
        rows = []
        for name, m in ms.items():
            if name in writers or name in readers:
                continue
            if name.startswith("__"):
                continue
            src = _fn_src(m)
            writes = any(re.search(rf"self\.{re.escape(w)}\s*\(", src) for w in writers)
            reads = any(re.search(rf"self\.{re.escape(r)}\s*\(", src) for r in readers)
            if writes:
                rows.append((name, reads, m.lineno))
        if len(rows) < 2:
            continue
        with_read = [r for r in rows if r[1]]
        no_read = [r for r in rows if not r[1]]
        if not with_read or not no_read:
            continue   # 全部一致（要么都读要么都不读）→ 无"不一致"
        # 锁保护情况
        cls_src = ast.unparse(cls)
        has_lock = bool(re.search(r"(?i)(threading\.Lock|RLock|FileLock|with self\._lock)", cls_src))
        out.append({
            "rule": "RMW-01-rmw-inconsistency", "severity": "high",
            "file": rel, "line": cls.lineno, "class": cls.name,
            "message": (f"{cls.name} 的写盘方法中：{len(with_read)} 个先重读 "
                        f"({[r[0] for r in with_read]})，{len(no_read)} 个不重读 "
                        f"({[r[0] for r in no_read]})；不重读者用陈旧内存快照"
                        f"**全量覆盖**，会抹掉其他实例/进程的写入"),
            "writers": [w for w in writers],
            "with_read": [r[0] for r in with_read],
            "no_read": [(r[0], r[2]) for r in no_read],
            "lock": has_lock,
        })
    return out


# ────────────────────────────────────────────────────────────────────
# RMW-02 全量覆盖写但无锁
# ────────────────────────────────────────────────────────────────────
def check_full_overwrite_no_lock(tree, rel):
    out = []
    for cls in ast.walk(tree):
        if not isinstance(cls, ast.ClassDef):
            continue
        ms = _methods(cls)
        writers = [n for n in ms if PERSIST_HINT.search(n)]
        if not writers:
            continue
        cls_src = ast.unparse(cls)
        has_lock = bool(re.search(r"(?i)(threading\.Lock|RLock|FileLock|with self\._lock)", cls_src))
        if has_lock:
            continue
        # _persist 是否写整个容器
        for w in writers:
            wsrc = _fn_src(ms[w])
            # 首版正则括号不平衡 → re.error，5 个模块直接跳过（静默漏检）。
            # 改为逐模式简单匹配。
            full = bool(re.search(r"(?i)json\.dumps\s*\(", wsrc)) and bool(
                re.search(r"(?i)(list\s*\(\s*self\.|\.values\s*\(\s*\)|dict\s*\(\s*self\.)", wsrc))
            if full:
                out.append({
                    "rule": "RMW-02-full-overwrite-no-lock", "severity": "medium",
                    "file": rel, "line": ms[w].lineno, "class": cls.name, "function": w,
                    "message": f"{cls.name}.{w}() 全量覆盖写整个容器，但类内未见锁；"
                               f"并发调用会互相截断",
                })
    return out


# ────────────────────────────────────────────────────────────────────
# SNG-01 / SNG-02 模块级懒初始化单例
# ────────────────────────────────────────────────────────────────────
def check_module_singleton(tree, rel):
    out = []
    # 模块级 `X: T | None = None`
    singles = {}
    for n in tree.body:
        if isinstance(n, ast.AnnAssign) and isinstance(n.target, ast.Name) \
                and n.value is None:
            ann = ast.unparse(n.annotation) if n.annotation else ""
            if "None" in ann:
                singles[n.target.id] = n.lineno
        elif isinstance(n, ast.Assign):
            for t in n.targets:
                if isinstance(t, ast.Name) and isinstance(n.value, ast.Constant) \
                        and n.value.value is None and not t.id.startswith("__"):
                    singles.setdefault(t.id, n.lineno)
    if not singles:
        return out
    src_all = ast.unparse(tree)
    for name, lineno in singles.items():
        # 懒初始化：if X is None
        lazy = bool(re.search(rf"if\s+{re.escape(name)}\s+is\s+None", src_all))
        if not lazy:
            continue
        # 是否有锁保护
        guarded = bool(re.search(
            rf"(?i)(with\s+\w*lock\w*|threading\.Lock)", src_all))
        # 是否有 reset / setter
        has_setter = bool(re.search(rf"(?i)def\s+(set_{re.escape(name.lstrip('_'))}"
                                    rf"|reset_{re.escape(name.lstrip('_'))})", src_all))
        out.append({
            "rule": "SNG-01-lazy-singleton", "severity": "low" if guarded else "medium",
            "file": rel, "line": lineno, "function": name,
            "message": (f"模块级懒初始化单例 {name}（if {name} is None 模式），"
                        + ("有锁保护" if guarded else "**未见锁**")
                        + ("；有 setter 可重置" if has_setter else "；无 reset/setter，测试无法隔离")),
            "guarded": guarded, "has_setter": has_setter,
        })
    return out


# ────────────────────────────────────────────────────────────────────
# SNG-03 单例 fallback 到每次新建
# ────────────────────────────────────────────────────────────────────
def check_singleton_fallback(tree, rel):
    out = []
    singles = set()
    for n in tree.body:
        if isinstance(n, ast.AnnAssign) and isinstance(n.target, ast.Name) and n.value is None:
            singles.add(n.target.id)
        elif isinstance(n, ast.Assign):
            for t in n.targets:
                if isinstance(t, ast.Name) and isinstance(n.value, ast.Constant) \
                        and n.value.value is None:
                    singles.add(t.id)
    if not singles:
        return out
    for fn in ast.walk(tree):
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        src = _fn_src(fn)
        for s in singles:
            # `return X or NewCls(...)` —— 单例为空则每次新建
            if re.search(rf"return\s+{re.escape(s)}\s+or\s+\w+\(", src):
                out.append({
                    "rule": "SNG-03-singleton-fallback", "severity": "medium",
                    "file": rel, "line": fn.lineno, "function": fn.name,
                    "message": (f"{fn.name}() 用 `{s} or NewCls(...)` 回退："
                                f"单例未装配时**每次调用新建实例**；"
                                f"若该实例持有内存状态，多实例间状态不共享"),
                    "singleton": s,
                })
    return out


CHECKS = [
    check_rmw_inconsistency,
    check_full_overwrite_no_lock,
    check_module_singleton,
    check_singleton_fallback,
]


def main() -> int:
    root = Path(sys.argv[1] if len(sys.argv) > 1 else "/data/workspace/audit/src/src/autoforge")
    outdir = Path(sys.argv[2] if len(sys.argv) > 2 else "/data/workspace/audit/rounds/round-019/rmw")
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
    (outdir / "rmw-findings.json").write_text(
        json.dumps({"findings": findings}, ensure_ascii=False, indent=2))
    print(json.dumps({"files": files, "total": len(findings),
                      "by_severity": dict(Counter(f["severity"] for f in findings)),
                      "by_rule": dict(Counter(f["rule"] for f in findings))},
                     ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
