#!/usr/bin/env python3
"""Stage 1 —— 候选生成：静态扫描。

三条腿，任一可用即工作，全部可用则交叉验证：
  A. vulture  死代码 / 不可达代码
  B. ruff     F821 未定义名 / F811 重定义 / F841 未使用
  C. radon    圈复杂度（排序用，Stage 2 消费）

工具缺失时走内置 AST 降级实现（coverage 略低但能出候选）。
关键纪律：降级必须在输出里显式标注，不得静默。
"""
from __future__ import annotations

import ast
import builtins
import json
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from core import FOUND, Finding  # noqa: E402

BUILTIN = set(dir(builtins))


def _py_files(repo: str, root: str = "."):
    base = os.path.join(repo, root)
    for d, dirs, fs in os.walk(base):
        dirs[:] = [x for x in dirs if x not in ("__pycache__", ".git", "node_modules")]
        for f in fs:
            if f.endswith(".py"):
                yield os.path.join(d, f)


# ─────────────────────── A. 死代码 / 不可达 ───────────────────────

def _vulture(repo, root="butler"):
    try:
        r = subprocess.run([sys.executable, "-m", "vulture", os.path.join(repo, root),
                            "--min-confidence", "90"],
                           capture_output=True, text=True, cwd=repo, timeout=300)
    except Exception as e:
        return None, f"vulture 不可用: {e}"
    # 关键：命令失败但 stdout 为空 ≠ 「没有死代码」。
    # 工具未安装时 subprocess 不抛异常（rc≠0、stdout 空），若不判 rc，
    # 就会把「工具缺失」报成「0 条死代码」—— 这正是 S0 纪律要防的洗白。
    #
    # 但 vulture 的退出码语义特殊（已实测）：
    #   0 = 跑通且无发现    3 = 跑通且有发现    其它 = 失败
    # 所以不能一刀切「rc!=0 即失败」——那样会把「有发现」误判成「工具挂了」。
    # 判定失败的正确信号：rc 不在 {0,3}，或 stderr 出现 No module named。
    if r.returncode not in (0, 3):
        return None, f"vulture 退出码 {r.returncode}（失败）"
    if "No module named" in (r.stderr or ""):
        return None, "vulture 未安装"
    out = []
    for ln in r.stdout.splitlines():
        if " (100% confidence)" in ln or " (90% confidence)" in ln:
            parts = ln.split(":", 2)
            if len(parts) >= 3:
                out.append((parts[0], int(parts[1]), parts[2].strip()))
    return out, None


def _ast_dead(repo, root="butler"):
    """降级：不可达代码（return 之后仍有语句）+ 函数内孤立 docstring。"""
    out = []
    for p in _py_files(repo, root):
        try:
            src = open(p, encoding="utf-8").read()
            t = ast.parse(src)
        except Exception:
            continue
        rel = os.path.relpath(p, repo)
        for n in ast.walk(t):
            if not isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            for i, st in enumerate(n.body):
                # return 之后紧跟 docstring → 强特征：双函数叠写
                if isinstance(st, ast.Return) and i + 1 < len(n.body):
                    nxt = n.body[i + 1]
                    if (isinstance(nxt, ast.Expr) and isinstance(nxt.value, ast.Constant)
                            and isinstance(nxt.value.value, str) and len(nxt.value.value) > 10
                            and i + 2 < len(n.body)):
                        out.append((rel, nxt.lineno,
                                    f"疑似双函数叠写：return 后的 docstring（{n.name}）"))
                # 函数体内非首条的孤立 docstring
                if i > 0 and isinstance(st, ast.Expr) and isinstance(st.value, ast.Constant) \
                        and isinstance(st.value.value, str) and len(st.value.value) > 10:
                    out.append((rel, st.lineno,
                                f"孤立 docstring（置于 {n.name} 体内非首行）"))
    return out


def scan_dead(repo, root="butler"):
    res, err = _vulture(repo, root)
    if res is not None:
        return res, "vulture"
    return _ast_dead(repo, root), f"AST 降级（{err}）"


# ─────────────────────── B. 未定义名 / 重定义 ───────────────────────

def _ruff(repo, root="butler"):
    try:
        r = subprocess.run(["ruff", "check", os.path.join(repo, root),
                            "--select", "F821,F811,F841,E722",
                            "--output-format", "concise"],
                           capture_output=True, text=True, cwd=repo, timeout=300)
    except Exception:
        return None
    # 同上：rc 非 0/1 且无输出 → 工具不可用，不是「无问题」
    if r.returncode not in (0, 1):
        return None
    if "No module named" in (r.stderr or "") or not r.stdout and r.returncode != 0:
        return None
    out = []
    for ln in (r.stdout or "").splitlines():
        p = ln.split(":", 3)
        if len(p) >= 4:
            try:
                out.append((p[0], int(p[1]), p[3].strip()))
            except ValueError:
                pass
    return out


def _ast_undef(repo, root="butler"):
    """降级：函数内引用了既非参数、非局部赋值、非模块级符号、非内建的名字。"""
    out = []
    for p in _py_files(repo, root):
        try:
            src = open(p, encoding="utf-8").read()
            t = ast.parse(src)
        except Exception:
            continue
        rel = os.path.relpath(p, repo)
        mod_syms = set()
        for g in t.body:
            if isinstance(g, (ast.Import, ast.ImportFrom)):
                for a in g.names:
                    mod_syms.add(a.asname or a.name.split(".")[0])
            elif isinstance(g, ast.Assign):
                for tg in g.targets:
                    if isinstance(tg, ast.Name):
                        mod_syms.add(tg.id)
            elif isinstance(g, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                mod_syms.add(g.name)
        for n in ast.walk(t):
            if not isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            params = {a.arg for a in n.args.args} | {a.arg for a in n.args.kwonlyargs}
            if n.args.vararg:
                params.add(n.args.vararg.arg)
            if n.args.kwarg:
                params.add(n.args.kwarg.arg)
            assigned = set(params)
            for x in ast.walk(n):
                if isinstance(x, ast.Name) and isinstance(x.ctx, ast.Store):
                    assigned.add(x.id)
                if isinstance(x, ast.ExceptHandler) and x.name:
                    assigned.add(x.name)
                if isinstance(x, (ast.Import, ast.ImportFrom)):
                    for a in x.names:
                        assigned.add(a.asname or a.name.split(".")[0])
                if isinstance(x, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    assigned.add(x.name)
                    for a in x.args.args:
                        assigned.add(a.arg)
            # 闭包内层函数的参数也算
            for inner in ast.walk(n):
                if inner is not n and isinstance(inner, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    for a in inner.args.args:
                        assigned.add(a.arg)
            for x in ast.walk(n):
                if isinstance(x, ast.Name) and isinstance(x.ctx, ast.Load):
                    if x.id not in assigned and x.id not in mod_syms and x.id not in BUILTIN:
                        out.append((rel, x.lineno, f"未定义名 `{x.id}`（{n.name}）"))
                        break  # 每个函数只报一次，避免刷屏
    return out


def scan_undef(repo, root="butler"):
    res = _ruff(repo, root)
    if res is not None:
        return res, "ruff"
    return _ast_undef(repo, root), "AST 降级（ruff 不可用）"


# ─────────────────────── C. 复杂度 ───────────────────────

def _radon(repo, root="butler"):
    try:
        r = subprocess.run(["radon", "cc", os.path.join(repo, root), "-j"],
                           capture_output=True, text=True, cwd=repo, timeout=300)
        if r.returncode != 0 or not (r.stdout or "").strip():
            return None
        d = json.loads(r.stdout)
    except Exception:
        return None
    rows = []
    for f, items in d.items():
        for it in items:
            if isinstance(it, dict):
                rows.append({"cc": it.get("complexity", 0),
                             "file": os.path.relpath(f, repo),
                             "name": it.get("name", ""), "line": it.get("lineno", 0)})
    return rows


def _ast_cc(repo, root="butler"):
    """降级：近似圈复杂度 = 1 + 分支节点数。"""
    BR = (ast.If, ast.For, ast.While, ast.ExceptHandler, ast.With,
          ast.Assert, ast.comprehension)
    rows = []
    for p in _py_files(repo, root):
        try:
            t = ast.parse(open(p, encoding="utf-8").read())
        except Exception:
            continue
        rel = os.path.relpath(p, repo)
        for n in ast.walk(t):
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
                c = 1
                for x in ast.walk(n):
                    if x is not n and isinstance(x, BR):
                        c += 1
                    if isinstance(x, ast.BoolOp):
                        c += len(x.values) - 1
                rows.append({"cc": c, "file": rel, "name": n.name, "line": n.lineno})
    return rows


def scan_cc(repo, root="butler"):
    res = _radon(repo, root)
    if res is not None:
        return res, "radon"
    return _ast_cc(repo, root), "AST 降级（radon 不可用，近似值）"


# ─────────────────────── 已证实的反模式规则 ───────────────────────

def scan_patterns(repo, root="butler"):
    """自写 AST 规则：本项目五轮已证实的反模式，可增量扩充。

    新增规则只改这里。每条规则注释必须写明它由哪条审计发现反推而来。
    """
    hits = []
    for p in _py_files(repo, root):
        try:
            src = open(p, encoding="utf-8").read()
            t = ast.parse(src)
        except Exception:
            continue
        rel = os.path.relpath(p, repo)
        for n in ast.walk(t):
            # P1 ← V13：协程 Future 未取结果，异常被静默吞掉并误记成功
            if (isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
                    and n.func.attr == "run_coroutine_threadsafe"):
                if not any(isinstance(q, ast.Call) and isinstance(q.func, ast.Attribute)
                           and q.func.attr in ("result", "add_done_callback")
                           and any(a is n for a in ast.walk(q)) for q in ast.walk(t)):
                    hits.append((rel, n.lineno, "P1 协程 Future 未取结果（V13）"))
            # P2 ← V18：async 函数内阻塞式 time.sleep
            if isinstance(n, ast.AsyncFunctionDef):
                for s in ast.walk(n):
                    if (isinstance(s, ast.Call) and isinstance(s.func, ast.Attribute)
                            and s.func.attr == "sleep"
                            and isinstance(s.func.value, ast.Name) and s.func.value.id == "time"):
                        hits.append((rel, s.lineno, "P2 async 内阻塞 time.sleep（V18）"))
            # P3 ← V6：create_task 返回值未保存（asyncio 仅持弱引用）
            if (isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
                    and n.func.attr == "create_task"):
                saved = any(isinstance(q, ast.Assign) and any(a is n for a in ast.walk(q))
                            for q in ast.walk(t))
                added = any(isinstance(q, ast.Call) and isinstance(q.func, ast.Attribute)
                            and q.func.attr in ("add", "add_done_callback")
                            and any(a is n for a in ast.walk(q)) for q in ast.walk(t))
                if not saved and not added:
                    hits.append((rel, n.lineno, "P3 create_task 引用未保存（V6）"))
            # P4：except 直接 pass（兜底文化量化）
            if isinstance(n, ast.ExceptHandler) and len(n.body) == 1 \
                    and isinstance(n.body[0], ast.Pass):
                hits.append((rel, n.lineno, "P4 except 直接 pass"))
            # P5：非原子写（open(...,"w") + json.dump，无 os.replace）
            if (isinstance(n, ast.Call) and isinstance(n.func, ast.Name)
                    and n.func.id == "open" and len(n.args) >= 2
                    and isinstance(n.args[1], ast.Constant) and "w" in str(n.args[1].value)):
                seg = ast.get_source_segment(src, n) or ""
                hits.append((rel, n.lineno, f"P5 待核：直接写文件 {seg[:40]}（是否需原子写 T-2）"))
    return hits, "自写 AST 规则（P1-P5）"


def run(repo, root="butler", verbose=True):
    """返回 (findings, meta)。meta 记录每条用的是哪个工具/降级。"""
    repo = os.path.abspath(repo)   # 相对路径会让 radon 静默返回 0 样本
    findings, meta = [], {}

    dead, src_a = scan_dead(repo, root)
    meta["dead"] = src_a
    for f, l, msg in dead:
        findings.append(Finding(f"D{len(findings)+1:02d}", msg, "S1-dead",
                                loc=f"{f}:{l}", evidence=src_a))

    undef, src_b = scan_undef(repo, root)
    meta["undef"] = src_b
    for f, l, msg in undef:
        findings.append(Finding(f"U{len(findings)+1:02d}", msg, "S1-undef",
                                severity="P1", loc=f"{f}:{l}", evidence=src_b))

    pats, src_d = scan_patterns(repo, root)
    meta["patterns"] = src_d
    for f, l, msg in pats:
        sev = "P1" if msg.startswith("P1") else ("P2" if msg.startswith("P2") else "P3")
        findings.append(Finding(f"R{len(findings)+1:02d}", msg, "S1-pattern",
                                severity=sev, loc=f"{f}:{l}", evidence=src_d))

    cc, src_c = scan_cc(repo, root)
    meta["cc"] = src_c
    meta["cc_rows"] = cc

    if verbose:
        print("─" * 72)
        print("Stage 1  候选生成（静态扫描）")
        print("─" * 72)
        print(f"  死代码/不可达  {len(dead):>4} 条   ← {src_a}")
        print(f"  未定义名/重定义 {len(undef):>4} 条   ← {src_b}")
        print(f"  反模式规则      {len(pats):>4} 条   ← {src_d}")
        print(f"  复杂度样本      {len(cc):>4} 个   ← {src_c}")
        print(f"  候选池合计      {len(findings):>4} 条")
        print()
    return findings, meta
