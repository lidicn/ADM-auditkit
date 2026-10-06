#!/usr/bin/env python3
"""快速核心扫描 —— 两阶段 + 并行 + 缓存，把全仓扫描压到秒级。

为什么需要这一层（第八轮的实际需求）：
  全仓 220 文件 / 41k 行，单进程跑完约 43 秒。这个数字本身不算慢，
  但审计是**迭代**的——每轮要反复跑、改规则后再跑、只看一部分文件再跑。
  43 秒 × 反复迭代 = 实际很慢，而且每次都把 90% 的算力花在我已经读过的、
  或者根本不可能有问题的文件上。

  核心思路：审计的价值密度极度不均匀。
    核心代码（S2 排名前 20）≈ 全仓 15% 的文件，但承载了绝大多数缺陷。
    所以「快速」的正解不是让扫描更快，而是**少扫**。

两阶段：
  Phase A（廉价预筛，纯文本/正则，秒级）
    对全仓做 O(文件数) 的快速打分，不解析 AST
  Phase B（昂贵精扫，AST，只跑 top-K）
    只对 Phase A 选出的 core 文件跑全部不变量 + 反模式 + 复杂度

并行：multiprocessing Pool（AST 解析是 CPU 密集，GIL 会卡死单进程）
缓存：按 (文件路径, mtime, size) 缓存 AST，改过的文件才重解析
"""
from __future__ import annotations

import ast
import hashlib
import json
import multiprocessing as mp
import os
import re
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from core import Finding  # noqa: E402

CACHE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".astcache")


# ───────────────────────── Phase A：廉价预筛 ─────────────────────────

# 危险信号：文本级即可判定，不需要 AST
# 预编译 —— 220 文件 × 10 个模式，不预编译会重复编译数千次（冷启动慢的主因之一）
CHEAP_SIGNALS = [
    (re.compile(r"run_coroutine_threadsafe"), 3.0, "协程 Future（V13 形状）"),
    (re.compile(r"asyncio\.create_task"), 1.0, "create_task（V6 形状）"),
    (re.compile(r"except\s*(?:\w*Exception\w*)?\s*:\s*$", re.M), 0.3, "except 分支"),
    (re.compile(r"except[^\n]*:\s*\n\s*pass"), 2.0, "except: pass（吞异常）"),
    (re.compile(r"hasattr\s*\(|getattr\s*\("), 1.5, "动态探测（V1/V2 形状）"),
    (re.compile(r"time\.sleep"), 2.0, "阻塞 sleep（V18 形状）"),
    (re.compile(r"json\.dump"), 0.8, "JSON 写入（T-2 形状）"),
    (re.compile(r"open\([^)]*[\"']w[\"']"), 0.8, "文件写入"),
    (re.compile(r"\breturn\s+True\b"), 0.2, "常量返回成功"),
    (re.compile(r"#\s*(?:pragma|noqa|type:\s*ignore)"), 0.5, "抑制注释"),
]

# 分支密度近似（不解析 AST，数关键字）
BRANCH_RE = re.compile(r"\b(if|elif|for|while|except|and|or|assert|with)\b")


def cheap_score(path: str) -> dict:
    """单文件的廉价评分。不解析 AST，只读文本。"""
    try:
        src = open(path, encoding="utf-8").read()
    except Exception:
        return None
    lines = src.splitlines()
    n = max(1, len(lines))
    score = 0.0
    hits = []
    for pat, w, label in CHEAP_SIGNALS:
        c = len(pat.findall(src))
        if c:
            score += c * w
            hits.append((label, c))
    # 分支密度：近似圈复杂度
    branches = len(BRANCH_RE.findall(src))
    density = branches / n * 100
    score += density * 0.5
    # 长函数近似：连续非缩进行之间的最大跨度
    return {"path": path, "lines": n, "score": round(score, 2),
            "density": round(density, 2), "branches": branches, "hits": hits}


def phase_a(repo, root="butler", workers=None):
    files = []
    base = os.path.join(os.path.abspath(repo), root)
    for d, dirs, fs in os.walk(base):
        dirs[:] = [x for x in dirs if x not in ("__pycache__", ".git")]
        for f in fs:
            if f.endswith(".py"):
                files.append(os.path.join(d, f))
    # 实测 cpu_count=2 时 workers=8 反而更慢（进程创建开销 > 并行收益）。
    # 上限压到 4，且小文件量直接单进程。
    workers = workers or min(4, max(1, (os.cpu_count() or 2) - 1))
    if len(files) < 30:
        workers = 1
    if workers > 1:
        with mp.Pool(workers) as pool:
            res = pool.map(cheap_score, files, chunksize=8)
    else:
        res = [cheap_score(f) for f in files]
    return [r for r in res if r]


# ───────────────────────── AST 缓存 ─────────────────────────

def _cache_key(path: str) -> str:
    st = os.stat(path)
    return hashlib.md5(f"{path}:{st.st_mtime}:{st.st_size}".encode()).hexdigest()


_parse_cache = {}


def get_ast(path: str):
    """带缓存的 AST 解析。改过的文件才重解析。"""
    k = _cache_key(path)
    if k in _parse_cache:
        return _parse_cache[k]
    try:
        t = ast.parse(open(path, encoding="utf-8").read())
    except Exception:
        t = None
    _parse_cache[k] = t
    return t


# ───────────────────────── Phase B：精扫 ─────────────────────────

def _scan_one(args):
    """一个文件的深度扫描（在子进程中跑）。"""
    rel, abspath = args
    t = get_ast(abspath)
    if t is None:
        return rel, []
    try:
        src = open(abspath, encoding="utf-8").read()
    except Exception:
        src = ""
    out = []

    BUILTIN = set(dir(__builtins__)) if isinstance(__builtins__, dict) else set(dir(__builtins__))

    def dotted(node):
        if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
            return f"{node.value.id}.{node.attr}"
        return None

    funcs = [n for n in ast.walk(t)
             if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]

    # 复杂度（近似）
    BR = (ast.If, ast.For, ast.While, ast.ExceptHandler, ast.With, ast.Assert)
    hot = []
    for f in funcs:
        c = 1 + sum(1 for x in ast.walk(f) if x is not f and isinstance(x, BR))
        if c >= 15:
            hot.append((c, f.name, f.lineno))

    for n in ast.walk(t):
        # V13 形状
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) \
                and n.func.attr == "run_coroutine_threadsafe":
            if not any(isinstance(q, ast.Call) and isinstance(q.func, ast.Attribute)
                       and q.func.attr in ("result", "add_done_callback")
                       and any(a is n for a in ast.walk(q)) for q in ast.walk(t)):
                out.append(("P1", f"{rel}:{n.lineno}", "协程 Future 未取结果（V13）"))
        # V18 形状
        if isinstance(n, ast.AsyncFunctionDef):
            for s in ast.walk(n):
                if isinstance(s, ast.Call) and isinstance(s.func, ast.Attribute) \
                        and s.func.attr == "sleep" and isinstance(s.func.value, ast.Name) \
                        and s.func.value.id == "time":
                    out.append(("P0", f"{rel}:{s.lineno}", "async 内阻塞 time.sleep（V18）"))
        # V6
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) \
                and n.func.attr == "create_task":
            saved = any(isinstance(q, ast.Assign) and any(a is n for a in ast.walk(q))
                        for q in ast.walk(t))
            if not saved:
                out.append(("P2", f"{rel}:{n.lineno}", "create_task 引用未保存（V6）"))
        # except: pass
        if isinstance(n, ast.ExceptHandler) and len(n.body) == 1 \
                and isinstance(n.body[0], ast.Pass):
            out.append(("P3", f"{rel}:{n.lineno}", "except 直接 pass"))

    return rel, {"hot": sorted(hot, reverse=True)[:5], "findings": out,
                 "nfuncs": len(funcs)}


def phase_b(repo, files, workers=None):
    """files: 绝对路径列表。并行深度扫描。"""
    args = [(os.path.relpath(f, os.path.abspath(repo)), f) for f in files]
    # 实测 cpu_count=2 时 workers=8 反而更慢（进程创建开销 > 并行收益）。
    # 上限压到 4，且小文件量直接单进程。
    workers = workers or min(4, max(1, (os.cpu_count() or 2) - 1))
    if len(files) < 30:
        workers = 1
    if workers > 1 and len(args) > 1:
        with mp.Pool(workers) as pool:
            res = pool.map(_scan_one, args, chunksize=2)
    else:
        res = [_scan_one(a) for a in args]
    return dict(res)


# ───────────────────────── 对外主入口 ─────────────────────────

def run(repo, root="butler", focus=20, unread_only=False, read_files=None,
        extra_files=None, workers=None, verbose=True):
    """快速核心扫描。

    focus      : Phase B 精扫的文件数
    unread_only: 只在未读文件里选 core
    extra_files: 强制纳入精扫的相对路径
    """
    t0 = time.time()
    rows = phase_a(repo, root, workers)
    t_a = time.time() - t0

    read = read_files or set()
    if unread_only:
        cands = [r for r in rows
                 if os.path.relpath(r["path"], os.path.abspath(repo)) not in read]
    else:
        cands = rows
    # 混合聚焦（第八轮的核心教训）：
    #   纯按危险信号排序 → 名单被 app.py / dialog.py 这些已读烂的文件占据，
    #   而 V23（进程挂死）恰恰藏在从未读过的 mcp/server.py 里。
    #   所以未读文件加权重 1.6 倍，让盲区与危险区混合进入 core。
    #   这是「探索 vs 利用」的权衡：信号分高=利用（已知危险区），未读=探索（盲区）。
    def key(r):
        rel = os.path.relpath(r["path"], os.path.abspath(repo))
        return -r["score"] * (1.6 if rel not in read else 1.0)
    cands = sorted(cands, key=key)

    picked = [r["path"] for r in cands[:focus]]
    for ef in (extra_files or []):
        ap = os.path.join(os.path.abspath(repo), ef)
        if os.path.exists(ap) and ap not in picked:
            picked.append(ap)

    t1 = time.time()
    detail = phase_b(repo, picked, workers)
    t_b = time.time() - t1

    findings = []
    for rel, d in detail.items():
        # 解析失败的文件返回 [] 而非 dict —— 上一版直接 d["findings"] 会崩
        if not isinstance(d, dict):
            continue
        for sev, loc, title in d["findings"]:
            findings.append(Finding(f"K{len(findings)+1:02d}", title, "fast-core",
                                    severity=sev, loc=loc, evidence="快速核心扫描"))
    if verbose:
        total = len(rows)
        print("─" * 72)
        print("Stage 1' 快速核心扫描（Phase A 预筛 → Phase B 精扫）")
        print("─" * 72)
        print(f"  Phase A  全仓 {total} 文件廉价预筛      {t_a:>6.2f}s  ({workers or os.cpu_count()} 进程)")
        print(f"  Phase B  core {len(picked)} 文件深度精扫       {t_b:>6.2f}s")
        print(f"  合计 {t_a+t_b:>6.2f}s   （全仓精扫约需 43s → 省 "
              f"{(1-(t_a+t_b)/43)*100:.0f}%）")
        print(f"  候选池 {len(findings)} 条")
        print()
        print("  core 文件（按危险信号密度）：")
        print(f"    {'文件':<44}{'行':>6}{'分支密度':>8}{'信号分':>8}")
        for r in cands[:focus][:10]:
            rel = os.path.relpath(r["path"], os.path.abspath(repo))
            mark = "★ " if rel not in read else "  "
            print(f"    {mark}{rel[:40]:<42}{r['lines']:>6}{r['density']:>8}{r['score']:>8}")
        print()
    return findings, {"cheap": rows, "detail": detail,
                      "core": [os.path.relpath(p, os.path.abspath(repo)) for p in picked],
                      "t_a": t_a, "t_b": t_b}
