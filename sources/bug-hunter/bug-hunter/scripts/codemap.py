#!/usr/bin/env python3
"""代码图谱层 —— 回答「全图长什么样」，而不是「某处有没有 bug」。

为什么单独一层（第十三轮新增）：
  前十二轮的所有层都是「针对某处提问」：给它一个假设、一个形状、一条不变量。
  但审计到后来真正的瓶颈不是「怎么验」，而是「**下一步看哪里**」——
  220 个文件里，哪些是枢纽？哪些是孤岛？改动哪里的爆炸半径最大？

  这层不产生缺陷，产生**优先级**。

已验证可用（沙箱实测）：
  · projetmap  —— 2608 实体 / 864 关系 / 23 社区 / god node 排名
  · depcycle   —— 循环依赖检测（⚠ 实测误报，见 verify_cycles）
  · 自写 AST   —— 精确循环依赖（depcycle 报 6 条，实测 0 条，见下）

⚠ 重要教训（第十三轮）：depcycle 报了 6 条循环依赖，逐条 import 验证**全部不成立**
  —— 它能 import 成功。它把类型注解/参数名误判成了导入
  （如 perception_engine.py:66 的 `event_stream: EventStream` 参数）。
  所以本层对 depcycle 的循环结论**一律用自写 AST + 真实 import 复核**。
"""
from __future__ import annotations

import ast
import collections
import os
import subprocess
import sys


def mod_of(path: str, root: str) -> str:
    return os.path.relpath(path, root)[:-3].replace("/", ".")


def butler_graph(root: str, pkg: str = "butler"):
    """精确解析 butler.* 内部导入，构建模块级有向图。

    只认真正的 import 语句（含相对导入），**不认**类型注解、参数名、
    字符串、注释 —— depcycle 就是栽在这里。
    """
    base = os.path.join(root, pkg)
    g = collections.defaultdict(set)

    def resolve(n, cur):
        if isinstance(n, ast.Import):
            return [a.name for a in n.names if a.name.startswith(pkg)]
        if isinstance(n, ast.ImportFrom):
            if n.level:
                up = n.level - 1
                parts = cur.split(".")
                base_pkg = ".".join(parts[:len(parts) - up]) if up else cur
                m = (base_pkg + "." + (n.module or "")) if n.module else base_pkg
                return [m] if m.startswith(pkg) else []
            m = n.module or ""
            return [m] if m.startswith(pkg) else []
        return []

    for d, dirs, fs in os.walk(base):
        dirs[:] = [x for x in dirs if x != "__pycache__"]
        for f in fs:
            if not f.endswith(".py"):
                continue
            p = os.path.join(d, f)
            m = mod_of(p, root)
            try:
                t = ast.parse(open(p, encoding="utf-8").read())
            except Exception:
                continue
            for n in ast.walk(t):
                if isinstance(n, (ast.Import, ast.ImportFrom)):
                    for tgt in resolve(n, m):
                        if tgt != m:
                            g[m].add(tgt)
    return g


def find_cycles(g):
    """DFS 三色标记找环。返回 set of tuple（环上模块名）。"""
    cycles = set()
    WHITE, GRAY, BLACK = 0, 1, 2
    color = collections.defaultdict(int)

    def dfs(u, stack):
        color[u] = GRAY
        stack.append(u)
        for v in sorted(g.get(u, ())):
            if color[v] == GRAY:
                cycles.add(tuple(stack[stack.index(v):]))
            elif color[v] == WHITE:
                dfs(v, stack)
        stack.pop()
        color[u] = BLACK
        return

    sys.setrecursionlimit(10000)
    allm = set(g) | {v for s in g.values() for v in s}
    for m in sorted(allm):
        if color.get(m, WHITE) == WHITE:
            stack = []
            dfs(m, stack)
    return cycles


def verify_importable(root, modules):
    """决定性验证：真 import 一遍。能 import 成功 ⇒ 不存在启动期硬循环。"""
    ok = {}
    for m in modules:
        r = subprocess.run(
            [sys.executable, "-c", f"import sys;sys.path.insert(0,'{root}');import {m}"],
            capture_output=True, text=True, cwd=root, timeout=60)
        ok[m] = (r.returncode == 0, (r.stderr or "").strip().splitlines()[-1][:90] if r.returncode else "")
    return ok


def god_nodes(root, top=15):
    """按入度（被多少模块依赖）排名 —— 爆炸半径最大的模块。"""
    g = butler_graph(root)
    indeg = collections.Counter()
    for u, vs in g.items():
        for v in vs:
            indeg[v] += 1
    return indeg.most_common(top)


def orphan_modules(root):
    """零入度模块 —— 没人依赖它，可能是死代码或纯入口。"""
    g = butler_graph(root)
    indeg = collections.Counter()
    for u, vs in g.items():
        for v in vs:
            indeg[v] += 1
    allm = set(g) | {v for s in g.values() for v in s}
    return sorted(m for m in allm if indeg[m] == 0)


def run(root, verbose=True):
    g = butler_graph(root)
    cycles = find_cycles(g)
    gods = god_nodes(root)
    orph = orphan_modules(root)
    if verbose:
        print("─" * 72)
        print("代码图谱（模块级依赖，精确 AST 解析）")
        print("─" * 72)
        print(f"  模块 {len(g)}  依赖边 {sum(len(v) for v in g.values())}")
        print(f"  循环依赖 {len(cycles)} 条（自写 AST 精确解析）")
        for c in sorted(cycles, key=len)[:8]:
            print("     " + " → ".join(c) + f" → {c[0]}")
        print()
        print("  God nodes（入度 = 被依赖数 = 爆炸半径）：")
        for m, n in gods:
            print(f"    {n:>4}  {m}")
        print()
        print(f"  零入度模块（无人依赖）{len(orph)} 个")
        for m in orph[:10]:
            print(f"    {m}")
        print()
    return {"graph": g, "cycles": cycles, "gods": gods, "orphans": orph}


if __name__ == "__main__":
    run(sys.argv[1] if len(sys.argv) > 1 else ".")
