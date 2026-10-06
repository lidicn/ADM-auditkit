#!/usr/bin/env python3
"""轻量变异测试器 —— 回答「这些测试有多少是真在测东西」。

为什么自写而不直接用 mutmut（第十四轮）：
  mutmut 会把 tests/ 整份复制进 mutants/ 再跑，本项目 tests 用
  `from butler.core import briefing` 这类绝对导入，路径一换就
  ImportError（实测）。且 mutmut 全量跑 41k 行需数十分钟到数小时。

  自写版本：
    · 只变异「被测试覆盖到的文件」中的**纯函数/小函数**
    · 只跑**相关测试**（按文件名启发式匹配），不是全量
    · 有超时、有上限、有进度

判定：
  killed   —— 测试红了 ⇒ 这个变异被抓住 ⇒ 测试有效
  survived —— 测试仍绿 ⇒ **没人发现这个改动** ⇒ 测试盲区
  timeout  —— 超时，单独计

存活率高 = 测试看着绿但抓不住改动 = 当前的 641 passed 有水分。
"""
from __future__ import annotations

import ast
import os
import re
import subprocess
import sys
import time

REPO_DEFAULT = "/data/workspace/doubao-butler-main"

# 变异算子：只改「一个字符/一个token」级别，保证语义变化单一
OPS = [
    (r"\b==\b", "!="),
    (r"\b!=\b", "=="),
    (r"\b<\b", "<="),
    (r"\b<=\b", "<"),
    (r"\b>\b", ">="),
    (r"\b>=\b", ">"),
    (r"\band\b", "or"),
    (r"\bor\b", "and"),
    (r"\bnot\b\s+", ""),          # 去掉 not
    (r"\bTrue\b", "False"),
    (r"\bFalse\b", "True"),
    (r"\+\s*1", "- 1"),
    (r"-\s*1", "+ 1"),
    (r"\bmax\(", "min("),
    (r"\bmin\(", "max("),
]


def _candidate_lines(src_lines):
    """可选变异行：跳过注释、docstring、空行、import。"""
    out = []
    for i, ln in enumerate(src_lines):
        st = ln.strip()
        if not st or st.startswith("#") or st.startswith(("import ", "from ")):
            continue
        if st.startswith(('"""', "'''", '"', "'")):
            continue
        out.append(i)
    return out


def _mutate_line(ln):
    """产出该行所有可行的单算子变异，返回 [(newline, op_desc)]。"""
    res = []
    for pat, rep in OPS:
        if re.search(pat, ln):
            new = re.sub(pat, rep, ln, count=1)
            if new != ln:
                res.append((new, f"{pat} -> {rep}"))
    return res


def _modname(rel_path):
    """butler/triggers/engine.py -> butler.triggers.engine"""
    return rel_path[:-3].replace("/", ".")


def _related_tests(rel_path, tests_dir):
    """按**真实 import 关系**找相关测试，而不是文件名字符串匹配。

    ⚠ 第十四轮踩到的坑：原实现按 stem（文件名去扩展名）匹配，
      `butler/triggers/engine.py` 的 stem 是 "engine"，
      于是匹配到 `test_decision_engine.py` —— 但那个测试测的是
      **`butler/decision/engine.py`**，根本不 import triggers。
      结果：25 个变异全部"存活"，误得「杀死率 0%、该测试是空测试」的错误结论。
      手动核查才发现测试文件本身有 9 个断言、测的是另一个 engine。

      教训：**文件名相似 ≠ 测的同一个东西**。必须按 import 关系匹配。
    """
    mod = _modname(rel_path)
    # 候选导入写法：完整路径、末段、末两段
    parts = mod.split(".")
    cands = {mod, parts[-1], ".".join(parts[-2:])}
    hits = []
    for f in sorted(os.listdir(tests_dir)):
        if not f.startswith("test_") or not f.endswith(".py"):
            continue
        fp = os.path.join(tests_dir, f)
        try:
            txt = open(fp, encoding="utf-8", errors="ignore").read()
        except Exception:
            continue
        for c in cands:
            if re.search(r"(from\s+%s\b|import\s+%s\b)" % (re.escape(c), re.escape(c)), txt):
                hits.append(os.path.join("tests", f))
                break
    return hits


def run_file(rel_path, repo=REPO_DEFAULT, timeout=90, max_mutants=25, verbose=True):
    p = os.path.join(repo, rel_path)
    src = open(p, encoding="utf-8").read()
    lines = src.splitlines()
    cands = _candidate_lines(lines)

    tests_dir = os.path.join(repo, "tests")
    related = _related_tests(rel_path, tests_dir)
    if not related:
        return None, f"{rel_path}: 未找到相关测试文件，跳过"

    killed = survived = timeout_n = invalid = 0
    survivors = []
    made = 0
    for i in cands:
        if made >= max_mutants:
            break
        for new_ln, desc in _mutate_line(lines[i])[:2]:
            if made >= max_mutants:
                break
            made += 1
            new_src = "\n".join(lines[:i] + [new_ln] + lines[i + 1:])
            # 语法必须是合法的，否则这个变异无意义
            try:
                ast.parse(new_src)
            except SyntaxError:
                made -= 1
                continue
            bak = src
            try:
                open(p, "w", encoding="utf-8").write(new_src)
                t0 = time.time()
                r = subprocess.run(
                    [sys.executable, "-m", "pytest", "-q", "--no-header",
                     "-p", "no:cacheprovider", "-x", *related],
                    cwd=repo, capture_output=True, text=True, timeout=timeout)
                el = time.time() - t0
                # ⚠ 关键修正（第十四轮）：不能只看 returncode != 0 就算 killed。
                #   pytest 在「模块加载失败」时也是非 0，但那不是测试抓住了变异，
                #   而是变异把模块弄坏了 —— 这种是 **invalid mutant**，
                #   计入 killed 会虚高杀死率（实测虚高到 100%）。
                #   判据：输出里必须有真实的 "failed" 行；只有 "error" 的算 invalid。
                out = (r.stdout or "") + (r.stderr or "")
                m = re.search(r"(\d+) failed", out)
                has_failed = bool(m) and int(m.group(1)) > 0
                has_error = bool(re.search(r"(\d+ error|errors)", out))
                if r.returncode == 0:
                    survived += 1
                    survivors.append((i + 1, desc, lines[i].strip()[:70]))
                elif has_failed:
                    killed += 1
                elif has_error:
                    invalid += 1
                else:
                    invalid += 1
            except subprocess.TimeoutExpired:
                timeout_n += 1
            finally:
                open(p, "w", encoding="utf-8").write(bak)

    # 分母排除 invalid：无效变异不该给测试记功
    total = killed + survived
    score = (killed / total * 100) if total else 0.0
    if verbose:
        print(f"  {rel_path}")
        print(f"    相关测试: {', '.join(related)}")
        print(f"    变异 {total} 个 → 杀 {killed} / 存活 {survived} / "
              f"无效 {invalid} / 超时 {timeout_n}   杀死率 {score:.0f}%")
        for ln, desc, code in survivors[:6]:
            print(f"      ⚠ 存活 L{ln}: {desc}   `{code}`")
        print()
    return {"file": rel_path, "total": total, "killed": killed,
            "survived": survived, "invalid": invalid, "timeout": timeout_n,
            "score": score, "survivors": survivors}, None


def run(paths, repo=REPO_DEFAULT, **kw):
    print("─" * 72)
    print("变异测试（自写轻量版：存活 = 测试盲区）")
    print("─" * 72)
    results, skipped = [], []
    for rel in paths:
        r, skip = run_file(rel, repo=repo, **kw)
        if r:
            results.append(r)
        else:
            skipped.append(skip)
    tot = sum(r["total"] for r in results)
    kil = sum(r["killed"] for r in results)
    sur = sum(r["survived"] for r in results)
    inv = sum(r["invalid"] for r in results)
    print(f"合计：有效变异 {tot} → 杀 {kil} / 存活 {sur} （另 {inv} 个无效已排除）"
          f"｜杀死率 {kil / tot * 100:.0f}%" if tot else "无有效变异")
    if skipped:
        print(f"跳过 {len(skipped)} 个（无相关测试）")
    return results


if __name__ == "__main__":
    args = sys.argv[1:] or ["butler/core/dedup.py"]
    run(args)
