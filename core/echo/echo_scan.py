#!/usr/bin/env python3
"""Echo —— 跨过程「沉默链」检测器。

═══ 定位：与现有单文件规则正交 ═══════════════════════════════════════

    py.silent_except_no_trace   单 handler   留痕"有无"（print 也算留痕）
    py.print_trace_not_logger   单 handler   留痕"质量"（print 是弱通道）
    core/graph/build_graph.py   模块级       入口→sink 信任边界
    ───────────────────────────────────────────────────────────────────
    Echo                        函数级+跨过程 失败信号沿调用图是否转化为可观测

Echo 不问"这里有没有 logger"，它问：**这个失败信号一路往上，最后有没有变成
任何一个可观测决策？** 没有，就是断链。

═══ 判据链 ═══════════════════════════════════════════════════════════

    失败出口（except 内 return 空值 / 裸 pass / continue）
      │
      ├─ 出口已发声？（logger / raise / 记账毒化）→ 是：不算沉默，终止
      │   ⚠ print 不算发声（P21：不进日志系统，与成功同形）
      │
      └─ 出口沉默 → 沿调用图向上传播
           │
           调用方"接住"了吗？（检查返回值 + 告警）
             ├─ 接住 → 链终止（已观测）
             └─ 没接住 → 沉默继续上溯
                  │
                  └─ 到顶层（无调用者）仍无人发声 → ★断链★

═══ 方向性（PITFALLS N14/P22：假阴性比假阳性危险）══════════════════════

    · 调用图按**函数名全仓保守匹配**（宁可连错，不可漏连）
    · "是否接住"从严判定：只有明确看到"检查返回值+告警"才算接住
      ⇒ 偏向多报（假阳性方向），由人工 triage 过滤
    · 不自动降 severity（同 dead_code_hint 的处理原则）
"""
from __future__ import annotations

import ast
import json
import re
import sys
import tempfile
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path

# ── 通道判据 ────────────────────────────────────────────────────────────
# 强通道：进日志系统 / 外抛 / 记账毒化 —— 任一出现即视为"已发声"
STRONG_LOG = re.compile(
    r"\b(?:logger|logging|_log|_LOG|log|self\.log|self\._log|LOG)\s*\.\s*"
    r"(?:debug|info|warning|warn|error|exception|critical|fatal)")
LEDGER = re.compile(
    r"(?:POISON|poisoned|_poisoned|degraded|stale|dirty|mark_error|record_failure|"
    r"_note\s*\(|\.append\s*\(\s*['\"][^'\"]*(?:err|fail|skip|reason))", re.I)
RAISE = re.compile(r"\braise\b")
# 弱通道：不进日志系统（P21），仅作提示，不终止链
PRINT = re.compile(r"\bprint\s*\(")

# 空/降级返回值
EMPTY_VALS = {"None", "{}", "[]", "''", '""', "0", "False", "set()", "dict()",
              "list()", "tuple()", "0.0", "-1", "''''''"}

EXCLUDE_PARTS = {"__pycache__", ".git", "node_modules", ".venv", "venv",
                 "attic", "scripts", "benchmarks", ".qoder", "doc", "docs",
                 "tests", "test"}
EXCLUDE_SUFFIX = {"_test.py", "test_.py", "conftest.py"}

# 入口特征（用于判级：沉默最终流向对外面）
ENTRY_HINT = re.compile(
    r"(route|handler|endpoint|api|view|_periodic|periodic|consumer|main|entry|dispatch)", re.I)


@dataclass
class Func:
    rel: str            # 相对路径
    name: str
    cls: str            # 所属类（'' 表示模块级函数）
    lineno: int
    end: int
    node: ast.AST
    text: str = ""      # 函数源码（unparse）

    @property
    def qual(self) -> str:
        return f"{self.cls}.{self.name}" if self.cls else self.name


def iter_py(root: Path):
    for p in sorted(root.rglob("*.py")):
        if set(p.parts) & EXCLUDE_PARTS:
            continue
        if any(p.name.endswith(s) for s in EXCLUDE_SUFFIX):
            continue
        if "__pycache__" in str(p):
            continue
        yield p


def collect_funcs(root: Path) -> list[Func]:
    """收集全仓函数定义（含方法 + **嵌套函数**）。

    ⚠ 必须递归进函数体：MCP 工具 / 路由 handler 常见「外层工厂函数内 def 工具」
      写法（如 mcp_server.save_skill 定义在 _build_server() 内，缩进 4）。
      只走 tree.body 会漏掉全仓 1159 个嵌套函数 ⇒ 调用图缺边 ⇒ 假阴性
      （MA59 即因此漏报）。
    """
    funcs: list[Func] = []
    for p in iter_py(root):
        try:
            src = p.read_text(encoding="utf-8-sig", errors="ignore")
            tree = ast.parse(src)
        except (SyntaxError, UnicodeDecodeError, OSError):
            continue
        try:
            rel = str(p.relative_to(root)).replace("\\", "/")
        except ValueError:
            rel = p.name

        # node -> parent 映射（求最近 ClassDef 祖先）
        parents: dict[int, ast.AST] = {}
        for node in ast.walk(tree):
            for child in ast.iter_child_nodes(node):
                parents[id(child)] = node

        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            cls = ""
            cur = parents.get(id(node))
            while cur is not None:
                if isinstance(cur, ast.ClassDef):
                    cls = cur.name
                    break
                cur = parents.get(id(cur))
            try:
                text = ast.unparse(node)
            except Exception:
                text = ""
            funcs.append(Func(rel, node.name, cls,
                              getattr(node, "lineno", 0),
                              getattr(node, "end_lineno", 0) or getattr(node, "lineno", 0),
                              node, text))
    return funcs


def own_calls(fn_node: ast.AST) -> list[ast.Call]:
    """函数体内的调用点，**不进入嵌套函数体**。

    避免同一调用被外层函数重复归属（嵌套函数自己收自己的 Call）。
    """
    out: list[ast.Call] = []

    def visit(node: ast.AST) -> None:
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
                continue                      # 不进入嵌套函数/lambda
            if isinstance(child, ast.Call):
                out.append(child)
            visit(child)

    visit(fn_node)
    return out


# ── 1. 失败出口识别 ──────────────────────────────────────────────────────
def _is_degraded_dict(node: ast.Dict) -> bool:
    """dict 字面量的值全为 False/None/空 → 「降级字典」。

    典型 MA89：`return {available:False, duplicate:False, conflict:False, neighbors:[]}`
    形状合法、行数正常，但去重/冲突门禁已 fail-open。
    """
    if not node.keys:
        return True
    for v in node.values:
        try:
            s = ast.unparse(v)
        except Exception:
            return False
        if s not in ("False", "None", "[]", "{}", "''", '""', "0", "0.0", "set()", "tuple()"):
            return False
    return True


def failure_exits(fn: Func) -> list[dict]:
    """找出函数内的『沉默失败出口』。

    沉默 = 失败形态成立 且 出口未走强通道（print 不算）。

    失败形态六类（按真缺陷样本归纳）：
      empty_return        return {} / [] / None / "" / 0 / False
      degraded_dict       return {flag:False, ...}（MA89 fail-open 形态）
      default_return      return "split" 等安全默认常量（MA83 形态）
      degrade_assign      x = None / [] / {}（MA66/79/54/58 形态）
      swallow_pass        except: pass
      swallow_continue    except: continue
      bare_return         except: return（隐式 None）
      print_only_swallow  except 内只 print，无显式出口（MA87/88 形态）
    """
    out: list[dict] = []
    for h in ast.walk(fn.node):
        if not isinstance(h, ast.ExceptHandler):
            continue
        # 关停语义 ≠ 容错语义
        if h.type is not None:
            try:
                if "CancelledError" in ast.unparse(h.type):
                    continue
            except Exception:
                pass
        try:
            hsrc = ast.unparse(h)
        except Exception:
            continue

        # ① 出口已走强通道 → 不算沉默（print 不算强通道）
        if STRONG_LOG.search(hsrc) or RAISE.search(hsrc) or LEDGER.search(hsrc):
            continue

        # ② 失败形态识别
        kind, detail = None, ""
        for sub in ast.walk(h):
            if isinstance(sub, ast.Return):
                if sub.value is None:
                    kind, detail = "bare_return", "return"
                    break
                try:
                    v = ast.unparse(sub.value)
                except Exception:
                    v = ""
                if v in EMPTY_VALS:
                    kind, detail = "empty_return", v
                    break
                if isinstance(sub.value, ast.Dict) and _is_degraded_dict(sub.value):
                    kind, detail = "degraded_dict", v[:70]
                    break
                if isinstance(sub.value, ast.Constant) and isinstance(
                        sub.value.value, (str, int, float, bool)):
                    kind, detail = "default_return", v
                    break
            if isinstance(sub, ast.Assign):
                try:
                    rv = ast.unparse(sub.value)
                    tg = ast.unparse(sub.targets[0]) if sub.targets else "?"
                except Exception:
                    continue
                if rv in EMPTY_VALS:
                    kind, detail = "degrade_assign", f"{tg} = {rv}"
                    break
                # 异常存变量 → 静默重试（MA86 形态）：
                #   except Exception as exc: last_err = exc   ← 重试期零留痕
                if h.name and rv == h.name:
                    kind, detail = "err_capture_retry", f"{tg} = {rv}（重试期零留痕）"
                    break
            if isinstance(sub, ast.Pass):
                kind, detail = "swallow_pass", "pass"
                break
            if isinstance(sub, ast.Continue):
                kind, detail = "swallow_continue", "continue"
                break

        # ③ 兜底：handler 只 print、无显式出口 → 吞掉并继续
        if kind is None and PRINT.search(hsrc):
            kind, detail = "print_only_swallow", "print-only"

        if kind is None:
            continue

        out.append({
            "file": fn.rel, "line": h.lineno, "func": fn.name, "cls": fn.cls,
            "qual": fn.qual, "kind": kind, "detail": detail,
            "weak_print": bool(PRINT.search(hsrc)),
            "src": hsrc[:160],
        })
    return out


# ── 2. 调用图（按函数名保守匹配）────────────────────────────────────────
def build_callers(funcs: list[Func]) -> dict[str, list[tuple[Func, int]]]:
    """callee_name -> [(caller_func, call_line), ...]

    保守：`self.foo()` / `obj.foo()` 一律按 attr 名匹配全仓同名函数。
    宁可连错（假阳性），不可漏连（假阴性）。
    """
    callers: dict[str, list[tuple[Func, int]]] = defaultdict(list)
    for fn in funcs:
        for node in own_calls(fn.node):
            nm = None
            f = node.func
            if isinstance(f, ast.Name):
                nm = f.id
            elif isinstance(f, ast.Attribute):
                nm = f.attr
            if nm:
                callers[nm].append((fn, getattr(node, "lineno", 0)))
    return callers


# ── 3. 调用方"是否接住" ─────────────────────────────────────────────────
def caller_observes(caller: Func, call_line: int, callee_name: str) -> bool:
    """caller 在 call_line 调用了 callee —— 它检查返回值并告警了吗？

    从严判定：只有当明确看到『判空/判假 + 强通道』才算接住。
    """
    # 调用是否赋值给变量（x = foo()）
    var = None
    for node in ast.walk(caller.node):
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Call):
            if getattr(node, "lineno", -1) == call_line:
                tg = node.targets[0] if node.targets else None
                if isinstance(tg, ast.Name):
                    var = tg.id
                    break

    if var is None:
        # 非赋值调用：看调用点之后 4 行内是否有强通道（宽松但限窗）
        lines = caller.text.splitlines()
        idx = call_line - caller.lineno
        window = "\n".join(lines[idx:idx + 4])
        return bool(STRONG_LOG.search(window) or LEDGER.search(window) or RAISE.search(window))

    # 赋值调用：找后续引用该变量的 if 判空分支，看是否告警
    var_re = re.compile(r"\b" + re.escape(var) + r"\b")
    for node in ast.walk(caller.node):
        if not isinstance(node, ast.If):
            continue
        try:
            tsrc = ast.unparse(node.test)
        except Exception:
            continue
        if not var_re.search(tsrc):
            continue
        try:
            bsrc = ast.unparse(node)
        except Exception:
            continue
        if STRONG_LOG.search(bsrc) or LEDGER.search(bsrc) or RAISE.search(bsrc):
            return True
    return False


# ── 4. 传播：DFS 找"到达顶层仍未被接住"的路径 ───────────────────────────
def trace_silent(start_name: str, start_file: str, callers: dict,
                 max_depth: int = 6) -> list[dict] | None:
    """返回第一条『全程沉默且到达顶层』的路径；被接住则返回 None。"""
    visited: set[tuple[str, str, int]] = set()

    def dfs(name: str, f: str, path: list[dict], depth: int) -> list[dict] | None:
        if depth >= max_depth:
            return None                       # 深度截断 → 不报（避免爆炸）
        key = (name, f, depth)
        if key in visited:
            return None
        visited.add(key)

        ups = [(cf, cl) for (cf, cl) in callers.get(name, [])
               if not (cf.rel == f and cf.name == name)]   # 排除自身递归
        if not ups:
            return path                       # ★顶层，无人发声 → 断链

        for (cf, cl) in ups:
            if caller_observes(cf, cl, name):
                continue                      # 被接住 → 这条路径终止
            nxt = path + [{"file": cf.rel, "line": cl, "func": cf.name, "role": "silent"}]
            r = dfs(cf.name, cf.rel, nxt, depth + 1)
            if r is not None:
                return r
        return None

    return dfs(start_name, start_file, [], 0)


# ── 5. 编排 ──────────────────────────────────────────────────────────────
def run_echo(root: Path, max_depth: int = 6) -> dict:
    funcs = collect_funcs(root)
    callers = build_callers(funcs)

    exits: list[dict] = []
    for fn in funcs:
        exits.extend(failure_exits(fn))

    chains: list[dict] = []
    for ex in exits:
        path = trace_silent(ex["name"] if "name" in ex else ex["func"],
                            ex["file"], callers, max_depth)
        if path is None:
            continue                          # 被接住或深度截断
        tail = path[-1] if path else {"file": ex["file"], "func": ex["func"]}
        is_entry = bool(ENTRY_HINT.search(str(tail.get("func", ""))) or
                        ENTRY_HINT.search(str(tail.get("file", ""))))
        chains.append({
            "rule": "echo.silence_chain",
            "severity": "high" if is_entry else "medium",
            "exit": {"file": ex["file"], "line": ex["line"],
                     "func": ex["qual"], "kind": ex["kind"],
                     "detail": ex["detail"], "weak_print": ex["weak_print"],
                     "src": ex["src"]},
            "hops": len(path),
            "path": path,
            "tail": tail,
            "message": (f"失败信号 {len(path)} 跳未转化为可观测："
                        f"{ex['qual']}() → … → {tail.get('func', '?')}()"
                        f"（末端{'为入口/周期面' if is_entry else '无调用者'}）"),
        })

    chains.sort(key=lambda c: (c["severity"] != "high", -c["hops"]))
    return {
        "root": str(root),
        "stats": {"files_scanned": len({f.rel for f in funcs}),
                  "functions": len(funcs),
                  "silent_exits": len(exits),
                  "broken_chains": len(chains)},
        "chains": chains,
    }


# ── 6. 自检（已知阳性必须命中）───────────────────────────────────────────
SELFTEST_CASES = {
    # ── dirty：应报断链 ──
    "dirty_3hop": ("""
def inner():
    try:
        return read()
    except Exception:
        return None

def middle():
    r = inner()
    return save(r)

def handle_request():
    middle()
""", True),
    "dirty_swallow": ("""
def load():
    try:
        return read()
    except Exception:
        pass

def run_job():
    load()
""", True),
    # ── clean：出口已 logger 发声 ──
    "clean_exit_logs": ("""
import logging
def inner():
    try:
        return read()
    except Exception as e:
        logging.error("fail %s", e)
        return None

def handle_request():
    inner()
""", False),
    # ── clean：出口沉默，但调用方接住并告警 ──
    "clean_caller_catches": ("""
def inner():
    try:
        return read()
    except Exception:
        return None

def outer():
    r = inner()
    if r is None:
        logger.warning("inner failed, skipping")
        return None
    return save(r)

def handle_request():
    outer()
""", False),
    # ── clean：出口 raise（fail-loud）──
    "clean_raise": ("""
def inner():
    try:
        return read()
    except Exception as e:
        raise ValueError("bad") from e

def handle_request():
    inner()
""", False),
}


def selftest() -> int:
    """已知阳性自检：dirty 必须命中，clean 必须不命中。"""
    ok = True
    tmp = Path(tempfile.mkdtemp(prefix="echo_selftest_"))
    for name, (code, expect_hit) in SELFTEST_CASES.items():
        d = tmp / name
        d.mkdir(exist_ok=True)
        (d / "mod.py").write_text(code, encoding="utf-8")
        res = run_echo(d)
        hit = res["stats"]["broken_chains"] > 0
        passed = (hit == expect_hit)
        ok &= passed
        print(f"  [{'PASS' if passed else 'FAIL'}] {name:24s} "
              f"expect_hit={expect_hit!s:5s} got={hit!s:5s} "
              f"chains={res['stats']['broken_chains']}")
    print(f"\nselftest: {'ALL PASS' if ok else 'HAS FAILURE'}")
    return 0 if ok else 1


def main() -> int:
    args = [a for a in sys.argv[1:]]
    if "--selftest" in args:
        print("=== Echo selftest（已知阳性自检）===")
        return selftest()

    root = Path(args[0]) if args else Path(".")
    out = args[1] if len(args) > 1 else None
    res = run_echo(root)
    print(json.dumps(res["stats"], ensure_ascii=False, indent=2))
    print(f"\n=== 断链 TOP 20 / 共 {res['stats']['broken_chains']} ===")
    for c in res["chains"][:20]:
        print(f"[{c['severity']:6s}] {c['exit']['file']}:{c['exit']['line']} "
              f"{c['exit']['func']} ({c['exit']['kind']}) hops={c['hops']}")
        for step in c["path"]:
            print(f"          → {step['file']}:{step['line']} {step['func']}")
    if out:
        Path(out).write_text(json.dumps(res, ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"\n[written] {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
