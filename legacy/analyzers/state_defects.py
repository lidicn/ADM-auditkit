#!/usr/bin/env python3
"""第二轮专题：状态一致性 / 错误恢复 / 崩溃恢复（纯 stdlib AST，不依赖外部工具）。

与第一轮（资源泄漏、除零、索引越界、竞态、混合返回）不重叠。
每条检测都尽量给出"为什么会真的出错"的机制，而不是模式匹配。

用法: state_defects.py <src_root> <outdir>
"""
import ast
import json
import sys
from pathlib import Path

IO_IN_LOCK = {"read_text", "write_text", "read_bytes", "write_bytes", "dump", "dumps",
              "execute", "get", "post", "put", "delete", "connect", "send", "recv", "fetch"}
def _fn_name(node) -> str:
    return getattr(node, "name", "<lambda>")


# ────────────────────────────────────────────────────────────────────
# AFS-01 静默失败：except 分支返回一个"看起来成功但没数据"的值
# ────────────────────────────────────────────────────────────────────
def _silent_ok_value(ret: ast.Return) -> str | None:
    v = ret.value
    if v is None:
        return "None"
    if isinstance(v, ast.Dict) and not v.keys:
        return "{}"
    if isinstance(v, ast.List) and not v.elts:
        return "[]"
    if isinstance(v, ast.Constant):
        # 注意：Python 中 False == 0 / True == 1，必须先判 bool 再判数字，
        # 否则把「异常时 return False」这种正确的 fail-closed 误报成返回 0。
        if isinstance(v.value, bool):
            return "False" if v.value is False else "True"
        if v.value == "":
            return '""'
        if v.value == 0:
            return "0"
        if v.value is None:
            return "None"
    if isinstance(v, ast.Call):
        f = v.func
        name = getattr(f, "id", None) or getattr(f, "attr", None)
        if name in ("dict", "list", "set", "tuple", "str", "int", "float"):
            return f"{name}()"
    return None


def _handler_in_finally(fn, handler) -> bool:
    """该 except handler 是否位于某个 try 的 finalbody 内。

    `finally:` 里的 `except OSError: pass` 通常是**清理失败**（删临时文件/解锁），
    吞掉是正确取舍——清理失败不该影响主流程。首版未排除 → clean 样本上
    atomic_write/replace_file 两条误报（PITFALLS 新增条目 P14）。
    """
    for t in ast.walk(fn):
        if isinstance(t, ast.Try) and t.finalbody:
            for x in ast.walk(ast.Module(body=t.finalbody, type_ignores=[])):
                if x is handler:
                    return True
            # finalbody 内的嵌套 try/except
            for x in ast.walk(ast.Module(body=t.finalbody, type_ignores=[])):
                if isinstance(x, ast.Try):
                    for h in x.handlers:
                        if h is handler:
                            return True
    return False


def check_silent_failure(tree, path, rel):
    out = []
    for fn in ast.walk(tree):
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for h in [n for n in ast.walk(fn) if isinstance(n, ast.ExceptHandler)]:
            if not h.body:
                continue
            last = h.body[-1]
            if isinstance(last, ast.Return):
                val = _silent_ok_value(last)
                # 只保留真正会"伪装成成功"的：返回空容器 / True / 0 / None。
                # return False 是正确的 fail-closed，不报。
                if val in ("{}", "[]", '""', "True", "0", "None", "dict()", "list()",
                           "set()", "tuple()", "str()", "int()", "float()"):
                    etype = ast.unparse(h.type) if h.type else "Exception"
                    out.append({
                        "rule": "AFS-01-silent-failure",
                        "severity": "high" if val in ("True", "{}", "[]") else "medium",
                        "file": rel, "line": last.lineno,
                        "function": fn.name,
                        "message": (f"{fn.name}() 捕获 {etype} 后返回 {val}：调用方不会崩溃，"
                                    f"会把「失败」当成「成功但没数据」继续走"),
                    })
    return out


# ────────────────────────────────────────────────────────────────────
# AFS-02 循环内 except: continue —— 批量操作静默少做一部分
# ────────────────────────────────────────────────────────────────────
def check_loop_continue(tree, path, rel):
    out = []
    for fn in ast.walk(tree):
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        loops = [n for n in ast.walk(fn) if isinstance(n, (ast.For, ast.While))]
        handlers = [n for n in ast.walk(fn) if isinstance(n, ast.ExceptHandler)]
        for h in handlers:
            if not h.body:
                continue
            last = h.body[-1]
            if not isinstance(last, ast.Continue):
                continue
            # 只报位于循环体内的 handler
            for lp in loops:
                if any(x is h for x in ast.walk(lp)):
                    # 检查是否有计数/记录副作用（有则不算静默）
                    src = ast.unparse(h)
                    logged = any(k in src for k in
                                 ("append", "logging", "logger", "warn", "error", "failures",
                                  "errors", "skipped", "count"))
                    out.append({
                        "rule": "AFS-02-partial-batch",
                        "severity": "low" if logged else "medium",
                        "file": rel, "line": last.lineno, "function": fn.name,
                        "message": (f"{fn.name}() 循环内 except → continue"
                                    + ("（有记录副作用，可追踪）" if logged
                                       else "，无计数无日志：单条失败被完全吞掉")),
                    })
                    break
    return out


# ────────────────────────────────────────────────────────────────────
# AFS-03 非原子落盘：绕过 atomic_write_text 直接写状态文件
# ────────────────────────────────────────────────────────────────────
ATOMIC_NAMES = {"atomic_write_text", "_atomic_write_text", "_atomic_write", "atomic_write"}


def check_nonatomic_write(tree, path, rel):
    out = []
    for fn in ast.walk(tree):
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if fn.name in ATOMIC_NAMES:
            continue  # 原子写实现自身豁免
        for n in ast.walk(fn):
            call = None
            if isinstance(n, ast.Call):
                call = n
            if call is None:
                continue
            f = call.func
            attr = getattr(f, "attr", None)
            base = None
            if isinstance(f, ast.Attribute) and isinstance(f.value, ast.Name):
                base = f.value.id
            is_write = attr in ("write_text", "write_bytes") or (
                attr == "dump" and isinstance(f.value, ast.Attribute)
                and getattr(f.value, "attr", "") == "json")
            if not is_write:
                continue
            # 只在 try 之外或没有 tmp+rename 配套时报
            wrapped = False
            for parent in ast.walk(fn):
                if isinstance(parent, ast.Try) and any(x is n for x in ast.walk(parent)):
                    wrapped = True
            has_rename = any(
                getattr(getattr(c.func, "attr", None), "__str__", lambda: "")() in ("replace", "rename")
                for c in ast.walk(fn) if isinstance(c, ast.Call))
            if has_rename:
                continue
            out.append({
                "rule": "AFS-03-nonatomic-write",
                "severity": "medium" if not wrapped else "low",
                "file": rel, "line": n.lineno, "function": fn.name,
                "message": (f"{fn.name}() 直接 {attr}() 写盘，未见 tmp+rename 配套；"
                            f"写一半崩溃会留下截断/损坏文件，重启加载失败"),
            })
    return out


# ────────────────────────────────────────────────────────────────────
# AFS-04 状态文件读取无异常保护 —— 损坏即崩溃，无降级
# ────────────────────────────────────────────────────────────────────
def check_unguarded_load(tree, path, rel):
    out = []
    try_nodes = {id(n) for n in ast.walk(tree) if isinstance(n, ast.Try)}
    for fn in ast.walk(tree):
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for n in ast.walk(fn):
            if not isinstance(n, ast.Call):
                continue
            f = n.func
            attr = getattr(f, "attr", None)
            name = getattr(f, "id", None)
            hit = None
            if name == "loads" or attr == "loads":
                hit = "json.loads"
            elif attr == "load":
                hit = "json.load"
            elif attr == "read_text":
                hit = "read_text"
            if not hit:
                continue
            # 是否被任何 try 包裹
            guarded = False
            for t in ast.walk(fn):
                if isinstance(t, ast.Try) and any(x is n for x in ast.walk(t)):
                    guarded = True
                    break
            if guarded:
                continue
            # 读取目标是否像状态文件
            arg = ast.unparse(n.args[0]) if n.args else ""
            out.append({
                "rule": "AFS-04-unguarded-load",
                "severity": "medium",
                "file": rel, "line": n.lineno, "function": fn.name,
                "message": (f"{fn.name}() 中 {hit}({arg[:60]}) 未包裹异常处理；"
                            f"文件损坏会让加载直接抛异常，无降级路径"),
            })
    return out


# ────────────────────────────────────────────────────────────────────
# AFS-05 墙上时钟做超时/租约判定
# ────────────────────────────────────────────────────────────────────
CLOCK_RE = None


def check_wallclock_timeout(tree, path, rel):
    import re as _re
    pat = _re.compile(r"(?i)(deadline|timeout|expire|elapsed|lease|until|duration|window|ttl)")
    out = []
    for fn in ast.walk(tree):
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if not pat.search(fn.name):
            continue
        for n in ast.walk(fn):
            if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) \
                    and n.func.attr == "time" and isinstance(n.func.value, ast.Name) \
                    and n.func.value.id == "time":
                out.append({
                    "rule": "AFS-05-wallclock-timeout",
                    "severity": "medium",
                    "file": rel, "line": n.lineno, "function": fn.name,
                    "message": (f"{fn.name}() 用 time.time()（墙上时钟）做超时/租约判定；"
                                f"NTP 校时或改表会让超时瞬间失效或永久卡死，应用 monotonic()"),
                })
    return out


# ────────────────────────────────────────────────────────────────────
# AFS-06 naive datetime 参与存储/比较
# ────────────────────────────────────────────────────────────────────
def check_naive_datetime(tree, path, rel):
    out = []
    for fn in ast.walk(tree):
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for n in ast.walk(fn):
            if not isinstance(n, ast.Call):
                continue
            f = n.func
            if not (isinstance(f, ast.Attribute) and isinstance(f.value, ast.Name)
                    and f.value.id == "datetime" and f.attr in ("now", "utcnow")):
                continue
            # 有 tz 参数则跳过
            if n.args or any(kw.arg in ("tz", "tzinfo") for kw in n.keywords):
                continue
            out.append({
                "rule": "AFS-06-naive-datetime",
                "severity": "medium",
                "file": rel, "line": n.lineno, "function": fn.name,
                "message": (f"{fn.name}() 使用 datetime.{f.attr}() 产出 naive 时间；"
                            f"与 aware 时间相减会抛 TypeError，跨时区部署会调度漂移"),
            })
    return out


# ────────────────────────────────────────────────────────────────────
# AFS-07 持锁期间做 IO
# ────────────────────────────────────────────────────────────────────
def check_io_under_lock(tree, path, rel):
    out = []
    lock_hint = ("lock", "mutex", "_LOCK", "flock", "guard")
    for fn in ast.walk(tree):
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for w in ast.walk(fn):
            if not isinstance(w, ast.With):
                continue
            for item in w.items:
                ctx = ast.unparse(item.context_expr)
                if not any(h in ctx.lower() for h in lock_hint):
                    continue
                for n in ast.walk(w):
                    if not isinstance(n, ast.Call):
                        continue
                    f = n.func
                    attr = getattr(f, "attr", None) or getattr(f, "id", None)
                    if attr in IO_IN_LOCK:
                        out.append({
                            "rule": "AFS-07-io-under-lock",
                            "severity": "medium",
                            "file": rel, "line": n.lineno, "function": fn.name,
                            "message": (f"{fn.name}() 持锁（{ctx[:40]}）期间调用 {attr}()；"
                                        f"IO 阻塞会把锁持有时间放大几个数量级，写入面串行化"),
                        })
    return out


# ────────────────────────────────────────────────────────────────────
# AFS-08 缓存赋值但同类内无失效路径
# ────────────────────────────────────────────────────────────────────
def check_cache_no_invalidate(tree, path, rel):
    out = []
    cache_re = None
    import re as _re
    cache_re = _re.compile(r"(?i)^_?(cache|cached|_loaded|_snapshot|_data|_index)$")
    for cls in ast.walk(tree):
        if not isinstance(cls, ast.ClassDef):
            continue
        assigns = []
        for fn in ast.walk(cls):
            if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            for n in ast.walk(fn):
                if isinstance(n, ast.Assign):
                    for t in n.targets:
                        if isinstance(t, ast.Attribute) and isinstance(t.value, ast.Name) \
                                and t.value.id == "self" and cache_re.match(t.attr):
                            assigns.append((fn.name, n.lineno, t.attr))
                elif isinstance(n, ast.Attribute) and isinstance(n.value, ast.Name) \
                        and n.value.id == "self" and cache_re.match(n.attr):
                    if isinstance(getattr(n, "ctx", None), ast.Store):
                        assigns.append((fn.name, n.lineno, n.attr))
        if not assigns:
            continue
        # 是否存在置空/失效
        body = ast.unparse(cls)
        invalidated = ("= None" in body) or ("pop(" in body) or ("clear()" in body)
        if invalidated:
            continue
        for fname, line, attr in assigns:
            out.append({
                "rule": "AFS-08-cache-no-invalidate",
                "severity": "low",
                "file": rel, "line": line, "function": fname,
                "message": (f"类 {cls.name} 的 self.{attr} 被赋值，但类内未见置空/失效路径；"
                            f"底层数据更新后仍返回旧值，表现为「改了不生效」"),
            })
    return out


CHECKS = [
    check_silent_failure,
    check_loop_continue,
    check_nonatomic_write,
    check_unguarded_load,
    check_wallclock_timeout,
    check_naive_datetime,
    check_io_under_lock,
    check_cache_no_invalidate,
]


def main() -> int:
    root = Path(sys.argv[1] if len(sys.argv) > 1 else "/data/workspace/audit/src/src/autoforge")
    outdir = Path(sys.argv[2] if len(sys.argv) > 2 else "/data/workspace/audit/rounds/round-002/state")
    outdir.mkdir(parents=True, exist_ok=True)

    findings = []
    files = 0
    for p in sorted(root.rglob("*.py")):
        if any(part.startswith("test") for part in p.parts):
            continue
        try:
            tree = ast.parse(p.read_text(errors="ignore"))
        except SyntaxError:
            continue
        rel = str(p.relative_to(root))
        files += 1
        for c in CHECKS:
            try:
                findings += c(tree, p, rel)
            except Exception as e:  # noqa: BLE001
                print(f"[warn] {c.__name__} on {rel}: {e}", file=sys.stderr)

    sev_order = {"high": 0, "medium": 1, "low": 2}
    findings.sort(key=lambda x: (sev_order.get(x["severity"], 9), x["file"], x["line"]))
    (outdir / "state-findings.json").write_text(
        json.dumps({"findings": findings}, ensure_ascii=False, indent=2))

    from collections import Counter
    print(json.dumps({
        "files": files, "total": len(findings),
        "by_severity": dict(Counter(f["severity"] for f in findings)),
        "by_rule": dict(Counter(f["rule"] for f in findings)),
    }, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
