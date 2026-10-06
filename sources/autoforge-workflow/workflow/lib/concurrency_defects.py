#!/usr/bin/env python3
"""第三轮专题：并发与异步正确性（纯 stdlib AST，不依赖外部工具）。

与第一轮（资源泄漏、除零、索引、竞态静态共享）、第二轮（持久化、崩溃恢复）不重叠。
本轮只关心**会真的卡死或串扰**的并发问题：死锁、可重入、锁序反转、跨线程无锁写、
async 阻塞事件循环、协程丢失 await、async 里用同步锁。

用法: concurrency_defects.py <src_root> <outdir>
"""
import ast
import json
import re
import sys
from collections import defaultdict
from pathlib import Path

LOCK_HINT = re.compile(r"(?i)(lock|mutex|guard)")
BLOCKING_CALLS = {
    "time.sleep": "time.sleep",
    "requests.get": "requests", "requests.post": "requests", "requests.put": "requests",
    "httpx.get": "httpx", "httpx.post": "httpx",
    "urllib.request.urlopen": "urllib",
    "subprocess.run": "subprocess", "subprocess.Popen": "subprocess",
    "os.system": "os.system",
}


def _attr_chain(node):
    """把 a.b.c 变成字符串。"""
    parts = []
    cur = node
    while isinstance(cur, ast.Attribute):
        parts.append(cur.attr)
        cur = cur.value
    if isinstance(cur, ast.Name):
        parts.append(cur.id)
        return ".".join(reversed(parts))
    return None


def _call_name(node: ast.Call):
    """返回调用的完整名字（尽量）。"""
    if isinstance(node.func, ast.Name):
        return node.func.id
    if isinstance(node.func, ast.Attribute):
        chain = _attr_chain(node.func)
        return chain
    return None


# ────────────────────────────────────────────────────────────────────
# 收集：类里每个方法持有哪些锁；锁是否 RLock
# ────────────────────────────────────────────────────────────────────
def _lock_ctx_name(item) -> str | None:
    expr = item.context_expr
    if isinstance(expr, ast.Name) and LOCK_HINT.search(expr.id):
        return expr.id
    if isinstance(expr, ast.Attribute) and LOCK_HINT.search(expr.attr):
        return ast.unparse(expr)
    if isinstance(expr, ast.Call):
        n = _call_name(expr)
        if n and LOCK_HINT.search(n):
            return ast.unparse(expr)
    return None


class ClassLocks:
    def __init__(self, cls: ast.ClassDef):
        self.cls = cls
        self.rlock_attrs: set[str] = set()
        self.method_locks: dict[str, list[str]] = {}   # method -> 按顺序持有的锁
        self.method_calls: dict[str, list[str]] = {}   # method -> 调用的 self.X()
        self.locked_calls: dict[str, list[tuple[str, str]]] = {}  # method -> [(lock, called_method)]

        self._scan_rlocks()
        self._scan_methods()

    def _scan_rlocks(self):
        for n in ast.walk(self.cls):
            if isinstance(n, ast.Assign):
                v = n.value
                if isinstance(v, ast.Call):
                    nm = _call_name(v)
                    if nm and "RLock" in nm:
                        for t in n.targets:
                            if isinstance(t, ast.Attribute):
                                self.rlock_attrs.add(t.attr)
                            elif isinstance(t, ast.Name):
                                self.rlock_attrs.add(t.id)

    def _scan_methods(self):
        for fn in self.cls.body:
            if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            seq: list[str] = []
            calls: list[str] = []
            locked: list[tuple[str, str]] = []
            # 逐层扫描，记录 with-lock 嵌套顺序
            def walk(body, stack):
                for st in body:
                    if isinstance(st, ast.With):
                        names = [_lock_ctx_name(i) for i in st.items]
                        new_stack = stack + [x for x in names if x]
                        for x in names:
                            if x and x not in seq:
                                seq.append(x)
                        walk(st.body, new_stack)
                    else:
                        for sub in ast.iter_child_nodes(st):
                            if isinstance(sub, ast.With):
                                walk([sub], stack)
                            elif isinstance(sub, ast.Call):
                                nm = _call_name(sub)
                                if nm and nm.startswith("self."):
                                    m = nm.split(".", 1)[1]
                                    if "(" not in m:
                                        calls.append(m)
                                        if stack:
                                            locked.append((stack[-1], m))
                        walk_body_generic(st, stack)

            def walk_body_generic(st, stack):
                for child in ast.iter_child_nodes(st):
                    if isinstance(child, ast.With):
                        walk([child], stack)

            walk(fn.body, [])
            # 直接 acquire() 也算
            for n in ast.walk(fn):
                if isinstance(n, ast.Call):
                    nm = _call_name(n)
                    if nm and nm.endswith(".acquire") and LOCK_HINT.search(nm):
                        base = nm.rsplit(".acquire", 1)[0]
                        if base not in seq:
                            seq.append(base)
            self.method_locks[fn.name] = seq
            self.method_calls[fn.name] = calls
            self.locked_calls[fn.name] = locked


def _is_rlock(cls_locks: ClassLocks, lock_name: str) -> bool:
    for a in cls_locks.rlock_attrs:
        if a and a in lock_name:
            return True
    return False


# ────────────────────────────────────────────────────────────────────
# C-01 可重入死锁：持锁时调用同类中也取同一把锁的方法
# ────────────────────────────────────────────────────────────────────
def check_reentrant_deadlock(tree, rel):
    out = []
    for cls in ast.walk(tree):
        if not isinstance(cls, ast.ClassDef):
            continue
        cl = ClassLocks(cls)
        if not cl.rlock_attrs:
            pass  # 仍可报告（Lock 才致命），RLock 由下面过滤
        for m, locked in cl.locked_calls.items():
            for lock, callee in locked:
                callee_locks = cl.method_locks.get(callee, [])
                if not callee_locks:
                    continue
                if lock not in callee_locks:
                    continue
                if _is_rlock(cl, lock):
                    continue  # RLock 可重入，安全
                out.append({
                    "rule": "CONC-01-reentrant-deadlock",
                    "severity": "high",
                    "file": rel, "line": 0, "class": cls.name,
                    "function": m,
                    "message": (f"{cls.name}.{m}() 持有 {lock} 期间调用 self.{callee}()，"
                                f"而 {callee}() 也获取 {lock}；若锁非 RLock 则必然自锁"),
                })
    return out


# ────────────────────────────────────────────────────────────────────
# C-02 锁序反转：同类中 A→B 与 B→A 两种顺序都存在
# ────────────────────────────────────────────────────────────────────
def check_lock_order_inversion(tree, rel):
    out = []
    for cls in ast.walk(tree):
        if not isinstance(cls, ast.ClassDef):
            continue
        cl = ClassLocks(cls)
        pairs = defaultdict(list)   # (A,B) -> [methods]
        for m, seq in cl.method_locks.items():
            for i in range(len(seq) - 1):
                for j in range(i + 1, len(seq)):
                    a, b = seq[i], seq[j]
                    if a == b:
                        continue
                    pairs[(a, b)].append(m)
        for (a, b), ms in pairs.items():
            rev = pairs.get((b, a))
            if not rev:
                continue
            out.append({
                "rule": "CONC-02-lock-order-inversion",
                "severity": "high",
                "file": rel, "line": 0, "class": cls.name,
                "function": ms[0],
                "message": (f"{cls.name} 中同时存在 {a}→{b}（{', '.join(ms[:2])}）与 "
                            f"{b}→{a}（{', '.join(rev[:2])}）两种加锁顺序，存在 ABBA 死锁风险"),
            })
    return out


# ────────────────────────────────────────────────────────────────────
# C-03 async 函数内阻塞调用 —— 卡死整个事件循环
# ────────────────────────────────────────────────────────────────────
def check_async_blocking(tree, rel):
    out = []
    for fn in ast.walk(tree):
        if not isinstance(fn, ast.AsyncFunctionDef):
            continue
        for n in ast.walk(fn):
            if not isinstance(n, ast.Call):
                continue
            nm = _call_name(n)
            if not nm:
                continue
            for pat, label in BLOCKING_CALLS.items():
                if nm == pat or nm.endswith("." + pat.split(".")[-1]) and pat.split(".")[0] in nm:
                    out.append({
                        "rule": "CONC-03-async-blocking",
                        "severity": "high",
                        "file": rel, "line": n.lineno, "function": fn.name,
                        "message": (f"async 函数 {fn.name}() 内调用阻塞式 {nm}()；"
                                    f"会卡死整个事件循环，所有协程一起停摆"),
                    })
                    break
    return out


# ────────────────────────────────────────────────────────────────────
# C-04 协程丢失 await —— 任务静默不执行
# ────────────────────────────────────────────────────────────────────
def check_missing_await(tree, rel):
    out = []
    async_names = {n.name for n in ast.walk(tree) if isinstance(n, ast.AsyncFunctionDef)}
    # 注意：只认「模块级函数」与「同类 self 方法」两种形态。
    # 若按方法名粗匹配，会把 `self.runtime.emit()`（同步方法，恰好与某 async 方法同名）
    # 和 `StreamingResponse(gen())`（异步生成器，合法用法）都误报成丢失 await。
    for fn in ast.walk(tree):
        if not isinstance(fn, ast.AsyncFunctionDef):
            continue
        owner = None
        for cls in ast.walk(tree):
            if isinstance(cls, ast.ClassDef) and fn in cls.body:
                owner = cls
                break
        own_async = {n.name for n in (owner.body if owner else [])
                     if isinstance(n, ast.AsyncFunctionDef)}
        for n in ast.walk(fn):
            if not isinstance(n, ast.Call):
                continue
            f = n.func
            if isinstance(f, ast.Name):
                base = f.id
                if base not in async_names:
                    continue
            elif isinstance(f, ast.Attribute) and isinstance(f.value, ast.Name) \
                    and f.value.id == "self":
                base = f.attr
                if base not in own_async:
                    continue
            else:
                continue
            # 异步生成器作为返回值/参数传递是合法用法（如 StreamingResponse(gen())）
            parents = {}
            for anc in ast.walk(fn):
                for ch in ast.iter_child_nodes(anc):
                    parents[id(ch)] = anc
            anc = parents.get(id(n))
            if isinstance(anc, ast.Return):
                continue
            if isinstance(anc, ast.Call) and (n in anc.args):
                continue
            if isinstance(anc, ast.keyword):
                continue
            # 是否被 await / create_task / gather 包裹
            parent_awaited = False
            for p in ast.walk(fn):
                if isinstance(p, ast.Await) and p.value is n:
                    parent_awaited = True
                if isinstance(p, ast.Call) and n in p.args:
                    pn = _call_name(p) or ""
                    if any(k in pn for k in ("create_task", "ensure_future", "gather", "wait",
                                             "as_completed", "run", "to_thread")):
                        parent_awaited = True
            if parent_awaited:
                continue
            out.append({
                "rule": "CONC-04-missing-await",
                "severity": "medium",
                "file": rel, "line": n.lineno, "function": fn.name,
                "message": (f"async 函数 {fn.name}() 中调用协程 {base}() 但既未 await "
                            f"也未 create_task；协程不会执行，且异常永久丢失"),
            })
    return out


# ────────────────────────────────────────────────────────────────────
# C-05 async 函数中使用同步锁 —— 阻塞事件循环且可能死锁
# ────────────────────────────────────────────────────────────────────
def check_sync_lock_in_async(tree, rel):
    out = []
    for fn in ast.walk(tree):
        if not isinstance(fn, ast.AsyncFunctionDef):
            continue
        for n in ast.walk(fn):
            if isinstance(n, ast.With):
                for i in n.items:
                    nm = _lock_ctx_name(i)
                    if not nm:
                        continue
                    src = ast.unparse(n)
                    if "asyncio.Lock" in src or "RLock" in src:
                        continue
                    out.append({
                        "rule": "CONC-05-sync-lock-in-async",
                        "severity": "medium",
                        "file": rel, "line": n.lineno, "function": fn.name,
                        "message": (f"async 函数 {fn.name}() 使用同步锁 {nm}；"
                                    f"争锁时会阻塞事件循环，且跨协程持锁易死锁"),
                    })
    return out


# ────────────────────────────────────────────────────────────────────
# C-06 跨线程共享可变状态且无锁写入
#     条件：模块启动了线程（或含 tick/loop 函数）+ 模块级可变容器 + 写入点无锁
# ────────────────────────────────────────────────────────────────────
def check_cross_thread_unsync_write(tree, rel):
    out = []
    src_all = ast.unparse(tree)
    starts_thread = ("threading.Thread" in src_all or "ThreadPoolExecutor" in src_all
                     or "start_ticker" in src_all or "_ticker_thread" in src_all)
    has_loop_fn = bool(re.search(r"def\s+(_\w*loop\w*|tick\w*|_run\b)", src_all))
    if not (starts_thread or has_loop_fn):
        return out

    module_mutables = set()
    for n in tree.body:
        if isinstance(n, ast.Assign):
            for t in n.targets:
                if not isinstance(t, ast.Name):
                    continue
                if isinstance(n.value, (ast.Dict, ast.List, ast.Set)):
                    module_mutables.add(t.id)
                elif isinstance(n.value, ast.Call):
                    cn = _call_name(n.value) or ""
                    if cn in ("dict", "list", "set", "defaultdict", "deque", "Counter"):
                        module_mutables.add(t.id)
    if not module_mutables:
        return out

    for fn in ast.walk(tree):
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for n in ast.walk(fn):
            mut = None
            if isinstance(n, ast.Call):
                cn = _call_name(n)
                if cn and "." in cn:
                    obj, meth = cn.rsplit(".", 1)
                    if obj in module_mutables and meth in (
                            "append", "pop", "clear", "update", "add", "discard", "popitem"):
                        mut = cn
            elif isinstance(n, ast.Assign):
                for t in n.targets:
                    if isinstance(t, ast.Subscript) and isinstance(t.value, ast.Name) \
                            and t.value.id in module_mutables:
                        mut = f"{t.value.id}[...] = "
                    elif isinstance(t, ast.Name) and t.id in module_mutables:
                        mut = f"{t.id} = "
            elif isinstance(n, ast.AugAssign):
                if isinstance(n.target, ast.Name) and n.target.id in module_mutables:
                    mut = f"{n.target.id} += "
            if not mut:
                continue
            # 是否有锁保护
            guarded = False
            for w in ast.walk(fn):
                if isinstance(w, ast.With):
                    for i in w.items:
                        if _lock_ctx_name(i) and any(x is n for x in ast.walk(w)):
                            guarded = True
            if guarded:
                continue
            out.append({
                "rule": "CONC-06-cross-thread-unsync-write",
                "severity": "medium",
                "file": rel, "line": getattr(n, "lineno", 0), "function": fn.name,
                "message": (f"{fn.name}() 无锁写入模块级共享容器 {mut}；本模块存在线程/tick 循环，"
                            f"并发写入会丢失更新或产生半写状态"),
            })
    return out


# ────────────────────────────────────────────────────────────────────
# C-07 持锁期间 sleep —— 把锁持有时间放大
# ────────────────────────────────────────────────────────────────────
def check_sleep_under_lock(tree, rel):
    out = []
    for fn in ast.walk(tree):
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for w in ast.walk(fn):
            if not isinstance(w, ast.With):
                continue
            for i in w.items:
                if not _lock_ctx_name(i):
                    continue
                for n in ast.walk(w):
                    if isinstance(n, ast.Call):
                        cn = _call_name(n) or ""
                        if cn in ("time.sleep", "sleep") or cn.endswith(".join") \
                                or cn.endswith(".wait"):
                            out.append({
                                "rule": "CONC-07-sleep-under-lock",
                                "severity": "medium",
                                "file": rel, "line": n.lineno, "function": fn.name,
                                "message": (f"{fn.name}() 持锁期间调用 {cn}()；"
                                            f"等待被计入锁持有时间，其他线程全部排队"),
                            })
    return out


# ────────────────────────────────────────────────────────────────────
# C-08 部分加锁覆盖：同一个可变成员，有的方法持锁写、有的方法裸写
#      这是最容易被漏掉的真并发 bug —— 看起来"有锁"，实际有路径绕过
# ────────────────────────────────────────────────────────────────────
def _mutated_attrs(fn) -> dict[str, list[tuple[int, int]]]:
    """返回该函数内被写入/增删的 self.X 成员 → [(行号, 节点id)]。"""
    res: dict[str, list[tuple[int, int]]] = {}

    def add(name, node):
        res.setdefault(name, []).append((getattr(node, "lineno", 0), id(node)))

    for n in ast.walk(fn):
        if isinstance(n, ast.Assign):
            for t in n.targets:
                if isinstance(t, ast.Subscript) and isinstance(t.value, ast.Attribute) \
                        and isinstance(t.value.value, ast.Name) and t.value.value.id == "self":
                    add(t.value.attr, n)
                elif isinstance(t, ast.Attribute) and isinstance(t.value, ast.Name) \
                        and t.value.id == "self":
                    add(t.attr, n)
        elif isinstance(n, ast.AugAssign):
            t = n.target
            if isinstance(t, ast.Attribute) and isinstance(t.value, ast.Name) \
                    and t.value.id == "self":
                add(t.attr, n)
        elif isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) \
                and isinstance(n.func.value, ast.Attribute) \
                and isinstance(n.func.value.value, ast.Name) \
                and n.func.value.value.id == "self":
            if n.func.attr in ("append", "add", "pop", "clear", "update", "discard",
                               "popitem", "extend", "remove"):
                add(n.func.value.attr, n)
    return res


def check_partial_lock_coverage(tree, rel):
    out = []
    for cls in ast.walk(tree):
        if not isinstance(cls, ast.ClassDef):
            continue
        methods = [m for m in cls.body
                   if isinstance(m, (ast.FunctionDef, ast.AsyncFunctionDef))]
        # attr -> {guarded: [(method,line)], unguarded: [(method,line)]}
        state: dict[str, dict] = {}

        for m in methods:
            if m.name.startswith("__") and m.name != "__init__":
                continue
            muts = _mutated_attrs(m)
            if not muts:
                continue
            # 方法内所有 with-lock 覆盖到的节点集合
            guarded_nodes = set()
            for w in ast.walk(m):
                if isinstance(w, ast.With) and any(_lock_ctx_name(i) for i in w.items):
                    for x in ast.walk(w):
                        guarded_nodes.add(id(x))
            for attr, items in muts.items():
                # 仅关注容器型成员：初始化为 dict/list/set 的
                rec = state.setdefault(attr, {"guarded": [], "unguarded": [], "container": False})
                for ln, nid in items:
                    inlock = nid in guarded_nodes
                    (rec["guarded"] if inlock else rec["unguarded"]).append((m.name, ln))

        # 判定容器型：看 __init__
        init = next((m for m in methods if m.name == "__init__"), None)
        if init is not None:
            for n in ast.walk(init):
                # 同时处理 `self.x = {}` 与 `self.x: dict = {}`（后者是 AnnAssign）
                targets, value = [], None
                if isinstance(n, ast.Assign):
                    targets, value = n.targets, n.value
                elif isinstance(n, ast.AnnAssign):
                    targets, value = [n.target], (n.value or None)
                for t in targets:
                    if not (isinstance(t, ast.Attribute) and isinstance(t.value, ast.Name)
                            and t.value.id == "self"):
                        continue
                    is_container = isinstance(value, (ast.Dict, ast.List, ast.Set))
                    if not is_container and isinstance(value, ast.Call):
                        cn = _call_name(value) or ""
                        is_container = cn in ("dict", "list", "set", "defaultdict",
                                              "deque", "Counter")
                    if is_container:
                        rec = state.setdefault(t.attr, {"guarded": [], "unguarded": [],
                                                        "container": True})
                        rec["container"] = True

        for attr, rec in state.items():
            if not rec["container"]:
                continue
            g, u = rec["guarded"], rec["unguarded"]
            if not g or not u:
                continue  # 全加锁或全不加锁（后者是设计选择，不在这里报）
            # __init__ 内的裸写是初始化，不算
            u = [(m, ln) for m, ln in u if m != "__init__"]
            if not u:
                continue
            out.append({
                "rule": "CONC-08-partial-lock-coverage",
                "severity": "high",
                "file": rel, "line": u[0][1], "class": cls.name,
                "function": u[0][0],
                "message": (f"{cls.name}.self.{attr} 存在不一致的加锁覆盖："
                            f"{', '.join(m for m, _ in g[:3])} 持锁写，"
                            f"但 {', '.join(m for m, _ in u[:3])} 裸写同一成员"),
            })
    return out


# ────────────────────────────────────────────────────────────────────
# C-09 持锁期间真实磁盘 IO（精确版，只认落盘调用）
# ────────────────────────────────────────────────────────────────────
DISK_IO = {"write_text", "write_bytes", "atomic_write_text", "_atomic_write_text",
           "_atomic_write", "dump", "unlink", "remove", "rename", "replace", "read_text"}


def check_disk_io_under_lock(tree, rel):
    out = []
    for fn in ast.walk(tree):
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for w in ast.walk(fn):
            if not isinstance(w, ast.With):
                continue
            if not any(_lock_ctx_name(i) for i in w.items):
                continue
            for n in ast.walk(w):
                if not isinstance(n, ast.Call):
                    continue
                nm = _call_name(n) or ""
                base = nm.split(".")[-1]
                if base not in DISK_IO:
                    continue
                if base == "dump" and "json" not in nm:
                    continue
                out.append({
                    "rule": "CONC-09-disk-io-under-lock",
                    "severity": "medium",
                    "file": rel, "line": n.lineno, "function": fn.name,
                    "message": (f"{fn.name}() 持锁期间执行磁盘 IO {nm}()；"
                                f"落盘耗时被计入锁持有时间，所有并发写请求串行排队"),
                })
    return out


CHECKS = [
    check_reentrant_deadlock,
    check_lock_order_inversion,
    check_async_blocking,
    check_missing_await,
    check_sync_lock_in_async,
    check_cross_thread_unsync_write,
    check_sleep_under_lock,
    check_partial_lock_coverage,
    check_disk_io_under_lock,
]


def main() -> int:
    root = Path(sys.argv[1] if len(sys.argv) > 1 else "/data/workspace/audit/src/src/autoforge")
    outdir = Path(sys.argv[2] if len(sys.argv) > 2 else "/data/workspace/audit/rounds/round-003/concurrency")
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
                findings += c(tree, rel)
            except Exception as e:  # noqa: BLE001
                print(f"[warn] {c.__name__} on {rel}: {e}", file=sys.stderr)

    sev = {"high": 0, "medium": 1, "low": 2}
    findings.sort(key=lambda x: (sev.get(x["severity"], 9), x["file"], x["line"]))
    (outdir / "concurrency-findings.json").write_text(
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
