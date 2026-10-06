#!/usr/bin/env python3
"""不变量断言 —— 本工作流唯一具备「自动发现」能力的层。

与 Stage 1 的本质区别：
  Stage 1 是「模式匹配」——我得先知道 bug 长什么样，才能写规则去搜。
  不变量是「属性断言」——我先声明系统必须恒真的事，再让代码去证伪。
  后者能发现我没预料到的形状。

每条不变量都写明它由哪条审计发现反推而来，以及它**还能**发现什么
（即：超出原始发现的能力边界）。
"""
from __future__ import annotations

import ast
import builtins
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from core import Finding  # noqa: E402
from stage1_scan import _py_files  # noqa: E402

BUILTIN = set(dir(builtins))

# 阻塞调用黑名单（async 内不得出现）
BLOCKING = {
    "time.sleep": "阻塞式睡眠",
    "requests.get": "同步 HTTP", "requests.post": "同步 HTTP",
    "httpx.get": "同步 HTTP", "httpx.post": "同步 HTTP",
    "subprocess.run": "同步子进程", "subprocess.call": "同步子进程",
    "os.system": "同步子进程",
}
# 允许的替代
ASYNC_ALT = {
    "time.sleep": "asyncio.sleep",
    "requests.get": "httpx.AsyncClient", "requests.post": "httpx.AsyncClient",
    "httpx.get": "httpx.AsyncClient", "httpx.post": "httpx.AsyncClient",
    "subprocess.run": "asyncio.create_subprocess_*",
    "subprocess.call": "asyncio.create_subprocess_*",
}


def _dotted(node):
    if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
        return f"{node.value.id}.{node.attr}"
    if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Attribute):
        base = _dotted(node.value)
        return f"{base}.{node.attr}" if base else None
    return None


# ───────────────── INV-1 async 纯净 ─────────────────
def inv_async_pure(repo, root="butler"):
    """INV: async 函数内不得调用阻塞 API。

    源起 V18（docker_tools async 内 time.sleep 且 time 未 import）。
    超出 V18 的能力：V18 只命中 sleep，本条覆盖全部同步 HTTP / 子进程 / os.system，
    能发现「函数标了 async 但内部全同步」这类假异步——事件循环照样被卡死，
    而且比 V18 更隐蔽（没有缺 import 这种显眼信号）。
    """
    out = []
    for p in _py_files(repo, root):
        try:
            src = open(p, encoding="utf-8").read()
            t = ast.parse(src)
        except Exception:
            continue
        rel = os.path.relpath(p, repo)
        for n in ast.walk(t):
            if not isinstance(n, ast.AsyncFunctionDef):
                continue
            # 该函数是否被 run_in_executor / to_thread 整体包裹？
            # （同步代码扔线程池跑是合法写法，不算假异步）
            executor_wrapped = any(
                isinstance(q, ast.Call) and isinstance(q.func, ast.Attribute)
                and q.func.attr in ("run_in_executor", "to_thread")
                for q in ast.walk(t))
            # 更精确：本函数是否被上述调用以 None/名字形式传入
            fn_in_executor = False
            for q in ast.walk(t):
                if isinstance(q, ast.Call) and isinstance(q.func, ast.Attribute)                    and q.func.attr in ("run_in_executor", "to_thread"):
                    for arg in q.args:
                        if isinstance(arg, ast.Name) and arg.id == n.name:
                            fn_in_executor = True
            # 阻塞调用所在的最内层函数（可能是嵌套的同步 helper）
            for s in ast.walk(n):
                if not isinstance(s, ast.Call):
                    continue
                d = _dotted(s.func)
                if d in BLOCKING:
                    # 找该调用所在的最内层函数
                    owner = None
                    for cand in ast.walk(t):
                        if isinstance(cand, (ast.FunctionDef, ast.AsyncFunctionDef)) \
                           and cand.lineno <= s.lineno <= (cand.end_lineno or 0):
                            if owner is None or cand.lineno > owner.lineno:
                                owner = cand
                    # owner 是同步 helper 且被 executor 调用 → 合法
                    in_exec = False
                    for q in ast.walk(t):
                        if isinstance(q, ast.Call) and isinstance(q.func, ast.Attribute) \
                           and q.func.attr in ("run_in_executor", "to_thread"):
                            for arg in q.args:
                                if isinstance(arg, ast.Name) and owner is not None \
                                   and arg.id == owner.name:
                                    in_exec = True
                    if in_exec or fn_in_executor:
                        continue
                    seg = ast.get_source_segment(src, s) or ""
                    out.append(Finding(
                        f"A{len(out)+1:02d}",
                        f"async 函数 `{n.name}` 内阻塞调用 {d}（{BLOCKING[d]}）",
                        "INV-async-pure", severity="P0" if "sleep" in d else "P1",
                        loc=f"{rel}:{s.lineno}",
                        evidence=f"替代方案：{ASYNC_ALT.get(d,'?')} 或 asyncio.to_thread",
                        detail=[f"    {seg[:90]}"]))
    return out


# ───────────────── INV-2 状态文件耐久 ─────────────────
def inv_durable_write(repo, root="butler"):
    """INV: 持久化状态文件必须原子写（tmp + os.replace）。

    源起 T-2（trigger 冷却文件非原子写 → 中断后静默归零 → 触发风暴）。
    超出 T-2 的能力：T-2 是我在 triggers/engine 撞见的，本条扫全仓状态写，
    能发现别处的同类隐患——项目里 config_routes / skills/store / deps 都做了原子写，
    唯独漏了冷却文件，说明这是「想做但漏了一处」，同类遗漏大概率不止一处。
    """
    out = []
    for p in _py_files(repo, root):
        try:
            src = open(p, encoding="utf-8").read()
            t = ast.parse(src)
        except Exception:
            continue
        rel = os.path.relpath(p, repo)
        has_replace = "os.replace" in src or "os.rename" in src
        for n in ast.walk(t):
            if not isinstance(n, ast.With):
                continue
            for item in n.items:
                ctx = item.context_expr
                if not (isinstance(ctx, ast.Call) and isinstance(ctx.func, ast.Name)
                        and ctx.func.id == "open"):
                    continue
                if not (len(ctx.args) >= 2 and isinstance(ctx.args[1], ast.Constant)
                        and "w" in str(ctx.args[1].value)):
                    continue
                # 是否写 .tmp
                seg = ast.get_source_segment(src, ctx) or ""
                is_tmp = ".tmp" in seg
                if is_tmp:
                    continue
                # 目标是否 json 状态文件
                body = ast.get_source_segment(src, n) or ""
                if "json.dump" in body or "json.dumps" in body:
                    if not has_replace:
                        out.append(Finding(
                            f"W{len(out)+1:02d}",
                            "状态文件非原子写（无 os.replace 兜底）",
                            "INV-durable-write", severity="P1",
                            loc=f"{rel}:{ctx.lineno}",
                            evidence="中断即产生截断文件 → 加载失败 → 防护静默消失",
                            detail=[f"    {seg[:90]}"]))
    return out


# ───────────────── INV-3 失败可观测 ─────────────────
def inv_failure_visible(repo, root="butler"):
    """INV: 交给调度器的协程，其结果必须被取回。

    源起 V13（15 处 run_coroutine_threadsafe 的 Future 从不 .result()
    → 定时任务崩溃被记成 mark_success）。
    超出 V13 的能力：V13 只盯 run_coroutine_threadsafe，本条同时覆盖
    create_task 未保存引用（V6，17 处）——两者后果同构：
    异常消失在 Future 里，监控系统看到的是一片绿。
    """
    out = []
    for p in _py_files(repo, root):
        try:
            src = open(p, encoding="utf-8").read()
            t = ast.parse(src)
        except Exception:
            continue
        rel = os.path.relpath(p, repo)
        for n in ast.walk(t):
            if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute):
                if n.func.attr == "run_coroutine_threadsafe":
                    if not any(isinstance(q, ast.Call) and isinstance(q.func, ast.Attribute)
                               and q.func.attr in ("result", "add_done_callback")
                               and any(a is n for a in ast.walk(q)) for q in ast.walk(t)):
                        out.append(Finding(
                            f"F{len(out)+1:02d}", "协程 Future 未取结果",
                            "INV-failure-visible", severity="P1",
                            loc=f"{rel}:{n.lineno}",
                            evidence="异常存于 Future，调度线程无感 → 失败被记成成功"))
                elif n.func.attr == "create_task":
                    saved = any(isinstance(q, ast.Assign) and any(a is n for a in ast.walk(q))
                                for q in ast.walk(t))
                    added = any(isinstance(q, ast.Call) and isinstance(q.func, ast.Attribute)
                                and q.func.attr in ("add", "add_done_callback")
                                and any(a is n for a in ast.walk(q)) for q in ast.walk(t))
                    if not saved and not added:
                        out.append(Finding(
                            f"F{len(out)+1:02d}", "create_task 引用未保存",
                            "INV-failure-visible", severity="P2",
                            loc=f"{rel}:{n.lineno}",
                            evidence="asyncio 仅持弱引用 → Task 可能在完成前被 GC"))
    return out


# ───────────────── INV-4 异常可见 ─────────────────
def inv_exception_visible(repo, root="butler"):
    """INV: except 分支不得静默吞掉异常。

    源起：本项目系统性病灶「兜底掩盖故障」——门禁基线 106 条豁免里
    42 条 except-pass-broad，我独立扫出 55 处 except: pass。
    这条不变量是**该病灶的量化探针**：数值本身就是结论，不需要逐条定性。
    """
    total = n_pass = 0
    samples = []
    for p in _py_files(repo, root):
        try:
            t = ast.parse(open(p, encoding="utf-8").read())
        except Exception:
            continue
        rel = os.path.relpath(p, repo)
        for n in ast.walk(t):
            if not isinstance(n, ast.ExceptHandler):
                continue
            total += 1
            if len(n.body) == 1 and isinstance(n.body[0], ast.Pass):
                n_pass += 1
                if len(samples) < 3:
                    samples.append(f"{rel}:{n.lineno}")
    return n_pass, total, samples


# ───────────────── INV-5 副作用守恒 ─────────────────
def _exit_paths(fn):
    """收集函数的『出口路径』：(return行, return之前已执行的副作用调用集合)。

    改进点（第六轮时本条 0 命中、等于失效）：
      旧版只按「顶层语句顺序 + lineno < return.lineno」近似判断，
      把 if/else 两个互斥分支的调用算进了同一条路径 —— 于是路径间
      「看起来」永远一致，永远 0 命中。
    新版做真正的分支展开：
      · 每条顶层语句序列切分为若干「路径段」
      · if/else：分支互斥，各成一条路径
      · try/except：视为两条路径
      · return/raise 终止当前路径
    """
    # 关键词必须覆盖 V7 的真实形状：dialog.speak 走队列时调的是 enqueue_tts，
    # 漏的是 dedup.record / repo.add_turn / _publish_dialog。
    # 第六版关键词表太窄（缺 enqueue/send/put/insert/update），导致 V7 形状
    # 的出口被判成「一条副作用都没做」而过滤掉 —— 规则看不见自己要抓的目标。
    SIDE = ("add_", "record", "publish", "save", "write", "emit", "notify",
            "commit", "enqueue", "send", "put", "insert", "update", "delete",
            "append", "persist", "flush", "store", "track", "log_")

    def calls_in(stmts):
        out = set()
        for st in stmts:
            for q in ast.walk(st):
                if isinstance(q, ast.Call):
                    d = _dotted(q.func) or (q.func.id if isinstance(q.func, ast.Name) else None)
                    if d and any(k in d.lower() for k in SIDE):
                        out.add(d)
        return out

    paths = []          # [(exit_lineno, calls_so_far)]
    cur = set()
    for st in fn.body:
        # 分支结构：各分支独立成路径，不互相累加
        if isinstance(st, ast.If):
            for branch in (st.body, st.orelse):
                b = set(cur) | calls_in(branch)
                for x in branch:
                    if isinstance(x, (ast.Return, ast.Raise)):
                        paths.append((x.lineno, b))
        elif isinstance(st, ast.Try):
            b = set(cur) | calls_in(st.body)
            for x in st.body:
                if isinstance(x, (ast.Return, ast.Raise)):
                    paths.append((x.lineno, b))
            for h in st.handlers:
                hb = set(cur) | calls_in(h.body)
                for x in h.body:
                    if isinstance(x, (ast.Return, ast.Raise)):
                        paths.append((x.lineno, hb))
        elif isinstance(st, (ast.Return, ast.Raise)):
            paths.append((st.lineno, set(cur)))
        else:
            cur |= calls_in([st])
    return paths


def inv_side_effect_conserved(repo, root="butler"):
    """INV: 同一操作的多个出口，副作用集合必须一致。

    源起 T-1 / V7（dialog.speak 走队列后提前 return，
    丢掉 dedup.record / repo.add_turn / _publish_dialog 三个副作用）。

    超出源发现的能力：这个形状极其通用——任何「if 快路径: return」都可能漏副作用。
    第六轮时因只做 lineno 近似而 0 命中（等于失效），本轮改为真正的分支展开。
    """
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
            paths = _exit_paths(n)
            if len(paths) < 2:
                continue
            allc = set().union(*[c for _, c in paths])
            for ln, c in paths:
                miss = allc - c
                if not miss:
                    continue
                # 关键过滤：守卫式提前 return（if not found: return / if g: return g）
                # 合法地跳过所有副作用 —— 它不是缺陷，是正常控制流。
                # V7 的真实形状是：该出口**已经做了一部分**副作用，却漏了其余
                # （speak 入了队，但没 record / add_turn / publish）。
                # 所以判据是：c 非空（做过一些）且 miss 非空（漏了一些）。
                # 第六版未加此过滤时命中 34 条，人工核验后绝大多数是守卫子句。
                if not c:
                    continue   # 一条副作用都没做 = 守卫式提前返回，跳过
                # 只在「其他出口全都做了、唯独这条没做」时才报 —— 排除纯粹的分支差异
                others = [x for l2, x in paths if l2 != ln]
                if others and all(m <= x for x in others for m in [miss]):
                    out.append(Finding(
                        f"S{len(out)+1:02d}",
                        f"`{n.name}` 在 L{ln} 出口缺失副作用 {sorted(miss)}",
                        "INV-side-effect", severity="P0",
                        loc=f"{rel}:{ln}",
                        evidence=f"其余 {len(others)} 条出口均执行了这些调用 → 疑似提前 return",
                        detail=["    启发式结论，必须经行为验证才能定性"]))
    return out


# ───────────────── INV-6 动态调用契约 ─────────────────
def inv_dynamic_contract(repo, root="butler"):
    """INV: 探测存在性后再调用，其签名必须匹配全仓真实定义。

    源起 V1+V2（af_bridge 用 hasattr 探测 devices.by_room()——该方法不存在，
    探测短路为 []，for 循环零次；循环体内 tts.speak(device=...) 参数名也错，
    被短路掩盖着从没机会抛异常）。

    超出源发现：把「探测 + 错参」组合形状抽象出来。修好探测层的当天就会炸。
    """
    sigs = {}
    for p in _py_files(repo, root):
        try:
            t = ast.parse(open(p, encoding="utf-8").read())
        except Exception:
            continue
        for n in ast.walk(t):
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
                sigs.setdefault(n.name, set()).update(
                    {a.arg for a in n.args.args} | {a.arg for a in n.args.kwonlyargs})
    out = []
    for p in _py_files(repo, root):
        try:
            src = open(p, encoding="utf-8").read()
            t = ast.parse(src)
        except Exception:
            continue
        rel = os.path.relpath(p, repo)
        for n in ast.walk(t):
            if not (isinstance(n, ast.Call) and isinstance(n.func, ast.Name)
                    and n.func.id in ("hasattr", "getattr")):
                continue
            if not (n.args and isinstance(n.args[-1], ast.Constant)
                    and isinstance(n.args[-1].value, str)):
                continue
            attr = n.args[-1].value
            same = next((q for q in ast.walk(t) if q is not n
                         and isinstance(q, ast.Call) and isinstance(q.func, ast.Attribute)
                         and q.func.attr == attr), None)
            if same is None:
                continue
            kw = [k.arg for k in same.keywords if k.arg]
            if not kw:
                continue
            known = sigs.get(attr)
            if known is None:
                out.append(Finding(f"C{len(out)+1:02d}",
                    f"探测 `{attr}` 后调用，但全仓无同名方法定义",
                    "INV-dynamic-contract", severity="P1", loc=f"{rel}:{same.lineno}",
                    evidence="方法不存在 → hasattr 短路 → 调用点永不执行（V1 形状）"))
                continue
            bad = [k for k in kw if k not in known]
            if bad:
                out.append(Finding(f"C{len(out)+1:02d}",
                    f"探测 `{attr}` 后传入不被接受的参数 {bad}",
                    "INV-dynamic-contract", severity="P0", loc=f"{rel}:{same.lineno}",
                    evidence=f"真实签名接受 {sorted(known)} → 必 TypeError；探测短路则永不暴露"))
    return out


def _bound_names(node):
    names = set()
    for x in ast.walk(node):
        if isinstance(x, ast.Name) and isinstance(x.ctx, ast.Store):
            names.add(x.id)
        elif isinstance(x, (ast.FunctionDef, ast.AsyncFunctionDef)):
            names.add(x.name)
            for a in list(x.args.args) + list(x.args.kwonlyargs):
                names.add(a.arg)
            if x.args.vararg: names.add(x.args.vararg.arg)
            if x.args.kwarg: names.add(x.args.kwarg.arg)
        elif isinstance(x, ast.ExceptHandler) and x.name:
            names.add(x.name)
        elif isinstance(x, (ast.Import, ast.ImportFrom)):
            for a in x.names:
                names.add(a.asname or a.name.split(".")[0])
        elif isinstance(x, ast.ClassDef):
            names.add(x.name)
        elif isinstance(x, (ast.Global, ast.Nonlocal)):
            names.update(x.names)
        elif isinstance(x, ast.alias):
            names.add(x.asname or x.name.split(".")[0])
    return names


# ───────────────── INV-7 降级路径自洽 ─────────────────
def inv_degrade_path_sane(repo, root="butler"):
    """INV: except 降级分支内不得引用未定义符号。

    源起 P0-3（config_routes.py:23 的 except 引用未定义 logger
    → 配置损坏时「兜底代码自己崩」→ 全站 500 且无法自愈）。
    超出源发现：P0-3 是单点，本条扫全仓降级分支——主路径坏了还有兜底，兜底坏了就裸奔。
    """
    out = []
    for p in _py_files(repo, root):
        try:
            t = ast.parse(open(p, encoding="utf-8").read())
        except Exception:
            continue
        rel = os.path.relpath(p, repo)
        mod = _bound_names(t)
        funcs = [n for n in ast.walk(t)
                 if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]
        for n in ast.walk(t):
            if not isinstance(n, ast.ExceptHandler):
                continue
            owner = None
            for f in funcs:
                if f.lineno <= n.lineno <= (f.end_lineno or f.lineno):
                    if owner is None or f.lineno > owner.lineno:
                        owner = f
            scope = mod | (_bound_names(owner) if owner is not None else set())
            if n.name:
                scope.add(n.name)
            for x in ast.walk(n):
                if not (isinstance(x, ast.Name) and isinstance(x.ctx, ast.Load)):
                    continue
                if x.id in BUILTIN or x.id in scope:
                    continue
                out.append(Finding(f"D{len(out)+1:02d}",
                    f"降级分支引用未定义符号 `{x.id}`", "INV-degrade-sane",
                    severity="P0", loc=f"{rel}:{x.lineno}",
                    evidence="兜底代码自己崩 → 主路径坏了没兜底，等于裸奔"))
    seen, uniq = set(), []
    for f in out:
        k = (f.loc.split(":")[0], f.title)
        if k not in seen:
            seen.add(k); uniq.append(f)
    return uniq


# ───────────── 统一入口（必须在文件末尾，所有不变量已定义之后） ─────────────

def run(repo, root="butler", verbose=True):
    repo = os.path.abspath(repo)   # 相对路径会让 radon/文件遍历静默返回空
    res = {}
    res["async_pure"] = inv_async_pure(repo, root)
    res["durable"] = inv_durable_write(repo, root)
    res["failure"] = inv_failure_visible(repo, root)
    res["side_effect"] = inv_side_effect_conserved(repo, root)
    res["contract"] = inv_dynamic_contract(repo, root)
    res["degrade"] = inv_degrade_path_sane(repo, root)
    res["except_pass"] = inv_exception_visible(repo, root)

    if verbose:
        print("─" * 72)
        print("Stage 3  不变量断言（唯一具备自动发现能力的层）")
        print("─" * 72)
        for k in ("async_pure", "durable", "failure", "side_effect", "contract", "degrade"):
            print(f"  {k:<14} {len(res[k]):>4} 条")
        n, tot, _ = res["except_pass"]
        print(f"  except_pass     {n:>4} 处 / 共 {tot} 个 except 处理器 "
              f"（{n/max(1,tot)*100:.0f}%）")
        print()
        for f in (res.get("degrade") or [])[:5]:
            print(f"  ⚑ {f.title}")
            print(f"      {f.loc}")
        for f in res["side_effect"][:5]:
            print(f"  ⚑ {f.title}")
            print(f"      {f.loc}")
        if res["side_effect"]:
            print()
    return res
