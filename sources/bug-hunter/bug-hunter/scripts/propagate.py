#!/usr/bin/env python3
"""同类缺陷全仓排查器（pattern propagation）。

为什么需要这一层（第十轮起）：
  前九轮的模式是「在一个文件里发现缺陷 → 报告 → 下一轮在别的文件里
  偶然又撞见同形状的另一个」。V23（_run_coro 跨事件循环挂死）在
  mcp/server.py 被发现后，我**没有机制**去回答一个显然该问的问题：
      「全仓还有几个地方在已有 loop 时新建事件循环？」

  没有这一层，同类缺陷只能靠下一轮撞运气。有了它，发现一个就能挖出一串。

设计：
  输入一个「形状定义」（AST 谓词），输出全仓所有匹配点。
  形状库从已实锤的缺陷反推而来，每条注明源发现。
  与 S1 的静态规则的区别：S1 是常驻普查（每轮都跑），
  本层是**定向深挖**（发现某个 P0 后，专门把它的形状挖到底）。
"""
from __future__ import annotations

import ast
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from core import Finding  # noqa: E402
from stage1_scan import _py_files  # noqa: E402


def _dotted(n):
    if isinstance(n, ast.Attribute) and isinstance(n.value, ast.Name):
        return f"{n.value.id}.{n.attr}"
    if isinstance(n, ast.Attribute) and isinstance(n.value, ast.Attribute):
        b = _dotted(n.value)
        return f"{b}.{n.attr}" if b else None
    return None


# ───────────────── 形状库 ─────────────────
# 每条：(id, 说明, 源发现, 谓词)  谓词输入 (树, 源文件路径) 输出 [(lineno, 片段)]

def _shape_new_loop_in_async(t, p):
    """在已有事件循环时又创建新的循环 —— V23 形状。

    源：mcp/server.py:389 _run_coro 用 ThreadPoolExecutor+asyncio.run，
    在 running loop 内又起了新 loop → 跨循环锁等待 → 进程挂死。
    """
    out = []
    for n in ast.walk(t):
        if not isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        is_async = isinstance(n, ast.AsyncFunctionDef)
        for x in ast.walk(n):
            d = _dotted(x.func) if isinstance(x, ast.Call) else None
            if d in ("asyncio.run",) and is_async:
                out.append((x.lineno, "async 函数内 asyncio.run（可能起新 loop）"))
            elif d == "asyncio.run" and _has_executor(n):
                out.append((x.lineno, "同步函数内 asyncio.run + 线程池（可能起新 loop）"))
            elif d in ("asyncio.new_event_loop", "loop.run_until_complete"):
                out.append((x.lineno, f"手工建循环 {d}"))
            elif d == "asyncio.run_coroutine_threadsafe":
                # 取了 result 的算已处理；否则是 V13
                if not any(isinstance(q, ast.Call) and isinstance(q.func, ast.Attribute)
                           and q.func.attr == "result" and any(a is x for a in ast.walk(q))
                           for q in ast.walk(t)):
                    out.append((x.lineno, "run_coroutine_threadsafe 未取 result（V13）"))
    return out


def _has_executor(fn):
    for x in ast.walk(fn):
        d = _dotted(x.func) if isinstance(x, ast.Call) else None
        if d and ("ThreadPoolExecutor" in d or "to_thread" in d
                  or "run_in_executor" in d):
            return True
    return False


def _shape_direct_bypass(t, p):
    """绕过 TTSQueue 直接发声 —— V15 形状。

    源：manager.py:192 明写「via 只进日志」，5 处主动发声（proactive /
    anomaly / notifier / morning / af_bridge）绕过队列保护。
    """
    out = []
    for n in ast.walk(t):
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute):
            if n.func.attr in ("speak", "speak_as_role", "notify_message",
                               "play_tts", "enqueue_tts"):
                kw = {k.arg for k in n.keywords if k.arg}
                if "via" in kw:
                    out.append((n.lineno, f"发声调用带 via= 参数（可能绕过队列）"))
                elif n.func.attr != "enqueue_tts":
                    out.append((n.lineno, f"直接调 {n.func.attr}（非 enqueue_tts）"))
    return out


def _shape_success_on_error(t, p):
    """捕获异常后仍返回成功态 —— V13 + 系统性「兜底掩盖故障」。

    源：V13 的 mark_success、以及全仓 {"ok": True} 常量返回。
    """
    out = []
    for n in ast.walk(t):
        if not isinstance(n, ast.ExceptHandler):
            continue
        for x in ast.walk(n):
            # return {"ok": True} / return True / mark_success()
            if isinstance(x, ast.Return) and x.value is not None:
                v = x.value
                if isinstance(v, ast.Constant) and v.value is True:
                    out.append((x.lineno, "except 内 return True"))
                elif isinstance(v, ast.Dict):
                    for k in v.keys:
                        if isinstance(k, ast.Constant) and k.value == "ok":
                            for val in v.values:
                                if isinstance(val, ast.Constant) and val.value is True:
                                    out.append((x.lineno, 'except 内 return {"ok": True}'))
            if isinstance(x, ast.Call) and isinstance(x.func, ast.Attribute) \
                    and x.func.attr in ("mark_success", "mark_ok"):
                out.append((x.lineno, f"except 内调 {x.func.attr}（失败记为成功）"))
    return out


def _shape_blocking_in_async(t, p):
    """async 内阻塞调用 —— V18 形状（含 executor 豁免判断）。"""
    BL = {"time.sleep", "subprocess.run", "subprocess.call", "os.system",
          "requests.get", "requests.post", "httpx.get", "httpx.post"}
    out = []
    for n in ast.walk(t):
        if not isinstance(n, ast.AsyncFunctionDef):
            continue
        for x in ast.walk(n):
            if not isinstance(x, ast.Call):
                continue
            d = _dotted(x.func)
            if d not in BL:
                continue
            # 该调用所在的最内层函数是否被 executor 包裹
            owner = None
            for c in ast.walk(t):
                if isinstance(c, (ast.FunctionDef, ast.AsyncFunctionDef)) \
                        and c.lineno <= x.lineno <= (c.end_lineno or c.lineno):
                    if owner is None or c.lineno > owner.lineno:
                        owner = c
            ok = False
            for q in ast.walk(t):
                if isinstance(q, ast.Call) and isinstance(q.func, ast.Attribute) \
                        and q.func.attr in ("run_in_executor", "to_thread"):
                    for arg in q.args:
                        if isinstance(arg, ast.Name) and owner is not None \
                                and arg.id == owner.name:
                            ok = True
            if not ok:
                out.append((x.lineno, f"async 内阻塞 {d}"))
    return out


def _shape_nonatomic_state_write(t, p):
    """状态文件非原子写 —— T-2 / V20 形状。"""
    src = open(p, encoding="utf-8").read()
    if "os.replace" in src or ".tmp" in src:
        return []   # 该文件懂原子写，跳过（避免误判已正确实现的文件）
    out = []
    for n in ast.walk(t):
        if isinstance(n, ast.With):
            for it in n.items:
                c = it.context_expr
                if isinstance(c, ast.Call) and isinstance(c.func, ast.Name) \
                        and c.func.id == "open" and len(c.args) >= 2 \
                        and isinstance(c.args[1], ast.Constant) \
                        and "w" in str(c.args[1].value):
                    body = ast.get_source_segment(src, n) or ""
                    if "json.dump" in body:
                        out.append((c.lineno, "JSON 状态文件非原子写"))
    return out


SHAPES = {
    "new-loop":     ("已有 loop 时新建事件循环（V23 → 进程挂死）", _shape_new_loop_in_async),
    "direct-speak": ("绕过 TTSQueue 直接发声（V15）", _shape_direct_bypass),
    "success-err":  ("捕获异常后仍报成功（V13 同源）", _shape_success_on_error),
    "blocking":     ("async 内阻塞调用（V18）", _shape_blocking_in_async),
    "nonatomic":    ("状态文件非原子写（T-2 / V20）", _shape_nonatomic_state_write),
}

# 排查状态：避免重复挖同一形状，也让"还剩几个形状没挖"可计算。
# 已深挖的形状会带来新缺陷（R10 new-loop→V24，R11 direct-speak→V26），
# 未挖的是后续轮次最直接的产出来源。
STATUS = {
    "new-loop":     "done @R10 → 坐实 V24；证伪 runner.py:450",
    "direct-speak": "done @R11 → 坐实 V26；确认绕过点多于原记 5 处",
    "success-err":  "done @R16 → 坐实 V30（require_presence 失败放行）+ V31（旧残留）",
    "blocking":     "done @R16 → 2 处均已核实：docker_tools=真缺陷(V18)；app.py:264=启动期一次性 ffmpeg，降 P3",
    "nonatomic":    "done @R16 → 4 处已逐个核实降级行为（fast_routes 最重=V21，cron_task 最轻=P3）",
}


def propagate(repo, shape, root="butler"):
    """对全仓跑一个形状，返回 Finding 列表。

    去重是必须的：形状谓词对「函数」做外层 walk、对「调用」做内层 walk，
    嵌套定义的函数会被其每个外层祖先各命中一次（实测 app.py:550 被报 3 遍）。
    不去重会让计数虚高 2-3 倍，直接毁掉这条排查器的可信度。
    """
    if shape not in SHAPES:
        raise ValueError(f"未知形状 {shape}，可用：{list(SHAPES)}")
    _, fn = SHAPES[shape]
    out, seen = [], set()
    for p in _py_files(repo, root):
        rel = os.path.relpath(p, repo)
        try:
            t = ast.parse(open(p, encoding="utf-8").read())
        except Exception:
            continue
        for lineno, desc in fn(t, p):
            key = (rel, lineno, desc)
            if key in seen:
                continue
            seen.add(key)
            out.append(Finding(f"{shape[:2].upper()}{len(out)+1:02d}",
                               desc, f"propagate:{shape}", severity="P1",
                               loc=f"{rel}:{lineno}",
                               evidence=f"形状来源：{SHAPES[shape][0]}"))
    return out


def run_all(repo, root="butler", verbose=True):
    res = {}
    for k in SHAPES:
        res[k] = propagate(repo, k, root)
    if verbose:
        print("─" * 72)
        print("同类缺陷全仓排查（定向深挖，非每轮普查）")
        print("─" * 72)
        for k, v in res.items():
            print(f"  [{STATUS[k][:12]:<12}] {SHAPES[k][0][:38]:<40}{len(v):>4} 处")
        print()
        # 只展示最危险的 new-loop
        for f in res.get("new-loop", [])[:10]:
            print(f"  ⚑ {f.title}")
            print(f"      {f.loc}")
        if len(res.get("new-loop", [])) > 10:
            print(f"    ... 另 {len(res['new-loop'])-10} 处")
        print()
    return res
