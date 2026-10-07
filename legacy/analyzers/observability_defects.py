#!/usr/bin/env python3
"""第十二轮专题：可观测性与遥测正确性（纯 stdlib AST）。

前十一轮覆盖：稳定性、持久化、并发、复杂度、控制流、死代码/缓存、时间数值、
输入边界、事务边界、序列化、错误处理/降级。本轮看**观测数据本身对不对**：

  OBS-01 计数器只增不复位（跨周期统计会把历史累进当期）
  OBS-02 有界容器被无界累加（deque 有 maxlen 但 dict/list 无）
  OBS-03 指标分母语义错误（成功率/比率的分子分母不同源）
  OBS-04 遥测裁剪吃掉当期数据（有界 deque 满了之后新数据被丢）
  OBS-05 日志埋点缺失关键上下文（无 id/无错误类型）
  OBS-06 审计事件在失败路径上不落（只在成功路径 append）

设计原则：本类问题**不影响功能，只影响你能否发现问题**——但正因为如此
最容易被忽略。命中一律给机制说明。

用法: observability_defects.py <src_root> <outdir>
"""
from __future__ import annotations

import ast
import json
import re
import sys
from collections import Counter
from pathlib import Path

try:
    from . import _common as C
except ImportError:                      # 直接以脚本方式运行时
    import sys as _s, pathlib as _p
    _s.path.insert(0, str(_p.Path(__file__).resolve().parent))
    import _common as C


RESET_HINT = ("clear", "reset", "= 0", "=0", "popleft", "rotate")


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
        # 接收者不是简单 Name（如 `(p / "x.json").write_text(...)`、数组下标、
        # 函数调用结果）→ 首版直接返回 ""，整条调用被丢弃（PITFALLS N7）。
        # 改为保留已收集的属性链，至少能匹配方法名。
        if parts:
            return ".".join(reversed(parts))
    return ""


def _fn_src(fn) -> str:
    try:
        return ast.unparse(fn)
    except Exception:
        return ""


def _is_bounded(tree, name: str) -> bool:
    """判断某个名字是否是有界容器。

    首版只认 deque(maxlen=)，把以下两种常见裁剪判成"无界"：
      - `if len(self.X) > self.max_X: del self.X[: len - max]`（FeedbackRecorder.events）
      - `self.X = self.X[-N:]` 尾部保留
    """
    src = ast.unparse(tree)
    if re.search(rf"{re.escape(name)}\s*=\s*deque\([^)]*maxlen", src):
        return True
    if re.search(rf"len\(self\.{re.escape(name)}\)\s*>\s*self\.\w*(?:max|_max|limit)", src) \
            and re.search(rf"del\s+self\.{re.escape(name)}\s*\[", src):
        return True
    if re.search(rf"self\.{re.escape(name)}\s*=\s*self\.{re.escape(name)}\s*\[-", src):
        return True
    return False


# ────────────────────────────────────────────────────────────────────
# OBS-01 计数器只增不复位
# ────────────────────────────────────────────────────────────────────
def check_counter_no_reset(tree, rel):
    out = []
    for cls in ast.walk(tree):
        if not isinstance(cls, ast.ClassDef):
            continue
        src = ast.unparse(cls)
        # 类内 self.X[...] += 1 形式的计数
        counters = set()
        for n in ast.walk(cls):
            if isinstance(n, ast.AugAssign) and isinstance(n.op, ast.Add) \
                    and isinstance(n.target, ast.Subscript) \
                    and isinstance(n.target.value, ast.Attribute) \
                    and isinstance(n.target.value.value, ast.Name) \
                    and n.target.value.value.id == "self":
                counters.add(n.target.value.attr)
        if not counters:
            continue
        has_reset = any(k in src for k in RESET_HINT)
        # 有界容器不算问题（自裁剪）
        bounded = {c for c in counters if _is_bounded(tree, c)}
        real = counters - bounded
        if real and not has_reset:
            out.append({
                "rule": "OBS-01-counter-no-reset", "severity": "low",
                "file": rel, "line": cls.lineno, "class": cls.name, "function": "<class>",
                "message": f"{cls.name} 的计数器 {sorted(real)} 只增不减且类内无复位动作；"
                           f"若是按周期上报的指标，历史会累进当期（需人工确认是否有外部复位）"})
    return out


# ────────────────────────────────────────────────────────────────────
# OBS-02 无界容器被累加
# ────────────────────────────────────────────────────────────────────
UNBOUNDED_FACTORY = ("list", "dict", "set", "defaultdict", "Counter")


def check_unbounded_accumulation(tree, rel):
    out = []
    for cls in ast.walk(tree):
        if not isinstance(cls, ast.ClassDef):
            continue
        # 容器字段识别 —— 统一走共享 helper。
        # 首版只认 `self.X = []`(Assign) 与 dataclass 的 AnnAssign+Name，
        # 漏掉 `self.X: list[str] = []`(AnnAssign + Attribute) 这一形态
        # → AF BUG-01 的 node_visits 正是这个写法，漏检（PITFALLS N8 续）。
        targets = C.container_inits(cls)
        if not targets:
            continue
        appends = set()
        for n in ast.walk(cls):
            if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) \
                    and n.func.attr in ("append", "add", "update", "extend"):
                # 接收者可能是**链式调用**：`self.samples.setdefault(k, []).append(v)`
                # 首版要求 func.value 直接是 self.X → 这类写法全部漏检
                # （AF BUG-14 的 ConfidenceStore.samples 正是这个形态）。
                # 沿 Call 链向内剥，只要最内层 receiver 是 self.X 就算。
                recv = n.func.value
                hops = 0
                while isinstance(recv, ast.Call) and hops < 6:
                    recv = recv.func
                    if isinstance(recv, ast.Attribute):
                        recv = recv.value
                    hops += 1
                if isinstance(recv, ast.Attribute) and isinstance(recv.value, ast.Name) \
                        and recv.value.id == "self":
                    appends.add(recv.attr)
            # self.X[...] = v 也算写入
            if isinstance(n, (ast.Assign, ast.AugAssign)):
                tgts = n.targets if isinstance(n, ast.Assign) else [n.target]
                for t in tgts:
                    if isinstance(t, ast.Subscript) and isinstance(t.value, ast.Attribute) \
                            and isinstance(t.value.value, ast.Name) \
                            and t.value.value.id == "self":
                        appends.add(t.value.attr)
        risky = sorted(appends & set(targets))
        if not risky:
            continue
        # 排除**映射型容器**：有删除路径（pop/del/clear/remove/discard/popitem）
        # 的容器不是单调累加（如 code store 的 create/consume 成对）。
        # OBS-02 的语义是"遥测类单调增长"，混入映射型会误报（PITFALLS P14）。
        src_all0 = ast.unparse(cls)
        # 按**容器名**判定删除路径（早期用类级判定 → 同类中真无界的容器被连坐
        # 跳过，AF BUG-18 的 records 因此漏报）
        risky = [r for r in risky if not C.has_removal_path(src_all0, r)]
        if not risky:
            continue
        src = ast.unparse(cls)
        bounded = {r for r in risky
                   if C.is_bounded(ast.unparse(cls), r) or C.is_bounded(ast.unparse(tree), r)}
        real = [r for r in risky if r not in bounded]
        if real:
            out.append({
                "rule": "OBS-02-unbounded-accumulation", "severity": "medium",
                "file": rel, "line": cls.lineno, "class": cls.name, "function": "<class>",
                "message": f"{cls.name} 的容器 {real} 被持续累加且未见有界化/裁剪；"
                           f"常驻进程会单调增长（与 P1-1 修复的 deque(maxlen) 同类）"})
    return out


# ────────────────────────────────────────────────────────────────────
# OBS-03 指标分母语义
# ────────────────────────────────────────────────────────────────────
def check_ratio_semantics(tree, rel):
    out = []
    for fn in ast.walk(tree):
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        src = _fn_src(fn)
        if not re.search(r"(?i)(rate|ratio|success_rate|sr\b|pct|percent)", src):
            continue
        for n in ast.walk(fn):
            if not isinstance(n, ast.BinOp) or not isinstance(n.op, ast.Div):
                continue
            s = ast.unparse(n)
            num = ast.unparse(n.left)
            den = ast.unparse(n.right)
            # 分子分母引用同一个变量名不同键 → 正常
            # 分子是一个计数、分母是另一个集合的长度 → 可能不同源
            if re.search(r"\blen\(", den) and not re.search(r"\blen\(", num):
                num_base = re.match(r"([A-Za-z_][\w]*)\[", num)
                den_base = re.search(r"len\(([A-Za-z_][\w]*)", den)
                if num_base and den_base and num_base.group(1) != den_base.group(1):
                    out.append({
                        "rule": "OBS-03-ratio-source-mismatch", "severity": "low",
                        "file": rel, "line": n.lineno, "function": fn.name,
                        "message": f"{fn.name}() 的比率 {s[:50]}：分子取自 "
                                   f"{num_base.group(1)}、分母取自 len({den_base.group(1)})，"
                                   f"两者来源不同 → 比值可能 >1 或语义不符"})
    return out


# ────────────────────────────────────────────────────────────────────
# OBS-04 有界 deque 满了丢数据
# ────────────────────────────────────────────────────────────────────
def check_bounded_drop(tree, rel):
    out = []
    src_all = ast.unparse(tree)
    for m in re.finditer(r"(\w+)\s*[:=].*deque\([^)]*maxlen\s*=\s*(\d+)", src_all):
        name, cap = m.group(1), int(m.group(2))
        # 该文件里是否有基于它的聚合/统计函数
        agg = re.search(rf"(?i)def\s+\w*(summary|stats|report|aggregate)\w*\s*\(", src_all)
        if agg:
            out.append({
                "rule": "OBS-04-bounded-drop", "severity": "low",
                "file": rel, "line": 0, "function": "<module>",
                "message": f"{name} 是 maxlen={cap} 的有界 deque，且文件内含统计函数；"
                           f"超容量后最老数据被丢弃 → 长周期统计的样本不完整（属有意取舍，需确认口径）"})
    return out


# ────────────────────────────────────────────────────────────────────
# OBS-05 日志埋点缺上下文
# ────────────────────────────────────────────────────────────────────
def check_log_context(tree, rel):
    out = []
    for fn in ast.walk(tree):
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for n in ast.walk(fn):
            if not isinstance(n, ast.Call):
                continue
            c = _chain(n)
            if not re.search(r"(?i)(logger|log)\.(error|warning|warn)", c):
                continue
            s = ast.unparse(n)
            # 无参数化（纯常量字符串）且无 f-string → 缺上下文
            has_fmt = n.args and (isinstance(n.args[0], ast.JoinedStr)
                                  or "%" in s or "{".find(s) >= 0)
            has_id = re.search(r"(?i)(id|name|key|path|count|reason|error)", s) is not None
            if n.args and isinstance(n.args[0], ast.Constant) and not has_fmt:
                out.append({
                    "rule": "OBS-05-log-no-context", "severity": "low",
                    "file": rel, "line": n.lineno, "function": fn.name,
                    "message": f"{fn.name}() 的 {c}() 使用纯常量消息"
                               + ("（无 id/原因等上下文）" if not has_id else "")
                               + "：排障时无法定位到具体对象"})
    return out


# ────────────────────────────────────────────────────────────────────
# OBS-06 审计只在成功路径落
# ────────────────────────────────────────────────────────────────────
def check_audit_coverage(tree, rel):
    out = []
    for fn in ast.walk(tree):
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        # 函数内有 try 且 try 内有 append/record
        for n in ast.walk(fn):
            if not isinstance(n, ast.Try):
                continue
            in_try = False
            for x in ast.walk(ast.Module(body=n.body, type_ignores=[])):
                if isinstance(x, ast.Call) and re.search(
                        r"(?i)(append|record|emit|log_event)", _chain(x)):
                    in_try = True
            if not in_try:
                continue
            # handlers 里是否也有记账
            for h in n.handlers:
                hsrc = ast.unparse(ast.Module(body=h.body, type_ignores=[]))
                if not re.search(r"(?i)(append|record|emit|log_event)", hsrc):
                    # 仅 pass / return 的降级
                    if re.match(r"\s*(pass|return|continue|break)\b", hsrc.strip()):
                        out.append({
                            "rule": "OBS-06-audit-missing-on-failure", "severity": "low",
                            "file": rel, "line": h.lineno, "function": fn.name,
                            "message": f"{fn.name}() 在成功路径记账，但 except 分支仅 "
                                       f"{hsrc.strip()[:20]} 不记账："
                                       f"失败事件在审计流里不可见（与 BUG-07 同类形状）"})
    return out


CHECKS = [
    check_counter_no_reset,
    check_unbounded_accumulation,
    check_ratio_semantics,
    check_bounded_drop,
    check_log_context,
    check_audit_coverage,
]


def main() -> int:
    root = Path(sys.argv[1] if len(sys.argv) > 1 else "/data/workspace/audit/src/src/autoforge")
    outdir = Path(sys.argv[2] if len(sys.argv) > 2 else "/data/workspace/audit/rounds/round-012/observability")
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
    (outdir / "observability-findings.json").write_text(
        json.dumps({"findings": findings}, ensure_ascii=False, indent=2))
    print(json.dumps({"files": files, "total": len(findings),
                      "by_severity": dict(Counter(f["severity"] for f in findings)),
                      "by_rule": dict(Counter(f["rule"] for f in findings))},
                     ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
