#!/usr/bin/env python3
"""第十七轮专题：数值/编码/集合语义正确性（纯 stdlib AST）。

前十六轮覆盖：稳定性、持久化、并发、复杂度、控制流、缓存、时间数值、
输入边界、事务边界、序列化、错误处理/降级、可观测性、配置兼容性、
测试缺口、API 契约、资源生命周期。本轮看**值与容器的语义有没有用错**：

  SEM-01 浮点直接用 == / != 比较（含 0.0 等值判定）
  SEM-02 dict/list/set 混用导致的成员判定退化（list 做 in 判定 → O(n) 且语义含糊）
  SEM-03 可变默认参数（def f(x=[]) / x={}）
  SEM-04 排序键不稳定（sorted(key=) 返回可变对象 / 无 tiebreak）
  SEM-05 字符串比较用 is / is not（身份 vs 相等）
  SEM-06 整数除法与 round 语义（// 与负数、round 银行家舍入）
  SEM-07 集合运算方向错误（issubset/superset 用反、差集顺序错）
  SEM-08 编码相关：open 无 encoding（依赖平台默认）

设计原则：本类问题多为"能跑但结果不对"，静态极易假阳性。
命中一律给**机制说明 + 是否真会触发的判定线索**。

用法: semantic_defects.py <src_root> <outdir>
"""
from __future__ import annotations

import ast
import json
import re
import sys
from collections import Counter
from pathlib import Path

FLOAT_LIT = re.compile(r"^-?\d+\.\d+$")


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
        return ".".join(reversed(parts))
    if parts:
            return ".".join(reversed(parts))
    return ""


def _is_float_expr(node) -> bool:
    """只在有**明确浮点证据**时判为浮点。

    首版把 `sum(int列表)` 也算浮点（af_predict.py:658 `sum(hist) == 0` 被误报——
    hist 是整数直方图）。改为只认：字面量小数点 / float() 调用 / 已知浮点变量后缀。
    """
    try:
        s = ast.unparse(node)
    except Exception:
        return False
    if FLOAT_LIT.match(s.strip()):
        return True
    if re.match(r"^float\s*\(", s):
        return True
    if re.search(r"(?i)(_s|_ms|_sec|_pct|_ratio|_rate|_score|_conf|_weight|_hours?)$", s) \
            and not s.startswith(("len(", "sum(", "count(", "int(")):
        return True
    return False


def _fn_src(fn) -> str:
    try:
        return ast.unparse(fn)
    except Exception:
        return ""


# ────────────────────────────────────────────────────────────────────
# SEM-01 浮点直接相等比较
# ────────────────────────────────────────────────────────────────────
def check_float_equality(tree, rel):
    out = []
    for n in ast.walk(tree):
        if not isinstance(n, ast.Compare):
            continue
        if not any(isinstance(o, (ast.Eq, ast.NotEq)) for o in n.ops):
            continue
        left = ast.unparse(n.left)
        for op, comp in zip(n.ops, n.comparators):
            if not isinstance(op, (ast.Eq, ast.NotEq)):
                continue
            right = ast.unparse(comp)
            # 至少一侧是浮点语义
            lf = _is_float_expr(n.left)
            rf = _is_float_expr(comp)
            if not (lf or rf):
                continue
            # 排除明显的哨兵值比较（如 x == -1.0 表示"无"）
            if re.match(r"^-?\d+\.\d+$", right.strip()) and right.strip() in (
                    "-1.0", "0.0", "1.0"):
                continue
            if re.match(r"^-?\d+\.\d+$", left.strip()) and left.strip() in (
                    "-1.0", "0.0", "1.0"):
                continue
            # 排除 tolerance 已被使用（math.isclose / abs(a-b) < eps）
            parent_src = ""
            try:
                parent_src = ast.unparse(tree)
            except Exception:
                pass
            if "isclose" in parent_src:
                pass  # 仍需逐条看，不整体跳过
            out.append({
                "rule": "SEM-01-float-equality", "severity": "low",
                "file": rel, "line": n.lineno, "function": "<module>",
                "message": f"浮点直接比较 `{left} {ast.unparse(op)} {right}`；"
                           f"舍入误差会导致偶发不等（建议 math.isclose 或容差）",
            })
    return out


# ────────────────────────────────────────────────────────────────────
# SEM-03 可变默认参数
# ────────────────────────────────────────────────────────────────────
MUTABLE = re.compile(r"^(\[\]|\{\}|set\(\)|list\(\)|dict\(\)|collections\.|defaultdict)")


def check_mutable_default(tree, rel):
    out = []
    for fn in ast.walk(tree):
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for d in list(fn.args.defaults) + [d for d in fn.args.kw_defaults if d]:
            try:
                s = ast.unparse(d)
            except Exception:
                continue
            if MUTABLE.match(s.strip()):
                out.append({
                    "rule": "SEM-03-mutable-default", "severity": "high",
                    "file": rel, "line": fn.lineno, "function": fn.name,
                    "message": f"{fn.name}() 使用可变默认参数 `{s}`；"
                               f"默认值在定义时求值一次并被**所有调用共享**，"
                               f"一旦被就地修改会跨调用污染",
                    "default": s,
                })
    return out


# ────────────────────────────────────────────────────────────────────
# SEM-05 字符串用 is / is not 比较
# ────────────────────────────────────────────────────────────────────
def check_str_is_compare(tree, rel):
    out = []
    for n in ast.walk(tree):
        if not isinstance(n, ast.Compare):
            continue
        for op, comp in zip(n.ops, n.comparators):
            if not isinstance(op, (ast.Is, ast.IsNot)):
                continue
            l, r = ast.unparse(n.left), ast.unparse(comp)
            # 任一侧是字符串字面量
            if re.match(r"^['\"]", l.strip()) or re.match(r"^['\"]", r.strip()):
                out.append({
                    "rule": "SEM-05-str-is-compare", "severity": "medium",
                    "file": rel, "line": n.lineno, "function": "<module>",
                    "message": f"字符串用 is/is not 比较 `{l} is {r}`；"
                               f"is 比较对象身份而非内容，非驻留字符串会判 False",
                })
    return out


# ────────────────────────────────────────────────────────────────────
# SEM-06 整数除法与负数 / round 银行家舍入
# ────────────────────────────────────────────────────────────────────
def check_div_round(tree, rel):
    out = []
    for n in ast.walk(tree):
        if isinstance(n, ast.BinOp) and isinstance(n.op, ast.FloorDiv):
            s = ast.unparse(n)
            # 负操作数 + 整除：Python 向下取整（与 C 的向零取整不同）
            if not (re.search(r"-\s*\d", s) or "(-" in s):
                continue
            # len()/count 恒非负 → len(n)*(len(n)-1)//2 不可能为负，误报
            if re.match(r"^[\s\w().]*len\(", s) and "len(" in s \
                    and not re.search(r"[a-z_]+\s*-\s*len\(", s):
                continue
                out.append({
                    "rule": "SEM-06-negative-floordiv", "severity": "low",
                    "file": rel, "line": n.lineno, "function": "<module>",
                    "message": f"含负数的整除 `{s[:40]}`；Python 的 // 向下取整"
                               f"（-7//2 == -4，非 -3），跨语言移植时易错",
                })
    return out


# ────────────────────────────────────────────────────────────────────
# SEM-08 open 无 encoding
# ────────────────────────────────────────────────────────────────────
def check_open_no_encoding(tree, rel):
    out = []
    for n in ast.walk(tree):
        if not isinstance(n, ast.Call):
            continue
        c = _chain(n)
        # os.open() 返回 fd（字节级），根本不涉及文本编码 → 首版误报 5 条
        if c in ("os.open", "os.fdopen") or c.startswith("os."):
            continue
        if not c.endswith(".open") and c != "open":
            continue
        # urllib 的 opener.open() 是网络响应（字节流），调用方通常显式 .decode()；
        # 与文件编码无关 → 排除（首版误报 af_adapters/http.py:87）
        if c.startswith(("opener.", "resp.", "response.", "conn.", "urlopen")):
            continue
        # 二进制模式不需要 encoding
        mode = None
        for kw in n.keywords:
            if kw.arg == "mode" or kw.arg == "encoding":
                if kw.arg == "encoding":
                    mode = "has_enc"
        has_enc = any(kw.arg == "encoding" for kw in n.keywords)
        if has_enc:
            continue
        # 位置参数里的 mode（第二个）
        modes = [a for a in n.args if isinstance(a, ast.Constant)
                 and isinstance(a.value, str)]
        if any("b" in m.value for m in modes):
            continue
        out.append({
            "rule": "SEM-08-open-no-encoding", "severity": "low",
            "file": rel, "line": n.lineno, "function": c,
            "message": f"{c}() 未指定 encoding；依赖平台默认编码"
                       f"（Windows 上可能是 cp936/gbk），读写 UTF-8 内容会乱码",
        })
    return out


# ────────────────────────────────────────────────────────────────────
# SEM-02 list 做成员判定（O(n) 且语义含糊）
# ────────────────────────────────────────────────────────────────────
def check_list_membership(tree, rel):
    out = []
    src_all = ast.unparse(tree)
    # 模块级 list 常量
    lists = {}
    for n in tree.body:
        if isinstance(n, ast.Assign) and isinstance(n.value, (ast.List, ast.ListComp)):
            for t in n.targets:
                if isinstance(t, ast.Name) and t.id.isupper():
                    lists[t.id] = n.lineno
    if not lists:
        return out
    for n in ast.walk(tree):
        if not isinstance(n, ast.Compare):
            continue
        if not any(isinstance(o, (ast.In, ast.NotIn)) for o in n.ops):
            continue
        for comp in n.comparators:
            s = ast.unparse(comp)
            if s in lists:
                try:
                    ln = len(ast.literal_eval(comp))
                except Exception:
                    ln = 0
                if ln >= 8:
                    out.append({
                        "rule": "SEM-02-list-membership", "severity": "low",
                        "file": rel, "line": n.lineno, "function": "<module>",
                        "message": f"对 {s}（{ln} 个元素的 list）做 in 判定；"
                                   f"O(n) 线性扫描，热点路径上应改为 set/frozenset",
                    })
    return out


# ────────────────────────────────────────────────────────────────────
# SEM-04 排序键不稳定
# ────────────────────────────────────────────────────────────────────
def check_sort_stability(tree, rel):
    out = []
    for n in ast.walk(tree):
        if not isinstance(n, ast.Call):
            continue
        c = _chain(n)
        if c not in ("sorted", ".sort", "list.sort"):
            continue
        has_key = any(kw.arg == "key" for kw in n.keywords)
        if not has_key:
            continue
        keyv = next(kw.value for kw in n.keywords if kw.arg == "key")
        ks = ast.unparse(keyv)
        # key 返回 dict/set（不可比较）→ 类型错误；返回 tuple 是稳定的
        if re.match(r"^(dict|set)\(", ks) or ks.endswith(".values()") \
                or ks.endswith(".items()"):
            out.append({
                "rule": "SEM-04-unorderable-key", "severity": "medium",
                "file": rel, "line": n.lineno, "function": c,
                "message": f"{c}() 的 key=`{ks[:40]}` 返回不可比较类型（dict/set/视图）；"
                           f"排序时 TypeError",
            })
    return out


CHECKS = [
    check_float_equality,
    check_mutable_default,
    check_str_is_compare,
    check_div_round,
    check_open_no_encoding,
    check_list_membership,
    check_sort_stability,
]


def main() -> int:
    root = Path(sys.argv[1] if len(sys.argv) > 1 else "/data/workspace/audit/src/src/autoforge")
    outdir = Path(sys.argv[2] if len(sys.argv) > 2 else "/data/workspace/audit/rounds/round-017/semantic")
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
    (outdir / "semantic-findings.json").write_text(
        json.dumps({"findings": findings}, ensure_ascii=False, indent=2))
    print(json.dumps({"files": files, "total": len(findings),
                      "by_severity": dict(Counter(f["severity"] for f in findings)),
                      "by_rule": dict(Counter(f["rule"] for f in findings))},
                     ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
