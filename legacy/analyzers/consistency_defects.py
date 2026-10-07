#!/usr/bin/env python3
"""第九轮专题：数据一致性与事务边界（纯 stdlib AST）。

前八轮覆盖：稳定性、持久化、并发、复杂度、控制流、死代码/缓存、时间数值、输入边界。
本轮看**一次操作涉及多个状态写入时，中途失败会留下什么**：

  TX-01 多文件写入序列无事务（中途失败留下部分写入，无回滚/补偿）
  TX-02 写入顺序违反依赖（先写依赖方、后写主体；崩溃后引用悬空）
  TX-03 先落盘后校验（校验失败但盘已改）—— 顺序颠倒
  TX-04 删除与写入混合且无回滚（删了旧的、新的没写成）
  TX-05 内存状态与磁盘状态更新顺序不一致（先改内存后落盘 vs 反之）
  TX-06 跨模块状态不同步（A 写了但 B 的镜像没更新）

设计原则：本类问题天然高假阳性（很多"多写"是有意的、且单写本身是原子的）。
所以 TX-01/04 只报"同一个函数内出现 >=2 个落盘站点、且无 try/无回滚"，
并强制人工核验。命中一律标注站点清单便于定位。

用法: consistency_defects.py <src_root> <outdir>
"""
from __future__ import annotations

import ast
import json
import sys
from collections import Counter
from pathlib import Path

WRITE_CALLS = {
    "atomic_write_text", "_atomic_write_text", "_atomic_write", "atomic_write",
    "write_text", "write_bytes", "unlink", "rmtree", "remove", "replace", "rename",
}
IS_WRITE = WRITE_CALLS | {"dump"}


def _chain(n: ast.Call):
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


def _is_write_call(n: ast.Call) -> str | None:
    c = _chain(n)
    base = c.split(".")[-1]
    if base == "dump":
        return c if "json" in c or "dump" == base else None
    if base in WRITE_CALLS:
        return base
    return None


def _is_delete_call(n: ast.Call) -> str | None:
    c = _chain(n)
    base = c.split(".")[-1]
    return base if base in ("unlink", "rmtree", "remove") else None


def _enclosing_try(fn, node):
    """node 是否被某个 try 包裹（返回该 try 或 None）。"""
    for t in ast.walk(fn):
        if isinstance(t, ast.Try) and any(x is node for x in ast.walk(t)):
            return t
    return None


def _try_has_rollback(t: ast.Try) -> bool:
    """try 是否有补偿动作：except 里有写/删/回滚调用，或有 finally 清理。"""
    for h in t.handlers:
        for n in ast.walk(h):
            if isinstance(n, ast.Call):
                c = _chain(n).lower()
                if any(k in c for k in ("rollback", "undo", "restore", "unlink", "remove",
                                        "write", "cleanup", "revert")):
                    return True
        if h.body and any(isinstance(s, (ast.Return, ast.Raise, ast.Pass)) for s in h.body):
            pass
    if t.finalbody:
        for n in ast.walk(ast.Module(body=t.finalbody, type_ignores=[])):
            if isinstance(n, ast.Call):
                c = _chain(n).lower()
                if any(k in c for k in ("close", "release", "unlock", "cleanup", "unlink")):
                    return True
    return False


def _fn_write_sites(fn):
    """返回 [(kind, call_name, lineno, node)]，按源码顺序。"""
    sites = []
    for n in ast.walk(fn):
        if not isinstance(n, ast.Call):
            continue
        d = _is_delete_call(n)
        if d:
            sites.append(("delete", d, n.lineno, n))
            continue
        w = _is_write_call(n)
        if w:
            sites.append(("write", w, n.lineno, n))
    sites.sort(key=lambda x: x[2])
    return sites


# ────────────────────────────────────────────────────────────────────
# TX-01 多文件写入序列无事务
# ────────────────────────────────────────────────────────────────────
def check_multi_write_no_tx(tree, rel):
    out = []
    for fn in ast.walk(tree):
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        sites = _fn_write_sites(fn)
        if len(sites) < 2:
            continue
        # 是否所有站点都在同一个 try 内、且该 try 有补偿
        tries = {id(_enclosing_try(fn, s[3])) for s in sites}
        covered = False
        for t in [x for x in ast.walk(fn) if isinstance(x, ast.Try)]:
            if all(any(y is s[3] for y in ast.walk(t)) for s in sites):
                if _try_has_rollback(t):
                    covered = True
        if covered:
            continue
        # 全在循环内逐个写入（批量操作），降级为提示
        in_loop = False
        for lp in ast.walk(fn):
            if isinstance(lp, (ast.For, ast.While)) and \
                    all(any(x is s[3] for x in ast.walk(lp)) for s in sites):
                in_loop = True
        desc = "、".join(f"{k}:{n}@{l}" for k, n, l, _ in sites[:4])
        out.append({
            "rule": "TX-01-multi-write-no-tx",
            "severity": "low" if in_loop else "medium",
            "file": rel, "line": sites[0][2], "function": fn.name,
            "message": (f"{fn.name}() 内有 {len(sites)} 个落盘/删除站点（{desc}），"
                        + ("位于循环中（批量写入，单条失败不影响已写部分）" if in_loop
                           else "未包裹在同一 try 或该 try 无补偿动作")
                        + "：中途失败会留下部分写入状态，无回滚/补偿"),
            "sites": [{"kind": k, "call": n, "line": l} for k, n, l, _ in sites],
        })
    return out


# ────────────────────────────────────────────────────────────────────
# TX-03 先落盘后校验（顺序颠倒）
# ────────────────────────────────────────────────────────────────────
VALIDATE_HINT = ("valid", "check", "assert", "verify", "ensure", "guard", "sanity")


def check_write_before_validate(tree, rel):
    out = []
    for fn in ast.walk(tree):
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        sites = [s for s in _fn_write_sites(fn) if s[0] == "write"]
        if not sites:
            continue
        first_write_line = sites[0][2]
        # 找写之后的校验调用
        for n in ast.walk(fn):
            if not isinstance(n, ast.Call):
                continue
            c = _chain(n).lower()
            if not any(k in c for k in VALIDATE_HINT):
                continue
            if n.lineno <= first_write_line:
                continue
            # 该校验是否可能 raise（在被 if 里且 if 体含 raise/return False）
            may_raise = False
            for anc in ast.walk(fn):
                if isinstance(anc, ast.If) and any(x is n for x in ast.walk(anc)):
                    for s in ast.walk(anc):
                        if isinstance(s, (ast.Raise,)) or \
                           (isinstance(s, ast.Return) and ast.unparse(s.value or ast.Constant(None)).lower().startswith("false")):
                            may_raise = True
            if not may_raise:
                continue
            out.append({
                "rule": "TX-03-write-before-validate", "severity": "medium",
                "file": rel, "line": n.lineno, "function": fn.name,
                "message": (f"{fn.name}() 在第 {first_write_line} 行落盘之后才在第 {n.lineno} 行"
                            f"校验 {c}()（且该校验可能 reject）→ 校验失败时盘已改，"
                            f"应先校验后落盘"),
            })
    return out


# ────────────────────────────────────────────────────────────────────
# TX-04 删除与写入混合无回滚
# ────────────────────────────────────────────────────────────────────
def check_delete_then_write(tree, rel):
    out = []
    for fn in ast.walk(tree):
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        sites = _fn_write_sites(fn)
        dels = [s for s in sites if s[0] == "delete"]
        wrs = [s for s in sites if s[0] == "write"]
        if not dels or not wrs:
            continue
        # 存在「先删后写」的相邻对
        for d in dels:
            later = [w for w in wrs if w[2] > d[2]]
            if not later:
                continue
            t = _enclosing_try(fn, d[3])
            if t is not None and _try_has_rollback(t):
                continue
            out.append({
                "rule": "TX-04-delete-then-write", "severity": "high",
                "file": rel, "line": d[2], "function": fn.name,
                "message": (f"{fn.name}() 在第 {d[2]} 行 {d[1]}() 删除，之后才在 "
                            f"第 {later[0][2]} 行写入 {later[0][1]}()，且无回滚保护；"
                            f"写入失败时旧数据已删除 → 状态丢失且不可逆"),
                "sites": [{"kind": d[0], "call": d[1], "line": d[2]},
                          {"kind": later[0][0], "call": later[0][1], "line": later[0][2]}],
            })
            break
    return out


# ────────────────────────────────────────────────────────────────────
# TX-05 内存状态与磁盘更新顺序
#   条件：函数内既有 self.X[...] = / self.X = 的内存态写入，又有落盘调用，
#         且落盘在前、内存更新在后（崩溃 → 盘上已有、内存没有，或反之）
# ────────────────────────────────────────────────────────────────────
def _self_state_writes(fn):
    res = []
    for n in ast.walk(fn):
        if isinstance(n, ast.Assign):
            for t in n.targets:
                if isinstance(t, ast.Attribute) and isinstance(t.value, ast.Name) \
                        and t.value.id == "self":
                    res.append((n.lineno, t.attr, n))
                elif isinstance(t, ast.Subscript) and isinstance(t.value, ast.Attribute) \
                        and isinstance(t.value.value, ast.Name) and t.value.value.id == "self":
                    res.append((n.lineno, t.value.attr, n))
    return res


def check_memory_disk_order(tree, rel):
    out = []
    for fn in ast.walk(tree):
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        writes = [s for s in _fn_write_sites(fn) if s[0] == "write"]
        mem = _self_state_writes(fn)
        if not writes or not mem:
            continue
        first_write = writes[0][2]
        later_mem = [m for m in mem if m[0] > first_write]
        if not later_mem:
            continue
        out.append({
            "rule": "TX-05-memory-disk-order", "severity": "low",
            "file": rel, "line": first_write, "function": fn.name,
            "message": (f"{fn.name}() 在第 {first_write} 行落盘，之后才更新内存态 "
                        f"self.{later_mem[0][1]}（第 {later_mem[0][0]} 行）；"
                        f"若落盘后崩溃，盘上与内存中状态不一致（需人工确认是否有意为之）"),
        })
    return out


# ────────────────────────────────────────────────────────────────────
# TX-06 跨模块镜像不同步：同一函数内写 A 的落盘，但没写 B（B 是 A 的已知镜像）
#   用启发式：函数内出现两个不同 store/repo 对象的落盘调用，但只有一个
# ────────────────────────────────────────────────────────────────────
def check_mirror_desync(tree, rel):
    out = []
    for fn in ast.walk(tree):
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        writes = [s for s in _fn_write_sites(fn) if s[0] == "write"]
        if len(writes) < 2:
            continue
        # 落盘目标分属不同对象（按调用链前缀分组）
        objs = set()
        for _, c, _, _ in writes:
            parts = c.split(".")
            objs.add(parts[0] if len(parts) > 1 else "<bare>")
        if len(objs) >= 2:
            out.append({
                "rule": "TX-06-mirror-desync", "severity": "low",
                "file": rel, "line": writes[0][2], "function": fn.name,
                "message": (f"{fn.name}() 对多个不同对象落盘（{', '.join(sorted(objs))}）；"
                            f"若其中一个是另一个的镜像/索引，需确认是否同步更新"),
            })
    return out


CHECKS = [
    check_multi_write_no_tx,
    check_write_before_validate,
    check_delete_then_write,
    check_memory_disk_order,
    check_mirror_desync,
]


def main() -> int:
    root = Path(sys.argv[1] if len(sys.argv) > 1 else "/data/workspace/audit/src/src/autoforge")
    outdir = Path(sys.argv[2] if len(sys.argv) > 2 else "/data/workspace/audit/rounds/round-009/consistency")
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
    (outdir / "consistency-findings.json").write_text(
        json.dumps({"findings": findings}, ensure_ascii=False, indent=2))
    print(json.dumps({"files": files, "total": len(findings),
                      "by_severity": dict(Counter(f["severity"] for f in findings)),
                      "by_rule": dict(Counter(f["rule"] for f in findings))},
                     ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
