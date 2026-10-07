#!/usr/bin/env python3
"""第十七轮核心迭代：基于已确证缺陷的**模式泛化搜索**（纯 stdlib AST）。

背景：前十六轮确证 16 个缺陷，每个都有精确源码指纹。但这些指纹是**具体文本**，
只覆盖被发现的那一处。本工具把每个缺陷抽象成**可泛化的结构模式**，回头在
全仓库搜索同形但未被发现的点——即"已知的已知"之外的"已知的未知"。

泛化的 8 个模式（对应 BUG-01/03/04/08/10/11/13/15）：

  PAT-01 (BUG-08) 写入函数未失效同类读取缓存
  PAT-02 (BUG-04) 解析/转换语句位于 try 之外（try 只包一半）
  PAT-03 (BUG-15) 解析结果未经 isinstance 校验即使用
  PAT-04 (BUG-10) 模块/类级裸 int()/float() 解析（非函数内）
  PAT-05 (BUG-11) 不可逆删除先于写入/校验
  PAT-06 (BUG-13) except 分支内的调用未被内层 try 包裹（降级路径无兜底）
  PAT-07 (BUG-01) 实例级容器 append 无裁剪（跨调用累积）
  PAT-08 (BUG-03) 状态落盘用裸写入（非原子）且读取无保护

用法: pattern_propagation.py <src_root> <outdir>
"""
from __future__ import annotations

import ast
import json
import re
import sys
from collections import Counter
from pathlib import Path

CACHE_HINT = re.compile(r"(?i)(cache|_cache|memo|_loaded|_snapshot)")
PARSE_CALL = re.compile(r"(?i)^(json\.loads|json\.load|int|float|yaml\.safe_load|_parse)")
IRREVERSIBLE = re.compile(r"(?i)(unlink|rmtree|remove|os\.remove|\.pop\(|del\s|truncate|drop)")


#: 被调方自带 try/except 的函数名集合（模块级建索引，见 build_self_protected）
SELF_PROTECTED: set[str] = set()


def build_self_protected(idx) -> None:
    """被调方是否自带兜底：函数体内 try 的 handler 只有 pass/return/logger.*。

    BUG-13 的真身是 `ConflictService._audit_degraded()`（无兜底、会落盘）；
    而 `af_conflict._emit` / `af_version._audit` 内部就有 `try: ... except: pass`
    （注释明写"审计是旁路 fail-open"）——这两类**形状完全相同**，只有看被调方
    内部才能区分。首版只看调用点 → 29 条里大部分是假阳性。
    """
    for name, defs in idx.funcs.items():
        for _rel, fn in defs:
            for t_ in ast.walk(fn):
                if not isinstance(t_, ast.Try) or not t_.finalbody:
                    pass
                if not isinstance(t_, ast.Try):
                    continue
                if not t_.handlers:
                    continue
                ok = True
                for h in t_.handlers:
                    for st in h.body:
                        if isinstance(st, ast.Pass):
                            continue
                        if isinstance(st, ast.Return):
                            continue
                        if isinstance(st, ast.Expr) and isinstance(st.value, ast.Call):
                            c = _chain(st.value).split(".")[-1]
                            if c in ("warning", "error", "info", "debug", "exception", "critical"):
                                continue
                        ok = False
                if ok:
                    SELF_PROTECTED.add(name)


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


def _fn_src(fn) -> str:
    try:
        return ast.unparse(fn)
    except Exception:
        return ""


def _base(c: str) -> str:
    return c.split(".")[-1]


def _stms(fn):
    """本函数体的语句（不下降进嵌套函数）。"""
    out, stack = [], list(fn.body)
    while stack:
        n = stack.pop()
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        out.append(n)
        for f in ast.iter_fields(n):
            v = f[1]
            if isinstance(v, list):
                stack.extend(x for x in v if isinstance(x, ast.AST))
    return out


def _enclosing_try(fn, node):
    for t in ast.walk(fn):
        if isinstance(t, ast.Try):
            for x in ast.walk(ast.Module(body=t.body, type_ignores=[])):
                if x is node:
                    return t
    return None


# ────────────────────────────────────────────────────────────────────
# PAT-01 (BUG-08) 写入函数未失效缓存
# ────────────────────────────────────────────────────────────────────
def check_cache_invalidation(tree, rel):
    out = []
    for cls in ast.walk(tree):
        if not isinstance(cls, ast.ClassDef):
            continue
        methods = {m.name: m for m in cls.body
                   if isinstance(m, (ast.FunctionDef, ast.AsyncFunctionDef))}
        # 缓存属性
        caches = set()
        for m in methods.values():
            for n in ast.walk(m):
                if isinstance(n, ast.Attribute) and isinstance(n.value, ast.Name) \
                        and n.value.id == "self" and CACHE_HINT.search(n.attr):
                    caches.add(n.attr)
        if not caches:
            continue
        for wname, wm in methods.items():
            # 写入函数：名字含 save/write/persist/set/add/put/update/delete
            if not re.match(r"(?i)(save|write|persist|set_|add_|put|update|delete|remove|clear)", wname):
                continue
            wsrc = _fn_src(wm)
            writes_disk = bool(re.search(r"(?i)(write_text|write_bytes|\.write\(|atomic_write|replace\()", wsrc))
            invalidates = any(c in wsrc for c in caches)
            if writes_disk and not invalidates:
                out.append({
                    "rule": "PAT-01-write-without-cache-invalidation", "severity": "medium",
                    "file": rel, "line": wm.lineno, "class": cls.name, "function": wname,
                    "message": (f"{cls.name}.{wname}() 写盘但未见失效缓存 "
                                f"{sorted(caches)}（BUG-08 同形：af_catalog._save 的 mtime/size "
                                f"键 + 不失效 → 实测 16/30 陈旧读）"),
                    "caches": sorted(caches),
                })
    return out


# ────────────────────────────────────────────────────────────────────
# PAT-02 (BUG-04) 解析语句在 try 之外
# ────────────────────────────────────────────────────────────────────
def check_parse_outside_try(tree, rel):
    out = []
    for fn in ast.walk(tree):
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if not any(isinstance(t, ast.Try) for t in ast.walk(fn)):
            continue
        for n in _stms(fn):
            if not isinstance(n, ast.Call):
                continue
            c = _chain(n)
            if not PARSE_CALL.match(_base(c)) and not PARSE_CALL.match(c):
                continue
            if _enclosing_try(fn, n):
                continue
            out.append({
                "rule": "PAT-02-parse-outside-try", "severity": "medium",
                "file": rel, "line": n.lineno, "function": fn.name,
                "message": (f"{fn.name}() 内有 try，但 `{c}()` 在 try 之外"
                            f"（BUG-04 同形：json.loads 在 try 外 → 单条坏行永久卡死重发）"),
            })
    return out


# ────────────────────────────────────────────────────────────────────
# PAT-03 (BUG-15) 解析结果未 isinstance 校验即下标/get 使用
# ────────────────────────────────────────────────────────────────────
def check_parse_result_unchecked(tree, rel):
    out = []
    for fn in ast.walk(tree):
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        src = _fn_src(fn)
        # 解析赋给变量
        for n in _stms(fn):
            if not isinstance(n, ast.Assign) or not isinstance(n.value, ast.Call):
                continue
            c = _chain(n.value)
            if not (c.startswith("json.") or _base(c) == "loads" or _base(c) == "load"):
                continue
            tgt = n.targets[0]
            if not isinstance(tgt, ast.Name):
                continue
            v = tgt.id
            guarded = bool(re.search(rf"isinstance\(\s*{re.escape(v)}", src))
            if guarded:
                continue
            # 后续是否用 .get / 下标
            if not (re.search(rf"{re.escape(v)}\.get\(", src) or re.search(rf"{re.escape(v)}\s*\[", src)):
                continue
            # 是否在 try 内
            if _enclosing_try(fn, n):
                continue
            out.append({
                "rule": "PAT-03-parsed-unchecked", "severity": "medium",
                "file": rel, "line": n.lineno, "function": fn.name,
                "message": (f"{fn.name}() 把解析结果赋给 {v} 后直接用 .get/下标，"
                            f"既无 isinstance({v}, dict) 也不在 try 内"
                            f"（BUG-15 同形：旧档顶层非 dict → AttributeError 穿出）"),
                "var": v,
            })
    return out


# ────────────────────────────────────────────────────────────────────
# PAT-04 (BUG-10) 模块级裸数值解析
# ────────────────────────────────────────────────────────────────────
def check_module_level_parse(tree, rel):
    out = []
    for n in tree.body:
        if not isinstance(n, ast.Assign):
            continue
        for x in ast.walk(n.value):
            if not isinstance(x, ast.Call):
                continue
            c = _chain(x)
            if _base(c) not in ("int", "float"):
                continue
            # 是否在 try 内（模块级 try 少见）
            in_try = False
            for t in ast.walk(tree):
                if isinstance(t, ast.Try) and isinstance(t.body, list):
                    for y in ast.walk(ast.Module(body=t.body, type_ignores=[])):
                        if y is x:
                            in_try = True
            if in_try:
                continue
            # 实参是否含 os.getenv / environ
            args_src = ast.unparse(x)
            if not re.search(r"(?i)(getenv|environ)", args_src):
                continue
            out.append({
                "rule": "PAT-04-module-level-env-parse", "severity": "high",
                "file": rel, "line": x.lineno, "function": "<module>",
                "message": (f"模块级裸解析 `{args_src[:60]}`；"
                            f"环境变量脏值会让 **import 直接失败**"
                            f"（BUG-10 同形，已知 5 处）"),
            })
    return out


# ────────────────────────────────────────────────────────────────────
# PAT-05 (BUG-11) 不可逆删除先于写入
# ────────────────────────────────────────────────────────────────────
def check_delete_before_write(tree, rel):
    out = []
    for fn in ast.walk(tree):
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        dels, writes = [], []
        for n in _stms(fn):
            s = ast.unparse(n) if not isinstance(n, ast.Call) else _chain(n)
            if isinstance(n, ast.Call) and IRREVERSIBLE.search(_chain(n)):
                dels.append((n.lineno, _chain(n)))
            elif isinstance(n, ast.Delete):
                dels.append((n.lineno, "del"))
            if isinstance(n, ast.Call) and re.search(
                    r"(?i)(write_text|write_bytes|atomic_write|\.write\(|replace\(|mkdir)", _chain(n)):
                writes.append((n.lineno, _chain(n)))
        if not dels or not writes:
            continue
        first_del = min(d[0] for d in dels)
        # 存在删除之后才发生的写入 → 删除先于写入
        later_writes = [w for w in writes if w[0] > first_del]
        if not later_writes:
            continue
        # 删除前是否有备份（rename/backup/copy）
        src = _fn_src(fn)
        if re.search(r"(?i)(backup|\.bak|rename|copy|shutil\.copy)", src):
            continue
        out.append({
            "rule": "PAT-05-delete-before-write", "severity": "medium",
            "file": rel, "line": first_del, "function": fn.name,
            "message": (f"{fn.name}() 先执行不可逆删除 {dels[0][1]}()（第 {first_del} 行），"
                        f"之后才写入 {later_writes[0][1]}()，且未见备份动作"
                        f"（BUG-11 同形：删旧成功后写新失败 → 归档不可逆丢失）"),
        })
    return out


# ────────────────────────────────────────────────────────────────────
# PAT-06 (BUG-13) except 分支内调用无内层 try
# ────────────────────────────────────────────────────────────────────
AUDIT_HINT = re.compile(r"(?i)(audit|record|log|emit|notify|report|telemetry|metric)")
# BUG-13 的真身是 `self._audit_degraded()` —— 会**落盘**（JSONL 写入失败即抛）。
# 而 logger.*/logging.* 是标准库日志，设计上永不抛出，不属同类。
# 首版未排除 → 73 条里绝大多数是 logger.warning()，全是假阳性。
SAFE_IN_EXCEPT = re.compile(
    r"(?i)^(logging\.[a-z_.]*|logger\.[a-z_]*|warnings\.warn|_logger\.[a-z_]*|print)$")


def check_bare_call_in_except(tree, rel):
    out = []
    for fn in ast.walk(tree):
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for t in ast.walk(fn):
            if not isinstance(t, ast.Try):
                continue
            for h in t.handlers:
                hmod = ast.Module(body=h.body, type_ignores=[])
                inner_try = any(isinstance(x, ast.Try) for x in ast.walk(hmod))
                if inner_try:
                    continue
                for x in ast.walk(hmod):
                    if not isinstance(x, ast.Call):
                        continue
                    c = _chain(x)
                    if not AUDIT_HINT.search(c):
                        continue
                    base = c.split(".")[-1]
                    if SAFE_IN_EXCEPT.match(c) or base in ("warning", "error", "info",
                                                           "debug", "exception", "critical"):
                        continue
                    # 被调方自带兜底 → 调用点无需再包
                    if base in SELF_PROTECTED or c.split(".")[0] in ("logger", "logging"):
                        continue
                    out.append({
                        "rule": "PAT-06-audit-in-except-unprotected", "severity": "medium",
                        "file": rel, "line": x.lineno, "function": fn.name,
                        "message": (f"{fn.name}() 在 except 分支调用 {c}() 但无内层 try；"
                                    f"记账/通知自身失败会替换原异常并阻断降级"
                                    f"（BUG-13 同形，已知 13 处）"),
                    })
                    break   # 每个 handler 只报一次
    return out


# ────────────────────────────────────────────────────────────────────
# PAT-07 (BUG-01) 实例级容器 append 无裁剪
# ────────────────────────────────────────────────────────────────────
def check_instance_level_unbounded(tree, rel):
    out = []
    for cls in ast.walk(tree):
        if not isinstance(cls, ast.ClassDef):
            continue
        methods = {m.name: m for m in cls.body
                   if isinstance(m, (ast.FunctionDef, ast.AsyncFunctionDef))}
        src_cls = ast.unparse(cls)
        # 类级容器声明
        containers = {}
        for n in ast.walk(cls):
            if isinstance(n, ast.AnnAssign) and isinstance(n.target, ast.Name):
                ann = ast.unparse(n.annotation) if n.annotation else ""
                if any(k in ann for k in ("list[", "dict[", "deque")):
                    containers[n.target.id] = n.lineno
        if not containers:
            continue
        for mname, m in methods.items():
            for n in ast.walk(m):
                if not isinstance(n, ast.Call):
                    continue
                if not (isinstance(n.func, ast.Attribute)
                        and isinstance(n.func.value, ast.Attribute)
                        and isinstance(n.func.value.value, ast.Name)
                        and n.func.value.value.id == "self"):
                    continue
                if n.func.attr not in ("append", "add", "update", "extend"):
                    continue
                cname = n.func.value.attr
                if cname not in containers:
                    continue
                # 是否有裁剪（本方法内 或 类内任一方法）
                trimmed = bool(re.search(
                    rf"(?i)(del\s+self\.{re.escape(cname)}|self\.{re.escape(cname)}\s*=\s*self\.{re.escape(cname)}\s*\[-"
                    rf"|max_?\w*)\s*", src_cls)) and bool(re.search(r"maxlen|max_", src_cls))
                if trimmed:
                    continue
                out.append({
                    "rule": "PAT-07-instance-unbounded", "severity": "medium",
                    "file": rel, "line": n.lineno, "class": cls.name, "function": mname,
                    "message": (f"{cls.name}.{mname}() 对实例级容器 self.{cname} 做 "
                                f"{n.func.attr}()，类内未见裁剪/上限"
                                f"（BUG-01/BUG-14 同形：跨调用单调增长）"),
                    "container": cname,
                })
    return out


# ────────────────────────────────────────────────────────────────────
# PAT-08 (BUG-03) 状态落盘裸写入 + 读取无保护
# ────────────────────────────────────────────────────────────────────
def check_bare_state_write(tree, rel):
    out = []
    for fn in ast.walk(tree):
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for n in _stms(fn):
            # open(..., "w") 裸写
            if isinstance(n, ast.Call) and _chain(n) in ("open",):
                modes = [a for a in n.args if isinstance(a, ast.Constant)
                         and isinstance(a.value, str)]
                kwmode = [kw.value for kw in n.keywords if kw.arg == "mode"]
                allm = [m.value for m in modes] + [
                    k.value for k in kwmode if isinstance(k, ast.Constant)]
                if not any("w" in m or "a" in m for m in allm):
                    continue
                if _enclosing_try(fn, n):
                    continue
                out.append({
                    "rule": "PAT-08-bare-state-write", "severity": "medium",
                    "file": rel, "line": n.lineno, "function": fn.name,
                    "message": (f"{fn.name}() 用裸 open(...,'w') 写状态且不在 try 内；"
                                f"写一半被杀会留下半截文件"
                                f"（BUG-03 同形，已知 af_runtime_ext.persist）"),
                })
    return out


CHECKS = [
    check_cache_invalidation,
    check_parse_outside_try,
    check_parse_result_unchecked,
    check_module_level_parse,
    check_delete_before_write,
    check_bare_call_in_except,
    check_instance_level_unbounded,
    check_bare_state_write,
]

# 已知缺陷所在位置（用于从结果里区分"已知"与"新发现"）
KNOWN = {
    "af_catalog.py": {"_save"},
    "af_metrics.py": {"flush_buffer"},
    "af_preference.py": {"_migrate_legacy"},
    "af_conflict_runtime.py": {"_audit_degraded"},
    "af_runtime_ext.py": {"persist"},
    "af_executor.py": {"run"},
    "af_conf.py": {"emit"},
    "af_draft.py": {"_resolve_entity"},
    "af_service.py": {"import_bundle"},
    "af_instance.py": {"_transition"},
}


def main() -> int:
    root = Path(sys.argv[1] if len(sys.argv) > 1 else "/data/workspace/audit/src/src/autoforge")
    outdir = Path(sys.argv[2] if len(sys.argv) > 2 else "/data/workspace/audit/rounds/round-017/patterns")
    outdir.mkdir(parents=True, exist_ok=True)

    # 第一遍：全仓库建索引（被调方是否自带兜底）
    import ast as _ast
    class _Idx:
        funcs: dict = {}
    for p0 in sorted(root.rglob("*.py")):
        if any(x.startswith("test") for x in p0.parts):
            continue
        try:
            tr = _ast.parse(p0.read_text(errors="ignore"))
        except SyntaxError:
            continue
        for n in _ast.walk(tr):
            if isinstance(n, (_ast.FunctionDef, _ast.AsyncFunctionDef)):
                _Idx.funcs.setdefault(n.name, []).append((str(p0), n))
    build_self_protected(_Idx)

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

    # 标注是否已知
    for f in findings:
        base = f["file"].split("/")[-1]
        fknown = KNOWN.get(base, set())
        # BUG-10 等为模块级命中（function="<module>"），"按 function 比对"会漏标；
        # 改为：function 命中 或 该文件的已知集合里含 "<module>" 且本条也是模块级
        f["known"] = (f.get("function") in fknown
                      or (f.get("function") == "<module>" and "<module>" in fknown))

    sev = {"high": 0, "medium": 1, "low": 2}
    findings.sort(key=lambda x: (x.get("known", False), sev.get(x["severity"], 9),
                                 x["file"], x["line"]))
    (outdir / "pattern-findings.json").write_text(
        json.dumps({"findings": findings}, ensure_ascii=False, indent=2))
    new = [f for f in findings if not f.get("known")]
    print(json.dumps({"files": files, "total": len(findings), "new": len(new),
                      "by_rule": dict(Counter(f["rule"] for f in findings)),
                      "by_rule_new": dict(Counter(f["rule"] for f in new))},
                     ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
