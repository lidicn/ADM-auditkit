#!/usr/bin/env python3
"""第十五轮专题：内部 API 契约一致性（纯 stdlib AST，跨模块）。

前十四轮覆盖了稳定性、持久化、并发、复杂度、控制流、缓存、时间数值、
输入边界、事务边界、序列化、错误处理/降级、可观测性、配置兼容性、测试缺口。
本轮看**模块与模块之间调用时，契约有没有对上**：

  API-01 调用点传入被调函数不存在的关键字参数（kwargs 拼错 / 改名未同步）
  API-02 调用点位置参数个数超出被调函数形参容量
  API-03 子类方法与基类/Protocol 同名但签名不一致（LSP 违背）
  API-04 同一方法在不同实现里返回形状不一致（dict vs None vs list）
  API-05 Protocol 声明的方法在实现类中缺失
  API-06 同名函数跨模块签名不同（易误用）

设计原则：Python 动态性使这类判定天然有假阳性（*args/**kwargs、装饰器、
运行时注册）。因此：**命中一律给调用点与被调点双方定位**，便于人工秒判；
对含 **kwargs / *args 的函数一律跳过。

用法: api_contract_defects.py <src_root> <outdir>
"""
from __future__ import annotations

import ast
import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path


def _is_dynamic(fn) -> bool:
    """含 *args / **kwargs 的函数跳过（静态无法判定）。"""
    a = fn.args
    return bool(a.vararg or a.kwarg or a.kwonlyargs)


def _params(fn) -> list[str]:
    a = fn.args
    names = [x.arg for x in a.posonlyargs] + [x.arg for x in a.args]
    return names


def _required_count(fn) -> int:
    return len(_params(fn)) - len(fn.args.defaults)


def _methods(cls: ast.ClassDef) -> dict[str, object]:
    out = {}
    for m in cls.body:
        if isinstance(m, (ast.FunctionDef, ast.AsyncFunctionDef)):
            out.setdefault(m.name, m)
    return out


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


#: 标准库/第三方类型的常见方法名。这些调用的接收者类型静态不可知，
#: 若按"仓库内无同名定义"判定会大量误报（如 Path(...).read_text(encoding=...)）。
#: PITFALLS P15。
STDLIB_METHODS = {
    "read_text", "write_text", "read_bytes", "write_bytes", "unlink", "exists",
    "is_file", "is_dir", "mkdir", "glob", "iterdir", "open", "resolve", "rglob",
    "with_suffix", "with_name", "relative_to", "get", "items", "values", "keys",
    "append", "update", "pop", "setdefault", "join", "startswith", "endswith",
    "strip", "split", "replace", "format", "encode", "decode", "loads", "dumps",
    "dump", "load", "close", "flush", "read", "write", "sleep", "asdict",
    "isoformat", "strftime", "strptime", "fromisoformat", "now", "today",
    "total_seconds", "compare_digest", "token_hex", "urlopen",
}


def _bases(cls: ast.ClassDef) -> list[str]:
    out = []
    for b in cls.bases:
        if isinstance(b, ast.Name):
            out.append(b.id)
        elif isinstance(b, ast.Attribute):
            out.append(b.attr)
        elif isinstance(b, ast.Subscript):
            v = b.value
            if isinstance(v, ast.Name):
                out.append(v.id)
            elif isinstance(v, ast.Attribute):
                out.append(v.attr)
    return out


# ────────────────────────────────────────────────────────────────────
# 索引：收集全仓库函数/方法签名
# ────────────────────────────────────────────────────────────────────
class Index:
    def __init__(self):
        self.funcs: dict[str, list[tuple[str, object]]] = {}   # name → [(file, fn)]
        self.classes: dict[str, list[tuple[str, ast.ClassDef]]] = {}
        self.methods: dict[tuple[str, str], list[tuple[str, object]]] = {}
        self.protocols: dict[str, ast.ClassDef] = {}
        self.trees: dict[str, ast.Module] = {}

    def add(self, rel: str, tree: ast.Module):
        self.trees[rel] = tree
        for n in ast.walk(tree):
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self.funcs.setdefault(n.name, []).append((rel, n))
            if isinstance(n, ast.ClassDef):
                self.classes.setdefault(n.name, []).append((rel, n))
                if any(b in ("Protocol", "ABC") for b in _bases(n)):
                    self.protocols.setdefault(n.name, n)
                for mn, m in _methods(n).items():
                    self.methods.setdefault((n.name, mn), []).append((rel, m))


# ────────────────────────────────────────────────────────────────────
# API-01 / API-02 调用点与签名不符
# ────────────────────────────────────────────────────────────────────
def check_call_signature(idx: Index):
    out = []
    for rel, tree in idx.trees.items():
        for n in ast.walk(tree):
            if not isinstance(n, ast.Call):
                continue
            c = _chain(n)
            if not c or "." in c:
                continue      # 只查模块级函数调用（方法调用需类型推断，跳过）
            cands = idx.funcs.get(c)
            if not cands:
                continue
            if c.split(".")[-1] in STDLIB_METHODS:
                continue
            # 收集所有同名定义的形参集合（任一定义接受即可）
            all_params, max_req, dyn = set(), 0, False
            for f, fn in cands:
                if _is_dynamic(fn):
                    dyn = True
                    break
                all_params |= set(_params(fn))
                max_req = max(max_req, _required_count(fn))
            if dyn:
                continue
            # API-01: 关键字参数不在任何定义的形参里
            for kw in n.keywords:
                if kw.arg is None:
                    continue
                if kw.arg not in all_params:
                    out.append({
                        "rule": "API-01-unknown-kwarg", "severity": "high",
                        "file": rel, "line": n.lineno, "function": c,
                        "message": (f"调用 {c}() 传入关键字 `{kw.arg}=`，"
                                    f"但全部 {len(cands)} 个同名定义的形参 "
                                    f"{sorted(all_params)} 中都没有它 → TypeError"),
                        "callee_files": sorted({f for f, _ in cands}),
                    })
            # API-02: 位置参数过多
            npos = len([a for a in n.args if not isinstance(a, ast.Starred)])
            cap = len(all_params)
            if npos > cap > 0:
                out.append({
                    "rule": "API-02-too-many-args", "severity": "high",
                    "file": rel, "line": n.lineno, "function": c,
                    "message": (f"调用 {c}() 传入 {npos} 个位置参数，"
                                f"但形参最多 {cap} 个 → TypeError"),
                    "callee_files": sorted({f for f, _ in cands}),
                })
    return out


# ────────────────────────────────────────────────────────────────────
# API-07 self.<method>() 调用与类内/基类方法签名不符
#   （首版只查裸函数调用，漏掉了占绝大多数的 self.m() 形式）
# ────────────────────────────────────────────────────────────────────
def _class_method_sources(idx: Index, cls: ast.ClassDef, name: str, seen=None):
    """类自身 + 基类 + 同名类（跨文件重复定义）里该方法的所有定义。"""
    seen = seen or set()
    res = []
    m = _methods(cls).get(name)
    if m is not None:
        res.append(m)
    for b in _bases(cls):
        for _, bcls in idx.classes.get(b, []):
            if id(bcls) in seen:
                continue
            seen.add(id(bcls))
            res += _class_method_sources(idx, bcls, name, seen)
    # 同名类（可能在不同文件重复定义）
    for _, ocls in idx.classes.get(cls.name, []):
        if ocls is cls:
            continue
        m2 = _methods(ocls).get(name)
        if m2 is not None and m2 not in res:
            res.append(m2)
    return res


def check_self_call_signature(idx: Index):
    out = []
    for rel, tree in idx.trees.items():
        for cls in ast.walk(tree):
            if not isinstance(cls, ast.ClassDef):
                continue
            for fn in cls.body:
                if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    continue
                for n in ast.walk(fn):
                    if not isinstance(n, ast.Call):
                        continue
                    if not (isinstance(n.func, ast.Attribute)
                            and isinstance(n.func.value, ast.Name)
                            and n.func.value.id == "self"):
                        continue
                    mname = n.func.attr
                    cands = _class_method_sources(idx, cls, mname)
                    if not cands:
                        continue
                    if any(_is_dynamic(m) for m in cands):
                        continue
                    allp, cap = set(), 0
                    for m in cands:
                        ps = [x for x in _params(m) if x != "self"]
                        allp |= set(ps)
                        cap = max(cap, len(ps))
                    for kw in n.keywords:
                        if kw.arg is None:
                            continue
                        if kw.arg not in allp:
                            out.append({
                                "rule": "API-07-self-unknown-kwarg", "severity": "high",
                                "file": rel, "line": n.lineno, "class": cls.name,
                                "function": mname,
                                "message": (f"{cls.name}.{fn.name}() 调用 "
                                            f"self.{mname}({kw.arg}=...)，但 "
                                            f"{mname} 的形参 {sorted(allp)} 中没有 "
                                            f"`{kw.arg}` → TypeError"),
                            })
                    npos = len([a for a in n.args if not isinstance(a, ast.Starred)])
                    if npos > cap > 0:
                        out.append({
                            "rule": "API-07-self-too-many-args", "severity": "high",
                            "file": rel, "line": n.lineno, "class": cls.name,
                            "function": mname,
                            "message": (f"{cls.name}.{fn.name}() 调用 self.{mname}() "
                                        f"传入 {npos} 个位置参数，形参最多 {cap} 个 → TypeError"),
                        })
    return out


# ────────────────────────────────────────────────────────────────────
# API-03 子类方法与基类签名不一致
# ────────────────────────────────────────────────────────────────────
def check_lsp_violation(idx: Index):
    out = []
    for cname, plist in idx.classes.items():
        for rel, cls in plist:
            bases = _bases(cls)
            sub_methods = _methods(cls)
            for b in bases:
                for brel, bcls in idx.classes.get(b, []):
                    bmeth = _methods(bcls)
                    for mn, m in sub_methods.items():
                        bm = bmeth.get(mn)
                        if bm is None:
                            continue
                        if _is_dynamic(m) or _is_dynamic(bm):
                            continue
                        sp, bp = _params(m), _params(bm)
                        if sp == bp:
                            continue
                        # 允许子类在末尾追加有默认值的新参数（安全扩展）
                        if sp[:len(bp)] == bp and len(sp) > len(bp):
                            extra = sp[len(bp):]
                            if len(m.args.defaults) >= len(extra):
                                continue
                        out.append({
                            "rule": "API-03-lsp-signature", "severity": "medium",
                            "file": rel, "line": m.lineno, "class": cname, "function": mn,
                            "message": (f"{cname}.{mn}() 形参 {sp} 与基类 {b}.{mn}() "
                                        f"形参 {bp} 不一致；以基类类型调用时会 TypeError"),
                            "base_file": brel,
                        })
    return out


# ────────────────────────────────────────────────────────────────────
# API-05 Protocol 方法缺失
# ────────────────────────────────────────────────────────────────────
def check_protocol_methods(idx: Index):
    out = []
    for pname, pcls in idx.protocols.items():
        need = {m for m in _methods(pcls) if not m.startswith("_")}
        if not need:
            continue
        for cname, clist in idx.classes.items():
            for rel, cls in clist:
                if pname not in _bases(cls):
                    continue
                # 首版把基类**已实现的**具体方法也算作"必须重写"，8 条全误报
                # （DeviceSM.drain_followups/reset 是具体方法，子类继承即可）。
                # 只有 @abstractmethod 才是子类必须实现的。
                abstract = {
                    mn for mn, m in _methods(pcls).items()
                    if any((getattr(d, "id", None) or getattr(d, "attr", None)) == "abstractmethod"
                           for d in getattr(m, "decorator_list", []))
                }
                if not abstract:
                    continue
                have = set(_methods(cls))
                missing = sorted((abstract & need) - have)
                if missing:
                        out.append({
                            "rule": "API-05-protocol-missing", "severity": "medium",
                            "file": rel, "line": cls.lineno, "class": cname,
                            "message": f"{cname} 声明继承 {pname}，但缺少方法 {missing}",
                        })
    return out


# ────────────────────────────────────────────────────────────────────
# API-04 同一方法在不同实现里返回形状不一致
# ────────────────────────────────────────────────────────────────────
def _return_shapes(fn):
    """粗略分类返回值形状：none / dict / list / tuple / bool / num / str / other。"""
    shapes = set()
    for n in ast.walk(fn):
        if not isinstance(n, ast.Return):
            continue
        v = n.value
        if v is None:
            shapes.add("none")
        elif isinstance(v, ast.Constant) and v.value is None:
            shapes.add("none")
        elif isinstance(v, ast.Dict):
            shapes.add("dict")
        elif isinstance(v, (ast.List, ast.ListComp)):
            shapes.add("list")
        elif isinstance(v, ast.Tuple):
            shapes.add("tuple")
        elif isinstance(v, ast.Constant) and isinstance(v.value, bool):
            shapes.add("bool")
        elif isinstance(v, ast.Constant) and isinstance(v.value, (int, float)):
            shapes.add("num")
        elif isinstance(v, ast.Constant) and isinstance(v.value, str):
            shapes.add("str")
        elif isinstance(v, ast.Call):
            c = _chain(v)
            if c in ("dict", "defaultdict"):
                shapes.add("dict")
            elif c in ("list", "sorted"):
                shapes.add("list")
            else:
                shapes.add("call")
        else:
            shapes.add("other")
    return shapes


IMPL_SUFFIX = re.compile(r"(?i)(base|default|impl|simple|fake|mock|memory|file|json)$")


def check_return_shape_divergence(idx: Index):
    out = []
    for cname, clist in idx.classes.items():
        # 同一方法名在多个类中实现（视为不同实现）
        by_method: dict[str, list[tuple[str, str, object]]] = defaultdict(list)
        for rel, cls in clist:
            pass
        for (cn, mn), impls in idx.methods.items():
            if len(impls) < 2:
                continue
            shapes_by = {}
            for rel, m in impls:
                s = _return_shapes(m)
                if len(s) >= 1:
                    shapes_by.setdefault(rel, set()).update(s)
            if len(shapes_by) < 2:
                continue
            # 只在"形状集合互不相同"时报（排除都含 call 的情况）
            sets = [v for v in shapes_by.values()]
            uniq = {frozenset(s) for s in sets}
            if len(uniq) == 1:
                continue
            # 排除都包含 "call" 的（无法判定）
            if all("call" in s for s in sets):
                continue
            out.append({
                "rule": "API-04-return-shape-divergence", "severity": "low",
                "file": sorted(shapes_by)[0], "line": 0, "class": cn, "function": mn,
                "message": f"{cn}.{mn}() 在 {len(impls)} 处实现，返回形状不同："
                           + "；".join(f"{f}:{sorted(s)}" for f, s in sorted(shapes_by.items())),
                "impl_files": sorted(shapes_by),
            })
    return out


# ────────────────────────────────────────────────────────────────────
# API-08 注解为非 Optional 但实际返回 None（调用方按注解取属性/下标会崩）
# ────────────────────────────────────────────────────────────────────
def _ret_annotation(fn):
    if fn.returns is None:
        return None
    try:
        return ast.unparse(fn.returns)
    except Exception:
        return None


def _is_optional(ann: str) -> bool:
    a = ann.replace(" ", "")
    return ("None" in a) or a.startswith("Optional[") or "|None" in a


def _own_returns(fn):
    """只取本函数体的 return，**不下降进嵌套函数**。

    首版用 ast.walk(fn) 把内层 def 的 `return None` 也算到外层头上
    （如 extract_entity_ids 内的 _walk、build_app 内的 dep）→ 8 条全误报。
    """
    res = []
    stack = list(fn.body)
    while stack:
        n = stack.pop()
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        if isinstance(n, ast.Return):
            res.append(n)
        for f in ast.iter_fields(n):
            v = f[1]
            if isinstance(v, list):
                stack.extend(x for x in v if isinstance(x, ast.AST))
    return res


def check_annotation_none_return(idx: Index):
    out = []
    for rel, tree in idx.trees.items():
        for fn in ast.walk(tree):
            if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            ann = _ret_annotation(fn)
            if not ann or _is_optional(ann):
                continue
            if "Any" in ann:
                continue
            # 生成器函数：裸 return 只是结束迭代（yield 空），不是返回 None。
            # 首版未排除 → af_closedloop/history.iter 与 af_live.events 两条误报。
            if any(isinstance(x, (ast.Yield, ast.YieldFrom)) for x in _own_returns(fn)) \
                    or any(isinstance(x, (ast.Yield, ast.YieldFrom)) for x in ast.walk(fn)):
                continue
            # 找裸 return / return None
            for n in _own_returns(fn):
                if not isinstance(n, ast.Return):
                    continue
                if n.value is None:
                    out.append({
                        "rule": "API-08-annotated-returns-none", "severity": "medium",
                        "file": rel, "line": n.lineno, "function": fn.name,
                        "message": (f"{fn.name}() 注解返回 `{ann}`（非 Optional），"
                                    f"但存在裸 return / return None 路径；"
                                    f"调用方按注解取下标或属性会 AttributeError/TypeError"),
                        "annotation": ann,
                    })
                    break
                if isinstance(n.value, ast.Constant) and n.value.value is None:
                    out.append({
                        "rule": "API-08-annotated-returns-none", "severity": "medium",
                        "file": rel, "line": n.lineno, "function": fn.name,
                        "message": (f"{fn.name}() 注解返回 `{ann}`（非 Optional），"
                                    f"但存在 return None；调用方按注解取下标或属性会崩"),
                        "annotation": ann,
                    })
                    break
    return out


# ────────────────────────────────────────────────────────────────────
# API-06 同名函数跨模块签名不同
# ────────────────────────────────────────────────────────────────────
def check_same_name_diff_sig(idx: Index):
    out = []
    for name, defs in idx.funcs.items():
        if len(defs) < 2 or name.startswith("_"):
            continue
        sigs = {}
        for rel, fn in defs:
            if _is_dynamic(fn):
                continue
            sigs.setdefault(rel, tuple(_params(fn)))
        if len(sigs) < 2:
            continue
        uniq = set(sigs.values())
        if len(uniq) == 1:
            continue
        out.append({
            "rule": "API-06-same-name-diff-sig", "severity": "low",
            "file": sorted(sigs)[0], "line": defs[0][1].lineno, "function": name,
            "message": f"同名函数 {name}() 在 {len(sigs)} 个文件里形参不同："
                       + "；".join(f"{f}{list(s)}" for f, s in sorted(sigs.items())),
        })
    return out


def main() -> int:
    root = Path(sys.argv[1] if len(sys.argv) > 1 else "/data/workspace/audit/src/src/autoforge")
    outdir = Path(sys.argv[2] if len(sys.argv) > 2 else "/data/workspace/audit/rounds/round-015/apicontract")
    outdir.mkdir(parents=True, exist_ok=True)

    idx = Index()
    for p in sorted(root.rglob("*.py")):
        if any(x.startswith("test") for x in p.parts):
            continue
        try:
            tree = ast.parse(p.read_text(errors="ignore"))
        except SyntaxError:
            continue
        idx.add(str(p.relative_to(root)), tree)

    findings = []
    for c in (check_call_signature, check_self_call_signature, check_lsp_violation,
              check_protocol_methods, check_annotation_none_return,
              check_return_shape_divergence, check_same_name_diff_sig):
        try:
            findings += c(idx)
        except Exception as e:  # noqa: BLE001
            print(f"[warn] {c.__name__}: {e}", file=sys.stderr)

    sev = {"high": 0, "medium": 1, "low": 2}
    findings.sort(key=lambda x: (sev.get(x["severity"], 9), x["file"], x["line"]))
    (outdir / "apicontract-findings.json").write_text(
        json.dumps({"findings": findings,
                    "stats": {"funcs": len(idx.funcs), "classes": len(idx.classes),
                              "protocols": sorted(idx.protocols)}},
                   ensure_ascii=False, indent=2))
    print(json.dumps({"total": len(findings),
                      "by_severity": dict(Counter(f["severity"] for f in findings)),
                      "by_rule": dict(Counter(f["rule"] for f in findings))},
                     ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
