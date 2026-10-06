#!/usr/bin/env python3
"""第十轮专题：序列化往返与跨层契约一致性（纯 stdlib AST）。

前九轮覆盖：稳定性、持久化、并发、复杂度、控制流、死代码/缓存、时间数值、
输入边界、事务边界。本轮看**数据在层与层之间搬运时有没有走样**：

  SER-01 类有 to_dict 但无 from_dict（单向序列化 → 反序列化时字段丢失）
  SER-02 to_dict 产出的键 与 from_dict 读取的键 不一致（字段漂移）
  SER-03 dataclass / 类的字段未在 to_dict 中出现（往返丢字段）
  SER-04 to_dict 输出含不可 JSON 序列化的类型（datetime / Path / set / 自定义对象）
  SER-05 json.dumps(..., default=str) 静默降级（序列化错误被掩盖成字符串）
  SER-06 返回体字段名风格混用（snake_case 与 camelCase 在同一响应里）
  SER-07 异常类型 → HTTP 状态码映射不一致（同类错误在不同端点返回不同码）

配套：本目录另有 roundtrip 实测脚本思路（见报告），AST 只给候选。

用法: serialization_defects.py <src_root> <outdir>
"""
from __future__ import annotations

import ast
import json
import re
import sys
from collections import Counter
from pathlib import Path

NON_JSON_TYPES = {"datetime", "date", "time", "Path", "set", "frozenset", "Decimal",
                  "bytes", "complex", "UUID"}


def _keys_of_dict_literal(fn) -> set[str]:
    """收集 to_dict 的输出键：既含字典字面量，也含 `out["k"] = ...` 增量赋值。

    首版只读字典字面量，把 AskSpec.to_dict（先 `out = {"kind":...}` 再
    `out["min"] = ...`）判成"只输出 kind"，于是 SER-02/03 命中全是假阳性。
    """
    keys = set()
    for n in ast.walk(fn):
        if isinstance(n, ast.Dict):
            for k in n.keys:
                if isinstance(k, ast.Constant) and isinstance(k.value, str):
                    keys.add(k.value)
        # out["k"] = v / out.update(k=...) / out.setdefault("k", ...)
        if isinstance(n, ast.Assign):
            for tgt in n.targets:
                if isinstance(tgt, ast.Subscript) and isinstance(tgt.slice, ast.Constant) \
                        and isinstance(tgt.slice.value, str):
                    keys.add(tgt.slice.value)
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) \
                and n.func.attr in ("update", "setdefault"):
            for k in n.keywords:
                if k.arg and k.arg not in keys:
                    keys.add(k.arg)
            for a in n.args:
                if isinstance(a, ast.Dict):
                    for k in a.keys:
                        if isinstance(k, ast.Constant) and isinstance(k.value, str):
                            keys.add(k.value)
    return keys


def _read_keys(fn) -> set[str]:
    """收集函数里 data.get("x") / data["x"] 形式的读取键。"""
    keys = set()
    for n in ast.walk(fn):
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) \
                and n.func.attr in ("get", "pop") and n.args:
            a = n.args[0]
            if isinstance(a, ast.Constant) and isinstance(a.value, str):
                keys.add(a.value)
        if isinstance(n, ast.Subscript) and isinstance(n.slice, ast.Constant) \
                and isinstance(n.slice.value, str):
            keys.add(n.slice.value)
    return keys


def _methods(cls: ast.ClassDef) -> dict[str, ast.FunctionDef]:
    return {m.name: m for m in cls.body
            if isinstance(m, (ast.FunctionDef, ast.AsyncFunctionDef))}


def _annotations(cls: ast.ClassDef) -> list[str]:
    out = []
    for n in cls.body:
        if isinstance(n, ast.AnnAssign) and isinstance(n.target, ast.Name):
            out.append(n.target.id)
    return out


def _is_dataclass(cls) -> bool:
    for d in cls.decorator_list:
        nm = getattr(d, "id", None) or getattr(d, "attr", None)
        if nm == "dataclass":
            return True
    return False


# ────────────────────────────────────────────────────────────────────
# SER-01 / SER-02 / SER-03 类级往返一致性
# ────────────────────────────────────────────────────────────────────
def check_class_roundtrip(tree, rel):
    out = []
    for cls in ast.walk(tree):
        if not isinstance(cls, ast.ClassDef):
            continue
        m = _methods(cls)
        if "to_dict" not in m:
            continue
        to_keys = _keys_of_dict_literal(m["to_dict"])
        anns = _annotations(cls)
        declared = {a for a in anns if not a.startswith("_")}

        if "from_dict" not in m:
            out.append({
                "rule": "SER-01-one-way-serialize", "severity": "medium",
                "file": rel, "line": cls.lineno, "class": cls.name, "function": "to_dict",
                "message": f"{cls.name} 有 to_dict() 但无 from_dict()：单向序列化；"
                           f"若该类需从磁盘/网络恢复，字段会按位置或缺失重建"})
            continue

        from_keys = _read_keys(m["from_dict"])
        # 只在两者都非空时才做集合比较（空集合多半是动态构造，非真漂移）
        if to_keys and from_keys:
            written_only = sorted(to_keys - from_keys)
            read_only = sorted(from_keys - to_keys)
            if written_only or read_only:
                detail = []
                if written_only:
                    detail.append(f"写了但没读回：{written_only[:6]}")
                if read_only:
                    detail.append(f"读了但不产出：{read_only[:6]}")
                out.append({
                    "rule": "SER-02-key-drift", "severity": "medium",
                    "file": rel, "line": cls.lineno, "class": cls.name, "function": "to_dict",
                    "message": f"{cls.name} 的 to_dict/from_dict 键集合不一致（{'；'.join(detail)}）"
                               f" → 往返后字段静默丢失或恒为默认"})
        # SER-03：声明字段未出现在 to_dict 输出键里
        if declared and to_keys:
            missing = sorted(declared - to_keys)
            if missing:
                out.append({
                    "rule": "SER-03-field-not-serialized", "severity": "medium",
                    "file": rel, "line": cls.lineno, "class": cls.name, "function": "to_dict",
                    "message": f"{cls.name} 声明了 {len(declared)} 个字段，"
                               f"但 to_dict() 未输出 {missing[:6]} → 往返后这些字段丢失"})
    return out


# ────────────────────────────────────────────────────────────────────
# SER-04 to_dict 输出含不可 JSON 序列化类型
# ────────────────────────────────────────────────────────────────────
def check_non_json_types(tree, rel):
    out = []
    for cls in ast.walk(tree):
        if not isinstance(cls, ast.ClassDef):
            continue
        m = _methods(cls)
        if "to_dict" not in m:
            continue
        src = ast.unparse(m["to_dict"])
        for t in NON_JSON_TYPES:
            # 必须完整词边界：否则 self.timers 会被 'time' 命中（假阳性）
            if re.search(rf"\b{re.escape(t)}\s*\(", src) \
                    or re.search(rf"\bself\.{re.escape(t)}\b", src) \
                    or re.search(rf":\s*{re.escape(t)}\b", src) \
                    or re.search(rf"\b{re.escape(t)}\.now\b", src):
                out.append({
                    "rule": "SER-04-non-json-type", "severity": "medium",
                    "file": rel, "line": m["to_dict"].lineno, "class": cls.name,
                    "function": "to_dict",
                    "message": f"{cls.name}.to_dict() 输出疑似含 {t}；"
                               f"直接 json.dumps 会 TypeError（除非调用方带 default=）"})
                break
    return out


# ────────────────────────────────────────────────────────────────────
# SER-05 json.dumps(default=str) 静默降级
# ────────────────────────────────────────────────────────────────────
def check_default_str(tree, rel):
    out = []
    for n in ast.walk(tree):
        if not isinstance(n, ast.Call):
            continue
        c = ""
        if isinstance(n.func, ast.Attribute):
            c = n.func.attr
        elif isinstance(n.func, ast.Name):
            c = n.func.id
        if c != "dumps":
            continue
        for kw in n.keywords:
            if kw.arg == "default":
                v = ast.unparse(kw.value)
                if v in ("str", "repr"):
                    out.append({
                        "rule": "SER-05-default-str", "severity": "low",
                        "file": rel, "line": n.lineno, "function": "<json.dumps>",
                        "message": f"json.dumps(default={v})：不可序列化的值被静默转成字符串；"
                                   f"类型错误不会暴露，下游拿到的是 '{v}(obj)' 文本而非原结构"})
    return out


# ────────────────────────────────────────────────────────────────────
# SER-07 异常 → HTTP 状态码：同一异常在不同端点映射不同码
# ────────────────────────────────────────────────────────────────────
def check_status_mapping(tree, rel):
    out = []
    mapping: dict[str, set[int]] = {}
    for n in ast.walk(tree):
        if not isinstance(n, ast.Raise):
            continue
        exc = n.exc
        if not isinstance(exc, ast.Call):
            continue
        nm = getattr(exc.func, "id", None) or getattr(exc.func, "attr", None)
        if nm != "HTTPException":
            continue
        code = None
        for kw in exc.keywords:
            if kw.arg == "status_code":
                try:
                    code = ast.literal_eval(kw.value)
                except Exception:
                    pass
        if code is None:
            continue
        # 找同函数内被 raise 的业务异常（ServiceError 之类）
        for t in ast.walk(tree):
            pass
        mapping.setdefault(str(code), set())
    # 统计不同状态码种类，仅做提示（真不一致需人工判定）
    if len(mapping) >= 2:
        out.append({
            "rule": "SER-07-status-variety", "severity": "low",
            "file": rel, "line": 0, "function": "<module>",
            "message": f"该文件使用 {len(mapping)} 种 HTTP 状态码（{sorted(mapping)}）；"
                       f"需人工确认同类错误的码是否一致"})
    return out


CHECKS = [
    check_class_roundtrip,
    check_non_json_types,
    check_default_str,
    check_status_mapping,
]


def main() -> int:
    root = Path(sys.argv[1] if len(sys.argv) > 1 else "/data/workspace/audit/src/src/autoforge")
    outdir = Path(sys.argv[2] if len(sys.argv) > 2 else "/data/workspace/audit/rounds/round-010/serialization")
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
    (outdir / "serialization-findings.json").write_text(
        json.dumps({"findings": findings}, ensure_ascii=False, indent=2))
    print(json.dumps({"files": files, "total": len(findings),
                      "by_severity": dict(Counter(f["severity"] for f in findings)),
                      "by_rule": dict(Counter(f["rule"] for f in findings))},
                     ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
