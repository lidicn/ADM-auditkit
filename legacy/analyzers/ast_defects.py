#!/usr/bin/env python3
"""功能性缺陷静态分析（AST，补 semgrep 之不足）。

检测 1：混合返回 —— 函数既有 `return <值>` 又存在可 fall-through 到末尾的路径
        （隐式 None）。调用方解引用即 AttributeError/TypeError。
检测 2：异常分支 `return None` 与正常 `return <值>` 混用（同上，且是"失败伪装成空"）。
检测 3：函数声明了非 Optional 返回类型，却存在隐式 None 路径（类型契约违背）。
"""
import ast
import json
import sys
from pathlib import Path


def is_none_return(node: ast.Return) -> bool:
    if node.value is None:
        return True
    return isinstance(node.value, ast.Constant) and node.value.value is None


def returns_none(node: ast.Return) -> bool:
    return is_none_return(node)


def block_terminates(body: list) -> bool:
    """判断语句块是否在所有路径上以 return/raise 结束（穿透 with/try/if）。"""
    if not body:
        return False
    for stmt in reversed(body):
        if isinstance(stmt, (ast.Return, ast.Raise)):
            return True
        # 不可达之后的语句（如 raise 后面），继续往前看
        if isinstance(stmt, (ast.Break, ast.Continue)):
            continue
        if isinstance(stmt, ast.With):
            return block_terminates(stmt.body)
        if isinstance(stmt, ast.If):
            if not block_terminates(stmt.body):
                return False
            if stmt.orelse:
                return block_terminates(stmt.orelse)
            return False  # 无 else 分支 → 条件为假时 fall-through
        if isinstance(stmt, ast.Try):
            if stmt.finalbody and block_terminates(stmt.finalbody):
                return True
            if not block_terminates(stmt.body):
                return False
            for h in stmt.handlers:
                if not block_terminates(h.body):
                    return False
            if stmt.orelse and not block_terminates(stmt.orelse):
                return False
            return True
        if isinstance(stmt, (ast.For, ast.While)):
            # 循环可能 0 次迭代 → 不保证终止（保守）
            if isinstance(stmt, ast.While) and isinstance(getattr(stmt, "test", None), ast.Constant) \
                    and stmt.test.value is True:
                return block_terminates(stmt.body) or any(
                    isinstance(n, (ast.Return, ast.Raise)) for n in ast.walk(stmt))
            return False
        if isinstance(stmt, ast.Match):
            if not all(block_terminates(c.body) for c in stmt.cases):
                return False
            return True
        return False
    return False


def analyze(path: Path) -> list:
    try:
        tree = ast.parse(path.read_text(errors="ignore"))
    except SyntaxError:
        return []
    out = []
    for fn in ast.walk(tree):
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue

        rets = [n for n in ast.walk(fn) if isinstance(n, ast.Return)]
        if not rets:
            continue
        val_rets = [r for r in rets if not returns_none(r)]
        none_rets = [r for r in rets if returns_none(r)]
        if not val_rets:
            continue  # 纯 None/过程函数，不算混合

        implicit = not block_terminates(fn.body)
        if not (implicit or none_rets):
            continue

        ann = fn.returns
        ann_s = ast.unparse(ann) if ann else None
        optional = ann_s and ("Optional" in ann_s or "| None" in ann_s or "None |" in ann_s)

        kinds = []
        if implicit:
            kinds.append("存在 fall-through 到末尾（隐式 None）")
        if none_rets:
            kinds.append(f"{len(none_rets)} 处显式 return None")

        sev = "medium"
        if ann_s and not optional:
            sev = "high"   # 类型契约说不会是 None，实际会
            kinds.append(f"返回类型标注为 {ann_s}（非 Optional），契约被违背")

        out.append({
            "rule": "AF-AST-MIXED-RETURN",
            "severity": sev,
            "file": str(path),
            "line": fn.lineno,
            "message": f"函数 {fn.name}() 混合返回：{len(val_rets)} 处返回值 / " + "；".join(kinds),
            "function": fn.name,
            "annotated": ann_s,
        })
    return out


def main() -> int:
    root = Path(sys.argv[1] if len(sys.argv) > 1 else "/data/workspace/audit/src/src/autoforge")
    outdir = Path(sys.argv[2] if len(sys.argv) > 2 else "/data/workspace/audit/rounds/round-001/ast")
    outdir.mkdir(parents=True, exist_ok=True)

    findings = []
    files = 0
    for p in sorted(root.rglob("*.py")):
        if any(part.startswith("test") for part in p.parts):
            continue
        findings += analyze(p)
        files += 1

    findings.sort(key=lambda x: (0 if x["severity"] == "high" else 1, x["file"], x["line"]))
    (outdir / "ast-findings.json").write_text(json.dumps({"findings": findings}, ensure_ascii=False, indent=2))
    print(json.dumps({"files": files, "total": len(findings),
                      "high": sum(1 for f in findings if f["severity"] == "high")}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
