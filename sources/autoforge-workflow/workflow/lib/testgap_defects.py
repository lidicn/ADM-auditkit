#!/usr/bin/env python3
"""第十四轮专题：测试与验证缺口（纯 stdlib AST + 目录扫描）。

前十三轮看的是**生产代码**。本轮反过来问：**这些代码有没有被验证过**？
重点不是统计覆盖率（沙箱跑不了项目），而是找**结构性缺口**：

  TST-01 生产模块无对应测试文件（按命名约定匹配）
  TST-02 生产代码中的 TODO/FIXME/占位（未完成实现）
  TST-03 NotImplementedError 在函数体内（未完成分支）
  TST-04 仅 `pass` 的函数体（空实现）
  TST-05 高危模块无测试（按本审计已发现 BUG 的模块反查）
  TST-06 测试文件里的断言密度异常低（形同空测试）

设计原则：测试缺失本身不是 bug，但**已发现缺陷的模块没有测试**说明
修复后无法回归验证——这才值得报。本轮产出以"缺口清单"为主，不虚报缺陷。

用法: testgap_defects.py <src_root> <outdir> <tests_root>
"""
from __future__ import annotations

import ast
import json
import re
import sys
from collections import Counter
from pathlib import Path

TODO_HINT = re.compile(r"(TODO|FIXME|XXX|HACK|WIP|暂未实现|待实现|未完成)")


def _module_key(name: str) -> str:
    """文件名 → 归一化模块键（去掉 af_ 前缀与 test_ 前缀）。"""
    n = name.lower()
    for pre in ("test_af_", "test_", "af_"):
        if n.startswith(pre):
            n = n[len(pre):]
            break
    return n


# ────────────────────────────────────────────────────────────────────
# TST-01 生产模块无对应测试
# ────────────────────────────────────────────────────────────────────
def check_module_without_test(pkg: Path, tests: Path, bug_modules: set[str]):
    out = []
    if not tests.exists():
        return out
    test_keys = set()
    for p in tests.rglob("test_*.py"):
        test_keys.add(_module_key(p.stem))
    # 也接受以模块名命名的目录（tests/acceptance/... 里的文件也算）
    for p in tests.rglob("*.py"):
        test_keys.add(_module_key(p.stem))

    for p in sorted(pkg.glob("af_*.py")):
        key = _module_key(p.stem)
        if key in test_keys:
            continue
        # 宽松匹配：测试名包含模块键 或 模块键包含测试名
        fuzzy = any(key in t or t in key for t in test_keys if len(t) > 3)
        sev = "medium" if key in bug_modules else "low"
        out.append({
            "rule": "TST-01-no-test", "severity": sev,
            "file": f"src/autoforge/{p.name}", "line": 0,
            "function": "<module>",
            "message": (f"模块 {p.name} 无按命名匹配的测试文件"
                        + (f"；且本审计已在该模块发现缺陷（{key}）→ 修复后无法回归验证"
                           if key in bug_modules else
                           "（可能被其他测试间接覆盖，需人工确认）")),
            "fuzzy_covered": fuzzy,
        })
    return out


# ────────────────────────────────────────────────────────────────────
# TST-02 TODO / FIXME 占位
# ────────────────────────────────────────────────────────────────────
def check_todo_markers(tree, rel, raw: str):
    out = []
    for i, line in enumerate(raw.splitlines(), start=1):
        if TODO_HINT.search(line):
            out.append({
                "rule": "TST-02-todo-marker", "severity": "low",
                "file": rel, "line": i, "function": "<module>",
                "message": f"未完成标记：{line.strip()[:80]}",
            })
    return out


# ────────────────────────────────────────────────────────────────────
# TST-03 NotImplementedError 在函数体内
# ────────────────────────────────────────────────────────────────────
def check_not_implemented(tree, rel):
    out = []
    for fn in ast.walk(tree):
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for n in ast.walk(fn):
            if isinstance(n, ast.Raise) and isinstance(n.exc, ast.Call):
                nm = getattr(n.exc.func, "id", None) or getattr(n.exc.func, "attr", None)
                if nm == "NotImplementedError":
                    out.append({
                        "rule": "TST-03-not-implemented", "severity": "low",
                        "file": rel, "line": n.lineno, "function": fn.name,
                        "message": f"{fn.name}() 含 NotImplementedError 分支；"
                                   f"若该分支可达则功能不完整（需确认是否死分支）"})
    return out


# ────────────────────────────────────────────────────────────────────
# TST-04 仅 pass / 仅 docstring 的空实现
# ────────────────────────────────────────────────────────────────────
def check_empty_implementation(tree, rel):
    out = []
    for fn in ast.walk(tree):
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        body = [s for s in fn.body
                if not (isinstance(s, ast.Expr) and isinstance(s.value, ast.Constant)
                        and isinstance(s.value.value, str))]
        if not body:
            continue
        if len(body) == 1 and isinstance(body[0], ast.Pass):
            # 抽象/协议方法不算
            deco = [getattr(d, "id", None) or getattr(d, "attr", None)
                    for d in fn.decorator_list]
            if any(d in ("abstractmethod", "overload") for d in deco):
                continue
            out.append({
                "rule": "TST-04-empty-impl", "severity": "low",
                "file": rel, "line": fn.lineno, "function": fn.name,
                "message": f"{fn.name}() 函数体仅 `pass`（无实现）；"
                           f"若非故意的空钩子，调用方会拿到 None 且无提示",
                "decorators": [d for d in deco if d],
            })
    return out


# ────────────────────────────────────────────────────────────────────
# TST-06 测试文件断言密度异常低
# ────────────────────────────────────────────────────────────────────
def check_test_assert_density(tests: Path):
    out = []
    if not tests.exists():
        return out
    for p in sorted(tests.rglob("test_*.py")):
        try:
            tree = ast.parse(p.read_text(errors="ignore"))
        except SyntaxError:
            continue
        testfns = [f for f in ast.walk(tree)
                   if isinstance(f, (ast.FunctionDef, ast.AsyncFunctionDef))
                   and f.name.startswith("test")]
        if not testfns:
            continue
        for f in testfns:
            # 首版只认裸 `assert` 与 pytest.raises，把 unittest 风格的
            # `self.assertEqual(...)` / `self.assertTrue(...)` 全部漏掉（139 条假阳性）。
            n_assert = 0
            for x in ast.walk(f):
                if isinstance(x, ast.Assert):
                    n_assert += 1
                    continue
                if isinstance(x, ast.Call):
                    c = ""
                    if isinstance(x.func, ast.Attribute):
                        c = x.func.attr
                    elif isinstance(x.func, ast.Name):
                        c = x.func.id
                    if re.match(r"(?i)^(assert\w*|fail|raises)$", c) \
                            or re.search(r"(?i)(pytest\.raises|\.raises\()", ast.unparse(x)):
                        n_assert += 1
            # 有 mocking/patch 说明在测行为
            has_mock = re.search(r"(?i)(mock|patch|monkeypatch|stub|fake)",
                                 ast.unparse(f)) is not None
            if n_assert == 0 and not has_mock:
                out.append({
                    "rule": "TST-06-no-assert", "severity": "low",
                    "file": str(p.relative_to(tests)), "line": f.lineno,
                    "function": f.name,
                    "message": f"测试函数 {f.name}() 既无断言也无 mock；"
                               f"只调用不校验 → 通过不代表正确（仅防崩溃）",
                })
    return out


def main() -> int:
    root = Path(sys.argv[1] if len(sys.argv) > 1 else "/data/workspace/audit/src/src/autoforge")
    outdir = Path(sys.argv[2] if len(sys.argv) > 2 else "/data/workspace/audit/rounds/round-014/testgap")
    tests = Path(sys.argv[3] if len(sys.argv) > 3 else "/data/workspace/audit/src/tests")
    outdir.mkdir(parents=True, exist_ok=True)

    bug_modules = set()
    bm = Path("/data/workspace/audit/baseline/bugs.json")
    if bm.exists():
        try:
            for b in json.loads(bm.read_text()).get("bugs", []):
                f = b.get("file", "")
                m = re.search(r"([\w/]+)\.py", f)
                if m:
                    bug_modules.add(_module_key(Path(m.group(1)).name))
        except Exception:
            pass

    findings = []
    findings += check_module_without_test(root, tests, bug_modules)
    findings += check_test_assert_density(tests)

    files = 0
    for p in sorted(root.rglob("*.py")):
        if any(x.startswith("test") for x in p.parts):
            continue
        try:
            tree = ast.parse(p.read_text(errors="ignore"))
            raw = p.read_text(errors="ignore")
        except SyntaxError:
            continue
        rel = str(p.relative_to(root))
        files += 1
        for c in (check_todo_markers, check_not_implemented, check_empty_implementation):
            try:
                findings += c(tree, rel) if c is check_not_implemented or c is check_empty_implementation \
                    else c(tree, rel, raw)
            except Exception as e:  # noqa: BLE001
                print(f"[warn] {c.__name__} on {rel}: {e}", file=sys.stderr)

    sev = {"high": 0, "medium": 1, "low": 2}
    findings.sort(key=lambda x: (sev.get(x["severity"], 9), x["file"], x["line"]))
    (outdir / "testgap-findings.json").write_text(
        json.dumps({"findings": findings, "bug_modules": sorted(bug_modules)},
                   ensure_ascii=False, indent=2))
    print(json.dumps({"files": files, "total": len(findings),
                      "by_severity": dict(Counter(f["severity"] for f in findings)),
                      "by_rule": dict(Counter(f["rule"] for f in findings))},
                     ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
