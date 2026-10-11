"""py.fixed_tmp_replace_nonatomic —— 固定名 tmp + os.replace 的并发交错写。

来源：AutoForge 多轮确证缺陷族——同一进程（线程）或跨进程的两个写者写**同一个
固定名**临时文件，内容交错后被最后一次 `os.replace` 装上，读侧按坏 JSON 跳过 ⇒
数据静默消失：
    - R10 `catalog.json.tmp`（af_catalog，确证）
    - R13 `af_insight_queue` proposal 静默消失（确证，代码注释留档）
    - `af_store` `v{N}.tmp` 双写（确证，注释留档）
正解 = 随机名（`tempfile.mkstemp` / `uuid4`），AutoForge 的 `af_atomic.py`
即标准写法（mkstemp + fsync + os.replace）。项目内已修复处以
`# fixed-tmp: exempt(...)` 注释声明豁免——本规则尊重该注释。

判据（对**同一个** tmp 标识，三件事齐备才报——通则4"判不一致"降噪）：
    ① tmp 名派生是确定性的：表达式含 .tmp/.temp/.part/.new/.swp 字面量，
       且不含 mkstemp/uuid/random/secrets 等随机源
    ② 有写入（write_text / write_bytes / open(…, 'w…') / .open('w…')）
    ③ 被 os.replace(tmp, dst)（或 tmp.replace(dst)）的第一参数消费
只写不换（暂存文件）、只换不写（挪走现场，如 .corrupt 归档）都不报；
mkstemp/uuid 派生整体豁免。分析按函数作用域隔离，防跨函数同名变量假关联。
"""
from __future__ import annotations

import ast

from engine.base import BaseRule, Finding, node_source, call_chain
from engine.helpers import all_walk, own_walk

_SUFFIXES = (".tmp", ".temp", ".part", ".new", ".swp")
_RANDOM_MARKERS = (
    "mkstemp", "mkdtemp", "uuid", "random", "secrets", "getrandbits",
    "NamedTemporaryFile", "TemporaryDirectory", "SystemRandom",
)
_WRITE_MODE_PREFIX = ("w", "x")   # open() 第二参以 w/x 开头才算写
_SCOPE = (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)


def _deterministic_tmp(expr_text: str) -> bool:
    return (any(s in expr_text for s in _SUFFIXES)
            and not any(m in expr_text for m in _RANDOM_MARKERS))


def _names_in(node) -> set[str]:
    return {n.id for n in ast.walk(node) if isinstance(n, ast.Name)}


class FixedTmpReplaceRule(BaseRule):
    id = "py.fixed_tmp_replace_nonatomic"
    name = "固定名 tmp + os.replace 并发交错"
    description = ("临时文件名由目标路径确定性派生（如 path+'.tmp'）且存在写入 + os.replace："
                   "并发写者交错内容，最后一次 replace 静默装上坏数据；应改随机名（mkstemp/uuid4）")
    applies_to = []
    mode = "static_ast"
    severity = "high"
    status = "testing"
    version = "1.0.0"

    tests = {
        "dirty": [
            {"name": "fixed-tmp-var-write-replace",
             "code": "def save_state(path, data):\n"
                     "    tmp = path.with_suffix('.tmp')\n"
                     "    tmp.write_text(json.dumps(data))\n"
                     "    os.replace(tmp, path)"},
            {"name": "fixed-tmp-fstring-inline",
             "code": "def save(path, data):\n"
                     "    with open(f'{path}.tmp', 'w', encoding='utf-8') as f:\n"
                     "        json.dump(data, f)\n"
                     "    os.replace(f'{path}.tmp', path)"},
        ],
        "clean": [
            {"name": "mkstemp-random-name",
             "code": "def save(path, data):\n"
                     "    fd, tmp = tempfile.mkstemp(dir=str(path.parent), suffix='.tmp')\n"
                     "    with os.fdopen(fd, 'w', encoding='utf-8') as f:\n"
                     "        json.dump(data, f)\n"
                     "    os.replace(tmp, path)"},
            {"name": "uuid-random-name",
             "code": "def save(path, data):\n"
                     "    tmp = f'{path}.{uuid.uuid4().hex}.tmp'\n"
                     "    Path(tmp).write_text(data)\n"
                     "    os.replace(tmp, path)"},
            {"name": "stage-only-no-replace",
             "code": "def stage(path, data):\n"
                     "    tmp = path.with_suffix('.tmp')\n"
                     "    tmp.write_text(data)"},
            {"name": "replace-only-no-write",
             "code": "def salvage(path):\n"
                     "    tmp = path.with_suffix('.tmp')\n"
                     "    os.replace(tmp, path)"},
            {"name": "exempt-annotated",
             "code": "def save(path, data):\n"
                     "    tmp = path.with_suffix('.tmp')\n"
                     "    tmp.write_text(data)\n"
                     "    os.replace(tmp, path)  # fixed-tmp: exempt(单写者 CLI，无并发)"},
        ],
    }

    def run(self, tree, profile=None, adapter=None) -> list[Finding]:
        out: list[Finding] = []
        src_lines = (getattr(tree, "source", "") or "").splitlines()
        scopes = [n for n in all_walk(tree)
                  if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]
        scopes.append(tree)  # 模块顶层
        for scope in scopes:
            out.extend(self._scan_scope(tree, scope, src_lines))
        return out

    # -- 单作用域扫描 ---------------------------------------------------
    def _scan_scope(self, tree, scope, src_lines) -> list[Finding]:
        derivs: set[str] = set()      # 确定性 tmp 标识（变量名或表达式文本）
        writes: dict[str, int] = {}   # 标识 → 写入行
        replaces: dict[str, int] = {} # 标识 → os.replace 行

        for node in own_walk(scope):
            if isinstance(node, ast.Assign) and len(node.targets) == 1 \
                    and isinstance(node.targets[0], ast.Name):
                # BinOp(f'{p}'+'.tmp') / JoinedStr(f'{p}.tmp') / Call(with_suffix) 均覆盖
                expr = ast.unparse(node.value)
                if _deterministic_tmp(expr):
                    derivs.add(node.targets[0].id)
                continue
            if not isinstance(node, ast.Call):
                continue
            chain = call_chain(node)
            # 写入：X.write_text / X.write_bytes / X.open('w…') / open(X, 'w…')
            if isinstance(node.func, ast.Attribute) and node.func.attr in ("write_text", "write_bytes", "open"):
                key = self._tmp_key(node.func.value, derivs)
                if key and (node.func.attr == "open" and node.args
                            and isinstance(node.args[0], ast.Constant)
                            and str(node.args[0].value)[:1] in _WRITE_MODE_PREFIX
                            or node.func.attr != "open"):
                    writes.setdefault(key, node.lineno)
                continue
            if chain == "open" and node.args:
                key = self._tmp_key(node.args[0], derivs)
                if key and len(node.args) >= 2 and isinstance(node.args[1], ast.Constant) \
                        and str(node.args[1].value)[:1] in _WRITE_MODE_PREFIX:
                    writes.setdefault(key, node.lineno)
                continue
            # 替换：os.replace(tmp, dst) 或 tmp.replace(dst)（Path.replace 单参）
            if chain == "os.replace" and node.args:
                key = self._tmp_key(node.args[0], derivs)
                if key:
                    replaces.setdefault(key, node.lineno)
                continue
            if isinstance(node.func, ast.Attribute) and node.func.attr == "replace" \
                    and len(node.args) == 1 and isinstance(node.func.value, ast.Name) \
                    and node.func.value.id in derivs:
                replaces.setdefault(node.func.value.id, node.lineno)

        out: list[Finding] = []
        for key, lineno in replaces.items():
            if key not in writes:
                continue
            if self._exempted(src_lines, lineno):
                continue
            shown = key if len(key) <= 40 else key[:37] + "..."
            out.append(Finding(
                rule_id=self.id, file=str(tree.path), line=lineno,
                severity=self.severity, title=self.name,
                detail=(f"固定名 tmp `{shown}`（第 {writes[key]} 行写入）被 os.replace 消费："
                        f"并发写者交错内容后最后一次 replace 静默装上坏数据；"
                        f"应改随机名 tempfile.mkstemp/uuid4（参照 af_atomic.py）"),
                evidence=node_source(tree, lineno)[:200],
            ))
        return out

    # -- 辅助 -----------------------------------------------------------
    @staticmethod
    def _tmp_key(expr: ast.AST, derivs: set[str]) -> str | None:
        """把写入/替换处的表达式归一到 tmp 标识：优先变量名，否则确定性表达式文本。"""
        if isinstance(expr, ast.Name):
            return expr.id if expr.id in derivs else None
        names = _names_in(expr) & derivs
        if names:
            return sorted(names)[0]
        text = ast.unparse(expr)
        return text if _deterministic_tmp(text) else None

    @staticmethod
    def _exempted(src_lines: list[str], lineno: int) -> bool:
        """项目注释豁免约定：命中行及上方 2 行含 `fixed-tmp: exempt`。"""
        for i in range(max(0, lineno - 3), min(len(src_lines), lineno)):
            if "fixed-tmp: exempt" in src_lines[i]:
                return True
        return False
