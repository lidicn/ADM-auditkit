"""py.rmw_silent_empty —— 读-改-写中"读失败静默变空"。

来源：AutoForge R10-02 / R16-01、memory-agent MA-17（均确证）。
    读侧 `except: data = {}` ⇒ 下一次**完全正常**的写操作会用空集覆盖写回，
    历史数据永久消失，且全程无提示。

判据（三条同时满足，避免 §9.3 的假阳性）：
    ① 函数内既有"读"又有"写"
    ② except 体内把目标变量赋成空容器 `{}` / `[]`
    ③ 该 except 无留痕
clean 样本：读失败 raise（拒绝写入）或留痕后返回 ⇒ 不命中。
"""
from __future__ import annotations

import ast

from engine.base import BaseRule, Finding, node_source
from engine.helpers import own_walk, all_walk, has_trace

_READ = {"read_text", "loads", "load", "read"}
_WRITE = {"write_text", "dump", "dumps", "write"}


class RmwSilentEmptyRule(BaseRule):
    id = "py.rmw_silent_empty"
    name = "读-改-写：读失败静默变空"
    description = "读取失败时赋空容器且无留痕，随后的写回会永久抹掉历史数据"
    applies_to = []
    mode = "static_ast"
    severity = "high"
    status = "active"
    version = "1.0.0"

    tests = {
        "dirty": [
            {"name": "read-fail-to-empty-dict",
             "code": "def set_alias(path, alias, target):\n"
                     "    try:\n"
                     "        data = json.loads(Path(path).read_text())\n"
                     "    except Exception:\n"
                     "        data = {}\n"
                     "    data[alias] = target\n"
                     "    Path(path).write_text(json.dumps(data))"},
            {"name": "read-fail-to-empty-list",
             "code": "def ingest(path, payload):\n"
                     "    try:\n"
                     "        store = json.loads(Path(path).read_text())\n"
                     "    except Exception:\n"
                     "        store = []\n"
                     "    store.append(payload)\n"
                     "    Path(path).write_text(json.dumps(store))"},
        ],
        "clean": [
            {"name": "read-fail-raises",
             "code": "def set_alias(path, alias, target):\n"
                     "    try:\n"
                     "        data = json.loads(Path(path).read_text())\n"
                     "    except (OSError, ValueError) as exc:\n"
                     "        raise RuntimeError(f'损坏，拒绝写入: {exc}') from exc\n"
                     "    data[alias] = target\n"
                     "    Path(path).write_text(json.dumps(data))"},
            {"name": "read-fail-but-logged",
             "code": "def set_alias(path, alias, target):\n"
                     "    try:\n"
                     "        data = json.loads(Path(path).read_text())\n"
                     "    except Exception:\n"
                     "        logger.error('alias 读取失败，放弃本次写入')\n"
                     "        return None\n"
                     "    data[alias] = target\n"
                     "    Path(path).write_text(json.dumps(data))"},
        ],
    }

    def run(self, tree, profile=None, adapter=None) -> list[Finding]:
        out = []
        for fn in all_walk(tree):
            if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            body = ast.unparse(fn)
            if not (any(w in body for w in _WRITE) and any(r in body for r in _READ)):
                continue
            for h in own_walk(fn):
                if not isinstance(h, ast.ExceptHandler):
                    continue
                if has_trace(h)[0]:
                    continue
                for node in ast.walk(h):
                    if not isinstance(node, ast.Assign):
                        continue
                    if not isinstance(node.value, (ast.Dict, ast.List)):
                        continue
                    if node.value.elts if isinstance(node.value, ast.List) else node.value.keys:
                        continue  # 只认空容器 {} / []
                    out.append(Finding(
                        rule_id=self.id, file=str(tree.path), line=node.lineno,
                        severity=self.severity, title=self.name,
                        detail=f"`{fn.name}` 读失败赋空容器且无留痕，随后写回将抹掉历史",
                        evidence=node_source(tree, node.lineno)[:200],
                    ))
        return out
