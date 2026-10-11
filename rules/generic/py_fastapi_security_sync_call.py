"""py.fastapi_security_sync_call —— FastAPI 安全依赖被直接调用（协程泄漏 → 端点 500）。

来源：AutoForge af_api.py 历史确证缺陷——pair/SSE 端点里 `creds = _bearer(request)`
直接调用 `HTTPBearer` 实例：其 `__call__` 是 async，直接调用得到的是**协程对象**
（未 await 也不报错），随后访问 `creds.credentials` 抛
`AttributeError: 'coroutine' object has no attribute 'credentials'` ⇒ 端点 500。
正确写法是 `Depends(_bearer)`（AutoForge 已修复，现网全部走 Depends）。本规则
同时是**回归护栏**：防止将来有人再写回直接调用形态。

判据：
    ① `X = HTTPBearer()/HTTPBasic()/APIKeyHeader()/APIKeyQuery()/APIKeyCookie()/
        OAuth2PasswordBearer()` 实例赋给名字 X（含注解赋值）
    ② 同文件出现 `X(...)` 直接调用，且该 Call 不在 `await` 表达式内
       ——`await _bearer(request)` 是合法用法（async __call__ 可 await，PITFALLS P12）
`Depends(X)` 里 X 是 Name 不是 Call，天然不报。
"""
from __future__ import annotations

import ast

from engine.base import BaseRule, Finding, node_source
from engine.helpers import all_walk, call_name

_DEP_CLASSES = {
    "HTTPBearer", "HTTPBasic", "APIKeyHeader", "APIKeyQuery",
    "APIKeyCookie", "OAuth2PasswordBearer",
}


class FastApiSecuritySyncCallRule(BaseRule):
    id = "py.fastapi_security_sync_call"
    name = "FastAPI 安全依赖被直接调用"
    description = ("HTTPBearer 等安全依赖实例被直接调用（__call__ 是 async）：得到协程对象，"
                   "后续属性访问抛 AttributeError ⇒ 端点 500；应改用 Depends(X)")
    applies_to = []
    mode = "static_ast"
    severity = "high"
    status = "testing"
    version = "1.0.0"

    tests = {
        "dirty": [
            {"name": "bearer-called-directly",
             "code": "_bearer = HTTPBearer(auto_error=False)\n"
                     "\n"
                     "async def endpoint(request):\n"
                     "    creds = _bearer(request)\n"
                     "    return creds.credentials"},
            {"name": "bearer-called-directly-sync-def",
             "code": "_sec = APIKeyHeader(name='X-Token', auto_error=False)\n"
                     "\n"
                     "def endpoint(request):\n"
                     "    return _sec(request)"},
        ],
        "clean": [
            {"name": "awaited-call",
             "code": "_bearer = HTTPBearer(auto_error=False)\n"
                     "\n"
                     "async def endpoint(request):\n"
                     "    creds = await _bearer(request)\n"
                     "    return creds.credentials"},
            {"name": "depends-form",
             "code": "_bearer = HTTPBearer(auto_error=False)\n"
                     "\n"
                     "def endpoint(creds=Depends(_bearer)):\n"
                     "    return creds"},
            {"name": "no-security-dep",
             "code": "def endpoint(request):\n"
                     "    return auth(request)"},
        ],
    }

    def run(self, tree, profile=None, adapter=None) -> list[Finding]:
        deps: set[str] = set()
        for n in all_walk(tree):
            if not isinstance(n, (ast.Assign, ast.AnnAssign)):
                continue
            value = getattr(n, "value", None)
            if not (isinstance(value, ast.Call) and call_name(value) in _DEP_CLASSES):
                continue
            targets = n.targets if isinstance(n, ast.Assign) else [n.target]
            for t in targets:
                if isinstance(t, ast.Name):
                    deps.add(t.id)
        if not deps:
            return []

        hits: list[ast.Call] = []

        def walk(node, in_await: bool = False) -> None:
            if isinstance(node, ast.Await):
                for c in ast.iter_child_nodes(node):
                    walk(c, True)
                return
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) \
                    and node.func.id in deps and not in_await:
                hits.append(node)
            for c in ast.iter_child_nodes(node):
                walk(c, in_await)

        walk(tree)

        out: list[Finding] = []
        for call in hits:
            name = call.func.id
            out.append(Finding(
                rule_id=self.id, file=str(tree.path), line=call.lineno,
                severity=self.severity, title=self.name,
                detail=(f"`{name}(...)` 直接调用安全依赖实例：其 __call__ 是 async，"
                        f"得到的是协程对象（未 await 不报错），后续属性访问抛 "
                        f"AttributeError ⇒ 端点 500；应改用 Depends({name})"),
                evidence=node_source(tree, call)[:200],
            ))
        return out
