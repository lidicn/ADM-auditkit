"""py.query_numeric_unguarded —— 数值型入参未守护，坏值即 500。

来源：20261012 跨项目审计（doubao-butler 决策/列表路由族）。

【缺陷形态】`int(request.query_params.get("limit", 50))` 这类写法只守护了"参数缺席"
（默认值 50），**没有守护"参数存在但不是数字"**。`?limit=abc` 时 `int()` 抛 ValueError；
若该语句不在 try 里，异常一路冒到框架。doubao-butler 的 `butler/app.py:959` 挂了
`exception_handlers={Exception: _global_exc}`，而 `_global_exc`（`:232-234`）做
`logger.exception("unhandled: %s", exc)` + `JSONResponse({"ok": False, "error": "internal_error"}, 500)`
⇒ 现网表现不是进程崩，而是**每个坏值一发整栈 traceback + 500**：
  - 语义错：客户端传错参数是 400 的活儿，回 500 让调用方无法区分"我写错了"和"服务坏了"；
  - 噪声面：日志被单一输入刷爆，真正的 unhandled 异常被淹（本生态 butler 一处即 34 个站点此形态）；
  - 稳定性：有 `limit`/`offset`/`days`/`seconds` 的读端点全部可被远程刷量。

【判据】只判"能被机械坐实的那一半"：
 1. int()/float() 的实参是 `<request-ish>.query_params|path_params|form|data.get(...)`（显式入站取参），或
 2. int()/float() 的实参是 `body|payload|json_data|body_json|json_body.get(...)`（约定的已解析请求体名），
    或 `data.get(...)` 且**同一函数内**存在 `data = await request.json()` / `data = json.loads(await request.body())`
    这类入站赋值；且该名字没有被内部来源赋值（json.loads(非 request)/read_text/read_bytes/load*）；
 3. 该行不在同一函数的任何 try 块范围内（有 try 就不报，避免与 py.except_broad_swallow 双重计账）。

【v1.1.0 为什么加"data 需要入站赋值"】round-216 实测 AutoForge 13/13、memory-agent 3/4 命中全是同一族
假阳性：`int(data.get("total", 0))` 里的 `data` 是**本地 JSON 存档/反序列化字典**（af_catalog.py:599-605
`data = json.loads(path.read_text(...))`、af_conflict_audit.py:62 `def lock_from_dict(data: dict)`、
memory-agent entity_resolution.py:307 `from_dict(cls, data)`），不是 HTTP 请求体。变量名撞车 ≠ 数据流入站。

【v1.1.1 为什么把"形参必须叫 request"改掉】v1.1.0 用"最内层函数有 request/req 形参"当作入站前置，
`auditkit diff doubao-butler/autoforge/memory-agent 216 219` 显示 -13/-3 之后，另两族 diff 暴露出
**误杀了一条真阳性**：tvpilot `tvpilot/routes/ask.py:15` `duration = max(1, min(int(body.get('duration', 30)), 60))`
在 `def handle_ask_post(handler, path, body)` 里——http.server 风格的 handler 形参根本叫 `handler`，
请求体是当参数传进来的，且该语句在 `:16` 的 try **之外**（try 包的是下游转发，不是这次转换）。
⇒ 前置从"函数签名"改成"名字的赋值来源"：签名是框架习惯，来源才是数据流。

【已知假阳性面】
- 名字来源是内部存档但赋值写法不在识别表内（如 `data = store.read()` 之后被别处改名再取值）。
- 外层框架已做类型校验（FastAPI 的 `Query(...)` 声明式校验）——本规则只吃 `request.query_params`
  显式取值形态，声明式路由天然不命中。
【已知漏报面】
- `int(str(body["n"]))`、`operator.index()`、`Decimal(...)` 等别名形态。
- try 在更外层（跨函数包装）——按行号范围判定，够不着包装层。
- 数值入参在处理器之外的 helper 里转换，且 helper 里没有入站赋值。
"""
from __future__ import annotations

import ast
import re

from engine.base import BaseRule, Finding, call_chain

CASTS = ("int", "float")
# request 侧显式取参：request.query_params.get(...) / req.path_params.get(...) / form.get(...)
REQ_SHAPE = re.compile(r"^(request|req|self\.request)\.(query_params|path_params|form|formdata|data)\.get")
# 已解析的请求体字典（约定名）：body / payload / json_data / body_json / json_body
BODY_SHAPE = re.compile(r"^(body|payload|json_data|body_json|json_body)\.get")
# data 是最常见的局部字典名，只有在同一函数内被"入站来源"赋值过才算请求体
DATA_SHAPE = re.compile(r"^data\.get")
INBOUND_PARAMS = ("request", "req")
INBOUND_SOURCE = re.compile(r"^(request|req|self\.request)\.(json|body|form|formdata|data)$")
# 内部来源重绑：这些右侧说明该名字不是 HTTP 入站
INTERNAL_BIND = re.compile(r"^(json\.loads|json\.load|ast\.literal_eval)")
INTERNAL_ATTRS = ("read_text", "read_bytes", "loads", "load", "_load", "read_json")


def _args_touch_request(call: ast.Call) -> bool:
    """json.loads(...) 之类内部解析的参数是否直接来自 request.*（则算入站）。"""
    vals = list(call.args) + [k.value for k in call.keywords if k.value is not None]
    for v in vals:
        node = v.value if isinstance(v, ast.Await) else v
        if not isinstance(node, ast.Call):
            continue
        c = (call_chain(node) or "").lower()
        if c.startswith(INBOUND_PARAMS + ("self.request",)) or ".request." in c:
            return True
    return False


def _is_inbound_source(val: ast.AST, chain: str) -> bool:
    """赋值右侧是否入站来源：await request.json()/body()/form() 或 json.loads(await request.body())。"""
    if INBOUND_SOURCE.match(chain):
        return True
    return bool(INTERNAL_BIND.match(chain) and _args_touch_request(val))


class QueryNumericUnguardedRule(BaseRule):
    id = "py.query_numeric_unguarded"
    name = "数值入参未守护（坏值直冲 500）"
    description = (
        "int()/float() 直接转换入站请求参数（request.query_params/path_params/form 或处理器内的"
        "已解析 body），且该行不在 try 内：非数字值抛 ValueError，经全局 Exception 处理器变成 500 + 整栈日志"
    )
    applies_to = []
    mode = "static_ast"
    severity = "medium"
    status = "active"
    version = "1.1.1"
    intent = "discovery"

    tests = {
        "dirty": [
            {"name": "butler-decision-limit",
             "code": "async def decision_list(request):\n"
                     "    limit = int(request.query_params.get(\"limit\", 50))\n"
                     "    return ok(store.list(limit=limit))\n"},
            {"name": "path-param-int",
             "code": "async def detail(request):\n"
                     "    pid = int(request.path_params.get(\"id\"))\n"
                     "    return get(pid)\n"},
            {"name": "body-dict-int",
             "code": "async def patch(request):\n"
                     "    body = await request.json()\n"
                     "    n = int(body.get(\"count\", 1))\n"
                     "    return apply(n)\n"},
            {"name": "no-default-form",
             "code": "async def days(request):\n"
                     "    d = int(request.query_params.get(\"days\"))\n"
                     "    return d\n"},
            {"name": "notify-body-volume",
             "code": "async def notify_create(request):\n"
                     "    body = await request.json()\n"
                     "    volume = int(body.get(\"volume\", 80))\n"
                     "    return ok(volume)\n"},
            {"name": "tvpilot-body-param-no-request-name",
             "code": "def handle_ask_post(handler, path, body):\n"
                     "    duration = max(1, min(int(body.get('duration', 30)), 60))\n"
                     "    return duration\n"},
            {"name": "data-from-request-body",
             "code": "async def h(request):\n"
                     "    data = json.loads(await request.body())\n"
                     "    n = int(data.get(\"n\", 1))\n"
                     "    return n\n"},
        ],
        "clean": [
            {"name": "guarded-by-try",
             "code": "async def h(request):\n"
                     "    try:\n"
                     "        limit = int(request.query_params.get(\"limit\", 50))\n"
                     "    except (TypeError, ValueError):\n"
                     "        return err(\"bad limit\", 400)\n"
                     "    return limit\n"},
            {"name": "safe-coerce-helper",
             "code": "async def h(request):\n"
                     "    limit = to_int(request.query_params.get(\"limit\", 50), 50)\n"
                     "    return limit\n"},
            {"name": "declared-query-model",
             "code": "async def h(limit: int = Query(50)):\n    return limit\n"},
            {"name": "env-not-request",
             "code": "def h():\n    return int(os.environ.get(\"PORT\", 8080))\n"},
            {"name": "internal-dict-not-cast",
             "code": "def h(cfg):\n    return cfg.get(\"limit\", 50)\n"},
            {"name": "literal-int",
             "code": "def h():\n    return int(\"42\")\n"},
            {"name": "json-store-record-not-http",
             "code": "def _bump(self):\n"
                     "    data = json.loads(self.path.read_text(encoding=\"utf-8\"))\n"
                     "    total = int(data.get(\"total\", 0)) + 1\n"
                     "    return total\n"},
            {"name": "from-dict-desugar",
             "code": "def lock_from_dict(data):\n"
                     "    return ResourceLock(acquired_at=float(data.get(\"acquired_at\", 0.0)))\n"},
            {"name": "handler-with-internal-rebind",
             "code": "async def h(request):\n"
                     "    data = load_record()\n"
                     "    return int(data.get(\"count\", 0))\n"},
        ],
    }

    @staticmethod
    def _try_ranges(fn: ast.AST) -> list:
        spans = []
        for n in ast.walk(fn):
            if isinstance(n, ast.Try):
                lo = n.lineno
                hi = n.end_lineno or lo
                for h in n.handlers:
                    hi = max(hi, h.end_lineno or h.lineno)
                spans.append((lo, hi))
        return spans

    @staticmethod
    def _looks_like_input(call: ast.Call) -> bool:
        chain = call_chain(call) or ""
        low = chain.lower()
        return bool(REQ_SHAPE.match(low) or BODY_SHAPE.match(low) or DATA_SHAPE.match(low))

    @staticmethod
    def _input_kind(call: ast.Call) -> str:
        low = (call_chain(call) or "").lower()
        if REQ_SHAPE.match(low):
            return "request"
        if DATA_SHAPE.match(low):
            return "data"
        m = BODY_SHAPE.match(low)
        return m.group(1) if m else ""

    @staticmethod
    def _inbound_bound(fn: ast.AST, name: str) -> bool:
        """该名字在本函数内是否被入站来源赋值过（data = await request.json()）。"""
        if fn is None:
            return False
        for n in ast.walk(fn):
            if not isinstance(n, ast.Assign):
                continue
            if not any(isinstance(t, ast.Name) and t.id == name for t in n.targets):
                continue
            val = n.value
            if isinstance(val, ast.Await):
                val = val.value
            if not isinstance(val, ast.Call):
                continue
            low = (call_chain(val) or "").lower()
            if _is_inbound_source(val, low):
                return True
        return False

    @staticmethod
    def _internally_bound(fn: ast.AST, name: str) -> bool:
        """该名字在本函数内是否被内部来源（JSON 存档/文件读取/load*）赋值过。"""
        if fn is None:
            return False
        for n in ast.walk(fn):
            if isinstance(n, ast.Assign):
                targets = [t for t in n.targets if isinstance(t, ast.Name) and t.id == name]
                if not targets:
                    continue
                val = n.value
                if isinstance(val, ast.Await):
                    val = val.value
                chain = (call_chain(val) or "").lower() if isinstance(val, ast.Call) else ""
                if isinstance(val, ast.Call) and _is_inbound_source(val, chain):
                    continue
                if INTERNAL_BIND.match(chain):
                    return True
                func = getattr(val, "func", None)
                if isinstance(func, ast.Attribute) and func.attr in INTERNAL_ATTRS:
                    return True
                if isinstance(func, ast.Name) and re.match(r"^(load|_load|read_)", func.id):
                    return True
                if isinstance(val, ast.Attribute) and val.attr in INTERNAL_ATTRS:
                    return True
        return False

    @staticmethod
    def _scopes(root: ast.AST):
        """yield (node, innermost enclosing function or None)——避免嵌套函数重复发射。"""
        def visit(node, fn):
            inner = node if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) else fn
            for child in ast.iter_child_nodes(node):
                yield child, inner
                yield from visit(child, inner)
        yield from visit(root, None)

    def run(self, tree, profile, adapter) -> list:
        out = []
        module_spans = []
        for n in ast.walk(tree):
            if isinstance(n, ast.Try):
                module_spans.append((n.lineno, n.end_lineno or n.lineno))
        spans_by_fn: dict = {}
        for node, fn in self._scopes(tree):
            if not isinstance(node, ast.Call):
                continue
            f = node.func
            if not (isinstance(f, ast.Name) and f.id in CASTS):
                continue
            if not node.args:
                continue
            arg = node.args[0]
            if not (isinstance(arg, ast.Call) and self._looks_like_input(arg)):
                continue
            line = getattr(node, "lineno", 0)
            if fn is None:
                spans = module_spans
            else:
                key = id(fn)
                if key not in spans_by_fn:
                    spans_by_fn[key] = self._try_ranges(fn)
                spans = spans_by_fn[key] + module_spans
            if any(lo <= line <= hi for lo, hi in spans):
                continue
            kind = self._input_kind(arg)
            if kind == "request":
                pass
            elif self._internally_bound(fn, kind):
                continue
            elif kind == "data" and not self._inbound_bound(fn, "data"):
                # data 是通用局部名：没有入站赋值就不算请求体
                continue
            out.append(Finding(
                rule_id=self.id,
                file=str(getattr(tree, "path", "<memory>")),
                line=int(line),
                severity=self.severity,
                title=self.name,
                detail=f"{f.id}(...) 直接转换未守护的请求入参 {call_chain(arg) or ''}，"
                       "非数字值抛 ValueError → 全局 Exception 处理器回 500 并刷整栈日志",
                evidence="",
            ))
        return out
