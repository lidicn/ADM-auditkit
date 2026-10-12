"""py.json_envelope_ok_unchecked —— 信封响应只取数据、不看成败位。

来源：20261012 跨项目审计 X-02（AutoForge ↔ doubao-butler 的 ask 桥）。

【为什么是跨项目缺陷】本生态的服务端普遍返回统一信封 `{"ok": bool, ...}`，并且**在失败分支
也带一个合法的空数据**：现网实例——AutoForge `src/autoforge/af_api.py:680-687`
    try:  return {"ok": True,  "asks": [...]}
    except Exception:  # BUG-L1 修复：读失败不得静默返回 asks:[]
        return {"ok": False, "asks": [], "error": "read_failed"}
消费方 doubao-butler `butler/af_bridge.py:126-130`
    data = await r.json()          # 只查过 r.status >= 400（:121）
    asks = data.get("asks", [])    # ← 没有看 data["ok"]
⇒ 生产方**专门为零值加了 ok=False 的那条分支，在消费方被还原成"当前无待答"**：AF 侧读
pending_asks 失败时，管家把"读失败"当"没问题要答"，提问静默丢失——正是 af_api:684 注释里
点名要防的事，生产方修了自己那一半，消费方那一半没跟上。

【判据】同一函数内：
 1. 有 `X = <某>.json()` / `X = await <某>.json()` 的绑定；
 2. X 之后被读过（不是直接 return 的透明代理）；
 3. 该函数里**从未出现** "ok"/"success"/"status"/"error"/"code" 这几个信封位字面量。
⇒ 只看函数内的字符串常量，不跨函数推断；因此判据局部性成立，代价见下。

【已知假阳性面】
- 该函数只把 json() 结果透传/落盘，成败由调用方判（返回直传的已在 2. 抑制，跨函数的判不了）。
- 服务端本来就不带 ok 位的第三方 API（GitHub/HA 等）⇒ 空信封位 ⇒ 命中；这类需人工 reject。
【已知漏报面】
- 用 `resp["ok"]` 之外形态判成败（如判 `data.get("result") is None`、判 HTTP 码后直接抛）。
- 信封位检查写在另一个函数/中间件里。
"""
from __future__ import annotations

import ast

from engine.base import BaseRule, Finding

ENVELOPE_KEYS = ("ok", "success", "status", "error", "code")

# 入站解析（服务端 handler 读客户端 body）没有"信封成败位"这回事，不属于本类。
# round-215 实测：本规则在 doubao-butler 出 77 条 uniq 命中，其中绝大多数是
# `body = await request.json()`，属于误报形态，故按被调对象名排除。
INBOUND_OBJECTS = ("request", "req", "self.request")


class JsonEnvelopeOkUncheckedRule(BaseRule):
    id = "py.json_envelope_ok_unchecked"
    name = "信封响应未检查成败位（失败被当空集）"
    description = (
        "函数内解析了 .json() 响应并读取其字段，却全程未出现 ok/success/status/error/code "
        "任一信封位字面量：服务端返回 ok=False + 空数据时，调用方把失败读成「没有数据」"
    )
    applies_to = []
    mode = "static_ast"
    severity = "medium"
    status = "active"
    version = "1.1.0"
    intent = "discovery"

    tests = {
        "dirty": [
            {"name": "butler-asks-bridge",
             "code": "async def poll(session):\n"
                     "    async with session.get(url) as r:\n"
                     "        if r.status >= 400:\n"
                     "            raise RuntimeError('http')\n"
                     "        data = await r.json()\n"
                     "    return [a['ask_id'] for a in data.get('asks', [])]\n"},
            {"name": "sync-requests-json",
             "code": "def fetch(url, s):\n"
                     "    resp = s.get(url).json()\n"
                     "    return resp['items']\n"},
        ],
        "clean": [
            {"name": "checks-ok-flag",
             "code": "async def post_answer(session, url, body):\n"
                     "    async with session.post(url, json=body) as r:\n"
                     "        resp = await r.json()\n"
                     "        if not isinstance(resp, dict) or resp.get('ok') is not True:\n"
                     "            raise RuntimeError('rejected')\n"
                     "    return True\n"},
            {"name": "transparent-proxy",
             "code": "async def handler(request):\n"
                     "    payload = await request.json()\n"
                     "    return payload\n"},
            {"name": "inbound-handler-body-read",
             "code": "async def handler(request):\n"
                     "    body = await request.json()\n"
                     "    name = body['name']\n"
                     "    return {'saved': name}\n"},
            {"name": "reads-error-slot",
             "code": "def fetch(url, s):\n"
                     "    j = s.get(url).json()\n"
                     "    if j.get('error'):\n"
                     "        raise ValueError(j['error'])\n"
                     "    return j['data']\n"},
            {"name": "no-json-at-all",
             "code": "def parse(txt):\n"
                     "    d = json.loads(txt)\n"
                     "    return d.get('asks', [])\n"},
        ],
    }

    @staticmethod
    def _is_json_call(node: ast.AST) -> bool:
        if isinstance(node, ast.Await):
            node = node.value
        return (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                and node.func.attr == "json")

    @staticmethod
    def _call_object(node: ast.AST) -> str:
        """取 `.json()` 左侧对象名的点号链文本，用于分辨入站 request 与出站响应。"""
        if isinstance(node, ast.Await):
            node = node.value
        if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)):
            return ""
        parts = []
        cur = node.func.value
        while isinstance(cur, ast.Attribute):
            parts.append(cur.attr)
            cur = cur.value
        if isinstance(cur, ast.Name):
            parts.append(cur.id)
        return ".".join(reversed(parts)).lower()

    def run(self, tree, profile, adapter) -> list:
        out = []
        for fn in [n for n in ast.walk(tree)
                   if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]:
            bound = {}
            for node in ast.walk(fn):
                if isinstance(node, (ast.Assign, ast.AnnAssign)):
                    targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                    names = [t.id for t in targets if isinstance(t, ast.Name)]
                    if not (names and self._is_json_call(node.value)):
                        continue
                    if self._call_object(node.value) in INBOUND_OBJECTS:
                        continue
                    for nm in names:
                        bound[nm] = node
            if not bound:
                continue
            consts = set()
            used = set()
            returned_only = set()
            for node in ast.walk(fn):
                if isinstance(node, ast.Constant) and isinstance(node.value, str):
                    consts.add(node.value)
                if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load) and node.id in bound:
                    used.add(node.id)
                if isinstance(node, ast.Return) and isinstance(node.value, ast.Name) \
                        and node.value.id in bound:
                    returned_only.add(node.value.id)
            if consts & set(ENVELOPE_KEYS):
                continue
            for nm, node in bound.items():
                if nm not in used or nm in returned_only:
                    continue
                out.append(Finding(
                    rule_id=self.id,
                    file=str(getattr(tree, "path", "<memory>")),
                    line=int(getattr(node, "lineno", 0)),
                    severity=self.severity,
                    title=self.name,
                    detail=f"{nm} 取自 .json() 后被读取，但本函数未出现过 ok/success/status/error/code "
                           "任一信封位 ⇒ 服务端 ok=False 的空结果会被当\"确实没有数据\"",
                    evidence="",
                ))
        return out
