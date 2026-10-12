"""py.outbound_call_no_timeout —— 外部阻塞调用未设超时。

来源：AutoForge 20261011 审计；v1.2.0 修复 2026-10-11T14:56:47Z（commit 5382661）引入的自检回归；
v1.2.1 收敛 v1.2.0 放宽会话判定后暴露出的 `.get` 假阳性族。

【为什么重要】未设 timeout 的外部调用在对端挂死时会无限期阻塞调用方。本生态
管家(8095) / memory-agent(8086) / AutoForge / TVPilot / PosterWall 之间存在 HTTP
与子进程调用，一处挂死会拖住整条链，属稳定性缺陷。

【v1.2.0 相对 5382661 的三处变更】
1. 恢复 dirty 样本 `requests.get` 的覆盖面。5382661 为排除映射取值而加的
   `if tail == "get": return False` 位于 HTTP 动词判定**之前**，把 `requests.get`
   一并杀掉 ⇒ 该规则自己的 dirty 样本 dirty_miss ⇒ loader 标 broken ⇒
   runner 的 `active_rules = list(report.registry)` 不含它 ⇒ **该缺陷类从此零覆盖**。
   实测差分（同一 loader、同一验证门，只换文件版本）：
     6d92162（v1.1.0）  loaded=1 broken=0
     5382661（HEAD）    loaded=0 broken=1
2. `subprocess.Popen` 与 `subprocess.check_call` 移出目标集。容器内
   `inspect.signature` 实测：Popen / check_call 的签名**没有** timeout 形参
   （run / call / check_output 有）⇒ 报它们"未传 timeout"是不可修的假缺陷。
   原代码 `if tail == "popen": return False` 是小写比较、链尾实为 `Popen`，
   永不命中，属"意图写了但没生效"的死分支。
3. 放宽会话判定：原 `low.startswith("session.")` 漏掉 `self.session.get(...)` 写法。

【v1.2.1：`.get` 改为整词判定，动词仍按词根提示判定】
v1.2.0 用 `any(h in low for h in ("requests","session","httpx","aiohttp"))` 做**子串**匹配，
把 `.get` 这一族全放进了目标集。round-011 实测该族几乎全是映射取值假阳性：
  - doubao-butler `butler/integrations/ilink/client.py`：`self._session` 是 **dict**
    （同文件 `write_json_atomic(self.session_file, self._session)`、
      `self._session.get("baseurl", ILINK_BASE_URL)`），链名含 "session" 子串 ⇒ 命中；
  - 同类 `self._sessions.get(mid)` / `self.sessions.get(sid)` / `payload.get(k)`。
⇒ 现改为两条不同口径：
  - `get`：只有**被调用对象那一节**整名等于 HTTP 客户端词（requests/httpx/aiohttp/
    session/sess/...）才算出站。`_session`、`sessions`、`session_file` 因非整词而排除，
    `requests.get` / `ctx.session.get` / `httpx.get` 仍命中（保住 v1.2.0 修的回归）。
  - post/put/delete/patch/head/request：保留词根子串判定。原因是 `put` 与
    `queue.put` / 内部容器写操作同名，去掉子串闸会立刻造出大批假阳性；
    代价是 `client.post(...)` 这类别名变量成为**已知漏报面**（见下）。

【已知假阳性面（按判据局部性接受，留人工 triage）】
- 变量整名恰为 session / sess 的映射对象取值（`session.get("key")` 取 dict 值）。
- `requests` 作为变量名被用于非 HTTP 容器。

【v1.2.2：`sess` 从整名词表移除】
round-012 实测 memory-agent 两处 `sess` 都是**段/会话 dict**，不是 HTTP 会话：
  - `src/memory_agent/insights/utils.py:308` → `"room": sess.get("room", "")`
  - `scripts/_p2_smoke.py:48` → `len(sess.get("light.living", [])) == 1`
`sess` 在本生态同时是 "session dict" 与 "requests.Session" 两种身份，歧义不可判 ⇒
移除（代价并入下面的已知漏报面）。

【已知漏报面】
- `s = requests.Session()` / `sess = requests.Session()` 后 `s.get(url)`：别名层面不可判。
- `client.post(url)` / `api.get(url)`：词根提示表不含 client/api（为压 queue.put 假阳性付出的代价）。
- `subprocess.Popen(...).communicate()` 的阻塞：Popen 签名无 timeout 形参，按局部性不纳入。
"""
from __future__ import annotations

import ast

from engine.base import BaseRule, Finding, call_chain

URL_TAILS = ("urlopen", "urlretrieve")
# 仅纳入签名接受 timeout 的子进程入口（容器内 inspect.signature 实测）。
SUBPROC_TAILS = ("run", "call", "check_output")
# `.get` 单独口径：只认整名 HTTP 客户端，避免 dict 取值假阳性。
GET_TAIL = "get"
HTTP_OBJECT_NAMES = ("requests", "httpx", "aiohttp", "session",
                     "httpsession", "requests_session", "http_session")
VERB_TAILS = ("post", "put", "delete", "patch", "head", "request")
HTTP_SESSION_HINTS = ("requests", "session", "httpx", "aiohttp")
TIMEOUT_KEYS = ("timeout", "timeout_s", "timeout_seconds", "request_timeout")


class OutboundCallNoTimeoutRule(BaseRule):
    id = "py.outbound_call_no_timeout"
    name = "外部阻塞调用未设超时"
    description = (
        "urlopen / subprocess.run|call|check_output / requests|session|httpx|aiohttp 动词 / "
        "socket.create_connection 未传 timeout，对端挂死时调用方无限期阻塞"
    )
    applies_to = []
    mode = "static_ast"
    severity = "medium"
    status = "active"
    version = "1.2.2"

    tests = {
        "dirty": [
            {"name": "urlopen", "code": "def f(u):\n    return urllib.request.urlopen(u)\n"},
            {"name": "subprocess-run", "code": "def f(cmd):\n    return subprocess.run(cmd)\n"},
            {"name": "requests-get", "code": "def f(u):\n    return requests.get(u)\n"},
            {"name": "requests-post", "code": "def f(u, p):\n    return requests.post(u, json=p)\n"},
            {"name": "self-session-get", "code": "def f(u, ctx):\n    return ctx.session.get(u)\n"},
            {"name": "httpx-get", "code": "def f(u):\n    return httpx.get(u)\n"},
            {"name": "socket-conn", "code": "def f(addr):\n    return socket.create_connection(addr)\n"},
        ],
        "clean": [
            {"name": "urlopen-ok", "code": "def f(u):\n    return urllib.request.urlopen(u, timeout=30)\n"},
            {"name": "subprocess-ok", "code": "def f(cmd):\n    return subprocess.run(cmd, timeout=10)\n"},
            {"name": "requests-ok", "code": "def f(u):\n    return requests.get(u, timeout=5)\n"},
            {"name": "requests-timeout-var", "code": "def f(u, t):\n    return requests.get(u, timeout=t)\n"},
            {"name": "plain-call", "code": "def f(x):\n    return obj.run(x)\n"},
            {"name": "queue-join", "code": "def f(q):\n    return q.join()\n"},
            {"name": "dict-get", "code": "def f(payload):\n    return payload.get('k')\n"},
            {"name": "environ-get", "code": "def f(k):\n    return os.environ.get(k)\n"},
            {"name": "popen-no-timeout-kwarg", "code": "def f(cmd):\n    return subprocess.Popen(cmd)\n"},
            {"name": "check-call-no-timeout-kwarg", "code": "def f(cmd):\n    return subprocess.check_call(cmd)\n"},
            {"name": "underscore-session-get", "code": "def f(self, k):\n    return self._session.get(k, \"\")\n"},
            {"name": "sessions-plural-get", "code": "def f(self, mid):\n    return self._sessions.get(mid)\n"},
            {"name": "self-sessions-get", "code": "def f(self, sid):\n    return self.sessions.get(sid)\n"},
            {"name": "session-map-get", "code": "def f(session_map, k):\n    return session_map.get(k)\n"},
            {"name": "queue-put", "code": "def f(q, p):\n    return q.put(p)\n"},
            {"name": "session-file-get", "code": "def f(self):\n    return self.session_file.read()\n"},
            {"name": "sess-alias-dict-get", "code": "def f(sess, k):\n    return sess.get(k, '')\n"},
            {"name": "sess-dict-in-dict", "code": "def f(sess):\n    return {'room': sess.get('room', '')}\n"},
        ],
    }

    def _has_timeout(self, node: ast.Call) -> bool:
        return any((kw.arg or "") in TIMEOUT_KEYS for kw in node.keywords)

    @staticmethod
    def _object_segment(chain: str) -> str:
        parts = chain.split(".")
        return parts[-2].lower() if len(parts) >= 2 else ""

    def _is_target(self, chain: str) -> bool:
        if not chain:
            return False
        parts = chain.split(".")
        tail = parts[-1]
        low = chain.lower()
        if tail in URL_TAILS:
            return True
        if tail in SUBPROC_TAILS and "subprocess" in low:
            return True
        if tail == GET_TAIL:
            return self._object_segment(chain) in HTTP_OBJECT_NAMES
        if tail in VERB_TAILS and any(h in low for h in HTTP_SESSION_HINTS):
            return True
        if tail == "create_connection" and "socket" in low:
            return True
        return False

    def run(self, tree, profile, adapter) -> list:
        out = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            chain = call_chain(node)
            if not self._is_target(chain):
                continue
            if self._has_timeout(node):
                continue
            out.append(Finding(
                rule_id=self.id,
                file=str(getattr(tree, "path", "<memory>")),
                line=int(getattr(node, "lineno", 0)),
                severity=self.severity,
                title=self.name,
                detail=f"调用 {chain or '<call>'} 未传 timeout，外部调用可能无限期挂起",
                evidence="",
            ))
        return out
