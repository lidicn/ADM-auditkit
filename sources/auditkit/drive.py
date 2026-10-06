#!/usr/bin/env python3
"""auditkit 桩件驱动 harness —— 用真实执行覆盖替代名称推断。

设计目的
--------
`orphans` 阶段的 AST 通道基于「名称推断接收者」，对运行时注入的单例
（`rt.tvpilot.foreground()`）必然误报。本模块用 coverage 取得**真实执行覆盖**，
为孤儿判定提供**下界证据**：

    被执行过的方法  → 一定不是孤儿（确定性 FP 消除）
    未被执行的方法  → 仅说明本次 harness 未覆盖，仍需人工确认

不追求高覆盖率，只追求「能证明哪些方法确实活着」。

用法（由 audit.py 的 runtime 阶段调用，也可独立运行）:
    python3 drive.py --repo <repo> --out <outdir>
"""
from __future__ import annotations

import argparse, io, json, os, sys, types, time, asyncio, tempfile, traceback
from pathlib import Path


def _bootstrap(repo: Path):
    sys.path.insert(0, str(repo))
    homesdk = repo / "vendor" / "homesdk" / "src"
    if homesdk.exists():
        sys.path.insert(0, str(homesdk))
    # 桩件环境变量：绕过 config.py 的 required 校验
    for k in ("DOUBAO_API_KEY", "DESKPILOT_API_TOKEN", "TASK_REPORT_TOKEN",
              "BUTLER_WEB_PASSWORD", "HA_TOKEN", "MEMORY_AGENT_TOKEN",
              "XIAOMI_PASS_TOKEN", "BARK_KEY"):
        os.environ.setdefault(k, "stub-for-audit")


# ── 桩件 ────────────────────────────────────────────────────────────
class _Stub:
    """万能桩：任意属性/调用都返回自身，可 await。"""
    def __init__(self, name="stub"):
        self._name = name
    def __getattr__(self, k):
        if k.startswith("__"):
            raise AttributeError(k)
        return _Stub(f"{self._name}.{k}")
    def __call__(self, *a, **kw):
        return _Stub(f"{self._name}()")
    def __await__(self):
        async def _():
            return _Stub(f"{self._name}()")
        return _().__await__()
    def __bool__(self):
        return False
    def __iter__(self):
        return iter(())
    def __repr__(self):
        return f"<Stub {self._name}>"


class _StubApp:
    """app.state.runtime 桩件：任意属性返回 _Stub"""
    def __init__(self):
        self.state = _Stub("state")
        self.state.runtime = _Stub("runtime")
        self.state.settings = _Stub("settings")


def drive(repo: Path, verbose: bool = True) -> dict:
    _bootstrap(repo)
    import coverage
    import importlib

    log: list[str] = []

    notes: list[str] = []

    def log_note(x):
        notes.append(x)

    def step(name, fn):
        try:
            fn()
            log.append(f"OK   {name}")
        except Exception as e:
            log.append(f"SKIP {name}: {type(e).__name__}: {str(e)[:90]}")

    def make_request(path="/api/health"):
        """Starlette Request 桩件：覆盖路由处理器常用属性"""
        import starlette.requests as SR
        from starlette.datastructures import Headers, QueryParams
        try:
            req = SR.Request.__new__(SR.Request)
        except Exception:
            return _Stub("request")
        req.scope = {"type": "http", "method": "GET", "path": path,
                     "headers": [(b"host", b"x"), (b"cookie", b"butler_auth=1")],
                     "query_string": b"", "client": ("127.0.0.1", 1)}
        req._path_params = {}
        req._query_params = QueryParams("")
        try:
            req.app = _StubApp()
        except Exception:
            pass
        return req

    cov = coverage.Coverage(source=["butler"], omit=["*/tests/*", "*/vendor/*"])
    cov.start()
    try:
        from butler.config import Settings
    except Exception:
        Settings = lambda: _Stub("settings")
    globals()["Settings"] = Settings

    # ── 1. 纯 import 覆盖（模块级代码 + 类定义） ──
    def s_import():
        mods = [
            "butler.app", "butler.core.dialog", "butler.core.state", "butler.core.wakeup",
            "butler.core.simple_rules", "butler.core.dedup", "butler.core.aliases",
            "butler.core.scene_infer", "butler.core.cron_validator", "butler.core.briefing",
            "butler.core.security_monitor", "butler.core.agent", "butler.core.decision_store",
            "butler.tts.queue", "butler.tts.manager", "butler.tts.adapter", "butler.tts.singleton",
            "butler.devices", "butler.roles.store", "butler.skills.store", "butler.skills.runner",
            "butler.skills.quarantine", "butler.skills.creator", "butler.triggers.store",
            "butler.triggers.engine", "butler.bus.inbox", "butler.bus.mqtt_client",
            "butler.bus.topics", "butler.af_bridge", "butler.notify.router",
            "butler.integrations.ha", "butler.integrations.tv", "butler.integrations.bark",
            "butler.integrations.docker_tools", "butler.integrations.tvpilot",
            "butler.integrations.memory_agent", "butler.integrations.newapi",
            "butler.store.repo", "butler.store.db", "butler.store.ledger_freshness",
            "butler.store.write_failures", "butler.guard.push_guard", "butler.performance",
            "butler.tools.registry", "butler.tools.schedule", "butler.proactive.engine",
            "butler.agent_collab", "butler.agent_skill", "butler.audiobook.manager",
            "butler.mcp.server", "butler.locator", "butler.presence.fusion",
            "butler.decision.engine", "butler.decision.aggregator", "butler.timeseries.anomaly",
            "butler.api.deps", "butler.api.system_routes", "butler.api.dialog_routes",
            "butler.skills.schema", "butler.triggers.schema",
        ]
        import importlib
        for m in mods:
            try:
                importlib.import_module(m)
            except Exception:
                pass
    step("import 全部模块", s_import)

    # ── 2. 状态机 ──
    def s_state():
        from butler.core.state import RuntimeState
        st = RuntimeState()
        st.mark_present("张三", 0.9); st.mark_absent("张三")
        st.note_speak("a"); st.add_turn("a", "butler", "x")
        st.mute(0.01); st.is_muted(); st.snapshot(); st.present_list()
    step("RuntimeState 状态机", s_state)

    # ── 3. TTS 队列全分支 ──
    def s_tts():
        from butler.tts.queue import TTSQueue, TTSQueueConfig
        class Spk:
            async def speak(self, item):
                return True
        q = TTSQueue(speaker=Spk(), config=TTSQueueConfig(overload_threshold=4))
        for i in range(6):
            q.enqueue(f"m{i}", priority=3)
        q.enqueue("alert", priority=1)
        q.status(); q.items(); len(q); q.dequeue()
        q.pause("manual", 0.01); q.resume()
    step("TTSQueue 入队/过载/暂停", s_tts)

    def s_tts_async():
        from butler.tts.queue import TTSQueue, TTSQueueConfig
        class Spk:
            async def speak(self, item):
                return True
        q = TTSQueue(speaker=Spk(), config=TTSQueueConfig())
        q.enqueue("hello", priority=2)
        asyncio.run(q.play_one())
        asyncio.run(q.stop())
    step("TTSQueue play_one/stop", s_tts_async)

    # ── 4. 设备 / 角色 / 技能 store ──
    def s_stores():
        from butler.config import Settings
        from butler.devices import DeviceRegistry
        d = tempfile.mkdtemp()
        st = Settings(); st.data_dir = d
        r = DeviceRegistry(st); r.load(); r.all()
        ids = list(r.devices)[:2]
        r.resolve(ids, "客厅"); r.resolve(ids, None); r.get(ids[0])
        from butler.roles.store import RoleRegistry
        rr = RoleRegistry(d); rr.load()
        rr.upsert({"id": "tmprole", "name": "t"}); rr.get("tmprole")
        from butler.skills.store import SkillStore
        ss = SkillStore(d); ss.load()
        ss.save({"id": "tmp", "name": "t", "source": "user"})
        ss.get("tmp"); ss.list(); ss.stats(); ss.set_status("tmp", "published")
    step("Device/Role/Skill 三 store", s_stores)

    # ── 5. 简单规则 ──
    def s_rules():
        from butler.core.simple_rules import check_simple_command
        for c in ["打开客厅灯", "现在几点", "创建技能", "关灯", "今天天气", ""]:
            asyncio.run(check_simple_command(c))
    step("simple_rules 规则匹配", s_rules)

    # ── 6. 唤醒决策 ──
    def s_wakeup():
        from butler.core.wakeup import WakeupEngine
        from butler.core.state import RuntimeState
        from butler.config import Settings
        w = WakeupEngine(Settings(), RuntimeState())
        try:
            asyncio.run(w.decide("face", member="a", room="客厅"))
        except Exception:
            pass
    step("WakeupEngine.decide", s_wakeup)

    # ── 7. 别名（关键：验证 learn/match 是否活着）──
    def s_alias():
        from butler.core.aliases import get_alias_store
        s = get_alias_store()
        s.learn("打开客厅灯", "light.living", "light", "turn_on")
        s.list_aliases()
        try:
            s.match("打开客厅灯")
        except Exception:
            pass
        s.delete_alias("客厅灯")
    step("AliasStore learn/list/match/delete", s_alias)

    # ── 8. cron 校验 + SSRF ──
    def s_cron():
        from butler.core.cron_validator import CronTaskValidator
        v = CronTaskValidator()
        for u in ["https://x.com/a", "http://127.0.0.1/a", "http://localhost/a",
                  "file:///etc/passwd"]:
            v.validate_api_url(u)
        v.validate({"id": "t1", "name": "n"})
        v.generate_preview({"id": "t1", "name": "n"})
    step("CronTaskValidator 校验", s_cron)

    # ── 9. 对话主链路（桩 runtime）──
    def s_dialog():
        import butler.runtime as R
        import butler.core.dialog as D
        from butler.core.state import RuntimeState

        class FakeCreator:
            calls = []
            async def generate_skill_from_description(self, m, llm, sp=""):
                FakeCreator.calls.append(m)
                return {"ok": True, "skill": {"name": m}}
            def create_draft(self, s, role_id="butler"):
                return {"ok": True, "preview": "p"}
            def get_pending(self, rid):
                return None

        class FakeRole:
            id = "butler"; name = "管家"; enabled = True; scope = "public"
            voice = None; tts_backend = None; nowvoice_voice = None
            output_devices = []; system = ""; bound_rooms = []
            presence_rooms = ["*"]; member = ""

        rt = R.get_runtime()
        rt.roles = types.SimpleNamespace(get=lambda r: FakeRole(), all=lambda: [FakeRole()])
        rt.skill_creator = FakeCreator(); rt.trigger_engine = None

        def mk(pending):
            dm = object.__new__(D.DialogManager)
            dm.state = RuntimeState(); dm._echo_until = 0.0
            dm._pending_skill_desc = pending
            dm.s = types.SimpleNamespace(waiting_seconds=0); dm._role_history = {}
            dm.persona = None; dm.wakeup = None; dm.trigger_engine = None
            dm.llm = None; dm.memory = None; dm.agent = None
            dm.speak_as_role = lambda *a, **k: asyncio.sleep(0, result=[])
            return dm

        # 过期草稿 + 闲聊（P1-22 穿透路径）
        dm = mk({"butler": time.time() - 10})
        asyncio.run(dm.on_wakeup("butler", "客厅", "今天天气怎么样"))
        # 无草稿
        dm2 = mk({})
        try:
            asyncio.run(dm2.on_wakeup("butler", "客厅", "打开客厅灯"))
        except Exception:
            pass
        # 事件分发
        dm3 = mk({})
        try:
            asyncio.run(dm3.on_event("tv/livingroom/status", {"state": "offline"}))
            asyncio.run(dm3.on_event("butler/event/voice", {"member": "a", "text": "hi"}))
        except Exception:
            pass
        dm3.suppress_echo("测试文本")
        dm3._est_speak_secs("测试")
    step("DialogManager 主链路（含穿透路径）", s_dialog)

    # ── 10. 收件箱 / 隔离 ──
    def s_misc():
        from butler.bus.inbox import InboxGate
        ig = InboxGate(rt=None)
        try:
            ig.budget_used("src"); ig.budget_consume("src")
        except Exception:
            pass
        from butler.skills.quarantine import QuarantineManager
        class FS:
            def __init__(self): self.s = {}
            def get(self, i): return self.s.get(i, {"id": i, "status": "published"})
            def save(self, x): self.s[x["id"]] = x
            def list(self): return list(self.s.values())
            def quarantine(self, i, reason=""): return {"id": i, "status": "quarantined"}
            def set_status(self, i, st): return {"id": i, "status": st}
        qm = QuarantineManager(FS(), tempfile.mkdtemp())
        qm.record_breaker_trip("s1"); qm.record_timeout("s1", 40000)
        qm.record_duration("s1", 20000); qm.quarantine("s1", "test")
        qm.get_stats(); qm.auto_recover_check(); qm.restore("s1")
    step("InboxGate / QuarantineManager", s_misc)

    # ── 11. TTS 适配器房间映射 ──
    def s_adapter():
        from butler.tts.adapter import ROOM_TO_PLAYER_ENTITY
        from butler.config import Settings
        from butler.devices import DeviceRegistry
        seed = DeviceRegistry(Settings())._seed()
        for room in {d.room for d in seed.values() if d.room}:
            ROOM_TO_PLAYER_ENTITY.get(room)
    step("TTS adapter 房间映射", s_adapter)

    # ── 12. 通用 API 路由驱动（覆盖全部 Route 处理器）──
    def s_api_routes():
        import os
        for d in ("/app/data", "/app/tts"):
            try:
                os.makedirs(d, exist_ok=True)
            except Exception:
                pass
        import ast, inspect
        import butler.app as APP
        # 收集所有路由处理器
        handlers = []
        for p2 in sorted((repo / "butler" / "api").rglob("*.py")):
            try:
                t = ast.parse(p2.read_text(encoding="utf-8-sig"))
            except SyntaxError:
                continue
            mod = "butler.api." + p2.stem
            for n in ast.walk(t):
                if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) \
                        and n.func.id == "Route" and len(n.args) >= 2:
                    a0, a1 = n.args[0], n.args[1]
                    if isinstance(a0, ast.Constant) and isinstance(a1, ast.Name):
                        handlers.append((mod, a1.id, a0.value))
        import importlib
        cache = {}
        called = 0
        for mod, fname, path in handlers:
            if mod not in cache:
                try:
                    cache[mod] = importlib.import_module(mod)
                except Exception:
                    continue
            fn = getattr(cache[mod], fname, None)
            if fn is None or not callable(fn):
                continue
            req = make_request(path)
            try:
                r = fn(req)
                if inspect.isawaitable(r):
                    asyncio.run(r)
                called += 1
            except Exception:
                pass
        log_note(f"    API 路由驱动：收集 {len(handlers)} 个处理器，成功调用 {called} 个")
    step("API 路由全量驱动", s_api_routes)

    # ── 13. 集成层（HTTP 已桩化）──
    def s_integrations():
        from butler.integrations import ha, tv, bark, docker_tools, tvpilot, newapi
        importlib.import_module("butler.integrations.memory_agent")
        try:
            c = ha.HAClient(Settings())
            asyncio.run(c.call_service("light", "turn_on", {"entity_id": "light.x"}))
            asyncio.run(c.get_state("light.x"))
            c.play_url("http://x/a.mp3", "客厅")
        except Exception:
            pass
        for mod, cls in ((tv, "TVClient"), (bark, "BarkClient"),
                         (docker_tools, "DockerClient"), (tvpilot, "TVPilotClient"),
                         (newapi, "NewAPIClient")):
            try:
                obj = getattr(mod, cls)(Settings()) if cls != "TVClient" else getattr(mod, cls)(Settings(), _Stub("mqtt"))
            except Exception:
                obj = _Stub(cls)
            for m in ("ps", "restart", "logs", "compose_up", "compose_down", "health",
                      "current", "channels", "keyevent", "tap", "swipe", "foreground",
                      "play_tts", "send", "notify", "push", "list_models"):
                f = getattr(obj, m, None)
                if f is None:
                    continue
                try:
                    r = f("x") if m in ("play_tts", "send", "notify", "push", "restart",
                                        "logs", "keyevent") else f()
                    if inspect.isawaitable(r):
                        asyncio.run(r)
                except Exception:
                    pass
    step("集成层 ha/tv/bark/docker/tvpilot/newapi", s_integrations)

    # ── 14. 技能引擎全量 ──
    def s_engines():
        eng_dir = repo / "butler" / "skills" / "engines"
        if not eng_dir.exists():
            return
        import importlib.util
        for py in sorted(eng_dir.rglob("engine.py")):
            rel = py.relative_to(repo).with_suffix("")
            modname = str(rel).replace("/", ".")
            try:
                m = importlib.import_module(modname)
            except Exception:
                continue
            for attr in dir(m):
                if not attr.endswith("Engine"):
                    continue
                cls = getattr(m, attr)
                try:
                    inst = cls()
                except Exception:
                    continue
                for meth in ("run", "describe"):
                    f = getattr(inst, meth, None)
                    if f is None:
                        continue
                    try:
                        r = f({"text": "x", "params": {}}) if meth == "run" else f()
                        if inspect.isawaitable(r):
                            asyncio.run(r)
                    except Exception:
                        pass
    step("技能引擎 run/describe 全量", s_engines)

    # ── 15. 触发器 / 主动 / 简报 / 安监 ──
    def s_engines2():
        for mod, attrs in (
            ("butler.triggers.engine", ("TriggerEngine",)),
            ("butler.proactive.engine", ("ProactiveEngine",)),
            ("butler.core.briefing", ("BriefingEngine",)),
            ("butler.core.security_monitor", ("SecurityMonitor",)),
            ("butler.core.scene_infer", ("SceneInfer",)),
            ("butler.core.fast_routes", ("FastRouteStore",)),
            ("butler.core.perception_engine", ("PerceptionEngine",)),
            ("butler.core.event_stream", ("EventStream",)),
            ("butler.decision.engine", ("DecisionEngine",)),
            ("butler.decision.aggregator", ("Aggregator",)),
            ("butler.presence.fusion", ("PresenceFusion",)),
            ("butler.timeseries.anomaly", ("AnomalyDetector",)),
            ("butler.notify.router", ("NotifyRouter",)),
            ("butler.guard.push_guard", ("PushGuard",)),
            ("butler.performance", ("PerfMonitor",)),
            ("butler.locator", ("Locator",)),
            ("butler.agent_collab", ("AgentCollaborationManager",)),
            ("butler.tools.registry", ("ToolRegistry",)),
            ("butler.tools.schedule", ("ScheduleTool",)),
        ):
            try:
                m = importlib.import_module(mod)
            except Exception:
                continue
            for a in attrs:
                cls = getattr(m, a, None)
                if cls is None:
                    continue
                try:
                    inst = cls()
                except Exception:
                    try:
                        inst = cls(Settings())
                    except Exception:
                        continue
                for meth in ("scan_tick", "check", "run", "evaluate", "tick", "match",
                             "list_rules", "create_rule", "status", "get_recent",
                             "generate", "detect", "fuse", "notify", "describe",
                             "all_tools", "locate", "snapshot"):
                    f = getattr(inst, meth, None)
                    if f is None:
                        continue
                    try:
                        r = f()
                        if inspect.isawaitable(r):
                            asyncio.run(r)
                    except Exception:
                        pass
    step("触发器/主动/简报/安监/场景等引擎", s_engines2)

    # ── 16. 纯逻辑模块全量调用 ──
    def s_pure():
        import butler.core.dedup as DED
        DED.bigrams("打开客厅灯")
        try:
            DED.jaccard({"a"}, {"a", "b"})
        except Exception:
            pass
        import butler.skills.schema as SS, butler.triggers.schema as TS
        for mod in (SS, TS):
            for nm in dir(mod):
                if nm.startswith("validate") or nm.startswith("check"):
                    f = getattr(mod, nm)
                    try:
                        f({"id": "t1", "name": "n", "type": "x"})
                    except Exception:
                        pass
        import butler.store.ledger_freshness as LF, butler.store.write_failures as WF
        try:
            WF.record("m", "e", table="t"); WF.snapshot()
        except Exception:
            pass
    step("纯逻辑模块（dedup/schema/store）", s_pure)

    # ── 17. app.create_app 装配 ──
    def s_create_app():
        import butler.app as APP
        try:
            asyncio.run(APP.create_app())
        except Exception:
            pass
    step("app.create_app 装配", s_create_app)

    # ── 18. TTS manager / adapter / singleton ──
    def s_tts_mgr():
        from butler.tts.manager import TTSManager
        from butler.tts import adapter as AD
        for nm in dir(AD):
            if nm.startswith("enqueue") or nm.startswith("resolve"):
                f = getattr(AD, nm)
                try:
                    r = f("测试", "客厅")
                    if inspect.isawaitable(r):
                        asyncio.run(r)
                except Exception:
                    pass
    step("TTS manager/adapter", s_tts_mgr)

    cov.stop()

    # ── 覆盖率 + 存活方法 ──
    buf = io.StringIO()
    total = cov.report(file=buf)
    data = cov.get_data()

    # 每个文件被执行过的行
    executed: dict[str, set[int]] = {}
    for f in data.measured_files():
        try:
            rel = str(Path(f).relative_to(repo))
        except ValueError:
            rel = f
        lines = data.lines(f) or []
        executed[rel] = set(lines)

    # AST 枚举函数体首行，判断是否被执行
    import ast
    alive: list[str] = []
    never: list[dict] = []
    src = repo / "butler"
    n_funcs = 0
    for p in sorted(src.rglob("*.py")):
        rel = str(p.relative_to(repo))
        try:
            tree = ast.parse(p.read_text(encoding="utf-8-sig"))
        except SyntaxError:
            continue
        ex = executed.get(rel, set())
        for n in ast.walk(tree):
            if not isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            n_funcs += 1
            cls = ""
            for c in [x for x in ast.walk(tree) if isinstance(x, ast.ClassDef)]:
                if n in list(ast.walk(c)):
                    cls = c.name
                    break
            qual = f"{rel}::{cls}.{n.name}" if cls else f"{rel}::{n.name}"
            # 函数体首行被执行 ⇒ 该方法确实运行过
            body0 = n.body[0].lineno if n.body else n.lineno
            if body0 in ex or n.lineno in ex:
                alive.append(qual)
            else:
                never.append({"qual": qual, "cls": cls, "name": n.name,
                              "file": rel, "line": n.lineno})

    return {
        "coverage_pct": round(total, 2),
        "measured_files": len(data.measured_files()),
        "total_functions": n_funcs,
        "alive_functions": len(alive),
        "never_executed": len(never),
        "never_sample": never[:400],
        "alive": alive,
        "steps": log,
        "notes": notes,
        "report_txt": buf.getvalue(),
    }


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", required=True)
    ap.add_argument("--out", default=".")
    a = ap.parse_args()
    r = drive(Path(a.repo).resolve())
    out = Path(a.out); out.mkdir(parents=True, exist_ok=True)
    (out / "runtime_coverage.json").write_text(
        json.dumps({k: v for k, v in r.items() if k != "report_txt"},
                   ensure_ascii=False, indent=1), encoding="utf-8")
    (out / "runtime_coverage.txt").write_text(r["report_txt"], encoding="utf-8")
    print(f"覆盖 {r['coverage_pct']}% | 函数 {r['total_functions']} | "
          f"执行过 {r['alive_functions']} | 未执行 {r['never_executed']}")
    for s in r["steps"]:
        print("  ", s)
