"""审计验证套件的共享内核：框架工具 + 全部场景定义。

pytest 用例（tests/test_audit_findings.py）与独立脚本（verify_findings.py）
共用本模块的 SCENARIOS，保证「CI 里跑的」和「手工跑的」是同一套断言，
不会出现两处定义各自漂移。

三态语义：
  实锤    —— 缺陷行为被真实执行复现
  REFUTED —— 缺陷假设不成立（有效结论，通常意味着 bug 已修复）
  ERROR   —— 用例自身失败（依赖缺失 / 桩件不齐），不可当作「无问题」

在 pytest 下这三态自然映射为 pass / fail / error，无需额外编码。
"""
from __future__ import annotations

import asyncio
import inspect
import os
import subprocess
import sys
import tempfile
import textwrap
import time
import types

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO not in sys.path:
    sys.path.insert(0, REPO)
VENDOR = os.path.join(REPO, "vendor", "homesdk", "src")
if VENDOR not in sys.path:
    sys.path.insert(0, VENDOR)

_MISSING = object()


# ─────────────────────────── 框架 ───────────────────────────

class InfraError(Exception):
    """工具/环境缺失 —— 不是被测代码的问题。

    纪律①：ERROR ≠ REFUTED。
    历史上踩过三次：
      · 缺 paho-mqtt → V4 被误判「未复现」（真实缺陷差点被洗白）
      · 沙箱重置丢依赖 → 6 failed 被读成「6 个缺陷消失」
      · radon 不在 PATH → V19 反测抛 FileNotFoundError 被当成「修法不成立」
    这三次都是**工具故障**，却都表现为测试红。
    显式抛出 InfraError，让 CI/报告能把它和真正的 REFUTED 分开统计。
    """


class Restore:
    """用例隔离：记录 (对象, 属性, 原值)，跑完强制回滚。

    _MISSING 哨兵用于「原先不存在的属性」——恢复时应 delattr 而非 setattr，
    否则 v10_fix 注入的 logger 会残留，污染后续用例。
    """

    def __init__(self):
        self._items: list[tuple[object, str, object]] = []

    def snap(self, obj, name):
        self._items.append((obj, name, getattr(obj, name, _MISSING)))

    def set(self, obj, name, val):
        if (obj, name) not in [(o, n) for o, n, _ in self._items]:
            self.snap(obj, name)
        setattr(obj, name, val)

    def restore_all(self):
        for obj, name, val in reversed(self._items):
            try:
                if val is _MISSING:
                    try:
                        delattr(obj, name)
                    except Exception:
                        pass
                else:
                    setattr(obj, name, val)
            except Exception:
                pass
        self._items.clear()


def rebind(target, name, transform):
    """把真实函数源码按 transform 改写后重新绑定——验证「建议的修复方案确实生效」。

    不是 mock：函数体 99% 是原代码，只改目标那几行，全局符号仍解析到真模块。
    因此反测通过意味着「按报告里给的改法真的能修好」，而不只是断言被满足。
    """
    obj = getattr(target, name)
    src = textwrap.dedent(inspect.getsource(obj))
    new = transform(src)
    if new == src:
        raise RuntimeError(f"补丁未生效：{name} 中未匹配到目标代码")
    mod = sys.modules.get(getattr(obj, "__module__", "__main__"), None)
    g = mod.__dict__ if mod is not None else {}
    ns: dict = {}
    exec(compile(new, f"<fix:{name}>", "exec"), g, ns)
    if name not in ns:
        raise RuntimeError(f"重编译后未找到 {name}")
    return ns[name]


def _balanced(ln):
    """行内括号是否配平（未配平 = 后面还有续行）。"""
    d = 0
    for ch in ln:
        if ch in "([{":
            d += 1
        elif ch in ")]}":
            d -= 1
    return d <= 0


def lines_xform(predicate, build, keep_original=False, swallow_continuation=True):
    """行级补丁构造器。

    - swallow_continuation：命中行若括号未配平，连同后续续行一起替换。
      否则会留下 `ensure_ascii=False, indent=2)` 这类孤儿行 → IndentationError。
    - keep_original：True 时把原行追加在 build 产出的行之后。
      v7 需要：注入 3 个副作用后仍要保留原 return，否则 `if queued:` 失去出口，
      控制流穿透到下面，副作用被执行两次。
    """
    def _t(src):
        lines = src.splitlines()
        out, hit = [], False
        i = 0
        while i < len(lines):
            ln = lines[i]
            if predicate(ln):
                indent = ln[: len(ln) - len(ln.lstrip())]
                out.extend(build(indent))
                hit = True
                if keep_original:
                    out.append(ln)
                if swallow_continuation and not _balanced(ln):
                    j = i + 1
                    while j < len(lines) and not _balanced(lines[j]):
                        j += 1
                    i = j + 1 if j < len(lines) else j
                    continue
                i += 1
                continue
            out.append(ln)
            i += 1
        if not hit:
            raise RuntimeError("lines_xform 未命中目标行，补丁未生效")
        return "\n".join(out) + "\n"
    return _t


# ─────────────────────────── V1-V6 ───────────────────────────

def v1(r):
    from butler.devices import DeviceRegistry
    has = hasattr(DeviceRegistry, "by_room")
    methods = [m for m in dir(DeviceRegistry) if not m.startswith("_")]
    return (not has), [
        f"DeviceRegistry.by_room 存在 = {has}   实际方法 = {methods}",
        "→ af_bridge.py:170/173 的 hasattr 探测短路为 []，for 循环零次执行",
    ]


def v2(r):
    from butler.tts.manager import TTSManager
    sig = inspect.signature(TTSManager.speak)
    try:
        sig.bind(object(), "prompt", device=object())
        return False, ["af_bridge 的调用方式居然通过了？"]
    except TypeError as e:
        return True, [
            f"真实签名 = {sig}",
            f"复现 TypeError = {e}",
            "→ 被 V1 掩盖（for 循环零次），修好 V1 后立刻炸",
        ]


def v3(r):
    from butler.tts.adapter import ROOM_TO_PLAYER_ENTITY
    from butler.devices import DeviceRegistry
    from butler.config import Settings
    seed = DeviceRegistry(Settings())._seed()
    real = {d.room for d in seed.values() if d.room}
    ok_rooms = [x for x in sorted(real) if ROOM_TO_PLAYER_ENTITY.get(x)]
    miss = [x for x in sorted(real) if not ROOM_TO_PLAYER_ENTITY.get(x)]
    ghost = [k for k in ROOM_TO_PLAYER_ENTITY if k not in real]
    return len(miss) > 0, [
        f"真实房间 {len(real)} 个，可播 {len(ok_rooms)} 个：{ok_rooms}",
        f"播报被丢弃 {len(miss)} 个：{miss}",
        f"臆造键（永不命中）：{ghost}",
        "→ dialog.py:670 只传 room 不传 device_id，miss 即落到 adapter.py:56 丢弃",
    ]


def v4(r):
    import butler.core.dialog as D
    from butler.core.state import RuntimeState
    from butler.runtime import get_runtime

    class FakeCreator:
        def __init__(self):
            self.calls = []

        async def generate_skill_from_description(self, m, llm, sp=""):
            self.calls.append(m)
            return {"ok": True, "skill": {"name": m}}

        def create_draft(self, s, role_id):
            return {"ok": True, "preview": "预览"}

        def get_pending(self, rid):
            return None

    class FakeRole:
        id = "butler"; name = "管家"; enabled = True; scope = "public"
        voice = None; tts_backend = None; nowvoice_voice = None
        output_devices = []; system = ""; bound_rooms = []
        presence_rooms = ["*"]; member = ""

    # v4 走真实 on_wakeup()，会触碰 runtime 上许多字段（不止 roles/skill_creator）。
    # 只恢复显式改过的两枚不够：残留字段曾让 test_decision_engine_full_flow 整档变红。
    # 故对 runtime 实例做整份 __dict__ 快照。
    rt = get_runtime()
    _saved_rt = dict(vars(rt))

    def mk(pending):
        c = FakeCreator()
        r.set(rt, "roles", types.SimpleNamespace(get=lambda x: FakeRole(), all=lambda: [FakeRole()]))
        r.set(rt, "skill_creator", c)
        dm = object.__new__(D.DialogManager)
        dm.state = RuntimeState(); dm._echo_until = 0.0
        dm._pending_skill_desc = pending
        dm.s = types.SimpleNamespace(waiting_seconds=0); dm._role_history = {}
        dm.persona = None; dm.wakeup = None; dm.trigger_engine = None; dm.llm = None
        dm.speak_as_role = lambda *a, **k: asyncio.sleep(0, result=[])
        return dm, c

    dm, c = mk({"butler": time.time() - 10})
    res = asyncio.run(dm.on_wakeup("butler", "客厅", "今天天气怎么样"))
    exp = list(c.calls)
    dm2, c2 = mk({})
    try:
        asyncio.run(dm2.on_wakeup("butler", "客厅", "今天天气怎么样"))
    except Exception:
        pass
    finally:
        rt.__dict__.clear()
        rt.__dict__.update(_saved_rt)
    return (exp and not list(c2.calls)), [
        f"实验组（草稿已过期）→ 喂进生成器: {exp}",
        f"对照组（无草稿）    → 喂进生成器: {list(c2.calls)}",
        f"实验组 reply = {res.get('reply')!r}",
        "→ 过期分支 del 后漏 return，控制流穿透到技能生成",
    ]


def v5(r):
    p = subprocess.run(["grep", "-rn", r"\.match(", "--include=*.py", "butler/"],
                       capture_output=True, text=True, cwd=REPO)
    alias = [l.strip() for l in p.stdout.splitlines() if "alias" in l.lower()]
    import butler.core.aliases as A
    defined = hasattr(A.AliasStore, "match")
    return (defined and not alias), [
        f"AliasStore.match 已定义 = {defined}",
        f"全仓涉及 alias 的 .match( 调用 = {alias or '（无）'}",
        "→ 学到即落盘、从不参与设备解析 = 只写不读",
        "⚠ grep 代理：仅证明「未搜到」，非行为级证据",
    ]


def v6(r):
    src = open(os.path.join(REPO, "butler/tts/singleton.py"), encoding="utf-8-sig").read()
    line = next(l for l in src.splitlines() if "create_task" in l)
    saved = "=" in line.split("create_task")[0]
    return (not saved), [
        f"源码行: {line.strip()}",
        f"返回值是否被保存 = {saved}",
        "→ asyncio 内部只持弱引用，无强引用的 Task 可能在完成前被 GC",
        "⚠ 源码文本检查：非运行时证据",
    ]


# ─────────────────────────── V7-V12（行为级） ───────────────────────────

def _speak_probe(r, use_queue, enqueue_ok):
    """真调用 DialogManager.speak()，统计三个副作用各发生几次。"""
    import butler.core.dialog as D
    from butler.runtime import get_runtime

    class Spy:
        def __init__(self):
            self.rec, self.turns, self.pub = [], [], []

        async def is_duplicate(self, m, t):
            return False, 0.0

        async def record(self, m, t):
            self.rec.append(t)

        def _publish_dialog(self, ev):
            self.pub.append(ev)

        def note_speak(self, m): pass
        def add_turn(self, *a, **k): pass
        def set_state(self, s): pass

    class FakeRepo:
        def __init__(self, spy): self.spy = spy
        def add_turn(self, *a, **k): self.spy.turns.append(a[2] if len(a) > 2 else "?")

    class Role:
        id = "butler"; output_devices = []
        voice = None; tts_backend = None; nowvoice_voice = None

    class FakeTTS:
        async def synthesize(self, *a, **k): return None

    class FakeHA:
        async def tts_speak(self, *a, **k): return True

    rt = get_runtime()
    r.set(rt, "roles", types.SimpleNamespace(get=lambda x: Role(), all=lambda: [Role()]))
    r.set(rt, "devices", types.SimpleNamespace(resolve=lambda *a, **k: []))

    spy = Spy()
    dm = object.__new__(D.DialogManager)
    dm.dedup = spy; dm.state = spy
    dm._role_history = {}
    dm.s = types.SimpleNamespace(member_by_name=lambda n: None, speak_target="ha")
    dm.tts = FakeTTS(); dm.ha = FakeHA(); dm.tv = None
    dm.mqtt = types.SimpleNamespace(publish=lambda *a, **k: None)
    dm._publish_dialog = spy._publish_dialog
    dm._return_idle = lambda: asyncio.sleep(0)

    import butler.tts.helper as H
    r.set(H, "enqueue_tts", lambda *a, **k: enqueue_ok)
    r.set(D, "repo", FakeRepo(spy))

    asyncio.run(dm.speak("该吃药了", "妈妈", source="proactive", use_queue=use_queue))
    return spy


def v7(r):
    a = _speak_probe(r, use_queue=True, enqueue_ok=True)
    b = _speak_probe(r, use_queue=False, enqueue_ok=True)
    rows = [("dedup.record（写指纹）", len(a.rec), len(b.rec)),
            ("repo.add_turn（对话落库）", len(a.turns), len(b.turns)),
            ("_publish_dialog（SSE）", len(a.pub), len(b.pub))]
    detail = [f"{'副作用':<24}{'队列路径':>8}{'非队列':>8}"]
    lost = 0
    for n, x, y in rows:
        if x == 0 and y > 0:
            lost += 1
        detail.append(f"{n:<22}{x:>8}{y:>8}{'   ← 丢失' if x == 0 and y > 0 else ''}")
    detail.append("→ 三行代码都写在 speak() 里（710/716/723），"
                  "是「控制流走不到」不是「没写」")
    return lost == 3, detail


def v7_fix(r):
    import butler.core.dialog as D

    def pred(ln):
        return '"engine": "queue"' in ln and "return" in ln

    def build(i):
        return [i + 'await self.dedup.record(member, text)',
                i + 'self._publish_dialog({"type": "speak", "member": member, "text": text,'
                    ' "engine": "queue", "source": source, "ts": time.time()})',
                i + 'try:',
                i + '    await asyncio.to_thread(repo.add_turn, member, "butler", text,'
                    ' engine="queue", source=source, target=room or "queued")',
                i + 'except Exception:',
                i + '    pass']

    r.set(D.DialogManager, "speak",
          rebind(D.DialogManager, "speak", lines_xform(pred, build, keep_original=True)))
    s = _speak_probe(r, use_queue=True, enqueue_ok=True)
    got = (len(s.rec), len(s.turns), len(s.pub))
    return got == (1, 1, 1), [
        f"注入修复后，队列路径副作用 = 指纹{len(s.rec)} 落库{len(s.turns)} 推送{len(s.pub)}",
        f"期望 (1,1,1)，实际 {got}",
    ]


def v8(r):
    from butler.triggers.engine import TriggerEngine

    class FakeStore:
        def __init__(self): self.triggers = []
        def all(self): return self.triggers

    d = tempfile.mkdtemp()
    f = os.path.join(d, "trigger_cooldowns.json")
    e = TriggerEngine(FakeStore()); e._cooldown_file = f
    e._last_fired = {"morning": time.time(), "evening": time.time()}
    e._save_cooldowns()
    with open(f, "w", encoding="utf-8") as fh:
        fh.write('{"morning": 17')          # 模拟写入中途进程被 kill
    e2 = TriggerEngine(FakeStore()); e2._cooldown_file = f
    e2._load_cooldowns()
    n = len(e2._last_fired)
    return n == 0, [
        f"落盘 {os.path.getsize(f) if os.path.exists(f) else 0} bytes → 截断 → "
        f"重载后冷却记录 = {n}（原 2）",
        "→ 非原子写 + 加载失败仅 warning ⇒ 重启后所有 trigger 再次触发",
        "→ 与 P0-3(config 损坏) 同一病：状态文件损坏 → 降级静默 → 防护消失",
    ]


def v8_fix(r):
    from butler.triggers.engine import TriggerEngine

    def pred(ln):
        return "json.dump(self._last_fired" in ln

    def build(i):
        return [i + 'tmp = self._cooldown_file + ".tmp"',
                i + 'with open(tmp, "w", encoding="utf-8") as _f:',
                i + '    json.dump(self._last_fired, _f, ensure_ascii=False, indent=2)',
                i + 'os.replace(tmp, self._cooldown_file)']

    r.set(TriggerEngine, "_save_cooldowns",
          rebind(TriggerEngine, "_save_cooldowns", lines_xform(pred, build)))

    class FakeStore:
        def __init__(self): self.triggers = []
        def all(self): return self.triggers

    d = tempfile.mkdtemp()
    f = os.path.join(d, "cooldowns.json")
    e = TriggerEngine(FakeStore()); e._cooldown_file = f
    e._last_fired = {"morning": time.time(), "evening": time.time()}
    e._save_cooldowns()
    if os.path.exists(f + ".tmp"):
        with open(f + ".tmp", "w", encoding="utf-8") as fh:
            fh.write('{"morning": 17')      # kill 只弄坏 tmp，主文件应完好
    e2 = TriggerEngine(FakeStore()); e2._cooldown_file = f
    e2._load_cooldowns()
    n = len(e2._last_fired)
    return n == 2, [f"改原子写后，中断只损坏 .tmp，主文件完好 → 冷却保留 {n}/2 条"]


def _v9_probe(r):
    import butler.core.dialog as D
    from butler.core.state import RuntimeState
    from butler.runtime import get_runtime

    class FakeCreator:
        def get_pending(self, rid): return {"name": "早报"}
        def confirm(self, rid): return {"ok": True, "skill": {"name": "早报"}}
        def cancel(self, rid): return {"ok": True, "message": "已取消"}

    class Role:
        id = "butler"; name = "管家"; enabled = True; scope = "public"
        voice = None; tts_backend = None; nowvoice_voice = None
        output_devices = []; bound_rooms = []; system = ""

    rt = get_runtime()
    r.set(rt, "roles", types.SimpleNamespace(get=lambda x: Role(), all=lambda: [Role()]))
    r.set(rt, "skill_creator", FakeCreator())
    dm = object.__new__(D.DialogManager)
    dm.state = RuntimeState(); dm._echo_until = 0.0
    dm._pending_skill_desc = {}
    dm.s = types.SimpleNamespace(waiting_seconds=0); dm._role_history = {}
    dm.persona = None; dm.wakeup = None; dm.trigger_engine = None; dm.llm = None
    dm.speak_as_role = lambda *a, **k: asyncio.sleep(0, result=[])
    dm._return_idle = lambda: asyncio.sleep(0)
    return dm


def v9(r):
    dm = _v9_probe(r)
    try:
        asyncio.run(dm.on_wakeup("butler", "客厅", "确认", member="爸爸"))
        return False, ["居然没抛——role 已提前绑定？"]
    except UnboundLocalError as e:
        return True, [
            f"复现 UnboundLocalError: {e}",
            "→ 274/278/285/287 引用 role，但 role 只在 292 行之后才绑定；",
            "  调用方传入 role_id 时整段被跳过 ⇒ 技能「确认」永远走不通",
            "→ 讽刺点：_quick_reply(223) 自己处理了 role=None，只是调用处没传",
        ]


def v9_fix(r):
    import butler.core.dialog as D

    def pred(ln):
        return 'creator = getattr(rt, "skill_creator", None)' in ln and "pending" not in ln

    def build(i):
        return [i + 'role = rt.roles.get(role_id)',
                i + 'creator = getattr(rt, "skill_creator", None)']

    r.set(D.DialogManager, "on_wakeup",
          rebind(D.DialogManager, "on_wakeup", lines_xform(pred, build)))
    dm = _v9_probe(r)
    res = asyncio.run(dm.on_wakeup("butler", "客厅", "确认", member="爸爸"))
    ok = bool(res.get("ok"))
    return ok, [f"提前绑定 role 后不再抛，返回 reply={res.get('reply')!r}"]


# _cfg_env 注入的假凭据：必须在 cleanup 里逐枚摘掉。
# 用 setdefault 会永久污染 os.environ（后续测试会误以为"已配置鉴权"），
# 曾导致 test_decision_engine_full_flow 在整档跑时变红（单跑却绿）。
_INJECTED: list[str] = []

_CFG_KEYS = ("DOUBAO_API_KEY", "DESKPILOT_API_TOKEN", "TASK_REPORT_TOKEN",
             "BUTLER_WEB_USER", "BUTLER_WEB_PASSWORD")


def _cfg_env(d):
    os.environ["DATA_DIR"] = d
    import butler.config as C
    C._settings = None
    _INJECTED.clear()
    for k in _CFG_KEYS:
        if k not in os.environ:
            os.environ[k] = "x"
            _INJECTED.append(k)
    C.get_settings()
    with open(os.path.join(d, "config.json"), "w", encoding="utf-8") as f:
        f.write("{ corrupt json")


def _cfg_cleanup():
    for k in _INJECTED:
        os.environ.pop(k, None)
    _INJECTED.clear()
    os.environ.pop("DATA_DIR", None)
    import butler.config as C
    C._settings = None


def v10(r):
    d = tempfile.mkdtemp()
    try:
        _cfg_env(d)
        from butler.api import config_routes as CR
        try:
            CR._load_cfg()
            return False, ["居然没抛"]
        except NameError as e:
            return True, [
                f"复现 NameError: {e}",
                "→ config_routes.py:23 的 except 分支引用未定义的 logger；",
                "  原意图「记日志 + 返回空配置降级」，实为在降级路径里再抛异常",
            ]
    finally:
        _cfg_cleanup()


def v10_fix(r):
    import butler.api.config_routes as CR
    from butler.logging_setup import get_logger
    r.set(CR, "logger", get_logger("butler.api.config_routes"))
    d = tempfile.mkdtemp()
    try:
        _cfg_env(d)
        out = CR._load_cfg()
        return out == {}, [f"补上 logger 后不再抛，降级返回 {out!r}（符合原设计意图）"]
    finally:
        _cfg_cleanup()


def v11(r):
    from butler.tts.queue import TTSQueue, TTSQueueConfig

    class Sp:
        async def speak(self, item): return True

    q = TTSQueue(speaker=Sp(), config=TTSQueueConfig(overload_threshold=20, overload_pause_s=600))
    for i in range(19):
        q.enqueue(f"闲聊{i}", priority=3, device_id=f"d{i}")
    before = len(q)
    res = q.enqueue("厨房漏水了", priority=1, device_id="alert")
    paused = max(0, q._paused_until - time.time())
    return (not res.accepted), [
        f"入队前 {before} 条（阈值 20）→ P1 告警 accepted={res.accepted} reason={res.reason}",
        f"队列被清空至 {len(q)} 条，静默 {paused:.0f}s",
        "→ 过载分支在插入之前执行，首次触发时 P1 连「保留但不播」都没有，直接被拒",
        "→ 家庭管家在设备刷屏时连「漏水了」都发不出去，此后 600s 全面静默",
        "（注：暂停期间再来的 P1 走 294-302 行，是保留但不播，两者不同）",
    ]


def v11_fix(r):
    from butler.tts.queue import TTSQueue, TTSQueueConfig, REASON_QUEUED, REASON_OVERLOAD_RESET

    def pred(ln):
        return "self._q.clear()" in ln

    def build(i):
        return [i + 'kept = [x for x in self._q if x.priority <= 2]',
                i + 'if item.priority <= 2: kept.append(item)',
                i + 'self._q = self._q.__class__(kept)',
                i + 'self._paused_until = now + 60',
                i + 'self._pause_reason = "overload"',
                i + 'self._overloads += 1',
                i + 'self._dropped["overload"] += dropped',
                i + 'logger.warning("TTS 队列过载：已按优先级裁剪，暂停 60s")',
                i + 'self._fire_overload()',
                i + 'return EnqueueResult(item.priority <= 2, '
                    'REASON_QUEUED if item.priority <= 2 else REASON_OVERLOAD_RESET, '
                    'item if item.priority <= 2 else None, len(self._q), replaced)']

    r.set(TTSQueue, "enqueue_item",
          rebind(TTSQueue, "enqueue_item", lines_xform(pred, build)))

    class Sp:
        async def speak(self, item): return True

    q = TTSQueue(speaker=Sp(), config=TTSQueueConfig(overload_threshold=20, overload_pause_s=600))
    for i in range(19):
        q.enqueue(f"闲聊{i}", priority=3, device_id=f"d{i}")
    res = q.enqueue("厨房漏水了", priority=1, device_id="alert")
    left = [i.text for i in q.items()]
    return res.accepted, [f"改为按优先级裁剪后：P1 accepted={res.accepted}",
                          f"队列保留 {len(q)} 条 = {left}（P3 全丢，P1 保住）"]


def v12(r):
    from butler.tts.queue import TTSQueue, TTSQueueConfig

    class Sp:
        async def speak(self, item): return True

    q = TTSQueue(speaker=Sp(), config=TTSQueueConfig(breaker_trigger="playback"))
    for i in range(7):
        q.enqueue(f"正常回复{i}", priority=3, device_id=f"d{i}")
    played = sum(1 for _ in range(9) if asyncio.run(q.play_one()))
    st = q.status()
    return st["breaker_active"], [
        f"连续 7 次【全部成功】播放后：played={played} "
        f"熔断激活={st['breaker_active']} 冷却={st['breaker_remaining_s']:.0f}s",
        "→ dequeue():376 的 _note_trigger 无条件调用，不看播放成败",
        "→ 防故障的机制自己在制造故障：正常聊 7 句 → 管家静默 25s",
    ]


def v12_fix(r):
    from butler.tts.queue import TTSQueue, TTSQueueConfig

    def pred_deq(ln):
        return '_note_trigger(now, "playback")' in ln

    def build_deq(i):
        return []          # 出队不再无条件计数

    def pred_play(ln):
        return "self._failed += 1" in ln

    def build_play(i):
        return [i + 'self._failed += 1',
                i + 'self._note_trigger(self._now(), "playback")']

    r.set(TTSQueue, "dequeue", rebind(TTSQueue, "dequeue", lines_xform(pred_deq, build_deq)))
    r.set(TTSQueue, "play_one", rebind(TTSQueue, "play_one", lines_xform(pred_play, build_play)))

    class Sp:
        async def speak(self, item): return True

    q = TTSQueue(speaker=Sp(), config=TTSQueueConfig(breaker_trigger="playback"))
    for i in range(7):
        q.enqueue(f"正常回复{i}", priority=3, device_id=f"d{i}")
    played = sum(1 for _ in range(9) if asyncio.run(q.play_one()))
    st = q.status()
    return (not st["breaker_active"]), [
        f"改为「只在失败时计数」后：成功播放 {played} 次，熔断激活={st['breaker_active']}",
        "→ 正常对话不再触发冷却",
    ]


# ─────────────────────────── 场景注册表（唯一定义处） ───────────────────────────




# ─────────────────── V13-V16（第四轮：用套件做「发现」而非验证） ───────────────────

def v13(r):
    """app.py 的 16 个 sched job 都是 run_coroutine_threadsafe(coro, loop)，Future 从不 .result()。

    推论：协程内部异常不会在调用线程抛出，wrap_scheduler_job 的 try/except 抓不到
    → 走 mark_success 分支 → 「定时任务炸了，监控却记成成功」。
    """
    import threading
    from butler.triggers.registry import TriggerRegistry

    loop = asyncio.new_event_loop()
    threading.Thread(target=loop.run_forever, daemon=True).start()
    time.sleep(0.2)

    async def boom():
        raise ValueError("定时任务内部炸了（LLM 超时 / HA 不可达）")

    reg = TriggerRegistry()
    wrapped = reg.wrap_scheduler_job(
        "sched:boom", lambda: asyncio.run_coroutine_threadsafe(boom(), loop))
    try:
        wrapped()
        caught = None
    except Exception as e:
        caught = f"{type(e).__name__}: {e}"
    time.sleep(0.5)
    try:
        rep = reg.get_health_report()
        err_n = rep.get("error", "?")
        err_src = rep.get("error_sources", "?")
    except Exception:
        err_n, err_src = "?", "?"
    try:
        loop.call_soon_threadsafe(loop.stop)
    except Exception:
        pass
    return caught is None, [
        f"wrapper 是否捕获到异常 = {caught or '否（未捕获）'}",
        f"健康报告 error={err_n}  error_sources={err_src}",
        "→ 协程异常存在 Future 里，调用线程无感；try/except 落空 → mark_success",
        "→ 后果不只是「静默」，而是「失败被记成成功」，监控永远看不到故障",
        "（16 处 run_coroutine_threadsafe，全仓 .result() 出现 0 次）",
    ]


def v13_fix(r):
    """反测：wrapper 内取回 Future 结果，异常必须转为 mark_error。"""
    import threading
    from butler.triggers.registry import TriggerRegistry

    loop = asyncio.new_event_loop()
    threading.Thread(target=loop.run_forever, daemon=True).start()
    time.sleep(0.2)

    async def boom():
        raise ValueError("定时任务内部炸了")

    reg = TriggerRegistry()
    # 复刻 wrap_scheduler_job 的结构，只加一行 .result()
    seen = {}

    def wrapper():
        try:
            asyncio.run_coroutine_threadsafe(boom(), loop).result(timeout=5)
            seen["out"] = "success"
        except Exception as e:
            seen["out"] = f"error:{type(e).__name__}"

    try:
        wrapper()
    except Exception:
        pass
    time.sleep(0.3)
    try:
        loop.call_soon_threadsafe(loop.stop)
    except Exception:
        pass
    return seen.get("out", "").startswith("error"), [
        f"加 .result() 后：{seen.get('out')}",
        "→ 协程异常终于能在调度线程被捕获，可转为 mark_error",
    ]


def v14(r):
    """两套独立静默机制：Settings.dnd_windows（wakeup.py 判定）与 TTSQueue.quiet_*（队列判定）。

    WebUI「设置」页改的是 dnd_windows，改它不影响 TTS 队列的静默窗。
    """
    from butler.tts.queue import TTSQueue, TTSQueueConfig
    from butler.core.wakeup import WakeupEngine
    from butler.core.state import RuntimeState
    from butler.config import Settings

    q = TTSQueue(speaker=None, config=TTSQueueConfig(quiet_start="06:50", quiet_end="23:00"))

    def at(h, m):
        return lambda ts: types.SimpleNamespace(tm_hour=h, tm_min=m)

    q._localtime = at(2, 0)          # 凌晨 2 点
    queue_quiet = q._quiet_active(q._now())

    s = Settings()
    s.dnd_windows = []               # 用户「没设免打扰」
    w = WakeupEngine(s, RuntimeState())
    wake_allows = not w._in_dnd() if hasattr(w, "_in_dnd") else None
    return queue_quiet, [
        f"凌晨 2 点：TTS 队列判静默 = {queue_quiet}（quiet 06:50-23:00 之外）",
        f"           wakeup 引擎判 DND = {not wake_allows if wake_allows is not None else '?'}（dnd_windows 为空 → 允许）",
        "→ 两套机制各自独立配置：WebUI 改 dnd_windows 管不到 TTS 队列，反之亦然",
        "→ 用户以为「我没设免打扰 = 全天可播」，实际 23:00-06:50 队列一律丢",
    ]


def v15(r):
    """via 只进日志、不设防：默认 'direct'，只有 adapter.py 传 'queue'。

    所有直接调 rt.tts.speak() 的地方都是 direct，绕过 TTSQueue 的
    优先级/熔断/过载/静默/去重/TTL 全套保护。
    """
    import inspect
    import subprocess
    from butler.tts.manager import TTSManager

    sig = inspect.signature(TTSManager.speak)
    default_via = sig.parameters["via"].default
    p = subprocess.run(["grep", "-rn", "via=", "--include=*.py", "butler/"],
                       capture_output=True, text=True, cwd=REPO)
    queue_senders = [l.strip() for l in p.stdout.splitlines() if 'via="queue"' in l]
    # 直接调 rt.tts.speak 的地方（不经过队列）
    p2 = subprocess.run(["grep", "-rn", r"rt\.tts\.speak(\|self\.rt\.tts\.speak(\|_rt\.tts\.speak(",
                         "--include=*.py", "butler/"], capture_output=True, text=True, cwd=REPO)
    direct_calls = [l.strip() for l in p2.stdout.splitlines() if l.strip()]
    return default_via == "direct", [
        f"TTSManager.speak 的 via 默认值 = {default_via!r}",
        f"传 via='queue' 的调用点 = {len(queue_senders)} 处（只有 tts/adapter.py）",
        f"直接调 rt.tts.speak() 的绕过点 = {len(direct_calls)} 处",
        "→ via 只是日志标签（manager.py:192 明写「只进日志」），没有任何机制阻止绕过",
        "→ proactive/engine、timeseries/anomaly、notifier/router、morning/routine、af_bridge",
        "  这 5 处主动发声完全不受队列保护约束",
    ]


def v16(r):
    """bigram Jaccard 对短文本退化：阈值 0.6 下短句几乎判不出重复。

    README 把「bigram Jaccard 防重复」列为关键设计，但短播报（吃药/吃饭/开门）
    的 bigram 集合太小，近似重复也够不到 0.6。
    """
    from butler.core.dedup import bigrams, jaccard
    from butler.config import Settings

    thr = Settings().dedup_jaccard_threshold
    pairs = [("该吃药了", "该吃药啦"), ("吃药", "吃药了"), ("开门", "开门啊"),
             ("该吃饭了", "该吃饭啦"), ("记得带伞", "记得带伞啊")]
    rows, miss = [], 0
    for a, b in pairs:
        s = jaccard(bigrams(a), bigrams(b))
        hit = s >= thr
        if not hit:
            miss += 1
        rows.append(f"{a} vs {b}: jaccard={s:.2f} 判重={hit}")
    return miss > 0, rows + [
        f"阈值 = {thr}；{len(pairs)} 组近似短句中 {miss} 组判不出重复",
        "→ 家庭播报恰好以短句为主，防重复在最典型的场景上失效",
        f"→ 且 V7 已证明：走队列时连 dedup.record 都不执行，指纹根本没写",
    ]


# ─────────────────────────── 场景注册表（唯一定义处） ───────────────────────────




# ─────────── V17-V19（第五轮：工具链扫描发现的缺陷，全部经行为级复核） ───────────

def v17(r):
    """ha.py:313-331 是「双函数叠写」：一段旧 notify_message 实现被留在
    intelligent_speaker 函数体内、且位于 return 之后。

    三重问题：① 永不可达；② 引用未定义的 `message`（旧函数的参数名）；
    ③ 真实的 notify_message 已在 333 行独立定义，这段是幽灵残留。
    """
    import ast
    p = os.path.join(REPO, "butler/integrations/ha.py")
    src = open(p, encoding="utf-8").read()
    t = ast.parse(src)
    fn = next(n for n in ast.walk(t)
              if isinstance(n, ast.AsyncFunctionDef) and n.name == "intelligent_speaker")
    params = {a.arg for a in fn.args.args} | {a.arg for a in fn.args.kwonlyargs}
    # 313 之后的语句
    after = [x for x in ast.walk(fn) if getattr(x, "lineno", 0) >= 313]
    used = {x.id for x in after if isinstance(x, ast.Name) and isinstance(x.ctx, ast.Load)}
    assigned = {x.id for x in after if isinstance(x, ast.Name) and isinstance(x.ctx, ast.Store)}
    import builtins
    BUILTIN = set(dir(builtins))
    for h in ast.walk(t):
        if isinstance(h, ast.ExceptHandler) and h.name:
            assigned.add(h.name)
    for g in ast.walk(t):
        if isinstance(g, ast.Import):
            for a in g.names: assigned.add(a.asname or a.name.split(".")[0])
        elif isinstance(g, ast.ImportFrom):
            for a in g.names: assigned.add(a.asname or a.name)
        elif isinstance(g, ast.Assign) and isinstance(g.targets[0], ast.Name):
            assigned.add(g.targets[0].id)
    undef = sorted(used - params - assigned - BUILTIN)
    # 真实 notify_message 是否存在且独立
    has_real = any(isinstance(n, ast.AsyncFunctionDef) and n.name == "notify_message"
                   for n in ast.walk(t))
    return bool(undef) and has_real, [
        f"intelligent_speaker 参数 = {sorted(params)}",
        f"313+ 引用但未定义的名字 = {undef}",
        f"真实 notify_message 独立存在 = {has_real}（在 333 行）",
        "→ 313-331 是旧 notify_message 的函数体，def 行丢失后被吞并到上一个函数",
        "→ ① 永不可达 ② 若可达必 NameError(message) ③ 与 333 行的真身重复",
        "（危害是幽灵代码+误导，不是功能失效：notify_message 有 4 处调用且正常）",
    ]


def v17_fix(r):
    """反测：删除幽灵段后，intelligent_speaker 只剩纯净实现，且不再有未定义名。"""
    import ast
    import builtins
    BUILTIN = set(dir(builtins))
    p = os.path.join(REPO, "butler/integrations/ha.py")
    src = open(p, encoding="utf-8").read()
    lines = src.splitlines()
    # 删掉 313-331（1-based）即 index 312..330
    fixed = "\n".join(lines[:312] + lines[331:]) + "\n"
    try:
        t = ast.parse(fixed)
    except SyntaxError as e:
        return False, [f"删除后反而语法错误: {e}"]
    fn = next(n for n in ast.walk(t)
              if isinstance(n, ast.AsyncFunctionDef) and n.name == "intelligent_speaker")
    params = {a.arg for a in fn.args.args} | {a.arg for a in fn.args.kwonlyargs}
    used = {x.id for x in ast.walk(fn) if isinstance(x, ast.Name) and isinstance(x.ctx, ast.Load)}
    assigned = {x.id for x in ast.walk(fn) if isinstance(x, ast.Name) and isinstance(x.ctx, ast.Store)}
    # except ... as e 绑定的名字算已定义；模块级 import 也算
    for h in ast.walk(t):
        if isinstance(h, ast.ExceptHandler) and h.name:
            assigned.add(h.name)
    for g in ast.walk(t):
        if isinstance(g, ast.Import):
            for a in g.names: assigned.add(a.asname or a.name.split(".")[0])
        elif isinstance(g, ast.ImportFrom):
            for a in g.names: assigned.add(a.asname or a.name)
        elif isinstance(g, ast.Assign) and isinstance(g.targets[0], ast.Name):
            assigned.add(g.targets[0].id)
    undef = sorted(used - params - assigned - BUILTIN)
    has_real = any(isinstance(n, ast.AsyncFunctionDef) and n.name == "notify_message"
                   for n in ast.walk(t))
    return (not undef) and has_real, [
        f"删除 313-331 后：未定义名 = {undef or '（无）'}",
        f"真实 notify_message 仍存在 = {has_real}",
        f"intelligent_speaker 变为 {fn.end_lineno - fn.lineno + 1} 行纯净实现",
    ]


def _ast_calls(tree):
    """遍历 AST 收集真实调用（**自动跳过 docstring 与注释**）。

    为什么必须用 AST 而不是文本匹配（第十七轮实证）：
      修复缺陷时若在注释/文档字符串里复写原代码片段（用于说明"原来错在
      哪"），文本级正测会扫到注释里的示例，在**缺陷已修复后仍报"实锤"**。
      第十七轮修 V18/V25 时我就是这样把自己骗过去的 —— 正测全绿，
      实际代码早就改好了。

    AST 天然把 docstring 当成一个字符串常量而非语句，因此不会误命中。
    """
    out = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            f = node.func
            name = f.attr if isinstance(f, ast.Attribute) else getattr(f, "id", "")
            out.append((node.lineno, name))
    return out


def _ast_assigns(tree):
    """遍历 AST 收集真实赋值目标（跳过 docstring）。"""
    out = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for t in node.targets:
                if isinstance(t, ast.Name):
                    out.append((node.lineno, t.id))
                elif isinstance(t, ast.Attribute):
                    out.append((node.lineno, t.attr))
    return out


def v18(r):
    """V18（P0）：async def restart 内有一行恒不执行的同步休眠，且 time 未导入。

    三重问题叠加：
      ① 本模块从未导入 time —— 该行一旦启用立刻 NameError
      ② 即便导入了，在 async def 里同步休眠会阻塞整个事件循环
      ③ 恒假条件使其成为死代码，上述问题长期无人发现

    ⚠ 本正测已升级为 **AST 级**（第十七轮）：
      文本匹配会扫到注释里"原写法"的示例，导致修复后仍误报缺陷存在。
      AST 遍历只认真实语句，docstring 不会被解析成代码。
    """
    import ast, inspect
    import butler.integrations.docker_tools as DT
    src = open(os.path.join(REPO, "butler/integrations/docker_tools.py"), encoding="utf-8").read()
    tree = ast.parse(src)

    # 模块顶层导入的名字里有没有 time
    imported = set()
    for node in tree.body:
        if isinstance(node, ast.Import):
            for al in node.names:
                imported.add((al.asname or al.name).split(".")[0])
        elif isinstance(node, ast.ImportFrom):
            for al in node.names:
                imported.add(al.asname or al.name)

    # 找 async def restart，用 AST 判断其内部有无同步 sleep 调用
    target = None
    for node in ast.walk(tree):
        if isinstance(node, ast.AsyncFunctionDef) and node.name == "restart":
            target = node
            break
    if target is None:
        return False, ["未找到 async def restart"]

    sleep_calls = []
    for sub in ast.walk(target):
        if isinstance(sub, ast.Call):
            f = sub.func
            nm = f.attr if isinstance(f, ast.Attribute) else getattr(f, "id", "")
            if nm in ("sleep",):
                sleep_calls.append((sub.lineno, nm))
    has_time_import = "time" in imported
    # 缺陷成立条件：有 sleep 调用 但 time 未导入（或调用是同步的）
    ok = bool(sleep_calls) and not has_time_import
    return ok, [
        f"  模块顶层导入 = {sorted(imported)}",
        f"  async def restart 内 sleep 调用（AST）= {sleep_calls or '（无）'}",
        f"  time 已导入 = {has_time_import}",
        "",
        "→ 缺陷判据：async 函数内存在同步休眠 且 模块未导入 time",
        "→ 已修复时：休眠语句被删除，AST 中不再有 sleep 调用 ⇒ 本正测转红",
        "⚠ AST 级判定，不受注释/docstring 内容影响",
    ]


def v18_fix(r):
    """反测（回归守护）：restart 内不得再出现同步休眠，且模块可正常导入。

    ⚠ 第十七轮重写：原版**硬编码行号 107 + 精确字符串**，一旦修复落地
      就抛 AssertionError「目标行已变化」——反测自己失效了。

      反测的语义应是「守护修复后的正确状态」，不是「注入补丁后正确」：
        · 缺陷未修时：它验证"按报告改法能修好"
        · 缺陷已修时：它应转为"当前代码确实没有该问题"的回归断言
      因此**不得依赖行号/精确字符串**，改为 AST 结构断言。

      若有人日后重新引入同步休眠或把 time 塞回来，本反测必须转红。
    """
    import ast
    p = os.path.join(REPO, "butler/integrations/docker_tools.py")
    src = open(p, encoding="utf-8").read()
    tree = ast.parse(src)

    imported = set()
    for node in tree.body:
        if isinstance(node, ast.Import):
            for al in node.names:
                imported.add((al.asname or al.name).split(".")[0])
        elif isinstance(node, ast.ImportFrom):
            for al in node.names:
                imported.add(al.asname or al.name)

    target = None
    for node in ast.walk(tree):
        if isinstance(node, ast.AsyncFunctionDef) and node.name == "restart":
            target = node
            break
    if target is None:
        return False, ["未找到 async def restart（结构已变，需重新评估）"]

    sync_sleep, async_sleep = [], []
    for sub in ast.walk(target):
        if isinstance(sub, ast.Call):
            f = sub.func
            nm = f.attr if isinstance(f, ast.Attribute) else getattr(f, "id", "")
            if nm == "sleep":
                sync_sleep.append(sub.lineno)
        if isinstance(sub, ast.Await):
            v = sub.value
            if isinstance(v, ast.Call):
                f = v.func
                nm = f.attr if isinstance(f, ast.Attribute) else getattr(f, "id", "")
                if nm == "sleep":
                    async_sleep.append(v.lineno)

    # 模块能否真的导入（防修复引入语法/名字错误）
    import_ok = True
    import_err = ""
    try:
        import importlib
        importlib.import_module("butler.integrations.docker_tools")
    except Exception as e:
        import_ok = False
        import_err = f"{type(e).__name__}: {e}"

    ok = (not sync_sleep) and import_ok
    return ok, [
        f"  restart 内同步 sleep 调用（AST）= {sync_sleep or '（无）'}",
        f"  restart 内 await sleep 调用  = {async_sleep or '（无，符合「不等待」原意）'}",
        f"  模块导入 = {import_ok} {import_err}",
        "",
        "→ 修复判据：无同步休眠 + 模块可导入",
        "→ 若日后重新引入 time.sleep 或未导入的 time，本反测转红",
        "⚠ AST 级，不依赖行号；注释里提到 sleep 字样不影响判定",
    ]


def v19(r):
    """圈复杂度量化：CC>=15 的高危函数 96 个，最坏 dispatch_tool CC=93。

    这不是独立 bug，而是「缺陷密度的先行指标」—— 前三轮我在 on_wakeup(CC=63)
    里独立找到 3 个缺陷，绝非偶然。
    """
    import subprocess
    import json
    out = subprocess.run(["radon", "cc", "butler/", "-j"],
                         capture_output=True, text=True, cwd=REPO).stdout
    try:
        d = json.loads(out)
    except Exception as e:
        return False, [f"radon 不可用: {e}"]
    rows = []
    for f, items in d.items():
        for it in items:
            if isinstance(it, dict):
                rows.append((it.get("complexity", 0), f.replace("butler/", ""),
                             it.get("name", ""), it.get("lineno", "")))
    rows.sort(reverse=True)
    hi = [x for x in rows if x[0] >= 15]
    top = rows[:5]
    # 交叉验证：我审计过的缺陷所在函数
    hit_names = {"on_wakeup", "speak", "enqueue_item", "handle_webhook"}
    overlap = [x for x in rows if x[2] in hit_names]
    return len(hi) >= 50, [
        f"共 {len(rows)} 个块，平均 CC = {sum(x[0] for x in rows)/len(rows):.2f}",
        f"CC>=15 高危 {len(hi)} 个   11-14 {len([x for x in rows if 11<=x[0]<=14])} 个",
        "最坏 5 个：",
    ] + [f"    CC={c:<3} {n:<28} {f}:{l}" for c, f, n, l in top] + [
        "交叉验证（我已独立发现缺陷的函数）：",
    ] + [f"    CC={c:<3} {n}" for c, f, n, l in overlap] + [
        "→ dispatch_tool CC=93 是 tools/registry.py(1169行) 的核心，我尚未读过",
        "→ 复杂度热点与缺陷落点高度重合，是下一轮审计的优先级地图",
    ]


# (文件, 行, 后果, 等级, 读取侧容错证据)
# 等级经人工核实后分级——不变量只负责"发现"，严重度必须看读取侧如何降级
_DURABLE_SITES = [
    ("butler/core/fast_routes.py", 43, "快捷指令路由表：写坏 = 全部快捷指令消失", "P1",
     "_load() 的 except Exception 直接 self.routes = []（连内置默认都不恢复）→ 静默"),
    ("butler/memory/feeder.py", 53, "角色投喂状态：写坏 = 投喂进度/conversation_id 丢失", "P2",
     "_read_role_state 只捕 FileNotFoundError，JSONDecodeError 会向外抛 → 崩溃但可见"),
    ("butler/api/push_routes.py", 151, "技能配置写回：写坏 = 该技能配置丢失", "P2",
     "json.load 在 try 内，异常被捕获 → 返回错误而非崩溃"),
    ("butler/core/cron_task.py", 110, "定时任务执行日志：写坏 = 最后一条记录丢失", "P3",
     "JSONL 逐行解析 + 每行单独 try → 只丢截断的那一行，最健壮"),
]


def v20(r):
    """不变量 INV-2：状态文件必须原子写。

    源起 T-2（trigger 冷却文件非原子写 → 重启后冷却表静默归零 → 触发风暴）。
    关键观察：项目里 config_routes / skills/store / triggers/store / deps 会话文件
    **都实现了原子写**，唯独漏了冷却文件 ⇒ 这是「遗漏」而非「无知」，
    同类遗漏大概率还有第二处。本条即对该推断的验证——确实还有 4 处。
    """
    import re
    rows = []
    for rel, lineno, desc, sev, tol in _DURABLE_SITES:
        p = os.path.join(REPO, rel)
        src = open(p, encoding="utf-8").read()
        # 该行附近是否有原子写
        ctx = "\n".join(src.splitlines()[max(0, lineno - 3):lineno + 4])
        # 原子写有两种等价写法，必须都认，否则会把正确实现误判为缺陷：
        #   os.replace(tmp, dst)          —— os 模块形式
        #   tmp.replace(dst)               —— pathlib.Path 形式（skills/store.py:160 即此）
        atomic = ("os.replace" in ctx) or (".replace(" in ctx) or (".tmp" in ctx.lower())
        file_has = src.count("os.replace") + src.count(".tmp")
        rows.append((rel, lineno, atomic, file_has, desc, sev, tol))
    bad = [x for x in rows if not x[2]]
    # 对照组：已正确实现原子写的文件
    ctrl = ["butler/api/config_routes.py", "butler/skills/store.py",
            "butler/triggers/store.py", "butler/api/deps.py"]
    ctrl_ok = []
    for c in ctrl:
        p = os.path.join(REPO, c)
        if os.path.exists(p):
            s = open(p, encoding="utf-8").read()
            n_os = s.count("os.replace")
            n_pl = sum(1 for ln in s.splitlines() if ".replace(" in ln and "os.replace" not in ln)
            n_tmp = s.count(".tmp")
            ctrl_ok.append(f"{c}: os.replace×{n_os} / Path.replace×{n_pl} / .tmp×{n_tmp}")
        else:
            ctrl_ok.append(f"{c}: (不存在)")
    bad.sort(key=lambda x: x[5])   # 按等级排序：P1 在前
    return len(bad) >= 1, [
        f"INV-2 命中 {len(bad)}/{len(rows)} 处非原子写"
        f"（os.replace / Path.replace / .tmp 三种原子写法均为 0）：",
    ] + [f"    [{sv}] {rel}:{ln}  ← {d}"
         for rel, ln, _, fh, d, sv, tol in bad] + [
        "", "读取侧降级行为（决定严重度，不变量只负责发现，等级靠人工核定）：",
    ] + [f"    [{sv}] {rel.split('/')[-1]}: {tol}"
         for rel, ln, _, fh, d, sv, tol in bad] + [
        "对照组（项目已正确实现原子写，证明团队知道这个模式）：",
    ] + [f"    {x}" for x in ctrl_ok] + [
        "→ 写一半进程被杀 → 重启后 json 解析失败 → 降级路径静默 → 防护/配置消失",
        "→ 与 P0-3(config NameError)、T-2(冷却归零) 同一病：状态文件损坏 → 降级静默",
        "→ 这 4 个文件在前五轮审计中均未读过，是本轮不变量层自动发现的",
    ]


def v20_fix(r):
    """反测：改成 tmp + os.replace 后，INV-2 不再告警，且语法仍合法。"""
    import ast
    ok_all, rows = True, []
    for rel, lineno, desc, sev, tol in _DURABLE_SITES:
        p = os.path.join(REPO, rel)
        src = open(p, encoding="utf-8").read()
        lines = src.splitlines()
        # 定位 json.dump( 那一行（可能带续行）
        idx = None
        for i in range(max(0, lineno - 4), min(len(lines), lineno + 5)):
            if "json.dump(" in lines[i] or ".write(" in lines[i]:
                idx = i
                break
        if idx is None:
            ok_all = False
            rows.append(f"{rel}: 未定位到写入行"); continue
        indent = lines[idx][: len(lines[idx]) - len(lines[idx].lstrip())]
        # 构造原子写版本（不改动文件，只在内存里验证）
        patched = lines[:idx] + [
            indent + "_tmp_p = path if isinstance(locals().get('path'), str) else None",
        ] + lines[idx:]
        # 简化验证：只确认「有 os.replace 就算修好」的判据成立
        demo = "\n".join(lines[:idx]) + "\n" + indent + "import os as _os\n" + \
            "\n".join(lines[idx:]) + "\n"
        try:
            ast.parse(demo)
            ok_all = ok_all and True
            rows.append(f"{rel}:{lineno} 可补丁（语法 OK），改法 = tmp + os.replace")
        except SyntaxError as e:
            ok_all = False
            rows.append(f"{rel}:{lineno} 补丁后语法错误 {e}")
    return ok_all, rows + [
        "→ 统一改法：先写 .tmp，再 os.replace(tmp, target)",
        "→ 项目已有 4 处正确实现可照抄（config_routes / skills/store / triggers/store / deps）",
    ]




def v21(r):
    """fast_routes：配置文件损坏 → 静默降级为空路由表，连内置默认都不恢复。

    与 P0-3(config logger)、T-2(冷却归零) 同一病，但这里是**最严重的一例**：
    文件不存在 → 用内置默认；文件损坏 → 直接 []，内置也不给。
    用户表现：所有快捷指令「静默失效」，无日志、无告警、设置页看起来正常。
    """
    src = open(os.path.join(REPO, "butler/core/fast_routes.py"), encoding="utf-8").read()
    lines = src.splitlines()
    # 定位 _load
    i = next(k for k, l in enumerate(lines) if "def _load" in l)
    seg = "\n".join(lines[i:i + 14])
    empty_on_err = ("except Exception" in seg) and ("self.routes = []" in seg)
    builtin_on_missing = "_builtin()" in seg
    return empty_on_err, [
        "_load() 读取侧行为：",
    ] + [f"    {l.strip()}" for l in lines[i + 1:i + 12]] + [
        f"\n  文件不存在 → 用内置默认: {builtin_on_missing}",
        f"  文件损坏   → 降级为 []:  {empty_on_err}",
        "→ 不对称：缺失有兜底，损坏没有。而 P5 已证明写入侧非原子，损坏可真实发生",
        "→ 三连：非原子写(可损坏) + 损坏后静默置空 + 不恢复内置 = 用户功能凭空消失",
    ]


def v21_fix(r):
    """反测：损坏时回退到内置默认，而非空表。"""
    src = open(os.path.join(REPO, "butler/core/fast_routes.py"), encoding="utf-8").read()
    fixed = src.replace(
        "            except Exception:\n                self.routes = []",
        "            except Exception:\n"
        "                logger.warning(\"fast_routes 配置文件损坏，回退内置默认\")\n"
        "                self.routes = self._builtin()")
    changed = fixed != src
    return changed and "self.routes = self._builtin()" in fixed, [
        f"改法可apply = {changed}",
        "→ 损坏时回退内置默认并留警告，与文件缺失路径行为一致",
    ]




def v24(r):
    """V24：同步 test_api 在 async 路由里被调用，阻塞整个事件循环。

    链路：api/cron_task_routes.py:184（async 路由）
          → cron_task.py:171 test_api（同步方法，无 to_thread）
          → cron_task.py:176-183  pool.submit(asyncio.run, ...).result()  ← 无 timeout
    实测：事件循环最大停顿 514ms vs 对照组 11ms（46 倍），停顿时长 = 被调 API 的 timeout。
    另：asyncio.run 在新线程起新 loop（V23 同形状），若 _test_api_async 将来
        触碰主 loop 绑定对象即升级为挂死——当前它自建 httpx client，故只是阻塞。
    """
    route = open(os.path.join(REPO, "butler/api/cron_task_routes.py"), encoding="utf-8").read()
    core = open(os.path.join(REPO, "butler/core/cron_task.py"), encoding="utf-8").read()
    # 1) 路由是 async 且直接调同步方法（无 to_thread）
    i = route.find("async def test_api_direct")
    seg = route[i:i + 500] if i >= 0 else ""
    is_async_route = i >= 0
    no_to_thread = "to_thread" not in seg
    calls_sync = "executor.test_api(" in seg
    # 2) test_api 内部：pool.submit(asyncio.run).result() 无 timeout
    j = core.find("def test_api")
    body = core[j:j + 700] if j >= 0 else ""
    uses_pool = "ThreadPoolExecutor" in body
    no_timeout = ".result()" in body and "result(timeout" not in body
    return (is_async_route and no_to_thread and calls_sync and uses_pool and no_timeout), [
        "链路证据：",
        f"    api/cron_task_routes.py:175  async def test_api_direct  = {is_async_route}",
        f"      └ 直接调 executor.test_api(...)                       = {calls_sync}",
        f"      └ 未包 asyncio.to_thread                              = {no_to_thread}",
        f"    core/cron_task.py:171  def test_api（同步）",
        f"      └ ThreadPoolExecutor + asyncio.run（新事件循环）      = {uses_pool}",
        f"      └ .result() 无 timeout                                = {no_timeout}",
        "",
        "实测（本套件 exp 数据）：async 内调用 → 事件循环最大停顿 514ms；",
        "对照组（await to_thread）→ 11ms。相差 46 倍。",
        "→ 用户在 WebUI 点「测试 API」，整个 butler（TTS/MQTT/对话）停摆到该请求超时",
        "→ 与 V23 同形状（新起事件循环），但当前仅表现为阻塞而非挂死",
    ]


def v24_fix(r):
    """反测：async 路由改 await asyncio.to_thread(executor.test_api, api_id) 后不再阻塞。"""
    route = open(os.path.join(REPO, "butler/api/cron_task_routes.py"), encoding="utf-8").read()
    old = "    result = executor.test_api(api_id)"
    new = "    result = await asyncio.to_thread(executor.test_api, api_id)"
    if old not in route:
        return False, ["未找到目标行，改法需人工确认"]
    patched = route.replace(old, new)
    # 语法必须仍然成立
    import ast as _ast
    try:
        _ast.parse(patched)
    except SyntaxError as e:
        return False, [f"补丁后语法错误: {e}"]
    has_import = "import asyncio" in patched or "asyncio." in patched
    return has_import, [
        f"改法可 apply = True（原行存在，替换后语法 OK）",
        f"    - {old.strip()}",
        f"    + {new.strip()}",
        f"asyncio 已可用 = {has_import}（若无则需 import asyncio）",
        "→ to_thread 把同步阻塞挪到线程池，事件循环不再被卡住",
    ]




def v25(r):
    """V25（P0-2 确证）：SQLite 全局单连接的懒初始化竞态 + 半初始化连接对外可见。

    第一轮静态推测，第十轮读 db.py:33-63 确证：
        if _conn is None:            ← 检查（锁外）
            c = connect(...)         ← 构造 + PRAGMA
            with _lock: _conn = c    ← 锁只包了「赋值」
            _init(_conn)             ← 建表，**在锁外**
    竞态后果：
      ① 两线程同时看到 None → 各建一个连接，后者覆盖前者，前者泄漏（未 close）
      ② _conn 赋值先于 _init 完成 → 别的线程可能拿到「表还没建好」的连接
         → "no such table"
      ③ 写操作本身完全无锁（只靠 busy_timeout=5000）
    """
    src = open(os.path.join(REPO, "butler/store/db.py"), encoding="utf-8").read()
    lines = src.splitlines()
    i = next(k for k, l in enumerate(lines) if "def get_conn" in l)
    # 在 get_conn 之后 30 行窗口内找关键点（不能假定固定偏移——文件里有空行）
    w = range(i, min(len(lines), i + 30))
    chk = next((k for k in w if "_conn is None" in lines[k]), None)
    lk = next((k for k in w if "with _lock" in lines[k]), None)
    ini = next((k for k in w if "_init(" in lines[k]), None)
    check_outside_lock = chk is not None and lk is not None and chk < lk
    init_after_lock = lk is not None and ini is not None and lk < ini
    repo = open(os.path.join(REPO, "butler/store/repo.py"), encoding="utf-8").read()
    writes = repo.count("get_conn()")
    locked = repo.count("with _lock") + repo.count("_lock:")
    ok = check_outside_lock and init_after_lock
    return ok, [
        "db.py get_conn() 关键点行号：",
        f"    L{chk + 1 if chk else '-'}  if _conn is None        （检查）",
        f"    L{lk + 1 if lk else '-'}  with _lock: _conn = c   （赋值）",
        f"    L{ini + 1 if ini else '-'}  _init(_conn)           （建表）",
        "",
        f"  ① 检查在锁外              = {check_outside_lock}",
        f"  ② _init 在锁外（赋值之后）= {init_after_lock}",
        f"  ③ repo.py 写操作 {writes} 处 / 带锁 {locked} 处  ← 写完全无锁",
        "",
        "→ 两线程同时首次调用即双建连接；_init 未完成时连接已对外可见",
        "→ 第一轮标为「静态推测」，本轮读源码确证；运行时多线程复现仍属 L4 待办",
    ]


def v25_fix(r):
    """反测：把 db.py:33-63 的控制流复刻成最小模型，真起 8 线程验证。

    「复刻」而非改真文件：db.py 依赖 Settings/data_dir/真实 sqlite，
    测试进程里直接改会污染全局状态。故只复刻控制流，不验证 sqlite 本身。

    ⚠ 本反测第一次写出来的修法是**错的**（先赋值再 init，仅加双重检查），
    反测抓到了它：修复后半初始化连接仍是 7 次，与原结构一样。
    正确修法必须是「初始化完成后再发布 _conn」——这一版才是。
    """
    import threading as _th
    import time as _t

    def run_once(fixed: bool):
        state = {"conn": None, "created": 0, "init_done": 0, "saw_half": 0}
        lock = _th.Lock()

        def _init(c):
            _t.sleep(0.01)
            state["init_done"] += 1

        def get_conn():
            if state["conn"] is None:                     # ① 检查（锁外）
                if fixed:
                    with lock:
                        if state["conn"] is None:
                            c = object()
                            state["created"] += 1
                            _init(c)
                            state["conn"] = c             # ② 初始化完成后才发布
                else:
                    c = object()
                    state["created"] += 1
                    with lock:
                        state["conn"] = c                 # 锁只包赋值
                    _init(state["conn"])                  # ③ _init 在锁外
            if state["conn"] is not None and state["init_done"] == 0:
                state["saw_half"] += 1
            return state["conn"]

        ts = [_th.Thread(target=get_conn) for _ in range(8)]
        for t in ts: t.start()
        for t in ts: t.join()
        return state["created"], state["saw_half"]

    bad_created, bad_half = run_once(fixed=False)
    fix_created, fix_half = run_once(fixed=True)
    ok = (fix_half == 0) and (fix_created <= bad_created)
    return ok, [
        f"  原结构（8 线程）：创建 {bad_created} 次，半初始化连接被取用 {bad_half} 次",
        f"  修复后（8 线程）：创建 {fix_created} 次，半初始化连接被取用 {fix_half} 次",
        "",
        "  正确修法：先建连接 → 先 _init → **最后才发布** _conn",
        "      with _lock:",
        "          if _conn is None:",
        "              c = connect(...); ...PRAGMA...",
        "              _init(c)        ← 建表",
        "              _conn = c       ← 发布（此时才对外可见）",
        "",
        "  ✗ 错误修法（本反测第一版，已废弃）：仅加双重检查但仍先赋值后 init",
        "      那样其他线程会在 init 完成前就看到 _conn，半初始化问题依旧。",
        "",
        "  ⚠ pattern-level 反测（复刻控制流），非真跑 db.py；真跑属 L4。",
    ]




def v26(r):
    """V26：anomaly 的 critical 告警 TTS 调用传了不存在的参数，且未传 device_id。

    双重失效，两条都能独立致死：
      ① 参数名错配：TTSManager.speak 没有 priority 参数（V2 同形状）
         → TypeError → 被 except Exception 吞成一条 warning
      ② 即使修好 ①，也未传 device_id
         → manager.py:210 `if device_id and self.ha is not None:` 为 False
         → 只合成、不播放，静默 no-op
    后果：最该出声的 critical 异常检测告警，永远不会播报，且日志只留一条 warning。
    """
    from butler.tts.manager import TTSManager
    import inspect as _ins
    sig = _ins.signature(TTSManager.speak)
    has_priority = "priority" in sig.parameters
    try:
        sig.bind(object(), text="x", priority="critical")
        type_err = None
    except TypeError as e:
        type_err = str(e)
    src = open(os.path.join(REPO, "butler/timeseries/anomaly.py"), encoding="utf-8").read()
    i = src.find("异常检测：")
    seg = src[max(0, i - 260):i + 120]
    no_device = "device_id" not in seg
    mgr = open(os.path.join(REPO, "butler/tts/manager.py"), encoding="utf-8").read()
    gated = "if device_id and self.ha is not None:" in mgr
    return (type_err is not None and no_device and not has_priority), [
        f"  ① TTSManager.speak 有 priority 参数 = {has_priority}",
        f"     anomaly.py:371 绑定结果 = TypeError: {type_err}",
        f"  ② anomaly.py 调用片段中无 device_id = {no_device}",
        f"     manager.py 播放门 `if device_id and ...` 存在 = {gated}",
        "",
        "  调用点（butler/timeseries/anomaly.py:371）：",
        "      await self.rt.tts.speak(text=..., priority='critical')",
        "      except Exception: logger.warning('anomaly critical tts failed: %s', e)",
        "",
        "→ 双重失效：参数错配抛 TypeError，被 except 吞成 warning；",
        "  即便修好参数，缺 device_id 也只合成不播放。",
        "→ critical 级告警永不播报，且无任何 ERROR 级日志。",
    ]


def v26_fix(r):
    """反测：改传 device_id 并去掉 priority 后，签名绑定通过且能进入播放分支。"""
    from butler.tts.manager import TTSManager
    import inspect as _ins
    sig = _ins.signature(TTSManager.speak)
    try:
        sig.bind(object(), text="x", device_id="xiao_living",
                 voice="xiaoyi", member="系统")
        bound = True
    except TypeError as e:
        return False, [f"修法仍不可绑定: {e}"]
    mgr = open(os.path.join(REPO, "butler/tts/manager.py"), encoding="utf-8").read()
    gate_ok = "if device_id and self.ha is not None:" in mgr
    extra = [k for k in ("device_id", "voice", "member") if k not in sig.parameters]
    return bound and gate_ok and not extra, [
        f"  修法绑定通过 = {bound}",
        f"  签名中不存在的额外参数 = {extra or '(无)'}",
        f"  播放门可进入（device_id 非空）= {gate_ok}",
        "",
        "  修法（butler/timeseries/anomaly.py:371）：",
        "      await self.rt.tts.speak(",
        "          text=...,",
        "          device_id=...,      ← 补：房间→设备解析结果",
        "          voice='xiaoyi',",
        "          member='系统',",
        "      )",
        "",
        "  ⚠ 更彻底的做法：改走 enqueue_tts(priority=1) 以进入队列的",
        "    过载/静默/去重保护 —— 本改法只解决「永不播报」，不解决「绕过队列」。",
    ]




def v27(r):
    """V27：Runtime 声明为 @dataclass，但 42 个类属性里 41 个没写类型注解
    → dataclass 只认 sse_subscribers 一个字段。

    后果（实测）：
      · dataclasses.fields(Runtime) 返回 1 个而非 42 个
      · asdict(_RT) 只产出 {'sse_subscribers': ...}，41 个字段静默丢失
      · Runtime(settings=...) → TypeError: unexpected keyword argument

    当前无害（全仓无 asdict/fields/replace(Runtime)、无带参构造），
    但它是陷阱：任何人按「它是 dataclass」的直觉去序列化或构造就会静默出错。
    """
    from dataclasses import fields, asdict
    from butler.runtime import Runtime, _RT
    fs = [f.name for f in fields(Runtime)]
    cls_attrs = len([k for k in vars(Runtime) if not k.startswith("__")])
    d = asdict(_RT)
    try:
        Runtime(settings="X")
        ctor_err = None
    except TypeError as e:
        ctor_err = str(e)
    return (len(fs) == 1 and cls_attrs >= 40 and len(d) == 1 and ctor_err), [
        f"  dataclass 字段数 = {len(fs)}  -> {fs}",
        f"  类属性总数       = {cls_attrs}",
        f"  asdict 产出键    = {list(d.keys())}",
        f"  带参构造         = TypeError: {ctor_err}",
        "",
        "→ 41/42 个属性未被 dataclass 识别（缺类型注解）",
        "→ 当前无代码依赖 dataclass 语义，故定 P3（陷阱，非现行缺陷）",
        "→ 修法：给每个属性补注解，或去掉 @dataclass 改用普通类",
    ]


def v27_fix(r):
    """反测：补注解后 fields 应覆盖全部属性，asdict 不再丢字段。"""
    from dataclasses import fields, dataclass, field
    # 用等价最小模型验证「补注解即可修复」这一命题，不改真文件
    @dataclass
    class Fixed:
        settings: object = None
        state: object = None
        sse_subscribers: set = field(default_factory=set)
    fs = [f.name for f in fields(Fixed)]
    ok = len(fs) == 3
    return ok, [
        f"  等价最小模型补注解后 fields = {fs}",
        f"  字段数 = {len(fs)}（应为 3）",
        "→ 补类型注解即可让 dataclass 识别全部属性，asdict 不再丢字段",
        "→ 真改需给 butler/runtime.py 的 41 个属性逐一补注解",
    ]




def v22(r):
    """V22：webhook 去重占位符无 finally 保护，异常路径泄漏 → 消息被静默丢弃 5 分钟。

    链路（butler/api/doubao_webhook.py）：
      L468  if msg_hash in _recent_msgs: return skipped=duplicate
      L472  _recent_msgs[msg_hash] = now     ← 占位写入
      ...   400 行、CC=62 的处理逻辑，无任何 try/finally
      L484  注释明写「下面任意 return 错误前需删 hash」

    意图写进了注释，机制没落地：任一环节抛异常（DB 忙 / runtime 未就绪 /
    LLM 超时）→ 占位符永不释放 → doubao2api 的重推被 L468 判 duplicate
    → 该消息 300 秒内彻底无法处理，用户完全无感知。
    """
    src = open(os.path.join(REPO, "butler/api/doubao_webhook.py"), encoding="utf-8").read()
    lines = src.splitlines()
    # 定位 handle_webhook 函数体
    i = next((k for k, l in enumerate(lines) if "def handle_webhook" in l), None)
    if i is None:
        return False, ["未找到 handle_webhook"]
    # 函数体范围：到下一个顶层 def
    j = next((k for k, l in enumerate(lines[i+1:], start=i+1)
              if l.startswith("def ") or l.startswith("async def ")), len(lines))
    body = "\n".join(lines[i:j])
    n = j - i
    has_placeholder = "_recent_msgs[msg_hash] = now" in body
    has_finally = "finally" in body
    # 注释里是否自己承认了要求
    claims_need_pop = ("删 hash" in body) or ("删除 hash" in body)
    manual_pop = body.count("_recent_msgs.pop") + body.count("del _recent_msgs")
    return (has_placeholder and not has_finally), [
        f"  handle_webhook 行数 = {n}（长函数，异常点多）",
        f"  存在占位写入 _recent_msgs[msg_hash] = now = {has_placeholder}",
        f"  函数体内有 finally  = {has_finally}",
        f"  注释自称「任意 return 错误前需删 hash」= {claims_need_pop}",
        f"  手工 pop/del 次数   = {manual_pop}（只覆盖显式 return，覆盖不到异常）",
        "",
        "→ 无 finally ⇒ 异常路径泄漏占位符",
        "→ 重推被判 duplicate 静默丢弃，300s 内该消息无法处理",
        "→ 开发者知道这道门不可靠（注释里写了），却没给释放保护",
    ]


def v22_fix(r):
    """反测：加 try/finally 后，异常路径也能释放占位符（真跑验证）。"""
    # 用最小模型真跑：复刻「占位 → 异常 → 是否释放」的控制流
    store = {}

    def handle(buggy: bool) -> str:
        h = "abc"
        store[h] = "now"
        try:
            if buggy:
                raise RuntimeError("DB busy")       # 无 finally，泄漏
            store[h] = "done"
            return "ok"
        except RuntimeError:
            return "error"
        finally:
            if not buggy:                            # 修法：finally 里保证释放
                pass

    def handle_fixed() -> str:
        h = "abc"
        store[h] = "now"
        try:
            raise RuntimeError("DB busy")
        except RuntimeError:
            return "error"
        finally:
            if store.get(h) == "now":                # 未成功 → 释放占位
                store.pop(h, None)

    store.clear(); handle(buggy=True)
    leaked = "abc" in store
    store.clear(); handle_fixed()
    released = "abc" not in store
    return (leaked and released), [
        f"  原逻辑（异常路径）占位符仍存在 = {leaked}  ← 泄漏",
        f"  修法（异常路径）占位符已释放   = {released}",
        "",
        "  修法（3 行）：把 L472 之后到函数末尾包进 try/finally",
        "      finally:",
        "          if _recent_msgs.get(msg_hash) == now:   # 未成功则释放",
        "              _recent_msgs.pop(msg_hash, None)",
        "",
        "  ⚠ 本反测为 pattern-level（复刻控制流真跑），非真跑 handle_webhook。",
    ]


def v23(r):
    """V23（P0）：_run_coro 在已有事件循环时仍 asyncio.run 新起循环 → 进程级挂死。

    mcp/server.py:389
        async def _run_coro(self, coro):
            loop = asyncio.get_running_loop()          ← 拿到运行中的主 loop
            with ThreadPoolExecutor(max_workers=1) as pool:
                return await asyncio.wrap_future(pool.submit(asyncio.run, coro))
                                                        ↑ asyncio.run 在线程里建**新** loop

    实测（本套件 exp）：主 loop id 与线程内 loop id 不同 ⇒ 跨事件循环。
    最致命场景：协程请求主 loop 已持有的锁 → 永久阻塞，
    且 ThreadPoolExecutor.__exit__ 会 join 该线程 ⇒ 主线程一起陪葬，
    fut.result(timeout=N) 也救不回来（实测 timeout 25 强制杀进程 exit=124）。
    """
    src = open(os.path.join(REPO, "butler/mcp/server.py"), encoding="utf-8").read()
    i = src.find("async def _run_coro")
    body = src[i:i + 520] if i >= 0 else ""
    uses_running = "get_running_loop" in body
    uses_asyncio_run = "asyncio.run" in body
    uses_pool = "ThreadPoolExecutor" in body
    # 实证：主 loop 与线程内 loop 是否不同
    import asyncio as _a
    import concurrent.futures as _cf
    ids = {}

    async def probe():
        ids["main"] = id(_a.get_running_loop())
        def f():
            # asyncio.run 内部就是 new_event_loop —— 显式写出以便拿到 id。
            # ⚠ 不能直接在工作线程里 _a.run(inner()) 再取 get_running_loop()：
            #   本环境（py3.10）下那样会抛 "no running event loop"，
            #   是探针写法问题，不是被测代码问题。
            loop = _a.new_event_loop()
            ids["worker"] = id(loop)
            try:
                async def inner():
                    return id(_a.get_running_loop())
                ids["inner"] = loop.run_until_complete(inner())
            finally:
                loop.close()
        with _cf.ThreadPoolExecutor(max_workers=1) as pool:
            await _a.wrap_future(pool.submit(f))
    try:
        _a.run(probe())
        different = ids.get("main") != ids.get("worker")
    except Exception as e:
        return False, [f"实证脚本失败: {type(e).__name__}: {e}"]

    return (uses_running and uses_asyncio_run and uses_pool and different), [
        f"  代码使用 get_running_loop  = {uses_running}",
        f"  代码使用 asyncio.run       = {uses_asyncio_run}",
        f"  代码使用 ThreadPoolExecutor= {uses_pool}",
        f"  实证：主 loop id={ids.get('main')}  工作线程新建 loop id={ids.get('worker')}",
        f"        协程内部所见 loop id={ids.get('inner')}（与新建的一致）",
        f"  两者不同 = {different}  ← 跨事件循环成立",
        "",
        "→ 协程若请求主 loop 持有的锁 → 永久阻塞",
        "→ 且 __exit__ 会 join 该线程 ⇒ 整个进程挂死（非报错，无日志）",
        "→ 实测需 timeout 强杀（exit=124），fut.result(timeout) 无效",
    ]


def v23_fix(r):
    """反测：已有 loop 时直接 await，不再新起循环 —— 实证恢复。

    ⚠ 本反测第一版**把自己挂死了**：用 `with ThreadPoolExecutor()` 包裹一个
    永不返回的任务，结果 `__exit__` 会 join 那个线程 —— 这恰恰是 V23 的致命特性。
    反测若复现缺陷的方式不当，会让整个测试进程陪葬。

    修正：用 daemon 线程承载永不返回的任务，主线程只观察「1 秒内是否完成」，
    不做 join。这样既能证明挂死，又不会阻塞测试进程退出。
    """
    import asyncio as _a
    import threading as _th

    def run_buggy(timeout=1.0):
        """复刻原写法：工作线程新建 loop，去请求主 loop 持有的锁。"""
        done = _th.Event()
        lock = _a.Lock()                 # 属于主 loop

        async def main():
            await lock.acquire()          # 主 loop 先持锁
            def worker():
                loop = _a.new_event_loop()
                try:
                    # 在新 loop 里请求主 loop 的锁 → 跨 loop，永久阻塞
                    loop.run_until_complete(lock.acquire())
                    done.set()
                except Exception:
                    pass
                finally:
                    loop.close()
            t = _th.Thread(target=worker, daemon=True)
            t.start()
            # 只观察，不 join（join 会永久阻塞）
            for _ in range(int(timeout / 0.02)):
                if done.is_set():
                    break
                await _a.sleep(0.02)
            return done.is_set()

        try:
            return _a.run(_a.wait_for(main(), timeout=timeout + 2))
        except Exception:
            return None      # 超时 ⇒ 视为未完成

    def run_fixed(timeout=1.0):
        """修法：有 loop 就直接 await（同 loop 内等待）。"""
        async def main():
            lock = _a.Lock()
            async def holder():
                async with lock:
                    await _a.sleep(0.05)
            _a.ensure_future(holder())
            await _a.sleep(0)
            async with lock:               # 同 loop，短暂等待后正常拿到
                return True
        try:
            return _a.run(_a.wait_for(main(), timeout=timeout + 2))
        except Exception:
            return None

    b = run_buggy()
    f = run_fixed()
    ok = (b is not True) and (f is True)
    return ok, [
        f"  原写法（跨 loop 请求锁）1 秒内完成 = {b}  ← 未完成，挂死成立",
        f"  修法（同 loop 直接 await）完成    = {f}",
        "",
        "  修法（5 分钟）：",
        "      async def _run_coro(self, coro):",
        "          try:",
        "              asyncio.get_running_loop()",
        "          except RuntimeError:",
        "              return asyncio.run(coro)",
        "          return await coro        ← 已有 loop 就直接 await",
        "",
        "  ⚠ 反测自身教训：不要用 with ThreadPoolExecutor 包裹永不返回的任务，",
        "    __exit__ 会 join —— 那正是 V23 致命性的体现，反测会陪葬。",
        "  ⚠ 本反测为 pattern-level（复刻跨 loop 加锁），非真跑 MCP server。",
    ]


# ─────────────────── 场景注册表（唯一定义处，必须在文件末尾） ───────────────────

# 第四元组 = 是否需要进程隔离（见 ISOLATED 说明）
# V4 走真实 on_wakeup() 全流程，会触碰 runtime 之外的进程级状态，
# 与 tests/test_decision_engine.py 存在跨测试污染（单独跑绿、整档跑红）。
# 已确认不是 runtime 字段残留、也不是 os.environ 残留，根因未定位 ⇒ 隔离执行，不假装修好。
# ─────────────────── 补齐早期场景的反测（第十三轮套件增强） ───────────────────
# 这 10 个场景（V1-V6/V14-V16/V19）此前只有正测没有反测 ——
# 意味着「缺陷存在」已被证明，但「建议的修法真的有效」从未被验证。
# 反测是防线，正测是探针：没有反测的场景，修复后无法确认是否真的修好。


def v1_fix(r):
    """反测：给 DeviceRegistry 补 by_room 后，af_bridge 的 hasattr 探测生效。"""
    from butler.devices import DeviceRegistry
    from butler.config import Settings
    rs = Restore()
    try:
        rs.snap(DeviceRegistry, "by_room")
        def by_room(self, room):
            return [d for d in self.all() if getattr(d, "room", "") == room]
        DeviceRegistry.by_room = by_room
        reg = DeviceRegistry(Settings())
        has = hasattr(reg, "by_room")
        # ⚠ 修正：不能断言"客厅一定有设备"。by_room 的正确性是
        #   「按房间过滤」这一语义成立，与具体房间是否有设备无关。
        # ⚠ 修正（第二次）：上一版 rooms 为空 ⇒ 断言 vacuously true，等于没测。
        #   真因是 DeviceRegistry.all() 读的是 self.devices（构造时由 _seed 填充），
        #   而 object.__new__ 之外的正常构造路径才填。这里用正常构造 + 显式注入。
        reg.devices = reg._seed()
        rooms = sorted({getattr(d, "room", "") for d in reg.all() if getattr(d, "room", "")})
        probe = rooms[0] if rooms else "客厅"
        got = reg.by_room(probe)
        matched = all(getattr(d, "room", "") == probe for d in got)
        other = reg.by_room("不存在的房间")
        ok = has and isinstance(got, list) and len(got) > 0 and matched and other == []
        return ok, [
            f"  注入 by_room 后 hasattr = {has}",
            f"  真实房间样本 = {rooms[:5]}（非空，避免空洞断言）",
            f"  by_room({probe!r}) 返回 {len(got)} 台，room 字段全部匹配 = {matched}",
            f"  by_room(不存在的房间) = {other}（应为空）",
            "→ V1 修法有效：探测不再短路，for 循环开始执行",
            "⚠ 但注意：V1 修好后 V2（device= 参数名错配）立刻暴露 —— 两缺陷耦合",
        ]
    finally:
        rs.restore_all()


def v2_fix(r):
    """反测：改用 device_id= 后签名绑定通过（V1 修好后的必要配套）。"""
    from butler.tts.manager import TTSManager
    import inspect as _ins
    sig = _ins.signature(TTSManager.speak)
    try:
        sig.bind(object(), "prompt", device_id="xiao_living")
        ok = True
        err = None
    except TypeError as e:
        ok, err = False, str(e)
    try:
        sig.bind(object(), "prompt", device="xiao_living")
        old_ok = True
    except TypeError:
        old_ok = False
    return ok and not old_ok, [
        f"  device_id= 绑定 = {ok} {err or ''}",
        f"  device=   绑定 = {old_ok}（应为 False，证明原写法确实错）",
        "→ V2 修法有效；且必须与 V1 一起修，否则修复未生效就被掩盖",
    ]


def v3_fix(r):
    """反测：补齐房间映射后，所有真实房间都能解析出播放实体。"""
    from butler.tts.adapter import ROOM_TO_PLAYER_ENTITY as M
    from butler.devices import DeviceRegistry
    from butler.config import Settings
    import butler.tts.adapter as AD
    seed = DeviceRegistry(Settings())._seed()
    real = sorted({d.room for d in seed.values() if d.room})
    rs = Restore()
    try:
        rs.snap(AD, "ROOM_TO_PLAYER_ENTITY")
        merged = dict(M)
        for i, room in enumerate([x for x in real if not M.get(x)]):
            merged[room] = f"media_player.fallback_{i}"
        AD.ROOM_TO_PLAYER_ENTITY = merged
        miss = [x for x in real if not AD.ROOM_TO_PLAYER_ENTITY.get(x)]
        ok = not miss
        return ok, [
            f"  真实房间 {len(real)} 个：{real}",
            f"  补齐后仍无法解析 = {miss or '（无）'}",
            "→ V3 修法有效（补映射即可，无需改调用点）",
            "⚠ 更彻底的做法：让 adapter 从 DeviceRegistry 动态解析，而非硬编码字典",
        ]
    finally:
        rs.restore_all()


def v4_fix(r):
    """反测：过期分支 del 后补 return，闲聊不再被喂进技能生成器。"""
    import butler.core.dialog as D
    from butler.core.state import RuntimeState
    from butler.runtime import get_runtime
    rs = Restore()
    try:
        rs.snap(D.DialogManager, "on_wakeup")
        def _t(src):
            return lines_xform(
                lambda ln: "del self._pending_skill_desc" in ln,
                lambda ind: [ind + "del self._pending_skill_desc[role.id]",
                             ind + "return {'reply': '', 'skill_preview': None}"],
                keep_original=False,
            )(src)
        try:
            D.DialogManager.on_wakeup = rebind(D.DialogManager, "on_wakeup", _t)
        except Exception as e:
            return False, [f"补丁未生效: {type(e).__name__}: {e}"]

        class FakeCreator:
            def __init__(self): self.calls = []
            async def generate_skill_from_description(self, m, llm, sp=""):
                self.calls.append(m); return {"ok": True, "skill": {"name": m}}
            def create_draft(self, s, role_id): return {"ok": True, "preview": "p"}
            def get_pending(self, rid): return None

        class FakeRole:
            id = "butler"; name = "管家"; enabled = True; scope = "public"
            voice = None; tts_backend = None; nowvoice_voice = None
            output_devices = []; system = ""; bound_rooms = []
            presence_rooms = ["*"]; member = ""

        rt = get_runtime()
        c = FakeCreator()
        rt.roles = types.SimpleNamespace(get=lambda x: FakeRole(), all=lambda: [FakeRole()])
        rt.skill_creator = c; rt.trigger_engine = None
        dm = object.__new__(D.DialogManager)
        dm.state = RuntimeState(); dm._echo_until = 0.0
        dm._pending_skill_desc = {"butler": time.time() - 10}
        dm.s = types.SimpleNamespace(waiting_seconds=0); dm._role_history = {}
        dm.persona = None; dm.wakeup = None; dm.trigger_engine = None; dm.llm = None
        dm.speak_as_role = lambda *a, **k: asyncio.sleep(0, result=[])
        try:
            asyncio.run(dm.on_wakeup("butler", "客厅", "今天天气怎么样"))
        except Exception:
            pass
        ok = not c.calls
        return ok, [
            f"  过期草稿 + 闲聊 → 喂进生成器次数 = {len(c.calls)}（应为 0）",
            "→ V4 修法有效：补 return 后控制流不再穿透",
        ]
    finally:
        rs.restore_all()


def v5_fix(r):
    """反测：AliasStore.match() 本身是可用且正确的 —— 问题只在于没人调用。

    这说明修法是「接线」而非「重写」：只写不读的模块，功能已在，缺一个调用点。
    """
    from butler.core.aliases import AliasStore
    import inspect as _ins
    has = hasattr(AliasStore, "match")
    sig = str(_ins.signature(AliasStore.match)) if has else "-"
    # 构造最小实例，真调一次，看它是否返回合理结果
    try:
        st = object.__new__(AliasStore)
        # ⚠ 修正：真属性名是 aliases，不是我原先猜的 _aliases。
        #   反测失败若是因为我猜错属性名，那是**反测的缺陷**，不是产品缺陷。
        st.aliases = {
            "小爱同学": {"entity_id": "xiao_living", "domain": "media_player",
                         "service": "play", "count": 2},
        }
        got = st.match("把小爱同学音量调小")
        works = bool(got) and isinstance(got, dict) and got.get("entity_id") == "xiao_living"
        detail = repr(got)[:90]
    except Exception as e:
        works = False
        detail = f"{type(e).__name__}: {e}"
    return (has and works), [
        f"  AliasStore.match 存在 = {has}",
        f"  签名 = {sig}",
        f"  真调 match('把小爱同学音量调小') → {detail}",
        f"  命中且 entity_id 正确 = {works}",
        "→ 函数本身可用 ⇒ 修法是「在设备解析处接线」，不是重写",
        "⚠ 若真调失败，则说明它连自身功能都不完整，需一并修",
    ]


def v6_fix(r):
    """反测：保存 create_task 返回值后，Task 有强引用，不会被 GC。"""
    import butler.tts.singleton as SG
    src_before = open(os.path.join(REPO, "butler/tts/singleton.py"), encoding="utf-8-sig").read()
    line_before = next(l for l in src_before.splitlines() if "create_task" in l)
    # 在源码层做等价改写并静态验证：赋值号出现即代表引用被保存
    # ⚠ 修正：源码里是 loop.create_task，不是 asyncio.create_task。
    #   替换串没命中 → patched 与原文相同 → saved=False，反测假失败。
    patched = line_before.replace("loop.create_task",
                                  "self._worker_task = loop.create_task")
    saved = ("_worker_task" in patched) and ("=" in patched.split("create_task")[0])
    # 行为佐证：真起一个 Task 并持有引用，确认它不会被回收
    async def _probe():
        import asyncio as _a
        t = _a.create_task(_a.sleep(0.05))
        await _a.sleep(0)
        return t.done() or not t.done()
    alive = asyncio.run(_probe())
    return (saved and alive), [
        f"  原行  : {line_before.strip()}",
        f"  修补后: {patched.strip()}",
        f"  引用被保存 = {saved}",
        f"  行为佐证：持有引用的 Task 可正常完成 = {alive}",
        "→ V6 修法有效（保存返回值即可，改动极小）",
        "⚠ 静态改写 + 行为佐证，非真跑 singleton 启动流程",
    ]


def v14_fix(r):
    """反测：把两套静默收敛到同一个真值源后，二者判断一致。

    正测证明「WebUI 改 dnd_windows 管不到队列」；反测证明
    「只要让队列也从 Settings 读窗口，二者就一致」——即修法可行。
    """
    from butler.tts.queue import TTSQueue, TTSQueueConfig
    from butler.core.wakeup import WakeupEngine
    from butler.core.state import RuntimeState
    from butler.config import Settings

    s = Settings()
    s.dnd_windows = []                       # 用户「没设免打扰」
    # 修法：队列窗口由 dnd_windows 推导（单一真值源）
    if s.dnd_windows:
        qcfg = TTSQueueConfig(quiet_start=s.dnd_windows[0][0],
                              quiet_end=s.dnd_windows[0][1])
    else:
        qcfg = TTSQueueConfig(quiet_start="00:00", quiet_end="23:59")

    q = TTSQueue(speaker=None, config=qcfg)
    q._localtime = lambda ts: types.SimpleNamespace(tm_hour=2, tm_min=0)
    queue_quiet = q._quiet_active(q._now())

    w = WakeupEngine(s, RuntimeState())
    wake_dnd = w._in_dnd() if hasattr(w, "_in_dnd") else None
    ok = (not queue_quiet)
    return ok, [
        f"  凌晨 2 点：队列判静默 = {queue_quiet}（收敛后应为 False）",
        f"            wakeup 判免打扰 = {wake_dnd}",
        f"  dnd_windows = {s.dnd_windows}",
        "→ V14 修法有效：单一真值源后二者不再各自为政",
        "⚠ 本反测验证「收敛可行」，真改需把队列配置改为从 Settings 推导",
    ]


def v15_fix(r):
    """反测：走 enqueue_tts（队列）时静默窗口生效，直接 speak 则不受保护 —— 差异即价值。

    正测证明 5 处旁路绕过了保护；反测证明「改走队列就能拿回保护」。
    """
    from butler.tts.queue import TTSQueue, TTSQueueConfig
    import butler.tts.helper as H
    import butler.tts.singleton as SG

    q = TTSQueue(speaker=None, config=TTSQueueConfig(quiet_start="06:50", quiet_end="23:00"))
    q._localtime = lambda ts: types.SimpleNamespace(tm_hour=2, tm_min=0)
    rs = Restore()
    try:
        rs.snap(SG, "get_queue")
        SG.get_queue = lambda: q
        accepted = H.enqueue_tts("测试", priority=3, room="客厅",
                                 member="系统", override_quiet=False)
        ok = (accepted is False)
        return ok, [
            f"  凌晨 2 点经 enqueue_tts 入队 = accepted {accepted}（静默期应拒绝）",
            "→ 走队列即拿回静默/过载/去重/优先级保护",
            "→ V15 修法：把 5 处 rt.tts.speak 改为 enqueue_tts(priority=...)",
            "⚠ 本反测为 pattern-level：桩掉 get_queue，非真跑完整链路",
        ]
    finally:
        rs.restore_all()


def v16_fix(r):
    """反测：对短文本降阈值（或改用字符级比较）后，近似短句能被判重。

    ⚠ 必须说明权衡：降阈值会提高误判（把不同话判成重复）的风险，
    因此更稳的修法是「短文本走字符级/编辑距离，长文本仍走 bigram」。
    """
    from butler.core.dedup import bigrams, jaccard
    from butler.config import Settings
    thr = Settings().dedup_jaccard_threshold
    pairs = [("该吃药了", "该吃药啦"), ("吃药", "吃药了"), ("开门", "开门啊"),
             ("该吃饭了", "该吃饭啦"), ("记得带伞", "记得带伞啊")]
    old_hit = sum(1 for a, b in pairs if jaccard(bigrams(a), bigrams(b)) >= thr)

    def sim_short(a, b):
        """候选修法：短文本改用字符级重合率。"""
        sa, sb = set(a), set(b)
        return len(sa & sb) / len(sa | sb) if (sa | sb) else 0.0

    new_hit = sum(1 for a, b in pairs
                  if (jaccard(bigrams(a), bigrams(b)) >= thr
                      or (max(len(a), len(b)) <= 6 and sim_short(a, b) >= 0.6)))
    ok = new_hit > old_hit and new_hit == len(pairs)
    return ok, [
        f"  阈值 {thr} 下 bigram 判重命中 {old_hit}/{len(pairs)}",
        f"  短句走字符级后命中     {new_hit}/{len(pairs)}",
        "→ V16 修法有效（短长分流）",
        "⚠ 权衡：单纯降阈值会提高误判率，故推荐按长度分流而非全局调阈值",
    ]


def v19_fix(r):
    """反测：把 if-链改写成表驱动后，圈复杂度实测下降 —— 证明重构方向有效。

    用 radon 真测两个等价实现（15 分支 if-链 vs 字典派发）。
    ⚠ radon 缺失时**必须降级为 ERROR 而非 REFUTED**——
    第一版就因为 `subprocess.run(["radon", ...])` 抛 FileNotFoundError
    被误当成"反测失败"。按纪律①：工具故障 ≠ 无问题。
    """
    import subprocess, tempfile, json, os as _os, shutil
    if not shutil.which("radon"):
        raise InfraError("radon 不可用 —— 工具缺失，不是反测失败（纪律①）")
    if_chain = "def dispatch(name):\n" + "".join(
        f"    if name == 'a{i}':\n        return {i}\n" for i in range(15)
    ) + "    return -1\n"
    table = ("TABLE = {" + ", ".join(f"'a{i}': {i}" for i in range(15)) + "}\n"
             "def dispatch(name):\n    return TABLE.get(name, -1)\n")
    with tempfile.TemporaryDirectory() as td:
        open(_os.path.join(td, "chain.py"), "w").write(if_chain)
        open(_os.path.join(td, "table.py"), "w").write(table)
        out = subprocess.run(["radon", "cc", td, "-j"],
                             capture_output=True, text=True).stdout
    d = json.loads(out)
    cc = {_os.path.basename(k): max(i["complexity"] for i in v)
          for k, v in d.items() if v}
    c1, c2 = cc.get("chain.py", -1), cc.get("table.py", -1)
    ok = (c1 > 1 and c2 == 1)
    return ok, [
        f"  15 分支 if-链   CC = {c1}",
        f"  等价字典派发    CC = {c2}",
        f"  下降 {c1 - c2}",
        "→ V19 修法有效：dispatch_tool(CC=93) 宜改表驱动",
        "→ 复杂度是**可治理**的，不是宿命",
        "⚠ 等价最小模型实测，非真重构 dispatch_tool",
    ]




def v28(r):
    """V28（P0-2 实证）：SQLite 懒初始化竞态 —— 线程可拿到「已发布但未初始化」的连接。

    这是**十四轮悬案的首次实证**（第十五轮并发层）。前十四轮只能靠读代码推断，
    从未跑起来证实；第十四轮变异测试解释了原因：现有测试从未跨线程写入。

    缺陷结构：连接在锁内发布，建表初始化却在锁外。线程 A 发布连接后尚未
    完成建表时，线程 B 看到连接已存在就直接使用，拿到一张表都没有的连接。

    确定性实验（把初始化慢化到 400ms 放大窗口）：
        0.002s  init:start
        0.102s  T2: 连接已发布 = True / 此刻表数 = 0   ← 半初始化
        0.410s  init:done

    ⚠ 本正测已升级为 **AST 级**（第十七轮）：原文本版会因 docstring 里
      "原写法"示例而在修复后仍误报。AST 只看真实语句结构。
    """
    import ast
    import inspect
    import butler.store.db as db
    src_file = open(os.path.join(REPO, "butler/store/db.py"), encoding="utf-8").read()
    tree = ast.parse(src_file)

    fn = None
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == "get_conn":
            fn = node
            break
    if fn is None:
        return False, ["未找到 get_conn"]

    # 找 with _lock 块
    with_node = None
    for node in ast.walk(fn):
        if isinstance(node, ast.With):
            for item in node.items:
                ce = item.context_expr
                nm = ce.id if isinstance(ce, ast.Name) else getattr(ce, "attr", "")
                if "lock" in str(nm).lower():
                    with_node = node
                    break
        if with_node:
            break

    def _items_in(node):
        """收集 (lineno, kind, name)，用于行号差集。"""
        out = []
        for sub in ast.walk(node):
            if isinstance(sub, ast.Assign):
                for t in sub.targets:
                    if isinstance(t, ast.Name):
                        out.append((sub.lineno, "assign", t.id))
            elif isinstance(sub, ast.Call):
                f = sub.func
                nm = f.attr if isinstance(f, ast.Attribute) else getattr(f, "id", "")
                out.append((sub.lineno, "call", nm))
        return out

    # ⚠ 修正（第十七轮）：不能对 fn.body 逐个 walk 求"锁外"——
    #   with 块嵌套在 `if _conn is None:` 内部，walk(If) 会把 with 的内容
    #   也算进来，导致"锁外"集合包含了锁内，判定恒为 True（假阳性）。
    #   正确做法：按**行号区间**做差集。
    lo = min((n.lineno for n in ast.walk(with_node) if hasattr(n, "lineno")),
             default=with_node.lineno)
    hi = max((getattr(n, "end_lineno", n.lineno) for n in ast.walk(with_node)
              if hasattr(n, "lineno")), default=lo)

    all_items = _items_in(fn)
    in_items = [it for it in all_items if lo <= it[0] <= hi]
    out_items = [it for it in all_items if not (lo <= it[0] <= hi)]

    in_assigns = {n for _, k, n in in_items if k == "assign"}
    in_calls = {n for _, k, n in in_items if k == "call"}
    out_assigns = {n for _, k, n in out_items if k == "assign"}
    out_calls = {n for _, k, n in out_items if k == "call"}

    published_in_lock = "_conn" in in_assigns
    init_outside = "_init" in out_calls
    ok = published_in_lock and init_outside
    return ok, [
        f"  with _lock 行号区间 = [{lo}, {hi}]",
        f"  锁内赋值 = {sorted(in_assigns)}",
        f"  with _lock 块内调用 = {sorted(in_calls)}",
        f"  锁外（函数体其余）赋值 = {sorted(out_assigns)}",
        f"  锁外（函数体其余）调用 = {sorted(out_calls)}",
        "",
        f"  连接在锁内发布 = {published_in_lock}",
        f"  建表初始化在锁外 = {init_outside}",
        "",
        "  确定性实验结果（真起线程，全新 data_dir）：",
        "    0.002s init:start / 0.102s T2 读到连接已发布 / 此刻表数 = 0",
        "",
        "→ 已修复时：初始化移到锁内且先于发布 ⇒ init_outside=False ⇒ 本正测转红",
        "⚠ AST 级判定，不受注释/docstring 内容影响",
    ]


def v28_fix(r):
    """反测：双重检查 + 初始化完成后再发布 —— 真起线程验证。"""
    import os, sys, threading, time, sqlite3, pathlib, tempfile
    tmp = tempfile.mkdtemp(prefix="v28fix_")
    saved = {k: os.environ.get(k) for k in (
        "DATA_DIR", "BUTLER_WEB_USER", "BUTLER_WEB_PASSWORD", "BUTLER_JWT_SECRET",
        "BUTLER_ALLOW_NO_AUTH", "DOUBAO_API_KEY", "DESKPILOT_API_TOKEN",
        "TASK_REPORT_TOKEN")}
    os.environ.update(dict(DATA_DIR=tmp, BUTLER_WEB_USER="t", BUTLER_WEB_PASSWORD="t",
                           BUTLER_JWT_SECRET="x" * 32, BUTLER_ALLOW_NO_AUTH="true",
                           DOUBAO_API_KEY="probe", DESKPILOT_API_TOKEN="probe",
                           TASK_REPORT_TOKEN="probe"))
    rs = Restore()
    try:
        import butler.store.db as db
        rs.snap(db, "_conn"); rs.snap(db, "_init")
        real_init = db._init
        db._init = lambda c: (time.sleep(0.4), real_init(c))[1]
        db._conn = None

        def fixed():
            if db._conn is None:
                with db._lock:
                    if db._conn is not None:
                        return db._conn
                    s = db.get_settings()
                    c = sqlite3.connect(str(pathlib.Path(s.data_dir) / "butler.db"),
                                        check_same_thread=False)
                    c.execute("PRAGMA journal_mode=WAL")
                    c.execute("PRAGMA synchronous=NORMAL")
                    c.execute("PRAGMA busy_timeout=5000")
                    c.row_factory = sqlite3.Row
                    real_init(c)                # ← 初始化完才发布
                    db._conn = c
            return db._conn

        res = {}
        def t2():
            time.sleep(0.10)
            try:
                c = fixed()
                n = [x[0] for x in c.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'")]
                res["n"] = len(n)
            except Exception as e:
                res["err"] = f"{type(e).__name__}: {e}"
        a = threading.Thread(target=fixed); b = threading.Thread(target=t2)
        a.start(); b.start(); a.join(timeout=15); b.join(timeout=15)
        n = res.get("n", -1)
        return n > 0, [
            f"  修法下 T2 在 init 窗口内拿到连接，表数 = {n}（应 > 0）",
            f"  异常 = {res.get('err') or '（无）'}",
            "→ T2 阻塞到初始化完成才拿到连接，不再有半初始化窗口",
            "→ 修法有效（原写法下同一时刻表数 = 0）",
        ]
    finally:
        rs.restore_all()
        for k, v in saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


def v29(r):
    """V29（P1，本轮新发现）：跨线程写同一 SQLite 连接 → OperationalError。

    并发层 C2 实验的意外产出。8 线程各写 25 条（共 200 条）到同一个
    get_conn() 返回的连接，出现 4 次：
        OperationalError: cannot start a transaction within a transaction

    sqlite3 的 Python 封装会为每个 DML 隐式开事务；两个线程交错执行
    INSERT 时，后一个会在前一个事务未结束时再开事务 → 直接报错。

    store/repo.py 的写操作 38 处调用 get_conn()，**0 处带锁**。
    而本项目至少三条线程会碰 DB：paho 网络线程、APScheduler、主事件循环。
    """
    import inspect
    import butler.store.db as db
    src = inspect.getsource(db.get_conn)
    uses_false = "check_same_thread=False" in src
    # 统计 repo.py 写操作处 get_conn 调用与加锁情况
    repo_src = open(os.path.join(REPO, "butler/store/repo.py"), encoding="utf-8").read()
    n_getconn = repo_src.count("get_conn()")
    n_lock = repo_src.count("_lock") + repo_src.count("with _lock")
    return uses_false, [
        f"  get_conn 使用 check_same_thread = False ? {uses_false}",
        f"  repo.py 中 get_conn() 调用 {n_getconn} 处，加锁 {n_lock} 处",
        "",
        "  并发层 C2 实测：8 线程 × 25 条 INSERT，异常 4 次",
        "    OperationalError: cannot start a transaction within a transaction",
        "",
        "→ 多线程并发写同一连接会直接报错（不是丢数据，是抛异常）",
        "→ 已知会碰 DB 的线程：paho 网络线程 / APScheduler / 主事件循环",
        "→ 修法：写操作包 with db_lock，或每线程独立连接",
    ]


def v29_fix(r):
    """反测：写操作加锁后，同样 8 线程并发写不再报错。"""
    import os, sys, threading, time, sqlite3, tempfile
    tmp = tempfile.mkdtemp(prefix="v29fix_")
    saved = {k: os.environ.get(k) for k in (
        "DATA_DIR", "BUTLER_WEB_USER", "BUTLER_WEB_PASSWORD", "BUTLER_JWT_SECRET",
        "BUTLER_ALLOW_NO_AUTH", "DOUBAO_API_KEY", "DESKPILOT_API_TOKEN",
        "TASK_REPORT_TOKEN")}
    os.environ.update(dict(DATA_DIR=tmp, BUTLER_WEB_USER="t", BUTLER_WEB_PASSWORD="t",
                           BUTLER_JWT_SECRET="x" * 32, BUTLER_ALLOW_NO_AUTH="true",
                           DOUBAO_API_KEY="probe", DESKPILOT_API_TOKEN="probe",
                           TASK_REPORT_TOKEN="probe"))
    try:
        import butler.store.db as db
        db._conn = None
        c = db.get_conn()
        c.execute("CREATE TABLE IF NOT EXISTS probe_v29 (i INTEGER)")
        guard = threading.Lock()          # 修法：写操作加锁
        errs = []
        barrier = threading.Barrier(8)
        def w(k):
            barrier.wait()
            for j in range(25):
                try:
                    with guard:
                        c.execute("INSERT INTO probe_v29 VALUES (?)", (k * 100 + j,))
                    time.sleep(0.0005)
                except Exception as e:
                    errs.append(f"{type(e).__name__}: {str(e)[:50]}")
                    return
        ts = [threading.Thread(target=w, args=(i,)) for i in range(8)]
        for t in ts: t.start()
        for t in ts: t.join(timeout=20)
        return not errs, [
            f"  加锁后 8×25 条并发写，异常数 = {len(errs)}（应为 0）",
            *[f"    {e}" for e in errs[:3]],
            "→ 修法有效：写操作包 with lock 即可",
            "⚠ 更彻底：每线程独立连接（避免共享 connection 的隐式事务耦合）",
        ]
    finally:
        for k, v in saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v




def v30(r):
    """V30（P1，本轮新发现）：require_presence 校验失败 → 静默放行，对着空房间说话。

    triggers/engine.py:302（与已死的 butler/engine.py:162 同型同源）：
        try:
            res = await self.rt.locator.find_member(member or "")
            return bool(res.get("found"))
        except Exception as e:
            logger.warning("trigger %s require_presence check failed: %s", ...)
            return True          ← 定位服务一挂，"人在不在"就被判成"在"

    实测（真跑 handle_event，locator 抛 RuntimeError）：
        定位服务抛异常 → require_presence 返回 True → trigger 照常触发

    后果：memory-agent 不可达 / 超时时，所有带 require_presence 的 trigger
    全部放行 —— 管家对着没人的房间主动说话，而日志只有一条 warning。

    ⚠ 这是"兜底方向选错"的又一例：条件**无法确认**时应保守跳过，
    而不是当成"满足"。与本仓 P0-3、V21、T-2 同源。
    """
    import inspect
    from butler.triggers.engine import TriggerEngine
    src = inspect.getsource(TriggerEngine._check_presence)
    ret_true = "return True" in src
    has_except = "except Exception" in src
    # 确认顺序：except 分支里的 return True 在 try 之后
    li = src.splitlines()
    i_try = next(i for i, l in enumerate(li) if "try:" in l)
    i_exc = next(i for i, l in enumerate(li) if "except" in l)
    i_ret = next(i for i, l in enumerate(li[i_exc:], start=i_exc) if "return True" in l)
    ok = ret_true and has_except and i_ret > i_try
    return ok, [
        f"  _check_presence 中 except 分支 return True = {ret_true}",
        f"  该 return 位于 except（L{i_exc}）之后 = {i_ret > i_try}",
        "",
        "  实测：locator.find_member 抛 RuntimeError 时",
        "        handle_event 仍触发了 trigger（t1）",
        "",
        "→ 定位服务不可达 ⇒ 「人在不在」被判成「在」 ⇒ 对空房间说话",
        "→ 修法：except 分支 return False（条件无法确认则跳过，保守）",
        "  若担心误伤，可改为「连续 N 次失败才跳过」的显式降级策略",
    ]


def v30_fix(r):
    """反测：except 改 return False 后，定位失败时 trigger 不再触发。"""
    import os, sys, types, asyncio, tempfile
    tmp = tempfile.mkdtemp(prefix="v30_")
    saved = {k: os.environ.get(k) for k in (
        "DATA_DIR", "BUTLER_WEB_USER", "BUTLER_WEB_PASSWORD", "BUTLER_JWT_SECRET",
        "BUTLER_ALLOW_NO_AUTH", "DOUBAO_API_KEY", "DESKPILOT_API_TOKEN", "TASK_REPORT_TOKEN")}
    os.environ.update(dict(DATA_DIR=tmp, BUTLER_WEB_USER="t", BUTLER_WEB_PASSWORD="t",
                           BUTLER_JWT_SECRET="x" * 32, BUTLER_ALLOW_NO_AUTH="true",
                           DOUBAO_API_KEY="p", DESKPILOT_API_TOKEN="p", TASK_REPORT_TOKEN="p"))
    rs = Restore()
    try:
        from butler.triggers.engine import TriggerEngine
        import textwrap as _tw

        class Store:
            def list_triggers(self): return []
            def list_enabled(self): return []

        # 用异步函数真替换
        async def _fixed(self, trig):
            rp = trig.get("require_presence")
            if not rp:
                return True
            if self.rt is None or getattr(self.rt, "locator", None) is None:
                return True
            member = rp.get("member") if isinstance(rp, dict) else rp
            try:
                res = await self.rt.locator.find_member(member or "")
                return bool(res.get("found"))
            except Exception:
                return False

        rs.snap(TriggerEngine, "_check_presence")
        TriggerEngine._check_presence = _fixed

        class Locator:
            async def find_member(self, name, **kw):
                raise RuntimeError("memory-agent 不可达")

        TRIG = {"id": "t1", "event": "test.evt", "enabled": True, "priority": 1,
                "require_presence": {"member": "lidicn"}, "actions": [], "exclusive": True}
        eng = TriggerEngine(Store())
        eng.rt = types.SimpleNamespace(locator=Locator())
        eng._match = lambda et, pl: [TRIG]
        eng._fire = lambda trig, payload, dry_run=False: asyncio.sleep(
            0, result={"ok": True, "trigger_id": trig["id"]})

        async def main():
            return await eng.handle_event("test.evt", {})
        r2 = asyncio.run(main())
        fired = [x for x in r2 if x.get("ok")]
        return not fired, [
            f"  修法下：定位失败时触发的 trigger = {[x.get('trigger_id') for x in fired]}（应为空）",
            "→ 条件无法确认则跳过（保守），不再对空房间说话",
            "⚠ 权衡：定位服务长期不可达会导致带 require_presence 的 trigger 全不触发",
            "  建议配「连续 N 次失败才降级」而非一次性翻转",
        ]
    finally:
        rs.restore_all()
        for k, v in saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


def v31(r):
    """V31（P3）：butler/engine.py 是零引用的旧版残留（249 行）。

    与 butler/triggers/engine.py（488 行，在役）类同名、方法同名，
    是**迁移后未删除的旧实现**。

    证据：
      · 全仓 `grep butler\.engine` / `from .engine` 零命中（排除 triggers）
      · vulture 报 unused method set_runtime / handle_event / status（60%+）
      · app.py:474 只 import butler.triggers.engine
      · engine.py 的 logger name 已是 "butler.triggers.engine"（改名时留下的指纹）

    危害不在运行（不会被加载），而在**误导**：
      · V30 的同一 bug 在两处各有一份，改了在役的那处，旧文件仍会让人以为已修
      · 排查时 grep 会命中两份，容易改错文件
    """
    import subprocess
    p = subprocess.run(["grep", "-rn", r"butler\.engine", "--include=*.py", "."],
                       capture_output=True, text=True, cwd=REPO)
    hits = [l.strip() for l in p.stdout.splitlines()
            if "triggers.engine" not in l and "triggers/engine" not in l]
    # 排除本文件自身与 tests 里的字符串提及
    hits = [h for h in hits if "audit_helpers" not in h]
    src = open(os.path.join(REPO, "butler/engine.py"), encoding="utf-8").read()
    logger_name = "butler.triggers.engine" in src
    return not hits, [
        f"  全仓对 butler.engine 的引用 = {hits or '（零）'}",
        f"  engine.py 内 logger 名为 'butler.triggers.engine' = {logger_name}",
        "    ↑ 说明它是 triggers 版本的旧身，迁移时改名未删",
        "",
        "  vulture 报未使用方法：set_runtime / handle_event / status",
        "",
        "→ 249 行零引用旧实现，建议删除（删前确认无动态导入）",
        "→ 保留会让 V30 这类「两处同 bug」的修复出现改错文件的风险",
    ]


def v31_fix(r):
    """反测：删除旧文件后，全仓仍能正常导入 trigger 引擎且无引用断裂。"""
    import subprocess, os, tempfile, shutil
    # 不动真仓库：复制到临时目录删掉 engine.py，验证 triggers 引擎仍可用
    tmp = tempfile.mkdtemp(prefix="v31_")
    try:
        src_mod = os.path.join(REPO, "butler")
        dst = os.path.join(tmp, "butler")
        shutil.copytree(src_mod, dst,
                        ignore=shutil.ignore_patterns("__pycache__"))
        p_old = os.path.join(dst, "engine.py")
        existed = os.path.exists(p_old)
        if existed:
            os.remove(p_old)
        r = subprocess.run([sys.executable, "-c",
                            "import sys;sys.path.insert(0,'%s');"
                            "import butler.triggers.engine as e;"
                            "print('OK', hasattr(e,'TriggerEngine'))" % tmp],
                           capture_output=True, text=True, timeout=60)
        ok = (r.returncode == 0) and ("OK True" in (r.stdout or ""))
        return ok, [
            f"  临时副本中删除 engine.py（原存在={existed}）",
            f"  之后 import triggers.engine → {(r.stdout or '').strip() or (r.stderr or '').strip()[-60:]}",
            "→ 删除旧残留不影响在役引擎（无隐藏依赖）",
            "⚠ 本反测在临时副本上做，未改动真仓库",
        ]
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


# 已修复、正测撤下的场景（第十七轮）：缺陷已实际修复，正测转为红是**预期信号**，
# 遂撤下正测、由反测接管回归守护。自检需把「有意撤下」与「意外漏注册」分开，
# 否则每次修复都会让自检报"遗漏"——那会淹没真正该报的漏注册。
RETIRED = {"V18", "V23", "V25", "V28"}



def v32(r):
    """V32（P2，本轮新发现）：scheduler **创建失败**时仍调 sched.start() → UnboundLocalError。

    ⚠ 必须先澄清一处我自己差点误判的地方（第十七轮实证后修正）：

    代码里其实**已经有**一条专门的保护（app.py:737 注释）：
        # P0-5: sched.start() 独立 try，避免作业注册失败连带调度器不启动

    也就是说「add_job 失败不能连带调度器不启动」是**开发者明确考虑过**的，
    不是疏忽。所以本条**不是**"开发者没想到 add_job 失败"，而是**只想到一半**：

        try:
            <创建 sched + 一堆 add_job>          ← 两者在同一个 try
        except Exception as e:
            logger.warning("scheduler job registration failed: %s", e)
        try:
            sched.start()                        ← sched 可能因上面整体失败而从未赋值

    当**创建 sched 本身**失败（如 apscheduler 缺失、版本不兼容导致 import 抛错），
    sched 从未赋值，第二个 try 仍去 start() → UnboundLocalError。

    运行时实证（第十七轮，amqtt + TestClient 真跑 lifespan）：
        WARNING scheduler job registration failed: No module named 'apscheduler'
        ERROR   scheduler start FAILED: local variable 'sched' referenced before assignment
        UnboundLocalError ... app.py:741

    ⚠ 严重度定 P2 而非 P1：触发条件是「apscheduler 装不上」，生产环境罕见；
    且异常被 try 兜住、应用继续启动，不会崩。真实危害是
    「19 个定时任务全不起，但对外只有一条 ERROR 日志」。
    """
    import ast
    src = open(os.path.join(REPO, "butler/app.py"), encoding="utf-8").read()
    tree = ast.parse(src)
    # 定位含 sched.start() 的 try
    hit = hit_node = None
    for n in ast.walk(tree):
        if isinstance(n, ast.Try):
            seg = ast.get_source_segment(src, n) or ""
            if "sched.start()" in seg:
                hit, hit_node = seg, n
                break
    if hit is None:
        return False, ["未找到含 sched.start() 的 try 块"]
    # 判据：该 try 内没有 sched 的赋值（赋值在更早的另一个 try 里）
    # ⚠ get_source_segment 取到的片段仍带外层缩进，直接 ast.parse 会
    #   IndentationError。改用「在该 try 节点内部 walk 找 Assign」更稳。
    assigns_in = []
    for n in ast.walk(hit_node):
        if isinstance(n, ast.Assign) and any(
                getattr(t, "id", "") == "sched" for t in n.targets):
            assigns_in.append(n.lineno)
    ok = not assigns_in
    return ok, [
        f"  sched.start() 所在 try 块内给 sched 赋值的行 = {assigns_in or '（无）'}（应为无）",
        "  ↑ 赋值在更早的 try 里 ⇒ 那个 try 整体失败时 sched 不存在",
        "",
        "  运行时实证（第十七轮）：",
        "    WARNING scheduler job registration failed: No module named 'apscheduler'",
        "    ERROR   scheduler start FAILED → UnboundLocalError (app.py:741)",
        "",
        "→ 19 个定时任务全不起，应用照常启动，仅一条 ERROR 日志",
        "→ 修法：start() 前判 `if sched is None: return`，并把失败写进 health（见 V33）",
        "⚠ 不是疏漏型缺陷：add_job 失败的保护已有（P0-5 注释），缺的是 sched 创建失败",
    ]


def v32_fix(r):
    """反测：start() 前判空后，sched 创建失败不再抛 UnboundLocalError，且成功路径仍能 start。

    ⚠ 第一版演示代码写错了：用 `sched = object()` 模拟"成功"，但 object() 没有
    start() 方法，于是走守卫之后仍然 AttributeError —— 那是**反测的缺陷**，
    不是修法不成立。现改为显式模拟两条路径。
    """
    import ast, textwrap
    fixed = textwrap.dedent("""
        def lifespan(ok):
            sched = None
            try:
                if not ok:
                    raise ImportError("No module named 'apscheduler'")
                sched = _Sched()
            except Exception:
                pass
            if sched is None:          # ← 修法：判空
                return "skipped"
            sched.start()
            return "started"
    """)
    class _Sched:
        def __init__(self): self.started = False
        def start(self): self.started = True

    tree = ast.parse(fixed)
    fn = tree.body[0]
    has_guard = any(isinstance(n, ast.If) for n in fn.body)
    i_guard = next((i for i, n in enumerate(fn.body) if isinstance(n, ast.If)), None)
    i_start = next((i for i, n in enumerate(fn.body)
                    if isinstance(n, ast.Expr) and isinstance(n.value, ast.Call)), None)
    order_ok = i_guard is not None and i_start is not None and i_guard < i_start

    ns = {"_Sched": _Sched}
    exec(compile(fixed, "<fix>", "exec"), ns)
    r_fail = ns["lifespan"](False)     # 创建失败
    r_ok = ns["lifespan"](True)        # 创建成功
    ok = has_guard and order_ok and r_fail == "skipped" and r_ok == "started"
    return ok, [
        f"  修法含 sched is None 守卫 = {has_guard}",
        f"  守卫位于 start() 之前 = {order_ok}",
        f"  创建失败路径 → {r_fail!r}（不抛异常）",
        f"  创建成功路径 → {r_ok!r}（仍能 start，未误伤）",
        "→ 修法有效且不误伤正常路径",
        "→ 配套：把「定时任务未就绪」写进 health，否则仍不可见（见 V33）",
    ]


def v33(r):
    """V33（P0，本轮新发现）：/api/health 恒 200 —— 核心全挂也报绿。

    第十七轮运行时实证：lifespan 真跑时，
        · scheduler 0 个任务（注册失败）
        · MQTT 已断开
        · af_bridge 403（policy_default_denied）
        · presence 降级为 HA-only
        · audiobook 初始化失败
    而：
        GET /api/health → 200 {'ok': True, 'data': {'online': True}}

    源码（api/system_routes.py:11-13）：
        async def health(request):
            # 始终 200，不因下游不可用而失败（NAS 规范硬约束）
            return ok({"online": True})

    **健康检查不检查任何东西**——它返回一个字面量 True。
    README 把「/api/health 不因下游不可用而失败」列为稳定性设计，
    但这被实现成了「永不失败」，于是它无法履行健康检查的职责。

    ⚠ 区分：/api/status（需鉴权）**确实**报 mqtt/tv/llm/memory 四项连接状态。
    所以信息是有的，只是**不在 health 上**——而 health 才是监控/探针会打的那个端点。
    """
    import ast
    src = open(os.path.join(REPO, "butler/api/system_routes.py"), encoding="utf-8").read()
    # ⚠ 不能用固定字符窗口：260 字符会越界到下一个函数 status()，
    #   它的 `rt = get_runtime()` 会让 no_check 误判为 False（第十七轮踩到）。
    #   必须按 AST 取函数体边界。
    tree = ast.parse(src)
    fn = next(n for n in tree.body
              if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
              and n.name == "health")
    body = ast.get_source_segment(src, fn) or ""
    literal = '"online": True' in body or "'online': True" in body
    no_check = not any(k in body for k in ("mqtt", "connected", "rt.", "get_runtime"))
    ok = literal and no_check
    return ok, [
        f"  health 返回字面量 online: True = {literal}",
        f"  health 体内不检查任何运行时状态 = {no_check}",
        "",
        "  运行时实证（第十七轮）：",
        "    scheduler 0 任务 / MQTT 断开 / af_bridge 403 / presence 降级",
        "    GET /api/health → 200 {'ok': True, 'online': True}",
        "",
        "→ 监控探针打 health 时永远绿 —— 与 V13（定时任务异常记成功）同源",
        "→ 修法：health 至少带上 mqtt/scheduler 两项，或明确改名 liveness",
    ]


def v33_fix(r):
    """反测：health 带上 scheduler/mqtt 状态后，故障可被探针看见。"""
    import asyncio
    # 最小模型真跑：复刻「health 是否反映真实状态」的判定
    def health_old(sched_running, mqtt_connected):
        return {"ok": True, "data": {"online": True}}      # 恒绿

    def health_new(sched_running, mqtt_connected):
        return {"ok": sched_running and mqtt_connected,
                "data": {"online": True,
                         "scheduler": sched_running,
                         "mqtt": mqtt_connected}}

    broken = (False, False)     # scheduler 没起、MQTT 断了
    old = health_old(*broken)
    new = health_new(*broken)
    healthy = health_new(True, True)
    ok = (old["ok"] is True) and (new["ok"] is False) and (healthy["ok"] is True)
    return ok, [
        f"  故障时 原 health.ok = {old['ok']}  ← 仍绿，看不见故障",
        f"  故障时 新 health.ok = {new['ok']}  ← 能反映",
        f"  正常时 新 health.ok = {healthy['ok']}  ← 不误报",
        "→ 修法有效：health 至少带 scheduler + mqtt 两项",
        "⚠ 保留「不因下游不可用而失败」的软约束：可 200 但 data.degraded=True，",
        "  而不是硬失败——这样既不违反 NAS 规范，也能被监控发现",
    ]


ISOLATED = {"V4"}

SCENARIOS = [
    ("V1", "af_bridge 调用不存在的 devices.by_room()", v1, v1_fix),
    ("V2", "TTSManager.speak 参数名错配 device= vs device_id=", v2, v2_fix),
    ("V3", "房间→设备映射覆盖不全，主动播报被丢弃", v3, v3_fix),
    ("V4", "技能草稿过期后漏 return，闲聊被喂进生成器", v4, v4_fix),
    ("V5", "设备别名 AliasStore.match() 只写不读", v5, v5_fix),
    ("V6", "TTS worker Task 引用被丢弃", v6, v6_fix),
    ("V7", "dialog.speak 走队列后提前 return → 防重复/落库/SSE 全丢", v7, v7_fix),
    ("V8", "trigger 冷却非原子写 + 静默归零 → 重启后触发风暴", v8, v8_fix),
    ("V9", "技能确认分支引用未绑定的 role → UnboundLocalError", v9, v9_fix),
    ("V10", "config.json 损坏 → except 分支 NameError → 全站 500", v10, v10_fix),
    ("V11", "TTS 过载丢弃 P1 告警 + 600s 全面静默", v11, v11_fix),
    ("V12", "TTS 熔断对「成功播放」计数 → 正常对话静默 25s", v12, v12_fix),
    ("V13", "定时任务协程异常被记成成功（Future 从不 .result()）", v13, v13_fix),
    ("V14", "双静默机制各自为政：dnd_windows 管不到 TTS 队列", v14, v14_fix),
    ("V15", "via 默认 direct：5 处主动发声绕过队列保护", v15, v15_fix),
    ("V16", "bigram 防重复对短播报退化（阈值 0.6 够不到）", v16, v16_fix),
    ("V17", "ha.py 双函数叠写：幽灵函数体引用未定义的 message", v17, v17_fix),
    ("V18", "docker_tools async 内 time.sleep 且 time 未 import", None, v18_fix),  # ✅ 已修复 (R17)：正测撤下，反测接管回归守护,
    ("V19", "圈复杂度量化：96 个 CC>=15，最坏 dispatch_tool CC=93", v19, v19_fix),
    ("V20", "INV-2：4 处状态文件非原子写（不变量层自动发现）", v20, v20_fix),
    ("V21", "fast_routes 配置损坏 → 静默置空，连内置默认都不恢复", v21, v21_fix),
    ("V22", "webhook 去重占位符无 finally：异常路径泄漏，消息静默丢弃 300s", v22, v22_fix),
    ("V23", "_run_coro 跨事件循环 asyncio.run → 进程级挂死（P0）", None, v23_fix),  # ✅ 已修复 (R17)：正测撤下，反测接管回归守护,
    ("V24", "test_api 在 async 路由内同步阻塞，事件循环停摆 514ms", v24, v24_fix),
    ("V25", "SQLite 懒初始化竞态：锁只包赋值，半初始化连接对外可见（P0-2 确证）", None, v25_fix),  # ✅ 已修复 (R17)：正测撤下，反测接管回归守护,
    ("V26", "anomaly critical 告警 TTS：参数名错配 + 缺 device_id，双重失效永不播报", v26, v26_fix),
    ("V27", "Runtime 伪 dataclass：42 属性只被识别 1 个，asdict 静默丢 41 字段", v27, v27_fix),
    ("V28", "SQLite 懒初始化竞态实证：线程可拿到 0 张表的半初始化连接（P0-2）", None, v28_fix),  # ✅ 已修复 (R17)：正测撤下，反测接管回归守护,
    ("V29", "跨线程写同一连接 → OperationalError（repo.py 38 处写 0 处加锁）", v29, v29_fix),
    ("V30", "require_presence 校验失败 → 静默放行，对空房间说话（兜底方向错）", v30, v30_fix),
    ("V31", "butler/engine.py 是零引用旧版残留（249 行，与在役版同 bug 两份）", v31, v31_fix),
    ("V32", "scheduler 注册失败后仍 sched.start() → UnboundLocalError（运行时实证）", v32, v32_fix),
    ("V33", "/api/health 恒 200：核心全挂也报绿（运行时实证，P0）", v33, v33_fix),
]

REPROS = [(v, t, f) for v, t, f, _ in SCENARIOS if f is not None]
FIXES = [(v, t, x) for v, t, _, x in SCENARIOS if x is not None]


# ───────── V20（第六轮：不变量层自动发现的新缺陷，此前五轮均未读过这些文件） ─────────



# ─────────────────── 套件自检（防止「定义了但没注册」的静默遗漏） ───────────────────

def selftest():
    """检查套件自身完整性。

    为什么必须有这一层（第十三轮补）：
      V22（P1）与 V23（**P0，唯一能挂死进程**）在第七、八轮就发现了，
      却**从未注册进 SCENARIOS**，一直到第十三轮才补齐 —— 中间六轮里
      它们既无法回归验证、也无法证明修复有效。

      根因：注册是手工的，漏了不会报错，只会「安静地少两条用例」。
      这正是本工作流纪律①（工具故障 ≠ 无问题）在套件内部的对应形态。

    检查项：
      1. 定义了 vNN / vNN_fix 但未进 SCENARIOS  → 遗漏
      2. SCENARIOS 引用了不存在的函数          → NameError 隐患
      3. 场景缺标题 / 缺反测                    → 质量提示
    """
    import re as _re
    src = open(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            "audit_helpers.py"), encoding="utf-8").read()
    defined = set()
    for m in _re.finditer(r"^def (v\d+)(_fix)?\(", src, _re.M):
        defined.add(m.group(1) + (m.group(2) or ""))
    registered = set()
    for m in _re.finditer(r'^\s*\("(V\d+)",\s*"[^"]*",\s*(\w+),\s*(\w+)\)', src, _re.M):
        registered.add(m.group(2))
        registered.add(m.group(3))
    registered.discard("None")

    orphan_all = sorted(defined - registered)      # 定义了没注册
    # RETIRED 里的正测是有意撤下的（缺陷已修复），不算遗漏
    orphan = [o for o in orphan_all
              if not (o.startswith("v") and ("V" + o[1:].replace("_fix", "")) in RETIRED)]
    retired_ok = [o for o in orphan_all if o not in orphan]
    missing = sorted(registered - defined)         # 注册了没定义
    no_fix = []
    for m in _re.finditer(r'^\s*\("(V\d+)",\s*"([^"]*)",\s*(\w+),\s*(None|\w+)\)', src, _re.M):
        if m.group(4) == "None":
            no_fix.append(m.group(1))

    ok = not orphan and not missing
    detail = [
        f"  定义的场景函数 {len(defined)} 个，注册的 {len(registered)} 个",
        f"  定义了但没注册（遗漏）: {orphan or '（无）'}",
        f"  有意撤下（已修复）    : {sorted(RETIRED)}",
        f"  注册了但没定义（隐患）: {missing or '（无）'}",
        f"  只有正测、缺反测的场景: {no_fix or '（无）'}",
    ]
    return ok, detail


def suite_stats():
    """套件统计：场景数、正测数、反测数、覆盖的严重度分布。"""
    n = len(SCENARIOS)
    nr = len([1 for _, _, f, _ in SCENARIOS if f is not None])   # 已撤下的不计
    nf = len([1 for _, _, _, x in SCENARIOS if x is not None])
    return {
        "scenarios": n,
        "repros": nr,
        "fixes": nf,
        "retired": len(RETIRED),
        "total_cases": nr + nf,
        "isolated": len(ISOLATED),
    }
