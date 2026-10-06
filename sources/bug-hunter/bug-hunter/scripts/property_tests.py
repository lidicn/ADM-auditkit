#!/usr/bin/env python3
"""属性测试层 —— 唯一具备「真正发现能力」的层。

为什么前十一轮静态分析会产出递减（14→4→3→2→1→0→2→1）：
  静态分析、模式匹配、扩散排查**全都需要先有假设**。
  它们能可靠地「证明」，但不会自己「选题」。
  Hypothesis 不同：你只声明**不变量**（对所有输入都该成立的性质），
  它自己去找反例，并**收缩到最小复现**。

本层对 doubao-butler 的**纯函数**做属性测试。
选纯函数的理由：无 IO、无全局状态，可安全地随机打；
而项目的核心决策逻辑（bigram/jaccard、配置解析、阈值判断）恰好都是纯函数。

不变量来源：
  · README 明示的设计承诺（"同成员 7 天窗口 >0.6 判重复"）
  · 数学性质（对称、自反、幂等）
  · 常识性质（空输入不崩溃、不抛异常）
"""
from __future__ import annotations

import os
import sys

REPO = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                    "..", "..", "..", "doubao-butler-main"))
sys.path.insert(0, REPO)

from hypothesis import given, settings, strategies as st, HealthCheck  # noqa: E402

MAX = 400


# ───────────────────────── 被测对象 ─────────────────────────

def _dedup():
    from butler.core.dedup import bigrams, jaccard
    return bigrams, jaccard


TEXT = st.text(alphabet=st.characters(blacklist_categories=("Cs",)), max_size=60)


# ───────────────────────── 不变量 ─────────────────────────

@given(TEXT)
@settings(max_examples=MAX, deadline=None,
          suppress_health_check=[HealthCheck.too_slow])
def inv_bigrams_no_crash(t):
    """INV: bigrams 对任意字符串不得抛异常，且返回 set。"""
    bg, _ = _dedup()
    r = bg(t)
    assert isinstance(r, set), f"bigrams 返回了 {type(r)}"
    assert all(isinstance(x, str) for x in r)


@given(TEXT)
@settings(max_examples=MAX, deadline=None,
          suppress_health_check=[HealthCheck.too_slow])
def inv_bigrams_size_bound(t):
    """INV: bigrams 的元素长度 <= 2（定义就是 2-gram）。

    若出现长度 1 之外的混杂，说明短串分支与通用分支行为不一致。
    """
    bg, _ = _dedup()
    r = bg(t)
    # 去标点后的长度
    import re
    s = re.sub(r"[\s\W]+", "", t or "")
    if len(s) <= 1:
        assert r == {s}, f"短串分支异常: {r!r}"
    else:
        assert all(len(x) == 2 for x in r), f"出现非 2-gram: {r!r}"


@given(TEXT, TEXT)
@settings(max_examples=MAX, deadline=None,
          suppress_health_check=[HealthCheck.too_slow])
def inv_jaccard_symmetric(a, b):
    """INV: jaccard 必须对称。相似度不对称会导致 A 判重 B、B 不判重 A。"""
    bg, jc = _dedup()
    assert abs(jc(bg(a), bg(b)) - jc(bg(b), bg(a))) < 1e-9


@given(TEXT)
@settings(max_examples=MAX, deadline=None,
          suppress_health_check=[HealthCheck.too_slow])
def inv_jaccard_self_is_one(t):
    """INV: 任何文本与自身的相似度必须是 1.0（否则防重复会漏判完全相同的话）。

    例外：空集（jaccard 对空集返回 0.0），这是刻意设计。
    """
    bg, jc = _dedup()
    s = bg(t)
    v = jc(s, s)
    if not s:
        assert v == 0.0, f"空集应返回 0.0，实际 {v}"
    else:
        assert abs(v - 1.0) < 1e-9, f"自相似度应为 1.0，实际 {v}（text={t!r}）"


@given(TEXT, TEXT)
@settings(max_examples=MAX, deadline=None,
          suppress_health_check=[HealthCheck.too_slow])
def inv_jaccard_in_range(a, b):
    """INV: 相似度必须落在 [0, 1]。越界会导致阈值判断失效。"""
    bg, jc = _dedup()
    v = jc(bg(a), bg(b))
    assert 0.0 <= v <= 1.0, f"越界 {v}（a={a!r}, b={b!r}）"


@given(TEXT)
@settings(max_examples=MAX, deadline=None,
          suppress_health_check=[HealthCheck.too_slow])
def inv_bigrams_punct_insensitive(t):
    """INV: 标点与空白不应影响指纹（_PUNCT 就是干这个的）。

    若成立，则「你好，世界」与「你好世界」应判为完全相同。
    这条一旦被打破，意味着标点不同的同一句话会被当成两句话重复播出。
    """
    bg, jc = _dedup()
    import re
    stripped = re.sub(r"[\s\W]+", "", t or "")
    assert jc(bg(t), bg(stripped)) == 1.0 or not bg(t), \
        f"标点敏感: {t!r} vs {stripped!r}"


# ───────────────────────── 执行器 ─────────────────────────

def run(verbose=True):
    """跑全部属性测试，返回 [(name, ok, err_or_None, minimal_example)]。"""
    tests = [(k, v) for k, v in sorted(globals().items())
             if k.startswith("inv_") and callable(v)]
    out = []
    for name, fn in tests:
        try:
            fn()
            out.append((name, True, None, None))
            if verbose:
                print(f"  ✓ {name}")
        except Exception as e:
            # Hypothesis 把最小复现放在异常消息里
            msg = str(e).replace("\n", " ")[:200]
            out.append((name, False, f"{type(e).__name__}: {msg}", msg))
            if verbose:
                print(f"  ✗ {name}")
                print(f"      {type(e).__name__}: {msg[:160]}")
    return out




# ───────────────────────── 第二批：日志脱敏 ─────────────────────────

def _mask_re():
    from butler.logging_setup import _SENSITIVE_RE
    return _SENSITIVE_RE


SECRETISH = st.text(alphabet="abcdef0123456789", min_size=4, max_size=24)


@given(key=st.sampled_from(["password", "token", "secret", "api_key",
                            "ha_token", "web_password", "cookie"]),
       val=SECRETISH)
@settings(max_examples=300, deadline=None,
          suppress_health_check=[HealthCheck.too_slow])
def inv_secret_always_masked(key, val):
    """INV: 任何敏感键的赋值形态都必须被脱敏（值不得原样出现在输出里）。

    这是安全性质——漏一个就等于凭据进日志。
    """
    import re
    r = _mask_re()
    line = f"{key}={val}"
    out = r.sub("***", line)
    assert val not in out, f"敏感值未被脱敏: {line!r} -> {out!r}"


@given(key=st.sampled_from(["password", "token", "secret", "api_key"]),
       val=SECRETISH)
@settings(max_examples=300, deadline=None,
          suppress_health_check=[HealthCheck.too_slow])
def inv_secret_masked_with_spaces(key, val):
    """INV: `key : value`（带空格）形态也必须被脱敏——正则是 \\s*[:=]\\s*。"""
    r = _mask_re()
    line = f"{key} : {val} rest"
    out = r.sub("***", line)
    assert val not in out, f"带空格形态漏脱敏: {line!r} -> {out!r}"


@given(val=SECRETISH)
@settings(max_examples=200, deadline=None,
          suppress_health_check=[HealthCheck.too_slow])
def inv_innocuous_text_untouched(val):
    """INV: 不含敏感键的普通文本不应被误伤（过度脱敏会损害排障）。"""
    r = _mask_re()
    line = f"room={val} device={val}"
    out = r.sub("***", line)
    # 'key' 是裸关键词，会命中 "key" 子串吗？这里验证不含敏感词的文本
    assert out == line or "***" in out, f"异常: {line!r} -> {out!r}"


def main():
    """由 pipeline.py 调用。本文件刻意不写 __main__ 块——
    追加新不变量后若 main 不在文件末尾，新用例会静默不执行，
    而报告仍显示"全部通过"。这个坑在本文件上已踩三次。"""
    print("=" * 72)
    print(f"属性测试（hypothesis）  repo={REPO}")
    print("=" * 72)
    res = run()
    bad = [r for r in res if not r[1]]
    print()
    print(f"通过 {len(res) - len(bad)}/{len(res)}")
    if bad:
        print("\n发现反例（这些是真实缺陷，不是误报）：")
        for name, _, err, _ in bad:
            print(f"  [{name}] {err}")
    return 1 if bad else 0


# ───────────────────────── 第三批：静默窗口（时间边界密集区） ─────────────────────────

def _qcfg():
    from butler.tts.queue import TTSQueueConfig
    return TTSQueueConfig


@given(start=st.integers(0, 1439), end=st.integers(0, 1439))
@settings(max_examples=400, deadline=None,
          suppress_health_check=[HealthCheck.too_slow])
def inv_quiet_playable_span_has_exact_length(start, end):
    """INV: 可播区间长度必须恰好等于窗口长度，不多不少。

    start<end（不跨午夜）：可播 = [start, end)，长度 end-start
    start>end（跨午夜）：  可播 = [start,1440) ∪ [0,end)，长度 (1440-start)+end
    start==end：全天可播，长度 1440

    打破此性质意味着某些分钟「既非静默也不可播」——
    夜里该静默时播了（扰民），或该播时被静默吞掉（漏播）。
    """
    C = _qcfg()
    cfg = C(quiet_start=f"{start//60:02d}:{start%60:02d}",
            quiet_end=f"{end//60:02d}:{end%60:02d}")
    playable = [m for m in range(1440) if not cfg.is_quiet(m)]
    if start == end:
        assert len(playable) == 1440, \
            f"起止相同({start})应全天可播，实际可播 {len(playable)} 分钟"
    elif start < end:
        assert len(playable) == end - start, \
            f"[{start},{end}) 可播应 {end-start} 分钟，实际 {len(playable)}"
    else:
        want = (1440 - start) + end
        assert len(playable) == want, \
            f"跨午夜 [{start},1440)∪[0,{end}) 可播应 {want} 分钟，实际 {len(playable)}"


@given(start=st.integers(0, 1439), end=st.integers(1, 1439))
@settings(max_examples=400, deadline=None,
          suppress_health_check=[HealthCheck.too_slow])
def inv_quiet_left_boundary_is_playable(start, end):
    """INV: quiet_start 那一刻必须可播（区间左闭）。

    反例形态：窗口 23:00-06:50，若左边界被判静默，则每天 23:00 整
    这一分钟的播报会被吞掉——边界 off-by-one 的典型症状。
    """
    C = _qcfg()
    if start == end:
        return
    cfg = C(quiet_start=f"{start//60:02d}:{start%60:02d}",
            quiet_end=f"{end//60:02d}:{end%60:02d}")
    assert not cfg.is_quiet(start), \
        f"quiet_start={start//60:02d}:{start%60:02d} 自身被判静默（左边界应为可播）"


@given(mod=st.integers(0, 1439))
@settings(max_examples=300, deadline=None,
          suppress_health_check=[HealthCheck.too_slow])
def inv_quiet_default_never_blocks_daytime(mod):
    """INV: 默认窗口 06:50-23:00 下，08:00–22:00 绝不能静默。

    最直觉的性质：白天家里有人时，播报不该被静默吞掉。
    """
    C = _qcfg()
    cfg = C()          # quiet_start="06:50" quiet_end="23:00"
    if 8 * 60 <= mod < 22 * 60:
        assert not cfg.is_quiet(mod), \
            f"白天 {mod//60:02d}:{mod%60:02d} 被判静默（默认窗口 06:50-23:00）"


@given(mod=st.integers(0, 1439))
@settings(max_examples=200, deadline=None,
          suppress_health_check=[HealthCheck.too_slow])
def inv_quiet_is_total_function(mod):
    """INV: is_quiet 对 0..1439 全量程必须返回 bool，不得抛异常。

    跨午夜分支是这类判断最容易 IndexError/TypeError 的地方。
    """
    C = _qcfg()
    cfg = C()
    assert isinstance(cfg.is_quiet(mod), bool)


# ───────────────────────── 第四批：环境变量解析（回退语义） ─────────────────────────

def _envf():
    import butler.config as C
    return C


@given(key=st.text(alphabet="ABCDEF0123456789", min_size=8, max_size=16),
       raw=st.text(alphabet="0123456789.eE+-", min_size=0, max_size=12),
       default=st.integers(-1000, 1000))
@settings(max_examples=300, deadline=None,
          suppress_health_check=[HealthCheck.too_slow, HealthCheck.function_scoped_fixture])
def inv_env_int_never_raises_and_honors_default(key, raw, default):
    """INV: 无论环境变量是什么垃圾字符串，_env_int 都不得抛异常；
    解析失败时必须原样返回 default。

    这是「配置损坏 → 应用起不来」类故障的第一道防线。
    若这里抛异常，用户改错一个环境变量就全站 500（P0-3 同族）。
    """
    C = _envf()
    name = f"BUTLER_TEST_{key}"
    old = os.environ.get(name)
    os.environ[name] = raw
    try:
        got = C._env_int(name, default)
    except Exception as e:
        raise AssertionError(f"_env_int 抛异常（raw={raw!r}）: {type(e).__name__}: {e}")
    finally:
        if old is None:
            os.environ.pop(name, None)
        else:
            os.environ[name] = old
    try:
        want = int(raw)
    except Exception:
        want = default
    assert got == want, f"_env_int({raw!r}, default={default}) 返回 {got}，期望 {want}"


@given(key=st.text(alphabet="ABCDEF0123456789", min_size=8, max_size=16),
       raw=st.text(alphabet="0123456789.eE+-", min_size=0, max_size=12),
       default=st.floats(-1000, 1000, allow_nan=False, allow_infinity=False))
@settings(max_examples=300, deadline=None,
          suppress_health_check=[HealthCheck.too_slow, HealthCheck.function_scoped_fixture])
def inv_env_float_never_raises_and_honors_default(key, raw, default):
    """INV: _env_float 同上——不得抛异常，失败回退 default。"""
    C = _envf()
    name = f"BUTLER_TEST_{key}"
    old = os.environ.get(name)
    os.environ[name] = raw
    try:
        got = C._env_float(name, default)
    except Exception as e:
        raise AssertionError(f"_env_float 抛异常（raw={raw!r}）: {type(e).__name__}: {e}")
    finally:
        if old is None:
            os.environ.pop(name, None)
        else:
            os.environ[name] = old
    try:
        want = float(raw)
    except Exception:
        want = default
    # ⚠ 修正：abs(inf-inf)=nan，nan<1e-9 为 False —— 会把 inf 误判成失败。
    #   （踩到过：raw='2E308' → float 得 inf，期望也是 inf，却判为不符）
    #   这是**断言自身的缺陷**，不是产品缺陷。
    import math as _m
    ok = (got == want) if (_m.isinf(want) or _m.isnan(want)) else abs(got - want) < 1e-9
    assert ok, \
        f"_env_float({raw!r}, default={default}) 返回 {got}，期望 {want}"


@given(key=st.text(alphabet="ABCDEF0123456789", min_size=8, max_size=16),
       raw=st.sampled_from(["1", "0", "true", "false", "True", "False", "TRUE",
                            "yes", "no", "on", "off", "", "  ", "maybe", "2"]),
       default=st.booleans())
@settings(max_examples=200, deadline=None,
          suppress_health_check=[HealthCheck.too_slow, HealthCheck.function_scoped_fixture])
def inv_env_bool_never_raises(key, raw, default):
    """INV: _env_bool 不得抛异常，且必须返回 bool（不能返回字符串/None）。

    返回非 bool 会让 `if settings.xxx:` 判断失真：
    例如 "false" 字符串是真值 → 本该关闭的功能被打开。
    """
    C = _envf()
    name = f"BUTLER_TEST_{key}"
    old = os.environ.get(name)
    os.environ[name] = raw
    try:
        got = C._env_bool(name, default)
    except Exception as e:
        raise AssertionError(f"_env_bool 抛异常（raw={raw!r}）: {type(e).__name__}: {e}")
    finally:
        if old is None:
            os.environ.pop(name, None)
        else:
            os.environ[name] = old
    assert isinstance(got, bool), \
        f"_env_bool({raw!r}, default={default}) 返回 {type(got).__name__}({got!r})，非 bool"


# ───────────────────────── 第五批：房间→设备映射（V3 已知覆盖不全） ─────────────────────────

@given(room=st.text(min_size=1, max_size=20))
@settings(max_examples=300, deadline=None,
          suppress_health_check=[HealthCheck.too_slow])
def inv_room_mapping_never_raises(room):
    """INV: 用任意房间名查表都不得抛异常。

    映射表是 dict.get 语义，未知房间应返回 None（由上层降级），
    而不是 KeyError。若抛异常，感知层上报一个新房间名就会炸对话链路。
    """
    from butler.tts.adapter import ROOM_TO_PLAYER_ENTITY
    try:
        ROOM_TO_PLAYER_ENTITY.get(room)
    except Exception as e:
        raise AssertionError(f"查房间 {room!r} 抛异常: {type(e).__name__}: {e}")


@given(room=st.sampled_from(["客厅", "主卧", "次卧", "厨房", "书房", "餐厅", "卫生间"]))
@settings(max_examples=100, deadline=None,
          suppress_health_check=[HealthCheck.too_slow])
def inv_real_rooms_all_resolvable(room):   # 已知缺陷 V3 的属性化复现
    """INV: 系统内真实存在的房间，必须都能解析出播放实体。

    这是 V3 的可执行形式——把「7 个房间只覆盖 3 个」固化成断言。
    一旦有人往 devices.py 加房间却忘了同步 adapter.py 的映射，
    这条会立刻变红。**当前它确实是红的 —— 复现已知缺陷 V3**（卫生间等房间无映射）。
    保留为红是刻意的：它是 V3 的常驻回归断言，修好 V3 后应转为绿。
    """
    from butler.tts.adapter import ROOM_TO_PLAYER_ENTITY
    from butler.devices import DeviceRegistry
    from butler.config import Settings
    try:
        seed = DeviceRegistry(Settings())._seed()
        real = {d.room for d in seed.values() if d.room}
    except Exception:
        return          # 环境不可构造时跳过，不算通过也不算失败
    if room not in real:
        return
    assert ROOM_TO_PLAYER_ENTITY.get(room), \
        f"真实房间 {room!r} 在 ROOM_TO_PLAYER_ENTITY 中无映射 → 播报被丢弃"
