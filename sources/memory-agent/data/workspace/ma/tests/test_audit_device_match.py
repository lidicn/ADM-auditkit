"""审计补测：voice_util.match_device 的设备匹配语义契约。

覆盖审计 P2-9：候选名互为前缀时，匹配退化为『按 friendly_name 长度降序
取最长』，导致用户问『书房电脑』拿到『书房电脑插座』。

**先红后绿**：P2-9 相关断言当前应失败（红）。

命名歧义在家庭 HA 中极常见：电脑/电脑插座、灯/灯带、空调/空调插座、
电视/电视机顶盒。
"""

from __future__ import annotations

import pytest

from memory_agent.voice_util import match_device


class _FakeInsights:
    """最小替身：match_device 只用到 name_map 与 resolve_room_in_text。"""

    def __init__(self, name_map):
        self._nm = name_map

    def name_map(self):
        return self._nm

    def resolve_room_in_text(self, text):
        return {}


def _insights(pairs=None):
    if pairs is None:
        pairs = [
            ("switch.study_pc", "书房电脑", "书房"),      # 4 字
            ("switch.study_plug", "书房电脑插座", "书房"),  # 6 字
        ]
    nm = {
        eid: {"friendly_name": name, "domain": eid.split(".")[0], "room": room}
        for eid, name, room in pairs
    }
    return _FakeInsights(nm)


# ── P2-9 主断言 ────────────────────────────────────────────────


def test_exact_name_wins_over_longer_prefix_extension():
    """查询『书房电脑』应命中『书房电脑』，而不是『书房电脑插座』。"""
    ins = _insights()
    r = match_device("书房电脑开了多久", ins)
    assert r.get("entity_id") == "switch.study_pc", (
        f"应精确命中书房电脑，实得 {r.get('entity_id')} ({r.get('query')})"
    )


def test_bare_noun_does_not_match_its_own_plug():
    """用户只说『电脑』时，不应匹配到『电脑插座』。"""
    ins = _insights()
    r = match_device("电脑", ins)
    assert r.get("entity_id") == "switch.study_pc", (
        f"裸名词『电脑』应命中电脑本体，实得 {r.get('entity_id')}"
    )


def test_full_name_still_matches_itself():
    """查询完整名『书房电脑插座』时仍应命中插座（对照组，当前应通过）。"""
    ins = _insights()
    r = match_device("书房电脑插座用了多久", ins)
    assert r.get("entity_id") == "switch.study_plug"


# ── 同类命名歧义（灯/灯带、空调/空调插座）─────────────────────


@pytest.mark.parametrize(
    "short,long_short_query",
    [
        ("客厅灯", "客厅灯带"),
        ("主卧空调", "主卧空调插座"),
    ],
)
def test_prefix_ambiguity_family(short, long_short_query):
    """同一族命名歧义：查短名应得短名实体，不应被更长的派生名抢走。"""
    pairs = [
        (f"switch.{short}", short, "测试房"),
        (f"switch.{long_short_query}", long_short_query, "测试房"),
    ]
    ins = _insights(pairs)
    r = match_device(f"{short}开了多久", ins)
    assert r.get("entity_id") == f"switch.{short}", (
        f"查『{short}』应命中本体，实得 {r.get('entity_id')} ({r.get('query')})"
    )


# ── 不应 regressions 的正常语义 ────────────────────────────────


def test_no_match_returns_none():
    """查不存在的设备应返回 None，不崩溃（当前应通过）。

    注：初版此处误写成 `assert r is not None`，与真实语义相反。
    无匹配返回 None 是正确行为，测试应反映实际契约。
    """
    ins = _insights()
    r = match_device("车库门开了多久", ins)
    assert r is None
