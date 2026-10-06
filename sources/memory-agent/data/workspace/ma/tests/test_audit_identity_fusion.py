"""审计补测：identity_fusion 身份融合的语义契约。

覆盖审计 P1-5：未匹配信号不应稀释已匹配结果。

**先红后绿**：这些断言在当前实现下应当失败（红），
修复 normalize 分母后应转绿。若一开始就全绿，说明断言写错了。

数据来源：A2 缺陷验证矩阵中真实 `fuse()` 的实测结果。
"""

from __future__ import annotations

import time

import pytest

from memory_agent.identity_fusion import (
    ManualMode,
    SignalEvidence,
    Source,
    fuse,
)

NOW = time.time()


def mk(src: Source, cid, conf: float, room: str = "study"):
    return SignalEvidence(
        signal_id=f"s_{src.value}_{cid}_{conf}",
        source=src,
        candidate_id=cid,
        confidence=conf,
        event_ts=NOW,
        room_id=room,
        manual_mode=ManualMode.CONFIRM if src == Source.MANUAL else None,
        raw_score=conf,
    )


def score_of(result, cid):
    for s in result.scores:
        if s.candidate_id == cid:
            return s.score_final
    return None


# ── P1-5 主断言 ────────────────────────────────────────────────


def test_matched_signal_alone_has_full_confidence():
    """仅一路已匹配信号时，得分应等于该信号置信度。"""
    r = fuse("study", [mk(Source.ARCFACE, "A", 0.9)], now=NOW)
    assert score_of(r, "A") == pytest.approx(0.9, abs=1e-6), "单信号应保留原置信度"
    assert r.chosen_id == "A"


def test_unmatched_signal_must_not_dilute_matched_one():
    """核心断言：多来一路『未匹配』信号，不应降低已匹配候选的得分。

    当前实现把未匹配信号的权重计入归一化分母 total_weight，
    但分子不含它 → 已匹配结果被稀释。这是语义错误。
    """
    r = fuse("study", [mk(Source.ARCFACE, "A", 0.9)], now=NOW)
    base = score_of(r, "A")

    r2 = fuse(
        "study",
        [mk(Source.ARCFACE, "A", 0.9), mk(Source.HA_FACE, None, 0.9)],
        now=NOW,
    )
    after = score_of(r2, "A")

    assert after == pytest.approx(base, abs=1e-6), (
        f"未匹配信号不应改变已匹配候选得分：{base} → {after}"
    )


def test_unmatched_signal_must_not_invert_winner():
    """已认出 A 之后，再来一路『没认出来』的信号，不应把结果翻成陌生人。"""
    r = fuse(
        "study",
        [mk(Source.ARCFACE, "A", 0.9), mk(Source.HA_FACE, None, 0.9)],
        now=NOW,
    )
    assert r.chosen_id == "A", "已被人脸识别命中的候选不应被未匹配信号反超"


def test_weak_unmatched_signal_must_not_downgrade_level():
    """即使不足以翻盘，未匹配信号也不应压低置信度等级。

    实测：A 从 0.900/HIGH 被压到 0.600/NEEDS_REVIEW，而 A 的证据本身没变。
    """
    solo = fuse("study", [mk(Source.ARCFACE, "A", 0.9)], now=NOW)
    with_weak = fuse(
        "study",
        [mk(Source.ARCFACE, "A", 0.9), mk(Source.HA_FACE, None, 0.5)],
        now=NOW,
    )
    assert with_weak.confidence == pytest.approx(solo.confidence, abs=1e-6), (
        f"置信度不应被未匹配信号压低：{solo.confidence} → {with_weak.confidence}"
    )
    assert with_weak.level == solo.level


# ── 不应 regressions 的正常语义 ────────────────────────────────


def test_two_agreeing_signals_stay_high():
    """两路都指向 A 时，结果应为 A 且不低于单路置信度（对照组，当前应通过）。"""
    r = fuse(
        "study",
        [mk(Source.ARCFACE, "A", 0.9), mk(Source.HA_FACE, "A", 0.8)],
        now=NOW,
    )
    assert r.chosen_id == "A"
    assert r.confidence >= 0.8


def test_no_signals_returns_none():
    """无信号时应返回陌生人，不应崩溃（当前应通过）。"""
    r = fuse("study", [], now=NOW)
    assert r.chosen_id is None
