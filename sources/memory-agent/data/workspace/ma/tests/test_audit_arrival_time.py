"""审计补测：behavior_predictor / daily_profile 的『到家时间』语义契约。

覆盖审计 P1-4 与 P1-6：

    两个函数都自称『每天第一次出现』，但函数内不排序，
    实际取的是输入序列里该天的第一条/最后一条——取决于调用方喂的顺序。
    生产侧 `list_behavior_events` 的 SQL 是 ORDER BY server_ts DESC。

**先红后绿**：DESC 相关断言当前应失败（红）。

⚠ 关键：本文件的入参必须与生产一致（**DESC**）。
若用 ASC 数据，会得到『测试通过但生产错误』的假安全——
这正是第三轮 P1-6 的教训：那个测试喂 ASC、生产是 DESC。
"""

from __future__ import annotations

import json
from datetime import datetime

import pytest

from memory_agent.behavior_predictor import predict_arrival_time
from memory_agent.daily_profile import compute_return_time_baseline

PERSON = "Kevin"
# 每天的 3 个事件：8 点离家 / 19 点到家 / 23 点睡前
# 真实到家 = 19.0
EVENT_HOURS = (8, 19, 23)
TRUE_ARRIVAL = 19.0
DAYS = 3


def _events(field: str):
    """构造 N 天数据；field 是两个函数各用的字段名。"""
    out = []
    for d in range(1, DAYS + 1):
        for h in EVENT_HOURS:
            dt = datetime(2026, 10, d, h, 0, 0)
            ev = {"server_ts": dt.isoformat()}
            if field == "persons_json":
                ev["persons_json"] = json.dumps([{"name": PERSON}])
            else:
                ev["persons"] = [{"name": PERSON}]
            out.append(ev)
    return out


def _desc(evs):
    """生产顺序：ORDER BY server_ts DESC。"""
    return sorted(evs, key=lambda e: e["server_ts"], reverse=True)


def _asc(evs):
    return sorted(evs, key=lambda e: e["server_ts"])


# ── P1-4 predict_arrival_time ──────────────────────────────────


def test_arrival_desc_matches_real_arrival():
    """生产喂 DESC 时，predict_arrival_time 应返回真实到家时间 19.0。"""
    evs = _desc(_events("persons_json"))
    r = predict_arrival_time(evs, PERSON, min_days=3)
    assert r is not None, "数据充足不应返回 None"
    assert r["predicted_hour"] == pytest.approx(TRUE_ARRIVAL, abs=0.01), (
        f"DESC 输入下应取日到家时间 {TRUE_ARRIVAL}，实得 {r['predicted_hour']}"
    )


def test_arrival_asc_also_matches_real_arrival():
    """ASC 同样应返回 19.0——不只是『改成 ASC』就能修好。

    第二轮审计曾建议『改成 ASC 即可』，真实验证推翻了：
    ASC 下取到的是 8.0（离家时间），同样错误。
    """
    evs = _asc(_events("persons_json"))
    r = predict_arrival_time(evs, PERSON, min_days=3)
    assert r is not None
    assert r["predicted_hour"] == pytest.approx(TRUE_ARRIVAL, abs=0.01), (
        f"ASC 输入下也应取到家时间 {TRUE_ARRIVAL}，实得 {r['predicted_hour']}"
    )


def test_arrival_is_order_independent():
    """同一批数据，顺序不同结果必须一致（核心契约）。"""
    evs = _events("persons_json")
    a = predict_arrival_time(_asc(evs), PERSON, min_days=3)
    b = predict_arrival_time(_desc(evs), PERSON, min_days=3)
    assert a["predicted_hour"] == pytest.approx(b["predicted_hour"], abs=0.01)


# ── P1-6 compute_return_time_baseline ──────────────────────────


def test_baseline_desc_matches_real_arrival():
    evs = _desc(_events("persons"))
    r = compute_return_time_baseline(evs, PERSON, min_days=3)
    assert r is not None
    assert r["median_hour"] == pytest.approx(TRUE_ARRIVAL, abs=0.01), (
        f"基线应为 {TRUE_ARRIVAL}，实得 {r['median_hour']}"
    )


def test_baseline_is_order_independent():
    evs = _events("persons")
    a = compute_return_time_baseline(_asc(evs), PERSON, min_days=3)
    b = compute_return_time_baseline(_desc(evs), PERSON, min_days=3)
    assert a["median_hour"] == pytest.approx(b["median_hour"], abs=0.01)


# ── 不应 regressions 的正常语义 ────────────────────────────────


def test_insufficient_days_returns_none():
    """数据不足 min_days 时应返回 None（当前应通过）。"""
    evs = _events("persons_json")[:2]
    assert predict_arrival_time(evs, PERSON, min_days=3) is None


def test_other_person_excluded():
    """只应统计目标人物的事件（当前应通过）。"""
    evs = _desc(_events("persons_json"))
    assert predict_arrival_time(evs, "Nobody", min_days=3) is None
