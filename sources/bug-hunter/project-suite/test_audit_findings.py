"""审计发现的缺陷复现套件（pytest 版，可直接挂 CI）。

与 verify_findings.py 共用 tests/audit_helpers.py 的 SCENARIOS，不存在两份定义。

用例分两类，生命周期不同：

  bug_repro（正测）  断言「缺陷行为成立」。
                    失败只有两种可能：
                      ① bug 已修复 → 删掉这条正测，反测已接管回归守护
                      ② 桩件/依赖失效 → 修用例，绝不能当成「项目已恢复健康」
                    它是「缺陷还活着」的探针，不是健康度指标。

  countermeasure（反测）  注入报告里给出的修复方案后，断言行为恢复正常。
                    常驻不动——这才是真正的回归防线。

跑法：
    python3 -m pytest tests/test_audit_findings.py -v
    python3 -m pytest -m countermeasure        # 只跑常驻防线
    python3 -m pytest -m bug_repro             # 只看缺陷是否还在
"""
from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from audit_helpers import FIXES, ISOLATED, REPROS, InfraError, Restore  # noqa: E402


_INFRA_HITS: list = []


def _mark_infra(vid):
    """记录 INFRA-ERROR，供 session 结束时汇总。

    ERROR 与 REFUTED 必须分开统计：
      ERROR   = 工具/环境坏了 —— 结论是「本轮这条没验成」
      REFUTED = 断言真的不成立 —— 结论是「缺陷/修法有问题」
    混在一起会让「依赖缺失」静默洗白真实缺陷。
    """
    _INFRA_HITS.append(vid)


@pytest.fixture(scope="session", autouse=True)
def _report_infra():
    yield
    if _INFRA_HITS:
        print("\n" + "=" * 72)
        print(f"INFRA-ERROR（工具/环境缺失，非缺陷结论）：{len(_INFRA_HITS)} 条")
        print("  " + " ".join(sorted(set(_INFRA_HITS))))
        print("  → 这些条目本轮**未验成**，不得计入「已通过」也不得计入「已推翻」")
        print("=" * 72)


@pytest.fixture
def restore():
    """每条用例一个隔离器，跑完强制回滚所有被改动的全局状态。"""
    r = Restore()
    yield r
    r.restore_all()


def _show(detail):
    for line in detail:
        print(f"       {line}")


@pytest.mark.bug_repro
@pytest.mark.isolated
@pytest.mark.skipif(
    os.environ.get("RUN_ISOLATED") != "1",
    reason="需进程隔离：单独跑变绿、整档跑会污染 test_decision_engine（RUN_ISOLATED=1 才执行）",
)
@pytest.mark.parametrize("vid,title,fn", [x for x in REPROS if x[0] in ISOLATED],
                         ids=[x[0] for x in REPROS if x[0] in ISOLATED])
def test_bug_reproduced_isolated(vid, title, fn, restore):
    ok, detail = fn(restore)
    _show(detail)
    assert ok, f"[{vid}] {title} —— 缺陷未复现（同 test_bug_reproduced 的两类判定）"


@pytest.mark.bug_repro
@pytest.mark.parametrize("vid,title,fn", [x for x in REPROS if x[0] not in ISOLATED],
                         ids=[x[0] for x in REPROS if x[0] not in ISOLATED])
def test_bug_reproduced(vid, title, fn, restore):
    try:
        ok, detail = fn(restore)
    except InfraError as e:
        _mark_infra(vid)
        pytest.fail(f"INFRA-ERROR [{vid}] 环境/工具缺失，非缺陷被推翻：{e}", pytrace=False)
    _show(detail)
    assert ok, (
        f"[{vid}] {title} —— 缺陷未复现。\n"
        f"        两种可能，请人工判定，不要直接删断言：\n"
        f"        ① 已修复 → 删除本条正测（{vid}_fix 反测已接管回归守护）\n"
        f"        ② 桩件/依赖失效 → 修用例（若属此项而误判为①，等于把缺陷洗白）"
    )


@pytest.mark.countermeasure
@pytest.mark.parametrize("vid,title,fix", FIXES, ids=[f"{x[0]}*" for x in FIXES])
def test_countermeasure(vid, title, fix, restore):
    try:
        ok, detail = fix(restore)
    except InfraError as e:
        _mark_infra(vid)
        pytest.fail(f"INFRA-ERROR [{vid}*] 环境/工具缺失，非修法不成立：{e}", pytrace=False)
    _show(detail)
    assert ok, (
        f"[{vid}*] {title} —— 注入修复方案后行为仍未恢复正常。\n"
        f"        这说明报告里给出的修法不成立，需重新设计修复方案。"
    )


# ─────────────────── 套件自身完整性 ───────────────────

def test_suite_selftest():
    """套件自检：定义了但没注册的场景 = 静默遗漏。

    第十三轮补：V22/V23 曾遗漏六轮未被发现（V23 是 P0）。
    """
    from audit_helpers import selftest
    ok, detail = selftest()
    assert ok, "套件自检未通过：\n  " + "\n  ".join(detail)


def test_every_scenario_has_countermeasure():
    """每个已注册场景都应有反测（证明修法有效）。

    当前 10 个早期场景缺反测，属于历史债 —— 这里标记为 xfail 而非失败，
    避免阻塞 CI，但让它持续可见。
    """
    from audit_helpers import SCENARIOS
    no_fix = [v for v, _, _, x in SCENARIOS if x is None]
    if no_fix:
        import pytest
        pytest.xfail(f"{len(no_fix)} 个场景缺反测: {no_fix}")
