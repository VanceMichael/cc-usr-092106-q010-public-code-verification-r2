from datetime import datetime, timedelta, timezone

import pytest

from src.cache import EntryKind
from src.statuses import PublishedStatus
from src.tracecodes import make_trace_code, normalize
from src.verifier import (
    MISS_LIMIT,
    QUERY_QUOTA,
    OutcomeKind,
    ScanSignalCollector,
    Verifier,
)

T0 = datetime(2026, 9, 20, 8, 0, tzinfo=timezone.utc)


class Clock:
    def __init__(self, t=T0):
        self.t = t

    def __call__(self):
        return self.t

    def advance(self, **kw):
        self.t += timedelta(**kw)


@pytest.fixture
def clock():
    return Clock()


@pytest.fixture
def verifier(store, clock):
    return Verifier(store, clock=clock)


def _verify(v, code, client="c1", region="河北", **kw):
    return v.verify(code, client=client, region=region, **kw)


def test_normal_query_legit_flow(verifier, chained):
    out = _verify(verifier, chained["code"])
    assert out.kind is OutcomeKind.RESULT
    assert out.decision.status is PublishedStatus.LEGIT_FLOW
    assert out.cache_entry_kind is EntryKind.POSITIVE


def test_repeated_scan_hits_cache(verifier, chained):
    first = _verify(verifier, chained["code"])
    second = _verify(verifier, chained["code"])
    assert second.kind is OutcomeKind.RESULT
    assert second.view is first.view


def test_damaged_input_returns_rescan_without_quota(verifier):
    before = len(verifier.security_events)
    for _ in range(5):
        out = verifier.verify("1234", client="c1", region="河北")
        assert out.kind is OutcomeKind.RESCAN
        assert out.rescan_reasons
    # 残损请求不查库、不计数、不产生安全事件
    assert len(verifier.security_events) == before


def test_unknown_code_is_unconfirmed_and_negative_cached(verifier):
    code = make_trace_code("1111111111111111111")
    out = _verify(verifier, code)
    assert out.decision.status is PublishedStatus.UNCONFIRMED
    assert out.cache_entry_kind is EntryKind.NEGATIVE
    # 页面不向枚举者额外泄露细节：结论与正常无法确认形状一致
    assert out.view is None or out.view.status is PublishedStatus.UNCONFIRMED


def test_enumeration_blocked_after_miss_limit(verifier):
    bodies = (f"{i:019d}" for i in range(100000, 100000 + MISS_LIMIT + 5))
    codes = [make_trace_code(b) for b in bodies]
    throttled = 0
    for code in codes:
        out = verifier.verify(code, client="attacker", region="X")
        if out.kind is OutcomeKind.THROTTLED:
            throttled += 1
    assert throttled >= 1
    assert any(e["type"] == "enumeration_suspected" for e in verifier.security_events)


def test_rate_limit_capacity(verifier, chained):
    # 正常用户超过每分钟配额也会被节流，但不会触发枚举熔断
    blocked = 0
    for i in range(QUERY_QUOTA + 30):
        out = verifier.verify(chained["code"], client="heavy", region="河北")
        if out.kind is OutcomeKind.THROTTLED:
            blocked += 1
    assert blocked >= 1
    assert not any(e["type"] == "enumeration_suspected" for e in verifier.security_events)


def test_idempotency_key_replays_same_result(verifier, chained):
    out1 = verifier.verify(
        chained["code"], client="c1", region="河北", idempotency_key="K-1"
    )
    out2 = verifier.verify(
        chained["code"], client="c1", region="北京", idempotency_key="K-1"
    )
    assert out2.idempotent_replay is True
    assert out2.view is out1.view


def test_offline_replay_does_not_create_multi_region_signal(verifier, produced_only):
    code = produced_only["code"]
    times = [T0 - timedelta(minutes=m) for m in (30, 20, 10)]
    for t, region in zip(times, ["广东", "四川", "北京"]):
        verifier.verify(
            code, client="c1", region=region, offline=True, scanned_at=t
        )
    fp = normalize(code).fingerprint
    signals = verifier.signals.signals(fp, now=T0)
    assert signals.distinct_regions_1h == 0  # 离线补传不参与异地统计
    assert signals.offline_replay is True


def test_online_multi_region_is_weak_signal_only(verifier, produced_only):
    code = produced_only["code"]
    for i, region in enumerate(["广东", "四川", "北京"]):
        verifier.verify(
            code, client=f"c{i}", region=region,
            scanned_at=T0 - timedelta(minutes=5 * i),
        )
    out = verifier.verify(code, client="c4", region="上海", scanned_at=T0)
    # 多地扫码不改变权威结论
    assert out.decision.status is PublishedStatus.PRODUCED


def test_authority_outage_serves_stale_then_unconfirmed(verifier, chained):
    out = _verify(verifier, chained["code"])
    assert out.cache_entry_kind is EntryKind.POSITIVE

    verifier.source_available = False
    again = _verify(verifier, chained["code"])
    assert again.cache_entry_kind is EntryKind.STALE

    fresh_code = make_trace_code("2222222222222222222")
    no_cache = _verify(verifier, fresh_code)
    assert no_cache.decision.status is PublishedStatus.UNCONFIRMED
    assert no_cache.decision.source_available is False


def test_cache_invalidated_after_authority_recall(verifier, store, chained):
    _verify(verifier, chained["code"])
    from src.authority import NodeKind

    store.append(
        kind=NodeKind.RECALLED, actor_id="R1",
        occurred_at="2026-09-21T00:00:00+00:00",
        batch=chained["batch"], code=None,
    )
    out = _verify(verifier, chained["code"])
    assert out.decision.status is PublishedStatus.RECALLED
    assert out.cache_entry_kind is EntryKind.POSITIVE


def test_signal_collector_dedupes(clock):
    collector = ScanSignalCollector(clock=clock)
    fp = "fp"
    collector.record(fp, "河北", T0, False)
    collector.record(fp, "河北", T0, False)  # 完全重复
    assert collector.signals(fp, now=T0).scans_1h == 1
