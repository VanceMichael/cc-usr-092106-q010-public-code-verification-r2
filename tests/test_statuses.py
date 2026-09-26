from src.authority import NodeKind
from src.statuses import (
    PublishedStatus,
    Reason,
    ScanSignals,
    decide,
)
from src.tracecodes import make_trace_code


def test_produced_only(store, produced_only):
    report = store.inspect(produced_only["code"])
    d = decide(report)
    assert d.status is PublishedStatus.PRODUCED
    assert Reason.PRODUCTION_CONFIRMED in d.reasons


def test_legit_flow(chained, store):
    report = store.inspect(chained["code"])
    d = decide(report)
    assert d.status is PublishedStatus.LEGIT_FLOW
    assert Reason.CHAIN_COMPLETE in d.reasons


def test_recalled(chained, store):
    store.append(
        kind=NodeKind.RECALLED, actor_id="R1",
        occurred_at="2026-08-10T00:00:00+00:00",
        batch=chained["batch"], code=None,
    )
    d = decide(store.inspect(chained["code"]))
    assert d.status is PublishedStatus.RECALLED
    assert Reason.BATCH_RECALLED in d.reasons


def test_hold_is_pending_review(store, produced_only):
    store.append(
        kind=NodeKind.HOLD, actor_id="R1",
        occurred_at="2026-09-10T00:00:00+00:00",
        batch=produced_only["batch"], code=None,
    )
    d = decide(store.inspect(produced_only["code"]))
    assert d.status is PublishedStatus.PENDING_REVIEW
    assert Reason.BATCH_HELD in d.reasons


def test_chain_anomaly_is_pending_review(store):
    code = make_trace_code("4444444444444444444")
    store.append(
        kind=NodeKind.DISPENSED, actor_id="P1",
        occurred_at="2026-09-01T08:00:00+00:00",
        batch="B-A", code=code, prev_id="ghost",
    )
    d = decide(store.inspect(code))
    assert d.status is PublishedStatus.PENDING_REVIEW


def test_unknown_code_is_unconfirmed():
    d = decide(None, unknown=True)
    assert d.status is PublishedStatus.UNCONFIRMED
    assert Reason.CODE_NOT_REGISTERED in d.reasons


def test_source_unavailable_is_unconfirmed():
    d = decide(None, source_available=False)
    assert d.status is PublishedStatus.UNCONFIRMED
    assert d.source_available is False
    assert Reason.SOURCE_UNAVAILABLE in d.reasons


def test_multi_region_alone_does_not_downgrade(store, produced_only):
    # 短时多地扫码是弱信号：完整来源的码不应被改判。
    signals = ScanSignals(distinct_regions_1h=5, scans_1h=12)
    d = decide(store.inspect(produced_only["code"]), signals)
    assert d.status is PublishedStatus.PRODUCED
    assert Reason.WEAK_SCAN_SIGNAL in d.reasons  # 内部保留，不改变结论


def test_multi_region_with_anomaly_stays_pending(store):
    code = make_trace_code("5555555555555555555")
    store.append(
        kind=NodeKind.DISPENSED, actor_id="P1",
        occurred_at="2026-09-01T08:00:00+00:00",
        batch="B-B", code=code, prev_id="ghost",
    )
    signals = ScanSignals(distinct_regions_1h=4, scans_1h=9)
    d = decide(store.inspect(code), signals)
    assert d.status is PublishedStatus.PENDING_REVIEW


def test_decision_carries_revision_and_basis(chained, store):
    d = decide(store.inspect(chained["code"]))
    assert d.batch == chained["batch"]
    assert d.batch_revision >= 1
    assert len(d.basis_event_ids) >= 1
    assert "@" in d.data_version
