import pytest

from src.authority import (
    ChainAnomaly,
    NodeKind,
    UnknownCode,
)
from src.tracecodes import make_trace_code


def test_unknown_code_raises(store):
    with pytest.raises(UnknownCode):
        store.inspect(make_trace_code("1111111111111111111"))


def test_complete_chain_report(store, chained):
    report = store.inspect(chained["code"])
    assert report.complete is True
    assert report.last_transfer.kind == NodeKind.DISPENSED
    assert report.batch == chained["batch"]


def test_missing_origin(store, chained):
    # 构造一枚只有销售、没有生产的码
    code = make_trace_code("2222222222222222222")
    store.append(
        kind=NodeKind.DISPENSED, actor_id="P1",
        occurred_at="2026-09-01T08:00:00+00:00",
        batch="B-X", code=code, prev_id="evt-unknown",
    )
    report = store.inspect(code)
    assert ChainAnomaly.MISSING_ORIGIN in report.anomalies
    assert ChainAnomaly.BROKEN_CHAIN in report.anomalies


def test_unlicensed_actor_flagged(store):
    code = make_trace_code("3333333333333333333")
    batch = "B-UNLICENSED"
    e1 = store.append(
        kind=NodeKind.PRODUCED, actor_id="M1",
        occurred_at="2026-09-01T08:00:00+00:00", batch=batch, code=code,
    )
    store.append(
        kind=NodeKind.DISPENSED, actor_id="P2",  # licensed=False
        occurred_at="2026-09-02T08:00:00+00:00",
        batch=batch, code=code, prev_id=e1.node_id,
    )
    report = store.inspect(code)
    assert ChainAnomaly.UNLICENSED_ACTOR in report.anomalies


def test_recall_sets_flag(store, chained):
    store.append(
        kind=NodeKind.RECALLED, actor_id="R1",
        occurred_at="2026-08-10T00:00:00+00:00",
        batch=chained["batch"], code=None,
        public_payload={"notice": "企业主动召回", "recall_level": "二级"},
    )
    report = store.inspect(chained["code"])
    assert report.recalled is True
    assert report.complete is True  # 召回发生在销售之后，链路本身不断


def test_move_after_recall_is_anomaly(store, chained):
    store.append(
        kind=NodeKind.RECALLED, actor_id="R1",
        occurred_at="2026-08-04T00:00:00+00:00",  # 销售前召回
        batch=chained["batch"], code=None,
    )
    report = store.inspect(chained["code"])
    assert ChainAnomaly.MOVE_AFTER_CONTROL in report.anomalies


def test_correction_is_append_only(store, chained):
    target = chained["events"][0]
    rev_before = store.batch_revision(chained["batch"])
    correction = store.correct(
        target.node_id, actor_id="M1",
        occurred_at="2026-08-20T00:00:00+00:00",
        reason="报送规格填写错误",
        new_public_payload={"product_name": "虚构注射用示例粉针（规格更正）"},
    )
    # 原节点保留且被回填 corrected_by
    refreshed = store.node(target.node_id)
    assert refreshed.corrected_by == correction.node_id
    assert refreshed.public_payload["spec"] == "0.5g"  # 原貌未改
    assert correction.corrects_id == target.node_id
    assert store.batch_revision(chained["batch"]) == rev_before + 1


def test_corrected_recall_is_released(store, chained):
    recall = store.append(
        kind=NodeKind.RECALLED, actor_id="R1",
        occurred_at="2026-08-10T00:00:00+00:00",
        batch=chained["batch"], code=None,
    )
    assert store.inspect(chained["code"]).recalled is True
    store.correct(
        recall.node_id, actor_id="R1",
        occurred_at="2026-08-12T00:00:00+00:00",
        reason="经核实本批次不在召回范围，解除召回",
        new_public_payload={"notice": "解除召回"},
    )
    report = store.inspect(chained["code"])
    assert report.recalled is False
