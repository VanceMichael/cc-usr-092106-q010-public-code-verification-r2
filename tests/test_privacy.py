import json

from src.authority import NodeKind
from src.privacy import build_view
from src.statuses import decide


def test_view_masks_code_and_hides_restricted(chained, store):
    decision = decide(store.inspect(chained["code"]))
    view = build_view(decision, chained["code"], store)
    payload = view.to_dict()

    assert chained["code"] not in json.dumps(payload, ensure_ascii=False)
    serialized = json.dumps(payload, ensure_ascii=False)
    for secret in ["前购药人", "购药人身份", "员工X", "侦办案件", "case_no", "buyer_id", "operator_id"]:
        assert secret not in serialized

    labels = [item.label for item in view.timeline]
    assert "生产出厂" in labels and "正规渠道销售" in labels


def test_view_does_not_name_specific_institution(chained, store):
    view = build_view(decide(store.inspect(chained["code"])), chained["code"], store)
    serialized = json.dumps(view.to_dict(), ensure_ascii=False)
    # 具体机构名称不出现，只出现类型与省级区域
    assert "虚构社区药房" not in serialized
    assert "虚构医药流通公司" not in serialized
    assert "河北" in serialized
    assert "零售/医疗机构药房" in serialized


def test_hold_node_shows_minimal_summary(store, produced_only):
    store.append(
        kind=NodeKind.HOLD, actor_id="R1",
        occurred_at="2026-09-10T00:00:00+00:00",
        batch=produced_only["batch"], code=None,
        restricted_payload={"case_no": "侦办案件-保密"},
    )
    view = build_view(decide(store.inspect(produced_only["code"])), produced_only["code"], store)
    hold_items = [i for i in view.timeline if i.label == "监管核查中"]
    assert len(hold_items) == 1
    item = hold_items[0]
    assert item.actor_summary == "" and item.region == "" and item.details == {}
    assert "侦办案件" not in json.dumps(view.to_dict(), ensure_ascii=False)


def test_released_recall_disappears_from_timeline(chained, store):
    recall = store.append(
        kind=NodeKind.RECALLED, actor_id="R1",
        occurred_at="2026-08-10T00:00:00+00:00",
        batch=chained["batch"], code=None,
    )
    before = build_view(decide(store.inspect(chained["code"])), chained["code"], store)
    assert any(i.label == "批次召回" for i in before.timeline)

    store.correct(
        recall.node_id, actor_id="R1", occurred_at="2026-08-12T00:00:00+00:00",
        reason="范围核实有误", new_public_payload={"notice": "解除召回"},
    )
    after = build_view(decide(store.inspect(chained["code"])), chained["code"], store)
    assert not any(i.label == "批次召回" for i in after.timeline)


def test_transfer_correction_shows_updated_info_only(chained, store):
    target = chained["events"][0]
    store.correct(
        target.node_id, actor_id="M1", occurred_at="2026-08-20T00:00:00+00:00",
        reason="规格误录",
        new_public_payload={"product_name": "虚构注射用示例粉针（更正名）"},
    )
    view = build_view(decide(store.inspect(chained["code"])), chained["code"], store)
    serialized = json.dumps(view.to_dict(), ensure_ascii=False)
    assert "规格误录" not in serialized  # 更正理由不进公众视图
    # 原生产节点与更正代理各一条生产标签，但旧名称不再出现
    assert "（更正名）" in serialized


def test_weak_signal_reason_not_public(chained, store):
    from src.statuses import ScanSignals

    decision = decide(
        store.inspect(chained["code"]),
        ScanSignals(distinct_regions_1h=3, scans_1h=5),
    )
    view = build_view(decision, chained["code"], store)
    assert all(r.value != "weak_scan_signal_only" for r in view.reasons)
