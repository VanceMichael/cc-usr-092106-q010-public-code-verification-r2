import pytest

from src.authority import NodeKind
from src.disputes import (
    DisputeError,
    DisputePortal,
    TicketState,
)
from src.tracecodes import make_trace_code


@pytest.fixture
def portal(store):
    return DisputePortal(store)


def _evidence(**over):
    item = {
        "evidence_id": "EV-1",
        "media_type": "image/jpeg",
        "size_bytes": 1024,
        "sha256": "a" * 64,
        "note": "购药小票照片",
    }
    item.update(over)
    return item


def test_submit_creates_received_ticket(portal, chained):
    ticket = portal.submit(
        chained["code"], contact_ref="contact-hash-1",
        claim="包装与页面信息不符", client="c1",
        evidences=[_evidence()],
    )
    assert ticket.state is TicketState.RECEIVED
    assert ticket.evidences[0].quarantined is True
    assert chained["code"] not in ticket.masked_code


def test_damaged_code_dispute_rejected(portal):
    with pytest.raises(DisputeError):
        portal.submit("1234", contact_ref="x", claim="问题", client="c1")


def test_unknown_code_dispute_allowed(portal):
    # 对“码未登记”同样可以异议（可能是企业未上报），只要码结构完整
    code = make_trace_code("1111111111111111111")
    ticket = portal.submit(code, contact_ref="x", claim="查不到但药是真的", client="c1")
    assert ticket.state is TicketState.RECEIVED


def test_evidence_type_and_size_limits(portal, chained):
    with pytest.raises(DisputeError):
        portal.submit(
            chained["code"], contact_ref="x", claim="c", client="c1",
            evidences=[_evidence(media_type="application/exe")],
        )
    with pytest.raises(DisputeError):
        portal.submit(
            chained["code"], contact_ref="x", claim="c", client="c1",
            evidences=[_evidence(size_bytes=10 * 1024 * 1024 + 1)],
        )
    with pytest.raises(DisputeError):
        portal.submit(
            chained["code"], contact_ref="x", claim="c", client="c1",
            evidences=[_evidence(sha256="short")],
        )


def test_rate_limit(portal, chained):
    for _ in range(5):
        portal.submit(chained["code"], contact_ref="x", claim="重复问题", client="c1")
    with pytest.raises(DisputeError):
        portal.submit(chained["code"], contact_ref="x", claim="第六次", client="c1")


def test_review_workflow_does_not_touch_authority_until_accepted(portal, store, chained):
    ticket = portal.submit(
        chained["code"], contact_ref="x", claim="疑似假药", client="c1",
        evidences=[_evidence()],
    )
    rev_before = store.batch_revision(chained["batch"])
    portal.begin_review(ticket.ticket_id, "reviewer-1")
    assert store.batch_revision(chained["batch"]) == rev_before  # 评审中不改权威库

    # 采纳必须由复核人显式执行权威动作
    def authority_action():
        store.append(
            kind=NodeKind.HOLD, actor_id="R1",
            occurred_at="2026-09-21T00:00:00+00:00",
            batch=chained["batch"], code=None,
        )

    accepted = portal.accept(ticket.ticket_id, "reviewer-1", authority_action=authority_action)
    assert accepted.state is TicketState.ACCEPTED
    assert store.batch_revision(chained["batch"]) == rev_before + 1
    # 工单自身从未直接写轨迹：全部历史只记录动作
    assert any("authority_updated" in a for _, a in accepted.history)


def test_reject_workflow(portal, chained):
    ticket = portal.submit(chained["code"], contact_ref="x", claim="不成立的问题", client="c1")
    portal.begin_review(ticket.ticket_id, "reviewer-1")
    rejected = portal.reject(ticket.ticket_id, "reviewer-1", "证据不足")
    assert rejected.state is TicketState.REJECTED


def test_cannot_accept_without_review(portal, chained):
    ticket = portal.submit(chained["code"], contact_ref="x", claim="x", client="c1")
    with pytest.raises(DisputeError):
        portal.accept(ticket.ticket_id, "r", authority_action=lambda: None)
