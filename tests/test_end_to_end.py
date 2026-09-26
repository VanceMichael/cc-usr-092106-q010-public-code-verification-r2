"""端到端叙事：正常扫码 → 订阅 → 批次风险升级 → 精准通知与缓存失效
→ 旧结论可追溯 → 公众异议隔离评审 → 风险解除后只通知仍受影响者。

对应需求原文的完整链路，确保各模块组合后行为仍符合发布规则。
"""

import json
from datetime import datetime, timedelta, timezone

from src.authority import NodeKind
from src.cache import EntryKind, HistoryCause
from src.disputes import DisputePortal, TicketState
from src.statuses import PublishedStatus
from src.subscriptions import NotificationService
from src.tracecodes import fingerprint, mask, normalize
from src.verifier import OutcomeKind, Verifier

T0 = datetime(2026, 9, 20, 10, 0, tzinfo=timezone.utc)


class Clock:
    def __init__(self, t=T0):
        self.t = t

    def __call__(self):
        return self.t

    def advance(self, **kw):
        self.t += timedelta(**kw)


def test_full_public_safeguard_narrative(store, chained):
    clock = Clock()
    verifier = Verifier(store, clock=clock)
    portal = DisputePortal(store, clock=clock)
    notifications = NotificationService(clock=clock)
    code, batch = chained["code"], chained["batch"]

    # 1) 患者扫码：看到合法流转，看不到前购药人与具体机构
    first = verifier.verify(code, client="patient-1", region="河北")
    assert first.kind is OutcomeKind.RESULT
    assert first.decision.status is PublishedStatus.LEGIT_FLOW
    page = json.dumps(first.view.to_dict(), ensure_ascii=False)
    assert code not in page
    for secret in ["前购药人", "购药人身份", "侦办案件", "虚构社区药房"]:
        assert secret not in page

    # 2) 患者在结果页显式订阅并完成二次确认
    sub = notifications.subscribe(
        code_fingerprint=normalize(code).fingerprint,
        masked_code=mask(code),
        batch=batch, channel_ref="push:patient-1", consent=True,
    )
    notifications.confirm(sub.subscription_id, token="otp", expected_token="otp")

    # 3) 短时多地被扫：不改变结论（弱信号）
    for i, region in enumerate(["广东", "云南"]):
        verifier.verify(code, client=f"traveler-{i}", region=region,
                        scanned_at=clock.t - timedelta(minutes=3 + i))
    weak = verifier.verify(code, client="patient-1", region="河北")
    assert weak.decision.status is PublishedStatus.LEGIT_FLOW

    # 4) 权威发布批次召回：缓存精准失效，新结论为已召回
    store.append(
        kind=NodeKind.RECALLED, actor_id="R1",
        occurred_at="2026-09-20T12:00:00+00:00", batch=batch, code=None,
        public_payload={"notice": "风险升级召回", "guidance": "停止使用", "recall_level": "一级"},
        restricted_payload={"case_no": "侦办案件-保密"},
    )
    recalled = verifier.verify(code, client="patient-1", region="河北")
    assert recalled.decision.status is PublishedStatus.RECALLED
    assert recalled.cache_entry_kind is EntryKind.POSITIVE
    recall_page = json.dumps(recalled.view.to_dict(), ensure_ascii=False)
    assert "侦办案件" not in recall_page

    # 5) 只通知显式订阅、已确认的人；同结论去重
    sent = notifications.notify_batch_change(
        batch, signature="recall-20260920-1",
        data_version=recalled.decision.data_version,
        headline="您订阅的药品批次已发布召回",
    )
    assert len(sent) == 1 and sent[0].subscription_id == sub.subscription_id
    assert notifications.notify_batch_change(
        batch, signature="recall-20260920-1",
        data_version=recalled.decision.data_version, headline="重复推送",
    ) == []

    # 6) 旧页面结论的依据仍可追溯（当时为何显示“合法流转”）
    history = verifier.cache.history(fingerprint(code))
    assert len(history) == 1
    old = history[0]
    assert old.status == "legit_flow"
    assert old.cause is HistoryCause.RISK_ESCALATION
    assert old.view_snapshot["status"] == "legit_flow"
    assert len(old.basis) >= 1
    assert "购药人身份" not in repr(old.basis)

    # 7) 公众提交异议与证据：隔离评审，不直接改轨迹
    rev_before = store.batch_revision(batch)
    ticket = portal.submit(
        code, contact_ref="contact-hash", claim="我买到的这盒包装异样",
        client="patient-1",
        evidences=[{
            "evidence_id": "EV-9", "media_type": "image/jpeg",
            "size_bytes": 2048, "sha256": "b" * 64,
        }],
    )
    assert store.batch_revision(batch) == rev_before
    portal.begin_review(ticket.ticket_id, "reviewer-9")
    # 复核认为证据不成立：驳回，权威轨迹保持召回结论
    portal.reject(ticket.ticket_id, "reviewer-9", "包装差异系新旧版本，不影响召回结论")
    # 驳回路径权威库零写入：修订号仍停留在召回后的那一版
    assert store.batch_revision(batch) == rev_before
    assert portal.ticket(ticket.ticket_id).state is TicketState.REJECTED

    # 8) 召回范围更正收窄：该码不在影响集合 → 不再向订阅者推送新通知
    recall = [n for n in store.batch_events(batch) if n.kind == NodeKind.RECALLED][0]
    store.correct(
        recall.node_id, actor_id="R1",
        occurred_at="2026-09-21T08:00:00+00:00",
        reason="经核实风险仅限其他包装规格",
        new_public_payload={"notice": "召回范围收窄"},
    )
    narrowed = verifier.verify(code, client="patient-1", region="河北")
    assert narrowed.decision.status is PublishedStatus.LEGIT_FLOW
    sent_narrow = notifications.notify_batch_change(
        batch, signature="recall-20260921-narrowed",
        data_version=narrowed.decision.data_version,
        headline="召回范围更正", affected_codes=set(),  # 本码已不在范围
    )
    assert sent_narrow == []


def test_aggregator_never_sees_plaintext_or_identity(store, chained):
    """安全侧只接收匿名统计与安全事件，不接收身份。"""
    verifier = Verifier(store)
    for i in range(30):
        body = f"{9000000000000000000 + i}"[:19]
        verifier.verify(_safe_code(body), client="enum-bot", region="X")
    assert verifier.security_events
    for event in verifier.security_events:
        assert "enum-bot" not in json.dumps(event)  # 仅存散列令牌


def _safe_code(body):
    from src.tracecodes import make_trace_code
    return make_trace_code(body.zfill(19))
