"""公众异议受理：受控证据隔离评审，绝不直接改写权威轨迹。

公众可以对页面结论提出异议并上传受控证据（照片、小票、说明）。证据与
权威库物理隔离：

* 证据有类型/大小上限，进入隔离存储，按“未核验”标注，不参与任何自动判定；
* 异议只产生评审工单，工单状态推进不修改 ``AuthorityStore``；
* 即使评审采纳，也必须由具权威角色的复核人通过 ``AuthorityStore.correct``
  或追加召回/封存事件落库——公众输入永远没有直接写轨迹的通路；
* 频次受限，防止异议通道被刷成注入或淹没渠道。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from itertools import count

from .authority import AuthorityStore
from .tracecodes import DamagedCode, mask, normalize

MAX_EVIDENCE_BYTES = 10 * 1024 * 1024  # 单个证据 10MB
ALLOWED_EVIDENCE_TYPES = {"image/jpeg", "image/png", "application/pdf"}
DISPUTES_PER_CLIENT_HOUR = 5


class TicketState(str, Enum):
    RECEIVED = "received"
    IN_REVIEW = "in_review"
    ACCEPTED = "accepted"     # 复核确认，权威侧已另行更正
    REJECTED = "rejected"


class DisputeError(ValueError):
    pass


@dataclass(frozen=True)
class Evidence:
    evidence_id: str
    media_type: str
    size_bytes: int
    sha256: str
    quarantined: bool = True   # 始终先隔离，扫毒/人工确认前不外发
    note: str = ""


@dataclass(frozen=True)
class DisputeTicket:
    ticket_id: str
    code_fingerprint: str
    masked_code: str
    contact_ref: str            # 联系方式的引用/哈希，不存原文
    claim: str
    evidences: tuple[Evidence, ...]
    state: TicketState
    created_at: str
    history: tuple[tuple[str, str], ...] = field(default_factory=tuple)  # (时间, 动作)


class DisputePortal:
    def __init__(self, store: AuthorityStore, *, clock=None) -> None:
        self._store = store
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._ids = count(1)
        self._tickets: dict[str, DisputeTicket] = {}
        self._client_recent: dict[str, list[datetime]] = {}

    def submit(
        self,
        raw_code: object,
        *,
        contact_ref: str,
        claim: str,
        client: str,
        evidences: list[dict] | None = None,
    ) -> DisputeTicket:
        self._rate_limit(client)

        # 异议允许针对“码不存在”的情形，但残损输入仍需先重扫：
        # 无法确定是哪枚码的异议没有评审对象。
        try:
            normalized = normalize(raw_code)
            fp, masked = normalized.fingerprint, mask(normalized.code)
        except DamagedCode as exc:
            raise DisputeError(f"追溯码无法识别，请重新扫码后再提交：{exc}") from None

        claim = (claim or "").strip()
        if not claim:
            raise DisputeError("请填写异议说明")
        if len(claim) > 1000:
            raise DisputeError("异议说明过长")
        if not contact_ref:
            raise DisputeError("需要可回访的联系方式引用")

        checked: list[Evidence] = []
        for item in evidences or []:
            checked.append(self._check_evidence(item))
        if len(checked) > 6:
            raise DisputeError("证据数量超出上限")

        ticket_id = f"DISP-{next(self._ids):06d}"
        now = self._clock().isoformat()
        ticket = DisputeTicket(
            ticket_id=ticket_id,
            code_fingerprint=fp,
            masked_code=masked,
            contact_ref=contact_ref,
            claim=claim,
            evidences=tuple(checked),
            state=TicketState.RECEIVED,
            created_at=now,
            history=((now, "submitted"),),
        )
        self._tickets[ticket_id] = ticket
        return ticket

    # ---- 评审侧（权威角色） --------------------------------------------

    def begin_review(self, ticket_id: str, reviewer: str) -> DisputeTicket:
        return self._transition(ticket_id, TicketState.IN_REVIEW, f"review_started:{reviewer}")

    def accept(
        self,
        ticket_id: str,
        reviewer: str,
        *,
        authority_action,
    ) -> DisputeTicket:
        """采纳异议：先执行权威动作（由复核人显式给出），再推进工单。

        ``authority_action`` 是对权威库的写操作闭包；工单系统自身不构造
        轨迹写入，确保公众异议没有直达权威轨迹的代码路径。
        """
        self._require(ticket_id, TicketState.IN_REVIEW)  # 状态前置校验
        authority_action()  # 预期为 store.correct(...) / store.append(recall|hold)
        return self._transition(
            ticket_id, TicketState.ACCEPTED, f"accepted:{reviewer};authority_updated"
        )

    def reject(self, ticket_id: str, reviewer: str, reason: str) -> DisputeTicket:
        self._require(ticket_id, TicketState.IN_REVIEW)
        return self._transition(
            ticket_id, TicketState.REJECTED, f"rejected:{reviewer}:{reason[:200]}"
        )

    def ticket(self, ticket_id: str) -> DisputeTicket:
        return self._require(ticket_id, None)

    # ---- 内部 -----------------------------------------------------------

    def _check_evidence(self, item: dict) -> Evidence:
        media = item.get("media_type", "")
        size = int(item.get("size_bytes", 0))
        digest = item.get("sha256", "")
        if media not in ALLOWED_EVIDENCE_TYPES:
            raise DisputeError(f"不支持的证据类型：{media}")
        if size <= 0 or size > MAX_EVIDENCE_BYTES:
            raise DisputeError("证据大小超出限制")
        if len(digest) != 64:
            raise DisputeError("证据缺少完整性摘要")
        return Evidence(
            evidence_id=item.get("evidence_id", f"EV-{next(self._ids):06d}"),
            media_type=media,
            size_bytes=size,
            sha256=digest,
            quarantined=True,
            note=str(item.get("note", ""))[:500],
        )

    def _rate_limit(self, client: str) -> None:
        now = self._clock()
        recent = [t for t in self._client_recent.get(client, []) if now - t < timedelta(hours=1)]
        if len(recent) >= DISPUTES_PER_CLIENT_HOUR:
            raise DisputeError("提交过于频繁，请稍后再试")
        recent.append(now)
        self._client_recent[client] = recent

    def _transition(self, ticket_id: str, new_state: TicketState, action: str) -> DisputeTicket:
        ticket = self._require(ticket_id, None)
        now = self._clock().isoformat()
        updated = DisputeTicket(
            ticket_id=ticket.ticket_id,
            code_fingerprint=ticket.code_fingerprint,
            masked_code=ticket.masked_code,
            contact_ref=ticket.contact_ref,
            claim=ticket.claim,
            evidences=ticket.evidences,
            state=new_state,
            created_at=ticket.created_at,
            history=ticket.history + ((now, action),),
        )
        self._tickets[ticket_id] = updated
        return updated

    def _require(self, ticket_id: str, expected: TicketState | None) -> DisputeTicket:
        ticket = self._tickets.get(ticket_id)
        if ticket is None:
            raise DisputeError("工单不存在")
        if expected is not None and ticket.state is not expected:
            raise DisputeError(f"工单状态不允许该操作：{ticket.state.value}")
        return ticket
