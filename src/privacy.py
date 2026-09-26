"""公众视图裁剪：敏感节点只展示必要摘要。

规则：

* 永不输出 ``restricted_payload``（购药人身份、经办人、侦办案件编号等）；
* 机构不展示名称与许可编号，只展示机构类型 + 省级区域，避免定位到具体
  就诊/购药机构；
* 封存、核查类节点只给“监管核查中”摘要，不暴露发起机构与文号；
* 更正事件不进时间线（更正已体现在结论中），其依据只用于内部复核；
* 扫码弱信号理由仅供内部，不出现在公众视图。
"""

from __future__ import annotations

from dataclasses import dataclass

from .authority import (
    Actor,
    ChainNode,
    NodeKind,
    TRANSFER_KINDS,
    UnknownCode,
)
from .statuses import Decision, PublishedStatus, Reason
from .tracecodes import mask

_ACTOR_KIND_TEXT = {
    "manufacturer": "药品生产企业",
    "distributor": "合规流通企业",
    "pharmacy": "零售/医疗机构药房",
    "regulator": "监管部门",
}

_NODE_KIND_TEXT = {
    NodeKind.PRODUCED: "生产出厂",
    NodeKind.SHIPPED: "合法调出",
    NodeKind.RECEIVED: "合法接收",
    NodeKind.DISPENSED: "正规渠道销售",
    NodeKind.RECALLED: "批次召回",
    NodeKind.HOLD: "监管核查中",
}

_PUBLIC_REASONS = {
    Reason.PRODUCTION_CONFIRMED,
    Reason.CHAIN_COMPLETE,
    Reason.BATCH_RECALLED,
    Reason.BATCH_HELD,
    Reason.CHAIN_ANOMALY,
    Reason.CODE_NOT_REGISTERED,
    Reason.SOURCE_UNAVAILABLE,
}

# 各类节点允许透出的公开字段白名单；白名单之外一律不展示。
_PUBLIC_FIELD_ALLOWLIST = {
    NodeKind.PRODUCED: {"product_name", "spec", "approval_number"},
    NodeKind.SHIPPED: set(),
    NodeKind.RECEIVED: set(),
    NodeKind.DISPENSED: set(),  # 销售节点不附带任何公开细节，保护购药场景
    NodeKind.RECALLED: {"notice", "guidance", "recall_level"},
    NodeKind.HOLD: set(),
}


@dataclass(frozen=True)
class TimelineItem:
    label: str
    actor_summary: str
    region: str
    date: str
    details: dict


@dataclass(frozen=True)
class PublicView:
    masked_code: str
    status: PublishedStatus
    headline: str
    reasons: tuple[Reason, ...]
    timeline: tuple[TimelineItem, ...]
    data_version: str
    decided_at: str
    as_of: str

    def to_dict(self) -> dict:
        return {
            "code": self.masked_code,
            "status": self.status.value,
            "headline": self.headline,
            "reasons": [r.value for r in self.reasons],
            "timeline": [
                {
                    "label": i.label,
                    "actor": i.actor_summary,
                    "region": i.region,
                    "date": i.date,
                    "details": i.details,
                }
                for i in self.timeline
            ],
            "data_version": self.data_version,
            "decided_at": self.decided_at,
            "as_of": self.as_of,
        }


def _actor_summary(actor: Actor | None) -> tuple[str, str]:
    if actor is None:
        return "已登记机构", ""
    return _ACTOR_KIND_TEXT.get(actor.kind, "已登记机构"), actor.region


def _node_to_item(node: ChainNode, actor: Actor | None) -> TimelineItem:
    label = _NODE_KIND_TEXT[node.kind]
    actor_text, region = _actor_summary(actor)
    if node.kind == NodeKind.HOLD:
        # 侦办/核查中的敏感节点：无机构、无区域、无文号。
        return TimelineItem(label=label, actor_summary="", region="",
                            date=node.occurred_at[:10], details={})
    allowed = _PUBLIC_FIELD_ALLOWLIST[node.kind]
    details = {k: v for k, v in node.public_payload.items() if k in allowed}
    return TimelineItem(
        label=label,
        actor_summary=actor_text,
        region=region,
        date=node.occurred_at[:10],
        details=details,
    )


def build_view(decision: Decision, code: str, store) -> PublicView:
    """根据判定结论与权威库构造公众视图；store 仅用于读取机构摘要。"""
    nodes: list[ChainNode] = []
    try:
        nodes = list(store.events_for(code))
        nodes.extend(store.batch_events(store.batch_of(code)))
    except UnknownCode:
        nodes = []

    timeline: list[TimelineItem] = []
    for node in sorted(nodes, key=lambda n: n.occurred_at):
        if node.kind == NodeKind.CORRECTION:
            continue
        if node.corrected_by is not None:
            continue  # 被更正/被解除的节点不按原貌展示
        timeline.append(_node_to_item(node, store.actor(node.actor_id)))

    # 对流转节点的更正：以“信息更正”展示更正后的公开内容，
    # 原貌与更正理由留存在权威库与历史判定记录中，不进公众视图。
    for node in sorted(nodes, key=lambda n: n.occurred_at):
        if node.kind != NodeKind.CORRECTION or not node.corrects_id:
            continue
        target = store.node(node.corrects_id)
        if target.kind not in TRANSFER_KINDS:
            continue
        proxy = ChainNode(
            node_id=node.node_id,
            batch=node.batch,
            kind=target.kind,
            actor_id=target.actor_id,
            occurred_at=node.occurred_at,
            seq=node.seq,
            code=node.code,
            public_payload=node.public_payload,
        )
        timeline.append(_node_to_item(proxy, store.actor(target.actor_id)))

    public_reasons = tuple(r for r in decision.reasons if r in _PUBLIC_REASONS)
    return PublicView(
        masked_code=mask(code),
        status=decision.status,
        headline=decision.public_text,
        reasons=public_reasons,
        timeline=tuple(timeline),
        data_version=decision.data_version,
        decided_at=decision.decided_at,
        as_of=decision.decided_at[:10],
    )
