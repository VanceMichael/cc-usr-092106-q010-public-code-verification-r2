"""发布规则：把权威事实映射为五类可解释公众状态。

发布状态只有五种（发布规则要求）：

``PRODUCED``       生产 —— 可确认由合规企业生产，尚无后续流转记录
``LEGIT_FLOW``     合法流转 —— 链路完整、机构持资质、无未解除控制
``RECALLED``       已召回 —— 批次存在生效中的召回指令
``PENDING_REVIEW`` 待复核 —— 权威链路存在疑点或控制，正在人工/监管复核
``UNCONFIRMED``    无法确认 —— 码未登记、来源不可达或残损之外的一切不可判定

扫码行为信号（短时多地、重复频次）是**弱信号**，单独出现绝不改变结论；
只有与权威链路异常同时出现时才参与升级，避免把正常的异地购药、家庭代查
误判为造假。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum

from .authority import ChainAnomaly, ChainReport, NodeKind


class PublishedStatus(str, Enum):
    PRODUCED = "produced"
    LEGIT_FLOW = "legit_flow"
    RECALLED = "recalled"
    PENDING_REVIEW = "pending_review"
    UNCONFIRMED = "unconfirmed"


# 向公众解释结论的理由码；文案由前端按码本地化，这里不拼长句。
class Reason(str, Enum):
    PRODUCTION_CONFIRMED = "production_confirmed"
    CHAIN_COMPLETE = "chain_complete"
    BATCH_RECALLED = "batch_recalled"
    BATCH_HELD = "batch_held"
    CHAIN_ANOMALY = "chain_anomaly"
    WEAK_SCAN_SIGNAL = "weak_scan_signal_only"
    CODE_NOT_REGISTERED = "code_not_registered"
    SOURCE_UNAVAILABLE = "authoritative_source_unavailable"


_STATUS_TEXT = {
    PublishedStatus.PRODUCED: "可确认生产来源，暂未采集到后续流转",
    PublishedStatus.LEGIT_FLOW: "来源与流转记录一致，未见异常",
    PublishedStatus.RECALLED: "该批次已发布召回，请勿使用并按指引处置",
    PublishedStatus.PENDING_REVIEW: "该码存在待核实情形，结论以监管复核为准",
    PublishedStatus.UNCONFIRMED: "暂时无法确认来源，请谨慎购买并可提交异议",
}


@dataclass(frozen=True)
class ScanSignals:
    """近期扫码观测（去身份化后的统计量），全部为弱信号。"""

    distinct_regions_1h: int = 1
    scans_1h: int = 1
    offline_replay: bool = False

    @property
    def multi_region(self) -> bool:
        return self.distinct_regions_1h >= 2


@dataclass(frozen=True)
class Decision:
    status: PublishedStatus
    reasons: tuple[Reason, ...]
    anomalies: tuple[ChainAnomaly, ...]
    batch: str | None
    batch_revision: int
    decided_at: str
    basis_event_ids: tuple[str, ...] = field(default_factory=tuple)
    source_available: bool = True

    @property
    def public_text(self) -> str:
        return _STATUS_TEXT[self.status]

    @property
    def data_version(self) -> str:
        """结论版本：批次 + 修订号 + 判定时刻，缓存与历史页共用。"""
        return f"{self.batch or 'none'}@{self.batch_revision}#{self.decided_at}"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def decide(
    report: ChainReport | None,
    signals: ScanSignals | None = None,
    *,
    source_available: bool = True,
    unknown: bool = False,
    now: str | None = None,
) -> Decision:
    """执行发布判定。权威源不可达或码未登记时，``report`` 传 ``None``。"""
    signals = signals or ScanSignals()
    stamp = now or _now()

    if not source_available:
        # 高可用兜底：权威源故障不做任何正向背书，也不把旧缓存伪装成实时结论
        # （是否允许展示“截至某时”的旧结论由缓存层的 stale 策略决定）。
        return Decision(
            status=PublishedStatus.UNCONFIRMED,
            reasons=(Reason.SOURCE_UNAVAILABLE,),
            anomalies=(),
            batch=None,
            batch_revision=0,
            decided_at=stamp,
            source_available=False,
        )

    if unknown or report is None:
        return Decision(
            status=PublishedStatus.UNCONFIRMED,
            reasons=(Reason.CODE_NOT_REGISTERED,),
            anomalies=(),
            batch=None,
            batch_revision=0,
            decided_at=stamp,
        )

    reasons: list[Reason] = []
    anomaly_present = bool(report.anomalies)

    if report.recalled:
        status = PublishedStatus.RECALLED
        reasons.append(Reason.BATCH_RECALLED)
    elif report.held:
        status = PublishedStatus.PENDING_REVIEW
        reasons.append(Reason.BATCH_HELD)
    elif anomaly_present:
        status = PublishedStatus.PENDING_REVIEW
        reasons.append(Reason.CHAIN_ANOMALY)
    elif report.complete:
        if report.last_transfer is None or report.last_transfer.kind == NodeKind.PRODUCED:
            status = PublishedStatus.PRODUCED
            reasons.append(Reason.PRODUCTION_CONFIRMED)
        else:
            status = PublishedStatus.LEGIT_FLOW
            reasons.append(Reason.CHAIN_COMPLETE)
    else:
        status = PublishedStatus.UNCONFIRMED

    # 弱信号规则：多地扫码单独出现只记录理由、不降级；
    # 与链路异常并存时，结论本就是待复核，理由中保留该信号供复核人员参考
    # （该理由不进入公众文案，仅进入内部依据）。
    if signals.multi_region:
        reasons.append(Reason.WEAK_SCAN_SIGNAL)

    basis = tuple(
        n.node_id
        for n in (report.production, report.last_transfer)
        if n is not None
    )
    return Decision(
        status=status,
        reasons=tuple(reasons),
        anomalies=report.anomalies,
        batch=report.batch,
        batch_revision=report.revision,
        decided_at=stamp,
        basis_event_ids=basis,
    )
