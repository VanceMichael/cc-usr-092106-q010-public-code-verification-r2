"""风险升级订阅：显式订阅、影响面过滤、按结论去重。

约束：

* **只接受显式订阅**：扫码本身不产生订阅；需要用户在结果页主动订阅并经
  渠道二次确认后才生效。
* **只通知仍受影响的人**：批次风险结论变化时，若召回范围被更正收窄，已不在
  影响范围内的订阅者不通知；退订或过期的订阅不通知。
* **同一结论只通知一次**：按批次结论签名去重，重复推送（重发、多机房）不产生
  重复通知；通知记录带数据版本，可回溯“当时通知的依据”。
* 通知内容沿用公众视图口径，只含必要摘要，不含轨迹细节与他人信息。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from itertools import count

SUBSCRIPTION_TTL = timedelta(days=180)


class SubscriptionState(str, Enum):
    PENDING = "pending"       # 已申请，等待渠道二次确认
    ACTIVE = "active"
    CANCELLED = "cancelled"


@dataclass(frozen=True)
class Subscription:
    subscription_id: str
    code_fingerprint: str
    masked_code: str
    batch: str
    channel_ref: str          # 渠道凭据的不可逆引用，不存手机号原文
    state: SubscriptionState
    created_at: str
    notified_signatures: tuple[str, ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class Notification:
    notification_id: str
    subscription_id: str
    batch: str
    masked_code: str
    signature: str
    data_version: str
    headline: str
    sent_at: str


class SubscriptionError(ValueError):
    pass


class NotificationService:
    def __init__(
        self,
        *,
        clock=None,
        ttl: timedelta = SUBSCRIPTION_TTL,
    ) -> None:
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._ttl = ttl
        self._ids = count(1)
        self._subs: dict[str, Subscription] = {}
        self.delivered: list[Notification] = []

    # ---- 订阅生命周期 ---------------------------------------------------

    def subscribe(
        self,
        *,
        code_fingerprint: str,
        masked_code: str,
        batch: str,
        channel_ref: str,
        consent: bool,
    ) -> Subscription:
        """登记订阅意向；consent 必须为用户显式勾选，否则拒绝。

        调用方传入码指纹与脱敏展示值，本服务不接触明文追溯码；批次由
        应用层在核验时解析后一并提供。
        """
        if not consent:
            raise SubscriptionError("订阅需要用户明确同意")
        if not channel_ref:
            raise SubscriptionError("缺少通知渠道")
        if not code_fingerprint or not batch:
            raise SubscriptionError("缺少码或批次标识")
        sub = Subscription(
            subscription_id=f"SUB-{next(self._ids):06d}",
            code_fingerprint=code_fingerprint,
            masked_code=masked_code,
            batch=batch,
            channel_ref=channel_ref,
            state=SubscriptionState.PENDING,
            created_at=self._clock().isoformat(),
        )
        self._subs[sub.subscription_id] = sub
        return sub

    def confirm(self, subscription_id: str, token: str, expected_token: str) -> Subscription:
        """渠道二次确认（如短信/推送回执令牌），令牌错误不激活。"""
        sub = self._get(subscription_id)
        if sub.state is not SubscriptionState.PENDING:
            raise SubscriptionError("订阅当前状态无法确认")
        if not token or token != expected_token:
            raise SubscriptionError("确认凭据无效")
        return self._update(sub, state=SubscriptionState.ACTIVE)

    def cancel(self, subscription_id: str) -> Subscription:
        sub = self._get(subscription_id)
        return self._update(sub, state=SubscriptionState.CANCELLED)

    # ---- 风险变化时的通知派发 ------------------------------------------

    def notify_batch_change(
        self,
        batch: str,
        *,
        signature: str,
        data_version: str,
        headline: str,
        affected_codes: set[str] | None = None,
    ) -> list[Notification]:
        """批次风险结论变化时调用。

        ``affected_codes`` 为更正收窄后的实际影响码集合；``None`` 表示整批。
        只有：有效、未过期、已确认、码仍在影响集合内、未收到过同签名通知的
        订阅者才会收到。
        """
        sent: list[Notification] = []
        for sub in list(self._subs.values()):
            if sub.state is not SubscriptionState.ACTIVE or sub.batch != batch:
                continue
            if self._clock() - datetime.fromisoformat(sub.created_at) > self._ttl:
                self._update(sub, state=SubscriptionState.CANCELLED)
                continue
            if signature in sub.notified_signatures:
                continue  # 同一结论已通知，去重
            if affected_codes is not None and sub.code_fingerprint not in affected_codes:
                continue  # 范围收窄：不再受影响
            notification = Notification(
                notification_id=f"NTF-{next(self._ids):06d}",
                subscription_id=sub.subscription_id,
                batch=batch,
                masked_code=sub.masked_code,
                signature=signature,
                data_version=data_version,
                headline=headline,
                sent_at=self._clock().isoformat(),
            )
            self.delivered.append(notification)
            self._update(sub, notified=signature)
            sent.append(notification)
        return sent

    # ---- 内部 -----------------------------------------------------------

    def _get(self, subscription_id: str) -> Subscription:
        sub = self._subs.get(subscription_id)
        if sub is None:
            raise SubscriptionError("订阅不存在")
        return sub

    def _update(self, sub: Subscription, *, state=None, notified: str | None = None) -> Subscription:
        notified_signatures = sub.notified_signatures
        if notified is not None and notified not in notified_signatures:
            notified_signatures = notified_signatures + (notified,)
        updated = Subscription(
            subscription_id=sub.subscription_id,
            code_fingerprint=sub.code_fingerprint,
            masked_code=sub.masked_code,
            batch=sub.batch,
            channel_ref=sub.channel_ref,
            state=state or sub.state,
            created_at=sub.created_at,
            notified_signatures=notified_signatures,
        )
        self._subs[sub.subscription_id] = updated
        return updated
