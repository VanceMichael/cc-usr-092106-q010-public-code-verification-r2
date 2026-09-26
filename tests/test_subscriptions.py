from datetime import datetime, timedelta, timezone

import pytest

from src.subscriptions import (
    NotificationService,
    SubscriptionError,
    SubscriptionState,
)
from src.tracecodes import fingerprint, mask

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
def service(clock):
    return NotificationService(clock=clock)


def _sub(service, code, batch="BATCH-1", channel="ch-1", consent=True):
    return service.subscribe(
        code_fingerprint=fingerprint(code),
        masked_code=mask(code),
        batch=batch,
        channel_ref=channel,
        consent=consent,
    )


def test_subscribe_requires_explicit_consent(service):
    with pytest.raises(SubscriptionError):
        service.subscribe(
            code_fingerprint="fp", masked_code="1234****5678",
            batch="B1", channel_ref="x", consent=False,
        )


def test_subscription_pending_until_double_confirm(service):
    code = "1234567890123456789"
    sub = _sub(service, code)
    assert sub.state is SubscriptionState.PENDING
    with pytest.raises(SubscriptionError):
        service.confirm(sub.subscription_id, token="wrong", expected_token="right")
    confirmed = service.confirm(sub.subscription_id, token="right", expected_token="right")
    assert confirmed.state is SubscriptionState.ACTIVE


def test_only_confirmed_subscribers_notified(service):
    code = "1234567890123456789"
    sub = _sub(service, code)
    sent = service.notify_batch_change(
        "BATCH-1", signature="recall-v1", data_version="BATCH-1@9",
        headline="批次召回",
    )
    assert sent == []
    service.confirm(sub.subscription_id, "t", "t")
    sent = service.notify_batch_change(
        "BATCH-1", signature="recall-v1", data_version="BATCH-1@9",
        headline="批次召回",
    )
    assert len(sent) == 1
    assert sent[0].headline == "批次召回"
    assert code not in repr(sent[0])  # 通知不含明文码


def test_duplicate_conclusion_notifies_once(service):
    code = "1234567890123456789"
    service.confirm(_sub(service, code).subscription_id, "t", "t")
    kwargs = dict(signature="recall-v1", data_version="BATCH-1@9", headline="召回")
    first = service.notify_batch_change("BATCH-1", **kwargs)
    second = service.notify_batch_change("BATCH-1", **kwargs)  # 重发/多机房
    assert len(first) == 1 and second == []
    assert len(service.delivered) == 1


def test_narrowed_recall_skips_unaffected_subscribers(service):
    code_in = "1234567890123456789"
    code_out = "2234567890123456780"
    service.confirm(_sub(service, code_in).subscription_id, "t", "t")
    service.confirm(_sub(service, code_out, channel="ch-2").subscription_id, "t", "t")

    sent = service.notify_batch_change(
        "BATCH-1", signature="recall-v2", data_version="BATCH-1@12",
        headline="召回范围更正收窄",
        affected_codes={fingerprint(code_in)},
    )
    notified_fps = {n.subscription_id for n in sent}
    assert len(notified_fps) == 1
    assert sent[0].masked_code == mask(code_in)


def test_cancelled_subscription_not_notified(service):
    code = "1234567890123456789"
    sub = service.confirm(_sub(service, code).subscription_id, "t", "t")
    service.cancel(sub.subscription_id)
    sent = service.notify_batch_change(
        "BATCH-1", signature="recall-v1", data_version="x", headline="h"
    )
    assert sent == []


def test_expired_subscription_auto_cancels(clock):
    service = NotificationService(clock=clock)
    code = "1234567890123456789"
    service.confirm(
        service.subscribe(
            code_fingerprint=fingerprint(code), masked_code=mask(code),
            batch="B1", channel_ref="c", consent=True,
        ).subscription_id,
        "t", "t",
    )
    clock.advance(days=181)
    sent = service.notify_batch_change(
        "B1", signature="s", data_version="v", headline="h"
    )
    assert sent == []
