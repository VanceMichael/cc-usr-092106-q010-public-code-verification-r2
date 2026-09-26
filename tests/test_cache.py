from datetime import datetime, timedelta, timezone

from src.authority import NodeKind
from src.cache import EntryKind, HistoryCause, VerificationCache, snapshot_basis
from src.privacy import build_view
from src.statuses import PublishedStatus, decide

T0 = datetime(2026, 9, 20, 8, 0, tzinfo=timezone.utc)


class Clock:
    def __init__(self, t):
        self.t = t

    def __call__(self):
        return self.t

    def advance(self, delta):
        self.t += delta


def _build(store, code, batch):
    decision = decide(store.inspect(code))
    view = build_view(decision, code, store)
    basis = snapshot_basis(store, code, batch)
    return decision, view, basis


def test_positive_entry_invalidated_on_batch_revision(store, chained):
    clock = Clock(T0)
    cache = VerificationCache(clock=clock)
    fp = __import__("src.tracecodes", fromlist=["fingerprint"]).fingerprint(chained["code"])

    decision, view, basis = _build(store, chained["code"], chained["batch"])
    cache.put_positive(fp, "****", chained["batch"], decision, view, basis)
    assert cache.get(fp, store).kind is EntryKind.POSITIVE

    store.append(
        kind=NodeKind.HOLD, actor_id="R1", occurred_at="2026-09-21T00:00:00+00:00",
        batch=chained["batch"], code=None,
    )
    assert cache.get(fp, store) is None  # 修订号变化，当场失效
    history = cache.history(fp)
    assert len(history) == 1
    assert history[0].cause is HistoryCause.RISK_ESCALATION
    assert history[0].status == PublishedStatus.LEGIT_FLOW.value
    # 旧依据快照保留：可解释旧页面为何给出“合法流转”
    assert len(history[0].basis) >= 1
    assert history[0].view_snapshot["status"] == "legit_flow"


def test_recall_correction_history_cause(store, chained):
    clock = Clock(T0)
    cache = VerificationCache(clock=clock)
    from src.tracecodes import fingerprint

    fp = fingerprint(chained["code"])
    decision, view, basis = _build(store, chained["code"], chained["batch"])
    cache.put_positive(fp, "****", chained["batch"], decision, view, basis)

    recall = store.append(
        kind=NodeKind.RECALLED, actor_id="R1", occurred_at="2026-09-21T00:00:00+00:00",
        batch=chained["batch"], code=None,
    )
    assert cache.get(fp, store) is None
    assert cache.history(fp)[0].cause is HistoryCause.RISK_ESCALATION

    # 重算后缓存召回结论；随后召回被更正解除 → 再次失效，归因为普通权威更新
    decision2, view2, basis2 = _build(store, chained["code"], chained["batch"])
    assert decision2.status is PublishedStatus.RECALLED
    cache.put_positive(fp, "****", chained["batch"], decision2, view2, basis2)
    store.correct(
        recall.node_id, actor_id="R1", occurred_at="2026-09-22T00:00:00+00:00",
        reason="范围有误", new_public_payload={"notice": "解除"},
    )
    assert cache.get(fp, store) is None
    causes = [h.cause for h in cache.history(fp)]
    assert causes[-1] is HistoryCause.AUTHORITY_UPDATE


def test_negative_entry_ttl_expires(store):
    clock = Clock(T0)
    cache = VerificationCache(clock=clock)
    decision = decide(None, unknown=True, now=T0.isoformat())
    cache.put_negative("fp-x", "1234****5678", decision)
    assert cache.get("fp-x", store).kind is EntryKind.NEGATIVE

    clock.advance(timedelta(minutes=10, seconds=1))
    assert cache.get("fp-x", store) is None


def test_explicit_batch_invalidation(store, chained):
    cache = VerificationCache(clock=Clock(T0))
    from src.tracecodes import fingerprint

    fp = fingerprint(chained["code"])
    decision, view, basis = _build(store, chained["code"], chained["batch"])
    cache.put_positive(fp, "****", chained["batch"], decision, view, basis)
    assert cache.invalidate_batch(chained["batch"]) == 1
    assert cache.get(fp, store) is None


def test_stale_fallback_during_outage(store, chained):
    cache = VerificationCache(clock=Clock(T0))
    from src.tracecodes import fingerprint

    fp = fingerprint(chained["code"])
    decision, view, basis = _build(store, chained["code"], chained["batch"])
    cache.put_positive(fp, "****", chained["batch"], decision, view, basis)

    # 权威侧已变更但源不可达：get_stale 仍可提供带标记的旧结论
    store.append(
        kind=NodeKind.HOLD, actor_id="R1", occurred_at="2026-09-21T00:00:00+00:00",
        batch=chained["batch"], code=None,
    )
    stale = cache.get_stale(fp)
    assert stale is not None
    assert stale.kind is EntryKind.STALE


def test_basis_snapshot_excludes_restricted(store, chained):
    basis = snapshot_basis(store, chained["code"], chained["batch"])
    serialized = repr(basis)
    assert "购药人身份" not in serialized
    assert "侦办案件" not in serialized
    assert all(b.public_payload is not None for b in basis)
