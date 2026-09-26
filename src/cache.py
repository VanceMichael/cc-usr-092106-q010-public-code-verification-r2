"""版本感知缓存：随权威更正/风险升级精准失效，并留存旧结论依据。

失效策略不靠 TTL 撞运气：条目记录所属批次与批次修订号，读取时比对权威库
当前修订号；任何影响该批次的追加/更正都会让修订号递增，条目随即失效并重
算。失效不是删除——旧条目连同当时的判定理由与公开事件快照进入历史档案，
支撑“此前页面当时为何给出旧结果”的追责与复算。

负缓存（码不存在）使用独立短 TTL：码可能晚些才被企业上报，不能长期固化。
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum

from .authority import NodeKind
from .privacy import PublicView
from .statuses import Decision

NEGATIVE_TTL = timedelta(minutes=10)


class EntryKind(str, Enum):
    POSITIVE = "positive"
    NEGATIVE = "negative"
    STALE = "stale"  # 权威源不可达时兜底展示的旧结论


class HistoryCause(str, Enum):
    AUTHORITY_UPDATE = "authority_update"   # 权威更正/新节点
    RISK_ESCALATION = "risk_escalation"     # 召回/封存等风险升级


@dataclass(frozen=True)
class BasisEvent:
    """结论所依据的事件快照（只含公开字段，绝不含受限内容）。"""

    node_id: str
    kind: str
    actor_id: str
    occurred_at: str
    public_payload: dict
    corrected_by: str | None


@dataclass(frozen=True)
class CacheEntry:
    fingerprint: str
    masked_code: str
    batch: str | None
    batch_revision: int
    decision: Decision
    view: PublicView | None
    basis: tuple[BasisEvent, ...]
    created_at: str
    kind: EntryKind

    def revision_current(self, store) -> bool:
        if self.batch is None:
            return True
        return store.batch_revision(self.batch) == self.batch_revision


@dataclass(frozen=True)
class HistoricalRecord:
    fingerprint: str
    masked_code: str
    status: str
    reasons: tuple[str, ...]
    data_version: str
    view_snapshot: dict
    basis: tuple[BasisEvent, ...]
    decided_at: str
    superseded_at: str
    cause: HistoryCause


def snapshot_basis(store, code: str | None, batch: str | None) -> tuple[BasisEvent, ...]:
    """固化当前公开事件作为结论依据；受限字段不进快照。"""
    if not batch:
        return ()
    nodes: list = []
    if code is not None:
        nodes.extend(store.events_for(code))
    nodes.extend(store.batch_events(batch))
    basis: list[BasisEvent] = []
    for node in sorted(nodes, key=lambda n: n.occurred_at):
        if node.kind == NodeKind.CORRECTION:
            continue
        basis.append(
            BasisEvent(
                node_id=node.node_id,
                kind=node.kind.value,
                actor_id=node.actor_id,
                occurred_at=node.occurred_at,
                public_payload=dict(node.public_payload),
                corrected_by=node.corrected_by,
            )
        )
    return tuple(basis)


class VerificationCache:
    def __init__(self, *, clock=lambda: datetime.now(timezone.utc)) -> None:
        self._clock = clock
        self._entries: dict[str, CacheEntry] = {}
        self._fingerprint_batch: dict[str, str] = {}
        self._history: list[HistoricalRecord] = []

    # ---- 读 -------------------------------------------------------------

    def get(self, fingerprint: str, store) -> CacheEntry | None:
        """返回仍有效的条目；被权威修订取代的条目当场归档。"""
        entry = self._entries.get(fingerprint)
        if entry is None:
            return None
        if entry.kind is EntryKind.NEGATIVE:
            age = self._clock() - datetime.fromisoformat(entry.created_at)
            if age >= NEGATIVE_TTL:
                self._entries.pop(fingerprint, None)
            return entry if age < NEGATIVE_TTL else None
        if not entry.revision_current(store):
            self._archive(fingerprint, entry, _StoreContext(store))
            self._entries.pop(fingerprint, None)
            return None
        return entry

    def get_stale(self, fingerprint: str) -> CacheEntry | None:
        """权威源不可达时兜底：允许返回旧结论，但标记 STALE 并要求页面标注。"""
        entry = self._entries.get(fingerprint)
        if entry is None or entry.kind is EntryKind.NEGATIVE:
            return None
        return CacheEntry(
            fingerprint=entry.fingerprint,
            masked_code=entry.masked_code,
            batch=entry.batch,
            batch_revision=entry.batch_revision,
            decision=entry.decision,
            view=entry.view,
            basis=entry.basis,
            created_at=entry.created_at,
            kind=EntryKind.STALE,
        )

    # ---- 写 -------------------------------------------------------------

    def put_positive(
        self,
        fingerprint: str,
        masked_code: str,
        batch: str,
        decision: Decision,
        view: PublicView,
        basis: tuple[BasisEvent, ...],
    ) -> CacheEntry:
        old = self._entries.get(fingerprint)
        if old is not None and old.kind in (EntryKind.POSITIVE, EntryKind.STALE):
            self._archive(fingerprint, old, _RevisionOnlyContext(decision.batch_revision))
        entry = CacheEntry(
            fingerprint=fingerprint,
            masked_code=masked_code,
            batch=batch,
            batch_revision=decision.batch_revision,
            decision=decision,
            view=view,
            basis=basis,
            created_at=self._clock().isoformat(),
            kind=EntryKind.POSITIVE,
        )
        self._entries[fingerprint] = entry
        self._fingerprint_batch[fingerprint] = batch
        return entry

    def put_negative(self, fingerprint: str, masked_code: str, decision: Decision) -> CacheEntry:
        entry = CacheEntry(
            fingerprint=fingerprint,
            masked_code=masked_code,
            batch=None,
            batch_revision=0,
            decision=decision,
            view=None,
            basis=(),
            created_at=self._clock().isoformat(),
            kind=EntryKind.NEGATIVE,
        )
        self._entries[fingerprint] = entry
        return entry

    def invalidate_batch(self, batch: str) -> int:
        """权威推送到达时的显式批量失效；返回失效条目数。"""
        hit = [fp for fp, b in self._fingerprint_batch.items() if b == batch]
        for fp in hit:
            self._entries.pop(fp, None)
        return len(hit)

    # ---- 历史档案 -------------------------------------------------------

    def _archive(self, fingerprint: str, old: CacheEntry, ctx) -> None:
        new_rev = ctx.current_revision(old.batch)
        if new_rev == old.batch_revision:
            return
        old_status = old.decision.status.value
        if ctx.has_active_control(old.batch) and old_status != "recalled":
            cause = HistoryCause.RISK_ESCALATION
        else:
            cause = HistoryCause.AUTHORITY_UPDATE
        self._history.append(
            HistoricalRecord(
                fingerprint=fingerprint,
                masked_code=old.masked_code,
                status=old_status,
                reasons=tuple(r.value for r in old.decision.reasons),
                data_version=old.decision.data_version,
                view_snapshot=old.view.to_dict() if old.view else {},
                basis=old.basis,
                decided_at=old.decision.decided_at,
                superseded_at=self._clock().isoformat(),
                cause=cause,
            )
        )

    def history(self, fingerprint: str) -> list[HistoricalRecord]:
        return [h for h in self._history if h.fingerprint == fingerprint]


class _ArchiveContext:
    """归档时只需要新修订号与当前控制事件。"""

    def current_revision(self, batch: str | None) -> int:  # pragma: no cover - 协议
        raise NotImplementedError

    def has_active_control(self, batch: str | None) -> bool:  # pragma: no cover
        raise NotImplementedError


class _StoreContext(_ArchiveContext):
    """读取失效路径：用真实权威库判断修订号与风险升级。"""

    def __init__(self, store) -> None:
        self._store = store

    def current_revision(self, batch: str | None) -> int:
        return self._store.batch_revision(batch) if batch else 0

    def has_active_control(self, batch: str | None) -> bool:
        if not batch:
            return False
        return bool(self._store.active_control(batch))


class _RevisionOnlyContext(_ArchiveContext):
    """覆盖写入路径：无 store 可读，保守归因为权威更新。"""

    def __init__(self, revision: int) -> None:
        self._revision = revision

    def current_revision(self, batch: str | None) -> int:
        return self._revision

    def has_active_control(self, batch: str | None) -> bool:
        return False
