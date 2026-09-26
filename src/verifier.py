"""公众核验服务：入口编排与各类异常输入的分流处理。

五类入口情形分别处理，互不混用：

* **重复扫码**：缓存命中直接返回同一结论；同一幂等键重复提交只返回原结果，
  不产生重复记录、不重复通知。
* **离线补查**：设备离线期间缓存的查询随开机补传，按原始扫码时间入账，且
  幂等去重；补传时刻形成的瞬时流量不构成“多地异常”信号。
* **恶意枚举**：按匿名客户端令牌桶限频；对短时间大量“码不存在”命中设熔断，
  统一返回节流响应，响应形状与正常结论一致，不额外泄露码是否登记。
* **码不存在**：事实性结论 → 无法确认（码未登记），短 TTL 负缓存，
  累计命中量进入安全监测，但不向前端暴露更多细节。
* **残损输入**：结构性失败 → 提示重扫，不查库、不缓存、不占用查询配额。

权威源不可达时降级：优先展示带“截至某时”标注的旧结论，否则给无法确认，
绝不把旧缓存伪装成实时结论。
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum
from hashlib import blake2b

from .authority import AuthorityStore
from .cache import EntryKind, VerificationCache, snapshot_basis
from .privacy import PublicView, build_view
from .statuses import Decision, ScanSignals, decide
from .tracecodes import DamagedCode, NormalizedCode, mask, normalize

QUERY_QUOTA = 60            # 每客户端每分钟常规查询上限
MISS_WINDOW = timedelta(minutes=10)
MISS_LIMIT = 25             # 窗口内“码不存在”上限，超过即视为枚举
BLOCK_DURATION = timedelta(minutes=30)
SIGNAL_WINDOW = timedelta(hours=1)
IDEM_TTL = timedelta(hours=24)


class OutcomeKind(str, Enum):
    RESULT = "result"                    # 正常返回公众视图
    RESCAN = "rescan"                    # 残损：请重新扫码
    THROTTLED = "throttled"              # 频控/枚举熔断


@dataclass(frozen=True)
class VerifyOutcome:
    kind: OutcomeKind
    view: PublicView | None = None
    decision: Decision | None = None
    cache_entry_kind: EntryKind | None = None
    rescan_reasons: tuple[str, ...] = ()
    retry_after_seconds: int = 0
    idempotent_replay: bool = False

    @property
    def served_fresh(self) -> bool:
        return self.kind is OutcomeKind.RESULT and self.cache_entry_kind is EntryKind.POSITIVE


@dataclass(frozen=True)
class ScanEvent:
    fingerprint_key: str
    region: str
    scanned_at: datetime
    offline: bool


class _TokenBucket:
    def __init__(self, capacity: int, per_seconds: float, clock) -> None:
        self.capacity, self.per = capacity, per_seconds
        self._clock = clock
        self.tokens = float(capacity)
        self.updated = clock()

    def take(self) -> bool:
        now = self._clock()
        self.tokens = min(
            self.capacity, self.tokens + (now - self.updated).total_seconds() * self.capacity / self.per
        )
        self.updated = now
        if self.tokens >= 1:
            self.tokens -= 1
            return True
        return False


class ScanSignalCollector:
    """按码指纹保留近期去身份化扫码观测，只出统计量、不留身份。"""

    def __init__(self, *, window: timedelta = SIGNAL_WINDOW, clock=None) -> None:
        self._window = window
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._events: dict[str, deque[ScanEvent]] = {}

    def record(self, fp: str, region: str, scanned_at: datetime, offline: bool) -> None:
        bucket = self._events.setdefault(fp, deque())
        # 离线补传按原始扫码时间插入；重复（同区域同时间）直接丢弃。
        if any(e.region == region and e.scanned_at == scanned_at for e in bucket):
            return
        bucket.append(ScanEvent(fp, region, scanned_at, offline))

    def signals(self, fp: str, *, now: datetime | None = None) -> ScanSignals:
        now = now or self._clock()
        bucket = self._events.get(fp, deque())
        cutoff = now - self._window
        recent = [e for e in bucket if cutoff <= e.scanned_at <= now]
        # 只保留在线扫码参与异地统计：一批离线补传跨地域是正常现象。
        online = [e for e in recent if not e.offline]
        return ScanSignals(
            distinct_regions_1h=len({e.region for e in online}),
            scans_1h=len(recent),
            offline_replay=any(e.offline for e in recent),
        )

    def prune(self) -> None:
        now = self._clock()
        for fp in list(self._events):
            bucket = self._events[fp]
            while bucket and bucket[0].scanned_at < now - self._window:
                bucket.popleft()
            if not bucket:
                del self._events[fp]


def client_token(raw: str) -> str:
    """对 IP/设备标识做不可逆散列，限频桶不保存可识别身份。"""
    return blake2b(raw.encode(), digest_size=16, person=b"rate-client").hexdigest()


class Verifier:
    def __init__(
        self,
        store: AuthorityStore,
        *,
        cache: VerificationCache | None = None,
        signals: ScanSignalCollector | None = None,
        clock=None,
    ) -> None:
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self.store = store
        self.source_available = True
        self.cache = cache or VerificationCache(clock=self._clock)
        self.signals = signals or ScanSignalCollector(clock=self._clock)
        self._buckets: dict[str, _TokenBucket] = {}
        self._misses: dict[str, deque[datetime]] = {}
        self._blocked: dict[str, datetime] = {}
        self._idem: dict[str, tuple[str, datetime]] = {}
        self.security_events: list[dict] = []

    # ---- 对外主入口 -----------------------------------------------------

    def verify(
        self,
        raw_code: object,
        *,
        client: str,
        region: str,
        idempotency_key: str | None = None,
        offline: bool = False,
        scanned_at: datetime | None = None,
    ) -> VerifyOutcome:
        token = client_token(client)
        scanned_at = scanned_at or self._clock()

        # 1) 残损输入：结构层失败，直接提示重扫，不查库、不计数。
        try:
            normalized = normalize(raw_code)
        except DamagedCode as damaged:
            return VerifyOutcome(
                kind=OutcomeKind.RESCAN, rescan_reasons=tuple(damaged.reasons)
            )

        # 2) 幂等去重（离线补传重复上传、用户重复点按）。
        if idempotency_key is not None:
            replay = self._idem.get(idempotency_key)
            if replay is not None:
                normalized_replay, region_replay, at_replay, offline_replay = replay
                return self._resolve(
                    normalized_replay, token, region_replay, at_replay, offline_replay,
                    replay=True,
                )

        # 3) 频控与枚举熔断（残损不计入，枚举者无法借此侧信道区分）。
        throttled = self._throttle_check(token)
        if throttled is not None:
            return throttled

        result = self._resolve(normalized, token, region, scanned_at, offline)

        if idempotency_key is not None:
            self._idem[idempotency_key] = (normalized, region, scanned_at, offline)
            self._prune_idem()
        return result

    # ---- 内部 -----------------------------------------------------------

    def _resolve(
        self,
        normalized: NormalizedCode,
        token: str,
        region: str,
        scanned_at: datetime,
        offline: bool,
        *,
        replay: bool = False,
    ) -> VerifyOutcome:
        fp, code = normalized.fingerprint, normalized.code

        # 缓存优先：重复扫码不触达权威库。
        if self.source_available:
            cached = self.cache.get(fp, self.store)
            if cached is not None:
                self.signals.record(fp, region, scanned_at, offline)
                return VerifyOutcome(
                    kind=OutcomeKind.RESULT,
                    view=cached.view,
                    decision=cached.decision,
                    cache_entry_kind=cached.kind,
                    idempotent_replay=replay,
                )

        if not self.source_available:
            stale = self.cache.get_stale(fp)
            if stale is not None:
                self.signals.record(fp, region, scanned_at, offline)
                return VerifyOutcome(
                    kind=OutcomeKind.RESULT,
                    view=stale.view,
                    decision=stale.decision,
                    cache_entry_kind=EntryKind.STALE,
                    idempotent_replay=replay,
                )
            decision = decide(None, source_available=False, now=self._clock().isoformat())
            return VerifyOutcome(
                kind=OutcomeKind.RESULT, decision=decision, idempotent_replay=replay
            )

        # 权威库查询：码不存在是事实，不是异常。
        if not self.store.known_code(code):
            self._record_miss(token)
            decision = decide(None, unknown=True, now=self._clock().isoformat())
            self.cache.put_negative(fp, mask(code), decision)
            return VerifyOutcome(
                kind=OutcomeKind.RESULT,
                decision=decision,
                cache_entry_kind=EntryKind.NEGATIVE,
                idempotent_replay=replay,
            )

        report = self.store.inspect(code)
        current_signals = self.signals.signals(fp, now=scanned_at)
        decision = decide(report, current_signals, now=self._clock().isoformat())
        view = build_view(decision, code, self.store)
        basis = snapshot_basis(self.store, code, report.batch)
        self.cache.put_positive(fp, mask(code), report.batch, decision, view, basis)
        self.signals.record(fp, region, scanned_at, offline)
        return VerifyOutcome(
            kind=OutcomeKind.RESULT,
            view=view,
            decision=decision,
            cache_entry_kind=EntryKind.POSITIVE,
            idempotent_replay=replay,
        )

    # ---- 频控/熔断 ------------------------------------------------------

    def _throttle_check(self, token: str) -> VerifyOutcome | None:
        until = self._blocked.get(token)
        if until is not None:
            if self._clock() < until:
                return self._throttled(until)
            self._blocked.pop(token, None)

        bucket = self._buckets.setdefault(
            token, _TokenBucket(QUERY_QUOTA, 60.0, self._clock)
        )
        if not bucket.take():
            return self._throttled(self._clock() + timedelta(seconds=30))

        misses = self._misses.setdefault(token, deque())
        cutoff = self._clock() - MISS_WINDOW
        while misses and misses[0] < cutoff:
            misses.popleft()
        if len(misses) >= MISS_LIMIT:
            until = self._clock() + BLOCK_DURATION
            self._blocked[token] = until
            self.security_events.append(
                {"type": "enumeration_suspected", "client": token, "at": self._clock().isoformat()}
            )
            return self._throttled(until)
        return None

    def _throttled(self, until: datetime) -> VerifyOutcome:
        retry = max(1, int((until - self._clock()).total_seconds()))
        return VerifyOutcome(kind=OutcomeKind.THROTTLED, retry_after_seconds=retry)

    def _record_miss(self, token: str) -> None:
        # 计数挂在匿名客户端令牌上：码维度的不存在不构成枚举，
        # 同一来源短时间大量不存在才构成。
        self._misses.setdefault(token, deque()).append(self._clock())

    def _prune_idem(self) -> None:
        cutoff = self._clock() - IDEM_TTL
        dead = [k for k, (_, _, at, _) in self._idem.items() if at < cutoff]
        for k in dead:
            self._idem.pop(k, None)
