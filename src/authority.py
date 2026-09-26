"""权威轨迹库：只追加事件、更正留痕、批次结论版本化。

权威方（生产企业、经营企业、监管机构）推送的节点只能追加，不能删除或静默
覆盖。更正以“更正事件”形式追加，被更正节点原样保留，从而支撑“此前页面
当时为何给出旧结果”的追责与复算。

本库保存完整内部资料（含受限字段），公众可见范围由 ``privacy`` 模块裁剪；
受限字段（经办人身份、侦办案件编号、具体购药人等）永不进入发布视图。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from itertools import count


class NodeKind(str, Enum):
    PRODUCED = "produced"          # 生产入库
    SHIPPED = "shipped"            # 合法调出
    RECEIVED = "received"          # 合法接收
    DISPENSED = "dispensed"        # 销售/交付到患者
    RECALLED = "recalled"          # 批次召回
    HOLD = "hold"                  # 监管封存/风险待查
    CORRECTION = "correction"      # 对既有节点的权威更正


TRANSFER_KINDS = {
    NodeKind.PRODUCED,
    NodeKind.SHIPPED,
    NodeKind.RECEIVED,
    NodeKind.DISPENSED,
}
CONTROL_KINDS = {NodeKind.RECALLED, NodeKind.HOLD}


class ChainAnomaly(str, Enum):
    MISSING_ORIGIN = "missing_origin"          # 缺生产源头
    BROKEN_CHAIN = "broken_chain"              # 流转断链/前驱未知
    LOOP = "loop"                              # 节点重复或成环
    UNKNOWN_ACTOR = "unknown_actor"            # 机构未在白名单
    UNLICENSED_ACTOR = "unlicensed_actor"      # 机构资质失效
    MOVE_AFTER_CONTROL = "move_after_control"  # 召回/封存后仍流转
    EVENT_AFTER_DISPENSE = "event_after_dispense"


class UnknownCode(LookupError):
    """权威库中没有该码的任何记录——事实层面的“码不存在”。"""


@dataclass(frozen=True)
class Actor:
    actor_id: str
    name: str
    kind: str           # manufacturer / distributor / pharmacy / regulator
    region: str         # 省级区域，公众视图最多到此粒度
    licensed: bool = True


@dataclass(frozen=True)
class ChainNode:
    node_id: str
    batch: str
    kind: NodeKind
    actor_id: str
    occurred_at: str                    # ISO8601，权威方报送时间
    seq: int
    code: str | None = None             # 批次级事件为 None
    prev_id: str | None = None          # 流转链前驱
    doc_ref: str = ""                   # 权威单据/文号
    public_payload: dict = field(default_factory=dict)
    restricted_payload: dict = field(default_factory=dict)
    corrects_id: str | None = None      # 更正事件指向的节点
    correction_reason: str = ""
    corrected_by: str | None = None     # 被哪个更正事件更正（运行期回填）


@dataclass(frozen=True)
class ChainReport:
    code: str
    batch: str
    complete: bool
    anomalies: tuple[ChainAnomaly, ...]
    recalled: bool
    held: bool
    production: ChainNode | None
    last_transfer: ChainNode | None
    revision: int


class AuthorityStore:
    """内存版权威库；接口即边界，生产实现可换成事件库/CDC 订阅。"""

    def __init__(self) -> None:
        self._actors: dict[str, Actor] = {}
        self._nodes: list[ChainNode] = []
        self._ids: set[str] = set()
        self._code_batch: dict[str, str] = {}
        self._batch_codes: dict[str, set[str]] = {}
        self._batch_rev: dict[str, int] = {}
        self._seq = count(1)

    # ---- 基础资料 -------------------------------------------------------

    def register_actor(self, actor: Actor) -> None:
        self._actors[actor.actor_id] = actor

    def actor(self, actor_id: str) -> Actor | None:
        return self._actors.get(actor_id)

    def known_code(self, code: str) -> bool:
        return code in self._code_batch

    def batch_revision(self, batch: str) -> int:
        """批次结论版本：任何影响该批的追加/更正都会单调递增。"""
        return self._batch_rev.get(batch, 0)

    # ---- 只追加写入 -----------------------------------------------------

    def append(
        self,
        *,
        kind: NodeKind,
        actor_id: str,
        occurred_at: str,
        batch: str,
        code: str | None = None,
        prev_id: str | None = None,
        doc_ref: str = "",
        public_payload: dict | None = None,
        restricted_payload: dict | None = None,
        node_id: str | None = None,
    ) -> ChainNode:
        node_id = node_id or f"evt-{next(self._seq)}"
        if node_id in self._ids:
            raise ValueError(f"节点标识重复：{node_id}")
        node = ChainNode(
            node_id=node_id,
            batch=batch,
            kind=kind,
            actor_id=actor_id,
            occurred_at=occurred_at,
            seq=next(self._seq),
            code=code,
            prev_id=prev_id,
            doc_ref=doc_ref,
            public_payload=dict(public_payload or {}),
            restricted_payload=dict(restricted_payload or {}),
        )
        self._ids.add(node_id)
        self._nodes.append(node)
        self._batch_rev[batch] = self._batch_rev.get(batch, 0) + 1
        if code is not None:
            self._code_batch[code] = batch
            self._batch_codes.setdefault(batch, set()).add(code)
        return node

    def correct(
        self,
        target_id: str,
        *,
        actor_id: str,
        occurred_at: str,
        reason: str,
        new_public_payload: dict,
        doc_ref: str = "",
    ) -> ChainNode:
        """追加更正事件；被更正节点保留原貌，仅回填 ``corrected_by``。"""
        index = self._find_index(target_id)
        target = self._nodes[index]
        correction = self.append(
            kind=NodeKind.CORRECTION,
            actor_id=actor_id,
            occurred_at=occurred_at,
            batch=target.batch,
            code=target.code,
            doc_ref=doc_ref,
            public_payload=dict(new_public_payload),
        )
        object.__setattr__(target, "corrected_by", correction.node_id)
        object.__setattr__(correction, "corrects_id", target.node_id)
        object.__setattr__(correction, "correction_reason", reason)
        return correction

    def _find_index(self, node_id: str) -> int:
        for i, node in enumerate(self._nodes):
            if node.node_id == node_id:
                return i
        raise KeyError(f"未知节点：{node_id}")

    # ---- 读取 -----------------------------------------------------------

    def node(self, node_id: str) -> ChainNode:
        return self._nodes[self._find_index(node_id)]

    def events_for(self, code: str) -> list[ChainNode]:
        batch = self._code_batch.get(code)
        if batch is None:
            raise UnknownCode(code)
        return [n for n in self._nodes if n.code == code]

    def batch_events(self, batch: str) -> list[ChainNode]:
        return [n for n in self._nodes if n.batch == batch and n.code is None]

    def batch_of(self, code: str) -> str:
        try:
            return self._code_batch[code]
        except KeyError:
            raise UnknownCode(code) from None

    def active_control(self, batch: str) -> list[ChainNode]:
        """当前仍生效的批次级召回/封存事件（被更正的视为解除）。"""
        return [
            n
            for n in self.batch_events(batch)
            if n.kind in CONTROL_KINDS and n.corrected_by is None
        ]

    def inspect(self, code: str) -> ChainReport:
        """对单码执行链路完整性检查，供发布规则使用。"""
        batch = self.batch_of(code)
        code_events = sorted(
            (n for n in self.events_for(code) if n.kind in TRANSFER_KINDS),
            key=lambda n: (n.occurred_at, n.seq),
        )
        controls = sorted(self.active_control(batch), key=lambda n: n.occurred_at)

        anomalies: list[ChainAnomaly] = []
        ids = [n.node_id for n in code_events]
        if len(ids) != len(set(ids)):
            anomalies.append(ChainAnomaly.LOOP)

        production = next((n for n in code_events if n.kind == NodeKind.PRODUCED), None)
        if production is None or code_events[0].kind != NodeKind.PRODUCED:
            anomalies.append(ChainAnomaly.MISSING_ORIGIN)

        prev: ChainNode | None = None
        dispensed_at: str | None = None
        for node in code_events:
            actor = self._actors.get(node.actor_id)
            if actor is None:
                anomalies.append(ChainAnomaly.UNKNOWN_ACTOR)
            elif not actor.licensed:
                anomalies.append(ChainAnomaly.UNLICENSED_ACTOR)
            if prev is not None and node.prev_id != prev.node_id:
                anomalies.append(ChainAnomaly.BROKEN_CHAIN)
            if node.prev_id is not None and node.prev_id not in self._ids:
                anomalies.append(ChainAnomaly.BROKEN_CHAIN)
            if dispensed_at is not None and node.kind != NodeKind.DISPENSED:
                anomalies.append(ChainAnomaly.EVENT_AFTER_DISPENSE)
            if any(
                c.occurred_at <= node.occurred_at
                and node.kind in {NodeKind.SHIPPED, NodeKind.RECEIVED, NodeKind.DISPENSED}
                for c in controls
            ):
                anomalies.append(ChainAnomaly.MOVE_AFTER_CONTROL)
            if node.kind == NodeKind.DISPENSED:
                dispensed_at = node.occurred_at
            prev = node

        recalled = any(c.kind == NodeKind.RECALLED for c in controls)
        held = any(c.kind == NodeKind.HOLD for c in controls)
        return ChainReport(
            code=code,
            batch=batch,
            complete=not anomalies and bool(code_events),
            anomalies=tuple(dict.fromkeys(anomalies)),
            recalled=recalled,
            held=held,
            production=production,
            last_transfer=code_events[-1] if code_events else None,
            revision=self.batch_revision(batch),
        )
