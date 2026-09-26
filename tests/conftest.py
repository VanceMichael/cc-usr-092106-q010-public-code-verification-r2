"""构造一套虚构但链路完整的权威库，供各测试复用。"""

import pytest

from src.authority import AuthorityStore, Actor, NodeKind
from src.tracecodes import make_trace_code


@pytest.fixture
def store():
    s = AuthorityStore()
    s.register_actor(Actor("M1", "虚构制药有限公司", "manufacturer", "北京"))
    s.register_actor(Actor("D1", "虚构医药流通公司", "distributor", "河北"))
    s.register_actor(Actor("P1", "虚构社区药房", "pharmacy", "河北"))
    s.register_actor(Actor("P2", "虚构过期资质药房", "pharmacy", "河南", licensed=False))
    s.register_actor(Actor("R1", "省级药监部门", "regulator", "北京"))
    return s


@pytest.fixture
def chained(store):
    """一枚完整走完全链路的码：生产→调出→接收→销售。"""
    code = make_trace_code("1234567890123456789")
    batch = "BATCH-2026-0001"
    e1 = store.append(
        kind=NodeKind.PRODUCED, actor_id="M1", occurred_at="2026-08-01T08:00:00+00:00",
        batch=batch, code=code, doc_ref="生产入库单001",
        public_payload={"product_name": "虚构注射用示例粉针", "spec": "0.5g",
                        "approval_number": "国药准字H00000000"},
        restricted_payload={"operator_id": "员工X-保密", "patient": "前购药人-保密"},
    )
    e2 = store.append(
        kind=NodeKind.SHIPPED, actor_id="M1", occurred_at="2026-08-02T08:00:00+00:00",
        batch=batch, code=code, prev_id=e1.node_id,
        restricted_payload={"case_no": "侦办案件-保密"},
    )
    e3 = store.append(
        kind=NodeKind.RECEIVED, actor_id="D1", occurred_at="2026-08-03T08:00:00+00:00",
        batch=batch, code=code, prev_id=e2.node_id,
    )
    e4 = store.append(
        kind=NodeKind.DISPENSED, actor_id="P1", occurred_at="2026-08-05T08:00:00+00:00",
        batch=batch, code=code, prev_id=e3.node_id,
        restricted_payload={"buyer_id": "购药人身份-保密"},
    )
    return {"code": code, "batch": batch, "events": [e1, e2, e3, e4]}


@pytest.fixture
def produced_only(store):
    code = make_trace_code("9876543210987654321")
    batch = "BATCH-2026-0002"
    store.append(
        kind=NodeKind.PRODUCED, actor_id="M1", occurred_at="2026-09-01T08:00:00+00:00",
        batch=batch, code=code,
        public_payload={"product_name": "虚构示例片剂", "spec": "10mg",
                        "approval_number": "国药准字H00000001"},
    )
    return {"code": code, "batch": batch}
