"""校验公众核验结果与查询错误契约。

只依赖标准库：把 ``contracts/*.schema.json`` 中实际用到的 JSON Schema 子集
（required / const / enum / minItems / minLength / additionalProperties /
条件 contains）固化为代码，并额外执行业务侧发布规则：

- 轨迹节点禁止携带机构名、个人与案件字段；
- 异地扫码异常不得作为待复核的唯一理由；
- 已召回必须带对外公告与行动指引；
- 轨迹时间只精确到日；
- 陈旧缓存必须显式标记 ``stale`` 且数据时间早于生成时间；
- 无法确认必须区分"未登记"与"上游不可用"理由。
"""

import json
from datetime import datetime
from pathlib import Path

CONTRACTS_DIR = Path(__file__).resolve().parent.parent / "contracts"

STATES = {
    "PRODUCED",
    "LEGIT_CIRCULATION",
    "RECALLED",
    "PENDING_REVIEW",
    "UNCONFIRMED",
}
REASONS = {
    "manufacturer_record_found",
    "manufacturer_qualified",
    "chain_continuous",
    "legal_chain_latest",
    "recall_active",
    "chain_gap_detected",
    "qualification_under_check",
    "authority_hold",
    "scan_geo_anomaly",
    "code_not_registered",
    "upstream_unavailable",
}
NODE_TYPES = {"MANUFACTURER", "WHOLESALE", "RETAIL", "MEDICAL_INSTITUTION", "RECALL"}
INSTRUCTIONS = {
    "STOP_USE_AND_RETURN",
    "FOLLOW_RECALL_NOTICE",
    "VERIFY_VIA_OTHER_CHANNEL",
    "WAIT_REVIEW",
}
ERROR_CODES = {"MALFORMED_INPUT", "RATE_LIMITED"}
ERROR_DETAILS = {
    "checksum_invalid",
    "length_invalid",
    "charset_invalid",
    "decode_failed",
    "quota_soft",
    "quota_hard",
}

# 永不出现在公众 DTO 中的内部字段（小写匹配）。
FORBIDDEN_KEYS = {
    "patient",
    "patient_name",
    "patient_id",
    "medical_insurance_id",
    "phone",
    "institution_name",
    "hospital_name",
    "pharmacy_name",
    "case_id",
    "investigation",
    "operator_name",
    "plain_code",
}

_REVIEW_REASONS = {"chain_gap_detected", "qualification_under_check", "authority_hold"}
_UNCONFIRMED_REASONS = {"code_not_registered", "upstream_unavailable"}
_RESULT_REQUIRED = {
    "schema_version",
    "domain",
    "result_ref",
    "state",
    "reasons",
    "rule_version",
    "data_as_of",
    "data_epoch",
    "generated_at",
    "code_ref",
}
_RESULT_ALLOWED = _RESULT_REQUIRED | {
    "stale",
    "product",
    "trail",
    "notice_ref",
    "action",
    "subscription",
}
_TRAIL_ALLOWED = {"node_type", "region", "at", "summary"}
_ACTION_ALLOWED = {"guidance_ref", "instruction_code"}
_ERROR_REQUIRED = {"schema_version", "domain", "error_code", "retryable"}
_ERROR_ALLOWED = _ERROR_REQUIRED | {
    "detail_code",
    "retry_after_seconds",
    "public_message",
}


class ContractViolation(ValueError):
    """响应不满足对外契约或发布规则。"""


def _require_keys(data: dict, required: set[str], where: str) -> None:
    missing = required - data.keys()
    if missing:
        raise ContractViolation(f"{where}缺少必要字段：{sorted(missing)}")


def _reject_extra_keys(data: dict, allowed: set[str], where: str) -> None:
    extra = data.keys() - allowed
    if extra:
        raise ContractViolation(f"{where}存在未授权字段：{sorted(extra)}")


def _reject_forbidden(data: object, where: str = "$") -> None:
    if isinstance(data, dict):
        for key, value in data.items():
            if key.lower() in FORBIDDEN_KEYS:
                raise ContractViolation(f"{where}.{key} 属于禁止对公众发布的内部字段")
            _reject_forbidden(value, f"{where}.{key}")
    elif isinstance(data, list):
        for index, item in enumerate(data):
            _reject_forbidden(item, f"{where}[{index}]")


def _parse_dt(value: str, field: str) -> datetime:
    try:
        return datetime.fromisoformat(value)
    except ValueError as exc:
        raise ContractViolation(f"{field} 不是合法的 ISO 时间：{value}") from exc


def validate_result(data: dict) -> dict:
    """校验公众核验结果，通过后原样返回。"""
    if not isinstance(data, dict):
        raise ContractViolation("结果必须是对象")
    _require_keys(data, _RESULT_REQUIRED, "结果")
    _reject_extra_keys(data, _RESULT_ALLOWED, "结果")

    if data["schema_version"] != 1:
        raise ContractViolation("schema_version 必须为 1")
    if data["domain"] != "public-code-verification":
        raise ContractViolation("domain 必须为 public-code-verification")
    if not isinstance(data["result_ref"], str) or len(data["result_ref"]) < 8:
        raise ContractViolation("result_ref 必须是不少于 8 个字符的不可变引用")

    state = data["state"]
    if state not in STATES:
        raise ContractViolation(f"未知状态：{state}")

    reasons = data["reasons"]
    if not isinstance(reasons, list) or not reasons:
        raise ContractViolation("reasons 至少包含一条理由码")
    unknown = set(reasons) - REASONS
    if unknown:
        raise ContractViolation(f"未知理由码：{sorted(unknown)}")

    if not isinstance(data["rule_version"], int) or data["rule_version"] < 1:
        raise ContractViolation("rule_version 必须为不小于 1 的整数")
    if not isinstance(data["data_epoch"], int) or data["data_epoch"] < 0:
        raise ContractViolation("data_epoch 必须为非负整数")

    data_as_of = _parse_dt(data["data_as_of"], "data_as_of")
    generated_at = _parse_dt(data["generated_at"], "generated_at")

    code_ref = data["code_ref"]
    _require_keys(code_ref, {"code_hash"}, "code_ref")
    _reject_extra_keys(code_ref, {"code_hash"}, "code_ref")
    if len(code_ref["code_hash"]) < 16:
        raise ContractViolation("code_ref.code_hash 长度不足，疑似明文码")

    # 状态与理由的发布规则。
    if state == "RECALLED":
        if "recall_active" not in reasons:
            raise ContractViolation("RECALLED 必须携带 recall_active 理由")
        _require_keys(data, {"notice_ref", "action"}, "RECALLED 结果")
        if not data.get("notice_ref"):
            raise ContractViolation("RECALLED 必须引用对外公告编号")
    if state == "UNCONFIRMED" and not (set(reasons) & _UNCONFIRMED_REASONS):
        raise ContractViolation(
            "UNCONFIRMED 必须区分 code_not_registered 或 upstream_unavailable"
        )
    if state == "PENDING_REVIEW" and not (set(reasons) & _REVIEW_REASONS):
        raise ContractViolation(
            "PENDING_REVIEW 必须有链路断点/资质核查/权威挂起之一作为实质理由，"
            "异地扫码异常不得单独触发待复核"
        )

    if "stale" in data:
        if not isinstance(data["stale"], bool):
            raise ContractViolation("stale 必须是布尔值")
        if data["stale"] and data_as_of >= generated_at:
            raise ContractViolation("陈旧缓存的 data_as_of 必须早于 generated_at")

    if "product" in data:
        product = data["product"]
        _require_keys(product, {"generic_name", "batch_id"}, "product")
        _reject_extra_keys(product, {"generic_name", "batch_id", "produced_on"}, "product")

    if "trail" in data:
        trail = data["trail"]
        if not isinstance(trail, list):
            raise ContractViolation("trail 必须是数组")
        for index, node in enumerate(trail):
            where = f"trail[{index}]"
            _require_keys(node, {"node_type", "region", "at"}, where)
            _reject_extra_keys(node, _TRAIL_ALLOWED, where)
            if node["node_type"] not in NODE_TYPES:
                raise ContractViolation(f"{where}.node_type 非法")
            # 时间只精确到日：必须是 YYYY-MM-DD，不含时分秒。
            try:
                parsed = datetime.strptime(node["at"], "%Y-%m-%d")
            except ValueError as exc:
                raise ContractViolation(f"{where}.at 必须精确到日 (YYYY-MM-DD)") from exc
            if parsed.date() > generated_at.date():
                raise ContractViolation(f"{where}.at 不能晚于结果生成时间")
            if "summary" in node and len(node["summary"]) > 60:
                raise ContractViolation(f"{where}.summary 不得超过 60 字")

    if "action" in data:
        action = data["action"]
        _require_keys(action, {"guidance_ref", "instruction_code"}, "action")
        _reject_extra_keys(action, _ACTION_ALLOWED, "action")
        if action["instruction_code"] not in INSTRUCTIONS:
            raise ContractViolation("action.instruction_code 非法")

    if "subscription" in data:
        sub = data["subscription"]
        _require_keys(sub, {"subscribed"}, "subscription")
        _reject_extra_keys(sub, {"subscribed", "subscribe_path"}, "subscription")

    _reject_forbidden(data)
    return data


def validate_error(data: dict) -> dict:
    """校验查询错误响应（残损输入 / 限速），通过后原样返回。"""
    if not isinstance(data, dict):
        raise ContractViolation("错误响应必须是对象")
    _require_keys(data, _ERROR_REQUIRED, "错误响应")
    _reject_extra_keys(data, _ERROR_ALLOWED, "错误响应")
    if data["schema_version"] != 1 or data["domain"] != "public-code-verification":
        raise ContractViolation("错误响应标识字段不正确")
    if data["error_code"] not in ERROR_CODES:
        raise ContractViolation(f"未知错误码：{data['error_code']}")
    if "detail_code" in data and data["detail_code"] not in ERROR_DETAILS:
        raise ContractViolation(f"未知错误明细：{data['detail_code']}")
    if not isinstance(data["retryable"], bool):
        raise ContractViolation("retryable 必须是布尔值")
    if data["error_code"] == "RATE_LIMITED" and "retry_after_seconds" not in data:
        raise ContractViolation("RATE_LIMITED 必须给出 retry_after_seconds")
    return data


def load_validated(path: Path) -> dict:
    """读取 JSON 并按其形态选择结果/错误校验器。"""
    data = json.loads(path.read_text(encoding="utf-8"))
    if "state" in data:
        return validate_result(data)
    if "error_code" in data:
        return validate_error(data)
    raise ContractViolation(f"{path} 既不是核验结果也不是错误响应")
