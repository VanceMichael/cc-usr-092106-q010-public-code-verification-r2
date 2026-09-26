"""追溯码输入的归一化、残损识别与指纹。

公众入口面对的是手机摄像头和手工录入：同一枚码可能携带空格、连字符、
大小写差异，也可能刮损、抄录不全。本模块把输入收敛为三类：

* 结构完整且校验位正确 → 规范化码，可进入权威库查询；
* 疑似残损/歧义 → ``DamagedCode``，提示重扫，不访问权威库；
* 码“存不存在”属于权威库事实，本模块不做存在性判断。

缓存键与限流桶一律使用指纹，避免明文追溯码出现在日志和缓存里。
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass

CODE_LENGTH = 20  # 药品消费单元追溯码：19 位本体 + 1 位校验位
_SEPARATORS = re.compile(r"[\s\-]")
# 残损标签上常见的字母/数字混淆。只给提示，绝不自动纠正——
# 自动猜码可能把患者引向另一枚真实存在的码。
_AMBIGUOUS = {"O": "0", "I": "1", "Z": "2", "S": "5", "B": "8"}
_DIGITS = set("0123456789")


class DamagedCode(ValueError):
    """输入残损或无法可靠识别，区别于“码不存在”。"""

    def __init__(self, reasons: list[str]):
        self.reasons = reasons
        super().__init__("；".join(reasons))


@dataclass(frozen=True)
class NormalizedCode:
    code: str
    fingerprint: str

    @property
    def body(self) -> str:
        return self.code[: CODE_LENGTH - 1]


def check_digit(body: str) -> int:
    """按交替权重 3/1 计算模 10 校验位。"""
    total = sum((3 if i % 2 == 0 else 1) * int(ch) for i, ch in enumerate(body))
    return (10 - total % 10) % 10


def make_trace_code(body: str) -> str:
    """生成带校验位的追溯码，供示例资料与测试使用。"""
    if len(body) != CODE_LENGTH - 1 or not body.isdigit():
        raise ValueError("本体必须为 19 位数字")
    return body + str(check_digit(body))


def fingerprint(code: str) -> str:
    """明文码 → 不可逆短指纹，用作缓存键与限流键。"""
    return hashlib.blake2b(
        code.encode("utf-8"), digest_size=16, person=b"medicine-trace"
    ).hexdigest()


def mask(code: str) -> str:
    """回执、通知中使用的脱敏展示值。"""
    if len(code) <= 8:
        return "*" * len(code)
    return f"{code[:4]}{'*' * (len(code) - 8)}{code[-4:]}"


def normalize(raw: object) -> NormalizedCode:
    """把入口输入归一化；任何不可靠情形都抛 ``DamagedCode``。"""
    if not isinstance(raw, str):
        raise DamagedCode(["输入为空或无法识别"])
    text = _SEPARATORS.sub("", raw.strip().upper())
    if not text:
        raise DamagedCode(["输入为空或无法识别"])

    reasons: list[str] = []
    if any(ord(ch) < 32 for ch in text):
        reasons.append("含不可识别字符")
    ambiguous = sorted({ch for ch in text if ch in _AMBIGUOUS})
    if ambiguous:
        hint = "、".join(f"{ch}≈{_AMBIGUOUS[ch]}" for ch in ambiguous)
        reasons.append(f"存在刮损歧义字符（{hint}），请重新扫码")
    foreign = sorted({ch for ch in text if ch not in _DIGITS and ch not in _AMBIGUOUS})
    if foreign:
        reasons.append(f"含非数字字符：{''.join(foreign)}")
    if len(text) != CODE_LENGTH and not foreign:
        reasons.append(f"位数异常：应为 {CODE_LENGTH} 位，实际 {len(text)} 位")

    if reasons:
        raise DamagedCode(reasons)

    body, given = text[:-1], text[-1]
    if str(check_digit(body)) != given:
        raise DamagedCode(["校验位不符，可能残损或抄录错误"])
    return NormalizedCode(code=text, fingerprint=fingerprint(text))
