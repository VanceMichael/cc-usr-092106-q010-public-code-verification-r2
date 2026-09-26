import pytest

from src.tracecodes import (
    CODE_LENGTH,
    DamagedCode,
    check_digit,
    fingerprint,
    make_trace_code,
    mask,
    normalize,
)


def test_valid_code_normalizes_and_fingerprints():
    code = make_trace_code("1234567890123456789")
    result = normalize(code)
    assert result.code == code
    assert len(result.fingerprint) == 32


def test_normalize_strips_separators_and_case():
    code = make_trace_code("1234567890123456789")
    spaced = " ".join(code[i:i + 4] for i in range(0, len(code), 4)).lower()
    assert normalize(spaced).code == code


def test_check_digit_deterministic():
    assert 0 <= check_digit("1234567890123456789") <= 9


@pytest.mark.parametrize(
    "raw",
    [
        "",
        "   ",
        None,
        12345,
        "12345",
        "abcdefghijklmnopqrst",
    ],
)
def test_damaged_inputs(raw):
    with pytest.raises(DamagedCode):
        normalize(raw)


def test_wrong_check_digit_is_damaged():
    code = make_trace_code("1234567890123456789")
    wrong_last = "1" if code[-1] != "1" else "2"
    with pytest.raises(DamagedCode):
        normalize(code[:-1] + wrong_last)


def test_ambiguous_letter_is_damaged_not_autocorrected():
    # 0 与 O 混淆：绝不猜码，要求重扫。
    body = "1234567890123456789"
    code = make_trace_code(body)
    ambiguous = "O" + code[1:]
    with pytest.raises(DamagedCode) as exc:
        normalize(ambiguous)
    assert any("歧义" in r for r in exc.value.reasons)


def test_wrong_length_is_damaged():
    with pytest.raises(DamagedCode) as exc:
        normalize("12345")
    assert any("位数异常" in r for r in exc.value.reasons)


def test_fingerprint_stable_and_masked():
    code = make_trace_code("1234567890123456789")
    assert fingerprint(code) == fingerprint(code)
    masked = mask(code)
    assert masked.startswith(code[:4]) and masked.endswith(code[-4:])
    assert code[4:-4] not in masked
    assert len(masked) == CODE_LENGTH
