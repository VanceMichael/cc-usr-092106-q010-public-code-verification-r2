import json
import unittest
from pathlib import Path

from src.verification import (
    ContractViolation,
    load_validated,
    validate_error,
    validate_result,
)

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"
VERIFY_FIXTURES = FIXTURES / "verify"
ERROR_FIXTURES = FIXTURES / "errors"


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _all_result_fixtures():
    return sorted(VERIFY_FIXTURES.glob("*.json"))


class FixtureContractTest(unittest.TestCase):
    def test_all_result_fixtures_pass(self):
        self.assertTrue(_all_result_fixtures())
        for path in _all_result_fixtures():
            with self.subTest(fixture=path.name):
                self.assertIn("state", load_validated(path))

    def test_error_fixtures_pass(self):
        for path in sorted(ERROR_FIXTURES.glob("*.json")):
            with self.subTest(fixture=path.name):
                self.assertIn("error_code", load_validated(path))

    def test_five_states_covered(self):
        states = {_load(p)["state"] for p in _all_result_fixtures()}
        self.assertEqual(
            states,
            {
                "PRODUCED",
                "LEGIT_CIRCULATION",
                "RECALLED",
                "PENDING_REVIEW",
                "UNCONFIRMED",
            },
        )


class PublicationRuleTest(unittest.TestCase):
    def setUp(self):
        self.base = _load(VERIFY_FIXTURES / "legit-circulation.json")

    def test_geo_anomaly_alone_cannot_escalate(self):
        data = dict(self.base)
        data["state"] = "PENDING_REVIEW"
        data["reasons"] = ["scan_geo_anomaly"]
        with self.assertRaisesRegex(ContractViolation, "实质理由"):
            validate_result(data)

    def test_geo_anomaly_allowed_with_substantive_reason(self):
        pending = _load(VERIFY_FIXTURES / "pending-review.json")
        validate_result(pending)  # chain_gap + geo anomaly 可发布

    def test_recalled_requires_notice_and_action(self):
        recalled = _load(VERIFY_FIXTURES / "recalled.json")
        validate_result(recalled)
        for drop in ("notice_ref", "action"):
            bad = dict(recalled)
            del bad[drop]
            with self.subTest(drop=drop):
                with self.assertRaises(ContractViolation):
                    validate_result(bad)

    def test_unconfirmed_must_distinguish_reason(self):
        data = _load(VERIFY_FIXTURES / "unconfirmed-not-registered.json")
        validate_result(data)
        data["reasons"] = ["manufacturer_record_found"]
        with self.assertRaisesRegex(ContractViolation, "code_not_registered"):
            validate_result(data)

    def test_stale_cache_must_be_marked(self):
        stale = _load(VERIFY_FIXTURES / "stale-positive.json")
        validate_result(stale)
        bad = dict(stale)
        bad["stale"] = False
        # stale=false 与更早快照不冲突，但不得谎称数据时间晚于生成时间
        bad["data_as_of"] = bad["generated_at"]
        bad["stale"] = True
        with self.assertRaisesRegex(ContractViolation, "data_as_of"):
            validate_result(bad)

    def test_trail_dates_are_day_precision_only(self):
        data = dict(self.base)
        data["trail"] = [
            {"node_type": "WHOLESALE", "region": "江苏省", "at": "2026-08-20T10:30:00+08:00"}
        ]
        with self.assertRaisesRegex(ContractViolation, "精确到日"):
            validate_result(data)


class PrivacyWhitelistTest(unittest.TestCase):
    def setUp(self):
        self.base = _load(VERIFY_FIXTURES / "legit-circulation.json")

    def test_no_institution_or_person_fields(self):
        for forbidden in ("institution_name", "patient", "case_id", "phone"):
            data = dict(self.base)
            data["trail"] = [
                {
                    "node_type": "RETAIL",
                    "region": "上海市",
                    "at": "2026-09-10",
                    forbidden: "X",
                }
            ]
            with self.subTest(forbidden=forbidden):
                # 白名单拒绝未授权字段，禁词扫描兜底，任何一条命中都不得发布
                with self.assertRaises(ContractViolation):
                    validate_result(data)

    def test_no_plaintext_code(self):
        data = dict(self.base)
        data["code_ref"] = {"code_hash": "abc"}
        with self.assertRaisesRegex(ContractViolation, "明文码"):
            validate_result(data)

    def test_extra_top_level_field_rejected(self):
        data = dict(self.base)
        data["internal_risk_tag"] = "investigating"
        with self.assertRaisesRegex(ContractViolation, "未授权字段"):
            validate_result(data)


class ErrorContractTest(unittest.TestCase):
    def test_rate_limited_needs_retry_after(self):
        data = _load(ERROR_FIXTURES / "rate-limited.json")
        validate_error(data)
        del data["retry_after_seconds"]
        with self.assertRaisesRegex(ContractViolation, "retry_after_seconds"):
            validate_error(data)

    def test_malformed_input_accepted(self):
        validate_error(_load(ERROR_FIXTURES / "malformed-input.json"))


if __name__ == "__main__":
    unittest.main()
