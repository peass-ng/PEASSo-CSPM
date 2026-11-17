"""Differential IAM truth cases preserve pinned query joins and variants."""
import copy

import pytest

from peaso.checks import CHECKS, aws_a_iam
from peaso.checks.fixtures import CASES
from peaso.checks.aws_a_facts import scope_fixture


REGISTRY = {c.id: c for c in CHECKS if c.id in aws_a_iam.NATIVE_IDS}
SUBJECT = {"scope": "123456789012/us-east-1"}


@pytest.mark.parametrize("cid", sorted(REGISTRY))
def test_all_iam_variants_have_real_pass_fail_missing_denied_malformed_truths(cid):
    check, cases = REGISTRY[cid], CASES[cid]
    for state, expected in (("pass", "PASS"), ("fail", "FAIL"), ("missing", "UNKNOWN"), ("malformed", "UNKNOWN")):
        item = copy.deepcopy(cases[state])
        index = copy.deepcopy(cases.get(state + "_index", cases.get("index", {})))
        before = copy.deepcopy((item, index))
        assert check.evaluate(item, index)[0] == expected, (cid, state)
        assert (item, index) == before
    assert check.evaluate({"collection_status": "denied"}, cases.get("index", {}))[0] == "UNKNOWN"


@pytest.mark.parametrize("cid", [cid for cid, c in REGISTRY.items() if c.target == "scope"])
def test_account_left_join_absence_only_fails_with_complete_inventory(cid):
    check = REGISTRY[cid]
    assert check.evaluate(SUBJECT, scope_fixture("iam_password_policy", []))[0] == "FAIL"
    for status in ("denied", "partial", "unknown", "timeout", "malformed", "not_collected"):
        assert check.evaluate(SUBJECT, scope_fixture("iam_password_policy", [], status=status))[0] == "UNKNOWN"
    assert check.evaluate(SUBJECT, {})[0] == "UNKNOWN"
    duplicate = scope_fixture("iam_password_policy", [{"PasswordPolicy": {}}, {"PasswordPolicy": {}}])
    assert check.evaluate(SUBJECT, duplicate)[0] == "UNKNOWN"


@pytest.mark.parametrize("cid", [cid for cid, c in REGISTRY.items() if c.target == "scope"])
def test_foreign_account_or_unverified_foreign_region_policy_cannot_satisfy_scope(cid):
    index = copy.deepcopy(CASES[cid]["index"])
    envelope = index["collections"]["iam_password_policy"][0]
    envelope["account_id"] = "999999999999"
    envelope["scope"] = "999999999999/us-east-1"
    assert REGISTRY[cid].evaluate(SUBJECT, index)[0] == "UNKNOWN"
    envelope["scope"] = "123456789012/eu-west-1"
    envelope.pop("global")
    envelope.pop("account_id")
    assert REGISTRY[cid].evaluate(SUBJECT, index)[0] == "UNKNOWN"


@pytest.mark.parametrize("value,expected", [(23, "FAIL"), (24, "PASS"), (25, "PASS"), (True, "UNKNOWN"), ("24", "UNKNOWN")])
def test_sql_reuse_greater_equal_is_kept_separate_from_prowler_exact_equality(value, expected):
    index = scope_fixture("iam_password_policy", [{"PasswordPolicy": {"PasswordReusePrevention": value}}])
    assert REGISTRY["aws.a.iam.password_policy_reuse_at_least_24"].evaluate(SUBJECT, index)[0] == expected


@pytest.mark.parametrize("value,expected", [(0, "PASS"), (90, "PASS"), (91, "FAIL"), (True, "UNKNOWN")])
def test_sql_age_upper_bound_is_kept_separate_from_positive_age_prowler_variant(value, expected):
    index = scope_fixture("iam_password_policy", [{"PasswordPolicy": {"MaxPasswordAge": value}}])
    assert REGISTRY["aws.a.iam.password_policy_expiry_at_most_90"].evaluate(SUBJECT, index)[0] == expected


@pytest.mark.parametrize("suffix,minimum", [("strong_min_length_8", 8), ("strong_min_length_14_reuse_24_age_90", 14)])
def test_strong_policy_requires_the_complete_compound_not_just_minimum_length(suffix, minimum):
    cid = "aws.a.iam.password_policy_" + suffix
    good = copy.deepcopy(CASES[cid]["index"]["collections"]["iam_password_policy"][0]["items"][0])
    for field in aws_a_iam.STRONG_FIELDS:
        bad = copy.deepcopy(good)
        bad["PasswordPolicy"][field] = False
        assert REGISTRY[cid].evaluate(SUBJECT, scope_fixture("iam_password_policy", [bad]))[0] == "FAIL"
    good["PasswordPolicy"]["MinimumPasswordLength"] = minimum - 1
    assert REGISTRY[cid].evaluate(SUBJECT, scope_fixture("iam_password_policy", [good]))[0] == "FAIL"


@pytest.mark.parametrize("password,mfa,expected", [("true", "true", "PASS"), ("true", "false", "FAIL"), ("false", "false", "PASS"), ("not_supported", "false", "UNKNOWN"), (True, "true", "UNKNOWN")])
def test_credential_report_console_and_all_principal_mfa_variants_are_distinct(password, mfa, expected):
    item = {"password_enabled": password, "mfa_active": mfa}
    assert REGISTRY["aws.a.iam.report_console_mfa"].evaluate(item, {})[0] == expected
    if mfa == "false":
        # Every principal that can sign in needs MFA; one with no console password has nothing for MFA to protect.
        all_mfa = {"true": "FAIL", "false": "NOT_APPLICABLE", "not_supported": "FAIL"}[password]
        assert REGISTRY["aws.a.iam.report_all_mfa"].evaluate(item, {})[0] == all_mfa


def test_root_key_count_is_not_a_boolean_and_mfa_flag_is_bounded():
    assert REGISTRY["aws.a.iam.root_summary_no_keys"].evaluate({"SummaryMap": {"AccountAccessKeysPresent": 2}}, {})[0] == "FAIL"
    assert REGISTRY["aws.a.iam.root_summary_no_keys"].evaluate({"SummaryMap": {"AccountAccessKeysPresent": False}}, {})[0] == "UNKNOWN"
    assert REGISTRY["aws.a.iam.root_summary_mfa"].evaluate({"SummaryMap": {"AccountMFAEnabled": 2}}, {})[0] == "UNKNOWN"
