"""Cognito independent password/authentication policies and native risk metadata."""
import copy
import pytest
from peaso.checks import CHECKS, HACKTRICKS
from peaso.checks import aws_b_cognito as module
from peaso.checks.fixtures import CASES
from peaso.collectors import aws_b_services as plugin


def check(cid):
    return next(c for c in CHECKS if c.id == cid)


@pytest.mark.parametrize("cid", module.IDS)
def test_independent_native_predicates_and_unavailable_facts(cid):
    c = check(cid)
    for label, expected in (("pass", "PASS"), ("fail", "FAIL")):
        data = copy.deepcopy(CASES[cid][label]);before = copy.deepcopy(data)
        assert c.evaluate(data, {})[0] == expected
        assert data == before
    for data in ({}, None, {"Configuration": {"collection_status": "denied"}}, {"_coverage": []}):
        assert c.evaluate(data, {})[0] == "UNKNOWN"
    assert HACKTRICKS in c.frameworks


def test_only_successful_identified_user_pool_can_use_source_omission_defaults():
    data = {"Configuration": {"collection_status": "collected", "UserPool": {"Id": "region_fixture"}}}
    assert check("aws.b.cognito.password_lowercase").evaluate(data, {})[0] == "FAIL"
    assert check("aws.b.cognito.admin_only_signup").evaluate(data, {})[0] == "FAIL"
    assert check("aws.b.cognito.temporary_password_seven_days").evaluate(data, {})[0] == "PASS"
    data["Configuration"].pop("collection_status")
    assert check("aws.b.cognito.password_lowercase").evaluate(data, {})[0] == "UNKNOWN"
    data["Configuration"]["collection_status"] = "collected"
    data["Configuration"]["UserPool"]["_coverage"] = {"Policies": {"status": "denied"}}
    assert check("aws.b.cognito.password_lowercase").evaluate(data, {})[0] == "UNKNOWN"


def test_separate_fourteen_character_requirement_is_not_merged_with_eight_character_compound():
    c = check("aws.b.cognito.password_minimum_fourteen")
    for length, expected in ((8, "FAIL"), (13, "FAIL"), (14, "PASS"), (99, "PASS"), (100, "UNKNOWN"), (True, "UNKNOWN")):
        data = {"Configuration": {"UserPool": {"Policies": {"PasswordPolicy": {"MinimumLength": length}}}}}
        assert c.evaluate(data, {})[0] == expected


def test_optional_mfa_and_audit_only_threat_protection_fail_stronger_source_requirements():
    data = {"Configuration": {"UserPool": {"MfaConfiguration": "OPTIONAL", "UserPoolAddOns": {"AdvancedSecurityMode": "AUDIT"}}}}
    assert check("aws.b.cognito.required_mfa").evaluate(data, {})[0] == "FAIL"
    assert check("aws.b.cognito.enforced_threat_protection").evaluate(data, {})[0] == "FAIL"


def test_compromised_signin_requires_enforced_mode_event_and_blocking_response():
    cid = "aws.b.cognito.block_compromised_signin";data = copy.deepcopy(CASES[cid]["pass"])
    c = check(cid)
    data["Risk"]["RiskConfiguration"]["CompromisedCredentialsRiskConfiguration"]["EventFilter"] = ["SIGN_UP"]
    assert c.evaluate(data, {})[0] == "FAIL"
    data = copy.deepcopy(CASES[cid]["pass"]);data["Risk"] = {"collection_status": "denied"}
    assert c.evaluate(data, {})[0] == "UNKNOWN"
    data["Configuration"]["UserPool"]["UserPoolAddOns"]["AdvancedSecurityMode"] = "OFF"
    assert c.evaluate(data, {})[0] == "FAIL"
    data["Configuration"]["UserPool"]["UserPoolAddOns"]["AdvancedSecurityMode"] = "ENFORCED"
    data["Risk"] = {"collection_status": "collected"}
    assert c.evaluate(data, {})[0] == "FAIL"


@pytest.mark.parametrize("level", ["LowAction", "MediumAction", "HighAction"])
def test_all_takeover_risk_levels_are_required(level):
    cid = "aws.b.cognito.block_all_takeover_risks";data = copy.deepcopy(CASES[cid]["pass"])
    data["Risk"]["RiskConfiguration"]["AccountTakeoverRiskConfiguration"]["Actions"][level]["EventAction"] = "MFA_REQUIRED"
    assert check(cid).evaluate(data, {})[0] == "FAIL"


def test_risk_metadata_enrichment_uses_shared_sdk_and_preserves_denial():
    class Reads:
        def detail(self, session, service, region, operation, **kwargs):
            if operation == "describe_user_pool":
                return {"collection_status": "collected", "UserPool": {"Id": "fixture", "UserPoolAddOns": {"AdvancedSecurityMode": "ENFORCED"}}}
            return {"collection_status": "denied"}
        def pages(self, *args, **kwargs):
            from peaso.collectors.aws import ReadResult
            return ReadResult([], "empty")
    data = plugin.ENRICHERS["cognito_user_pool"](Reads(), object(), "us-east-1", [{"Id": "fixture"}])[0]
    assert data["Risk"]["collection_status"] == "denied"
    assert check("aws.b.cognito.block_all_takeover_risks").evaluate(data, {})[0] == "UNKNOWN"


