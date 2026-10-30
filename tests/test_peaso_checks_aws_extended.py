"""Independently specified semantic fixtures for the reviewed AWS extension."""
import copy

import pytest

from peaso.checks import CHECKS, aws_extended
from peaso.checks.fixtures import CASES

REGISTRY = {c.id: c for c in CHECKS if c.id in aws_extended.EXTENDED_IDS}


@pytest.mark.parametrize("cid", sorted(REGISTRY))
def test_every_extended_check_has_semantic_states_and_is_pure(cid):
    check = REGISTRY[cid]
    cases = CASES[cid]
    for label, expected in (("pass", "PASS"), ("fail", "FAIL"), ("missing", "UNKNOWN"), ("malformed", "UNKNOWN"), ("not_applicable", "NOT_APPLICABLE")):
        if label not in cases:
            continue
        item = copy.deepcopy(cases[label])
        before = copy.deepcopy(item)
        assert check.evaluate(item, {})[0] == expected, (cid, label)
        assert item == before
    assert check.evaluate({**copy.deepcopy(cases["pass"]), "collection_status": "denied"}, {})[0] == "UNKNOWN"
    assert check.evaluate({"collection_status": "timeout"}, {})[0] == "UNKNOWN"


@pytest.mark.parametrize("cid", sorted(REGISTRY))
def test_nested_denied_detail_cannot_pass_using_present_fields(cid):
    passing = CASES[cid]["pass"]
    def visit(value, path=()):
        if not isinstance(value, dict):
            return
        if path:
            item = copy.deepcopy(passing)
            target = item
            for part in path:
                target = target[part]
            target["collection_status"] = "denied"
            assert REGISTRY[cid].evaluate(item, {})[0] == "UNKNOWN", (cid, path)
        for key, child in value.items():
            if isinstance(child, dict):
                visit(child, path + (key,))
    visit(passing)


def evaluate(cid, item):
    return REGISTRY[cid].evaluate(item, {})[0]


@pytest.mark.parametrize("value,expected", [(0, "FAIL"), (1, "PASS"), (90, "PASS"), (91, "FAIL"), (True, "UNKNOWN"), ("90", "UNKNOWN"), (-1, "UNKNOWN")])
def test_password_age_threshold_and_native_integer_type(value, expected):
    assert evaluate("aws.iam.password_max_age", {"PasswordPolicy": {"MaxPasswordAge": value}}) == expected


@pytest.mark.parametrize("value,expected", [(13, "FAIL"), (14, "PASS"), (20, "PASS"), (True, "UNKNOWN"), ("14", "UNKNOWN")])
def test_password_length_lower_bound_matches_reviewed_predicate(value, expected):
    assert evaluate("aws.iam.password_minimum_length", {"PasswordPolicy": {"MinimumPasswordLength": value}}) == expected


@pytest.mark.parametrize("value,expected", [(0, "FAIL"), (23, "FAIL"), (24, "PASS"), (25, "FAIL"), (False, "UNKNOWN")])
def test_password_reuse_is_exactly_24_per_pinned_source(value, expected):
    assert evaluate("aws.iam.password_reuse_prevention", {"PasswordPolicy": {"PasswordReusePrevention": value}}) == expected


@pytest.mark.parametrize("engine", ["aurora", "aurora-mysql", "aurora-postgresql"])
def test_rds_copy_tags_excludes_aurora_without_guessing_cluster_setting(engine):
    assert evaluate("aws.rds.copy_snapshot_tags", {"Engine": engine}) == "NOT_APPLICABLE"
    assert evaluate("aws.rds.copy_snapshot_tags", {"CopyTagsToSnapshot": True}) == "UNKNOWN"


@pytest.mark.parametrize("mode,drop,expected", [("strictest", "false", "PASS"), ("defensive", "false", "PASS"), ("monitor", "true", "PASS"), ("monitor", "false", "FAIL"), ("new-mode", "true", "UNKNOWN"), ("monitor", "unknown", "UNKNOWN")])
def test_load_balancer_desync_preserves_header_drop_alternative(mode, drop, expected):
    assert evaluate("aws.elbv2.desync_mitigation", aws_extended.desync_fixture(mode, drop)) == expected


def test_load_balancer_attribute_duplicate_malformed_missing_and_denied():
    cid = "aws.elbv2.deletion_protection"
    item = aws_extended.lb_fixture("deletion_protection.enabled", "true")
    item["Attributes"]["Attributes"].append({"Key": "deletion_protection.enabled", "Value": "false"})
    assert evaluate(cid, item) == "UNKNOWN"
    assert evaluate(cid, {"Attributes": {"Attributes": []}}) == "UNKNOWN"
    assert evaluate(cid, {"Attributes": {"Attributes": [{"Key": "deletion_protection.enabled", "Value": True}]}}) == "UNKNOWN"
    assert evaluate(cid, {"Attributes": {"collection_status": "denied", "Attributes": [{"Key": "deletion_protection.enabled", "Value": "true"}]}}) == "UNKNOWN"


@pytest.mark.parametrize("attributes,expected", [
    ({"KmsMasterKeyId": "kms-key"}, "PASS"),
    ({"SqsManagedSseEnabled": "true"}, "PASS"),
    ({"KmsMasterKeyId": "", "SqsManagedSseEnabled": "false"}, "FAIL"),
    ({"SqsManagedSseEnabled": "false"}, "UNKNOWN"),
    ({}, "UNKNOWN"),
    ({"KmsMasterKeyId": [], "SqsManagedSseEnabled": "true"}, "UNKNOWN"),
    ({"KmsMasterKeyId": "", "SqsManagedSseEnabled": True}, "UNKNOWN"),
])
def test_sqs_kms_and_sse_alternatives_require_evidence_before_failure(attributes, expected):
    assert evaluate("aws.sqs.encryption", {"Attributes": {"Attributes": attributes}}) == expected


def test_ecr_absence_denial_and_missing_policy_are_distinct():
    cid = "aws.ecr.lifecycle_policy"
    assert evaluate(cid, {"LifecyclePolicy": {"collection_status": "empty", "absent": True}}) == "FAIL"
    assert evaluate(cid, {"LifecyclePolicy": {"collection_status": "denied"}}) == "UNKNOWN"
    assert evaluate(cid, {"LifecyclePolicy": {}}) == "UNKNOWN"
    assert evaluate(cid, {"LifecyclePolicy": {"lifecyclePolicyText": {"rules": []}}}) == "UNKNOWN"


def test_existing_function_url_auth_and_absence_have_correct_applicability():
    cid = "aws.lambda.function_url_authentication"
    assert evaluate(cid, {"FunctionUrl": {"collection_status": "empty", "absent": True}}) == "NOT_APPLICABLE"
    assert evaluate(cid, {"FunctionUrl": {}}) == "UNKNOWN"
    assert evaluate(cid, {"FunctionUrl": {"AuthType": "unknown"}}) == "UNKNOWN"
    assert evaluate(cid, {"FunctionUrl": {"collection_status": "denied", "AuthType": "NONE"}}) == "UNKNOWN"


def test_config_service_role_gates_on_recording_and_matches_account_partition():
    cid = "aws.config.service_linked_role"
    item = aws_extended.config_fixture("arn:aws-us-gov:iam::123456789012:role/aws-service-role/config.amazonaws.com/AWSServiceRoleForConfig")
    assert evaluate(cid, item) == "PASS"
    item["AccountId"] = "999999999999"
    assert evaluate(cid, item) == "FAIL"
    item["Status"]["ConfigurationRecordersStatus"][0]["recording"] = False
    assert evaluate(cid, item) == "NOT_APPLICABLE"
    item["Status"] = {"collection_status": "denied"}
    assert evaluate(cid, item) == "UNKNOWN"


def test_kms_manager_state_and_disabled_key_eligibility():
    cid = "aws.kms.no_pending_key_deletion"
    assert evaluate(cid, {"Metadata": {"KeyMetadata": {"KeyManager": "AWS"}}}) == "NOT_APPLICABLE"
    assert evaluate(cid, {"Metadata": {"KeyMetadata": {"KeyManager": "CUSTOMER", "KeyState": "Disabled"}}}) == "NOT_APPLICABLE"
    assert evaluate(cid, {"Metadata": {"KeyMetadata": {"KeyManager": "CUSTOMER", "KeyState": "PendingDeletion"}}}) == "FAIL"
    assert evaluate(cid, {"Metadata": {"KeyMetadata": {"KeyManager": "CUSTOMER", "KeyState": "new-state"}}}) == "UNKNOWN"


@pytest.mark.parametrize("version,configs,expected", [
    ("1.27", [], "FAIL"), ("1.27", [{"resources": ["secrets"]}], "PASS"),
    ("1.27", [{"resources": ["configmaps"]}], "FAIL"), ("1.28", None, "PASS"),
    ("1.34", None, "PASS"), ("2.0", None, "PASS"), ("invalid", [], "UNKNOWN"),
])
def test_eks_default_envelope_encryption_from_128_and_old_explicit_config(version, configs, expected):
    cluster = {"version": version}
    if configs is not None:
        cluster["encryptionConfig"] = configs
    assert evaluate("aws.eks.secrets_encryption", {"Cluster": {"cluster": cluster}}) == expected


# This shard retains its original review pin. The later AWS source admission
# advanced Prowler's manifest revision without changing any of these 26
# evaluator digests. Accept only that exact revision/URL substitution; never
# treat an arbitrary current manifest revision as a new review.
@pytest.mark.parametrize("cid", [cid for cid in REGISTRY if cid.startswith("aws.guardduty.")])
def test_guardduty_features_empty_missing_denied_malformed_and_duplicate(cid):
    feature = CASES[cid]["pass"]["Configuration"]["Features"][0]["Name"]
    assert evaluate(cid, {"Configuration": {"Status": "ENABLED", "Features": []}}) == "FAIL"
    assert evaluate(cid, {"Configuration": {}}) == "UNKNOWN"
    assert evaluate(cid, {"Configuration": {"Status": "ENABLED", "Features": [{"Name": feature, "Status": "unknown"}]}}) == "UNKNOWN"
    assert evaluate(cid, {"Configuration": {"Status": "ENABLED", "Features": [{"Name": feature, "Status": "ENABLED"}, {"Name": feature, "Status": "DISABLED"}]}}) == "UNKNOWN"
    assert evaluate(cid, {"Configuration": {"collection_status": "denied", "Features": [{"Name": feature, "Status": "ENABLED"}]}}) == "UNKNOWN"
