"""Native account boundaries distinguish AWS service/owner grants from foreign access."""
import copy
import pytest
from peaso.analysis.internet_exposure import assess

ACCOUNT = "123456789012"
REGION = "us-east-1"
SCOPE = ACCOUNT + "/" + REGION
SNAPSHOT = {"provider": "aws", "scopes": [SCOPE]}
KEY = f"arn:aws:kms:{REGION}:{ACCOUNT}:key/key-1"
TOPIC = f"arn:aws:sns:{REGION}:{ACCOUNT}:alerts"


def resource(kind, data):
    return {"id": kind, "type": kind, "scope": SCOPE, "data": data}


def selected(kind, data, exposure):
    return [a for a in assess(SNAPSHOT, [resource(kind, data)]) if a.kind == exposure]


def test_service_kms_grant_is_not_an_unattributable_foreign_account():
    grant = {"KeyId": "key-1", "KeyArn": KEY, "GrantId": "grant-1", "Operations": ["Decrypt"],
             "GranteePrincipal": "rds.us-east-1.amazonaws.com"}
    assert selected("kms_grant", grant, "external_kms_grant") == []
    grant["GranteePrincipal"] = "unresolved-principal"
    assert selected("kms_grant", grant, "external_kms_grant")[0].verdict() == "UNKNOWN"


def test_conditional_service_key_policy_is_not_a_foreign_account_grant():
    key = {"KeyId": "key-1", "KeyArn": KEY, "Metadata": {"collection_status": "collected", "KeyMetadata": {
        "KeyId": "key-1", "Arn": KEY, "KeyManager": "CUSTOMER", "KeyUsage": "ENCRYPT_DECRYPT", "KeyState": "Enabled", "Enabled": True}},
        "Policy": {"collection_status": "collected", "Policy": {"Statement": [{"Effect": "Allow", "Principal": {"Service": "logs.us-east-1.amazonaws.com"},
            "Action": "kms:Decrypt*", "Resource": "*", "Condition": {"ArnEquals": {"kms:EncryptionContext:aws:logs:arn": "arn:aws:logs:us-east-1:123456789012:log-group:db"}}}]}}}
    assert selected("kms_key", key, "external_kms_decrypt_grant") == []
    key["Policy"]["Policy"]["Statement"][0]["Principal"] = {"AWS": "*"}
    assert selected("kms_key", key, "external_kms_decrypt_grant")[0].verdict() == "UNKNOWN"


@pytest.mark.parametrize("operator,owner,expected", [("StringEquals", ACCOUNT, None), ("StringEqualsIfExists", ACCOUNT, "UNKNOWN"), ("StringEquals", "999999999999", "UNKNOWN")])
def test_sns_source_owner_restriction_is_required_and_exact(operator, owner, expected):
    policy = {"Statement": [{"Effect": "Allow", "Principal": {"AWS": "*"}, "Action": ["sns:Subscribe", "sns:Publish"], "Resource": TOPIC,
                             "Condition": {operator: {"AWS:SourceOwner": owner}}}]}
    topic = {"TopicArn": TOPIC, "Attributes": {"collection_status": "collected", "Attributes": {"TopicArn": TOPIC, "Owner": ACCOUNT, "Policy": policy}}}
    generic = {"ResourceArn": TOPIC, "Policy": policy, "_provenance": {"read_only": True, "owner_account": ACCOUNT, "families": ["sns-base"], "covered_services": ["sns"]}}
    for kind, data, exposure in [("sns_topic", topic, "external_topic_subscribe_grant"), ("aws_resource_policy", generic, "external_generic_policy_grant")]:
        rows = selected(kind, data, exposure)
        assert ([a.verdict() for a in rows] == [expected]) if expected else rows == []


def test_unconfigured_athena_destination_declares_no_external_delivery_path():
    workgroup = {"Name": "primary", "WorkGroup": {"collection_status": "collected", "WorkGroup": {"Name": "primary", "State": "ENABLED", "Configuration": {"ResultConfiguration": {}}}}}
    assert selected("athena_workgroup", workgroup, "external_query_result_delivery") == []
    workgroup["WorkGroup"]["WorkGroup"]["Configuration"]["ResultConfiguration"]["OutputLocation"] = 17
    assert selected("athena_workgroup", workgroup, "external_query_result_delivery")[0].verdict() == "UNKNOWN"


def test_native_backup_plan_arn_is_not_reported_as_unattributable():
    arn = f"arn:aws:backup:{REGION}:{ACCOUNT}:backup-plan:p"
    plan = {"BackupPlanId": "p", "BackupPlanArn": arn, "Plan": {"collection_status": "collected", "BackupPlanId": "p", "BackupPlanArn": arn, "BackupPlan": {"Rules": [{"RuleName": "daily"}]}}}
    assert selected("backup_plan", plan, "external_backup_copy_plan") == []
