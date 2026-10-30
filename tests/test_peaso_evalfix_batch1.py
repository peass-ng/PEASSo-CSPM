"""Independent, in-memory regressions for verified evaluator corrections."""
import pytest

from peaso.checks import CHECKS
from peaso.checks.claude_aws_a_common import idx
from peaso.checks import aws_gap_metrics


CHECK = {check.id: check for check in CHECKS}
ACCOUNT = "123456789012"


def status(check_id, item, index=None):
    return CHECK[check_id].evaluate(item, index or {})[0]


def test_cloudtrail_future_delivery_unknown_prior_pass_old_fail():
    item = {"Name": "audit", "Status": {"LatestCloudWatchLogsDeliveryTime": "2026-10-10T13:00:00+00:00"}}
    index = {"context": {"created_at": "2026-10-10T12:00:00+00:00"}}
    assert status("aws.a.cloudtrail.cloudwatch_delivery_24h", item, index) == "UNKNOWN"
    item["Status"]["LatestCloudWatchLogsDeliveryTime"] = "2026-10-10T11:00:00+00:00"
    assert status("aws.a.cloudtrail.cloudwatch_delivery_24h", item, index) == "PASS"
    item["Status"]["LatestCloudWatchLogsDeliveryTime"] = "2026-10-09T11:00:00+00:00"
    assert status("aws.a.cloudtrail.cloudwatch_delivery_24h", item, index) == "FAIL"


@pytest.mark.parametrize("check_id,port", [
    ("aws.claude_a.vpc.nacl_no_world_all_ports", None),
    ("aws.claude_a.vpc.nacl_no_world_tcp_22", 22),
    ("aws.claude_a.vpc.nacl_no_world_tcp_3389", 3389),
])
def test_nacl_rule_order_without_security_groups(check_id, port):
    rule = {"RuleNumber": 100, "Egress": False, "RuleAction": "allow",
            "Protocol": "-1" if port is None else "6", "CidrBlock": "0.0.0.0/0"}
    if port is not None:
        rule["PortRange"] = {"From": port, "To": port}
    item = {"Entries": [rule]}
    index = idx(security_group=[])
    assert status(check_id, item, index) == "FAIL"
    item["Entries"][0]["RuleAction"] = "deny"
    assert status(check_id, item, index) == "PASS"
    item["Entries"].append({**rule, "RuleNumber": 200, "RuleAction": "allow"})
    assert status(check_id, item, index) == "PASS"
    item["Entries"][0]["RuleNumber"] = "invalid"
    assert status(check_id, item, index) == "UNKNOWN"


def test_setup_rotation_is_unknown_and_absent_key_passes():
    item = {"password_enabled": "true", "access_key_1_last_rotated": "2026-01-01T00:00:01+00:00"}
    assert status("aws.a.iam.console_key_created_at_setup", item) == "UNKNOWN"
    item["access_key_1_last_rotated"] = "N/A"
    assert status("aws.a.iam.console_key_created_at_setup", item) == "PASS"


def _credential():
    return {"user": "alice", "arn": "arn:aws:iam::123456789012:user/alice", "user_creation_time": "2024-12-01T00:00:00+00:00",
            "ReportGeneratedTime": "2026-01-01T00:00:00+00:00", "password_enabled": "true", "password_last_used": "no_information",
            "password_last_changed": "2025-01-01T00:00:00+00:00", "access_key_1_active": "true",
            "access_key_1_last_used_date": "N/A", "access_key_1_last_rotated": "2025-01-01T00:00:00+00:00",
            "access_key_2_active": "false", "access_key_2_last_used_date": "N/A"}


@pytest.mark.parametrize("check_id,age_field,used_field", [
    ("aws.claude_a.iam.prowler_console_password_used_45", "password_last_changed", "password_last_used"),
    ("aws.claude_a.iam.access_keys_used_45", "access_key_1_last_rotated", "access_key_1_last_used_date"),
])
def test_never_used_credential_grace_period(check_id, age_field, used_field):
    item = _credential()
    index = {"context": {"created_at": "2026-01-01T00:00:00+00:00"}}
    # Never used since a credential date older than the threshold is stale.
    assert status(check_id, item, index) == "FAIL"
    # A never-used credential newer than the threshold does not cover a full window.
    item[age_field] = "2025-12-31T00:00:00+00:00"
    assert status(check_id, item, index) == "UNKNOWN"
    item[used_field] = "2025-12-31T12:00:00+00:00"
    assert status(check_id, item, index) == "PASS"
    item[used_field] = "no_information" if used_field == "password_last_used" else "N/A"
    item[age_field] = "N/A"
    assert status(check_id, item, index) == "UNKNOWN"
    # The report clock must belong to this snapshot.
    item = _credential()
    item.pop("ReportGeneratedTime")
    assert status(check_id, item, index) == "UNKNOWN"


def _tls_statement(resource):
    return {"Effect": "Deny", "Principal": "*", "Action": "s3:*", "Resource": resource,
            "Condition": {"Bool": {"aws:SecureTransport": "false"}}}


def test_tls_deny_statements_can_cover_resources_separately():
    bucket = "arn:aws:s3:::audit"
    item = {"Name": "audit", "Policy": {"collection_status": "collected", "Policy": {
        "Statement": [_tls_statement(bucket), _tls_statement(bucket + "/*")]}}}
    index = idx()
    check_id = "aws.gap.s3.bucket_policy_denies_insecure_transport"
    assert status(check_id, item, index) == "PASS"
    item["Policy"]["Policy"]["Statement"].pop()
    assert status(check_id, item, index) == "FAIL"
    item["Policy"]["Policy"]["Statement"].append(_tls_statement(bucket + "/any/object-key"))
    assert status(check_id, item, index) == "FAIL"
    item["Policy"] = {"collection_status": "denied"}
    assert status(check_id, item, index) == "UNKNOWN"


@pytest.mark.parametrize("family", ["console_sign_in_without_mfa", "root_account_usage",
    "iam_policy_changes", "console_authentication_failures", "organizations_changes"])
def test_global_alarm_requires_global_events_even_on_multiregion_trail(family, monkeypatch):
    monkeypatch.setattr(aws_gap_metrics, "_records", lambda *args: True)
    monkeypatch.setattr(aws_gap_metrics, "_log_group_covered", lambda *args: True)
    trail = {"CloudWatchLogsLogGroupArn": "arn:aws:logs:us-east-1:123456789012:log-group:a:*",
             "IsMultiRegionTrail": True, "IncludeGlobalServiceEvents": False,
             "Status": {"collection_status": "collected", "IsLogging": True}}
    row = {"SourceRegion": "us-east-1", "id": "metric-alarm-coverage/123456789012/us-east-1"}
    check_id = "aws.gap.cloudwatch.cis_alarm." + family
    index = idx(cloudtrail_account_inventory=[trail], metric_alarm_account_inventory=[row])
    assert status(check_id, {"id": "account-configuration"}, index) == "FAIL"
    trail["IncludeGlobalServiceEvents"] = True
    index = idx(cloudtrail_account_inventory=[trail], metric_alarm_account_inventory=[row])
    assert status(check_id, {"id": "account-configuration"}, index) == "PASS"
    trail.pop("IncludeGlobalServiceEvents")
    index = idx(cloudtrail_account_inventory=[trail], metric_alarm_account_inventory=[row])
    assert status(check_id, {"id": "account-configuration"}, index) == "UNKNOWN"


@pytest.mark.parametrize("check_id,feature", [
    ("aws.guardduty.rds_login_events", "RDS_LOGIN_EVENTS"),
    ("aws.guardduty.lambda_network_logs", "LAMBDA_NETWORK_LOGS"),
    ("aws.guardduty.s3_data_events", "S3_DATA_EVENTS"),
    ("aws.guardduty.runtime_monitoring", "RUNTIME_MONITORING"),
    ("aws.guardduty.eks_audit_logs", "EKS_AUDIT_LOGS"),
])
def test_guardduty_feature_requires_enabled_detector(check_id, feature):
    item = {"Configuration": {"Status": "DISABLED", "Features": [{"Name": feature, "Status": "ENABLED"}]}}
    assert status(check_id, item) == "FAIL"
    item["Configuration"]["Status"] = "ENABLED"
    assert status(check_id, item) == "PASS"
    item["Configuration"].pop("Status")
    assert status(check_id, item) == "UNKNOWN"


def test_ebs_malware_feature_requires_enabled_detector():
    item = {"Configuration": {"Status": "DISABLED", "Features": [
        {"Name": "EBS_MALWARE_PROTECTION", "Status": "ENABLED"}]}}
    check_id = "aws.claude_a.guardduty.ebs_malware_protection_feature"
    assert status(check_id, item) == "FAIL"
    item["Configuration"]["Status"] = "ENABLED"
    assert status(check_id, item) == "PASS"
    item["Configuration"].pop("Status")
    assert status(check_id, item) == "UNKNOWN"


def test_region_scp_must_attach_to_account():
    policy = {"Id": "p1", "Type": "SERVICE_CONTROL_POLICY", "Targets": [{"TargetId": ACCOUNT}],
              "Content": {"Statement": [{"Effect": "Deny", "NotAction": "iam:*", "Resource": "*",
                "Condition": {"StringNotEquals": {"aws:RequestedRegion": ["us-east-1"]}}}]}}
    config = {"Organization": {"collection_status": "collected", "OrganizationId": "o-example"}}
    check_id = "aws.claude_a.organizations.scp_restricts_regions"
    index = idx(aws_account_configuration=[config], organization_policy=[policy])
    assert status(check_id, {}, index) == "PASS"
    policy["Targets"] = [{"TargetId": "r-example"}]
    index = idx(aws_account_configuration=[config], organization_policy=[policy])
    assert status(check_id, {}, index) == "UNKNOWN"
    policy["Targets"] = []
    index = idx(aws_account_configuration=[config], organization_policy=[policy])
    assert status(check_id, {}, index) == "FAIL"


def test_region_scp_extra_condition_and_narrow_resource_are_unknown():
    statement = {"Effect": "Deny", "NotAction": "iam:*", "Resource": "*",
                 "Condition": {"StringNotEquals": {"aws:RequestedRegion": "us-east-1"}}}
    policy = {"Id": "p1", "Type": "SERVICE_CONTROL_POLICY", "Targets": [{"TargetId": ACCOUNT}],
              "Content": {"Statement": [statement]}}
    config = {"Organization": {"collection_status": "collected", "OrganizationId": "o-example"}}
    check_id = "aws.claude_a.organizations.scp_restricts_regions"
    index = idx(aws_account_configuration=[config], organization_policy=[policy])
    assert status(check_id, {}, index) == "PASS"
    statement["Condition"]["StringEquals"] = {"aws:PrincipalTag/Env": "prod"}
    assert status(check_id, {}, index) == "UNKNOWN"
    statement["Condition"].pop("StringEquals")
    statement["Condition"]["StringNotEquals"]["aws:PrincipalTag/Env"] = "prod"
    assert status(check_id, {}, index) == "UNKNOWN"
    statement["Condition"]["StringNotEquals"].pop("aws:PrincipalTag/Env")
    statement["Resource"] = "arn:aws:s3:::one-bucket"
    assert status(check_id, {}, index) == "UNKNOWN"


@pytest.mark.parametrize("exclusions,expected", [
    (["cloudfront:*", "iam:*", "organizations:*", "route53:*", "support:*"], "PASS"),
    (["iam:*", "budgets:*", "waf:*"], "PASS"),
    ("ec2:*", "UNKNOWN"),
    (["iam:*", "ec2:*"], "UNKNOWN"),
    ("*:*", "UNKNOWN"),
    ("*", "UNKNOWN"),
    ("iam:", "UNKNOWN"),
    ([], "UNKNOWN"),
])
def test_region_scp_notaction_only_documented_global_services(exclusions, expected):
    statement = {"Effect": "Deny", "NotAction": exclusions, "Resource": "*",
                 "Condition": {"StringNotEquals": {"aws:RequestedRegion": ["eu-west-1"]}}}
    policy = {"Id": "p1", "Type": "SERVICE_CONTROL_POLICY", "Targets": [{"TargetId": ACCOUNT}],
              "Content": {"Statement": [statement]}}
    config = {"Organization": {"collection_status": "collected", "OrganizationId": "o-example"}}
    index = idx(aws_account_configuration=[config], organization_policy=[policy])
    assert status("aws.claude_a.organizations.scp_restricts_regions", {}, index) == expected


def test_world_security_group_port_range_ipv4_only():
    rule = {"IpProtocol": "tcp", "FromPort": 80, "ToPort": 100,
            "IpRanges": [{"CidrIp": "0.0.0.0/0"}], "Ipv6Ranges": []}
    item = {"GroupId": "sg-1", "IpPermissions": [rule]}
    check_id = "aws.claude_a.vpc.sg_world_v4_only_80_443"
    assert status(check_id, item) == "FAIL"
    rule["ToPort"] = 80
    assert status(check_id, item) == "PASS"
    rule["IpRanges"] = []
    rule["Ipv6Ranges"] = [{"CidrIpv6": "::/0"}]
    rule["ToPort"] = 100
    assert status(check_id, item) == "PASS"
    rule["IpRanges"] = [{"CidrIp": "0.0.0.0/0"}]
    rule["ToPort"] = "invalid"
    assert status(check_id, item) == "UNKNOWN"


def test_s3_event_notification_empty_arrays_fail():
    item = {"Notifications": {"TopicConfigurations": [], "QueueConfigurations": [],
                              "LambdaFunctionConfigurations": []}}
    check_id = "aws.claude_a.s3.event_notifications"
    assert status(check_id, item) == "FAIL"
    item["Notifications"]["TopicConfigurations"] = [{"TopicArn": "arn:aws:sns:us-east-1:123456789012:t"}]
    assert status(check_id, item) == "PASS"
    item["Notifications"] = {"EventBridgeConfiguration": {}}
    assert status(check_id, item) == "PASS"


def test_s3_versioning_lifecycle_only_applies_when_versioned():
    item = {"Versioning": {"Status": "Suspended"}, "Lifecycle": {"Rules": []}}
    check_id = "aws.claude_a.s3.versioning_and_lifecycle"
    assert status(check_id, item) == "NOT_APPLICABLE"
    item["Versioning"]["Status"] = "Enabled"
    assert status(check_id, item) == "FAIL"
    item["Lifecycle"]["Rules"] = [{"ID": "r1", "Status": "Enabled"}]
    assert status(check_id, item) == "PASS"


def test_ecs_empty_insights_settings_fail():
    arn = "arn:aws:ecs:us-east-1:123456789012:cluster/c"
    item = {"clusterArn": arn, "Configuration": {"clusters": [{"clusterArn": arn, "settings": []}]}}
    check_id = "aws.c2b.ecs.container_insights_setting"
    assert status(check_id, item) == "FAIL"
    item["Configuration"]["clusters"][0]["settings"] = [{"name": "containerInsights", "value": "enabled"}]
    assert status(check_id, item) == "PASS"
    item["Configuration"]["clusters"][0].pop("settings")
    assert status(check_id, item) == "UNKNOWN"
