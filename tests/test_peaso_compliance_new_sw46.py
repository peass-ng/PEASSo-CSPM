"""Isolated signed wave-46 predicates and authority boundaries."""
from __future__ import annotations

import copy

import pytest
from peaso.checks import CHECKS, evaluate_check
from peaso.checks import compliance_new_sw46 as sw46

ACCOUNT = "123456789012"
REGION = "us-east-1"
SCOPE = f"{ACCOUNT}/{REGION}"
GLOBAL = f"{ACCOUNT}/global"
NOW = "2026-10-12T00:00:00Z"


@pytest.fixture(scope="module", autouse=True)
def clean_draft_registry():
    yield
    CHECKS[:] = [check for check in CHECKS if check.id not in sw46.SIGNED]


def index(kind, row, *, scope=SCOPE, extra=None, policy=None, status="collected"):
    collections = {kind: [{"type": kind, "scope": scope, "status": status, "items": [row]}]}
    resources = {kind: [{"type": kind, "scope": scope, "data": row}]}
    for other_kind, other_rows in (extra or {}).items():
        collections[other_kind] = [{"type": other_kind, "scope": scope, "status": "collected", "items": other_rows}]
        resources[other_kind] = [{"type": other_kind, "scope": scope, "data": other} for other in other_rows]
    return {"context": {"provider": "aws", "scope": scope, "created_at": NOW},
            "collections": collections, **resources,
            "approved_policy": {"scope": scope, "checks": policy or {}}}


def grade(cid, row, facts, *, scoped=False):
    subject = {"scope": facts["context"]["scope"]} if scoped else row
    return evaluate_check(cid, subject, facts)[0]


def ec2_row():
    return {"InstanceId": "i-123", "InstanceType": "m5.large",
            "Tags": [{"Key": "Workload", "Value": "AI"}], "State": {"Name": "running"},
            "TimeOffset": {"collection_status": "collected", "InstanceId": "i-123", "Namespace": "CWAgent",
                           "MetricName": "time_offset", "Timestamp": NOW, "ValueMilliseconds": 25},
            "PublicReachability": {"collection_status": "collected", "InstanceId": "i-123",
                                   "route_inventory_complete": True, "ingress_inventory_complete": True,
                                   "target_inventory_complete": True, "listener_inventory_complete": True,
                                   "Paths": []}}


def alarm(name="StatusCheckFailed"):
    return {"AlarmArn": f"arn:aws:cloudwatch:{REGION}:{ACCOUNT}:alarm:test", "Namespace": "AWS/EC2",
            "MetricName": name, "Dimensions": [{"Name": "InstanceId", "Value": "i-123"}],
            "Period": 60, "EvaluationPeriods": 1, "Threshold": 1,
            "ComparisonOperator": "GreaterThanOrEqualToThreshold", "ActionsEnabled": True,
            "AlarmActions": [f"arn:aws:sns:{REGION}:{ACCOUNT}:alerts"], "TreatMissingData": "breaching"}


def detector():
    return {"DetectorId": "det-1", "Configuration": {"Status": "ENABLED"},
            "ThreatIntelSets": {"collection_status": "collected", "DetectorId": "det-1", "items": [
                {"Id": "feed-1", "Status": "ACTIVE", "Location": "s3://approved/doh.txt", "Format": "TXT"}]},
            "Filters": {"collection_status": "collected", "DetectorId": "det-1", "items": [
                {"Name": "noise", "Action": "ARCHIVE", "FindingCriteria": {"Criterion": {"type": "low"}}}]},
            "Administrator": {"collection_status": "collected", "DetectorId": "det-1",
                              "AdminAccounts": [{"AdminAccountId": "111111111111"}]},
            "Invitations": {"collection_status": "collected", "DetectorId": "det-1", "items": []}}


def topic():
    return {"TopicArn": f"arn:aws:sns:{REGION}:{ACCOUNT}:topic",
            "Attributes": {"collection_status": "collected", "Attributes": {
                "TopicArn": f"arn:aws:sns:{REGION}:{ACCOUNT}:topic",
                "Policy": {"Version": "2012-10-17", "Statement": [{"Effect": "Allow",
                    "Principal": {"AWS": f"arn:aws:iam::{ACCOUNT}:root"}, "Action": "sns:Publish",
                    "Resource": f"arn:aws:sns:{REGION}:{ACCOUNT}:topic"}]},
                "SQSFailureFeedbackRoleArn": "arn:aws:iam::123456789012:role/failure",
                "SQSSuccessFeedbackRoleArn": "arn:aws:iam::123456789012:role/success",
                "SQSSuccessFeedbackSampleRate": "10"}}}


def role():
    return {"Arn": f"arn:aws:iam::{ACCOUNT}:role/partner",
            "AssumeRolePolicyDocument": {"Version": "2012-10-17", "Statement": [{
                "Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::111111111111:root"},
                "Action": "sts:AssumeRole", "Condition": {"StringEquals": {"sts:ExternalId": "customer-123"},
                    "DateLessThan": {"aws:CurrentTime": "2026-10-13T00:00:00Z"}}}]}}


@pytest.mark.parametrize("cid,mutate,expected", [
    ("aws_ec2_ai_nitro_instance_type", lambda row: row.update(InstanceType="m4.large"), "FAIL"),
    ("aws_ec2_instance_time_offset_monitored", lambda row: row["TimeOffset"].update(ValueMilliseconds=1001), "FAIL"),
    ("aws_nist_ec2_instance_not_publicly_accessible", lambda row: row["PublicReachability"]["Paths"].append(
        {"Source": "public_ipv4", "AddressOrTargetArn": "8.8.8.8", "RouteToInternet": True,
         "IngressAllowed": True, "ListeningPortVerified": True}), "FAIL"),
])
def test_ec2_pass_fail_and_unknown(cid, mutate, expected):
    row = ec2_row()
    extra = {"ec2_instance_type": [{"InstanceType": "m5.large", "Hypervisor": "nitro"}]} if "nitro" in cid else None
    policy = {cid: {"workload_tag_key": "Workload", "ai_workload_values": ["AI"]}} if "nitro" in cid else None
    facts = index("instance", row, extra=extra, policy=policy)
    assert grade(cid, row, facts) == "PASS"
    bad = copy.deepcopy(row)
    mutate(bad)
    bad_extra = {"ec2_instance_type": [{"InstanceType": "m4.large", "Hypervisor": "xen"}]} if "nitro" in cid else extra
    assert grade(cid, bad, index("instance", bad, extra=bad_extra, policy=policy)) == expected
    missing = copy.deepcopy(row)
    missing.pop({"aws_ec2_ai_nitro_instance_type": "Tags", "aws_ec2_instance_time_offset_monitored": "TimeOffset",
                 "aws_nist_ec2_instance_not_publicly_accessible": "PublicReachability"}[cid])
    assert grade(cid, missing, index("instance", missing, extra=extra, policy=policy)) == "UNKNOWN"
    assert grade(cid, row, index("instance", row, extra=extra, policy=policy, status="partial")) == "UNKNOWN"
    foreign = index("instance", row, extra=extra, policy=policy)
    foreign["context"]["scope"] = "123456789012/eu-west-1"
    assert grade(cid, row, foreign) == "UNKNOWN"


def test_ec2_not_applicable_and_stale_telemetry():
    row = ec2_row()
    row["Tags"] = []
    cid = "aws_ec2_ai_nitro_instance_type"
    facts = index("instance", row, extra={"ec2_instance_type": []},
                  policy={cid: {"workload_tag_key": "Workload", "ai_workload_values": ["AI"]}})
    assert grade(cid, row, facts) == "NOT_APPLICABLE"
    row = ec2_row()
    row["State"]["Name"] = "stopped"
    cid = "aws_ec2_instance_time_offset_monitored"
    assert grade(cid, row, index("instance", row)) == "NOT_APPLICABLE"
    row["State"]["Name"] = "running"
    row["TimeOffset"]["Timestamp"] = "2026-10-10T00:00:00Z"
    assert grade(cid, row, index("instance", row)) == "FAIL"
    row["TimeOffset"]["ValueMilliseconds"] = "bad"
    assert grade(cid, row, index("instance", row)) == "UNKNOWN"


ALARM_SETTINGS = "aws.pci.cloudwatch.metric_alarm_settings"
RESOURCE_ALARM = "aws.pci.cloudwatch.resource_metric_alarm"
INACTIVITY = "aws_cloudwatch_alarm_missing_data_realert"
SHIELD = "aws_shield_ddos_detected_alarm"
ACTION = f"arn:aws:sns:{REGION}:{ACCOUNT}:alerts"


def alarm_policy():
    return {
        ALARM_SETTINGS: {"Namespace": "AWS/EC2", "MetricName": "StatusCheckFailed",
                         "Dimensions": [{"Name": "InstanceId", "Value": "i-123"}], "Period": 60,
                         "Threshold": 1, "ComparisonOperator": "GreaterThanOrEqualToThreshold",
                         "EvaluationPeriods": 1, "AlarmActions": [ACTION]},
        RESOURCE_ALARM: {"resource_kind": "instance", "dimension_name": "InstanceId",
                         "Namespace": "AWS/EC2", "MetricName": "StatusCheckFailed",
                         "resource_dimension_values": ["i-123"]},
        INACTIVITY: {"metrics": [{"Namespace": "AWS/EC2", "MetricName": "StatusCheckFailed",
                                  "Dimensions": [{"Name": "InstanceId", "Value": "i-123"}],
                                  "approved_interval_seconds": 120}]},
    }


@pytest.mark.parametrize("cid,bad_change", [
    (ALARM_SETTINGS, {"Threshold": 2}),
    (RESOURCE_ALARM, {"ActionsEnabled": False}),
    (INACTIVITY, {"TreatMissingData": "notBreaching"}),
])
def test_alarm_scope_pass_fail_unknown(cid, bad_change):
    row = alarm()
    policy = alarm_policy()
    facts = index("cloudwatch_alarm", row, policy=policy)
    assert grade(cid, row, facts, scoped=True) == "PASS"
    bad = {**row, **bad_change}
    assert grade(cid, bad, index("cloudwatch_alarm", bad, policy=policy), scoped=True) == "FAIL"
    missing = copy.deepcopy(facts)
    del missing["approved_policy"]
    assert grade(cid, row, missing, scoped=True) == "UNKNOWN"
    malformed = copy.deepcopy(row)
    malformed["Dimensions"] = "invalid"
    assert grade(cid, malformed, index("cloudwatch_alarm", malformed, policy=policy), scoped=True) == "UNKNOWN"
    assert grade(cid, row, index("cloudwatch_alarm", row, policy=policy, status="partial"), scoped=True) == "UNKNOWN"


def test_shield_protection_alarm_and_empty_scope():
    row = alarm("DDoSDetected")
    row.update(Namespace="AWS/DDoSProtection", Dimensions=[{"Name": "ResourceArn", "Value": "arn:aws:ec2:us-east-1:123456789012:eip-allocation/eipalloc-1"}])
    resource = row["Dimensions"][0]["Value"]
    projection = [{"ResourceArn": resource, "SourceRegion": REGION}]
    facts = index("cloudwatch_alarm", row, extra={"shield_protection_region": projection})
    assert grade(SHIELD, row, facts, scoped=True) == "PASS"
    bad = {**row, "Threshold": 2}
    assert grade(SHIELD, bad, index("cloudwatch_alarm", bad, extra={"shield_protection_region": projection}), scoped=True) == "FAIL"
    assert grade(SHIELD, row, index("cloudwatch_alarm", row), scoped=True) == "UNKNOWN"
    assert grade(SHIELD, row, index("cloudwatch_alarm", row, extra={"shield_protection_region": []}), scoped=True) == "NOT_APPLICABLE"
    assert grade(SHIELD, row, index("cloudwatch_alarm", row, extra={"shield_protection_region": projection}, status="partial"), scoped=True) == "UNKNOWN"
    malformed = [{"ResourceArn": resource, "SourceRegion": "elsewhere"}]
    assert grade(SHIELD, row, index("cloudwatch_alarm", row, extra={"shield_protection_region": malformed}), scoped=True) == "UNKNOWN"


GD_DOH = "aws_guardduty_doh_threat_list"
GD_FILTER = "aws_guardduty_suppression_filters"
GD_FEED = "aws_guardduty_threat_feed"
GD_ADMIN = "aws_guardduty_trusted_administrator"
GD_POLICY = {GD_DOH: {"approved_doh_locations": ["s3://approved/doh.txt"]},
             GD_FILTER: {"approved_low_value_criteria": [{"Criterion": {"type": "low"}}]},
             GD_FEED: {"approved_threat_set_ids": ["feed-1"]},
             GD_ADMIN: {"trusted_account_ids": ["111111111111"]}}


@pytest.mark.parametrize("cid,change", [
    (GD_DOH, lambda row: row["ThreatIntelSets"]["items"].clear()),
    (GD_FILTER, lambda row: row["Filters"]["items"].clear()),
    (GD_FEED, lambda row: row["ThreatIntelSets"]["items"][0].update(Status="INACTIVE")),
    (GD_ADMIN, lambda row: row["Administrator"]["AdminAccounts"][0].update(AdminAccountId="222222222222")),
])
def test_guardduty_pass_fail_and_missing_detail(cid, change):
    row = detector()
    assert grade(cid, row, index("guardduty_detector", row, policy=GD_POLICY)) == "PASS"
    bad = copy.deepcopy(row)
    change(bad)
    assert grade(cid, bad, index("guardduty_detector", bad, policy=GD_POLICY)) == "FAIL"
    missing = copy.deepcopy(row)
    missing.pop({GD_DOH: "ThreatIntelSets", GD_FILTER: "Filters", GD_FEED: "ThreatIntelSets",
                 GD_ADMIN: "Administrator"}[cid])
    assert grade(cid, missing, index("guardduty_detector", missing, policy=GD_POLICY)) == "UNKNOWN"
    malformed = copy.deepcopy(row)
    malformed["DetectorId"] = None
    assert grade(cid, malformed, index("guardduty_detector", malformed, policy=GD_POLICY)) == "UNKNOWN"
    assert grade(cid, row, index("guardduty_detector", row, policy=GD_POLICY, status="partial")) == "UNKNOWN"


SNS_POLICY = "aws_g6_sns_no_named_cross_account_principals"
SNS_DELIVERY = "aws_nist_sns_topic_notification_delivery_status_enabled"
SUB = {"id": f"arn:aws:sns:{REGION}:{ACCOUNT}:topic:sub", "TopicArn": f"arn:aws:sns:{REGION}:{ACCOUNT}:topic", "Protocol": "sqs"}


def test_sns_cross_account_policy_boundaries():
    row = topic()
    policy = {SNS_POLICY: {"approved_account_ids": []}}
    assert grade(SNS_POLICY, row, index("sns_topic", row, policy=policy)) == "PASS"
    bad = copy.deepcopy(row)
    bad["Attributes"]["Attributes"]["Policy"]["Statement"][0]["Principal"]["AWS"] = "arn:aws:iam::222222222222:root"
    assert grade(SNS_POLICY, bad, index("sns_topic", bad, policy=policy)) == "FAIL"
    assert grade(SNS_POLICY, bad, index("sns_topic", bad, policy={SNS_POLICY: {"approved_account_ids": ["222222222222"]}})) == "PASS"
    bad["Attributes"]["Attributes"]["Policy"]["Statement"][0]["Condition"] = {"StringEquals": {"aws:SourceAccount": ACCOUNT}}
    assert grade(SNS_POLICY, bad, index("sns_topic", bad, policy=policy)) == "UNKNOWN"
    missing = copy.deepcopy(row)
    del missing["Attributes"]
    assert grade(SNS_POLICY, missing, index("sns_topic", missing, policy=policy)) == "UNKNOWN"
    assert grade(SNS_POLICY, row, index("sns_topic", row, policy=policy, status="partial")) == "UNKNOWN"


def test_sns_delivery_protocol_scope_and_feedback():
    row = topic()
    facts = index("sns_topic", row, extra={"sns_subscription": [SUB]})
    assert grade(SNS_DELIVERY, row, facts) == "PASS"
    bad = copy.deepcopy(row)
    del bad["Attributes"]["Attributes"]["SQSSuccessFeedbackRoleArn"]
    assert grade(SNS_DELIVERY, bad, index("sns_topic", bad, extra={"sns_subscription": [SUB]})) == "FAIL"
    assert grade(SNS_DELIVERY, row, index("sns_topic", row)) == "UNKNOWN"
    assert grade(SNS_DELIVERY, row, index("sns_topic", row, extra={"sns_subscription": [SUB]}, status="partial")) == "UNKNOWN"
    assert grade(SNS_DELIVERY, row, index("sns_topic", row, extra={"sns_subscription": []})) == "NOT_APPLICABLE"
    malformed = copy.deepcopy(row)
    malformed["Attributes"]["Attributes"]["SQSSuccessFeedbackSampleRate"] = "bad"
    assert grade(SNS_DELIVERY, malformed, index("sns_topic", malformed, extra={"sns_subscription": [SUB]})) == "UNKNOWN"
    malformed_role = copy.deepcopy(row)
    malformed_role["Attributes"]["Attributes"]["SQSFailureFeedbackRoleArn"] = "not-an-arn"
    assert grade(SNS_DELIVERY, malformed_role, index("sns_topic", malformed_role, extra={"sns_subscription": [SUB]})) == "UNKNOWN"
    masked = copy.deepcopy(row)
    masked["Attributes"]["Attributes"]["_coverage"] = {"SQSFailureFeedbackRoleArn": {"status": "denied"}}
    assert grade(SNS_DELIVERY, masked, index("sns_topic", masked, extra={"sns_subscription": [SUB]})) == "UNKNOWN"


TEMP = "aws.pci.iam.third_party_temporary_access"
EXTERNAL = "aws_partner_role_external_id_present"
ROLE_POLICY = {TEMP: {"third_party_principal_arns": ["arn:aws:iam::111111111111:root"],
                      "approved_window_end": "2026-10-13T00:00:00Z"},
               EXTERNAL: {"customer_role_arns": [f"arn:aws:iam::{ACCOUNT}:role/partner"],
                          "provider_principal_arns": ["arn:aws:iam::111111111111:root"]}}


@pytest.mark.parametrize("cid,remove_condition", [
    (TEMP, "DateLessThan"), (EXTERNAL, "StringEquals")])
def test_iam_trust_pass_fail_unknown(cid, remove_condition):
    row = role()
    facts = index("iam_role", row, scope=GLOBAL, policy=ROLE_POLICY)
    assert grade(cid, row, facts) == "PASS"
    bad = copy.deepcopy(row)
    del bad["AssumeRolePolicyDocument"]["Statement"][0]["Condition"][remove_condition]
    assert grade(cid, bad, index("iam_role", bad, scope=GLOBAL, policy=ROLE_POLICY)) == "FAIL"
    missing = copy.deepcopy(row)
    del missing["AssumeRolePolicyDocument"]
    assert grade(cid, missing, index("iam_role", missing, scope=GLOBAL, policy=ROLE_POLICY)) == "UNKNOWN"
    malformed = copy.deepcopy(row)
    malformed["AssumeRolePolicyDocument"] = "not-json"
    assert grade(cid, malformed, index("iam_role", malformed, scope=GLOBAL, policy=ROLE_POLICY)) == "UNKNOWN"
    assert grade(cid, row, index("iam_role", row, scope=GLOBAL, policy=ROLE_POLICY, status="partial")) == "UNKNOWN"


def test_iam_not_applicable_and_expired_absent_partner():
    row = role()
    row["AssumeRolePolicyDocument"]["Statement"] = []
    assert grade(EXTERNAL, row, index("iam_role", row, scope=GLOBAL, policy=ROLE_POLICY)) == "NOT_APPLICABLE"
    assert grade(TEMP, row, index("iam_role", row, scope=GLOBAL, policy=ROLE_POLICY)) == "NOT_APPLICABLE"
    expired = copy.deepcopy(ROLE_POLICY)
    expired[TEMP]["approved_window_end"] = "2026-10-11T00:00:00Z"
    assert grade(TEMP, row, index("iam_role", row, scope=GLOBAL, policy=expired)) == "PASS"


def test_snapshot_metadata_policy_path_and_foreign_policy_scope():
    row = alarm()
    facts = index("cloudwatch_alarm", row, policy=alarm_policy())
    facts["context"]["metadata"] = {"approved_policy": facts.pop("approved_policy")}
    assert grade(ALARM_SETTINGS, row, facts, scoped=True) == "PASS"
    facts["context"]["metadata"]["approved_policy"]["scope"] = f"{ACCOUNT}/eu-west-1"
    assert grade(ALARM_SETTINGS, row, facts, scoped=True) == "UNKNOWN"
