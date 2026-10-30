"""Isolated tests for the 15 signed sw42 AWS checks."""
from __future__ import annotations

import copy

import pytest

from peaso.checks import CHECKS
from peaso.checks import compliance_new_sw42 as sw42


SCOPE = "123456789012/us-east-1"
ACCOUNT = "123456789012"
REGION = "us-east-1"
LB_ARN = f"arn:aws:elasticloadbalancing:{REGION}:{ACCOUNT}:loadbalancer/app/demo/abc"
TG_ARN = f"arn:aws:elasticloadbalancing:{REGION}:{ACCOUNT}:targetgroup/demo/abc"
PLAN_ARN = f"arn:aws:backup:{REGION}:{ACCOUNT}:plan:abc"
BUCKET_ARN = f"arn:aws:lightsail:{REGION}:{ACCOUNT}:Bucket/demo"
HUB_ARN = f"arn:aws:securityhub:{REGION}:{ACCOUNT}:hub/default"


def bundle(resources, policy=None):
    collections = {}
    wrappers = {}
    for kind, rows in resources.items():
        status = "collected" if rows else "empty"
        collections[kind] = [{"type": kind, "scope": SCOPE, "status": status,
                              "items": copy.deepcopy(rows)}]
        wrappers[kind] = [{"type": kind, "scope": SCOPE, "data": copy.deepcopy(row)} for row in rows]
    index = {"context": {"provider": "aws", "scope": SCOPE,
                         "created_at": "2026-10-12T00:00:00+00:00",
                         "metadata": {"compliance_policy": {"status": "collected", "scope": SCOPE,
                                                          **(policy or {})}}},
             "collections": collections, **wrappers}
    return index


def evaluate(cid, item, index):
    return next(check for check in CHECKS if check.id == cid).evaluate(item, index)[0]


def plan(schedule="rate(1 day)", retention=35, continuous=False):
    rule = {"ScheduleExpression": schedule, "Lifecycle": {"DeleteAfterDays": retention},
            "EnableContinuousBackup": continuous}
    return {"BackupPlanArn": PLAN_ARN, "Plan": {"collection_status": "collected",
            "BackupPlan": {"Rules": [rule]}}}


def lb(lb_type="application"):
    return {"LoadBalancerArn": LB_ARN, "Type": lb_type,
            "AvailabilityZones": [{"ZoneName": REGION + "a"}, {"ZoneName": REGION + "b"}],
            "Listeners": {"collection_status": "empty", "items": []}}


def tg(duration="1800", zones=("a", "b")):
    return {"TargetGroupArn": TG_ARN, "LoadBalancerArns": [LB_ARN], "TargetType": "instance",
            "Attributes": {"collection_status": "collected", "Attributes": [
                {"Key": "stickiness.enabled", "Value": "true"},
                {"Key": "stickiness.type", "Value": "lb_cookie"},
                {"Key": "stickiness.lb_cookie.duration_seconds", "Value": duration}]},
            "TargetHealth": {"collection_status": "collected", "TargetHealthDescriptions": [
                {"Target": {"Id": "i-" + zone, "AvailabilityZone": REGION + zone},
                 "TargetHealth": {"State": "healthy"}} for zone in zones]}}


def activity(cid, fail=False):
    names, source, field = sw42._ACTIVITY[cid]
    rows = []
    if fail:
        rows = [{"EventId": "evt-1", "EventName": sorted(names)[0],
                 "EventTime": "2026-10-11T12:00:00+00:00",
                 "CloudTrailEvent": {"recipientAccountId": ACCOUNT, "awsRegion": REGION,
                     "eventSource": source, "userIdentity": {"arn": f"arn:aws:iam::{ACCOUNT}:user/unapproved"}}}]
    index = bundle({"aws_cloudtrail_activity": rows}, {field: [f"arn:aws:iam::{ACCOUNT}:user/approved"]})
    index["collections"]["aws_cloudtrail_activity"][0]["EventCoverage"] = {
        "collection_status": "collected", "projection": "full_event_identity_and_error",
        "EventNames": sorted(names), "WindowStart": "2026-10-11T00:00:00+00:00",
        "WindowEnd": "2026-10-12T00:00:00+00:00"}
    return {"scope": SCOPE}, index


def case(cid, fail=False):
    if cid == "aws_vpc_uses_amazonprovided_dns":
        row = {"VpcId": "vpc-abcd", "DhcpOptionsId": "dopt-abcd"}
        dns = ["AmazonProvidedDNS", "8.8.8.8"] if fail else ["AmazonProvidedDNS"]
        index = bundle({"vpc": [row], "dhcp_options": [{"DhcpOptionsId": "dopt-abcd",
            "DhcpConfigurations": [{"Key": "domain-name-servers", "Values": [{"Value": v} for v in dns]}]}]})
    elif cid == "aws_cis_lightsail_bucket_iam_policy":
        row = {"arn": BUCKET_ARN, "name": "demo"}
        attachments = [] if fail else [{"PrincipalArn": f"arn:aws:iam::{ACCOUNT}:role/approved",
            "PolicyDocument": {"Statement": [{"Effect": "Allow", "Action": "lightsail:GetBucket",
                                               "Resource": BUCKET_ARN}]}}]
        index = bundle({"lightsail_bucket": [row], "lightsail_iam_policy_attachment": attachments},
                       {"iam_required_lightsail_bucket_arns": [BUCKET_ARN],
                        "approved_lightsail_principals": [f"arn:aws:iam::{ACCOUNT}:role/approved"],
                        "approved_lightsail_actions": ["lightsail:GetBucket"]})
    elif cid == "aws_cis_lightsail_bucket_private":
        row = {"arn": BUCKET_ARN, "accessRules": {"getObject": "public" if fail else "private",
                                                   "allowPublicOverrides": False}}
        index = bundle({"lightsail_bucket": [row]})
    elif cid in ("aws.pci.backup.plan_frequency_retention", "aws_backup_plan_rule_required_frequency",
                 "aws_nist_backup_plan_min_retention_35_days"):
        row = plan(schedule="rate(2 days)" if fail else "rate(1 day)", retention=10 if fail else 35)
        index = bundle({"backup_plan": [row]}, {"required_frequency_hours": 24,
                                               "required_retention_days": 35})
    elif cid == "aws_cis_elbv2_only_tls_listeners":
        row = lb()
        row["Listeners"] = {"collection_status": "collected", "items": [
            {"ListenerArn": LB_ARN + "/listener/one", "Protocol": "HTTP" if fail else "HTTPS",
             "DefaultActions": [{"Type": "forward"}]}]}
        index = bundle({"load_balancer": [row]}, {"approved_https_redirect_listener_arns": []})
    elif cid == "aws_elbv2_stickiness_duration_30_minutes":
        row = lb()
        index = bundle({"load_balancer": [row], "target_group": [tg("1801" if fail else "1800")]})
    elif cid == "aws_nist_elb_application_gateway_network_lb_multiple_az_configured":
        row = lb()
        index = bundle({"load_balancer": [row], "target_group": [tg(zones=("a",) if fail else ("a", "b"))]})
    elif cid in sw42._ACTIVITY:
        return activity(cid, fail)
    elif cid == "aws_securityhub_aggregated_findings_present":
        row = {"HubArn": HUB_ARN,
               "FindingAggregators": {"collection_status": "collected", "items": [
                   {"FindingAggregatorArn": f"arn:aws:securityhub:{REGION}:{ACCOUNT}:finding-aggregator/one",
                    "RegionLinkingMode": "SPECIFIED_REGIONS", "Regions": ["eu-west-1"]}]},
               "AggregatedFindings": {"collection_status": "empty" if fail else "collected",
                   "items": [] if fail else [{"Region": "eu-west-1", "AwsAccountId": ACCOUNT}]}}
        index = bundle({"securityhub_hub": [row]}, {"required_aggregated_regions": ["eu-west-1"]})
    elif cid == "aws_securityhub_standards_control_baseline":
        standard = "arn:aws:securityhub:us-east-1::standards/aws-foundational-security-best-practices/v/1.0.0"
        subscription = f"arn:aws:securityhub:{REGION}:{ACCOUNT}:subscription/aws-foundational-security-best-practices/v/1.0.0"
        row = {"HubArn": HUB_ARN,
               "EnabledStandards": {"collection_status": "collected", "items": [
                   {"StandardsArn": standard, "StandardsSubscriptionArn": subscription,
                    "StandardsStatus": "READY"}]},
               "StandardsControls": {"collection_status": "collected", "items": [
                   {"StandardsSubscriptionArn": subscription,
                    "Controls": {"collection_status": "collected", "items": [
                        {"ControlId": "S3.1", "ControlStatus": "DISABLED" if fail else "ENABLED"}]}}]}}
        index = bundle({"securityhub_hub": [row]}, {"securityhub_standards_baseline": [
            {"StandardsArn": standard, "Controls": {"S3.1": "ENABLED"}}]})
    elif cid == "aws_backup_recent_restore_test":
        testing_arn = f"arn:aws:backup:{REGION}:{ACCOUNT}:restore-testing-plan:abc"
        resources = {"backup_restore_testing_plan": [{"RestoreTestingPlanName": "daily",
                                                       "RestoreTestingPlanArn": testing_arn}],
                     "backup_restore_testing_selection": [{"RestoreTestingPlanName": "daily",
                                                             "ProtectedResourceType": "EBS"}],
                     "backup_restore_job": [{"RestoreJobId": "job-1", "AccountId": ACCOUNT,
                         "CreatedBy": {"RestoreTestingPlanArn": testing_arn}, "ResourceType": "EBS",
                         "Status": "COMPLETED", "CompletionDate": "2025-01-01T00:00:00+00:00" if fail else "2026-10-01T00:00:00+00:00"}]}
        return {"scope": SCOPE}, bundle(resources)
    else:
        raise AssertionError(cid)
    return row, index


@pytest.mark.parametrize("cid", list(sw42.SPECS))
def test_pass_fail_unknown_for_every_signed_check(cid):
    good, index = case(cid)
    assert evaluate(cid, good, index) == "PASS"
    bad, bad_index = case(cid, fail=True)
    assert evaluate(cid, bad, bad_index) == "FAIL"
    incomplete = copy.deepcopy(index)
    first = next(iter(incomplete["collections"]))
    incomplete["collections"][first][0]["status"] = "partial"
    assert evaluate(cid, good, incomplete) == "UNKNOWN"
    missing = copy.deepcopy(index)
    missing["collections"].pop(first)
    assert evaluate(cid, good, missing) == "UNKNOWN"
    malformed = copy.deepcopy(index)
    malformed["collections"][first][0]["items"] = {"unexpected": "object, not list"}
    assert evaluate(cid, good, malformed) == "UNKNOWN"
    wrong_provider = copy.deepcopy(index)
    wrong_provider["context"]["provider"] = "azure"
    assert evaluate(cid, good, wrong_provider) == "UNKNOWN"
    foreign = copy.deepcopy(index)
    foreign["collections"][first][0]["scope"] = "123456789012/eu-west-1"
    assert evaluate(cid, good, foreign) == "UNKNOWN"


def test_not_applicable_boundaries():
    for cid in ("aws_cis_lightsail_bucket_iam_policy", "aws_cis_elbv2_only_tls_listeners",
                "aws_backup_recent_restore_test"):
        row, index = case(cid)
        if cid == "aws_cis_lightsail_bucket_iam_policy":
            index["context"]["metadata"]["compliance_policy"]["iam_required_lightsail_bucket_arns"] = []
        elif cid == "aws_cis_elbv2_only_tls_listeners":
            row["Type"] = "gateway"
            row["LoadBalancerArn"] = LB_ARN.replace("loadbalancer/app/", "loadbalancer/gwy/")
            index["collections"]["load_balancer"][0]["items"][0]["Type"] = "gateway"
            index["collections"]["load_balancer"][0]["items"][0]["LoadBalancerArn"] = row["LoadBalancerArn"]
            index["load_balancer"][0]["data"]["Type"] = "gateway"
            index["load_balancer"][0]["data"]["LoadBalancerArn"] = row["LoadBalancerArn"]
        else:
            index = bundle({"backup_restore_testing_plan": [], "backup_restore_testing_selection": [],
                            "backup_restore_job": []})
        assert evaluate(cid, row, index) == "NOT_APPLICABLE"


def test_backup_schedule_and_continuous_semantics_are_bounded():
    cid = "aws_backup_plan_rule_required_frequency"
    row, index = case(cid)
    rule = row["Plan"]["BackupPlan"]["Rules"][0]
    rule["ScheduleExpression"] = "cron(0 */6 * * ? *)"
    index = bundle({"backup_plan": [row]}, {"required_frequency_hours": 6})
    assert evaluate(cid, row, index) == "PASS"
    rule["ScheduleExpression"] = "cron(0 0 ? * MON-FRI *)"
    index = bundle({"backup_plan": [row]}, {"required_frequency_hours": 24})
    assert evaluate(cid, row, index) == "UNKNOWN"
    rule["ScheduleExpression"] = "rate(2 days)"
    rule["EnableContinuousBackup"] = True
    index = bundle({"backup_plan": [row]}, {"required_frequency_hours": 24})
    assert evaluate(cid, row, index) == "UNKNOWN"
    rule["ContinuousRecoveryPointMaxGapHours"] = 1
    index = bundle({"backup_plan": [row]}, {"required_frequency_hours": 24})
    assert evaluate(cid, row, index) == "PASS"
    rule["ScheduleExpressionTimezone"] = "America/New_York"
    index = bundle({"backup_plan": [row]}, {"required_frequency_hours": 24})
    assert evaluate(cid, row, index) == "UNKNOWN"


def test_approved_https_redirect_and_unapproved_redirect():
    cid = "aws_cis_elbv2_only_tls_listeners"
    row, index = case(cid, fail=True)
    listener = row["Listeners"]["items"][0]
    listener["DefaultActions"] = [{"Type": "redirect", "RedirectConfig": {
        "Protocol": "HTTPS", "Port": "443", "StatusCode": "HTTP_301"}}]
    index = bundle({"load_balancer": [row]}, {"approved_https_redirect_listener_arns": [listener["ListenerArn"]]})
    assert evaluate(cid, row, index) == "PASS"
    listener["DefaultActions"].insert(0, {"Type": "authenticate-oidc"})
    index = bundle({"load_balancer": [row]}, {"approved_https_redirect_listener_arns": [listener["ListenerArn"]]})
    assert evaluate(cid, row, index) == "PASS"
    index["context"]["metadata"]["compliance_policy"]["approved_https_redirect_listener_arns"] = []
    assert evaluate(cid, row, index) == "UNKNOWN"


def test_lightsail_public_object_acl_and_unapproved_identity():
    cid = "aws_cis_lightsail_bucket_private"
    row, _ = case(cid)
    row["accessRules"]["allowPublicOverrides"] = True
    row["Objects"] = {"collection_status": "collected", "items": [{"Key": "secret",
        "Grants": [{"Grantee": {"Type": "CanonicalUser", "ID": "owner"}, "Permission": "FULL_CONTROL"}]}]}
    index = bundle({"lightsail_bucket": [row]})
    assert evaluate(cid, row, index) == "UNKNOWN"
    row["Objects"]["items"][0]["Grants"].append({"Grantee": {"Type": "Group",
        "URI": "http://acs.amazonaws.com/groups/global/AllUsers"}, "Permission": "READ"})
    index = bundle({"lightsail_bucket": [row]})
    assert evaluate(cid, row, index) == "UNKNOWN"
    cid = "aws_cis_lightsail_bucket_iam_policy"
    row, index = case(cid)
    index["collections"]["lightsail_iam_policy_attachment"][0]["items"].append({
        "PrincipalArn": f"arn:aws:iam::{ACCOUNT}:role/unapproved",
        "PolicyDocument": {"Statement": [{"Effect": "Allow", "Action": "lightsail:GetBucket",
                                           "Resource": BUCKET_ARN}]}})
    index["lightsail_iam_policy_attachment"].append({"type": "lightsail_iam_policy_attachment",
        "scope": SCOPE, "data": copy.deepcopy(index["collections"]["lightsail_iam_policy_attachment"][0]["items"][-1])})
    assert evaluate(cid, row, index) == "FAIL"


def test_cloudtrail_failed_operation_is_not_a_flag():
    cid = "aws_cloudtrail_administration_command"
    subject, index = activity(cid, True)
    event = index["aws_cloudtrail_activity"][0]["data"]
    event["CloudTrailEvent"]["errorCode"] = "AccessDenied"
    index["collections"]["aws_cloudtrail_activity"][0]["items"][0]["CloudTrailEvent"]["errorCode"] = "AccessDenied"
    assert evaluate(cid, subject, index) == "PASS"
