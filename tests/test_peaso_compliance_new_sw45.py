"""Isolated sw45 signed draft checks; run this file alone with --noconftest."""
from __future__ import annotations

import copy
import pytest

from peaso.checks import CHECKS, evaluate_check
from peaso.checks import compliance_new_sw45 as sw

SCOPE = "123456789012/us-east-1"
ACCOUNT = "123456789012"
REGION = "us-east-1"
ACL_ARN = f"arn:aws:wafv2:{REGION}:{ACCOUNT}:regional/webacl/test/abc"
EVENT_ARN = f"arn:aws:events:{REGION}:{ACCOUNT}:rule/test"
ALARM_ARN = f"arn:aws:cloudwatch:{REGION}:{ACCOUNT}:alarm:test"


@pytest.fixture(scope="module", autouse=True)
def clean_registry_after_file():
    yield
    CHECKS[:] = [check for check in CHECKS if check.id not in sw.SPECS]


def index(**kinds):
    collections = {}
    wrappers = {}
    for kind, rows in kinds.items():
        collections[kind] = [{"type": kind, "scope": SCOPE,
                              "status": "collected" if rows else "empty", "items": rows}]
        wrappers[kind] = [{"type": kind, "scope": SCOPE, "data": row} for row in rows]
    return {"context": {"provider": "aws", "scope": SCOPE, "metadata": {}},
            "collections": collections, **wrappers}


def evaluate(check_id, item, facts):
    return evaluate_check(check_id, item, facts)[0]


def waf(rules=None, **extra):
    return {"ARN": ACL_ARN, "Id": "abc", "Scope": "REGIONAL",
            "WebACL": {"ARN": ACL_ARN, "Id": "abc", "Name": "test",
                       "VisibilityConfig": {"MetricName": "web-metric"},
                       "Rules": [] if rules is None else rules},
            "ResourceArns": {"collection_status": "collected", "ResourceArns": []}, **extra}


def alarm(metric="rate-metric", dimensions=None, threshold=3):
    if dimensions is None:
        dimensions = {"WebACL": "web-metric", "Rule": "rate-metric"}
    return {"AlarmArn": ALARM_ARN, "MetricName": metric, "Namespace": "AWS/WAFV2",
            "Dimensions": [{"Name": k, "Value": v} for k, v in dimensions.items()],
            "ActionsEnabled": True, "AlarmActions": ["arn:aws:sns:us-east-1:123456789012:alert"],
            "Threshold": threshold}


def rate_rule(kind="RateBasedStatement", **extra):
    return {"Name": "rate", "Statement": {kind: {"Limit": 10} if kind == "RateBasedStatement" else
            {"VendorName": "AWS", "Name": "AWSManagedRulesCommonRuleSet"}},
            "VisibilityConfig": {"CloudWatchMetricsEnabled": True, "MetricName": "rate-metric"}, **extra}


def event(pattern, *, state="ENABLED", targets=None):
    return {"Arn": EVENT_ARN, "EventBusName": "default", "State": state,
            "EventPattern": pattern, "Targets": {"collection_status": "collected", "items":
                [{"Arn": "arn:aws:sns:us-east-1:123456789012:alert"}] if targets is None else targets}}


def pattern(source, detail_type, detail):
    return {"source": [source], "detail-type": [detail_type], "detail": detail}


def _event_facts(row, **extra):
    return index(event_rule=[row], **extra)


def test_waf_global_allow_block_lists():
    allow_arn = f"arn:aws:wafv2:{REGION}:{ACCOUNT}:regional/ipset/allow/a"
    block_arn = f"arn:aws:wafv2:{REGION}:{ACCOUNT}:regional/ipset/block/b"
    rows = [{"ARN": allow_arn, "Addresses": ["10.0.0.0/8"]},
            {"ARN": block_arn, "Addresses": ["192.0.2.0/24"]}]
    rules = [{"Name": "allow", "Priority": 1, "Action": {"Allow": {}},
              "Statement": {"IPSetReferenceStatement": {"ARN": allow_arn}}},
             {"Name": "block", "Priority": 2, "Action": {"Block": {}},
              "Statement": {"IPSetReferenceStatement": {"ARN": block_arn}}}]
    item = waf(rules)
    facts = index(wafv2_web_acl=[item], wafv2_ip_set=rows)
    facts["context"]["metadata"] = {"approved_allow_cidrs": ["10.0.0.0/8"],
        "approved_block_cidrs": ["192.0.2.0/24"], "approved_allow_priority": 1,
        "approved_block_priority": 2}
    check = "aws_wafv2_global_allow_block_lists"
    assert evaluate(check, item, facts) == "PASS"
    bad = copy.deepcopy(item); bad["WebACL"]["Rules"][1]["Priority"] = 4
    bad_facts = copy.deepcopy(facts); bad_facts["wafv2_web_acl"][0]["data"] = bad
    bad_facts["collections"]["wafv2_web_acl"][0]["items"] = [bad]
    assert evaluate(check, bad, bad_facts) == "FAIL"
    assert evaluate(check, item, index(wafv2_web_acl=[item])) == "UNKNOWN"
    facts["collections"]["wafv2_ip_set"][0]["status"] = "partial"
    assert evaluate(check, item, facts) == "UNKNOWN"
    facts["collections"]["wafv2_ip_set"][0]["status"] = "collected"
    facts["wafv2_ip_set"][0]["data"]["Addresses"] = "bad"
    assert evaluate(check, item, facts) == "UNKNOWN"


@pytest.mark.parametrize("check_id,kind,metric", [
    ("aws_wafv2_rate_rule_alarm", "RateBasedStatement", "rate-metric"),
    ("aws_wafv2_managed_block_alarm", "ManagedRuleGroupStatement", "BlockedRequests")])
def test_waf_rule_alarms(check_id, kind, metric):
    item = waf([rate_rule(kind)])
    facts = index(wafv2_web_acl=[item], cloudwatch_alarm=[alarm(metric)])
    if kind == "ManagedRuleGroupStatement":
        facts["context"]["metadata"]["approved_blocked_request_threshold"] = 5
    assert evaluate(check_id, item, facts) == "PASS"
    facts["cloudwatch_alarm"][0]["data"]["ActionsEnabled"] = False
    facts["collections"]["cloudwatch_alarm"][0]["items"][0]["ActionsEnabled"] = False
    assert evaluate(check_id, item, facts) == "FAIL"
    facts["collections"]["cloudwatch_alarm"][0]["status"] = "denied"
    assert evaluate(check_id, item, facts) == "UNKNOWN"
    facts["collections"]["cloudwatch_alarm"][0]["status"] = "collected"
    facts["cloudwatch_alarm"][0]["data"]["Dimensions"] = "bad"
    assert evaluate(check_id, item, facts) == "UNKNOWN"
    assert evaluate(check_id, item, index(wafv2_web_acl=[item])) == "UNKNOWN"
    empty = waf()
    empty_facts = index(wafv2_web_acl=[empty], cloudwatch_alarm=[])
    if kind == "ManagedRuleGroupStatement":
        empty_facts["context"]["metadata"]["approved_blocked_request_threshold"] = 5
    assert evaluate(check_id, empty, empty_facts) == "NOT_APPLICABLE"


def test_monitoring_rate_rule():
    statement = {"ByteMatchStatement": {"SearchString": "health"}}
    rule = rate_rule(Action={"Block": {}})
    rule["Statement"]["RateBasedStatement"]["ScopeDownStatement"] = statement
    resource = "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/a/1"
    item = waf([rule], ResourceArns={"collection_status": "collected", "ResourceArns": [resource]})
    facts = index(wafv2_web_acl=[item], cloudwatch_alarm=[alarm()])
    facts["context"]["metadata"]["monitoring_endpoints"] = [{"ResourceArn": resource,
        "ApprovedRequestThreshold": 20, "ScopeDownStatement": statement}]
    check = "aws_wafv2_monitoring_rate_rule"
    assert evaluate(check, item, facts) == "PASS"
    facts["context"]["metadata"]["monitoring_endpoints"][0]["ApprovedRequestThreshold"] = 5
    assert evaluate(check, item, facts) == "FAIL"
    facts["context"]["metadata"].pop("monitoring_endpoints")
    assert evaluate(check, item, facts) == "UNKNOWN"
    facts["context"]["metadata"]["monitoring_endpoints"] = []
    assert evaluate(check, item, facts) == "NOT_APPLICABLE"
    facts["collections"]["cloudwatch_alarm"][0]["status"] = "partial"
    facts["context"]["metadata"]["monitoring_endpoints"] = [{"ResourceArn": resource,
        "ApprovedRequestThreshold": 20, "ScopeDownStatement": statement}]
    assert evaluate(check, item, facts) == "UNKNOWN"
    facts["collections"]["cloudwatch_alarm"][0]["status"] = "collected"
    facts["context"]["metadata"]["monitoring_endpoints"][0]["ApprovedRequestThreshold"] = "bad"
    assert evaluate(check, item, facts) == "UNKNOWN"


def test_waf_redacted_siem_logging():
    item = waf(LoggingConfiguration={"collection_status": "collected",
        "LoggingConfiguration": {"ResourceArn": ACL_ARN,
            "RedactedFields": [{"SingleHeader": {"Name": "authorization"}}],
            "LogDestinationConfigs": ["arn:aws:logs:us-east-1:123456789012:log-group:waf"]}})
    filter_row = {"LogGroupArn": "arn:aws:logs:us-east-1:123456789012:log-group:waf",
        "DestinationArn": "arn:aws:firehose:us-east-1:123456789012:deliverystream/siem"}
    facts = index(wafv2_web_acl=[item], log_subscription_filter=[filter_row])
    facts["context"]["metadata"] = {"approved_sensitive_headers": ["authorization"],
        "require_query_string_redaction": False,
        "approved_siem_destination_arns": [filter_row["DestinationArn"]]}
    check = "aws_wafv2_redacted_siem_logging"
    assert evaluate(check, item, facts) == "PASS"
    facts["context"]["metadata"]["approved_sensitive_headers"] = ["authorization", "cookie"]
    assert evaluate(check, item, facts) == "FAIL"
    facts["collections"]["log_subscription_filter"][0]["status"] = "partial"
    assert evaluate(check, item, facts) == "UNKNOWN"
    item2 = copy.deepcopy(item); item2["LoggingConfiguration"] = {"collection_status": "empty"}
    f2 = index(wafv2_web_acl=[item2], log_subscription_filter=[])
    f2["context"]["metadata"] = copy.deepcopy(facts["context"]["metadata"])
    assert evaluate(check, item2, f2) == "FAIL"
    item2["LoggingConfiguration"] = {"collection_status": "collected", "LoggingConfiguration": []}
    assert evaluate(check, item2, f2) == "UNKNOWN"


def test_request_validation_rules():
    rule = rate_rule("ManagedRuleGroupStatement", OverrideAction={"None": {}})
    item = waf([rule])
    lb = {"LoadBalancerArn": f"arn:aws:elasticloadbalancing:{REGION}:{ACCOUNT}:loadbalancer/app/a/1",
          "Type": "application", "Scheme": "internet-facing", "WAFWebACLArn": ACL_ARN}
    facts = index(wafv2_web_acl=[item], load_balancer_v2=[lb])
    check = "aws_wafv2_request_validation_rules"
    assert evaluate(check, item, facts) == "PASS"
    lb["WAFWebACLArn"] = ""
    assert evaluate(check, item, facts) == "FAIL"
    del lb["WAFWebACLArn"]
    assert evaluate(check, item, facts) == "UNKNOWN"
    lb["Scheme"] = "internal"
    assert evaluate(check, item, facts) == "NOT_APPLICABLE"
    lb["Scheme"] = "internet-facing"
    facts["collections"]["load_balancer_v2"][0]["status"] = "partial"
    assert evaluate(check, item, facts) == "UNKNOWN"
    facts["collections"]["load_balancer_v2"][0]["status"] = "collected"
    lb["Type"] = []
    assert evaluate(check, item, facts) == "UNKNOWN"


@pytest.mark.parametrize("check_id,source,detail_type,detail,key,required", [
    ("aws_eventbridge_iam_user_change_alert", "aws.iam", "AWS API Call via CloudTrail",
     {"eventSource": ["iam.amazonaws.com"], "eventName": ["CreateUser", "DeleteUser", "UpdateUser",
      "CreateAccessKey", "UpdateAccessKey", "DeleteAccessKey"]}, "eventName", "CreateUser"),
    ("aws_eventbridge_snapshot_change_alert", "aws.ec2", "AWS API Call via CloudTrail",
     {"eventSource": ["ec2.amazonaws.com"], "eventName": ["CreateSnapshot", "ModifySnapshotAttribute",
      "DeleteSnapshot"]}, "eventName", "CreateSnapshot"),
    ("aws_securityhub_findings_alerted", "aws.securityhub", "Security Hub Findings - Imported",
     {"findings": {"Severity": {"Label": ["HIGH", "CRITICAL"]}}}, "findings", "HIGH"),
    ("aws_securityhub_medium_findings_alert", "aws.securityhub", "Security Hub Findings - Imported",
     {"findings": {"Severity": {"Label": ["MEDIUM", "LOW", "INFORMATIONAL"]}}}, "findings", "LOW"),
])
def test_event_alert_coverage(check_id, source, detail_type, detail, key, required):
    row = event(pattern(source, detail_type, detail))
    facts = _event_facts(row)
    assert evaluate(check_id, row, facts) == "PASS"
    row["State"] = "DISABLED"
    assert evaluate(check_id, row, facts) == "FAIL"
    row["State"] = "ENABLED"
    row["EventPattern"]["detail"].pop(key)
    assert evaluate(check_id, row, facts) == "UNKNOWN"
    assert evaluate(check_id, row, index()) == "UNKNOWN"
    facts["collections"]["event_rule"][0]["status"] = "partial"
    assert evaluate(check_id, row, facts) == "UNKNOWN"


def test_inspector_critical_findings_alert():
    row = event(pattern("aws.inspector2", "Inspector2 Finding", {"severity": ["CRITICAL"],
        "resources": {"type": ["AWS_EC2_INSTANCE", "AWS_ECR_CONTAINER_IMAGE"]}}))
    facts = _event_facts(row)
    check = "aws_inspector_critical_image_findings_alert"
    assert evaluate(check, row, facts) == "PASS"
    row["Targets"]["items"] = []
    assert evaluate(check, row, facts) == "FAIL"
    row["Targets"]["collection_status"] = "denied"
    assert evaluate(check, row, facts) == "UNKNOWN"
    row["Targets"]["collection_status"] = "collected"
    row["EventPattern"]["detail"]["resources"] = "bad"
    assert evaluate(check, row, facts) == "UNKNOWN"


def test_ecr_scan_metric_export():
    target = "arn:aws:lambda:us-east-1:123456789012:function:metrics"
    row = event(pattern("aws.ecr", "ECR Image Scan", {}), targets=[{"Arn": target}])
    metric = {"Namespace": "Custom/Security", "MetricName": "ECRScanFindings"}
    facts = _event_facts(row, cloudwatch_metric=[metric])
    facts["context"]["metadata"] = {"metric_ingestion_target_arn": target,
        "ecr_scan_metric_namespace": metric["Namespace"], "ecr_scan_metric_name": metric["MetricName"]}
    check = "aws_ecr_scan_findings_metric_export"
    assert evaluate(check, row, facts) == "PASS"
    facts["collections"]["cloudwatch_metric"][0]["items"] = []
    facts["cloudwatch_metric"] = []
    facts["collections"]["cloudwatch_metric"][0]["status"] = "empty"
    assert evaluate(check, row, facts) == "FAIL"
    facts["collections"]["cloudwatch_metric"][0]["status"] = "denied"
    assert evaluate(check, row, facts) == "UNKNOWN"
    facts["context"]["metadata"].pop("metric_ingestion_target_arn")
    assert evaluate(check, row, facts) == "UNKNOWN"
    row["EventPattern"] = "not-json"
    assert evaluate(check, row, facts) == "UNKNOWN"


def test_resolver_blocked_query_alert():
    row = event(pattern("aws.iam", "AWS API Call via CloudTrail", {}))
    association = {"Status": "COMPLETE", "VpcId": "vpc-123"}
    a = alarm("BlockedQueries", {"VpcId": "vpc-123"})
    a["Namespace"] = "AWS/Route53Resolver"
    facts = _event_facts(row, resolver_firewall_association=[association], cloudwatch_alarm=[a])
    check = "aws_route53resolver_blocked_query_alert"
    assert evaluate(check, row, facts) == "PASS"
    a["ActionsEnabled"] = False
    assert evaluate(check, row, facts) == "FAIL"
    facts["collections"]["resolver_firewall_association"][0]["status"] = "partial"
    assert evaluate(check, row, facts) == "UNKNOWN"
    empty = _event_facts(row, resolver_firewall_association=[], cloudwatch_alarm=[])
    assert evaluate(check, row, empty) == "NOT_APPLICABLE"
    a["Dimensions"] = "bad"
    facts["collections"]["resolver_firewall_association"][0]["status"] = "collected"
    assert evaluate(check, row, facts) == "UNKNOWN"


def test_instance_approved_ami():
    item = {"InstanceId": "i-123", "ImageId": "ami-123", "State": {"Name": "running"}}
    image = {"ImageId": "ami-123", "OwnerId": ACCOUNT}
    facts = index(instance=[item], ec2_instance_image=[image])
    facts["context"]["metadata"] = {"approved_image_ids": ["ami-123"], "approved_owner_ids": [ACCOUNT]}
    check = "aws_cis_ec2_instance_approved_ami"
    assert evaluate(check, item, facts) == "PASS"
    facts["context"]["metadata"]["approved_owner_ids"] = ["999999999999"]
    assert evaluate(check, item, facts) == "FAIL"
    facts["collections"]["ec2_instance_image"][0]["status"] = "partial"
    assert evaluate(check, item, facts) == "UNKNOWN"
    item["State"]["Name"] = "stopped"
    assert evaluate(check, item, facts) == "NOT_APPLICABLE"
    item["State"]["Name"] = "running"
    item.pop("ImageId")
    assert evaluate(check, item, facts) == "UNKNOWN"
    item["ImageId"] = ["ami-123"]
    assert evaluate(check, item, facts) == "UNKNOWN"


def test_userdata_embedded_secrets():
    indicator = {"collection_status": "collected", "InstanceId": "i-123",
                 "Present": True, "HighConfidenceSecretPresent": False, "MatchedCategories": []}
    item = {"InstanceId": "i-123", "UserDataSecretIndicators": indicator}
    facts = index(instance=[item])
    check = "aws_cis_ec2_userdata_embedded_secrets"
    assert evaluate(check, item, facts) == "PASS"
    indicator["HighConfidenceSecretPresent"] = True
    indicator["MatchedCategories"] = ["private_key"]
    assert evaluate(check, item, facts) == "FAIL"
    indicator["collection_status"] = "denied"
    assert evaluate(check, item, facts) == "UNKNOWN"
    indicator["collection_status"] = "collected"
    indicator["MatchedCategories"] = "bad"
    assert evaluate(check, item, facts) == "UNKNOWN"
    item.pop("UserDataSecretIndicators")
    assert evaluate(check, item, facts) == "UNKNOWN"


def test_scope_event_checks_handle_empty_complete_rule_inventory():
    facts = index(event_rule=[])
    context = facts["context"]
    for check_id in ("aws_eventbridge_iam_user_change_alert",
                     "aws_eventbridge_snapshot_change_alert",
                     "aws_securityhub_findings_alerted",
                     "aws_securityhub_medium_findings_alert",
                     "aws_inspector_critical_image_findings_alert"):
        check = next(check for check in CHECKS if check.id == check_id)
        assert check.target == "scope"
        assert evaluate(check_id, context, facts) == "FAIL"
    assert evaluate("aws_eventbridge_iam_user_change_alert", context, index()) == "UNKNOWN"


def test_inventory_validation_is_shared_but_subject_membership_is_not(monkeypatch):
    from peaso.checks.facts import MemoIndex, Unavailable
    rows=[{'InstanceId':'i-one','InstanceType':'t3.micro'}, {'InstanceId':'i-two','InstanceType':'t3.micro'}]
    facts=MemoIndex(index(instance=rows));original=sw._validated_inventory;calls=[]
    def counted(index,kind):
        calls.append(kind);return original(index,kind)
    monkeypatch.setattr(sw,'_validated_inventory',counted)
    first=sw._inventory(facts,'instance',rows[0]);first.clear()
    assert sw._inventory(facts,'instance',rows[1])==rows
    with pytest.raises(Unavailable):sw._inventory(facts,'instance',{'InstanceId':'i-one','InstanceType':'forged'})
    assert calls==['instance']
    facts['context']={**facts['context'],'scope':'999999999999/us-east-1'}
    with pytest.raises(Unavailable):sw._inventory(facts,'instance',rows[0])
    assert calls==['instance','instance']


@pytest.mark.parametrize('malformed',['partial','duplicate'])
def test_negative_inventory_validation_is_cached_without_certifying_subjects(monkeypatch,malformed):
    from peaso.checks.facts import MemoIndex, Unavailable
    row={'InstanceId':'i-one'}
    facts=index(instance=[row,row]if malformed=='duplicate'else[row])
    if malformed=='partial':facts['collections']['instance'][0]['status']='partial'
    facts=MemoIndex(facts);original=sw._validated_inventory;calls=[]
    def counted(index,kind):
        calls.append(kind);return original(index,kind)
    monkeypatch.setattr(sw,'_validated_inventory',counted)
    for _ in range(2):
        with pytest.raises(Unavailable):sw._inventory(facts,'instance',row)
    assert calls==['instance']
