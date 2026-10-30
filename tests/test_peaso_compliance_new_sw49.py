"""Isolated signed sw49 predicates; run this draft file alone with --noconftest."""
from __future__ import annotations

import copy

import pytest

from peaso.checks import CHECKS, evaluate_check
from peaso.checks import compliance_new_sw49 as sw49


SCOPE = "123456789012/us-east-1"
ACCOUNT = "123456789012"
GROUP = f"arn:aws:logs:us-east-1:{ACCOUNT}:log-group:security"
FORWARDER = f"arn:aws:lambda:us-east-1:{ACCOUNT}:function:siem"
STREAM = f"arn:aws:firehose:us-east-1:{ACCOUNT}:deliverystream:central"
ACL = f"arn:aws:wafv2:us-east-1:{ACCOUNT}:regional/webacl/main/abcdef"
API = f"arn:aws:appsync:us-east-1:{ACCOUNT}:apis/abc123"


@pytest.fixture(scope="module", autouse=True)
def remove_draft_registration():
    yield
    CHECKS[:] = [check for check in CHECKS if check.id not in sw49.SPECS]


def snapshot(rows, policy=None):
    policy = {} if policy is None else policy
    return {"context": {"provider": "aws", "scope": SCOPE, "metadata": policy},
            "collections": {kind: [{"type": kind, "scope": SCOPE, "status": "collected" if items else "empty",
                                    "items": items}] for kind, items in rows.items()},
            **{kind: [{"type": kind, "scope": SCOPE, "data": item} for item in items]
               for kind, items in rows.items()}}


def grade(check_id, item, index):
    return evaluate_check(check_id, item, index)[0]


def setup_resolver():
    rows = {"vpc": [{"VpcId": "vpc-123"}],
            "resolver_query_log_config_association": [{"ResourceId": "vpc-123", "Status": "ACTIVE",
                                                       "ResolverQueryLogConfigId": "rqlc-1"}],
            "resolver_query_log_config": [{"Id": "rqlc-1", "DestinationArn": GROUP}],
            "resolver_log_subscription": [{"LogGroupArn": GROUP, "DestinationArn": FORWARDER}]}
    return {"scope": SCOPE}, snapshot(rows, {"approved_siem_forwarder_arns": [FORWARDER]})


def test_aws_route53resolver_query_logs_forwarded():
    cid = "aws_route53resolver_query_logs_forwarded"
    item, index = setup_resolver()
    assert grade(cid, item, index) == "PASS"
    failed = copy.deepcopy(index)
    failed["collections"]["resolver_query_log_config_association"][0]["items"].clear()
    failed["resolver_query_log_config_association"].clear()
    assert grade(cid, item, failed) == "FAIL"
    partial = copy.deepcopy(index)
    partial["collections"]["resolver_log_subscription"][0]["status"] = "partial"
    assert grade(cid, item, partial) == "UNKNOWN"
    missing = copy.deepcopy(index)
    del missing["collections"]["resolver_log_subscription"]
    assert grade(cid, item, missing) == "UNKNOWN"
    malformed = copy.deepcopy(index)
    malformed["resolver_log_subscription"][0]["data"]["DestinationArn"] = 7
    assert grade(cid, item, malformed) == "UNKNOWN"


def setup_security_logs():
    rows = {"cloudwatch_log_group": [{"logGroupName": "security"}],
            "cloudwatch_subscription_filter": [{"logGroupName": "security", "destinationArn": STREAM,
                                                 "collection_status": "collected"}],
            "firehose_delivery_stream": [{"DeliveryStreamARN": STREAM, "DeliveryStreamStatus": "ACTIVE"}]}
    return {"scope": SCOPE}, snapshot(rows, {"security_log_group_names": ["security"],
                                        "approved_central_delivery_stream_arn": STREAM})


def test_aws_security_logs_central_search():
    cid = "aws_security_logs_central_search"
    item, index = setup_security_logs()
    assert grade(cid, item, index) == "PASS"
    failed = copy.deepcopy(index)
    failed["collections"]["cloudwatch_subscription_filter"][0]["items"].clear()
    failed["cloudwatch_subscription_filter"].clear()
    assert grade(cid, item, failed) == "FAIL"
    for kind in ("cloudwatch_log_group", "cloudwatch_subscription_filter", "firehose_delivery_stream"):
        partial = copy.deepcopy(index)
        partial["collections"][kind][0]["status"] = "partial"
        assert grade(cid, item, partial) == "UNKNOWN"
    missing = copy.deepcopy(index)
    del missing["collections"]["firehose_delivery_stream"]
    assert grade(cid, item, missing) == "UNKNOWN"
    malformed = copy.deepcopy(index)
    malformed["firehose_delivery_stream"][0]["data"]["DeliveryStreamStatus"] = []
    assert grade(cid, item, malformed) == "UNKNOWN"


def setup_api():
    item = {"id": "arn:aws:apigateway:us-east-1::/restapis/abc123/stages/prod",
            "_provenance": {"source_operation": "get_stages", "read_only": True},
            "methodSettings": {"*/*": {"loggingLevel": "INFO"}},
            "accessLogSettings": {"destinationArn": GROUP,
                                  "format": "$context.requestId $context.requestTime $context.status"}}
    return item, snapshot({"apigateway_stage": [item]})


def test_aws_api_customer_log_delivery():
    cid = "aws_api_customer_log_delivery"
    item, index = setup_api()
    assert grade(cid, item, index) == "PASS"
    fail, index = setup_api()
    fail["accessLogSettings"]["destinationArn"] = ""
    assert grade(cid, fail, index) == "FAIL"
    fail, index = setup_api()
    fail["methodSettings"]["~1pets/GET"] = {"loggingLevel": "OFF"}
    assert grade(cid, fail, index) == "FAIL"
    item, index = setup_api()
    item["methodSettings"]["*/*"]["loggingLevel"] = "OFF"
    assert grade(cid, item, index) == "UNKNOWN"
    item, index = setup_api()
    index["collections"]["apigateway_stage"][0]["status"] = "partial"
    assert grade(cid, item, index) == "UNKNOWN"
    item, index = setup_api()
    del index["collections"]["apigateway_stage"]
    assert grade(cid, item, index) == "UNKNOWN"
    item, index = setup_api()
    item["methodSettings"]["*/*"]["loggingLevel"] = []
    assert grade(cid, item, index) == "UNKNOWN"


def setup_macie():
    bucket = "arn:aws:s3:::authorized-bucket"
    rows = {"macie_scan_coverage": [{"authorized": True, "complete": True, "bucketArns": [bucket]}],
            "macie_finding": []}
    policy = {"prohibited_auth_identifier_names": ["CVV", "PIN", "TRACK"],
              "authorized_macie_bucket_arns": [bucket]}
    return {"scope": SCOPE}, snapshot(rows, policy)


def test_aws_pci_s3_sensitive_auth_data_findings():
    cid = "aws.pci.s3.sensitive_auth_data_findings"
    item, index = setup_macie()
    assert grade(cid, item, index) == "PASS"
    finding = {"id": "finding-1", "accountId": ACCOUNT, "region": "us-east-1",
               "s3Object": {"bucketArn": "arn:aws:s3:::authorized-bucket"},
               "archived": False, "customIdentifierNames": ["CVV"]}
    failed = copy.deepcopy(index)
    failed["collections"]["macie_finding"][0]["items"].append(finding)
    failed["collections"]["macie_finding"][0]["status"] = "collected"
    failed["macie_finding"].append({"type": "macie_finding", "scope": SCOPE, "data": finding})
    assert grade(cid, item, failed) == "FAIL"
    partial = copy.deepcopy(index)
    partial["collections"]["macie_finding"][0]["status"] = "partial"
    assert grade(cid, item, partial) == "UNKNOWN"
    missing = copy.deepcopy(index)
    del missing["collections"]["macie_scan_coverage"]
    assert grade(cid, item, missing) == "UNKNOWN"
    malformed = copy.deepcopy(index)
    malformed["macie_scan_coverage"][0]["data"]["complete"] = "yes"
    assert grade(cid, item, malformed) == "UNKNOWN"


def setup_appsync(acl=ACL):
    item = {"arn": API}
    rows = {"appsync_graphql_api": [item], "wafv2_appsync_association":
            [{"ResourceArn": API, "WebACLArn": acl}]}
    return item, snapshot(rows)


def test_aws_pci_appsync_waf_web_acl():
    cid = "aws.pci.appsync.waf_web_acl"
    item, index = setup_appsync()
    assert grade(cid, item, index) == "PASS"
    item, index = setup_appsync("")
    assert grade(cid, item, index) == "FAIL"
    item, index = setup_appsync()
    index["collections"]["wafv2_appsync_association"][0]["status"] = "partial"
    assert grade(cid, item, index) == "UNKNOWN"
    item, index = setup_appsync()
    del index["collections"]["wafv2_appsync_association"]
    assert grade(cid, item, index) == "UNKNOWN"
    item, index = setup_appsync()
    index["wafv2_appsync_association"][0]["data"]["WebACLArn"] = 1
    assert grade(cid, item, index) == "UNKNOWN"


def setup_fms():
    item = {"PolicyId": "p-1", "SecurityServiceType": "WAFV2"}
    rows = {"fms_policy": [item], "fms_web_acl_rules":
            [{"PolicyId": "p-1", "WebACLArn": ACL, "complete": True,
              "Rules": [{"Name": "first", "Priority": 1}, {"Name": "second", "Priority": 2}]}]}
    return item, snapshot(rows, {"approved_fms_rule_priorities": {"p-1":
                                 [{"Name": "first", "Priority": 1}, {"Name": "second", "Priority": 2}]}})


def test_aws_pci_fms_web_acl_rule_priority():
    cid = "aws.pci.fms.web_acl_rule_priority"
    item, index = setup_fms()
    assert grade(cid, item, index) == "PASS"
    item, index = setup_fms()
    index["fms_web_acl_rules"][0]["data"]["Rules"][1]["Priority"] = 1
    assert grade(cid, item, index) == "FAIL"
    item, index = setup_fms()
    item["SecurityServiceType"] = "SHIELD_ADVANCED"
    assert grade(cid, item, index) == "NOT_APPLICABLE"
    item, index = setup_fms()
    index["collections"]["fms_web_acl_rules"][0]["status"] = "partial"
    assert grade(cid, item, index) == "UNKNOWN"
    item, index = setup_fms()
    del index["collections"]["fms_web_acl_rules"]
    assert grade(cid, item, index) == "UNKNOWN"
    item, index = setup_fms()
    index["fms_web_acl_rules"][0]["data"]["Rules"][0]["Priority"] = "one"
    assert grade(cid, item, index) == "UNKNOWN"


def setup_ou():
    rows = {"organization_account": [{"Id": ACCOUNT, "Status": "ACTIVE"},
                                      {"Id": "999999999999", "Status": "ACTIVE"}],
            "organization_parent": [
                {"ChildId": "999999999999", "ParentId": "ou-abcd-12345678", "ParentType": "ORGANIZATIONAL_UNIT", "OrganizationalUnitName": "prod"},
                {"ChildId": "ou-abcd-12345678", "ParentId": "ou-abcd-87654321", "ParentType": "ORGANIZATIONAL_UNIT", "OrganizationalUnitName": "sensitive"},
                {"ChildId": "ou-abcd-87654321", "ParentId": "r-root", "ParentType": "ROOT"}]}
    return {"scope": SCOPE}, snapshot(rows, {"organization_management_account_id": ACCOUNT,
                                        "approved_environment_ou_patterns": ["prod"],
                                        "approved_sensitivity_ou_patterns": ["sensitive"]})


def test_aws_cis_organization_units_environment_sensitivity():
    cid = "aws_cis_organization_units_environment_sensitivity"
    item, index = setup_ou()
    assert grade(cid, item, index) == "PASS"
    failed = copy.deepcopy(index)
    failed["context"]["metadata"]["approved_environment_ou_patterns"] = ["dev"]
    assert grade(cid, item, failed) == "FAIL"
    partial = copy.deepcopy(index)
    partial["collections"]["organization_parent"][0]["status"] = "partial"
    assert grade(cid, item, partial) == "UNKNOWN"
    missing = copy.deepcopy(index)
    del missing["collections"]["organization_parent"]
    assert grade(cid, item, missing) == "UNKNOWN"
    malformed = copy.deepcopy(index)
    malformed["organization_parent"][0]["data"]["OrganizationalUnitName"] = None
    assert grade(cid, item, malformed) == "UNKNOWN"


def setup_tag():
    rows = {"organization_tag_policy": [{"Id": "p-1", "PolicyType": "TAG_POLICY",
                                          "AttachedToAccountPath": True,
                                          "Complete": True,
                                          "Ec2Tags": {"owner": ["security"], "environment": ["prod"]}}]}
    return {"scope": SCOPE}, snapshot(rows, {"approved_ec2_tag_values":
                                           {"owner": ["security"], "environment": ["prod"]}})


def test_aws_cis_ec2_tag_policy():
    cid = "aws_cis_ec2_tag_policy"
    item, index = setup_tag()
    assert grade(cid, item, index) == "PASS"
    item, index = setup_tag()
    index["organization_tag_policy"][0]["data"]["AttachedToAccountPath"] = False
    assert grade(cid, item, index) == "FAIL"
    item, index = setup_tag()
    del index["organization_tag_policy"][0]["data"]["Ec2Tags"]["owner"]
    assert grade(cid, item, index) == "FAIL"
    item, index = setup_tag()
    index["organization_tag_policy"][0]["data"]["Ec2Tags"]["owner"].append("unknown")
    assert grade(cid, item, index) == "FAIL"
    item, index = setup_tag()
    index["collections"]["organization_tag_policy"][0]["status"] = "partial"
    assert grade(cid, item, index) == "UNKNOWN"
    item, index = setup_tag()
    del index["collections"]["organization_tag_policy"]
    assert grade(cid, item, index) == "UNKNOWN"
    item, index = setup_tag()
    index["organization_tag_policy"][0]["data"]["Ec2Tags"]["owner"] = None
    assert grade(cid, item, index) == "UNKNOWN"


def setup_region():
    services = ("s3", "rds", "ec2_volume", "dynamodb", "efs", "redshift", "backup")
    rows = {"aws_enabled_region": [{"RegionName": "eu-west-1", "OptInStatus": "opt-in-not-required"},
                                   {"RegionName": "us-east-1", "OptInStatus": "opt-in-not-required"}],
            "aws_data_resource_coverage": [{"Region": region, "Service": service, "Complete": True}
                                           for region in ("eu-west-1", "us-east-1") for service in services],
            "aws_data_resource": [{"ResourceId": "arn:aws:rds:eu-west-1:123456789012:db:sample",
                                   "Region": "eu-west-1", "Service": "rds", "AccountId": ACCOUNT}]}
    return {"scope": SCOPE}, snapshot(rows, {"approved_region_names": ["eu-west-1"]})


def test_aws_account_non_eu_resource_region_detected():
    cid = "aws_account_non_eu_resource_region_detected"
    item, index = setup_region()
    assert grade(cid, item, index) == "PASS"
    item, index = setup_region()
    index["aws_data_resource"][0]["data"]["Region"] = "us-east-1"
    assert grade(cid, item, index) == "FAIL"
    item, index = setup_region()
    index["collections"]["aws_data_resource_coverage"][0]["status"] = "partial"
    assert grade(cid, item, index) == "UNKNOWN"
    item, index = setup_region()
    del index["collections"]["aws_data_resource_coverage"]
    assert grade(cid, item, index) == "UNKNOWN"
    item, index = setup_region()
    index["aws_enabled_region"][0]["data"]["OptInStatus"] = 1
    assert grade(cid, item, index) == "UNKNOWN"


def test_signed_metadata_and_foreign_scope():
    item, index = setup_security_logs()
    index["collections"]["cloudwatch_log_group"][0]["scope"] = "000000000000/us-east-1"
    assert grade("aws_security_logs_central_search", item, index) == "UNKNOWN"
