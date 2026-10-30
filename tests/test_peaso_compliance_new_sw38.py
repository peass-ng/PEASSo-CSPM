"""Isolated signed sw38 AWS evaluator cases. Run this draft file alone with --noconftest."""
from __future__ import annotations

import pytest

from peaso.checks import evaluate_check
from peaso.checks import compliance_new_sw38 as sw38

ACCOUNT = "123456789012"
REGION = "us-east-1"
REGIONAL = ACCOUNT + "/" + REGION
GLOBAL = ACCOUNT + "/global"
BUCKET = "example-bucket"
BUCKET_ARN = "arn:aws:s3:::" + BUCKET
SIEM_ARN = f"arn:aws:es:{REGION}:{ACCOUNT}:domain/siem"


def index(kind, row, *, scope=REGIONAL, extras=None, policy=None, covered=None):
    policy = {} if policy is None else policy
    policy = {"status": "collected", "scope": scope, **policy}
    collections = {}
    out = {"context": {"provider": "aws", "scope": scope,
                       "metadata": {"sw38_policy": policy}}, "collections": collections}
    for key, values in {kind: [row], **(extras or {})}.items():
        envelope = {"type": key, "scope": scope, "status": "collected" if values else "empty",
                    "items": values}
        if key == kind and covered is not None:
            envelope["covered_source_kinds"] = covered
        collections[key] = [envelope]
        out[key] = [{"type": key, "scope": scope, "data": value} for value in values]
    return out


def case(cid, bad=False):
    policy = {}
    extras = {}
    scope = REGIONAL
    if cid in {"aws_cloudwatchlogs_cloud_storage_staging", "aws_cloudwatchlogs_information_repository_read"}:
        event = {"eventName": "PutObject" if cid.endswith("cloud_storage_staging") else "GetObject",
                 "eventTime": "2026-10-01T12:00:00Z", "userIdentity": {"arn": "arn:aws:iam::123456789012:role/" + ("bad" if bad else "good")},
                 "resourceArn": BUCKET_ARN + "/key", "errorCode": None}
        row = {"logGroupName": "/aws/cloudtrail/events", "CloudTrailDataEvents": {
            "collection_status": "collected", "selectors_complete": True, "retention_complete": True,
            "log_group_name": "/aws/cloudtrail/events", "scope": scope, "items": [event]}}
        policy = {"staging_bucket_writers": {BUCKET: ["arn:aws:iam::123456789012:role/good"]},
                  "information_repository_arns": [BUCKET_ARN],
                  "approved_data_access_principals": ["arn:aws:iam::123456789012:role/good"]}
        kind = "log_group"
    elif cid == "aws.pci.s3.allowed_policy_principals":
        scope = GLOBAL
        row = {"Name": BUCKET, "Policy": {"collection_status": "collected", "Policy": {
            "Statement": [{"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::123456789012:role/" + ("bad" if bad else "good")},
                           "Action": "s3:GetObject", "Resource": BUCKET_ARN + "/*"}]}}}
        policy = {"allowed_s3_principals": ["arn:aws:iam::123456789012:role/good"],
                  "allowed_s3_source_ips": [], "allowed_s3_source_vpcs": []}
        kind = "bucket"
    elif cid == "aws.pci.s3.bucket_backup_plan":
        scope = GLOBAL
        row = {"Name": BUCKET}
        selection = {"Region": REGION, "Active": True, "ScheduledRules": 1,
                     "Resources": [] if bad else [BUCKET_ARN], "NotResources": [], "Conditions": {}, "ListOfTags": []}
        extras = {"s3_backup_plan_coverage": [{"AccountId": ACCOUNT, "AllEnabledRegionsCollected": True,
                                                 "Selections": [selection]}]}
        kind = "bucket"
    elif cid == "aws_cis_s3_macie_classification_coverage":
        scope = GLOBAL
        row = {"Name": BUCKET, "Location": {"collection_status": "collected", "LocationConstraint": REGION}}
        extras = {"s3_macie_region_coverage": [{"AccountId": ACCOUNT, "AllEnabledRegionsCollected": True,
            "Regions": [{"Region": REGION, "Session": {"status": "ENABLED"},
                         "AutomatedDiscovery": {"status": "DISABLED" if bad else "ENABLED"},
                         "Jobs": {"collection_status": "empty", "items": []}}]}]}
        kind = "bucket"
    elif cid == "aws_nist_vpc_igw_attached_to_authorized_vpc":
        row = {"InternetGatewayId": "igw-aabbccdd", "Attachments": [{"VpcId": "vpc-" + ("2222" if bad else "1111"), "State": "available"}]}
        policy = {"approved_vpc_ids": ["vpc-1111"]}
        kind = "internet_gateway"
    elif cid in {"aws.nist.sc_8_coverage", "aws.nist.sc_8_1_coverage"}:
        row = {"id": f"arn:aws:elasticloadbalancing:{REGION}:{ACCOUNT}:listener/app/a/b/c",
               "AccountId": ACCOUNT, "Scope": scope, "SourceKind": "elbv2_listener",
               "External": True, "Protocol": "HTTP" if bad else "HTTPS", "TLSPolicy": "TLS-1-2"}
        policy = {"approved_tls_policies": ["TLS-1-2"]}
        kind = "transport_endpoint"
    elif cid in {"aws.nist.waf_classic_regional_acl_logging", "aws_nist_waf_web_acl_logging_enabled"}:
        scope = GLOBAL
        row = {"WebACLId": "global-acl", "WebACL": {"WebACLArn": f"arn:aws:waf::{ACCOUNT}:webacl/global-acl"},
               "LoggingConfiguration": {"collection_status": "collected",
               "LoggingConfiguration": {"LogDestinationConfigs": ["arn:aws:firehose:us-east-1:123456789012:deliverystream/global"]}}}
        regional = {"WebACLId": "regional-acl", "Region": REGION,
                    "WebACL": {"WebACLArn": f"arn:aws:waf-regional:{REGION}:{ACCOUNT}:webacl/regional-acl"},
                    "LoggingConfiguration": {"collection_status": "collected", "LoggingConfiguration": {
                        "LogDestinationConfigs": [] if bad else ["arn:aws:firehose:us-east-1:123456789012:deliverystream/regional"]}}}
        extras = {"waf_account_acl_inventory": [{"AccountId": ACCOUNT, "AllEnabledRegionsCollected": True,
                     "RegionalClassic": [regional], "WAFv2": []}]}
        kind = "waf_web_acl"
    elif cid == "aws_logging_service_multi_az":
        row = {"DomainName": "siem", "Domain": {"collection_status": "collected", "DomainStatus": {
            "ARN": SIEM_ARN, "DomainName": "siem", "ClusterConfig": {"ZoneAwarenessEnabled": True,
                "ZoneAwarenessConfig": {"AvailabilityZoneCount": 1 if bad else 2}}}}}
        policy = {"siem_domain_arn": SIEM_ARN}
        kind = "opensearch_domain"
    elif cid == "aws_nist_opensearch_domain_logs_to_cloudwatch":
        row = {"DomainName": "siem", "Domain": {"collection_status": "collected", "DomainStatus": {
            "ARN": SIEM_ARN, "DomainName": "siem", "LogPublishingOptions": {"AUDIT_LOGS": {
                "Enabled": not bad, "CloudWatchLogsLogGroupArn": f"arn:aws:logs:{REGION}:{ACCOUNT}:log-group:audit"}}}}}
        policy = {"required_opensearch_log_types": ["AUDIT_LOGS"]}
        kind = "opensearch_domain"
    elif cid == "aws_resource_priority_tags_present":
        row = {"ResourceArn": f"arn:aws:ec2:{REGION}:{ACCOUNT}:instance/i-abc", "SourceKind": "instance",
               "AccountId": ACCOUNT,
               "Tags": {"classification": "confidential", "priority": "" if bad else "critical"}}
        policy = {"classification_tag_keys": ["classification"], "priority_tag_keys": ["priority"],
                  "allowed_classification_values": ["confidential"], "allowed_priority_values": ["critical"]}
        kind = "aws_tagged_resource"
    elif cid == "aws_nist_elasticache_redis_cluster_automatic_backup_retention_15_days":
        row = {"ARN": f"arn:aws:elasticache:{REGION}:{ACCOUNT}:replicationgroup:cache",
               "Engine": "redis", "SnapshotRetentionLimit": 7 if bad else 15}
        kind = "elasticache_replication_group"
    elif cid == "aws_nist_autoscaling_use_multiple_instance_types_in_multiple_az":
        row = {"AutoScalingGroupARN": f"arn:aws:autoscaling:{REGION}:{ACCOUNT}:autoScalingGroup:abc:autoScalingGroupName/a",
               "AvailabilityZones": ["us-east-1a", "us-east-1b"],
               "MixedInstancesPolicy": {"collection_status": "collected",
                   "EffectiveInstanceTypes": ["m5.large"] if bad else ["m5.large", "m6i.large"]}}
        kind = "autoscaling_group"
    else:
        raise AssertionError(cid)
    covered = ["instance", "bucket", "rds_db_instance", "lambda_function"] if kind == "aws_tagged_resource" else None
    snapshot = index(kind, row, scope=scope, extras=extras, policy=policy, covered=covered)
    if cid in {"aws.nist.waf_classic_regional_acl_logging", "aws_nist_waf_web_acl_logging_enabled",
               "aws.nist.sc_8_coverage", "aws.nist.sc_8_1_coverage",
               "aws_logging_service_multi_az"}:
        return snapshot["context"], snapshot
    return row, snapshot


IDS = list(sw38.SPECS)


@pytest.mark.parametrize("cid", IDS)
def test_signed_metadata_and_pass_fail(cid):
    good, good_index = case(cid)
    bad, bad_index = case(cid, bad=True)
    assert evaluate_check(cid, good, good_index)[0] == "PASS"
    assert evaluate_check(cid, bad, bad_index)[0] == "FAIL"


@pytest.mark.parametrize("cid", IDS)
def test_unknown_incomplete_malformed_and_missing_fact(cid):
    row, snapshot = case(cid)
    incomplete_kind = ("waf_account_acl_inventory" if cid == "aws.nist.waf_classic_regional_acl_logging"
                       else sw38.SPECS[cid]["kind"])
    snapshot["collections"][incomplete_kind][0]["status"] = "partial"
    assert evaluate_check(cid, row, snapshot)[0] == "UNKNOWN"
    row, snapshot = case(cid)
    row["collection_status"] = "malformed"
    assert evaluate_check(cid, row, snapshot)[0] == "UNKNOWN"
    row, snapshot = case(cid)
    row.pop(next(iter(row)))
    assert evaluate_check(cid, row, snapshot)[0] == "UNKNOWN"
    row, snapshot = case(cid)
    snapshot["context"]["provider"] = "azure"
    assert evaluate_check(cid, row, snapshot)[0] == "UNKNOWN"


def test_not_applicable_branches():
    cid = "aws.nist.sc_8_coverage"
    row, snapshot = case(cid)
    snapshot["transport_endpoint"][0]["data"]["External"] = False
    assert evaluate_check(cid, row, snapshot)[0] == "NOT_APPLICABLE"
    cid = "aws_logging_service_multi_az"
    row, snapshot = case(cid)
    snapshot["context"]["metadata"]["sw38_policy"]["siem_domain_arn"] = f"arn:aws:es:{REGION}:{ACCOUNT}:domain/other"
    assert evaluate_check(cid, row, snapshot)[0] == "UNKNOWN"
    cid = "aws_nist_elasticache_redis_cluster_automatic_backup_retention_15_days"
    row, snapshot = case(cid)
    row["Engine"] = "memcached"
    assert evaluate_check(cid, row, snapshot)[0] == "NOT_APPLICABLE"
    cid = "aws.nist.waf_classic_regional_acl_logging"
    row, snapshot = case(cid)
    snapshot["waf_account_acl_inventory"][0]["data"]["RegionalClassic"] = []
    assert evaluate_check(cid, row, snapshot)[0] == "NOT_APPLICABLE"


@pytest.mark.parametrize("cid", IDS)
def test_missing_decision_fact_is_unknown(cid):
    subject, snapshot = case(cid)
    native = snapshot[sw38.SPECS[cid]["kind"]][0]["data"]
    if cid.startswith("aws_cloudwatchlogs_"):
        native.pop("CloudTrailDataEvents")
    elif cid == "aws.pci.s3.allowed_policy_principals":
        native["Policy"]["collection_status"] = "denied"
    elif cid == "aws.pci.s3.bucket_backup_plan":
        snapshot["collections"].pop("s3_backup_plan_coverage")
    elif cid == "aws_cis_s3_macie_classification_coverage":
        snapshot["collections"].pop("s3_macie_region_coverage")
    elif cid == "aws_nist_vpc_igw_attached_to_authorized_vpc":
        native.pop("Attachments")
    elif cid.startswith("aws.nist.sc_8"):
        native.pop("TLSPolicy")
    elif cid in {"aws.nist.waf_classic_regional_acl_logging", "aws_nist_waf_web_acl_logging_enabled"}:
        snapshot["collections"].pop("waf_account_acl_inventory")
    elif cid == "aws_logging_service_multi_az":
        native.pop("Domain")
    elif cid == "aws_nist_opensearch_domain_logs_to_cloudwatch":
        native["Domain"]["DomainStatus"].pop("LogPublishingOptions")
    elif cid == "aws_resource_priority_tags_present":
        native.pop("Tags")
    elif cid == "aws_nist_elasticache_redis_cluster_automatic_backup_retention_15_days":
        native.pop("Engine")
    elif cid == "aws_nist_autoscaling_use_multiple_instance_types_in_multiple_az":
        native["MixedInstancesPolicy"].pop("EffectiveInstanceTypes")
    assert evaluate_check(cid, subject, snapshot)[0] == "UNKNOWN"


def test_macie_includes_minus_excludes_and_unresolved_criteria():
    cid = "aws_cis_s3_macie_classification_coverage"
    row, snapshot = case(cid, bad=True)
    regional = snapshot["s3_macie_region_coverage"][0]["data"]["Regions"][0]
    includes = {"and": [{"simpleCriterion": {"key": "S3_BUCKET_NAME", "comparator": "EQ", "values": [BUCKET]}}]}
    excludes = {"and": [{"simpleCriterion": {"key": "S3_BUCKET_NAME", "comparator": "EQ", "values": ["other-bucket"]}}]}
    regional["Jobs"] = {"collection_status": "collected", "items": [{"jobStatus": "COMPLETE",
        "s3JobDefinition": {"bucketCriteria": {"includes": includes, "excludes": excludes}}}]}
    assert evaluate_check(cid, row, snapshot)[0] == "PASS"
    excludes["and"][0]["simpleCriterion"]["values"] = [BUCKET]
    assert evaluate_check(cid, row, snapshot)[0] == "FAIL"
    regional["Jobs"]["items"][0]["s3JobDefinition"]["bucketCriteria"]["includes"] = {
        "and": [{"tagCriterion": {"comparator": "EQ", "tagValues": [{"key": "team", "value": "a"}]}}]}
    assert evaluate_check(cid, row, snapshot)[0] == "UNKNOWN"


def test_backup_wildcard_and_redis_omission_boundaries():
    cid = "aws.pci.s3.bucket_backup_plan"
    row, snapshot = case(cid, bad=True)
    snapshot["s3_backup_plan_coverage"][0]["data"]["Selections"][0]["Resources"] = ["*"]
    assert evaluate_check(cid, row, snapshot)[0] == "UNKNOWN"
    cid = "aws_nist_elasticache_redis_cluster_automatic_backup_retention_15_days"
    row, snapshot = case(cid)
    row.pop("SnapshotRetentionLimit")
    assert evaluate_check(cid, row, snapshot)[0] == "UNKNOWN"
    row["_provenance"] = {"operation": "elasticache:DescribeReplicationGroups", "native_response_complete": True}
    assert evaluate_check(cid, row, snapshot)[0] == "FAIL"


def test_scope_checks_handle_empty_native_resource_inventory():
    cid = "aws.nist.waf_classic_regional_acl_logging"
    subject, snapshot = case(cid, bad=True)
    snapshot["waf_web_acl"] = []
    snapshot["collections"]["waf_web_acl"][0]["items"] = []
    snapshot["collections"]["waf_web_acl"][0]["status"] = "empty"
    assert evaluate_check(cid, subject, snapshot)[0] == "FAIL"
    cid = "aws_logging_service_multi_az"
    subject, snapshot = case(cid)
    snapshot["opensearch_domain"] = []
    snapshot["collections"]["opensearch_domain"][0]["items"] = []
    snapshot["collections"]["opensearch_domain"][0]["status"] = "empty"
    assert evaluate_check(cid, subject, snapshot)[0] == "UNKNOWN"


def test_scope_only_not_applicable_contexts():
    global_target = {"provider": "aws", "scope": GLOBAL}
    global_index = {"context": global_target, "collections": {}}
    assert evaluate_check("aws_logging_service_multi_az", global_target, global_index)[0] == "NOT_APPLICABLE"
    regional_target = {"provider": "aws", "scope": REGIONAL}
    regional_index = {"context": regional_target, "collections": {}}
    for cid in ("aws.nist.waf_classic_regional_acl_logging", "aws_nist_waf_web_acl_logging_enabled"):
        assert evaluate_check(cid, regional_target, regional_index)[0] == "NOT_APPLICABLE"
