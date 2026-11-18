"""CloudTrail captured-time and joined-bucket predicates, all offline."""
from __future__ import annotations

from datetime import datetime, timedelta

from . import register, result, unknown
from .facts import get, list_of_objects
from .fixtures import CASES
from .aws_a_facts import captured_clock, complete_items, scope_fixture

NATIVE_IDS = []


@register("aws.a.cloudtrail.insights_logging_trail", "aws", "hardening", "cloudtrail", "Logging CloudTrail trail has Insights selectors",
    "medium", "AU-6", "Configure appropriate Insights selectors for the logging trail.")
def insights(item, index):
    logging = get(item, "Status.IsLogging", bool)
    if not logging:
        return "NOT_APPLICABLE", {"is_logging": False, "reason": "Pinned predicate evaluates only logging trails"}
    config = get(item, "InsightSelectors", dict)
    if config.get("collection_status") == "empty" and config.get("absent") is True:
        return result(True, insight_selectors="absent")
    selectors = list_of_objects(get(config, "InsightSelectors", list))
    return result(not bool(selectors), insight_selectors=selectors)
CASES["aws.a.cloudtrail.insights_logging_trail"] = {"pass": {"Status": {"IsLogging": True}, "InsightSelectors": {"InsightSelectors": [{"InsightType": "ApiCallRateInsight"}]}},
    "fail": {"Status": {"IsLogging": True}, "InsightSelectors": {"collection_status": "empty", "absent": True}}, "missing": {}, "malformed": None,
    "not_applicable": {"Status": {"IsLogging": False}}}
NATIVE_IDS.append("aws.a.cloudtrail.insights_logging_trail")


@register("aws.a.cloudtrail.cloudwatch_delivery_24h", "aws", "hardening", "cloudtrail", "CloudTrail has delivered to CloudWatch within the captured prior 24 hours",
    "medium", "AU-2", "Review CloudWatch delivery configuration and errors against the captured observation time.")
def delivery(item, index):
    get(item, "Name", str)
    status = get(item, "Status", dict)
    if "LatestCloudWatchLogsDeliveryTime" not in status:
        if status.get("collection_status") == "collected":
            return result(True, latest_cloudwatch_delivery="absent", reason="Successful native status retrieval reported no delivery time")
        return unknown("latest CloudWatch delivery fact unavailable")
    stamp = get(status, "LatestCloudWatchLogsDeliveryTime", str)
    delivered = datetime.fromisoformat(stamp.replace("Z", "+00:00"))
    if delivered.tzinfo is None:
        return unknown("delivery timestamp lacks timezone")
    observed = captured_clock(item, index)
    age = observed - delivered
    if age < timedelta(0):
        return unknown("delivery timestamp is later than captured observation")
    return result(age > timedelta(days=1), latest_cloudwatch_delivery=stamp, observed_at=observed.isoformat(), maximum_age_hours=24)
CASES["aws.a.cloudtrail.cloudwatch_delivery_24h"] = {"pass": {"Name": "audit", "Status": {"LatestCloudWatchLogsDeliveryTime": "2026-10-09T12:00:00+00:00"}},
    "fail": {"Name": "audit", "Status": {"LatestCloudWatchLogsDeliveryTime": "2026-10-08T12:00:00+00:00"}}, "missing": {}, "malformed": None,
    "index": {"context": {"created_at": "2026-10-10T12:00:00+00:00"}}}
NATIVE_IDS.append("aws.a.cloudtrail.cloudwatch_delivery_24h")


def trail_bucket(item, index):
    name = get(item, "S3BucketName", str)
    scope = get(index, "context.scope", str)
    rows = complete_items(index, "bucket", scope)
    matches = [row for row in rows if get(row, "Name", str) == name]
    if not matches:
        return None
    if len(matches) != 1:
        raise ValueError("ambiguous trail bucket")
    return matches[0]


@register("aws.a.cloudtrail.bucket_mfa_delete", "aws", "hardening", "cloudtrail", "Logging CloudTrail trail's in-scope bucket has MFA Delete enabled",
    "medium", "AU-9", "Review MFA Delete on the trail bucket; an unreadable destination remains UNKNOWN.", dependencies=["cloudtrail", "bucket"])
def bucket_mfa(item, index):
    logging = get(item, "Status.IsLogging", bool)
    if not logging:
        return "NOT_APPLICABLE", {"is_logging": False}
    bucket = trail_bucket(item, index)
    if bucket is None:
        return "MANUAL", {"reason": "CloudTrail destination bucket is outside the collected account; review its owner-account evidence", "bucket": get(item, "S3BucketName", str), "required_actions": ["s3:GetBucketLogging", "s3:GetBucketVersioning"]}
    config = get(bucket, "Versioning", dict)
    if "MFADelete" not in config:
        if config.get("collection_status") == "collected":
            return result(True, mfa_delete="not_reported")
        return unknown("MFA Delete fact unavailable")
    state = get(config, "MFADelete", str)
    if state not in {"Enabled", "Disabled"}:
        return unknown("unrecognized MFA Delete state")
    return result(state != "Enabled", mfa_delete=state)
BUCKET_MFA_GOOD = {"Name": "audit-bucket", "Versioning": {"MFADelete": "Enabled"}}
BUCKET_MFA_BAD = {"Name": "audit-bucket", "Versioning": {"MFADelete": "Disabled"}}
CASES["aws.a.cloudtrail.bucket_mfa_delete"] = {"pass": {"Status": {"IsLogging": True}, "S3BucketName": "audit-bucket"}, "fail": {"Status": {"IsLogging": True}, "S3BucketName": "audit-bucket"},
    "missing": {}, "malformed": None, "index": {**scope_fixture("bucket", [BUCKET_MFA_GOOD]), "context": {"scope": "123456789012/us-east-1"}},
    "fail_index": {**scope_fixture("bucket", [BUCKET_MFA_BAD]), "context": {"scope": "123456789012/us-east-1"}}, "not_applicable": {"Status": {"IsLogging": False}}}
NATIVE_IDS.append("aws.a.cloudtrail.bucket_mfa_delete")


@register("aws.a.cloudtrail.bucket_access_logging", "aws", "hardening", "cloudtrail", "Named CloudTrail trail's in-scope bucket has server access logging",
    "medium", "AU-2", "Configure bucket access logging; an unreadable destination remains UNKNOWN.", dependencies=["cloudtrail", "bucket"])
def bucket_logging(item, index):
    get(item, "Name", str)
    bucket = trail_bucket(item, index)
    if bucket is None:
        return "MANUAL", {"reason": "CloudTrail destination bucket is outside the collected account; review its owner-account evidence", "bucket": get(item, "S3BucketName", str), "required_actions": ["s3:GetBucketLogging", "s3:GetBucketVersioning"]}
    config = get(bucket, "Logging", dict)
    if "LoggingEnabled" not in config:
        if config.get("collection_status") == "collected":
            return result(True, bucket_logging="absent")
        return unknown("bucket logging fact unavailable")
    target = get(config, "LoggingEnabled.TargetBucket", str)
    return result(not bool(target), logging_target=target)
BUCKET_LOG_GOOD = {"Name": "audit-bucket", "Logging": {"LoggingEnabled": {"TargetBucket": "access-logs"}}}
BUCKET_LOG_BAD = {"Name": "audit-bucket", "Logging": {"collection_status": "collected"}}
CASES["aws.a.cloudtrail.bucket_access_logging"] = {"pass": {"Name": "audit", "S3BucketName": "audit-bucket"}, "fail": {"Name": "audit", "S3BucketName": "audit-bucket"},
    "missing": {}, "malformed": None, "index": {**scope_fixture("bucket", [BUCKET_LOG_GOOD]), "context": {"scope": "123456789012/us-east-1"}},
    "fail_index": {**scope_fixture("bucket", [BUCKET_LOG_BAD]), "context": {"scope": "123456789012/us-east-1"}}}
NATIVE_IDS.append("aws.a.cloudtrail.bucket_access_logging")
