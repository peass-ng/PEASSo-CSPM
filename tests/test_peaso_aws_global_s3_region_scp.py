"""Account-wide S3 reads under an organization SCP that denies most regions.

Enabled regions are sorted, so the first one (ap-northeast-1 here) is often a
region an SCP denies. Account-wide S3 and S3 Control reads must still be made
from a region the account allows.
"""
import boto3
from botocore.exceptions import ClientError

from peaso.collectors import aws
from peaso.engine import evaluate_snapshot

ACCOUNT = "123456789012"
ALLOWED = {"us-east-1", "us-west-2"}
ENABLED = ["ap-northeast-1", "eu-west-1", "us-east-1", "us-west-2"]
BUCKET = "fixture-bucket"
ACCOUNT_PAB_CHECKS = ["aws.claude_a.s3.account_public_access_block_all"]


def error(code, operation, status=403):
    return ClientError({"Error": {"Code": code, "Message": "fixture"},
                        "ResponseMetadata": {"HTTPStatusCode": status}}, operation)


def fake_cloud(monkeypatch, *, allowed=ALLOWED, bucket_region="us-west-2", account_pab=None):
    calls = []

    def call(self, session, service, region, operation, **arguments):
        calls.append((service, region, operation))
        if service == "sts" and operation == "get_caller_identity":
            return {"Account": ACCOUNT, "Arn": f"arn:aws:sts::{ACCOUNT}:assumed-role/audit/session", "UserId": "audit"}
        if service == "ec2" and operation == "describe_regions":
            return {"Regions": [{"RegionName": name, "OptInStatus": "opt-in-not-required"} for name in ENABLED]}
        if region not in allowed:
            raise error("AccessDenied", operation)
        if (service, operation) == ("s3", "list_buckets"):
            return {"Buckets": [{"Name": BUCKET}]}
        if (service, operation) == ("s3", "get_bucket_location"):
            return {"LocationConstraint": None if bucket_region == "us-east-1" else bucket_region}
        if (service, operation) == ("s3control", "get_public_access_block"):
            if account_pab is None:
                raise error("NoSuchPublicAccessBlockConfiguration", operation, 404)
            return {"PublicAccessBlockConfiguration": account_pab}
        if (service, operation) == ("s3control", "list_access_points"):
            return {"AccessPointList": []}
        if service == "s3":
            if region != bucket_region:
                raise error("AccessDenied", operation)
            if operation == "get_public_access_block":
                raise error("NoSuchPublicAccessBlockConfiguration", operation, 404)
            return {}
        raise error("AccessDenied", operation)

    session = boto3.Session(aws_access_key_id="fixture", aws_secret_access_key="fixture", region_name="us-east-1")
    monkeypatch.setattr(aws, "_session", lambda auth, region: (session, "fixture"))
    monkeypatch.setattr(aws.Requests, "call", call)
    return calls


def collect(kinds):
    connector = {"provider": "aws", "scopes": [ACCOUNT], "options": {"service_concurrency": 1, "retry_attempts": 1}}
    snapshot = aws.collect(connector, kinds)
    return snapshot, {(c["type"], c["scope"]): c for c in snapshot["collections"]}


def test_account_wide_s3_reads_succeed_when_first_enabled_region_is_denied(monkeypatch):
    fake_cloud(monkeypatch)
    _, rows = collect(["bucket", "s3_account_public_access_block"])
    buckets = rows[("bucket", f"{ACCOUNT}/global")]
    assert buckets["status"] == "collected"
    assert [item["Name"] for item in buckets["items"]] == [BUCKET]
    assert rows[("s3_account_public_access_block", f"{ACCOUNT}/global")]["status"] in {"collected", "empty"}


def test_missing_account_public_access_block_is_a_failure_not_an_error(monkeypatch):
    fake_cloud(monkeypatch)
    snapshot, rows = collect(["bucket", "s3_account_public_access_block", "aws_account"])
    assert rows[("s3_account_public_access_block", f"{ACCOUNT}/global")]["status"] == "empty"
    findings = evaluate_snapshot(snapshot, checks=ACCOUNT_PAB_CHECKS)["findings"]
    assert [f["status"] for f in findings] == ["FAIL"]


def test_configured_account_public_access_block_passes(monkeypatch):
    fake_cloud(monkeypatch, account_pab={name: True for name in (
        "BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets")})
    snapshot, _ = collect(["bucket", "s3_account_public_access_block", "aws_account"])
    findings = evaluate_snapshot(snapshot, checks=ACCOUNT_PAB_CHECKS)["findings"]
    assert [f["status"] for f in findings] == ["PASS"]


def test_falls_back_across_scanned_regions_when_home_region_is_denied(monkeypatch):
    fake_cloud(monkeypatch, allowed={"eu-west-1"}, bucket_region="eu-west-1")
    _, rows = collect(["bucket", "s3_account_public_access_block"])
    assert rows[("bucket", f"{ACCOUNT}/global")]["status"] == "collected"
    assert rows[("s3_account_public_access_block", f"{ACCOUNT}/global")]["status"] == "empty"


def test_bucket_in_denied_region_keeps_inventory_and_marks_only_its_fields(monkeypatch):
    fake_cloud(monkeypatch, bucket_region="eu-west-1")
    _, rows = collect(["bucket"])
    buckets = rows[("bucket", f"{ACCOUNT}/global")]
    assert buckets["status"] == "collected"
    [item] = buckets["items"]
    assert item["PolicyStatus"].get("collection_status") == "denied"


def test_every_region_denied_stays_denied(monkeypatch):
    fake_cloud(monkeypatch, allowed=set())
    _, rows = collect(["bucket", "s3_account_public_access_block"])
    assert rows[("bucket", f"{ACCOUNT}/global")]["status"] == "denied"
    assert rows[("s3_account_public_access_block", f"{ACCOUNT}/global")]["status"] == "denied"


def test_access_points_are_read_in_each_allowed_region(monkeypatch):
    fake_cloud(monkeypatch)
    _, rows = collect(["s3_access_point"])
    statuses = {region: rows[("s3_access_point", f"{ACCOUNT}/{region}")]["status"] for region in ENABLED}
    assert statuses == {"ap-northeast-1": "denied", "eu-west-1": "denied", "us-east-1": "empty", "us-west-2": "empty"}
