"""An S3 bucket policy read from several Regions is one blocked or exposed grant."""
from peaso.analysis import analyze
from peaso.snapshot import make_snapshot

ACCOUNT = "111122223333"
REGIONS = ("eu-west-1", "us-east-1", "us-west-2")
ARN = "arn:aws:s3:::b"
POLICY = {"Version": "2012-10-17", "Statement": [
    {"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject", "Resource": ARN + "/*"}]}
ALL_BLOCKED = {"BlockPublicAcls": True, "IgnorePublicAcls": True, "BlockPublicPolicy": True, "RestrictPublicBuckets": True}


def _policy_copy(region):
    row = {"ResourceArn": ARN, "Policy": POLICY, "_provenance": {
        "read_only": True, "owner_account": ACCOUNT, "source_region": region, "collection_region": region,
        "families": ["s3-buckets"], "source_operations": ["s3:get_bucket_policy"]}}
    return {"type": "aws_resource_policy", "scope": f"{ACCOUNT}/{region}", "service": "s3",
            "status": "collected", "items": [row]}


def _generic_grants(bucket_block):
    bucket = {"Name": "b", "Policy": {"collection_status": "collected", "Policy": POLICY},
              "PolicyStatus": {"collection_status": "collected", "PolicyStatus": {"IsPublic": True}},
              "Acl": {"collection_status": "collected", "Grants": []},
              "PublicAccessBlock": ({"collection_status": "collected", "PublicAccessBlockConfiguration": bucket_block}
                                    if bucket_block else {"collection_status": "empty", "absent": True})}
    collections = [
        {"type": "bucket", "scope": f"{ACCOUNT}/global", "service": "s3", "status": "collected", "items": [bucket]},
        {"type": "s3_account_public_access_block", "scope": f"{ACCOUNT}/global", "service": "s3control",
         "status": "empty", "items": []},
        *(_policy_copy(region) for region in REGIONS)]
    snapshot = make_snapshot("aws", [f"{ACCOUNT}/{region}" for region in REGIONS], collections,
                             created_at="2026-10-10T00:00:00+00:00")
    return [f for f in analyze(snapshot)["findings"] if f["check_id"] == "analysis.internet_exposure"
            and f["evidence"].get("exposure_kind") == "external_generic_policy_grant"]


def test_public_bucket_policy_in_every_region_is_one_failure():
    found = _generic_grants(None)
    assert [f["status"] for f in found] == ["FAIL"]


def test_restrict_public_buckets_blocks_the_wildcard_bucket_grant():
    assert _generic_grants(ALL_BLOCKED) == []
    assert [f["status"] for f in _generic_grants({**ALL_BLOCKED, "RestrictPublicBuckets": False})] == ["FAIL"]
