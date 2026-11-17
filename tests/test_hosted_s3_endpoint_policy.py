"""The hosted S3 gateway endpoint must not deny reads the collector issues.

In-Region bucket reads from the hosted tasks traverse the endpoint; an action
missing from its policy turns into AccessDenied (UNKNOWN checks) in production
only, while the same customer role reads it fine from anywhere else.
"""
from pathlib import Path
import re

from peaso.collectors.aws import READ_ACTIONS

# S3 API operation -> IAM action that authorizes it (differs from the API name).
IAM_ACTION = {
    "list_buckets": "s3:ListAllMyBuckets",
    "get_bucket_location": "s3:GetBucketLocation",
    "get_public_access_block": "s3:GetBucketPublicAccessBlock",
    "get_bucket_policy_status": "s3:GetBucketPolicyStatus",
    "get_bucket_policy": "s3:GetBucketPolicy",
    "get_bucket_encryption": "s3:GetEncryptionConfiguration",
    "get_bucket_versioning": "s3:GetBucketVersioning",
    "get_bucket_acl": "s3:GetBucketAcl",
    "get_bucket_ownership_controls": "s3:GetBucketOwnershipControls",
    "get_bucket_logging": "s3:GetBucketLogging",
    "get_bucket_lifecycle_configuration": "s3:GetLifecycleConfiguration",
    "get_bucket_notification_configuration": "s3:GetBucketNotification",
    "get_bucket_replication": "s3:GetReplicationConfiguration",
    "get_object_lock_configuration": "s3:GetBucketObjectLockConfiguration",
    "get_bucket_tagging": "s3:GetBucketTagging",
    "get_bucket_website": "s3:GetBucketWebsite",
    "list_objects_v2": "s3:ListBucket",
    "get_object": "s3:GetObject",
    "head_object": "s3:GetObject",
    "get_object_acl": "s3:GetObjectAcl",
    # S3 Express directory buckets use the s3express endpoint, not this one.
    "list_directory_buckets": None,
}


def _customer_actions():
    text = Path(__file__).resolve().parents[1].joinpath("infra/aws/network.tf").read_text()
    block = text[text.index('resource "aws_vpc_endpoint" "s3"'):]
    block = block[:block.index("\nresource ")]
    statements = re.findall(r"\{([^{}]*)\}", block)
    wildcard = [s for s in statements if re.search(r'Resource\s*=\s*"\*"', s)]
    return {action for s in wildcard for action in re.findall(r'"(s3:[A-Za-z]+)"', s)}


def test_endpoint_allows_every_s3_read_the_collector_issues():
    allowed = _customer_actions()
    operations = sorted(op for service, op in READ_ACTIONS if service == "s3")
    unmapped = [op for op in operations if op not in IAM_ACTION]
    assert not unmapped, f"map these S3 operations to their IAM action: {unmapped}"
    missing = {op: IAM_ACTION[op] for op in operations if IAM_ACTION[op] and IAM_ACTION[op] not in allowed}
    assert not missing, f"hosted S3 endpoint denies collector reads: {missing}"


def test_selected_object_versions_are_readable_through_the_endpoint():
    # Selected leak sources may pin a VersionId, which S3 authorizes separately.
    assert "s3:GetObjectVersion" in _customer_actions()
