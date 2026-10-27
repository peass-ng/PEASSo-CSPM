"""claude_aws_a S3 predicates (Steampipe aws-compliance / aws-perimeter and Prowler).

Bucket facts are the collector's ``bucket`` detail responses (PublicAccessBlock, PolicyStatus, Policy, Encryption,
Versioning, Acl, OwnershipControls, Logging, Lifecycle, Notifications, Replication, ObjectLock, Location). A detail
whose read failed (denied/throttled/malformed) is UNKNOWN; a documented absent-configuration error code
(``{"collection_status": "empty", "absent": true}``) is the source's "not configured" value. Facts the collector does
not gather yet (website configuration, access points, multi-Region access points, directory buckets, Macie jobs) are
read from documented fields/kinds and are UNKNOWN until collected (see COLLECTOR FACTS NEEDED).
"""
from __future__ import annotations

import re

from . import result
from .facts import Unavailable, get, guard, list_of_objects, optional
from .claude_aws_a_common import (install, items, idx, account, region, strings, as_list, policy_document, turbot_public_statements,
                                  is_policy_public, _conditions, C, P, R, ACCOUNT)
from .claude_aws_a_ec2 import w, DROP, partition
from .claude_aws_a_iam import std

S3API = "https://docs.aws.amazon.com/AmazonS3/latest/API/"
S3UG = "https://docs.aws.amazon.com/AmazonS3/latest/userguide/"
# GetBucketLocation response values, AWS API reference reviewed 2026-10-17.
# us-east-1 is represented by null/omission, and EU aliases eu-west-1.
S3_LOCATION_CONSTRAINTS = frozenset("""
    af-south-1 ap-east-1 ap-east-2 ap-northeast-1 ap-northeast-2 ap-northeast-3
    ap-south-1 ap-south-2 ap-southeast-1 ap-southeast-2 ap-southeast-3
    ap-southeast-4 ap-southeast-5 ap-southeast-6 ap-southeast-7
    ca-central-1 ca-west-1 cn-north-1 cn-northwest-1 EU
    eu-central-1 eu-central-2 eu-north-1 eu-south-1 eu-south-2
    eu-west-1 eu-west-2 eu-west-3 il-central-1 me-central-1 me-south-1
    mx-central-1 sa-east-1 us-east-2 us-gov-east-1 us-gov-west-1
    us-west-1 us-west-2
""".split())
FSBP = "https://docs.aws.amazon.com/securityhub/latest/userguide/s3-controls.html"
BLOCKS = ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets")
ALL_USERS = "http://acs.amazonaws.com/groups/global/AllUsers"
AUTH_USERS = "http://acs.amazonaws.com/groups/global/AuthenticatedUsers"
OWNER = "a" * 64
ABSENT = {"collection_status": "empty", "absent": True}


_S3_DETAIL_PAYLOAD_KEYS = {
    "PublicAccessBlock": ("PublicAccessBlockConfiguration",),
    "Policy": ("Policy",),
    "Encryption": ("ServerSideEncryptionConfiguration",),
    "Lifecycle": ("Rules",),
    "Replication": ("ReplicationConfiguration",),
    "ObjectLock": ("ObjectLockConfiguration",),
    "OwnershipControls": ("OwnershipControls",),
    "PolicyStatus": ("PolicyStatus",),
    "Website": ("IndexDocument", "ErrorDocument", "RedirectAllRequestsTo", "RoutingRules"),
    "Tags": ("TagSet",),
}


def section(item, key):
    """Collected detail response, or None when the source's documented absent-configuration code was returned."""
    value = get(item, key, dict)
    if optional(value, "collection_status", None, str) == "empty":
        if get(value, "absent", bool) is not True:
            raise Unavailable("unproven empty detail: " + key)
        coverage = value.get("_coverage", {})
        for field in _S3_DETAIL_PAYLOAD_KEYS.get(key, ()):
            if field in value:
                raise Unavailable("empty detail retains native configuration payload: " + key)
            if field in coverage:
                entry = coverage[field]
                if not isinstance(entry, dict) or entry.get("status") != "empty":
                    raise Unavailable("empty detail contradicts native payload coverage: " + key)
        return None
    return value


def blocks(config):
    """Public Access Block flags of a GetPublicAccessBlock response (absent configuration: all false)."""
    if config is None:
        return {k: False for k in BLOCKS}
    values = get(config, "PublicAccessBlockConfiguration", dict)
    return {k: get(values, k, bool) for k in BLOCKS}


def bucket_blocks(item):
    return blocks(section(item, "PublicAccessBlock"))


def account_blocks(index):
    # Validate the complete native response rows before any wrapper deduplication.
    from .aws_a_facts import complete_items as native_items
    scope = index.get("context", {}).get("scope")
    rows = native_items(index, "s3_account_public_access_block", scope=scope if isinstance(scope, str) else None)
    if len(rows) > 1:
        raise Unavailable("ambiguous account public access block")
    if not rows:
        for envelope in index["collections"]["s3_account_public_access_block"]:
            error = optional(envelope, "error", None)
            if error is not None and get(error, "code", str) != "NoSuchPublicAccessBlockConfiguration":
                raise Unavailable("account block absence contradicts source error")
        return {k: False for k in BLOCKS}
    row = rows[0]
    if "AccountId" in row or "AccountId" in row.get("_coverage", {}):
        if get(row, "AccountId", str) != account(index):
            raise Unavailable("account public access block identity mismatch")
    if optional(row, "collection_status", None, str) == "empty":
        if get(row, "absent", bool) is not True or "PublicAccessBlockConfiguration" in row:
            raise Unavailable("unproven or contradictory account block absence")
        return {k: False for k in BLOCKS}
    return blocks(row)


def bucket_policy(item):
    """Parsed bucket policy document or None (NoSuchBucketPolicy)."""
    value = section(item, "Policy")
    if value is None:
        return None
    policy = get(value, "Policy", dict)
    return policy


def statements(item):
    policy = bucket_policy(item)
    return [] if policy is None else policy_document(policy)


def grants(item):
    return list_of_objects(get(item, "Acl.Grants", list))


def grant_uri(grant):
    grantee = get(grant, "Grantee", dict)
    return optional(grantee, "URI", None, str)


def versioning_enabled(item):
    value = get(item, "Versioning", dict)
    status = optional(value, "Status", None, str)
    if status not in (None, "Enabled", "Suspended"):
        raise Unavailable("unrecognized versioning status")
    return status == "Enabled"


def lifecycle_rules(item):
    value = section(item, "Lifecycle")
    return [] if value is None else list_of_objects(get(value, "Rules", list))


def encryption_rules(item):
    value = section(item, "Encryption")
    return None if value is None else list_of_objects(get(value, "ServerSideEncryptionConfiguration.Rules", list))


def bucket_region(item):
    location = get(item, "Location", dict)
    # GetBucketLocation returns null for us-east-1; the collector can omit it.
    constraint = optional(location, "LocationConstraint", None)
    if constraint is None:
        return "us-east-1"
    if not isinstance(constraint, str) or constraint not in S3_LOCATION_CONSTRAINTS:
        raise Unavailable("unrecognized bucket location constraint")
    return "eu-west-1" if constraint == "EU" else constraint


def bucket_arn(item, index):
    return "arn:%s:s3:::%s" % (partition(index), get(item, "Name", str))


# --------------------------------------------------------------------------- fixtures
GOOD_BLOCK = {"collection_status": "collected", "PublicAccessBlockConfiguration": {k: True for k in BLOCKS}}
OPEN_BLOCK = {"collection_status": "collected", "PublicAccessBlockConfiguration": {k: False for k in BLOCKS}}
OWNER_GRANT = {"Grantee": {"Type": "CanonicalUser", "ID": OWNER}, "Permission": "FULL_CONTROL"}
B = {"Name": "b1", "CreationDate": "2025-01-01T00:00:00+00:00", "Location": {"collection_status": "collected", "LocationConstraint": None},
     "PublicAccessBlock": GOOD_BLOCK, "PolicyStatus": {"collection_status": "collected", "PolicyStatus": {"IsPublic": False}},
     "Policy": ABSENT,
     "Encryption": {"collection_status": "collected", "ServerSideEncryptionConfiguration": {"Rules": [{"ApplyServerSideEncryptionByDefault": {
         "SSEAlgorithm": "aws:kms", "KMSMasterKeyID": "arn:aws:kms:us-east-1:%s:key/k1" % ACCOUNT}, "BucketKeyEnabled": True}]}},
     "Versioning": {"collection_status": "collected", "Status": "Enabled", "MFADelete": "Enabled"},
     "Acl": {"collection_status": "collected", "Owner": {"ID": OWNER}, "Grants": [OWNER_GRANT]},
     "OwnershipControls": {"collection_status": "collected", "OwnershipControls": {"Rules": [{"ObjectOwnership": "BucketOwnerEnforced"}]}},
     "Logging": {"collection_status": "collected", "LoggingEnabled": {"TargetBucket": "logs", "TargetPrefix": "b1/"}},
     "Lifecycle": {"collection_status": "collected", "Rules": [{"ID": "r1", "Status": "Enabled", "Filter": {}}]},
     "Notifications": {"collection_status": "collected", "EventBridgeConfiguration": {}},
     "Replication": {"collection_status": "collected", "ReplicationConfiguration": {"Role": "arn:aws:iam::%s:role/rep" % ACCOUNT,
         "Rules": [{"ID": "rep", "Status": "Enabled", "Destination": {"Bucket": "arn:aws:s3:::b2"}}]}},
     "ObjectLock": {"collection_status": "collected", "ObjectLockConfiguration": {"ObjectLockEnabled": "Enabled"}},
     "Website": ABSENT, "Tags": ABSENT}
B2 = w(B, Name="b2", Location__LocationConstraint="eu-west-1", Replication=ABSENT)
ACCT_OK = {"PublicAccessBlockConfiguration": {k: True for k in BLOCKS}}
ACCT_OPEN = {"PublicAccessBlockConfiguration": {k: False for k in BLOCKS}}
PUBLIC_POLICY = {"collection_status": "collected", "Policy": {"Version": "2012-10-17", "Statement": [
    {"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::b1/*"}]}}
PUBLIC_WRITE_POLICY = {"collection_status": "collected", "Policy": {"Version": "2012-10-17", "Statement": [
    {"Effect": "Allow", "Principal": "*", "Action": "s3:PutObject", "Resource": "arn:aws:s3:::b1/*"}]}}
OWN_POLICY = {"collection_status": "collected", "Policy": {"Version": "2012-10-17", "Statement": [
    {"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::%s:root" % ACCOUNT}, "Action": "s3:*", "Resource": "arn:aws:s3:::b1/*"}]}}
CROSS_POLICY = {"collection_status": "collected", "Policy": {"Version": "2012-10-17", "Statement": [
    {"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::999999999999:root"}, "Action": ["s3:PutBucketPolicy", "s3:GetObject"], "Resource": "arn:aws:s3:::b1"}]}}


def acl_with(uri, permission):
    return {"collection_status": "collected", "Owner": {"ID": OWNER},
            "Grants": [OWNER_GRANT, {"Grantee": {"Type": "Group", "URI": uri}, "Permission": permission}]}


IDX = idx(s3_account_public_access_block=[ACCT_OPEN], bucket=[B, B2])
IDX_ACCOUNT_OK = idx(s3_account_public_access_block=[ACCT_OK], bucket=[B, B2])


# =========================================================================== account / bucket public access block
@install("aws.claude_a.s3.account_public_access_block_all", "s3_account_public_access_block", "S3 account-level Block Public Access enables all four settings",
    {}, {}, target="scope", pass_index=idx(s3_account_public_access_block=[ACCT_OK]),
    fail_index=idx(s3_account_public_access_block=[w(ACCT_OK, PublicAccessBlockConfiguration__RestrictPublicBuckets=False)]),
    rows=[C + "s3_public_access_block_account", C + "foundational_security_s3_1", R + "s3_public_access_block_account"],
    severity="high", category="exposure", control="AC-3", remediation="Enable all four account-level S3 Block Public Access settings.",
    docs=[S3API + "API_control_GetPublicAccessBlock.html", FSBP + "#s3-1"], extra={"fail_absent": ({}, idx(s3_account_public_access_block=[]))},
    note="No account configuration (NoSuchPublicAccessBlockConfiguration) is all-false, as in aws_s3_account_settings. Compliance and perimeter SQL are identical.")
def account_all(context, index):
    flags = account_blocks(index)
    return result(not all(flags.values()), settings=flags)


@install("aws.claude_a.s3.bucket_public_access_block_all", "bucket", "S3 bucket-level Block Public Access enables all four settings",
    B, w(B, PublicAccessBlock=ABSENT), rows=[C + "s3_public_access_block_bucket", C + "foundational_security_s3_8", R + "s3_public_access_block_bucket"],
    severity="high", category="exposure", control="AC-3", remediation="Enable all four bucket-level Block Public Access settings.",
    docs=[S3API + "API_GetPublicAccessBlock.html", FSBP + "#s3-8"], extra={"fail_one": w(B, PublicAccessBlock__PublicAccessBlockConfiguration__IgnorePublicAcls=False)},
    note="Bucket settings only (account settings are not ORed); absent configuration is all-false.")
def bucket_all(item, index):
    flags = bucket_blocks(item)
    return result(not all(flags.values()), settings=flags)


@install("aws.claude_a.s3.prowler_account_ignore_restrict", "s3_account_public_access_block", "S3 account Block Public Access ignores public ACLs and restricts public buckets (Prowler)",
    {}, {}, target="scope", pass_index=idx(s3_account_public_access_block=[ACCT_OK], bucket=[B]),
    fail_index=idx(s3_account_public_access_block=[ACCT_OPEN], bucket=[B]), dependencies=["s3_account_public_access_block", "bucket"],
    rows=[P + "s3_account_level_public_access_blocks"], severity="high", category="exposure", control="AC-3",
    remediation="Enable IgnorePublicAcls and RestrictPublicBuckets at account level.", docs=[S3API + "API_control_GetPublicAccessBlock.html"],
    extra={"na": ({}, idx(s3_account_public_access_block=[ACCT_OPEN], bucket=[]))},
    note="Prowler: not configured fails only when the account has buckets (scan_unused_services default False); otherwise no finding.")
def prowler_account(context, index):
    flags = account_blocks(index)
    if flags["IgnorePublicAcls"] and flags["RestrictPublicBuckets"]:
        return result(False, settings=flags)
    if not items(index, "bucket"):
        return "NOT_APPLICABLE", {"reason": "no buckets (Prowler scan_unused_services disabled)"}
    return result(True, settings=flags)


@install("aws.claude_a.s3.prowler_bucket_level_public_access_block", "bucket", "S3 bucket or account ignores public ACLs and restricts public buckets (Prowler)",
    w(B, PublicAccessBlock=ABSENT), w(B, PublicAccessBlock=ABSENT), index=IDX_ACCOUNT_OK, fail_index=IDX, dependencies=["bucket", "s3_account_public_access_block"],
    rows=[P + "s3_bucket_level_public_access_block"], severity="high", category="exposure", control="AC-3",
    remediation="Enable IgnorePublicAcls and RestrictPublicBuckets on the bucket or the account.", docs=[S3API + "API_GetPublicAccessBlock.html"],
    extra={"pass_bucket": (B, IDX)}, note="Bucket IgnorePublicAcls and RestrictPublicBuckets, else the same two account settings.")
def prowler_bucket_level(item, index):
    flags = bucket_blocks(item)
    if flags["IgnorePublicAcls"] and flags["RestrictPublicBuckets"]:
        return result(False, level="bucket", settings=flags)
    acct = account_blocks(index)
    ok = acct["IgnorePublicAcls"] and acct["RestrictPublicBuckets"]
    return result(not ok, level="account" if ok else None, settings=acct)


# =========================================================================== encryption / versioning / lifecycle / lock / replication
@install("aws.claude_a.s3.default_encryption_kms_key", "bucket", "S3 bucket default encryption names a KMS key",
    B, w(B, Encryption__ServerSideEncryptionConfiguration__Rules=[{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]),
    rows=[C + "s3_bucket_default_encryption_enabled_kms"], severity="medium", control="SC-13",
    remediation="Configure SSE-KMS default encryption with a customer managed key.", docs=[S3API + "API_GetBucketEncryption.html"],
    extra={"fail_absent": w(B, Encryption=ABSENT)}, note="Steampipe: any rule with ApplyServerSideEncryptionByDefault.KMSMasterKeyID (aws:kms without a key id fails).")
def kms_key(item, index):
    rules = encryption_rules(item) or []
    named = []
    unresolved = False
    for rule in rules:
        try:
            default = optional(rule, "ApplyServerSideEncryptionByDefault", None, dict)
            if default is None:
                continue
            key = optional(default, "KMSMasterKeyID", None)
            if key is None:
                continue
            if not isinstance(key, str):
                raise Unavailable("malformed KMS key identifier")
            named.append(key)
        except Unavailable:
            unresolved = True
    if named:
        return result(False, kms_rules=len(named))
    if unresolved:
        raise Unavailable("default encryption key fields unavailable")
    return result(True, kms_rules=0)


@install("aws.claude_a.s3.prowler_kms_encryption", "bucket", "S3 bucket default encryption algorithm is SSE-KMS or DSSE-KMS (Prowler)",
    w(B, Encryption__ServerSideEncryptionConfiguration__Rules=[{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "aws:kms"}}]),
    w(B, Encryption__ServerSideEncryptionConfiguration__Rules=[{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]),
    rows=[P + "s3_bucket_kms_encryption"], severity="medium", control="SC-13", remediation="Use aws:kms or aws:kms:dsse default encryption.",
    docs=[S3API + "API_GetBucketEncryption.html"], extra={"fail_absent": w(B, Encryption=ABSENT)}, note="Prowler reads Rules[0] SSEAlgorithm only.")
def prowler_kms(item, index):
    rules = encryption_rules(item)
    if not rules:
        return result(True, algorithm=None)
    algorithm = get(rules[0], "ApplyServerSideEncryptionByDefault.SSEAlgorithm", str)
    return result(algorithm not in ("aws:kms", "aws:kms:dsse"), algorithm=algorithm)


@install("aws.claude_a.s3.replication_rule_enabled", "bucket", "S3 bucket has an enabled replication rule",
    B, w(B, Replication=ABSENT), rows=[C + "s3_bucket_cross_region_replication_enabled"], severity="low", control="CP-9",
    remediation="Configure replication to a bucket in another Region.", docs=[S3API + "API_GetBucketReplication.html"],
    extra={"fail_disabled": w(B, Replication__ReplicationConfiguration__Rules=[{"ID": "rep", "Status": "Disabled"}])},
    note="Steampipe only requires a replication rule with Status Enabled; the destination Region is not checked.")
def replication_enabled(item, index):
    value = section(item, "Replication")
    rules = [] if value is None else list_of_objects(get(value, "ReplicationConfiguration.Rules", list))
    enabled = []
    unresolved = False
    for rule in rules:
        try:
            status = get(rule, "Status", str)
            if status not in ("Enabled", "Disabled"):
                raise Unavailable("unrecognized replication rule status")
        except Unavailable:
            unresolved = True
            continue
        if status == "Enabled":
            # ID is only an evidence label; status is the Steampipe predicate.
            try:
                label = optional(rule, "ID", None, str)
            except Unavailable:
                label = None
            enabled.append(label)
    if enabled:
        return result(False, enabled_rules=enabled)
    if unresolved:
        raise Unavailable("replication rule status unavailable")
    return result(True, enabled_rules=[])


@install("aws.claude_a.s3.prowler_cross_region_replication", "bucket", "Versioned S3 bucket replicates to a bucket in another Region (Prowler)",
    B, w(B, Replication__ReplicationConfiguration__Rules=[{"ID": "rep", "Status": "Enabled", "Destination": {"Bucket": "arn:aws:s3:::b1copy"}}]),
    index=idx(bucket=[B, B2, w(B2, Name="b1copy", Location__LocationConstraint=None)]), rows=[P + "s3_bucket_cross_region_replication"],
    severity="low", control="CP-9", remediation="Replicate to a destination bucket located in a different Region.", docs=[S3API + "API_GetBucketReplication.html"],
    extra={"fail_unversioned": w(B, Versioning__Status="Suspended"), "fail_none": w(B, Replication=ABSENT)},
    note="PASS > MANUAL (destination outside the collected buckets) > FAIL. A failed versioning or replication read is UNKNOWN (Prowler MANUAL).")
def prowler_replication(item, index):
    versioned = versioning_enabled(item)
    if not versioned:
        return result(True, versioned=False)
    value = section(item, "Replication")
    rules = [] if value is None else list_of_objects(get(value, "ReplicationConfiguration.Rules", list))
    if not rules:
        return result(True, versioned=True, rules=0)
    # Resource wrappers deduplicate identities. This join must see the raw
    # complete source rows to reject conflicting copies of a destination.
    from .aws_a_facts import complete_items as native_items
    context_scope = index.get("context", {}).get("scope")
    by_arn = {}
    for bucket in native_items(index, "bucket", scope=context_scope if isinstance(context_scope, str) else None):
        by_arn.setdefault(bucket_arn(bucket, index), []).append(bucket)
    unresolvable = False
    unresolved = False
    for rule in rules:
        try:
            status = get(rule, "Status", str)
            if status not in ("Enabled", "Disabled"):
                raise Unavailable("unrecognized replication rule status")
            if status == "Disabled":
                continue
            destination = get(rule, "Destination.Bucket", str)
            if not destination:
                raise Unavailable("replication destination bucket unavailable")
        except Unavailable:
            unresolved = True
            continue
        if destination not in by_arn:
            unresolvable = True
            continue
        if len(by_arn[destination]) != 1:
            unresolved = True
            continue
        try:
            if bucket_region(by_arn[destination][0]) != bucket_region(item):
                return result(False, destination=destination)
        except Unavailable:
            unresolved = True
    if unresolved:
        raise Unavailable("replication rule or destination region unavailable")
    if unresolvable:
        return "MANUAL", {"reason": "replication destination bucket is outside the collected inventory"}
    return result(True, versioned=True, rules=len(rules), cross_region_destination_found=False,
                  observed="No enabled replication rule resolves to an observed destination in another Region.")


def _enabled_lifecycle_rules(item):
    enabled, unresolved = [], []
    for rule in lifecycle_rules(item):
        try:
            status = get(rule, "Status", str)
            if status not in ("Enabled", "Disabled"):
                raise Unavailable("unrecognized lifecycle status")
            if status == "Enabled":
                # The optional identifier labels evidence; it does not determine enablement.
                enabled.append(rule.get("ID"))
        except Unavailable as exc:
            unresolved.append(str(exc))
    if not enabled and unresolved:
        raise Unavailable("lifecycle status unavailable: " + "; ".join(unresolved))
    return enabled


@install("aws.claude_a.s3.lifecycle_rule_enabled", "bucket", "S3 bucket has an enabled lifecycle rule",
    B, w(B, Lifecycle=ABSENT), rows=[C + "s3_bucket_lifecycle_policy_enabled", C + "foundational_security_s3_13", P + "s3_bucket_lifecycle_enabled"],
    severity="low", control="CM-6", remediation="Add an enabled lifecycle rule.", docs=[S3API + "API_GetBucketLifecycleConfiguration.html", FSBP + "#s3-13"],
    extra={"fail_disabled": w(B, Lifecycle__Rules=[{"ID": "r1", "Status": "Disabled"}])},
    note="Steampipe and Prowler both pass when any lifecycle rule has Status Enabled.")
def lifecycle(item, index):
    enabled = _enabled_lifecycle_rules(item)
    return result(not enabled, enabled_rules=enabled)


@install("aws.claude_a.s3.versioning_and_lifecycle", "bucket", "Versioned S3 bucket has an enabled lifecycle rule",
    B, w(B, Lifecycle=ABSENT), rows=[C + "s3_bucket_versioning_and_lifecycle_policy_enabled", C + "foundational_security_s3_10"],
    severity="low", control="CP-9", remediation="Enable versioning and add an enabled lifecycle rule.", docs=[S3API + "API_GetBucketVersioning.html", FSBP + "#s3-10"],
    extra={"not_applicable": w(B, Versioning__Status="Suspended")}, note="Only version-enabled buckets apply; an enabled lifecycle rule passes.")
def versioning_lifecycle(item, index):
    versioned = versioning_enabled(item)
    if not versioned:
        return "NOT_APPLICABLE", {"versioning": False}
    enabled = _enabled_lifecycle_rules(item)
    return result(not enabled, versioning=True, enabled_rules=enabled)


@install("aws.claude_a.s3.object_lock_configured", "bucket", "S3 bucket has an Object Lock configuration",
    B, w(B, ObjectLock=ABSENT), rows=[C + "s3_bucket_object_lock_enabled", P + "s3_bucket_object_lock"], severity="low", control="CP-9",
    remediation="Enable Object Lock (set at bucket creation or through supported enablement).", docs=[S3API + "API_GetObjectLockConfiguration.html"],
    note="Both sources pass when GetObjectLockConfiguration returns a configuration (ObjectLockConfigurationNotFoundError fails).")
def object_lock(item, index):
    value = section(item, "ObjectLock")
    if value is None:
        return result(True, object_lock=False)
    get(value, "ObjectLockConfiguration", dict)
    return result(False, object_lock=True)


@install("aws.claude_a.s3.event_notifications", "bucket", "S3 bucket has event notifications configured",
    B, w(B, Notifications={"collection_status": "collected"}), rows=[C + "s3_bucket_event_notifications_enabled", C + "foundational_security_s3_11",
    P + "s3_bucket_event_notifications_enabled"], severity="low", control="SI-4", remediation="Configure S3 event notifications (SNS, SQS, Lambda or EventBridge).",
    docs=[S3API + "API_GetBucketNotificationConfiguration.html", FSBP + "#s3-11"],
    extra={"pass_topic": w(B, Notifications={"collection_status": "collected", "TopicConfigurations": [{"TopicArn": "arn:aws:sns:us-east-1:%s:t" % ACCOUNT, "Events": ["s3:ObjectCreated:*"]}]})},
    note="Any of Topic/Queue/LambdaFunction configurations or EventBridgeConfiguration present (omitted when empty in both sources).")
def notifications(item, index):
    value = get(item, "Notifications", dict)
    present, unresolved = [], []
    for key in ("TopicConfigurations", "QueueConfigurations", "LambdaFunctionConfigurations", "EventBridgeConfiguration"):
        try:
            configured = optional(value, key, None, dict if key == "EventBridgeConfiguration" else list)
            if key == "EventBridgeConfiguration":
                if configured is not None:
                    get(value, key, dict)
                    present.append(key)
            elif configured is not None:
                if list_of_objects(configured):
                    present.append(key)
        except Unavailable as exc:
            unresolved.append(str(exc))
    if not present and unresolved:
        raise Unavailable("notification configuration unavailable: " + "; ".join(unresolved))
    return result(not present, configured=present)


# =========================================================================== ACLs
@install("aws.claude_a.s3.acls_prohibit_user_access", "bucket", "S3 bucket ACL grants no canonical users besides the owner, or ACLs are disabled",
    w(B, OwnershipControls=ABSENT), w(B, OwnershipControls=ABSENT, Acl__Grants=[OWNER_GRANT, {"Grantee": {"Type": "CanonicalUser", "ID": "b" * 64}, "Permission": "READ"}]),
    rows=[C + "s3_bucket_acls_should_prohibit_user_access", C + "foundational_security_s3_12"], severity="medium", control="AC-3",
    remediation="Set Object Ownership to BucketOwnerEnforced or remove grants to other accounts.", docs=[S3API + "API_GetBucketAcl.html", FSBP + "#s3-12"],
    extra={"pass_enforced": w(B, Acl__Grants=[OWNER_GRANT, {"Grantee": {"Type": "CanonicalUser", "ID": "b" * 64}, "Permission": "READ"}])},
    note="Steampipe: BucketOwnerEnforced passes; otherwise grantee IDs other than Owner.ID fail (URI group grants carry no ID and are not counted).")
def acl_users(item, index):
    ownership_unknown = False
    try:
        controls = section(item, "OwnershipControls")
        if controls is not None:
            rules = get(controls, "OwnershipControls.Rules", list)
            if not rules:
                ownership_unknown = True
            for rule in rules:
                try:
                    ownership = get(rule, "ObjectOwnership", str)
                    if ownership == "BucketOwnerEnforced":
                        return result(False, acls_disabled=True)
                    if ownership not in ("BucketOwnerPreferred", "ObjectWriter"):
                        raise Unavailable("unrecognized object ownership")
                except Unavailable:
                    ownership_unknown = True
    except Unavailable:
        ownership_unknown = True
    owner = get(item, "Acl.Owner.ID", str)
    ids, unresolved = [], False
    for grant in get(item, "Acl.Grants", list):
        try:
            grantee = get(grant, "Grantee", dict)
            identity = optional(grantee, "ID", None, str)
            if identity is not None:
                if not identity:
                    raise Unavailable("empty ACL grantee ID")
                ids.append(identity)
        except Unavailable:
            unresolved = True
    others = [identity for identity in ids if identity != owner]
    if others and not ownership_unknown:
        return result(True, other_grantees=len(others))
    if unresolved or others and ownership_unknown:
        raise Unavailable("ACL ownership or grantee identities unavailable")
    if not ids:
        return "NOT_APPLICABLE", {"reason": "no grantee IDs (source yields no row)"}
    return result(False, other_grantees=0)


@install("aws.claude_a.s3.no_authenticated_users_acl", "bucket", "S3 bucket ACL has no AuthenticatedUsers grant",
    B, w(B, Acl=acl_with(AUTH_USERS, "READ")), rows=[C + "s3_bucket_not_accessible_to_all_authenticated_user"], severity="high",
    category="exposure", control="AC-3", remediation="Remove grants to the AuthenticatedUsers group.", docs=[S3UG + "acl-overview.html"],
    note="Any permission granted to the global AuthenticatedUsers group fails; Block Public Access is not considered.")
def no_auth_users(item, index):
    hit, unresolved = [], False
    for grant in get(item, "Acl.Grants", list):
        try:
            if grant_uri(grant) == AUTH_USERS:
                # Permission is an evidence label, not part of this any-grant predicate.
                try:
                    permission = optional(grant, "Permission", None, str)
                except Unavailable:
                    permission = None
                hit.append(permission)
        except Unavailable:
            unresolved = True
    if not hit and unresolved:
        raise Unavailable("ACL grantee URI unavailable")
    return result(bool(hit), permissions=hit)


@install("aws.claude_a.s3.prowler_acl_disabled", "bucket", "S3 bucket Object Ownership is BucketOwnerEnforced (Prowler)",
    B, w(B, OwnershipControls__OwnershipControls__Rules=[{"ObjectOwnership": "ObjectWriter"}]), rows=[P + "s3_bucket_acl_prohibited"],
    severity="medium", control="AC-3", remediation="Set Object Ownership to BucketOwnerEnforced to disable ACLs.", docs=[S3API + "API_GetBucketOwnershipControls.html"],
    extra={"fail_absent": w(B, OwnershipControls=ABSENT)}, note="Prowler reads OwnershipControls.Rules[0].ObjectOwnership.")
def prowler_acl_disabled(item, index):
    controls = section(item, "OwnershipControls")
    if controls is None:
        return result(True, ownership=None)
    if get(controls, "collection_status", str) != "collected":
        raise Unavailable("ownership controls detail unavailable")
    rules = list_of_objects(get(controls, "OwnershipControls.Rules", list))
    if not rules:
        raise Unavailable("empty ownership rules")
    ownership = get(rules[0], "ObjectOwnership", str)
    return result("BucketOwnerEnforced" not in ownership, ownership=ownership)


def _group_grants(item, permissions=None):
    out, unresolved = [], False
    for grant in get(item, "Acl.Grants", list):
        try:
            grantee = get(grant, "Grantee", dict)
            kind = get(grantee, "Type", str)
            if kind not in ("Group", "CanonicalUser", "AmazonCustomerByEmail"):
                raise Unavailable("unrecognized ACL grantee type")
            if kind != "Group":
                continue
            if permissions is not None:
                permission_unknown = False
                try:
                    permission = optional(grant, "Permission", None, str)
                    if permission is not None and permission not in ("FULL_CONTROL", "READ", "READ_ACP", "WRITE", "WRITE_ACP"):
                        raise Unavailable("unrecognized ACL permission")
                except Unavailable:
                    permission, permission_unknown = None, True
                if not permission_unknown and permission not in permissions:
                    continue
            else:
                # General public-group membership does not depend on this label.
                try:
                    permission = optional(grant, "Permission", None, str)
                except Unavailable:
                    permission = None
            uri = grant_uri(grant) or ""
            if "AllUsers" in uri or "AuthenticatedUsers" in uri:
                if permissions is not None and permission_unknown:
                    raise Unavailable("public ACL permission unavailable")
                out.append((uri.split("/")[-1], permission))
        except Unavailable:
            unresolved = True
    if not out and unresolved:
        raise Unavailable("ACL group grant facts unavailable")
    return out


def _public_acl_or_policy(item, index):
    hits, unresolved = [], False
    try:
        hits.extend(_group_grants(item))
    except Unavailable:
        unresolved = True
    try:
        if bucket_policy(item) is not None and is_policy_public(statements(item), account(index)):
            hits.append("policy")
    except Unavailable:
        unresolved = True
    if not hits and unresolved:
        raise Unavailable("public ACL or policy facts unavailable")
    return hits


def _prowler_public(item, index, finder):
    """Prowler account-first public evaluation: account IgnorePublicAcls+RestrictPublicBuckets, then the bucket's own block, then findings."""
    # A complete account block is sufficient even if the bucket detail is unreadable.
    try:
        flags = bucket_blocks(item)
    except Unavailable:
        flags = None
    if flags is not None and flags["IgnorePublicAcls"] and flags["RestrictPublicBuckets"]:
        return result(False, blocked="bucket")
    try:
        hits = finder(item, index)
    except Unavailable:
        # Existing account mitigation can independently settle an unreadable finder.
        try:
            acct = account_blocks(index)
            if acct["IgnorePublicAcls"] and acct["RestrictPublicBuckets"]:
                return result(False, blocked="account")
        except Unavailable:
            pass
        raise
    if not hits:
        return result(False, public=[])
    acct = account_blocks(index)
    if acct["IgnorePublicAcls"] and acct["RestrictPublicBuckets"]:
        return result(False, blocked="account")
    if flags is None:
        raise Unavailable("bucket public access block unavailable")
    return result(True, public=hits)


def _public_case(cid, title, row, finder, failing, *, note, extra=None):
    extras = {"pass_account": (failing, IDX_ACCOUNT_OK)}
    extras.update(extra or {})

    @install(cid, "bucket", title, w(B, PublicAccessBlock=ABSENT), failing, index=IDX, dependencies=["bucket", "s3_account_public_access_block"],
             rows=[P + row], severity="critical", category="exposure", control="AC-3",
             remediation="Block public access at account or bucket level and remove public grants/policies.",
             docs=[S3UG + "access-control-block-public-access.html", S3UG + "acl-overview.html"], extra=extras, note=note)
    def evaluate(item, index):
        return _prowler_public(item, index, finder)
    return evaluate


_public_case("aws.claude_a.s3.prowler_public_access", "S3 bucket is not public through its ACL or policy (Prowler)", "s3_bucket_public_access",
    _public_acl_or_policy,
    w(B, PublicAccessBlock=ABSENT, Acl=acl_with(ALL_USERS, "READ")), extra={"fail_policy": w(B, PublicAccessBlock=ABSENT, Policy=PUBLIC_POLICY)},
    note="Prowler: account IgnorePublicAcls+RestrictPublicBuckets passes; else the bucket's own two settings; else AllUsers/AuthenticatedUsers group grant or a public policy fails.")
_public_case("aws.claude_a.s3.prowler_public_list_acl", "S3 bucket ACL does not make it publicly listable (Prowler)", "s3_bucket_public_list_acl",
    lambda i, x: _group_grants(i, ("FULL_CONTROL", "READ", "READ_ACP")), w(B, PublicAccessBlock=ABSENT, Acl=acl_with(AUTH_USERS, "READ")),
    note="Group grants FULL_CONTROL/READ/READ_ACP to AllUsers or AuthenticatedUsers fail unless public ACLs are ignored and buckets restricted.")
_public_case("aws.claude_a.s3.prowler_public_write_acl", "S3 bucket ACL does not make it publicly writable (Prowler)", "s3_bucket_public_write_acl",
    lambda i, x: _group_grants(i, ("FULL_CONTROL", "WRITE", "WRITE_ACP")), w(B, PublicAccessBlock=ABSENT, Acl=acl_with(ALL_USERS, "WRITE")),
    note="Group grants FULL_CONTROL/WRITE/WRITE_ACP to AllUsers or AuthenticatedUsers fail unless public ACLs are ignored and buckets restricted.")


# =========================================================================== bucket policies
READ_ACL = ("FULL_CONTROL", "READ_ACP", "READ")


def _read_actions(actions):
    return any(a in ("*", "*:*", "s3:*") or a.startswith("s3:get") or a.startswith("s3:list") for a in actions)


@install("aws.claude_a.s3.restrict_public_read", "bucket", "S3 bucket has no stored public read ACL grant or public read policy",
    B, w(B, PublicAccessBlock=ABSENT, Acl=acl_with(ALL_USERS, "READ")), rows=[C + "s3_bucket_restrict_public_read_access", C + "foundational_security_s3_2"],
    severity="critical", category="exposure", control="AC-3", remediation="Remove public read grants and public read statements; enable Block Public Access.",
    docs=[S3API + "API_GetBucketPolicyStatus.html", FSBP + "#s3-2"],
    extra={"fail_policy": w(B, PublicAccessBlock=ABSENT, Policy=PUBLIC_POLICY, PolicyStatus__PolicyStatus__IsPublic=True),
           "fail_blocked_policy": w(B, Policy=PUBLIC_POLICY, PolicyStatus__PolicyStatus__IsPublic=True)},
    note="Intentional correction to pinned Steampipe SQL: BlockPublicPolicy and BlockPublicAcls reject future writes, but do not remove stored public policy/ACL grants. "
         "This checks stored grants, not effective anonymous reachability; IgnorePublicAcls and RestrictPublicBuckets are reported as runtime mitigations.")
def public_read(item, index):
    # Bucket Public Access Block flags are runtime mitigation labels here;
    # stored ACL and policy findings can be decided independently of them.
    try:
        flags = bucket_blocks(item)
    except Unavailable:
        flags = None
    public_acl, unresolved_acl = False, False
    for grant in get(item, "Acl.Grants", list):
        permission_unknown = False
        try:
            permission = optional(grant, "Permission", None, str)
            if permission is not None and permission not in ("FULL_CONTROL", "READ", "READ_ACP", "WRITE", "WRITE_ACP"):
                raise Unavailable("unrecognized ACL permission")
        except Unavailable:
            permission, permission_unknown = None, True
        if not permission_unknown and permission not in READ_ACL:
            continue
        try:
            if grant_uri(grant) not in (ALL_USERS, AUTH_USERS):
                continue
            if permission_unknown:
                raise Unavailable("public read ACL permission unavailable")
            public_acl = True
        except Unavailable:
            unresolved_acl = True
    if public_acl:
        return result(True, public_acl=True, policy_is_public=None, read_policy=None,
                      bucket_public_access_block=flags,
                      runtime_acl_ignored=None if flags is None else flags["IgnorePublicAcls"],
                      runtime_public_policy_restricted=None if flags is None else flags["RestrictPublicBuckets"],
                      effective_public_access="not determined by stored-policy check")
    status = section(item, "PolicyStatus")
    is_public = None if status is None else get(status, "PolicyStatus.IsPublic", bool)
    policy = statements(item)
    read_candidates = []
    unresolved_policy = False
    for statement in policy:
        try:
            s = std([statement], resource_policy=True, principal_action_ok=_read_actions)[0]
        except Unavailable:
            unresolved_policy = True
            continue
        if s["Effect"] == "Allow" and s.get("PrincipalAWS") == ["*"] and _read_actions(s.get("Action", [])):
            read_candidates.append(s)
    # The normalized statements retain the Condition. An uncertain condition cannot certify a safe policy.
    restrictions = [_restrictive(s["_raw"]) for s in read_candidates]
    read_policy = any(value is False for value in restrictions)
    if not read_policy and unresolved_acl:
        return "UNKNOWN", {"reason": "public read ACL facts unavailable", "bucket_public_access_block": flags}
    if not public_acl and not read_policy and unresolved_policy:
        return "UNKNOWN", {"reason": "bucket policy statement unavailable", "bucket_public_access_block": flags}
    if not public_acl and not read_policy and any(value is None for value in restrictions):
        return "UNKNOWN", {"reason": "public read policy condition needs review", "bucket_public_access_block": flags}
    if not public_acl and not read_policy and policy and is_public is None:
        return "UNKNOWN", {"reason": "bucket policy public status unavailable", "bucket_public_access_block": flags}
    if not public_acl and not read_policy and is_public is True:
        return "UNKNOWN", {"reason": "bucket policy is public, but public read scope is not established by parsed statements",
                           "bucket_public_access_block": flags}
    return result(public_acl or read_policy, public_acl=public_acl, policy_is_public=is_public, read_policy=read_policy,
                  bucket_public_access_block=flags,
                  runtime_acl_ignored=None if flags is None else flags["IgnorePublicAcls"],
                  runtime_public_policy_restricted=None if flags is None else flags["RestrictPublicBuckets"],
                  effective_public_access="not determined by stored-policy check")


CHANGE_ACTIONS = ("s3:deletebucketpolicy", "s3:putbucketacl", "s3:putbucketpolicy", "s3:putencryptionconfiguration", "s3:putobjectacl")


@install("aws.claude_a.s3.policy_no_cross_account_permission_changes", "bucket", "S3 bucket policy does not let other accounts change bucket permissions",
    w(B, Policy=OWN_POLICY), w(B, Policy=CROSS_POLICY), index=idx(), rows=[C + "s3_bucket_policy_restricts_cross_account_permission_changes", C + "foundational_security_s3_6"],
    severity="high", control="AC-3", remediation="Remove Allow statements granting other accounts DeleteBucketPolicy, PutBucketAcl, PutBucketPolicy, PutEncryptionConfiguration or PutObjectAcl.",
    docs=[S3API + "API_GetBucketPolicy.html", FSBP + "#s3-6"], extra={"pass_no_policy": B},
    note="Steampipe: Allow, Principal.AWS element '*' or whose 5th ARN field differs from the bucket account, with one of the five exact (lowercased) actions; wildcards like s3:* are not matched.")
def cross_account_changes(item, index):
    owner = account(index)
    hits = []
    unresolved_policy = False
    for statement in statements(item):
        try:
            s = std([statement], resource_policy=True,
                    principal_action_ok=lambda actions: any(a in CHANGE_ACTIONS for a in actions))[0]
        except Unavailable:
            unresolved_policy = True
            continue
        if s["Effect"] != "Allow":
            continue
        actions = [a for a in s.get("Action", []) if a in CHANGE_ACTIONS]
        if not actions:
            continue
        for p in s.get("PrincipalAWS", []):
            parts = p.split(":")
            if p == "*" or (len(parts) > 4 and parts[4] != owner):
                hits.append((p, actions))
    if unresolved_policy and not hits:
        raise Unavailable("bucket policy statement unavailable")
    return result(bool(hits), cross_account_statements=hits)


WILDCARD_OPS = ("StringEquals", "StringEqualsIfExists", "StringEqualsIgnoreCase", "ForAnyValue:StringEquals", "ForAllValues:StringEquals")
ARN_OPS = ("ArnEquals", "ArnLike", "ForAnyValue:ArnEquals", "ForAllValues:ArnEquals", "ForAnyValue:ArnLike", "ForAllValues:ArnLike")
RESTRICTING = {key: WILDCARD_OPS for key in ("aws:principalorgid", "aws:sourceaccount", "aws:principalaccount", "aws:sourceowner")}
RESTRICTING["aws:principalarn"] = ("StringEquals", "StringEqualsIfExists", "ForAnyValue:StringEquals", "ForAllValues:StringEquals") + ARN_OPS
RESTRICTING["aws:sourcearn"] = ARN_OPS


def _wildcard_principal_any(statement):
    principal = statement.get("Principal")
    if principal == "*":
        return True
    if isinstance(principal, dict):
        # policy_std turns every principal value into an array; the SQL CASE inspects the first present of AWS,
        # CanonicalUser, Federated only.
        for key in ("AWS", "CanonicalUser", "Federated"):
            if principal.get(key) is not None:
                return "*" in as_list(principal[key])
        return False
    if isinstance(principal, list):
        return "*" in principal
    return False


def _restrictive(statement):
    """True for an evidenced fixed restriction, False for none, None for an undecidable one.

    IfExists and ForAllValues can match an absent context key. A wildcard-looking
    literal under StringEquals is not a wildcard match, while an ArnLike pattern
    may still be bounded; neither proves a fixed restriction or an open grant.
    """
    cond = _conditions(statement)
    if not cond:
        return False
    uncertain = False
    for operator, values in cond.items():
        for key, candidates in values.items():
            if key not in RESTRICTING:
                uncertain = True
                continue
            if operator not in RESTRICTING[key] or "IfExists" in operator or operator.startswith("ForAllValues:"):
                uncertain = True
                continue
            if not candidates or any(not isinstance(v, str) or not v for v in candidates):
                uncertain = True
                continue
            if any("*" in v or "?" in v or "${" in v for v in candidates):
                uncertain = True
                continue
            if key == "aws:principalorgid":
                valid = all(re.fullmatch(r"o-[a-z0-9]{10,32}", v) for v in candidates)
            elif key in ("aws:sourceaccount", "aws:principalaccount", "aws:sourceowner"):
                valid = all(re.fullmatch(r"[0-9]{12}", v) for v in candidates)
            else:
                valid = all(v.startswith("arn:") and len(v.split(":")) >= 6 and bool(v.split(":", 5)[5]) for v in candidates)
            if valid:
                return True
            uncertain = True
    return None if uncertain else False


@install("aws.claude_a.s3.policy_restrict_public_access", "bucket", "S3 bucket policy has no unconditioned wildcard-principal Allow",
    w(B, Policy=OWN_POLICY), w(B, Policy=PUBLIC_POLICY), rows=[C + "s3_bucket_policy_restrict_public_access"], severity="critical",
    category="exposure", control="AC-3", remediation="Remove wildcard principals or restrict them with account/organization/ARN conditions.",
    docs=[S3API + "API_GetBucketPolicy.html", "https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_condition-keys.html"],
    extra={"na": B, "pass_conditioned": w(B, Policy={"collection_status": "collected", "Policy": {"Version": "2012-10-17", "Statement": [
               dict(PUBLIC_POLICY["Policy"]["Statement"][0], Condition={"StringEquals": {"aws:PrincipalOrgID": "o-abcdefghij"}})]}})},
    note="Intentional correction to pinned Steampipe SQL: condition key/operator presence is insufficient. Only concrete fixed organization, account, or ARN restrictions certify a wildcard Allow; unsupported condition forms are UNKNOWN.")
def policy_public(item, index):
    if bucket_policy(item) is None:
        return "NOT_APPLICABLE", {"reason": "bucket has no policy"}
    restrictions = [_restrictive(s) for s in statements(item) if s.get("Effect") == "Allow" and _wildcard_principal_any(s)]
    bad = sum(value is False for value in restrictions)
    if bad:
        return result(True, unrestricted_public_statements=bad, uncertain_public_statements=sum(value is None for value in restrictions),
                      effective_public_access="not determined by stored-policy check")
    if any(value is None for value in restrictions):
        return "UNKNOWN", {"reason": "wildcard Allow has unsupported or unproven policy restriction",
                           "uncertain_public_statements": sum(value is None for value in restrictions)}
    return result(False, unrestricted_public_statements=0, effective_public_access="not determined by stored-policy check")


@install("aws.claude_a.s3.perimeter_policy_not_public", "bucket", "S3 bucket policy has no public Allow statement (perimeter)",
    w(B, Policy=OWN_POLICY), w(B, Policy=PUBLIC_POLICY), rows=[R + "s3_bucket_policy_prohibit_public_access"], severity="critical",
    category="exposure", control="AC-3", remediation="Remove wildcard principals or add aws:SourceAccount/PrincipalOrgID/PrincipalAccount/PrincipalArn/SourceArn restrictions.",
    docs=[S3API + "API_GetBucketPolicy.html"], extra={"na": B},
    note="aws-perimeter resource_policy_public_sql: StringLike/ArnEquals/ArnLike containing '*' do not restrict; no policy is info.")
def perimeter_policy(item, index):
    if bucket_policy(item) is None:
        return "NOT_APPLICABLE", {"reason": "bucket has no policy"}
    bad = turbot_public_statements(statements(item), arn_equals_wildcard=True)
    return result(bool(bad), public_statements=len(bad))


@install("aws.claude_a.s3.prowler_cross_account_policy", "bucket", "S3 bucket policy does not allow other accounts (Prowler)",
    w(B, Policy=OWN_POLICY), w(B, Policy=CROSS_POLICY), index=idx(), rows=[P + "s3_bucket_cross_account_access"], severity="high", control="AC-3",
    remediation="Remove or condition statements that grant principals outside the account.", docs=[S3API + "API_GetBucketPolicy.html"],
    extra={"pass_no_policy": B}, note="Prowler is_policy_public(policy, audited account, is_cross_account_allowed=False); trusted_account_ids default [].")
def prowler_cross_account(item, index):
    if bucket_policy(item) is None:
        return result(False, policy=False)
    public = is_policy_public(statements(item), account(index), is_cross_account_allowed=False)
    return result(public, cross_account=public)


WRITE_ACTIONS = ["s3:PutObject", "s3:DeleteObject", "s3:*", "s3:Put*", "s3:Delete*"]


@install("aws.claude_a.s3.prowler_policy_public_write", "bucket", "S3 bucket policy does not allow public write (Prowler)",
    w(B, PublicAccessBlock=ABSENT, Policy=PUBLIC_POLICY), w(B, PublicAccessBlock=ABSENT, Policy=PUBLIC_WRITE_POLICY), index=IDX,
    dependencies=["bucket", "s3_account_public_access_block"], rows=[P + "s3_bucket_policy_public_write_access"], severity="critical",
    category="exposure", control="AC-3", remediation="Remove public write statements or enable RestrictPublicBuckets.", docs=[S3API + "API_GetBucketPolicy.html"],
    extra={"pass_account": (w(B, PublicAccessBlock=ABSENT, Policy=PUBLIC_WRITE_POLICY), IDX_ACCOUNT_OK), "pass_bucket": w(B, Policy=PUBLIC_WRITE_POLICY)},
    note="No policy passes; account or bucket RestrictPublicBuckets passes; else is_policy_public with PutObject/DeleteObject/s3:*/s3:Put*/s3:Delete* fails.")
def prowler_public_write(item, index):
    if bucket_policy(item) is None:
        return result(False, policy=False)
    if bucket_blocks(item)["RestrictPublicBuckets"]:
        return result(False, blocked="bucket")
    public = is_policy_public(statements(item), account(index), not_allowed_actions=WRITE_ACTIONS)
    if not public:
        return result(False, public_write=False)
    if account_blocks(index)["RestrictPublicBuckets"]:
        return result(False, blocked="account")
    return result(True, public_write=True)


# =========================================================================== facts not collected yet
@install("aws.claude_a.s3.static_website_disabled", "bucket", "S3 bucket static website hosting is disabled",
    B, w(B, Website={"collection_status": "collected", "IndexDocument": {"Suffix": "index.html"}}), rows=[C + "s3_bucket_static_website_hosting_disabled"],
    severity="medium", category="exposure", control="CM-7", remediation="Remove the bucket website configuration; serve content through CloudFront with OAC.",
    docs=[S3API + "API_GetBucketWebsite.html"], note="Needs s3:GetBucketWebsite as bucket.Website (NoSuchWebsiteConfiguration = absent); collector fact.")
def website(item, index):
    value = section(item, "Website")
    document = None if value is None else optional(value, "IndexDocument", None, dict)
    suffix = None if document is None else get(document, "Suffix", str)
    if suffix is not None and not suffix:
        raise Unavailable("empty website index document suffix")
    return result(suffix is not None, index_document=suffix)


TRAIL = {"Name": "t", "HomeRegion": "us-east-1", "IsMultiRegionTrail": True,
         "EventSelectors": {"collection_status": "collected", "EventSelectors": [{"DataResources": [{"Type": "AWS::S3::Object", "Values": ["arn:aws:s3:::b1/"]}]}]}}


def _global_scope(index):
    context = index.get("context", {}) if isinstance(index, dict) else {}
    scope = context.get("scope") if isinstance(context, dict) else None
    return isinstance(scope, str) and re.fullmatch(r"[0-9]{12}/global", scope) is not None


_S3_UNSET = object()


def _selected_source(item, key, expected=None, default=_S3_UNSET):
    """Selected source field, including coherent explicit empty coverage."""
    guard(item)
    if key != "collection_status":
        # Reuse the leaf reader so the parent's own status coverage is honored.
        status = _selected_source(item, "collection_status", str, None)
        if status == "empty" and key in item and item[key] not in (None, "", [], {}):
            raise Unavailable("empty parent source retains selected value: " + key)
    marker = item.get("_coverage", {}).get(key)
    if isinstance(marker, dict) and marker.get("status") == "empty":
        if key in item and item[key] not in (None, "", [], {}):
            raise Unavailable("empty source coverage contradicts retained value: " + key)
        if default is not _S3_UNSET:
            return default
        if expected is list:
            return []
        raise Unavailable("required selected source field is empty: " + key)
    if default is _S3_UNSET:
        return get(item, key, expected)
    return optional(item, key, default, expected)


def _data_values(trail):
    selectors = _selected_source(trail, "EventSelectors", dict)
    status = _selected_source(selectors, "collection_status", str, None)
    if status not in (None, "collected"):
        raise Unavailable("trail event selectors not collected")
    out, advanced, unresolved = [], False, False
    for selector in list_of_objects(_selected_source(selectors, "EventSelectors", list, [])):
        try:
            resources = list_of_objects(_selected_source(selector, "DataResources", list, []))
        except Unavailable:
            unresolved = True
            continue
        for resource in resources:
            try:
                if _selected_source(resource, "Type", str) == "AWS::S3::Object":
                    out.extend(v.replace('"', "").replace("/", "")
                               for v in strings(_selected_source(resource, "Values", list, [])))
            except Unavailable:
                unresolved = True
    for selector in list_of_objects(_selected_source(selectors, "AdvancedEventSelectors", list, [])):
        try:
            fields = list_of_objects(_selected_source(selector, "FieldSelectors", list, []))
        except Unavailable:
            unresolved = True
            continue
        for field in fields:
            try:
                kind = _selected_source(field, "Field", str)
                if kind != "eventCategory" and "AWS::S3::Object" in strings(_selected_source(field, "Equals", list, [])):
                    advanced = True
            except Unavailable:
                unresolved = True
    return out, advanced, unresolved



def _trail_label(trail):
    """Trail ARN is only a finding label after a selector already proves the result."""
    try:
        return _selected_source(trail, "TrailARN", str, None)
    except Unavailable:
        return None


@install("aws.claude_a.s3.object_level_logging", "bucket", "S3 bucket object-level data events are logged by CloudTrail",
    B, B, index=idx(cloudtrail=[TRAIL]), fail_index=idx(cloudtrail=[w(TRAIL, EventSelectors={"collection_status": "collected", "EventSelectors": []})]),
    dependencies=["bucket", "cloudtrail"], rows=[C + "s3_bucket_object_logging_enabled"], severity="medium", control="AU-2",
    remediation="Log S3 data events (all buckets or this bucket) in a trail in the bucket's Region.", docs=["https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/API_GetEventSelectors.html"],
    extra={"pass_region": (B, idx(cloudtrail=[w(TRAIL, EventSelectors__EventSelectors=[{"DataResources": [{"Type": "AWS::S3::Object", "Values": ["arn:aws:s3"]}]}])])),
           "pass_advanced": (B, idx(cloudtrail=[w(TRAIL, EventSelectors={"collection_status": "collected", "AdvancedEventSelectors": [
               {"FieldSelectors": [{"Field": "eventCategory", "Equals": ["Data"]}, {"Field": "resources.type", "Equals": ["AWS::S3::Object"]}]}]})]))},
    note="Explicit bucket ARN in any visible trail's S3 data selectors, or a same-Region trail with arn:aws:s3 / advanced S3 object selectors. "
         "Trails are visible only for the bucket's collection scope: a bucket homed in another Region without a match is UNKNOWN; a same-Region "
         "non-match FAILS (single-Region trails elsewhere cannot log this bucket's data events).")
def object_logging(item, index):
    arn = bucket_arn(item, index)
    home = bucket_region(item)
    unresolved = False
    if _global_scope(index):
        # Account-global inventory covers enabled Regions; a matching trail is
        # sufficient even when an unrelated peer's selected facts are unreadable.
        trails = items(index, "cloudtrail_account_inventory")
        for trail in trails:
            try:
                eligibility = []
                try:
                    eligibility.append(_selected_source(trail, "IsMultiRegionTrail", bool))
                except Unavailable:
                    eligibility.append(None)
                try:
                    trail_home = _selected_source(trail, "HomeRegion", str)
                    if not trail_home:
                        raise Unavailable("trail home Region unavailable")
                    eligibility.append(trail_home == home)
                except Unavailable:
                    eligibility.append(None)
                # Existing OR: either observed true term is sufficient.
                if True not in eligibility:
                    if None in eligibility:
                        raise Unavailable("trail Region eligibility unavailable")
                    continue
                values, advanced, trail_unresolved = _data_values(trail)
                unresolved = unresolved or trail_unresolved
                if arn in values:
                    return result(False, match="bucket arn", trail=_trail_label(trail))
                if "arn:%s:s3" % partition(index) in values or "arn:%s:s3:::" % partition(index) in values or advanced:
                    return result(False, match="all-bucket selector", trail=_trail_label(trail))
            except Unavailable:
                unresolved = True
        if unresolved:
            raise Unavailable("account trail selector or Region facts unavailable")
        return result(True, match=None, trails_considered=len(trails))
    here = region(index)
    for trail in items(index, "cloudtrail"):
        try:
            values, advanced, trail_unresolved = _data_values(trail)
            unresolved = unresolved or trail_unresolved
            if arn in values:
                return result(False, match="bucket arn")
            if home == here and ("arn:aws:s3" in values or advanced):
                return result(False, match="regional selector")
        except Unavailable:
            unresolved = True
    if home != here or unresolved:
        raise Unavailable("bucket Region trail coverage or selector unavailable")
    return result(True, match=None)



MACIE_JOB = {"jobId": "j1", "s3JobDefinition": {"bucketDefinitions": [{"accountId": ACCOUNT, "buckets": ["b1"]}]}}


@install("aws.claude_a.s3.protected_by_macie", "bucket", "S3 bucket is included in a Macie classification job",
    B, B, index=idx(macie2_classification_job=[MACIE_JOB]), fail_index=idx(macie2_classification_job=[]), dependencies=["bucket", "macie2_classification_job"],
    rows=[C + "s3_bucket_protected_by_macie"], severity="low", control="RA-5", remediation="Include the bucket in a Macie sensitive-data discovery job.",
    docs=["https://docs.aws.amazon.com/macie/latest/APIReference/jobs-jobid.html"],
    note="Needs macie2:ListClassificationJobs + DescribeClassificationJob (kind macie2_classification_job, collector fact). us-gov Regions skip; "
         "jobs of other Regions are not in scope, so a non-match for a bucket homed elsewhere is UNKNOWN.")
def macie(item, index):
    home = bucket_region(item)
    if home in ("us-gov-east-1", "us-gov-west-1"):
        return "NOT_APPLICABLE", {"reason": "source skips GovCloud"}
    name = get(item, "Name", str)
    uncertain_scope = False
    if _global_scope(index):
        # Account-global inventory has one source row per enabled Region.
        rows = []
        for row in items(index, "macie2_account_classification_job_inventory"):
            try:
                source_region = _selected_source(row, "SourceRegion", str)
                if not source_region:
                    raise Unavailable("Macie source Region unavailable")
            except Unavailable:
                uncertain_scope = True
                continue
            if source_region == home:
                rows.append(row)
        if len(rows) != 1:
            raise Unavailable("Macie jobs of the bucket Region were not uniquely collected")
        state = _selected_source(rows[0], "ServiceState", str)
        if state == "service_not_enabled":
            if uncertain_scope:
                raise Unavailable("Macie Region identity unavailable")
            jobs_parent = _selected_source(rows[0], "Jobs", dict)
            jobs_status = _selected_source(jobs_parent, "collection_status", str)
            jobs = list_of_objects(_selected_source(jobs_parent, "items", list))
            if jobs_status != "empty" or jobs:
                raise Unavailable("disabled Macie source contradicts collected or retained jobs")
            return "NOT_APPLICABLE", {"reason": "Macie is not enabled in the bucket Region (documented GetMacieSession/ListClassificationJobs state)", "region": home}
        if state != "available":
            raise Unavailable("Macie service state unavailable")
        jobs_parent = _selected_source(rows[0], "Jobs", dict)
        jobs_status = _selected_source(jobs_parent, "collection_status", str)
        if jobs_status not in ("collected", "empty"):
            raise Unavailable("Macie jobs of the bucket Region were not collected")
        jobs = list_of_objects(_selected_source(jobs_parent, "items", list))
        if jobs_status == "empty" and jobs:
            raise Unavailable("Macie empty jobs contradict retained items")
    else:
        envelopes = index.get("collections", {}).get("macie2_classification_job") or []
        service_disabled = False
        for envelope in envelopes:
            if _selected_source(envelope, "status", str) == "empty":
                error = _selected_source(envelope, "error", dict, None)
                if error is not None and _selected_source(error, "code", str) == "service_not_enabled":
                    service_disabled = True
        if service_disabled:
            return "NOT_APPLICABLE", {"reason": "Macie is not enabled in this Region"}
        jobs = items(index, "macie2_classification_job")
    criteria, unresolved = False, False
    for job in jobs:
        try:
            definition_block = _selected_source(job, "s3JobDefinition", dict)
        except Unavailable:
            unresolved = True
            continue
        try:
            criteria = criteria or bool(_selected_source(definition_block, "bucketCriteria", default=None))
        except Unavailable:
            unresolved = True
        try:
            definitions = list_of_objects(_selected_source(definition_block, "bucketDefinitions", list, []))
        except Unavailable:
            unresolved = True
            continue
        for definition in definitions:
            try:
                if name in strings(_selected_source(definition, "buckets", list, [])):
                    try:
                        job_id = _selected_source(job, "jobId", str, None)
                    except Unavailable:
                        job_id = None  # Only an evidence label, not membership proof.
                    return result(False, job=job_id)
            except Unavailable:
                unresolved = True
    if criteria or unresolved or uncertain_scope:
        raise Unavailable("Macie job membership or bucket criteria unresolved")
    if _global_scope(index):
        return result(True, job=None, region=home)
    if home != region(index):
        raise Unavailable("Macie jobs of the bucket Region are not in this scope")
    return result(True, job=None)



def _all_access_point_flags(config):
    """All four settings require readable booleans; a known false disproves all."""
    flags, unresolved = {}, []
    for key in BLOCKS:
        try:
            flags[key] = get(config, key, bool)
        except Unavailable as exc:
            unresolved.append(str(exc))
    if any(value is False for value in flags.values()):
        return result(True, settings=flags)
    if unresolved:
        raise Unavailable("access-point settings unavailable: " + "; ".join(unresolved))
    return result(False, settings=flags)


AP = {"Name": "ap1", "Bucket": "b1", "AccessPointArn": "arn:aws:s3:us-east-1:%s:accesspoint/ap1" % ACCOUNT,
      "PublicAccessBlockConfiguration": {k: True for k in BLOCKS}}


@install("aws.claude_a.s3.access_point_public_access_block", "s3_access_point", "S3 access point blocks all public access",
    AP, w(AP, PublicAccessBlockConfiguration__BlockPublicPolicy=False), rows=[C + "s3_access_point_restrict_public_access", C + "foundational_security_s3_19",
    P + "s3_access_point_public_access_block"], severity="high", category="exposure", control="AC-3",
    remediation="Recreate the access point with all Block Public Access settings enabled.", docs=[S3API + "API_control_GetAccessPoint.html", FSBP + "#s3-19"],
    note="Needs s3control:ListAccessPoints + GetAccessPoint (kind s3_access_point, collector fact). Steampipe and Prowler both require all four.")
def access_point(item, index):
    config = get(item, "PublicAccessBlockConfiguration", dict)
    return _all_access_point_flags(config)


MRAP = {"Name": "m1", "Alias": "m1.mrap", "PublicAccessBlock": {k: True for k in BLOCKS}, "Regions": [{"Bucket": "b1"}]}


@install("aws.claude_a.s3.multi_region_access_point_public_access_block", "s3_multi_region_access_point", "S3 Multi-Region Access Point blocks all public access",
    MRAP, w(MRAP, PublicAccessBlock__IgnorePublicAcls=False), rows=[C + "s3_multi_region_access_point_public_access_blocked", C + "foundational_security_s3_24",
    P + "s3_multi_region_access_point_public_access_block"], severity="high", category="exposure", control="AC-3",
    remediation="Recreate the Multi-Region Access Point with all Block Public Access settings enabled.", docs=[S3API + "API_control_ListMultiRegionAccessPoints.html", FSBP + "#s3-24"],
    note="Needs s3control:ListMultiRegionAccessPoints (us-west-2; kind s3_multi_region_access_point, collector fact).")
def mrap(item, index):
    config = get(item, "PublicAccessBlock", dict)
    return _all_access_point_flags(config)


DIR = {"Name": "d1--use1-az4--x-s3", "Lifecycle": {"collection_status": "collected", "Rules": [{"ID": "r", "Status": "Enabled"}]}}


@install("aws.claude_a.s3.directory_bucket_lifecycle", "s3_directory_bucket", "S3 directory bucket has a lifecycle configuration",
    DIR, w(DIR, Lifecycle=ABSENT), rows=[C + "s3_directory_bucket_lifecycle_policy_configured", C + "foundational_security_s3_25"],
    severity="low", control="CM-6", remediation="Add a lifecycle configuration to the directory bucket.", docs=[S3API + "API_GetBucketLifecycleConfiguration.html", FSBP + "#s3-25"],
    note="Needs s3:ListDirectoryBuckets + GetBucketLifecycleConfiguration (kind s3_directory_bucket, collector fact). Any configuration passes.")
def directory_lifecycle(item, index):
    value = section(item, "Lifecycle")
    return result(value is None, lifecycle=value is not None)


__all__ = ["DROP"]
