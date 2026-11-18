"""Signed CloudTrail and SSM compliance checks over authoritative snapshot facts."""
from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timezone
import json
import re

from . import CHECKS, register, result, unknown
from .facts import Unavailable, complete_items, get, guard

_ACCOUNT_REGION = re.compile(r"^([0-9]{12})/([a-z]{2}(?:-[a-z]+)+-[0-9])$")
_TRAIL_ARN = re.compile(r"^arn:(aws(?:-[a-z0-9-]+)?):cloudtrail:([a-z0-9-]+):([0-9]{12}):trail/[^/]+$")
_KMS_ARN = re.compile(r"^arn:(aws(?:-[a-z0-9-]+)?):kms:([a-z0-9-]+):([0-9]{12}):key/[^/]+$")
_LOG_ARN = re.compile(r"^arn:(aws(?:-[a-z0-9-]+)?):logs:([a-z0-9-]+):([0-9]{12}):log-group:.+$")


def _context(item, index):
    context = get(index, "context", dict)
    scope = get(context, "scope", str)
    match = _ACCOUNT_REGION.fullmatch(scope)
    if get(context, "provider", str) != "aws" or not match or item != context:
        raise Unavailable("AWS scoped context unavailable")
    return context, match.group(1), match.group(2), scope


def _rows(index, kind, account, scope, *, global_ok=False):
    collections = get(index, "collections", dict)
    envelopes = get(collections, kind, list)
    if not envelopes:
        raise Unavailable("inventory not collected: " + kind)
    envelope_rows = []
    for envelope in envelopes:
        e_scope = get(envelope, "scope", str)
        if e_scope != scope:
            if not global_ok or get(envelope, "global", bool) is not True or get(envelope, "account_id", str) != account or e_scope.split("/")[0] != account:
                raise Unavailable("foreign inventory scope: " + kind)
        if envelope.get("account_id") not in (None, account):
            raise Unavailable("foreign inventory account: " + kind)
        if get(envelope, "status", str) not in ("collected", "empty"):
            raise Unavailable("incomplete inventory: " + kind)
        items = get(envelope, "items", list)
        if envelope["status"] == "empty" and items:
            raise Unavailable("malformed empty inventory: " + kind)
        envelope_rows.extend(items)
    rows = complete_items(index, kind)
    if (any(not isinstance(row, dict) for row in rows) or len(rows) != len(envelope_rows) or
            sorted(json.dumps(row, sort_keys=True, separators=(",", ":")) for row in rows) !=
            sorted(json.dumps(row, sort_keys=True, separators=(",", ":")) for row in envelope_rows)):
        raise Unavailable("inventory resources differ from scoped collection: " + kind)
    return rows


def _trails(index, account, region, scope):
    rows = _rows(index, "cloudtrail_account_inventory", account, scope, global_ok=True)
    selected, seen = [], set()
    for row in rows:
        arn = get(row, "TrailARN", str)
        match = _TRAIL_ARN.fullmatch(arn)
        home = get(row, "HomeRegion", str)
        name = get(row, "Name", str)
        source = get(row, "SourceRegion", str)
        provenance = get(row, "_provenance", dict)
        foreign_org = match is not None and match.group(3) != account
        if foreign_org:
            binding = row.get("_account_trail_binding")
            context = get(index, "context", dict)
            capture_at = get(context, "created_at", str)
            if (row.get("IsOrganizationTrail") is not True or row.get("AccountId") != account or
                    not isinstance(binding, dict) or binding.get("caller_account_id") != account or
                    binding.get("identity_operation") != "sts:GetCallerIdentity" or
                    binding.get("describe_operation") != "cloudtrail:DescribeTrails" or
                    binding.get("include_shadow_trails") is not True or binding.get("trail_arn") != arn or
                    binding.get("capture_observed_at") != capture_at):
                raise Unavailable("organization trail native account binding unavailable")
        if (not match or match.group(2) != home or not name or source != home or
                provenance.get("operation") != "cloudtrail:DescribeTrails" or
                provenance.get("native_response_complete") is not True or arn in seen):
            raise Unavailable("trail identity, home Region, provenance, or uniqueness unavailable")
        seen.add(arn)
        if home == region:
            selected.append(row)
    return selected


def _logging_trails(trails):
    selected = []
    for trail in trails:
        state = get(trail, "Status.IsLogging", bool)
        if state:
            selected.append(trail)
    return selected


def _buckets(index, account, scope):
    rows = _rows(index, "bucket", account, scope, global_ok=True)
    buckets = {}
    for row in rows:
        name = get(row, "Name", str)
        if not name or name in buckets:
            raise Unavailable("bucket identity missing or duplicate")
        buckets[name] = row
    return buckets


def _bucket(trail, buckets):
    name = get(trail, "S3BucketName", str)
    if not name or name not in buckets:
        raise Unavailable("CloudTrail destination bucket unresolved")
    return name, buckets[name]


def _bucket_logging(bucket):
    logging = get(bucket, "Logging", dict)
    if logging.get("collection_status") not in (None, "collected", "empty"):
        raise Unavailable("bucket logging read incomplete")
    if "LoggingEnabled" not in logging:
        if logging.get("collection_status") in ("collected", "empty"):
            return False
        raise Unavailable("bucket logging absence unproven")
    enabled = get(logging, "LoggingEnabled", dict)
    target = get(enabled, "TargetBucket", str)
    prefix = get(enabled, "TargetPrefix", str)
    if not target:
        raise Unavailable("bucket logging target malformed")
    return True


def _log_groups(index, account, scope):
    rows = _rows(index, "log_group", account, scope)
    groups = {}
    for row in rows:
        arn = get(row, "arn", str).removesuffix(":*")
        match = _LOG_ARN.fullmatch(arn)
        if not match or match.group(3) != account or match.group(2) != scope.split("/", 1)[1] or arn in groups:
            raise Unavailable("log group identity unresolved")
        groups[arn] = row
    return groups


def _log_group(trail, groups, account, *, missing_is_none=False):
    arn = get(trail, "CloudWatchLogsLogGroupArn", str).removesuffix(":*")
    if not arn:
        return None
    match = _LOG_ARN.fullmatch(arn)
    if not match or match.group(2) != get(trail, "HomeRegion", str) or match.group(3) != account:
        raise Unavailable("CloudWatch destination log group unresolved")
    if arn not in groups:
        if missing_is_none:
            return None
        raise Unavailable("CloudWatch destination log group unresolved")
    return groups[arn]


def _keys(index, account, scope):
    rows = _rows(index, "kms_key", account, scope)
    keys = {}
    for row in rows:
        arn = get(row, "KeyArn", str)
        match = _KMS_ARN.fullmatch(arn)
        if not match or match.group(3) != account or match.group(2) != scope.split("/", 1)[1] or arn in keys:
            raise Unavailable("KMS key identity unresolved")
        keys[arn] = row
    return keys


def _cmk(reference, keys, region, account):
    if not isinstance(reference, str):
        raise Unavailable("KMS reference malformed")
    if not reference:
        return False
    match = _KMS_ARN.fullmatch(reference)
    if not match or match.group(2) != region or match.group(3) != account:
        raise Unavailable("KMS reference is not an exact same-account regional key ARN")
    if reference not in keys:
        raise Unavailable("KMS key reference unresolved")
    metadata = get(keys[reference], "Metadata.KeyMetadata", dict)
    if get(metadata, "Arn", str) != reference:
        raise Unavailable("KMS metadata identity mismatch")
    manager = get(metadata, "KeyManager", str)
    state = get(metadata, "KeyState", str)
    if manager not in ("CUSTOMER", "AWS") or state not in ("Enabled", "Disabled", "PendingDeletion", "PendingImport", "Unavailable"):
        raise Unavailable("KMS key state or manager unrecognized")
    return manager == "CUSTOMER" and state == "Enabled"


def _time(value):
    if not isinstance(value, str):
        raise Unavailable("timestamp malformed")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise Unavailable("timestamp malformed") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise Unavailable("timestamp timezone absent")
    return parsed.astimezone(timezone.utc)


def _fresh(value, context):
    age = (_time(get(context, "created_at", str)) - _time(value)).total_seconds()
    if age < 0:
        raise Unavailable("observation after snapshot capture")
    return age <= 86400


def _cloudtrail(item, index, check_id):
    context, account, region, scope = _context(item, index)
    trails = _trails(index, account, region, scope)
    if check_id in _BUCKET_LOG_IDS:
        if check_id == "aws_nist_cloudtrail_s3_logging_enabled":
            trails = _logging_trails(trails)
        if not trails:
            return "NOT_APPLICABLE", {"reason": "no applicable home-region trails"}
        buckets = _buckets(index, account, scope)
        failures = []
        for trail in trails:
            name, bucket = _bucket(trail, buckets)
            if not _bucket_logging(bucket):
                failures.append(name)
        return result(bool(failures), trail_count=len(trails), unlogged_buckets=sorted(set(failures)))
    if check_id == "aws_cloudtrail_bucket_lifecycle_retention_365":
        trails = _logging_trails(trails)
        if not trails:
            return "NOT_APPLICABLE", {"reason": "no logging home-region trails"}
        buckets = _buckets(index, account, scope)
        outside = sorted({get(trail, "S3BucketName", str) for trail in trails} - set(buckets))
        if outside:
            return "MANUAL", {"reason": "CloudTrail destination lifecycle is managed in an account outside this snapshot", "buckets": outside, "required_actions": ["s3:GetLifecycleConfiguration", "s3:GetBucketObjectLockConfiguration"]}
        failed, uncertain = [], []
        for trail in trails:
            name, bucket = _bucket(trail, buckets)
            prefix = get(trail, "S3KeyPrefix", str).strip("/")
            audit_prefix = (prefix + "/" if prefix else "") + "AWSLogs/"
            lifecycle = get(bucket, "Lifecycle", dict)
            if lifecycle.get("collection_status") not in (None, "collected", "empty"):
                raise Unavailable("bucket lifecycle read incomplete")
            rules = get(lifecycle, "Rules", list) if "Rules" in lifecycle else [] if lifecycle.get("collection_status") in ("collected", "empty") else None
            if rules is None:
                raise Unavailable("bucket lifecycle absence unproven")
            for rule in rules:
                rule_status = get(rule, "Status", str)
                if rule_status not in ("Enabled", "Disabled"):
                    raise Unavailable("lifecycle rule status unrecognized")
                if rule_status == "Disabled":
                    continue
                rule_prefix = rule.get("Prefix")
                if rule_prefix is None:
                    filter_obj = get(rule, "Filter", dict)
                    if "Prefix" in filter_obj:
                        rule_prefix = get(filter_obj, "Prefix", str)
                    elif not filter_obj:
                        rule_prefix = ""
                    else:
                        raise Unavailable("lifecycle tag or compound filter overlap unknown")
                if not isinstance(rule_prefix, str):
                    raise Unavailable("lifecycle prefix malformed")
                overlap = audit_prefix.startswith(rule_prefix) or rule_prefix.startswith(audit_prefix)
                if not overlap:
                    continue
                for field in ("Expiration", "NoncurrentVersionExpiration"):
                    if field in rule:
                        expiry = get(rule, field, dict)
                        days_field = "Days" if field == "Expiration" else "NoncurrentDays"
                        if days_field in expiry:
                            count = get(expiry, days_field, int)
                            if count < 365:
                                failed.append(name)
                        elif "Date" in expiry or "ExpiredObjectDeleteMarker" in expiry:
                            raise Unavailable("lifecycle expiry timing cannot be proven")
                        else:
                            raise Unavailable("lifecycle expiration duration missing")
            if name in failed:
                continue
            lock = get(bucket, "ObjectLock", dict)
            lock_status = get(lock, "collection_status", str)
            if lock_status not in ("collected", "empty"):
                raise Unavailable("Object Lock read incomplete")
            absent_lock = (lock.get("collection_status") == "empty" and lock.get("absent") is True and
                           get(lock, "error.code", str) == "ObjectLockConfigurationNotFoundError")
            if absent_lock:
                uncertain.append(name)
                continue
            if lock_status != "collected":
                raise Unavailable("Object Lock success or absence unproven")
            # GetObjectLockConfiguration retains its response wrapper in the
            # bucket collector; denied/malformed coverage remains authoritative.
            lock = get(lock, "ObjectLockConfiguration", dict)
            lock_enabled = get(lock, "ObjectLockEnabled", str)
            if lock_enabled not in ("Enabled", "Disabled"):
                raise Unavailable("Object Lock state unrecognized")
            lock_good = False
            if lock_enabled == "Enabled":
                retention = get(lock, "Rule.DefaultRetention", dict)
                mode = get(retention, "Mode", str)
                if mode not in ("COMPLIANCE", "GOVERNANCE"):
                    raise Unavailable("Object Lock mode unrecognized")
                days = retention.get("Days")
                years = retention.get("Years")
                if type(days) is int and years is None:
                    lock_good = days >= 365
                elif type(years) is int and days is None:
                    lock_good = years >= 1
                else:
                    raise Unavailable("Object Lock retention duration unavailable")
            if not lock_good:
                uncertain.append(name)
        if failed:
            return result(True, early_retention_buckets=sorted(set(failed)))
        if uncertain:
            return unknown("365-day Object Lock default retention not proven", buckets=sorted(set(uncertain)))
        return result(False, retained_buckets=sorted({get(t, "S3BucketName", str) for t in trails}))
    if check_id == "aws_cloudtrail_s3_siem_delivery":
        from ..collectors.aws_cloudtrail_s3_delivery_metadata import PROFILE, key_prefix, timestamp, valid_key
        trails = [trail for trail in trails if get(trail, "IsOrganizationTrail", bool)]
        if not trails:
            return "NOT_APPLICABLE", {"reason": "no organization trail in home Region"}
        failed, uncertain = [], []
        outside = [get(trail, "S3BucketName", str) for trail in trails if get(trail, "TrailARN", str).split(":")[4] != account]
        if outside:
            return "MANUAL", {"reason": "CloudTrail writes to a bucket outside this snapshot; correlate account-specific log-object metadata in the destination account", "buckets": sorted(set(outside)), "required_actions": ["s3:GetBucketLocation", "s3:ListBucket"]}
        for trail in trails:
            arn = get(trail, "TrailARN", str)
            try:
                objects = get(trail, "CloudTrailS3DeliveryObjects", dict)
                proof = get(objects, "_provenance", dict)
                org = get(objects, "OrganizationId", str)
                source_prefix = get(trail, "S3KeyPrefix", str)
                prefix = key_prefix(source_prefix) + "AWSLogs/" + org + "/" + account + "/CloudTrail/" + region + "/"
                if (get(objects, "collection_status", str) not in ("collected", "empty")
                        or get(objects, "listing_complete", bool) is not True
                        or get(objects, "TrailARN", str) != arn or get(objects, "AccountId", str) != account
                        or get(objects, "HomeRegion", str) != region or get(objects, "ExpectedBucketOwner", str) != account
                        or get(objects, "Bucket", str) != get(trail, "S3BucketName", str)
                        or not re.fullmatch(r"[a-z]{2}(?:-[a-z]+)+-[0-9]", get(objects, "BucketRegion", str))
                        or not re.fullmatch(r"o-[a-z0-9]{10,32}", org)
                        or get(objects, "S3KeyPrefix", str) != source_prefix or get(objects, "Prefix", str) != prefix
                        or get(objects, "source_operation", str) != "s3:ListObjectsV2"
                        or get(proof, "profile", str) != PROFILE or get(proof, "read_only", bool) is not True
                        or get(proof, "identity_operation", str) != "sts:GetCallerIdentity"
                        or get(proof, "organization_operation", str) != "organizations:DescribeOrganization"
                        or get(proof, "describe_operation", str) != "cloudtrail:DescribeTrails"
                        or get(proof, "native_destination_unique", bool) is not True
                        or get(proof, "scope", str) != "unique_destination_account_region_object_metadata_correlation"
                        or get(proof, "siem_receipt_verified", bool) is not False):
                    raise Unavailable("CloudTrail object metadata binding or completeness unavailable")
                rows = get(objects, "Contents", list)
                if ((objects["collection_status"] == "empty") != (not rows)
                        or len(rows) > 4000 or any(not isinstance(row, dict) for row in rows)):
                    raise Unavailable("CloudTrail S3 object inventory malformed")
                keys = [get(row, "Key", str) for row in rows]
                if len(set(keys)) != len(keys) or any(not valid_key(key, prefix) for key in keys):
                    raise Unavailable("CloudTrail S3 object paths are foreign or ambiguous")
                error = get(trail, "Status.LatestDeliveryError", str)
                delivery = timestamp(get(trail, "Status.LatestDeliveryTime"))
                object_freshness = [_fresh(timestamp(get(row, "LastModified")), context) for row in rows]
                if error or not _fresh(delivery, context) or not any(object_freshness):
                    failed.append(arn)
            except (Unavailable, ValueError, TypeError):
                uncertain.append(arn)
        if uncertain and not failed:
            return unknown("Complete uniquely correlated CloudTrail S3 delivery metadata unavailable", trails=uncertain,
                           semantics="S3 object metadata correlation only; SIEM receipt remains manual")
        return result(bool(failed), undelivered_trails=failed, semantics="S3 delivery only; SIEM receipt remains manual")
    if check_id in _INTEGRATION_IDS:
        if check_id == "aws_nist_cloudtrail_trail_integrated_with_logs":
            trails = _logging_trails(trails)
        if not trails:
            return "NOT_APPLICABLE", {"reason": "no applicable home-region trails"}
        groups = _log_groups(index, account, scope)
        failed = []
        for trail in trails:
            arn = get(trail, "TrailARN", str)
            if check_id == "aws.nist.cloudtrail_cloudwatch_integration" and not get(trail, "Status.IsLogging", bool):
                failed.append(arn)
            dest = get(trail, "CloudWatchLogsLogGroupArn", str)
            role = get(trail, "CloudWatchLogsRoleArn", str) if check_id != "aws.nist.cloudtrail_cloudwatch_integration" else None
            if not dest or (role is not None and not role):
                failed.append(arn)
                continue
            group = _log_group(trail, groups, account, missing_is_none=True)
            if group is None:
                failed.append(arn)
                continue
            if check_id == "aws_nist_cloudtrail_trail_integrated_with_logs":
                if get(trail, "IsOrganizationTrail", bool):
                    raise Unavailable("organization or multi-Region delivery permission scope unresolved")
                is_multiregion = get(trail, "IsMultiRegionTrail", bool)
                role_fact = get(trail, "CloudWatchLogsRole", dict)
                provenance = get(role_fact, "_provenance", dict)
                expected_stream = (f"arn:aws:logs:{region}:{account}:log-group:"
                                   f"{group['arn'].removesuffix(':*').split(':log-group:', 1)[1]}:"
                                   f"log-stream:{account}_CloudTrail_{region}")
                expected_scope = expected_stream.rsplit("_CloudTrail_", 1)[0] + "_CloudTrail_*" if is_multiregion else expected_stream + "*"
                if (get(role_fact, "role_arn", str) != role or
                        get(role_fact, "log_group_arn", str).removesuffix(":*") != dest.removesuffix(":*") or
                        get(role_fact, "simulation_context_complete", bool) is not True or
                        provenance.get("read_only") is not True or
                        provenance.get("trail_arn") != arn or
                        provenance.get("simulated_resource_arn") != expected_stream or
                        provenance.get("effective_live_delivery_verified") is not False or
                        provenance.get("SCP_RCP_verified") is not False or
                        provenance.get("operations") != ["DescribeTrails", "GetTrailStatus", "GetEventSelectors", "GetRole", "GetContextKeysForPrincipalPolicy", "SimulatePrincipalPolicy"]):
                    raise Unavailable("bounded CloudTrail delivery role evidence unavailable")
                decisions = get(role_fact, "decisions", dict)
                actions = {"logs:CreateLogStream", "logs:PutLogEvents"}
                if set(decisions) != actions or any(get(decisions, action, str) not in {"allowed", "explicitDeny", "implicitDeny"} for action in actions):
                    raise Unavailable("CloudTrail simulation decision unrecognized")
                if (get(role_fact, "trust_valid", bool) is not True or
                        get(decisions, "logs:CreateLogStream", str) != "allowed" or
                        get(decisions, "logs:PutLogEvents", str) != "allowed"):
                    failed.append(arn)
                else:
                    proof = get(provenance, "role_scope_proof", dict)
                    operations = get(proof, "operations", list)
                    permitted = {"ListRolePolicies", "ListAttachedRolePolicies", "GetRolePolicy", "GetPolicy", "GetPolicyVersion"}
                    if (get(role_fact, "full_role_stream_scope_proven", bool) is not True or
                            get(role_fact, "supported_stream_prefix", str) != expected_scope or
                            proof.get("method") != "complete_native_role_policies_v1" or
                            proof.get("identity_policy_inventory_complete") is not True or
                            proof.get("permissions_boundary_policy_complete") is not True or
                            proof.get("stream_prefix") != expected_scope or
                            proof.get("stream_region_scope", "home_region") != ("all_source_regions" if is_multiregion else "home_region") or
                            proof.get("SCP_RCP_verified") is not False or
                            proof.get("effective_live_delivery_verified") is not False or
                            any(not isinstance(op, str) for op in operations) or
                            len(set(operations)) != len(operations) or not set(operations) <= permitted or
                            not {"ListRolePolicies", "ListAttachedRolePolicies"} <= set(operations) or
                            not ("GetRolePolicy" in operations or {"GetPolicy", "GetPolicyVersion"} <= set(operations)) or
                            (("GetPolicy" in operations) != ("GetPolicyVersion" in operations))):
                        raise Unavailable("full CloudTrail stream role permission scope unproven")
        if check_id == "aws_nist_cloudtrail_trail_integrated_with_logs":
            return result(bool(failed), trails_without_integration=sorted(set(failed)),
                          permission_scope="declared role permissions for documented same-account streams across configured source Regions; live delivery and organization effects unverified")
        return result(bool(failed), trails_without_integration=sorted(set(failed)))
    if check_id in _KMS_IDS:
        if check_id in ("aws_nist_cloudtrail_trail_logs_encrypted_with_kms_cmk", "aws.nist.cloudtrail_cloudwatch_destination_kms"):
            trails = _logging_trails(trails) if check_id == "aws_nist_cloudtrail_trail_logs_encrypted_with_kms_cmk" else [t for t in trails if get(t, "CloudWatchLogsLogGroupArn", str)]
        if not trails:
            return "NOT_APPLICABLE", {"reason": "no applicable home-region trails"}
        keys = _keys(index, account, scope)
        need_groups = any(get(t, "CloudWatchLogsLogGroupArn", str) for t in trails)
        groups = _log_groups(index, account, scope) if need_groups else {}
        failed = []
        for trail in trails:
            arn = get(trail, "TrailARN", str)
            trail_good = _cmk(get(trail, "KmsKeyId", str), keys, region, account)
            group_good = True
            if get(trail, "CloudWatchLogsLogGroupArn", str):
                group = _log_group(trail, groups, account)
                group_good = _cmk(get(group, "kmsKeyId", str), keys, region, account)
            if not trail_good or not group_good:
                failed.append(arn)
        return result(bool(failed), trails_without_enabled_customer_keys=failed)
    raise Unavailable("unsupported CloudTrail predicate")

_BUCKET_LOG_IDS = {"aws.nist.all_cloudtrail_destination_bucket_access_logging", "aws_g6_all_cloudtrail_destination_bucket_access_logging", "aws_nist_cloudtrail_s3_logging_enabled"}
_INTEGRATION_IDS = {"aws.nist.cloudtrail_cloudwatch_integration", "aws_g6_cloudtrail_all_trails_cloudwatch_integration", "aws_nist_cloudtrail_trail_integrated_with_logs"}
_KMS_IDS = {"aws.nist.cloudtrail_cloudwatch_destination_kms", "aws_g6_cloudtrail_kms_destination_join", "aws_nist_cloudtrail_trail_logs_encrypted_with_kms_cmk"}

def _policy(context, scope, field):
    policy = get(context, "metadata.compliance_policy", dict)
    if get(policy, "status", str) != "collected" or get(policy, "scope", str) != scope:
        raise Unavailable("scoped compliance policy unavailable")
    value = get(policy, field, list if field not in ("approved_antimalware_packages",) else dict)
    if field == "approved_antimalware_packages":
        if not value or any(not isinstance(k, str) or not k or not isinstance(v, str) or not v for k, v in value.items()):
            raise Unavailable("approved antimalware baseline malformed")
    elif field == "required_applications":
        if not value or any(not isinstance(row, dict) or not isinstance(row.get("Name"), str) or not row["Name"] or not isinstance(row.get("minimumVersion"), str) or not row["minimumVersion"] for row in value):
            raise Unavailable("required application baseline malformed")
    else:
        if not value or any(not isinstance(v, str) or not v for v in value) or len(set(value)) != len(value):
            raise Unavailable("designated instance inventory malformed")
    return value


def _versions_at_least(actual, minimum):
    # Package versions that cannot be ordered numerically need an explicit policy comparator.
    pattern = re.compile(r"^[0-9]+(?:\.[0-9]+)*$")
    if not isinstance(actual, str) or not pattern.fullmatch(actual) or not pattern.fullmatch(minimum):
        raise Unavailable("application version comparison unavailable")
    left = tuple(map(int, actual.split(".")))
    right = tuple(map(int, minimum.split(".")))
    width = max(len(left), len(right))
    return left + (0,) * (width - len(left)) >= right + (0,) * (width - len(right))


def _ssm(item, index, check_id):
    context, account, region, scope = _context(item, index)
    rows = _rows(index, "ssm_managed_instance", account, scope)
    instances = {}
    for row in rows:
        iid = get(row, "InstanceId", str)
        if not iid or iid in instances:
            raise Unavailable("managed instance identity missing or duplicate")
        instances[iid] = row
    if check_id == "aws.pci.ssm.antimalware_inventory":
        baseline = _policy(context, scope, "approved_antimalware_packages")
        selected = list(instances)
    elif check_id == "aws.pci.ssm.required_applications":
        baseline = _policy(context, scope, "required_applications")
        selected = list(instances)
    else:
        field = "logging_host_instance_ids" if check_id == "aws_log_clock_sync_compliance" else "malware_managed_instance_ids"
        selected = _policy(context, scope, field)
        if any(iid not in instances for iid in selected):
            raise Unavailable("designated managed instance unresolved")
    if not selected:
        return "NOT_APPLICABLE", {"reason": "no applicable SSM managed instances"}
    failed = []
    for iid in selected:
        row = instances[iid]
        if check_id in ("aws.pci.ssm.antimalware_inventory", "aws.pci.ssm.required_applications"):
            inventory = get(row, "ApplicationInventory", dict)
            if (get(inventory, "collection_status", str) not in ("collected", "empty") or
                    get(inventory, "source_operation", str) != "ssm:ListInventoryEntries" or
                    get(inventory, "TypeName", str) != "AWS:Application" or
                    get(inventory, "InstanceId", str) != iid):
                raise Unavailable("AWS:Application inventory incomplete")
            entries = get(inventory, "Entries", list)
            if inventory["collection_status"] == "empty" and entries:
                raise Unavailable("malformed empty application inventory")
            observed = {}
            for entry in entries:
                name = get(entry, "Name", str)
                version = get(entry, "Version", str)
                if not name or not version:
                    raise Unavailable("malformed application entry")
                observed.setdefault(name, []).append(version)
            if check_id == "aws.pci.ssm.antimalware_inventory":
                matches = [_versions_at_least(version, minimum)
                           for name, minimum in baseline.items()
                           for version in observed.get(name, [])]
                if not any(matches):
                    failed.append({"instance_id": iid, "application": "approved antimalware package"})
            else:
                for requirement in baseline:
                    name, minimum = requirement["Name"], requirement["minimumVersion"]
                    satisfies = [_versions_at_least(version, minimum) for version in observed.get(name, [])]
                    if not any(satisfies):
                        failed.append({"instance_id": iid, "application": name})
        else:
            field = "TimeSyncCompliance" if check_id == "aws_log_clock_sync_compliance" else "MalwareDefinitionsCompliance"
            required_type = "Custom:TimeSync" if check_id == "aws_log_clock_sync_compliance" else "Custom:MalwareDefinitions"
            response = get(row, field, dict)
            if get(response, "collection_status", str) not in ("collected", "empty") or get(response, "source_operation", str) != "ssm:ListComplianceItems" or get(response, "ComplianceType", str) != required_type:
                raise Unavailable("custom compliance producer or item inventory unavailable")
            entries = get(response, "ComplianceItems", list)
            if response["collection_status"] == "empty" and entries:
                raise Unavailable("malformed empty custom compliance inventory")
            if not entries:
                raise Unavailable("custom compliance producer has no item")
            compliant = False
            for entry in entries:
                if get(entry, "ResourceId", str) != iid:
                    raise Unavailable("custom compliance item belongs to another instance")
                status = get(entry, "Status", str)
                if status not in ("COMPLIANT", "NON_COMPLIANT"):
                    raise Unavailable("custom compliance status unrecognized")
                timestamp = get(entry, "ExecutionSummary.ExecutionTime", str)
                fresh = _fresh(timestamp, context)
                details = get(entry, "Details", dict)
                if check_id == "aws_log_clock_sync_compliance":
                    offset = get(details, "offsetMilliseconds")
                    if type(offset) not in (int, float) or not (-1e12 < offset < 1e12):
                        raise Unavailable("time offset malformed")
                    good = status == "COMPLIANT" and fresh and abs(offset) <= 1000
                else:
                    version = get(details, "definitionVersion", str)
                    good = status == "COMPLIANT" and fresh and bool(version.strip())
                compliant |= good
            if not compliant:
                failed.append({"instance_id": iid})
    return result(bool(failed), checked_instance_count=len(selected), noncompliant_instances=failed)


def _evaluate(check_id, item, index):
    if check_id.startswith("aws.pci.ssm.") or check_id in ("aws_log_clock_sync_compliance", "aws_malware_definitions_fresh"):
        return _ssm(item, index, check_id)
    return _cloudtrail(item, index, check_id)

META = {'aws.nist.all_cloudtrail_destination_bucket_access_logging': {'provider': 'aws', 'resource_kind': 'cloudtrail', 'severity': 'medium', 'category': 'hardening', 'title': 'All CloudTrail destination buckets enable S3 access logging', 'remediation_hint': 'Enable access logging on each CloudTrail destination bucket.', 'proposed_spec_sha256': '78febca86292fb6af04e0a32209cd89eacbd49652ee25eacdf4ee3de3445428f'}, 'aws.nist.cloudtrail_cloudwatch_destination_kms': {'provider': 'aws', 'resource_kind': 'cloudtrail', 'severity': 'medium', 'category': 'hardening', 'title': 'CloudTrail and its CloudWatch log destination use customer-managed KMS keys', 'remediation_hint': 'Set customer-managed KMS keys on the trail and destination log group.', 'proposed_spec_sha256': 'd174f9f20050d56031bb66f0eac3097ecb5125e4e333394415d6dca10dce206c'}, 'aws.nist.cloudtrail_cloudwatch_integration': {'provider': 'aws', 'resource_kind': 'cloudtrail', 'severity': 'medium', 'category': 'hardening', 'title': 'Logging CloudTrail trails have a CloudWatch Logs destination', 'remediation_hint': 'Enable CloudTrail logging and configure a valid CloudWatch Logs group.', 'proposed_spec_sha256': '9fc459adbe9f767c18e26ad46b02fe77935a92bc9876ff561f6ef43426c342c8'}, 'aws_cloudtrail_bucket_lifecycle_retention_365': {'provider': 'aws', 'resource_kind': 'cloudtrail', 'severity': 'medium', 'category': 'hardening', 'title': 'CloudTrail destination retains logs for 365 days', 'remediation_hint': 'Set an S3 lifecycle rule on the CloudTrail destination bucket so current and noncurrent logs remain at least 365 days.', 'proposed_spec_sha256': '777a39c5f2fc6183fed8692646c8597b5dfcdeb00fdd91666d4afe5b3ce312da'}, 'aws_cloudtrail_s3_siem_delivery': {'provider': 'aws', 'resource_kind': 'cloudtrail', 'severity': 'medium', 'category': 'hardening', 'title': 'CloudTrail logs delivered to S3 and SIEM', 'remediation_hint': 'Set the CloudTrail destination S3 bucket and add a subscription or delivery path from its log group to the approved SIEM ARN.', 'proposed_spec_sha256': '6ff534fcae96a1ac94ec79fcdb9bb1b73c093fc3301ed582b2f7cb0070e76e2f'}, 'aws_g6_all_cloudtrail_destination_bucket_access_logging': {'provider': 'aws', 'resource_kind': 'cloudtrail', 'severity': 'medium', 'category': 'hardening', 'title': 'Every CloudTrail destination bucket has access logging', 'remediation_hint': 'Enable S3 server access logging on each CloudTrail destination bucket.', 'proposed_spec_sha256': 'f327488bd0e78298bad7ccc001422ccaff0bd37f25e801c8819bc24c740db4e7'}, 'aws_g6_cloudtrail_all_trails_cloudwatch_integration': {'provider': 'aws', 'resource_kind': 'cloudtrail', 'severity': 'medium', 'category': 'hardening', 'title': 'All CloudTrail trails integrate with CloudWatch Logs', 'remediation_hint': 'Configure a CloudWatch Logs log group and delivery role for each trail.', 'proposed_spec_sha256': '5b772d72467fe2312e55386a29a952e62645c8f56240dcd83a01876fea8360f5'}, 'aws_g6_cloudtrail_kms_destination_join': {'provider': 'aws', 'resource_kind': 'cloudtrail', 'severity': 'medium', 'category': 'hardening', 'title': 'CloudTrail and its CloudWatch log destination use CMKs', 'remediation_hint': 'Assign enabled customer-managed KMS keys to each trail and associated CloudWatch log group.', 'proposed_spec_sha256': 'bb52891ed24a58c53f74ae4c909d218aee2b60903a98c7da9edcf42a70ede859'}, 'aws_nist_cloudtrail_s3_logging_enabled': {'provider': 'aws', 'resource_kind': 'cloudtrail', 'severity': 'medium', 'category': 'compliance', 'title': 'Ensure S3 bucket access logging is enabled on the CloudTrail S3 bucket', 'remediation_hint': 'Configure the resource to satisfy the stated predicate and review missing inventory or policy inputs.', 'proposed_spec_sha256': 'de9038525ba32c465c6506aa82848a862601d81fe2456cfcfa0e04f707a8e8cb'}, 'aws_nist_cloudtrail_trail_integrated_with_logs': {'provider': 'aws', 'resource_kind': 'cloudtrail', 'severity': 'medium', 'category': 'compliance', 'title': 'CloudTrail trails should be integrated with CloudWatch logs', 'remediation_hint': 'Configure the resource to satisfy the stated predicate and review missing inventory or policy inputs.', 'proposed_spec_sha256': '34d9d1c3f3e448f63b5952d43320762ca8c32a7de354d2c2dca715e5fcea689b'}, 'aws_nist_cloudtrail_trail_logs_encrypted_with_kms_cmk': {'provider': 'aws', 'resource_kind': 'cloudtrail', 'severity': 'medium', 'category': 'compliance', 'title': 'CloudTrail trail logs should be encrypted with KMS CMK', 'remediation_hint': 'Configure the resource to satisfy the stated predicate and review missing inventory or policy inputs.', 'proposed_spec_sha256': '7503c659dca4a2b64b830d020e334d48a52d19b0406bb10bbe5793be372ae3b6'}, 'aws.pci.ssm.antimalware_inventory': {'provider': 'aws', 'resource_kind': 'ssm_managed_instance', 'severity': 'medium', 'category': 'malware', 'title': 'Managed instances have approved anti-malware agents', 'remediation_hint': 'Install the approved antimalware package on each SSM managed instance and update it to the minimum approved version.', 'proposed_spec_sha256': '768e27160d10cac450e536a6a454814c7849ec7d87714628ce9c984519b73ba8'}, 'aws.pci.ssm.required_applications': {'provider': 'aws', 'resource_kind': 'ssm_managed_instance', 'severity': 'medium', 'category': 'hardening', 'title': 'Required applications are installed on SSM instances', 'remediation_hint': 'Install each required application and minimum version on the managed instance, then refresh SSM AWS:Application inventory.', 'proposed_spec_sha256': 'f11f22378954473f861792f4edcfb935810815fa7d841e5efcffeefa83696edd'}, 'aws_log_clock_sync_compliance': {'provider': 'aws', 'resource_kind': 'ssm_managed_instance', 'severity': 'medium', 'category': 'hardening', 'title': 'Logging hosts have current clock synchronization', 'remediation_hint': 'Publish time-offset compliance from managed logging hosts to SSM.', 'proposed_spec_sha256': '6fca4ed77321f430bda74564f4c728fd82fe80a8a43b3e06f8364e6dd9be6aa7'}, 'aws_malware_definitions_fresh': {'provider': 'aws', 'resource_kind': 'ssm_managed_instance', 'severity': 'high', 'category': 'hardening', 'title': 'Malware signatures are reported current', 'remediation_hint': 'Publish daily malware-definition compliance from the endpoint agent to SSM.', 'proposed_spec_sha256': 'f751f1ccfd068cf67823bb0ed2826d644d4655cec61b4b568f1ffaf016db249c'}}

for _id, _meta in META.items():
    _deps = ["ssm_managed_instance"] if _meta["resource_kind"] == "ssm_managed_instance" else ["cloudtrail_account_inventory"]
    if _id in _BUCKET_LOG_IDS or _id == "aws_cloudtrail_bucket_lifecycle_retention_365":
        _deps.append("bucket")
    if _id in _INTEGRATION_IDS or _id in _KMS_IDS:
        _deps.append("log_group")
    if _id in _KMS_IDS:
        _deps.append("kms_key")
    @register(_id, "aws", _meta["category"] if _meta["category"] in ("hardening", "network", "exposure", "least_privilege", "iam_graph") else "hardening",
              _meta["resource_kind"], _meta["title"], _meta["severity"], "CM-6",
              _meta["remediation_hint"], target="scope", dependencies=_deps)
    def _registered(item, index, check_id=_id):
        return _evaluate(check_id, item, index)
    if _meta["resource_kind"] == "cloudtrail":
        _registered.evaluation_scope = "aws_region"
    if CHECKS[-1].category != _meta["category"]:
        CHECKS[-1] = replace(CHECKS[-1], category=_meta["category"])
