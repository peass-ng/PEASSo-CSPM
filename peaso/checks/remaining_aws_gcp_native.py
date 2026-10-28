"""Reviewed signed RDS declarations over existing, complete AWS facts.

No collector/API calls are made by evaluators.  Signed source kinds and control
edges are retained in the private companion; runtime kinds follow real AWS
collector types rather than inventing a second RDS inventory.
"""
from __future__ import annotations

import re
from collections import Counter

from . import alias_check, register, result
from .facts import Unavailable, complete_items, get, memoized
from ..snapshot import digest

_SCOPE = re.compile(r"([0-9]{12})/([a-z]{2}(?:-[a-z]+)+-[0-9])")
_RDS_CLUSTER = re.compile(r"arn:(aws|aws-cn|aws-us-gov):rds:([a-z0-9-]+):([0-9]{12}):cluster:(.+)")
_RDS_INSTANCE = re.compile(r"arn:(aws|aws-cn|aws-us-gov):rds:([a-z0-9-]+):([0-9]{12}):db:(.+)")
_IAM_ROLE = re.compile(r"arn:(aws|aws-cn|aws-us-gov):iam::([0-9]{12}):role/(?:[!-~]+/)?[A-Za-z0-9+=,.@_-]+")


def _authority(index, kind):
    context = get(index, "context", dict)
    if get(context, "provider", str) != "aws":
        raise Unavailable("AWS provider context unavailable")
    scope = get(context, "scope", str)
    match = _SCOPE.fullmatch(scope)
    if match is None:
        raise Unavailable("regional AWS scope unavailable")
    account, region = match.groups()
    envelopes = get(index, "collections", dict).get(kind)
    if not isinstance(envelopes, list) or len(envelopes) != 1:
        raise Unavailable("collection authority absent or ambiguous: " + kind)
    env = envelopes[0]
    if not isinstance(env, dict) or env.get("type") != kind or env.get("scope") != scope or env.get("account_id") != account or env.get("global") is not False:
        raise Unavailable("foreign collection authority: " + kind)
    wrappers = index.get(kind)
    if not isinstance(wrappers, list) or any(not isinstance(w, dict) or w.get("type") != kind or w.get("scope") != scope for w in wrappers):
        raise Unavailable("foreign or malformed resource wrapper: " + kind)
    rows = complete_items(index, kind)
    if len(wrappers) != len(rows) or any(w.get("data") != row for w, row in zip(wrappers, rows)):
        raise Unavailable("resource wrappers differ from inventory: " + kind)
    # Resource projection deduplicates by native ID. Compare the authoritative
    # envelope with the projected rows so duplicate or conflicting raw members
    # cannot silently become one apparently unique resource. Order is immaterial.
    native_rows = env.get("items")
    if not isinstance(native_rows, list) or len(native_rows) != len(rows):
        raise Unavailable("native inventory differs from projected resources: " + kind)
    try:
        if Counter(digest(row) for row in native_rows) != Counter(digest(row) for row in rows):
            raise Unavailable("native inventory differs from projected resources: " + kind)
    except (TypeError, ValueError) as exc:
        raise Unavailable("native inventory contains malformed members: " + kind) from exc
    return account, region, rows


def _scope_partition(index, account):
    metadata = get(get(index, "context", dict), "metadata", dict)
    identities = get(metadata, "caller_identities", list)
    partitions = set()
    for identity in identities:
        if not isinstance(identity, dict) or identity.get("Account") != account:
            continue
        arn = identity.get("Arn")
        match = re.fullmatch(r"arn:(aws|aws-cn|aws-us-gov):(iam|sts)::" + account + r":.+", arn) if isinstance(arn, str) else None
        if match is None:
            raise Unavailable("caller partition provenance malformed")
        partitions.add(match.group(1))
    if len(partitions) != 1:
        raise Unavailable("caller partition provenance absent or ambiguous")
    return partitions.pop()


def _bind_arn(item, account, region, pattern, name_key, *, partition=None):
    arn = get(item, name_key, str)
    match = pattern.fullmatch(arn)
    if match is None or match.group(2) != region or match.group(3) != account or (partition is not None and match.group(1) != partition):
        raise Unavailable("resource ARN outside audited partition/account/Region")
    if get(item, "AccountId", str) != account or get(item, "Region", str) != region:
        raise Unavailable("resource account/Region provenance missing")
    return arn, match.group(4)


def _rds_index(index):
    account, region, clusters = _authority(index, "rds_cluster")
    other_account, other_region, instances = _authority(index, "rds_instance")
    if (account, region) != (other_account, other_region):
        raise Unavailable("RDS cluster/instance scope mismatch")
    partition = _scope_partition(index, account)
    cluster_map, instance_map = {}, {}
    for row in clusters:
        arn, name = _bind_arn(row, account, region, _RDS_CLUSTER, "DBClusterArn", partition=partition)
        if get(row, "DBClusterIdentifier", str) != name or name in cluster_map:
            raise Unavailable("duplicate or conflicting RDS cluster")
        cluster_map[name] = row
    for row in instances:
        arn, name = _bind_arn(row, account, region, _RDS_INSTANCE, "DBInstanceArn", partition=partition)
        if get(row, "DBInstanceIdentifier", str) != name or name in instance_map:
            raise Unavailable("duplicate or conflicting RDS instance")
        instance_map[name] = row
    return cluster_map, instance_map, partition


@register("aws.nist.rds_cluster_member_enhanced_monitoring", "aws", "hardening", "rds_cluster",
          "Every RDS cluster member has Enhanced Monitoring and a monitoring role", "medium", "AU-12",
          "Enable Enhanced Monitoring and configure MonitoringRoleArn on each RDS cluster member.",
          dependencies=["rds_cluster", "rds_instance"])
def rds_cluster_member_monitoring(item, index):
    clusters, instances, partition = memoized(index, ("remaining_aws_gcp", "rds_member_index"), lambda: _rds_index(index))
    name = get(item, "DBClusterIdentifier", str)
    if name not in clusters or clusters[name] != item:
        raise Unavailable("RDS cluster differs from complete scoped inventory")
    members = get(item, "DBClusterMembers", list)
    if not members or any(not isinstance(m, dict) for m in members):
        raise Unavailable("RDS cluster member inventory unavailable")
    seen, missing = set(), []
    for member in members:
        member_id = get(member, "DBInstanceIdentifier", str)
        if not member_id or member_id in seen or member_id not in instances:
            raise Unavailable("RDS member missing, duplicated or outside scoped inventory")
        seen.add(member_id)
        instance = instances[member_id]
        if get(instance, "DBClusterIdentifier", str) != name:
            raise Unavailable("RDS instance belongs to a different cluster")
        interval = get(instance, "MonitoringInterval", int)
        if interval not in {0, 1, 5, 10, 15, 30, 60}:
            raise Unavailable("invalid monitoring interval")
        role = get(instance, "MonitoringRoleArn", str) if "MonitoringRoleArn" in instance or "MonitoringRoleArn" in instance.get("_coverage", {}) else ""
        if role:
            role_match = _IAM_ROLE.fullmatch(role)
            if role_match is None or role_match.group(1) != partition or role_match.group(2) != get(instance, "AccountId", str):
                raise Unavailable("monitoring role ARN outside audited partition/account or malformed")
        if interval == 0 or not role:
            missing.append(member_id)
    return result(bool(missing), cluster_identifier=name, members_without_monitoring=missing,
                  assessed_members=len(seen))


# The FedRAMP source uses <=0 while NIST says =0. DescribeDBInstances has a
# nonnegative MonitoringInterval domain; malformed negative facts are UNKNOWN
# in both. Therefore the valid-source PASS/FAIL and incomplete UNKNOWN coincide.
alias_check("aws_fedramp_rds_cluster_members_enhanced_monitoring", "aws.nist.rds_cluster_member_enhanced_monitoring")

_ECS_TASK = re.compile(r"arn:(aws|aws-cn|aws-us-gov):ecs:([a-z0-9-]+):([0-9]{12}):task-definition/([^:]+:[0-9]+)")
_CREDENTIAL_NAMES = frozenset({"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "ECS_ENGINE_AUTH_DATA"})


def _ecs_index(index):
    account, region, rows = _authority(index, "ecs_task_definition")
    by_arn = {}
    partition = _scope_partition(index, account)
    for row in rows:
        arn, _ = _bind_arn(row, account, region, _ECS_TASK, "taskDefinitionArn", partition=partition)
        if arn in by_arn:
            raise Unavailable("duplicate ECS task definition")
        by_arn[arn] = row
    return by_arn


@register("aws_ecs_task_definition_credential_environment_names", "aws", "hardening", "ecs_task_definition",
          "ECS task definition does not declare AWS credential environment names", "medium", "CM-6",
          "Remove credential environment names and use task role or secret references.",
          dependencies=["ecs_task_definition"])
def ecs_credential_environment_names(item, index):
    rows = memoized(index, ("remaining_aws_gcp", "ecs_task_definitions"), lambda: _ecs_index(index))
    arn = get(item, "taskDefinitionArn", str)
    if arn not in rows or rows[arn] != item:
        raise Unavailable("ECS task definition absent from complete scoped inventory")
    detail = get(item, "Definition", dict)
    if get(detail, "collection_status", str) != "collected":
        raise Unavailable("ECS DescribeTaskDefinition detail incomplete")
    definition = get(detail, "taskDefinition", dict)
    if get(definition, "taskDefinitionArn", str) != arn:
        raise Unavailable("ECS task definition detail identity mismatch")
    containers = get(definition, "containerDefinitions", list)
    if not containers or any(not isinstance(container, dict) for container in containers):
        raise Unavailable("ECS container inventory missing or malformed")
    seen, flagged = set(), []
    for container in containers:
        name = get(container, "name", str)
        if not name or name in seen:
            raise Unavailable("ECS container identity missing or duplicated")
        seen.add(name)
        environment = get(container, "environment", list)
        if any(not isinstance(entry, dict) for entry in environment):
            raise Unavailable("ECS environment name projection malformed")
        for entry in environment:
            variable = get(entry, "name", str)
            if not variable:
                raise Unavailable("ECS environment variable name missing")
            if variable in _CREDENTIAL_NAMES:
                flagged.append({"container": name, "name": variable})
    return result(bool(flagged), task_definition_arn=arn, credential_environment_names=flagged,
                  assessed_containers=len(containers))

_SECRET = re.compile(r"arn:(aws|aws-cn|aws-us-gov):secretsmanager:([a-z0-9-]+):([0-9]{12}):secret:([^:]+)")
_KMS_KEY = re.compile(r"arn:(aws|aws-cn|aws-us-gov):kms:([a-z0-9-]+):([0-9]{12}):key/([0-9A-Za-z-]+)")
_KMS_ID = re.compile(r"(?:[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}|mrk-[0-9a-fA-F]{32})")
_KMS_STATES = frozenset({"Enabled", "Disabled", "PendingDeletion", "PendingImport", "Unavailable", "Creating", "Updating"})


def _secret_index(index):
    return memoized(index, ("remaining_aws_gcp", "secrets_index"), lambda: _build_secret_index(index))


def _build_secret_index(index):
    account, region, rows = _authority(index, "secret")
    partition = _scope_partition(index, account)
    by_arn = {}
    for row in rows:
        arn, _ = _bind_arn(row, account, region, _SECRET, "ARN", partition=partition)
        if arn in by_arn:
            raise Unavailable("duplicate Secrets Manager ARN")
        by_arn[arn] = row
    return by_arn, account, region, partition


def _kms_index(index):
    account, region, rows = _authority(index, "kms_key")
    partition = _scope_partition(index, account)
    by_arn, by_id = {}, {}
    for row in rows:
        arn, key_id = _bind_arn(row, account, region, _KMS_KEY, "KeyArn", partition=partition)
        if get(row, "KeyId", str) != key_id:
            raise Unavailable("KMS ListKeys identity mismatch")
        if arn in by_arn or key_id in by_id:
            raise Unavailable("duplicate KMS key in complete scoped inventory")
        by_arn[arn] = row
        by_id[key_id] = row
    return by_arn, by_id, account, region, partition


@register("aws.pci.secretsmanager.kms_encryption_any", "aws", "hardening", "secret",
          "Secrets Manager secret uses an enabled AWS or customer managed KMS key", "medium", "SC-13",
          "Configure an enabled AWS or customer managed KMS key for the secret.",
          dependencies=["secret", "kms_key"])
def secret_uses_enabled_kms(item, index):
    secrets, account, region, partition = memoized(index, ("remaining_aws_gcp", "secrets_index"), lambda: _secret_index(index))
    arn = get(item, "ARN", str)
    if arn not in secrets or secrets[arn] != item:
        raise Unavailable("secret absent from complete scoped inventory")
    coverage = get(item, "_coverage", dict).get("KmsKeyId")
    if not isinstance(coverage, dict) or coverage.get("status") not in {"collected", "empty"} or coverage.get("source_operation") != "secretsmanager:DescribeSecret":
        raise Unavailable("KMS key reference lacks identity-bound DescribeSecret coverage")
    # AWS omits KmsKeyId for aws/secretsmanager in an authoritative
    # DescribeSecret response. AWS managed keys are permanently enabled.
    if "KmsKeyId" not in item:
        if coverage.get("status") != "empty" or coverage.get("native_member_present") is not False or coverage.get("documented_default") != "aws/secretsmanager":
            raise Unavailable("KMS key omission lacks documented DescribeSecret default proof")
        return result(False, secret_arn=arn, key_manager="AWS", key_state="Enabled",
                      key_reference="aws/secretsmanager", key_identity_source="documented_DescribeSecret_omission")
    if coverage.get("status") != "collected":
        raise Unavailable("KMS key reference contradicts DescribeSecret coverage")
    key_ref = get(item, "KmsKeyId", str)
    if not key_ref:
        raise Unavailable("empty KMS key reference is not a documented omission")
    keys_by_arn, keys_by_id, key_account, key_region, key_partition = memoized(
        index, ("remaining_aws_gcp", "kms_index"), lambda: _kms_index(index))
    if (account, region, partition) != (key_account, key_region, key_partition):
        raise Unavailable("secret and KMS key inventory scopes conflict")
    if key_ref.startswith("arn:"):
        match = _KMS_KEY.fullmatch(key_ref)
        if match is None or match.group(1) != partition or match.group(2) != region or match.group(3) != account:
            raise Unavailable("KMS key ARN is foreign, malformed or an unresolved alias")
        key = keys_by_arn.get(key_ref)
    elif _KMS_ID.fullmatch(key_ref):
        key = keys_by_id.get(key_ref)
    else:
        raise Unavailable("KMS alias or key reference cannot be resolved from ListKeys")
    if key is None:
        raise Unavailable("referenced KMS key absent from complete scoped inventory")
    # ListKeys establishes complete scoped identity. An unrelated DescribeKey
    # denial must not erase a known result for this exact referenced key.
    def selected_metadata():
        detail = get(key, "Metadata", dict)
        if get(detail, "collection_status", str) != "collected":
            raise Unavailable("KMS DescribeKey detail unavailable")
        metadata = get(detail, "KeyMetadata", dict)
        if get(metadata, "Arn", str) != get(key, "KeyArn", str) or get(metadata, "KeyId", str) != get(key, "KeyId", str):
            raise Unavailable("KMS DescribeKey identity mismatch")
        return metadata
    metadata = memoized(index, ("remaining_aws_gcp", "kms_metadata", get(key, "KeyArn", str)), selected_metadata)
    manager = get(metadata, "KeyManager", str)
    state = get(metadata, "KeyState", str)
    if manager not in {"AWS", "CUSTOMER"} or state not in _KMS_STATES:
        raise Unavailable("unrecognized KMS key manager or state")
    return result(state != "Enabled", secret_arn=arn, key_arn=get(metadata, "Arn", str),
                  key_manager=manager, key_state=state)
