"""AWS data, analytics, identity and devtools facts; read-only extension.

All I/O uses the shared scan scheduler (single-flight cache, global budget).
Only list/get/describe/batch_get operations are declared. Records are reduced
to explicit allowlists before they leave this module, so connection settings,
passwords, RADIUS shared secrets, certificate PEM/wallets, prompt text, data
source configuration, stack parameters/outputs and environment variable values
are never retained. A failed read keeps its status; only a documented
not-found becomes the {"collection_status": "empty", "absent": True} marker.
"""
from __future__ import annotations
import copy
import hashlib
import json
import re
from datetime import datetime, timezone

from .aws_b_services import _metadata

SPECS = {
    "athena_workgroup": ("athena", "list_work_groups", "WorkGroups"),
    "athena_session": ("athena", "list_sessions", "Sessions"),
    "backup_recovery_point": ("backup", "list_recovery_points_by_backup_vault", "RecoveryPoints"),
    "backup_copy_job": ("backup", "list_copy_jobs", "CopyJobs"),
    "redshift_datashare": ("redshift", "describe_data_shares_for_producer", "DataShares"),
    "workspaces_image": ("workspaces", "describe_workspace_images", "Images"),
    "datasync_task": ("datasync", "list_tasks", "Tasks"),
    "dax_cluster": ("dax", "describe_clusters", "Clusters"),
    "dlm_lifecycle_policy": ("dlm", "get_lifecycle_policies", "Policies"),
    "dms_endpoint": ("dms", "describe_endpoints", "Endpoints"),
    "dms_replication_task": ("dms", "describe_replication_tasks", "ReplicationTasks"),
    "dms_certificate": ("dms", "describe_certificates", "Certificates"),
    "drs_job": ("drs", "describe_jobs", "items"),
    "drs_source_server": ("drs", "describe_source_servers", "items"),
    "appautoscaling_target": ("application-autoscaling", "describe_scalable_targets", "ScalableTargets"),
    "elasticache_subnet_group": ("elasticache", "describe_cache_subnet_groups", "CacheSubnetGroups"),
    "efs_access_point": ("efs", "describe_access_points", "AccessPoints"),
    "efs_mount_target": ("efs", "describe_mount_targets", "MountTargets"),
    "emr_security_configuration": ("emr", "list_security_configurations", "SecurityConfigurations"),
    "emr_block_public_access_configuration": ("emr", "get_block_public_access_configuration", None),
    "firehose_delivery_stream": ("firehose", "list_delivery_streams", "DeliveryStreamNames"),
    "acmpca_certificate_authority": ("acm-pca", "list_certificate_authorities", "CertificateAuthorities"),
    "connect_instance": ("connect", "list_instances", "InstanceSummaryList"),
    "directory_service_directory": ("ds", "describe_directories", "DirectoryDescriptions"),
    "fms_policy": ("fms", "list_policies", "PolicyList"),
    "bedrock_guardrail": ("bedrock", "list_guardrails", "guardrails"),
    "bedrock_agent": ("bedrock-agent", "list_agents", "agentSummaries"),
    "bedrock_custom_model": ("bedrock", "list_custom_models", "modelSummaries"),
    "bedrock_prompt": ("bedrock-agent", "list_prompts", "promptSummaries"),
    "bedrock_knowledge_base": ("bedrock-agent", "list_knowledge_bases", "knowledgeBaseSummaries"),
    "bedrock_model_invocation_logging": ("bedrock", "get_model_invocation_logging_configuration", None),
    "iam_service_specific_credential": ("iam", "list_service_specific_credentials", "ServiceSpecificCredentials"),
    "codebuild_source_credential": ("codebuild", "list_source_credentials", "sourceCredentialsInfos"),
    "codebuild_report_group": ("codebuild", "list_report_groups", "reportGroups"),
    "cloudformation_stack": ("cloudformation", "describe_stacks", "Stacks"),
    "codedeploy_deployment_group": ("codedeploy", "list_applications", "applications"),
    "eventbridge_bus": ("events", "list_event_buses", "EventBuses"),
    "eventbridge_custom_bus": ("eventbridgev2", "list_event_buses", "EventBuses"),
    "lambda_microvm_image": ("lambda-microvms", "list_microvm_images", "items"),
    "eventbridge_endpoint": ("events", "list_endpoints", "Endpoints"),
    "eventbridge_schema_registry": ("schemas", "list_registries", "Registries"),
    "codeartifact_domain": ("codeartifact", "list_domains", "domains"),
    "codeartifact_repository": ("codeartifact", "list_repositories", "repositories"),
}
NATIVE_IDS = {
    "athena_workgroup": "Name", "athena_session": "SessionId", "backup_recovery_point": "RecoveryPointArn", "backup_copy_job": "CopyJobId", "redshift_datashare": "DataShareArn", "workspaces_image": "ImageId", "datasync_task": "TaskArn", "dax_cluster": "ClusterArn",
    "dlm_lifecycle_policy": "PolicyId", "dms_endpoint": "EndpointArn", "dms_replication_task": "ReplicationTaskArn", "dms_certificate": "CertificateArn",
    "drs_job": "jobID", "drs_source_server": "sourceServerID", "appautoscaling_target": "ScalableTargetARN", "elasticache_subnet_group": "ARN", "efs_access_point": "AccessPointArn",
    "efs_mount_target": "MountTargetId", "emr_security_configuration": "Name", "emr_block_public_access_configuration": "id",
    "firehose_delivery_stream": "DeliveryStreamARN", "acmpca_certificate_authority": "Arn", "connect_instance": "Arn",
    "directory_service_directory": "DirectoryId", "fms_policy": "PolicyArn", "bedrock_guardrail": "arn", "bedrock_agent": "agentId",
    "bedrock_custom_model": "modelArn", "bedrock_prompt": "arn", "bedrock_knowledge_base": "knowledgeBaseId", "bedrock_model_invocation_logging": "id",
    "iam_service_specific_credential": "ServiceSpecificCredentialId", "codebuild_source_credential": "arn", "codebuild_report_group": "arn",
    "cloudformation_stack": "StackId", "codedeploy_deployment_group": "deploymentGroupId", "eventbridge_bus": "Arn", "eventbridge_custom_bus": "EventBusArn", "eventbridge_endpoint": "Arn", "lambda_microvm_image": "imageArn",
    "eventbridge_schema_registry": "RegistryArn", "codeartifact_domain": "arn", "codeartifact_repository": "arn",
}
GLOBAL_TYPES = {"iam_service_specific_credential"}
READ_ACTIONS = {(service, operation) for service, operation, expression in SPECS.values()}
READ_ACTIONS.update({
    ("athena", "get_work_group"), ("athena", "list_work_groups"), ("athena", "get_session"),
    ("backup", "list_backup_vaults"), ("backup", "get_backup_vault_access_policy"),
    ("workspaces", "describe_workspace_image_permissions"),
    ("dynamodb", "get_resource_policy"), ("dynamodb", "list_tags_of_resource"),
    ("efs", "describe_file_systems"), ("efs", "describe_backup_policy"), ("efs", "describe_file_system_policy"),
    ("efs", "describe_mount_target_security_groups"),
    ("datasync", "describe_task"), ("docdb", "describe_db_cluster_parameters"),
    ("emr", "describe_security_configuration"), ("firehose", "describe_delivery_stream"),
    ("wafv2", "get_web_acl_for_resource"), ("connect", "describe_instance_attribute"),
    ("ds", "describe_event_topics"), ("ds", "list_log_subscriptions"), ("ds", "get_snapshot_limits"), ("ds", "list_certificates"),
    ("ds", "describe_shared_directories"), ("fms", "list_compliance_status"),
    ("bedrock", "get_guardrail"), ("bedrock", "get_custom_model"), ("bedrock-agent", "get_prompt"),
    ("bedrock-agent", "list_data_sources"), ("bedrock-agent", "get_data_source"),
    ("codebuild", "batch_get_projects"), ("codebuild", "list_builds_for_project"), ("codebuild", "batch_get_builds"),
    ("codebuild", "batch_get_report_groups"), ("codedeploy", "list_deployment_groups"), ("codedeploy", "batch_get_deployment_groups"),
    ("ecr", "describe_images"), ("ecr", "describe_image_scan_findings"), ("events", "describe_event_bus"), ("schemas", "get_resource_policy"),
    ("codeartifact", "get_domain_permissions_policy"), ("codeartifact", "get_repository_permissions_policy"),
    ("codeartifact", "list_packages"), ("codeartifact", "list_package_versions"),
})

_BATCH = 100


def _aws():
    from . import aws
    return aws


def _pick(value, keys):
    """Explicit allowlist projection; nested dicts are given as {key: subkeys}."""
    if not isinstance(value, dict):
        return value
    out = {}
    for key in keys:
        name, sub = (key, None) if isinstance(key, str) else key
        if name not in value:
            continue
        item = value[name]
        if sub is None:
            out[name] = copy.deepcopy(item)
        elif isinstance(item, list):
            out[name] = [_pick(row, sub) for row in item]
        else:
            out[name] = _pick(item, sub)
    return out


def _status(response):
    return {key: response[key] for key in ("collection_status", "absent", "error") if key in response}


def _detail(requests, session, region, service, operation, *, absent=(), keys=None, **arguments):
    response = requests.detail(session, service, region, operation, absent=absent, **arguments)
    if response.get("collection_status") != "collected":
        return response
    return {**(_metadata(response) if keys is None else _pick(response, keys)), "collection_status": "collected"}


def _list(read, keys=None):
    items = [_metadata(row) if keys is None else _pick(row, keys) for row in read.items]
    out = {"collection_status": read.status, "items": items}
    if read.error:
        out["error"] = read.error
    return out


def _unavailable(code):
    return {"collection_status": "not_collected", "error": {"code": code}}


def _result(items, failures):
    aws = _aws()
    if failures:
        return aws.ReadResult(items, "partial" if items else failures[0][0], failures[0][1])
    return aws.ReadResult(items, "collected" if items else "empty")


def _failure(exc):
    failure = _aws()._failure(exc)
    return failure.status, {"code": failure.code}


def _paged(service, operation, expression, tokens=None, **fixed):
    """Primary list for an operation botocore declares without a paginator."""
    def fetch(requests, session, region, account):
        return requests.pages(session, service, region, operation, expression, _tokens=tokens, **fixed)
    return fetch


def _athena_sessions(requests, session, region, account):
    """Collect only the exact role and state of sessions in listed workgroups."""
    groups = requests.pages(session, "athena", region, "list_work_groups", "WorkGroups",
                            _tokens=("NextToken", "NextToken"))
    if groups.status not in ("collected", "empty", "partial"):
        return _aws().ReadResult([], groups.status, groups.error)
    rows = []
    failures = [(groups.status, groups.error)] if groups.status == "partial" else []
    for group in groups.items:
        name = group.get("Name") if isinstance(group, dict) else None
        if not isinstance(name, str) or not name:
            failures.append(("malformed", {"code": "athena_workgroup_name_missing"}))
            continue
        listed = requests.pages(session, "athena", region, "list_sessions", "Sessions",
                                _tokens=("NextToken", "NextToken"), WorkGroup=name)
        if listed.status not in ("collected", "empty"):
            failures.append((listed.status, listed.error))
        for summary in listed.items:
            session_id = summary.get("SessionId") if isinstance(summary, dict) else None
            if not isinstance(session_id, str) or not session_id:
                failures.append(("malformed", {"code": "athena_session_id_missing"}))
                continue
            detail = requests.detail(session, "athena", region, "get_session", SessionId=session_id)
            if detail.get("collection_status") != "collected":
                failures.append((detail.get("collection_status", "malformed"), detail.get("error")))
                continue
            if detail.get("SessionId") != session_id or detail.get("WorkGroup") != name:
                failures.append(("malformed", {"code": "athena_session_identity_mismatch"}))
                continue
            config = detail.get("SessionConfiguration")
            status = detail.get("Status")
            rows.append({"SessionId": session_id, "WorkGroup": name,
                         "SessionConfiguration": _pick(config, ["ExecutionRole"]),
                         "Status": _pick(status, ["State"]),
                         "NotebookVersion": detail.get("NotebookVersion"),
                         "EngineVersion": detail.get("EngineVersion")})
    return _result(rows, failures)


# ----------------------------------------------------------------------------- data

def _recovery_points(requests, session, region, account):
    vaults = requests.pages(session, "backup", region, "list_backup_vaults", "BackupVaultList")
    if vaults.status not in ("collected", "empty"):
        return _aws().ReadResult([], vaults.status, vaults.error)
    items, failures = [], []
    for vault in vaults.items:
        name = vault.get("BackupVaultName") if isinstance(vault, dict) else None
        if not isinstance(name, str):
            failures.append(("malformed", {"code": "malformed_backup_vault"}))
            continue
        read = requests.pages(session, "backup", region, "list_recovery_points_by_backup_vault", "RecoveryPoints", BackupVaultName=name)
        if read.status not in ("collected", "empty"):
            failures.append((read.status, read.error))
        for row in read.items:
            items.append(_pick(row, ["RecoveryPointArn", "BackupVaultName", "BackupVaultArn", "ResourceArn", "ResourceType", "IsEncrypted",
                "EncryptionKeyArn", "Lifecycle", "CalculatedLifecycle", "Status", "CreationDate", "VaultType"]))
    return _result(items, failures)


def _copy_jobs(requests, session, region, account):
    read = requests.pages(session, "backup", region, "list_copy_jobs", "CopyJobs",
                          _tokens=("NextToken", "NextToken"))
    read.items = [_pick(row, ["CopyJobId", "AccountId", "State", "SourceBackupVaultArn",
                              "SourceRecoveryPointArn", "DestinationBackupVaultArn",
                              "DestinationRecoveryPointArn", "CompletionDate", "IsParent"])
                  for row in read.items]
    return read


def _redshift_datashares(requests, session, region, account):
    read = requests.pages(session, "redshift", region, "describe_data_shares_for_producer", "DataShares",
                          _tokens=("Marker", "Marker"))
    read.items = [_pick(row, ["DataShareArn", "ProducerArn", "ManagedBy", "AllowPubliclyAccessibleConsumers",
                              ("DataShareAssociations", ["ConsumerIdentifier", "ConsumerRegion", "Status",
                                                         "ProducerAllowedWrites", "ConsumerAcceptedWrites"])])
                  for row in read.items]
    return read


def _workspaces_images(requests, session, region, account):
    read = requests.pages(session, "workspaces", region, "describe_workspace_images", "Images",
                          ImageType="OWNED", _tokens=("NextToken", "NextToken"))
    if read.status not in ("collected", "empty") and not read.items:
        return _aws().ReadResult([], read.status, read.error)
    rows, failures = [], [] if read.status in ("collected", "empty") else [(read.status, read.error)]
    for item in read.items:
        image = _pick(item, ["ImageId", "OwnerAccountId", "State", "RequiredTenancy"])
        image_id = image.get("ImageId") if isinstance(image, dict) else None
        if (not isinstance(image_id, str) or not re.fullmatch(r"wsi-[0-9a-z]{9,63}", image_id) or
                image.get("OwnerAccountId") != account):
            failures.append(("malformed", {"code": "unattributed_workspace_image"}))
            continue
        permissions = requests.pages(session, "workspaces", region, "describe_workspace_image_permissions",
                                     "ImagePermissions", ImageId=image_id, _tokens=("NextToken", "NextToken"))
        image["SharedPermissions"] = _list(permissions, ["SharedAccountId"])
        image["SharedPermissions"]["ImageId"] = image_id
        rows.append(image)
    return _result(rows, failures)


def _drs_jobs(requests, session, region, account):
    read = requests.pages(session, "drs", region, "describe_jobs", "items")
    if read.error and read.error.get("code") == "UninitializedAccountException" and not read.items:
        # Documented: Elastic Disaster Recovery was never initialized here, so no jobs exist.
        return _aws().ReadResult([], "empty", {"code": "UninitializedAccountException"})
    read.items = [_pick(row, ["jobID", "arn", "type", "status", "initiatedBy", "creationDateTime", "endDateTime"]) for row in read.items]
    return read


def _drs_source_servers(requests, session, region, account):
    """Current DRS source/replication facts, without recovery job history."""
    read = requests.pages(session, "drs", region, "describe_source_servers", "items")
    if read.error and read.error.get("code") == "UninitializedAccountException" and not read.items:
        return _aws().ReadResult([], "empty", {"code": "UninitializedAccountException"})
    read.items = [_pick(row, ["sourceServerID", ("dataReplicationInfo", ["dataReplicationState"])]) for row in read.items]
    return read


def _scalable_targets(requests, session, region, account):
    return requests.pages(session, "application-autoscaling", region, "describe_scalable_targets", "ScalableTargets", ServiceNamespace="dynamodb")


def _mount_targets(requests, session, region, account):
    systems = requests.pages(session, "efs", region, "describe_file_systems", "FileSystems")
    if systems.status not in ("collected", "empty"):
        return _aws().ReadResult([], systems.status, systems.error)
    items, failures = [], []
    for system in systems.items:
        fs_id = system.get("FileSystemId") if isinstance(system, dict) else None
        if not isinstance(fs_id, str):
            failures.append(("malformed", {"code": "malformed_file_system"}))
            continue
        read = requests.pages(session, "efs", region, "describe_mount_targets", "MountTargets", FileSystemId=fs_id)
        if read.status not in ("collected", "empty"):
            failures.append((read.status, read.error))
        for row in read.items:
            item = _pick(row, ["MountTargetId", "FileSystemId", "SubnetId", "VpcId", "AvailabilityZoneId", "AvailabilityZoneName",
                "LifeCycleState", "NetworkInterfaceId", "OwnerId", "IpAddress", "Ipv6Address"])
            if isinstance(item.get("MountTargetId"), str):
                groups = _aws()._single(requests, session, region, "efs", "describe_mount_target_security_groups", MountTargetId=item["MountTargetId"])
                if groups.status == "collected" and len(groups.items) == 1 and isinstance(groups.items[0].get("SecurityGroups"), list):
                    item["SecurityGroups"] = groups.items[0]["SecurityGroups"]
                else:
                    item["_coverage"] = {"SecurityGroups": {"status": groups.status if groups.status != "collected" else "malformed"}}
            items.append(item)
    return _result(items, failures)


def _emr_block_public_access(requests, session, region, account):
    aws = _aws()
    read = aws._single(requests, session, region, "emr", "get_block_public_access_configuration")
    read.items = [{**_pick(row, ["BlockPublicAccessConfiguration", "BlockPublicAccessConfigurationMetadata"]),
        "id": f"emr-block-public-access/{account}/{region}"} for row in read.items]
    return read


def _firehose_streams(requests, session, region, account):
    names, start, seen, page = [], None, set(), 0
    try:
        while True:
            page += 1
            if requests.max_pages is not None and page > requests.max_pages:
                raise _aws().ReadFailure("not_collected", "page_limit")
            arguments = {"Limit": 100, **({"ExclusiveStartDeliveryStreamName": start} if start else {})}
            response = requests.call(session, "firehose", region, "list_delivery_streams", **arguments)
            batch = response.get("DeliveryStreamNames")
            more = response.get("HasMoreDeliveryStreams")
            if not isinstance(batch, list) or any(not isinstance(name, str) for name in batch) or not isinstance(more, bool):
                raise _aws().ReadFailure("malformed", "malformed_response")
            names.extend(batch)
            if not more:
                break
            if not batch or batch[-1] in seen:
                raise _aws().ReadFailure("malformed", "repeated_pagination_token")
            seen.add(batch[-1])
            start = batch[-1]
    except Exception as exc:
        status, error = _failure(exc)
        return _aws().ReadResult([], status, error)
    items, failures = [], []
    for name in names:
        response = requests.detail(session, "firehose", region, "describe_delivery_stream", absent=("ResourceNotFoundException",), DeliveryStreamName=name)
        if response.get("absent"):
            continue  # deleted between list and describe
        description = response.get("DeliveryStreamDescription")
        if response.get("collection_status") != "collected" or not isinstance(description, dict):
            failures.append((response.get("collection_status", "malformed"), response.get("error", {"code": "malformed_response"})))
            items.append({"DeliveryStreamName": name, **_status(response)})
            continue
        # Destinations (endpoint credentials, HEC tokens, usernames) are never retained.
        items.append(_pick(description, ["DeliveryStreamName", "DeliveryStreamARN", "DeliveryStreamStatus", "DeliveryStreamType",
            "DeliveryStreamEncryptionConfiguration", "VersionId", "CreateTimestamp", "LastUpdateTimestamp"]))
    return _result(items, failures)


# ----------------------------------------------------------------------------- devtools

def _service_specific_credentials(requests, session, region, account):
    # AllUsers is account-wide; omitting ServiceName includes every supported
    # service rather than silently excluding CodeCommit, Keyspaces or Logs.
    # This metadata API has no last-used field: creation age is not inactivity.
    read = requests.pages(session, "iam", region, "list_service_specific_credentials", "ServiceSpecificCredentials",
        _tokens=("Marker", "Marker"), AllUsers=True)
    read.items = [_pick(row, ["ServiceSpecificCredentialId", "UserName", "ServiceName", "Status", "CreateDate", "ExpirationDate"]) for row in read.items]
    return read


def _deployment_groups(requests, session, region, account):
    apps = requests.pages(session, "codedeploy", region, "list_applications", "applications")
    if apps.status not in ("collected", "empty"):
        return _aws().ReadResult([], apps.status, apps.error)
    items, failures = [], []
    for app in apps.items:
        if not isinstance(app, str):
            failures.append(("malformed", {"code": "malformed_application"}))
            continue
        groups = requests.pages(session, "codedeploy", region, "list_deployment_groups", "deploymentGroups", applicationName=app)
        if groups.status not in ("collected", "empty"):
            failures.append((groups.status, groups.error))
        for offset in range(0, len(groups.items), _BATCH):
            try:
                response = requests.call(session, "codedeploy", region, "batch_get_deployment_groups",
                    applicationName=app, deploymentGroupNames=groups.items[offset:offset + _BATCH])
            except Exception as exc:
                failures.append(_failure(exc))
                continue
            rows = response.get("deploymentGroupsInfo")
            if not isinstance(rows, list) or response.get("errorMessage"):
                failures.append(("partial" if isinstance(rows, list) else "malformed", {"code": "batch_get_incomplete"}))
            for row in rows if isinstance(rows, list) else []:
                items.append(_pick(row, ["applicationName", "deploymentGroupName", "deploymentGroupId", "computePlatform", "deploymentConfigName",
                    "serviceRoleArn", "deploymentStyle", "autoRollbackConfiguration", "alarmConfiguration",
                    # Instance targeting (EC2/on-premises tag filters and Auto Scaling groups) for the privesc host join.
                    "ec2TagFilters", "ec2TagSet", "onPremisesInstanceTagFilters", "onPremisesTagSet", "autoScalingGroups"]))
    return _result(items, failures)


def _custom_models(requests, session, region, account):
    return requests.pages(session, "bedrock", region, "list_custom_models", "modelSummaries", isOwned=True)


def _model_invocation_logging(requests, session, region, account):
    read = _aws()._single(requests, session, region, "bedrock", "get_model_invocation_logging_configuration")
    read.items = [{**_pick(row, ["loggingConfig"]), "id": f"bedrock-model-invocation-logging/{account}/{region}"} for row in read.items]
    return read


FETCHERS = {
    "athena_workgroup": _paged("athena", "list_work_groups", "WorkGroups", ("NextToken", "NextToken")),
    "athena_session": _athena_sessions,
    "backup_recovery_point": _recovery_points,
    "backup_copy_job": _copy_jobs,
    "redshift_datashare": _redshift_datashares,
    "workspaces_image": _workspaces_images,
    "drs_job": _drs_jobs,
    "drs_source_server": _drs_source_servers,
    "appautoscaling_target": _scalable_targets,
    "efs_mount_target": _mount_targets,
    "emr_block_public_access_configuration": _emr_block_public_access,
    "firehose_delivery_stream": _firehose_streams,
    "iam_service_specific_credential": _service_specific_credentials,
    "codedeploy_deployment_group": _deployment_groups,
    "bedrock_custom_model": _custom_models,
    "bedrock_model_invocation_logging": _model_invocation_logging,
    "eventbridge_bus": _paged("events", "list_event_buses", "EventBuses", ("NextToken", "NextToken")),
    "eventbridge_custom_bus": _paged("eventbridgev2", "list_event_buses", "EventBuses", ("NextToken", "NextToken")),
    "lambda_microvm_image": _paged("lambda-microvms", "list_microvm_images", "items", ("nextToken", "nextToken")),
    "eventbridge_endpoint": _paged("events", "list_endpoints", "Endpoints", ("NextToken", "NextToken")),
}


# ----------------------------------------------------------------------------- enrichers

def _each(function):
    def enrich(requests, session, region, items):
        # Independent per-resource reads run concurrently, in input order.
        from .aws_request_pool import ordered_map
        return ordered_map(requests, items, lambda item: function(requests, session, region, copy.deepcopy(item)))
    return enrich


def _project(keys):
    return _each(lambda requests, session, region, item: _pick(item, keys))


@_each
def _bedrock_agent(requests, session, region, item):
    from .aws_bedrock_security_metadata import agent_metadata
    summary = _pick(item, ["agentId", "agentName", "agentStatus", "latestAgentVersion", "updatedAt", "guardrailConfiguration"])
    return agent_metadata(requests, session, region, summary)


@_each
def _athena(requests, session, region, item):
    item = _metadata(item)
    item["WorkGroup"] = _detail(requests, session, region, "athena", "get_work_group", WorkGroup=item["Name"])
    return item


@_each
def _backup_vault(requests, session, region, item):
    # Same cached GetBackupVaultAccessPolicy read; a vault without a policy is the absent marker.
    item["Policy"] = _detail(requests, session, region, "backup", "get_backup_vault_access_policy",
        absent=("ResourceNotFoundException",), keys=["BackupVaultName", "BackupVaultArn", "Policy"], BackupVaultName=item["BackupVaultName"])
    return item


@_each
def _dynamodb_table(requests, session, region, item):
    table = item.get("Table")
    arn = table.get("Table", {}).get("TableArn") if isinstance(table, dict) and table.get("collection_status") in (None, "collected") else None
    if not isinstance(arn, str):
        item["ResourcePolicy"] = item["Tags"] = _unavailable("table_arn_unavailable")
        return item
    item["ResourcePolicy"] = _detail(requests, session, region, "dynamodb", "get_resource_policy",
        absent=("PolicyNotFoundException",), keys=["Policy", "RevisionId"], ResourceArn=arn)
    item["Tags"] = _list(requests.pages(session, "dynamodb", region, "list_tags_of_resource", "Tags", ResourceArn=arn), ["Key", "Value"])
    return item


@_each
def _efs_file_system(requests, session, region, item):
    fs_id = item["FileSystemId"]
    item["BackupPolicy"] = _detail(requests, session, region, "efs", "describe_backup_policy", absent=("PolicyNotFound",),
        keys=["BackupPolicy"], FileSystemId=fs_id)
    item["Policy"] = _detail(requests, session, region, "efs", "describe_file_system_policy", absent=("PolicyNotFound",),
        keys=["FileSystemId", "Policy"], FileSystemId=fs_id)
    return item


@_each
def _datasync_task(requests, session, region, item):
    item = _pick(item, ["TaskArn", "Name", "Status", "TaskMode"])
    item["Task"] = _detail(requests, session, region, "datasync", "describe_task", keys=["TaskArn", "Name", "Status", "CloudWatchLogGroupArn",
        "Options", "SourceLocationArn", "DestinationLocationArn", "TaskMode", "CreationTime"], TaskArn=item["TaskArn"])
    return item


@_each
def _docdb_cluster(requests, session, region, item):
    if item.get("Engine") != "docdb":
        return item
    group = item.get("DBClusterParameterGroup")
    if not isinstance(group, str):
        item["ClusterParameterGroupValues"] = _unavailable("parameter_group_unavailable")
        return item
    read = requests.pages(session, "docdb", region, "describe_db_cluster_parameters", "Parameters", DBClusterParameterGroupName=group)
    if read.status not in ("collected", "empty"):
        item["ClusterParameterGroupValues"] = {"collection_status": read.status, "error": read.error}
        return item
    # Only the tls parameter is retained; a missing value stays unknown downstream.
    values = {row["ParameterName"]: row["ParameterValue"] for row in read.items
        if isinstance(row, dict) and row.get("ParameterName") == "tls" and isinstance(row.get("ParameterValue"), str)}
    item["ClusterParameterGroupValues"] = values
    return item


_DMS_ENDPOINT = ["EndpointArn", "EndpointIdentifier", "EndpointType", "EngineName", "EngineDisplayName", "Status", "SslMode", "CertificateArn",
    "KmsKeyId", ("MongoDbSettings", ["AuthType", "AuthMechanism", "AuthSource"]), ("NeptuneSettings", ["IamAuthEnabled"]),
    ("RedisSettings", ["ServerName", "Port", "SslSecurityProtocol", "AuthType", "SslCaCertificateArn"])]
_DMS_TASK = ["ReplicationTaskArn", "ReplicationTaskIdentifier", "SourceEndpointArn", "TargetEndpointArn", "ReplicationInstanceArn",
    "MigrationType", "Status", "ReplicationTaskSettings"]
_DMS_CERTIFICATE = ["CertificateArn", "CertificateIdentifier", "CertificateOwner", "CertificateCreationDate", "ValidFromDate", "ValidToDate",
    "SigningAlgorithm", "KeyLength"]


@_each
def _emr_security_configuration(requests, session, region, item):
    item = _pick(item, ["Name", "CreationDateTime"])
    detail = _detail(requests, session, region, "emr", "describe_security_configuration", Name=item["Name"])
    if detail.get("collection_status") == "collected":
        try:
            document = json.loads(detail.get("SecurityConfiguration"))
        except (TypeError, ValueError):
            detail = {"collection_status": "malformed", "error": {"code": "malformed_security_configuration"}}
        else:
            if not isinstance(document, dict):
                detail = {"collection_status": "malformed", "error": {"code": "malformed_security_configuration"}}
            else:
                # Retain only the runtime-role enablement bit from the
                # authorization block; its external ID and other contents
                # are not needed for this inventory.
                kept = _pick(document, ["EncryptionConfiguration", "InstanceMetadataServiceConfiguration"])
                authorization = document.get("AuthorizationConfiguration") or {}
                iam = (authorization.get("IAMConfiguration") or {}) if isinstance(authorization, dict) else {}
                if isinstance(iam, dict) and type(iam.get("EnableApplicationScopedIAMRole")) is bool:
                    kept_iam = {"EnableApplicationScopedIAMRole": iam["EnableApplicationScopedIAMRole"]}
                    scoped = iam.get("ApplicationScopedIAMRoleConfiguration") or {}
                    external = scoped.get("ExternalId") if isinstance(scoped, dict) else None
                    if isinstance(external, str) and external:
                        kept_iam["ExternalIdSha256"] = hashlib.sha256(external.encode()).hexdigest()
                    kept["AuthorizationConfiguration"] = {"IAMConfiguration": kept_iam}
                detail = {"collection_status": "collected", "Name": detail.get("Name"), "SecurityConfiguration": json.dumps(kept, sort_keys=True)}
    item["Configuration"] = detail
    return item


# ----------------------------------------------------------------------------- identity

_RADIUS = ["RadiusServers", "RadiusServersIpv6", "RadiusPort", "RadiusTimeout", "RadiusRetries", "AuthenticationProtocol", "DisplayLabel", "UseSameUsername"]


@_each
def _cognito_user_pool(requests, session, region, item):
    configuration = item.get("Configuration")
    pool = configuration.get("UserPool") if isinstance(configuration, dict) and configuration.get("collection_status") in (None, "collected") else None
    arn = pool.get("Arn") if isinstance(pool, dict) else None
    if not isinstance(arn, str):
        item["WebAcl"] = _unavailable("user_pool_arn_unavailable")
        return item
    item["WebAcl"] = _detail(requests, session, region, "wafv2", "get_web_acl_for_resource", keys=[("WebACL", ["Name", "Id", "ARN"])], ResourceArn=arn)
    return item


@_each
def _connect_instance(requests, session, region, item):
    item = _pick(item, ["Id", "Arn", "InstanceAlias", "IdentityManagementType", "InstanceStatus", "CreatedTime"])
    item["ContactflowLogs"] = _detail(requests, session, region, "connect", "describe_instance_attribute", absent=("ResourceNotFoundException",),
        keys=[("Attribute", ["AttributeType", "Value"])], InstanceId=item["Id"], AttributeType="CONTACTFLOW_LOGS")
    return item


@_each
def _directory(requests, session, region, item):
    item = _pick(item, ["DirectoryId", "Name", "Type", "Edition", "Size", "Stage", "ShareStatus", "ShareMethod", "LaunchTime", "RadiusStatus",
        ("RadiusSettings", _RADIUS), ("VpcSettings", ["VpcId", "SubnetIds", "SecurityGroupId", "AvailabilityZones"]),
        ("OwnerDirectoryDescription", ["DirectoryId", "AccountId", "RadiusStatus", ("RadiusSettings", _RADIUS)])])
    directory, kind = item["DirectoryId"], item.get("Type")
    if kind != "SharedMicrosoftAD":
        topics = requests.detail(session, "ds", region, "describe_event_topics", DirectoryId=directory)
        if topics.get("collection_status") == "collected" and isinstance(topics.get("EventTopics"), list):
            rows = [_pick(row, ["DirectoryId", "TopicName", "TopicArn", "Status", "CreatedDateTime"]) for row in topics["EventTopics"]]
            item["EventTopics"] = {"collection_status": "collected" if rows else "empty", "items": rows}
        else:
            item["EventTopics"] = topics if topics.get("collection_status") != "collected" else {"collection_status": "malformed", "error": {"code": "malformed_response"}}
        shared = requests.pages(session, "ds", region, "describe_shared_directories", "SharedDirectories", OwnerDirectoryId=directory)
        item["SharedDirectories"] = _list(shared, ["OwnerAccountId", "OwnerDirectoryId", "SharedAccountId", "SharedDirectoryId", "ShareStatus", "ShareMethod"])
    item["LogSubscriptions"] = _list(requests.pages(session, "ds", region, "list_log_subscriptions", "LogSubscriptions", DirectoryId=directory),
        ["DirectoryId", "LogGroupName", "SubscriptionCreatedDateTime"])
    # Unsupported for the directory type is the documented "no snapshot quota" case.
    item["SnapshotLimits"] = _detail(requests, session, region, "ds", "get_snapshot_limits", absent=("UnsupportedOperationException",),
        keys=["SnapshotLimits"], DirectoryId=directory)
    if kind != "SimpleAD":
        certificates = requests.pages(session, "ds", region, "list_certificates", "CertificatesInfo", DirectoryId=directory)
        if certificates.error and certificates.error.get("code") == "UnsupportedOperationException" and not certificates.items:
            item["Certificates"] = {"collection_status": "empty", "absent": True, "items": [], "error": certificates.error}
        else:
            item["Certificates"] = _list(certificates, ["CertificateId", "CommonName", "State", "Type", "ExpiryDateTime"])
    return item


@_each
def _fms_policy(requests, session, region, item):
    item = _pick(item, ["PolicyId", "PolicyName", "PolicyArn", "ResourceType", "SecurityServiceType", "RemediationEnabled", "PolicyStatus"])
    item["ComplianceStatus"] = _list(requests.pages(session, "fms", region, "list_compliance_status", "PolicyComplianceStatusList", PolicyId=item["PolicyId"]),
        ["PolicyOwner", "PolicyId", "PolicyName", "MemberAccount", "EvaluationResults", "LastUpdated"])
    return item


_FILTERS = ("filters", ["type", "inputStrength", "outputStrength", "inputAction", "outputAction", "inputEnabled", "outputEnabled",
    "threshold", "action", "enabled"])


@_each
def _guardrail(requests, session, region, item):
    item = _pick(item, ["id", "arn", "name", "status", "version"])
    # Word/topic lists, regex patterns and blocked messaging are free text: not retained.
    item["Guardrail"] = _detail(requests, session, region, "bedrock", "get_guardrail", absent=("ResourceNotFoundException",),
        keys=["guardrailId", "guardrailArn", "name", "version", "status", "kmsKeyArn", ("contentPolicy", [_FILTERS]),
            ("contextualGroundingPolicy", [_FILTERS]), ("sensitiveInformationPolicy", [("piiEntities", ["type", "action"]), ("regexes", ["name", "action"])])],
        guardrailIdentifier=item["id"])
    return item


@_each
def _custom_model(requests, session, region, item):
    item = _pick(item, ["modelArn", "modelName", "baseModelArn", "customizationType", "creationTime", "modelStatus", "ownerAccountId"])
    item["Model"] = _detail(requests, session, region, "bedrock", "get_custom_model", absent=("ResourceNotFoundException",),
        keys=["modelArn", "modelName", "modelKmsKeyArn", "customizationType", "baseModelArn", "modelStatus", "creationTime"], modelIdentifier=item["modelArn"])
    return item


@_each
def _prompt(requests, session, region, item):
    item = _pick(item, ["id", "arn", "name", "version", "createdAt", "updatedAt"])
    # Variants hold the prompt text and are never requested into the snapshot.
    item["Prompt"] = _detail(requests, session, region, "bedrock-agent", "get_prompt", absent=("ResourceNotFoundException",),
        keys=["id", "arn", "name", "version", "customerEncryptionKeyArn", "createdAt", "updatedAt"], promptIdentifier=item["id"])
    return item


@_each
def _knowledge_base(requests, session, region, item):
    item = _pick(item, ["knowledgeBaseId", "name", "status", "updatedAt"])
    kb = item["knowledgeBaseId"]
    sources = _list(requests.pages(session, "bedrock-agent", region, "list_data_sources", "dataSourceSummaries", knowledgeBaseId=kb),
        ["knowledgeBaseId", "dataSourceId", "name", "status", "updatedAt"])
    for source in sources["items"]:
        # dataSourceConfiguration (URLs, credential secret ARNs) is never retained.
        source["Detail"] = _detail(requests, session, region, "bedrock-agent", "get_data_source", absent=("ResourceNotFoundException",),
            keys=[("dataSource", ["knowledgeBaseId", "dataSourceId", "name", "status", "serverSideEncryptionConfiguration", "dataDeletionPolicy"])],
            knowledgeBaseId=kb, dataSourceId=source["dataSourceId"])
    item["DataSources"] = sources
    return item


# ----------------------------------------------------------------------------- devtools enrichers

def _codebuild_project(requests, session, region, items):
    from .aws_request_pool import ordered_map
    return ordered_map(requests, items, lambda original: _codebuild_project_one(requests, session, region, original))


def _codebuild_project_one(requests, session, region, original):
    item = copy.deepcopy(original)
    name = item.get("name")
    configuration = item.get("Configuration")
    if isinstance(name, str) and isinstance(configuration, dict) and configuration.get("collection_status") == "collected":
        # Same cached BatchGetProjects response; keep each variable's name and
        # type only (the value member is never copied).
        try:
            raw = requests.call(session, "codebuild", region, "batch_get_projects", names=[name])
        except Exception:
            raw = {}
        raw_rows = [row for row in raw.get("projects", []) if isinstance(row, dict) and row.get("name") == name]
        kept_rows = [row for row in configuration.get("projects", []) if isinstance(row, dict) and row.get("name") == name]
        if len(raw_rows) == 1 and len(kept_rows) == 1 and isinstance(kept_rows[0].get("environment"), dict):
            variables = raw_rows[0].get("environment", {}).get("environmentVariables", [])
            if isinstance(variables, list):
                kept_rows[0]["environment"]["environmentVariables"] = [_pick(v, ["name", "type"]) for v in variables if isinstance(v, dict)]
    if isinstance(name, str):
        item["Builds"] = _builds(requests, session, region, name)
    return item


def _builds(requests, session, region, name):
    """The newest page of builds (ListBuildsForProject DESCENDING), in list order."""
    try:
        response = requests.call(session, "codebuild", region, "list_builds_for_project", projectName=name, sortOrder="DESCENDING")
    except Exception as exc:
        status, error = _failure(exc)
        return {"collection_status": status, "error": error}
    ids = response.get("ids")
    if not isinstance(ids, list) or any(not isinstance(i, str) for i in ids):
        return {"collection_status": "malformed", "error": {"code": "malformed_response"}}
    ids = ids[:_BATCH]
    if not ids:
        return {"collection_status": "empty", "items": []}
    try:
        builds = requests.call(session, "codebuild", region, "batch_get_builds", ids=ids)
    except Exception as exc:
        status, error = _failure(exc)
        return {"collection_status": status, "error": error}
    rows = {row.get("id"): row for row in builds.get("builds", []) if isinstance(row, dict)}
    items = [_pick(rows[i], ["id", "buildNumber", "buildStatus", "startTime", "endTime"]) for i in ids if i in rows]
    out = {"collection_status": "collected" if items else "empty", "items": items,
        "_provenance": {"source_operation": "list_builds_for_project/batch_get_builds", "order": "DESCENDING", "newest": len(ids)}}
    # Every enumerated build needs details. buildsNotFound proves a raced/deleted
    # build exists in the listing, not that the project was never invoked.
    missing = [i for i in ids if i not in rows]
    if missing:
        out = {"collection_status": "partial", "items": items, "error": {"code": "batch_get_incomplete"}}
    return out


def _report_groups(requests, session, region, items):
    arns = [item.get("arn") for item in items]
    if any(not isinstance(arn, str) for arn in arns):
        raise ValueError("malformed report group")
    found, failed = {}, {}
    for offset in range(0, len(arns), _BATCH):
        chunk = arns[offset:offset + _BATCH]
        try:
            response = requests.call(session, "codebuild", region, "batch_get_report_groups", reportGroupArns=chunk)
        except Exception as exc:
            status, error = _failure(exc)
            failed.update({arn: (status, error) for arn in chunk})
            continue
        for row in response.get("reportGroups", []):
            if isinstance(row, dict) and isinstance(row.get("arn"), str):
                found[row["arn"]] = _pick(row, ["arn", "name", "type", "status", "created", "lastModified",
                    ("exportConfig", ["exportConfigType", ("s3Destination", ["bucket", "bucketOwner", "path", "packaging", "encryptionKey", "encryptionDisabled"])])])
    output = []
    for arn in arns:
        if arn in found:
            output.append(found[arn])
        else:
            status, error = failed.get(arn, ("unknown", {"code": "report_group_not_returned"}))
            output.append({"arn": arn, "collection_status": status, "error": error})
    return output


@_each
def _cloudformation_stack(requests, session, region, item):
    # Parameters and Outputs can carry secrets: only CDKToolkit BootstrapVersion is kept.
    outputs = item.get("Outputs")
    kept = _pick(item, ["StackName", "StackId", "StackStatus", "CreationTime", "LastUpdatedTime", "NotificationARNs", "DisableRollback",
        "EnableTerminationProtection", "DriftInformation", "ParentId", "RootId", "RoleARN", "ConfigurationSecretIndicators"])
    if item.get("StackName") == "CDKToolkit" and isinstance(outputs, list):
        kept["Outputs"] = [_pick(o, ["OutputKey", "OutputValue"]) for o in outputs if isinstance(o, dict) and o.get("OutputKey") == "BootstrapVersion"]
    return kept


_ECR_SCANNABLE_MEDIA = {
    "application/vnd.docker.container.image.v1+json", "application/vnd.docker.image.rootfs.diff.tar",
    "application/vnd.docker.image.rootfs.diff.tar.gzip", "application/vnd.oci.image.config.v1+json",
    "application/vnd.oci.image.layer.v1.tar", "application/vnd.oci.image.layer.v1.tar+gzip",
}


def _ecr_scannable(row):
    tags = row.get("imageTags", [])
    return (isinstance(row.get("artifactMediaType"), str) and row["artifactMediaType"] in _ECR_SCANNABLE_MEDIA
        and isinstance(tags, list) and not any(isinstance(tag, str) and tag.startswith("sha256-") and tag.endswith(".sig") for tag in tags))


def _ecr_pushed_at(row):
    value = row.get("imagePushedAt")
    if isinstance(value, datetime):
        stamp = value
    elif isinstance(value, str):
        stamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
    else:
        raise ValueError("image push timestamp unavailable")
    if stamp.tzinfo is None:
        raise ValueError("image push timestamp has no timezone")
    return stamp.astimezone(timezone.utc)


def _ecr_latest_scan(requests, session, region, arguments, digest):
    """Read only the latest digest; retain aggregate facts, never finding bodies."""
    fact = {"source_api": "ecr:DescribeImageScanFindings", "imageDigest": digest}
    token, seen = None, set()
    page = 0
    while True:
        # Honor only the caller's explicit page budget. A default cap would
        # silently turn a complete service response into incomplete evidence.
        if requests.max_pages is not None and page >= requests.max_pages:
            return {**fact, "collection_status": "partial", "error": {"code": "scan_page_limit"}}
        params = {**arguments, "imageId": {"imageDigest": digest}, "maxResults": 1000}
        if token is not None:
            params["nextToken"] = token
        try:
            response = requests.call(session, "ecr", region, "describe_image_scan_findings", **params)
        except Exception as exc:
            status, error = _failure(exc)
            return {**fact, "collection_status": status, "error": error}
        if not isinstance(response, dict):
            return {**fact, "collection_status": "malformed", "error": {"code": "scan_response_not_object"}}
        image_id = response.get("imageId")
        if (not isinstance(image_id, dict) or image_id.get("imageDigest") != digest
                or response.get("repositoryName") != arguments["repositoryName"]
                or ("registryId" in arguments and response.get("registryId") != arguments["registryId"])):
            return {**fact, "collection_status": "malformed", "error": {"code": "scan_target_mismatch"}}
        status = response.get("imageScanStatus")
        findings = response.get("imageScanFindings")
        page_fact = {
            "imageScanStatus": _pick(status, ["status"]) if isinstance(status, dict) else status,
            "imageScanFindingsSummary": _pick(findings, ["findingSeverityCounts", "imageScanCompletedAt", "vulnerabilitySourceUpdatedAt"]) if isinstance(findings, dict) else findings,
        }
        if page == 0:
            fact.update(page_fact)
        elif page_fact != {key: fact[key] for key in page_fact}:
            return {**fact, "collection_status": "malformed", "error": {"code": "scan_summary_changed_during_pagination"}}
        token = response.get("nextToken")
        if token is None or token == "":
            return {**fact, "collection_status": "collected", "pages": page + 1}
        if not isinstance(token, str) or token in seen:
            return {**fact, "collection_status": "malformed", "error": {"code": "invalid_scan_pagination_token"}}
        seen.add(token)
        page += 1


def _ecr_repository(requests, session, region, items):
    output = []
    for original in items:
        item = copy.deepcopy(original)
        scanning = item.get("imageScanningConfiguration")
        name = item.get("repositoryName")
        # Image tags also establish whether an existing ECR source can start a pipeline.
        if isinstance(name, str):
            arguments = {"repositoryName": name, **({"registryId": item["registryId"]} if isinstance(item.get("registryId"), str) else {})}
            item["Images"] = _list(requests.pages(session, "ecr", region, "describe_images", "imageDetails", **arguments),
                ["imageDigest", "imageTags", "imagePushedAt", "artifactMediaType", "imageManifestMediaType", ("imageScanStatus", ["status"]),
                 ("imageScanFindingsSummary", ["findingSeverityCounts", "imageScanCompletedAt"])])
            if (isinstance(scanning, dict) and scanning.get("scanOnPush") is True
                    and getattr(requests, "ecr_latest_scan_requested", False)
                    and item["Images"]["collection_status"] == "collected"):
                images = [row for row in item["Images"]["items"] if isinstance(row, dict) and _ecr_scannable(row)]
                if images:
                    try:
                        # Stable tie behavior matches the native predicate.
                        latest = sorted(images, key=_ecr_pushed_at)[-1]
                    except (TypeError, ValueError):
                        item["Images"]["collection_status"] = "malformed"
                        item["Images"]["error"] = {"code": "image_push_timestamp_malformed"}
                    else:
                        digest = latest.get("imageDigest")
                        if not isinstance(digest, str) or not digest.startswith("sha256:"):
                            latest["ScanFindings"] = {"collection_status": "malformed", "error": {"code": "image_digest_missing"}}
                        else:
                            latest["ScanFindings"] = _ecr_latest_scan(requests, session, region, arguments, digest)
        output.append(item)
    return output


@_each
def _event_bus(requests, session, region, item):
    item = _pick(item, ["Name", "Arn", "CreationTime", "LastModifiedTime"])
    detail = requests.detail(session, "events", region, "describe_event_bus", Name=item["Name"])
    if detail.get("collection_status") == "collected":
        if isinstance(detail.get("Policy"), str):
            item["Policy"] = detail["Policy"]
        if isinstance(detail.get("KmsKeyIdentifier"), str):
            item["KmsKeyIdentifier"] = detail["KmsKeyIdentifier"]
    else:
        item["_coverage"] = {"Policy": {"status": detail.get("collection_status", "unknown"), "error": detail.get("error", {})}}
    return item


_event_custom_bus = _project(["Name", "EventBusArn", "EventBusAccountId", "State", "KmsKeyIdentifier"])
_microvm_image = _project(["imageArn", "name", "state", "latestActiveImageVersion"])


_project_endpoint = _project(["Name", "Arn", "EndpointId", "State", "ReplicationConfig", "RoutingConfig", "EventBuses", "RoleArn", "CreationTime"])


@_each
def _schema_registry(requests, session, region, item):
    item = _pick(item, ["RegistryName", "RegistryArn"])
    if isinstance(item.get("RegistryName"), str) and not item["RegistryName"].startswith("aws."):
        item["Policy"] = _detail(requests, session, region, "schemas", "get_resource_policy", absent=("NotFoundException",),
            keys=["Policy", "RevisionId"], RegistryName=item["RegistryName"])
    return item


@_each
def _codeartifact_domain(requests, session, region, item):
    item = _pick(item, ["name", "owner", "arn", "status", "encryptionKey", "createdTime"])
    item["Policy"] = _detail(requests, session, region, "codeartifact", "get_domain_permissions_policy", absent=("ResourceNotFoundException",),
        keys=[("policy", ["resourceArn", "document", "revision"])], domain=item["name"], domainOwner=item["owner"])
    return item


@_each
def _codeartifact_repository(requests, session, region, item):
    item = _pick(item, ["name", "arn", "domainName", "domainOwner", "administratorAccount", "createdTime"])
    scope = {"domain": item["domainName"], "domainOwner": item["domainOwner"], "repository": item["name"]}
    item["Policy"] = _detail(requests, session, region, "codeartifact", "get_repository_permissions_policy", absent=("ResourceNotFoundException",),
        keys=[("policy", ["resourceArn", "document", "revision"])], **scope)
    packages = _list(requests.pages(session, "codeartifact", region, "list_packages", "packages", **scope),
        ["format", "namespace", "package", "originConfiguration"])
    for package in packages["items"]:
        # Latest version only (sortBy PUBLISHED_TIME, maxResults 1), as the upstream rule.
        arguments = {**scope, "format": package.get("format"), "package": package.get("package"), "sortBy": "PUBLISHED_TIME", "maxResults": 1}
        if isinstance(package.get("namespace"), str):
            arguments["namespace"] = package["namespace"]
        package["LatestVersion"] = _detail(requests, session, region, "codeartifact", "list_package_versions",
            keys=[("versions", ["version", "status", ("origin", ["originType"])])], **arguments)
    item["Packages"] = packages
    return item


ENRICHERS = {
    "athena_workgroup": _athena,
    "backup_vault": _backup_vault,
    "dynamodb_table": _dynamodb_table,
    "efs_file_system": _efs_file_system,
    "datasync_task": _datasync_task,
    "docdb_cluster": _docdb_cluster,
    "dms_endpoint": _project(_DMS_ENDPOINT),
    "dms_replication_task": _project(_DMS_TASK),
    "dms_certificate": _project(_DMS_CERTIFICATE),
    "efs_access_point": _each(lambda requests, session, region, item: {**_pick(item, ["AccessPointId", "AccessPointArn", "FileSystemId", "Name", "OwnerId", "LifeCycleState", "RootDirectory", "PosixUser"]), "_provenance": {"operation": "efs:DescribeAccessPoints", "root_directory_representation_complete": True}}),
    "emr_security_configuration": _emr_security_configuration,
    "acmpca_certificate_authority": _project(["Arn", "OwnerAccount", "Type", "Status", "CreatedAt", "LastStateChangeAt", "NotBefore", "NotAfter",
        "KeyStorageSecurityStandard", "UsageMode", ("CertificateAuthorityConfiguration", ["KeyAlgorithm", "SigningAlgorithm"])]),
    "cognito_user_pool": _cognito_user_pool,
    "connect_instance": _connect_instance,
    "directory_service_directory": _directory,
    "fms_policy": _fms_policy,
    "bedrock_guardrail": _guardrail,
    "bedrock_agent": _bedrock_agent,
    "bedrock_custom_model": _custom_model,
    "bedrock_prompt": _prompt,
    "bedrock_knowledge_base": _knowledge_base,
    "codebuild_project": _codebuild_project,
    "codebuild_source_credential": _project(["arn", "serverType", "authType"]),
    "codebuild_report_group": _report_groups,
    "cloudformation_stack": _cloudformation_stack,
    "ecr_repository": _ecr_repository,
    "eventbridge_bus": _event_bus,
    "eventbridge_custom_bus": _event_custom_bus,
    "lambda_microvm_image": _microvm_image,
    "eventbridge_endpoint": _project_endpoint,
    "eventbridge_schema_registry": _schema_registry,
    "codeartifact_domain": _codeartifact_domain,
    "codeartifact_repository": _codeartifact_repository,
}
