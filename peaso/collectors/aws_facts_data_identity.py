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
from urllib.parse import urlsplit

from .aws_b_services import _metadata

SPECS = {
    "athena_workgroup": ("athena", "list_work_groups", "WorkGroups"),
    "athena_query_export": ("athena", "list_work_groups", "WorkGroups"),
    "athena_session": ("athena", "list_sessions", "Sessions"),
    "appconfig_extension_association": ("appconfig", "list_extension_associations", "Items"),
    "appconfig_configuration_profile": ("appconfig", "list_configuration_profiles", "Items"),
    "lakeformation_permission": ("lakeformation", "list_permissions", "PrincipalResourcePermissions"),
    "lakeformation_settings": ("lakeformation", "get_data_lake_settings", None),
    "cloudtrail_query_export": ("cloudtrail", "list_queries", "Queries"),
    "backup_recovery_point": ("backup", "list_recovery_points_by_backup_vault", "RecoveryPoints"),
    "backup_copy_job": ("backup", "list_copy_jobs", "CopyJobs"),
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
    "efs_replication": ("efs", "describe_replication_configurations", "Replications"),
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
    "eventbridge_api_destination": ("events", "list_api_destinations", "ApiDestinations"),
    "eventbridge_schema_registry": ("schemas", "list_registries", "Registries"),
    "glacier_vault_notification": ("glacier", "list_vaults", "VaultList"),
    "glacier_job_notification": ("glacier", "list_vaults", "VaultList"),
    "codeartifact_domain": ("codeartifact", "list_domains", "domains"),
    "codeartifact_repository": ("codeartifact", "list_repositories", "repositories"),
}
NATIVE_IDS = {
    'appconfig_configuration_profile': "id",
    'appconfig_extension_association': "Id",
    'athena_query_export': "QueryExecutionId",
    'cloudtrail_query_export': "id",
    'lakeformation_permission': "id",
    'lakeformation_settings': "id",
    "athena_workgroup": "Name", "athena_session": "SessionId", "backup_recovery_point": "RecoveryPointArn", "backup_copy_job": "CopyJobId", "redshift_datashare": "DataShareArn", "workspaces_image": "ImageId", "datasync_task": "TaskArn", "dax_cluster": "ClusterArn",
    "dlm_lifecycle_policy": "PolicyId", "dms_endpoint": "EndpointArn", "dms_replication_task": "ReplicationTaskArn", "dms_certificate": "CertificateArn",
    "drs_job": "jobID", "drs_source_server": "sourceServerID", "appautoscaling_target": "ScalableTargetARN", "elasticache_subnet_group": "ARN", "efs_access_point": "AccessPointArn",
    "efs_mount_target": "MountTargetId", "efs_replication": "SourceFileSystemArn", "emr_security_configuration": "Name", "emr_block_public_access_configuration": "id",
    "firehose_delivery_stream": "DeliveryStreamARN", "acmpca_certificate_authority": "Arn", "connect_instance": "Arn",
    "directory_service_directory": "DirectoryId", "fms_policy": "PolicyArn", "bedrock_guardrail": "arn", "bedrock_agent": "agentId",
    "bedrock_custom_model": "modelArn", "bedrock_prompt": "arn", "bedrock_knowledge_base": "knowledgeBaseId", "bedrock_model_invocation_logging": "id",
    "iam_service_specific_credential": "ServiceSpecificCredentialId", "codebuild_source_credential": "arn", "codebuild_report_group": "arn",
    "cloudformation_stack": "StackId", "codedeploy_deployment_group": "deploymentGroupId", "eventbridge_bus": "Arn", "eventbridge_custom_bus": "EventBusArn", "eventbridge_endpoint": "Arn", "eventbridge_api_destination": "ApiDestinationArn", "lambda_microvm_image": "imageArn",
    "eventbridge_schema_registry": "RegistryArn", "codeartifact_domain": "arn", "codeartifact_repository": "arn",
    "glacier_vault_notification": "VaultARN",
    "glacier_job_notification": "VaultARN",
}
GLOBAL_TYPES = {"iam_service_specific_credential"}
READ_ACTIONS = {(service, operation) for service, operation, expression in SPECS.values()}
READ_ACTIONS.update({
    ("athena", "get_work_group"), ("athena", "list_work_groups"), ("athena", "get_session"),
    ("athena", "list_query_executions"), ("athena", "batch_get_query_execution"),
    ("appconfig", "list_applications"), ("appconfig", "get_extension_association"),
    ("appconfig", "get_extension"), ("appconfig", "get_configuration_profile"),
    ("cloudtrail", "list_event_data_stores"), ("cloudtrail", "describe_query"),
    ("backup", "list_backup_vaults"), ("backup", "get_backup_vault_access_policy"),
    ("workspaces", "describe_workspace_image_permissions"),
    ("dynamodb", "get_resource_policy"), ("dynamodb", "list_tags_of_resource"),
    ("efs", "describe_file_systems"), ("efs", "describe_backup_policy"), ("efs", "describe_file_system_policy"),
    ("efs", "describe_mount_target_security_groups"),
    ("datasync", "describe_task"), ("datasync", "list_locations"), ("docdb", "describe_db_cluster_parameters"),
    ("emr", "describe_security_configuration"), ("firehose", "describe_delivery_stream"),
    ("wafv2", "get_web_acl_for_resource"), ("connect", "describe_instance_attribute"),
    ("ds", "describe_event_topics"), ("ds", "list_log_subscriptions"), ("ds", "get_snapshot_limits"), ("ds", "list_certificates"),
    ("ds", "describe_shared_directories"), ("ds", "describe_trusts"), ("fms", "list_compliance_status"),
    ("bedrock", "get_guardrail"), ("bedrock", "get_custom_model"), ("bedrock-agent", "get_prompt"),
    ("bedrock-agent", "list_data_sources"), ("bedrock-agent", "get_data_source"),
    ("codebuild", "batch_get_projects"), ("codebuild", "list_builds_for_project"), ("codebuild", "batch_get_builds"),
    ("codebuild", "batch_get_report_groups"), ("codedeploy", "list_deployment_groups"), ("codedeploy", "batch_get_deployment_groups"),
    ("ecr", "describe_images"), ("ecr", "describe_image_scan_findings"), ("events", "describe_event_bus"), ("schemas", "get_resource_policy"),
    ("eventbridgev2", "list_subscribers"), ("eventbridgev2", "list_resource_policies"), ("eventbridgev2", "get_resource_policy"),
    ("events", "describe_connection"),
    ("autoscaling", "describe_notification_configurations"), ("autoscaling", "describe_lifecycle_hooks"),
    ("codeartifact", "get_domain_permissions_policy"), ("codeartifact", "get_repository_permissions_policy"),
    ("codeartifact", "list_packages"), ("codeartifact", "list_package_versions"),
    ("glacier", "get_vault_notifications"),
    ("glacier", "list_jobs"),
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


def _athena_literal_export_buckets(query):
    """Return only literal UNLOAD/CTAS destination bucket names, never SQL text."""
    if not isinstance(query, str):
        return []
    if re.match(r"\s*UNLOAD\s*\(", query, re.IGNORECASE):
        matches = re.findall(r"\)\s+TO\s*'s3://([a-z0-9][a-z0-9.-]{1,61}[a-z0-9])(?:/|')", query, re.IGNORECASE)
    elif re.match(r"\s*CREATE\s+TABLE\b", query, re.IGNORECASE) and re.search(r"\bAS\s+SELECT\b", query, re.IGNORECASE):
        matches = re.findall(r"\b(?:external_location|location)\s*=\s*'s3://([a-z0-9][a-z0-9.-]{1,61}[a-z0-9])(?:/|')", query, re.IGNORECASE)
    else:
        matches = []
    return sorted(set(matches))


def _athena_query_exports(requests, session, region, account):
    """Collect result-bucket metadata for visible executions, never query text or S3 paths."""
    groups = requests.pages(session, "athena", region, "list_work_groups", "WorkGroups",
                            _tokens=("NextToken", "NextToken"))
    if groups.status not in ("collected", "empty", "partial"):
        return _aws().ReadResult([], groups.status, groups.error)
    rows, failures = [], [(groups.status, groups.error)] if groups.status == "partial" else []
    for group in groups.items:
        name = group.get("Name") if isinstance(group, dict) else None
        if not isinstance(name, str) or not name:
            failures.append(("malformed", {"code": "athena_workgroup_name_missing"}))
            continue
        listed = requests.pages(session, "athena", region, "list_query_executions", "QueryExecutionIds",
                                _tokens=("NextToken", "NextToken"), WorkGroup=name)
        if listed.status not in ("collected", "empty"):
            failures.append((listed.status, listed.error))
        ids = [i for i in listed.items if isinstance(i, str) and i]
        if len(ids) != len(listed.items) or len(ids) != len(set(ids)):
            failures.append(("malformed", {"code": "athena_query_execution_ids_invalid"}))
        for offset in range(0, len(ids), 50):
            batch = ids[offset:offset + 50]
            try:
                detail = requests.call(session, "athena", region, "batch_get_query_execution", QueryExecutionIds=batch)
            except Exception as exc:
                failures.append(_failure(exc))
                continue
            executions = detail.get("QueryExecutions")
            if not isinstance(executions, list):
                failures.append(("malformed", {"code": "athena_query_execution_batch_invalid"}))
                continue
            by_id = {row.get("QueryExecutionId"): row for row in executions if isinstance(row, dict)}
            if detail.get("UnprocessedQueryExecutionIds") or any(i not in by_id for i in batch):
                failures.append(("partial", {"code": "athena_query_execution_batch_incomplete"}))
            for query_id in batch:
                execution = by_id.get(query_id)
                if not isinstance(execution, dict):
                    continue
                if execution.get("WorkGroup") != name:
                    failures.append(("malformed", {"code": "athena_query_execution_workgroup_mismatch"}))
                    continue
                result = execution.get("ResultConfiguration")
                output = result.get("OutputLocation") if isinstance(result, dict) else None
                uri = urlsplit(output) if isinstance(output, str) else None
                bucket = uri.netloc if uri and uri.scheme == "s3" and uri.netloc else None
                rows.append({"QueryExecutionId": query_id, "WorkGroup": name,
                             "State": (execution.get("Status") or {}).get("State") if isinstance(execution.get("Status"), dict) else None,
                             "ResultBucket": bucket,
                             "LiteralExportBuckets": _athena_literal_export_buckets(execution.get("Query")),
                             "ExpectedBucketOwner": result.get("ExpectedBucketOwner") if isinstance(result, dict) else None,
                             "S3AclOption": (result.get("AclConfiguration") or {}).get("S3AclOption")
                             if isinstance(result, dict) and isinstance(result.get("AclConfiguration"), dict) else None})
    return _result(rows, failures)


def _appconfig_profiles(requests, session, region, account):
    applications = requests.pages(session, "appconfig", region, "list_applications", "Items",
                                  _tokens=("NextToken", "NextToken"))
    if applications.status not in ("collected", "empty", "partial"):
        return _aws().ReadResult([], applications.status, applications.error)
    rows, failures = [], []
    if applications.status == "partial":
        failures.append(("partial", applications.error))
    for application in applications.items:
        app_id = application.get("Id") if isinstance(application, dict) else None
        if not isinstance(app_id, str) or not app_id:
            failures.append(("malformed", {"code": "appconfig_application_id_missing"}))
            continue
        profiles = requests.pages(session, "appconfig", region, "list_configuration_profiles", "Items",
                                  _tokens=("NextToken", "NextToken"), ApplicationId=app_id)
        if profiles.status not in ("collected", "empty"):
            failures.append((profiles.status, profiles.error))
        for profile in profiles.items:
            profile_id = profile.get("Id") if isinstance(profile, dict) else None
            if not isinstance(profile_id, str) or not profile_id:
                failures.append(("malformed", {"code": "appconfig_profile_id_missing"}))
                continue
            rows.append({"id": app_id + "/" + profile_id, "ApplicationId": app_id, "Id": profile_id})
    return _result(rows, failures)


def _lakeformation_permissions(requests, session, region, account):
    read = requests.pages(session, "lakeformation", region, "list_permissions", "PrincipalResourcePermissions",
                          _tokens=("NextToken", "NextToken"), CatalogId=account, MaxResults=1000)
    if read.status in ("collected", "empty"):
        # AWS filters results by the caller's own LF permissions. An empty list
        # cannot prove that the account has no external grants.
        return _aws().ReadResult(read.items, "partial", {"code": "lakeformation_caller_filtered_permissions"})
    return read


def _lakeformation_settings(requests, session, region, account):
    result = requests.detail(session, "lakeformation", region, "get_data_lake_settings", CatalogId=account)
    if not isinstance(result, dict) or result.get("collection_status") != "collected":
        status = result.get("collection_status", "malformed") if isinstance(result, dict) else "malformed"
        return _aws().ReadResult([], status, result.get("error") if isinstance(result, dict) else {"code": "lakeformation_settings_malformed"})
    settings = result.get("DataLakeSettings")
    if not isinstance(settings, dict):
        return _aws().ReadResult([], "malformed", {"code": "lakeformation_settings_missing"})
    principal_keys = ("DataLakeAdmins", "ReadOnlyAdmins", "ExternalDataFilteringAllowList")
    projected = {"id": account, "CatalogId": account,
                 "AllowExternalDataFiltering": settings.get("AllowExternalDataFiltering"),
                 "TrustedResourceOwners": settings.get("TrustedResourceOwners", [])}
    if not isinstance(projected["TrustedResourceOwners"], list) or any(not isinstance(x, str) for x in projected["TrustedResourceOwners"]):
        return _aws().ReadResult([], "malformed", {"code": "lakeformation_trusted_resource_owners_malformed"})
    for key in principal_keys:
        values = settings.get(key, [])
        if not isinstance(values, list):
            return _aws().ReadResult([], "malformed", {"code": "lakeformation_" + key + "_malformed"})
        projected[key] = [value.get("DataLakePrincipalIdentifier") for value in values if isinstance(value, dict)]
    return _aws().ReadResult([projected], "collected")


def _cloudtrail_query_exports(requests, session, region, account):
    """Read the API-visible seven-day query window, retaining only S3 bucket names."""
    stores = requests.pages(session, "cloudtrail", region, "list_event_data_stores", "EventDataStores",
                            _tokens=("NextToken", "NextToken"))
    if stores.status not in ("collected", "empty", "partial"):
        return _aws().ReadResult([], stores.status, stores.error)
    failures = []
    if stores.status == "partial":
        failures.append(("partial", stores.error))
    keys = []
    for store in stores.items:
        arn = store.get("EventDataStoreArn") if isinstance(store, dict) else None
        parts = arn.split(":", 5) if isinstance(arn, str) else []
        if len(parts) != 6 or parts[2] != "cloudtrail" or parts[3:5] != [region, account] or not parts[5].startswith("eventdatastore/"):
            failures.append(("malformed", {"code": "cloudtrail_event_store_identity_invalid"}))
            continue
        read = requests.pages(session, "cloudtrail", region, "list_queries", "Queries",
                              _tokens=("NextToken", "NextToken"), EventDataStore=arn, MaxResults=1000)
        if read.status not in ("collected", "empty"):
            failures.append((read.status, read.error))
        for query in read.items:
            query_id = query.get("QueryId") if isinstance(query, dict) else None
            if not isinstance(query_id, str) or not query_id:
                failures.append(("malformed", {"code": "cloudtrail_query_id_missing"}))
                continue
            keys.append((arn, query_id))
    from .aws_request_pool import ordered_map
    def describe(key):
        arn, query_id = key
        detail = requests.detail(session, "cloudtrail", region, "describe_query", EventDataStore=arn, QueryId=query_id)
        row = {"id": arn + "/" + query_id, "EventDataStoreArn": arn, "QueryId": query_id}
        if not isinstance(detail, dict) or detail.get("collection_status") != "collected":
            row["collection_status"] = detail.get("collection_status", "malformed") if isinstance(detail, dict) else "malformed"
            return row
        row.update({key: detail.get(key) for key in ("QueryStatus", "DeliveryStatus")})
        uri = detail.get("DeliveryS3Uri")
        if isinstance(uri, str):
            parsed = urlsplit(uri)
            if parsed.scheme == "s3" and parsed.hostname and not parsed.username and not parsed.password:
                row["DestinationBucket"] = parsed.hostname
            else:
                row["collection_status"] = "malformed"
        if detail.get("QueryId") != query_id:
            row["collection_status"] = "malformed"
        return row
    rows = ordered_map(requests, keys, describe)
    failures.append(("partial", {"code": "cloudtrail_query_history_seven_days"}))
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
        # Keep only routing facts. HTTP paths, access keys, HEC tokens and users
        # are deliberately excluded from the persisted snapshot.
        row = _pick(description, ["DeliveryStreamName", "DeliveryStreamARN", "DeliveryStreamStatus", "DeliveryStreamType",
            "DeliveryStreamEncryptionConfiguration", "VersionId", "CreateTimestamp", "LastUpdateTimestamp"])
        destinations = description.get("Destinations")
        row["Destinations"] = [_firehose_destination(dest) for dest in destinations] if isinstance(destinations, list) else []
        row["DestinationsComplete"] = isinstance(destinations, list) and description.get("HasMoreDestinations") is False
        seen_destinations, dest_page = set(), 1
        while row["DestinationsComplete"] is False and description.get("HasMoreDestinations") is True:
            if (not isinstance(destinations, list) or not destinations or
                    requests.max_pages is not None and dest_page >= requests.max_pages):
                failures.append(("malformed", {"code": "firehose_destinations_incomplete"}))
                break
            last = destinations[-1].get("DestinationId") if isinstance(destinations[-1], dict) else None
            if not isinstance(last, str) or not last or last in seen_destinations:
                failures.append(("malformed", {"code": "firehose_destination_cursor_invalid"}))
                break
            seen_destinations.add(last)
            dest_page += 1
            next_read = requests.detail(session, "firehose", region, "describe_delivery_stream",
                                        DeliveryStreamName=name, ExclusiveStartDestinationId=last)
            next_description = next_read.get("DeliveryStreamDescription")
            if next_read.get("collection_status") != "collected" or not isinstance(next_description, dict):
                failures.append((next_read.get("collection_status", "malformed"), next_read.get("error", {"code": "firehose_destinations_incomplete"})))
                break
            description = next_description
            destinations = description.get("Destinations")
            if not isinstance(destinations, list):
                failures.append(("malformed", {"code": "firehose_destinations_malformed"}))
                break
            row["Destinations"].extend(_firehose_destination(dest) for dest in destinations)
            row["DestinationsComplete"] = description.get("HasMoreDestinations") is False
        if not row["DestinationsComplete"]:
            failures.append(("partial", {"code": "firehose_destinations_incomplete"}))
        items.append(row)
    return _result(items, failures)


def _firehose_destination(destination):
    if not isinstance(destination, dict):
        return {"Malformed": True}
    types = [key for key in destination if key.endswith("DestinationDescription")]
    if len(types) != 1 or not isinstance(destination[types[0]], dict):
        return {"Malformed": True}
    kind, detail = types[0], destination[types[0]]
    row = {"DestinationId": destination.get("DestinationId"), "Type": kind,
           "BucketARNs": [], "EndpointHosts": [], "TargetARNs": []}
    for key in ("S3DestinationDescription", "S3BackupDescription"):
        bucket = detail.get(key)
        if isinstance(bucket, dict) and isinstance(bucket.get("BucketARN"), str):
            row["BucketARNs"].append(bucket["BucketARN"])
    if kind in ("S3DestinationDescription", "ExtendedS3DestinationDescription") and isinstance(detail.get("BucketARN"), str):
        row["BucketARNs"].append(detail["BucketARN"])
    for key in ("DomainARN",):
        if isinstance(detail.get(key), str):
            row["TargetARNs"].append(detail[key])
    catalog = detail.get("CatalogConfiguration")
    if isinstance(catalog, dict) and isinstance(catalog.get("CatalogARN"), str):
        row["TargetARNs"].append(catalog["CatalogARN"])
    endpoints = [detail.get("HECEndpoint"), detail.get("AccountUrl"), detail.get("ClusterEndpoint"),
                 detail.get("CollectionEndpoint")]
    config = detail.get("EndpointConfiguration")
    if isinstance(config, dict):
        endpoints.append(config.get("Url"))
    for endpoint in endpoints:
        if isinstance(endpoint, str):
            try:
                parsed = urlsplit(endpoint)
                host, port = parsed.hostname, parsed.port
            except ValueError:
                row["MalformedEndpoint"] = True
                continue
            if host and parsed.scheme in ("http", "https"):
                row["EndpointHosts"].append({"Scheme": parsed.scheme, "Host": host, "Port": port})
            else:
                row["MalformedEndpoint"] = True
    jdbc = detail.get("ClusterJDBCURL")
    if isinstance(jdbc, str):
        try:
            parsed = urlsplit("https://" + jdbc[len("jdbc:redshift://"):]) if jdbc.startswith("jdbc:redshift://") else None
            host = parsed.hostname if parsed is not None else None
        except ValueError:
            host = None
        if host:
            row["RedshiftHost"] = host
        else:
            row["MalformedEndpoint"] = True
    processing = detail.get("ProcessingConfiguration")
    row["LambdaProcessing"] = any(isinstance(x, dict) and x.get("Type") == "Lambda" for x in
                                  (processing.get("Processors", []) if isinstance(processing, dict) else []))
    return row


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


def _glacier_vaults(requests, session, region, account):
    return requests.pages(session, "glacier", region, "list_vaults", "VaultList",
                          _tokens=("Marker", "marker"), accountId=account)


FETCHERS = {
    "athena_workgroup": _paged("athena", "list_work_groups", "WorkGroups", ("NextToken", "NextToken")),
    "athena_query_export": _athena_query_exports,
    "athena_session": _athena_sessions,
    "appconfig_extension_association": _paged("appconfig", "list_extension_associations", "Items", ("NextToken", "NextToken")),
    "appconfig_configuration_profile": _appconfig_profiles,
    "lakeformation_permission": _lakeformation_permissions,
    "lakeformation_settings": _lakeformation_settings,
    "cloudtrail_query_export": _cloudtrail_query_exports,
    "backup_recovery_point": _recovery_points,
    "workspaces_image": _workspaces_images,
    "drs_job": _drs_jobs,
    "drs_source_server": _drs_source_servers,
    "appautoscaling_target": _scalable_targets,
    "efs_mount_target": _mount_targets,
    "efs_replication": _paged("efs", "describe_replication_configurations", "Replications", ("NextToken", "NextToken")),
    "emr_block_public_access_configuration": _emr_block_public_access,
    "firehose_delivery_stream": _firehose_streams,
    "iam_service_specific_credential": _service_specific_credentials,
    "codedeploy_deployment_group": _deployment_groups,
    "bedrock_custom_model": _custom_models,
    "bedrock_model_invocation_logging": _model_invocation_logging,
    "eventbridge_bus": _paged("events", "list_event_buses", "EventBuses", ("NextToken", "NextToken")),
    "eventbridge_custom_bus": lambda requests, session, region, account: _eventbridge_custom_buses(requests, session, region, account),
    "lambda_microvm_image": _paged("lambda-microvms", "list_microvm_images", "items", ("nextToken", "nextToken")),
    "eventbridge_endpoint": _paged("events", "list_endpoints", "Endpoints", ("NextToken", "NextToken")),
    "eventbridge_api_destination": _paged("events", "list_api_destinations", "ApiDestinations", ("NextToken", "NextToken")),
    "glacier_vault_notification": _glacier_vaults,
    "glacier_job_notification": _glacier_vaults,
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
        "Options", "SourceLocationArn", "DestinationLocationArn", "TaskMode", "CreationTime",
        ("TaskReportConfig", ["OutputType", ("Destination", [("S3", ["S3BucketArn"])])])], TaskArn=item["TaskArn"])
    task = item["Task"]
    if task.get("collection_status") != "collected":
        return item
    destination_arn = task.get("DestinationLocationArn")
    if not isinstance(destination_arn, str) or not destination_arn:
        item["DestinationLocation"] = _unavailable("destination_location_arn_unavailable")
        return item
    # The regional list is shared through the scan's single-flight cache across tasks.
    locations = requests.pages(session, "datasync", region, "list_locations", "Locations")
    matches = [row for row in locations.items if isinstance(row, dict) and row.get("LocationArn") == destination_arn]
    if len(matches) != 1 or not isinstance(matches[0].get("LocationUri"), str):
        item["DestinationLocation"] = {"collection_status": "partial" if locations.status == "partial" else
            locations.status if locations.status not in ("collected", "empty") else "not_collected",
            "error": locations.error or {"code": "destination_location_missing"}}
        return item
    uri = urlsplit(matches[0]["LocationUri"])
    # LocationUri may include a source path; only the destination kind and host are needed.
    if not uri.scheme or not uri.hostname:
        item["DestinationLocation"] = _unavailable("destination_location_uri_invalid")
        return item
    item["DestinationLocation"] = {"collection_status": "collected", "LocationArn": destination_arn,
                                   "Type": uri.scheme.lower(), "Target": uri.hostname.lower()}
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
    "KmsKeyId", ("MongoDbSettings", ["AuthType", "AuthMechanism", "AuthSource"]), ("NeptuneSettings", ["IamAuthEnabled", "S3BucketName"]),
    ("RedisSettings", ["ServerName", "Port", "SslSecurityProtocol", "AuthType", "SslCaCertificateArn"]),
    ("S3Settings", ["BucketName", "ExpectedBucketOwner", "CannedAclForObjects"]),
    ("RedshiftSettings", ["BucketName"]), ("LakehouseSettings", ["Arn"])]
_DMS_TASK = ["ReplicationTaskArn", "ReplicationTaskIdentifier", "SourceEndpointArn", "TargetEndpointArn", "ReplicationInstanceArn",
    "MigrationType", "Status", "ReplicationTaskSettings"]
_DMS_CERTIFICATE = ["CertificateArn", "CertificateIdentifier", "CertificateOwner", "CertificateCreationDate", "ValidFromDate", "ValidToDate",
    "SigningAlgorithm", "KeyLength"]


@_each
def _dms_endpoint(requests, session, region, item):
    projected = _pick(item, _DMS_ENDPOINT)
    if str(item.get("EndpointType", "")).lower() != "target":
        return projected
    hosts = set()
    def keep_host(value):
        if not isinstance(value, str) or not value or len(value) > 1024:
            return
        try:
            parsed = urlsplit(value if "://" in value else "//" + value)
            host = parsed.hostname
        except ValueError:
            return
        if host and not parsed.username and not parsed.password:
            hosts.add(host)
    keep_host(item.get("ServerName"))
    if isinstance(item.get("RedisSettings"), dict):
        keep_host(item["RedisSettings"].get("ServerName"))
    if isinstance(item.get("ElasticsearchSettings"), dict):
        keep_host(item["ElasticsearchSettings"].get("EndpointUri"))
    if isinstance(item.get("KafkaSettings"), dict):
        brokers = item["KafkaSettings"].get("Broker")
        if isinstance(brokers, str):
            for broker in brokers.split(","):
                keep_host(broker.strip())
    if hosts:
        projected["TargetHosts"] = sorted(hosts)
    return projected


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
    item = _pick(item, ["DirectoryId", "Name", "Type", "Edition", "Size", "Stage", "ShareStatus", "ShareMethod", "LaunchTime", "RadiusStatus", "AccessUrl", "SsoEnabled",
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
        if kind == "MicrosoftAD":
            trusts = requests.pages(session, "ds", region, "describe_trusts", "Trusts", DirectoryId=directory)
            item["Trusts"] = _list(trusts, ["DirectoryId", "TrustId", "RemoteDomainName", "TrustType", "TrustDirection", "TrustState", "SelectiveAuth"])
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
        if isinstance(detail.get("DeadLetterConfig"), dict):
            item["DeadLetterConfig"] = _pick(detail["DeadLetterConfig"], ["Arn"])
    else:
        item["_coverage"] = {"Policy": {"status": detail.get("collection_status", "unknown"), "error": detail.get("error", {})}}
    return item


def _eventbridge_custom_buses(requests, session, region, account):
    read = requests.pages(session, "eventbridgev2", region, "list_event_buses", "EventBuses",
                          _tokens=("NextToken", "NextToken"))
    owned = [row for row in read.items if isinstance(row, dict) and
             row.get("EventBusAccountId") == account and
             isinstance(row.get("EventBusArn"), str) and row["EventBusArn"].split(":")[4:5] == [account]]
    return _aws().ReadResult(owned, read.status if owned or read.status != "collected" else "empty", read.error)


@_each
def _event_custom_bus(requests, session, region, item):
    item = _pick(item, ["Name", "EventBusArn", "EventBusAccountId", "State"])
    arn = item.get("EventBusArn")
    if not isinstance(arn, str) or not arn:
        item["Subscribers"] = _unavailable("event_bus_arn_missing")
        item["Policies"] = _unavailable("event_bus_arn_missing")
        return item
    item["Subscribers"] = _list(requests.pages(session, "eventbridgev2", region,
        "list_subscribers", "Subscribers", _tokens=("NextToken", "NextToken"), EventBusArn=arn),
        ["SubscriberArn", "EventBusArn", "TargetArn", "SubscriberAccountId", "State", "Revoked", "Type"])
    policies = _list(requests.pages(session, "eventbridgev2", region,
        "list_resource_policies", "PolicySummaries", _tokens=("NextToken", "NextToken"), ResourceArn=arn),
        ["PolicyName"])
    for summary in policies["items"]:
        name = summary.get("PolicyName")
        if isinstance(name, str) and name:
            detail = requests.detail(session, "eventbridgev2", region, "get_resource_policy",
                                     ResourceArn=arn, PolicyName=name)
            summary["Document"] = _pick(detail, ["collection_status", "PolicyDocument", "error"])
    item["Policies"] = policies
    return item
_microvm_image = _project(["imageArn", "name", "state", "latestActiveImageVersion"])


def _autoscaling_group(requests, session, region, items):
    """Retain delivery destinations, never lifecycle notification metadata."""
    if not items:
        return []
    notifications = _list(requests.pages(session, "autoscaling", region,
        "describe_notification_configurations", "NotificationConfigurations",
        _tokens=("NextToken", "NextToken")),
        ["AutoScalingGroupName", "TopicARN", "NotificationType"])
    by_group = {}
    for row in notifications["items"]:
        if isinstance(row, dict):
            by_group.setdefault(row.get("AutoScalingGroupName"), []).append(row)
    output = []
    for original in items:
        item = copy.deepcopy(original)
        name = item.get("AutoScalingGroupName")
        if not isinstance(name, str) or not name:
            item["NotificationConfigurations"] = _unavailable("autoscaling_group_name_missing")
            item["LifecycleHooks"] = _unavailable("autoscaling_group_name_missing")
        else:
            item["NotificationConfigurations"] = {**_status(notifications),
                "items": by_group.get(name, [])}
            item["LifecycleHooks"] = _list(requests.pages(session, "autoscaling", region,
                "describe_lifecycle_hooks", "LifecycleHooks", _tokens=("NextToken", "NextToken"),
                AutoScalingGroupName=name),
                ["AutoScalingGroupName", "LifecycleHookName", "LifecycleTransition", "NotificationTargetARN"])
        output.append(item)
    return output


def _appconfig_delivery_reference(value):
    """Keep destination identity without URL path, query, credentials or payload."""
    if not isinstance(value, str):
        return None
    if value.startswith("arn:") and len(value.split(":", 5)) == 6 and len(value) <= 1600:
        return {"Arn": value}
    try:
        parsed = urlsplit(value)
    except ValueError:
        return None
    if parsed.scheme == "https" and parsed.hostname and not parsed.username and not parsed.password:
        return {"Host": parsed.hostname}
    return None


@_each
def _appconfig_association(requests, session, region, item):
    item = _pick(item, ["Id", "ExtensionArn", "ResourceArn"])
    association_id = item.get("Id")
    if not isinstance(association_id, str) or not association_id:
        item["Details"] = _unavailable("appconfig_association_id_missing")
        return item
    detail = _detail(requests, session, region, "appconfig", "get_extension_association",
                     keys=["Id", "Arn", "ExtensionArn", "ResourceArn", "ExtensionVersionNumber", "Parameters"],
                     ExtensionAssociationId=association_id)
    if detail.get("collection_status") != "collected":
        item["Details"] = detail
        return item
    targets = []
    params = detail.get("Parameters")
    if isinstance(params, dict):
        for key, value in params.items():
            if isinstance(key, str) and any(word in key.lower() for word in
                    ("topic", "queue", "target", "destination", "webhook", "url", "uri", "jira")):
                ref = _appconfig_delivery_reference(value)
                if ref:
                    targets.append({"Source": "association_parameter", "Name": key, **ref})
    item["Details"] = {**_pick(detail, ["Id", "Arn", "ExtensionArn", "ResourceArn", "ExtensionVersionNumber"]),
                       "Targets": targets, "collection_status": "collected"}
    extension = detail.get("ExtensionArn")
    if not isinstance(extension, str) or not extension:
        item["Extension"] = _unavailable("appconfig_extension_arn_missing")
        return item
    args = {"ExtensionIdentifier": extension}
    if isinstance(detail.get("ExtensionVersionNumber"), int):
        args["VersionNumber"] = detail["ExtensionVersionNumber"]
    extension_detail = _detail(requests, session, region, "appconfig", "get_extension",
                               keys=["Arn", "Name", "VersionNumber", "Actions"], **args)
    if extension_detail.get("collection_status") != "collected":
        item["Extension"] = extension_detail
        return item
    actions = []
    for point, rows in (extension_detail.get("Actions") or {}).items():
        if not isinstance(rows, list):
            continue
        for action in rows:
            if not isinstance(action, dict):
                continue
            ref = _appconfig_delivery_reference(action.get("Uri"))
            if ref:
                row = {"ActionPoint": point, "Name": action.get("Name"), **ref}
                role = action.get("RoleArn")
                if isinstance(role, str) and role.startswith("arn:"):
                    row["RoleArn"] = role
                actions.append(row)
    item["Extension"] = {**_pick(extension_detail, ["Arn", "Name", "VersionNumber"]),
                         "Targets": actions, "collection_status": "collected"}
    return item


@_each
def _appconfig_profile(requests, session, region, item):
    item = _pick(item, ["id", "ApplicationId", "Id"])
    app_id, profile_id = item.get("ApplicationId"), item.get("Id")
    if not isinstance(app_id, str) or not isinstance(profile_id, str):
        item["Details"] = _unavailable("appconfig_profile_identity_missing")
        return item
    detail = _detail(requests, session, region, "appconfig", "get_configuration_profile",
                     keys=["ApplicationId", "Id", "Validators"],
                     ApplicationId=app_id, ConfigurationProfileId=profile_id)
    if detail.get("collection_status") != "collected":
        item["Details"] = detail
        return item
    validators = []
    for validator in detail.get("Validators") or []:
        if isinstance(validator, dict) and validator.get("Type") == "LAMBDA":
            ref = _appconfig_delivery_reference(validator.get("Content"))
            validators.append({"Type": "LAMBDA", **(ref or {})})
    item["Details"] = {"ApplicationId": detail.get("ApplicationId"), "Id": detail.get("Id"),
                       "Validators": validators, "collection_status": "collected"}
    return item


@_each
def _lakeformation_permission(requests, session, region, item):
    """Keep grant identity and permission names, without tag values or filters."""
    principal = (item.get("Principal") or {}).get("DataLakePrincipalIdentifier") if isinstance(item.get("Principal"), dict) else None
    resource = item.get("Resource")
    kind, body = next(iter(resource.items())) if isinstance(resource, dict) and len(resource) == 1 else (None, None)
    if not isinstance(body, dict):
        body = {}
    fields = {
        "Catalog": ("Id",), "Database": ("CatalogId", "Name"),
        "Table": ("CatalogId", "DatabaseName", "Name"),
        "TableWithColumns": ("CatalogId", "DatabaseName", "Name"),
        "DataCellsFilter": ("TableCatalogId", "DatabaseName", "TableName", "Name"),
        "DataLocation": ("CatalogId", "ResourceArn"),
        "LFTag": ("CatalogId", "TagKey"),
        "LFTagPolicy": ("CatalogId", "ResourceType", "ExpressionName"),
        "LFTagExpression": ("CatalogId", "Name"),
        "RLSPolicy": ("CatalogId", "Name"),
    }
    locator = _pick(body, fields.get(kind, ()))
    permissions = item.get("Permissions")
    grants = item.get("PermissionsWithGrantOption")
    summary = {"Principal": principal, "ResourceType": kind, "Resource": locator,
               "Permissions": sorted(permissions) if isinstance(permissions, list) and all(isinstance(x, str) for x in permissions) else [],
               "PermissionsWithGrantOption": sorted(grants) if isinstance(grants, list) and all(isinstance(x, str) for x in grants) else [],
               "Conditional": bool(item.get("Condition"))}
    encoded = json.dumps(item, sort_keys=True, separators=(",", ":"), default=str)
    summary["id"] = hashlib.sha256(encoded.encode()).hexdigest()[:32]
    if not isinstance(principal, str) or not principal or kind not in fields or not summary["Permissions"]:
        summary["collection_status"] = "malformed"
    return summary


_project_endpoint = _project(["Name", "Arn", "EndpointId", "State", "ReplicationConfig", "RoutingConfig", "EventBuses", "RoleArn", "CreationTime"])


@_each
def _api_destination(requests, session, region, item):
    item = _pick(item, ["ApiDestinationArn", "Name", "ApiDestinationState", "ConnectionArn", "InvocationEndpoint", "HttpMethod"])
    connection_arn = item.get("ConnectionArn")
    parts = connection_arn.split(":", 5) if isinstance(connection_arn, str) else []
    path = parts[5].split("/") if len(parts) == 6 else []
    if len(path) != 3 or path[0] != "connection" or not path[1]:
        item["Connection"] = _unavailable("eventbridge_connection_arn_missing")
        return item
    item["Connection"] = _detail(requests, session, region, "events", "describe_connection",
                                 keys=["ConnectionArn", "ConnectionState", ("InvocationConnectivityParameters",
                                       [("ResourceParameters", ["ResourceConfigurationArn", "ResourceAssociationArn"])])],
                                 Name=path[1])
    return item


@_each
def _glacier_vault_notification(requests, session, region, item):
    item = _pick(item, ["VaultName", "VaultARN"])
    arn = item.get("VaultARN")
    name = item.get("VaultName")
    if not isinstance(arn, str) or not isinstance(name, str) or not name:
        item["Notifications"] = _unavailable("glacier_vault_identity_missing")
        return item
    account = arn.split(":")[4] if len(arn.split(":")) == 6 else ""
    if not account.isdigit() or len(account) != 12:
        item["Notifications"] = _unavailable("glacier_vault_owner_missing")
        return item
    item["Notifications"] = _detail(requests, session, region, "glacier", "get_vault_notifications",
                                    absent=("ResourceNotFoundException",), keys=[("vaultNotificationConfig", ["SNSTopic", "Events"])],
                                    accountId=account, vaultName=name)
    return item


@_each
def _glacier_job_notification(requests, session, region, item):
    item = _pick(item, ["VaultName", "VaultARN"])
    arn = item.get("VaultARN")
    name = item.get("VaultName")
    account = arn.split(":")[4] if isinstance(arn, str) and len(arn.split(":")) == 6 else ""
    if not isinstance(name, str) or not name or len(account) != 12 or not account.isdigit():
        item["Jobs"] = _unavailable("glacier_vault_identity_missing")
        return item
    read = requests.pages(session, "glacier", region, "list_jobs", "JobList",
                          _tokens=("Marker", "marker"), accountId=account, vaultName=name)
    item["Jobs"] = _list(read, ["VaultARN", "SNSTopic", "Action", "Completed", "StatusCode"])
    return item


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
    "appconfig_extension_association": _appconfig_association,
    "appconfig_configuration_profile": _appconfig_profile,
    "lakeformation_permission": _lakeformation_permission,
    "backup_vault": _backup_vault,
    "dynamodb_table": _dynamodb_table,
    "efs_file_system": _efs_file_system,
    "datasync_task": _datasync_task,
    "docdb_cluster": _docdb_cluster,
    "dms_endpoint": _dms_endpoint,
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
    "autoscaling_group": _autoscaling_group,
    "eventbridge_custom_bus": _event_custom_bus,
    "lambda_microvm_image": _microvm_image,
    "eventbridge_endpoint": _project_endpoint,
    "eventbridge_api_destination": _api_destination,
    "glacier_vault_notification": _glacier_vault_notification,
    "glacier_job_notification": _glacier_job_notification,
    "eventbridge_schema_registry": _schema_registry,
    "codeartifact_domain": _codeartifact_domain,
    "codeartifact_repository": _codeartifact_repository,
}
