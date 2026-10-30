"""AWS-B config metadata plugin; all I/O uses the main shared read scheduler.

No resource creation, secret-value API, function code, document content, object
contents or server-side execution is requested. Response configuration literals
that can carry credentials are discarded before any snapshot construction.
"""
from __future__ import annotations
import copy
from concurrent.futures import ThreadPoolExecutor
import json
import re

SPECS = {
    "inspector_organization_review": ("inspector2", "get_delegated_admin_account", None),
    "rest_api_stage": ("apigateway", "get_stages", "item"),
    "http_api_stage": ("apigatewayv2", "get_stages", "Items"),
    "ecr_registry_scanning_configuration": ("ecr", "get_registry_scanning_configuration", None),
    "rds_event_subscription": ("rds", "describe_event_subscriptions", "EventSubscriptionsList"),
    "rds_proxy": ("rds", "describe_db_proxies", "DBProxies"),
    "rds_cluster_snapshot": ("rds", "describe_db_cluster_snapshots", "DBClusterSnapshots"),
    "rds_certificate": ("rds", "describe_certificates", "Certificates"),
    "acm_certificate": ("acm", "list_certificates", "CertificateSummaryList"),
    "cloudfront_distribution": ("cloudfront", "list_distributions", "DistributionList.Items || `[]`"),
    "deadline_queue": ("deadline", "list_farms", "farms"),
    "deadline_fleet_role": ("deadline", "list_farms", "farms"),
    "deadline_worker": ("deadline", "list_farms", "farms"),
    "ecs_cluster": ("ecs", "list_clusters", "clusterArns"),
    "ecs_task_definition": ("ecs", "list_task_definitions", "taskDefinitionArns"),
    "elasticache_cluster": ("elasticache", "describe_cache_clusters", "CacheClusters"),
    "elasticache_replication_group": ("elasticache", "describe_replication_groups", "ReplicationGroups"),
    "memorydb_cluster": ("memorydb", "describe_clusters", "Clusters"),
    "dms_replication_instance": ("dms", "describe_replication_instances", "ReplicationInstances"),
    "redshift_cluster": ("redshift", "describe_clusters", "Clusters"),
    "redshift_snapshot": ("redshift", "describe_cluster_snapshots", "Snapshots"),
    "neptune_cluster": ("neptune", "describe_db_clusters", "DBClusters"),
    "docdb_cluster": ("docdb", "describe_db_clusters", "DBClusters"),
    "docdb_instance": ("docdb", "describe_db_instances", "DBInstances"),
    "backup_plan": ("backup", "list_backup_plans", "BackupPlansList"),
    "backup_copy_job": ("backup", "list_copy_jobs", "CopyJobs"),
    "backup_report_plan": ("backup", "list_report_plans", "ReportPlans"),
    "inspector_organization_configuration": ("inspector2", "describe_organization_configuration", None),
    "backup_vault": ("backup", "list_backup_vaults", "BackupVaultList"),
    "backup_protected_resource": ("backup", "list_protected_resources", "Results"),
    "backup_region_settings": ("backup", "describe_region_settings", None),
    "efs_file_system": ("efs", "describe_file_systems", "FileSystems"),
    "fsx_file_system": ("fsx", "describe_file_systems", "FileSystems"),
    "cognito_user_pool": ("cognito-idp", "list_user_pools", "UserPools"),
    "cognito_identity_pool": ("cognito-identity", "list_identity_pools", "IdentityPools"),
    "route53_zone": ("route53", "list_hosted_zones", "HostedZones"),
    "route53_health_check": ("route53", "list_health_checks", "HealthChecks"),
    "codebuild_project": ("codebuild", "list_projects", "projects"),
    "codebuild_sandbox": ("codebuild", "list_sandboxes", "ids"),
    "codepipeline_pipeline": ("codepipeline", "list_pipelines", "pipelines"),
    "glue_job": ("glue", "get_jobs", "Jobs"),
    "glue_security_configuration": ("glue", "get_security_configurations", "SecurityConfigurations"),
    "mq_broker": ("mq", "list_brokers", "BrokerSummaries"),
    "ssm_document_metadata": ("ssm", "list_documents", "DocumentIdentifiers"),
    "ssm_managed_instance": ("ssm", "describe_instance_information", "InstanceInformationList"),
    "ssm_maintenance_window": ("ssm", "describe_maintenance_windows", "WindowIdentities"),
    "ssm_parameter_metadata": ("ssm", "describe_parameters", "Parameters"),
    "ssm_service_settings": ("ssm", "get_service_setting", None),
}
NATIVE_IDS = {
    "inspector_organization_review": "id",
    "rest_api_stage": "id", "http_api_stage": "id",
    "ecr_registry_scanning_configuration": "registryId",
    "rds_event_subscription": "EventSubscriptionArn", "rds_proxy": "DBProxyArn", "rds_cluster_snapshot": "DBClusterSnapshotArn", "rds_certificate": "CertificateIdentifier",
    "acm_certificate": "CertificateArn", "cloudfront_distribution": "ARN", "deadline_queue": "id", "deadline_fleet_role": "id", "deadline_worker": "id", "ecs_cluster": "clusterArn", "ecs_task_definition": "taskDefinitionArn",
    "elasticache_cluster": "ARN", "elasticache_replication_group": "ARN", "memorydb_cluster": "ARN", "dms_replication_instance": "ReplicationInstanceArn",
    "redshift_cluster": "ClusterIdentifier", "redshift_snapshot": "SnapshotIdentifier", "neptune_cluster": "DBClusterArn", "docdb_cluster": "DBClusterArn", "docdb_instance": "DBInstanceArn",
    "backup_plan": "BackupPlanArn", "backup_copy_job": "CopyJobId", "backup_report_plan": "ReportPlanArn", "inspector_organization_configuration": "id", "backup_vault": "BackupVaultArn", "backup_protected_resource": "ResourceArn", "backup_region_settings": "id",
    "efs_file_system": "FileSystemArn", "fsx_file_system": "ResourceARN", "cognito_user_pool": "Id", "cognito_identity_pool": "IdentityPoolId",
    "route53_zone": "Id", "route53_health_check": "Id", "codebuild_project": "name", "codebuild_sandbox": "id", "codepipeline_pipeline": "name", "glue_job": "Name",
    "glue_security_configuration": "Name", "mq_broker": "BrokerArn", "ssm_document_metadata": "Name", "ssm_managed_instance": "InstanceId", "ssm_maintenance_window": "WindowId", "ssm_parameter_metadata": "Name", "ssm_service_settings": "id",
}
GLOBAL_TYPES = {"cloudfront_distribution", "route53_zone", "route53_health_check"}
READ_ACTIONS = {(service, operation) for service, operation, expression in SPECS.values()}
READ_ACTIONS.update({
    ("deadline", "list_queues"), ("deadline", "get_queue"), ("deadline", "list_fleets"),
    ("deadline", "get_fleet"), ("deadline", "list_workers"),
    ("ecr", "describe_repositories"), ("acm", "describe_certificate"), ("cloudfront", "get_distribution_config"),
    ("ecs", "describe_clusters"), ("ecs", "describe_task_definition"), ("ecs", "list_services"), ("ecs", "describe_services"),
    ("backup", "get_backup_plan"), ("backup", "list_backup_selections"), ("backup", "get_backup_selection"), ("backup", "describe_backup_vault"), ("backup", "get_backup_vault_access_policy"),
    ("backup", "list_restore_access_backup_vaults"),
    ("lambda", "get_function_concurrency"), ("lambda", "get_function_configuration"),
    ("dynamodb", "describe_continuous_backups"), ("dynamodb", "describe_table_replica_auto_scaling"),
    ("elasticache", "describe_cache_parameters"), ("elasticache", "describe_users"),
    ("rds", "describe_db_parameters"), ("rds", "describe_db_cluster_parameters"), ("rds", "describe_option_groups"),
    ("redshift", "describe_logging_status"), ("redshift", "describe_cluster_parameters"),
    ("cognito-idp", "describe_user_pool"), ("cognito-idp", "list_user_pool_clients"), ("cognito-idp", "describe_user_pool_client"),
    ("cognito-idp", "describe_risk_configuration"),
    ("cognito-identity", "describe_identity_pool"), ("route53", "get_query_logging_config"), ("route53", "list_query_logging_configs"),
    ("codebuild", "batch_get_projects"), ("codebuild", "batch_get_sandboxes"), ("mq", "describe_broker"),
    ("mq", "describe_shared_resources"), ("mq", "describe_configuration_revision"),
    ("efs", "describe_backup_policy"), ("efs", "describe_file_system_policy"),
    ("ssm", "describe_document_permission"), ("ssm", "describe_maintenance_window_tasks"), ("ssm", "get_service_setting"),
    ("apigateway", "get_stages"), ("apigatewayv2", "get_stages"),
})

# These are configuration literals capable of carrying secrets/code. Resource
# policy declarations, password POLICY requirements and names remain metadata.
_OMIT = {"environmentvariables", "variables", "command", "entrypoint", "userdata", "code", "clientsecret", "secretstring", "secretbinary", "password", "masteruserpassword",
    "authparameters", "connectionstring", "authorizationtoken", "parameters", "defaultarguments", "nonoverridablearguments", "protectedsettings", "customheaders", "auth", "repositorycredentials", "secrets", "secretoptions"}


def _metadata(value):
    if isinstance(value, list):
        return [_metadata(item) for item in value]
    if not isinstance(value, dict):
        return value
    output = {}
    for key, item in value.items():
        if key.lower() in _OMIT or (key.lower() == "environment" and not isinstance(item, dict)):
            continue
        output[key] = _metadata(item)
    return output


def _ecs_definition_metadata(item):
    """_detail already filtered Definition and re-added only the admitted
    environment names; a second _metadata pass would drop those names."""
    output = _metadata({key: value for key, value in item.items() if key != "Definition"})
    if "Definition" in item:
        output["Definition"] = item["Definition"]
    return output


def _read_list(requests, session, region, service, operation, expression, **arguments):
    read = requests.pages(session, service, region, operation, expression, **arguments)
    result = {"collection_status": read.status, "items": _metadata(read.items)}
    if read.error:
        result["error"] = read.error
    return result


_ACM_STATUSES = ("PENDING_VALIDATION", "ISSUED", "INACTIVE", "EXPIRED", "VALIDATION_TIMED_OUT", "REVOKED", "FAILED")
_ACM_ORIGINS = ("AWS_MANAGED", "ACME", "CUSTOMER_PROVIDED")
_ACM_KEY_TYPES = ("RSA_1024", "RSA_2048", "RSA_3072", "RSA_4096", "EC_prime256v1", "EC_secp384r1", "EC_secp521r1")


def _acm_certificates(requests, session, region, account):
    """One modeled, complete known-enum ACM list read per Region.

    The older SDK omits ACME origin filtering and its default list excludes
    ACME/nondefault key types. Never treat that response as all certificates.
    """
    from .aws import ReadResult

    try:
        model = requests.client(session, "acm", region).meta.service_model.operation_model("ListCertificates")
        members = model.input_shape.members
        statuses = members["CertificateStatuses"].member.metadata["enum"]
        origins = members["CertificateKeyPairOrigins"].member.metadata["enum"]
        key_types = members["Includes"].members["keyTypes"].member.metadata["enum"]
    except (AttributeError, KeyError, TypeError):
        return ReadResult([], "not_collected", {"code": "acm_complete_filter_unsupported_sdk"})
    if any(set(observed) != set(expected) for observed, expected in (
            (statuses, _ACM_STATUSES), (origins, _ACM_ORIGINS), (key_types, _ACM_KEY_TYPES))):
        return ReadResult([], "not_collected", {"code": "acm_filter_enum_unreviewed"})
    read = requests.pages(session, "acm", region, "list_certificates", "CertificateSummaryList",
                          CertificateStatuses=list(_ACM_STATUSES),
                          CertificateKeyPairOrigins=list(_ACM_ORIGINS),
                          Includes={"keyTypes": list(_ACM_KEY_TYPES)})
    if read.status in {"collected", "empty"}:
        for row in read.items:
            if not isinstance(row, dict) or row.get("CertificateKeyPairOrigin") not in (*_ACM_ORIGINS, None):
                return ReadResult(read.items, "partial" if read.items else "malformed",
                                  {"code": "acm_unreviewed_origin_response"})
    return read


def _detail(requests, session, region, service, operation, **arguments):
    detail = requests.detail(session, service, region, operation, **arguments)
    output = _metadata(detail)
    if (service, operation) == ('ecs', 'describe_task_definition') and isinstance(output, dict):
        # Requests.call has already removed plaintext values. Carry only its
        # admitted environment names into the native view so the later ECS
        # enricher needs no second DescribeTaskDefinition read.
        source = detail.get('taskDefinition') if isinstance(detail, dict) else None
        target = output.get('taskDefinition')
        arn = arguments.get('taskDefinition')
        if (isinstance(source, dict) and isinstance(target, dict)
                and source.get('taskDefinitionArn') == target.get('taskDefinitionArn') == arn):
            original = source.get('containerDefinitions')
            copied = target.get('containerDefinitions')
            if isinstance(original, list) and isinstance(copied, list) and len(original) == len(copied):
                names = []
                for before, after in zip(original, copied):
                    if not isinstance(before, dict) or not isinstance(after, dict) or before.get('name') != after.get('name'):
                        break
                    entries = before.get('environment', [])
                    if (not isinstance(entries, list) or any(not isinstance(entry, dict)
                            or set(entry) - {'name', 'type'} or not isinstance(entry.get('name'), str)
                            or not entry['name'] for entry in entries)):
                        break
                    names.append([{'name': entry['name']} for entry in entries])
                if len(names) == len(copied):
                    for after, entries in zip(copied, names):
                        after['environment'] = entries
    error = detail.get("error") if isinstance(detail, dict) else None
    if isinstance(output, dict) and isinstance(error, dict) and isinstance(error.get("code"), str):
        # Collector-sanitized read error codes are status metadata, not the
        # omitted "code" content field (for example Lambda function code).
        output["error"] = {**(output.get("error") or {}), "code": error["code"]}
    return output


def _single(requests, session, region, service, operation, **arguments):
    from .aws import _single as single
    read = single(requests, session, region, service, operation, **arguments)
    read.items = _metadata(read.items)
    return read


def _single_settings(requests, session, region, account):
    return _single(requests, session, region, "ssm", "get_service_setting", SettingId=f"arn:aws:ssm:{region}:{account}:servicesetting/ssm/documents/console/public-sharing-permission")


def _cognito_pools(service, operation, expression, size):
    def fetch(requests, session, region, account):
        return requests.pages(session, service, region, operation, expression, MaxResults=size)
    return fetch


def _self_documents(requests, session, region, account):
    return requests.pages(session, "ssm", region, "list_documents", "DocumentIdentifiers", Filters=[{"Key": "Owner", "Values": ["Self"]}])


def _backup_report_plans(requests, session, region, account):
    # ListReportPlans returns NextToken but SDK 1.43.38 does not declare a
    # paginator. A first page with a token is not a complete presence or absence
    # inventory; let the shared read scheduler follow every page.
    return requests.pages(session, "backup", region, "list_report_plans", "ReportPlans",
                          _tokens=("NextToken", "NextToken"))


def _inspector_review(requests, session, region, account):
    """Keep independent admin proof and config availability in separate fields.

    This inventory is an assessment record, not a replacement for the original
    organization-configuration inventory. Each native read retains its status;
    failed admin/config reads cannot be treated as absent settings.
    """
    from .aws import ReadResult
    return ReadResult([{
        "id": "inspector-organization-review",
        "AccountId": account,
        "Administrator": _detail(requests, session, region, "inspector2", "get_delegated_admin_account"),
        "Configuration": _detail(requests, session, region, "inspector2", "describe_organization_configuration"),
    }])


def _api_stages(service, parent_op, parent_expr, parent_key, child_expr, argument):
    def fetch(requests, session, region, account):
        from .aws import ReadResult
        # The SDK endpoint resolver supplies the partition without a provider
        # request. REST stage ARNs use /restapis/; APIv2 stages use /apis/.
        resolver = getattr(session, "get_partition_for_region", None)
        if resolver is None:
            # Offline callers may pass a lightweight session adapter. Use the
            # same SDK endpoint model without touching credentials or network.
            from boto3.session import Session
            resolver = Session().get_partition_for_region
        partition = resolver(region)
        if not isinstance(partition, str) or not partition:
            return ReadResult([], "malformed", {"code": "unknown_region_partition"})
        stage_path = "restapis" if service == "apigateway" else "apis"
        parents = requests.pages(session, service, region, parent_op, parent_expr)
        if parents.status not in ("collected", "empty"):
            return ReadResult([], parents.status, parents.error)
        items, failures = [], []
        for parent in parents.items:
            # GetApis is the authority for v2 protocol. A retained value with
            # field-level denial must never be used to classify a stage.
            if not isinstance(parent, dict) or parent.get("collection_status", "collected") != "collected":
                return ReadResult(items, "partial" if items else "malformed", {"code": "malformed_parent_api"})
            coverage = parent.get("_coverage", {})
            if not isinstance(coverage, dict):
                return ReadResult(items, "partial" if items else "malformed", {"code": "malformed_parent_api_coverage"})
            if any(key in coverage and (not isinstance(coverage[key], dict) or coverage[key].get("status") != "collected")
                   for key in ((parent_key, "ProtocolType") if service == "apigatewayv2" else (parent_key,))):
                return ReadResult(items, "partial" if items else "malformed", {"code": "apigateway_parent_field_unavailable"})
            api_id = parent.get(parent_key)
            protocol = parent.get("ProtocolType") if service == "apigatewayv2" else None
            if service == "apigatewayv2" and protocol not in ("HTTP", "WEBSOCKET"):
                return ReadResult(items, "partial" if items else "malformed", {"code": "apigateway_parent_protocol_unavailable"})
            if not isinstance(api_id, str):
                return ReadResult(items, "partial" if items else "malformed", {"code": "malformed_parent_api"})
            children = requests.pages(session, service, region, "get_stages", child_expr, **{argument: api_id})
            if children.status not in ("collected", "empty"):
                failures.append(children)
            for child in children.items:
                name = child.get("stageName") if service == "apigateway" else child.get("StageName")
                if not isinstance(name, str):
                    return ReadResult(items, "partial" if items else "malformed", {"code": "malformed_stage"})
                row = _metadata(child)
                row["ParentApiId"] = api_id
                if service == "apigatewayv2":
                    row["ParentProtocolType"] = protocol
                row["id"] = f"arn:{partition}:apigateway:{region}::/{stage_path}/{api_id}/stages/{name}"
                row["_provenance"] = {"source_operation": "get_stages", "parent_api_id": api_id, "read_only": True}
                if service == "apigatewayv2":
                    row["_provenance"]["parent_protocol_source_operation"] = "get_apis"
                if service == 'apigateway':
                    # AccessLogSettings is optional in the complete native
                    # Stage response and survives the metadata projection.
                    # This proves only that field's absence, never full-row or
                    # log-delivery completeness.
                    row['_provenance']['optional_fields_complete'] = ['accessLogSettings', 'methodSettings']
                items.append(row)
        if failures:
            return ReadResult(items, "partial" if items else failures[0].status, failures[0].error)
        return ReadResult(items, "collected" if items else "empty")
    return fetch


def _deadline_queues(requests, session, region, account):
    """Collect exact queue-to-role bindings without requesting any role credentials."""
    from .aws import ReadResult

    farms = requests.pages(session, "deadline", region, "list_farms", "farms", maxResults=100)
    if farms.status not in ("collected", "empty"):
        return ReadResult([], farms.status, farms.error)
    rows, incomplete = [], False
    farm_ids = set()
    for farm in farms.items:
        if requests.max_items is not None and len(rows) >= requests.max_items:
            incomplete = True
            break
        farm_id = farm.get("farmId") if isinstance(farm, dict) else None
        if not isinstance(farm_id, str) or not re.fullmatch(r"farm-[0-9a-f]{32}", farm_id) or farm_id in farm_ids:
            incomplete = True
            continue
        farm_ids.add(farm_id)
        queues = requests.pages(session, "deadline", region, "list_queues", "queues",
                                farmId=farm_id, maxResults=100)
        if queues.status not in ("collected", "empty"):
            incomplete = True
        seen = set()
        for summary in queues.items:
            if requests.max_items is not None and len(rows) >= requests.max_items:
                incomplete = True
                break
            queue_id = summary.get("queueId") if isinstance(summary, dict) else None
            if (not isinstance(queue_id, str) or not re.fullmatch(r"queue-[0-9a-f]{32}", queue_id)
                    or summary.get("farmId") != farm_id or queue_id in seen):
                incomplete = True
                continue
            seen.add(queue_id)
            detail = requests.detail(session, "deadline", region, "get_queue",
                                     farmId=farm_id, queueId=queue_id)
            if (not isinstance(detail, dict) or detail.get("collection_status") != "collected"
                    or detail.get("farmId") != farm_id or detail.get("queueId") != queue_id
                    or not isinstance(detail.get("roleArn"), str)):
                incomplete = True
                continue
            rows.append({"id": farm_id + "/" + queue_id, "farmId": farm_id,
                         "queueId": queue_id, "roleArn": detail["roleArn"],
                         "status": detail.get("status"), "collection_status": "collected",
                         "_provenance": {"source_operation": "deadline:GetQueue", "read_only": True}})
    return ReadResult(rows, "partial" if incomplete else "collected" if rows else "empty",
                      {"code": "deadline_queue_inventory_incomplete"} if incomplete else None)


def _deadline_workers(requests, session, region, account):
    """Join existing workers to their exact fleet role without vending credentials."""
    from .aws import ReadResult

    farms = requests.pages(session, "deadline", region, "list_farms", "farms", maxResults=100)
    if farms.status not in ("collected", "empty"):
        return ReadResult([], farms.status, farms.error)
    rows, incomplete = [], False
    seen_farms = set()
    for farm in farms.items:
        farm_id = farm.get("farmId") if isinstance(farm, dict) else None
        if (not isinstance(farm_id, str) or not re.fullmatch(r"farm-[0-9a-f]{32}", farm_id)
                or farm_id in seen_farms):
            incomplete = True
            continue
        seen_farms.add(farm_id)
        fleets = requests.pages(session, "deadline", region, "list_fleets", "fleets",
                                farmId=farm_id, maxResults=100)
        if fleets.status not in ("collected", "empty"):
            incomplete = True
        seen_fleets = set()
        for summary in fleets.items:
            fleet_id = summary.get("fleetId") if isinstance(summary, dict) else None
            if (not isinstance(fleet_id, str) or not re.fullmatch(r"fleet-[0-9a-f]{32}", fleet_id)
                    or summary.get("farmId") != farm_id or fleet_id in seen_fleets):
                incomplete = True
                continue
            seen_fleets.add(fleet_id)
            detail = requests.detail(session, "deadline", region, "get_fleet",
                                     farmId=farm_id, fleetId=fleet_id)
            if (not isinstance(detail, dict) or detail.get("collection_status") != "collected"
                    or detail.get("farmId") != farm_id or detail.get("fleetId") != fleet_id
                    or not isinstance(detail.get("roleArn"), str)):
                incomplete = True
                continue
            workers = requests.pages(session, "deadline", region, "list_workers", "workers",
                                     farmId=farm_id, fleetId=fleet_id, maxResults=100)
            if workers.status not in ("collected", "empty"):
                incomplete = True
            seen_workers = set()
            for worker in workers.items:
                if requests.max_items is not None and len(rows) >= requests.max_items:
                    incomplete = True
                    break
                worker_id = worker.get("workerId") if isinstance(worker, dict) else None
                if (not isinstance(worker_id, str) or not re.fullmatch(r"worker-[0-9a-f]{32}", worker_id)
                        or worker.get("farmId") != farm_id or worker.get("fleetId") != fleet_id
                        or worker_id in seen_workers):
                    incomplete = True
                    continue
                seen_workers.add(worker_id)
                rows.append({"id": farm_id + "/" + fleet_id + "/" + worker_id,
                             "farmId": farm_id, "fleetId": fleet_id, "workerId": worker_id,
                             "roleArn": detail["roleArn"], "fleetStatus": detail.get("status"),
                             "workerStatus": worker.get("status"),
                             "collection_status": "collected",
                             "_provenance": {"source_operation": "deadline:ListWorkers", "read_only": True}})
    return ReadResult(rows, "partial" if incomplete else "collected" if rows else "empty",
                      {"code": "deadline_worker_inventory_incomplete"} if incomplete else None)


def _deadline_fleet_roles(requests, session, region, account):
    """Collect eligible fleet-to-role bindings even when no workers exist yet."""
    from .aws import ReadResult

    farms = requests.pages(session, "deadline", region, "list_farms", "farms", maxResults=100)
    if farms.status not in ("collected", "empty"):
        return ReadResult([], farms.status, farms.error)
    rows, incomplete = [], False
    seen_farms = set()
    for farm in farms.items:
        farm_id = farm.get("farmId") if isinstance(farm, dict) else None
        if (not isinstance(farm_id, str) or not re.fullmatch(r"farm-[0-9a-f]{32}", farm_id)
                or farm_id in seen_farms):
            incomplete = True
            continue
        seen_farms.add(farm_id)
        fleets = requests.pages(session, "deadline", region, "list_fleets", "fleets",
                                farmId=farm_id, maxResults=100)
        if fleets.status not in ("collected", "empty"):
            incomplete = True
        seen_fleets = set()
        for summary in fleets.items:
            fleet_id = summary.get("fleetId") if isinstance(summary, dict) else None
            if (not isinstance(fleet_id, str) or not re.fullmatch(r"fleet-[0-9a-f]{32}", fleet_id)
                    or summary.get("farmId") != farm_id or fleet_id in seen_fleets):
                incomplete = True
                continue
            seen_fleets.add(fleet_id)
            detail = requests.detail(session, "deadline", region, "get_fleet",
                                     farmId=farm_id, fleetId=fleet_id)
            if (not isinstance(detail, dict) or detail.get("collection_status") != "collected"
                    or detail.get("farmId") != farm_id or detail.get("fleetId") != fleet_id
                    or not isinstance(detail.get("roleArn"), str)):
                incomplete = True
                continue
            config = detail.get("configuration")
            mode = ("customerManaged" if isinstance(config, dict) and "customerManaged" in config
                    else "serviceManagedEc2" if isinstance(config, dict) and "serviceManagedEc2" in config
                    else None)
            rows.append({"id": farm_id + "/" + fleet_id, "farmId": farm_id,
                         "fleetId": fleet_id, "roleArn": detail["roleArn"],
                         "fleetStatus": detail.get("status"), "fleetMode": mode,
                         "maxWorkerCount": detail.get("maxWorkerCount"),
                         "workerCount": detail.get("workerCount"),
                         "collection_status": "collected",
                         "_provenance": {"source_operation": "deadline:GetFleet", "read_only": True}})
            if requests.max_items is not None and len(rows) >= requests.max_items:
                incomplete = True
                break
    return ReadResult(rows, "partial" if incomplete else "collected" if rows else "empty",
                      {"code": "deadline_fleet_role_inventory_incomplete"} if incomplete else None)


def _backup_copy_jobs(requests, session, region, account):
    """Read recent own-account copy jobs once; keep only exposure metadata."""
    read = requests.pages(session, "backup", region, "list_copy_jobs", "CopyJobs", ByAccountId=account)
    read.items = [{key: row[key] for key in ("CopyJobId", "SourceBackupVaultArn", "DestinationBackupVaultArn",
                                           "State", "ResourceArn", "SourceRecoveryPointArn") if key in row}
                  for row in read.items if isinstance(row, dict)]
    return read


FETCHERS = {
    "backup_copy_job": _backup_copy_jobs,
    "deadline_queue": _deadline_queues,
    "deadline_fleet_role": _deadline_fleet_roles,
    "deadline_worker": _deadline_workers,
    "backup_report_plan": _backup_report_plans,
    "acm_certificate": _acm_certificates,
    "inspector_organization_review": _inspector_review,
    "rest_api_stage": _api_stages("apigateway", "get_rest_apis", "items", "id", "item", "restApiId"),
    "http_api_stage": _api_stages("apigatewayv2", "get_apis", "Items", "ApiId", "Items", "ApiId"),
    "ssm_service_settings": _single_settings, "ssm_document_metadata": _self_documents,
    "cognito_user_pool": _cognito_pools("cognito-idp", "list_user_pools", "UserPools", 60),
    "cognito_identity_pool": _cognito_pools("cognito-identity", "list_identity_pools", "IdentityPools", 60)}


def _enricher(kind):
    def enrich(requests, session, region, items):
        if kind == "ecs_task_definition" and len(items) > 1:
            # Each immutable revision has an independent DescribeTaskDefinition
            # read. Keep the SDK request/cache budget in Requests and preserve
            # list order while overlapping the network waits.
            def definition(original):
                item = copy.deepcopy(original)
                item["Definition"] = _detail(requests, session, region, "ecs", "describe_task_definition",
                    taskDefinition=item["taskDefinitionArn"])
                return _ecs_definition_metadata(item)

            with ThreadPoolExecutor(max_workers=min(4, requests.workers), thread_name_prefix="aws-ecs-definition") as pool:
                return list(pool.map(definition, items))
        output = []
        for item in items:
            item = copy.deepcopy(item)
            if kind == "acm_certificate":
                item["Certificate"] = _detail(requests, session, region, "acm", "describe_certificate", CertificateArn=item["CertificateArn"])
            elif kind == "cloudfront_distribution":
                item["Config"] = _detail(requests, session, region, "cloudfront", "get_distribution_config", Id=item["Id"])
            elif kind == "ecs_cluster":
                item["Configuration"] = _detail(requests, session, region, "ecs", "describe_clusters", clusters=[item["clusterArn"]], include=["SETTINGS", "CONFIGURATIONS"])
                item["Services"] = _read_list(requests, session, region, "ecs", "list_services", "serviceArns", cluster=item["clusterArn"])
            elif kind == "ecs_task_definition":
                item["Definition"] = _detail(requests, session, region, "ecs", "describe_task_definition", taskDefinition=item["taskDefinitionArn"])
            elif kind == "redshift_cluster":
                item["Logging"] = _detail(requests, session, region, "redshift", "describe_logging_status", ClusterIdentifier=item["ClusterIdentifier"])
            elif kind == "dynamodb_table":
                item["ContinuousBackups"] = _detail(requests, session, region, "dynamodb", "describe_continuous_backups", TableName=item["TableName"])
            elif kind == "lambda_function":
                name = item["FunctionName"]
                item["Concurrency"] = _detail(requests, session, region, "lambda", "get_function_concurrency", FunctionName=name)
                item["Configuration"] = _detail(requests, session, region, "lambda", "get_function_configuration", FunctionName=name)
            elif kind == "backup_plan":
                item["Plan"] = _detail(requests, session, region, "backup", "get_backup_plan", BackupPlanId=item["BackupPlanId"])
                item["Selections"] = _read_list(requests, session, region, "backup", "list_backup_selections", "BackupSelectionsList", BackupPlanId=item["BackupPlanId"])
                if item["Selections"]["collection_status"] in ("collected", "empty"):
                    for selection in item["Selections"]["items"]:
                        selection["Selection"] = _detail(requests, session, region, "backup", "get_backup_selection", BackupPlanId=item["BackupPlanId"], SelectionId=selection["SelectionId"])
            elif kind == "backup_vault":
                name = item["BackupVaultName"]
                item["Configuration"] = _detail(requests, session, region, "backup", "describe_backup_vault", BackupVaultName=name)
                item["Policy"] = _detail(requests, session, region, "backup", "get_backup_vault_access_policy", BackupVaultName=name)
                vault_type = item.get("VaultType") or item["Configuration"].get("VaultType")
                if vault_type == "LOGICALLY_AIR_GAPPED_BACKUP_VAULT":
                    item["RestoreAccessVaults"] = _read_list(requests, session, region, "backup",
                        "list_restore_access_backup_vaults", "RestoreAccessBackupVaults", BackupVaultName=name)
            elif kind == "cognito_user_pool":
                item["Configuration"] = _detail(requests, session, region, "cognito-idp", "describe_user_pool", UserPoolId=item["Id"])
                item["Risk"] = _detail(requests, session, region, "cognito-idp", "describe_risk_configuration", UserPoolId=item["Id"])
                item["Clients"] = _read_list(requests, session, region, "cognito-idp", "list_user_pool_clients", "UserPoolClients", UserPoolId=item["Id"], MaxResults=60)
                if item["Clients"]["collection_status"] in ("collected", "empty"):
                    for client in item["Clients"]["items"]:
                        client["Configuration"] = _detail(requests, session, region, "cognito-idp", "describe_user_pool_client", UserPoolId=item["Id"], ClientId=client["ClientId"])
            elif kind == "cognito_identity_pool":
                item["Configuration"] = _detail(requests, session, region, "cognito-identity", "describe_identity_pool", IdentityPoolId=item["IdentityPoolId"])
            elif kind == "codebuild_project":
                # Requests.call already projected this response before caching;
                # retain the safe source.auth type/resource reference which the
                # generic service metadata filter would otherwise discard.
                item["Configuration"] = requests.detail(session, "codebuild", region, "batch_get_projects", names=[item["name"]])
                config = item["Configuration"]
                if config.get("collection_status") == "collected":
                    rows = config.get("projects")
                    missing = config.get("projectsNotFound")
                    if (not isinstance(rows, list) or len(rows) != 1 or not isinstance(rows[0], dict)
                            or rows[0].get("name") != item["name"] or missing):
                        config["collection_status"] = "partial"
                        config["error"] = {"code": "codebuild_project_detail_incomplete"}
            elif kind == "mq_broker":
                item["Configuration"] = _detail(requests, session, region, "mq", "describe_broker", BrokerId=item["BrokerId"])
                if item.get("EngineType") == "RABBITMQ":
                    from .aws_network_inventory import MetadataSession
                    item["SharedResources"] = _read_list(
                        requests, MetadataSession(session), region, "mq", "describe_shared_resources",
                        "SharedResources", _tokens=("NextToken", "NextToken"), BrokerId=item["BrokerId"])
                elif item.get("EngineType") == "ACTIVEMQ":
                    config = item["Configuration"]
                    assigned = config.get("Configurations") if isinstance(config, dict) else None
                    current = assigned.get("Current") if isinstance(assigned, dict) else None
                    if (isinstance(current, dict) and isinstance(current.get("Id"), str)
                            and type(current.get("Revision")) is int and current["Revision"] > 0):
                        from .aws_network_inventory import MetadataSession
                        item["AppliedNetworkConnectors"] = _detail(
                            requests, MetadataSession(session), region, "mq", "describe_configuration_revision",
                            ConfigurationId=current["Id"], ConfigurationRevision=str(current["Revision"]))
                    else:
                        item["AppliedNetworkConnectors"] = {"collection_status": "not_collected"}
            elif kind == "efs_file_system":
                item["BackupPolicy"] = _detail(requests, session, region, "efs", "describe_backup_policy", FileSystemId=item["FileSystemId"])
                item["Policy"] = _detail(requests, session, region, "efs", "describe_file_system_policy", FileSystemId=item["FileSystemId"])
            elif kind == "ssm_document_metadata":
                item["Permissions"] = _detail(requests, session, region, "ssm", "describe_document_permission", Name=item["Name"], PermissionType="Share")
            elif kind == "ssm_maintenance_window":
                item["Tasks"] = _read_list(requests, session, region, "ssm", "describe_maintenance_window_tasks", "Tasks", WindowId=item["WindowId"])
            elif kind == "rest_api":
                item["Stages"] = _read_list(requests, session, region, "apigateway", "get_stages", "item", restApiId=item["id"])
            elif kind == "http_api":
                item["Stages"] = _read_list(requests, session, region, "apigatewayv2", "get_stages", "Items", ApiId=item["ApiId"])
            output.append(item if kind == "codebuild_project" else
                          _ecs_definition_metadata(item) if kind == "ecs_task_definition" else _metadata(item))
        return output
    return enrich


def _ecr_repository_metadata(requests, session, region, items):
    output = []
    for original in items:
        item = copy.deepcopy(original)
        coverage = item.setdefault("_coverage", {})
        if not isinstance(coverage, dict):
            raise ValueError("malformed resource detail coverage")
        source_operation = "describe_repositories/list"
        if "imageTagMutability" not in item:
            name = item.get("repositoryName")
            if not isinstance(name, str) or not name:
                coverage["imageTagMutability"] = {"status": "malformed", "reason": "repository_name_missing"}
                output.append(_metadata(item))
                continue
            details = _detail(requests, session, region, "ecr", "describe_repositories", repositoryNames=[name])
            if details.get("collection_status") not in (None, "collected", "empty"):
                for field in ("imageTagMutability", "imageTagMutabilityExclusionFilters"):
                    coverage[field] = {"status": details["collection_status"], "error": details.get("error", {})}
                output.append(_metadata(item))
                continue
            repositories = details.get("repositories")
            matches = [row for row in repositories if isinstance(row, dict) and row.get("repositoryName") == name] if isinstance(repositories, list) else []
            if len(matches) != 1:
                coverage["imageTagMutability"] = {"status": "malformed", "reason": "repository_configuration_not_unique"}
                output.append(_metadata(item))
                continue
            for field in ("imageTagMutability", "imageTagMutabilityExclusionFilters"):
                if field in matches[0]:
                    item[field] = copy.deepcopy(matches[0][field])
            source_operation = "describe_repositories/detail"
        mode = item.get("imageTagMutability")
        coverage["imageTagMutability"] = {"status": "collected" if isinstance(mode, str) else "malformed", "source_operation": source_operation}
        filters = item.get("imageTagMutabilityExclusionFilters")
        if filters is None and mode in ("MUTABLE", "IMMUTABLE"):
            coverage["imageTagMutabilityExclusionFilters"] = {"status": "empty", "reason": "mode_has_no_exclusion_filters", "source_operation": source_operation}
        elif isinstance(filters, list) and all(isinstance(row, dict) and isinstance(row.get("filterType"), str) and isinstance(row.get("filter"), str) for row in filters):
            coverage["imageTagMutabilityExclusionFilters"] = {"status": "collected" if filters else "empty", "source_operation": source_operation}
        else:
            coverage["imageTagMutabilityExclusionFilters"] = {"status": "unknown" if filters is None else "malformed", "reason": "exclusion_mode_requires_observed_filters"}
        output.append(_metadata(item))
    return output


ENRICHERS = {kind: _enricher(kind) for kind in ["acm_certificate", "cloudfront_distribution", "ecs_cluster", "ecs_task_definition", "redshift_cluster", "lambda_function", "dynamodb_table", "backup_plan", "backup_vault", "cognito_user_pool", "cognito_identity_pool", "codebuild_project", "mq_broker", "efs_file_system", "ssm_document_metadata", "ssm_maintenance_window", "rest_api", "http_api"]}


def _codebuild_sandboxes(requests, session, region, items):
    output = []
    for item in items:
        if not isinstance(item, dict) or not isinstance(item.get("id"), str):
            output.append({"id": str(item), "Detail": {"collection_status": "malformed"}})
            continue
        detail = requests.detail(session, "codebuild", region, "batch_get_sandboxes", ids=[item["id"]])
        rows = detail.get("sandboxes") if isinstance(detail, dict) else None
        missing = detail.get("sandboxesNotFound") if isinstance(detail, dict) else None
        status = detail.get("collection_status", "not_collected") if isinstance(detail, dict) else "malformed"
        valid = (status == "collected" and isinstance(rows, list)
                 and len(rows) == 1 and isinstance(rows[0], dict) and rows[0].get("id") == item["id"]
                 and not missing and isinstance(rows[0].get("arn"), str)
                 and re.fullmatch(r"arn:aws(?:-[a-z0-9-]+)?:codebuild:[a-z0-9-]+:[0-9]{12}:sandbox/[^:]+:[^:]+",
                                  rows[0]["arn"]) is not None
                 and rows[0]["arn"].endswith("/" + item["id"])
                 and rows[0].get("projectName") == item["id"].split(":", 1)[0])
        item["Detail"] = (dict(rows[0], collection_status="collected") if valid else
                          {"collection_status": "partial" if status == "collected" else status})
        output.append(item)
    return output


ENRICHERS["codebuild_sandbox"] = _codebuild_sandboxes

ENRICHERS["ecr_repository"] = _ecr_repository_metadata


def _global_inventory(kind):
    def fetch(requests, session, region, account):
        service, operation, expression = SPECS[kind]
        # All custom FETCHERS return raw native records. The main common
        # pipeline normalizes and applies registered ENRICHERS exactly once.
        return requests.pages(session, service, region, operation, expression)
    return fetch


for _global_kind in GLOBAL_TYPES:
    FETCHERS[_global_kind] = _global_inventory(_global_kind)
