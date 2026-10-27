"""Read-only AWS facts for the HackTricks Best Practices checks and the privesc evaluator.

Every request is a list/describe/get metadata read issued through the shared scan
request context (single-flight cache, retries, max_pages/max_resources bounds).
Outputs are explicit field allowlists:

* Lambda: layer versions with their resource policy, function aliases, event source
  mappings, and on ``lambda_function`` the environment variable *names* (never
  values, taken from the cached GetFunctionConfiguration response) plus the runtime
  management mode.
* ECR registry (replication rules, registry policy, pull-through cache rules,
  repository creation templates), EKS access entries (type, groups, associated
  access policies) and pod identity associations, KMS grants of customer keys
  (encryption-context constraint *keys* only), OpenSearch cross-cluster connections.
* Cognito: identity-pool role map (GetIdentityPoolRoles), user-pool identity
  providers (name/type only), MFA mode and groups with their IAM role.
* Route 53 record sets (record values only for A/AAAA/CNAME/NS; other types keep
  a value count), CloudFormation StackSet instances and Organizations access status, EC2 Instance Connect
  endpoints, IAM Roles Anywhere profiles.
* Workload hosts: Image Builder pipelines with their infrastructure instance
  profile and their image recipe's component ARNs (GetImageRecipe; no recipe
  content, parameters or user data), SageMaker user profiles / spaces / HyperPod clusters with their execution roles,
  SageMaker domain default execution roles.
* Application planes: Managed Grafana workspaces, QuickSight users (role and
  identity type, no e-mail) and subscription status/authentication type,
  Supply Chain instances, Amplify apps with their
  Gen 1 backend environments (no environment variables, build specs or basic-auth
  credentials), Device Farm uploads and device pools (no signed upload URLs or test content).
* IAM Identity Center account assignments (permission set, account, principal
  type/id) and group display names.

A denied or failed read keeps its own status; only documented "not found" codes
mean absence.
"""
from __future__ import annotations

import copy
import re

OK = ("collected", "empty")

SPECS = {
    "lambda_layer_version": ("lambda", "list_layers", "Layers"),
    "lambda_alias": ("lambda", "list_aliases", "Aliases"),
    "lambda_event_source_mapping": ("lambda", "list_event_source_mappings", "EventSourceMappings"),
    "ecr_registry": ("ecr", "describe_registry", None),
    "eks_access_entry": ("eks", "list_access_entries", "accessEntries"),
    "eks_pod_identity_association": ("eks", "list_pod_identity_associations", "associations"),
    "kms_grant": ("kms", "list_grants", "Grants"),
    "opensearch_connection": ("opensearch", "describe_outbound_connections", "Connections"),
    "route53_record_set": ("route53", "list_resource_record_sets", "ResourceRecordSets"),
    "cloudformation_stack_instance": ("cloudformation", "list_stack_instances", "Summaries"),
    "cloudformation_organizations_access": ("cloudformation", "describe_organizations_access", None),
    "ec2_instance_connect_endpoint": ("ec2", "describe_instance_connect_endpoints", "InstanceConnectEndpoints"),
    "rolesanywhere_profile": ("rolesanywhere", "list_profiles", "profiles"),
    "imagebuilder_pipeline": ("imagebuilder", "list_image_pipelines", "imagePipelineList"),
    "sagemaker_user_profile": ("sagemaker", "list_user_profiles", "UserProfiles"),
    "sagemaker_space": ("sagemaker", "list_spaces", "Spaces"),
    "sagemaker_cluster": ("sagemaker", "list_clusters", "ClusterSummaries"),
    "grafana_workspace": ("grafana", "list_workspaces", "workspaces"),
    "gamelift_ec2_compute": ("gamelift", "list_fleets", "FleetIds"),
    "iot_role_alias": ("iot", "list_role_aliases", "roleAliases"),
    "devicefarm_upload": ("devicefarm", "list_uploads", "uploads"),
    "devicefarm_device_pool": ("devicefarm", "list_device_pools", "devicePools"),
    "quicksight_user": ("quicksight", "list_users", "UserList"),
    "quicksight_account_subscription": ("quicksight", "describe_account_subscription", None),
    "supplychain_instance": ("supplychain", "list_instances", "instances"),
    "amplify_app": ("amplify", "list_apps", "apps"),
    "aws_identity_center_account_assignment": ("sso-admin", "list_account_assignments", "AccountAssignments"),
}
NATIVE_IDS = {kind: "id" for kind in SPECS}
GLOBAL_TYPES = {"route53_record_set"}
READ_ACTIONS = {
    ("lambda", "list_functions"), ("lambda", "list_layer_versions"), ("lambda", "get_layer_version_policy"),
    ("lambda", "get_function_configuration"), ("lambda", "get_runtime_management_config"),
    ("ecr", "get_registry_policy"), ("ecr", "describe_pull_through_cache_rules"), ("ecr", "describe_repository_creation_templates"),
    ("eks", "list_clusters"), ("eks", "describe_access_entry"), ("eks", "list_associated_access_policies"),
    ("eks", "describe_pod_identity_association"),
    ("kms", "list_keys"), ("kms", "describe_key"),
    ("cognito-identity", "get_identity_pool_roles"),
    ("cognito-idp", "list_identity_providers"), ("cognito-idp", "get_user_pool_mfa_config"), ("cognito-idp", "list_groups"),
    ("opensearch", "describe_inbound_connections"),
    ("route53", "list_hosted_zones"),
    ("cloudformation", "list_stack_sets"),
    ("cloudformation", "describe_organizations_access"),
    ("imagebuilder", "list_infrastructure_configurations"), ("imagebuilder", "get_image_recipe"),
    ("sagemaker", "describe_user_profile"), ("sagemaker", "describe_cluster"), ("sagemaker", "describe_domain"),
    ("sagemaker", "describe_space"),
    ("amplify", "list_backend_environments"), ("amplify", "list_branches"), ("amplify", "list_domain_associations"),
    ("grafana", "list_workspace_service_accounts"),
    ("quicksight", "describe_account_subscription"),
    ("gamelift", "describe_fleet_attributes"), ("gamelift", "list_compute"),
    ("devicefarm", "list_projects"), ("devicefarm", "get_device_pool_compatibility"),
    ("iot", "describe_role_alias"),
    ("sso-admin", "list_instances"), ("sso-admin", "list_permission_sets"),
    ("sso-admin", "list_accounts_for_provisioned_permission_set"), ("identitystore", "list_groups"),
}

# Route 53 record types whose values are kept (addresses / delegation / aliasing targets).
_RECORD_VALUE_TYPES = {"A", "AAAA", "CNAME", "NS"}
_ESM_FIELDS = ("UUID", "EventSourceMappingArn", "EventSourceArn", "FunctionArn", "State", "StateTransitionReason", "LastModified",
               "BatchSize", "StartingPosition", "MaximumRetryAttempts", "MaximumRecordAgeInSeconds", "BisectBatchOnFunctionError",
               "DestinationConfig", "Topics", "Queues", "KMSKeyArn", "FunctionResponseTypes")


def _aws():
    from . import aws
    return aws


def _iot_role_aliases(requests, session, region, account):
    read = requests.pages(session, "iot", region, "list_role_aliases", "roleAliases",
                          _tokens=("marker", "nextMarker"))
    if read.status not in OK:
        return _finish([], _cause(read))
    rows, failure = [], None
    for name in read.items:
        if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9_=,@-]{1,128}", name):
            failure = failure or ("malformed", {"code": "malformed_iot_role_alias"})
            continue
        arn = f"arn:{_partition(region)}:iot:{region}:{account}:rolealias/{name}"
        detail = requests.detail(session, "iot", region, "describe_role_alias", roleAlias=name)
        if detail.get("collection_status") != "collected":
            failure = failure or (detail.get("collection_status") or "unknown",
                                  {"code": "iot_role_alias_detail_unavailable"})
            continue
        description = detail.get("roleAliasDescription")
        role_arn = description.get("roleArn") if isinstance(description, dict) else None
        if (not isinstance(description, dict) or description.get("roleAlias") != name or
                description.get("roleAliasArn") != arn or
                not isinstance(role_arn, str) or not re.fullmatch(
                    rf"arn:{_partition(region)}:iam::{account}:role/.+", role_arn)):
            failure = failure or ("malformed", {"code": "malformed_iot_role_alias_detail"})
            continue
        rows.append({"RoleAlias": name, "RoleAliasArn": arn, "RoleArn": role_arn, "id": arn})
    return _finish(rows, failure)


def _devicefarm_project_children(kind):
    operation, response_key, fields = {
        "devicefarm_upload": ("list_uploads", "uploads", ("arn", "name", "type", "status", "category")),
        "devicefarm_device_pool": ("list_device_pools", "devicePools", ("arn", "name", "type", "maxDevices")),
    }[kind]

    def fetch(requests, session, region, account):
        projects = requests.pages(session, "devicefarm", region, "list_projects", "projects")
        if projects.status not in OK:
            return _finish([], _cause(projects))
        rows, failure = [], None
        project_prefix = f"arn:{_partition(region)}:devicefarm:{region}:{account}:project:"
        for project in projects.items:
            project_arn = project.get("arn") if isinstance(project, dict) else None
            if (not isinstance(project_arn, str) or not project_arn.startswith(project_prefix)
                    or not re.fullmatch(r"[A-Za-z0-9-]+", project_arn[len(project_prefix):])):
                failure = failure or ("malformed", {"code": "malformed_devicefarm_project"})
                continue
            children = requests.pages(session, "devicefarm", region, operation, response_key, arn=project_arn)
            if children.status not in OK:
                failure = failure or _cause(children)
            for child in children.items:
                arn = child.get("arn") if isinstance(child, dict) else None
                if kind == "devicefarm_upload":
                    valid_arn = isinstance(arn, str) and arn.startswith(
                        project_arn.replace(":project:", ":upload:") + "/")
                else:
                    pool_prefix = f"arn:{_partition(region)}:devicefarm:{region}:"
                    valid_arn = isinstance(arn, str) and any(
                        arn.startswith(pool_prefix + owner + ":devicepool:") and
                        re.fullmatch(r"[A-Za-z0-9-]+", arn[len(pool_prefix + owner + ":devicepool:"):])
                        for owner in (account, ""))
                if not valid_arn:
                    failure = failure or ("malformed", {"code": "malformed_devicefarm_child"})
                    continue
                row = {**_pick(child, fields), "ProjectArn": project_arn, "id": arn}
                if kind == "devicefarm_device_pool":
                    compatibility = requests.detail(session, "devicefarm", region,
                        "get_device_pool_compatibility", devicePoolArn=arn,
                        projectArn=project_arn, testType="APPIUM_WEB_NODE")
                    status = compatibility.get("collection_status")
                    if status != "collected":
                        failure = failure or (status or "unknown", {"code": "devicefarm_pool_compatibility_unavailable"})
                    elif not isinstance(compatibility.get("compatibleDevices"), list):
                        failure = failure or ("malformed", {"code": "malformed_devicefarm_pool_compatibility"})
                    else:
                        row["CompatibleWebNodeDevices"] = sum(
                            device.get("compatible") is True for device in compatibility["compatibleDevices"]
                            if isinstance(device, dict))
                rows.append(row)
        return _finish(rows, failure)
    return fetch


def _partition(region):
    return "aws-us-gov" if region.startswith("us-gov-") else "aws-cn" if region.startswith("cn-") else "aws"


def _pick(value, keys):
    return {key: copy.deepcopy(value[key]) for key in keys if isinstance(value, dict) and key in value}


def _cause(read, default="read_incomplete"):
    error = read.error or {}
    return error.get("cause_status", read.status), {"code": error.get("code", default)}


def _finish(items, failure):
    ReadResult = _aws().ReadResult
    if failure:
        status, error = failure
        return ReadResult(items, "partial" if items else status, {**error, "cause_status": status})
    return ReadResult(items, "collected" if items else "empty")


def _child(read, rows=None):
    out = {"collection_status": read.status, "items": read.items if rows is None else rows}
    if read.error:
        out["error"] = {"code": (read.error or {}).get("code")}
    return out


def _status(response):
    """Detail response metadata only (status, absence, error code)."""
    out = {"collection_status": response.get("collection_status")}
    if response.get("absent"):
        out["absent"] = True
    if response.get("error"):
        out["error"] = {"code": (response.get("error") or {}).get("code")}
    return out


def _raw(requests, session, service, region, operation, **arguments):
    """(response, None) or (None, (status, code)). Identical reads are single-flight cache hits."""
    try:
        return requests.call(session, service, region, operation, **arguments), None
    except Exception as exc:
        failure = _aws()._failure(exc)
        return None, (failure.status, failure.code)


def _functions(requests, session, region):
    # Identical to the lambda_function inventory read (single-flight cache).
    return requests.pages(session, "lambda", region, "list_functions", "Functions")


def _clusters(requests, session, region):
    return requests.pages(session, "eks", region, "list_clusters", "clusters")


# ------------------------------------------------------------------------- Lambda
def _layer_versions(requests, session, region, account):
    layers = requests.pages(session, "lambda", region, "list_layers", "Layers")
    if layers.status not in OK:
        return _finish([], _cause(layers))
    policy = _aws()._policy
    items, failure = [], None
    for layer in layers.items:
        name = layer.get("LayerName") if isinstance(layer, dict) else None
        if not isinstance(name, str):
            failure = failure or ("malformed", {"code": "malformed_layer"})
            continue
        versions = requests.pages(session, "lambda", region, "list_layer_versions", "LayerVersions", LayerName=name)
        if versions.status not in OK:
            failure = failure or _cause(versions)
        for version in versions.items:
            number = version.get("Version") if isinstance(version, dict) else None
            if not isinstance(number, int) or isinstance(number, bool):
                failure = failure or ("malformed", {"code": "malformed_layer_version"})
                continue
            row = {"LayerName": name, "LayerArn": layer.get("LayerArn"),
                   **_pick(version, ("LayerVersionArn", "Version", "CreatedDate", "CompatibleRuntimes", "CompatibleArchitectures"))}
            row["id"] = row.get("LayerVersionArn") or f"{name}:{number}"
            response = requests.detail(session, "lambda", region, "get_layer_version_policy", absent=("ResourceNotFoundException",),
                                       LayerName=name, VersionNumber=number)
            row["Policy"] = _status(response)
            if response.get("collection_status") == "collected":
                row["Policy"]["Policy"] = policy(response.get("Policy"))
            items.append(row)
    return _finish(items, failure)


def _aliases(requests, session, region, account):
    functions = _functions(requests, session, region)
    if functions.status not in OK:
        return _finish([], _cause(functions))
    items, failure = [], None
    for function in functions.items:
        name = function.get("FunctionName") if isinstance(function, dict) else None
        if not isinstance(name, str):
            failure = failure or ("malformed", {"code": "malformed_function"})
            continue
        read = requests.pages(session, "lambda", region, "list_aliases", "Aliases", FunctionName=name)
        if read.status not in OK:
            failure = failure or _cause(read)
        for alias in read.items:
            if not isinstance(alias, dict) or not isinstance(alias.get("AliasArn"), str):
                failure = failure or ("malformed", {"code": "malformed_alias"})
                continue
            row = _pick(alias, ("AliasArn", "Name", "FunctionVersion", "RoutingConfig"))
            row.update({"FunctionName": name, "FunctionArn": function.get("FunctionArn"), "id": alias["AliasArn"]})
            items.append(row)
    return _finish(items, failure)


def _event_source_mappings(requests, session, region, account):
    read = requests.pages(session, "lambda", region, "list_event_source_mappings", "EventSourceMappings")
    items = []
    for mapping in read.items:
        if not isinstance(mapping, dict) or not isinstance(mapping.get("UUID"), str):
            continue
        row = _pick(mapping, _ESM_FIELDS)
        if isinstance(mapping.get("FilterCriteria"), dict):
            row["FilterCount"] = len(mapping["FilterCriteria"].get("Filters") or [])
        if isinstance(mapping.get("SourceAccessConfigurations"), list):
            # References only (secret / VPC ARNs), never resolved.
            row["SourceAccessConfigurations"] = [_pick(x, ("Type", "URI")) for x in mapping["SourceAccessConfigurations"] if isinstance(x, dict)]
        if isinstance(mapping.get("SelfManagedEventSource"), dict):
            row["SelfManagedEventSource"] = {"EndpointTypes": sorted((mapping["SelfManagedEventSource"].get("Endpoints") or {}).keys())}
        row["id"] = mapping.get("EventSourceMappingArn") or mapping["UUID"]
        items.append(row)
    if len(items) != len(read.items) and read.status in OK:
        return _finish(items, ("malformed", {"code": "malformed_event_source_mapping"}))
    read.items = items
    return read


def _lambda_function(requests, session, region, items):
    """Environment variable NAMES (from the cached GetFunctionConfiguration response) and runtime management mode."""
    output = []
    for item in items:
        item = copy.deepcopy(item)
        name = item.get("FunctionName") if isinstance(item, dict) else None
        if not isinstance(name, str):
            output.append(item)
            continue
        response, failure = _raw(requests, session, "lambda", region, "get_function_configuration", FunctionName=name)
        if failure:
            item["EnvironmentVariableNames"] = {"collection_status": failure[0], "error": {"code": failure[1]}}
        else:
            environment = response.get("Environment") if isinstance(response, dict) else None
            variables = environment.get("Variables") if isinstance(environment, dict) else None
            if environment is None or (isinstance(environment, dict) and variables is None and not environment.get("Error")):
                item["EnvironmentVariableNames"] = {"collection_status": "empty", "names": []}
            elif isinstance(variables, dict):
                names = sorted(str(key) for key in variables)
                item["EnvironmentVariableNames"] = {"collection_status": "collected" if names else "empty", "names": names}
            else:
                item["EnvironmentVariableNames"] = {"collection_status": "not_collected", "error": {"code": "environment_unreadable"}}
        if item.get("PackageType") == "Image":
            item["RuntimeManagement"] = {"collection_status": "empty", "absent": True, "reason": "container_image_function"}
        else:
            runtime = requests.detail(session, "lambda", region, "get_runtime_management_config", FunctionName=name)
            item["RuntimeManagement"] = {**_status(runtime), **_pick(runtime, ("UpdateRuntimeOn", "RuntimeVersionArn"))}
        output.append(item)
    return output


# ------------------------------------------------------------------------- ECR
def _ecr_registry(requests, session, region, account):
    policy = _aws()._policy
    registry = requests.detail(session, "ecr", region, "describe_registry")
    registry_policy = requests.detail(session, "ecr", region, "get_registry_policy", absent=("RegistryPolicyNotFoundException",))
    caches = requests.pages(session, "ecr", region, "describe_pull_through_cache_rules", "pullThroughCacheRules")
    templates = requests.pages(session, "ecr", region, "describe_repository_creation_templates", "repositoryCreationTemplates")
    statuses = [registry.get("collection_status"), registry_policy.get("collection_status"), caches.status, templates.status]
    if all(status not in OK for status in statuses) and len(set(statuses)) == 1:
        return _aws().ReadResult([], statuses[0], {"code": (registry.get("error") or {}).get("code", "registry_unreadable")})
    row = {"id": f"ecr-registry/{account}/{region}", "registryId": registry.get("registryId") or account}
    row["Replication"] = _status(registry)
    if registry.get("collection_status") == "collected":
        rules = (registry.get("replicationConfiguration") or {}).get("rules") or []
        row["Replication"]["rules"] = [_pick(rule, ("destinations", "repositoryFilters")) for rule in rules if isinstance(rule, dict)]
    row["RegistryPolicy"] = _status(registry_policy)
    if registry_policy.get("collection_status") == "collected":
        row["RegistryPolicy"]["policyText"] = policy(registry_policy.get("policyText"))
    row["PullThroughCacheRules"] = _child(caches, [_pick(x, ("ecrRepositoryPrefix", "upstreamRegistryUrl", "upstreamRegistry",
        "upstreamRepositoryPrefix", "credentialArn", "customRoleArn", "registryId")) for x in caches.items if isinstance(x, dict)])
    rows = []
    for template in templates.items:
        if not isinstance(template, dict):
            continue
        entry = _pick(template, ("prefix", "appliedFor", "imageTagMutability", "customRoleArn", "encryptionConfiguration"))
        if "repositoryPolicy" in template:
            entry["repositoryPolicy"] = policy(template.get("repositoryPolicy"))
        rows.append(entry)
    row["RepositoryCreationTemplates"] = _child(templates, rows)
    return _aws().ReadResult([row], "collected")


# ------------------------------------------------------------------------- EKS
def _access_entries(requests, session, region, account):
    clusters = _clusters(requests, session, region)
    if clusters.status not in OK:
        return _finish([], _cause(clusters))
    items, failure = [], None
    for cluster in clusters.items:
        if not isinstance(cluster, str):
            failure = failure or ("malformed", {"code": "malformed_cluster"})
            continue
        entries = requests.pages(session, "eks", region, "list_access_entries", "accessEntries", clusterName=cluster)
        if entries.status not in OK:
            # Clusters in CONFIG_MAP mode answer InvalidRequestException: no access entries API.
            if (entries.error or {}).get("code") != "InvalidRequestException":
                failure = failure or _cause(entries)
            continue
        for principal in entries.items:
            if not isinstance(principal, str):
                failure = failure or ("malformed", {"code": "malformed_access_entry"})
                continue
            row = {"clusterName": cluster, "principalArn": principal, "id": f"{cluster}/{principal}"}
            detail = requests.detail(session, "eks", region, "describe_access_entry", clusterName=cluster, principalArn=principal)
            entry = detail.get("accessEntry") if detail.get("collection_status") == "collected" else None
            if isinstance(entry, dict):
                row.update(_pick(entry, ("accessEntryArn", "type", "kubernetesGroups", "username", "createdAt", "modifiedAt")))
                row["id"] = entry.get("accessEntryArn") or row["id"]
            else:
                row["_coverage"] = {"type": {"status": detail.get("collection_status") or "malformed", "source_operation": "eks:DescribeAccessEntry"}}
            policies = requests.pages(session, "eks", region, "list_associated_access_policies", "associatedAccessPolicies",
                                      clusterName=cluster, principalArn=principal)
            row["AssociatedAccessPolicies"] = _child(policies, [_pick(x, ("policyArn", "accessScope")) for x in policies.items if isinstance(x, dict)])
            items.append(row)
    return _finish(items, failure)


def _pod_identity_associations(requests, session, region, account):
    clusters = _clusters(requests, session, region)
    if clusters.status not in OK:
        return _finish([], _cause(clusters))
    items, failure = [], None
    for cluster in clusters.items:
        if not isinstance(cluster, str):
            continue
        read = requests.pages(session, "eks", region, "list_pod_identity_associations", "associations", clusterName=cluster)
        if read.status not in OK:
            failure = failure or _cause(read)
        for association in read.items:
            if not isinstance(association, dict) or not isinstance(association.get("associationId"), str):
                failure = failure or ("malformed", {"code": "malformed_pod_identity_association"})
                continue
            row = _pick(association, ("clusterName", "namespace", "serviceAccount", "associationArn", "associationId", "ownerArn"))
            row["clusterName"] = cluster
            row["id"] = association.get("associationArn") or f"{cluster}/{association['associationId']}"
            detail = requests.detail(session, "eks", region, "describe_pod_identity_association", clusterName=cluster,
                                     associationId=association["associationId"])
            found = detail.get("association") if detail.get("collection_status") == "collected" else None
            if isinstance(found, dict):
                row.update(_pick(found, ("roleArn", "targetRoleArn", "disableSessionTags", "externalId")))
                row.pop("externalId", None)
            else:
                row["_coverage"] = {"roleArn": {"status": detail.get("collection_status") or "malformed",
                                                "source_operation": "eks:DescribePodIdentityAssociation"}}
            items.append(row)
    return _finish(items, failure)


# ------------------------------------------------------------------------- KMS
def _kms_grants(requests, session, region, account):
    keys = requests.pages(session, "kms", region, "list_keys", "Keys")
    if keys.status not in OK:
        return _finish([], _cause(keys))
    items, failure = [], None
    for key in keys.items:
        key_id = key.get("KeyId") if isinstance(key, dict) else None
        if not isinstance(key_id, str):
            failure = failure or ("malformed", {"code": "malformed_key"})
            continue
        # Same read as the kms_key inventory enrichment (cache hit).
        metadata = requests.detail(session, "kms", region, "describe_key", KeyId=key_id)
        manager = (metadata.get("KeyMetadata") or {}).get("KeyManager") if metadata.get("collection_status") == "collected" else None
        if manager == "AWS":
            continue  # AWS managed keys carry service grants only.
        if manager is None:
            failure = failure or (metadata.get("collection_status") or "malformed", {"code": "key_metadata_unavailable"})
            continue
        read = requests.pages(session, "kms", region, "list_grants", "Grants", KeyId=key_id)
        if read.status not in OK:
            failure = failure or _cause(read)
        for grant in read.items:
            if not isinstance(grant, dict) or not isinstance(grant.get("GrantId"), str):
                failure = failure or ("malformed", {"code": "malformed_grant"})
                continue
            row = _pick(grant, ("GrantId", "Name", "GranteePrincipal", "RetiringPrincipal", "IssuingAccount", "Operations", "CreationDate"))
            constraints = grant.get("Constraints")
            if isinstance(constraints, dict):
                row["ConstraintKeys"] = {name: sorted(value) for name, value in constraints.items() if isinstance(value, dict)}
            row.update({"KeyId": key_id, "KeyArn": key.get("KeyArn"), "id": f"{key.get('KeyArn') or key_id}/grant/{grant['GrantId']}"})
            items.append(row)
    return _finish(items, failure)


# ------------------------------------------------------------------------- Cognito
def _identity_pool(requests, session, region, items):
    output = []
    for item in items:
        item = copy.deepcopy(item)
        pool = item.get("IdentityPoolId") if isinstance(item, dict) else None
        if isinstance(pool, str):
            response = requests.detail(session, "cognito-identity", region, "get_identity_pool_roles", IdentityPoolId=pool)
            item["Roles"] = {**_status(response), **_pick(response, ("Roles", "RoleMappings"))}
        output.append(item)
    return output


def _user_pool(requests, session, region, items):
    output = []
    for item in items:
        item = copy.deepcopy(item)
        pool = item.get("Id") if isinstance(item, dict) else None
        if isinstance(pool, str):
            providers = requests.pages(session, "cognito-idp", region, "list_identity_providers", "Providers", UserPoolId=pool, MaxResults=60)
            item["IdentityProviders"] = _child(providers, [_pick(x, ("ProviderName", "ProviderType")) for x in providers.items if isinstance(x, dict)])
            mfa = requests.detail(session, "cognito-idp", region, "get_user_pool_mfa_config", UserPoolId=pool)
            row = {**_status(mfa), **_pick(mfa, ("MfaConfiguration",))}
            if mfa.get("collection_status") == "collected":
                row["SoftwareTokenMfaEnabled"] = bool((mfa.get("SoftwareTokenMfaConfiguration") or {}).get("Enabled"))
                row["SmsMfaConfigured"] = "SmsMfaConfiguration" in mfa
                row["EmailMfaConfigured"] = "EmailMfaConfiguration" in mfa
                row["WebAuthnConfigured"] = "WebAuthnConfiguration" in mfa
            item["MfaConfig"] = row
            groups = requests.pages(session, "cognito-idp", region, "list_groups", "Groups", UserPoolId=pool)
            item["Groups"] = _child(groups, [_pick(x, ("GroupName", "RoleArn", "Precedence")) for x in groups.items if isinstance(x, dict)])
        output.append(item)
    return output


# ------------------------------------------------------------------------- OpenSearch
def _opensearch_connections(requests, session, region, account):
    keys = ("ConnectionId", "ConnectionAlias", "ConnectionMode", "LocalDomainInfo", "RemoteDomainInfo")
    items, failure = [], None
    for direction, operation in (("outbound", "describe_outbound_connections"), ("inbound", "describe_inbound_connections")):
        read = requests.pages(session, "opensearch", region, operation, "Connections", _tokens=("NextToken", "NextToken"))
        if read.status not in OK:
            failure = failure or _cause(read)
        for connection in read.items:
            if not isinstance(connection, dict) or not isinstance(connection.get("ConnectionId"), str):
                failure = failure or ("malformed", {"code": "malformed_connection"})
                continue
            row = _pick(connection, keys)
            row["StatusCode"] = (connection.get("ConnectionStatus") or {}).get("StatusCode")
            row.update({"Direction": direction, "id": f"{direction}/{connection['ConnectionId']}"})
            items.append(row)
    return _finish(items, failure)


# ------------------------------------------------------------------------- Route 53 (global)
def _record_sets(requests, session, region, account):
    zones = requests.pages(session, "route53", region, "list_hosted_zones", "HostedZones")
    if zones.status not in OK:
        return _finish([], _cause(zones))
    items, failure = [], None
    for zone in zones.items:
        zone_id = zone.get("Id") if isinstance(zone, dict) else None
        if not isinstance(zone_id, str):
            failure = failure or ("malformed", {"code": "malformed_zone"})
            continue
        private = bool((zone.get("Config") or {}).get("PrivateZone"))
        read = requests.pages(session, "route53", region, "list_resource_record_sets", "ResourceRecordSets", HostedZoneId=zone_id)
        if read.status not in OK:
            failure = failure or _cause(read)
        for record in read.items:
            if not isinstance(record, dict) or not isinstance(record.get("Name"), str) or not isinstance(record.get("Type"), str):
                failure = failure or ("malformed", {"code": "malformed_record"})
                continue
            row = _pick(record, ("Name", "Type", "TTL", "SetIdentifier", "AliasTarget", "Region", "Failover", "HealthCheckId"))
            values = [x.get("Value") for x in record.get("ResourceRecords") or [] if isinstance(x, dict)]
            if record["Type"] in _RECORD_VALUE_TYPES:
                row["Values"] = [v for v in values if isinstance(v, str)]
            else:
                row["ValueCount"] = len(values)
            row.update({"HostedZoneId": zone_id, "HostedZoneName": zone.get("Name"), "PrivateZone": private, "AccountId": account,
                        "id": f"{zone_id}/{record['Name']}/{record['Type']}/{record.get('SetIdentifier', '')}"})
            items.append(row)
    return _finish(items, failure)


# ------------------------------------------------------------------------- CloudFormation / EC2 / Roles Anywhere
def _stack_instances(requests, session, region, account):
    sets = requests.pages(session, "cloudformation", region, "list_stack_sets", "Summaries", Status="ACTIVE")
    if sets.status not in OK:
        return _finish([], _cause(sets))
    items, failure = [], None
    for stack_set in sets.items:
        name = stack_set.get("StackSetName") if isinstance(stack_set, dict) else None
        if not isinstance(name, str):
            failure = failure or ("malformed", {"code": "malformed_stack_set"})
            continue
        read = requests.pages(session, "cloudformation", region, "list_stack_instances", "Summaries", StackSetName=name)
        if read.status not in OK:
            failure = failure or _cause(read)
        for instance in read.items:
            if not isinstance(instance, dict):
                continue
            row = _pick(instance, ("StackSetId", "Account", "Region", "StackId", "Status", "OrganizationalUnitId", "DriftStatus"))
            row.update({"StackSetName": name, "PermissionModel": stack_set.get("PermissionModel"),
                        "AutoDeployment": copy.deepcopy(stack_set.get("AutoDeployment")),
                        "id": f"{stack_set.get('StackSetId') or name}/{instance.get('Account')}/{instance.get('Region')}"})
            items.append(row)
    return _finish(items, failure)


def _stackset_organizations_access(requests, session, region, account):
    response, failure = _raw(requests, session, "cloudformation", region, "describe_organizations_access")
    if failure:
        status, code = failure
        return _finish([], (status, {"code": code}))
    status = response.get("Status") if isinstance(response, dict) else None
    if status not in {"ENABLED", "DISABLED", "DISABLED_PERMANENTLY"}:
        return _finish([], ("malformed", {"code": "invalid_organizations_access_status"}))
    return _finish([{"id": f"{account}/{region}", "Status": status}], None)


def _instance_connect_endpoints(requests, session, region, account):
    read = requests.pages(session, "ec2", region, "describe_instance_connect_endpoints", "InstanceConnectEndpoints")
    keys = ("InstanceConnectEndpointId", "InstanceConnectEndpointArn", "OwnerId", "State", "VpcId", "SubnetId", "AvailabilityZone",
            "PreserveClientIp", "SecurityGroupIds", "IpAddressType", "CreatedAt", "Tags")
    items = []
    for endpoint in read.items:
        if isinstance(endpoint, dict) and isinstance(endpoint.get("InstanceConnectEndpointId"), str):
            row = _pick(endpoint, keys)
            row["id"] = endpoint.get("InstanceConnectEndpointArn") or endpoint["InstanceConnectEndpointId"]
            items.append(row)
    read.items = items
    return read


def _rolesanywhere_profiles(requests, session, region, account):
    read = requests.pages(session, "rolesanywhere", region, "list_profiles", "profiles")
    policy = _aws()._policy
    keys = ("profileArn", "profileId", "name", "enabled", "roleArns", "managedPolicyArns", "requireInstanceProperties",
            "durationSeconds", "acceptRoleSessionName", "attributeMappings", "createdAt", "updatedAt")
    items = []
    for profile in read.items:
        if not isinstance(profile, dict) or not isinstance(profile.get("profileArn"), str):
            continue
        row = _pick(profile, keys)
        if "managedPolicyArns" in profile:
            managed = profile["managedPolicyArns"]
            if (not isinstance(managed, list) or any(not isinstance(arn, str) or
                    re.fullmatch(r"arn:[a-z0-9-]+:iam::(?:[0-9]{12}|aws):policy/\S+", arn) is None
                    for arn in managed)):
                continue
        elif read.status in OK:
            # ProfileDetail omits this optional array when no managed session
            # policies are configured. Only a successful complete ListProfiles
            # read authenticates that omission; unreadability is not absence.
            row["managedPolicyArns"] = []
            row.setdefault("_coverage", {})["managedPolicyArns"] = {
                "status": "empty", "reason": "documented_optional_api_omission",
                "source_operation": "rolesanywhere:ListProfiles", "native_member_present": False}
        row["SessionPolicy"] = policy(profile["sessionPolicy"]) if profile.get("sessionPolicy") else None
        row["id"] = profile["profileArn"]
        items.append(row)
    if len(items) != len(read.items) and read.status in OK:
        return _finish(items, ("malformed", {"code": "malformed_profile"}))
    read.items = items
    return read


# ------------------------------------------------------------------------- workload hosts
def _recipe_components(requests, session, region, recipe):
    """Component ARNs of an image recipe only: no recipe content, component parameters, block devices or user data."""
    response = requests.detail(session, "imagebuilder", region, "get_image_recipe", imageRecipeArn=recipe)
    out = _status(response)
    if response.get("collection_status") == "collected":
        components = ((response.get("imageRecipe") or {}).get("components"))
        arns = [c.get("componentArn") for c in components or () if isinstance(c, dict)]
        if not isinstance(components, list) or not all(isinstance(a, str) for a in arns):
            return {"collection_status": "malformed", "error": {"code": "malformed_image_recipe"}}
        out["items"] = list(dict.fromkeys(arns))
    return out


def _image_pipelines(requests, session, region, account):
    pipelines = requests.pages(session, "imagebuilder", region, "list_image_pipelines", "imagePipelineList")
    if pipelines.status not in OK:
        return _finish([], _cause(pipelines))
    configs = requests.pages(session, "imagebuilder", region, "list_infrastructure_configurations", "infrastructureConfigurationSummaryList")
    profiles = {c.get("arn"): c.get("instanceProfileName") for c in configs.items if isinstance(c, dict)}
    items, failure, recipes = [], None, {}
    for pipeline in pipelines.items:
        if not isinstance(pipeline, dict) or not isinstance(pipeline.get("arn"), str):
            failure = failure or ("malformed", {"code": "malformed_pipeline"})
            continue
        row = _pick(pipeline, ("arn", "name", "status", "platform", "infrastructureConfigurationArn", "executionRole", "imageRecipeArn",
                               "containerRecipeArn", "dateLastRun"))
        infra = pipeline.get("infrastructureConfigurationArn")
        if isinstance(profiles.get(infra), str):
            row["InstanceProfileName"] = profiles[infra]
        else:
            row["_coverage"] = {"InstanceProfileName": {"status": configs.status if configs.status not in OK else "not_collected",
                                                        "source_operation": "imagebuilder:ListInfrastructureConfigurations"}}
        recipe = pipeline.get("imageRecipeArn")
        if isinstance(recipe, str):
            if recipe not in recipes:
                recipes[recipe] = _recipe_components(requests, session, region, recipe)
            row["RecipeComponents"] = copy.deepcopy(recipes[recipe])
        row["id"] = pipeline["arn"]
        items.append(row)
    if configs.status not in OK and items:
        failure = failure or _cause(configs)
    return _finish(items, failure)


def _domain_roles(requests, session, region, domain):
    response, failure = _raw(requests, session, "sagemaker", region, "describe_domain", DomainId=domain)
    if failure or not isinstance(response, dict):
        return None
    return {"DefaultUserExecutionRole": (response.get("DefaultUserSettings") or {}).get("ExecutionRole"),
            "DefaultSpaceExecutionRole": (response.get("DefaultSpaceSettings") or {}).get("ExecutionRole")}


def _user_profiles(requests, session, region, account):
    read = requests.pages(session, "sagemaker", region, "list_user_profiles", "UserProfiles")
    if read.status not in OK:
        return _finish([], _cause(read))
    items, failure = [], None
    for profile in read.items:
        domain = profile.get("DomainId") if isinstance(profile, dict) else None
        name = profile.get("UserProfileName") if isinstance(profile, dict) else None
        if not isinstance(domain, str) or not isinstance(name, str):
            failure = failure or ("malformed", {"code": "malformed_user_profile"})
            continue
        row = {"DomainId": domain, "UserProfileName": name, "Status": profile.get("Status"), "id": f"{domain}/{name}"}
        detail = requests.detail(session, "sagemaker", region, "describe_user_profile", DomainId=domain, UserProfileName=name)
        if detail.get("collection_status") != "collected":
            row["_coverage"] = {"ExecutionRole": {"status": detail.get("collection_status"), "source_operation": "sagemaker:DescribeUserProfile"}}
            items.append(row)
            continue
        row["UserProfileArn"] = detail.get("UserProfileArn")
        row["id"] = detail.get("UserProfileArn") or row["id"]
        role = (detail.get("UserSettings") or {}).get("ExecutionRole")
        if isinstance(role, str) and role:
            row.update({"ExecutionRole": role, "ExecutionRoleSource": "user_settings"})
        else:
            defaults = _domain_roles(requests, session, region, domain)
            if defaults is None:
                row["_coverage"] = {"ExecutionRole": {"status": "not_collected", "source_operation": "sagemaker:DescribeDomain"}}
            elif defaults.get("DefaultUserExecutionRole"):
                row.update({"ExecutionRole": defaults["DefaultUserExecutionRole"], "ExecutionRoleSource": "domain_default"})
            else:
                row["ExecutionRole"] = None
        items.append(row)
    return _finish(items, failure)


def _sagemaker_domain(requests, session, region, items):
    output = []
    for item in items:
        item = copy.deepcopy(item)
        domain = item.get("DomainId") if isinstance(item, dict) else None
        defaults = _domain_roles(requests, session, region, domain) if isinstance(domain, str) else None
        if defaults is not None:
            item.update({key: value for key, value in defaults.items() if value})
        output.append(item)
    return output


def _spaces(requests, session, region, account):
    read = requests.pages(session, "sagemaker", region, "list_spaces", "Spaces")
    if read.status not in OK:
        return _finish([], _cause(read))
    output, failure = [], None
    for space in read.items:
        domain = space.get("DomainId") if isinstance(space, dict) else None
        name = space.get("SpaceName") if isinstance(space, dict) else None
        if not isinstance(domain, str) or not domain or not isinstance(name, str) or not name:
            failure = failure or ("malformed", {"code": "malformed_space"})
            continue
        row = {"DomainId": domain, "SpaceName": name, "id": f"{domain}/{name}"}
        detail = requests.detail(session, "sagemaker", region, "describe_space", DomainId=domain, SpaceName=name)
        if detail.get("collection_status") != "collected":
            row["_coverage"] = {"SpaceDetails": {"status": detail.get("collection_status"),
                                                   "source_operation": "sagemaker:DescribeSpace"}}
            output.append(row)
            failure = failure or (detail.get("collection_status") or "not_collected", {"code": "space_detail_unavailable"})
            continue
        arn = detail.get("SpaceArn")
        expected_arn = f"arn:{_partition(region)}:sagemaker:{region}:{account}:space/{domain}/{name}"
        if arn != expected_arn or detail.get("DomainId") not in (None, domain) or detail.get("SpaceName") not in (None, name):
            failure = failure or ("malformed", {"code": "missing_space_arn"})
            output.append(row)
            continue
        settings = detail.get("SpaceSettings") or {}
        summary_settings = space.get("SpaceSettingsSummary") or {}
        detail_sharing = (detail.get("SpaceSharingSettings") or {}).get("SharingType")
        summary_sharing = (space.get("SpaceSharingSettingsSummary") or {}).get("SharingType")
        detail_owner = (detail.get("OwnershipSettings") or {}).get("OwnerUserProfileName")
        summary_owner = (space.get("OwnershipSettingsSummary") or {}).get("OwnerUserProfileName")
        detail_app, summary_app = settings.get("AppType"), summary_settings.get("AppType")
        if any(a and b and a != b for a, b in ((detail_sharing, summary_sharing),
                                                (detail_owner, summary_owner), (detail_app, summary_app),
                                                (detail.get("Status"), space.get("Status")))):
            row["_coverage"] = {"SpaceDetails": {"status": "malformed", "source_operation": "sagemaker:DescribeSpace"}}
            failure = failure or ("malformed", {"code": "space_list_detail_mismatch"})
            output.append(row)
            continue
        sharing = detail_sharing or summary_sharing
        owner = detail_owner or summary_owner
        row.update({"id": arn, "SpaceArn": arn, "Status": detail.get("Status") or space.get("Status"),
                    "AppType": detail_app or summary_app, "SharingType": sharing,
                    "OwnerUserProfileName": owner})
        if sharing == "Shared":
            defaults = _domain_roles(requests, session, region, domain)
            if defaults is None:
                row["_coverage"] = {"ExecutionRole": {"status": "not_collected", "source_operation": "sagemaker:DescribeDomain"}}
                failure = failure or ("not_collected", {"code": "space_domain_role_unavailable"})
            else:
                row["ExecutionRole"] = defaults.get("DefaultSpaceExecutionRole")
                row["ExecutionRoleSource"] = "domain_default_space"
        elif sharing == "Private" and isinstance(owner, str) and owner:
            profile = requests.detail(session, "sagemaker", region, "describe_user_profile",
                                      DomainId=domain, UserProfileName=owner)
            if profile.get("collection_status") != "collected":
                row["_coverage"] = {"ExecutionRole": {"status": profile.get("collection_status"),
                                                       "source_operation": "sagemaker:DescribeUserProfile"}}
                failure = failure or (profile.get("collection_status") or "not_collected", {"code": "space_owner_role_unavailable"})
            else:
                role = (profile.get("UserSettings") or {}).get("ExecutionRole")
                if isinstance(role, str) and role:
                    row["ExecutionRole"] = role
                    row["ExecutionRoleSource"] = "owner_user_settings"
                else:
                    defaults = _domain_roles(requests, session, region, domain)
                    if defaults is None:
                        row["_coverage"] = {"ExecutionRole": {"status": "not_collected", "source_operation": "sagemaker:DescribeDomain"}}
                        failure = failure or ("not_collected", {"code": "space_domain_role_unavailable"})
                    else:
                        row["ExecutionRole"] = defaults.get("DefaultUserExecutionRole")
                        row["ExecutionRoleSource"] = "domain_default_user"
        else:
            row["_coverage"] = {"ExecutionRole": {"status": "malformed", "source_operation": "sagemaker:DescribeSpace"}}
            failure = failure or ("malformed", {"code": "space_sharing_or_owner_missing"})
        output.append(row)
    return _finish(output, failure)


def _hyperpod_clusters(requests, session, region, account):
    read = requests.pages(session, "sagemaker", region, "list_clusters", "ClusterSummaries")
    if read.status not in OK:
        return _finish([], _cause(read))
    items, failure = [], None
    for cluster in read.items:
        name = cluster.get("ClusterName") if isinstance(cluster, dict) else None
        if not isinstance(name, str):
            failure = failure or ("malformed", {"code": "malformed_cluster"})
            continue
        row = {**_pick(cluster, ("ClusterArn", "ClusterName", "ClusterStatus")), "id": cluster.get("ClusterArn") or name}
        detail = requests.detail(session, "sagemaker", region, "describe_cluster", ClusterName=name)
        if detail.get("collection_status") != "collected":
            row["_coverage"] = {"InstanceGroups": {"status": detail.get("collection_status"), "source_operation": "sagemaker:DescribeCluster"}}
        else:
            groups = []
            for field in ("InstanceGroups", "RestrictedInstanceGroups"):
                groups += [_pick(g, ("InstanceGroupName", "InstanceType", "ExecutionRole", "CurrentCount", "Status", "ImageId"))
                           for g in detail.get(field) or [] if isinstance(g, dict)]
            row["InstanceGroups"] = groups
            row["Orchestrator"] = copy.deepcopy(detail.get("Orchestrator"))
        items.append(row)
    return _finish(items, failure)


# ------------------------------------------------------------------------- application planes
def _gamelift_ec2_computes(requests, session, region, account):
    """Join fleet role configuration to its computes without requesting access tokens."""
    fleets = requests.pages(session, "gamelift", region, "list_fleets", "FleetIds")
    if fleets.status not in OK:
        return _finish([], _cause(fleets))
    rows, failure = [], None
    for fleet_id in fleets.items:
        if not isinstance(fleet_id, str) or not fleet_id:
            failure = failure or ("malformed", {"code": "malformed_fleet_id"})
            continue
        if fleet_id.startswith("containerfleet-"):
            # DescribeFleetAttributes supports EC2/Anywhere, not containers.
            continue
        attributes = requests.pages(session, "gamelift", region, "describe_fleet_attributes",
                                    "FleetAttributes", FleetIds=[fleet_id])
        if attributes.status not in OK:
            failure = failure or _cause(attributes)
            continue
        if len(attributes.items) != 1 or not isinstance(attributes.items[0], dict):
            failure = failure or ("malformed", {"code": "missing_fleet_attributes"})
            continue
        fleet = attributes.items[0]
        if fleet.get("ComputeType") != "EC2":
            continue
        arn = fleet.get("FleetArn")
        valid_arns = {f"arn:{_partition(region)}:gamelift:{region}:{owner}:fleet/{fleet_id}"
                      for owner in ("", account)}
        if fleet.get("FleetId") != fleet_id or arn not in valid_arns:
            failure = failure or ("malformed", {"code": "fleet_identity_mismatch"})
            continue
        computes = requests.pages(session, "gamelift", region, "list_compute", "ComputeList", FleetId=fleet_id)
        if computes.status not in OK:
            failure = failure or _cause(computes)
        compute_rows = []
        for compute in computes.items:
            if (not isinstance(compute, dict) or compute.get("FleetId") != fleet_id
                    or (compute.get("FleetArn") not in (None, arn))
                    or not isinstance(compute.get("ComputeName"), str)):
                failure = failure or ("malformed", {"code": "compute_identity_mismatch"})
                continue
            compute_rows.append(_pick(compute, ("FleetId", "FleetArn", "ComputeName", "ComputeStatus")))
        row = _pick(fleet, ("FleetId", "FleetArn", "ComputeType", "Status", "InstanceRoleArn",
                            "InstanceRoleCredentialsProvider"))
        row.update({"id": arn, "Computes": _child(computes, compute_rows)})
        rows.append(row)
    return _finish(rows, failure)


def _grafana_workspaces(requests, session, region, account):
    read = requests.pages(session, "grafana", region, "list_workspaces", "workspaces")
    items = []
    for workspace in read.items:
        if isinstance(workspace, dict) and isinstance(workspace.get("id"), str):
            row = _pick(workspace, ("id", "name", "status", "authentication", "licenseType", "grafanaVersion", "created", "modified"))
            row["Arn"] = f"arn:{_partition(region)}:grafana:{region}:{account}:/workspaces/{workspace['id']}"
            version = re.match(r"^(\d+)(?:\.|$)", str(workspace.get("grafanaVersion") or ""))
            if version and int(version.group(1)) < 9:
                row["ServiceAccounts"] = {"collection_status": "empty", "items": []}
            else:
                accounts = requests.pages(session, "grafana", region,
                                          "list_workspace_service_accounts", "serviceAccounts",
                                          workspaceId=workspace["id"])
                summaries = [_pick(item, ("id", "name", "grafanaRole", "isDisabled"))
                             for item in accounts.items if isinstance(item, dict)]
                row["ServiceAccounts"] = _child(accounts, summaries)
            items.append(row)
    read.items = items
    return read


def _quicksight_users(requests, session, region, account):
    read = requests.pages(session, "quicksight", region, "list_users", "UserList", AwsAccountId=account, Namespace="default")
    if read.status not in OK and (read.error or {}).get("code") in ("ResourceNotFoundException", "UnsupportedUserEditionException"):
        # No QuickSight subscription (or no user management) in this account.
        return _aws().ReadResult([], "empty", {"code": "service_not_enabled"})
    items = []
    for user in read.items:
        if isinstance(user, dict) and isinstance(user.get("Arn"), str):
            items.append({**_pick(user, ("Arn", "UserName", "PrincipalId", "Role", "IdentityType", "Active", "CustomPermissionsName")), "id": user["Arn"]})
    read.items = items
    return read


def _quicksight_account_subscription(requests, session, region, account):
    response, failure = _raw(requests, session, "quicksight", region, "describe_account_subscription", AwsAccountId=account)
    if failure:
        status, code = failure
        if code in ("ResourceNotFoundException", "UnsupportedUserEditionException"):
            return _aws().ReadResult([], "empty", {"code": "service_not_enabled"})
        return _aws().ReadResult([], status, {"code": code})
    info = response.get("AccountInfo") if isinstance(response, dict) else None
    if not isinstance(info, dict) or not isinstance(info.get("AccountSubscriptionStatus"), str) or not isinstance(info.get("AuthenticationType"), str):
        return _aws().ReadResult([], "malformed", {"code": "missing_subscription_state"})
    row = _pick(info, ("AccountSubscriptionStatus", "AuthenticationType"))
    row["id"] = account
    return _aws().ReadResult([row], "collected")


def _supplychain_instances(requests, session, region, account):
    read = requests.pages(session, "supplychain", region, "list_instances", "instances")
    items = []
    for instance in read.items:
        if isinstance(instance, dict) and isinstance(instance.get("instanceId"), str):
            row = _pick(instance, ("instanceId", "awsAccountId", "state", "instanceName", "kmsKeyArn", "webAppDnsDomain", "createdTime"))
            row["Arn"] = f"arn:{_partition(region)}:scn:{region}:{instance.get('awsAccountId') or account}:instance/{instance['instanceId']}"
            row["id"] = row["Arn"]
            items.append(row)
    read.items = items
    return read


def _amplify_apps(requests, session, region, account):
    read = requests.pages(session, "amplify", region, "list_apps", "apps")
    if read.status not in OK:
        return _finish([], _cause(read))
    items, failure = [], None
    for app in read.items:
        if not isinstance(app, dict) or not isinstance(app.get("appId"), str):
            failure = failure or ("malformed", {"code": "malformed_app"})
            continue
        # Never environmentVariables, basicAuthCredentials, buildSpec or customHeaders.
        row = _pick(app, ("appId", "appArn", "name", "platform", "iamServiceRoleArn", "computeRoleArn", "defaultDomain", "enableBasicAuth",
                          "createTime", "updateTime"))
        row["RepositoryConnected"] = bool(app.get("repository"))
        row["AppBuildSpecPresent"] = (app["AppBuildSpecPresent"] if type(app.get("AppBuildSpecPresent")) is bool
                                      else bool(app.get("buildSpec")))
        if "AdditionalSecretIndicators" in app:
            row["AdditionalSecretIndicators"] = copy.deepcopy(app["AdditionalSecretIndicators"])
        row["id"] = app.get("appArn") or app["appId"]
        backends = requests.pages(session, "amplify", region, "list_backend_environments", "backendEnvironments",
                                  _tokens=("nextToken", "nextToken"), appId=app["appId"])
        row["BackendEnvironments"] = _child(backends, [_pick(x, ("backendEnvironmentArn", "environmentName", "stackName"))
                                                       for x in backends.items if isinstance(x, dict)])
        branches = requests.pages(session, "amplify", region, "list_branches", "branches",
                                  _tokens=("nextToken", "nextToken"), appId=app["appId"])
        row["Branches"] = _child(branches, [
            {**_pick(x, ("branchArn", "branchName", "displayName", "stage", "enableAutoBuild", "enableBasicAuth", "framework", "computeRoleArn")),
             "BranchBuildSpecPresent": bool(x.get("buildSpec"))}
            for x in branches.items if isinstance(x, dict)])
        domains = requests.pages(session, "amplify", region, "list_domain_associations", "domainAssociations",
                                 _tokens=("nextToken", "nextToken"), appId=app["appId"])
        row["DomainAssociations"] = _child(domains, [
            {**_pick(x, ("domainAssociationArn", "domainName", "domainStatus", "enableAutoSubDomain")),
             "subDomains": [
                 {"subDomainSetting": _pick(sub.get("subDomainSetting", {}), ("prefix", "branchName")),
                  "verified": sub.get("verified")}
                 for sub in x.get("subDomains", []) if isinstance(sub, dict)]}
            for x in domains.items if isinstance(x, dict)])
        items.append(row)
    return _finish(items, failure)


# ------------------------------------------------------------------------- Identity Center
def _account_assignments(requests, session, region, account):
    instances = requests.pages(session, "sso-admin", region, "list_instances", "Instances")
    if instances.status not in OK:
        return _finish([], _cause(instances))
    items, failure = [], None
    for instance in instances.items:
        arn = instance.get("InstanceArn") if isinstance(instance, dict) else None
        if not isinstance(arn, str):
            failure = failure or ("malformed", {"code": "malformed_identity_center_instance"})
            continue
        names = {}
        store = instance.get("IdentityStoreId")
        if isinstance(store, str) and store:
            groups = requests.pages(session, "identitystore", region, "list_groups", "Groups", IdentityStoreId=store)
            names = {g.get("GroupId"): g.get("DisplayName") for g in groups.items if isinstance(g, dict)}
        sets = requests.pages(session, "sso-admin", region, "list_permission_sets", "PermissionSets", InstanceArn=arn)
        if sets.status not in OK:
            failure = failure or _cause(sets)
        for permission_set in sets.items:
            if not isinstance(permission_set, str):
                failure = failure or ("malformed", {"code": "malformed_permission_set_arn"})
                continue
            accounts = requests.pages(session, "sso-admin", region, "list_accounts_for_provisioned_permission_set", "AccountIds",
                                      InstanceArn=arn, PermissionSetArn=permission_set)
            if accounts.status not in OK:
                failure = failure or _cause(accounts)
            for target in accounts.items:
                if not isinstance(target, str):
                    continue
                read = requests.pages(session, "sso-admin", region, "list_account_assignments", "AccountAssignments",
                                      InstanceArn=arn, AccountId=target, PermissionSetArn=permission_set)
                if read.status not in OK:
                    failure = failure or _cause(read)
                for assignment in read.items:
                    if not isinstance(assignment, dict) or not isinstance(assignment.get("PrincipalId"), str):
                        failure = failure or ("malformed", {"code": "malformed_account_assignment"})
                        continue
                    row = _pick(assignment, ("AccountId", "PermissionSetArn", "PrincipalType", "PrincipalId"))
                    row.update({"InstanceArn": arn, "InstanceOwnerAccountId": instance.get("OwnerAccountId"),
                                "id": f"{arn}/{target}/{permission_set}/{assignment.get('PrincipalType')}/{assignment['PrincipalId']}"})
                    if assignment.get("PrincipalType") == "GROUP" and names.get(assignment["PrincipalId"]):
                        row["GroupDisplayName"] = names[assignment["PrincipalId"]]
                    items.append(row)
    return _finish(items, failure)


FETCHERS = {
    "lambda_layer_version": _layer_versions,
    "lambda_alias": _aliases,
    "lambda_event_source_mapping": _event_source_mappings,
    "ecr_registry": _ecr_registry,
    "eks_access_entry": _access_entries,
    "eks_pod_identity_association": _pod_identity_associations,
    "kms_grant": _kms_grants,
    "opensearch_connection": _opensearch_connections,
    "route53_record_set": _record_sets,
    "cloudformation_stack_instance": _stack_instances,
    "cloudformation_organizations_access": _stackset_organizations_access,
    "ec2_instance_connect_endpoint": _instance_connect_endpoints,
    "rolesanywhere_profile": _rolesanywhere_profiles,
    "imagebuilder_pipeline": _image_pipelines,
    "sagemaker_user_profile": _user_profiles,
    "sagemaker_space": _spaces,
    "sagemaker_cluster": _hyperpod_clusters,
    "grafana_workspace": _grafana_workspaces,
    "gamelift_ec2_compute": _gamelift_ec2_computes,
    "iot_role_alias": _iot_role_aliases,
    "devicefarm_upload": _devicefarm_project_children("devicefarm_upload"),
    "devicefarm_device_pool": _devicefarm_project_children("devicefarm_device_pool"),
    "quicksight_user": _quicksight_users,
    "quicksight_account_subscription": _quicksight_account_subscription,
    "supplychain_instance": _supplychain_instances,
    "amplify_app": _amplify_apps,
    "aws_identity_center_account_assignment": _account_assignments,
}
ENRICHERS = {
    "lambda_function": _lambda_function,
    "cognito_identity_pool": _identity_pool,
    "cognito_user_pool": _user_pool,
    "sagemaker_domain": _sagemaker_domain,
}
