"""AWS compute/edge collector facts; all I/O uses the main shared read scheduler.

Read-only list/get/describe calls only. Values that can carry credentials or
code (environment values, user data, BGP auth keys, router configuration,
integration templates, OIDC client secrets, WAF lock tokens) are never kept:
records are projected onto the metadata the checks read.
"""
from __future__ import annotations
import copy
import re

from .aws_b_services import _metadata

SPECS = {
    "launch_configuration": ("autoscaling", "describe_launch_configurations", "LaunchConfigurations"),
    "ecs_service": ("ecs", "describe_services", None),
    "ecs_task_set": ("ecs", "describe_services", None),
    "ecs_account_setting": ("ecs", "list_account_settings", "settings"),
    "appstream_fleet": ("appstream", "describe_fleets", "Fleets"),
    "appstream_image": ("appstream", "describe_images", "Images"),
    "appstream_app_block": ("appstream", "describe_app_blocks", "AppBlocks"),
    "appstream_app_block_builder_association": ("appstream", "describe_app_block_builder_app_block_associations", "AppBlockBuilderAppBlockAssociations"),
    "elastic_beanstalk_environment": ("elasticbeanstalk", "describe_environments", "Environments"),
    "apigateway_domain_name": ("apigateway", "get_domain_names", "items"),
    "apigatewayv2_domain_name": ("apigatewayv2", "get_domain_names", "Items"),
    "appsync_graphql_api": ("appsync", "list_graphql_apis", "graphqlApis"),
    "directconnect_connection": ("directconnect", "describe_connections", "connections"),
    "directconnect_virtual_interface": ("directconnect", "describe_virtual_interfaces", "virtualInterfaces"),
    "managed_prefix_list": ("ec2", "describe_managed_prefix_lists", "PrefixLists"),
    "wafv2_web_acl": ("wafv2", "list_web_acls", "WebACLs"),
    "wafv2_rule_group": ("wafv2", "list_rule_groups", "RuleGroups"),
    "waf_web_acl": ("waf", "list_web_acls", "WebACLs"),
    "waf_rule": ("waf", "list_rules", "Rules"),
    "waf_rule_group": ("waf", "list_rule_groups", "RuleGroups"),
    "wafregional_web_acl": ("waf-regional", "list_web_acls", "WebACLs"),
    "wafregional_rule": ("waf-regional", "list_rules", "Rules"),
    "wafregional_rule_group": ("waf-regional", "list_rule_groups", "RuleGroups"),
}
NATIVE_IDS = {
    "launch_configuration": "LaunchConfigurationARN", "ecs_service": "serviceArn", "ecs_task_set": "taskSetArn", "ecs_account_setting": "name",
    "appstream_fleet": "Arn", "appstream_image": "Arn", "appstream_app_block": "Arn", "appstream_app_block_builder_association": "AppBlockBuilderName", "elastic_beanstalk_environment": "EnvironmentArn", "apigateway_domain_name": "domainName", "apigatewayv2_domain_name": "DomainName", "appsync_graphql_api": "arn",
    "directconnect_connection": "connectionId", "directconnect_virtual_interface": "virtualInterfaceId", "managed_prefix_list": "PrefixListId",
    "wafv2_web_acl": "ARN", "wafv2_rule_group": "ARN", "waf_web_acl": "WebACLId", "waf_rule": "RuleId", "waf_rule_group": "RuleGroupId",
    "wafregional_web_acl": "WebACLId", "wafregional_rule": "RuleId", "wafregional_rule_group": "RuleGroupId",
}
# Classic (global) WAF is served from the us-east-1 endpoint once per account.
GLOBAL_TYPES = {"waf_web_acl", "waf_rule", "waf_rule_group"}
READ_ACTIONS = {(service, operation) for service, operation, expression in SPECS.values()}
READ_ACTIONS.update({
    ("ecs", "list_clusters"), ("ecs", "list_services"), ("ecs", "describe_task_definition"),
    ("appstream", "list_associated_stacks"),
    ("elasticbeanstalk", "describe_configuration_settings"),
    ("apigateway", "get_resources"), ("apigateway", "get_authorizers"),
    ("apigateway", "get_base_path_mappings"),
    ("apigatewayv2", "get_routes"), ("apigatewayv2", "get_authorizers"),
    ("apigatewayv2", "get_api_mappings"), ("apigatewayv2", "get_integrations"),
    ("apigatewayv2", "list_routing_rules"),
    ("elb", "describe_instance_health"),
    ("elbv2", "describe_target_group_attributes"),
    ("appsync", "get_api_cache"), ("eks", "describe_addon"), ("lambda", "get_function_configuration"),
    ("elbv2", "describe_rules"), ("logs", "describe_delivery_sources"), ("logs", "describe_deliveries"),
    ("ec2", "get_managed_prefix_list_entries"), ("ec2", "describe_image_attribute"),
    ("rds", "describe_db_cluster_snapshot_attributes"),
    ("wafv2", "get_web_acl"), ("wafv2", "get_rule_group"), ("wafv2", "get_logging_configuration"), ("wafv2", "list_resources_for_web_acl"),
    ("cloudfront", "list_distributions_by_web_acl_id"),
    ("cloudfront", "get_origin_access_control"),
    ("waf", "get_web_acl"), ("waf", "get_rule"), ("waf", "get_logging_configuration"), ("waf", "list_activated_rules_in_rule_group"),
    ("waf-regional", "get_web_acl"), ("waf-regional", "get_rule"), ("waf-regional", "get_logging_configuration"),
    ("waf-regional", "list_activated_rules_in_rule_group"), ("waf-regional", "list_resources_for_web_acl"),
})

_WAF_ABSENT = ("WAFNonexistentItemException",)
_WAFV2_RESOURCE_TYPES = ("APPLICATION_LOAD_BALANCER", "API_GATEWAY", "APPSYNC", "COGNITO_USER_POOL", "APP_RUNNER_SERVICE", "VERIFIED_ACCESS_INSTANCE", "AMPLIFY")
_WAFREGIONAL_RESOURCE_TYPES = ("APPLICATION_LOAD_BALANCER", "API_GATEWAY")
# A resource type this region's WAF does not support is not an association.
_UNSUPPORTED_TYPE = ("WAFInvalidParameterException", "WAFInvalidOperationException")
_BEANSTALK_OPTIONS = {("aws:elasticbeanstalk:cloudwatch:logs", "StreamLogs"), ("aws:elasticbeanstalk:managedactions", "ManagedActionsEnabled"),
                      ("aws:elasticbeanstalk:healthreporting:system", "SystemType"),
                      ("aws:elasticbeanstalk:hostmanager", "LogPublicationControl"),
                      ("aws:elasticbeanstalk:environment", "LoadBalancerType")}
_SECRET_KEYS = {"authKey", "customerRouterConfig", "macSecKeys", "LockToken", "UserData"}


def _result(*args, **kwargs):
    from .aws import ReadResult
    return ReadResult(*args, **kwargs)


def _failure(exc):
    from .aws import _failure as failure
    return failure(exc)


def _strip(value):
    if isinstance(value, list):
        return [_strip(item) for item in value]
    if not isinstance(value, dict):
        return value
    return {key: _strip(item) for key, item in value.items() if key not in _SECRET_KEYS}


def _usable(read):
    return read.status in ("collected", "empty")


def _fail(read, items=()):
    items = list(items)
    return _result(items, "partial" if items else read.status, read.error)


def _child(read, project=None):
    """A complete child list {collection_status: collected, items}; failed reads carry no items."""
    if not _usable(read):
        return {"collection_status": read.status, "error": read.error or {}}
    return {"collection_status": "collected", "items": [project(row) if project else row for row in _metadata(read.items)]}


def _pick(row, keys):
    return {key: copy.deepcopy(row[key]) for key in keys if isinstance(row, dict) and key in row}


def _global_region(region):
    """Global edge control planes (CloudFront logs, classic WAF, CLOUDFRONT-scope WAFv2)."""
    return region if region.startswith(("cn-", "us-gov-", "us-iso")) else "us-east-1"


# ---- compute -----------------------------------------------------------

def _ecs_services(requests, session, region):
    """ListClusters -> ListServices -> DescribeServices (10 per call), shared by
    ecs_service and ecs_task_set through the scan-local request cache."""
    clusters = requests.pages(session, "ecs", region, "list_clusters", "clusterArns")
    if not _usable(clusters):
        return [], clusters
    services, failed, seen = [], None, set()
    for cluster in clusters.items:
        arns = requests.pages(session, "ecs", region, "list_services", "serviceArns", cluster=cluster)
        if not _usable(arns):
            failed = failed or arns
            continue
        for offset in range(0, len(arns.items), 10):
            try:
                response = requests.call(session, "ecs", region, "describe_services", cluster=cluster, services=arns.items[offset:offset + 10])
            except Exception as exc:
                failure = _failure(exc)
                failed = failed or _result([], failure.status, {"code": failure.code})
                continue
            rows = response.get("services")
            if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
                failed = failed or _result([], "malformed", {"code": "malformed_response"})
                continue
            # Account for every requested identity before treating absence as
            # complete. Only an explicit MISSING failure proves a list/describe race.
            requested = set(arns.items[offset:offset + 10])
            failures = response.get("failures", [])
            if (not isinstance(failures, list) or
                    any(not isinstance(f, dict) or f.get("reason") != "MISSING" or
                        not isinstance(f.get("arn"), str) or f["arn"] not in requested
                        for f in failures)):
                failed = failed or _result([], "partial", {"code": "describe_services_failures"})
                failures = []
            missing = [f["arn"] for f in failures]
            for row in rows:
                service_arn = row.get("serviceArn")
                if isinstance(service_arn, str) and service_arn in seen:
                    # A duplicate detail makes this subject ambiguous; retaining
                    # the first row would allow a resource PASS beside UNKNOWN.
                    services[:] = [kept for kept in services if kept.get("serviceArn") != service_arn]
                if (not isinstance(service_arn, str) or service_arn not in requested or
                        service_arn in seen or row.get("clusterArn") != cluster):
                    failed = failed or _result([], "malformed", {"code": "describe_services_identity_mismatch"})
                    continue
                seen.add(service_arn)
                services.append(row)
            returned = {row["serviceArn"] for row in rows if isinstance(row.get("serviceArn"), str)}
            if (len(missing) != len(set(missing)) or returned.intersection(missing) or
                    returned.union(missing) != requested):
                failed = failed or _result([], "partial", {"code": "describe_services_incomplete"})
    return services, failed


def _ecs_service(requests, session, region, account):
    services, failed = _ecs_services(requests, session, region)
    rows = []
    for service in services:
        row = {key: value for key, value in service.items() if key not in ("events", "taskSets", "deployments")}
        # Service has no top-level volumeConfigurations member. The native
        # DescribeServices Deployment has it; retain only an exact PRIMARY view.
        service_arn, cluster_arn = row.get("serviceArn"), row.get("clusterArn")
        service_match = re.fullmatch(
            r"arn:(aws|aws-us-gov|aws-cn):ecs:" + re.escape(region) +
            r":" + re.escape(account) + r":service/(?:[^/]+/)?[^/]+", service_arn or "")
        cluster_match = re.fullmatch(
            r"arn:(aws|aws-us-gov|aws-cn):ecs:" + re.escape(region) +
            r":" + re.escape(account) + r":cluster/[^/]+", cluster_arn or "")
        deployments = service.get("deployments")
        if (not failed and service_match and cluster_match and
                service_match.group(1) == cluster_match.group(1) and
                "_coverage" not in service and "volumeConfigurations" not in service and
                isinstance(deployments, list) and len(deployments) == 1 and
                isinstance(deployments[0], dict) and
                "_coverage" not in deployments[0] and
                deployments[0].get("status") == "PRIMARY" and
                deployments[0].get("taskDefinition") == row.get("taskDefinition")):
            primary = deployments[0]
            if "volumeConfigurations" in primary:
                row["volumeConfigurations"] = primary["volumeConfigurations"]
                state = "collected"
            else:
                row["volumeConfigurations"] = []
                state = "empty"
            row.setdefault("_coverage", {})["volumeConfigurations"] = {
                "status": state, "source_operation": "ecs:DescribeServices",
                "native_member_present": state == "collected", "account_id": account,
                "region": region, "service_arn": service_arn,
                "cluster_arn": cluster_arn, "task_definition_arn": row["taskDefinition"],
                "deployment_status": "PRIMARY"}
        rows.append(_metadata(row))
    if failed:
        return _fail(failed, rows)
    return _result(rows, "collected" if rows else "empty")


def _ecs_task_set(requests, session, region, account):
    services, failed = _ecs_services(requests, session, region)
    rows = []
    for service in services:
        for task_set in service.get("taskSets") or []:
            if isinstance(task_set, dict):
                row = _metadata(task_set)
                row.setdefault("serviceArn", service.get("serviceArn"))
                row.setdefault("clusterArn", service.get("clusterArn"))
                rows.append(row)
    if failed:
        return _fail(failed, rows)
    return _result(rows, "collected" if rows else "empty")


def _ecs_account_setting(requests, session, region, account):
    return requests.pages(session, "ecs", region, "list_account_settings", "settings", name="defaultLogDriverMode", effectiveSettings=True)


def _beanstalk_environments(requests, session, region, account):
    return requests.pages(session, "elasticbeanstalk", region, "describe_environments", "Environments", IncludeDeleted=False)


def _beanstalk_configuration(requests, session, region, items):
    output = []
    for item in items:
        item = copy.deepcopy(item)
        response = requests.detail(session, "elasticbeanstalk", region, "describe_configuration_settings",
                                   ApplicationName=item["ApplicationName"], EnvironmentName=item["EnvironmentName"])
        if response.get("collection_status") != "collected":
            item["Configuration"] = {"collection_status": response.get("collection_status"), "error": response.get("error", {})}
        else:
            # Only the named options: other namespaces carry environment properties.
            item["Configuration"] = {"collection_status": "collected",
                "AdditionalSecretIndicators": copy.deepcopy(response.get("AdditionalSecretIndicators")), "ConfigurationSettings": [
                {**_pick(setting, ("ApplicationName", "EnvironmentName", "SolutionStackName", "PlatformArn")),
                 "OptionSettings": [_pick(option, ("Namespace", "OptionName", "Value")) for option in setting.get("OptionSettings") or []
                                    if isinstance(option, dict) and (option.get("Namespace"), option.get("OptionName")) in _BEANSTALK_OPTIONS]}
                for setting in response.get("ConfigurationSettings") or [] if isinstance(setting, dict)]}
        from .aws_beanstalk_runtime_metadata import enrich_environment
        output.append(enrich_environment(requests, session, region, item, response))
    return output


def _launch_configurations(requests, session, region, items):
    return [_strip(item) for item in items]


def _lambda_variable_count(requests, session, region, items):
    """Environment.VariableCount from the cached GetFunctionConfiguration; values never leave this function."""
    output = []
    for item in items:
        item = copy.deepcopy(item)
        try:
            raw = requests.call(session, "lambda", region, "get_function_configuration", FunctionName=item["FunctionName"])
        except Exception:
            raw = None
        environment = raw.get("Environment") if isinstance(raw, dict) else None
        if isinstance(raw, dict) and environment is None:
            item["Environment"] = {"VariableCount": 0}
        elif isinstance(environment, dict) and isinstance(environment.get("Variables"), dict):
            item["Environment"] = {"VariableCount": len(environment["Variables"])}
        else:
            # Unread, or an Environment.Error without variables: presence unknown.
            item["Environment"] = {}
        output.append(item)
    return output


def _ecs_environment_names(requests, session, region, items):
    """Add only ECS environment *names* from a matching complete cached detail.

    Values never enter the snapshot. A failed, malformed or identity-mismatched
    second view leaves environment absent so checks return UNKNOWN.
    """
    output = []
    for original in items:
        item = copy.deepcopy(original)
        detail = item.get("Definition")
        definition = detail.get("taskDefinition") if isinstance(detail, dict) else None
        if isinstance(detail, dict) and detail.get("collection_status") == "collected" and isinstance(definition, dict):
            try:
                raw = requests.call(session, "ecs", region, "describe_task_definition",
                                    taskDefinition=item["taskDefinitionArn"])
            except Exception:
                raw = None
            raw_definition = raw.get("taskDefinition") if isinstance(raw, dict) else None
            raw_containers = raw_definition.get("containerDefinitions") if isinstance(raw_definition, dict) else None
            projected_containers = definition.get("containerDefinitions")
            if (isinstance(raw_definition, dict) and
                    raw_definition.get("taskDefinitionArn") == item.get("taskDefinitionArn") == definition.get("taskDefinitionArn") and
                    isinstance(raw_containers, list) and isinstance(projected_containers, list)):
                names = {}
                valid = True
                for container in raw_containers:
                    if not isinstance(container, dict) or not isinstance(container.get("name"), str) or not container["name"] or container["name"] in names:
                        valid = False
                        break
                    environment = container.get("environment", [])
                    if not isinstance(environment, list) or any(not isinstance(entry, dict) or not isinstance(entry.get("name"), str)
                            or not entry["name"] for entry in environment):
                        valid = False
                        break
                    names[container["name"]] = [{"name": entry["name"]} for entry in environment]
                projected_names = [container.get("name") if isinstance(container, dict) else None for container in projected_containers]
                if valid and len(projected_names) == len(names) and set(projected_names) == set(names):
                    for container in projected_containers:
                        container["environment"] = names[container["name"]]
        output.append(item)
    return output


def _eks_vpc_cni(requests, session, region, items):
    output = []
    for item in items:
        item = copy.deepcopy(item)
        response = requests.detail(session, "eks", region, "describe_addon", clusterName=item["name"], addonName="vpc-cni", absent=("ResourceNotFoundException",))
        if response.get("collection_status") == "collected":
            addon = response.get("addon")
            if (not isinstance(addon, dict) or addon.get("clusterName") != item["name"]
                    or addon.get("addonName") != "vpc-cni"):
                item["VpcCniAddon"] = {"collection_status": "malformed",
                                       "error": {"code": "eks_addon_subject_identity_mismatch"}}
            else:
                item["VpcCniAddon"] = {"collection_status": "collected",
                                       "addon": _pick(addon, ("addonName", "addonVersion", "status", "configurationValues"))}
        else:
            item["VpcCniAddon"] = response
        output.append(item)
    return output


def _image_launch_permissions(requests, session, region, items):
    output = []
    for item in items:
        item = copy.deepcopy(item)
        image = item["ImageId"]
        response = requests.detail(session, "ec2", region, "describe_image_attribute", ImageId=image, Attribute="launchPermission")
        state = response.get("collection_status", "not_collected")
        values = response.get("LaunchPermissions", [])
        coverage = item.setdefault("_coverage", {})
        if state == "collected" and response.get("ImageId") == image and isinstance(values, list) and all(isinstance(v, dict) for v in values):
            item["LaunchPermissions"] = values
            coverage["LaunchPermissions"] = {"status": "collected" if values else "empty", "source_operation": "ec2:DescribeImageAttribute"}
        else:
            coverage["LaunchPermissions"] = {"status": "malformed" if state == "collected" else state, "source_operation": "ec2:DescribeImageAttribute",
                                             **({"error": response["error"]} if response.get("error") else {})}
        output.append(item)
    return output


def _cluster_snapshot_attributes(requests, session, region, items):
    output = []
    for item in items:
        item = copy.deepcopy(item)
        item["Attributes"] = requests.detail(session, "rds", region, "describe_db_cluster_snapshot_attributes",
                                             DBClusterSnapshotIdentifier=item["DBClusterSnapshotIdentifier"], absent=("DBClusterSnapshotNotFoundFault",))
        output.append(item)
    return output


def _appstream_fleets(requests, session, region, items):
    output = []
    for item in items:
        current = _strip(item)
        name = current.get("Name")
        current["AssociatedStacks"] = (_child(requests.pages(
            session, "appstream", region, "list_associated_stacks", "Names", FleetName=name))
            if isinstance(name, str) and name else {"collection_status": "malformed"})
        output.append(current)
    return output


def _appstream_images(requests, session, region, items):
    return [_pick(item, ("Arn", "Name", "State", "Visibility", "ImageType", "ImageBuilderSupported",
                         "ImagePermissions", "SupportedInstanceFamilies", "Platform")) for item in items]


def _appstream_app_blocks(requests, session, region, items):
    return [_pick(item, ("Arn", "Name", "PackagingType", "State")) for item in items]


# ---- edge --------------------------------------------------------------

def _rest_api_method(resource):
    row = _pick(resource, ("id", "parentId", "path"))
    row["resourceMethods"] = {}
    for verb, method in (resource.get("resourceMethods") or {}).items():
        if not isinstance(method, dict):
            continue
        selected = _pick(method, ("httpMethod", "authorizationType", "authorizerId", "authorizationScopes", "apiKeyRequired", "requestValidatorId", "operationName"))
        uri = (method.get("methodIntegration") or {}).get("uri")
        match = re.search(r"/functions/(arn:[^/]+:lambda:[^/]+:function:[^/]+)/", uri) if isinstance(uri, str) else None
        if match:
            selected["integrationLambdaArn"] = match.group(1)
        row["resourceMethods"][verb] = selected
    return row


def _api_domain_mappings(requests, session, region, items):
    output = []
    for item in items:
        current = copy.deepcopy(item)
        name = current.get("domainName")
        current["BasePathMappings"] = (_child(requests.pages(session, "apigateway", region,
            "get_base_path_mappings", "items", domainName=name),
            lambda row: _pick(row, ("basePath", "restApiId", "stage")))
            if isinstance(name, str) and name else {"collection_status": "malformed"})
        if "ROUTING_RULE" in str(current.get("routingMode", "")):
            def single_header_condition(row):
                conditions = row.get("Conditions")
                if not isinstance(conditions, list) or len(conditions) != 1 or not isinstance(conditions[0], dict):
                    return False
                condition = conditions[0]
                headers = condition.get("MatchHeaders")
                values = headers.get("AnyOf") if isinstance(headers, dict) else None
                return (set(condition) == {"MatchHeaders"} and isinstance(values, list) and len(values) == 1
                        and isinstance(values[0], dict) and isinstance(values[0].get("Header"), str)
                        and bool(values[0]["Header"]) and isinstance(values[0].get("ValueGlob"), str)
                        and bool(values[0]["ValueGlob"]))

            def single_base_path_condition(row):
                conditions = row.get("Conditions")
                if not isinstance(conditions, list) or len(conditions) != 1 or not isinstance(conditions[0], dict):
                    return False
                condition = conditions[0]
                paths = condition.get("MatchBasePaths")
                values = paths.get("AnyOf") if isinstance(paths, dict) else None
                return (set(condition) == {"MatchBasePaths"} and isinstance(values, list) and len(values) == 1
                        and isinstance(values[0], str) and bool(values[0]))

            current["RoutingRules"] = (_child(requests.pages(session, "apigatewayv2", region,
                "list_routing_rules", "RoutingRules", DomainName=name),
                lambda row: {"RoutingRuleId": row.get("RoutingRuleId"),
                             "Priority": row.get("Priority"),
                             "ConditionCount": len(row["Conditions"]) if isinstance(row.get("Conditions"), list) else None,
                             "SingleHeaderCondition": single_header_condition(row),
                             "SingleBasePathCondition": single_base_path_condition(row),
                             "Actions": [{"InvokeApi": _pick(action["InvokeApi"], ("ApiId", "Stage", "StripBasePath"))}
                                         for action in row.get("Actions", []) if isinstance(action, dict)
                                         and isinstance(action.get("InvokeApi"), dict)]})
                if isinstance(name, str) and name else {"collection_status": "malformed"})
        output.append(current)
    return output


def _http_api_domain_mappings(requests, session, region, items):
    output = []
    for item in items:
        current = copy.deepcopy(item)
        name = current.get("DomainName")
        current["ApiMappings"] = (_child(requests.pages(session, "apigatewayv2", region,
            "get_api_mappings", "Items", DomainName=name),
            lambda row: _pick(row, ("ApiId", "Stage", "ApiMappingKey", "ApiMappingId")))
            if isinstance(name, str) and name else {"collection_status": "malformed"})
        output.append(current)
    return output


def _http_integration(row):
    result = _pick(row, ("IntegrationId", "IntegrationType", "IntegrationMethod", "IntegrationSubtype"))
    uri = row.get("IntegrationUri")
    if isinstance(uri, str):
        match = re.search(r"arn:[^/\s]+:lambda:[^/\s]+:[0-9]{12}:function:[^/:\s]+(?::[^/\s]+)?", uri)
        if match:
            result["integrationLambdaArn"] = match.group(0)
    return result


def _rest_api(requests, session, region, items):
    output = []
    for item in items:
        item = copy.deepcopy(item)
        api = item["id"]
        item["Authorizers"] = _child(requests.pages(session, "apigateway", region, "get_authorizers", "items", restApiId=api),
                                     lambda a: _pick(a, ("id", "name", "type", "authType", "providerARNs", "authorizerUri", "identitySource", "identityValidationExpression", "authorizerResultTtlInSeconds")))
        if "items" in item["Authorizers"]:
            identities = [row.get("id") for row in item["Authorizers"]["items"]]
            if (any(not isinstance(value, str) or not value for value in identities)
                    or len(set(identities)) != len(identities)):
                item["Authorizers"] = {"collection_status": "malformed", "error": {"code": "authorizer_identity_incomplete_or_duplicate"}}
        item["Resources"] = _child(requests.pages(session, "apigateway", region, "get_resources", "items", restApiId=api, embed=["methods"]), _rest_api_method)
        if "items" in item["Resources"]:
            item["Methods"] = [{"resourceId": r.get("id"), "path": r.get("path"), **method}
                               for r in item["Resources"]["items"] for method in r["resourceMethods"].values()]
        output.append(item)
    return output


def _http_api(requests, session, region, items):
    output = []
    for item in items:
        item = copy.deepcopy(item)
        api = item["ApiId"]
        item["Authorizers"] = _child(requests.pages(session, "apigatewayv2", region, "get_authorizers", "Items", ApiId=api),
                                     lambda a: _pick(a, ("AuthorizerId", "Name", "AuthorizerType", "IdentitySource", "JwtConfiguration", "AuthorizerUri", "AuthorizerPayloadFormatVersion", "EnableSimpleResponses")))
        item["Routes"] = _child(requests.pages(session, "apigatewayv2", region, "get_routes", "Items", ApiId=api),
                                lambda r: _pick(r, ("RouteId", "RouteKey", "AuthorizationType", "AuthorizerId", "AuthorizationScopes", "ApiKeyRequired", "ApiGatewayManaged", "OperationName", "Target")))
        item["Integrations"] = _child(requests.pages(session, "apigatewayv2", region, "get_integrations", "Items", ApiId=api),
                                      _http_integration)
        output.append(item)
    return output


def _appsync_cache(requests, session, region, items):
    output = []
    for item in items:
        item = copy.deepcopy(item)
        item["ApiCache"] = _metadata(requests.detail(session, "appsync", region, "get_api_cache", apiId=item["apiId"], absent=("NotFoundException",)))
        output.append(item)
    return output


def _directconnect(operation, expression):
    def fetch(requests, session, region, account):
        read = requests.pages(session, "directconnect", region, operation, expression, _tokens=("nextToken", "nextToken"))
        read.items = _strip(read.items)
        return read
    return fetch


def _prefix_list_entries(requests, session, region, items):
    output = []
    for item in items:
        item = copy.deepcopy(item)
        version = item.get("Version")
        kwargs = {"PrefixListId": item["PrefixListId"]}
        if isinstance(version, int) and not isinstance(version, bool) and version > 0:
            kwargs["TargetVersion"] = version
        item["Entries"] = _child(requests.pages(session, "ec2", region, "get_managed_prefix_list_entries", "Entries", **kwargs))
        item["EntriesVersion"] = version if "TargetVersion" in kwargs else None
        output.append(item)
    return output


def _load_balancer_rules(requests, session, region, items):
    """DescribeRules for HTTP and HTTPS listeners of an application load balancer."""
    def action(row):
        return _pick(row, ("Type", "Order", "TargetGroupArn", "RedirectConfig", "ForwardConfig", "FixedResponseConfig"))

    def rule(row):
        conditions = []
        for condition in row.get("Conditions") or []:
            if not isinstance(condition, dict):
                conditions.append({"Field": "unknown"})
                continue
            field = condition.get("Field")
            entry = {"Field": field}
            if field == "source-ip":
                entry["Values"] = list((condition.get("SourceIpConfig") or {}).get("Values")
                    or condition.get("Values") or [])
            conditions.append(entry)
        return {**_pick(row, ("RuleArn", "Priority", "IsDefault")), "Conditions": conditions,
            "Actions": [action(a) for a in row.get("Actions") or [] if isinstance(a, dict)]}

    output = []
    for item in items:
        item = copy.deepcopy(item)
        listeners = item.get("Listeners")
        if item.get("Type") == "application" and isinstance(listeners, dict) and listeners.get("collection_status") == "collected":
            for listener in listeners.get("items") or []:
                if isinstance(listener, dict) and listener.get("Protocol") in {"HTTP", "HTTPS"} and isinstance(listener.get("ListenerArn"), str):
                    listener["Rules"] = _child(requests.pages(session, "elbv2", region, "describe_rules", "Rules", ListenerArn=listener["ListenerArn"]),
                                               rule)
        output.append(item)
    return output


def _classic_instance_health(requests, session, region, items):
    """Collect only Classic ELB target identity and health state via the scan cache."""
    output = []
    for item in items:
        current = copy.deepcopy(item)
        name = current.get("LoadBalancerName")
        if not isinstance(name, str) or not name:
            current["InstanceHealth"] = {"collection_status": "malformed"}
            output.append(current)
            continue
        read = requests.detail(session, "elb", region, "describe_instance_health", LoadBalancerName=name)
        status = read.get("collection_status", "not_collected")
        states = read.get("InstanceStates")
        if status == "collected" and isinstance(states, list) and all(isinstance(x, dict) for x in states):
            current["InstanceHealth"] = {"collection_status": "collected", "InstanceStates": [
                _pick(x, ("InstanceId", "State", "ReasonCode")) for x in states]}
        else:
            current["InstanceHealth"] = {"collection_status": "malformed" if status == "collected" else status,
                                         **({"error": read["error"]} if isinstance(read.get("error"), dict) else {})}
        output.append(current)
    return output


def _target_group_attributes(requests, session, region, items):
    """Keep the NLB client source mode from one cached read per target group."""
    output = []
    for item in items:
        current = copy.deepcopy(item)
        arn = current.get("TargetGroupArn")
        if not isinstance(arn, str) or not arn:
            current["SourceAttributes"] = {"collection_status": "malformed"}
            output.append(current)
            continue
        if current.get("Protocol") not in ("TCP", "TLS") or current.get("TargetType") != "ip":
            output.append(current)
            continue
        read = requests.detail(session, "elbv2", region, "describe_target_group_attributes", TargetGroupArn=arn)
        status = read.get("collection_status", "not_collected")
        attributes = read.get("Attributes")
        if status == "collected" and isinstance(attributes, list) and all(isinstance(x, dict) for x in attributes):
            values = [x.get("Value") for x in attributes if x.get("Key") == "preserve_client_ip.enabled"]
            if len(values) == 1 and values[0] in ("true", "false"):
                current["SourceAttributes"] = {"collection_status": "collected",
                                                "preserve_client_ip_enabled": values[0] == "true"}
            else:
                current["SourceAttributes"] = {"collection_status": "malformed"}
        else:
            current["SourceAttributes"] = {"collection_status": "malformed" if status == "collected" else status}
        output.append(current)
    return output


def _cloudfront_log_deliveries(requests, session, region, items):
    """CloudWatch Logs v2 deliveries whose source resourceArns name the distribution."""
    home = _global_region(region)
    sources = requests.pages(session, "logs", home, "describe_delivery_sources", "deliverySources")
    deliveries = requests.pages(session, "logs", home, "describe_deliveries", "deliveries")
    output = []
    oac_reads = {}
    for item in items:
        item = copy.deepcopy(item)
        config = item.get("Config")
        distribution = config.get("DistributionConfig") if isinstance(config, dict) else None
        origins = distribution.get("Origins") if isinstance(distribution, dict) else None
        origin_items = origins.get("Items") if isinstance(origins, dict) else None
        ids = {origin.get("OriginAccessControlId") for origin in origin_items or []
               if isinstance(origin, dict) and isinstance(origin.get("OriginAccessControlId"), str)
               and origin.get("OriginAccessControlId")}
        item["OriginAccessControls"] = {}
        for oac_id in sorted(ids):
            if oac_id not in oac_reads:
                read = requests.detail(session, "cloudfront", home, "get_origin_access_control",
                                       Id=oac_id, absent=("NoSuchOriginAccessControl",))
                control = read.get("OriginAccessControl") if isinstance(read, dict) else None
                settings = control.get("OriginAccessControlConfig") if isinstance(control, dict) else None
                if read.get("collection_status") == "collected" and isinstance(settings, dict) and control.get("Id") == oac_id:
                    oac_reads[oac_id] = {"collection_status": "collected", "Id": oac_id,
                                         "SigningBehavior": settings.get("SigningBehavior"),
                                         "SigningProtocol": settings.get("SigningProtocol"),
                                         "OriginAccessControlOriginType": settings.get("OriginAccessControlOriginType")}
                else:
                    oac_reads[oac_id] = {"collection_status": "malformed" if read.get("collection_status") == "collected" else read.get("collection_status"),
                                         "error": read.get("error", {})}
            item["OriginAccessControls"][oac_id] = oac_reads[oac_id]
        failed = next((read for read in (sources, deliveries) if not _usable(read)), None)
        if failed:
            item["LogDeliveries"] = {"collection_status": failed.status, "error": failed.error or {}}
        else:
            names = {s.get("name") for s in sources.items if isinstance(s, dict) and item.get("ARN") in (s.get("resourceArns") or [])}
            rows = [_pick(d, ("id", "deliverySourceName", "deliveryDestinationArn", "deliveryDestinationType"))
                    for d in deliveries.items if isinstance(d, dict) and d.get("deliverySourceName") in names]
            item["LogDeliveries"] = {"collection_status": "collected", "deliveries": rows}
        output.append(item)
    return output


# ---- WAF ---------------------------------------------------------------

def _resource_arns(requests, session, region, service, types, **arguments):
    arns, by_type = [], {}
    for resource_type in types:
        response = requests.detail(session, service, region, "list_resources_for_web_acl", ResourceType=resource_type, absent=_WAF_ABSENT + _UNSUPPORTED_TYPE, **arguments)
        state = response.get("collection_status")
        if state == "collected" and isinstance(response.get("ResourceArns"), list):
            arns.extend(a for a in response["ResourceArns"] if a not in arns)
            by_type[resource_type] = "collected"
        elif response.get("absent") and (response.get("error") or {}).get("code") in _UNSUPPORTED_TYPE:
            by_type[resource_type] = "not_applicable"
        else:
            return {"collection_status": "malformed" if state == "collected" else state, "error": response.get("error", {}), "ByResourceType": by_type}
    return {"collection_status": "collected", "ResourceArns": arns, "ByResourceType": by_type}


def _cloudfront_acl_resources(requests, session, region, acl_arn):
    read = requests.pages(session, "cloudfront", region, "list_distributions_by_web_acl_id", "DistributionList.Items || `[]`",
                          _tokens=("Marker", "DistributionList.NextMarker"), WebACLId=acl_arn)
    if not _usable(read):
        return {"collection_status": read.status, "error": read.error or {}}
    return {"collection_status": "collected", "ResourceArns": [d["ARN"] for d in read.items if isinstance(d, dict) and isinstance(d.get("ARN"), str)]}


def _detail_member(requests, session, region, service, operation, member, *, expected_identity=None, **arguments):
    response = requests.detail(session, service, region, operation, **arguments)
    if response.get("collection_status") == "collected" and isinstance(response.get(member), dict):
        body = response[member]
        if expected_identity and any(body.get(key) != value for key, value in expected_identity.items()):
            return {"collection_status": "malformed", "error": {"code": "detail_identity_mismatch"}}
        return _strip(body)
    return {"collection_status": response.get("collection_status"), "error": response.get("error", {})}


def _wafv2(kind):
    list_operation, expression = SPECS[kind][1:]

    def fetch(requests, session, region, account):
        # CLOUDFRONT-scope resources are only served from us-east-1.
        scopes = ["REGIONAL"] + (["CLOUDFRONT"] if region == "us-east-1" else [])
        rows = []
        for scope in scopes:
            read = requests.pages(session, "wafv2", region, list_operation, expression, _tokens=("NextMarker", "NextMarker"), Scope=scope, Limit=100)
            if not _usable(read):
                return _fail(read, rows)
            for summary in read.items:
                row = {**_strip(summary), "Scope": scope}
                ids = {"Name": summary["Name"], "Scope": scope, "Id": summary["Id"]}
                if kind == "wafv2_web_acl":
                    row["WebACL"] = _detail_member(requests, session, region, "wafv2", "get_web_acl", "WebACL", expected_identity={"ARN": summary["ARN"], "Id": summary["Id"], "Name": summary["Name"]}, **ids)
                    row["LoggingConfiguration"] = requests.detail(session, "wafv2", region, "get_logging_configuration", ResourceArn=summary["ARN"], absent=_WAF_ABSENT)
                    row["ResourceArns"] = (_cloudfront_acl_resources(requests, session, region, summary["ARN"]) if scope == "CLOUDFRONT"
                                           else _resource_arns(requests, session, region, "wafv2", _WAFV2_RESOURCE_TYPES, WebACLArn=summary["ARN"]))
                else:
                    row["RuleGroup"] = _detail_member(requests, session, region, "wafv2", "get_rule_group", "RuleGroup", **ids)
                rows.append(row)
        return _result(rows, "collected" if rows else "empty")
    return fetch


def _waf_classic(kind, service):
    list_operation, expression = SPECS[kind][1:]

    def fetch(requests, session, region, account):
        if service == "waf":
            region = _global_region(region)
            if region != "us-east-1":
                return _result([], "not_collected", {"code": "unsupported_partition_service"})
        read = requests.pages(session, service, region, list_operation, expression, _tokens=("NextMarker", "NextMarker"), Limit=100)
        if not _usable(read):
            return read
        rows = []
        for summary in read.items:
            row = _strip(summary)
            if kind.endswith("_web_acl"):
                row["WebACL"] = _detail_member(requests, session, region, service, "get_web_acl", "WebACL", WebACLId=summary["WebACLId"])
                arn = row["WebACL"].get("WebACLArn")
                row["LoggingConfiguration"] = (requests.detail(session, service, region, "get_logging_configuration", ResourceArn=arn, absent=_WAF_ABSENT) if isinstance(arn, str)
                                               else {"collection_status": "not_collected", "error": {"code": "web_acl_arn_unavailable"}})
                if service == "waf-regional":
                    row["ResourceArns"] = _resource_arns(requests, session, region, service, _WAFREGIONAL_RESOURCE_TYPES, WebACLId=summary["WebACLId"])
            elif kind.endswith("_rule_group"):
                activated = requests.pages(session, service, region, "list_activated_rules_in_rule_group", "ActivatedRules",
                                           _tokens=("NextMarker", "NextMarker"), RuleGroupId=summary["RuleGroupId"], Limit=100)
                row["ActivatedRules"] = ({"collection_status": "collected", "ActivatedRules": _metadata(activated.items)} if _usable(activated)
                                         else {"collection_status": activated.status, "error": activated.error or {}})
            else:
                row["Rule"] = _detail_member(requests, session, region, service, "get_rule", "Rule", RuleId=summary["RuleId"])
            rows.append(row)
        return _result(rows, "collected" if rows else "empty")
    return fetch


FETCHERS = {
    "ecs_service": _ecs_service, "ecs_task_set": _ecs_task_set, "ecs_account_setting": _ecs_account_setting,
    "elastic_beanstalk_environment": _beanstalk_environments,
    "directconnect_connection": _directconnect("describe_connections", "connections"),
    "directconnect_virtual_interface": _directconnect("describe_virtual_interfaces", "virtualInterfaces"),
    "wafv2_web_acl": _wafv2("wafv2_web_acl"), "wafv2_rule_group": _wafv2("wafv2_rule_group"),
    "waf_web_acl": _waf_classic("waf_web_acl", "waf"), "waf_rule": _waf_classic("waf_rule", "waf"), "waf_rule_group": _waf_classic("waf_rule_group", "waf"),
    "wafregional_web_acl": _waf_classic("wafregional_web_acl", "waf-regional"), "wafregional_rule": _waf_classic("wafregional_rule", "waf-regional"),
    "wafregional_rule_group": _waf_classic("wafregional_rule_group", "waf-regional"),
}

ENRICHERS = {
    "launch_configuration": _launch_configurations,
    "appstream_fleet": _appstream_fleets,
    "appstream_image": _appstream_images,
    "appstream_app_block": _appstream_app_blocks,
    "elastic_beanstalk_environment": _beanstalk_configuration,
    "lambda_function": _lambda_variable_count,
    "ecs_task_definition": _ecs_environment_names,
    "eks_cluster": _eks_vpc_cni,
    "ec2_image": _image_launch_permissions,
    "rds_cluster_snapshot": _cluster_snapshot_attributes,
    "rest_api": _rest_api,
    "apigateway_domain_name": _api_domain_mappings,
    "apigatewayv2_domain_name": _http_api_domain_mappings,
    "http_api": _http_api,
    "appsync_graphql_api": _appsync_cache,
    "managed_prefix_list": _prefix_list_entries,
    "load_balancer": _load_balancer_rules,
    "classic_load_balancer": _classic_instance_health,
    "target_group": _target_group_attributes,
    "cloudfront_distribution": _cloudfront_log_deliveries,
}
