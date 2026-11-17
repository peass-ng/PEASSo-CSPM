"""Compliance waves 05–07: read-only metadata on the shared AWS scheduler."""
from __future__ import annotations

import copy
import re

from .aws_facts_data_identity import _pick, _list, _detail

SPECS = {
    "eventbridge_rule": ("events", "list_rules", "Rules"),
    "event_rule": ("events", "list_rules", "Rules"),
    "detective_graph": ("detective", "list_graphs", "GraphList"),
    "dhcp_options": ("ec2", "describe_dhcp_options", "DhcpOptions"),
    "shield_drt_access": ("shield", "describe_drt_access", None),
    "vpc_peering_connection": ("ec2", "describe_vpc_peering_connections", "VpcPeeringConnections"),
    "load_balancer_v2": ("elbv2", "describe_load_balancers", "LoadBalancers"),
    "ecr_public_repository": ("ecr-public", "describe_repositories", "repositories"),
    "cognito_user_pool_client": ("cognito-idp", "list_user_pool_clients", "UserPoolClients"),
    "client_vpn_endpoint": ("ec2", "describe_client_vpn_endpoints", "ClientVpnEndpoints"),
    "lightsail_bucket": ("lightsail", "get_buckets", "buckets"),
    "batch_job_definition": ("batch", "describe_job_definitions", "jobDefinitions"),
    "kms_external_key_store": ("kms", "describe_custom_key_stores", "CustomKeyStores"),
    "ami": ("ec2", "describe_images", "Images"),
    "signer_profile": ("signer", "list_signing_profiles", "profiles"),
}
NATIVE_IDS = {
    "eventbridge_rule": "Arn",
    "event_rule": "Arn",
    "detective_graph": "Arn", "dhcp_options": "DhcpOptionsId", "shield_drt_access": "id",
    "vpc_peering_connection": "VpcPeeringConnectionId", "load_balancer_v2": "LoadBalancerArn",
    "ecr_public_repository": "repositoryArn", "cognito_user_pool_client": "id",
    "client_vpn_endpoint": "ClientVpnEndpointId", "lightsail_bucket": "arn",
    "batch_job_definition": "jobDefinitionArn", "kms_external_key_store": "CustomKeyStoreId", "ami": "ImageId",
    "signer_profile": "profileVersionArn",
}
READ_ACTIONS = {
    ("events", "list_event_buses"), ("events", "list_targets_by_rule"),
    ("ssm", "list_inventory_entries"), ("ssm", "list_compliance_items"),
    ("cognito-idp", "list_user_pools"), ("cognito-idp", "describe_user_pool_client"),
    ("elbv2", "describe_listeners"), ("elbv2", "describe_rules"), ("codepipeline", "get_pipeline"),
    ("apigateway", "get_client_certificate"), ("shield", "describe_protection"),
    ("route53", "get_health_check"), ("kafka", "describe_cluster_v2"),
    ("lambda", "get_function_code_signing_config"), ("lambda", "get_code_signing_config"),
    ("ec2", "describe_client_vpn_authorization_rules"), ("route53", "get_dnssec"),
    ("securityhub", "get_findings"), ("kms", "list_resource_tags"),
    ("lightsail", "get_bucket_access_keys"), ("backup", "get_backup_vault_notifications"),
    ("ec2", "describe_image_attribute"),
}
_OK = {"collected", "empty"}
GLOBAL_TYPES = {"shield_drt_access"}


def _each(fn):
    def enrich(requests, session, region, items):
        return [fn(requests, session, region, copy.deepcopy(item)) for item in items]
    return enrich


def _provenance(item, operation):
    item.setdefault("_provenance", {}).update(source_operation=operation, read_only=True)
    return item


def _fetch(service, operation, expression, tokens=None, **arguments):
    def fetch(requests, session, region, account):
        return requests.pages(session, service, region, operation, expression, _tokens=tokens, **arguments)
    return fetch


def _signer_profiles(requests, session, region, account):
    """Retain active and canceled profile-version identity without signing material."""
    from .aws import ReadResult
    read = requests.pages(session, "signer", region, "list_signing_profiles", "profiles", includeCanceled=True)
    rows = []
    for item in read.items:
        if not isinstance(item, dict) or not all(isinstance(item.get(key), str) and item[key]
            for key in ("profileName", "profileVersion", "profileVersionArn", "arn", "status")):
            return ReadResult(rows, "partial" if rows else "malformed", {"code": "signer_profile_identity_invalid"})
        rows.append(_pick(item, ("profileName", "profileVersion", "profileVersionArn", "arn", "platformId", "status")))
    return ReadResult(rows, read.status, read.error)


def _rules(requests, session, region, account):
    from .aws import ReadResult
    buses = requests.pages(session, "events", region, "list_event_buses", "EventBuses", _tokens=("NextToken", "NextToken"))
    if buses.status not in _OK:
        return ReadResult([], buses.status, buses.error)
    rows, failures = [], []
    # The default bus is present in ListEventBuses; do not read it twice.
    for bus in buses.items:
        name = bus.get("Name") if isinstance(bus, dict) else None
        if not name:
            failures.append(ReadResult([], "malformed", {"code": "missing_event_bus_name"}))
            continue
        read = requests.pages(session, "events", region, "list_rules", "Rules", _tokens=("NextToken", "NextToken"), EventBusName=name)
        if read.status not in _OK:
            failures.append(read)
        for rule in read.items:
            if isinstance(rule, dict):
                rows.append({**rule, "EventBusName": name})
            else:
                failures.append(ReadResult([], "malformed", {"code": "malformed_eventbridge_rule"}))
    return ReadResult(rows, "partial" if rows and failures else failures[0].status if failures else "collected" if rows else "empty", failures[0].error if failures else None)


def _native_schedule_shape(value):
    # ListRules is authoritative for the rule; this only rejects malformed
    # responses/fixtures, rather than interpreting when a cron will fire.
    if not isinstance(value, str) or not value or len(value) > 256 or value != value.strip():
        return False
    rate = re.fullmatch(r"rate\(([1-9][0-9]*) (minute|minutes|hour|hours|day|days)\)", value)
    if rate:
        return (int(rate.group(1)) == 1) == (not rate.group(2).endswith("s"))
    cron = re.fullmatch(r"cron\(([^()]*)\)", value)
    return bool(cron and len(cron.group(1).split()) == 6 and all(
        re.fullmatch(r"[A-Za-z0-9*?,/#LW-]+", part) for part in cron.group(1).split()))


def _default_rules(requests, session, region, account):
    from .aws import ReadResult
    read = requests.pages(session, "events", region, "list_rules", "Rules", _tokens=("NextToken", "NextToken"), EventBusName="default")
    rows = []
    for raw in read.items:
        if not isinstance(raw, dict):
            continue
        row = {**raw, "EventBusName": "default"}
        if (read.status == "collected" and "EventPattern" not in raw and "ManagedBy" not in raw
                and _native_schedule_shape(raw.get("ScheduleExpression"))
                and isinstance(raw.get("Name"), str) and raw["Name"]
                and isinstance(raw.get("Arn"), str) and raw["Arn"]):
            row["_coverage"] = {"EventPattern": {"status": "empty", "source_operation": "events:ListRules",
                                                  "rule_arn": raw["Arn"], "rule_name": raw["Name"],
                                                  "schedule_expression": raw["ScheduleExpression"],
                                                  "event_bus_name": "default"}}
        rows.append(row)
    if len(rows) != len(read.items):
        return ReadResult(rows, "partial" if rows else "malformed", {"code": "malformed_eventbridge_rule"})
    return ReadResult(rows, read.status, read.error)


def _shield_drt(requests, session, region, account):
    from .aws import ReadResult
    from .aws_facts_cb_ca import _home
    response = requests.detail(session, "shield", _home(region, "us-east-1"), "describe_drt_access")
    if response.get("collection_status") != "collected":
        return ReadResult([], response.get("collection_status", "malformed"), response.get("error"))
    role, buckets = response.get("RoleArn") or "", response.get("LogBucketList", [])
    if not isinstance(role, str) or not isinstance(buckets, list) or any(not isinstance(value, str) for value in buckets):
        return ReadResult([], "malformed", {"code": "malformed_drt_access"})
    return ReadResult([{"id": account, "RoleArn": role, "LogBucketList": buckets, "_provenance": {"source_operation": "shield:DescribeDRTAccess", "read_only": True}}])


def _application_inventory(requests, session, region, instance):
    from .aws import ReadResult
    rows, token, seen = [], None, set()
    page = 0
    while True:
        if requests.max_pages is not None and page >= requests.max_pages:
            return ReadResult(rows, "partial" if rows else "not_collected", {"code": "page_limit"})
        page += 1
        args = {"InstanceId": instance, "TypeName": "AWS:Application"}
        if token:
            args["NextToken"] = token
        response = requests.detail(session, "ssm", region, "list_inventory_entries", **args)
        if response.get("collection_status") != "collected":
            return ReadResult(rows, "partial" if rows else response.get("collection_status", "malformed"), response.get("error"))
        entries, capture = response.get("Entries"), response.get("CaptureTime")
        if not isinstance(entries, list) or (capture is not None and not isinstance(capture, str)):
            return ReadResult(rows, "partial" if rows else "malformed", {"code": "malformed_application_inventory"})
        for entry in entries:
            if not isinstance(entry, dict):
                return ReadResult(rows, "partial" if rows else "malformed", {"code": "malformed_application_entry"})
            row = _pick(entry, ["Name", "Version"])
            if capture:
                row["CaptureTime"] = capture
            rows.append(row)
            if requests.max_items is not None and len(rows) > requests.max_items:
                return ReadResult(rows[:requests.max_items], "partial" if requests.max_items else "not_collected", {"code": "resource_limit"})
        following = response.get("NextToken")
        if not following:
            return ReadResult(rows, "collected" if rows else "empty")
        if not isinstance(following, str) or following in seen:
            return ReadResult(rows, "partial" if rows else "malformed", {"code": "malformed_application_next_token"})
        seen.add(following)
        token = following


@_each
def _event_rule(requests, session, region, item):
    name, bus = item.get("Name"), item.get("EventBusName")
    if not name or not bus:
        item["Targets"] = {"collection_status": "malformed", "items": [], "error": {"code": "missing_rule_identity"}}
        return item
    read = requests.pages(session, "events", region, "list_targets_by_rule", "Targets", _tokens=("NextToken", "NextToken"), Rule=name, EventBusName=bus)
    item["Targets"] = _list(read, ["Id", "Arn", "DeadLetterConfig"])
    return _provenance(item, "events:ListRules")


@_each
def _ssm_inventory(requests, session, region, item):
    instance = item.get("InstanceId")
    if not instance:
        return item
    apps = _application_inventory(requests, session, region, instance)
    item["ApplicationInventory"] = {"collection_status": apps.status, "source_operation": "ssm:ListInventoryEntries", "InstanceId": instance, "TypeName": "AWS:Application", "Entries": apps.items}
    if apps.error:
        item["ApplicationInventory"]["error"] = apps.error
    for field, typ in (("AssociationCompliance", "Association"), ("TimeSyncCompliance", "Custom:TimeSync"), ("MalwareDefinitionsCompliance", "Custom:MalwareDefinitions")):
        read = requests.pages(session, "ssm", region, "list_compliance_items", "ComplianceItems", _tokens=("NextToken", "NextToken"), ResourceIds=[instance], ResourceTypes=["ManagedInstance"], Filters=[{"Key": "ComplianceType", "Values": [typ], "Type": "EQUAL"}])
        rows = []
        for row in read.items:
            selected = _pick(row, ["ResourceId", "ComplianceType", "Id", "Status", ("ExecutionSummary", ["ExecutionTime"]), ("Details", ["offsetMilliseconds", "definitionVersion"])])
            rows.append(selected)
        fact = {"collection_status": read.status, "source_operation": "ssm:ListComplianceItems"}
        if typ == "Association":
            fact["items"] = rows
        else:
            fact.update(ComplianceType=typ, ComplianceItems=rows)
        if read.error:
            fact["error"] = read.error
        item[field] = fact
    return _provenance(item, "ssm:DescribeInstanceInformation")


def _public_ecr(requests, session, region, account):
    # ECR Public has one endpoint; publish only in its actual regional scope.
    from .aws import ReadResult
    if region != "us-east-1":
        return ReadResult([], "not_collected", {"code": "ecr_public_requires_us_east_1_scope"})
    return requests.pages(session, "ecr-public", region, "describe_repositories", "repositories")


def _clients(requests, session, region, account):
    from .aws import ReadResult
    pools = requests.pages(session, "cognito-idp", region, "list_user_pools", "UserPools", MaxResults=60)
    items, failures = [], []
    if pools.status not in _OK:
        failures.append(pools)
    for pool in pools.items:
        read = requests.pages(session, "cognito-idp", region, "list_user_pool_clients", "UserPoolClients", UserPoolId=pool["Id"], MaxResults=60)
        if read.status not in _OK:
            failures.append(read)
        for client in read.items:
            items.append({**client, "UserPoolId": pool["Id"], "id": pool["Id"] + "/" + client["ClientId"]})
    if failures:
        return ReadResult(items, "partial" if items else failures[0].status, failures[0].error)
    return ReadResult(items, "collected" if items else "empty")


def _batch(requests, session, region, account):
    from .aws import ReadResult
    items, failures = [], []
    for status in ("ACTIVE", "INACTIVE"):
        read = requests.pages(session, "batch", region, "describe_job_definitions", "jobDefinitions", status=status)
        items.extend(read.items)
        if read.status not in _OK:
            failures.append(read)
    return ReadResult(items, "partial" if items and failures else failures[0].status if failures else "collected" if items else "empty", failures[0].error if failures else None)


@_each
def _peering(requests, session, region, item):
    return _provenance(item, "describe_vpc_peering_connections")


_ACTION_KEYS = ["Type", "Order", ("RedirectConfig", ["Protocol"])]


@_each
def _lb(requests, session, region, item):
    read = requests.pages(session, "elbv2", region, "describe_listeners", "Listeners", LoadBalancerArn=item["LoadBalancerArn"])
    listeners = _list(read, ["ListenerArn", "Protocol", "Port", ("Certificates", ["CertificateArn"]), ("DefaultActions", _ACTION_KEYS)])
    if read.status in _OK:
        for listener in listeners["items"]:
            # DescribeListeners omits Certificates when none are attached.
            listener.setdefault("Certificates", [])
            # ALB HTTP listeners that only redirect to HTTPS serve no plaintext content (Security Hub ELB.1);
            # the same cached DescribeRules read the load_balancer collector issues proves every rule redirects.
            if item.get("Type") == "application" and listener.get("Protocol") == "HTTP" and isinstance(listener.get("ListenerArn"), str):
                rules = requests.pages(session, "elbv2", region, "describe_rules", "Rules", ListenerArn=listener["ListenerArn"])
                listener["Rules"] = _list(rules, ["RuleArn", "IsDefault", ("Actions", _ACTION_KEYS)])
    item["Listeners"] = listeners
    return _provenance(item, "describe_load_balancers")


@_each
def _client(requests, session, region, item):
    item["ClientDetail"] = _detail(requests, session, region, "cognito-idp", "describe_user_pool_client",
        UserPoolId=item["UserPoolId"], ClientId=item["ClientId"],
        keys=[("UserPoolClient", ["UserPoolId", "ClientId", "AccessTokenValidity", "IdTokenValidity", "RefreshTokenValidity", "TokenValidityUnits", "ExplicitAuthFlows", "AllowedOAuthScopes", "SupportedIdentityProviders", "ClientSecretPresent", "RefreshTokenRotation"])])
    # Documented Cognito defaults for omitted units; missing lifetimes stay UNKNOWN.
    detail = item["ClientDetail"]
    client = detail.get("UserPoolClient")
    if detail.get("collection_status") == "collected" and isinstance(client, dict):
        units = client.setdefault("TokenValidityUnits", {})
        if isinstance(units, dict):
            for token, unit in (("AccessToken", "hours"), ("IdToken", "hours"), ("RefreshToken", "days")):
                units.setdefault(token, unit)
    return _provenance(item, "list_user_pool_clients")


@_each
def _pipeline(requests, session, region, item):
    item["Pipeline"] = _detail(requests, session, region, "codepipeline", "get_pipeline", name=item["name"],
        keys=[("pipeline", ["name", ("stages", [("actions", [("actionTypeId", ["category"])])])])])
    return item


@_each
def _stage(requests, session, region, item):
    item.setdefault("clientCertificateId", "")
    certificate = item["clientCertificateId"]
    if certificate:
        detail = _detail(requests, session, region, "apigateway", "get_client_certificate", clientCertificateId=certificate,
            absent=("NotFoundException",), keys=["clientCertificateId", "expirationDate"])
        if detail.get("collection_status") != "collected":
            detail["clientCertificateId"] = certificate
        item["ClientCertificate"] = detail
    return item


@_each
def _shield(requests, session, region, item):
    from .aws_facts_cb_ca import _home
    home = _home(region, "us-east-1")
    arn = item.get("ResourceArn", "")
    if ":cloudfront:" in arn or ":loadbalancer/app/" in arn:
        response = _detail(requests, session, home, "shield", "describe_protection", ProtectionId=item["Id"],
            keys=[("Protection", ["Id", "ApplicationLayerAutomaticResponseConfiguration"])])
        protection = response.get("Protection", {})
        if "ApplicationLayerAutomaticResponseConfiguration" in protection:
            protection["ApplicationLayerAutomaticResponse"] = protection.pop("ApplicationLayerAutomaticResponseConfiguration")
        item["Protection"] = {**protection, **{k: v for k, v in response.items() if k != "Protection"}}
    # ListProtections documents the omitted optional list as no associated checks.
    if item.get("HealthCheckIds") is None:
        item["HealthCheckIds"] = []
    item["HealthChecks"] = []
    for health_id in item["HealthCheckIds"]:
        response = _detail(requests, session, home, "route53", "get_health_check", HealthCheckId=health_id,
            absent=("NoSuchHealthCheck",), keys=[("HealthCheck", ["Id"])])
        item["HealthChecks"].append({"Id": health_id, **response})
    return item


@_each
def _msk(requests, session, region, item):
    if item.get("ClusterType") == "PROVISIONED":
        item["Detail"] = _detail(requests, session, region, "kafka", "describe_cluster_v2", ClusterArn=item["ClusterArn"],
            keys=[("ClusterInfo", ["ClusterArn", ("Provisioned", [("EncryptionInfo", [("EncryptionInTransit", ["InCluster"])])])])])
    return item


@_each
def _vpn(requests, session, region, item):
    endpoint = item["ClientVpnEndpointId"]
    read = requests.pages(session, "ec2", region, "describe_client_vpn_authorization_rules", "AuthorizationRules", ClientVpnEndpointId=endpoint)
    item["AuthorizationRules"] = {"ClientVpnEndpointId": endpoint, **_list(read, ["Status", "AuthorizeAllGroups", "DestinationCidr"])}
    return _provenance(item, "describe_client_vpn_endpoints")


@_each
def _lambda(requests, session, region, item):
    requested_name = item["FunctionName"]
    signing = _detail(requests, session, region, "lambda", "get_function_code_signing_config", FunctionName=requested_name, keys=["FunctionName", "FunctionArn", "CodeSigningConfigArn"])
    if signing.get("collection_status") == "collected":
        # Bind an omitted response identity to the exact successful read request.
        # This records request provenance, not a claimed response field.
        signing["_request"] = {"operation": "get_function_code_signing_config", "FunctionName": requested_name}
        # Successful read with no attachment omits this optional field.
        signing.setdefault("CodeSigningConfigArn", "")
        arn = signing.get("CodeSigningConfigArn")
        if arn:
            item["CodeSigningConfig"] = _detail(requests, session, region, "lambda", "get_code_signing_config", CodeSigningConfigArn=arn,
                keys=[("CodeSigningConfig", ["CodeSigningConfigArn", "AllowedPublishers", "CodeSigningPolicies"])])
    item["CodeSigning"] = signing
    return item


@_each
def _lightsail(requests, session, region, item):
    item = _pick(item, ["name", "arn", "accessRules", "accessLogConfig", "resourcesReceivingAccess"])
    # AWS returns resource records; evaluator requires their ARN strings.
    resources = item.get("resourcesReceivingAccess")
    if isinstance(resources, list):
        item["resourcesReceivingAccess"] = [r.get("arn") if isinstance(r, dict) else r for r in resources]
    elif resources is None:
        item["resourcesReceivingAccess"] = []
    if "accessLogConfig" not in item:
        item.setdefault("_coverage", {})["accessLogConfig"] = {"status": "not_collected", "reason": "missing_access_log_config"}
    keys = requests.pages(session, "lightsail", region, "get_bucket_access_keys", "accessKeys", _tokens=("pageToken", "nextPageToken"), bucketName=item["name"])
    item["AccessKeys"] = _list(keys, ["accessKeyId", "status", "createdAt", "lastUsed"])
    return _provenance(item, "get_buckets")


@_each
def _dnssec(requests, session, region, item):
    if item.get("Config", {}).get("PrivateZone") is False:
        item["DNSSEC"] = {"HostedZoneId": item["Id"], **_detail(requests, session, region, "route53", "get_dnssec", HostedZoneId=item["Id"], keys=["Status", ("KeySigningKeys", ["Status"])])}
    return item


@_each
def _critical(requests, session, region, item):
    account = item["HubArn"].split(":")[4]
    regions = getattr(requests, "audited_regions_by_account", {}).get(account, [region])
    rows, covered, failures = [], [], []
    for audited in regions:
        read = requests.pages(session, "securityhub", audited, "get_findings", "Findings",
            Filters={"SeverityLabel": [{"Value": "CRITICAL", "Comparison": "EQUALS"}], "RecordState": [{"Value": "ACTIVE", "Comparison": "EQUALS"}]})
        rows.extend(_list(read, ["Id", "Region", "Severity", "RecordState", "Workflow"])["items"])
        if read.status in _OK:
            covered.append(audited)
        else:
            failures.append(read)
    item["CriticalFindings"] = {"items": rows, "covered_regions": covered,
        "collection_status": "partial" if failures and rows else failures[0].status if failures else "collected" if rows else "empty"}
    if failures:
        item["CriticalFindings"]["error"] = failures[0].error
    return item


@_each
def _kms_tags(requests, session, region, item):
    read = requests.pages(session, "kms", region, "list_resource_tags", "Tags", KeyId=item["KeyId"])
    if read.status in _OK:
        item["Tags"] = _list(read, ["TagKey", "TagValue"])["items"]
    else:
        item.pop("Tags", None)
    item.setdefault("_coverage", {})["Tags"] = {"status": read.status, "source_operation": "kms:ListResourceTags"}
    return item


@_each
def _notifications(requests, session, region, item):
    item["Notifications"] = _detail(requests, session, region, "backup", "get_backup_vault_notifications", BackupVaultName=item["BackupVaultName"],
        absent=("ResourceNotFoundException",), keys=["SNSTopicArn", "BackupVaultEvents"])
    return item


_LOG = [("logConfiguration", ["logDriver", ("options", ["awslogs-group"])])]


@_each
def _job(requests, session, region, item):
    return _provenance(_pick(item, ["jobDefinitionArn", "jobDefinitionName", "revision", "status", "type",
        "platformCapabilities", "AdditionalSecretIndicators",
        ("containerProperties", ["jobRoleArn", "image", *_LOG]),
        ("nodeProperties", [("nodeRangeProperties", [("container", _LOG)])]),
        ("ecsProperties", [("taskProperties", [("containers", _LOG)])])]), "describe_job_definitions")


@_each
def _store(requests, session, region, item):
    proxy = item.get("XksProxyConfiguration")
    if isinstance(proxy, dict) and "Connectivity" in proxy:
        item["XksProxyConnectivity"] = proxy["Connectivity"]
    return _provenance(_pick(item, ["CustomKeyStoreId", "CustomKeyStoreName", "CustomKeyStoreType", "ConnectionState", "XksProxyConnectivity"]), "describe_custom_key_stores")


@_each
def _ami(requests, session, region, item):
    response = _detail(requests, session, region, "ec2", "describe_image_attribute", ImageId=item["ImageId"], Attribute="launchPermission", keys=["ImageId", "LaunchPermissions"])
    if response.get("collection_status") == "collected" and response.get("ImageId") == item["ImageId"]:
        permissions = response.get("LaunchPermissions", [])
        selectors = {"UserId", "OrganizationArn", "OrganizationalUnitArn", "Group"}
        if isinstance(permissions, list) and all(isinstance(p, dict) and len(set(p) & selectors) == 1 and set(p) <= selectors for p in permissions):
            item["LaunchPermissions"] = {"collection_status": "collected" if permissions else "empty", "items": permissions}
        else:
            item["LaunchPermissions"] = {"collection_status": "malformed"}
    else:
        item["LaunchPermissions"] = {**response, "collection_status": "malformed" if response.get("collection_status") == "collected" else response.get("collection_status")}
    return _provenance(item, "describe_images")


FETCHERS = {
    "signer_profile": _signer_profiles,
    "ecr_public_repository": _public_ecr,
    "cognito_user_pool_client": _clients,
    "lightsail_bucket": _fetch("lightsail", "get_buckets", "buckets", ("pageToken", "nextPageToken")),
    "batch_job_definition": _batch,
    "kms_external_key_store": _fetch("kms", "describe_custom_key_stores", "CustomKeyStores", ("Marker", "NextMarker")),
    # Identical arguments to ec2_image: all aliases share cached API pages.
    "ami": _fetch("ec2", "describe_images", "Images", Owners=["self"], IncludeDeprecated=True, IncludeDisabled=True),
}
ENRICHERS = {
    "eventbridge_rule": _event_rule, "event_rule": _event_rule, "ssm_managed_instance": _ssm_inventory,
    "vpc_peering_connection": _peering, "load_balancer_v2": _lb,
    "cognito_user_pool_client": _client, "codepipeline_pipeline": _pipeline,
    "rest_api_stage": _stage, "shield_protection": _shield, "msk_cluster": _msk,
    "client_vpn_endpoint": _vpn, "lambda_function": _lambda, "lightsail_bucket": _lightsail,
    "route53_zone": _dnssec, "securityhub_hub": _critical, "kms_key": _kms_tags,
    "backup_vault": _notifications, "batch_job_definition": _job,
    "kms_external_key_store": _store, "ami": _ami,
}

FETCHERS["eventbridge_rule"] = _rules
FETCHERS["event_rule"] = _default_rules
FETCHERS["shield_drt_access"] = _shield_drt


def project_access_keys(response):
    """Discard credential values before the shared request cache sees them."""
    from .aws import ReadFailure
    if not isinstance(response, dict) or not isinstance(response.get("accessKeys"), list):
        raise ReadFailure("malformed", "malformed_bucket_access_keys")
    return _pick(response, [("accessKeys", ["accessKeyId", "status", "createdAt", "lastUsed"]), "nextPageToken"])
