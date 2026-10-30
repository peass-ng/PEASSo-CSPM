"""Read-only Azure compliance inventory enrichments using the shared reader."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import re
from urllib.parse import urlsplit

ARM = "https://management.azure.com"
MG = "/providers/Microsoft.Management/managementGroups/"


def authorized_storage_service_scopes(snapshot, scope):
    """Expose exact native default-service reads through verified account GETs.

    An observed full account remains a configuration subject when another account
    page fails. This does not attest the unobserved subscription inventory.
    """
    if not isinstance(scope, str) or re.fullmatch(r'/subscriptions/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', scope, re.I) is None:
        return set()
    parents = [c for c in snapshot['collections'] if c['type'] == 'storage_account'
               and c['scope'].casefold() == scope.casefold()]
    if len(parents) != 1 or parents[0]['status'] not in ('collected', 'partial'):
        return set()
    accounts, seen = set(), set()
    pattern = re.escape(scope) + r'/resourceGroups/[^/?#%\\\s]+/providers/Microsoft\.Storage/storageAccounts/[a-z0-9]{3,24}'
    for row in parents[0]['items']:
        rid = row.get('id')
        if (not isinstance(rid, str) or re.fullmatch(pattern, rid, re.I) is None
                or any(part in ('.', '..') for part in rid.split('/')) or rid.casefold() in seen):
            return set()
        seen.add(rid.casefold())
        proof = row.get('_provenance', {})
        if (str(row.get('type', '')).casefold() == 'microsoft.storage/storageaccounts'
                and isinstance(row.get('properties'), dict) and isinstance(proof, dict)
                and proof.get('representation') == 'full' and proof.get('source_operation') == 'get'
                and proof.get('read_only') is True and proof.get('api_version') in ('2023-05-01', '2026-06-01')):
            accounts.add(rid.casefold())
    candidates = [c for c in snapshot['collections'] if c['type'] == 'storage_service']
    counts = {}
    for child in candidates:
        key = child['scope'].casefold()
        counts[key] = counts.get(key, 0) + 1
    allowed = set()
    for child in candidates:
        parent, separator, service = child['scope'].rpartition('/')
        service = service.casefold()
        if (not separator or parent.casefold() not in accounts or counts[child['scope'].casefold()] != 1
                or service not in ('blobservices', 'fileservices', 'queueservices', 'tableservices')):
            continue
        expected = child['scope'].casefold() + '/default'
        rows = child['items']
        if len(rows) > 1 or any(not isinstance(row, dict)
                or str(row.get('id', '')).casefold() != expected
                or str(row.get('type', '')).casefold() != 'microsoft.storage/storageaccounts/' + service
                for row in rows):
            continue
        # Retain denied/partial envelopes so the consumer cannot infer absence.
        allowed.add(child['scope'])
    return allowed


def authorized_subnet_scopes(snapshot, scope):
    """Join native subnet GETs only through the selected VNet's declarations."""
    if not isinstance(scope, str) or re.fullmatch(r'/subscriptions/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', scope, re.I) is None:
        return set()
    parents = [c for c in snapshot['collections'] if c['type'] == 'vnet'
               and c['scope'].casefold() == scope.casefold()]
    if len(parents) != 1 or parents[0]['status'] not in ('collected', 'empty'):
        return set()
    declarations = {}
    pattern = re.escape(scope) + r'/resourceGroups/[^/?#%\\\s]+/providers/Microsoft\.Network/virtualNetworks/[^/?#%\\\s]+'
    def full(row, typ):
        proof = row.get('_provenance', {})
        return (str(row.get('type', '')).casefold() == typ and isinstance(row.get('properties'), dict)
                and isinstance(proof, dict) and proof.get('representation') == 'full'
                and proof.get('source_operation') == 'get' and proof.get('read_only') is True
                and proof.get('api_version') == '2023-09-01')
    for row in parents[0]['items']:
        rid = row.get('id')
        if (not isinstance(rid, str) or re.fullmatch(pattern, rid, re.I) is None
                or any(part in ('.', '..') for part in rid.split('/'))
                or rid.casefold() in declarations or not full(row, 'microsoft.network/virtualnetworks')):
            return set()
        references = row['properties'].get('subnets')
        if not isinstance(references, list):
            return set()
        ids = []
        for reference in references:
            child_id = reference.get('id') if isinstance(reference, dict) else None
            if (not isinstance(child_id, str) or re.fullmatch(re.escape(rid) + r'/subnets/[^/?#%\\\s]+', child_id, re.I) is None
                    or any(part in ('.', '..') for part in child_id.split('/'))):
                return set()
            ids.append(child_id.casefold())
        if len(ids) != len(set(ids)):
            return set()
        declarations[rid.casefold()] = set(ids)
    children = [c for c in snapshot['collections'] if c['type'] == 'subnet']
    counts = {}
    for child in children:
        key = child['scope'].casefold()
        counts[key] = counts.get(key, 0) + 1
    allowed = set()
    for child in children:
        parent = child['scope'].casefold()
        if parent not in declarations or counts[parent] != 1:
            continue
        rows = child['items']
        ids = [row.get('id') for row in rows]
        if (any(not isinstance(rid, str) or rid.casefold() not in declarations[parent]
                or not full(row, 'microsoft.network/virtualnetworks/subnets') for row, rid in zip(rows, ids))
                or len(ids) != len(set(rid.casefold() for rid in ids))):
            continue
        if child['status'] in ('collected', 'empty') and set(rid.casefold() for rid in ids) != declarations[parent]:
            continue
        # Incomplete reads remain in the dependency index, never an empty proof.
        allowed.add(child['scope'])
    return allowed


def authorized_vault_collection_scopes(snapshot, scope):
    """Exact native vault/secret/diagnostic joins, without descendant-scope trust."""
    from peaso.checks.facts import resolve_embedded_fact, Unavailable
    uuid = r'[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}'
    metadata = snapshot.get('metadata', {})
    credential, customer = metadata.get('credential_context_id'), metadata.get('customer_context_id')
    if (not isinstance(credential, str) or not re.fullmatch(r'[0-9a-f]{32}', credential)
            or customer != 'scan-local:' + credential or metadata.get('collection') != 'read-only'):
        return set()
    def captured(value):
        proof = value.get('_provenance', {})
        return isinstance(proof, dict) and proof.get('credential_context_id') == credential and proof.get('customer_context_id') == customer
    selected = {str(s).casefold() for s in snapshot['scopes'] if re.fullmatch('/subscriptions/' + uuid, str(s), re.I)}
    parents = {}
    for collection in snapshot['collections']:
        root = collection['scope']
        if collection['type'] != 'vault' or root.casefold() not in selected or not captured(collection):
            continue
        if sum(c['type'] == 'vault' and c['scope'].casefold() == root.casefold() for c in snapshot['collections']) != 1:
            continue
        seen, valid = set(), True
        for row in collection['items']:
            rid = row.get('id')
            if (not isinstance(rid, str) or not re.fullmatch(re.escape(root) + r'/resourceGroups/[^/?#%]+/providers/Microsoft\.KeyVault/vaults/[A-Za-z0-9-]{3,24}', rid, re.I)
                    or any(p in ('.', '..') or any(ord(c) < 33 for c in p) for p in rid.split('/'))
                    or str(row.get('type', '')).casefold() != 'microsoft.keyvault/vaults'
                    or rid.casefold() in seen or not captured(row) or not isinstance(row.get('properties'), dict)):
                valid = False
                break
            seen.add(rid.casefold())
        if valid:
            for row in collection['items']:
                parents[row['id'].casefold()] = (root, collection, row)
    allowed = set()
    for collection in snapshot['collections']:
        parent = parents.get(collection['scope'].casefold())
        if parent is None or not captured(collection):
            continue
        root, parent_collection, row = parent
        if collection['type'] in ('secret_metadata', 'key_metadata') and scope.casefold() == row['id'].casefold():
            metadata_kind = collection['type']
            component = 'secrets' if metadata_kind == 'secret_metadata' else 'keys'
            if sum(c['type'] == metadata_kind and c['scope'].casefold() == scope.casefold() for c in snapshot['collections']) != 1:
                continue
            valid = True
            for child in collection['items']:
                identity, proof = child.get('id'), child.get('_provenance', {})
                if (not isinstance(identity, str) or not re.fullmatch(re.escape(row['id']) + '/' + component + r'/[A-Za-z0-9-]{1,127}', identity, re.I)
                        or str(child.get('parent_id', '')).casefold() != row['id'].casefold()
                        or str(child.get('type', '')).casefold() != 'microsoft.keyvault/vaults/' + component
                        or not captured(child) or proof.get('endpoint') != component + '/list' or proof.get('read_only') is not True):
                    valid = False
                    break
            if valid:
                allowed.add(('vault', root))
                if metadata_kind == 'key_metadata' and collection['status'] in ('collected', 'empty'):
                    keys = {key['id'].casefold(): key for key in collection['items']}
                    if len(keys) != len(collection['items']):
                        continue
                    for policy_collection in snapshot['collections']:
                        key = keys.get(policy_collection['scope'].casefold())
                        if (policy_collection['type'] != 'key_rotation_policy' or key is None
                                or not captured(policy_collection)):
                            continue
                        valid_policy = True
                        for policy in policy_collection['items']:
                            proof = policy.get('_provenance', {})
                            if (str(policy.get('id', '')).casefold() != (key['id'] + '/rotationpolicy').casefold()
                                    or str(policy.get('parent_id', '')).casefold() != key['id'].casefold()
                                    or str(policy.get('type', '')).casefold() != 'microsoft.keyvault/vaults/keys/rotationpolicy'
                                    or not captured(policy) or proof.get('endpoint') != 'keys/rotationpolicy/get'
                                    or proof.get('read_only') is not True):
                                valid_policy = False
                                break
                        if valid_policy and len(policy_collection['items']) <= 1:
                            allowed.add(('key_rotation_policy', policy_collection['scope']))
        elif collection['type'] == 'diagnostic_setting' and scope.casefold() == root.casefold():
            if parent_collection['status'] not in ('collected', 'empty', 'partial'):
                continue
            if sum(c['type'] == 'diagnostic_setting' and c['scope'].casefold() == row['id'].casefold() for c in snapshot['collections']) != 1:
                continue
            wrappers = [{'native_id': row['id'], 'provider': 'azure', 'type': 'vault', 'data': row}]
            valid = True
            for child in collection['items']:
                try:
                    child = resolve_embedded_fact(child, wrappers, child_status=collection['status'])
                except Unavailable:
                    valid = False
                    break
                identity, proof = child.get('id'), child.get('_provenance', {})
                path = row['id'] + '/providers/Microsoft.Insights/diagnosticSettings'
                if (not isinstance(identity, str) or not re.fullmatch(re.escape(path) + r'/[^/?#%]+', identity, re.I)
                        or str(child.get('type', '')).casefold() != 'microsoft.insights/diagnosticsettings'
                        or str(child.get('parent_id', '')).casefold() != row['id'].casefold()
                        or not captured(child) or proof.get('source_operation') != 'DiagnosticSettings_List'
                        or proof.get('api_version') != '2021-05-01-preview' or proof.get('read_only') is not True
                        or str(proof.get('scope', '')).casefold() != row['id'].casefold()
                        or str(proof.get('request_path', '')).casefold() != path.casefold()):
                    valid = False
                    break
            if valid:
                allowed.add(('diagnostic_setting', collection['scope']))
    return allowed


def authorized_service_diagnostic_scopes(snapshot, scope):
    """Join only captured native Application Gateway/Load Balancer diagnostics."""
    from peaso.checks.facts import resolve_embedded_fact, Unavailable
    uuid = r'[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}'
    if re.fullmatch('/subscriptions/' + uuid, scope, re.I) is None:
        return set()
    if scope.casefold() not in {s.casefold() for s in snapshot['scopes']}:
        return set()
    meta = snapshot.get('metadata', {})
    credential, customer = meta.get('credential_context_id'), meta.get('customer_context_id')
    if (not isinstance(credential, str) or re.fullmatch(r'[0-9a-f]{32}', credential) is None
            or customer != 'scan-local:' + credential or meta.get('collection') != 'read-only'):
        return set()
    def captured(row):
        p = row.get('_provenance', {})
        return isinstance(p, dict) and p.get('credential_context_id') == credential and p.get('customer_context_id') == customer
    kinds = {'application_gateway': 'Microsoft.Network/applicationGateways',
             'load_balancer': 'Microsoft.Network/loadBalancers'}
    parents = {}
    for kind, native_type in kinds.items():
        envelopes = [c for c in snapshot['collections'] if c['type'] == kind and c['scope'].casefold() == scope.casefold()]
        if len(envelopes) != 1 or not captured(envelopes[0]):
            continue
        rows, seen, valid = envelopes[0]['items'], set(), True
        for row in rows:
            rid = row.get('id')
            if (not isinstance(rid, str)
                    or re.fullmatch(re.escape(scope) + r'/resourceGroups/[^/?#%\\\s]+/providers/' + re.escape(native_type) + r'/[^/?#%\\\s]+', rid, re.I) is None
                    or any(p in ('.', '..') for p in rid.split('/'))
                    or rid.casefold() in seen or not captured(row)
                    or str(row.get('type', '')).casefold() != native_type.casefold()
                    or not isinstance(row.get('properties'), dict)):
                valid = False
                break
            seen.add(rid.casefold())
        if valid:
            parents.update({row['id'].casefold(): (kind, row) for row in rows})
    allowed = set()
    for child in snapshot['collections']:
        parent = parents.get(child['scope'].casefold())
        if child['type'] != 'diagnostic_setting' or parent is None or not captured(child):
            continue
        if sum(c['type'] == child['type'] and c['scope'].casefold() == child['scope'].casefold() for c in snapshot['collections']) != 1:
            continue
        kind, row = parent
        expected = row['id'] + '/providers/Microsoft.Insights/diagnosticSettings'
        # Empty native responses still need the actual completed LIST receipt.
        # Denied/partial envelopes retain their status and can never prove
        # absence; they may enter the exact tuple solely to propagate that gap.
        if child['status'] in ('collected', 'empty'):
            proof = child.get('_provenance', {})
            if (proof.get('source_operation') != 'DiagnosticSettings_List'
                    or proof.get('read_only') is not True
                    or proof.get('api_version') != '2021-05-01-preview'
                    or str(proof.get('scope', '')).casefold() != row['id'].casefold()
                    or str(proof.get('request_path', '')).casefold() != expected.casefold()):
                continue
        wrappers = [{'native_id': row['id'], 'provider': 'azure', 'type': kind, 'data': row}]
        expected = row['id'] + '/providers/Microsoft.Insights/diagnosticSettings'
        seen, valid = {}, True
        for raw in child['items']:
            try:
                item = resolve_embedded_fact(raw, wrappers, child_status=child['status'])
            except Unavailable:
                valid = False
                break
            rid, proof = item.get('id'), item.get('_provenance', {})
            if (not isinstance(rid, str) or re.fullmatch(re.escape(expected) + r'/[^/?#%\\\s]+', rid, re.I) is None
                    or not captured(item) or not isinstance(item.get('properties'), dict)
                    or str(item.get('type', '')).casefold() != 'microsoft.insights/diagnosticsettings'
                    or str(item.get('parent_id', '')).casefold() != row['id'].casefold()
                    or proof.get('source_operation') != 'DiagnosticSettings_List' or proof.get('read_only') is not True
                    or proof.get('api_version') != '2021-05-01-preview'
                    or str(proof.get('scope', '')).casefold() != row['id'].casefold()
                    or str(proof.get('request_path', '')).casefold() != expected.casefold()
                    or rid.casefold() in seen and seen[rid.casefold()] != item):
                valid = False
                break
            seen[rid.casefold()] = item
        # Retain denied and partial envelopes: consumers require their real
        # status before absence/cardinality, never a fabricated empty inventory.
        if valid:
            allowed.add(('diagnostic_setting', child['scope']))
    return allowed


def full_detail(value, kind, version):
    """Called only after the native GET identity and properties are verified."""
    value = {**value, "properties": dict(value["properties"]),
             "_provenance": {"representation": "full", "source_operation":
                             "GET" if kind in ("postgresql_single_server", "mariadb_server") else "get",
                             "read_only": True, "api_version": version}}
    if kind == "firewall_policy":
        value["properties"].setdefault("basePolicy", None)
    if kind == "aks_cluster":
        for field in ("fqdn", "privateFQDN"):
            value["properties"].setdefault(field, None)
    if kind == "image_template":
        # Inline customization scripts and download URLs can contain credentials.
        # Only the native build-network declaration is needed for this evaluator.
        value["properties"] = {key: data for key, data in value["properties"].items()
                               if key in ("vmProfile", "provisioningState")}
    if kind == "bot_service" and "cmekKeyVaultUrl" not in value["properties"]:
        value["properties"].setdefault("_coverage", {})["cmekKeyVaultUrl"] = {"status": "empty"}
    if kind == "bot_service":
        value["_provenance"]["source_operation"] = "botServices/get"
    if kind == "databox_job":
        value["_provenance"]["expand"] = "details"
    if kind == "vm":
        value["_provenance"]["expand"] = "instanceView"
    if kind == "purview_account" and isinstance(value.get("location"), str):
        value["location"] = value["location"].lower()
    if kind == "integration_service_environment":
        value['_provenance']['source_operation'] = 'Microsoft.Logic/integrationServiceEnvironments:GET'
    return value


def list_detail(value, kind):
    """Attest alert LISTs; retain action-group configuration as metadata only."""
    if kind == "playwright_workspace":
        props = value.get("properties")
        if (str(value.get("type", "")).casefold() != "microsoft.loadtestservice/playwrightworkspaces"
                or not isinstance(props, dict)):
            raise ValueError("Playwright workspace LIST identity or properties unavailable")
        return {**{key: value[key] for key in ("id", "name", "type", "location") if key in value},
                "properties": {key: props.get(key) for key in
                               ("dataplaneUri", "localAuth", "provisioningState")},
                "_provenance": {"source_operation": "PlaywrightWorkspaces_ListBySubscription",
                                "api_version": "2025-09-01", "read_only": True,
                                "representation": "metadata"}}
    if kind == "purview_account":
        props = value.get("properties")
        if not isinstance(props, dict):
            raise ValueError("Purview account properties unavailable")
        endpoints = props.get("endpoints")
        hosts = {}
        if isinstance(endpoints, dict):
            for field in ("catalog", "scan", "guardian"):
                raw = endpoints.get(field)
                try:
                    parsed = urlsplit(raw) if isinstance(raw, str) else None
                    host = parsed.hostname if parsed and parsed.scheme == "https" and not parsed.username and not parsed.password and parsed.port in (None, 443) else None
                except ValueError:
                    host = None
                if isinstance(host, str) and re.fullmatch(r"[a-z0-9.-]{1,253}", host.lower()):
                    hosts[field] = host.lower()
        connections = props.get("privateEndpointConnections")
        safe_connections = None
        if isinstance(connections, list):
            safe_connections = []
            for row in connections:
                if not isinstance(row, dict) or not isinstance(row.get("properties"), dict):
                    raise ValueError("Purview private connection malformed")
                detail = row["properties"]
                link = detail.get("privateEndpoint")
                state = detail.get("privateLinkServiceConnectionState")
                safe_connections.append({"privateEndpointId": link.get("id") if isinstance(link, dict) else None,
                                         "status": state.get("status") if isinstance(state, dict) else None,
                                         "provisioningState": detail.get("provisioningState")})
        managed = props.get("managedResources")
        managed_ids = {key: managed[key] for key in ("storageAccount", "eventHubNamespace")
                       if isinstance(managed, dict) and isinstance(managed.get(key), str)
                       and managed[key].startswith("/subscriptions/")}
        return {**{key: value[key] for key in ("id", "name", "type", "location") if key in value},
                "properties": {"provisioningState": props.get("provisioningState"),
                               "publicNetworkAccess": props.get("publicNetworkAccess"),
                               "managedResourcesPublicNetworkAccess": props.get("managedResourcesPublicNetworkAccess"),
                               "managedEventHubState": props.get("managedEventHubState"),
                               "endpointHosts": hosts, "managedResources": managed_ids,
                               "privateEndpointConnections": safe_connections},
                "_provenance": {"source_operation": "Accounts_ListBySubscription", "api_version": "2021-12-01",
                                "read_only": True, "representation": "metadata"}}
    if kind == "monitor_workspace":
        props = value.get("properties")
        if not isinstance(props, dict):
            raise ValueError("Monitor workspace properties unavailable")
        metrics = props.get("metrics")
        endpoint = metrics.get("prometheusQueryEndpoint") if isinstance(metrics, dict) else None
        try:
            parsed = urlsplit(endpoint) if isinstance(endpoint, str) else None
            host = parsed.hostname if parsed and parsed.scheme == "https" and not parsed.username and not parsed.password and parsed.port in (None, 443) else None
        except ValueError:
            host = None
        if not isinstance(host, str) or not host.lower().endswith(".prometheus.monitor.azure.com"):
            host = None
        connections = props.get("privateEndpointConnections")
        safe_connections = None
        if isinstance(connections, list):
            safe_connections = []
            for row in connections:
                if not isinstance(row, dict) or not isinstance(row.get("properties"), dict):
                    raise ValueError("Monitor workspace private connection malformed")
                detail = row["properties"]
                link = detail.get("privateEndpoint")
                state = detail.get("privateLinkServiceConnectionState")
                safe_connections.append({"privateEndpointId": link.get("id") if isinstance(link, dict) else None,
                                         "status": state.get("status") if isinstance(state, dict) else None,
                                         "provisioningState": detail.get("provisioningState"),
                                         "groupIds": detail.get("groupIds")})
        return {**{key: value[key] for key in ("id", "name", "type", "location") if key in value},
                "properties": {"publicNetworkAccess": props.get("publicNetworkAccess"),
                               "provisioningState": props.get("provisioningState"),
                               "queryEndpointHost": host,
                               "privateEndpointConnections": safe_connections},
                "_provenance": {"source_operation": "AzureMonitorWorkspaces_ListBySubscription",
                                "api_version": "2025-10-03", "read_only": True,
                                "representation": "metadata"}}
    if kind == "powerbi_capacity":
        props = value.get("properties")
        administration = props.get("administration") if isinstance(props, dict) else None
        members = administration.get("members") if isinstance(administration, dict) else None
        if not isinstance(props, dict):
            raise ValueError("Power BI capacity properties missing")
        if members is not None and (not isinstance(members, list) or any(
                not isinstance(member, str) for member in members)):
            raise ValueError("Power BI capacity administrators malformed")
        return {**{key: value[key] for key in ("id", "name", "type", "location") if key in value},
                "properties": {**{key: props[key] for key in ("state", "provisioningState") if key in props},
                               **({"administration": {"members": members}} if members is not None else {})},
                "_provenance": {"source_operation": "capacities/list-or-get", "read_only": True,
                                "api_version": "2021-01-01", "representation": "metadata"}}
    if kind == "managed_application":
        props = value.get("properties")
        if not isinstance(props, dict):
            raise ValueError("managed application properties missing")
        safe = {key: props[key] for key in (
            "managedResourceGroupId", "publisherTenantId", "managementMode", "provisioningState",
            "applicationDefinitionId")
            if key in props}
        if "authorizations" in props:
            authorizations = props["authorizations"]
            if not isinstance(authorizations, list) or any(
                    not isinstance(row, dict) or not isinstance(row.get("principalId"), str)
                    or not isinstance(row.get("roleDefinitionId"), str) for row in authorizations):
                raise ValueError("managed application publisher authorizations malformed")
            safe["authorizations"] = [{"principalId": row["principalId"],
                                       "roleDefinitionId": row["roleDefinitionId"]} for row in authorizations]
        if "jitAccessPolicy" in props:
            policy = props["jitAccessPolicy"]
            if policy is not None and not isinstance(policy, dict):
                raise ValueError("managed application JIT policy malformed")
            safe["jitAccessPolicy"] = {key: policy[key] for key in (
                "jitAccessEnabled", "jitApprovalMode", "maximumJitAccessDuration") if key in policy} if policy else None
        return {**{key: value[key] for key in ("id", "name", "type", "kind", "location") if key in value},
                "properties": safe, "_provenance": {"source_operation": "applications/list-or-get",
                                                    "read_only": True, "api_version": "2019-07-01",
                                                    "representation": "metadata"}}
    if kind in ("openshift_cluster", "openshift_hcp_cluster"):
        from .azure import _metadata_only
        return _metadata_only(value)
    if kind not in ("scheduled_query_rule", "action_group"):
        return value
    source = {"scheduled_query_rule": "scheduled_query_rules_list_by_subscription",
              "action_group": "action_groups_list_by_subscription"}[kind]
    if kind == "action_group":
        # Retain only destination metadata. Receiver URLs can contain bearer
        # tokens in path/query and must never enter a snapshot.
        properties = value.get("properties", {})
        receivers = []
        complete = isinstance(properties, dict)
        if complete:
            for field, category, url_field in (("webhookReceivers", "webhook", "serviceUri"),
                                               ("logicAppReceivers", "logicApp", "callbackUrl"),
                                               ("azureFunctionReceivers", "azureFunction", "httpTriggerUrl")):
                rows = properties.get(field, [])
                if not isinstance(rows, list):
                    complete = False
                    continue
                for row in rows:
                    if not isinstance(row, dict):
                        complete = False
                        continue
                    raw = row.get(url_field)
                    parsed = urlsplit(raw) if isinstance(raw, str) else None
                    host = parsed.hostname if parsed and parsed.scheme in ("http", "https") and not parsed.username and not parsed.password else None
                    if not isinstance(host, str) or re.fullmatch(r"[a-z0-9.-]{1,253}", host.lower()) is None:
                        host = None
                    receivers.append({"kind": category, "host": host})
            rows = properties.get("eventHubReceivers", [])
            if not isinstance(rows, list):
                complete = False
            else:
                for row in rows:
                    if not isinstance(row, dict):
                        complete = False
                        continue
                    tenant, subscription = row.get("tenantId"), row.get("subscriptionId")
                    uuid = r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
                    receivers.append({"kind": "eventHub",
                                      "tenantId": tenant if isinstance(tenant, str) and re.fullmatch(uuid, tenant, re.I) else None,
                                      "subscriptionId": subscription if isinstance(subscription, str) and re.fullmatch(uuid, subscription, re.I) else None})
            rows = properties.get("emailReceivers", [])
            if not isinstance(rows, list):
                complete = False
            else:
                for row in rows:
                    if not isinstance(row, dict):
                        complete = False
                        continue
                    address = row.get("emailAddress")
                    domain = address.rsplit("@", 1)[-1].lower() if isinstance(address, str) and "@" in address else None
                    if not isinstance(domain, str) or re.fullmatch(r"[a-z0-9.-]{1,253}", domain) is None:
                        domain = None
                    receivers.append({"kind": "email", "domain": domain})
        value = {key: data for key, data in value.items() if key in ("id", "name", "type", "location")}
        value["properties"] = {"enabled": properties["enabled"]} if isinstance(properties, dict) and "enabled" in properties else {}
        value["_exposureReceivers"] = receivers
        value["_coverage"] = {"receivers": {"status": "not_collected"},
                              "exposureReceivers": {"status": "collected" if complete else "partial"}}
        return {**value, "_provenance": {"source_operation": source, "read_only": True,
                                         "complete_fields": ["properties.enabled"] if isinstance(value.get("properties", {}).get("enabled"), bool) else [],
                                         "native_response_complete": False}}
    return {**value, "_provenance": {**value.get("_provenance", {}),
                                    "source_operation": source, "read_only": True,
                                    "native_response_complete": True,
                                    "representation": "full"}}


def collect_mysql_configurations(reader, scopes, wanted):
    """Reuse embedded legacy MySQL configuration reads at subscription scope."""
    if "mysql_single_configuration" not in wanted:
        return
    for scope in scopes:
        sources = [row for row in reader.collections
                   if row["type"] == "mysql_single_server" and row["scope"].casefold() == scope.casefold()]
        if not sources:
            continue
        items, states = [], []
        for source in sources:
            states.append(source["status"])
            for parent in source["items"]:
                coverage = parent.get("_coverage", {}).get("configurations", {})
                states.append(coverage.get("status", "not_collected"))
                items.extend(parent.get("configurations", []))
        status = _aggregate_status(states, items)
        reader.collections.append({"type": "mysql_single_configuration", "scope": scope,
                                   "service": "Microsoft.DBforMySQL",
                                   "status": status,
                                   "items": items,
                                   **({"error": {"code": "parent_inventory_incomplete"}} if status not in ("collected", "empty") else {})})


def mark_unresolved_bot_keys(reader, scopes, wanted):
    """Keep CMK usability unavailable until effective identity access is proven."""
    if "bot_cmk_key" not in wanted:
        return
    for scope in scopes:
        parents = [row for row in reader.collections
                   if row["type"] == "bot_service" and row["scope"].casefold() == scope.casefold()]
        complete = bool(parents) and all(row["status"] in ("collected", "empty") for row in parents)
        status = ("not_collected" if not parents else
                  "empty" if complete and not any(row["items"] for row in parents)
                  else "not_collected" if complete else
                  _aggregate_status([row["status"] for row in parents], []))
        reader.collections.append({"type": "bot_cmk_key", "scope": scope, "service": "Microsoft.KeyVault",
                                   "status": status, "items": [],
                                   **({"error": {"code": "effective_bot_key_access_unresolved"}} if status != "empty" else {})})


def collect_defender_pricing(reader, request, scopes, wanted):
    """Read both effective resource-scope plans for each AKS cluster."""
    if "defender_pricing" not in wanted:
        return
    from .azure import AzureReadError
    jobs = []
    for scope in scopes:
        sources = [row for row in reader.collections
                   if row["type"] == "aks_cluster" and row["scope"].casefold() == scope.casefold()]
        def fetch(sources=sources):
            failure = None
            for source in sources:
                for cluster in source["items"]:
                    rid = cluster["id"]
                    plans = []
                    for name in ("Containers", "CloudPosture"):
                        pid = rid + "/providers/Microsoft.Security/pricings/" + name
                        try:
                            plan = reader.call(request, ARM + pid + "?api-version=2024-01-01")
                            if not isinstance(plan, dict) or str(plan.get("id", "")).casefold() != pid.casefold() or plan.get("name") != name or not isinstance(plan.get("properties"), dict):
                                raise ValueError("malformed effective Defender pricing")
                            plans.append(plan)
                        except Exception as exc:
                            failure = exc
                            break
                    if len(plans) == 2:
                        yield [{"id": rid, "plans": plans,
                                "_provenance": {"source_operation": "Microsoft.Security/pricings GET",
                                                "api_version": "2024-01-01", "read_only": True,
                                                "effective_scope": rid}}]
            if failure:
                raise failure
            if not sources or any(source["status"] not in ("collected", "empty") for source in sources):
                raise AzureReadError("parent_inventory_incomplete")
        jobs.append(("defender_pricing", scope, "Microsoft.Security", fetch))
    reader.run(jobs)
    for collection in reader.collections:
        if collection["type"] != "defender_pricing" or collection["items"]:
            continue
        parents = [row for row in reader.collections if row["type"] == "aks_cluster"
                   and row["scope"].casefold() == collection["scope"].casefold()]
        incomplete = next((row for row in parents if row["status"] not in ("collected", "empty")), None)
        if incomplete is not None:
            collection["status"] = incomplete["status"]
            collection["error"] = incomplete.get("error", {"code": "parent_inventory_incomplete"})


def collect_vm_instance_views(reader, request, parents):
    """Attach one current Compute instance view per VM, with independent coverage."""
    jobs = []
    for kind, vm in parents:
        if kind != "vm":
            continue
        rid = vm["id"]
        def fetch(rid=rid):
            value = reader.call(request, ARM + rid + "/instanceView?api-version=2023-09-01")
            if not isinstance(value, dict) or "value" in value or ("id" in value and str(value["id"]).casefold() not in (rid.casefold(), (rid + "/instanceView").casefold())):
                raise ValueError("malformed VM instance view")
            view = {key: value[key] for key in ("patchStatus", "statuses", "vmAgent", "maintenanceRedeployStatus") if key in value}
            if not view:
                raise ValueError("empty VM instance view")
            yield [{"id": rid + "/instanceView", "view": view}]
        jobs.append((vm, "instanceView", ("embedded_instanceView", rid, "Microsoft.Compute", fetch)))
    with ThreadPoolExecutor(max_workers=reader.workers) as pool:
        for (vm, field, _), read in zip(jobs, pool.map(reader._read, [job[2] for job in jobs])):
            vm.setdefault("_coverage", {})[field] = _coverage(read)
            if read["status"] == "collected":
                vm[field] = read["items"][0]["view"]


def collect_diagnostic_categories(reader, request, parents, scopes, wanted):
    """Preserve native supported categories and every resource's list coverage."""
    if "diagnostic_category" not in wanted:
        return
    from .azure import _child_rows
    supported = {"application_gateway", "load_balancer", "app_service_environment",
                 "aks_cluster", "cosmos_account", "mongo_cluster", "sql_database"}
    jobs = []
    for kind, parent in parents:
        if kind not in supported:
            continue
        rid = parent["id"]
        def fetch(rid=rid):
            url = ARM + rid + "/providers/Microsoft.Insights/diagnosticSettingsCategories?api-version=2021-05-01-preview"
            seen_ids, seen_names = set(), set()
            for page in reader.pages(request, url):
                result = []
                for row in _child_rows(page, rid, "diagnosticCategories"):
                    cid = row["id"]
                    if not re.fullmatch(re.escape(rid) + r"/providers/Microsoft\.Insights/diagnosticSettingsCategories/[^/?#]+", cid, re.I):
                        raise ValueError("foreign diagnostic category")
                    properties = row.get("properties", {})
                    name = row.get("name")
                    groups = properties.get("categoryGroups", []) if isinstance(properties, dict) else None
                    if (not isinstance(properties, dict) or properties.get("categoryType") not in ("Logs", "Metrics")
                            or not isinstance(name, str) or not name or cid.rsplit('/', 1)[-1].casefold() != name.casefold()
                            or cid.casefold() in seen_ids or name.casefold() in seen_names
                            or not isinstance(groups, list)
                            or any(not isinstance(group, str) or not group for group in groups)
                            or len({group.casefold() for group in groups}) != len(groups)):
                        raise ValueError("malformed diagnostic category properties")
                    seen_ids.add(cid.casefold()); seen_names.add(name.casefold())
                    result.append({**row, "resourceId": rid,
                                   "categoryType": properties.get("categoryType"),
                                   "categoryGroups": groups})
                yield result
        jobs.append((parent, rid, ("embedded_diagnosticCategories", rid, "Microsoft.Insights", fetch)))
    with ThreadPoolExecutor(max_workers=reader.workers) as pool:
        for (parent, rid, _), read in zip(jobs, pool.map(reader._read, [job[2] for job in jobs])):
            parent.setdefault("_coverage", {})["diagnosticCategories"] = _coverage(read)
            if read["items"] or read["status"] in ("collected", "empty"):
                parent["diagnosticCategories"] = read["items"]
            if read["status"] in ("collected", "empty") and any(
                    parent["id"].casefold() == candidate["id"].casefold()
                    for source in reader.collections if source["type"] in ("cosmos_account", "mongo_cluster")
                    for candidate in source["items"]):
                parent["supported_log_categories"] = [row["name"] for row in read["items"] if row["categoryType"] == "Logs"]
                parent.setdefault("_coverage", {})["supported_log_categories"] = {"status": read["status"]}
                for setting in parent.get("diagnosticSettings", []):
                    for log in setting.get("properties", {}).get("logs", []):
                        if isinstance(log, dict) and isinstance(log.get("categoryGroup"), str):
                            group = log["categoryGroup"].casefold()
                            log["resolvedCategories"] = [row["name"] for row in read["items"]
                                                          if row["categoryType"] == "Logs" and isinstance(row.get("categoryGroups"), list)
                                                          and group in [str(value).casefold() for value in row["categoryGroups"]]]
    for scope in scopes:
        sources = [row for row in reader.collections if row["scope"].casefold() == scope.casefold()
                   and row["type"] in supported]
        states = [row["status"] for row in sources]
        items = []
        for source in sources:
            for parent in source["items"]:
                coverage = parent.get("_coverage", {}).get("diagnosticCategories", {})
                states.append(coverage.get("status", "not_collected"))
                items.extend(parent.get("diagnosticCategories", []))
        status = _aggregate_status(states, items) if sources else "not_collected"
        reader.collections.append({"type": "diagnostic_category", "scope": scope,
                                   "service": "Microsoft.Insights",
                                   "status": status,
                                   "items": items,
                                   **({"error": {"code": "category_inventory_incomplete"}} if status not in ("collected", "empty") else {})})


def collect_managed_instance_tde(reader, request, scopes, wanted):
    """Get the exact current TDE object for each fully listed MI database."""
    if "managed_instance_tde" not in wanted:
        return
    sources = [row for row in reader.collections if row["type"] == "managed_instance_database"]
    jobs = []
    for source in sources:
        for database in source["items"]:
            rid = database["id"]
            tid = rid + "/transparentDataEncryption/current"
            def fetch(rid=rid, tid=tid):
                value = reader.call(request, ARM + tid + "?api-version=2021-11-01")
                if not isinstance(value, dict) or str(value.get("id", "")).casefold() != tid.casefold() or not isinstance(value.get("properties"), dict):
                    raise ValueError("malformed managed-instance TDE GET")
                yield [{"id": tid, "parent_id": rid,
                        "properties": {"state": value["properties"].get("state")},
                        "_provenance": {"source_operation": "GET", "read_only": True}}]
            jobs.append((database, ("embedded_managed_instance_tde", rid, "Microsoft.Sql", fetch)))
    with ThreadPoolExecutor(max_workers=reader.workers) as pool:
        for (database, _), read in zip(jobs, pool.map(reader._read, [job[1] for job in jobs])):
            database.setdefault("_coverage", {})["transparentDataEncryption"] = _coverage(read)
            if read["status"] == "collected":
                database["transparentDataEncryption"] = read["items"][0]
    for scope in scopes:
        parents = [row for row in sources if row["scope"].casefold() == scope.casefold()]
        states = [row["status"] for row in parents]
        items = []
        for parent in parents:
            for database in parent["items"]:
                coverage = database.get("_coverage", {}).get("transparentDataEncryption", {})
                states.append(coverage.get("status", "not_collected"))
                if "transparentDataEncryption" in database:
                    items.append(database["transparentDataEncryption"])
        status = _aggregate_status(states, items) if parents else "not_collected"
        reader.collections.append({"type": "managed_instance_tde", "scope": scope, "service": "Microsoft.Sql",
                                   "status": status, "items": items,
                                   **({"error": {"code": "managed_instance_tde_incomplete"}} if status not in ("collected", "empty") else {})})


def _coverage(read):
    return {key: read[key] for key in ("status", "error") if key in read}


def _aggregate_status(states, items):
    bad = [state for state in states if state not in ("collected", "empty")]
    if not bad:
        return "collected" if items else "empty"
    if items or len(set(bad)) != 1:
        return "partial"
    return bad[0]


def _embed_jobs(reader, jobs):
    with ThreadPoolExecutor(max_workers=reader.workers) as pool:
        for (parent, field, _), read in zip(jobs, pool.map(reader._read, [job[2] for job in jobs])):
            parent.setdefault("_coverage", {})[field] = _coverage(read)
            if read["items"] or read["status"] in ("collected", "empty"):
                parent[field] = read["items"]


def _firewall_groups(reader, request, collections):
    jobs = []
    for source in collections:
        if source["type"] != "firewall_policy":
            continue
        for parent in source["items"]:
            rid = parent["id"]
            def fetch(rid=rid):
                failure = None
                for page in reader.pages(request, ARM + rid + "/ruleCollectionGroups?api-version=2023-09-01"):
                    for row in page:
                        gid = row.get("id") if isinstance(row, dict) else None
                        if not isinstance(gid, str) or not re.fullmatch(re.escape(rid) + r"/ruleCollectionGroups/[^/?#]+", gid, re.I):
                            raise ValueError("foreign firewall rule collection group")
                        try:
                            detail = reader.call(request, ARM + gid + "?api-version=2023-09-01")
                            if not isinstance(detail, dict) or str(detail.get("id", "")).casefold() != gid.casefold() or not isinstance(detail.get("properties"), dict):
                                raise ValueError("malformed firewall rule collection group GET")
                            yield [{**detail, "parent_id": rid, "_provenance": {
                                "representation": "full", "source_operation": "get_rule_collection_group",
                                "parent_policy_id": rid, "read_only": True, "api_version": "2023-09-01"}}]
                        except Exception as exc:
                            failure = exc
                            # Retain a failed child identity without full provenance.
                            yield [{"id": gid, "parent_id": rid}]
                if failure:
                    raise failure
            jobs.append((parent, "ruleCollectionGroups", ("embedded_ruleCollectionGroups", rid, "Microsoft.Network", fetch)))
    _embed_jobs(reader, jobs)


def _instant(value):
    if not isinstance(value, str):
        raise ValueError("missing assessment timestamp")
    instant = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if instant.utcoffset() is None:
        raise ValueError("assessment timestamp lacks timezone")
    return instant.astimezone(timezone.utc)


def _vmss_instances(reader, request, collections):
    from .azure import _child_rows, AzureReadError
    jobs = []
    for source in collections:
        if source["type"] != "vm_scale_set":
            continue
        for parent in source["items"]:
            rid, scope = parent["id"], source["scope"]
            def fetch(rid=rid, scope=scope):
                instances = []
                try:
                    seen = set()
                    for page in reader.pages(request, ARM + rid + "/virtualMachines?api-version=2024-07-01"):
                        rows = _child_rows(page, rid, "instances")
                        if any(not re.fullmatch(re.escape(rid) + r"/virtualMachines/[^/?#]+", row["id"], re.I) for row in rows):
                            raise ValueError("foreign VMSS instance")
                        for row in rows:
                            identity = row["id"].casefold()
                            if identity in seen:
                                raise ValueError("duplicate VMSS instance")
                            if reader.budget.max_items is not None and len(instances) >= reader.budget.max_items:
                                raise AzureReadError("resource_limit")
                            seen.add(identity)
                            instances.append(row)
                    if not instances:
                        return
                    ids = {row["id"].casefold(): row for row in instances}
                    if len(ids) != len(instances):
                        raise ValueError("duplicate VMSS instance")
                    query_id = rid.casefold().replace("\\", "\\\\").replace("'", "\\'")
                    body = {"subscriptions": [scope.rsplit("/", 1)[-1]],
                            "query": "patchassessmentresources | where type !has 'softwarepatches' "
                                     "| where tolower(id) startswith '" + query_id + "/virtualmachines/' "
                                     "| project id, type, properties | order by id asc",
                            "options": {"resultFormat": "objectArray", "$top": 1000}}
                    summaries = {key: [] for key in ids}
                    summary_count = 0
                    for page in reader.pages(request, ARM + "/providers/Microsoft.ResourceGraph/resources?api-version=2024-04-01",
                                             body=body, key="data", next_key="$skipToken"):
                        for row in page:
                            if reader.budget.max_items is not None and summary_count >= reader.budget.max_items:
                                raise AzureReadError("resource_limit")
                            summary_count += 1
                            identity = row.get("id") if isinstance(row, dict) else None
                            match = re.fullmatch(r"(.+)/patchAssessmentResults/[^/?#]+", identity or "", re.I)
                            if match is None or match.group(1).casefold() not in ids or "softwarepatches" in str(row.get("type", "")).casefold():
                                raise ValueError("foreign or non-summary patch assessment")
                            props = row.get("properties")
                            if not isinstance(props, dict):
                                raise ValueError("malformed patch assessment")
                            summaries[match.group(1).casefold()].append(props)
                    unresolved = False
                    for identity, instance in ids.items():
                        values = summaries[identity]
                        try:
                            latest_time = max(_instant(row.get("lastModifiedDateTime")) for row in values)
                            latest = [row for row in values if _instant(row.get("lastModifiedDateTime")) == latest_time]
                            if len(latest) != 1:
                                raise ValueError("duplicate latest patch assessment")
                            props = latest[0]
                            assessment = {key: props[key] for key in ("status", "lastModifiedDateTime", "availablePatchCountByClassification", "errorDetails") if key in props}
                            # Absence is unresolved, never a synthetic zero/error-free result.
                            counts = props.get("availablePatchCountByClassification")
                            assessment["unresolvedClassification"] = (
                                props.get("unresolvedClassification") is not False and "unresolvedClassification" in props or
                                not isinstance(counts, dict) or any(type(counts.get(key)) is not int or counts[key] < 0 for key in ("critical", "security")))
                            assessment.update(resourceId=instance["id"], _provenance={"source": "ResourceGraph.patchassessmentresources.summary", "latest": True})
                            instance["patchAssessment"] = assessment
                        except (ValueError, TypeError):
                            unresolved = True
                    if unresolved:
                        raise AzureReadError("patch_summary_unresolved")
                except Exception:
                    if instances:
                        yield instances
                    raise
                yield instances
            jobs.append((parent, "instances", ("embedded_instances", rid, "Microsoft.Compute", fetch)))
    _embed_jobs(reader, jobs)


def _ml_computes(reader, request, collections, scopes):
    from .azure import _child_rows, AzureReadError
    jobs = []
    for scope in scopes:
        sources = [c for c in collections if c["type"] == "ml_workspace" and c["scope"] == scope]
        def fetch(sources=sources):
            failure = None
            for source in sources:
                for parent in source["items"]:
                    rid = parent["id"]
                    try:
                        for page in reader.pages(request, ARM + rid + "/computes?api-version=2024-04-01"):
                            rows = _child_rows(page, rid, "computes")
                            for row in rows:
                                if not re.fullmatch(re.escape(rid) + r"/computes/[^/?#]+", row["id"], re.I):
                                    raise ValueError("foreign ML compute")
                                row["_provenance"] = {"source_operation": "LIST", "read_only": True, "api_version": "2024-04-01"}
                            yield rows
                    except Exception as exc:
                        failure = exc
            if failure:
                raise failure
            if not sources or any(c["status"] not in ("collected", "empty") for c in sources):
                raise AzureReadError("parent_inventory_incomplete")
        jobs.append(("ml_compute", scope, "Microsoft.MachineLearningServices", fetch))
    reader.run(jobs)


def _descendants(reader, request, scopes, options):
    from .azure import AzureReadError
    policy = options.get("sw02", {})
    master = policy.get("expectedManagementGroupId") if isinstance(policy, dict) and policy.get("status") == "collected" else None
    valid = isinstance(master, str) and re.fullmatch(re.escape(MG) + r"[^/?#]+", master, re.I)
    jobs = []
    for scope in scopes:
        # Reuse subscription discovery/bindings, reducing the same authoritative
        # response to one scope rather than issuing a second LIST.
        existing = [c for c in reader.collections if c["type"] == "subscription"]
        scoped = [c for c in existing if c["scope"].casefold() == scope.casefold()]
        if not scoped:
            matches = [c for c in existing if any(str(row.get("id", "")).casefold() == scope.casefold() for row in c["items"])]
            if matches:
                source = matches[0]
                reader.collections.append({**source, "scope": scope,
                                           "items": [row for row in source["items"] if str(row.get("id", "")).casefold() == scope.casefold()]})
            else:
                def binding(scope=scope):
                    value = reader.call(request, ARM + scope + "?api-version=2022-12-01")
                    if not isinstance(value, dict) or str(value.get("id", "")).casefold() != scope.casefold():
                        raise ValueError("subscription binding unavailable")
                    yield [value]
                jobs.append(("subscription", scope, "Microsoft.Resources", binding))
        def fetch():
            if not valid:
                raise AzureReadError("expected_management_group_policy_unavailable")
            yield from reader.pages(request, ARM + master + "/descendants?api-version=2020-05-01")
        jobs.append(("management_group_descendant", scope, "Microsoft.Management", fetch))
    reader.run(jobs)
    for collection in reader.collections:
        if collection["type"] == "management_group_descendant":
            collection["_provenance"] = {"source_operation": "get_descendants", "parent_management_group_id": master,
                                         "pages_complete": collection["status"] in ("collected", "empty"), "read_only": True}


def owner_metadata(options, scopes, tenant):
    """Whitelisted local policy inputs; no missing approval is synthesized."""
    from .azure import _metadata_only
    selected = {scope.casefold() for scope in scopes}
    output = {}
    raw = options.get("sw02")
    if isinstance(raw, dict):
        output["sw02"] = _metadata_only({key: value for key, value in raw.items()
                                         if key in ("status", "approvedVnetIds", "maxAssessmentAgeSeconds", "expectedManagementGroupId")})
    raw = options.get("compliance_policy")
    if isinstance(raw, dict):
        policy = {}
        if raw.get("tenant_id") == tenant:
            policy.update({key: value for key, value in raw.items() if key in ("status", "tenant_id", "required_group_ids")})
        if isinstance(raw.get("subscription_id"), str) and ("/subscriptions/" + raw["subscription_id"]).casefold() in selected:
            policy.update({key: value for key, value in raw.items() if key in ("status", "subscription_id", "approvedAaddsResourceIds", "requireLdaps")})
        sw03 = raw.get("sw03")
        if isinstance(sw03, dict) and str(sw03.get("scope", "")).casefold() in selected:
            fields = {"legacyAgentBaseline": {"required"}, "imageBuilder": {"approvedBuildSubnetIds", "isolatedSubnetIds"},
                      "storageAccess": {"expectedSettings"}, "activityLogWindow": {"start", "end"}}
            projected = {key: value for key, value in sw03.items() if key in ("status", "scope")}
            for key, allowed in fields.items():
                if isinstance(sw03.get(key), dict):
                    projected[key] = {field: value for field, value in sw03[key].items() if field in allowed}
            policy["sw03"] = projected
        if policy:
            output["compliance_policy"] = _metadata_only(policy)
    raw = options.get("ml_compute_classification")
    if isinstance(raw, dict):
        projected = {key: value for key, value in raw.items() if key in
                     ("status", "source", "read_only", "observed_at", "max_age_seconds")}
        if isinstance(raw.get("assignments"), list):
            projected["assignments"] = [{key: value for key, value in row.items() if key in ("resource_id", "classification")}
                                        if isinstance(row, dict) else None for row in raw["assignments"]]
        output["ml_compute_classification"] = _metadata_only(projected)
    return output


def activity_bounds(options, scopes, start, end):
    """Use a bounded owner window verbatim when it matches a selected scope."""
    policy = options.get("compliance_policy")
    policy = policy.get("sw03") if isinstance(policy, dict) else None
    window = policy.get("activityLogWindow") if isinstance(policy, dict) else None
    if (not isinstance(policy, dict) or policy.get("status") != "collected"
            or str(policy.get("scope", "")).casefold() not in {scope.casefold() for scope in scopes}
            or not isinstance(window, dict)):
        return start, end
    try:
        lower, upper = _instant(window.get("start")), _instant(window.get("end"))
        if not 0 < (upper - lower).total_seconds() <= 90 * 86400 or upper > _instant(end):
            return start, end
        return lower.isoformat(), upper.isoformat()
    except (ValueError, TypeError):
        return start, end


def collect_facts(reader, request, wanted, scopes, options):
    """Add facts without changing shared pagination, retry or budget rules."""
    sources = list(reader.collections)
    _firewall_groups(reader, request, sources)
    _vmss_instances(reader, request, sources)
    _storage_lock_chains(reader, request, sources)
    if "ml_compute" in wanted:
        _ml_computes(reader, request, sources, scopes)
    if "management_group_descendant" in wanted:
        _descendants(reader, request, scopes, options)


def _storage_lock_chains(reader, request, collections):
    """Prove subscription ancestry, then read locks at every exact ancestor."""
    accounts = [(source["scope"], item) for source in collections if source["type"] == "storage_account"
                for item in source["items"] if isinstance(item.get("properties"), dict)]
    if not accounts:
        return
    groups = {row["id"].casefold(): row for source in collections if source["type"] == "management_group" for row in source["items"]}
    def ancestry(scope):
        body = {"subscriptions": [scope.rsplit("/", 1)[-1]],
                "query": "resourcecontainers | where type =~ 'microsoft.resources/subscriptions' | project id, properties | order by id asc",
                "options": {"resultFormat": "objectArray", "$top": 1000}}
        rows = []
        for page in reader.pages(request, ARM + "/providers/Microsoft.ResourceGraph/resources?api-version=2024-04-01",
                                 body=body, key="data", next_key="$skipToken"):
            rows.extend(page)
        if len(rows) != 1 or not isinstance(rows[0], dict) or str(rows[0].get("id", "")).casefold() != scope.casefold():
            raise ValueError("subscription ancestry unavailable")
        raw = rows[0].get("properties", {}).get("managementGroupAncestorsChain")
        if not isinstance(raw, list) or not raw:
            raise ValueError("management group ancestry unavailable")
        chain = []
        for row in raw:
            name = row.get("name") if isinstance(row, dict) else None
            if not isinstance(name, str) or not re.fullmatch(r"[^/?#\x00-\x1f]+", name):
                raise ValueError("malformed management group ancestry")
            chain.append(MG + name)
        if len(set(rid.casefold() for rid in chain)) != len(chain):
            raise ValueError("cyclic management group ancestry")
        binding_id = chain[0] + "/subscriptions/" + scope.rsplit("/", 1)[-1]
        binding = reader.call(request, ARM + binding_id + "?api-version=2020-05-01")
        if (not isinstance(binding, dict) or str(binding.get("id", "")).casefold() != binding_id.casefold()
                or str(binding.get("properties", {}).get("parent", {}).get("id", "")).casefold() != chain[0].casefold()):
            raise ValueError("subscription management group binding unresolved")
        for i, rid in enumerate(chain):
            detail = groups.get(rid.casefold())
            if detail is None:
                detail = reader.call(request, ARM + rid + "?api-version=2020-05-01")
            if not isinstance(detail, dict) or str(detail.get("id", "")).casefold() != rid.casefold():
                raise ValueError("management group GET identity mismatch")
            details = detail.get("properties", {}).get("details")
            if not isinstance(details, dict):
                raise ValueError("management group parent details unavailable")
            parent = details.get("parent")
            expected = chain[i + 1] if i + 1 < len(chain) else None
            actual = parent.get("id") if isinstance(parent, dict) else None
            if (expected is None and parent is not None) or (expected is not None and (not isinstance(actual, str) or actual.casefold() != expected.casefold())):
                raise ValueError("management group ancestry conflicts with GET")
        yield [{"id": scope, "ancestors": chain}]
    selected = list(dict.fromkeys(scope for scope, _ in accounts))
    with ThreadPoolExecutor(max_workers=reader.workers) as pool:
        ancestry_reads = dict(zip(selected, pool.map(reader._read, [
            ("storage_lock_ancestry", scope, "Microsoft.Management", lambda scope=scope: ancestry(scope)) for scope in selected])))
    paths = {}
    needed = set()
    for scope, account in accounts:
        rid = account["id"]
        match = re.fullmatch(r"(/subscriptions/[^/?#]+)/resourceGroups/([^/?#]+)/providers/Microsoft\.Storage/storageAccounts/[^/?#]+", rid, re.I)
        if match is None:
            account["effectiveLockChain"] = {"status": "partial", "managementGroupAncestorsComplete": False, "scopes": []}
            continue
        read = ancestry_reads[scope]
        ancestors = read["items"][0]["ancestors"] if read["status"] == "collected" else []
        chain = [rid, match.group(1) + "/resourceGroups/" + match.group(2), scope] + ancestors
        paths[rid] = (chain, read)
        needed.update(chain)
    def locks(scope):
        for page in reader.pages(request, ARM + scope + "/providers/Microsoft.Authorization/locks?api-version=2016-09-01"):
            if any(not isinstance(row, dict) or not isinstance(row.get("id"), str) or not re.fullmatch(
                    re.escape(scope) + r"/providers/Microsoft\.Authorization/locks/[^/?#]+", row["id"], re.I) for row in page):
                raise ValueError("foreign management lock")
            yield page
    ordered = sorted(needed)
    with ThreadPoolExecutor(max_workers=reader.workers) as pool:
        lock_reads = dict(zip(ordered, pool.map(reader._read, [
            ("storage_lock_scope", scope, "Microsoft.Authorization", lambda scope=scope: locks(scope)) for scope in ordered])))
    for scope, account in accounts:
        if account["id"] not in paths:
            continue
        chain, ancestry_read = paths[account["id"]]
        complete = ancestry_read["status"] == "collected"
        evidence = {"managementGroupAncestorsComplete": complete, "scopes": [
            {"scope": path, **_coverage(lock_reads[path]), "locks": lock_reads[path]["items"]} for path in chain]}
        evidence["status"] = "collected" if complete and all(lock_reads[path]["status"] in ("collected", "empty") for path in chain) else "partial"
        if not complete:
            evidence["error"] = ancestry_read.get("error", {"code": "ancestry_incomplete"})
        account["effectiveLockChain"] = evidence
        account.setdefault("_coverage", {})["effectiveLockChain"] = {
            "status": evidence["status"], **({"error": evidence["error"]} if "error" in evidence else {})}


def collect_nested_metadata(reader, request, parents):
    """Event Hubs metadata only: no keys, event sampling or receiver execution."""
    from .azure import _child_rows
    jobs = []
    for kind, parent in parents:
        if kind != "eventhub_namespace":
            continue
        for field, nested in (("eventHubs", ("authorizationRules", "consumerGroups")),
                              ("disasterRecoveryConfigs", ("authorizationRules",))):
            for child in parent.get(field, []):
                for path in nested:
                    rid = child["id"]
                    def fetch(rid=rid, path=path):
                        for page in reader.pages(request, ARM + rid + "/" + path + "?api-version=2024-01-01"):
                            rows = _child_rows(page, rid, path)
                            if any(not re.fullmatch(re.escape(rid + "/" + path) + r"/[^/?#]+", row["id"], re.I) for row in rows):
                                raise ValueError("foreign Event Hubs child")
                            yield rows
                    jobs.append((child, path, ("embedded_" + path, rid, "Microsoft.EventHub", fetch)))
    _embed_jobs(reader, jobs)


def collect_current_certificates(reader, request, scopes, allow_vault=None, *, kind="key_vault_certificate"):
    from .azure import AzureReadError, VAULT
    VERSION = '2025-07-01'
    if kind not in ('key_vault_certificate', 'key_vault_certificate_current'):
        raise ValueError('unsupported native current certificate kind')
    KIND = kind
    ATTRIBUTES = frozenset({'enabled', 'exp', 'nbf', 'created', 'updated'})

    jobs = []
    proofs = {}
    for scope in scopes:
        parents = [c for c in reader.collections if c['type'] == 'vault' and c['scope'].casefold() == scope.casefold()]
        proof = {'scope': scope, '_provenance': {'source_operation': 'vault_current_certificate_inventory_read', 'read_only': True},
                 'resolution': {k: 'unknown' for k in ('vaults', 'certificatePages', 'currentVersions')},
                 'source_evidence_ids': []}
        proofs[scope.casefold()] = proof

        def fetch(scope=scope, parents=parents, proof=proof):
            if len(parents) != 1 or parents[0]['status'] not in ('collected', 'empty'):
                raise AzureReadError('certificate_parent_inventory_incomplete')
            vaults = parents[0]['items']
            if not isinstance(vaults, list) or (parents[0]['status'] == 'empty') != (not vaults):
                raise ValueError('certificate_parent_inventory_contradictory')
            seen_vaults, failures = set(), []
            proof['source_evidence_ids'].append('https://management.azure.com' + scope + '/providers/Microsoft.KeyVault/vaults')
            for vault in vaults:
                try:
                    rid = vault.get('id')
                    if (not isinstance(rid, str) or not re.fullmatch(re.escape(scope) + r'/resourceGroups/[^/?#]+/providers/Microsoft.KeyVault/vaults/[^/?#]+', rid, re.I)
                            or rid.casefold() in seen_vaults):
                        raise ValueError('certificate_vault_identity_invalid')
                    seen_vaults.add(rid.casefold())
                    uri = vault.get('properties', {}).get('vaultUri')
                    if not isinstance(uri, str) or not re.fullmatch(r'https://[A-Za-z0-9-]{3,24}\.vault\.azure\.net/?', uri):
                        raise ValueError('certificate_vault_endpoint_invalid')
                    origin = uri.rstrip('/')
                    if origin.casefold() != 'https://' + rid.rsplit('/', 1)[1].casefold() + '.vault.azure.net':
                        raise ValueError('certificate_vault_endpoint_parent_mismatch')
                    if allow_vault is not None:
                        allow_vault(origin)
                    list_url = origin + '/certificates?api-version=' + VERSION
                    proof['source_evidence_ids'].append(list_url)
                    names = set()
                    for page in reader.pages(request, list_url, audience=VAULT):
                        for certificate in page:
                            cid = certificate.get('id') if isinstance(certificate, dict) else None
                            if not isinstance(cid, str) or not re.fullmatch(re.escape(origin) + r'/certificates/[A-Za-z0-9-]{1,127}', cid):
                                raise ValueError('certificate_list_identity_invalid')
                            name = cid.rsplit('/', 1)[1]
                            if name.casefold() in names:
                                raise ValueError('certificate_duplicate_name')
                            names.add(name.casefold())
                            current = reader.call(request, cid + '?api-version=' + VERSION, audience=VAULT)
                            if (not isinstance(current, dict) or not isinstance(current.get('id'), str)
                                    or not re.fullmatch(re.escape(cid) + r'/[A-Za-z0-9-]+', current['id'])
                                    or not isinstance(current.get('attributes'), dict)):
                                raise ValueError('current_certificate_identity_or_attributes_invalid')
                            cer = current.get('cer')
                            if cer is not None and (not isinstance(cer, str) or len(cer) > 131072):
                                raise ValueError('current_certificate_public_der_invalid')
                            safe = {'id': current['id'], 'attributes': {k: v for k, v in current['attributes'].items() if k in ATTRIBUTES},
                                    '_provenance': {'source_operation': 'certificates_get_current', 'read_only': True,
                                                    'request_uri': cid, 'representation': 'full', 'api_version': VERSION}}
                            if cer is not None:
                                safe['cer'] = cer
                            row = {'id': rid + '/certificates/' + name, 'name': name, 'parent_id': rid, 'vault_uri': origin,
                                   'currentCertificate': safe}
                            if KIND == 'key_vault_certificate_current':
                                # Policy belongs to this current GET response, not a
                                # separately updated unversioned policy or import time.
                                policy = current.get('policy')
                                if not isinstance(policy, dict):
                                    raise ValueError('current_certificate_policy_unavailable')
                                issuer, key_props = policy.get('issuer'), policy.get('key_props')
                                if not isinstance(issuer, dict) or not isinstance(key_props, dict):
                                    raise ValueError('current_certificate_policy_incomplete')
                                row.update(isCurrentVersion=True, data_plane_id=current['id'], policy={
                                    'issuer': {k: v for k, v in issuer.items() if k == 'name'},
                                    'key_props': {k: v for k, v in key_props.items() if k in ('kty', 'key_size')}},
                                    _provenance={'source_operation': 'certificates_get_current', 'read_only': True,
                                                 'request_uri': cid, 'api_version': VERSION, 'representation': 'full'})
                                if 'crv' in key_props:
                                    row['policy']['key_props']['curve'] = key_props['crv']
                                    row['_provenance']['native_field_mapping'] = {'policy.key_props.curve': 'policy.key_props.crv'}
                            yield [row]
                except Exception as exc:
                    failures.append(exc)
            if failures:
                raise failures[0]
            proof['resolution'] = {k: 'complete' for k in proof['resolution']}

        jobs.append((KIND, scope, 'Microsoft.KeyVault', fetch))
    reader.run(jobs)
    for collection in reader.collections:
        if collection['type'] == KIND and collection['scope'].casefold() in proofs:
            collection['scopeCoverage'] = proofs[collection['scope'].casefold()]
