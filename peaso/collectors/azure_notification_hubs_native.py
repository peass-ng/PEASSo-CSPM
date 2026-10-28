"""Credential-free Notification Hubs namespace and authorization inventory."""
from __future__ import annotations

import re
import ipaddress
from urllib.parse import urlsplit

ARM = "https://management.azure.com"
KIND = "notification_hub_namespace"
VERSION = "2023-09-01"
NAMESPACE_TYPE = "Microsoft.NotificationHubs/namespaces"
HUB_TYPE = NAMESPACE_TYPE + "/notificationHubs"
RIGHTS = frozenset(("Manage", "Send", "Listen"))
PUSH_PROVIDERS = frozenset(("admCredential", "apnsCredential", "baiduCredential", "browserCredential",
                            "gcmCredential", "mpnsCredential", "wnsCredential", "xiaomiCredential"))


def _push_providers(properties):
    providers = set()
    for name in PUSH_PROVIDERS:
        value = properties.get(name)
        if isinstance(value, dict) and value:
            providers.add(name)
    nested = properties.get("pnsCredentials")
    if isinstance(nested, dict):
        for name in PUSH_PROVIDERS:
            value = nested.get(name)
            if isinstance(value, dict) and value:
                providers.add(name)
    return sorted(providers)


def _identity(row, prefix, resource_type):
    if not isinstance(row, dict):
        raise ValueError("malformed Notification Hubs resource")
    rid = row.get("id")
    name = row.get("name")
    if (not isinstance(rid, str) or not rid.casefold().startswith(prefix.casefold() + "/")
            or not isinstance(name, str) or not name
            or rid.rsplit("/", 1)[-1].casefold() != name.casefold()
            or str(row.get("type", "")).casefold() != resource_type.casefold()
            or "?" in rid or "#" in rid):
        raise ValueError("foreign or malformed Notification Hubs identity")
    return rid, name


def _rights(value):
    if not isinstance(value, list) or any(right not in RIGHTS for right in value):
        raise ValueError("malformed Notification Hubs rights")
    return sorted(set(value))


def _rules(reader, request, parent_id, resource_type):
    rows = []
    seen = set()
    prefix = parent_id + "/authorizationRules"
    for page in reader.pages(request, ARM + prefix + "?api-version=" + VERSION):
        for row in page:
            rid, name = _identity(row, prefix, resource_type + "/authorizationRules")
            if rid.casefold() in seen or not isinstance(row.get("properties"), dict):
                raise ValueError("duplicate or malformed Notification Hubs rule")
            seen.add(rid.casefold())
            rows.append({"id": rid, "name": name, "rights": _rights(row["properties"].get("rights"))})
    return rows


def _namespace(row, scope):
    rid, name = _identity(row, scope + "/resourceGroups", NAMESPACE_TYPE)
    if not re.fullmatch(re.escape(scope) + r"/resourceGroups/[^/]+/providers/Microsoft\.NotificationHubs/namespaces/[^/]+", rid, re.I):
        raise ValueError("foreign Notification Hubs namespace")
    props = row.get("properties")
    if not isinstance(props, dict):
        raise ValueError("missing Notification Hubs namespace properties")
    safe = {"publicNetworkAccess": props.get("publicNetworkAccess") if props.get("publicNetworkAccess") in ("Enabled", "Disabled") else None,
            "status": props.get("status") if props.get("status") in ("Created", "Creating", "Suspended", "Deleting") else None,
            "enabled": props.get("enabled") if isinstance(props.get("enabled"), bool) else None,
            "provisioningState": props.get("provisioningState") if props.get("provisioningState") in
            ("Unknown", "InProgress", "Succeeded", "Failed", "Canceled", "Pending", "Disabled") else None}
    if "serviceBusEndpoint" in props:
        safe["serviceBusEndpoint"] = props["serviceBusEndpoint"]
    safe["pushProviders"] = _push_providers(props)
    connections = props.get("privateEndpointConnections")
    if connections is not None:
        if not isinstance(connections, list):
            raise ValueError("malformed Notification Hubs private connections")
        safe_connections = []
        for connection in connections:
            details = connection.get("properties") if isinstance(connection, dict) else None
            remote = details.get("privateEndpoint") if isinstance(details, dict) else None
            state = details.get("privateLinkServiceConnectionState") if isinstance(details, dict) else None
            remote_id = remote.get("id") if isinstance(remote, dict) else None
            if (remote_id is not None and (not isinstance(remote_id, str) or not re.fullmatch(
                    r"/subscriptions/[^/]+/resourceGroups/[^/]+/providers/Microsoft\.Network/privateEndpoints/[^/]+",
                    remote_id, re.I))):
                raise ValueError("malformed Notification Hubs private endpoint identity")
            connection_status = state.get("status") if isinstance(state, dict) else None
            provisioning = details.get("provisioningState") if isinstance(details, dict) else None
            safe_connections.append({"privateEndpointId": remote_id,
                                     "status": connection_status if connection_status in
                                     ("Approved", "Pending", "Rejected", "Disconnected") else None,
                                     "provisioningState": provisioning if provisioning in
                                     ("Unknown", "Succeeded", "Creating", "Updating", "UpdatingByProxy", "Deleting",
                                      "DeletingByProxy", "Deleted") else None})
        safe["privateEndpointConnections"] = safe_connections
    if "serviceBusEndpoint" in safe:
        endpoint = safe["serviceBusEndpoint"]
        parsed = urlsplit(endpoint) if isinstance(endpoint, str) else None
        if (parsed is None or parsed.scheme != "https" or not parsed.hostname or parsed.username
                or parsed.password or parsed.query or parsed.fragment):
            raise ValueError("malformed Notification Hubs service endpoint")
    acls = props.get("networkAcls")
    if acls is not None:
        if not isinstance(acls, dict):
            raise ValueError("malformed Notification Hubs network ACL")
        public = acls.get("publicNetworkRule")
        rules = acls.get("ipRules")
        if public is not None:
            if not isinstance(public, dict):
                raise ValueError("malformed Notification Hubs public rule")
            safe_public = {"rights": _rights(public.get("rights"))}
        else:
            safe_public = None
        if rules is not None and (not isinstance(rules, list) or any(not isinstance(rule, dict) for rule in rules)):
            raise ValueError("malformed Notification Hubs IP rules")
        safe_rules = [] if rules is not None else None
        for rule in rules or []:
            mask = rule.get("ipMask")
            try:
                ipaddress.ip_network(mask, strict=False)
            except (TypeError, ValueError):
                raise ValueError("malformed Notification Hubs IP mask") from None
            safe_rules.append({"ipMask": mask, "rights": _rights(rule.get("rights"))})
        safe["networkAcls"] = {"publicNetworkRule": safe_public, "ipRules": safe_rules}
    return {"id": rid, "name": name, "type": NAMESPACE_TYPE, "properties": safe}


def collect(reader, request, scopes, wanted):
    if KIND not in wanted:
        return
    jobs = []
    for scope in scopes:
        def fetch(scope=scope):
            seen = set()
            url = ARM + scope + "/providers/" + NAMESPACE_TYPE + "?api-version=" + VERSION
            for page in reader.pages(request, url):
                projected = []
                for row in page:
                    namespace = _namespace(row, scope)
                    rid = namespace["id"]
                    if rid.casefold() in seen:
                        raise ValueError("duplicate Notification Hubs namespace")
                    seen.add(rid.casefold())
                    namespace["authorizationRules"] = _rules(reader, request, rid, NAMESPACE_TYPE)
                    hubs = []
                    hub_seen = set()
                    for hub_page in reader.pages(request, ARM + rid + "/notificationHubs?api-version=" + VERSION):
                        for hub in hub_page:
                            hub_id, hub_name = _identity(hub, rid + "/notificationHubs", HUB_TYPE)
                            if hub_id.casefold() in hub_seen:
                                raise ValueError("duplicate Notification Hub")
                            hub_seen.add(hub_id.casefold())
                            hub_props = hub.get("properties")
                            if not isinstance(hub_props, dict):
                                raise ValueError("malformed Notification Hub properties")
                            hubs.append({"id": hub_id, "name": hub_name,
                                         "pushProviders": _push_providers(hub_props),
                                         "authorizationRules": _rules(reader, request, hub_id, HUB_TYPE)})
                    namespace["hubs"] = hubs
                    projected.append(namespace)
                yield projected
        jobs.append((KIND, scope, "Microsoft.NotificationHubs", fetch))
    reader.run(jobs)
