"""Credential-free Azure Relay namespace, listener, and SAS-rights inventory.

ARM LIST contracts: https://learn.microsoft.com/en-us/rest/api/relay/namespaces/list?view=rest-relay-2024-01-01
https://learn.microsoft.com/en-us/rest/api/relay/namespaces/list-authorization-rules?view=rest-relay-2024-01-01
https://learn.microsoft.com/en-us/rest/api/relay/hybrid-connections/list-by-namespace?view=rest-relay-2024-01-01
https://learn.microsoft.com/en-us/rest/api/relay/hybrid-connections/list-authorization-rules?view=rest-relay-2024-01-01
https://learn.microsoft.com/en-us/rest/api/relay/wcf-relays/list-by-namespace?view=rest-relay-2024-01-01
https://learn.microsoft.com/en-us/rest/api/relay/wcf-relays/list-authorization-rules?view=rest-relay-2024-01-01
"""
from __future__ import annotations

import re
from urllib.parse import urlsplit


ARM = "https://management.azure.com"
VERSION = "2024-01-01"
KIND = "relay_namespace"
NAMESPACE = "Microsoft.Relay/namespaces"
ENTITY_TYPES = {"hybridConnections": NAMESPACE + "/hybridConnections",
                "wcfRelays": NAMESPACE + "/wcfRelays"}
RIGHTS = frozenset(("Manage", "Send", "Listen"))


def _identity(row, prefix, expected_type):
    if not isinstance(row, dict):
        raise ValueError("malformed Relay row")
    rid, name = row.get("id"), row.get("name")
    if (not isinstance(rid, str) or not isinstance(name, str) or not name
            or re.fullmatch(re.escape(prefix) + r"/[^/?#%\\\s]+", rid, re.I) is None
            or name.casefold() != rid.rsplit("/", 1)[-1].casefold()
            or str(row.get("type", "")).casefold() != expected_type.casefold()):
        raise ValueError("foreign or malformed Relay identity")
    return rid, name


def _rules(reader, request, rid, parent_type):
    seen, rules = set(), []
    url = ARM + rid + "/authorizationRules?api-version=" + VERSION
    for page in reader.pages(request, url):
        for row in page:
            rule_id, name = _identity(row, rid + "/authorizationRules", parent_type + "/authorizationRules")
            props = row.get("properties")
            rights = props.get("rights") if isinstance(props, dict) else None
            if (rule_id.casefold() in seen or not isinstance(rights, list)
                    or any(right not in RIGHTS for right in rights)):
                raise ValueError("malformed Relay SAS rule")
            seen.add(rule_id.casefold())
            rules.append({"id": rule_id, "name": name, "rights": sorted(set(rights))})
    return rules


def _connections(props):
    rows = props.get("privateEndpointConnections", [])
    if not isinstance(rows, list):
        raise ValueError("malformed Relay private endpoints")
    result = []
    for row in rows:
        detail = row.get("properties") if isinstance(row, dict) else None
        endpoint = detail.get("privateEndpoint") if isinstance(detail, dict) else None
        state = detail.get("privateLinkServiceConnectionState") if isinstance(detail, dict) else None
        remote_id = endpoint.get("id") if isinstance(endpoint, dict) else None
        status = state.get("status") if isinstance(state, dict) else None
        provisioning = detail.get("provisioningState") if isinstance(detail, dict) else None
        if (remote_id is not None and (not isinstance(remote_id, str) or re.fullmatch(
                r"/subscriptions/[^/]+/resourceGroups/[^/]+/providers/Microsoft\.Network/privateEndpoints/[^/]+",
                remote_id, re.I) is None)):
            raise ValueError("malformed Relay private endpoint ID")
        result.append({"privateEndpointId": remote_id,
                       "status": status if status in ("Approved", "Pending", "Rejected", "Disconnected") else None,
                       "provisioningState": provisioning if provisioning in
                       ("Succeeded", "Creating", "Updating", "Deleting", "Failed") else None})
    return result


def _entities(reader, request, namespace_id, field):
    seen, entities = set(), []
    entity_type = ENTITY_TYPES[field]
    url = ARM + namespace_id + "/" + field + "?api-version=" + VERSION
    for page in reader.pages(request, url):
        for row in page:
            rid, name = _identity(row, namespace_id + "/" + field, entity_type)
            props = row.get("properties")
            if rid.casefold() in seen or not isinstance(props, dict):
                raise ValueError("malformed Relay entity")
            seen.add(rid.casefold())
            count = props.get("listenerCount")
            if count is not None and (type(count) is not int or count < 0):
                raise ValueError("malformed Relay listener count")
            safe = {"listenerCount": count,
                    "requiresClientAuthorization": props.get("requiresClientAuthorization") if type(props.get("requiresClientAuthorization")) is bool else None}
            if field == "wcfRelays":
                safe.update({"relayType": props.get("relayType") if props.get("relayType") in ("Http", "NetTcp") else None,
                             "requiresTransportSecurity": props.get("requiresTransportSecurity") if type(props.get("requiresTransportSecurity")) is bool else None})
            entities.append({"id": rid, "name": name, "properties": safe,
                             "authorizationRules": _rules(reader, request, rid, entity_type)})
    return entities


def _namespace(reader, request, row, scope):
    if not isinstance(row, dict):
        raise ValueError("malformed Relay namespace")
    rid, name = row.get("id"), row.get("name")
    if (not isinstance(rid, str) or not isinstance(name, str) or not name
            or re.fullmatch(re.escape(scope) + r"/resourceGroups/[^/?#%\\\s]+/providers/Microsoft\.Relay/namespaces/[^/?#%\\\s]+", rid, re.I) is None
            or name.casefold() != rid.rsplit("/", 1)[-1].casefold()
            or str(row.get("type", "")).casefold() != NAMESPACE.casefold()):
        raise ValueError("foreign Relay namespace")
    props = row.get("properties")
    if not isinstance(props, dict):
        raise ValueError("malformed Relay namespace properties")
    endpoint = props.get("serviceBusEndpoint")
    parsed = urlsplit(endpoint) if isinstance(endpoint, str) else None
    if (parsed is None or parsed.scheme != "https" or parsed.hostname != name.casefold() + ".servicebus.windows.net"
            or parsed.port not in (None, 443) or parsed.username or parsed.password
            or parsed.path not in ("", "/") or parsed.query or parsed.fragment):
        raise ValueError("Relay namespace endpoint does not match ARM identity")
    safe = {"publicNetworkAccess": props.get("publicNetworkAccess") if props.get("publicNetworkAccess") in
            ("Enabled", "Disabled", "SecuredByPerimeter") else None,
            "provisioningState": props.get("provisioningState") if props.get("provisioningState") in
            ("Succeeded", "Creating", "Updating", "Deleting", "Failed") else None,
            "serviceBusEndpoint": endpoint,
            "privateEndpointConnections": _connections(props)}
    return {"properties": safe,
            "authorizationRules": _rules(reader, request, rid, NAMESPACE),
            "hybridConnections": _entities(reader, request, rid, "hybridConnections"),
            "wcfRelays": _entities(reader, request, rid, "wcfRelays")}


def collect(reader, request, scopes, wanted):
    if KIND not in wanted:
        return
    # The generic ARM inventory already performed the namespace LIST and GET.
    # Reuse those parents and append only child reads; no second namespace read.
    for collection in reader.collections:
        if collection.get("type") != KIND or collection.get("status") not in ("collected", "partial"):
            continue
        scope = collection["scope"]
        for row in collection["items"]:
            try:
                row["relayExposure"] = _namespace(reader, request, row, scope)
                row.setdefault("_coverage", {})["relayExposure"] = {"status": "collected"}
            except Exception as exc:
                row.pop("relayExposure", None)
                row.setdefault("_coverage", {})["relayExposure"] = {
                    "status": "unknown", "error": {"code": str(getattr(exc, "code", "read_failed"))}}
