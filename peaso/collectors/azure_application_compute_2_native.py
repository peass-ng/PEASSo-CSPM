"""Bound Synapse workspace SQL private-link declarations using native reads.

No connectivity, effective-access or log-delivery conclusions are produced.
The common reader owns call/page/resource/deadline limits and sanitized errors.
"""
from __future__ import annotations

import re

ARM = "https://management.azure.com"
KIND = "synapse_sql_private_endpoint_evidence"
NATIVE_TYPES = (KIND,)
WORKSPACE = r"/subscriptions/[^/?#%\s]+/resourceGroups/[^/?#%\s]+/providers/Microsoft\.Synapse/workspaces/[^/?#%\s]+"
ENDPOINT = r"/subscriptions/[^/?#%\s]+/resourceGroups/[^/?#%\s]+/providers/Microsoft\.Network/privateEndpoints/[^/?#%\s]+"


def _object(value):
    if not isinstance(value, dict):
        raise ValueError("native private endpoint object unavailable")
    return value


def _links(endpoint, workspace):
    props = _object(endpoint.get("properties"))
    if props.get("provisioningState") != "Succeeded":
        raise ValueError("private endpoint provisioning unresolved")
    links = props.get("privateLinkServiceConnections")
    if not isinstance(links, list) or not links or props.get("manualPrivateLinkServiceConnections"):
        raise ValueError("private endpoint connection form unresolved")
    seen, output = set(), []
    for link in links:
        link = _object(link)
        lid = link.get("id")
        if (not isinstance(lid, str) or not re.fullmatch(re.escape(endpoint["id"]) + r"/privateLinkServiceConnections/[^/?#%\s]+", lid, re.I)
                or lid.casefold() in seen):
            raise ValueError("foreign or duplicate private link service connection")
        seen.add(lid.casefold())
        fields = _object(link.get("properties"))
        target = fields.get("privateLinkServiceId")
        groups = fields.get("groupIds")
        state = _object(fields.get("privateLinkServiceConnectionState"))
        if (not isinstance(target, str) or target.casefold() != workspace.casefold() or
                not isinstance(groups, list) or not groups or any(not isinstance(group, str) or not group for group in groups) or
                state.get("status") != "Approved"):
            raise ValueError("private link target, group or approval unresolved")
        output.append({"id": lid, "properties": {"privateLinkServiceId": target, "groupIds": list(groups),
                                                    "privateLinkServiceConnectionState": {"status": state["status"]}}})
    return output


def _merge(parts):
    """One collection per subscription scope, even with several workspaces."""
    if len(parts) == 1:
        return parts[0]
    first = parts[0]
    items = [item for part in parts for item in part["items"]]
    failed = [part for part in parts if part["status"] not in ("collected", "empty")]
    if not failed:
        status = "collected" if items else "empty"
        return {"type": first["type"], "scope": first["scope"], "service": first["service"], "status": status, "items": items}
    merged = {"type": first["type"], "scope": first["scope"], "service": first["service"],
              "status": "partial" if items else failed[0]["status"], "items": items}
    error = next((part["error"] for part in failed if "error" in part), None)
    if error is not None:
        merged["error"] = error
    return merged

def required_types(wanted):
    return {"synapse_workspace"} if KIND in wanted else set()


def collect_synapse_sql_private_endpoints(reader, request, collections, wanted):
    if KIND not in wanted:
        return
    emitted = {}

    def emit(record):
        emitted.setdefault(record["scope"], []).append(record)

    for collection in list(collections):
        if collection["type"] != "synapse_workspace":
            continue
        scope = collection["scope"]
        if not collection["items"]:
            emit({"type": KIND, "scope": scope, "service": "Microsoft.Synapse",
                                       "status": collection["status"], "items": []})
        for item in collection["items"]:
            rid = item.get("id")
            if (not isinstance(rid, str) or not re.fullmatch(WORKSPACE, rid, re.I) or
                    not rid.casefold().startswith(scope.casefold() + "/") or
                    str(item.get("type", "")).casefold() != "microsoft.synapse/workspaces"):
                for field in ("privateEndpointConnections", "resolvedPrivateEndpoints"):
                    item.setdefault("_coverage", {})[field] = {"status": "not_collected", "error": {"code": "native_parent_identity_unresolved"}}
                emit({"type": KIND, "scope": scope, "service": "Microsoft.Synapse",
                                           "status": "not_collected", "items": [], "error": {"code": "native_parent_identity_unresolved"}})
                continue

            def connections(rid=rid):
                seen = set()
                for page in reader.pages(request, ARM + rid + "/privateEndpointConnections?api-version=2021-06-01"):
                    projected = []
                    for row in page:
                        row = _object(row)
                        identity = row.get("id")
                        if (not isinstance(identity, str) or not re.fullmatch(re.escape(rid) + r"/privateEndpointConnections/[^/?#%\s]+", identity, re.I)
                                or str(row.get("type", "")).casefold() != "microsoft.synapse/workspaces/privateendpointconnections"
                                or identity.casefold() in seen):
                            raise ValueError("foreign or duplicate Synapse endpoint connection")
                        seen.add(identity.casefold())
                        props = _object(row.get("properties"))
                        state = _object(props.get("privateLinkServiceConnectionState"))
                        if state.get("status") not in ("Approved", "Pending", "Rejected", "Disconnected"):
                            raise ValueError("unrecognized endpoint approval state")
                        endpoint = _object(props.get("privateEndpoint"))
                        eid = endpoint.get("id")
                        if (not isinstance(eid, str) or not re.fullmatch(ENDPOINT, eid, re.I) or
                                not eid.casefold().startswith(scope.casefold() + "/")):
                            raise ValueError("private endpoint outside selected subscription")
                        projected.append({"id": identity, "type": row["type"], "parent_id": rid,
                                          "properties": {"privateEndpoint": {"id": eid},
                                                         "privateLinkServiceConnectionState": {"status": state["status"]}}})
                    yield projected

            read = reader._read(("synapse_private_endpoint_connections", scope, "Microsoft.Synapse", connections))
            coverage = item.setdefault("_coverage", {})
            coverage["privateEndpointConnections"] = {key: read[key] for key in ("status", "error") if key in read}
            item["privateEndpointConnections"] = read["items"]

            def resolve(read=read, rid=rid, scope=scope):
                if read["status"] not in ("collected", "empty"):
                    raise ValueError("Synapse endpoint connection inventory incomplete")
                seen = set()
                for row in read["items"]:
                    if row["properties"]["privateLinkServiceConnectionState"]["status"] != "Approved":
                        continue
                    eid = row["properties"]["privateEndpoint"]["id"]
                    if eid.casefold() in seen:
                        continue
                    seen.add(eid.casefold())
                    value = reader.call(request, ARM + eid + "?api-version=2023-09-01")
                    value = _object(value)
                    if (not isinstance(value.get("id"), str) or value["id"].casefold() != eid.casefold() or
                            str(value.get("type", "")).casefold() != "microsoft.network/privateendpoints"):
                        raise ValueError("foreign private endpoint GET identity")
                    yield [{"id": value["id"], "type": value["type"],
                            "properties": {"privateLinkServiceConnections": _links(value, rid)},
                            "_provenance": {"source_operation": "PrivateEndpoints_Get", "read_only": True,
                                            "api_version": "2023-09-01", "workspace_id": rid, "scope": scope}}]

            resolved = reader._read(("synapse_resolved_private_endpoints", scope, "Microsoft.Network", resolve))
            coverage["resolvedPrivateEndpoints"] = {key: resolved[key] for key in ("status", "error") if key in resolved}
            item["resolvedPrivateEndpoints"] = resolved["items"]
            emit({"type": KIND, "scope": scope, "service": "Microsoft.Synapse",
                                       "status": "collected" if resolved["status"] in ("collected", "empty") else resolved["status"], "items": [{"id": rid, "parent_id": rid,
                                           "private_endpoint_connection_ids": [row["id"] for row in read["items"]],
                                           "resolved_private_endpoint_ids": [row["id"] for row in resolved["items"]],
                                           "_provenance": {"source_operation": "PrivateEndpointConnections_List+PrivateEndpoints_Get",
                                                           "read_only": True, "scope": scope}}] if resolved["status"] in ("collected", "empty") else [],
                                       **({"error": resolved["error"]} if "error" in resolved else {})})
    for parts in emitted.values():
        reader.collections.append(_merge(parts))
