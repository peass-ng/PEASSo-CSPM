"""Retain the Mongo cluster state needed for access analysis without credentials."""
from __future__ import annotations

import re


def project_private_connections(rows, parent_id):
    if not isinstance(rows, list):
        raise ValueError("malformed Mongo private endpoint list")
    seen, safe = set(), []
    for row in rows:
        rid = row.get("id") if isinstance(row, dict) else None
        props = row.get("properties") if isinstance(row, dict) else None
        endpoint = props.get("privateEndpoint") if isinstance(props, dict) else None
        state = props.get("privateLinkServiceConnectionState") if isinstance(props, dict) else None
        remote = endpoint.get("id") if isinstance(endpoint, dict) else None
        if (not isinstance(rid, str) or re.fullmatch(re.escape(parent_id + "/privateEndpointConnections/") + r"[^/?#%\\\s]+", rid, re.I) is None
                or rid.casefold() in seen
                or str(row.get("type", "")).casefold() != "microsoft.documentdb/mongoclusters/privateendpointconnections"
                or not isinstance(props, dict) or not isinstance(remote, str) or re.fullmatch(
                    r"/subscriptions/[^/]+/resourceGroups/[^/]+/providers/Microsoft\.Network/privateEndpoints/[^/]+", remote, re.I) is None):
            raise ValueError("foreign or malformed Mongo private endpoint")
        seen.add(rid.casefold())
        safe.append({"id": rid, "privateEndpointId": remote,
                     "status": state.get("status") if isinstance(state, dict) else None,
                     "provisioningState": props.get("provisioningState")})
    return safe


def project(row):
    if not isinstance(row, dict) or not isinstance(row.get("properties"), dict):
        raise ValueError("Mongo cluster detail has no properties")
    props = row["properties"]
    safe = {key: props[key] for key in (
        "provisioningState", "clusterStatus", "createMode", "publicNetworkAccess", "networkBypassMode") if key in props}
    data_api = props.get("dataApi")
    if isinstance(data_api, dict):
        safe["dataApi"] = {"mode": data_api.get("mode")}
    if "privateEndpointConnections" in props:
        try:
            safe["privateEndpointConnections"] = project_private_connections(props["privateEndpointConnections"], row["id"])
            safe.setdefault("_coverage", {})["privateEndpointConnections"] = {"status": "collected"}
        except ValueError:
            safe.setdefault("_coverage", {})["privateEndpointConnections"] = {"status": "malformed"}
    replica = props.get("replicaParameters")
    if isinstance(replica, dict) and "sourceResourceId" in replica:
        safe["replicaParameters"] = {"sourceResourceId": replica["sourceResourceId"]}
    auth = props.get("authConfig")
    if isinstance(auth, dict) and "allowedModes" in auth:
        safe["authConfig"] = {"allowedModes": auth["allowedModes"]}
    return {key: row[key] for key in ("id", "type", "name", "location", "_provenance") if key in row} | {
        "properties": safe}
