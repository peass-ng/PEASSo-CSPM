"""Cached read-only Mongo cluster firewall, private link, and data grant inventory."""
from __future__ import annotations

import re

from .azure_mongo_cluster_metadata import project_private_connections


ARM = "https://management.azure.com"
VERSION = "2026-06-01"
KIND = "mongo_cluster"


def _rows(reader, request, parent_id, field):
    seen, projected = set(), []
    url = ARM + parent_id + "/" + field + "?api-version=" + VERSION
    for page in reader.pages(request, url):
        for row in page:
            rid = row.get("id") if isinstance(row, dict) else None
            if (not isinstance(rid, str) or re.fullmatch(re.escape(parent_id + "/" + field + "/") + r"[^/?#%\\\s]+", rid, re.I) is None
                    or rid.casefold() in seen or str(row.get("type", "")).casefold() !=
                    ("Microsoft.DocumentDB/mongoClusters/" + field).casefold()):
                raise ValueError("foreign or duplicate Mongo cluster child")
            seen.add(rid.casefold())
            props = row.get("properties")
            if field == "firewallRules":
                if not isinstance(props, dict):
                    raise ValueError("malformed Mongo firewall rule")
                projected.append({"id": rid, "name": row.get("name"),
                                  "startIpAddress": props.get("startIpAddress"),
                                  "endIpAddress": props.get("endIpAddress")})
            elif field == "privateEndpointConnections":
                projected.extend(project_private_connections([row], parent_id))
            elif field == "users":
                identity = props.get("identityProvider") if isinstance(props, dict) else None
                roles = props.get("roles") if isinstance(props, dict) else None
                if (not isinstance(identity, dict) or identity.get("type") != "MicrosoftEntraID"
                        or not isinstance(roles, list) or any(
                            not isinstance(role, dict) or not isinstance(role.get("db"), str)
                            or not isinstance(role.get("role"), str) for role in roles)):
                    raise ValueError("malformed Mongo data grant")
                projected.append({"id": rid, "principalType": (identity.get("properties") or {}).get("principalType"),
                                  "roles": [{"db": role["db"], "role": role["role"]} for role in roles]})
    return projected


def collect(reader, request, scopes, wanted):
    if KIND not in wanted:
        return
    for collection in reader.collections:
        if collection.get("type") != KIND or collection.get("status") not in ("collected", "partial"):
            continue
        for row in collection["items"]:
            rid = row.get("id")
            if not isinstance(rid, str):
                continue
            exposure = row.setdefault("mongoExposure", {})
            coverage = row.setdefault("_coverage", {})
            for field in ("firewallRules", "privateEndpointConnections", "users"):
                if field == "privateEndpointConnections":
                    props = row.get("properties") or {}
                    embedded_coverage = (props.get("_coverage") or {}).get(field) or {}
                    if embedded_coverage.get("status") == "collected":
                        exposure[field] = props[field]
                        coverage[field] = {"status": "collected", "source": "parent_get"}
                        props.pop(field, None)
                        continue
                    if embedded_coverage.get("status") == "malformed":
                        coverage[field] = {"status": "malformed"}
                        continue
                try:
                    exposure[field] = _rows(reader, request, rid, field)
                    coverage[field] = {"status": "collected"}
                except Exception as exc:
                    exposure.pop(field, None)
                    coverage[field] = {"status": "unknown", "error": {"code": str(getattr(exc, "code", "read_failed"))}}
