"""Credential-free Defender EASM data connection inventory."""
from __future__ import annotations

import re
from urllib.parse import quote


KIND = "easm_data_connection"
AUDIENCE = "https://easm.defender.microsoft.com"
VERSION = "2024-10-01-preview"
_WORKSPACE = re.compile(r"^/subscriptions/([^/]+)/resourceGroups/([^/]+)/providers/Microsoft\.Easm/workspaces/([^/]+)$", re.I)
_REGION = re.compile(r"^[a-z0-9-]+$")


def collect(reader, request, wanted):
    if KIND not in wanted:
        return
    jobs = []
    parents = [row for row in reader.collections if row["type"] == "easm_workspace"]
    for parent in parents:
        for workspace in parent["items"]:
            rid = workspace.get("id")
            match = _WORKSPACE.fullmatch(rid) if isinstance(rid, str) else None
            region = workspace.get("location")
            if not match or not isinstance(region, str) or not _REGION.fullmatch(region.lower()):
                reader.collections.append({"type": KIND, "scope": rid or parent["scope"], "service": "Defender EASM",
                                           "status": "not_collected", "items": [], "error": {"code": "workspace_endpoint_unresolved"}})
                continue
            subscription, group, name = (quote(part, safe="") for part in match.groups())
            endpoint = (f"https://{region.lower()}.easm.defender.microsoft.com/subscriptions/{subscription}"
                        f"/resourceGroups/{group}/workspaces/{name}/dataConnections?api-version={VERSION}")

            def pages(endpoint=endpoint, rid=rid):
                seen = set()
                for page in reader.pages(request, endpoint, audience=AUDIENCE):
                    output = []
                    for raw in page:
                        if not isinstance(raw, dict) or not isinstance(raw.get("name"), str) or not raw["name"]:
                            raise ValueError("malformed EASM data connection identity")
                        name = raw["name"]
                        if name in seen or not re.fullmatch(r"[A-Za-z0-9_.-]+", name):
                            raise ValueError("duplicate or malformed EASM data connection name")
                        seen.add(name)
                        props = raw.get("properties")
                        if not isinstance(props, dict):
                            raise ValueError("missing EASM data connection properties")
                        kind = raw.get("kind")
                        safe = {"id": rid + "/dataConnections/" + name, "parent_id": rid,
                                "name": name, "kind": kind, "active": raw.get("active"),
                                "content": raw.get("content"), "frequency": raw.get("frequency")}
                        if kind == "logAnalytics":
                            safe["workspaceId"] = props.get("workspaceId")
                        elif kind == "azureDataExplorer":
                            safe.update({key: props.get(key) for key in ("clusterName", "databaseName", "region")})
                        else:
                            safe["destination_unknown"] = True
                        output.append(safe)
                    yield output

            jobs.append((KIND, rid, "Defender EASM", pages))
        if not parent["items"]:
            reader.collections.append({"type": KIND, "scope": parent["scope"], "service": "Defender EASM",
                                       "status": "empty" if parent["status"] == "empty" else parent["status"],
                                       "items": [], "parent_inventory": "easm_workspace"})
    reader.run(jobs)
