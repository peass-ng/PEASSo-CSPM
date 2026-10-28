"""Credential-free Sentinel source-control and federation inventory."""
from __future__ import annotations

import re
from urllib.parse import urlsplit

from .azure_sentinel_metadata_native import ARM, VERSION, _WORKSPACE

KIND = "sentinel_source_control"
_SOURCE = re.compile(r"/providers/Microsoft\.SecurityInsights/sourcecontrols/[^/?#%\s]+$", re.I)
_GUID = re.compile(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", re.I)


def _host(url):
    parsed = urlsplit(url) if isinstance(url, str) else None
    if (parsed is None or parsed.scheme != "https" or not parsed.hostname or parsed.username
            or parsed.password or parsed.port not in (None, 443) or not re.fullmatch(r"[A-Za-z0-9.-]+", parsed.hostname)):
        raise ValueError("Sentinel repository or issuer URL malformed")
    return parsed.hostname.lower()


def _tenant(value):
    if value is None:
        return None
    if not isinstance(value, str) or not _GUID.fullmatch(value):
        raise ValueError("Sentinel source-control tenant malformed")
    return value.lower()


def _project(raw, workspace):
    if not isinstance(raw, dict):
        raise ValueError("malformed Sentinel source control")
    rid = raw.get("id")
    prefix = workspace + "/providers/Microsoft.SecurityInsights/sourcecontrols/"
    if not isinstance(rid, str) or not _SOURCE.search(rid) or not rid.casefold().startswith(prefix.casefold()):
        raise ValueError("foreign Sentinel source control")
    props = raw.get("properties")
    if not isinstance(props, dict):
        raise ValueError("Sentinel source-control properties missing")
    repo_type = props.get("repoType")
    repository = props.get("repository")
    if repo_type not in ("Github", "AzureDevOps") or not isinstance(repository, dict):
        raise ValueError("Sentinel repository metadata missing")
    content = props.get("contentTypes")
    if not isinstance(content, list) or any(not isinstance(item, str) for item in content):
        raise ValueError("Sentinel repository content types missing")
    principal = props.get("servicePrincipal")
    federation = props.get("workloadIdentityFederation")
    if principal is not None and not isinstance(principal, dict):
        raise ValueError("Sentinel repository service principal malformed")
    if federation is not None and not isinstance(federation, dict):
        raise ValueError("Sentinel repository federation malformed")
    return {"id": rid, "workspace_id": workspace, "repo_type": repo_type,
            "repo_host": _host(repository.get("url")), "content_types": sorted(set(content)),
            "service_principal_tenant": _tenant(principal.get("tenantId")) if principal else None,
            "federation_tenant": _tenant(federation.get("tenantId")) if federation else None,
            "federation_issuer_host": _host(federation.get("issuer")) if federation and federation.get("issuer") else None,
            "federation_present": bool(federation)}


def collect(reader, request, wanted):
    if KIND not in wanted:
        return
    sentinel = [row for row in reader.collections if row["type"] == "sentinel_workspace"]
    parents = sentinel if sentinel else [row for row in reader.collections if row["type"] == "log_analytics_workspace"]
    jobs = []
    for parent in parents:
        if parent["status"] not in ("collected", "empty"):
            reader.collections.append({"type": KIND, "scope": parent["scope"],
                                       "service": "Microsoft.SecurityInsights", "status": parent["status"],
                                       "items": [], "error": {"code": "workspace_inventory_incomplete"}})
            continue
        for item in parent["items"]:
            workspace = item.get("id")
            if not isinstance(workspace, str) or not _WORKSPACE.fullmatch(workspace):
                reader.collections.append({"type": KIND, "scope": parent["scope"],
                                           "service": "Microsoft.SecurityInsights", "status": "not_collected",
                                           "items": [], "error": {"code": "workspace_identity_unresolved"}})
                continue
            endpoint = ARM + workspace + "/providers/Microsoft.SecurityInsights/sourcecontrols?api-version=" + VERSION

            def controls(endpoint=endpoint, workspace=workspace, onboarded=bool(sentinel)):
                if not onboarded:
                    onboarding = ARM + workspace + "/providers/Microsoft.SecurityInsights/onboardingStates?api-version=" + VERSION
                    ready = False
                    for page in reader.pages(request, onboarding):
                        ready |= any(str(row.get("name", "")).casefold() == "default" for row in page)
                    if not ready:
                        yield []
                        return
                seen = set()
                for page in reader.pages(request, endpoint):
                    output = [_project(raw, workspace) for raw in page]
                    for row in output:
                        if row["id"].casefold() in seen:
                            raise ValueError("duplicate Sentinel source control")
                        seen.add(row["id"].casefold())
                    yield output

            jobs.append((KIND, workspace, "Microsoft.SecurityInsights", controls))
        if not parent["items"]:
            reader.collections.append({"type": KIND, "scope": parent["scope"],
                                       "service": "Microsoft.SecurityInsights", "status": "empty",
                                       "items": [], "parent_inventory": parent["type"]})
    reader.run(jobs)
