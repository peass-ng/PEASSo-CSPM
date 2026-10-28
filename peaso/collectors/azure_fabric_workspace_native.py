"""Read-only Fabric workspace role inventory with tenant-wide parent discovery."""
from __future__ import annotations

import re

KIND = "fabric_workspace"
ITEM_KIND = "fabric_item"
SHARE_KIND = "fabric_external_data_share"
AUDIENCE = "https://api.fabric.microsoft.com"
BASE = AUDIENCE + "/v1"
_GUID = re.compile(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", re.I)
_ROLES = {"Admin", "Member", "Contributor", "Viewer"}
_PRINCIPALS = {"User", "Group", "ServicePrincipal", "ServicePrincipalProfile", "EntireTenant"}


def _pages(reader, request, path, key):
    """Fabric continuation URIs are bound to the exact read-only list route."""
    from urllib.parse import urlsplit, parse_qs

    url = BASE + path
    seen = set()
    count = 0
    while reader.budget.max_pages is None or count < reader.budget.max_pages:
        reader.check_cancelled()
        response = reader.call(request, url, audience=AUDIENCE)
        count += 1
        if not isinstance(response, dict) or not isinstance(response.get(key), list):
            raise ValueError("malformed Fabric list response")
        yield response[key]
        uri, token = response.get("continuationUri"), response.get("continuationToken")
        if not uri and not token:
            return
        if not isinstance(uri, str) or not isinstance(token, str) or not token or token in seen:
            raise ValueError("malformed Fabric continuation")
        parsed = urlsplit(uri)
        if (parsed.scheme != "https" or parsed.netloc != "api.fabric.microsoft.com"
                or parsed.path != "/v1" + path or parsed.username or parsed.password or parsed.fragment
                or set(parse_qs(parsed.query)) != {"continuationToken"}):
            raise ValueError("untrusted Fabric continuation")
        seen.add(token)
        url = uri
    raise ValueError("Fabric page limit")


def _grant(raw, *, item=False):
    if not isinstance(raw, dict):
        raise ValueError("malformed Fabric workspace access detail")
    principal = raw.get("principal")
    if not isinstance(principal, dict) or principal.get("type") not in _PRINCIPALS:
        raise ValueError("malformed Fabric role assignment principal")
    kind = principal["type"]
    principal_id = principal.get("id")
    if not isinstance(principal_id, str) or not _GUID.fullmatch(principal_id):
        raise ValueError("malformed Fabric principal identity")
    access = raw.get("itemAccessDetails" if item else "workspaceAccessDetails")
    if not isinstance(access, dict) or not isinstance(access.get("type"), str):
        raise ValueError("malformed Fabric access type")
    if item:
        permissions = access.get("permissions") or []
        additional = access.get("additionalPermissions") or []
        if (not isinstance(permissions, list) or not isinstance(additional, list)
                or any(not isinstance(value, str) or not value for value in permissions + additional)):
            raise ValueError("malformed Fabric item permissions")
        role = ",".join(sorted(set(permissions + additional)))
        if not role:
            return None
    else:
        if access.get("type") not in ("Workspace", "Personal", "AdminWorkspace") or access.get("workspaceRole") not in _ROLES:
            raise ValueError("malformed Fabric workspace role")
        role = access["workspaceRole"]
    parent_id = None
    parent_type = None
    if kind == "ServicePrincipalProfile":
        details = principal.get("servicePrincipalProfileDetails")
        parent = details.get("parentPrincipal") if isinstance(details, dict) else None
        if (not isinstance(parent, dict) or parent.get("type") not in _PRINCIPALS
                or not isinstance(parent.get("id"), str) or not _GUID.fullmatch(parent["id"])):
            raise ValueError("malformed Fabric service principal profile parent")
        parent_id = parent["id"].lower()
        parent_type = parent["type"]
    return {"principal_type": kind, "principal_id": principal_id.lower(),
            "parent_principal_id": parent_id, "parent_principal_type": parent_type,
            "role": role}


def collect(reader, request, wanted, tenant_scope):
    if KIND not in wanted:
        return

    def workspaces():
        seen = set()
        for page in _pages(reader, request, "/admin/workspaces", "workspaces"):
            for raw in page:
                wid = raw.get("id") if isinstance(raw, dict) else None
                if not isinstance(wid, str) or not _GUID.fullmatch(wid) or wid.lower() in seen:
                    raise ValueError("malformed or duplicate Fabric workspace identity")
                seen.add(wid.lower())
                state = raw.get("state")
                if state not in ("Active", "Deleted"):
                    raise ValueError("malformed Fabric workspace state")
                if state == "Deleted":
                    continue
                grants = []
                grant_status = "collected"
                try:
                    response = reader.call(request, BASE + "/admin/workspaces/" + wid + "/users", audience=AUDIENCE)
                    if not isinstance(response, dict) or not isinstance(response.get("accessDetails"), list):
                        raise ValueError("malformed Fabric workspace access response")
                    grants = [_grant(item) for item in response["accessDetails"]]
                    if len({(item["principal_type"], item["principal_id"], item["role"]) for item in grants}) != len(grants):
                        raise ValueError("duplicate Fabric workspace grant")
                except Exception as exc:
                    status = getattr(exc, "status_code", None) or getattr(exc, "status", None) or getattr(exc, "code", None)
                    if status not in (401, 403, 404, "401", "403", "404") and not isinstance(exc, PermissionError):
                        raise
                    # Permission failure or concurrent deletion leaves the
                    # parent visible, with its ACL explicitly unresolved.
                    grants = []
                    grant_status = "unavailable"
                yield [{"id": "fabric-workspace://" + wid.lower(),
                        "workspace_id": wid.lower(), "state": state,
                        "role_assignments": grants, "role_assignments_status": grant_status}]

    reader.run([(KIND, tenant_scope, "Microsoft Fabric", workspaces)])


def collect_items(reader, request, wanted, tenant_scope):
    if ITEM_KIND not in wanted:
        return

    def items():
        seen = set()
        for page in _pages(reader, request, "/admin/items", "itemEntities"):
            for raw in page:
                iid = raw.get("id") if isinstance(raw, dict) else None
                wid = raw.get("workspaceId") if isinstance(raw, dict) else None
                kind = raw.get("type") if isinstance(raw, dict) else None
                if (not isinstance(iid, str) or not _GUID.fullmatch(iid)
                        or not isinstance(wid, str) or not _GUID.fullmatch(wid)
                        or not isinstance(kind, str) or not re.fullmatch(r"[A-Za-z][A-Za-z0-9]*", kind)
                        or iid.lower() in seen):
                    raise ValueError("malformed or duplicate Fabric item identity")
                seen.add(iid.lower())
                endpoint = BASE + "/admin/workspaces/" + wid + "/items/" + iid + "/users"
                if kind in {"Report", "Dashboard", "SemanticModel", "App", "Dataflow"}:
                    endpoint += "?type=" + kind
                try:
                    response = reader.call(request, endpoint, audience=AUDIENCE)
                    if not isinstance(response, dict) or not isinstance(response.get("accessDetails"), list):
                        raise ValueError("malformed Fabric item access response")
                    grants = [_grant(item, item=True) for item in response["accessDetails"]]
                    grants = [item for item in grants if item is not None]
                    grant_status = "collected"
                except Exception as exc:
                    status = getattr(exc, "status_code", None) or getattr(exc, "status", None) or getattr(exc, "code", None)
                    if status not in (401, 403, 404, "401", "403", "404") and not isinstance(exc, PermissionError):
                        raise
                    grants = []
                    grant_status = "unavailable"
                yield [{"id": "fabric-item://" + wid.lower() + "/" + iid.lower(),
                        "workspace_id": wid.lower(), "item_id": iid.lower(), "item_type": kind,
                        "role_assignments": grants, "role_assignments_status": grant_status}]

    reader.run([(ITEM_KIND, tenant_scope, "Microsoft Fabric", items)])


def collect_external_shares(reader, request, wanted, tenant_scope):
    if SHARE_KIND not in wanted:
        return

    def shares():
        seen = set()
        for page in _pages(reader, request, "/admin/items/externalDataShares", "value"):
            output = []
            for raw in page:
                sid = raw.get("id") if isinstance(raw, dict) else None
                if not isinstance(sid, str) or not _GUID.fullmatch(sid) or sid.lower() in seen:
                    raise ValueError("malformed or duplicate Fabric external share")
                seen.add(sid.lower())
                wid, iid = raw.get("workspaceId"), raw.get("itemId")
                if (not isinstance(wid, str) or not _GUID.fullmatch(wid)
                        or not isinstance(iid, str) or not _GUID.fullmatch(iid)):
                    raise ValueError("malformed Fabric shared item identity")
                status = raw.get("status")
                if status not in ("Pending", "Active", "Revoked", "InvitationExpired"):
                    raise ValueError("malformed Fabric external share status")
                accepted = raw.get("acceptedByTenantId")
                if accepted is not None and (not isinstance(accepted, str) or not _GUID.fullmatch(accepted)):
                    raise ValueError("malformed Fabric recipient tenant")
                recipient = raw.get("recipient")
                if not isinstance(recipient, dict) or recipient.get("type", "User") not in ("User", "ServicePrincipal"):
                    raise ValueError("malformed Fabric external share recipient")
                recipient_tenant = recipient.get("tenantId")
                if recipient_tenant is not None and (not isinstance(recipient_tenant, str) or not _GUID.fullmatch(recipient_tenant)):
                    raise ValueError("malformed Fabric recipient tenant")
                output.append({"id": "fabric-external-share://" + sid.lower(),
                               "workspace_id": wid.lower(), "item_id": iid.lower(),
                               "status": status,
                               "recipient_type": recipient.get("type", "User"),
                               "recipient_tenant_id": recipient_tenant.lower() if recipient_tenant else None,
                               "accepted_by_tenant_id": accepted.lower() if accepted else None,
                               "shared_path_count": len(raw.get("paths")) if isinstance(raw.get("paths"), list) else None})
            yield output

    reader.run([(SHARE_KIND, tenant_scope, "Microsoft Fabric", shares)])
