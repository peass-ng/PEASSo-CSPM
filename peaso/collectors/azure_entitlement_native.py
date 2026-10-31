"""Read exact Entra entitlement access-package group grants."""
from __future__ import annotations

from urllib.parse import quote


PARENT = "entitlement_access_package"
RESOURCE = "entitlement_access_package_resource"
CATALOG = "entitlement_catalog"
CATALOG_RESOURCE = "entitlement_catalog_resource"
ROLE_ASSIGNMENT = "entitlement_role_assignment"
KINDS = (PARENT, RESOURCE, CATALOG, CATALOG_RESOURCE, ROLE_ASSIGNMENT)
PATH = "/v1.0/identityGovernance/entitlementManagement/accessPackages"
CATALOG_PATH = "/v1.0/identityGovernance/entitlementManagement/catalogs"


def required_types(selected):
    needed = set()
    if RESOURCE in selected:
        needed.add(PARENT)
    if CATALOG_RESOURCE in selected:
        needed.add(CATALOG)
    return needed


def _bind_catalog_ids(reader, tenant_scope):
    """Graph v1.0 exposes a package's catalog only as the expanded ``catalog`` relationship."""
    for collection in reader.collections:
        if collection.get("type") != PARENT or collection.get("scope") != tenant_scope:
            continue
        for package in collection.get("items", ()):
            catalog = package.get("catalog") if isinstance(package, dict) else None
            if isinstance(catalog, dict) and isinstance(catalog.get("id"), str) and catalog["id"]:
                package.setdefault("catalogId", catalog["id"])


def collect(reader, request, wanted, tenant_scope, graph):
    _bind_catalog_ids(reader, tenant_scope)
    if CATALOG_RESOURCE in wanted:
        catalogs = [c for c in reader.collections if c.get("type") == CATALOG
                    and c.get("scope") == tenant_scope]
        catalog_parent = catalogs[0] if len(catalogs) == 1 else None
        if catalog_parent is None or catalog_parent.get("status") not in ("collected", "empty", "partial"):
            reader.collections.append({"type": CATALOG_RESOURCE, "scope": tenant_scope,
                "service": "Microsoft.Graph", "status": catalog_parent.get("status", "not_collected")
                if catalog_parent else "not_collected", "items": [], "parent_inventory": CATALOG})
        else:
            catalog_jobs = []
            for catalog in catalog_parent.get("items", ()):
                if not isinstance(catalog, dict) or not isinstance(catalog.get("id"), str) or not catalog["id"]:
                    continue
                catalog_id = catalog["id"]
                url = graph + CATALOG_PATH + "/" + quote(catalog_id, safe="") + "/resources?$expand=roles,scopes"
                def resources(url=url, catalog_id=catalog_id):
                    for page in reader.pages(request, url, audience=graph, next_key="@odata.nextLink"):
                        rows = []
                        for item in page:
                            if (not isinstance(item, dict) or not isinstance(item.get("id"), str)
                                    or not isinstance(item.get("originId"), str)
                                    or not isinstance(item.get("originSystem"), str)
                                    or not isinstance(item.get("roles"), list)):
                                raise ValueError("incomplete catalog resource or role inventory")
                            rows.append({**item, "catalogId": catalog_id})
                        yield rows
                catalog_jobs.append((CATALOG_RESOURCE, tenant_scope + "/catalogs/" + catalog_id,
                                     "Microsoft.Graph", resources))
            if catalog_jobs:
                reader.run(catalog_jobs)
            if not catalog_jobs or catalog_parent.get("status") == "partial":
                reader.collections.append({"type": CATALOG_RESOURCE, "scope": tenant_scope,
                    "service": "Microsoft.Graph", "status": "partial" if catalog_parent.get("status") == "partial" else "empty",
                    "items": [], "parent_inventory": CATALOG})
    if RESOURCE not in wanted:
        return
    parents = [c for c in reader.collections if c.get("type") == PARENT
               and c.get("scope") == tenant_scope]
    parent = parents[0] if len(parents) == 1 else None
    if parent is None or parent.get("status") not in ("collected", "empty", "partial"):
        reader.collections.append({"type": RESOURCE, "scope": tenant_scope,
            "service": "Microsoft.Graph", "status": parent.get("status", "not_collected")
            if parent else "not_collected", "items": [], "parent_inventory": PARENT})
        return
    jobs = []
    for package in parent.get("items", ()):
        if not isinstance(package, dict) or not isinstance(package.get("id"), str) or not package["id"]:
            continue
        package_id = package["id"]
        catalog_id = package.get("catalogId")
        url = graph + PATH + "/" + quote(package_id, safe="") + "?$expand=resourceRoleScopes($expand=role,scope)"
        def role_scopes(url=url, package_id=package_id, catalog_id=catalog_id):
            detail = reader.call(request, url, audience=graph)
            if (not isinstance(detail, dict) or detail.get("id") != package_id
                    or not isinstance(detail.get("resourceRoleScopes"), list)
                    or detail.get("resourceRoleScopes@odata.nextLink")):
                raise ValueError("incomplete access package resource role scopes")
            rows = []
            for item in detail["resourceRoleScopes"]:
                if not isinstance(item, dict):
                    raise ValueError("malformed access package resource role scope")
                role, scope = item.get("role"), item.get("scope")
                if not isinstance(role, dict) or not isinstance(scope, dict):
                    raise ValueError("missing access package role or scope")
                origin = scope.get("originId")
                role_name = role.get("displayName")
                if not isinstance(origin, str) or not origin or not isinstance(role_name, str):
                    raise ValueError("missing access package group role identity")
                rows.append({"id": str(item.get("id") or package_id + ":" + origin + ":" + role_name),
                    "accessPackageId": package_id, "catalogId": catalog_id,
                    "originId": origin, "originSystem": scope.get("originSystem"),
                    "roleName": role_name, "roleOriginId": role.get("originId")})
            yield rows
        jobs.append((RESOURCE, tenant_scope + "/accessPackages/" + package_id,
                     "Microsoft.Graph", role_scopes))
    if jobs:
        reader.run(jobs)
    if not jobs or parent.get("status") == "partial":
        reader.collections.append({"type": RESOURCE, "scope": tenant_scope,
            "service": "Microsoft.Graph", "status": "partial" if parent.get("status") == "partial" else "empty", "items": [],
            "parent_inventory": PARENT})
