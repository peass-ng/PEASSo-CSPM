"""The bounded Graph collector preserves exact package-to-group role scopes."""
from __future__ import annotations

import importlib.util
from pathlib import Path


PATH = Path(__file__).resolve().parents[1] / "peaso/collectors/azure_entitlement_native.py"
SPEC = importlib.util.spec_from_file_location("azure_entitlement_native_test", PATH)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)
T = "/tenants/t"


class Reader:
    def __init__(self, status="collected", rows=None):
        self.collections = [{"type": MODULE.PARENT, "scope": T, "service": "Microsoft.Graph",
            "status": status, "items": rows if rows is not None else [{"id": "ap1", "catalogId": "cat1"}]}]
        self.urls = []

    def call(self, request, url, *, audience):
        self.urls.append(url)
        return {"id": "ap1", "resourceRoleScopes": [{"id": "rrs1",
            "role": {"displayName": "Member", "originId": "Member_g-in"},
            "scope": {"originId": "g-in", "originSystem": "AadGroup"}}]}

    def pages(self, request, url, *, audience, next_key):
        self.urls.append(url)
        yield [{"id": "resource1", "originId": "g-in", "originSystem": "AadGroup",
                "roles": [{"displayName": "Member"}], "scopes": []}]

    def run(self, jobs):
        for kind, scope, service, fetch in jobs:
            rows = [row for page in fetch() for row in page]
            self.collections.append({"type": kind, "scope": scope, "service": service,
                                     "status": "collected" if rows else "empty", "items": rows})


def test_exact_package_role_scope_is_recorded():
    reader = Reader()
    MODULE.collect(reader, object(), {MODULE.RESOURCE}, T, "https://graph.microsoft.com")
    child = reader.collections[1]
    assert child["scope"] == f"{T}/accessPackages/ap1"
    assert child["items"][0] == {"id": "rrs1", "accessPackageId": "ap1",
        "catalogId": "cat1", "originId": "g-in", "originSystem": "AadGroup",
        "roleName": "Member", "roleOriginId": "Member_g-in"}
    assert reader.urls == ["https://graph.microsoft.com/v1.0/identityGovernance/entitlementManagement/accessPackages/ap1?$expand=resourceRoleScopes($expand=role,scope)"]


def test_denied_or_partial_parent_preserves_uncertainty():
    denied = Reader(status="access_denied")
    MODULE.collect(denied, object(), {MODULE.RESOURCE}, T, "https://graph.microsoft.com")
    assert denied.collections[1]["status"] == "access_denied"
    assert not denied.urls
    partial = Reader(status="partial")
    MODULE.collect(partial, object(), {MODULE.RESOURCE}, T, "https://graph.microsoft.com")
    assert partial.collections[1]["status"] == "collected"
    assert partial.collections[2]["status"] == "partial"


def test_catalog_resource_roles_are_collected_per_catalog():
    reader = Reader()
    reader.collections.append({"type": MODULE.CATALOG, "scope": T, "status": "collected",
                               "items": [{"id": "cat1"}]})
    MODULE.collect(reader, object(), {MODULE.CATALOG_RESOURCE}, T, "https://graph.microsoft.com")
    child = reader.collections[-1]
    assert child["type"] == MODULE.CATALOG_RESOURCE
    assert child["items"][0]["catalogId"] == "cat1"
    assert child["items"][0]["roles"] == [{"displayName": "Member"}]
    assert reader.urls == ["https://graph.microsoft.com/v1.0/identityGovernance/entitlementManagement/catalogs/cat1/resources?$expand=roles,scopes"]


def test_expanded_v1_catalog_relationship_binds_the_package_catalog():
    reader = Reader(rows=[{"id": "ap1", "displayName": "p", "catalog": {"id": "cat1"}}])
    MODULE.collect(reader, object(), {MODULE.RESOURCE}, T, "https://graph.microsoft.com")
    assert reader.collections[0]["items"][0]["catalogId"] == "cat1"
    assert reader.collections[1]["items"][0]["catalogId"] == "cat1"

