"""Directory membership child routing when the Graph group parent is absent or incomplete."""

from urllib.parse import urlsplit

import pytest

from peaso.collectors import azure


TENANT = "22222222-2222-2222-2222-222222222222"
SUBSCRIPTION = "11111111-1111-1111-1111-111111111111"
GROUP = "33333333-3333-3333-3333-333333333333"
MEMBER = "44444444-4444-4444-4444-444444444444"
TENANT_SCOPE = "/tenants/" + TENANT
GROUP_PATH = "/v1.0/groups"
MEMBERS_PATH = GROUP_PATH + "/" + GROUP + "/members"


class StubGraph:
    tenant = verified_tenant = TENANT

    def __init__(self, group_response, member_response=None):
        self.group_response = group_response
        self.member_response = member_response or {"value": []}
        self.calls = []

    def request(self, url, *, body=None, audience=azure.ARM):
        assert body is None and audience == azure.GRAPH
        path = urlsplit(url).path
        self.calls.append(path)
        if path == GROUP_PATH:
            response = self.group_response
        elif path == MEMBERS_PATH:
            response = self.member_response
        else:
            raise AssertionError("unexpected Graph route: " + path)
        if isinstance(response, Exception):
            raise response
        return response


def collect(group_response, member_response=None):
    api = StubGraph(group_response, member_response)
    snapshot = azure.collect(
        {"scopes": [SUBSCRIPTION], "options": {"retries": 0}},
        ["directory_membership"], transport=api,
    )
    groups = [row for row in snapshot["collections"] if row["type"] == "directory_group"]
    members = [row for row in snapshot["collections"] if row["type"] == "directory_membership"]
    assert len(groups) == 1 and groups[0]["scope"] == TENANT_SCOPE
    return api, groups[0], members


def test_complete_empty_group_inventory_emits_empty_tenant_membership():
    api, parent, children = collect({"value": []})
    assert parent["status"] == "empty"
    assert len(children) == 1
    child = children[0]
    assert {key: child[key] for key in ("type", "scope", "service", "status", "items", "parent_inventory")} == {
        "type": "directory_membership", "scope": TENANT_SCOPE,
        "service": "Microsoft.Graph", "status": "empty", "items": [],
        "parent_inventory": "directory_group"}
    assert child["_provenance"]["tenant_id"] == TENANT
    assert child["_provenance"]["tenant_verified"] is True
    assert api.calls == [GROUP_PATH]


@pytest.mark.parametrize("response, parent_status", [
    (azure.AzureReadError("denied", 403), "denied"),
    (azure.AzureReadError("unavailable", 500), "unknown"),
])
def test_unavailable_group_inventory_emits_unavailable_tenant_membership(response, parent_status):
    api, parent, children = collect(response)
    assert parent["status"] == parent_status
    assert len(children) == 1
    child = children[0]
    assert child["scope"] == TENANT_SCOPE and child["service"] == "Microsoft.Graph"
    assert child["status"] == parent_status and child["items"] == []
    assert child["parent_inventory"] == "directory_group"
    assert child["error"]["code"] == "parent_inventory_unavailable"
    assert api.calls == [GROUP_PATH]


@pytest.mark.parametrize("group_types, visibility", [
    (["DynamicMembership"], "Private"),
    ([], "HiddenMembership"),
])
def test_partial_group_parent_keeps_child_and_unavailable_tenant_envelope(group_types, visibility):
    group = {"id": GROUP, "groupTypes": group_types, "visibility": visibility}
    def first_page_then_denial(url):
        if "page=2" in url:
            raise azure.AzureReadError("denied", 403)
        return {"value": [group], "@odata.nextLink": azure.GRAPH + GROUP_PATH + "?page=2"}

    class PartialGraph(StubGraph):
        def request(self, url, *, body=None, audience=azure.ARM):
            if urlsplit(url).path == GROUP_PATH:
                self.calls.append(GROUP_PATH)
                return first_page_then_denial(url)
            return super().request(url, body=body, audience=audience)

    api = PartialGraph(None, {"value": [{"id": MEMBER}]})
    snapshot = azure.collect({"scopes": [SUBSCRIPTION], "options": {"retries": 0}},
                             ["directory_membership"], transport=api)
    parent = next(row for row in snapshot["collections"] if row["type"] == "directory_group")
    children = [row for row in snapshot["collections"] if row["type"] == "directory_membership"]
    assert parent["status"] == "partial" and len(parent["items"]) == 1
    by_scope = {row["scope"]: row for row in children}
    assert set(by_scope) == {TENANT_SCOPE, TENANT_SCOPE + "/groups/" + GROUP}
    assert by_scope[TENANT_SCOPE]["status"] == "partial"
    assert by_scope[TENANT_SCOPE]["items"] == []
    assert by_scope[TENANT_SCOPE]["parent_inventory"] == "directory_group"
    assert by_scope[TENANT_SCOPE]["error"]["code"] == "parent_inventory_unavailable"
    member_child = by_scope[TENANT_SCOPE + "/groups/" + GROUP]
    assert member_child["status"] == "partial"
    assert member_child["error"]["code"] == "dynamic_or_hidden_membership_unresolved"
    assert len(member_child["items"]) == 1
    assert member_child["items"][0]["id"] == MEMBER
    assert member_child["items"][0]["_provenance"]["tenant_id"] == TENANT
    assert member_child["items"][0]["_provenance"]["tenant_verified"] is True
    assert api.calls == [GROUP_PATH, GROUP_PATH, MEMBERS_PATH]


def test_role_assignment_scan_uses_beta_membership_for_service_principals():
    class ExposureGraph:
        tenant = verified_tenant = TENANT

        def __init__(self):
            self.calls = []

        def request(self, url, *, body=None, audience=azure.ARM):
            path = urlsplit(url).path
            self.calls.append(path)
            if path == GROUP_PATH:
                return {"value": [{"id": GROUP}]}
            if path == "/beta/groups/" + GROUP + "/members":
                assert audience == azure.GRAPH
                return {"value": [{"id": MEMBER, "@odata.type": "#microsoft.graph.servicePrincipal"}]}
            return {"value": []}

    api = ExposureGraph()
    snapshot = azure.collect({"scopes": [SUBSCRIPTION], "options": {"retries": 0}},
                             ["directory_membership", "role_assignment"], transport=api)
    child = next(row for row in snapshot["collections"] if row["type"] == "directory_membership")
    assert child["items"][0]["id"] == MEMBER
    assert child["status"] == "collected"
    assert "/beta/groups/" + GROUP + "/members" in api.calls
    assert MEMBERS_PATH not in api.calls
