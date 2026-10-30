"""Portable transport -> native collector -> registered SW18 engine coverage."""
import copy
from http.client import HTTPConnection
from urllib.parse import parse_qs, urlsplit
from urllib.request import Request

import pytest

from peaso.collectors import azure
from peaso.engine import evaluate_snapshot
USER_MFA_ID = "azure.cis.multifactor_auth_status_non_privileged_users"

TENANT = "22222222-2222-2222-2222-222222222222"
USER = "33333333-3333-3333-3333-333333333333"
GROUP = "44444444-4444-4444-4444-444444444444"
ROLE = "55555555-5555-5555-5555-555555555555"
SUB = "/subscriptions/11111111-1111-1111-1111-111111111111"
OPAQUE = "lAPpYvVpN0KRkAEhdxReEJ2SvT9WjGJEhR4OuaezoqU-1"


class Denied(RuntimeError):
    status = 403


def run(monkeypatch, mode="ok", *, state="enabled", capable=True, role=False, seen=None):
    class Transport:
        tenant = verified_tenant = TENANT

        def close(self):
            pass

        def request(self, url, *, body=None, audience=azure.ARM):
            if seen is not None:
                seen.append(url)
            path = urlsplit(url).path.casefold()
            if audience == azure.GRAPH:
                if path == "/v1.0/users":
                    return {"value": [{"id": USER, "accountEnabled": mode != "disabled_user"}]}
                if path == "/v1.0/groups":
                    return {"value": [{"id": GROUP, "groupTypes": ["DynamicMembership"] if mode == "hidden_group" else [],
                                       "visibility": "Public", "isAssignableToRole": mode == "role_assignable_owner"}]}
                if path == "/v1.0/groups/" + GROUP + "/members":
                    if mode == "partial_group":
                        raise Denied()
                    return {"value": [] if mode in ("owner_only", "role_assignable_owner") else [{"id": USER}]}
                if path == "/v1.0/groups/" + GROUP + "/owners":
                    if mode == "owner_denied":
                        raise Denied()
                    if mode == "foreign_owner":
                        return {"value": [{"id": "foreign-owner"}]}
                    return {"value": [{"id": USER}]} if mode in ("owner_only", "role_assignable_owner") else {"value": []}
                if path == "/v1.0/users/" + USER + "/transitivememberof":
                    if mode in ("owner_only", "role_assignable_owner"):
                        return {"value": []}
                    return {"value": [{"id": GROUP, "@odata.type": "#microsoft.graph.group"}]}
                if path == "/v1.0/reports/authenticationmethods/userregistrationdetails":
                    values = [{"id": USER, "isMfaCapable": capable, "isMfaRegistered": True}]
                    if mode == "duplicate_registration":
                        values += copy.deepcopy(values)
                    return {"value": values}
                if path == "/v1.0/rolemanagement/directory/roledefinitions":
                    return {"value": [{"id": ROLE}]}
                if path == "/beta/rolemanagement/directory/roledefinitions":
                    if mode == "beta_unsupported":
                        raise RuntimeError("unsupported")
                    value = {"value": [{"id": ROLE, "isPrivileged": True}]}
                    if mode == "partial_beta":
                        value["@odata.nextLink"] = "https://evil.invalid/next"
                    return value
                if path == "/v1.0/rolemanagement/directory/roleassignments":
                    return {"value": [{"id": "66666666-6666-6666-6666-666666666666", "principalId": USER if role or mode == "opaque_permanent" else GROUP,
                                       "roleDefinitionId": ROLE, "directoryScopeId": "/"}]
                            if role or mode in ("group_role", "owner_only", "owner_denied", "foreign_owner", "opaque_permanent") else []}
                if path == "/v1.0/rolemanagement/directory/roleeligibilityschedules":
                    if mode == "denied_pim":
                        raise Denied()
                    return {"value": []}
                if path == "/v1.0/rolemanagement/directory/roleeligibilityscheduleinstances":
                    if mode == "null_eligible":
                        return {"value": [{"id": OPAQUE, "principalId": USER, "roleDefinitionId": ROLE,
                                           "startDateTime": None, "endDateTime": None}]}
                    return {"value": []}
                if path == "/v1.0/rolemanagement/directory/roleassignmentscheduleinstances":
                    if mode == "denied_active_pim":
                        raise Denied()
                    if mode in ("opaque_dated", "opaque_unproven", "opaque_permanent", "foreign_role"):
                        return {"value": [{"id": OPAQUE, "principalId": USER,
                                           "roleDefinitionId": GROUP if mode == "foreign_role" else ROLE,
                                           "directoryScopeId": "/", "startDateTime": None if mode != "opaque_dated" else "2020-01-01T00:00:00Z",
                                           "endDateTime": None}]}
                    return {"value": []}
                if path == "/v1.0/identitygovernance/privilegedaccess/group/eligibilityscheduleinstances":
                    if mode == "denied_group_pim":
                        raise Denied()
                    return {"value": []}
                if path == "/v1.0/identitygovernance/privilegedaccess/group/assignmentscheduleinstances":
                    if mode in ("group_pim_null_member", "group_pim_null_owner", "foreign_group_pim") and parse_qs(urlsplit(url).query).get("$filter") == ["principalId eq '" + USER + "'"]:
                        return {"value": [{"id": OPAQUE, "groupId": TENANT if mode == "foreign_group_pim" else GROUP, "principalId": USER,
                                           "accessId": "member" if mode == "group_pim_null_member" else "owner",
                                           "startDateTime": None, "endDateTime": None}]}
                    return {"value": []}
                if path == "/beta/users/" + USER + "/authentication/requirements":
                    if mode == "denied_requirements":
                        raise Denied()
                    if mode == "foreign_requirements":
                        return {"id": GROUP, "perUserMfaState": state}
                    return {"perUserMfaState": state}
                return {"value": []}
            if path == SUB.casefold():
                if mode == "subscription_denied":
                    raise Denied()
                if mode == "subscription_malformed":
                    return {"value": []}
                return {"id": SUB, "subscriptionId": SUB.rsplit("/", 1)[-1], "tenantId": TENANT}
            return {"value": []}

    monkeypatch.setattr(azure, "AzureTransportExposure", lambda auth: Transport())
    connector = {"provider": "azure", "scopes": [SUB],
                 "auth": {"method": "token", "arm_token": "mock", "graph_token": "mock"},
                 "options": {"retries": 0}}
    snapshot = azure.collect(connector, ["directory_user", "azure_sw18_evidence"])
    report = evaluate_snapshot(snapshot, checks=[USER_MFA_ID])
    findings = [f for f in report["findings"] if f["check_id"] == USER_MFA_ID]
    assert len(findings) == 1, findings
    return findings[0]["status"], snapshot


@pytest.mark.parametrize("state,capable,expected", [
    ("enabled", True, "PASS"), ("enforced", True, "PASS"),
    ("enabled", False, "FAIL"), ("enforced", False, "FAIL")])
def test_native_enabled_enforced(monkeypatch, state, capable, expected):
    status, snapshot = run(monkeypatch, state=state, capable=capable)
    assert status == expected
    row = next(c for c in snapshot["collections"] if c["type"] == "azure_sw18_evidence" and c["scope"] == "/tenants/" + TENANT)["items"][0]
    assert all(row["coverage"].values())
    assert row["registration"]["usableMfaRegistered"] is capable


@pytest.mark.parametrize("mode,expected", [
    ("disabled_user", "NOT_APPLICABLE"), ("partial_group", "UNKNOWN"),
    ("hidden_group", "UNKNOWN"), ("partial_beta", "UNKNOWN"),
    ("duplicate_registration", "UNKNOWN"), ("denied_pim", "UNKNOWN"),
    ("denied_active_pim", "UNKNOWN"),
    ("denied_group_pim", "UNKNOWN"), ("denied_requirements", "UNKNOWN"),
    ("foreign_requirements", "UNKNOWN"), ("beta_unsupported", "UNKNOWN")])
def test_unresolved_native_paths(monkeypatch, mode, expected):
    assert run(monkeypatch, mode)[0] == expected


@pytest.mark.parametrize("mode,collection_status", [
    ("partial_group", "denied"), ("hidden_group", "partial")])
def test_incomplete_group_diagnostic_preserves_native_cause(monkeypatch, mode, collection_status):
    status, snapshot = run(monkeypatch, mode)
    membership = next(c for c in snapshot["collections"] if c["type"] == "directory_membership")
    row = next(c for c in snapshot["collections"] if c["type"] == "azure_sw18_evidence"
               and c["scope"] == "/tenants/" + TENANT)["items"][0]
    assert membership["status"] == collection_status
    assert status == "UNKNOWN"
    assert row["coverage"] == {"directory_roles": False, "groups": False,
                               "registration": True, "per_user_requirements": True}
    assert row["_unresolved"]["groups"] == "partial, foreign, or duplicate group membership"
    assert "groups_index" not in str(row["_unresolved"])


def test_privileged_and_disabled_per_user(monkeypatch):
    assert run(monkeypatch, role=True)[0] == "NOT_APPLICABLE"
    assert run(monkeypatch, "group_role")[0] == "NOT_APPLICABLE"
    assert run(monkeypatch, "denied_pim", role=True)[0] == "UNKNOWN"
    assert run(monkeypatch, state="disabled")[0] == "UNKNOWN"


@pytest.mark.parametrize("mode", ["owner_only", "role_assignable_owner", "owner_denied", "foreign_owner"])
def test_owner_evidence_never_fabricates_nonprivileged_coverage(monkeypatch, mode):
    status, snapshot = run(monkeypatch, mode, capable=False)
    row = next(c for c in snapshot["collections"] if c["type"] == "azure_sw18_evidence"
               and c["scope"] == "/tenants/" + TENANT)["items"][0]
    assert status == "UNKNOWN"
    assert row["coverage"]["directory_roles"] is False


@pytest.mark.parametrize("mode,expected", [
    ("opaque_dated", "NOT_APPLICABLE"),
    ("opaque_permanent", "NOT_APPLICABLE"),
    ("opaque_unproven", "UNKNOWN"),
    ("null_eligible", "UNKNOWN"),
    ("foreign_role", "UNKNOWN"),
    ("group_pim_null_member", "PASS"),
    ("group_pim_null_owner", "UNKNOWN"),
    ("foreign_group_pim", "UNKNOWN"),
])
def test_opaque_pim_and_null_start_require_current_proof(monkeypatch, mode, expected):
    assert run(monkeypatch, mode)[0] == expected


def test_pim_filter_is_a_valid_offline_http_request_target(monkeypatch):
    urls = []
    assert run(monkeypatch, seen=urls)[0] == "PASS"
    pim = [u for u in urls if "/identityGovernance/privilegedAccess/group/" in u]
    assert pim
    for url in pim:
        request = Request(url)
        connection = HTTPConnection("graph.microsoft.com")
        connection.putrequest("GET", request.selector)  # validates before any socket opens
        assert " " not in request.selector
        assert parse_qs(urlsplit(url).query)["$filter"][0].startswith("principalId eq '")


@pytest.mark.parametrize("mode", ["subscription_denied", "subscription_malformed"])
def test_incomplete_selected_subscription_does_not_duplicate_binding(monkeypatch, mode):
    status, snapshot = run(monkeypatch, mode)
    subscriptions = [c for c in snapshot["collections"] if c["type"] == "subscription" and c["scope"] == SUB]
    assert len(subscriptions) == 1
    assert subscriptions[0]["status"] not in ("collected", "empty")
    assert SUB not in snapshot["metadata"]["subscription_tenants"]
    # This registered user check is tenant scoped; complete Graph tenant
    # evidence remains usable when an unrelated ARM subscription read fails.
    assert status == "PASS"


def test_shared_sw18_evidence_planner_keeps_guest_only_collection_independent():
    guest = azure._selected({}, ["vm", "azure_sw18_evidence"])
    native_user = azure._selected({}, ["directory_user", "azure_sw18_evidence"])
    assert "directory_user" not in guest
    assert "directory_role_assignment_instance" not in guest
    assert {"directory_user_group_membership", "directory_role_assignment_instance", "user_registration_detail"} <= native_user


@pytest.mark.parametrize("mutator", [
    lambda s: s["metadata"].update(tenant_id=GROUP),
    lambda s: s["metadata"].update(credential_context_id="foreign"),
    lambda s: next(c for c in s["collections"] if c["type"] == "azure_sw18_evidence" and c["scope"] == "/tenants/" + TENANT)["items"][0].update(subject_id=GROUP),
    lambda s: next(c for c in s["collections"] if c["type"] == "azure_sw18_evidence" and c["scope"] == "/tenants/" + TENANT)["items"].append(copy.deepcopy(next(c for c in s["collections"] if c["type"] == "azure_sw18_evidence" and c["scope"] == "/tenants/" + TENANT)["items"][0])),
])
def test_foreign_duplicate_capture_guards(monkeypatch, mutator):
    _, snapshot = run(monkeypatch)
    snapshot = copy.deepcopy(snapshot)
    mutator(snapshot)
    from peaso.snapshot import make_snapshot
    snapshot = make_snapshot("azure", snapshot["scopes"], snapshot["collections"], metadata=snapshot["metadata"])
    findings = evaluate_snapshot(snapshot, checks=[USER_MFA_ID])["findings"]
    assert [f["status"] for f in findings if f["check_id"] == USER_MFA_ID] == ["UNKNOWN"]
