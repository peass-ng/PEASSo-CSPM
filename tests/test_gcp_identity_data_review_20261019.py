"""Directed native metadata -> collector -> sealed snapshot -> registered checks.

Regressions cover independently reproduced defects and conservative unknowns.
No cloud credentials or content APIs are used. Existing storage/KMS/Workspace suites
are attributed separately in docs/gcp-review/identity-data-review.json.
"""
from copy import deepcopy
from urllib.parse import urlsplit

import pytest

from peaso.collectors.gcp import GCPCollector, ReadError
from peaso.engine import evaluate_snapshot

SCOPE = "projects/review-project"


class NativeMetadata:
    def __init__(self, family, mode="normal"):
        self.family, self.mode = family, mode
        self.requests, self.evidence = [], []

    def request(self, method, url, **kwargs):
        self.requests.append((method, url, deepcopy(kwargs)))
        rid = "review-" + str(len(self.requests))
        path, params = urlsplit(url).path, kwargs.get("params", {})
        if self.mode == "denied" and (path.endswith("/datasets/d") or path.endswith("/users")):
            error = ReadError("denied", "forbidden")
            error.request_id = rid
            raise error
        if path == "/v3/" + SCOPE:
            data = {"name": "projects/123456789", "projectId": "review-project", "parent": "folders/456"}
            if self.mode == "foreign_project":
                data["projectId"] = "other-project"
        elif path == "/v3/folders/456":
            data = {"name": "folders/456", "parent": "organizations/123"}
            if self.mode == "cycle":
                data["parent"] = "folders/456"
        elif path == "/v3/organizations/123":
            if self.mode == "binding_denied":
                raise ReadError("denied", "forbidden")
            data = {"name": "organizations/123", "directoryCustomerId": "Cnative"}
            if self.mode == "foreign_customer":
                data["directoryCustomerId"] = "Cforeign"
        elif path.endswith("/instances"):
            data = {"items": [{"name": "db", "project": "review-project", "databaseVersion": "SQLSERVER_2019_STANDARD",
                "settings": {"databaseFlags": [{"name": "3625 (trace flag)", "value": "on"}]}}]}
            if self.mode == "duplicate_alias":
                data["items"][0]["settings"]["databaseFlags"].append({"name": "3625", "value": "off"})
        elif path.endswith("/instances/db/users"):
            data = {"kind": "sql#usersList"}
        elif path.endswith("/datasets"):
            data = {"datasets": [{"datasetReference": {"projectId": "review-project", "datasetId": "d"}}]}
        elif path.endswith("/datasets/d"):
            data = {"datasetReference": {"projectId": "review-project", "datasetId": "d"}, "access": [
                {"role": "READER", "iamMember": "allUsers"}]}
            if self.mode == "omitted_acl":
                data.pop("access")
        elif path.endswith("/directory/v1/users"):
            user = {"id": "u1", "customerId": "Cnative", "primaryEmail": "admin@example.test", "suspended": False, "archived": False,
                "isEnrolledIn2Sv": True, "isEnforcedIn2Sv": False, "recoveryEmail": "recovery@example.test"}
            if self.mode == "enforced":
                user["isEnforcedIn2Sv"] = True
            if self.mode == "missing_enforcement":
                user.pop("isEnforcedIn2Sv")
            if self.mode == "malformed_enforcement":
                user["isEnforcedIn2Sv"] = "true"
            if self.mode == "archived":
                user["archived"] = True
            if self.mode == "missing_recovery":
                user.pop("recoveryEmail")
            # Honor the actual producer's partial-response field mask.
            if "fields" in params:
                user = {key: value for key, value in user.items() if key in params["fields"]}
            data = {"users": [user]}
            if self.family == "recovery":
                data["users"].extend({**user, "id": "u" + str(n), "primaryEmail": "operator" + str(n) + "@example.test"} for n in (2, 3))
            if self.mode == "users_partial":
                data["warning"] = {"code": "PARTIAL"}
        elif path.endswith(":getIamPolicy"):
            data = {"bindings": [{"role": "roles/viewer", "members": ["user:admin@example.test"]}]}
        elif path.endswith(":searchAllIamPolicies"):
            data = {"results": []}
        elif path.endswith("/roles"):
            data = {"items": [{"roleId": "r1", "isSuperAdminRole": True}]}
        elif path.endswith("/roleassignments"):
            data = {"items": [{"roleAssignmentId": "a1", "roleId": "r1", "assignedTo": "u1"}]}
        elif path == "/v1/groups":
            data = {"groups": [{"name": "groups/recovery", "groupKey": {"id": "recovery@example.test"}, "parent": "customers/Cnative"}]}
        elif path.endswith("/groups/recovery/memberships"):
            data = {"memberships": [{"name": "groups/recovery/memberships/m" + str(n),
                "preferredMemberKey": {"id": "operator" + str(n) + "@example.test"}, "roles": [{"name": "MEMBER"}]} for n in (2, 3)]}
            if self.mode == "one_member":
                data["memberships"].pop()
            if self.mode == "external_member":
                data["memberships"][0]["preferredMemberKey"]["id"] = "external@example.test"
            if self.mode == "expired_member":
                data["memberships"][0]["roles"][0]["expiryDetail"] = {"expireTime": "2000-01-01T00:00:00Z"}
            if self.mode == "members_denied":
                raise ReadError("denied", "forbidden")
        elif path.endswith("memberships:searchTransitiveMemberships"):
            data = {"memberships": []}
        elif path.endswith("/secrets"):
            data = {"secrets": [{"name": SCOPE + "/secrets/s", "rotation": {"nextRotationTime": "2099-01-01T00:00:00Z"}}]}
        else:
            data = {}
        if self.mode == "partial" and path.endswith("/instances"):
            data["nextPageToken"] = "next"
        self.evidence.append({"id": rid, "url": url, "method": method, "status": "collected"})
        return deepcopy(data), rid


def scan(family, kinds, ids, mode="normal"):
    api = NativeMetadata(family, mode)
    collector = GCPCollector({"provider": "gcp", "scopes": [SCOPE], "options": {
        "inventories": kinds, "include_inherited": False, "concurrency": 1,
        "workspace_customers": ["Cnative"], "resource_iam": False,
        **({"max_pages": 1} if mode == "partial" else {})}}, transport=api)
    snapshot = collector.collect()
    report = evaluate_snapshot(snapshot, checks=ids, include_not_applicable=True)
    statuses = {cid: [f["status"] for f in report["findings"] if f["check_id"] == cid] for cid in ids}
    assert all(method == "GET" or url.endswith(":getIamPolicy") for method, url, _ in api.requests)
    return snapshot, statuses, api


def test_native_sql_trace_alias_is_normalized_without_inverting_legacy_cis():
    reference = "gcp.ports.reference_sqlserver_trace3625"
    modern = "gcp.ports.sql_instance_sql_3625_trace_database_flag_on"
    legacy = "gcp.gap.sql_3625_trace_flag_off_cis_v1"
    _, statuses, _ = scan("sql", ["sql_instance"], [reference, modern, legacy])
    assert statuses == {reference: ["PASS"], modern: ["PASS"], legacy: ["FAIL"]}


def test_native_sql_duplicate_alias_is_unknown_in_normalized_consumers():
    ids = ["gcp.ports.reference_sqlserver_trace3625", "gcp.ports.sql_instance_sql_3625_trace_database_flag_on", "gcp.gap.sql_3625_trace_flag_off_cis_v1"]
    _, statuses, _ = scan("sql", ["sql_instance"], ids, "duplicate_alias")
    assert statuses == {cid: ["UNKNOWN"] for cid in ids}


def test_native_sql_partial_inventory_retains_scope_uncertainty_and_observed_row():
    cid = "gcp.ports.sql_instance_sql_3625_trace_database_flag_on"
    snapshot, statuses, _ = scan("sql", ["sql_instance"], [cid], "partial")
    env = next(c for c in snapshot["collections"] if c["type"] == "sql_instance")
    assert env["coverage_status"] == "partial"
    assert sorted(statuses[cid]) == ["PASS", "UNKNOWN"]  # known row plus incomplete-inventory finding


def test_native_bigquery_iam_member_all_users_reader_fails():
    signed = "gcp_pci_bigquery_dataset_a4e25dbf9640"
    broad = "gcp.reviewed.bigquery.no_public_acl"
    _, statuses, api = scan("bigquery", ["bigquery_dataset"], [signed, broad])
    assert statuses == {signed: ["FAIL"], broad: ["FAIL"]}
    get_params = [kw["params"] for _, url, kw in api.requests if url.endswith("/datasets/d")]
    assert get_params == [{"accessPolicyVersion": 3, "datasetView": "FULL"}]


@pytest.mark.parametrize("mode,expected", [("omitted_acl", "PASS"), ("denied", "UNKNOWN")])
def test_native_bigquery_full_omission_and_denied_details(mode, expected):
    cid = "gcp.reviewed.bigquery.no_public_acl"
    _, statuses, _ = scan("bigquery", ["bigquery_dataset"], [cid], mode)
    assert statuses[cid] == [expected]


# Since 120406f2 an unproven project-to-customer binding never lists Directory
# users; the user collection carries the binding failure instead.
BINDING_FAILURES = {"binding_denied": "forbidden", "foreign_customer": "project_directory_customer_not_selected",
                    "foreign_project": "directory_project_identity_mismatch", "cycle": "directory_hierarchy_cycle"}


def directory_users(snapshot, api, mode):
    users = next(c for c in snapshot["collections"] if c["type"] == "workspace_user")
    if mode not in BINDING_FAILURES:
        return users["items"][0]
    assert users["items"] == [] and users["error"]["code"] == BINDING_FAILURES[mode]
    assert not any(url.endswith("/directory/v1/users") for _, url, _ in api.requests)
    return None


@pytest.mark.parametrize("mode,expected", [("normal", "FAIL"), ("enforced", "PASS"),
    ("missing_enforcement", "UNKNOWN"), ("malformed_enforcement", "UNKNOWN"),
    ("binding_denied", "DENIED"), ("foreign_customer", "UNKNOWN"), ("foreign_project", "UNKNOWN"),
    ("cycle", "UNKNOWN"), ("archived", "NOT_APPLICABLE")])
def test_native_directory_enrollment_and_enforcement_require_customer_binding(mode, expected):
    cid = "gcp.identity.non_service_account_mfa"
    snapshot, statuses, api = scan("workspace", ["workspace_user", "iam_policy"], [cid], mode)
    user = directory_users(snapshot, api, mode)
    assert statuses[cid] == [expected]
    if user is None:
        return
    assert "identityProvider" not in user and "inDomain" not in user
    assert user["_coverage"]["directoryProjection"]["projection"] == "full"
    assert user["_provenance"].get("representation") != "full"
    assert any(kw.get("params", {}).get("projection") == "full" for _, url, kw in api.requests if url.endswith("/directory/v1/users"))


def test_native_directory_partial_user_inventory_remains_unknown():
    cid = "gcp.identity.non_service_account_mfa"
    _, statuses, _ = scan("workspace", ["workspace_user", "iam_policy"], [cid], "users_partial")
    assert statuses[cid] and set(statuses[cid]) == {"UNKNOWN"}


@pytest.mark.parametrize("mode,expected", [("normal", "PASS"), ("one_member", "FAIL"),
    ("missing_recovery", "FAIL"), ("external_member", "UNKNOWN"), ("members_denied", "UNKNOWN"),
    ("expired_member", "UNKNOWN"),
    ("foreign_customer", "UNKNOWN"), ("binding_denied", "DENIED")])
def test_native_directory_recovery_joins_cloud_identity_members_to_active_users(mode, expected):
    cid = "gcp.identity.super_admin_recovery_group"
    kinds = ["workspace_user", "workspace_role", "workspace_role_assignment", "group", "group_membership"]
    snapshot, statuses, api = scan("recovery", kinds, [cid], mode)
    user = directory_users(snapshot, api, mode)
    assert user is None or user["_coverage"]["directoryProjection"]["fields"]
    # Only the super-admin has an applicable result; the other Directory users do not.
    assert statuses[cid] and expected in statuses[cid]
    assert set(statuses[cid]) <= {expected, "NOT_APPLICABLE", "UNKNOWN"}
    if expected == "PASS":
        assert statuses[cid].count("PASS") == 1


def test_native_secret_read_input_only_period_does_not_create_rotation_pass():
    cid = "gcp.claude.secret.rotation_90_days"
    snapshot, statuses, _ = scan("secret", ["secret"], [cid])
    secret = next(c for c in snapshot["collections"] if c["type"] == "secret")["items"][0]
    assert "rotationPeriod" not in secret["rotation"]
    assert statuses[cid] == ["UNKNOWN"]


@pytest.mark.parametrize("mode,expected", [("acl_public_read", "FAIL"), ("ancestor_public", "FAIL"), ("complete", "PASS"),
    ("denied_ancestry", "UNKNOWN"), ("ancestor_custom", "UNKNOWN"), ("ancestor_conditional", "UNKNOWN"),
    ("managed", "UNKNOWN"), ("denied_managed", "UNKNOWN"), ("hns", "UNKNOWN"), ("public_write", "UNKNOWN")])
def test_storage_read_native_acl_ancestor_and_incomplete_evidence(mode, expected, monkeypatch):
    """The native ACL bridge and inherited-read declarations both reach the consumer.

    Reuses the native Storage API double from test_peaso_gcp_storage_acl_native
    with attribution; the response -> collector -> sealed engine path is real.
    """
    from tests.test_peaso_gcp_storage_acl_native import API, SCOPE as STORAGE_SCOPE
    from peaso.collectors import collect_live, gcp
    from peaso.engine import plan_collection

    cid = "gcp_pci_bucket_157fb0c69361"
    api = API(mode)
    monkeypatch.setattr(gcp, "Credentials", lambda *a, **kw: None)
    monkeypatch.setattr(gcp, "Transport", lambda *a, **kw: api)
    connector = {"provider": "gcp", "scopes": [STORAGE_SCOPE], "options": {
        "resource_iam": False, "metrics_scopes": False, "include_inherited": True}}
    kinds = plan_collection({"connector": connector, "checks": [cid]})
    assert set(kinds) >= {"bucket", "bucket_acl", "object_acl", "bucket_effective_iam", "project", "iam_policy"}
    snapshot = collect_live(connector, kinds)
    report = evaluate_snapshot(snapshot, checks=[cid], include_not_applicable=True)
    findings = [f for f in report["findings"] if f["check_id"] == cid]
    assert findings and {f["status"] for f in findings} == {expected}
    if mode == "acl_public_read":
        acls = next(c for c in snapshot["collections"] if c["type"] == "bucket_acl")
        assert any(row["entity"] == "allUsers" and row["role"] == "READER" for row in acls["items"])
    elif mode == "ancestor_public":
        effective = next(c for c in snapshot["collections"] if c["type"] == "bucket_effective_iam")
        assert any(row["publicAccess"] is True for row in effective["items"])


def test_storage_inherited_object_creator_does_not_become_a_read_grant(monkeypatch):
    from tests.test_peaso_gcp_storage_acl_native import API, SCOPE as STORAGE_SCOPE
    from peaso.collectors import collect_live, gcp
    from peaso.engine import plan_collection

    class CreatorAPI(API):
        def request(self, method, url, **kwargs):
            data, rid = super().request(method, url, **kwargs)
            if url.endswith("/v3/organizations/999:getIamPolicy"):
                data["bindings"] = [{"role": "roles/storage.objectCreator", "members": ["allUsers"]}]
            return data, rid

    api = CreatorAPI("ancestor_public")
    monkeypatch.setattr(gcp, "Credentials", lambda *a, **kw: None)
    monkeypatch.setattr(gcp, "Transport", lambda *a, **kw: api)
    cid = "gcp_pci_bucket_157fb0c69361"
    connector = {"provider": "gcp", "scopes": [STORAGE_SCOPE], "options": {
        "resource_iam": False, "metrics_scopes": False, "include_inherited": True}}
    snapshot = collect_live(connector, plan_collection({"connector": connector, "checks": [cid]}))
    report = evaluate_snapshot(snapshot, checks=[cid], include_not_applicable=True)
    assert [f["status"] for f in report["findings"] if f["check_id"] == cid] == ["PASS"]
