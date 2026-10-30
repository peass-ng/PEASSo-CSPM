"""Directed collector -> sealed snapshot -> registered engine SW52 cases."""
from copy import deepcopy
from urllib.parse import urlsplit

import pytest

from peaso.collectors.gcp import GCPCollector, ReadError
from peaso.engine import collect_snapshot, evaluate_snapshot, plan_collection, _registry
from peaso.checks import CHECKS

CHECK = "gcp.identity.super_admin_separation"
PROJECT = "projects/sw52-project"
ORG = "organizations/123"
FOLDER = "folders/456"
CUSTOMER = "Cnative"
KINDS = ["workspace_role_assignment", "workspace_role", "workspace_user", "iam_policy", "group", "group_membership"]


class Fake:
    def __init__(self, *, folder=True, bindings=None, customer=CUSTOMER, deny=None,
                 ancestry=None, assignment_customer=CUSTOMER, project_parent=None, folder_parent=None,
                 groups=None, partial=None):
        self.folder = folder
        self.bindings = bindings or {}
        self.customer = customer
        self.deny = deny
        self.ancestry = ancestry
        self.assignment_customer = assignment_customer
        self.project_parent = project_parent
        self.folder_parent = folder_parent
        self.groups = groups or []
        self.partial = partial
        self.calls = 0
        self.requests = []

    def request(self, method, url, **kwargs):
        self.calls += 1
        request_id = f"fake-{self.calls}"
        scope = kwargs["scope"]
        self.requests.append((method, url, scope))
        if self.deny and self.deny in url:
            error = ReadError("denied", "api_error", http_status=403)
            error.request_id = request_id
            raise error
        if url.endswith(":getAncestry"):
            chain = [{"resourceId": {"type": "project", "id": "sw52-project"}}]
            if self.folder:
                chain.append({"resourceId": {"type": "folder", "id": "456"}})
            chain.append({"resourceId": {"type": "organization", "id": "123"}})
            data = {"ancestor": deepcopy(self.ancestry if self.ancestry is not None else chain)}
        elif url.endswith(":getIamPolicy"):
            data = {"bindings": deepcopy(self.bindings.get(scope, [])), "version": 3, "etag": "etag"}
        elif url.endswith(":searchAllIamPolicies"):
            data = {"results": []}
        elif url.endswith("/v3/" + PROJECT):
            # Native CRM v3 projects.get names the project by number.
            data = {"name": "projects/505052", "projectId": "sw52-project", "parent": self.project_parent or (FOLDER if self.folder else ORG)}
        elif url.endswith("/compute/v1/" + PROJECT):
            data = {"commonInstanceMetadata": {"fingerprint": "fp"}}
        elif url.endswith("/v3/" + ORG):
            data = {"name": ORG, "directoryCustomerId": self.customer}
        elif "/v3/organizations/" in url and not url.endswith(":getIamPolicy"):
            # A foreign organization in the ancestry is not readable.
            error = ReadError("denied", "api_error", http_status=403)
            error.request_id = request_id
            raise error
        elif url.endswith("/v3/" + FOLDER):
            data = {"name": FOLDER, "parent": self.folder_parent or ORG}
        elif url.endswith("/directory/v1/users"):
            data = {"users": [{"id": "u1", "primaryEmail": "admin@example.test", "customerId": CUSTOMER}]}
        elif url.endswith("/roles"):
            data = {"items": [{"roleId": "r1", "isSuperAdminRole": True}]}
        elif url.endswith("/roleassignments"):
            data = {"items": [{"roleAssignmentId": "a1", "roleId": "r1", "assignedTo": "u1",
                               "customerId": self.assignment_customer}]}
        elif url.endswith("/v1/groups"):
            data = {"groups": deepcopy(self.groups)}
        else:
            raise AssertionError((method, url, scope))
        if self.partial and self.partial in url:
            data["warning"] = {"code": "PARTIAL"}
        return deepcopy(data), request_id


def run_case(*, sw52_option=None, **kwargs):
    fake = Fake(**kwargs)
    connector = {"provider": "gcp", "scopes": [PROJECT], "options": {"inventories": KINDS,
        "concurrency": 1, "metrics_scopes": False, "resource_iam": False}}
    if sw52_option is not None:
        connector["options"]["sw52"] = sw52_option
    snapshot = GCPCollector(connector, requirements=KINDS, transport=fake).collect()
    findings = [row for row in evaluate_snapshot(snapshot, checks=[CHECK])["findings"]
                if row["check_id"] == CHECK]
    assert all(method in ("GET", "POST") for method, _, _ in fake.requests)
    assert all(method != "POST" or url.endswith((":getAncestry", ":getIamPolicy"))
               for method, url, _ in fake.requests)
    return snapshot, findings, fake


@pytest.mark.parametrize("folder", [False, True])
def test_native_pass_with_and_without_folder(folder):
    snapshot, findings, fake = run_case(folder=folder)
    assert len(findings) == 1
    assert findings[0]["status"] == "PASS", findings[0]
    native = snapshot["metadata"]["sw52_native"][PROJECT]
    assert native["iam_policy_resource_names"] == ([PROJECT, FOLDER, ORG] if folder else [PROJECT, ORG])
    assert native["directory_customer"] == CUSTOMER
    assert {scope for method, url, scope in fake.requests if url.endswith(":getIamPolicy")} == set(native["iam_policy_resource_names"])


@pytest.mark.parametrize("role,scope", [("roles/owner", PROJECT), ("roles/editor", FOLDER),
                                         ("roles/resourcemanager.organizationAdmin", ORG)])
def test_direct_admin_fail(role, scope):
    _, findings, _ = run_case(bindings={scope: [{"role": role, "members": ["user:admin@example.test"]}]})
    assert findings[0]["status"] == "FAIL", findings[0]


@pytest.mark.parametrize("kwargs", [
    {"deny": "roleassignments"}, {"deny": ":getAncestry"}, {"deny": "organizations/123:getIamPolicy"},
    {"deny": "groups"}, {"deny": "/directory/v1/users"}, {"customer": "Cforeign"},
    {"partial": "roleassignments"},
    {"deny": "memberships", "groups": [{"name": "groups/g1", "groupKey": {"id": "admins@example.test"}}]},
    {"project_parent": "organizations/999"}, {"folder_parent": "organizations/999"},
    {"ancestry": [{"resourceId": {"type": "organization", "id": "123"}}]},
    {"ancestry": [{"resourceId": {"type": "project", "id": "sw52-project"}},
                  {"resourceId": {"type": "organization", "id": "999"}}]},
    {"bindings": {PROJECT: [{"role": "roles/owner", "members": ["user:admin@example.test"],
                             "condition": {"title": "only sometimes", "expression": "request.time < timestamp('2030-01-01T00:00:00Z')"}}]}},
    {"bindings": {ORG: [{"role": "roles/resourcemanager.organizationAdmin", "members": ["group:admins@example.test"]}]}},
])
def test_unresolved_is_unknown(kwargs):
    _, findings, _ = run_case(**kwargs)
    assert findings and all(row["status"] in ("UNKNOWN", "DENIED") for row in findings), findings


def test_operator_sw52_cannot_substitute_for_native_customer_binding():
    option = {"status": "collected", "scope": PROJECT,
              "iam_policy_levels": ["project", "folder", "organization"],
              "iam_policy_resource_names": [PROJECT, FOLDER, ORG]}
    _, findings, _ = run_case(customer="not-a-customer", sw52_option=option)
    assert findings[0]["status"] == "UNKNOWN"


def test_default_selection_and_broader_one_project_collection(monkeypatch):
    from peaso import collectors
    fake = Fake()
    request = {"connector": {"provider": "gcp", "scopes": [PROJECT], "options": {
        "inventories": [*KINDS, "folder"], "concurrency": 1,
        "metrics_scopes": False, "resource_iam": False}}}
    plan = plan_collection(request)
    assert set(KINDS) < set(plan)
    monkeypatch.setattr(collectors, "collect_live", lambda connector, requirements:
        GCPCollector(connector, requirements=requirements, transport=fake).collect())
    snapshot = collect_snapshot(request)
    assert snapshot["metadata"]["sw52_native"][PROJECT]["status"] == "collected"
    rows = [row for row in evaluate_snapshot(snapshot, checks=[CHECK])["findings"]
            if row["check_id"] == CHECK]
    assert len(rows) == 1 and rows[0]["status"] == "PASS", rows
    assert set(KINDS) <= set(plan_collection({"connector": {"provider": "gcp", "scopes": [PROJECT]}}))
    assert all(method != "POST" or url.endswith((":getAncestry", ":getIamPolicy"))
               for method, url, _ in fake.requests)


def test_registered_contract_catalog_metadata_and_source_pin():
    import hashlib
    from pathlib import Path
    from peaso.checks import batch_remaining_gcp, sw52_native_successor
    from peaso import engine
    check = next(check for check in CHECKS if check.id == CHECK)
    assert next(row for row in _registry() if row.id == CHECK) is check
    assert check.evaluate.__module__ == batch_remaining_gcp.__name__
    assert check.dependencies == KINDS
    public = check.public()
    assert public["dependencies"] == KINDS
    assert public["id"] == CHECK and public["evaluator"]["check_id"] == CHECK
    source_hash = hashlib.sha256(Path(sw52_native_successor.__file__).read_bytes()).hexdigest()
    assert source_hash in Path(batch_remaining_gcp.__file__).read_text()
    assert "91e8d5cbe97be325cc288584e091a335f3f70367ec79c0de9c1b74cbfb2630fa" in Path(batch_remaining_gcp.__file__).read_text()
    assert "_all_collections" not in Path(engine.__file__).read_text()


@pytest.mark.parametrize("change", ["foreign", "partial", "duplicate"])
def test_origin_projection_mismatch_cannot_pass(change):
    from peaso.snapshot import seal
    snapshot, _, _ = run_case()
    changed = deepcopy(snapshot)
    roots = changed["metadata"]["sw52_native"][PROJECT]["iam_policy_roots"]
    if change == "foreign":
        roots[1]["origin_scope"] = "folders/999"
    elif change == "partial":
        roots[1]["representation"] = "partial"
    else:
        roots.append(deepcopy(roots[1]))
    rows = [row for row in evaluate_snapshot(seal(changed), checks=[CHECK])["findings"]
            if row["check_id"] == CHECK]
    assert len(rows) == 1 and rows[0]["status"] == "UNKNOWN", rows
