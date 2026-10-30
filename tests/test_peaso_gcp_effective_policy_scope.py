"""Local read-only HTTP stubs for effective Org Policy response identity."""
from __future__ import annotations

import copy
import pytest

from peaso.collectors import gcp
from peaso.engine import evaluate_snapshot

SCOPE = "projects/p-one"
PAP = "gcp.storage.public_access_prevention"
OSLOGIN = "gcp.ports.compute_oslogin_metadata_precedence"


class Transport:
    def __init__(self, parent=SCOPE, *, suffix=None, project=None, lookup_error=None):
        self.parent, self.suffix = parent, suffix
        self.project = {"name": "projects/1", "projectId": "p-one"} if project is None else project
        self.lookup_error = lookup_error
        self.requests, self.evidence, self.calls = [], [], 0

    def request(self, method, url, **kwargs):
        self.calls += 1
        request_id = f"request-{self.calls}"
        self.requests.append({"method": method, "url": url, **kwargs})
        if url == "https://cloudresourcemanager.googleapis.com/v3/projects/p-one":
            if self.lookup_error is not None:
                exc = gcp.ReadError("denied", "api_error", http_status=403)
                exc.request_id = request_id
                raise exc
            data = self.project
        elif url == "https://compute.googleapis.com/compute/v1/projects/p-one":
            data = {"commonInstanceMetadata": {"fingerprint": "fp"}}
        elif url == "https://storage.googleapis.com/storage/v1/b":
            data = {"items": [{"name": "bucket-one", "iamConfiguration": {"publicAccessPrevention": "inherited"}}]}
        elif url == "https://storage.googleapis.com/storage/v1/b/bucket-one/iam":
            data = {"bindings": [], "version": 3}
        elif url == "https://compute.googleapis.com/compute/v1/projects/p-one/aggregated/instances":
            data = {"items": {"zones/us-central1-a": {"instances": [
                {"name": "vm-one", "id": "1", "zone": "https://compute.googleapis.com/compute/v1/projects/p-one/zones/us-central1-a",
                 "metadata": {"fingerprint": "fp"}}]}}}
        elif url == "https://compute.googleapis.com/compute/v1/projects/p-one/zones/us-central1-a/instances/vm-one/getIamPolicy":
            # Compute resource IAM is hydrated for every listed instance.
            data = {"bindings": [], "version": 3}
        elif url.startswith("https://orgpolicy.googleapis.com/v2/projects/p-one/policies/"):
            constraint = url.rsplit("/", 1)[1].split(":", 1)[0]
            name = None if self.parent is None else self.parent + "/policies/" + (self.suffix or constraint)
            data = {"spec": {"rules": [{"enforce": True}]}}
            if name is not None:
                data["name"] = name
        else:
            raise AssertionError(url)
        self.evidence.append({"id": request_id, "url": url, "method": method, "scope": kwargs.get("scope"), "status": "collected"})
        return copy.deepcopy(data), request_id


def collect(parent=SCOPE, *, kinds=("org_policy_effective",), **kwargs):
    transport = Transport(parent, **kwargs)
    connector = {"provider": "gcp", "scopes": [SCOPE], "options": {"inventories": list(kinds),
                 "concurrency": 1, "metrics_scopes": False, "resource_iam": False, "include_inherited": False}}
    snapshot = gcp.GCPCollector(connector, transport=transport).collect()
    policy = next(c for c in snapshot["collections"] if c["type"] == "org_policy_effective")
    return snapshot, policy, transport


def finding(snapshot, cid):
    rows = [row for row in evaluate_snapshot(snapshot, checks=[cid])["findings"] if row["check_id"] == cid]
    assert len(rows) == 1
    return rows[0]


def project_get_count(transport):
    return sum(r["url"] == "https://cloudresourcemanager.googleapis.com/v3/projects/p-one"
               for r in transport.requests)


def test_exact_requested_parent_needs_no_alias_lookup():
    _, policy, transport = collect()
    assert policy["status"] == "collected"
    assert len(policy["items"]) == len(gcp.ORG_POLICY_CONSTRAINTS)
    assert project_get_count(transport) == 0


def test_verified_numeric_alias_is_accepted_with_one_read():
    _, policy, transport = collect("projects/1")
    assert policy["status"] == "collected"
    assert project_get_count(transport) == 1
    assert len(policy["items"]) == len(gcp.ORG_POLICY_CONSTRAINTS)


@pytest.mark.parametrize("parent,project", [
    ("projects/999", None),
    ("projects/1", {"name": "projects/1", "projectId": "foreign"}),
    ("projects/1", {"name": "projects/not-a-number", "projectId": "p-one"}),
    ("organizations/1", None),
], ids=["foreign-number", "foreign-project-id", "malformed-number", "foreign-parent"])
def test_foreign_or_unverified_parent_is_incomplete(parent, project):
    _, policy, transport = collect(parent, project=project)
    assert policy["status"] not in ("collected", "empty")
    assert project_get_count(transport) <= 1


@pytest.mark.parametrize("parent,suffix", [(None, None), (SCOPE, "compute.requireOsLogin")],
                         ids=["missing-name", "wrong-constraint"])
def test_missing_or_wrong_constraint_name_is_incomplete(parent, suffix):
    _, policy, transport = collect(parent, suffix=suffix)
    assert policy["status"] not in ("collected", "empty")
    assert project_get_count(transport) == 0


def test_denied_alias_lookup_remains_unknown_but_exact_parent_still_works():
    _, alias_policy, alias_transport = collect("projects/1", lookup_error=True)
    assert alias_policy["status"] not in ("collected", "empty")
    assert project_get_count(alias_transport) == 1
    _, exact_policy, exact_transport = collect(SCOPE, lookup_error=True)
    assert exact_policy["status"] == "collected"
    assert project_get_count(exact_transport) == 0


@pytest.mark.parametrize("parent,expected", [(SCOPE, "PASS"), ("projects/1", "PASS"), ("projects/999", "UNKNOWN")])
def test_inherited_bucket_normal_collector_engine(parent, expected):
    snapshot, policy, transport = collect(parent, kinds=("bucket", "org_policy_effective"))
    row = finding(snapshot, PAP)
    assert row["status"] == expected
    assert (policy["status"] == "collected") == (expected == "PASS")
    assert project_get_count(transport) <= 1


@pytest.mark.parametrize("parent,expected", [("projects/1", "PASS"), ("projects/999", "UNKNOWN")])
def test_unset_oslogin_normal_collector_engine(parent, expected):
    snapshot, policy, transport = collect(parent, kinds=("instance", "project", "org_policy_effective"))
    row = finding(snapshot, OSLOGIN)
    assert row["status"] == expected
    assert (policy["status"] == "collected") == (expected == "PASS")
    assert project_get_count(transport) <= 2  # project inventory plus at most one alias verification
