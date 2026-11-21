"""Exact ownership and concurrent-policy preservation, without live mutations."""
import copy
import json

import pytest

from scripts.peaso_test_resources.gke_session_guard import NODE_ROLE, PROJECT, Session, SessionError, plan
from scripts.peaso_test_resources.gcp_live_acceptance import collect_gke, ordinary_joins, summarize
from peaso.snapshot import make_snapshot


@pytest.fixture
def session(tmp_path):
    plan(tmp_path)
    return Session(tmp_path)


def test_private_ledger_and_unowned_identity_refused(session):
    assert session.directory.stat().st_mode & 0o777 == 0o700
    assert session.ledger.stat().st_mode & 0o777 == 0o600
    data = json.loads(session.ledger.read_text())
    data["project"] = "another-project"
    session.ledger.write_text(json.dumps(data))
    with pytest.raises(SessionError, match="ledger_identity_mismatch"):
        Session(session.directory)


def test_foreign_cluster_label_refuses_deletion(session, monkeypatch):
    monkeypatch.setattr(session, "cluster", lambda: {"name": session.data["cluster"], "location": session.data["zone"],
                                                   "resourceLabels": {"peaso-owner": "foreign"}})
    monkeypatch.setattr(session, "cli", lambda *a, **kw: pytest.fail("unowned cluster reached deletion"))
    with pytest.raises(SessionError, match="cluster_ownership_mismatch"):
        session.cleanup()


def test_remove_only_owned_exact_membership_preserves_new_policy_changes(session, monkeypatch):
    email = session.data["resources"][0]["email"]
    member = "serviceAccount:" + email
    session.data["iam_additions"] = [{"member": member, "role": NODE_ROLE, "status": "added"}]
    policy = {"version": 3, "etag": "fresh-concurrent-etag", "auditConfigs": [{"service": "allServices"}], "bindings": [
        {"role": NODE_ROLE, "members": [member, "serviceAccount:unrelated@example.invalid"]},
        {"role": NODE_ROLE, "members": [member], "condition": {"expression": "false", "title": "unowned-conditional"}},
        {"role": "roles/viewer", "members": ["user:unrelated@example.invalid"]}]}
    written = []
    monkeypatch.setattr(session, "project_policy", lambda: copy.deepcopy(policy))
    def api(method, path, body=None, mutation=False):
        assert mutation is True
        assert body["policy"]["etag"] == "fresh-concurrent-etag"
        written.append(body["policy"])
        policy.clear()
        policy.update(copy.deepcopy(body["policy"]))
        policy["etag"] = "updated-etag"
        return copy.deepcopy(policy)
    monkeypatch.setattr(session, "api", api)
    session.membership(email, remove=True)
    assert written[0]["bindings"][0]["members"] == ["serviceAccount:unrelated@example.invalid"]
    assert written[0]["bindings"][1]["members"] == [member]
    assert written[0]["auditConfigs"] == [{"service": "allServices"}]
    assert session.data["iam_additions"][0]["verification"] == "exact_membership_absent"


def test_missing_etag_and_preexisting_member_never_mutate(session, monkeypatch):
    email = session.data["resources"][0]["email"]
    monkeypatch.setattr(session, "api", lambda *a, **kw: pytest.fail("unsafe IAM mutation"))
    monkeypatch.setattr(session, "project_policy", lambda: {"bindings": []})
    with pytest.raises(SessionError, match="policy_etag_missing"):
        session.membership(email)
    monkeypatch.setattr(session, "project_policy", lambda: {"etag": "etag", "bindings": [{"role": NODE_ROLE, "members": ["serviceAccount:" + email]}]})
    with pytest.raises(SessionError, match="preexisting_membership_not_owned"):
        session.membership(email)


def test_absent_resources_cleanup_is_idempotent_and_removes_private_credentials(session, monkeypatch):
    session.kubeconfig.write_text("fixture-private-context")
    cache = session.directory / "gke_gcloud_auth_plugin_cache"
    cache.write_text("fixture-auth-cache")
    monkeypatch.setattr(session, "cluster", lambda: None)
    monkeypatch.setattr(session, "service_account", lambda email: None)
    monkeypatch.setattr(session, "cli", lambda args, **kw: None if "describe" in args else pytest.fail("absent resource mutated"))
    monkeypatch.setattr(session, "membership", lambda email, remove=False: None)
    session.cleanup()
    session.cleanup()
    assert not session.kubeconfig.exists()
    assert not cache.exists() and session.data["credential_cache_removed"]
    assert session.data["phase"] == "cleaned"
    assert all(row["verification"] == "not_found" for row in session.data["resources"])


def test_cleanup_waits_for_deleted_service_account_to_disappear_from_list(session, monkeypatch):
    from scripts.peaso_test_resources import gke_session_guard as guard

    email = session.data["resources"][0]["email"]
    owned = {"displayName": "peaso-owned-" + session.data["owner"]}
    node_reads = iter((owned, owned, None))
    deletes = []
    sleeps = []
    monkeypatch.setattr(session, "cluster", lambda: None)
    monkeypatch.setattr(session, "service_account", lambda name: next(node_reads) if name == email else None)
    monkeypatch.setattr(session, "cli", lambda *args, **kwargs: None)
    monkeypatch.setattr(session, "membership", lambda *args, **kwargs: None)
    monkeypatch.setattr(session, "api", lambda method, path, **kwargs: deletes.append((method, path)))
    monkeypatch.setattr(guard.time, "sleep", sleeps.append)

    session.cleanup()

    assert deletes == [("DELETE", "iam.googleapis.com/v1/projects/" + PROJECT + "/serviceAccounts/" + email)]
    assert sleeps == [2]
    assert session.data["phase"] == "cleaned"


def test_declared_joins_use_exact_project_zone_and_identity_references():
    cloud = make_snapshot("gcp", [PROJECT], [
        {"type": "instance", "scope": PROJECT, "status": "collected", "items": [
            {"selfLink": "https://www.googleapis.com/compute/v1/projects/" + PROJECT + "/zones/us-central1-a/instances/same"},
            {"selfLink": "https://www.googleapis.com/compute/v1/projects/foreign/zones/us-central1-a/instances/same"}]},
        {"type": "service_account", "scope": PROJECT, "status": "collected", "items": [{"email": "owned@" + PROJECT + ".iam.gserviceaccount.com"}]}])
    kube = make_snapshot("k8s", ["fixture"], [
        {"type": "node", "scope": "fixture", "status": "collected", "items": [{"metadata": {"name": "same"}, "spec": {"providerID": "gce://" + PROJECT + "/us-central1-a/same"}}]},
        {"type": "serviceaccount", "scope": "fixture", "status": "collected", "items": [{"metadata": {"name": "work", "namespace": "fixture", "annotations": {
            "iam.gke.io/gcp-service-account": "owned@" + PROJECT + ".iam.gserviceaccount.com"}}}]}])
    joins = ordinary_joins(cloud, kube, "fixture")
    assert len(joins) == 2
    assert all(j["target"] for j in joins)
    assert all("effective access" in j["semantics"] or "no routing inference" in j["semantics"] for j in joins)


def test_live_summary_preserves_denied_empty_and_explicit_limit_evidence():
    snap = make_snapshot("gcp", [PROJECT], [
        {"type": "network", "scope": PROJECT, "status": "empty", "items": []},
        {"type": "bucket", "scope": PROJECT, "status": "denied", "items": [], "error": {"code": "api_error"}}],
        metadata={"intentional_limits": {"deadline_seconds": 100}})
    summary = summarize(snap)
    assert summary["collection_statuses"] == {"empty": 1, "denied": 1}
    assert summary["intentional_limits"] == {"deadline_seconds": 100}
    assert summary["resources"] == 0


def test_deleted_sa_absence_requires_successful_project_listing(session, monkeypatch):
    email = session.data["resources"][0]["email"]
    calls = []
    def listed(method, path, **kwargs):
        calls.append(path)
        assert method == "GET"
        assert path.startswith("iam.googleapis.com/v1/projects/" + PROJECT + "/serviceAccounts?")
        return {"accounts": []}
    monkeypatch.setattr(session, "api", listed)
    assert session.service_account(email) is None
    assert len(calls) == 1
    def denied(*args, **kwargs):
        raise SessionError("PERMISSION_DENIED")
    monkeypatch.setattr(session, "api", denied)
    with pytest.raises(SessionError, match="PERMISSION_DENIED"):
        session.service_account(email)


def test_summary_retains_service_disabled_reason_and_exact_source_request():
    snap = make_snapshot("gcp", [PROJECT], [{"type": "sql_instance", "scope": PROJECT, "service": "sqladmin", "status": "unknown",
        "coverage_status": "unavailable", "items": [], "source_requests": ["gcp-request-7"],
        "error": {"code": "api_error", "kind": "unavailable", "http_status": 403, "reason": "SERVICE_DISABLED"}}])
    summary = summarize(snap)
    assert summary["coverage_statuses"] == {"unavailable": 1}
    assert summary["api_error_evidence"][0]["source_requests"] == ["gcp-request-7"]
    assert summary["api_error_evidence"][0]["error"]["reason"] == "SERVICE_DISABLED"
    assert summary["service_coverage"]["sqladmin"]["statuses"] == {"unavailable": 1}


def test_sa_absence_check_follows_all_pages_and_does_not_confuse_projects(session, monkeypatch):
    email = session.data["resources"][0]["email"]
    calls = []
    def api(method, path, **kwargs):
        calls.append(path)
        if "pageToken=" not in path:
            return {"accounts": [{"email": email, "projectId": "foreign-project"}], "nextPageToken": "opaque+page"}
        assert "pageToken=opaque%2Bpage" in path
        return {"accounts": [{"email": email, "projectId": PROJECT, "uniqueId": "owned-id"}]}
    monkeypatch.setattr(session, "api", api)
    assert session.service_account(email)["uniqueId"] == "owned-id"
    assert len(calls) == 2


def test_captured_gke_evidence_cannot_be_overwritten_by_diagnostic_retry(session, monkeypatch):
    from peaso.collectors import gcp
    artifact = session.directory / "gke-k8s-snapshot.json"
    artifact.write_text("immutable-first-capture")
    monkeypatch.setattr(gcp, "collect", lambda *a, **kw: pytest.fail("retry reached a live cloud request"))
    with pytest.raises(SessionError, match="gke_evidence_already_exists"):
        collect_gke(session)
    assert artifact.read_text() == "immutable-first-capture"


def test_generated_node_ownership_handles_truncated_names_and_rejects_foreign_project(session):
    from scripts.peaso_test_resources.gcp_live_cleanup_verify import owned_generated_references
    network = "https://www.googleapis.com/compute/v1/projects/" + PROJECT + "/global/networks/" + session.data["cluster"]
    prefix = "https://www.googleapis.com/compute/v1/projects/" + PROJECT + "/zones/us-central1-a/"
    instance = {"name": "gke-truncated-name", "selfLink": prefix + "instances/gke-truncated-name", "id": "123",
                "labels": {"peaso-owner": session.data["owner"]}, "networkInterfaces": [{"network": network}],
                "disks": [{"source": prefix + "disks/owned-boot"}]}
    snapshot = {"collections": [{"type": "instance", "items": [instance]}]}
    refs = owned_generated_references(snapshot, session.data)
    assert {row["kind"] for row in refs} == {"instance", "disk"}
    instance["disks"][0]["source"] = "https://www.googleapis.com/compute/v1/projects/foreign/zones/us-central1-a/disks/owned-boot"
    with pytest.raises(SessionError, match="outside_authorized_project"):
        owned_generated_references(snapshot, session.data)
