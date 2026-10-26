"""IAM graph payload bounds: slim grant cards and one node per provider-managed definition.

The graph is a display/navigation view; findings and the complete grant lists are derived from the
snapshot (resources), never from the bounded graph card."""
import json

import pytest
from fastapi.testclient import TestClient

from peaso.analysis import analyze_findings, build_graphs
from peaso.analysis.iam import GRANT_SAMPLE, MANAGED_SCOPE, full_grants, grants
from peaso.engine import collect_snapshot, evaluate_snapshot, hydrate_frameworks
from peaso.report_quality import normalize_unknown_reasons
from peaso.server import create_app
from peaso.server.config import Settings
from peaso.snapshot import make_snapshot, resources
from peaso.worker import Worker

HIGH = ["iam.serviceAccounts.actAs", "resourcemanager.projects.setIamPolicy", "iam.serviceAccountKeys.create"]
OWNER_PERMISSIONS = HIGH + [f"svc{i:05d}.things.get" for i in range(10_000)]


def gcp_snapshot(projects, *, role_items=None, bound_roles=("roles/owner",)):
    collections = []
    for project in projects:
        scope = f"projects/{project}"
        items = role_items(project) if role_items else [{"name": "roles/owner", "title": "Owner", "includedPermissions": OWNER_PERMISSIONS}]
        collections.append({"type": "iam_role", "scope": scope, "service": "iam", "status": "collected", "items": items})
        collections.append({"type": "iam_policy", "scope": scope, "service": "resourcemanager", "status": "collected",
                            "items": [{"name": f"{scope}/iamPolicy", "bindings": [{"role": role, "members": [f"user:owner-{project}@example.com"]}
                                                                                   for role in bound_roles]}]})
    return make_snapshot("gcp", [f"projects/{p}" for p in projects], collections, created_at="2026-01-01T00:00:00+00:00")


def iam_graph(snapshot):
    return build_graphs(snapshot, resources(snapshot), max_nodes=None)["iam"]


def test_card_stays_bounded_for_a_role_with_ten_thousand_permissions():
    snap = gcp_snapshot(["p1"], role_items=lambda p: [{"name": f"projects/{p}/roles/huge", "includedPermissions": OWNER_PERMISSIONS}])
    role = next(n for n in iam_graph(snap)["nodes"] if n["type"] == "iam_role")
    card = role["card"]
    assert card["grant_count"] == len(OWNER_PERMISSIONS) and card["source_grants_truncated"] is True
    assert len(card["source_grants"]) == GRANT_SAMPLE
    assert len(json.dumps(card)) < 20_000  # was ~3.4 MB for a 10k-permission role
    # The sample is the highest-risk grants, with their native evidence (path + permission).
    assert {g["native_grant"] for g in card["source_grants"][:len(HIGH)]} == set(HIGH)
    assert all(g["path"].startswith("includedPermissions[") for g in card["source_grants"])
    summary = card["grant_summary"]
    assert sum(summary["by_severity"].values()) == len(OWNER_PERMISSIONS) == summary["allowed"]
    assert summary["high_risk_allowed"] >= len(HIGH) and summary["conditional"] == 0
    # The high-risk annotation comes from the complete list, not the sample.
    assert {"state": "conditional", "type": "high_risk_grant"} in role["risk_annotations"]
    native = next(r for r in resources(snap) if r["type"] == "iam_role")
    assert card["detail_ref"]["resource_ref"] == native["id"] == role["evidence"]["native_resource_ref"]


def test_small_cards_keep_the_complete_grant_list_in_declaration_order():
    snap = gcp_snapshot(["p1"], role_items=lambda p: [{"name": f"projects/{p}/roles/small", "includedPermissions": ["storage.buckets.list", HIGH[0]]}])
    card = next(n for n in iam_graph(snap)["nodes"] if n["type"] == "iam_role")["card"]
    assert [g["native_grant"] for g in card["source_grants"]] == ["storage.buckets.list", HIGH[0]]
    assert card["grant_count"] == 2 and card["source_grants_truncated"] is False


def test_predefined_role_used_in_fifty_projects_is_one_node():
    projects = [f"p{i:02d}" for i in range(50)]
    # roles/viewer is bound everywhere but never collected: one reference node, not 50.
    snap = gcp_snapshot(projects, bound_roles=("roles/owner", "roles/viewer"))
    graph = iam_graph(snap)
    owners = [n for n in graph["nodes"] if n["label"] == "roles/owner"]
    viewers = [n for n in graph["nodes"] if n["label"] == "roles/viewer"]
    assert len(owners) == 1 and len(viewers) == 1
    owner = owners[0]
    assert owner["scope"] == MANAGED_SCOPE and owner["provider_managed"] is True
    assert set(owner["scope_refs"]) == {f"projects/{p}" for p in projects}
    assert owner["card"]["grant_count"] == len(OWNER_PERMISSIONS)
    # Every binding edge keeps the scope it was declared at in its evidence.
    edges = [e for e in graph["edges"] if e["target"] == owner["id"] and e["type"] == "role_definition"]
    assert len(edges) == 50 and {e["evidence"]["scope"] for e in edges} == {f"projects/{p}" for p in projects}
    assert len({e["id"] for e in graph["edges"]}) == len(graph["edges"])
    assert len(json.dumps(graph)) < 2_000_000
    # Findings stay per collected resource: 50 role reviews, computed from the complete grants.
    reviews = [f for f in analyze_findings(snap) if f["check_id"] == "analysis.grant_review" and f["service"] == "iam"]
    native = {row["id"]: row for row in resources(snap)}
    policy_reviews = [f for f in reviews if native[f["resource_id"]]["type"] == "iam_policy"]
    assert len(policy_reviews) == 50 and all(f["status"] == "MANUAL" for f in policy_reviews)
    reviews = [f for f in reviews if native[f["resource_id"]]["type"] == "iam_role"]
    assert len(reviews) == 50 and {f["scope"] for f in reviews} == {f"projects/{p}" for p in projects}
    assert all(len(f["evidence"]["grants"]) >= len(HIGH) for f in reviews)


def test_principal_granted_in_fifty_projects_is_one_reference_node():
    projects = [f"p{i:02d}" for i in range(50)]
    collections = [{"type": "iam_policy", "scope": f"projects/{p}", "service": "resourcemanager", "status": "collected",
                    "items": [{"name": f"projects/{p}/iamPolicy", "bindings": [
                        {"role": "roles/viewer", "members": ["user:shared@example.com", "allUsers", f"user:only-{p}@example.com"]}]}]}
                   for p in projects]
    snap = make_snapshot("gcp", [f"projects/{p}" for p in projects], collections, created_at="2026-01-01T00:00:00+00:00")
    graph = iam_graph(snap)
    shared = [n for n in graph["nodes"] if n["label"] == "user:shared@example.com"]
    everyone = [n for n in graph["nodes"] if n["type"] == "everyone"]
    assert len(shared) == 1 and len(everyone) == 1
    assert len([n for n in graph["nodes"] if n["label"].startswith("user:only-")]) == 50
    assert shared[0]["referenced_scopes"] == sorted(f"projects/{p}" for p in projects)
    edges = [e for e in graph["edges"] if e["source"] == shared[0]["id"] and e["type"] == "declared_grant"]
    assert len(edges) == 50 and {e["evidence"]["source"]["scope"] for e in edges} == {f"projects/{p}" for p in projects}
    assert len(shared[0]["card"]["observed_bindings"]) == 50
    assert len({e["id"] for e in graph["edges"]}) == len(graph["edges"])


def test_a_managed_copy_with_different_grants_keeps_its_own_node():
    def items(project):
        permissions = OWNER_PERMISSIONS[:10] + (["extra.permission.get"] if project == "p2" else [])
        return [{"name": "roles/owner", "includedPermissions": permissions}]
    graph = iam_graph(gcp_snapshot(["p1", "p2", "p3"], role_items=items))
    owners = [n for n in graph["nodes"] if n["label"] == "roles/owner"]
    assert len(owners) == 2
    merged = next(n for n in owners if n.get("provider_managed"))
    assert set(merged["scope_refs"]) == {"projects/p1", "projects/p3"}
    assert next(n for n in owners if not n.get("provider_managed"))["scope"] == "projects/p2"


@pytest.mark.parametrize("provider", ["aws", "gcp", "azure", "k8s"])
def test_least_privilege_findings_come_from_complete_grants_on_demo_snapshots(provider):
    snap = collect_snapshot({"provider": provider, "options": {"demo": True}})
    report = hydrate_frameworks(evaluate_snapshot(snap, include_not_applicable=True))
    # The engine names the reason of every UNKNOWN finding; the analyzer output gets the same contract.
    # Manual-only grant reviews stay library/archive identities and are excluded from scans.
    from peaso.analysis import MANUAL_ONLY_ANALYSIS_CHECK_IDS
    direct = [f for f in normalize_unknown_reasons(analyze_findings(snap, include_manual_only=False)) if f["category"] == "least_privilege"]
    reported = [f for f in report["findings"] if f["category"] == "least_privilege" and f["check_id"].startswith("analysis.")]
    assert not any(f["check_id"] in MANUAL_ONLY_ANALYSIS_CHECK_IDS for f in reported)
    key = lambda f: (f["id"], f["status"], f["severity"], json.dumps(f["evidence"], sort_keys=True, default=str))
    assert sorted(map(key, reported)) == sorted(map(key, direct))
    inventory = {r["id"]: r for r in resources(snap)}
    for current in report["graphs"]["iam"]["nodes"]:
        card = current.get("card") or {}
        ref = (card.get("detail_ref") or {}).get("resource_ref")
        if ref in inventory:
            assert card["grant_count"] == len(grants(inventory[ref]))


def test_api_serves_the_complete_grant_list_behind_a_slim_card(tmp_path):
    snap = gcp_snapshot(["p1"])
    settings = Settings(state_dir=tmp_path / "state", identity_dir=tmp_path / "identity", local_token="local-test-token-0123456789abcdef")
    from tests.test_peaso_graph_scale import Identities
    with TestClient(create_app(settings, authenticator=Identities()), base_url="http://127.0.0.1:8000") as client:
        client.headers["Authorization"] = "Bearer alice"
        connector = client.post("/api/connectors", json={"name": "slim", "provider": "gcp", "auth": {}, "scopes": snap["scopes"],
                                                         "options": {"snapshot": snap}})
        assert connector.status_code == 201, connector.text
        job = client.post("/api/scans", json={"ai_enabled": False, "connector_id": connector.json()["id"], "categories": ["iam_graph", "least_privilege"]})
        assert job.status_code == 201, job.text
        assert Worker("collector", settings).run_once() and Worker("analyzer", settings).run_once()
        ident = job.json()["id"]
        graph = client.get(f"/api/scans/{ident}/graphs/iam").json()
        role = next(n for n in graph["nodes"] if n["label"] == "roles/owner")
        assert role["card"]["source_grants_truncated"] and len(role["card"]["source_grants"]) == GRANT_SAMPLE
        detail = client.get(f"/api/scans/{ident}/resources/{role['card']['detail_ref']['resource_ref']}")
        assert detail.status_code == 200
        complete = full_grants(detail.json(), "gcp")
        assert len(complete) == role["card"]["grant_count"] == len(OWNER_PERMISSIONS)
        assert [g["native_grant"] for g in complete] == OWNER_PERMISSIONS
