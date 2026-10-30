"""Cross-provider privesc joins (privesc.analyze related_snapshots) wired through the engine, the CLI and the
server/worker scan group, on the GKE + GCP fixture pattern of tests/test_peaso_privesc_audit_fixes.py."""
import json

from fastapi.testclient import TestClient

from peaso.engine import evaluate_snapshot, hydrate_frameworks
from peaso.snapshot import make_snapshot
from tests.test_peaso_privesc_audit_fixes import _gke, k8s, kobj

CREATED = "2026-10-10T00:00:00+00:00"


def _wrap(raw, metadata=None):
    collections = [{k: v for k, v in c.items() if not (k == "error" and v is None)} for c in raw["collections"]]
    return make_snapshot(raw["provider"], raw["scopes"], collections, created_at=CREATED, metadata=metadata or raw.get("metadata"))


def gke_pair():
    """A GCP project whose user may read KSA token secrets of GKE cluster c1, and the K8s snapshot of c1."""
    gcp = _gke("GCE_METADATA")
    for col in gcp["collections"]:
        if col["type"] == "iam_policy":
            col["items"][0]["bindings"].append({"role": "projects/p1/roles/secrets", "members": ["user:alice@x.com"]})
        if col["type"] == "gke_cluster":
            col["items"][0].update({"status": "RUNNING", "endpoint": "203.0.113.10"})
    gcp["collections"].append({"type": "iam_role", "scope": "projects/p1", "service": "iam_role", "status": "collected",
                               "items": [{"name": "projects/p1/roles/secrets", "includedPermissions": ["container.clusters.get", "container.secrets.get", "container.secrets.list"]}]})
    gcp["collections"].append({"type": "iam_deny_policy", "scope": "projects/p1", "service": "iam", "status": "empty", "items": []})
    secret = kobj("Secret", "tok", "a", type="kubernetes.io/service-account-token",
                  meta={"annotations": {"kubernetes.io/service-account.name": "builder",
                                        "kubernetes.io/service-account.uid": "builder-uid"}})
    account = kobj("ServiceAccount", "builder", "a", meta={"uid": "builder-uid"})
    return _wrap(gcp), _wrap(k8s(secrets=[secret], sas=[account]), {"cluster_id": "c1"})


def _cross_edges(report):
    return report["stats"]["privesc"]["cross_snapshot_edges"]


def _k8s_nodes(report):
    return [n for n in report["graphs"]["privesc"]["nodes"] if n.get("provider") == "k8s"]


def test_engine_passes_related_snapshots_to_privesc():
    gcp, cluster = gke_pair()
    alone = evaluate_snapshot(gcp, categories=["privesc"])
    assert _cross_edges(alone) == 0 and "related_snapshots" not in alone
    joined = evaluate_snapshot(gcp, categories=["privesc"], related_snapshots=[cluster])
    assert _cross_edges(joined) > 0 and _k8s_nodes(joined)
    assert all(n["attrs"].get("related_snapshot") for n in _k8s_nodes(joined) if n.get("kind") != "aggregate")
    assert joined["stats"]["privesc"]["related_snapshots"] == ["k8s"]
    assert joined["related_snapshots"] == [{"snapshot_id": cluster["snapshot_id"], "provider": "k8s", "scopes": cluster["scopes"], "created_at": CREATED}]
    # Findings stay about the primary snapshot; the primary itself, same-provider and duplicate snapshots are ignored.
    assert {f["provider"] for f in hydrate_frameworks(joined)["findings"]} <= {"gcp"}
    assert evaluate_snapshot(gcp, categories=["privesc"], related_snapshots=[cluster, cluster, gcp]) == joined
    # Non-privesc categories do not change with related snapshots.
    assert evaluate_snapshot(gcp, categories=["hardening"], related_snapshots=[cluster]) == {
        **evaluate_snapshot(gcp, categories=["hardening"]), "related_snapshots": joined["related_snapshots"]}


def test_cli_related_snapshot_flag(tmp_path):
    from peaso.cli import main
    gcp, cluster = gke_pair()
    (tmp_path / "gcp.json").write_text(json.dumps(gcp))
    (tmp_path / "gke.json").write_text(json.dumps(cluster))
    for command in (["evaluate", str(tmp_path / "gcp.json")], ["scan", "--snapshot", str(tmp_path / "gcp.json"), "--quiet"]):
        out = tmp_path / (command[0] + ".json")
        assert main(command + ["--categories", "privesc", "--related-snapshot", str(tmp_path / "gke.json"), "-o", str(out), "--quiet"]) == 0
        report = json.loads(out.read_text())
        assert _cross_edges(report) > 0 and report["related_snapshots"][0]["snapshot_id"] == cluster["snapshot_id"]
    single = tmp_path / "single.json"
    assert main(["evaluate", str(tmp_path / "gcp.json"), "--categories", "privesc", "-o", str(single), "--quiet"]) == 0
    assert _cross_edges(json.loads(single.read_text())) == 0


def test_server_scan_group_joins_cluster_and_cloud_scans_including_scheduled(tmp_path, monkeypatch):
    # Each run spawns collector and analyzer children that inherit the environment. The suite-wide
    # PEASO_SOURCE_ATTESTATION=always re-proves every source on their cold imports (minutes of CPU
    # per child), which can outlast the scan deadline. The children still prove every pinned source
    # once in the shipped mode; this process keeps the mode it was imported with.
    monkeypatch.delenv("PEASO_SOURCE_ATTESTATION", raising=False)
    from peaso.server import create_app
    from peaso.server.config import Settings
    from peaso.worker import Worker
    from tests.test_peaso_native_pipeline_acceptance import FixtureIdentities

    from peaso.auth import Identity

    class Paid(FixtureIdentities):  # several scans per week for one tenant
        def authenticate(self, authorization):
            return Identity(super().authenticate(authorization).tenant_id, paid=True)

        def is_paid(self, tenant):
            return True
    gcp, cluster = gke_pair()
    settings = Settings(state_dir=tmp_path / "state", identity_dir=tmp_path / "identity", local_token="related-fixture-token-0123456789abcdef")
    app = create_app(settings, authenticator=Paid())

    def run(client, connector_id):
        response = client.post("/api/scans", json={"ai_enabled": False, "connector_id": connector_id, "categories": ["privesc"]})
        assert response.status_code == 201, response.text
        ident = response.json()["id"]
        assert Worker("collector", settings).run_once() and Worker("analyzer", settings).run_once()
        assert client.get(f"/api/scans/{ident}").json()["status"] == "completed"
        return ident

    with TestClient(app, base_url="http://127.0.0.1:8000") as client:
        def connector(name, snapshot, token="fixture-owner"):
            client.headers["Authorization"] = "Bearer " + token
            response = client.post("/api/connectors", json={"name": name, "provider": snapshot["provider"], "auth": {},
                                                            "scopes": snapshot["scopes"], "options": {"snapshot": snapshot}})
            assert response.status_code == 201, response.text
            return response.json()["id"]
        # Another tenant's cluster never joins.
        run(client, connector("foreign cluster", cluster, "fixture-other"))
        gcp_id = connector("project p1", gcp)
        first = run(client, gcp_id)
        assert client.get(f"/api/scans/{first}/summary").json()["stats"]["privesc"]["cross_snapshot_edges"] == 0
        cluster_id = connector("cluster c1", cluster)
        cluster_scan = run(client, cluster_id)
        # A scheduled re-scan of the project joins the tenant's latest cluster snapshot.
        client.post("/api/schedules", json={"ai_enabled": False, "connector_id": gcp_id, "categories": ["privesc"], "next_run_at": "2020-01-01T00:00:00+00:00"})
        store = app.state.store
        triggered = store.trigger_schedule(store.due_schedules()[0], limit=10)
        assert Worker("collector", settings).run_once() and Worker("analyzer", settings).run_once()
        summary = client.get(f"/api/scans/{triggered['id']}/summary").json()
        assert summary["stats"]["privesc"]["cross_snapshot_edges"] > 0
        assert [(r["scan_id"], r["provider"]) for r in summary["related_snapshots"]] == [(cluster_scan, "k8s")]
        graph = client.get(f"/api/scans/{triggered['id']}/graphs/privesc").json()
        assert any(n.get("provider") == "k8s" and (n.get("attrs") or {}).get("related_snapshot") for n in graph["nodes"])
