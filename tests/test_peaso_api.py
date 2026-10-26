import concurrent.futures
import json
from pathlib import Path
import time
import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient
from peaso.auth import Identity, CredentialCipher
from peaso.server import create_app
from peaso.server.config import Settings
from peaso.storage import SQLiteStore, StoreError, FileArtifacts
from peaso.worker import Worker

TOKEN = "local-test-token-0123456789abcdef"
# The worker's public identity adapter accepts only canonical native scopes.
SCOPE = "123456789012/us-east-1"


class TestIdentities:
    __test__ = False
    def authenticate(self, authorization):
        users = {"Bearer alice": Identity("alice"), "Bearer bob": Identity("bob"), "Bearer paid": Identity("paid", True)}
        if authorization not in users:
            raise HTTPException(401, "Invalid authentication")
        return users[authorization]

    def is_paid(self, tenant):
        return tenant == "paid"


@pytest.fixture
def settings(tmp_path):
    return Settings(state_dir=tmp_path / "state", identity_dir=tmp_path / "identity", local_token=TOKEN)


@pytest.fixture
def client(settings, monkeypatch):
    # Model a configured AI deployment for API quota/ownership tests. Agent
    # execution and missing-token/isolation rejection have dedicated tests.
    # Scan creation now proves a provider/model configuration through
    # require_local_codex (resolve_access), not the codex_available probe.
    monkeypatch.setattr('peaso.ai.auth.require_local_codex', lambda *args: None)
    monkeypatch.setattr('peaso.ai.isolation.available', lambda: True)
    monkeypatch.setattr('peaso.server.access_check.check_access', lambda *args, **kwargs: {
        'status': 'pass', 'issues': [], 'principals': []})
    app = create_app(settings, authenticator=TestIdentities())
    with TestClient(app, base_url="http://127.0.0.1:8000") as value:
        value.headers["Authorization"] = "Bearer alice"
        yield value


def add_connector(client, **overrides):
    body = {"name": "Fixture", "provider": "aws", "auth": {}, "scopes": [SCOPE], "options": {}}
    body.update(overrides)
    if "snapshot" not in body["options"] and not body["options"].get("demo"):
        checked = client.post("/api/connectors/check-access", json=body)
        assert checked.status_code == 200, checked.text
        body["check_token"] = checked.json()["check_token"]
    response = client.post("/api/connectors", json=body)
    assert response.status_code == 201, response.text
    return response.json()


def snapshot():
    from peaso.snapshot import make_snapshot
    return make_snapshot("aws", [SCOPE], [{"type": "bucket", "scope": SCOPE, "service": "s3", "status": "collected", "items": [{"Name": "fixture-bucket", "public": True, "note": "secret-value-123456"}]}], created_at="2026-01-01T00:00:00+00:00")


def test_local_token_origin_and_host(settings):
    with TestClient(create_app(settings), base_url="http://127.0.0.1:8000") as client:
        assert client.get("/api/health").status_code == 200
        assert client.get("/api/me").status_code == 401
        headers = {"Authorization": "Bearer " + TOKEN}
        assert client.get("/api/me", headers=headers).json()["weekly_limit"] == 1
        assert client.get("/api/me", headers={**headers, "Origin": "https://evil.invalid"}).status_code == 403
        assert client.get("/api/me", headers={**headers, "Host": "evil.invalid"}).status_code == 403
        assert client.post("/api/scans", headers=headers, json={"connector_id": "x", "paid": True}).status_code == 422


def test_connector_ciphertext_redaction_validation_and_private_files(client, settings, caplog):
    secret = "secret-value-123456"
    value = add_connector(client, auth={"token": secret}, options={"snapshot": snapshot(), "password": secret}, name="Fixture " + secret)
    assert secret not in json.dumps(value)
    assert "snapshot" not in value["options"]
    assert value["auth"] == {"configured": True, "fields": ["token"]}
    assert secret not in client.get("/api/connectors").text
    response = client.post("/api/connectors", json={"name": "bad", "provider": "aws", "auth": secret})
    assert response.status_code == 422 and secret not in response.text
    assert secret not in caplog.text
    assert secret.encode() not in (settings.state_dir / "peaso.sqlite3").read_bytes()
    for path in [settings.state_dir / "peaso.sqlite3", settings.identity_dir / "credentials.key"]:
        assert path.stat().st_mode & 0o777 == 0o600


def test_redaction_never_corrupts_connector_route_or_structural_metadata(client):
    value = add_connector(client, auth={"method": "token", "token": "a", "context": "aws"}, options={"snapshot": snapshot()})
    listed = client.get("/api/connectors").json()["items"][0]
    assert listed["id"] == value["id"] and listed["provider"] == "aws"
    assert listed["input_mode"] == "offline_snapshot"
    assert client.get("/api/connectors/" + listed["id"]).status_code == 200


def test_tenant_escape_all_owned_endpoints(client):
    # Schedules require durable credentials (or offline input); temporary/empty
    # live auth is rejected before ownership could be exercised.
    connector = add_connector(client, options={"snapshot": snapshot()})
    scan = client.post("/api/scans", json={"connector_id": connector["id"]})
    assert scan.status_code == 201, scan.text
    scan = scan.json()
    schedule = client.post("/api/schedules", json={"connector_id": connector["id"], "interval_hours": 168})
    assert schedule.status_code == 201, schedule.text
    schedule = schedule.json()
    client.headers["Authorization"] = "Bearer bob"
    for path in ("connectors", "scans", "schedules"):
        assert client.get("/api/" + path).json() == {"items": []}
    for method, path, payload in [
        ("GET", f"connectors/{connector['id']}", None),
        ("PATCH", f"connectors/{connector['id']}", {"name": "stolen"}),
        ("DELETE", f"connectors/{connector['id']}", None),
        ("POST", "scans", {"connector_id": connector["id"]}),
        ("GET", f"scans/{scan['id']}", None),
        ("POST", f"scans/{scan['id']}/cancel", None),
        ("GET", f"scans/{scan['id']}/report", None),
        ("GET", f"scans/{scan['id']}/findings", None),
        ("GET", f"scans/{scan['id']}/graphs/network", None),
        ("GET", f"scans/{scan['id']}/graphs/iam", None),
        ("PATCH", f"schedules/{schedule['id']}", {"enabled": False}),
        ("DELETE", f"schedules/{schedule['id']}", None),
        ("POST", "schedules", {"connector_id": connector["id"]}),
    ]:
        response = client.request(method, "/api/" + path, json=payload) if payload is not None else client.request(method, "/api/" + path)
        assert response.status_code == 404, (method, path, response.text)
    assert client.app.state.store.usage("bob") == 0


def test_quota_idempotency_and_mismatch(client):
    connector = add_connector(client)
    request = {"connector_id": connector["id"]}
    headers = {"Idempotency-Key": "retry-safe"}
    first = client.post("/api/scans", json=request, headers=headers)
    assert first.status_code == 201
    assert client.post("/api/scans", json=request, headers=headers).json()["id"] == first.json()["id"]
    assert client.post("/api/scans", json={**request, "categories": ["network"]}, headers=headers).status_code == 409
    assert client.post("/api/scans", json=request).status_code == 429
    assert client.get("/api/me").json()["weekly_used"] == 1
    assert client.post(f"/api/scans/{first.json()['id']}/cancel").json()["status"] == "cancelled"
    assert client.post("/api/scans", json=request).status_code == 429  # no cancellation refunds


@pytest.mark.parametrize("limit", [1, 10])
def test_concurrent_atomic_weekly_quota(settings, limit):
    store = SQLiteStore(settings.state_dir)
    connector = store.add_connector("tenant", {"provider": "aws"}, "encrypted")
    def enqueue(index):
        try:
            return store.enqueue("tenant", {"connector_id": connector["id"]}, limit, idem="run-" + str(index))
        except StoreError as exc:
            return exc.status
    with concurrent.futures.ThreadPoolExecutor(max_workers=16) as executor:
        results = list(executor.map(enqueue, range(32)))
    assert sum(isinstance(result, dict) for result in results) == limit
    assert all(isinstance(result, dict) or result == 429 for result in results)
    assert store.usage("tenant") == limit
    assert len(SQLiteStore(settings.state_dir).jobs("tenant")) == limit


def test_concurrent_idempotency_single_charge(settings):
    store = SQLiteStore(settings.state_dir)
    connector = store.add_connector("tenant", {"provider": "aws"}, "encrypted")
    with concurrent.futures.ThreadPoolExecutor(max_workers=12) as executor:
        results = list(executor.map(lambda _: store.enqueue("tenant", {"connector_id": connector["id"]}, idem="same-key"), range(24)))
    assert len({result["id"] for result in results}) == 1
    assert store.usage("tenant") == 1


def test_lease_fencing_cancellation_deadline_and_restart(settings):
    store = SQLiteStore(settings.state_dir)
    connector = store.add_connector("tenant", {"provider": "aws"}, "encrypted")
    job = store.enqueue("tenant", {"connector_id": connector["id"]}, timeout=100, now=1000)
    first = store.claim("collector", lease_seconds=5, now=1001)
    assert first["id"] == job["id"]
    restarted = SQLiteStore(settings.state_dir)
    assert restarted.claim("collector", now=1002) is None
    second = restarted.claim("collector", now=1007)
    assert second["owner"] != first["owner"]
    assert not store.finish(job["id"], first["owner"], "collected", "stale", now=1008)
    assert restarted.finish(job["id"], second["owner"], "collected", "owned", now=1008)
    analyzer = restarted.claim("analyzer", now=1009)
    assert not restarted.finish(job["id"], analyzer["owner"], "collected", "bad-transition", now=1010)
    restarted.cancel("tenant", job["id"])
    assert not restarted.finish(job["id"], analyzer["owner"], "completed", "late", now=1010)
    other = restarted.enqueue("other", {"connector_id": restarted.add_connector("other", {"provider": "aws"}, "encrypted")["id"]}, timeout=1, now=1000)
    # A never-admitted job is bounded by the durable queue wait, not by its
    # execution timeout; only an admitted job can exceed its scan deadline.
    from peaso.storage.sqlite import QUEUE_WAIT_SECONDS
    restarted.expire(1002)
    assert restarted.job("other", other["id"])["status"] == "queued"
    restarted.expire(1000 + QUEUE_WAIT_SECONDS)
    assert restarted.job("other", other["id"])["status"] == "queue_exhausted"
    admitted = restarted.enqueue("third", {"connector_id": restarted.add_connector("third", {"provider": "aws"}, "encrypted")["id"]}, timeout=1, now=5000)
    assert restarted.claim("collector", now=5000, tenant="third", ident=admitted["id"])["id"] == admitted["id"]
    restarted.expire(5002)
    assert restarted.job("third", admitted["id"])["status"] == "timed_out"


def test_scheduler_occurrence_atomic_and_manual_shared_quota(settings):
    store = SQLiteStore(settings.state_dir)
    connector = store.add_connector("tenant", {"provider": "aws"}, "encrypted")
    store.add_schedule("tenant", {"connector_id": connector["id"], "interval_hours": 168}, next_run=1000)
    row = store.due_schedules(1000)[0]
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
        results = list(executor.map(lambda _: store.trigger_schedule(row, now=1000), range(16)))
    assert sum(result is not None for result in results) == 1
    assert store.usage("tenant", 1000) == 1
    with pytest.raises(StoreError) as error:
        store.enqueue("tenant", {"connector_id": connector["id"]}, now=1001)
    assert error.value.status == 429
    next_week = 1000 + 168 * 3600
    assert store.trigger_schedule(store.due_schedules(next_week)[0], now=next_week)
    assert store.usage("tenant", next_week) == 1


def test_scheduler_failure_advances_without_partial_charge(settings):
    store = SQLiteStore(settings.state_dir)
    connector = store.add_connector("tenant", {"provider": "aws"}, "encrypted")
    store.enqueue("tenant", {"connector_id": connector["id"]}, now=1000)
    store.add_schedule("tenant", {"connector_id": connector["id"], "interval_hours": 168}, next_run=1001)
    assert store.trigger_schedule(store.due_schedules(1001)[0], now=1001) is None
    assert store.schedules("tenant")[0]["last_error"] == "Weekly scan quota exhausted"
    assert store.due_schedules(1002) == []
    assert store.usage("tenant", 1001) == 1


def test_artifact_path_and_tenant_escape(settings):
    artifacts = FileArtifacts(settings.state_dir / "artifacts")
    reference = artifacts.put("alice", "a" * 32, "report", {"private": True})
    assert artifacts.get("alice", reference) == {"private": True}
    for tenant, invalid in [("bob", reference), ("alice", "../../secret"), ("alice", "/etc/passwd")]:
        with pytest.raises(ValueError):
            artifacts.get(tenant, invalid)


def test_worker_end_to_end_offline_report_and_downloads(client, settings, caplog):
    connector = add_connector(client, auth={"token": "secret-value-123456"}, options={"snapshot": snapshot()})
    job = client.post("/api/scans", json={"connector_id": connector["id"]}).json()
    collector = Worker("collector", settings)
    analyzer = Worker("analyzer", settings)
    assert collector.run_once()
    assert client.get(f"/api/scans/{job['id']}").json()["status"] == "collected"
    # Connector removal does not destroy the immutable job input/evidence.
    client.delete(f"/api/connectors/{connector['id']}")
    assert analyzer.run_once()
    status = client.get(f"/api/scans/{job['id']}").json()
    assert status["status"] == "completed", status
    report = client.get(f"/api/scans/{job['id']}/report")
    assert report.status_code == 200 and report.json()["input_mode"] == "offline_snapshot"
    assert "secret-value-123456" not in report.text
    markdown = client.get(f"/api/scans/{job['id']}/report?format=markdown")
    assert markdown.status_code == 200 and "attachment" in markdown.headers["content-disposition"]
    assert "secret-value-123456" not in markdown.text + caplog.text
    assert client.get(f"/api/scans/{job['id']}/graphs/network").json().keys() >= {"nodes", "edges"}
    assert isinstance(client.get(f"/api/scans/{job['id']}/findings").json()["items"], list)
    assert client.get(f"/api/scans/{job['id']}/findings?search=nonexistent-random-value").json()["items"] == []
    assert SQLiteStore(settings.state_dir).job("alice", job["id"])["status"] == "completed"


def test_invalid_selectors_do_not_charge_quota(client):
    connector = add_connector(client)
    for patch in ({"categories": ["offensive"]}, {"checks": ["unknown"]}, {"frameworks": ["unknown"]}):
        assert client.post("/api/scans", json={"connector_id": connector["id"], **patch}).status_code == 422
    assert client.get("/api/me").json()["weekly_used"] == 0


def test_worker_failed_input_keeps_secrets_out_of_errors(client, settings, caplog):
    connector = add_connector(client, auth={"token": "secret-value-123456"}, options={"snapshot": {"malformed": "secret-value-123456"}})
    job = client.post("/api/scans", json={"connector_id": connector["id"]}).json()
    assert Worker("collector", settings).run_once()
    value = client.get(f"/api/scans/{job['id']}")
    assert value.json()["status"] == "failed"
    assert "secret-value-123456" not in value.text + caplog.text


def test_reachability_uses_owned_scoped_facts_and_rejects_invalid_ports(client, settings):
    from peaso.snapshot import seal
    imported = snapshot()
    imported["metadata"]["original_snapshot_id"] = "sha256:untrusted-ancestor"
    connector = add_connector(client, options={"snapshot": seal(imported)})
    job = client.post("/api/scans", json={"connector_id": connector["id"]}).json()
    assert Worker("collector", settings).run_once()
    assert Worker("analyzer", settings).run_once()
    query = {"source_resource_id": "missing-source", "destination_resource_id": "missing-destination", "protocol": "tcp", "destination_port": 443}
    response = client.post(f"/api/scans/{job['id']}/reachability", json=query)
    assert response.status_code == 200 and response.json()["decision"] == "unknown"
    assert response.json()["modeled_configuration"] is True
    report = client.get(f"/api/scans/{job['id']}/report").json()
    assert response.json()["snapshot_id"] == report["snapshot_id"]
    batch = {"source_resource_id": "missing-source", "destination_resource_ids": ["missing-one", "missing-two"],
        "protocol": "tcp", "destination_port": 443}
    assessed = client.post(f"/api/scans/{job['id']}/reachability/batch", json=batch)
    assert assessed.status_code == 200
    assert assessed.json()["snapshot_id"] == report["snapshot_id"]
    assert len(assessed.json()["results"]) == 2
    assert all(item["decision"] == "unknown" for item in assessed.json()["results"])
    matrix = {"endpoint_resource_ids": ["missing-source", "missing-destination"],
        "protocol": "tcp", "destination_port": 443}
    assessed_matrix = client.post(f"/api/scans/{job['id']}/reachability/matrix", json=matrix)
    assert assessed_matrix.status_code == 200
    assert assessed_matrix.json()["snapshot_id"] == report["snapshot_id"]
    assert [(item["query"]["source_resource_id"], item["query"]["destination_resource_id"])
        for item in assessed_matrix.json()["results"]] == [
        ("missing-source", "missing-destination"), ("missing-destination", "missing-source")]
    assert client.post(f"/api/scans/{job['id']}/reachability/matrix", json={**matrix,
        "endpoint_resource_ids": ["duplicate", "duplicate"]}).status_code == 422
    assert client.post(f"/api/scans/{job['id']}/reachability/matrix", json={**matrix,
        "endpoint_resource_ids": [str(index) for index in range(13)]}).status_code == 422
    grid = {"first_endpoint_resource_ids": ["missing-source"],
        "second_endpoint_resource_ids": ["missing-destination"], "protocol": "tcp", "destination_port": 443}
    assessed_grid = client.post(f"/api/scans/{job['id']}/reachability/grid", json=grid)
    assert assessed_grid.status_code == 200
    assert assessed_grid.json()["snapshot_id"] == report["snapshot_id"]
    assert len(assessed_grid.json()["results"]) == 2
    assert client.post(f"/api/scans/{job['id']}/reachability/grid", json={**grid,
        "second_endpoint_resource_ids": ["missing-source"]}).status_code == 422
    assert client.post(f"/api/scans/{job['id']}/reachability/batch", json={**batch,
        "destination_resource_ids": ["duplicate", "duplicate"]}).status_code == 422
    assert client.post(f"/api/scans/{job['id']}/reachability/batch", json={**batch,
        "destination_resource_ids": [str(index) for index in range(25)]}).status_code == 422
    for port in (0, 65536, True):
        assert client.post(f"/api/scans/{job['id']}/reachability", json={**query, "destination_port": port}).status_code == 422
    client.headers["Authorization"] = "Bearer bob"
    assert client.post(f"/api/scans/{job['id']}/reachability", json=query).status_code == 404
    assert client.post(f"/api/scans/{job['id']}/reachability/batch", json=batch).status_code == 404
    assert client.post(f"/api/scans/{job['id']}/reachability/matrix", json=matrix).status_code == 404
    assert client.post(f"/api/scans/{job['id']}/reachability/grid", json=grid).status_code == 404


def test_reachability_batch_route_uses_owned_report_snapshot_without_worker_catalog(client, monkeypatch):
    from peaso.analysis.reachability import network_snapshot
    source = snapshot()
    scoped = network_snapshot(source)
    connector = add_connector(client)
    job = client.post("/api/scans", json={"connector_id": connector["id"]}).json()
    store, artifacts = client.app.state.store, client.app.state.artifacts
    claimed = store.claim("collector", tenant="alice", ident=job["id"])
    assert claimed and store.finish(job["id"], claimed["owner"], "collected",
        artifacts.put("alice", job["id"], "snapshot", source))
    claimed = store.claim("analyzer", tenant="alice", ident=job["id"])
    assert claimed
    network_ref = artifacts.put("alice", job["id"], "network-snapshot", scoped)
    manifest = {"summary": {"snapshot_id": source["snapshot_id"]}, "network_snapshot": network_ref}
    report_ref = artifacts.put("alice", job["id"], "manifest", manifest)
    assert store.finish(job["id"], claimed["owner"], "completed", report_ref)
    query = {"source_resource_id": "absent-source", "destination_resource_ids": ["absent-one", "absent-two"],
        "protocol": "tcp", "destination_port": 443}
    response = client.post(f"/api/scans/{job['id']}/reachability/batch", json=query)
    assert response.status_code == 200, response.text
    assert response.json()["snapshot_id"] == source["snapshot_id"]
    assert [item["query"]["destination_resource_id"] for item in response.json()["results"]] == query["destination_resource_ids"]
    assert all(item["decision"] == "unknown" for item in response.json()["results"])
    matrix_query = {"endpoint_resource_ids": ["absent-source", "absent-one"],
        "protocol": "tcp", "destination_port": 443}
    matrix_response = client.post(f"/api/scans/{job['id']}/reachability/matrix", json=matrix_query)
    assert matrix_response.status_code == 200, matrix_response.text
    assert matrix_response.json()["snapshot_id"] == source["snapshot_id"]
    assert len(matrix_response.json()["results"]) == 2
    grid_query = {"first_endpoint_resource_ids": ["absent-source"],
        "second_endpoint_resource_ids": ["absent-one"], "protocol": "tcp", "destination_port": 443}
    grid_response = client.post(f"/api/scans/{job['id']}/reachability/grid", json=grid_query)
    assert grid_response.status_code == 200, grid_response.text
    assert grid_response.json()["snapshot_id"] == source["snapshot_id"]
    assert len(grid_response.json()["results"]) == 2
    assert client.post(f"/api/scans/{job['id']}/reachability/batch", json={**query,
        "destination_resource_ids": ["same", "same"]}).status_code == 422
    original_get = artifacts.get
    def mismatched_report(tenant, reference):
        value = original_get(tenant, reference)
        return {**value, "summary": {"snapshot_id": "sha256:wrong-source"}} if reference == report_ref else value
    monkeypatch.setattr(artifacts, "get", mismatched_report)
    assert client.post(f"/api/scans/{job['id']}/reachability/batch", json=query).status_code == 409
    assert client.post(f"/api/scans/{job['id']}/reachability/matrix", json=matrix_query).status_code == 409
    assert client.post(f"/api/scans/{job['id']}/reachability/grid", json=grid_query).status_code == 409
    monkeypatch.setattr(artifacts, "get", original_get)
    client.headers["Authorization"] = "Bearer bob"
    assert client.post(f"/api/scans/{job['id']}/reachability/batch", json=query).status_code == 404
    assert client.post(f"/api/scans/{job['id']}/reachability/matrix", json=matrix_query).status_code == 404
    assert client.post(f"/api/scans/{job['id']}/reachability/grid", json=grid_query).status_code == 404
