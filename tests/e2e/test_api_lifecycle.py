"""Real local API/storage/worker integration; all test principals have free quota."""
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path

from fastapi import HTTPException
from fastapi.testclient import TestClient
import pytest

from peaso.auth import Identity
from peaso.server.app import create_app
from peaso.server.config import Settings
from peaso.snapshot import make_snapshot
from peaso.worker import Worker
from peaso.engine import catalog

SENTINEL = "INERT_QA_SENTINEL_NO_REAL_CREDENTIAL"


class FreeIdentities:
    """A local test seam for two distinct subjects; never grants paid status."""
    def authenticate(self, authorization):
        if authorization not in {"Bearer qa-subject-one", "Bearer qa-subject-two"}:
            raise HTTPException(401, "Invalid authentication")
        return Identity(authorization.removeprefix("Bearer "), paid=False)

    def is_paid(self, *args):
        return False


@pytest.fixture
def runtime(tmp_path):
    settings = Settings(state_dir=tmp_path / "state", identity_dir=tmp_path / "identity", auth_mode="local")
    app = create_app(settings, authenticator=FreeIdentities())
    with TestClient(app, base_url="http://localhost") as client:
        yield settings, app, client


def headers(subject="one"):
    return {"Authorization": "Bearer qa-subject-" + subject}


# The worker's public identity adapter accepts only canonical native scopes.
QA_SCOPE = "123456789012/us-east-1"


def connector(client):
    snapshot = make_snapshot("aws", [QA_SCOPE], [{"type": "bucket", "scope": QA_SCOPE, "service": "s3", "status": "empty", "items": []}])
    response = client.post("/api/connectors", headers=headers(), json={"name": "peaso-test-inert", "provider": "aws", "scopes": [QA_SCOPE],
        "auth": {"client_secret": SENTINEL}, "options": {"snapshot": snapshot}})
    assert response.status_code == 201, response.text
    assert SENTINEL not in response.text
    return response.json()["id"]


def test_scan_survives_api_restart_and_generates_both_formats(runtime):
    settings, app, client = runtime
    ident = connector(client)
    body = {"ai_enabled": False, "connector_id": ident, "categories": ["hardening"], "frameworks": ["hacktricks"]}
    queued = client.post("/api/scans", headers={**headers(), "Idempotency-Key": "qa-pipeline"}, json=body)
    assert queued.status_code == 201, queued.text
    scan = queued.json()["id"]
    assert queued.json()["status"] == "queued"
    assert client.get(f"/api/scans/{scan}/report", headers=headers()).status_code == 409
    assert Worker("collector", settings, authenticator=FreeIdentities()).run_once()
    assert client.get(f"/api/scans/{scan}", headers=headers()).json()["status"] == "collected"
    # A new API and analyzer reopen durable state and encryption identities.
    restarted = create_app(settings, authenticator=FreeIdentities())
    assert Worker("analyzer", settings).run_once()
    with TestClient(restarted, base_url="http://localhost") as second:
        assert second.get(f"/api/scans/{scan}", headers=headers()).json()["status"] == "completed"
        report = second.get(f"/api/scans/{scan}/report", headers=headers())
        assert report.status_code == 200, report.text
        assert report.json()["provider"] == "aws"
        assert report.json()["findings"]
        markdown = second.get(f"/api/scans/{scan}/report?format=markdown", headers=headers())
        assert markdown.status_code == 200
        assert "text/markdown" in markdown.headers["content-type"]
        assert report.json()["snapshot_id"] in markdown.text
        assert SENTINEL not in report.text + markdown.text
        replay = second.post("/api/scans", headers={**headers(), "Idempotency-Key": "qa-pipeline"}, json=body)
        assert replay.status_code == 201
        assert replay.json()["id"] == scan
        exhausted = second.post("/api/scans", headers=headers(), json=body)
        assert exhausted.status_code == 429
        assert second.get("/api/me", headers=headers()).json()["weekly_used"] == 1


def test_free_quota_is_atomic_with_concurrent_requests(runtime):
    _, _, client = runtime
    ident = connector(client)
    with ThreadPoolExecutor(max_workers=8) as pool:
        codes = list(pool.map(lambda _: client.post("/api/scans", headers=headers(), json={"ai_enabled": False, "connector_id": ident}).status_code, range(8)))
    assert codes.count(201) == 1
    assert codes.count(429) == 7
    assert client.get("/api/me", headers=headers()).json()["plan"] == "free"


def test_foreign_tenant_cannot_read_or_mutate_owned_state(runtime):
    _, _, client = runtime
    ident = connector(client)
    scan = client.post("/api/scans", headers=headers(), json={"ai_enabled": False, "connector_id": ident}).json()["id"]
    schedule = client.post("/api/schedules", headers=headers(), json={"ai_enabled": False, "connector_id": ident, "interval_hours": 168}).json()["id"]
    foreign = headers("two")
    assert client.get("/api/connectors", headers=foreign).json()["items"] == []
    assert client.get("/api/scans", headers=foreign).json()["items"] == []
    assert client.get("/api/schedules", headers=foreign).json()["items"] == []
    for method, path, body in [("get", f"/api/connectors/{ident}", None), ("patch", f"/api/connectors/{ident}", {"name": "foreign"}),
        ("delete", f"/api/connectors/{ident}", None), ("get", f"/api/scans/{scan}", None), ("post", f"/api/scans/{scan}/cancel", {}),
        ("get", f"/api/scans/{scan}/report", None), ("patch", f"/api/schedules/{schedule}", {"enabled": False}), ("delete", f"/api/schedules/{schedule}", None)]:
        response = client.request(method, path, headers=foreign, **({"json": body} if body is not None else {}))
        assert response.status_code == 404, (method, path, response.text)


def test_cancelled_queue_never_runs_and_schedules_use_server_quota(runtime):
    settings, _, client = runtime
    ident = connector(client)
    schedule = client.post("/api/schedules", headers=headers(), json={"ai_enabled": False, "connector_id": ident, "interval_hours": 1,
        "next_run_at": (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat()})
    assert schedule.status_code == 201, schedule.text
    collector = Worker("collector", settings, authenticator=FreeIdentities())
    assert collector.schedule_tick()
    scans = client.get("/api/scans", headers=headers()).json()["items"]
    assert len(scans) == 1
    scan = scans[0]["id"]
    response = client.post(f"/api/scans/{scan}/cancel", headers=headers())
    assert response.status_code == 200
    assert response.json()["status"] == "cancelled"
    assert collector.run_once() is False
    assert Worker("analyzer", settings).run_once() is False
    assert client.get(f"/api/scans/{scan}/report", headers=headers()).status_code == 409
    assert client.post("/api/scans", headers=headers(), json={"ai_enabled": False, "connector_id": ident}).status_code == 429
    assert client.patch(f"/api/schedules/{schedule.json()['id']}", headers=headers(), json={"enabled": False}).status_code == 200
    assert client.delete(f"/api/schedules/{schedule.json()['id']}", headers=headers()).status_code == 204


def test_credentials_are_encrypted_and_validation_does_not_echo_input(runtime):
    settings, _, client = runtime
    ident = connector(client)
    for path in ("/api/connectors", f"/api/connectors/{ident}"):
        response = client.get(path, headers=headers())
        assert SENTINEL not in response.text
        assert '"snapshot"' not in response.text
    invalid = client.post("/api/connectors", headers=headers(), json={"name": "invalid", "provider": "aws", "auth": SENTINEL})
    assert invalid.status_code == 422
    assert SENTINEL not in invalid.text
    for path in settings.state_dir.rglob("*"):
        if path.is_file():
            assert SENTINEL.encode() not in path.read_bytes()
    assert client.get("/api/connectors").status_code == 401
    assert client.get("/api/connectors", headers={**headers(), "Origin": "https://untrusted.invalid"}).status_code == 403


def test_published_exact_framework_checklist_can_enqueue(runtime):
    _, _, client = runtime
    ident = connector(client)
    selected = next(row for row in catalog()["framework_versions"] if row["provider"] == "aws" and row["native_check_ids"])
    response = client.post("/api/scans", headers=headers(), json={"ai_enabled": False, "connector_id": ident, "frameworks": [selected["id"]]})
    assert response.status_code == 201, response.text
    assert response.json()["frameworks"] == [selected["id"]]
