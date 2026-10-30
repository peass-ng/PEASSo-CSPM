"""Failure locations are useful; SDK text, locals and credential values stay private."""
import json
import multiprocessing
from pathlib import Path
import signal
import subprocess
import sys
from unittest.mock import patch

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

from peaso.auth import CredentialCipher, Identity
from peaso.server import create_app
from peaso.server.config import Settings
from peaso.storage import FileArtifacts, SQLiteStore
from peaso.storage.sqlite import GENERIC_FAILURE, failure_error
from peaso.worker import Worker, _safe_failure_details


def failure(source, error):
    try:
        exec(compile("raise captured_error", source, "exec"), {"captured_error": error})
    except Exception as exc:
        return _safe_failure_details(exc)


def test_builtin_failure_returns_application_location_without_value():
    package = Path(__file__).resolve().parents[1] / "peaso"
    result = failure(str(package / "worker.py"), TypeError("fixture-private-credential-value"))
    assert result == {"exception_type": "TypeError", "source": "peaso/worker.py:1"}
    assert "fixture-private-credential-value" not in json.dumps(result)


def test_external_paths_and_dynamic_exception_names_are_not_disclosed():
    error = type("fixture_private_credential_value", (Exception,), {})("fixture-body-secret")
    result = failure("/private/customer/fixture-private-credential-value.py", error)
    assert result == {"exception_type": "provider_error", "source": "unavailable"}
    assert "fixture" not in json.dumps(result)


@pytest.fixture(params=["sqlite", "dynamodb"])
def crash_store(request, tmp_path):
    if request.param == "sqlite":
        yield SQLiteStore(tmp_path / "state")
        return
    moto = pytest.importorskip("moto")
    boto3 = pytest.importorskip("boto3")
    from peaso.storage.dynamodb import DynamoStore
    with moto.mock_aws():
        client = boto3.client("dynamodb", region_name="us-east-1")
        client.create_table(TableName="peaso", BillingMode="PAY_PER_REQUEST",
                            KeySchema=[{"AttributeName": "PK", "KeyType": "HASH"}, {"AttributeName": "SK", "KeyType": "RANGE"}],
                            AttributeDefinitions=[{"AttributeName": name, "AttributeType": "S"} for name in ["PK", "SK"]])
        yield DynamoStore("peaso", client)


@pytest.mark.parametrize("role", ["collector", "analyzer"])
@pytest.mark.parametrize("terminal", [None, "cancelled", "completed"])
def test_owned_sigkill_uses_existing_worker_lifecycle(crash_store, tmp_path, role, terminal, caplog):
    """Kill only our tiny subprocess; exercise real pipe EOF and fenced stores."""
    settings = Settings(state_dir=tmp_path / "state", identity_dir=tmp_path / "identity")
    cipher = CredentialCipher(settings.identity_dir)
    secret = "fixture-private-credential-value"
    connector = crash_store.add_connector("alice", {"provider": "aws"}, cipher.encrypt({"auth": {"token": secret}, "options": {}}))
    job = crash_store.enqueue("alice", {"connector_id": connector["id"]})
    assert crash_store.admit("alice", job["id"])
    if role == "analyzer":
        claim = crash_store.claim("collector", tenant="alice", ident=job["id"])
        assert crash_store.finish(job["id"], claim["owner"], "collected", "unused-snapshot")
    actual_context = multiprocessing.get_context("spawn")
    owned_processes = []

    class OwnedKilledProcess:
        def __init__(self, *, target, args, daemon):
            self.connection = args[-1]
            self.process = None
            owned_processes.append(self)

        def start(self):
            self.process = subprocess.Popen([sys.executable, "-c", "import os,signal; os.kill(os.getpid(),signal.SIGKILL)"],
                                            pass_fds=(self.connection.fileno(),), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if terminal == "cancelled":
                crash_store.cancel("alice", job["id"])
            elif terminal == "completed":
                current = crash_store.job("alice", job["id"])
                # A concurrent owner transition must survive late child death.
                if role == "collector":
                    assert crash_store.finish(job["id"], current["owner"], "collected", "snapshot")
                    current = crash_store.claim("analyzer", tenant="alice", ident=job["id"])
                assert crash_store.finish(job["id"], current["owner"], "completed", "report")

        def is_alive(self):
            return self.process.poll() is None

        def join(self, timeout):
            self.process.wait(timeout=timeout)

        def terminate(self):
            self.process.terminate()

        def kill(self):
            self.process.kill()

    class OwnedContext:
        Pipe = staticmethod(actual_context.Pipe)
        Process = OwnedKilledProcess

    with patch("peaso.worker.multiprocessing.get_context", return_value=OwnedContext()):
        assert Worker(role, settings, store=crash_store, artifacts=FileArtifacts(tmp_path / "artifacts")).run_once("alice", job["id"])
    current = crash_store.job("alice", job["id"])
    public = crash_store.public_job(current)
    assert current["status"] == (terminal or "failed")
    assert current["owner"] is None and current["lease"] is None
    assert current["error_code"] == (None if terminal else "worker_interrupted")
    if not terminal:
        assert current["error_stage"] == role
        assert public["timeline"][-1]["status"] == "failed"
    assert secret not in json.dumps(public) + caplog.text
    assert all(not process.is_alive() for process in owned_processes)
    if not terminal:
        assert all(process.process.returncode == -signal.SIGKILL for process in owned_processes)


@pytest.mark.parametrize("reason_code", ["external_id_not_required_by_trust", "platform_owned_account", "role_target_limit"])
def test_all_targets_refused_surfaces_only_curated_reason(crash_store, tmp_path, monkeypatch, caplog, reason_code):
    from peaso import worker
    from peaso.snapshot import make_snapshot

    # This case supplies a synthetic collector denial, not live credentials.
    # Credential preflight has its own tests; keep this fixture offline.
    monkeypatch.setattr(worker, "_verify_aws_credentials", lambda connector: None)
    # The collector child runs inline here, so give it the fresh per-process
    # collection lease a spawned child would have.
    from peaso import collection_lease
    for name in ("_epoch", "_monotonic_deadline", "_pid"):
        monkeypatch.setattr(collection_lease, name, None)
    settings = Settings(state_dir=tmp_path / "state", identity_dir=tmp_path / "identity")
    artifacts = FileArtifacts(tmp_path / "artifacts")
    arn = "arn:aws:iam::222222222222:role/CustomerAudit"
    secret = "fixture-private-credential-value"
    raw = "fixture-private-sdk-response-and-jwt"
    connector = crash_store.add_connector("alice", {"provider": "aws"}, CredentialCipher(settings.identity_dir).encrypt({
        "auth": {"method": "task_role", "assume_roles": [{"role_arn": arn}], "external_id": secret},
        "options": {"hosted": True}}))
    job = crash_store.enqueue("alice", {"connector_id": connector["id"]})
    assert crash_store.admit("alice", job["id"])
    denied = make_snapshot("aws", ["222222222222"], [{"type": "vpc", "scope": "222222222222/us-east-1",
        "service": "ec2", "status": "denied", "items": [], "error": {"code": "AccessDenied"}}],
        metadata={"authentication_errors": [
            {"account": "222222222222", "role_arn": arn, "status": "denied", "error": {"code": reason_code, "raw": raw}},
            {"account": "222222222222", "role_arn": arn + raw, "status": "denied", "error": {"code": reason_code}},
            {"account": "222222222222", "role_arn": arn, "status": "denied", "error": {"code": raw}},
        ]})
    resource_calls = []
    monkeypatch.setattr("peaso.engine.collect_snapshot", lambda request: resource_calls.append(request) or denied)
    monkeypatch.setattr(worker.os, "dup2", lambda *args: None)
    actual_context = multiprocessing.get_context("spawn")

    class InlineProcess:
        def __init__(self, *, target, args, daemon):
            self.target, self.args = target, args
        def start(self):
            self.target(*self.args)
        def is_alive(self):
            return False
        def join(self, timeout):
            pass

    class InlineContext:
        Pipe = staticmethod(actual_context.Pipe)
        Process = InlineProcess

    with patch("peaso.worker.multiprocessing.get_context", return_value=InlineContext()):
        assert Worker("collector", settings, store=crash_store, artifacts=artifacts).run_once("alice", job["id"])
    stored = crash_store.job("alice", job["id"])
    public = crash_store.public_job(stored)
    assert len(resource_calls) == 1 and stored["status"] == "failed"
    assert stored["error_code"] == "credential_access_denied" and stored["error_stage"] == "collector"
    assert stored["report"] is None and stored["snapshot"] is None
    assert stored["owner"] is None and stored["lease"] is None
    assert public["failure_reasons"] == [{"code": reason_code, "role_arn": arn, "message": public["error"]}]
    if reason_code == "external_id_not_required_by_trust":
        assert public["error"] == f"Role {arn} was refused: trust policy does not require External ID; add the sts:ExternalId condition shown in onboarding."
    for leaked in (secret, raw, "raw", "snapshot", "Credentials"):
        assert leaked not in json.dumps(public) + caplog.text
    assert public["timeline"][-1]["status"] == "failed"
    with pytest.raises(Exception) as missing:
        crash_store.job("bob", job["id"])
    assert getattr(missing.value, "status", None) == 404

    class Identities:
        def authenticate(self, authorization):
            if authorization == "Bearer alice":
                return Identity("alice")
            if authorization == "Bearer bob":
                return Identity("bob")
            raise HTTPException(401, "Invalid authentication")

    with TestClient(create_app(settings, store=crash_store, artifacts=artifacts, authenticator=Identities()),
                    base_url="http://127.0.0.1:8000") as client:
        detail = client.get(f"/api/scans/{job['id']}", headers={"Authorization": "Bearer alice"}).json()
        assert {key: value for key, value in detail.items() if key not in {"connector_name", "display_name"}} == public
        assert isinstance(detail["display_name"], str) and detail["display_name"]
        assert client.get(f"/api/scans/{job['id']}", headers={"Authorization": "Bearer bob"}).status_code == 404


def test_store_rejects_untrusted_failure_text_and_preserves_generic_errors(crash_store, tmp_path):
    settings = Settings(state_dir=tmp_path / "state", identity_dir=tmp_path / "identity")
    connector = crash_store.add_connector("alice", {"provider": "aws"}, CredentialCipher(settings.identity_dir).encrypt({"auth": {}, "options": {}}))
    job = crash_store.enqueue("alice", {"connector_id": connector["id"]})
    assert crash_store.admit("alice", job["id"])
    claim = crash_store.claim("collector", tenant="alice", ident=job["id"])
    secret = "fixture-private-sdk-response"
    assert crash_store.finish(job["id"], claim["owner"], "failed", error_code="provider_error", failure_reasons=[
        {"code": "external_id_not_required_by_trust", "role_arn": "arn:aws:iam::222222222222:role/Audit", "message": secret},
        {"code": secret, "role_arn": "arn:aws:iam::222222222222:role/Audit"},
        {"code": "role_target_limit", "role_arn": "arn:aws:iam::222222222222:role/Audit:" + secret},
    ])
    public = crash_store.public_job(crash_store.job("alice", job["id"]))
    assert public["error_code"] == "provider_error"
    assert len(public["failure_reasons"]) == 1
    assert public["failure_reasons"][0]["message"] == public["error"]
    assert secret not in json.dumps(public)
    assert secret not in str(crash_store.job("alice", job["id"])["error"])

    other = crash_store.enqueue("alice", {"connector_id": connector["id"]}, limit=2)
    assert crash_store.admit("alice", other["id"])
    claim = crash_store.claim("collector", tenant="alice", ident=other["id"])
    assert crash_store.finish(other["id"], claim["owner"], "failed", error_code="provider_error")
    generic = crash_store.public_job(crash_store.job("alice", other["id"]))
    assert generic["error"] == "Scan processing failed; check connector access and coverage"
    assert generic["error_code"] == "provider_error" and "failure_reasons" not in generic


def test_public_failure_decoder_is_bounded_for_both_stores_and_scan_routes(crash_store, tmp_path, caplog):
    settings = Settings(state_dir=tmp_path / "state", identity_dir=tmp_path / "identity")
    artifacts = FileArtifacts(tmp_path / "artifacts")
    connector = crash_store.add_connector("alice", {"provider": "aws"},
                                          CredentialCipher(settings.identity_dir).encrypt({"auth": {}, "options": {}}))
    job = crash_store.enqueue("alice", {"connector_id": connector["id"]})

    def store_error(value):
        if isinstance(crash_store, SQLiteStore):
            with crash_store.connect() as db:
                db.execute("UPDATE jobs SET error=? WHERE id=?", (value, job["id"]))
        else:
            from peaso.storage.dynamodb import attrs
            crash_store.client.update_item(
                TableName=crash_store.table, Key=attrs(crash_store.key("alice", "job", job["id"])),
                UpdateExpression="SET #error=:error", ExpressionAttributeNames={"#error": "error"},
                ExpressionAttributeValues=attrs({":error": value}))

    class Identities:
        def authenticate(self, authorization):
            if authorization == "Bearer alice":
                return Identity("alice")
            raise HTTPException(401, "Invalid authentication")

    marker = "fixture-private-ExternalID-sdk-response"
    bad_envelopes = [
        '{"failure_reasons":' + marker,
        '{"failure_reasons":' + '[' * 1100 + '0' + ']' * 1100 + '}',
        '{"failure_reasons":"' + marker * 7000 + '"}',
        json.dumps({"failure_reasons": {"raw": marker}}, separators=(",", ":")),
        json.dumps({"failure_reasons": [{"code": marker, "role_arn": marker, "message": marker}]},
                   separators=(",", ":")),
        json.dumps({"failure_reasons": [], "raw": marker}, separators=(",", ":")),
    ]
    assert len(bad_envelopes[2].encode()) > 128 * 1024
    with TestClient(create_app(settings, store=crash_store, artifacts=artifacts, authenticator=Identities()),
                    base_url="http://127.0.0.1:8000") as client:
        for bad in bad_envelopes:
            store_error(bad)
            for path in ("/api/scans", f"/api/scans/{job['id']}"):
                response = client.get(path, headers={"Authorization": "Bearer alice"})
                assert response.status_code == 200
                public = response.json()["items"][0] if path == "/api/scans" else response.json()
                assert public["error"] == GENERIC_FAILURE
                assert "failure_reasons" not in public
                assert marker not in response.text

        longest_arn = "arn:aws:iam::222222222222:role/" + "A" * 512
        reasons = [{"code": "external_id_not_required_by_trust", "role_arn": longest_arn} for _ in range(50)]
        encoded = failure_error(reasons)
        assert len(encoded.encode()) < 64 * 1024
        store_error(encoded)
        for path in ("/api/scans", f"/api/scans/{job['id']}"):
            response = client.get(path, headers={"Authorization": "Bearer alice"})
            assert response.status_code == 200
            public = response.json()["items"][0] if path == "/api/scans" else response.json()
            assert len(public["failure_reasons"]) == 50
            assert public["error"] == public["failure_reasons"][0]["message"]
            assert all(reason["role_arn"] == longest_arn for reason in public["failure_reasons"])

        store_error("Legacy provider error")
        assert client.get(f"/api/scans/{job['id']}", headers={"Authorization": "Bearer alice"}).json()["error"] == "Legacy provider error"
    assert marker not in caplog.text
