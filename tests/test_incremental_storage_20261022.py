"""Tenant, lease and final-result fencing for durable partial checkpoints."""
import json
import sys
import types

import boto3
import moto
import pytest

from peaso.storage.artifacts import reference_for
from peaso.storage.sqlite import SQLiteStore
from peaso.storage.dynamodb import DynamoStore, attrs


TENANT = "tenant-a"
OTHER = "tenant-b"
SCAN = "a" * 32
OWNER = "owner-1"


def _job():
    return {"id": SCAN, "tenant": TENANT, "connector_id": "connector", "data": "{}",
            "connector": json.dumps({"data": {"provider": "aws"}}), "status": "collecting",
            "created": 1000.0, "deadline": 2000.0, "owner": OWNER, "lease": 1500.0,
            "error": None, "snapshot": None, "report": None,
            "history": [{"status": "collecting", "at": "2026-10-22T00:00:00Z"}]}


def _exercise(store):
    delta = reference_for(TENANT, SCAN, "snapshot")
    cumulative = reference_for(TENANT, SCAN, "snapshot")
    partial = reference_for(TENANT, SCAN, "report")
    assert store.record_checkpoint(TENANT, SCAN, OWNER, 1, delta,
                                   kind="bucket", scope="123456789012/us-east-1", now=1100)
    assert not store.record_checkpoint(TENANT, SCAN, "stale-owner", 2, delta,
                                       kind="bucket", scope="123456789012/us-east-1", now=1100)
    with pytest.raises(ValueError, match="Invalid checkpoint reference"):
        store.record_checkpoint(OTHER, SCAN, OWNER, 2, delta,
                                kind="bucket", scope="123456789012/us-east-1", now=1100)
    assert store.record_checkpoint(TENANT, SCAN, OWNER, 1, cumulative,
                                   report_ref=partial, now=1100)
    assert store.public_job(store.job(TENANT, SCAN))["result_available"] is True
    assert store.checkpoint_collections(TENANT, SCAN)[0]["reference"] == delta
    assert not store.record_checkpoint(TENANT, SCAN, OWNER, 1, delta,
                                       kind="bucket", scope="123456789012/us-east-1", now=1100)
    store_after_restart = store.job(TENANT, SCAN)
    assert store_after_restart["partial_report"] == partial
    assert store_after_restart["checkpoint_sequence"] == 1
    assert not store.record_checkpoint(TENANT, SCAN, OWNER, 2, cumulative,
                                       report_ref=partial, now=1100)
    # A raw batch can finish while an older cumulative report is uploading.
    # Its report may publish afterward without regressing raw durability.
    later_delta = reference_for(TENANT, SCAN, "snapshot")
    later_report = reference_for(TENANT, SCAN, "report")
    assert store.record_checkpoint(TENANT, SCAN, OWNER, 3, later_delta,
                                   kind="route_table", scope="123456789012/us-east-1", now=1100)
    assert store.record_checkpoint(TENANT, SCAN, OWNER, 2, cumulative,
                                   report_ref=later_report, now=1100)
    assert store.job(TENANT, SCAN)["checkpoint_sequence"] == 3
    assert store.job(TENANT, SCAN)["partial_report_sequence"] == 2
    if isinstance(store, SQLiteStore):
        with store.transaction() as db:
            db.execute("UPDATE jobs SET status='analyzing' WHERE tenant=? AND id=?", (TENANT, SCAN))
    else:
        store.client.update_item(TableName=store.table, Key=attrs(store.key(TENANT, "job", SCAN)),
                                 UpdateExpression="SET #status=:analyzing",
                                 ExpressionAttributeNames={"#status": "status"},
                                 ExpressionAttributeValues=attrs({":analyzing": "analyzing"}))
    assert store.record_checkpoint(TENANT, SCAN, OWNER, 4, cumulative,
                                   report_ref=partial, stage="analyzer_native", now=1100)
    assert store.job(TENANT, SCAN)["checkpoint_sequence"] == 4
    assert not store.record_checkpoint(TENANT, SCAN, OWNER, 1, delta,
                                       kind="bucket", scope="123456789012/us-east-1", now=1100)
    final = reference_for(TENANT, SCAN, "manifest")
    if isinstance(store, SQLiteStore):
        with store.transaction() as db:
            db.execute("UPDATE jobs SET status='completed',report=?,owner=NULL WHERE tenant=? AND id=?",
                       (final, TENANT, SCAN))
    else:
        store.client.update_item(TableName=store.table, Key=attrs(store.key(TENANT, "job", SCAN)),
                                 UpdateExpression="SET #status=:done,report=:report, #owner=:null",
                                 ExpressionAttributeNames={"#status": "status", "#owner": "owner"},
                                 ExpressionAttributeValues=attrs({":done": "completed", ":report": final, ":null": None}))
    assert not store.record_checkpoint(TENANT, SCAN, OWNER, 3, delta,
                                       kind="bucket", scope="123456789012/us-east-1", now=1100)
    assert store.job(TENANT, SCAN)["report"] == final


def test_sqlite_checkpoint_survives_restart_and_final_fences(tmp_path):
    store = SQLiteStore(tmp_path)
    with store.transaction() as db:
        row = _job()
        db.execute("INSERT INTO jobs(id,tenant,connector_id,data,connector,status,created,deadline,owner,lease,history) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                   tuple(row[key] if key != "history" else json.dumps(row[key]) for key in
                         ("id", "tenant", "connector_id", "data", "connector", "status", "created", "deadline", "owner", "lease", "history")))
    _exercise(store)
    assert SQLiteStore(tmp_path).checkpoint_collections(TENANT, SCAN)


def test_dynamo_checkpoint_survives_restart_and_final_fences():
    with moto.mock_aws():
        client = boto3.client("dynamodb", region_name="us-east-1")
        client.create_table(TableName="checkpoint-test", KeySchema=[{"AttributeName": "PK", "KeyType": "HASH"},
                      {"AttributeName": "SK", "KeyType": "RANGE"}], AttributeDefinitions=[
                      {"AttributeName": "PK", "AttributeType": "S"}, {"AttributeName": "SK", "AttributeType": "S"}],
                      BillingMode="PAY_PER_REQUEST")
        store = DynamoStore("checkpoint-test", client)
        store.clock = lambda: 1100
        client.put_item(TableName=store.table, Item=attrs(dict(store.key(TENANT, "job", SCAN), **_job())))
        _exercise(store)
        assert DynamoStore(store.table, client).checkpoint_collections(TENANT, SCAN)


def _exercise_stages(store):
    first, replacement = "2" * 32, "3" * 32
    result = reference_for(TENANT, SCAN, "ai-review")
    assert store.claim_stage(TENANT, SCAN, "ai", 1, first, 30, now=1100)
    assert not store.claim_stage(TENANT, SCAN, "ai", 1, replacement, 30, now=1101)
    assert store.heartbeat_stage(TENANT, SCAN, "ai", 1, first, 30, now=1101)
    assert store.claim_stage(TENANT, SCAN, "hardening", 0, replacement, 30, now=1101)
    assert store.finish_stage(TENANT, SCAN, "hardening", 0, replacement, result, now=1102)
    assert store.claim_stage(TENANT, SCAN, "ai", 1, replacement, 30, now=1132)
    assert not store.finish_stage(TENANT, SCAN, "ai", 1, first, result, now=1132)
    with pytest.raises(ValueError, match="Invalid progressive result reference"):
        store.finish_stage(TENANT, SCAN, "ai", 1, replacement, reference_for(OTHER, SCAN, "ai-review"), now=1133)
    assert store.finish_stage(TENANT, SCAN, "ai", 1, replacement, result, now=1133)
    assert store.stage_results(TENANT, SCAN)["ai"] == {"data_revision": 1, "result_ref": result}
    assert not store.claim_stage(TENANT, SCAN, "ai", 1, first, 30, now=1134)
    if isinstance(store, SQLiteStore):
        with store.transaction() as db:
            db.execute("UPDATE jobs SET status='collected',owner=NULL,lease=NULL WHERE tenant=? AND id=?", (TENANT, SCAN))
    else:
        store.client.update_item(TableName=store.table, Key=attrs(store.key(TENANT, "job", SCAN)),
                                 UpdateExpression="SET #status=:collected,#owner=:null,lease=:null",
                                 ExpressionAttributeNames={"#status": "status", "#owner": "owner"},
                                 ExpressionAttributeValues=attrs({":collected": "collected", ":null": None}))
    assert store.claim_stage(TENANT, SCAN, "ai", 2, first, 30, now=1134)
    assert "ai" not in store.stage_results(TENANT, SCAN)
    assert not store.finish_stage(TENANT, SCAN, "ai", 1, replacement, result, now=1135)
    if isinstance(store, SQLiteStore):
        with store.transaction() as db:
            db.execute("UPDATE jobs SET status='completed',report=? WHERE tenant=? AND id=?", (result, TENANT, SCAN))
    else:
        store.client.update_item(TableName=store.table, Key=attrs(store.key(TENANT, "job", SCAN)),
                                 UpdateExpression="SET #status=:completed,report=:report",
                                 ExpressionAttributeNames={"#status": "status"},
                                 ExpressionAttributeValues=attrs({":completed": "completed", ":report": result}))
    assert not store.finish_stage(TENANT, SCAN, "ai", 2, first, result, now=1135)
    assert not store.claim_stage(TENANT, SCAN, "ai", 3, replacement, 30, now=1135)


def test_sqlite_parallel_stage_owner_and_final_fencing(tmp_path):
    store = SQLiteStore(tmp_path)
    with store.transaction() as db:
        row = _job()
        db.execute("INSERT INTO jobs(id,tenant,connector_id,data,connector,status,created,deadline,owner,lease,history) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                   tuple(row[key] if key != "history" else json.dumps(row[key]) for key in
                         ("id", "tenant", "connector_id", "data", "connector", "status", "created", "deadline", "owner", "lease", "history")))
    _exercise_stages(store)


def test_dynamo_parallel_stage_owner_and_final_fencing():
    with moto.mock_aws():
        client = boto3.client("dynamodb", region_name="us-east-1")
        client.create_table(TableName="parallel-stage-test", KeySchema=[{"AttributeName": "PK", "KeyType": "HASH"},
                      {"AttributeName": "SK", "KeyType": "RANGE"}], AttributeDefinitions=[
                      {"AttributeName": "PK", "AttributeType": "S"}, {"AttributeName": "SK", "AttributeType": "S"}],
                      BillingMode="PAY_PER_REQUEST")
        store = DynamoStore("parallel-stage-test", client)
        store.clock = lambda: 1100
        client.put_item(TableName=store.table, Item=attrs(dict(store.key(TENANT, "job", SCAN), **_job())))
        _exercise_stages(store)


def test_authenticated_api_reads_partial_only_for_own_tenant_and_final_wins(tmp_path):
    from fastapi import HTTPException
    from fastapi.testclient import TestClient
    from peaso.auth import Identity
    from peaso.server import create_app
    from peaso.server.config import Settings
    from peaso.storage.artifacts import FileArtifacts

    state = tmp_path / "state"
    store = SQLiteStore(state)
    artifacts = FileArtifacts(tmp_path / "artifacts")
    native_finding = {"id": "native-hardening-1", "check_id": "aws.s3.default_encryption",
                      "title": "Bucket encryption", "provider": "aws", "category": "hardening",
                      "severity": "high", "status": "FAIL", "scope": "123456789012/us-east-1",
                      "resource_id": "bucket-1", "service": "s3"}
    partial = {"schema_version": "1.1", "provider": "aws", "snapshot_id": "partial",
               "scopes": ["123456789012/us-east-1"], "findings": [native_finding], "coverage": [],
               "stats": {"coverage_complete": False, "inventory_complete": False},
               "graphs": {"network": {"nodes": [], "edges": []}, "iam": {"nodes": [], "edges": []}},
               "publication": {"state": "partial", "phase": "collecting", "sequence": 1,
                               "sections": {"network": {"status": "complete", "data_revision": 1},
                                            "hardening": {"status": "complete", "data_revision": 1},
                                            "images": {"status": "running", "data_revision": 0}}}}
    partial_json = artifacts.put(TENANT, SCAN, "report", partial)
    finding_index = artifacts.put(TENANT, SCAN, "finding-index", {"items": [native_finding]})
    finding_detail = artifacts.put(TENANT, SCAN, "findings", {"items": [native_finding]})
    chunks = [{"index_reference": finding_index, "reference": finding_detail,
               "first_id": native_finding["id"], "last_id": native_finding["id"], "count": 1}]
    partial_ref = artifacts.put(TENANT, SCAN, "manifest", {"bundle_version": 1,
        "report_json": partial_json, "report_markdown": artifacts.put_text(TENANT, SCAN, "markdown", "Partial"),
        "summary": {"provider": "aws", "publication": partial["publication"], "stats": partial["stats"]},
        "finding_chunks": chunks, "finding_count": 1})
    final_ref = artifacts.put(TENANT, SCAN, "report", dict(partial, snapshot_id="final",
                                                  publication={"state": "final"}))
    with store.transaction() as db:
        row = _job()
        db.execute("INSERT INTO jobs(id,tenant,connector_id,data,connector,status,created,deadline,owner,lease,history,partial_report) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                   tuple(row[key] if key != "history" else json.dumps(row[key]) for key in
                         ("id", "tenant", "connector_id", "data", "connector", "status", "created", "deadline", "owner", "lease", "history")) + (partial_ref,))
    review_ref = artifacts.put(TENANT, SCAN, "ai-review", {"stage": "network", "data_revision": 1,
        "result": {"status": "completed", "reviews": {"hardening": [], "exposure": []},
                   "network": {"status": "completed", "findings": [{"id": "network-early", "title": "Early network finding"}]}}})
    stage_owner = "2" * 32
    assert store.claim_stage(TENANT, SCAN, "network", 1, stage_owner, 30, now=1100)
    assert store.finish_stage(TENANT, SCAN, "network", 1, stage_owner, review_ref, now=1101)
    hardening_ref = artifacts.put(TENANT, SCAN, "ai-review", {"stage": "hardening", "data_revision": 1,
        "result": {"status": "completed", "reviews": {"hardening": [
            {"finding_id": "native-hardening-1", "verdict": "PASS", "reason": "Verified safe configuration."}],
            "exposure": []}}})
    assert store.claim_stage(TENANT, SCAN, "hardening", 1, "3" * 32, 30, now=1100)
    assert store.finish_stage(TENANT, SCAN, "hardening", 1, "3" * 32, hardening_ref, now=1101)

    class Identities:
        def authenticate(self, authorization):
            if authorization == "Bearer alice":
                return Identity(TENANT)
            if authorization == "Bearer bob":
                return Identity(OTHER)
            raise HTTPException(401, "Invalid authentication")

        def is_paid(self, tenant):
            return False

    settings = Settings(state_dir=state, identity_dir=tmp_path / "identity")
    with TestClient(create_app(settings, store=store, artifacts=artifacts, authenticator=Identities()),
                    base_url="http://127.0.0.1:8000") as client:
        path = "/api/scans/" + SCAN + "/report"
        assert client.get(path, headers={"Authorization": "Bearer alice"}).json()["publication"]["state"] == "partial"
        assert client.get(path, headers={"Authorization": "Bearer bob"}).status_code == 404
        ai_path = "/api/scans/" + SCAN + "/ai"
        assert client.get(ai_path, headers={"Authorization": "Bearer bob"}).status_code == 404
        assert client.get(ai_path, headers={"Authorization": "Bearer alice"}).json()["network"]["findings"][0]["id"] == "network-early"
        summary = client.get("/api/scans/" + SCAN + "/summary", headers={"Authorization": "Bearer alice"}).json()
        assert summary["publication"]["ai_stages"] == {"network": 1, "hardening": 1}
        reviewed = client.get("/api/scans/" + SCAN + "/findings?status=PASS", headers={"Authorization": "Bearer alice"}).json()
        assert reviewed["items"][0]["id"] == "native-hardening-1"
        assert reviewed["items"][0]["scanner_status"] == "FAIL"
        assert client.get(path, headers={"Authorization": "Bearer alice"}).json()["ai"]["network"]["findings"][0]["id"] == "network-early"
        newer = dict(partial, publication=dict(partial["publication"], sequence=2))
        newer_json = artifacts.put(TENANT, SCAN, "report", newer)
        newer_ref = artifacts.put(TENANT, SCAN, "manifest", {"bundle_version": 1,
            "report_json": newer_json, "report_markdown": artifacts.put_text(TENANT, SCAN, "markdown", "Newer partial"),
            "summary": {"provider": "aws", "publication": newer["publication"], "stats": newer["stats"]},
            "finding_chunks": chunks, "finding_count": 1})
        with store.transaction() as db:
            db.execute("UPDATE jobs SET partial_report=? WHERE tenant=? AND id=?", (newer_ref, TENANT, SCAN))
        assert client.get(ai_path, headers={"Authorization": "Bearer alice"}).json()["network"]["findings"][0]["id"] == "network-early"
        changed_sections = dict(newer["publication"]["sections"], network={"status": "complete", "data_revision": 2},
                                hardening={"status": "complete", "data_revision": 2})
        changed = dict(newer, publication=dict(newer["publication"], sequence=3, sections=changed_sections))
        changed_json = artifacts.put(TENANT, SCAN, "report", changed)
        changed_ref = artifacts.put(TENANT, SCAN, "manifest", {"bundle_version": 1,
            "report_json": changed_json, "report_markdown": artifacts.put_text(TENANT, SCAN, "markdown", "Changed data"),
            "summary": {"provider": "aws", "publication": changed["publication"], "stats": changed["stats"]},
            "finding_chunks": chunks, "finding_count": 1})
        with store.transaction() as db:
            db.execute("UPDATE jobs SET partial_report=? WHERE tenant=? AND id=?", (changed_ref, TENANT, SCAN))
        assert "network" not in client.get(ai_path, headers={"Authorization": "Bearer alice"}).json()
        assert "ai_stages" not in client.get("/api/scans/" + SCAN + "/summary", headers={"Authorization": "Bearer alice"}).json()["publication"]
        with store.transaction() as db:
            db.execute("UPDATE jobs SET status='completed',report=?,owner=NULL WHERE tenant=? AND id=?",
                       (final_ref, TENANT, SCAN))
        assert client.get(path, headers={"Authorization": "Bearer alice"}).json()["snapshot_id"] == "final"
        assert "network" not in client.get(ai_path, headers={"Authorization": "Bearer alice"}).json()


def test_worker_offline_collection_commits_public_partial_before_analyzer(tmp_path):
    from peaso.auth import CredentialCipher
    from peaso.server.config import Settings
    from peaso.snapshot import make_snapshot
    from peaso.storage.artifacts import FileArtifacts
    from peaso.worker import Worker

    settings = Settings(state_dir=tmp_path / "state", identity_dir=tmp_path / "identity")
    store = SQLiteStore(settings.state_dir)
    artifacts = FileArtifacts(settings.state_dir / "artifacts")
    snapshot = make_snapshot("aws", ["123456789012/us-east-1"], [{
        "type": "bucket", "scope": "123456789012/us-east-1", "status": "collected", "items": [{
            "Name": "baseline", "Encryption": {"ServerSideEncryptionConfiguration": {"Rules": [
                {"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]}}}]}])
    encrypted = CredentialCipher(settings.identity_dir).encrypt({"auth": {}, "options": {"snapshot": snapshot}})
    connector = store.add_connector(TENANT, {"provider": "aws", "scopes": snapshot["scopes"],
                                             "input_mode": "offline_snapshot"}, encrypted)
    job = store.enqueue(TENANT, {"connector_id": connector["id"], "categories": ["hardening"],
                                 "checks": ["aws.s3.default_encryption"], "ai_enabled": False}, limit=10)
    assert store.admit(TENANT, job["id"])
    assert Worker("collector", settings, store=store, artifacts=artifacts).run_once(TENANT, job["id"])
    row = store.job(TENANT, job["id"])
    assert row["status"] == "collected", row
    assert row["snapshot"]
    checkpoints = store.checkpoint_collections(TENANT, job["id"])
    assert len(checkpoints) == 2  # bounded batch, then section-closure revision
    assert checkpoints[0]["kind"] == "__checkpoint_batch__"
    assert checkpoints[1]["kind"] == "bucket"
    # Since c7e3c243 a finished collection skips the redundant final cumulative
    # report; the background publisher may or may not have rendered one first.
    # Every durable batch and the section watermark are committed either way.
    if row["partial_report"]:
        assert row["partial_snapshot"]
        partial_manifest = artifacts.get(TENANT, row["partial_report"])
        assert partial_manifest["bundle_version"] == 1
        partial = artifacts.get(TENANT, partial_manifest["report_json"])
        assert partial["publication"]["state"] == "partial"
        assert partial["publication"]["sections"]["hardening"]["status"] == "complete"
        assert any(f["check_id"] == "aws.s3.default_encryption" and f["status"] == "PASS"
                   for f in partial["findings"])
    final_snapshot = artifacts.get(TENANT, row["snapshot"])
    assert final_snapshot["metadata"]["sections"]["hardening"]["status"] == "complete"
    assert Worker("analyzer", settings, store=store, artifacts=artifacts).run_once(TENANT, job["id"])
    completed = store.job(TENANT, job["id"])
    assert completed["status"] == "completed", completed
    # With AI disabled the analyzer's acknowledged native checkpoint is already
    # the final publication (168d57fb); it is reused instead of republished.
    assert completed["report"] and completed["report"] != row["partial_report"]
    assert completed["report"] == completed["partial_report"]
    final_manifest = artifacts.get(TENANT, completed["report"])
    assert final_manifest["bundle_version"] == 1
    final = artifacts.get(TENANT, final_manifest["report_json"])
    assert final["publication"]["state"] == "final" and final["publication"]["phase"] == "completed"
    assert final["publication"]["sections"]["hardening"]["status"] == "complete"
    assert any(f["check_id"] == "aws.s3.default_encryption" and f["status"] == "PASS"
               for f in final["findings"])


def test_reclaimed_collector_preserves_prior_encrypted_private_witnesses(tmp_path):
    from peaso.auth import CredentialCipher
    from peaso.secret_evidence import capture, private_reference
    from peaso.storage.artifacts import FileArtifacts
    from peaso.worker import _restore_secret_capture

    cipher = CredentialCipher(tmp_path / "identity")
    artifacts = FileArtifacts(tmp_path / "artifacts")
    with capture(cipher, tenant=TENANT, scan_id=SCAN) as first:
        first.remember("private-old-value", "a" * 64, {"resource_id": "old", "scope": "scope"},
                       "detector", "rule", ())
        artifacts.put_secret_evidence(TENANT, SCAN, first.document())
    with capture(cipher, tenant=TENANT, scan_id=SCAN) as reclaimed:
        _restore_secret_capture(reclaimed, artifacts, TENANT, SCAN)
        reclaimed.remember("private-new-value", "b" * 64, {"resource_id": "new", "scope": "scope"},
                           "detector", "rule", ())
        artifacts.put_secret_evidence(TENANT, SCAN, reclaimed.document())
    document = artifacts.get(TENANT, private_reference(TENANT, SCAN))
    assert set(document["records"]) == {"a" * 64, "b" * 64}
    assert "private-old-value" not in json.dumps(document)


def test_reclaimed_file_artifact_write_ignores_abandoned_temp(tmp_path):
    from peaso.secret_evidence import private_reference
    from peaso.storage.artifacts import FileArtifacts

    artifacts = FileArtifacts(tmp_path / "artifacts")
    reference = private_reference(TENANT, SCAN)
    target = artifacts.root / reference
    target.parent.mkdir(parents=True)
    target.with_suffix(".tmp").write_text("abandoned before replace")
    assert artifacts.put_secret_evidence(TENANT, SCAN, {"sealed": "new"}) == reference
    assert artifacts.get(TENANT, reference) == {"sealed": "new"}


def test_progressive_analyzer_cli_uses_targeted_watcher(monkeypatch):
    from peaso import worker

    called = []
    module = types.ModuleType("peaso.progressive_analyzer")
    def run_progressive(instance, tenant, ident):
        called.append((instance.role, tenant, ident))
        return "completed"
    module.run_progressive = run_progressive
    monkeypatch.setitem(sys.modules, "peaso.progressive_analyzer", module)
    monkeypatch.setattr(worker, "Worker", lambda role: types.SimpleNamespace(role=role,
                        stopping=types.SimpleNamespace(set=lambda: None)))
    monkeypatch.setattr(sys, "argv", ["peaso.worker", "analyzer", "--progressive", "--once",
                                    "--tenant-id", TENANT, "--scan-id", SCAN])
    worker.main()
    assert called == [("analyzer", TENANT, SCAN)]
    module.run_progressive = lambda *_: "failed"
    with pytest.raises(SystemExit) as exit_status:
        worker.main()
    assert exit_status.value.code == 1


def test_final_ai_stage_reuse_requires_complete_matching_revision(tmp_path):
    from peaso.storage.artifacts import FileArtifacts
    from peaso.worker import _reusable_stages

    artifacts = FileArtifacts(tmp_path)
    good = artifacts.put(TENANT, SCAN, "ai-review", {"stage": "hardening", "data_revision": 4,
        "result": {"status": "completed", "reviews": {"hardening": []}}})
    mismatched = artifacts.put(TENANT, SCAN, "ai-review", {"stage": "network", "data_revision": 3,
        "result": {"status": "completed"}})
    other_tenant = artifacts.put(OTHER, SCAN, "ai-review", {"stage": "exposure", "data_revision": 4,
        "result": {"status": "completed"}})
    sections = {"hardening": {"status": "complete", "data_revision": 4},
                "network": {"status": "complete", "data_revision": 4},
                "exposure": {"status": "complete", "data_revision": 4}}
    stages = {"hardening": {"data_revision": 4, "result_ref": good},
              "network": {"data_revision": 4, "result_ref": mismatched},
              "exposure": {"data_revision": 4, "result_ref": other_tenant}}
    assert set(_reusable_stages(artifacts, TENANT, sections, stages)) == {"hardening"}
    sections["hardening"]["status"] = "running"
    assert _reusable_stages(artifacts, TENANT, sections, stages) == {}
