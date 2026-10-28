"""The collector can outlive (or lose) a later optional image phase."""
import json
import sys
import threading
import time
import types
from types import SimpleNamespace

import pytest

from peaso.snapshot import make_snapshot, seal
from peaso.storage.artifacts import FileArtifacts


SCOPE = "123456789012/us-east-1"
TENANT = "tenant-a"
SCAN = "a" * 32


def _session(monkeypatch, tmp_path, *, second=False, fail_second=False, **batch_options):
    from peaso import engine
    from peaso.incremental import CheckpointSession

    hardening = SimpleNamespace(id="test.hardening", category="hardening", kind="bucket",
                                dependencies=("bucket",))
    image = SimpleNamespace(id="test.image", category="vulnerability", kind="image",
                            dependencies=("image",))
    checks = [hardening, image] if second else [hardening]
    def selected(*args, content_checks=None):
        # This legacy fixture intentionally selects ordinary checks only.
        assert content_checks in (None, [])
        return [c.category for c in checks], checks
    monkeypatch.setattr(engine, "_selection", selected)
    monkeypatch.setattr(engine, "_analysis_selection", lambda *args: [])
    monkeypatch.setattr(engine, "_privesc_selected", lambda *args: None)
    analysis = types.ModuleType("peaso.analysis")
    analysis.REQUIRED_TYPES = {}
    analysis.privesc_required_types = lambda provider: []
    monkeypatch.setitem(sys.modules, "peaso.analysis", analysis)

    def evaluate(snapshot, *, checks, **_):
        if fail_second and "test.image" in checks:
            raise RuntimeError("interrupted analysis")
        findings = [{"check_id": check, "scope": SCOPE, "category":
                     "vulnerability" if check == "test.image" else "hardening",
                     "status": "FAIL", "severity": "high"} for check in checks]
        return {"findings": findings,
                "coverage": [{"level": "check", "check_id": check, "scope": SCOPE,
                              "status": "evaluated"} for check in checks],
                "stats": {"finding_count": len(findings), "coverage_complete": True,
                          "inventory_complete": True}}

    monkeypatch.setattr(engine, "evaluate_snapshot", evaluate)
    artifacts = FileArtifacts(tmp_path)
    refs = []
    published = threading.Event()

    def public_snapshot(snapshot):
        # A stand-in for the worker's secret_capture.public_snapshot + auth
        # credential redact + seal boundary. Nothing private reaches artifacts.
        public = json.loads(json.dumps(snapshot).replace("PRIVATE", "[REDACTED]"))
        return seal(public)

    def on_checkpoint(snapshot, report, sequence):
        snapshot_ref = artifacts.put(TENANT, SCAN, "snapshot", snapshot)
        report_ref = artifacts.put(TENANT, SCAN, "report", report) if report else None
        refs.append((sequence, snapshot_ref, report_ref))
        if report_ref:
            published.set()

    connector_options = batch_options.pop("connector_options", None)
    request = {"connector": {"provider": "aws", "scopes": [SCOPE],
                             "options": connector_options or {}},
               "categories": [c.category for c in checks], "checks": [c.id for c in checks]}
    session = CheckpointSession(request, on_checkpoint, public_snapshot,
                                interval=0.02, **batch_options)
    return session, artifacts, refs, published


def test_hardening_report_survives_blocked_image_and_private_value(monkeypatch, tmp_path):
    session, artifacts, refs, published = _session(monkeypatch, tmp_path, second=True)
    image_blocked = threading.Event()
    try:
        assert session.on_collection({"type": "bucket", "scope": SCOPE, "status": "collected",
                                      "items": [{"id": "b", "private_field": "PRIVATE"}]}) == 1
        assert published.wait(2), "hardening should publish while image phase is still blocked"
        assert not image_blocked.is_set()
        report_ref = next(report for _, _, report in refs if report)
        report = artifacts.get(TENANT, report_ref)
        assert [row["check_id"] for row in report["findings"]] == ["test.hardening"]
        assert report["publication"]["state"] == "partial"
        assert report["stats"]["coverage_complete"] is False
        assert "PRIVATE" not in json.dumps([artifacts.get(TENANT, ref) for _, ref, _ in refs])
        # A provider timeout or child termination after this point cannot
        # remove the already durable tenant/scan-scoped artifact.
        assert artifacts.get(TENANT, report_ref)["findings"] == report["findings"]
    finally:
        session.close()


def test_duplicate_settlement_does_not_advance_checkpoint(monkeypatch, tmp_path):
    session, _, refs, _ = _session(monkeypatch, tmp_path)
    envelope = {"type": "bucket", "scope": SCOPE, "status": "empty", "items": []}
    try:
        assert session.on_collection(envelope) == 1
        assert session.on_collection(envelope) == 1
        assert not [row for row in refs if row[2] is None]
        session.flush()
        assert len([row for row in refs if row[2] is None]) == 1
    finally:
        session.close()


def test_cumulative_snapshot_includes_sections_with_original_digest(monkeypatch, tmp_path):
    from peaso.snapshot import make_snapshot, seal

    session, _, _, _ = _session(monkeypatch, tmp_path)
    envelope = {"type": "bucket", "scope": SCOPE, "status": "collected",
                "items": [{"id": "b", "Nested": {"dimensions": ["one", "two"]}}]}
    sections = {"hardening": {"status": "complete", "data_revision": 1}}
    try:
        current = session._snapshot([envelope], sequence=1, sections=sections)
        old = make_snapshot("aws", [SCOPE], [envelope], created_at=current["created_at"],
                            metadata={key: value for key, value in current["metadata"].items()
                                      if key != "sections"})
        old["metadata"]["sections"] = sections
        old = seal(old)
        assert current == old
        envelope["items"][0]["Nested"]["dimensions"].append("later")
        assert current == old
    finally:
        session.close()


def test_final_collector_metadata_reaches_last_public_checkpoint_with_partial_fences(monkeypatch, tmp_path):
    session, artifacts, refs, _ = _session(monkeypatch, tmp_path)
    envelope = {"type": "bucket", "scope": SCOPE, "status": "empty", "items": []}
    final = {"cluster_id": "validated-cluster", "selected_targets": [{"id": "validated"}],
             "note": "PRIVATE", "intentional_partial": False,
             "scope_coverage": {"status": "complete"}, "requested_scopes": ["foreign"],
             "incremental": {"phase": "complete", "sequence": 999},
             "sections": {"foreign": {"status": "complete"}}}
    original = json.loads(json.dumps(final))
    try:
        session.on_collection(envelope)
        assert "cluster_id" not in session._snapshot([envelope])["metadata"]
        session.finish_collection(final_metadata=final)
        assert final == original
        final["selected_targets"][0]["id"] = "changed-after-finish"
        session.flush()
        published = artifacts.get(TENANT, refs[-1][1])
        metadata = published["metadata"]
        assert metadata["cluster_id"] == "validated-cluster"
        assert metadata["selected_targets"] == [{"id": "validated"}]
        assert metadata["note"] == "[REDACTED]"
        assert metadata["intentional_partial"] is True
        assert metadata["scope_coverage"]["status"] == "partial"
        assert metadata["requested_scopes"] == [SCOPE]
        assert metadata["incremental"]["phase"] == "collecting"
        assert metadata["incremental"]["sequence"] != 999
        assert "foreign" not in metadata["sections"]
    finally:
        session.close()

    other, _, _, _ = _session(monkeypatch, tmp_path / "other")
    try:
        assert "cluster_id" not in other._snapshot([envelope])["metadata"]
        assert "selected_targets" not in other._snapshot([envelope])["metadata"]
    finally:
        other.close()


def test_interrupted_later_analysis_keeps_earlier_category(monkeypatch, tmp_path):
    session, artifacts, refs, published = _session(monkeypatch, tmp_path, second=True,
                                                   fail_second=True)
    try:
        session.on_collection({"type": "bucket", "scope": SCOPE, "status": "collected",
                               "items": [{"id": "b"}]})
        assert published.wait(2)
        first = next(report for _, _, report in refs if report)
        session.on_collection({"type": "image", "scope": SCOPE, "status": "collected",
                               "items": [{"id": "i"}]})
        with pytest.raises(RuntimeError, match="interrupted analysis"):
            session.flush()
        assert artifacts.get(TENANT, first)["publication"]["state"] == "partial"
        assert any(sequence == 2 and report is None for sequence, _, report in refs)
    finally:
        with pytest.raises(RuntimeError, match="checkpoint publication failed"):
            session.close()


def test_real_native_hardening_evaluation_publishes_before_optional_image_phase(tmp_path):
    from peaso.incremental import CheckpointSession

    artifacts = FileArtifacts(tmp_path)
    published = threading.Event()
    refs = []

    def on_checkpoint(snapshot, report, sequence):
        snapshot_ref = artifacts.put(TENANT, SCAN, "snapshot", snapshot)
        if report is not None:
            refs.append(artifacts.put(TENANT, SCAN, "report", report))
            published.set()
        assert snapshot_ref

    request = {"connector": {"provider": "aws", "scopes": [SCOPE]},
               "categories": ["hardening"], "checks": ["aws.s3.default_encryption"]}
    session = CheckpointSession(request, on_checkpoint, lambda snapshot: snapshot, interval=0.02)
    try:
        session.on_collection({"type": "bucket", "scope": SCOPE, "status": "collected",
                               "items": [{"Name": "baseline", "Encryption": {
                                   "ServerSideEncryptionConfiguration": {"Rules": [
                                       {"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]}}}]})
        assert published.wait(5), "native hardening evaluation must settle before any image read"
        report = artifacts.get(TENANT, refs[-1])
        rows = [row for row in report["findings"]
                if row["check_id"] == "aws.s3.default_encryption"]
        assert len(rows) == 1 and rows[0]["status"] == "PASS"
        assert report["publication"]["state"] == "partial"
        assert report["stats"]["inventory_complete"] is False
    finally:
        session.close()


def test_bounded_batches_and_duplicate_key_revision(monkeypatch, tmp_path):
    session, artifacts, refs, _ = _session(monkeypatch, tmp_path,
                                           batch_size=64, batch_interval=100)
    try:
        for index in range(64):
            session.on_collection({"type": "other", "scope": f"scope-{index}",
                                   "status": "empty", "items": []})
        assert [seq for seq, _, report in refs if report is None] == [64]
        first = artifacts.get(TENANT, refs[0][1])
        assert len(first['collections']) == 64
        assert first['metadata']['incremental']['batch_revisions'] == list(range(1, 65))
        session.on_collection({"type": "other", "scope": "scope-0",
                               "status": "denied", "items": []})
        for index in range(64, 127):
            session.on_collection({"type": "other", "scope": f"scope-{index}",
                                   "status": "empty", "items": []})
        assert [seq for seq, _, report in refs if report is None] == [64, 128]
        second = artifacts.get(TENANT, refs[-1][1])
        assert len(second['collections']) == 64
        assert next(row for row in second['collections'] if row['scope'] == 'scope-0')['status'] == 'denied'
        session.on_collection({"type": "other", "scope": "scope-0",
                               "status": "empty", "items": []})
        session.on_collection({"type": "other", "scope": "scope-0",
                               "status": "denied", "items": []})
        session.flush()
        last = artifacts.get(TENANT, refs[-1][1])
        assert len(last['collections']) == 1
        assert last['metadata']['incremental']['batch_revisions'] == [130]
        assert [seq for seq, _, report in refs if report is None] == [64, 128, 130]
    finally:
        session.close()


def test_time_and_byte_caps_flush_pending(monkeypatch, tmp_path):
    session, _, refs, _ = _session(monkeypatch, tmp_path, batch_interval=0.05)
    try:
        session.on_collection({"type": "other", "scope": SCOPE,
                               "status": "empty", "items": []})
        deadline = time.monotonic() + 2
        while not refs and time.monotonic() < deadline:
            time.sleep(0.01)
        assert [seq for seq, _, report in refs if report is None] == [1]
    finally:
        session.close()
    session, _, refs, _ = _session(monkeypatch, tmp_path / 'bytes',
                                  batch_interval=100, batch_bytes=1)
    try:
        session.on_collection({"type": "other", "scope": SCOPE,
                               "status": "empty", "items": []})
        assert [seq for seq, _, report in refs if report is None] == [1]
    finally:
        session.close()


def test_mixed_legacy_and_batch_restore_uses_latest_exact_key(monkeypatch, tmp_path):
    session, _, _, _ = _session(monkeypatch, tmp_path, second=True, batch_interval=100)
    old = {"type": "bucket", "scope": SCOPE, "status": "empty", "items": []}
    new = dict(old, status="denied")
    image = {"type": "image", "scope": SCOPE, "status": "empty", "items": []}
    legacy = make_snapshot('aws', [SCOPE], [old], metadata={
        'incremental': {'sequence': 1}})
    batch = make_snapshot('aws', [SCOPE], [new, image], metadata={
        'incremental': {'sequence': 3, 'batch_revisions': [2, 3]}})
    try:
        session.restore([batch, legacy], 3)
        assert session.sequence == session.next_sequence == 3
        assert session.collections['bucket', SCOPE]['status'] == 'denied'
        assert session.collection_revisions == {('bucket', SCOPE): 2, ('image', SCOPE): 3}
        assert session.on_collection(new) == 3
    finally:
        session.close()


def test_failed_batch_keeps_prior_commit_and_blocks_publication(monkeypatch, tmp_path):
    session, artifacts, refs, _ = _session(monkeypatch, tmp_path,
                                           batch_size=2, batch_interval=100)
    original = session.on_checkpoint
    def fail_second(snapshot, report, sequence):
        if report is None and sequence == 4:
            raise RuntimeError('fenced checkpoint rejected')
        original(snapshot, report, sequence)
    session.on_checkpoint = fail_second
    for index in range(3):
        session.on_collection({"type": "other", "scope": f"scope-{index}",
                               "status": "empty", "items": []})
    assert session.sequence == 2
    with pytest.raises(RuntimeError, match='fenced checkpoint rejected'):
        session.on_collection({"type": "other", "scope": "scope-3",
                               "status": "empty", "items": []})
    assert session.sequence == 2
    assert len(session.collections) == 2
    assert [seq for seq, _, report in refs if report is None] == [2]
    assert len(artifacts.get(TENANT, refs[0][1])['collections']) == 2
    with pytest.raises(RuntimeError, match='checkpoint publication failed'):
        session.close()


def test_report_never_overtakes_pending_batch(monkeypatch, tmp_path):
    session, artifacts, refs, _ = _session(monkeypatch, tmp_path,
                                           batch_interval=100)
    try:
        session.on_collection({"type": "bucket", "scope": SCOPE,
                               "status": "empty", "items": []})
        assert session.sequence == 0 and session.next_sequence == 1
        assert session._maybe_publish() is None
        assert refs == []
        session.flush()
        checkpoints = [row for row in refs if row[2] is None]
        reports = [row for row in refs if row[2] is not None]
        assert len(checkpoints) == len(reports) == 1
        assert reports[0][0] <= checkpoints[0][0] == session.sequence
        assert artifacts.get(TENANT, reports[0][1])['metadata']['incremental']['sequence'] == 1
    finally:
        session.close()




def test_throttled_publication_does_not_copy_the_accumulated_inventory(monkeypatch, tmp_path):
    session, _, _, _ = _session(monkeypatch, tmp_path)
    session.stop = True
    session.wake.set()
    session.thread.join(2)
    try:
        session.on_collection({'type': 'bucket', 'scope': SCOPE, 'status': 'collected', 'items': [{'id': 'b'}]})
        session.flush()
        session.on_collection({'type': 'bucket', 'scope': SCOPE, 'status': 'collected', 'items': [{'id': 'b', 'changed': True}]})
        with session.lock:
            session._flush_pending()
        session.interval = 1000000
        session.collection_stride = 1000000
        with monkeypatch.context() as guarded:
            def unnecessary_copy(*args, **kwargs):
                raise AssertionError('A throttled evaluation must not copy the full accumulated inventory')
            guarded.setattr('peaso.incremental.copy.deepcopy', unnecessary_copy)
            assert session._maybe_publish() is None
    finally:
        session.close()
