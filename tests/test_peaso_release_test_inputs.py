"""Source ZIP regression inputs work without the developer's private tree."""
import hashlib
import json
import lzma
from pathlib import Path
import shutil

import pytest

from tests import release_test_inputs as inputs


def archive_checkout(tmp_path):
    target = tmp_path / "tests/fixtures/release-test-inputs.json.xz"
    target.parent.mkdir(parents=True)
    shutil.copyfile(Path(__file__).parent / "fixtures/release-test-inputs.json.xz", target)
    source = Path(__file__).parent / "fixtures/post_dfaf_integration/pre_review_ledger_inputs.json.gz"
    retained = tmp_path / "tests/fixtures/post_dfaf_integration/pre_review_ledger_inputs.json.gz"
    retained.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, retained)
    pci_source = Path(__file__).parent / "fixtures/post_dfaf_integration/pre_review_gcp_pci.json.gz"
    shutil.copyfile(pci_source, retained.parent / pci_source.name)
    return target


def test_restore_all_inputs_and_preserve_existing_checkout(tmp_path):
    archive_checkout(tmp_path)
    existing = tmp_path / "tests/fixtures/bulk_pending_behavior.json"
    existing.write_text('{"local_edit":true}')
    restored = inputs.restore_missing_inputs(tmp_path)
    assert len(restored) == 73
    assert existing.read_text() == '{"local_edit":true}'
    assert inputs.restore_missing_inputs(tmp_path) == []
    descriptions = tmp_path / "docs/compliance-ledgers/.work/swarm/sw44-descriptions.json"
    assert "aws_incident_workflow_sla" in json.loads(descriptions.read_text())


def test_restore_bulk_behavior_in_empty_checkout(tmp_path):
    archive_checkout(tmp_path)
    assert len(inputs.restore_missing_inputs(tmp_path)) == 74
    cases = json.loads((tmp_path / "tests/fixtures/bulk_pending_behavior.json").read_text())
    assert len(cases) == 552
    assert "unknown" in cases["aws_incident_workflow_sla"]
    assert "pass" not in cases["aws_incident_workflow_sla"]


def test_corrupted_bundle_is_rejected_without_writes(tmp_path):
    target = archive_checkout(tmp_path)
    target.write_bytes(target.read_bytes() + b"corrupt")
    with pytest.raises(ValueError, match="digest"):
        inputs.restore_missing_inputs(tmp_path)
    assert list(tmp_path.rglob("*.json")) == []


def test_symlink_escape_is_rejected_before_any_writes(tmp_path):
    archive_checkout(tmp_path)
    outside = tmp_path.parent / (tmp_path.name + "-outside")
    outside.mkdir()
    (tmp_path / "docs").symlink_to(outside, target_is_directory=True)
    with pytest.raises(ValueError, match="escapes"):
        inputs.restore_missing_inputs(tmp_path)
    assert list(outside.rglob("*")) == []
    assert list((tmp_path / "tests").rglob("*.json")) == []


def test_reviewed_bundle_has_no_unbounded_payload(tmp_path, monkeypatch):
    target = archive_checkout(tmp_path)
    monkeypatch.setattr(inputs, "MAX_EXPANDED_BYTES", 100)
    with pytest.raises(ValueError, match="expanded limit"):
        inputs.restore_missing_inputs(tmp_path)


def test_bounded_fixture_collection_contains_all_reviewed_entries(tmp_path):
    import yaml
    archive_checkout(tmp_path)
    inputs.restore_missing_inputs(tmp_path)
    rows = [row for path in (tmp_path / "tests/fixtures/privesc_bounded").glob("*.yaml") for row in yaml.safe_load(path.read_text())]
    assert len(rows) == len({row["id"] for row in rows}) == 67




def test_retained_pre_review_ledger_inputs_reject_bundle_tampering(tmp_path, monkeypatch):
    from tests import release_successor_history as history
    archive_checkout(tmp_path)
    monkeypatch.setattr(history, "ROOT", tmp_path)
    retained = history.retained_ledger_inputs()
    assert hashlib.sha256(retained["manifest.json"]).hexdigest() == history.PRE_REVIEW_MANIFEST_SHA256
    bundle = tmp_path / history.PRE_REVIEW_LEDGER_BUNDLE
    bundle.write_bytes(bundle.read_bytes() + b"tampered")
    with pytest.raises(ValueError, match="bundle digest"):
        history.retained_ledger_inputs()




@pytest.mark.parametrize("suffix", [b"extra", lzma.compress(b"{}")])
def test_trailing_or_concatenated_stream_is_rejected_before_writes(tmp_path, monkeypatch, suffix):
    target = archive_checkout(tmp_path)
    packed = target.read_bytes() + suffix
    target.write_bytes(packed)
    monkeypatch.setattr(inputs, "BUNDLE_SHA256", hashlib.sha256(packed).hexdigest())
    with pytest.raises(ValueError, match="trailing data"):
        inputs.restore_missing_inputs(tmp_path)
    assert list(tmp_path.rglob("*.json")) == []


def test_truncated_stream_is_rejected_before_writes(tmp_path, monkeypatch):
    target = archive_checkout(tmp_path)
    packed = target.read_bytes()[:-8]
    target.write_bytes(packed)
    monkeypatch.setattr(inputs, "BUNDLE_SHA256", hashlib.sha256(packed).hexdigest())
    with pytest.raises(ValueError, match="truncated"):
        inputs.restore_missing_inputs(tmp_path)
    assert list(tmp_path.rglob("*.json")) == []


@pytest.mark.parametrize("worker_failure", [False, True])
def test_batch_owns_restored_inputs_until_every_worker_finishes(tmp_path, monkeypatch, worker_failure):
    import sys
    import threading
    from scripts import peaso_bulk_validation as batch

    archive_checkout(tmp_path)
    paths = []
    for index in range(4):
        path = tmp_path / "tests" / f"test_worker_{index}.py"
        path.write_text("# independent worker selection\n")
        paths.append(path)
    monkeypatch.setattr(batch, "ROOT", tmp_path)
    monkeypatch.setattr(batch, "batches", lambda: [])
    monkeypatch.setattr(batch, "source_hashes", lambda: {})
    barrier = threading.Barrier(4, timeout=10)
    fixture = tmp_path / "tests/fixtures/post_dfaf_integration/historical-release-manifests.json"
    seen = []

    def run_worker(path, output, timeout):
        assert fixture.is_file()
        barrier.wait()
        assert fixture.is_file()
        seen.append(path.name)
        if worker_failure and path == paths[0]:
            raise RuntimeError("worker failed")
        return {"passed": True, "returncode": 0}

    monkeypatch.setattr(batch, "run_test", run_worker)
    arguments = ["batch", "--output", str(tmp_path / "output")]
    for path in paths:
        arguments.extend(["--test", str(path.relative_to(tmp_path))])
    monkeypatch.setattr(sys, "argv", arguments)
    if worker_failure:
        with pytest.raises(RuntimeError, match="worker failed"):
            batch.main()
    else:
        assert batch.main() == 0
    assert len(seen) == 4
    assert not fixture.exists()
    assert all(path.is_file() for path in paths)


def test_parallel_restoration_publishes_complete_files_without_overwriting(tmp_path):
    from concurrent.futures import ThreadPoolExecutor
    archive_checkout(tmp_path)
    with ThreadPoolExecutor(max_workers=4) as pool:
        results = list(pool.map(lambda _: inputs.restore_missing_inputs(tmp_path), range(4)))
    assert sum(len(paths) for paths in results) == 74
    assert len(json.loads((tmp_path / 'tests/fixtures/bulk_pending_behavior.json').read_text())) == 552
    assert not list(tmp_path.rglob('.release-input-*'))


def test_historical_cohort_is_bound_to_its_release_not_later_native_admissions():
    from types import SimpleNamespace
    from peaso.checks import CHECKS
    from tests.release_successor_history import registered_before_bulk
    baseline = registered_before_bulk(CHECKS)
    later = SimpleNamespace(id='synthetic.later.native.admission')
    assert registered_before_bulk([*CHECKS, later]) == baseline
    missing = [check for check in CHECKS if check.id != baseline[0].id]
    with pytest.raises(AssertionError):
        registered_before_bulk(missing)
