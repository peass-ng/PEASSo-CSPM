import importlib.util
from pathlib import Path
import sys

import pytest

from test_gcp_image_stream_inspection import image
from peaso.collectors import gcp_job_trivy_stream_20261021 as stream
import gcp_job_image_vulnerability_fixture_20261021 as fixture


def released(runner):
    """Fake runners keep the real runner's contract: release staged scratch in finally."""
    from peaso import container_image_archive_20261020 as image_archive
    def run(identity, manifest, config, layers, **kwargs):
        try:
            return runner(identity, manifest, config, layers, **kwargs)
        finally:
            image_archive.release_staged(identity, manifest, config, layers)
    return run

def setup_large(monkeypatch, *, compressed=False, fault=None):
    row, blobs = image(9 * 1024 * 1024, compressed=compressed)
    base = 'https://us-central1-docker.pkg.dev/v2/review/images/app/'
    manifest_digest = row['digest']
    urls = {base + ('manifests/' if key == manifest_digest else 'blobs/') + key: value
            for key, value in blobs.items()}
    monkeypatch.setattr(fixture, 'image', lambda: (row, urls))
    selections, bodies, urls = fixture.fixtures()
    metadata = fixture.MetadataSession(bodies, fault=fault)
    images = fixture.ImageSession(urls)
    return selections, metadata, images, fixture.transport()


def clean(identity, manifest, config, layers, **kwargs):
    assert all(isinstance(value, Path) for value in layers)
    assert kwargs['native_verifier']() == identity
    assert len(layers) == 1
    return {'image': identity, 'status': 'PASS', 'complete': True,
        'scan_complete': True, 'coverage_status': 'COMPLETE',
        'database': {'fresh': True}, 'findings': []}


@pytest.mark.parametrize('compressed', [False, True])
def test_real_native_job_flow_streams_large_layers_and_cleans_every_file(tmp_path, monkeypatch, compressed):
    monkeypatch.setattr(stream.tempfile, 'tempdir', str(tmp_path))
    selections, metadata, images, wire = setup_large(monkeypatch, compressed=compressed)
    observed_paths = []
    def runner(identity, manifest, config, layers, **kwargs):
        observed_paths.extend(layers)
        return clean(identity, manifest, config, layers, **kwargs)
    result = stream.collect_native(wire, scope=fixture.SCOPE, selectors=selections, enabled=True,
        metadata_session=metadata, image_session=images, runner=released(runner))
    assert result['status'] == 'PASS', result
    assert result['complete'] is True
    assert result['rows'][0]['status'] == 'PASS'
    assert len(metadata.calls) == 8 and len(images.calls) == 3
    assert wire.calls == 11
    assert metadata.closed and images.closed
    assert observed_paths and all(not path.exists() for path in observed_paths)
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize('tamper', ['replace', 'delete'])
def test_fresh_native_verifier_rejects_changed_retained_file(tmp_path, monkeypatch, tamper):
    monkeypatch.setattr(stream.tempfile, 'tempdir', str(tmp_path))
    selections, metadata, images, wire = setup_large(monkeypatch)
    reached = []
    def runner(identity, manifest, config, layers, **kwargs):
        reached.append(True)
        if tamper == 'delete':
            layers[0].unlink()
        else:
            with layers[0].open('r+b') as output:
                output.write(b'corrupt')
        kwargs['native_verifier']()
        pytest.fail('changed content accepted')
    result = stream.collect_native(wire, scope=fixture.SCOPE, selectors=selections, enabled=True,
        metadata_session=metadata, image_session=images, runner=released(runner))
    assert reached
    assert result['status'] == 'UNKNOWN'
    assert result['complete'] is False
    assert metadata.closed and images.closed
    assert list(tmp_path.iterdir()) == []


def test_second_metadata_denial_prevents_scanner_and_cleans_capture(tmp_path, monkeypatch):
    monkeypatch.setattr(stream.tempfile, 'tempdir', str(tmp_path))
    selections, metadata, images, wire = setup_large(monkeypatch,
        fault=lambda url, count: 'denied' if count == 2 else None)
    calls = []
    result = stream.collect_native(wire, scope=fixture.SCOPE, selectors=selections, enabled=True,
        metadata_session=metadata, image_session=images, runner=lambda *args, **kwargs: calls.append(True))
    assert result['status'] == 'UNKNOWN'
    assert not calls
    assert metadata.closed and images.closed
    assert list(tmp_path.iterdir()) == []


def test_disabled_is_zero_access():
    result = stream.collect_native(object(), scope=object(), selectors=object(), enabled=False,
                                   metadata_session=object(), image_session=object())
    assert result['reason'] == 'disabled'
    assert result['status'] == 'UNKNOWN'


def test_file_hash_checks_cancellation_for_every_chunk(tmp_path):
    path = tmp_path / 'layer'
    path.write_bytes(b'x' * (stream.CHUNK + 1))
    calls = []
    def cancel():
        calls.append(True)
        if len(calls) == 2:
            raise RuntimeError('cancelled')
    with pytest.raises(RuntimeError, match='cancelled'):
        stream.sha256(path, cancel)
    assert len(calls) == 2


def test_confirmed_high_vulnerability_remains_fail_with_partial_database_coverage(tmp_path, monkeypatch):
    monkeypatch.setattr(stream.tempfile, 'tempdir', str(tmp_path))
    selections, metadata, images, wire = setup_large(monkeypatch, compressed=True)
    def runner(identity, manifest, config, layers, **kwargs):
        assert all(isinstance(value, Path) for value in layers)
        assert kwargs['native_verifier']() == identity
        return {'image': identity, 'status': 'FAIL', 'complete': False,
            'scan_complete': False, 'coverage_status': 'UNKNOWN', 'database': {'fresh': False},
            'findings': [{'vulnerability_id': 'CVE-2026-12345', 'severity': 'HIGH',
                'package_types': ['alpine'], 'package': 'package', 'version': '1.0',
                'fixed_in': ['1.1'], 'fix_status': 'fixed', 'classes': ['os-pkgs'],
                'image_digest': identity['manifest_digest']}]}
    result = stream.collect_native(wire, scope=fixture.SCOPE, selectors=selections, enabled=True,
        metadata_session=metadata, image_session=images, runner=released(runner))
    assert result['status'] == 'FAIL'
    assert result['complete'] is False
    record = result['rows'][0]['vulnerability_record']
    from peaso.checks import gcp_job_trivy_vulnerability_review_20261020 as review
    assert review.evaluate(record, {'scope': fixture.SCOPE,
        'selections': selections, 'source_requests': wire.evidence})[0] == 'FAIL'
    assert list(tmp_path.iterdir()) == []
