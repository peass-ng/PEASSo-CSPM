"""Proven-content memo, streamed archive reuse, scan reuse and shared DB lease."""
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import sys
import tarfile
import threading
import time

import pytest

from peaso import container_image_archive_20261020 as archive
from peaso import trivy_container_runner_20261020 as runner
from peaso import trivy_database_20261021 as database
from peaso.collectors import azure_acr_image_parallel_20261026 as parallel
from peaso.image_content_memo_20261026 import BoundedMemo


def wire(value):
    return json.dumps(value, separators=(',', ':')).encode()


def build(tmp_path, *, salt=b''):
    """One gzip layer and one uncompressed layer, independently hashed."""
    expanded = []
    for index in range(2):
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode='w', format=tarfile.USTAR_FORMAT) as tar:
            for name, data in ((f'etc/layer{index}', b'x' * 70000 + salt),
                               (f'usr/lib/random{index}.bin', os.urandom(300000))):
                item = tarfile.TarInfo(name)
                item.size = len(data)
                tar.addfile(item, io.BytesIO(data))
        expanded.append(buffer.getvalue())
    blobs = [gzip.compress(expanded[0], mtime=0), expanded[1]]
    kinds = ['application/vnd.oci.image.layer.v1.tar+gzip', 'application/vnd.oci.image.layer.v1.tar']
    layers = []
    for index, blob in enumerate(blobs):
        path = tmp_path / f'layer-{index}'
        path.write_bytes(blob)
        layers.append(path)
    config = wire({'os': 'linux', 'architecture': 'amd64',
                   'rootfs': {'type': 'layers', 'diff_ids': [archive.sha(raw) for raw in expanded]}})
    manifest = wire({'schemaVersion': 2, 'mediaType': archive.OCI,
                     'config': {'mediaType': 'application/vnd.oci.image.config.v1+json',
                                'digest': archive.sha(config), 'size': len(config)},
                     'layers': [{'mediaType': kind, 'digest': archive.sha(blob), 'size': len(blob)}
                                for kind, blob in zip(kinds, blobs)]})
    digest = archive.sha(manifest)
    identity = {'provider': 'aws', 'scope': '123456789012/us-east-1',
                'immutable_reference': '123456789012.dkr.ecr.us-east-1.amazonaws.com/example@' + digest,
                'manifest_digest': digest, 'config_digest': archive.sha(config)}
    return identity, manifest, config, layers


@pytest.fixture(autouse=True)
def fresh_memos():
    for memo in (archive._PROVEN, runner._SCANS, archive._STAGED):
        memo.clear()
    yield
    for memo in (archive._PROVEN, runner._SCANS, archive._STAGED):
        memo.clear()


@pytest.mark.parametrize('archive_format', ['docker', 'oci'])
def test_memo_hit_streams_byte_identical_archive(tmp_path, archive_format):
    identity, manifest, config, layers = build(tmp_path)
    cold, warm = tmp_path / 'cold.tar', tmp_path / 'warm.tar'
    first = archive.write_archive(cold, identity, manifest, config, layers, archive_format=archive_format)
    calls = []
    original = archive._validate
    archive._validate = lambda *a, **kw: calls.append(1) or original(*a, **kw)
    try:
        archive.validate(identity, manifest, config, layers)
        second = archive.write_archive(warm, identity, manifest, config, layers, archive_format=archive_format)
    finally:
        archive._validate = original
    assert calls == []
    assert first == second
    assert hashlib.sha256(cold.read_bytes()).digest() == hashlib.sha256(warm.read_bytes()).digest()


def test_memo_validate_result_matches_cold_validation(tmp_path):
    identity, manifest, config, layers = build(tmp_path)
    cold = archive.validate(identity, manifest, config, layers)
    warm = archive.validate(identity, manifest, config, layers)
    assert cold[0] == warm[0] and cold[2] == warm[2]


@pytest.mark.parametrize('index', [0, 1])
def test_tampered_layer_after_memo_hit_is_refused(tmp_path, index):
    identity, manifest, config, layers = build(tmp_path)
    archive.validate(identity, manifest, config, layers)
    raw = bytearray(layers[index].read_bytes())
    raw[len(raw) // 2] ^= 1
    layers[index].write_bytes(bytes(raw))
    with pytest.raises(ValueError, match='layer_descriptor_mismatch'):
        archive.validate(identity, manifest, config, layers)
    out = tmp_path / 'image.tar'
    with pytest.raises(ValueError):
        archive.write_archive(out, identity, manifest, config, layers)
    assert not out.exists()


def test_changed_limits_bypass_memo(tmp_path, monkeypatch):
    identity, manifest, config, layers = build(tmp_path)
    archive.validate(identity, manifest, config, layers)
    monkeypatch.setattr(archive, 'MAX_MEMBERS', 1)
    with pytest.raises(ValueError):
        archive.validate(identity, manifest, config, layers)


def test_streamed_reader_detects_change_during_archive(tmp_path):
    identity, manifest, config, layers = build(tmp_path)
    archive.validate(identity, manifest, config, layers)
    original = archive._proven

    def swap(*args):
        known = original(*args)
        raw = bytearray(layers[0].read_bytes())
        raw[-20] ^= 1
        layers[0].write_bytes(bytes(raw))
        return known
    archive._proven = swap
    try:
        with pytest.raises(ValueError):
            archive.write_archive(tmp_path / 'image.tar', identity, manifest, config, layers)
    finally:
        archive._proven = original
    assert not (tmp_path / 'image.tar').exists()


def test_bounded_memo_evicts_and_single_flight_serializes():
    memo = BoundedMemo(2, weight=10)
    memo.put('a', 1, 4); memo.put('b', 2, 4); memo.put('c', 3, 4)
    assert memo.get('a') is None and memo.get('b') == 2 and memo.get('c') == 3
    memo.put('huge', 0, 11)
    assert memo.get('huge') is None
    active, peak = [0], [0]

    def worker():
        with memo.single_flight('k'):
            active[0] += 1
            peak[0] = max(peak[0], active[0])
            time.sleep(0.05)
            active[0] -= 1
    threads = [threading.Thread(target=worker) for _ in range(4)]
    for thread in threads: thread.start()
    for thread in threads: thread.join()
    assert peak[0] == 1 and memo._inflight == {}


def database_dir(tmp_path):
    cache = tmp_path / 'db-cache'
    (cache / 'db').mkdir(parents=True)
    (cache / 'db/trivy.db').write_bytes(b'db')
    now = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
    (cache / 'db/metadata.json').write_text(json.dumps({'Version': 2, 'UpdatedAt': now,
                                                         'NextUpdate': '2999-01-01T00:00:00Z',
                                                         'DownloadedAt': now}))
    return cache


def stub_trivy(tmp_path, identity, config):
    log = tmp_path / 'calls.log'
    report = {'SchemaVersion': 2, 'ArtifactType': 'container_image',
              'Metadata': {'ImageID': identity['config_digest'],
                           'DiffIDs': json.loads(config)['rootfs']['diff_ids'],
                           'OS': {'Family': 'alpine', 'Name': '3.22.0'}},
              'Results': [{'Target': 'image', 'Class': 'os-pkgs', 'Type': 'alpine',
                           'Packages': [{'Name': 'musl'}],
                           'Vulnerabilities': [{'VulnerabilityID': 'CVE-2099-0001', 'Severity': 'HIGH',
                                                'PkgName': 'musl', 'InstalledVersion': '1.0',
                                                'FixedVersion': '1.1', 'Status': 'fixed'}]}]}
    script = tmp_path / 'trivy'
    script.write_text(f'#!{sys.executable}\nimport sys, json\n'
                      f'open({str(log)!r}, "a").write(sys.argv[1] + "\\n")\n'
                      'if sys.argv[1] == "--version":\n    print("Version: 0.68.1")\n'
                      f'else:\n    print({json.dumps(json.dumps(report))})\n')
    script.chmod(0o700)
    return script, log


def test_scan_reuse_skips_second_trivy_run_with_identical_result(tmp_path):
    identity, manifest, config, layers = build(tmp_path)
    cache = database_dir(tmp_path)
    cli, log = stub_trivy(tmp_path, identity, config)
    selected = archive.identity(identity)

    def scan():
        return runner.scan_image(identity, manifest, config, layers, native_verifier=lambda: selected,
                                 enabled=True, db_cache=cache, cli=cli, scratch_parent=tmp_path)
    first, second = scan(), scan()
    assert first['status'] == 'FAIL' and first['findings'], first
    for result in (first, second):  # wall-clock age at capture is not content
        result['database'].pop('age_seconds_at_capture')
    assert first == second
    assert log.read_text().split() == ['--version', 'image']


def test_scan_reuse_still_refuses_tampered_layer(tmp_path):
    identity, manifest, config, layers = build(tmp_path)
    cache = database_dir(tmp_path)
    cli, log = stub_trivy(tmp_path, identity, config)
    selected = archive.identity(identity)
    kwargs = dict(native_verifier=lambda: selected, enabled=True, db_cache=cache, cli=cli,
                  scratch_parent=tmp_path)
    assert runner.scan_image(identity, manifest, config, layers, **kwargs)['status'] == 'FAIL'
    raw = bytearray(layers[1].read_bytes()); raw[100] ^= 1
    layers[1].write_bytes(bytes(raw))
    second = runner.scan_image(identity, manifest, config, layers, **kwargs)
    assert second['status'] == 'UNKNOWN' and not second['findings']


def test_scan_reuse_keyed_by_database_generation(tmp_path):
    identity, manifest, config, layers = build(tmp_path)
    cache = database_dir(tmp_path)
    cli, log = stub_trivy(tmp_path, identity, config)
    selected = archive.identity(identity)
    kwargs = dict(native_verifier=lambda: selected, enabled=True, db_cache=cache, cli=cli,
                  scratch_parent=tmp_path)
    runner.scan_image(identity, manifest, config, layers, **kwargs)
    (cache / 'db/trivy.db').unlink()
    (cache / 'db/trivy.db').write_bytes(b'new generation')
    runner.scan_image(identity, manifest, config, layers, **kwargs)
    assert log.read_text().split() == ['--version', 'image', '--version', 'image']


def test_shared_lease_admits_concurrent_readers_and_excludes_refresh(tmp_path, monkeypatch):
    root = tmp_path / 'cache'
    generation = root / 'generations' / 'fixture'
    generation.mkdir(parents=True)
    monkeypatch.setattr(database, 'current_cache', lambda root: generation)
    monkeypatch.setattr(database, 'refresh', lambda *a, **kw: pytest.fail('unexpected refresh'))
    with database.database_lease(enabled=True, cache_root=root) as first:
        with database.database_lease(enabled=True, cache_root=root) as second:
            assert first == second == generation.resolve()
        fd = os.open(root / '.lease', os.O_RDWR)
        try:
            with pytest.raises(BlockingIOError):
                database.fcntl.flock(fd, database.fcntl.LOCK_EX | database.fcntl.LOCK_NB)
        finally:
            os.close(fd)


def test_refresh_waits_for_readers_and_readers_reuse_refresh(tmp_path, monkeypatch):
    root = tmp_path / 'cache'
    generation = root / 'generations' / 'fixture'
    refreshed = []

    def current(root):
        if not generation.exists():
            raise database.DatabaseUnavailable('missing')
        return generation

    def refresh(root, **kwargs):
        refreshed.append(1)
        generation.mkdir(parents=True)
    monkeypatch.setattr(database, 'current_cache', current)
    monkeypatch.setattr(database, 'refresh', refresh)
    root.mkdir()
    fd = os.open(root / '.lease', os.O_RDWR | os.O_CREAT, 0o600)
    database.fcntl.flock(fd, database.fcntl.LOCK_SH)
    seen, release = [], threading.Event()

    def reader():
        with database.database_lease(enabled=True, cache_root=root) as cache:
            seen.append(cache)
            release.wait(5)
    thread = threading.Thread(target=reader)
    thread.start()
    time.sleep(0.3)
    assert refreshed == [] and seen == []
    database.fcntl.flock(fd, database.fcntl.LOCK_UN)
    os.close(fd)
    for _ in range(50):
        if seen:
            break
        time.sleep(0.1)
    assert refreshed == [1] and seen == [generation.resolve()]
    release.set()
    thread.join(5)
    with database.database_lease(enabled=True, cache_root=root) as cache:
        assert cache == generation.resolve()
    assert refreshed == [1]


def test_parallel_targets_keep_order_and_private_receipts():
    jobs = [('scope', index) for index in range(5)]

    def scan(scope, target, receipts):
        time.sleep(0.02 * (5 - target))
        receipts.append(target)
        return {'target': target}
    serial = list(parallel.scan_targets(jobs, scan, workers=1))
    overlapped = list(parallel.scan_targets(jobs, scan))
    assert serial == overlapped == [({'target': i}, [i]) for i in range(5)]


def test_oci_manifest_builds_docker_save_layout_for_trivy_input(tmp_path):
    """Pinned Trivy --input reads docker-save tars; OCI images are archived that way."""
    identity, manifest, config, layers = build(tmp_path)
    assert json.loads(manifest)['mediaType'] == archive.OCI
    out = tmp_path / 'image.tar'
    proof = archive.write_archive(out, identity, manifest, config, layers, archive_format='docker')
    assert proof['format'] == 'docker'
    with tarfile.open(out) as tar:
        names = tar.getnames()
        listing = json.loads(tar.extractfile('manifest.json').read())
        assert 'index.json' not in names
        assert listing[0]['Config'] == identity['config_digest'][7:] + '.json'
        diffs = [archive.sha(tar.extractfile(name).read()) for name in listing[0]['Layers']]
    assert diffs == json.loads(config)['rootfs']['diff_ids']


def test_selected_oci_collectors_request_docker_archives():
    root = Path(__file__).resolve().parents[1] / 'peaso/collectors'
    for name in ('aws_ecr_public_image_native_20261021.py', 'k8s_selected_registry_image_20261021.py',
                 'azure_acr_image_vulnerabilities_20261021.py'):
        source = (root / name).read_text()
        assert "archive_format='oci'" not in source and "else 'docker'" not in source, name


def staged_dirs():
    return [item[1] for item in archive._STAGED._items.values()]


@pytest.mark.parametrize('archive_format', ['docker', 'oci'])
def test_validation_hands_expanded_layers_to_archive_once(tmp_path, archive_format, monkeypatch):
    identity, manifest, config, layers = build(tmp_path)
    cold = tmp_path / 'cold.tar'
    archive.write_archive(cold, identity, manifest, config, layers, archive_format=archive_format)
    archive._PROVEN.clear()
    archive.validate(identity, manifest, config, layers, stage=True)
    (scratch,) = staged_dirs()
    assert scratch.is_dir()
    monkeypatch.setattr(archive, '_ExpandingReader', lambda *a: pytest.fail('decompressed again'))
    warm = tmp_path / 'warm.tar'
    archive.write_archive(warm, identity, manifest, config, layers, archive_format=archive_format)
    assert cold.read_bytes() == warm.read_bytes()
    assert not scratch.exists() and staged_dirs() == []


def test_visit_files_hands_expanded_layers_to_archive(tmp_path, monkeypatch):
    identity, manifest, config, layers = build(tmp_path)
    seen = []
    archive.visit_files(identity, manifest, config, layers, lambda name, *rest: seen.append(name),
                        stage=True)
    assert seen and len(staged_dirs()) == 1
    monkeypatch.setattr(archive, '_ExpandingReader', lambda *a: pytest.fail('decompressed again'))
    archive.write_archive(tmp_path / 'image.tar', identity, manifest, config, layers, archive_format='docker')
    assert staged_dirs() == []


@pytest.mark.parametrize('how', ['rewrite', 'rewrite_preserving_mtime', 'replace', 'link'])
def test_tampered_staged_layer_is_refused_and_removed(tmp_path, how):
    identity, manifest, config, layers = build(tmp_path)
    archive.validate(identity, manifest, config, layers, stage=True)
    (scratch,) = staged_dirs()
    (victim,) = scratch.iterdir()
    raw = bytearray(victim.read_bytes()); raw[3000] ^= 1
    if how in ('rewrite', 'rewrite_preserving_mtime'):
        before = victim.stat()
        victim.write_bytes(bytes(raw))
        if how == 'rewrite_preserving_mtime':
            os.utime(victim, ns=(before.st_atime_ns, before.st_mtime_ns))
    elif how == 'replace':
        other = scratch / 'other'
        other.write_bytes(bytes(raw))
        other.replace(victim)
    else:
        (tmp_path / 'alias').hardlink_to(victim)
    out = tmp_path / 'image.tar'
    with pytest.raises(ValueError, match='layer_changed_during_archive'):
        archive.write_archive(out, identity, manifest, config, layers, archive_format='docker')
    assert not out.exists() and not scratch.exists()


def test_failed_validation_and_oversized_stage_leave_no_scratch(tmp_path, monkeypatch):
    identity, manifest, config, layers = build(tmp_path)
    monkeypatch.setattr(archive._STAGED, '_max_bytes', 10)
    archive.validate(identity, manifest, config, layers, stage=True)
    assert staged_dirs() == []
    raw = bytearray(layers[1].read_bytes()); raw[5] ^= 1
    layers[1].write_bytes(bytes(raw))
    archive._PROVEN.clear()
    made = []
    original = archive.tempfile.mkdtemp
    monkeypatch.setattr(archive.tempfile, 'mkdtemp', lambda **kw: made.append(original(**kw)) or made[-1])
    with pytest.raises(ValueError):
        archive.validate(identity, manifest, config, layers, stage=True)
    assert made and not Path(made[0]).exists()


def test_cancelling_archive_handoff_removes_output_and_scratch(tmp_path):
    identity, manifest, config, layers = build(tmp_path)
    archive.validate(identity, manifest, config, layers, stage=True)
    out = tmp_path / 'image.tar'

    def cancel_after_output_exists():
        if out.exists():
            raise RuntimeError('cancel archive handoff')

    with pytest.raises(RuntimeError, match='cancel archive handoff'):
        archive.write_archive(out, identity, manifest, config, layers,
                              archive_format='docker', check=cancel_after_output_exists)
    assert not out.exists() and staged_dirs() == []


def test_staged_scratch_expires_and_single_consumer(tmp_path):
    from peaso.image_content_memo_20261026 import StagedScratch
    stage = StagedScratch(100, 0.05)
    first, second = tmp_path / 'a', tmp_path / 'b'
    first.mkdir(); second.mkdir()
    stage.park('a', first, 'value', 10)
    assert stage.take('a') == (first, 'value') and stage.take('a') is None
    stage.park('b', second, 'value', 10)
    time.sleep(0.1)
    assert stage.take('b') is None and not second.exists()


def test_unstaged_validation_and_released_stage_leave_no_scratch(tmp_path, monkeypatch):
    identity, manifest, config, layers = build(tmp_path)
    made = []
    original = archive.tempfile.mkdtemp
    monkeypatch.setattr(archive.tempfile, 'mkdtemp', lambda **kw: made.append(original(**kw)) or made[-1])
    archive.validate(identity, manifest, config, layers)
    archive._PROVEN.clear()
    archive.visit_files(identity, manifest, config, layers, lambda *a: None)
    assert len(made) == 2 and staged_dirs() == [] and not any(Path(d).exists() for d in made)
    archive._PROVEN.clear()
    archive.validate(identity, manifest, config, layers, stage=True)
    assert len(staged_dirs()) == 1
    archive.release_staged(identity, manifest, config, layers)
    assert staged_dirs() == [] and not Path(made[-1]).exists()


def _variant(identity, manifest, config, os_name):
    """The same layer chain under another config of the same length."""
    other = config.replace(b'"amd64"', b'"arm64"')
    assert len(other) == len(config) and other != config
    doc = json.loads(manifest)
    doc['config']['digest'] = archive.sha(other)
    raw = wire(doc)
    digest = archive.sha(raw)
    return dict(identity, manifest_digest=digest, config_digest=archive.sha(other),
                immutable_reference=identity['immutable_reference'].split('@')[0] + '@' + digest), raw, other


def test_staged_archive_is_never_used_for_another_config_of_the_same_chain(tmp_path):
    identity, manifest, config, layers = build(tmp_path)
    other_identity, other_manifest, other_config = _variant(identity, manifest, config, 'arm64')
    cold = tmp_path / 'cold.tar'
    archive.write_archive(cold, other_identity, other_manifest, other_config, layers, archive_format='docker')
    archive._PROVEN.clear()
    archive.validate(identity, manifest, config, layers, stage=True)
    assert len(staged_dirs()) == 1
    warm = tmp_path / 'warm.tar'
    archive.write_archive(warm, other_identity, other_manifest, other_config, layers, archive_format='docker')
    assert warm.read_bytes() == cold.read_bytes() and staged_dirs() == []


def test_staged_archive_is_copied_when_it_cannot_be_linked(tmp_path, monkeypatch):
    import errno
    identity, manifest, config, layers = build(tmp_path)
    cold = tmp_path / 'cold.tar'
    archive.write_archive(cold, identity, manifest, config, layers, archive_format='docker')
    archive._PROVEN.clear()
    archive.validate(identity, manifest, config, layers, stage=True)
    (scratch,) = staged_dirs()

    def cross_device(*args):
        raise OSError(errno.EXDEV, 'cross-device link')
    monkeypatch.setattr(archive.os, 'link', cross_device)
    warm = tmp_path / 'warm.tar'
    archive.write_archive(warm, identity, manifest, config, layers, archive_format='docker')
    assert warm.read_bytes() == cold.read_bytes() and not scratch.exists()


def test_staged_archive_is_linked_without_a_second_copy(tmp_path, monkeypatch):
    identity, manifest, config, layers = build(tmp_path)
    archive.validate(identity, manifest, config, layers, stage=True)
    (scratch,) = staged_dirs()
    (built,) = scratch.iterdir()
    inode = built.stat().st_ino
    monkeypatch.setattr(archive.shutil, 'copyfileobj', lambda *a: pytest.fail('copied'))
    warm = tmp_path / 'warm.tar'
    archive.write_archive(warm, identity, manifest, config, layers, archive_format='docker')
    assert warm.stat().st_ino == inode and warm.stat().st_nlink == 1 and not scratch.exists()
