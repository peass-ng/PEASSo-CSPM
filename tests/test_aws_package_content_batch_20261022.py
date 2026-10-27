"""Synthetic, offline checks for bounded AWS package scan batching."""
from contextlib import contextmanager
import hashlib
import io
import json
import threading
from types import SimpleNamespace
import zipfile

import pytest

from peaso.collectors import aws_package_content_indicators as package


def _stub_prepared_groups(monkeypatch, prepared):
    # Production now consumes lease-bound groups. Keep these synthetic enqueue
    # tests at that seam; real decoder/lease behavior is covered separately.
    @contextmanager
    def groups(rows, requests):
        with prepared([(row[0], row[1]) for row in rows]):
            yield iter([rows])
    monkeypatch.setattr(package, '_archive_prepared_groups', groups)


def _zip(files):
    output = io.BytesIO()
    with zipfile.ZipFile(output, 'w') as archive:
        for name, payload in files:
            archive.writestr(name, payload)
    return output.getvalue()


def test_zip_prepares_bounded_original_members_and_scans_each_path(monkeypatch):
    groups, scanned = [], []

    @contextmanager
    def prepared(items):
        groups.append(list(items))
        yield

    def scan(payload, name, requests):
        scanned.append((payload, name))
        return []

    _stub_prepared_groups(monkeypatch, prepared)
    monkeypatch.setattr(package, '_scan', scan)
    monkeypatch.setattr(package, '_DEFAULT_SCAN', scan)
    files = [(f'file-{i}.txt', f'value={i}'.encode()) for i in range(package.BATCH_ITEMS + 3)]
    assert package.scan_zip(_zip(files), SimpleNamespace(check_deadline=lambda: None))[0] == []
    assert [len(group) for group in groups] == [package.BATCH_ITEMS, 3]
    assert [item for group in groups for item in group] == [(payload, name) for name, payload in files]
    assert scanned == [(payload, name) for name, payload in files]


def test_zip_retains_earlier_positive_when_later_scan_is_incomplete(monkeypatch):
    @contextmanager
    def prepared(items):
        yield

    def scan(payload, name, requests):
        if name == 'later.txt':
            raise package.PartialArchive([], 0, 0)
        return [{'File': name, 'Categories': ['secret'], 'Leaks': []}]

    _stub_prepared_groups(monkeypatch, prepared)
    monkeypatch.setattr(package, '_scan', scan)
    monkeypatch.setattr(package, '_DEFAULT_SCAN', scan)
    with pytest.raises(package.PartialArchive) as caught:
        package.scan_zip(_zip([('first.txt', b'positive'), ('later.txt', b'incomplete')]),
                         SimpleNamespace(check_deadline=lambda: None))
    assert caught.value.refs == [{'File': 'first.txt', 'Categories': ['secret'], 'Leaks': []}]


def test_zip_flushes_pending_positive_after_later_member_read_error(monkeypatch):
    @contextmanager
    def prepared(items):
        yield

    def scan(payload, name, requests):
        return [{'File': name, 'Categories': ['secret'], 'Leaks': []}]

    _stub_prepared_groups(monkeypatch, prepared)
    monkeypatch.setattr(package, '_scan', scan)
    monkeypatch.setattr(package, '_DEFAULT_SCAN', scan)
    raw = _zip([('first.txt', b'AAAA'), ('later.txt', b'BBBB')])
    assert raw.count(b'BBBB') == 1
    raw = raw.replace(b'BBBB', b'CCCC')
    with pytest.raises(package.PartialArchive) as caught:
        package.scan_zip(raw, SimpleNamespace(check_deadline=lambda: None))
    assert caught.value.refs == [{'File': 'first.txt', 'Categories': ['secret'], 'Leaks': []}]


def test_zip_batch_respects_byte_cap(monkeypatch):
    groups = []

    @contextmanager
    def prepared(items):
        groups.append(list(items))
        yield

    monkeypatch.setattr(package, 'BATCH_BYTES', 10)
    _stub_prepared_groups(monkeypatch, prepared)
    monkeypatch.setattr(package, '_scan', lambda *args: [])
    monkeypatch.setattr(package, '_DEFAULT_SCAN', package._scan)
    package.scan_zip(_zip([(str(i), b'123456') for i in range(3)]),
                     SimpleNamespace(check_deadline=lambda: None))
    assert [len(group) for group in groups] == [1, 1, 1]
    assert all(sum(len(payload) for payload, _ in group) <= 10 for group in groups)


def test_byte_aware_cap_keeps_legacy_groups_near_64mib_input(monkeypatch):
    requests = object()
    monkeypatch.setattr(package, '_archive_batch_items', lambda request: 2048 if request is requests else 512)
    assert package.BATCH_ITEMS == 512
    assert package.BATCH_BYTES == 64 * 1024 * 1024
    assert package.BATCH_TARGET_BYTES == 16 * 1024 * 1024
    assert not package._batch_flush_before(511, 511 * 32768, 32768, requests)
    assert package._batch_flush_before(512, 512 * 32768, 32768, requests)
    assert not package._batch_flush_before(2047, 2047 * 8192, 8192, requests)
    assert package._batch_flush_before(2048, 2048 * 8192, 8192, requests)


@pytest.mark.parametrize('failure', ['deadline', 'partial'])
def test_2048_boundary_retains_exact_earlier_evidence_on_late_failure(monkeypatch, failure):
    files = [(f'source-{i}', b'positive' if i == 0 else b'ordinary') for i in range(2048)]
    files.append(('terminal', b'failed'))
    archive = _zip(files)
    outcomes = []

    for cap in (512, 2048):
        groups = []

        @contextmanager
        def prepared(items):
            groups.append(len(items))
            yield

        def scan(payload, name, requests):
            if name == 'terminal':
                if failure == 'deadline':
                    raise TimeoutError('synthetic deadline')
                raise package.PartialArchive([{'File': 'terminal', 'Categories': ['secret'], 'Leaks': []}], 0, 0)
            return [{'File': name, 'Categories': ['secret'], 'Leaks': []}] if name == 'source-0' else []

        monkeypatch.setattr(package, '_archive_batch_items', lambda request: cap)
        _stub_prepared_groups(monkeypatch, prepared)
        monkeypatch.setattr(package, '_scan', scan)
        monkeypatch.setattr(package, '_DEFAULT_SCAN', scan)
        with pytest.raises(package.PartialArchive) as caught:
            package.scan_zip(archive, SimpleNamespace(check_deadline=lambda: None))
        outcomes.append(caught.value.refs)
        assert groups == ([512] * 4 + [1] if cap == 512 else [2048, 1])
    assert outcomes[0] == outcomes[1]
    assert outcomes[0][0] == {'File': 'source-0', 'Categories': ['secret'], 'Leaks': []}
    assert len(outcomes[0]) == (1 if failure == 'deadline' else 2)


def test_reader_enqueues_original_overlap_windows_and_preserves_budget(monkeypatch):
    monkeypatch.setattr(package, 'SCAN_WINDOW', 8)
    monkeypatch.setattr(package, 'SCAN_OVERLAP', 3)
    windows, remaining = [], [20]
    payload = b'abcdefghij'
    refs, covered = package._scan_reader(io.BytesIO(payload), len(payload), 'source.txt',
        SimpleNamespace(check_deadline=lambda: None), remaining,
        enqueue=lambda raw, name: windows.append((raw, name)) or True)
    assert (refs, covered, remaining) == ([], True, [10])
    assert windows == [(b'abcdefgh', 'source.txt'), (b'fghij', 'source.txt')]


def test_ecr_flush_preserves_layer_context_and_marks_engine_failure_incomplete(monkeypatch):
    account, region, repo = '123456789012', 'us-east-1', 'sample/image'
    digest = lambda raw: 'sha256:' + hashlib.sha256(raw).hexdigest()
    config = json.dumps({'config': {'Env': []}, 'history': []}).encode()
    layer_a, layer_b = b'layer-a', b'layer-b'
    descriptors = [(digest(config), config), (digest(layer_a), layer_a), (digest(layer_b), layer_b)]
    manifest = json.dumps({'schemaVersion': 2, 'mediaType': package.OCI,
        'config': {'digest': descriptors[0][0], 'size': len(config),
                   'mediaType': 'application/vnd.oci.image.config.v1+json'},
        'layers': [{'digest': ld, 'size': len(raw),
                    'mediaType': 'application/vnd.oci.image.layer.v1.tar+gzip'}
                   for ld, raw in descriptors[1:]]})
    image_digest = digest(manifest.encode())
    identity = f'arn:aws:ecr:{region}:{account}:repository/{repo}@{image_digest}'
    response = {'images': [{'registryId': account, 'repositoryName': repo,
        'imageId': {'imageDigest': image_digest}, 'imageManifest': manifest,
        'imageManifestMediaType': package.OCI}], 'failures': []}
    context, scanned, batches = [], [], []

    @contextmanager
    def source_context(**values):
        context.append(values)
        try:
            yield
        finally:
            context.pop()

    @contextmanager
    def prepared(items):
        batches.append(list(items))
        yield

    def scan(raw, name, requests):
        scanned.append((raw, name, dict(context[-1])))
        if name == 'bad.txt':
            raise package.PartialArchive([], 0, 0)
        if name == 'good.txt':
            return [{'File': name, 'Categories': ['secret'], 'Leaks': []}]
        return []

    requests = SimpleNamespace(_lock=threading.Lock(), check_deadline=lambda: None)
    def detail(session, service, selected_region, operation, **kwargs):
        ld, size, path = requests._package_scan_local.active
        path.write_bytes(dict(descriptors)[ld])
        return {'collection_status': 'collected', 'LayerDigest': ld,
                'RegistryId': account, 'RepositoryName': repo, 'CompressedBytes': size}
    requests.detail = detail

    def visit_files(image, manifest_raw, config_raw, paths, callback, *, check, partial_callback):
        partial_callback('good.txt', io.BytesIO(b'password=one'), 12, 0)
        partial_callback('bad.txt', io.BytesIO(b'password=two'), 12, 1)
        return {'expanded_bytes': 24, 'links_skipped': 0, 'partial': False}

    from peaso import container_image_archive_20261020 as archive
    monkeypatch.setattr(package, 'source_context', source_context)
    _stub_prepared_groups(monkeypatch, prepared)
    monkeypatch.setattr(package, '_scan', scan)
    monkeypatch.setattr(package, 'reuse_image_layer', lambda *args, **kwargs: None)
    monkeypatch.setattr(archive, 'visit_files', visit_files)
    result = package._image(response, {'registryId': account, 'repositoryName': repo,
        'imageIds': [{'imageDigest': image_digest}]}, requests, object(), region)
    marker = result['PackageSecretIndicators']
    assert batches == [[(b'password=one', 'good.txt'), (b'password=two', 'bad.txt')]]
    assert [(name, values['layer']) for _, name, values in scanned if name != 'image-config'] == [
        ('good.txt', descriptors[1][0]), ('bad.txt', descriptors[2][0])]
    assert all(values['resource_id'] == identity and values['image_digest'] == image_digest
               and values['scope'] == account + '/' + region and
               values['check_ids'] == {'aws.review.ecr_repository.package_content_secret_indicators'}
               for _, name, values in scanned if name != 'image-config')
    assert marker['References'] == [{'File': 'good.txt', 'Categories': ['secret'],
                                     'Leaks': [], 'LayerDigest': descriptors[1][0]}]
    assert marker['NativeResponseComplete'] is False
