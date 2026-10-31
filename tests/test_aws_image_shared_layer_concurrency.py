"""Two images of one repository that share a layer are scanned concurrently.

The ECR repository check scans the latest image while a container-image Lambda
scans an older image of the same repository. Both list the same base layer, so
both pipelines want the same blob at the same time; each must still read it.
"""
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import gzip
import json
import os
import subprocess
import sys
import tempfile
import threading
import time

import pytest

from peaso.collectors import aws_image_capture_20261022 as capture
from peaso.collectors import aws_package_content_indicators as p
from peaso.checks import aws_package_content_review_20261019 as c
from tests.test_aws_package_content_review_20261019 import (
    ACCOUNT, REGION, SECRET, URL, arn, digest, index, sdk, tar_bytes,
    isolated_detector_dependencies)  # noqa: F401 (autouse: offline detectors)


def _image(config_text, layers):
    config = json.dumps({'architecture': 'amd64', 'os': 'linux',
        'rootfs': {'type': 'layers', 'diff_ids': [digest(gzip.decompress(l)) for l in layers]},
        'config': {'Env': [config_text]}, 'history': [{'created_by': 'COPY safe'}]}).encode()
    manifest = json.dumps({'schemaVersion': 2, 'mediaType': p.OCI,
        'config': {'mediaType': 'application/vnd.oci.image.config.v1+json',
                   'digest': digest(config), 'size': len(config)},
        'layers': [{'mediaType': 'application/vnd.oci.image.layer.v1.tar+gzip',
                    'digest': digest(l), 'size': len(l)} for l in layers]})
    return digest(manifest.encode()), manifest, config


def _two_images_sharing_a_layer(monkeypatch):
    requests, session, repository, ops, calls, downloads, payloads = sdk(monkeypatch, 'ecr_repository')
    shared = gzip.compress(tar_bytes([('app/config.py', "PASSWORD='" + SECRET + "'")]))
    latest_only = gzip.compress(tar_bytes([('app/version.txt', 'v2')]))
    latest, latest_manifest, latest_config = _image('STAGE=prod', [shared, latest_only])
    older, older_manifest, older_config = _image('STAGE=old', [shared])
    blobs = {digest(b): b for b in (shared, latest_only, latest_config, older_config)}
    payloads.clear()
    payloads.update({URL + '-' + d: b for d, b in blobs.items()})
    manifests = {latest: latest_manifest, older: older_manifest}

    # Both pipelines must be inside their layer fetch before the shared blob
    # stream answers, so the two reads of that blob genuinely overlap.
    entered, overlap = [], threading.Event()
    original = p._download_image_layers
    def tracked(*args, **kwargs):
        entered.append(args[5])
        if len(entered) >= 2: overlap.set()
        return original(*args, **kwargs)
    monkeypatch.setattr(p, '_download_image_layers', tracked)
    shared_url = URL + '-' + digest(shared)
    serve = p.build_opener().open
    def open_(url, timeout):
        if url == shared_url: overlap.wait(timeout=5)
        return serve(url, timeout)
    monkeypatch.setattr(p, 'build_opener', lambda *a: type('O', (), {'open': staticmethod(open_)})())

    ops['batch_get_image'] = lambda **kw: {'images': [{'registryId': ACCOUNT, 'repositoryName': 'example',
        'imageId': kw['imageIds'][0], 'imageManifest': manifests[kw['imageIds'][0]['imageDigest']],
        'imageManifestMediaType': p.OCI}], 'failures': []}
    ops['get_download_url_for_layer'] = lambda **kw: {'layerDigest': kw['layerDigest'],
                                                      'downloadUrl': URL + '-' + kw['layerDigest']}
    ops['describe_images'] = {'imageDetails': [
        {'registryId': ACCOUNT, 'repositoryName': 'example', 'imageDigest': older,
         'imagePushedAt': datetime(2026, 10, 1, tzinfo=timezone.utc)},
        {'registryId': ACCOUNT, 'repositoryName': 'example', 'imageDigest': latest,
         'imagePushedAt': datetime(2026, 10, 19, tzinfo=timezone.utc)}]}
    function = {'FunctionArn': arn('lambda', 'function:imagefn'), 'FunctionName': 'imagefn',
                'Version': '$LATEST', 'PackageType': 'Image'}
    ops['get_function'] = {'Configuration': {**function, 'CodeSize': 0, 'CodeSha256': 'unused'},
        'Code': {'RepositoryType': 'ECR', 'ImageUri': f'{ACCOUNT}.dkr.ecr.{REGION}.amazonaws.com/example:old',
                 'ResolvedImageUri': f'{ACCOUNT}.dkr.ecr.{REGION}.amazonaws.com/example@{older}'}}
    return requests, session, repository, function, downloads, shared_url, entered


def _scan_both(requests, session, repository, function):
    barrier = threading.Barrier(2)
    def run(kind, item):
        barrier.wait(timeout=5)
        return p.ENRICHERS[kind](requests, session, REGION, [item])[0]
    with ThreadPoolExecutor(2) as pool:
        ecr = pool.submit(run, 'ecr_repository', repository)
        fn = pool.submit(run, 'lambda_function', function)
        return ecr.result(timeout=30), fn.result(timeout=30)


def _assert_both_complete_findings(ecr, fn):
    for check, result, kind in ((c.image_layers, ecr, 'ecr_repository'),
                                (c.function_code, fn, 'lambda_function')):
        indicators = result['PackageContentSource']['PackageSecretIndicators']
        assert indicators['NativeResponseComplete'] is True, indicators.get('Reason')
        status, evidence = check(result, index(kind, result))
        assert status == 'FAIL' and evidence['source_complete'] is True
        assert 'app/config.py' in {ref['File'] for ref in evidence['references']}


@pytest.mark.parametrize('scoped', [True, False], ids=['scan_capture', 'no_capture'])
def test_concurrent_images_sharing_a_layer_both_read_it(monkeypatch, tmp_path, scoped):
    monkeypatch.setattr(tempfile, 'tempdir', str(tmp_path))
    requests, session, repository, function, downloads, shared_url, entered = \
        _two_images_sharing_a_layer(monkeypatch)
    if scoped:
        with capture.capture_scope(requests) as store:
            ecr, fn = _scan_both(requests, session, repository, function)
        assert not store.root.exists()
    else:
        ecr, fn = _scan_both(requests, session, repository, function)
    assert len(set(entered)) == 2
    _assert_both_complete_findings(ecr, fn)
    shared_reads = sum(url == shared_url for url, _ in downloads)
    # A scan-scoped capture downloads each distinct blob once for every image.
    assert shared_reads == (1 if scoped else 2)
    assert _ecr_scratch(tmp_path) == []


def _ecr_scratch(root):
    return sorted(p.name for p in root.iterdir() if p.name.startswith('peaso-ecr-'))


@pytest.mark.parametrize('ending', ['exception', 'cancelled', 'deadline'])
def test_capture_and_image_scratch_removed_on_every_scan_ending(monkeypatch, tmp_path, ending):
    monkeypatch.setattr(tempfile, 'tempdir', str(tmp_path))
    requests, session, repository, function, *_ = _two_images_sharing_a_layer(monkeypatch)
    failure = {'exception': RuntimeError('collector failed'), 'cancelled': SystemExit(),
               'deadline': p._failure('deadline_exceeded')}[ending]
    original, on_disk = p._download_image_layers, []
    def interrupted(*args, **kwargs):
        original(*args, **kwargs)
        on_disk.append(_ecr_scratch(tmp_path))  # Payloads are on disk here.
        raise failure
    monkeypatch.setattr(p, '_download_image_layers', interrupted)
    with pytest.raises(BaseException):
        with capture.capture_scope(requests):
            _scan_both(requests, session, repository, function)
            raise failure
    assert on_disk and all(on_disk)
    assert _ecr_scratch(tmp_path) == []


def test_next_scan_removes_scratch_left_by_a_killed_scan(monkeypatch, tmp_path):
    monkeypatch.setattr(tempfile, 'tempdir', str(tmp_path))
    dead = subprocess.Popen([sys.executable, '-c', 'pass'])
    dead.wait()
    killed = tmp_path / f'peaso-ecr-capture-{dead.pid}-abc'
    killed_image = tmp_path / f'peaso-ecr-secret-{dead.pid}-def'
    running = tmp_path / f'peaso-ecr-capture-{os.getppid()}-ghi'
    legacy_old, legacy_new = tmp_path / 'peaso-ecr-capture-oldxyz', tmp_path / 'peaso-ecr-secret-newxyz'
    unrelated = tmp_path / 'peaso-scan-keep'
    for path in (killed, killed_image, running, legacy_old, legacy_new, unrelated):
        path.mkdir()
        (path / 'blob-0').write_bytes(b'payload')
    day_ago = time.time() - 2 * 24 * 3600
    os.utime(legacy_old, (day_ago, day_ago))
    requests = threading.local()
    requests._lock = threading.RLock()
    with capture.capture_scope(requests):
        pass
    left = sorted(p.name for p in tmp_path.iterdir())
    assert left == sorted([running.name, legacy_new.name, unrelated.name])
