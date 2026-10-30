"""Focused synthetic ECR image streaming and Lambda compatibility checks."""
import gzip
import hashlib
import base64
import importlib.util
import io
import json
from pathlib import Path
import sys
import tarfile
import threading
import zipfile
from types import ModuleType, SimpleNamespace

import pytest

HERE = Path(__file__).resolve().parents[1]
from peaso.collectors import aws_package_content_indicators as p
from peaso import secret_scanning

ACCOUNT = '123456789012'
REGION = 'us-east-1'
URL = 'https://owned.s3.us-east-1.amazonaws.com/blob?X-Amz-Signature=synthetic'
TOKEN = 'ghp_' + '7mQ2zR9wL4cV8nK1sF6aH3jP5uD0xB2yE9rT'


def digest(raw):
    return 'sha256:' + hashlib.sha256(raw).hexdigest()


def tar_bytes(entries):
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode='w', format=tarfile.USTAR_FORMAT) as tar:
        for kind, name, value in entries:
            info = tarfile.TarInfo(name)
            if kind == 'file':
                info.size = len(value)
                tar.addfile(info, io.BytesIO(value))
            else:
                info.type = tarfile.SYMTYPE if kind == 'symlink' else tarfile.LNKTYPE
                info.linkname = value
                tar.addfile(info)
    return stream.getvalue()


class Response:
    def __init__(self, raw, url=URL):
        self.source = io.BytesIO(raw)
        self.status = 200
        self.headers = {'Content-Length': str(len(raw))}
        self.url = url
    def geturl(self): return self.url
    def read(self, count): return self.source.read(count)
    def __enter__(self): return self
    def __exit__(self, *args): pass


class Requests:
    def __init__(self, blobs):
        self.blobs = blobs
        self._lock = threading.RLock()
        self.calls = 0
        self.max_calls = 100
        self.timeout = 3
        self.deadline = None
        self._package_scan_local = threading.local()
        self.content_secret_scans = True
    def check_deadline(self): pass
    def detail(self, session, service, region, operation, **kwargs):
        ld = kwargs['layerDigest']
        try:
            result = p._layer({'layerDigest': ld, 'downloadUrl': URL + ld},
                              {'registryId': ACCOUNT, 'repositoryName': 'example', 'layerDigest': ld}, self, REGION)
            return {**result, 'collection_status': 'collected'}
        except Exception:
            return {'collection_status': 'not_collected'}


def image_case(layer, *, gzip_layer=False):
    layers = list(layer) if isinstance(layer, (list, tuple)) else [layer]
    config = {'os': 'linux', 'architecture': 'amd64',
              'rootfs': {'type': 'layers', 'diff_ids': [digest(gzip.decompress(blob) if gzip_layer else blob)
                                                        for blob in layers]},
              'config': {'Env': ['STAGE=prod']}, 'history': [{'created_by': 'COPY safe'}]}
    config_raw = json.dumps(config, separators=(',', ':')).encode()
    manifest = {'schemaVersion': 2, 'mediaType': p.OCI,
                'config': {'mediaType': 'application/vnd.oci.image.config.v1+json',
                           'digest': digest(config_raw), 'size': len(config_raw)},
                'layers': [{'mediaType': 'application/vnd.oci.image.layer.v1.tar' +
                            ('+gzip' if gzip_layer else ''),
                            'digest': digest(blob), 'size': len(blob)} for blob in layers]}
    manifest_raw = json.dumps(manifest, separators=(',', ':'))
    image_digest = digest(manifest_raw.encode())
    response = {'images': [{'registryId': ACCOUNT, 'repositoryName': 'example',
                            'imageId': {'imageDigest': image_digest}, 'imageManifest': manifest_raw,
                            'imageManifestMediaType': p.OCI}], 'failures': []}
    args = {'registryId': ACCOUNT, 'repositoryName': 'example',
            'imageIds': [{'imageDigest': image_digest}]}
    blobs = {digest(config_raw): config_raw, **{digest(blob): blob for blob in layers}}
    return response, args, blobs


@pytest.fixture
def scanner(monkeypatch):
    monkeypatch.setattr(secret_scanning, '_scan_kingfisher',
                        lambda raw, path, timeout: [(TOKEN, 'synthetic', 1)] if TOKEN.encode() in raw else [])
    monkeypatch.setattr(secret_scanning, '_scan_trufflehog',
                        lambda raw, path, timeout: [(TOKEN, 'synthetic', 1)] if TOKEN.encode() in raw else [])
    secret_scanning._RESULTS.clear()
    yield
    secret_scanning._RESULTS.clear()


def exercise(monkeypatch, layer, **kwargs):
    response, args, blobs = image_case(layer, **kwargs)
    monkeypatch.setattr(p, 'build_opener', lambda *a: SimpleNamespace(open=lambda url, timeout: Response(blobs[url[len(URL):]], url)))
    requests = Requests(blobs)
    result = p._image(response, args, requests, None, REGION)['PackageSecretIndicators']
    return result, requests


def test_ordinary_large_layer_positive_streamed_and_dual_detected(monkeypatch, scanner):
    source = (b"password='" + TOKEN.encode() + b"'\n" + b'normal text line\n' * 1100000)
    layer = tar_bytes([('file', 'etc/app.txt', source)])
    assert len(layer) > 16 * 1024 * 1024
    result, requests = exercise(monkeypatch, layer)
    assert result['NativeResponseComplete'] is True
    assert result['References']
    leaks = result['References'][0]['Leaks']
    assert {v['engine'] for v in leaks[0]['detectors']} == {'kingfisher', 'trufflehog'}
    assert TOKEN not in json.dumps(result)
    assert requests.calls == 2


def test_reported_image_descriptor_sizes_fit_ecr_stream_bounds():
    assert 408165756 < p.ECR_LAYER_LIMIT
    assert 555978731 < p.ECR_IMAGE_LIMIT
    assert p.LAYER_LIMIT == 16 * 1024 * 1024
    assert p.EXPANDED_LIMIT == 64 * 1024 * 1024


def test_gzip_layer_streams_through_virtual_validator(monkeypatch, scanner):
    layer = gzip.compress(tar_bytes([('file', 'app.txt', b"password='" + TOKEN.encode() + b"'\n")]))
    result, _ = exercise(monkeypatch, layer, gzip_layer=True)
    assert result['NativeResponseComplete'] is True
    assert result['References']


def test_symlink_partial_hardlink_content_visited(monkeypatch, scanner):
    layer = tar_bytes([('file', 'etc/app.txt', b"password='" + TOKEN.encode() + b"'\n"),
                       ('hardlink', 'etc/alias.txt', 'etc/app.txt'),
                       ('symlink', 'etc/current.txt', 'app.txt')])
    result, _ = exercise(monkeypatch, layer)
    assert result['NativeResponseComplete'] is False
    assert result['collection_status'] == 'partial'
    assert result['References']
    assert any(r['File'] == 'etc/alias.txt' for r in result['References'])


@pytest.mark.parametrize('kind,name', [('traversal', '../escape'), ('unsupported', 'device')])
def test_unsafe_or_unsupported_layer_is_partial_and_temp_clean(monkeypatch, scanner, tmp_path, kind, name):
    if kind == 'traversal':
        layer = tar_bytes([('file', name, b'hello')])
    else:
        info = tarfile.TarInfo(name); info.type = tarfile.CHRTYPE
        layer = info.tobuf() + bytes(10240)
    result, _ = exercise(monkeypatch, layer)
    assert result['NativeResponseComplete'] is False
    assert result['References'] == []


def test_content_budget_skips_with_partial_unknown(monkeypatch, scanner):
    monkeypatch.setattr(p, 'FILE_LIMIT', 4)
    layer = tar_bytes([('file', 'large.txt', b'password=something')])
    result, _ = exercise(monkeypatch, layer)
    assert result['NativeResponseComplete'] is False
    assert result['References'] == []


def test_positive_from_verified_earlier_layer_survives_later_rejection(monkeypatch, scanner):
    good = tar_bytes([('file', 'first.txt', b"password='" + TOKEN.encode() + b"'\n")])
    bad = tar_bytes([('file', '../escape', b'other')])
    result, _ = exercise(monkeypatch, [good, bad])
    assert result['NativeResponseComplete'] is False
    assert result['References']
    assert TOKEN not in json.dumps(result)




def test_download_oversize_and_cancel_remove_partial_file(monkeypatch, tmp_path):
    monkeypatch.setattr(p, '_failure', lambda code: ValueError(code))
    raw = b'a' * (2 * 1024 * 1024)
    target = tmp_path / 'blob'
    request = Requests({})
    monkeypatch.setattr(p, 'build_opener', lambda *a: SimpleNamespace(
        open=lambda url, timeout: Response(raw, url)))
    with pytest.raises(ValueError):
        p.download_layer(request, URL, REGION, target, digest(raw), len(raw) - 1, [len(raw)])
    assert not target.exists()
    class Cancelled(Requests):
        def __init__(self):
            super().__init__({}); self.checks = 0
        def check_deadline(self):
            self.checks += 1
            if self.checks >= 4: raise RuntimeError('cancelled')
    with pytest.raises(ValueError):
        p.download_layer(Cancelled(), URL, REGION, target, digest(raw), len(raw), [len(raw)])
    assert not target.exists()
