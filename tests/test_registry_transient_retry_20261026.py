import hashlib
import socket

import pytest

from peaso.collectors import k8s_selected_registry_image_20261021 as image

BLOB = b'layer-bytes'
DIGEST = 'sha256:' + hashlib.sha256(BLOB).hexdigest()


class Response:
    def __init__(self, status, body=b''):
        self.status, self.body = status, body
        self.headers = {'Content-Length': str(len(body))}

    def read(self, n=-1):
        out, self.body = (self.body, b'') if n < 0 else (self.body[:n], self.body[n:])
        return out

    def close(self):
        pass


class Conn:
    def close(self):
        pass


@pytest.fixture(autouse=True)
def fast(monkeypatch):
    monkeypatch.setattr(image, 'TRANSIENT_BACKOFF', .01)


def reader(steps, log):
    def open_https(host, path, headers, timeout):
        log.append(path)
        step = steps.pop(0)
        if isinstance(step, BaseException):
            raise step
        return Conn(), step
    return image.RegistryReader('ghcr.io', 'org/app', lambda: None, open_https=open_https)


@pytest.mark.parametrize('first', [socket.timeout(), ConnectionResetError(), Response(503), Response(429), Response(500)])
def test_one_transient_failure_is_retried_once_with_one_receipt(first):
    log = []
    r = reader([first, Response(200, BLOB)], log)
    assert r.get('blobs', DIGEST, 1024, size=len(BLOB)) == BLOB
    assert len(log) == 2 and r.calls == 2 and r.total == len(BLOB)
    assert [x['status'] for x in r.receipts] == ['collected']


def test_second_transient_failure_stays_unavailable():
    log = []
    r = reader([socket.timeout(), socket.timeout(), Response(200, BLOB)], log)
    with pytest.raises(image.Incomplete, match='registry_unavailable') as caught:
        r.get('blobs', DIGEST, 1024, size=len(BLOB))
    assert type(caught.value) is image.Incomplete and len(log) == 2


@pytest.mark.parametrize('status,reason', [(401, 'registry_denied'), (403, 'registry_denied'), (404, 'registry_unavailable')])
def test_denied_and_missing_are_never_retried(status, reason):
    log = []
    r = reader([Response(status), Response(200, BLOB)], log)
    with pytest.raises(image.Incomplete, match=reason):
        r.get('blobs', DIGEST, 1024, size=len(BLOB))
    assert len(log) == 1


def test_digest_mismatch_is_not_retried():
    log = []
    r = reader([Response(200, b'other-bytes'), Response(200, BLOB)], log)
    with pytest.raises(image.Incomplete, match='registry_truncated_or_digest'):
        r.get('blobs', DIGEST, 1024, size=len(BLOB))
    assert len(log) == 1


def test_retry_honours_call_limit(monkeypatch):
    log = []
    r = reader([socket.timeout(), Response(200, BLOB)], log)
    r.calls = image.MAX_CALLS - 1
    with pytest.raises(image.Incomplete, match='registry_unavailable'):
        r.get('blobs', DIGEST, 1024, size=len(BLOB))
    assert len(log) == 1 and r.calls == image.MAX_CALLS


def test_retry_removes_partial_destination(tmp_path):
    class Broken(Response):
        def read(self, n=-1):
            raise ConnectionResetError()
    log = []
    target = tmp_path / 'layer'
    r = reader([Broken(200, BLOB), Response(200, BLOB)], log)
    assert r.get('blobs', DIGEST, 1024, size=len(BLOB), destination=target) == target
    assert target.read_bytes() == BLOB and len(log) == 2


def test_existing_destination_is_not_retried_or_removed(tmp_path):
    log = []
    target = tmp_path / 'layer'
    target.write_bytes(b'keep')
    r = reader([Response(200, BLOB), Response(200, BLOB)], log)
    with pytest.raises(image.Incomplete, match='registry_unavailable'):
        r.get('blobs', DIGEST, 1024, size=len(BLOB), destination=target)
    assert target.read_bytes() == b'keep' and len(log) == 1
