"""Actual loopback HTTP framing plus negative resume/source/cleanup cases."""
import hashlib
from http.client import IncompleteRead
import importlib.util
import io
from pathlib import Path
from types import SimpleNamespace

import pytest
from peaso.collectors import aws_package_content_indicators as content

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('peaso.collectors._resume_test',
    ROOT/'peaso/collectors/aws_image_vulnerability_native_20261021.py')
native = importlib.util.module_from_spec(spec)
spec.loader.exec_module(native)
spec = importlib.util.spec_from_file_location('resume_http_fixture',
    ROOT/'tests/synthetic/benchmark_peaso_ecr_resume.py')
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)
PAYLOAD = b'x'*(3*1024*1024+17)
DIGEST = 'sha256:'+hashlib.sha256(PAYLOAD).hexdigest()


def download(tmp_path, state):
    tmp_path.chmod(0o700)
    return native.download_blob_path(state, fixture.URL, fixture.REGION,
        DIGEST, len(PAYLOAD), tmp_path/'layer')


@pytest.mark.parametrize('mode,attempts', [('clean', 1), ('recover', 2)])
def test_real_http_recovers_without_changing_owned_bytes(tmp_path, monkeypatch, mode, attempts):
    state = fixture.requests()
    with fixture.LocalFixture(PAYLOAD, prefix=2*1024*1024, mode=mode) as server:
        monkeypatch.setattr(content, 'build_opener', server.opener)
        path = download(tmp_path, state)
    assert path.read_bytes() == PAYLOAD and path.stat().st_mode & 0o777 == 0o600
    assert state.calls == attempts
    assert server.requests == ([None] if mode == 'clean' else [None, 'bytes=2097152-'])
    assert server.bytes_sent == len(PAYLOAD)


@pytest.mark.parametrize('mode', ['ignored_range', 'wrong_start', 'wrong_end', 'wrong_total',
    'wrong_length', 'gzip', 'redirect', 'extra', 'corrupt'])
def test_invalid_resume_never_leaves_scanable_partial_bytes(tmp_path, monkeypatch, mode):
    state = fixture.requests()
    with fixture.LocalFixture(PAYLOAD, prefix=2*1024*1024, mode=mode) as server:
        monkeypatch.setattr(content, 'build_opener', server.opener)
        with pytest.raises(ValueError, match='^image_blob_download_unavailable$') as error:
            download(tmp_path, state)
    assert not (tmp_path/'layer').exists() and state.calls == 2
    assert 'synthetic-canary' not in str(error.value)


@pytest.mark.parametrize('kind', ['bounded_calls', 'zero_progress', 'retry_exhaustion'])
def test_attempt_and_explicit_global_bounds_remain_finite(tmp_path, monkeypatch, kind):
    state = fixture.requests()
    if kind == 'bounded_calls':
        state.max_calls = 100
    mode = 'always_short' if kind == 'retry_exhaustion' else 'recover'
    prefix = 0 if kind == 'zero_progress' else 1024*1024
    with fixture.LocalFixture(PAYLOAD, prefix=prefix, mode=mode) as server:
        monkeypatch.setattr(content, 'build_opener', server.opener)
        with pytest.raises(ValueError, match='^image_blob_download_unavailable$'):
            download(tmp_path, state)
    assert state.calls == (3 if kind == 'retry_exhaustion' else 1)
    assert not (tmp_path/'layer').exists()


@pytest.mark.parametrize('stop', ['cancel', 'deadline'])
def test_stop_after_progress_does_not_start_a_resume(tmp_path, monkeypatch, stop):
    state = fixture.requests()
    stopped = [False]
    clock = [100.0]
    if stop == 'deadline':
        monkeypatch.setattr(native, 'time', SimpleNamespace(monotonic=lambda: clock[0]))
        state.deadline = 101
    else:
        def check():
            if stopped[0]:
                raise RuntimeError('synthetic-canary')
        state.check_deadline = check
    with fixture.LocalFixture(PAYLOAD, prefix=1024*1024) as server:
        def opener(*handlers):
            base = server.opener(*handlers)
            def open(*args, **kwargs):
                response = base.open(*args, **kwargs)
                original = response.read
                def read(count):
                    value = original(count)
                    if value:
                        stopped[0], clock[0] = True, 102
                    return value
                response.read = read
                return response
            return SimpleNamespace(open=open)
        monkeypatch.setattr(content, 'build_opener', opener)
        with pytest.raises(ValueError, match='^image_blob_download_unavailable$'):
            download(tmp_path, state)
    assert state.calls == 1 and not (tmp_path/'layer').exists()


def test_incomplete_read_partial_is_refetched_from_committed_offset(tmp_path, monkeypatch):
    state = fixture.requests()
    calls = []
    class Response:
        def __init__(self, offset):
            self.offset, self.stream, self.reads = offset, io.BytesIO(PAYLOAD[offset:]), 0
            self.status = 206 if offset else 200
            self.headers = {'Content-Length': str(len(PAYLOAD)-offset)}
            if offset:
                self.headers['Content-Range'] = f'bytes {offset}-{len(PAYLOAD)-1}/{len(PAYLOAD)}'
        def geturl(self):
            return fixture.URL
        def read(self, count):
            self.reads += 1
            if not self.offset and self.reads == 2:
                raise IncompleteRead(b'never-committed', 100)
            return self.stream.read(count)
        def __enter__(self):
            return self
        def __exit__(self, *args):
            self.stream.close()
    def open(request, **kwargs):
        offset = 0 if isinstance(request, str) else int(request.get_header('Range')[6:-1])
        calls.append(offset)
        return Response(offset)
    monkeypatch.setattr(content, 'build_opener', lambda *handlers: SimpleNamespace(open=open))
    assert download(tmp_path, state).read_bytes() == PAYLOAD
    assert calls == [0, 1024*1024] and state.calls == 2


def test_existing_file_and_disallowed_endpoint_are_never_changed(tmp_path, monkeypatch):
    tmp_path.chmod(0o700)
    path = tmp_path/'layer'
    path.write_bytes(b'existing')
    monkeypatch.setattr(content, 'build_opener', lambda *a:
        SimpleNamespace(open=lambda *a, **k: pytest.fail('network opened')))
    with pytest.raises(ValueError):
        download(tmp_path, fixture.requests())
    assert path.read_bytes() == b'existing'
    with pytest.raises(ValueError):
        native.download_blob_path(fixture.requests(), 'https://not-allowed.invalid/layer',
            fixture.REGION, DIGEST, len(PAYLOAD), tmp_path/'other')
    assert not (tmp_path/'other').exists()


def test_resume_connection_failure_uses_only_remaining_attempt(tmp_path, monkeypatch):
    state = fixture.requests()
    calls = []
    with fixture.LocalFixture(PAYLOAD, prefix=2*1024*1024) as server:
        def factory(*handlers):
            base = server.opener(*handlers)
            def open(request, **kwargs):
                calls.append(request)
                if len(calls) == 2:
                    raise ConnectionResetError('synthetic-canary')
                return base.open(request, **kwargs)
            return SimpleNamespace(open=open)
        monkeypatch.setattr(content, 'build_opener', factory)
        assert download(tmp_path, state).read_bytes() == PAYLOAD
    assert state.calls == 3 and len(calls) == 3
    assert calls[1].get_header('Range') == calls[2].get_header('Range') == 'bytes=2097152-'
    assert server.requests == [None, 'bytes=2097152-']
