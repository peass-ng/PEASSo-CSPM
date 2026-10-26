"""Owned file handles, durable barriers and bounded Markdown artifact copies."""
from concurrent.futures import ThreadPoolExecutor
import gzip
import io
import os
from pathlib import Path
import random
import stat
import threading

import pytest

from peaso.storage import artifacts as module
from peaso.storage.artifacts import FileArtifacts, S3Artifacts, check_reference
from peaso.storage.report_reuse import ReusableReportArtifacts

TENANT, JOB = 'synthetic-owner', 'b' * 32


class BoundedSource(io.BytesIO):
    largest_read = 0

    def read(self, size=-1):
        assert 0 <= size <= 65536, 'Unbounded artifact source read'
        self.largest_read = max(self.largest_read, size)
        return super().read(size)


class Objects:
    def __init__(self):
        self.requests = []
        self.handles = []
        self.fail_kind = None

    def put_object(self, **request):
        if self.fail_kind and '/' + self.fail_kind + '-' in request['Key']:
            raise OSError('synthetic upload failure')
        body = request['Body']
        if isinstance(body, bytes):
            payload = body
        else:
            self.handles.append(body)
            chunks = []
            while True:
                chunk = body.read(65536)
                if not chunk:
                    break
                chunks.append(chunk)
            payload = b''.join(chunks)  # Test transport retains its fixture only.
        self.requests.append(dict(request, Body=payload))

    def get_object(self, Bucket, Key):
        return {'Body': io.BytesIO(next(r['Body'] for r in self.requests if r['Key'] == Key))}

    def head_object(self, Bucket, Key):
        row = next(r for r in self.requests if r['Key'] == Key)
        return {key: row[key] for key in ('ContentLength', 'ContentEncoding', 'Metadata') if key in row}


@pytest.mark.parametrize('kms', [None, 'synthetic-kms'])
@pytest.mark.parametrize('payload,compressed', [
    (b'', False), ('café 😀\n'.encode(), False), (b'x' * 65535, False),
    (b'x' * 65536, True), (random.Random(42).randbytes(100000), False),
])
def test_s3_streams_whole_file_preserving_headers_position_and_downloads(kms, payload, compressed):
    client = Objects()
    backend = S3Artifacts('private', client, kms_key=kms)
    source = BoundedSource(payload)
    source.seek(3)
    reference = backend.put_text_file(TENANT, JOB, 'markdown', source)
    assert source.tell() == 3 and not source.closed
    check_reference(TENANT, reference)
    assert reference.endswith('.md')
    request = client.requests[0]
    assert request['ContentType'] == 'text/markdown'
    assert request['ContentLength'] == len(request['Body'])
    assert request['ServerSideEncryption'] == ('aws:kms' if kms else 'AES256')
    assert request.get('SSEKMSKeyId') == kms
    if compressed:
        assert request['ContentEncoding'] == 'gzip'
        assert request['Metadata'] == {'peaso-uncompressed-bytes': str(len(payload))}
        assert gzip.decompress(request['Body']) == payload
        assert client.handles[-1].closed
    else:
        assert 'ContentEncoding' not in request and 'Metadata' not in request
        assert request['Body'] == payload
        assert client.handles[-1] is source
    assert backend.size(TENANT, reference) == len(payload)
    assert backend._get_bytes(TENANT, reference) == payload
    assert source.largest_read <= 65536


def test_local_atomic_mode_fsync_bounded_reads_and_position(tmp_path, monkeypatch):
    backend = FileArtifacts(tmp_path)
    source = BoundedSource(('é😀' * 30000).encode())
    source.seek(9)
    replaced, synced = [], []
    original_replace, original_fsync = os.replace, os.fsync

    def replace(before, after):
        assert stat.S_IMODE(Path(before).stat().st_mode) == 0o600
        assert not Path(after).exists()
        replaced.append((before, after))
        original_replace(before, after)

    def fsync(fd):
        synced.append(fd)
        return original_fsync(fd)

    monkeypatch.setattr(module.os, 'replace', replace)
    monkeypatch.setattr(module.os, 'fsync', fsync)
    reference = backend.put_text_file(TENANT, JOB, 'markdown', source)
    assert backend.get_text(TENANT, reference) == 'é😀' * 30000
    assert stat.S_IMODE((tmp_path/reference).stat().st_mode) == 0o600
    assert replaced and len(synced) == 2
    assert not list(tmp_path.rglob('*.tmp'))
    assert source.tell() == 9 and not source.closed


def test_local_read_failure_removes_temporary_object_and_restores_source(tmp_path):
    class FailedSource(BoundedSource):
        def read(self, size=-1):
            if self.tell() >= 65536:
                raise OSError('synthetic read failure')
            return super().read(size)

    source = FailedSource(b'x' * 100000)
    source.seek(4)
    with pytest.raises(OSError, match='synthetic read failure'):
        FileArtifacts(tmp_path).put_text_file(TENANT, JOB, 'markdown', source)
    assert source.tell() == 4 and not source.closed
    assert not [p for p in tmp_path.rglob('*') if p.is_file()]


def test_gzip_spool_closes_on_failed_upload_and_source_position_survives(monkeypatch):
    files = []
    original = module.tempfile.TemporaryFile

    def tracked(*args, **kwargs):
        result = original(*args, **kwargs)
        files.append(result)
        return result

    monkeypatch.setattr(module.tempfile, 'TemporaryFile', tracked)
    client = Objects()
    client.fail_kind = 'markdown'
    source = BoundedSource(b'x' * 100000)
    source.seek(7)
    with pytest.raises(OSError, match='synthetic upload failure'):
        S3Artifacts('private', client).put_text_file(TENANT, JOB, 'markdown', source)
    assert files and all(f.closed for f in files)
    assert source.tell() == 7 and not source.closed


@pytest.mark.parametrize('backend_type', [FileArtifacts, S3Artifacts])
def test_text_mode_source_is_rejected_before_commit(backend_type, tmp_path):
    client = Objects()
    backend = FileArtifacts(tmp_path) if backend_type is FileArtifacts else S3Artifacts('private', client)
    source = io.StringIO('synthetic')
    source.seek(2)
    with pytest.raises(TypeError, match='seekable binary file'):
        backend.put_text_file(TENANT, JOB, 'markdown', source)
    assert source.tell() == 2
    assert not client.requests
    assert not [p for p in tmp_path.rglob('*') if p.is_file()]


def test_batch_waits_for_pending_upload_before_stream_and_closes_handle_ownership():
    entered, release = threading.Event(), threading.Event()

    class Gated(Objects):
        def put_object(self, **request):
            if '/resources-' in request['Key']:
                entered.set()
                assert release.wait(5)
            super().put_object(**request)

    client = Gated()
    backend = S3Artifacts('private', client)
    source = BoundedSource(b'complete markdown\n')

    def publish():
        with backend.batch() as writer:
            writer.put(TENANT, JOB, 'resources', {'items': []})
            reference = writer.put_text_file(TENANT, JOB, 'markdown', source)
            writer.put(TENANT, JOB, 'manifest', {'markdown': reference})
        return writer

    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(publish)
        try:
            assert entered.wait(5)
            assert not future.done() and not client.requests
        finally:
            release.set()
        writer = future.result(timeout=5)
    assert ['/resources-' in client.requests[0]['Key'], '/markdown-' in client.requests[1]['Key'],
            '/manifest-' in client.requests[2]['Key']] == [True, True, True]
    with pytest.raises(RuntimeError, match='closed'):
        writer.put_text_file(TENANT, JOB, 'markdown', source)
    assert not source.closed


@pytest.mark.parametrize('failed_kind', ['resources', 'markdown'])
def test_batch_stream_failure_is_sticky_even_if_caught(failed_kind):
    client = Objects()
    client.fail_kind = failed_kind
    backend = S3Artifacts('private', client)
    source = BoundedSource(b'markdown')
    with pytest.raises(OSError, match='synthetic upload failure'):
        with backend.batch() as writer:
            if failed_kind == 'resources':
                writer.put(TENANT, JOB, 'resources', {'items': []})
            with pytest.raises(OSError, match='synthetic upload failure'):
                writer.put_text_file(TENANT, JOB, 'markdown', source)
            writer.put(TENANT, JOB, 'manifest', {'must_not_commit': True})
    assert not any('/manifest-' in row['Key'] for row in client.requests)


def test_exact_stream_reuse_composes_with_text_calls_and_missing_local_object(tmp_path):
    cached = ReusableReportArtifacts(FileArtifacts(tmp_path), TENANT, JOB)
    payload = 'Exact café 😀\n'
    first = cached.put_text_file(TENANT, JOB, 'markdown', BoundedSource(payload.encode()))
    assert cached.put_text(TENANT, JOB, 'markdown', payload) == first
    assert cached.put_text_file(TENANT, JOB, 'markdown', BoundedSource(payload.encode())) == first
    (tmp_path/first).unlink()
    retry = cached.put_text_file(TENANT, JOB, 'markdown', BoundedSource(payload.encode()))
    assert retry != first and cached.get_text(TENANT, retry) == payload
    assert all(isinstance(key[2], bytes) and len(key[2]) == 32 and isinstance(value, str)
               for key, value in cached.entries.items())


def test_stream_reuse_scope_fence_precedes_read_and_active_batch_cannot_be_bypassed():
    cached = ReusableReportArtifacts(S3Artifacts('private', Objects()), TENANT, JOB)

    class NoRead(io.BytesIO):
        def read(self, size=-1):
            raise AssertionError('Unauthorized read')

    with pytest.raises(ValueError):
        cached.put_text_file('another-tenant', JOB, 'markdown', NoRead())
    with pytest.raises(ValueError):
        cached.put_text_file(TENANT, 'c' * 32, 'markdown', NoRead())
    with cached.batch() as writer:
        with pytest.raises(RuntimeError, match='active report artifact batch'):
            cached.put_text_file(TENANT, JOB, 'markdown', NoRead())
        reference = writer.put_text_file(TENANT, JOB, 'markdown', BoundedSource(b'durable'))
        assert not cached.entries
    assert cached.put_text_file(TENANT, JOB, 'markdown', BoundedSource(b'durable')) == reference
    with pytest.raises(RuntimeError, match='closed'):
        writer.put_text_file(TENANT, JOB, 'markdown', NoRead())


def test_failed_reuse_batch_does_not_promote_synchronous_stream_reference():
    client = Objects()
    cached = ReusableReportArtifacts(S3Artifacts('private', client), TENANT, JOB)
    with pytest.raises(OSError):
        with cached.batch() as writer:
            reference = writer.put_text_file(TENANT, JOB, 'markdown', BoundedSource(b'durable'))
            client.fail_kind = 'manifest'
            writer.put(TENANT, JOB, 'manifest', {'markdown': reference})
    assert not cached.entries
    client.fail_kind = None
    retry = cached.put_text_file(TENANT, JOB, 'markdown', BoundedSource(b'durable'))
    assert retry != reference


def test_reused_stream_reference_still_waits_for_failed_new_dependency():
    client = Objects()
    cached = ReusableReportArtifacts(S3Artifacts('private', client), TENANT, JOB)
    cached.put_text_file(TENANT, JOB, 'markdown', BoundedSource(b'cached'))
    before = cached.entries.copy()
    client.fail_kind = 'resources'
    with pytest.raises(OSError):
        with cached.batch() as writer:
            writer.put(TENANT, JOB, 'resources', {'new': True})
            writer.put_text_file(TENANT, JOB, 'markdown', BoundedSource(b'cached'))
    assert cached.entries == before and len(client.requests) == 1


def test_custom_string_and_file_adapters_keep_their_publication_policy(tmp_path):
    class CustomFile(FileArtifacts):
        def put_text(self, tenant, job, kind, value):
            return super().put_text(tenant, job, kind, 'custom:' + value)

    class CustomS3(S3Artifacts):
        def put_text(self, tenant, job, kind, value):
            return super().put_text(tenant, job, kind, 'custom:' + value)

    for backend in (CustomFile(tmp_path), CustomS3('private', Objects())):
        cached = ReusableReportArtifacts(backend, TENANT, JOB)
        ref = cached.put_text_file(TENANT, JOB, 'markdown', BoundedSource('é😀'.encode()))
        assert backend.get_text(TENANT, ref) == 'custom:é😀'
        assert not cached.entries

    class CustomStream:
        def put_text_file(self, tenant, ident, kind, source):
            assert source.read(2) == b'ok'
            return 'custom-stream-reference'

    assert ReusableReportArtifacts(CustomStream(), TENANT, JOB).put_text_file(
        TENANT, JOB, 'markdown', BoundedSource(b'ok')) == 'custom-stream-reference'


def test_local_replace_failure_cleans_temp_without_committing_reference(tmp_path, monkeypatch):
    def fail(*args):
        raise OSError('synthetic atomic replace failure')

    monkeypatch.setattr(module.os, 'replace', fail)
    source = BoundedSource(b'synthetic')
    with pytest.raises(OSError, match='atomic replace failure'):
        FileArtifacts(tmp_path).put_text_file(TENANT, JOB, 'markdown', source)
    assert not [p for p in tmp_path.rglob('*') if p.is_file()]
    assert source.tell() == 0 and not source.closed


def test_failed_direct_stream_write_is_not_cached_and_retry_commits():
    client = Objects()
    cached = ReusableReportArtifacts(S3Artifacts('private', client), TENANT, JOB)
    client.fail_kind = 'markdown'
    with pytest.raises(OSError):
        cached.put_text_file(TENANT, JOB, 'markdown', BoundedSource(b'synthetic'))
    assert not cached.entries
    client.fail_kind = None
    reference = cached.put_text_file(TENANT, JOB, 'markdown', BoundedSource(b'synthetic'))
    assert cached.get_text(TENANT, reference) == 'synthetic'


def test_failed_batch_digest_is_sticky_and_never_publishes_manifest():
    class FailedSource(BoundedSource):
        def read(self, size=-1):
            if size:
                raise OSError('synthetic digest failure')
            return super().read(size)

    client = Objects()
    cached = ReusableReportArtifacts(S3Artifacts('private', client), TENANT, JOB)
    with pytest.raises(OSError, match='digest failure'):
        with cached.batch() as writer:
            with pytest.raises(OSError, match='digest failure'):
                writer.put_text_file(TENANT, JOB, 'markdown', FailedSource(b'data'))
            writer.put(TENANT, JOB, 'manifest', {})
    assert not cached.entries and not client.requests


def test_custom_legacy_adapter_without_file_method_and_reuse_lru(tmp_path):
    class Legacy:
        def put_text(self, tenant, ident, kind, text):
            assert text == 'é' * 40000
            return 'legacy-reference'

    source = BoundedSource(('é' * 40000).encode())
    source.seek(11)
    assert ReusableReportArtifacts(Legacy(), TENANT, JOB).put_text_file(
        TENANT, JOB, 'markdown', source) == 'legacy-reference'
    assert source.tell() == 11
    cached = ReusableReportArtifacts(FileArtifacts(tmp_path), TENANT, JOB, max_entries=1)
    first = cached.put_text_file(TENANT, JOB, 'markdown', BoundedSource(b'one'))
    cached.put_text_file(TENANT, JOB, 'markdown', BoundedSource(b'two'))
    assert len(cached.entries) == 1
    assert cached.put_text_file(TENANT, JOB, 'markdown', BoundedSource(b'one')) != first
