"""Private artifact storage interfaces. References are generated, never paths from HTTP."""
import hashlib
import gzip
import codecs
import io
import json
import os
import shutil
from pathlib import Path
import re
import uuid
import tempfile
from contextlib import contextmanager
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from typing import Protocol
from peaso.runtime_metrics import span as _runtime_span, add_bytes as _runtime_bytes
from peaso.gc_pause import gc_paused


_FILE_COPY_BYTES = 64 * 1024


@contextmanager
def _rewound_file(source):
    """Borrow a seekable binary file without changing its owner's position."""
    position = source.tell()
    try:
        source.seek(0)
        if type(source.read(0)) is not bytes:
            raise TypeError("artifact source must be a seekable binary file")
        yield source
    finally:
        source.seek(position)


def _file_chunks(source):
    while True:
        chunk = source.read(_FILE_COPY_BYTES)
        if type(chunk) is not bytes:
            raise TypeError("artifact source must be a seekable binary file")
        if not chunk:
            return
        yield chunk


def _legacy_text_file(source):
    """Compatibility for custom adapters that still own string serialization."""
    decoder = codecs.getincrementaldecoder("utf-8")()
    with _rewound_file(source), io.StringIO() as text:
        for chunk in _file_chunks(source):
            text.write(decoder.decode(chunk))
        text.write(decoder.decode(b"", final=True))
        return text.getvalue()


def _loads(body):
    # Decoding builds only acyclic containers; skip cyclic GC heap rescans.
    with gc_paused():
        return json.loads(body)


class ArtifactStore(Protocol):
    def put(self, tenant: str, job_id: str, kind: str, value: dict) -> str: ...
    def get(self, tenant: str, reference: str) -> dict: ...


def prefix(tenant):
    return hashlib.sha256(tenant.encode()).hexdigest()


def check_reference(tenant, reference):
    if not re.fullmatch(r"[a-f0-9]{64}/[a-f0-9]{32}/(snapshot|network-snapshot|report|manifest|findings|finding-index|coverage|graph-network|graph-iam|graph-privesc|markdown|detail|resources|least-privilege|ai-access|ai-review|secret-evidence)-[a-f0-9]{32}\.(json|md)", reference) or not reference.startswith(prefix(tenant) + "/"):
        raise ValueError("Invalid artifact reference")


def reference_for(tenant, job_id, kind):
    reference = f"{prefix(tenant)}/{job_id}/{kind}-{uuid.uuid4().hex}.{'md' if kind == 'markdown' else 'json'}"
    check_reference(tenant, reference)
    return reference


def job_prefix(tenant, job_id):
    if not isinstance(job_id, str) or not re.fullmatch(r"[a-f0-9]{32}", job_id):
        raise ValueError("Invalid scan ID")
    return f"{prefix(tenant)}/{job_id}/"


class FileArtifacts:
    def __init__(self, root: Path):
        self.root = root
        root.mkdir(parents=True, exist_ok=True, mode=0o700)

    def delete_workspace(self, tenant):
        directory = self.root / prefix(tenant)
        if directory.parent.resolve() != self.root.resolve() or directory.is_symlink():
            raise ValueError("Invalid artifact directory")
        if directory.exists():
            shutil.rmtree(directory)

    def delete_job(self, tenant, job_id):
        directory = self.root / job_prefix(tenant, job_id)
        expected_parent = self.root.resolve() / prefix(tenant)
        if directory.parent.resolve() != expected_parent or directory.is_symlink():
            raise ValueError("Invalid artifact directory")
        if directory.exists():
            shutil.rmtree(directory)

    def put(self, tenant, job_id, kind, value):
        with _runtime_span("artifact.serialize"):
            body = json.dumps(value, separators=(",", ":"), allow_nan=False)
        return self._write(tenant, job_id, kind, body)

    def put_secret_evidence(self, tenant, job_id, value):
        from peaso.secret_evidence import private_reference
        with _runtime_span("artifact.serialize"):
            body = json.dumps(value, separators=(',', ':'))
        return self._write(tenant, job_id, 'secret-evidence', body,
                           reference=private_reference(tenant, job_id))

    def put_text(self, tenant, job_id, kind, value):
        return self._write(tenant, job_id, kind, value)

    def put_text_file(self, tenant, job_id, kind, source):
        """Commit all source bytes atomically; borrow, never close, its handle.

        The caller must keep the source unchanged for this synchronous call.
        Custom string writers retain their existing publication policy.
        """
        if (type(self).put_text is not FileArtifacts.put_text
                or type(self)._write is not FileArtifacts._write):
            return self.put_text(tenant, job_id, kind, _legacy_text_file(source))
        reference = reference_for(tenant, job_id, kind)
        path = self.root / reference
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        temp = path.with_name(path.name + "." + uuid.uuid4().hex + ".tmp")
        with _runtime_span("artifact.file.write"), _rewound_file(source):
            try:
                fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(fd, "wb") as stream:
                    for chunk in _file_chunks(source):
                        stream.write(chunk)
                    stream.flush()
                    _runtime_bytes("artifact.file.write", stream.tell())
                    os.fsync(stream.fileno())
                os.replace(temp, path)
                directory = os.open(path.parent, os.O_RDONLY)
                try:
                    os.fsync(directory)
                finally:
                    os.close(directory)
            finally:
                temp.unlink(missing_ok=True)
        return reference

    def _write(self, tenant, job_id, kind, value, *, reference=None):
        reference = reference or reference_for(tenant, job_id, kind)
        check_reference(tenant, reference)
        path = self.root / reference
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        # A killed writer may leave its temp file behind. A fresh name lets
        # a reclaimed scan replace the same private artifact safely.
        temp = path.with_name(path.name + "." + uuid.uuid4().hex + ".tmp")
        with _runtime_span("artifact.file.write"):
            try:
                fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(fd, "w") as stream:
                    stream.write(value)
                    stream.flush()
                    _runtime_bytes("artifact.file.write", stream.buffer.tell())
                    os.fsync(stream.fileno())
                os.replace(temp, path)
                directory = os.open(path.parent, os.O_RDONLY)
                try:
                    os.fsync(directory)
                finally:
                    os.close(directory)
            finally:
                temp.unlink(missing_ok=True)
        return reference

    def get(self, tenant, reference):
        check_reference(tenant, reference)
        return _loads((self.root / reference).read_text())

    def get_text(self, tenant, reference):
        check_reference(tenant, reference)
        return (self.root / reference).read_text()

    def size(self, tenant, reference):
        check_reference(tenant, reference)
        return (self.root / reference).stat().st_size


class S3Artifacts:
    """Optional hosted artifact adapter; bucket policy must block public access."""
    def __init__(self, bucket, client=None, kms_key=None):
        if client is None:
            import boto3
            client = boto3.client("s3")
        self.client, self.bucket, self.kms_key = client, bucket, kms_key

    def delete_job(self, tenant, job_id):
        # The bucket is private and unversioned. Never enumerate another scan.
        self._delete_prefix("artifacts/" + job_prefix(tenant, job_id))

    def delete_workspace(self, tenant):
        self._delete_prefix("artifacts/" + prefix(tenant) + "/")

    def _delete_prefix(self, target):
        paginator = self.client.get_paginator("list_objects_v2")
        for page in paginator.paginate(Bucket=self.bucket, Prefix=target):
            keys = [item["Key"] for item in page.get("Contents", [])]
            if any(not key.startswith(target) for key in keys):
                raise ValueError("Artifact listing escaped scan prefix")
            for start in range(0, len(keys), 1000):
                result = self.client.delete_objects(Bucket=self.bucket, Delete={
                    "Objects": [{"Key": key} for key in keys[start:start + 1000]], "Quiet": True})
                if result.get("Errors"):
                    raise RuntimeError("Some scan artifacts could not be deleted; retry")

    def put(self, tenant, job_id, kind, value):
        with _runtime_span("artifact.serialize"):
            body = json.dumps(value, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode()
            _runtime_bytes("artifact.serialize", len(body))
        return self._put(tenant, job_id, kind, body, "application/json")

    def put_secret_evidence(self, tenant, job_id, value):
        from peaso.secret_evidence import private_reference
        with _runtime_span("artifact.serialize"):
            body = json.dumps(value, separators=(',', ':')).encode()
            _runtime_bytes("artifact.serialize", len(body))
        return self._put(tenant, job_id, 'secret-evidence', body, 'application/json',
                         reference=private_reference(tenant, job_id))

    def _put_json_bytes(self, tenant, job_id, kind, body):
        """Internal report serializer seam; retain the ordinary upload policy."""
        if type(body) is not bytes:
            raise TypeError("encoded artifact must be immutable bytes")
        return self._put(tenant, job_id, kind, body, "application/json")

    def _put(self, tenant, job_id, kind, body, content_type, *, reference=None):
        reference = reference or reference_for(tenant, job_id, kind)
        self._put_reserved(tenant, reference, body, content_type)
        return reference

    def _put_reserved(self, tenant, reference, body, content_type):
        check_reference(tenant, reference)
        encryption = {"ServerSideEncryption": "aws:kms", "SSEKMSKeyId": self.kms_key} if self.kms_key else {"ServerSideEncryption": "AES256"}
        encoding = {}
        if len(body) >= 64 * 1024:
            with _runtime_span("artifact.compress"):
                compressed = gzip.compress(body, compresslevel=1, mtime=0)
                _runtime_bytes("artifact.compress", len(body))
            if len(compressed) < len(body):
                encoding = {"ContentEncoding": "gzip", "Metadata": {"peaso-uncompressed-bytes": str(len(body))}}
                body = compressed
        with _runtime_span("artifact.s3.put"):
            self.client.put_object(Bucket=self.bucket, Key="artifacts/" + reference, Body=body, ContentType=content_type, **encoding, **encryption)
            _runtime_bytes("artifact.s3.put", len(body))

    def batch(self, *, workers=4, max_pending_bytes=16 * 1024 * 1024):
        """Bounded uploads; a manifest is written only after all prior writes succeed."""
        return _S3WriteBatch(self, workers, max_pending_bytes)

    def _get_bytes(self, tenant, reference):
        check_reference(tenant, reference)
        body = self.client.get_object(Bucket=self.bucket, Key="artifacts/" + reference)["Body"].read()
        # Also recognize the standard gzip signature for older clients/proxies
        # that omit encoding metadata. Plain JSON/UTF-8 Markdown cannot have it.
        return gzip.decompress(body) if body.startswith(b"\x1f\x8b") else body

    def get(self, tenant, reference):
        return _loads(self._get_bytes(tenant, reference))

    def put_text(self, tenant, job_id, kind, value):
        with _runtime_span("artifact.serialize"):
            body = value.encode()
            _runtime_bytes("artifact.serialize", len(body))
        return self._put(tenant, job_id, kind, body, "text/markdown")

    def put_text_file(self, tenant, job_id, kind, source):
        """Synchronously upload a borrowed seekable file with bounded gzip I/O."""
        if (type(self).put_text is not S3Artifacts.put_text
                or type(self)._put is not S3Artifacts._put
                or type(self)._put_reserved is not S3Artifacts._put_reserved):
            return self.put_text(tenant, job_id, kind, _legacy_text_file(source))
        reference = reference_for(tenant, job_id, kind)
        encryption = ({"ServerSideEncryption": "aws:kms", "SSEKMSKeyId": self.kms_key}
                      if self.kms_key else {"ServerSideEncryption": "AES256"})
        with _rewound_file(source):
            source.seek(0, os.SEEK_END)
            size = source.tell()
            source.seek(0)
            # The compressed candidate stays on disk even when incompressible.
            with tempfile.TemporaryFile(mode="w+b") as compressed:
                body, length, encoding = source, size, {}
                if size >= _FILE_COPY_BYTES:
                    with _runtime_span("artifact.compress"):
                        with gzip.GzipFile(filename="", fileobj=compressed, mode="wb",
                                           compresslevel=1, mtime=0) as writer:
                            for chunk in _file_chunks(source):
                                writer.write(chunk)
                        _runtime_bytes("artifact.compress", size)
                    candidate_size = compressed.tell()
                    source.seek(0)
                    if candidate_size < size:
                        compressed.seek(0)
                        body, length = compressed, candidate_size
                        encoding = {"ContentEncoding": "gzip",
                                    "Metadata": {"peaso-uncompressed-bytes": str(size)}}
                with _runtime_span("artifact.s3.put"):
                    self.client.put_object(Bucket=self.bucket, Key="artifacts/" + reference,
                        Body=body, ContentLength=length, ContentType="text/markdown",
                        **encoding, **encryption)
                    _runtime_bytes("artifact.s3.put", length)
        return reference

    def get_text(self, tenant, reference):
        return self._get_bytes(tenant, reference).decode()

    def size(self, tenant, reference):
        check_reference(tenant, reference)
        header = self.client.head_object(Bucket=self.bucket, Key="artifacts/" + reference)
        if header.get("ContentEncoding") == "gzip":
            size = header.get("Metadata", {}).get("peaso-uncompressed-bytes", "")
            # Never mistake a small compressed object for a small response. An
            # older compressed artifact without size metadata stays non-inline.
            return int(size) if size.isdigit() else 2**63 - 1
        return header["ContentLength"]

    def presign(self, tenant, reference, filename=None):
        check_reference(tenant, reference)
        if '/secret-evidence-' in reference:
            raise ValueError('Private secret evidence cannot be downloaded directly')
        arguments = {"Bucket": self.bucket, "Key": "artifacts/" + reference}
        if filename:
            if not re.fullmatch(r"(?:peaso|hacktricks-cspm)-[a-f0-9]{32}\.(json|md)", filename):
                raise ValueError("Invalid download filename")
            arguments["ResponseContentDisposition"] = f'attachment; filename="{filename}"'
        return self.client.generate_presigned_url("get_object", Params=arguments, ExpiresIn=300)


class _S3WriteBatch:
    """Reserve ordinary references in producer order, then overlap independent I/O.

    Serialize on the caller so later mutations cannot change queued artifacts.
    Only encoded bytes enter the bounded queue. Upload workers never wait on
    other workers: referenced artifacts are committed before the manifest.
    """
    def __init__(self, artifacts, workers, max_pending_bytes):
        if type(workers) is not int or not 1 <= workers <= 16:
            raise ValueError("artifact workers must be an integer between 1 and 16")
        if type(max_pending_bytes) is not int or max_pending_bytes < 1:
            raise ValueError("artifact pending bytes must be a positive integer")
        self.artifacts = artifacts
        self.max_pending = workers * 2
        self.max_pending_bytes = max_pending_bytes
        self.pending, self.pending_bytes = {}, 0
        self.error = None
        self.closed = False
        self.pool = ThreadPoolExecutor(max_workers=workers, thread_name_prefix="peaso-artifact")

    def __enter__(self):
        self._check_open()
        return self

    def _check_open(self):
        if self.closed:
            raise RuntimeError("artifact batch is closed")
        if self.error is not None:
            raise self.error

    def _drain(self):
        with _runtime_span("artifact.batch.wait"):
            completed, _ = wait(self.pending, return_when=FIRST_COMPLETED)
            for future in completed:
                self.pending_bytes -= self.pending.pop(future)
                try:
                    future.result()
                except BaseException as exc:
                    self.error = exc
                    raise

    def flush(self):
        self._check_open()
        while self.pending:
            self._drain()

    def _submit(self, tenant, job_id, kind, body, content_type):
        self._check_open()
        reference = reference_for(tenant, job_id, kind)
        if kind == "manifest" or len(body) > self.max_pending_bytes:
            self.flush()
            try:
                self.artifacts._put_reserved(tenant, reference, body, content_type)
            except BaseException as exc:
                self.error = exc
                raise
            return reference
        # Oversized artifacts were committed synchronously above, so queued
        # immutable bodies remain within the pending-byte budget.
        while self.pending and (len(self.pending) >= self.max_pending or
                               self.pending_bytes + len(body) > self.max_pending_bytes):
            self._drain()
        try:
            future = self.pool.submit(self.artifacts._put_reserved, tenant, reference, body, content_type)
        except BaseException as exc:
            self.error = exc
            raise
        self.pending[future] = len(body)
        self.pending_bytes += len(body)
        return reference

    def put(self, tenant, job_id, kind, value):
        with _runtime_span("artifact.serialize"):
            body = json.dumps(value, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode()
            _runtime_bytes("artifact.serialize", len(body))
        return self._submit(tenant, job_id, kind, body, "application/json")

    def _put_json_bytes(self, tenant, job_id, kind, body):
        if type(body) is not bytes:
            raise TypeError("encoded artifact must be immutable bytes")
        return self._submit(tenant, job_id, kind, body, "application/json")

    def put_text(self, tenant, job_id, kind, value):
        with _runtime_span("artifact.serialize"):
            body = value.encode()
            _runtime_bytes("artifact.serialize", len(body))
        return self._submit(tenant, job_id, kind, body, "text/markdown")

    def put_text_file(self, tenant, job_id, kind, source):
        self._check_open()
        try:
            # Never retain a caller-owned file in the asynchronous byte pool.
            self.flush()
            return self.artifacts.put_text_file(tenant, job_id, kind, source)
        except BaseException as exc:
            self.error = exc
            raise

    def __exit__(self, exc_type, exc, traceback):
        try:
            if exc_type is None:
                self.flush()
        finally:
            self.closed = True
            try:
                with _runtime_span("artifact.batch.wait"):
                    self.pool.shutdown(wait=True, cancel_futures=True)
            finally:
                self.pending.clear()
                self.pending_bytes = 0
                self.error = None
