"""Bounded reuse of immutable public artifacts during one live scan process.

Only exact serialized bytes are reused, under the same backend, tenant and scan.
Keep references and digests only; no native payload, secret or rendered text is
retained. New worker processes begin empty, and failed writes are never cached.
"""
from collections import OrderedDict
from contextlib import contextmanager
import hashlib
import json
import threading

from .artifacts import (FileArtifacts, S3Artifacts, check_reference, job_prefix,
                        _file_chunks, _rewound_file, _legacy_text_file)


PUBLIC_KINDS = frozenset({'report', 'markdown', 'manifest', 'findings', 'finding-index',
    'coverage', 'resources', 'least-privilege', 'detail', 'network-snapshot',
    'graph-network', 'graph-iam', 'graph-privesc'})


def _text_digest(value):
    digest = hashlib.sha256()
    for offset in range(0, len(value), 256 * 1024):
        digest.update(value[offset:offset + 256 * 1024].encode())
    return digest.digest()


def _file_digest(source):
    digest = hashlib.sha256()
    with _rewound_file(source):
        for chunk in _file_chunks(source):
            digest.update(chunk)
    return digest.digest()


class ReusableReportArtifacts:
    """Publish through the normal adapter, reusing identical durable objects.

    The reference-only default holds large report working sets (over 2,000
    chunks) without sequential LRU thrashing; payloads remain uncached.
    Own one instance per active worker/scan. Raw checkpoint batches and private
    evidence use the original adapter. The existing backend writes, encryption,
    compression and reference format remain authoritative.
    """
    def __init__(self, artifacts, tenant, ident, *, max_entries=8192):
        job_prefix(tenant, ident)
        self.artifacts, self.tenant, self.ident = artifacts, tenant, ident
        self.max_entries = max(0, int(max_entries))
        self.entries = OrderedDict()
        self.lock = threading.RLock()
        self._active_batch = False

    def __getattr__(self, name):
        if (name == '_put_json_bytes' and isinstance(self.artifacts, S3Artifacts)
                and type(self.artifacts)._put_json_bytes is S3Artifacts._put_json_bytes):
            return self._publish_json_bytes
        return getattr(self.artifacts, name)

    def _publish_json_bytes(self, tenant, ident, kind, body):
        self._scope(tenant, ident)
        if type(body) is not bytes:
            raise TypeError('encoded artifact must be immutable bytes')
        if kind not in PUBLIC_KINDS:
            return self._uncached_writer()._put_json_bytes(tenant, ident, kind, body)
        return self._publish(tenant, ident, kind, body, 'application/json')

    def _uncached_writer(self):
        return self.artifacts

    def _write_body(self, tenant, ident, kind, body, content_type):
        if isinstance(self.artifacts, FileArtifacts):
            return self.artifacts._write(tenant, ident, kind, body)
        return self.artifacts._put(tenant, ident, kind, body, content_type)

    @contextmanager
    def batch(self, **options):
        backend = self.artifacts
        batch = getattr(backend, 'batch', None)
        if not callable(batch):
            yield self
        elif (isinstance(backend, S3Artifacts)
              and type(backend).batch is S3Artifacts.batch
              and type(backend).put is S3Artifacts.put
              and type(backend).put_text is S3Artifacts.put_text
              and type(backend)._put_json_bytes is S3Artifacts._put_json_bytes):
            # Serialize producers/deletion, while the existing bounded pool still
            # overlaps uploads. Pending references are private to this context;
            # promote them only after every upload has completed successfully.
            with self.lock:
                self._check_idle()
                self._active_batch = True
                try:
                    with batch(**options) as writer:
                        cached = _ReusableS3Batch(self, writer)
                        yield cached
                    self.entries = cached.entries
                finally:
                    self._active_batch = False
        else:
            # Preserve custom adapters' publication policy.
            with batch(**options) as writer:
                yield writer

    def _scope(self, tenant, ident):
        if tenant != self.tenant or ident != self.ident:
            raise ValueError('Report artifact reuse belongs to one tenant and scan')

    def _check_idle(self):
        if self._active_batch:
            raise RuntimeError('use the active report artifact batch')

    def _publish(self, tenant, ident, kind, body, content_type):
        self._scope(tenant, ident)
        digest = _text_digest(body) if isinstance(body, str) else hashlib.sha256(body).digest()
        key = kind, content_type, digest
        with self.lock:
            self._check_idle()
            reference = self.entries.get(key)
            if reference is not None:
                check_reference(tenant, reference)
                # Local cleanup can remove an object before this cache dies.
                if not isinstance(self.artifacts, FileArtifacts) or (self.artifacts.root/reference).is_file():
                    self.entries.move_to_end(key)
                    return reference
                del self.entries[key]
            reference = self._write_body(tenant, ident, kind, body, content_type)
            if self.max_entries:
                self.entries[key] = reference
                self.entries.move_to_end(key)
                while len(self.entries) > self.max_entries:
                    self.entries.popitem(last=False)
            return reference

    def put(self, tenant, ident, kind, value):
        self._scope(tenant, ident)
        backend = self.artifacts
        if kind in PUBLIC_KINDS and isinstance(backend, FileArtifacts) and type(backend).put is FileArtifacts.put:
            body = json.dumps(value, separators=(',', ':'), allow_nan=False)
        elif kind in PUBLIC_KINDS and isinstance(backend, S3Artifacts) and type(backend).put is S3Artifacts.put:
            body = json.dumps(value, separators=(',', ':'), ensure_ascii=False, allow_nan=False).encode()
        else:
            return self._uncached_writer().put(tenant, ident, kind, value)
        return self._publish(tenant, ident, kind, body, 'application/json')

    def put_text(self, tenant, ident, kind, value):
        self._scope(tenant, ident)
        backend = self.artifacts
        if kind in PUBLIC_KINDS and isinstance(backend, FileArtifacts) and type(backend).put_text is FileArtifacts.put_text:
            body = value
        elif kind in PUBLIC_KINDS and isinstance(backend, S3Artifacts) and type(backend).put_text is S3Artifacts.put_text:
            body = value.encode()
        else:
            return self._uncached_writer().put_text(tenant, ident, kind, value)
        return self._publish(tenant, ident, kind, body, 'text/markdown')

    def put_text_file(self, tenant, ident, kind, source):
        """Reuse exact whole-file bytes under this adapter's tenant/scan fence.

        Only the digest and durable reference survive. The caller owns the file
        and must keep its contents unchanged until this synchronous call ends.
        Custom adapters retain their own file or legacy string publication path.
        """
        self._scope(tenant, ident)
        backend = self.artifacts
        native_file = (isinstance(backend, FileArtifacts)
            and type(backend).put_text is FileArtifacts.put_text
            and type(backend).put_text_file is FileArtifacts.put_text_file
            and type(backend)._write is FileArtifacts._write)
        native_s3 = (isinstance(backend, S3Artifacts)
            and type(backend).put_text is S3Artifacts.put_text
            and type(backend).put_text_file is S3Artifacts.put_text_file
            and type(backend)._put is S3Artifacts._put
            and type(backend)._put_reserved is S3Artifacts._put_reserved)
        with self.lock:
            self._check_idle()
            writer = self._uncached_writer()

            def commit():
                method = getattr(writer, 'put_text_file', None)
                if callable(method):
                    return method(tenant, ident, kind, source)
                return writer.put_text(tenant, ident, kind, _legacy_text_file(source))

            if kind not in PUBLIC_KINDS or not (native_file or native_s3):
                return commit()
            key = kind, 'text/markdown', _file_digest(source)
            reference = self.entries.get(key)
            if reference is not None:
                check_reference(tenant, reference)
                if not native_file or (backend.root/reference).is_file():
                    self.entries.move_to_end(key)
                    return reference
                del self.entries[key]
            reference = commit()
            if self.max_entries:
                self.entries[key] = reference
                self.entries.move_to_end(key)
                while len(self.entries) > self.max_entries:
                    self.entries.popitem(last=False)
            return reference

    def delete_job(self, tenant, ident):
        self._scope(tenant, ident)
        with self.lock:
            self._check_idle()
            self.artifacts.delete_job(tenant, ident)
            self.entries.clear()

    def delete_workspace(self, tenant):
        if tenant != self.tenant:
            raise ValueError('Report artifact reuse belongs to one tenant')
        with self.lock:
            self._check_idle()
            self.artifacts.delete_workspace(tenant)
            self.entries.clear()


class _ReusableS3Batch(ReusableReportArtifacts):
    """Bounded reference-only staging; the owner retains durable entries only."""
    def __init__(self, owner, writer):
        super().__init__(owner.artifacts, owner.tenant, owner.ident,
                         max_entries=owner.max_entries)
        self.entries = owner.entries.copy()
        self.writer = writer

    def _publish(self, tenant, ident, kind, body, content_type):
        self.writer._check_open()
        if kind == 'manifest':
            # A cached manifest is subject to the same dependency barrier.
            self.writer.flush()
        return super()._publish(tenant, ident, kind, body, content_type)

    def _write_body(self, tenant, ident, kind, body, content_type):
        return self.writer._submit(tenant, ident, kind, body, content_type)

    def _uncached_writer(self):
        return self.writer

    def put_text_file(self, tenant, ident, kind, source):
        self.writer._check_open()
        try:
            self._scope(tenant, ident)
            # Even an exact cache hit must observe failed pending dependencies.
            self.writer.flush()
            return super().put_text_file(tenant, ident, kind, source)
        except BaseException as exc:
            self.writer.error = exc
            raise

    def flush(self):
        self.writer.flush()

    def batch(self, **options):
        raise RuntimeError('report artifact batches cannot be nested')

    def delete_job(self, tenant, ident):
        raise RuntimeError('cannot delete artifacts during publication')

    def delete_workspace(self, tenant):
        raise RuntimeError('cannot delete artifacts during publication')
