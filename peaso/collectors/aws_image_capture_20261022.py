"""One bounded private payload capture per exact ECR image during dispatch.

Only paths live here; public request Futures still contain safe projections.
The collector must enclose all consumers (and their executor shutdown) in scope.
Without that owner, existing independently owned temporary downloads apply.
"""
from contextlib import contextmanager
import os
from pathlib import Path
import re
import shutil
import stat
import tempfile
import threading
import time

MAX_CAPTURE_BYTES = 16 * 1024 * 1024 * 1024
MAX_CAPTURE_BLOBS = 32768
FREE_RESERVE_BYTES = 512 * 1024 * 1024
# Private ECR payload scratch. Each directory name carries its owning process
# id, so a later scan can remove what a killed (SIGKILL/OOM) scan left behind.
SCRATCH_PREFIXES = ('peaso-ecr-capture-', 'peaso-ecr-secret-')
_OWNED = re.compile(r'(?:' + '|'.join(map(re.escape, SCRATCH_PREFIXES)) + r')([0-9]+)-[^/]+')
_LEGACY = re.compile(r'(?:' + '|'.join(map(re.escape, SCRATCH_PREFIXES)) + r')[^/]+')
LEGACY_STALE_SECONDS = 24 * 3600


def scratch_directory(prefix):
    """A private TemporaryDirectory whose name records this process as owner."""
    if prefix not in SCRATCH_PREFIXES:
        raise ValueError('unknown ECR scratch prefix')
    return tempfile.TemporaryDirectory(prefix=f'{prefix}{os.getpid()}-')


def _alive(pid):
    if pid == os.getpid():
        return True
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except OSError:
        return True  # Exists but belongs to someone else: never touch it.
    return True


def sweep_stale_scratch(root=None):
    """Remove ECR scratch directories whose owning process no longer exists.

    Only this user's real directories are considered. Directories from older
    releases (no owner id in the name) are removed once a day old.
    """
    root = Path(root or tempfile.gettempdir())
    removed = 0
    try:
        names = os.listdir(root)
    except OSError:
        return removed
    now = time.time()
    for name in names:
        owned = _OWNED.fullmatch(name)
        if owned is None and _LEGACY.fullmatch(name) is None:
            continue
        path = root / name
        try:
            info = os.lstat(path)
        except OSError:
            continue
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid():
            continue
        stale = (not _alive(int(owned.group(1))) if owned is not None
                 else now - info.st_mtime > LEGACY_STALE_SECONDS)
        if stale:
            shutil.rmtree(path, ignore_errors=True)
            removed += not path.exists()
    return removed


@contextmanager
def owned_scratch(prefix):
    """Yield a scratch path that is removed on every exit, cleanup races included."""
    temporary = scratch_directory(prefix)
    try:
        yield temporary.name
    finally:
        remove_scratch(temporary)


def remove_scratch(temporary):
    """Remove a scratch directory; retry once past late writers, then report."""
    try:
        temporary.cleanup()
    except Exception:
        shutil.rmtree(temporary.name, ignore_errors=True)
        if os.path.lexists(temporary.name):
            raise


def _authority(session):
    # Only the reviewed wrapper delegates authority to its original session.
    from .aws_workload_image_secret_native_20261021 import _PinnedSession
    return session.session if type(session) is _PinnedSession else session


class CaptureUnavailable(ValueError):
    def __init__(self, code=None):
        super().__init__('image_capture_unavailable')
        self.code = code


class _Capture:
    def __init__(self):
        try:
            sweep_stale_scratch()
        except Exception:
            pass  # Housekeeping never blocks a scan.
        self.temporary = scratch_directory('peaso-ecr-capture-')
        self.root = Path(self.temporary.name)
        # Leave at least half the currently available scratch for archive
        # construction and scanners; 16 GiB is a ceiling, never a reservation.
        try:
            self.capacity = min(MAX_CAPTURE_BYTES, max(0,
                (shutil.disk_usage(self.root).free - FREE_RESERVE_BYTES) // 2))
        except Exception:
            remove_scratch(self.temporary)
            raise
        self.lock = threading.Lock()
        self.entries, self.sessions, self.reserved = {}, [], 0
        self.closed = False

    def blob(self, requests, session, account, region, repo, image_digest, digest, size, load,
             *, check=None):
        check = check or requests.check_deadline
        check()
        authority = _authority(session)
        # A blob is content-addressed within its repository: every image of
        # the repository whose (independently authorized) manifest lists this
        # digest and size reads the same bytes. Keying by image as well would
        # let two images fetch one layer concurrently, and the scan-wide request
        # cache joins those reads into one provider call that fills only the
        # first image's file.
        key = (id(authority), account, region, repo, digest)
        with self.lock:
            if self.closed:
                raise ValueError('image_capture_closed')
            entry = self.entries.get(key)
            owner = entry is None
            if owner:
                if (type(size) is not int or size <= 0 or
                        self.reserved + size > self.capacity or
                        len(self.entries) >= MAX_CAPTURE_BLOBS):
                    raise ValueError('image_capture_bound')
                self.sessions.append(authority)  # Prevent session id recycling.
                self.reserved += size
                entry = self.entries[key] = {
                    'ready': threading.Event(), 'size': size, 'ok': False,
                    'path': self.root / ('blob-' + str(len(self.entries)))}
            elif entry['size'] != size:
                raise ValueError('image_capture_descriptor_changed')
        if owner:
            try:
                try:
                    load(entry['path'])
                except Exception as exc:
                    # Waiters report the owner's failure kind (for example a
                    # layer download failure), never its message.
                    code = getattr(exc, 'code', None)
                    entry['code'] = code if type(code) is str else None
                    raise
                if not entry['path'].is_file() or entry['path'].stat().st_size != size:
                    raise ValueError('image_capture_incomplete')
                entry['ok'] = True
            finally:
                try:
                    if not entry['ok']:
                        entry['path'].unlink(missing_ok=True)
                finally:
                    entry['ready'].set()
        else:
            while not entry['ready'].wait(0.1):
                check()
        check()
        requests.check_deadline()
        if not entry['ok']:
            raise CaptureUnavailable(entry.get('code'))
        return entry['path']

    def close(self):
        with self.lock:
            self.closed = True
        try:
            remove_scratch(self.temporary)
        finally:
            self.entries.clear()
            self.sessions.clear()


@contextmanager
def capture_scope(requests):
    """Own private files until every dispatched consumer has stopped.

    Enter before the executor contexts so executor shutdown precedes cleanup.
    Cleanup errors propagate; a collector must not claim complete capture then.
    """
    with requests._lock:
        if getattr(requests, '_ecr_image_capture', None) is not None:
            raise ValueError('image_capture_already_owned')
        capture = _Capture()
        requests._ecr_image_capture = capture
    try:
        yield capture
    finally:
        try:
            capture.close()
        finally:
            with requests._lock:
                del requests._ecr_image_capture


def shared_blob(requests, session, account, region, repo, image_digest,
                digest, size, load, fallback, *, check=None):
    """Reuse only after the caller independently authorized its exact manifest."""
    capture = getattr(requests, '_ecr_image_capture', None)
    if capture is None:
        return load(fallback)
    return capture.blob(requests, session, account, region, repo,
                        image_digest, digest, size, load, check=check)
