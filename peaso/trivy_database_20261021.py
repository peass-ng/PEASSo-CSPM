"""Explicit, bounded provisioning and offline admission for the Trivy vulnerability DB.

The collector must run ``check`` before an offline vulnerability scan and use
``--cache-dir <root>/current --skip-db-update --offline-scan``. A failed check is
unavailable evidence, never a clean vulnerability result.
"""

from __future__ import annotations

import argparse
from contextlib import contextmanager, ExitStack
from contextvars import ContextVar
from functools import wraps
import fcntl
import datetime as dt
import json
import os
from pathlib import Path
import resource
import signal
import struct
import shutil
import subprocess
import sys
import tempfile
import time
import uuid


UTC = dt.timezone.utc
MAX_AGE = dt.timedelta(hours=24)
MAX_CACHE_BYTES = 4 * 1024**3
FREE_RESERVE_BYTES = 512 * 1024**2
DOWNLOAD_TIMEOUT_SECONDS = 660
DOWNLOAD_POLL_SECONDS = 0.1
MAX_STAGING_ENTRIES = 64
DB_REPOSITORY = "ghcr.io/aquasecurity/trivy-db:2"


class DatabaseUnavailable(RuntimeError):
    pass


# Only fixed classifications and bounded numeric aggregates leave this module.
# The context is private to this acquisition and is never derived from options.
_DIAGNOSTICS = ContextVar("trivy_database_diagnostics", default=None)
_REASONS = {
    "DB timestamp missing": "timestamp_missing",
    "DB timestamp invalid": "timestamp_invalid",
    "DB timestamp has no timezone": "timestamp_timezone_missing",
    "DB files missing or linked": "files_missing_or_linked",
    "DB size is outside provisioning bounds": "database_size_limit",
    "DB meta page is truncated": "database_header_truncated",
    "DB bbolt meta page is invalid": "database_header_invalid",
    "DB metadata size is outside provisioning bounds": "metadata_size_limit",
    "DB files unreadable or metadata invalid": "metadata_unreadable_or_invalid",
    "DB schema is not version 2": "schema_unsupported",
    "DB is older than 24 hours or future dated": "database_stale_or_future",
    "DB NextUpdate has passed": "database_expired",
    "download staging contains excessive or linked entries": "staging_entries_or_links",
    "download exceeded cache size limit": "download_size_limit",
    "download staging contains an unsupported entry": "staging_entry_unsupported",
    "download exhausted reserved disk headroom": "download_disk_reserve",
    "cache root must not be linked": "cache_root_linked",
    "generation directory must not be linked": "generations_linked",
    "insufficient free disk for bounded DB refresh": "refresh_disk_headroom",
    "current DB pointer missing": "cache_pointer_missing",
    "current DB pointer escapes generation directory": "cache_pointer_escaped",
    "DB cache is busy": "lease_busy",
    "fresh_offline_database_required": "offline_database_not_fresh",
}
_PHASES = frozenset({"lease_acquisition", "cache_validation", "refresh",
                     "download", "database_validation", "offline_validation"})


def _classification(exc):
    if exc is None:
        return "ok", None
    if isinstance(exc, subprocess.TimeoutExpired):
        return "download_timeout", None
    if isinstance(exc, subprocess.CalledProcessError):
        code = exc.returncode
        return "download_process_failed", code if type(code) is int and -255 <= code <= 255 else None
    if isinstance(exc, FileNotFoundError):
        return "file_or_executable_missing", None
    if isinstance(exc, PermissionError):
        return "filesystem_permission_denied", None
    if isinstance(exc, DatabaseUnavailable):
        # Never stringify a foreign exception or emit an unrecognized message.
        message = exc.args[0] if exc.args and type(exc.args[0]) is str else None
        return _REASONS.get(message, "database_unavailable"), None
    if type(exc) is ValueError and exc.args == ("fresh_offline_database_required",):
        return "offline_database_not_fresh", None
    if isinstance(exc, OSError):
        return "filesystem_error", None
    return "validation_failed", None


@contextmanager
def _runtime_phase(phase):
    # Keep the already-approved bounded worker metrics transport. No direct log
    # handler, subprocess output or additional IPC protocol is introduced.
    labels = {"lease_acquisition": "image.database.acquire",
              "download": "image.database.download"}
    manager = None
    if phase in labels:
        try:
            from peaso.runtime_metrics import span
            manager = span(labels[phase])
            manager.__enter__()
        except Exception:
            manager = None
    exception = (None, None, None)
    try:
        yield
    except BaseException:
        exception = sys.exc_info()
        raise
    finally:
        if manager is not None:
            try:
                manager.__exit__(*exception)
            except Exception:
                pass


@contextmanager
def diagnostic_phase(phase, diagnostics=None):
    """Bounded, nonfatal diagnostics; no paths, output, parameters or values."""
    with _runtime_phase(phase):
        sink = _DIAGNOSTICS.get() if diagnostics is None else diagnostics
        if type(sink) is not dict or phase not in _PHASES:
            yield
            return
        started = time.monotonic()
        error = None
        try:
            yield
        except Exception as exc:
            error = exc
            raise
        finally:
            try:
                reason, code = _classification(error)
                # Aggregate a fixed number of phases, never append per-image rows.
                phases = sink.setdefault("phases", {})
                if type(phases) is dict:
                    previous = phases.get(phase, {})
                    calls = previous.get("calls", 0) if type(previous) is dict else 0
                    elapsed = previous.get("wall_ms", 0) if type(previous) is dict else 0
                    row = {"calls": min(1_000_000, calls + 1),
                           "wall_ms": min(86_400_000, elapsed + max(0, round((time.monotonic()-started)*1000))),
                           "status": "ok" if error is None else "unavailable", "reason": reason}
                    if code is not None:
                        row["exit_code"] = code
                    phases[phase] = row
            except Exception:
                # A diagnostic failure cannot change DB admission or scan outcomes.
                pass


def _diagnosed(phase):
    def decorate(function):
        @wraps(function)
        def call(*args, **kwargs):
            with diagnostic_phase(phase):
                return function(*args, **kwargs)
        return call
    return decorate


def _timestamp(value: object) -> dt.datetime:
    if not isinstance(value, str):
        raise DatabaseUnavailable("DB timestamp missing")
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise DatabaseUnavailable("DB timestamp invalid") from exc
    if parsed.tzinfo is None:
        raise DatabaseUnavailable("DB timestamp has no timezone")
    return parsed.astimezone(UTC)


@_diagnosed("database_validation")
def validate_db(cache: Path, now: dt.datetime | None = None) -> dict:
    """Reject absent, malformed, unsupported, expired, or stale DBs."""
    now = now or dt.datetime.now(UTC)
    db = cache / "db" / "trivy.db"
    metadata = cache / "db" / "metadata.json"
    if db.is_symlink() or metadata.is_symlink() or not db.is_file() or not metadata.is_file():
        raise DatabaseUnavailable("DB files missing or linked")
    try:
        # Trivy schema-2 uses bbolt, not SQLite. This bounded format
        # preflight verifies the initial meta page; Trivy must still open and
        # scan the DB successfully before any clean result can be accepted.
        if not 8192 <= db.stat().st_size <= MAX_CACHE_BYTES:
            raise DatabaseUnavailable("DB size is outside provisioning bounds")
        with db.open("rb") as handle:
            header = handle.read(80)
        if len(header) != 80:
            raise DatabaseUnavailable("DB meta page is truncated")
        page_id, page_flags, _, _ = struct.unpack_from("<QHHI", header)
        magic, version, page_size, _ = struct.unpack_from("<IIII", header, 16)
        checksum = 14695981039346656037
        for octet in header[16:72]:
            checksum = ((checksum ^ octet) * 1099511628211) & ((1 << 64) - 1)
        if (page_id != 0 or page_flags != 4 or magic != 0xed0cdaed or version != 2
                or page_size < 4096 or page_size > 65536 or page_size & (page_size - 1)
                or db.stat().st_size % page_size
                or checksum != struct.unpack_from("<Q", header, 72)[0]):
            raise DatabaseUnavailable("DB bbolt meta page is invalid")
        if not 0 < metadata.stat().st_size <= 8192:
            raise DatabaseUnavailable("DB metadata size is outside provisioning bounds")
        info = json.loads(metadata.read_text())
    except (OSError, ValueError) as exc:
        raise DatabaseUnavailable("DB files unreadable or metadata invalid") from exc
    if not isinstance(info, dict) or type(info.get("Version")) is not int or info["Version"] != 2:
        raise DatabaseUnavailable("DB schema is not version 2")
    updated = _timestamp(info.get("UpdatedAt"))
    next_update = _timestamp(info.get("NextUpdate"))
    if updated > now or now - updated > MAX_AGE:
        raise DatabaseUnavailable("DB is older than 24 hours or future dated")
    if next_update <= now or next_update <= updated:
        raise DatabaseUnavailable("DB NextUpdate has passed")
    return info


def _limit_file_size() -> None:
    resource.setrlimit(resource.RLIMIT_FSIZE, (MAX_CACHE_BYTES, MAX_CACHE_BYTES))


def _size(path: Path) -> int:
    total = 0
    entries = 0
    for item in path.rglob("*"):
        entries += 1
        if entries > MAX_STAGING_ENTRIES or item.is_symlink():
            raise DatabaseUnavailable("download staging contains excessive or linked entries")
        if item.is_file():
            total += item.stat().st_size
            if total > MAX_CACHE_BYTES:
                raise DatabaseUnavailable("download exceeded cache size limit")
        elif not item.is_dir():
            raise DatabaseUnavailable("download staging contains an unsupported entry")
    return total


@_diagnosed("download")
def _download(argv: list[str], staging: Path, env: dict[str, str]) -> None:
    """Observe total staging usage while running, retaining per-file OS limits.

    Polling bounds detection latency, not bytes written between observations.
    A filesystem quota is still required for a hard aggregate byte ceiling.
    """
    process = subprocess.Popen(
        argv, env=env, start_new_session=True,
        preexec_fn=_limit_file_size if os.name == "posix" else None,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    deadline = time.monotonic() + DOWNLOAD_TIMEOUT_SECONDS
    try:
        while True:
            _size(staging)
            if shutil.disk_usage(staging).free < FREE_RESERVE_BYTES:
                raise DatabaseUnavailable("download exhausted reserved disk headroom")
            status = process.poll()
            if status is not None:
                if status:
                    raise subprocess.CalledProcessError(status, argv)
                return
            if time.monotonic() >= deadline:
                raise subprocess.TimeoutExpired(argv, DOWNLOAD_TIMEOUT_SECONDS)
            time.sleep(DOWNLOAD_POLL_SECONDS)
    finally:
        # The child owns its process group; never signal a reused PID/group
        # after a successful wait. Always reap an interrupted download before
        # refresh removes its staging directory.
        if process.poll() is None:
            if os.name == "posix":
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            else:
                process.kill()
        process.wait()


@_diagnosed("refresh")
def refresh(root: Path, *, trivy: str = "trivy", now: dt.datetime | None = None) -> Path:
    """Download to a private cache, then atomically switch the current pointer."""
    now = now or dt.datetime.now(UTC)
    if root.is_symlink():
        raise DatabaseUnavailable("cache root must not be linked")
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    generations = root / "generations"
    if generations.is_symlink():
        raise DatabaseUnavailable("generation directory must not be linked")
    root.chmod(0o700)
    generations.mkdir(mode=0o700, exist_ok=True)
    free = shutil.disk_usage(root).free
    if free < MAX_CACHE_BYTES + FREE_RESERVE_BYTES:
        raise DatabaseUnavailable("insufficient free disk for bounded DB refresh")

    staging = Path(tempfile.mkdtemp(prefix=".staging-", dir=root))
    pointer = root / (".current-" + uuid.uuid4().hex)
    generation = generations / uuid.uuid4().hex
    published = False
    try:
        # Public DB update receives no workload credentials, cloud metadata URI,
        # user config, proxy credentials or scanner options from the caller.
        home = staging / "home"
        home.mkdir(mode=0o700)
        policy = home / "trivy.yaml"
        policy.write_text("{}\n")
        env = {"PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": str(home),
               "XDG_CONFIG_HOME": str(home), "TMPDIR": str(staging),
               "TRIVY_DISABLE_TELEMETRY": "true", "LANG": "C.UTF-8",
               "NO_COLOR": "1"}
        _download(
            [trivy, "image", "--config", str(policy), "--cache-dir", str(staging), "--download-db-only",
             "--db-repository", DB_REPOSITORY, "--timeout", "10m", "--no-progress"],
            staging, env,
        )
        if _size(staging) > MAX_CACHE_BYTES:
            raise DatabaseUnavailable("download exceeded cache size limit")
        validate_db(staging, now)
        os.replace(staging, generation)
        pointer.symlink_to(generation.relative_to(root), target_is_directory=True)
        os.replace(pointer, root / "current")
        published = True
        # Retain the immediately previous cache for readers that resolved it
        # before the switch. Never retain an unbounded sequence of daily DBs.
        previous = sorted(
            (item for item in generations.iterdir() if item.is_dir() and item != generation),
            key=lambda item: item.stat().st_mtime,
            reverse=True,
        )
        for old in previous[1:]:
            shutil.rmtree(old)
        return generation
    finally:
        if pointer.is_symlink():
            pointer.unlink()
        if staging.exists():
            shutil.rmtree(staging)
        if not published and generation.exists():
            shutil.rmtree(generation)


@_diagnosed("cache_validation")
def current_cache(root: Path, now: dt.datetime | None = None) -> Path:
    current = root / "current"
    if not current.is_symlink():
        raise DatabaseUnavailable("current DB pointer missing")
    resolved = current.resolve(strict=True)
    if resolved.parent != (root / "generations").resolve():
        raise DatabaseUnavailable("current DB pointer escapes generation directory")
    validate_db(resolved, now)
    return current


@contextmanager
def _database_lease(*, enabled=False, cache_root=Path("/tmp/peaso/trivy"),
                   trivy="/usr/local/bin/trivy", force_refresh=False):
    """Refresh once when selected; hold an exclusive lease through offline reads.

    The path and binary are trusted worker configuration, never connector input.
    Serializing readers with refresh prevents deletion of an in-use generation.
    Disabled mode creates no files and runs no command. Lock acquisition is bounded.
    """
    if enabled is not True:
        yield None
        return
    root = Path(cache_root)
    if root.is_symlink():
        raise DatabaseUnavailable("cache root must not be linked")
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    lock_path = root / ".lease"
    fd = os.open(lock_path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "a+") as lock:
        deadline = time.monotonic() + 30
        while True:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    raise DatabaseUnavailable("DB cache is busy")
                time.sleep(0.1)
        try:
            try:
                if force_refresh:
                    raise DatabaseUnavailable("explicit refresh")
                cache = current_cache(root)
            except (DatabaseUnavailable, OSError, ValueError):
                refresh(root, trivy=trivy)
                cache = current_cache(root)
            # Resolve once under the lease: the scanner must not chase a
            # subsequently changed current pointer between before/after hashes.
            yield cache.resolve(strict=True)
        finally:
            fcntl.flock(lock, fcntl.LOCK_UN)


@contextmanager
def database_lease(*, enabled=False, cache_root=Path("/tmp/peaso/trivy"),
                   trivy="/usr/local/bin/trivy", force_refresh=False, diagnostics=None):
    """Original lease semantics, with optional acquisition-only diagnostics."""
    token = _DIAGNOSTICS.set(diagnostics)
    try:
        with ExitStack() as stack:
            # This duration excludes image consumers but includes lease waiting,
            # refresh and both validation passes. Nested phases expose each cost.
            with diagnostic_phase("lease_acquisition"):
                cache = stack.enter_context(_database_lease(
                    enabled=enabled, cache_root=cache_root, trivy=trivy,
                    force_refresh=force_refresh))
            yield cache
    finally:
        _DIAGNOSTICS.reset(token)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("refresh", "check"))
    parser.add_argument("--cache-root", type=Path, default=Path("/var/lib/peaso/trivy"))
    parser.add_argument("--trivy", default="trivy")
    args = parser.parse_args(argv)
    try:
        if args.command == "refresh":
            with database_lease(enabled=True, cache_root=args.cache_root,
                                trivy=args.trivy, force_refresh=True) as cache:
                print(cache)
        else:
            print(current_cache(args.cache_root))
    except (DatabaseUnavailable, OSError, subprocess.SubprocessError) as exc:
        print(f"Trivy DB unavailable: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
