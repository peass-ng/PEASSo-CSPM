"""Bounded POSIX subprocess supervisor for owned container archives.

Neutral source fork of the preserved optional runner; no vendor authentication,
registry, Docker, collector registry, engine or UI dependency.
"""
import errno
import math
import os
from pathlib import Path
import selectors
import shutil
import signal
import stat
import subprocess
import sys
import time
from . import container_image_archive_20261020 as archive

MAX_STDOUT = 64 * 1024 * 1024
MAX_STDERR = 1024 * 1024
MAX_DISK = 10 * 1024 * 1024 * 1024
MAX_FILE = 6 * 1024 * 1024 * 1024
MAX_SCRATCH_FILES = 300000
POST_EXIT_DRAIN_SECONDS = 1.0

def _scratch_usage(root):
    total, count = 0, 0
    for directory, dirs, files in os.walk(root, followlinks=False):
        for name in dirs + files:
            item = Path(directory) / name
            try:
                info = item.lstat()
            except FileNotFoundError:
                continue
            archive.require(not stat.S_ISLNK(info.st_mode), 'scratch_symlink_refused')
            total += info.st_size
            count += 1
            archive.require(total <= MAX_DISK and count <= MAX_SCRATCH_FILES, 'scratch_disk_bound')
    return total

_LAUNCH = '''import os,resource,sys
def bound(kind, wanted):
    inherited = resource.getrlimit(kind)[1]
    limit = wanted if inherited == resource.RLIM_INFINITY else min(wanted, inherited)
    resource.setrlimit(kind, (limit, limit))
bound(resource.RLIMIT_CORE, 0)
bound(resource.RLIMIT_FSIZE, int(sys.argv[1]))
bound(resource.RLIMIT_CPU, int(sys.argv[2]))
os.execve(sys.argv[3], sys.argv[3:], os.environ)
'''

def _execute(argv, env, root, end, cancel):
    """Bound both pipes and scratch; kill the entire fresh process group always."""
    process, selector = None, selectors.DefaultSelector()
    outputs = {'stdout': bytearray(), 'stderr': bytearray()}
    code, reason = None, None
    exit_seen_at = None
    peak = _scratch_usage(root)
    try:
        cancel()
        archive.require(time.monotonic() < end, 'deadline')
        launcher = [sys.executable, '-I', '-c', _LAUNCH, str(MAX_FILE),
                    str(max(1, math.ceil(end - time.monotonic()))), *argv]
        process = subprocess.Popen(launcher, cwd=root, env=env, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=False, start_new_session=True,
            close_fds=True)
        for stream, name in ((process.stdout, 'stdout'), (process.stderr, 'stderr')):
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ, name)
        while selector.get_map():
            try:
                cancel()
            except Exception:
                reason = 'cancelled'
                break
            if time.monotonic() >= end:
                reason = 'timeout'
                break
            try:
                peak = max(peak, _scratch_usage(root))
                archive.require(shutil.disk_usage(root).free >= archive.MIN_FREE_DISK,
                                'scratch_disk_bound')
            except Exception:
                reason = 'scratch_disk_bound'
                break
            events = selector.select(timeout=.05)
            # Parent exit can race select(): EOF may have become readable
            # immediately after select returned no events. Drain through the
            # next readiness cycles before declaring an inherited pipe stuck.
            if process.poll() is not None and exit_seen_at is None:
                exit_seen_at = time.monotonic()
            for key, _ in events:
                chunk = os.read(key.fd, 65536)
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                target = outputs[key.data]
                cap = MAX_STDOUT if key.data == 'stdout' else MAX_STDERR
                if len(target) + len(chunk) > cap:
                    reason = 'stdio_bound'
                    break
                target.extend(chunk)
            if reason:
                break
            if (exit_seen_at is not None and selector.get_map()
                    and time.monotonic() - exit_seen_at >= POST_EXIT_DRAIN_SECONDS):
                reason = 'descendant_pipe_open'
                break
        if reason is None:
            try:
                code = process.wait(timeout=max(.001, end - time.monotonic()))
            except subprocess.TimeoutExpired:
                reason = 'timeout'
            try:
                peak = max(peak, _scratch_usage(root))
                archive.require(shutil.disk_usage(root).free >= archive.MIN_FREE_DISK,
                                'scratch_disk_bound')
            except Exception:
                reason = 'scratch_disk_bound'
    except Exception:
        reason = 'process_unavailable'
    finally:
        if process is not None:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except OSError as exc:
                if exc.errno != errno.ESRCH:
                    reason = 'process_group_cleanup_failed'
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                reason = 'process_group_cleanup_failed'
            for stream in (process.stdout, process.stderr):
                if stream is not None:
                    stream.close()
        selector.close()
    return bytes(outputs['stdout']), bytes(outputs['stderr']), code, reason, peak
