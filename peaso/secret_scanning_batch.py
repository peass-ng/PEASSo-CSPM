"""Context-local, bounded offline preparation for the pinned TruffleHog scanner."""
from contextlib import contextmanager
from contextvars import ContextVar
import json
import itertools
import os
import sys
import tempfile
import time


MAX_BATCH_ITEMS = 512
MAX_BATCH_BYTES = 64 * 1024 * 1024
_PREPARED_BATCH = ContextVar('prepared_content_batch', default=None)
_PREPARED_COHORT = ContextVar('prepared_content_cohort', default=None)
_BATCH_METRICS = ContextVar('content_batch_metrics', default=None)
_METRICS_SENDER = None
_METRICS_SEQUENCE = itertools.count(1)
_METRICS_KEYS = frozenset({'schema', 'batch', 'items', 'input_bytes', 'unique_payloads',
    'unique_bytes', 'prepared', 'reason', 'preparation_ms', 'consumer_ms',
    'lookups', 'prepared_reads', 'serial_lookups', 'consumer_failed'})
_METRICS_REASONS = frozenset({'none', 'single_source', 'volatile_shm_unavailable',
    'payload_exceeds_capacity', 'preparation_timeout', 'invalid_output',
    'scanner_unavailable', 'preparation_error', 'preparation_unavailable'})


def configure_metrics(sender):
    """Bind only the owned worker's synchronized one-way diagnostic sender."""
    global _METRICS_SENDER
    _METRICS_SENDER = sender


def safe_metrics(event):
    """Reject all unknown fields and nonbounded values before supervisor logging."""
    if type(event) is not dict or event.keys() != _METRICS_KEYS:
        return None
    if event['schema'] != 1 or type(event['schema']) is not int:
        return None
    if type(event['reason']) is not str or event['reason'] not in _METRICS_REASONS:
        return None
    for key, value in event.items():
        if key == 'reason':
            continue
        if type(value) is not int or not 0 <= value <= 2**63 - 1:
            return None
    if (not 0 <= event['items'] <= MAX_BATCH_ITEMS
            or event['input_bytes'] > MAX_BATCH_BYTES
            or event['unique_payloads'] > event['items']
            or event['unique_bytes'] > event['input_bytes']
            or any(event[key] not in (0, 1) for key in ('prepared', 'consumer_failed'))
            or event['prepared_reads'] + event['serial_lookups'] != event['lookups']):
        return None
    return dict(event)


def record_metrics(event, logger):
    value = safe_metrics(event)
    if value is None:
        return False
    try:
        logger.info('Content scanner batch metrics: %s', json.dumps(value, sort_keys=True, separators=(',', ':')))
    except Exception:
        # Diagnostic formatting or handlers must never fail an owned scan.
        return False
    return True


def _metric_reason(reason):
    metrics = _BATCH_METRICS.get()
    if metrics is not None:
        metrics['reason'] = reason


def _metric_emit(metrics):
    sender = _METRICS_SENDER
    if sender is not None:
        value = safe_metrics(metrics)
        if value is not None:
            try:
                sender(('__content_metrics__', value))
            except Exception:
                # Diagnostics never alter collection, deadlines or evidence.
                pass


def _after_fork():
    inherited = _PREPARED_BATCH.get()
    if inherited is not None:
        inherited.clear()
    _PREPARED_BATCH.set(None)
    _PREPARED_COHORT.set(None)
    _BATCH_METRICS.set(None)
    configure_metrics(None)


if hasattr(os, 'register_at_fork'):
    os.register_at_fork(after_in_child=_after_fork)


def prepared_output(payload, path):
    """Return exact-source NDJSON, including b'' for clean, or None for serial."""
    prepared = _PREPARED_BATCH.get()
    if prepared is not None:
        output = prepared.get((payload, path))
    else:
        cohort = _PREPARED_COHORT.get()
        output = None if cohort is None else cohort[0].output(cohort[1], payload, path)
    metrics = _BATCH_METRICS.get()
    if metrics is not None:
        metrics['lookups'] += 1
        metrics['prepared_reads' if output is not None else 'serial_lookups'] += 1
    return output


def _volatile_shm_available(total):
    """Require the exact /dev/shm mount to be volatile, with spare capacity."""
    if sys.platform != 'linux' or os.path.islink('/dev/shm') or not os.path.ismount('/dev/shm'):
        return False
    with open('/proc/self/mountinfo', encoding='utf-8') as mounts:
        if not any(line.split(' - ', 1)[0].split()[4] == '/dev/shm'
                   and line.split(' - ', 1)[1].split()[0] == 'tmpfs'
                   for line in mounts if ' - ' in line):
            return False
    space = os.statvfs('/dev/shm')
    return space.f_bavail * space.f_frsize >= total + 1024 * 1024


def _prepare_trufflehog_batch(items, timeout):
    # Import lazily: secret_scanning exports this module's context manager.
    from . import secret_scanning as scanning

    items = list(dict.fromkeys(items))
    payloads = list(dict.fromkeys(payload for payload, _ in items))
    total = sum(map(len, payloads))
    if not _volatile_shm_available(total):
        # A full 64 MiB content batch cannot fit a default 64 MiB /dev/shm
        # with the required safety margin. Keep the original per-source scan
        # semantics while staging smaller bounded groups in the same tmpfs.
        limit = MAX_BATCH_BYTES // 2
        while limit >= 1024 * 1024 and not _volatile_shm_available(limit):
            limit //= 2
        if limit < 1024 * 1024:
            _metric_reason('volatile_shm_unavailable')
            return None
        if any(len(payload) > limit for payload in payloads):
            _metric_reason('payload_exceeds_capacity')
            return None
        deadline = time.monotonic() + timeout
        prepared, pending, pending_bytes = {}, [], 0
        output_bytes, outputs = 0, set()
        for item in items:
            if pending and pending_bytes + len(item[0]) > limit:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError('content batch deadline')
                group = _prepare_trufflehog_batch(pending, remaining)
                if group is None:
                    return None
                for value in group.values():
                    if id(value) not in outputs:
                        outputs.add(id(value)); output_bytes += len(value)
                if output_bytes > scanning.MAX_OUTPUT:
                    raise ValueError('scanner output bound')
                prepared.update(group)
                pending, pending_bytes = [], 0
            pending.append(item)
            pending_bytes += len(item[0])
        if pending:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError('content batch deadline')
            group = _prepare_trufflehog_batch(pending, remaining)
            if group is None:
                return None
            for value in group.values():
                if id(value) not in outputs:
                    outputs.add(id(value)); output_bytes += len(value)
            if output_bytes > scanning.MAX_OUTPUT:
                raise ValueError('scanner output bound')
            prepared.update(group)
        return prepared
    with tempfile.TemporaryDirectory(prefix='peaso-scan-', dir='/dev/shm') as directory:
        os.chmod(directory, 0o700)
        paths = {}
        for index, payload in enumerate(payloads):
            filename = os.path.join(directory, str(index))
            fd = os.open(filename, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
            try:
                with os.fdopen(fd, 'wb') as staged:
                    staged.write(payload)
            except BaseException:
                try:
                    os.close(fd)
                except OSError:
                    pass
                raise
            paths[filename] = payload
        from .runtime_metrics import span
        with span('secret.trufflehog.prepared_process'):
            output = scanning._run([scanning._trufflehog(), 'filesystem', '--json',
                                    '--no-verification', '--no-update', '--log-level=-1',
                                    '--concurrency=1', '--force-skip-archives',
                                    '--no-verification-cache', '--fail-on-scan-errors',
                                    *paths], b'', timeout)
        grouped = {payload: [] for payload in payloads}
        for line in output.splitlines():
            row = json.loads(line)
            if not isinstance(row, dict):
                raise ValueError('invalid batch detector result')
            source = row.get('SourceMetadata', {}).get('Data', {}).get('Filesystem', {}).get('file')
            if not isinstance(source, str) or source not in paths:
                raise ValueError('invalid batch source')
            if not isinstance(row.get('Raw'), str) or not row['Raw'] or row.get('Verified') is not False:
                raise ValueError('invalid offline detector result')
            grouped[paths[source]].append(line)
        encoded = {payload: b'\n'.join(lines) for payload, lines in grouped.items()}
        # Detection consumes exact bytes; native paths and private source
        # attribution are still reconstructed by each original caller.
        return {item: encoded[item[0]] for item in items}


@contextmanager
def prepared_content_batch(items, *, timeout=60):
    """Prepare bounded per-source TruffleHog output for exact scan_content calls.

    Unsupported hosts or failed preparation use the existing serial scanner.
    No staged payload file survives entry to this context.
    """
    if (not isinstance(items, list) or len(items) > MAX_BATCH_ITEMS
            or not 0 < timeout <= 60):
        raise ValueError('content batch bound')
    total = 0
    for item in items:
        if (not isinstance(item, tuple) or len(item) != 2 or not isinstance(item[0], bytes)
                or not isinstance(item[1], str) or len(item[0]) > MAX_BATCH_BYTES):
            raise ValueError('content batch bound')
        total += len(item[0])
        if total > MAX_BATCH_BYTES:
            raise ValueError('content batch bound')
    metrics = None
    if _METRICS_SENDER is not None:
        payloads = set(payload for payload, _ in items)
        metrics = dict(schema=1, batch=next(_METRICS_SEQUENCE), items=len(items),
            input_bytes=total, unique_payloads=len(payloads), unique_bytes=sum(map(len, payloads)),
            prepared=0, reason='none', preparation_ms=0, consumer_ms=0,
            lookups=0, prepared_reads=0, serial_lookups=0, consumer_failed=0)
        del payloads
    metrics_token = _BATCH_METRICS.set(metrics)
    preparation_started = time.monotonic() if metrics is not None else None
    prepared = None
    try:
        if len(items) > 1:
            try:
                prepared = _prepare_trufflehog_batch(items, timeout)
            except Exception as error:
                # Retain only a finite type category, never the exception value.
                _metric_reason('preparation_timeout' if isinstance(error, TimeoutError) else
                    'invalid_output' if isinstance(error, (ValueError, json.JSONDecodeError)) else
                    'scanner_unavailable' if isinstance(error, FileNotFoundError) else 'preparation_error')
                prepared = None
        else:
            _metric_reason('single_source')
        if metrics is not None:
            metrics['prepared'] = int(prepared is not None)
            metrics['preparation_ms'] = max(0, int((time.monotonic() - preparation_started) * 1000))
            if prepared is None and metrics['reason'] == 'none':
                metrics['reason'] = 'preparation_unavailable'
        token = _PREPARED_BATCH.set(prepared)
        consumer_started = time.monotonic() if metrics is not None else None
        try:
            yield
        except BaseException:
            if metrics is not None:
                metrics['consumer_failed'] = 1
            raise
        finally:
            if metrics is not None:
                metrics['consumer_ms'] = max(0, int((time.monotonic() - consumer_started) * 1000))
            _PREPARED_BATCH.reset(token)
            if prepared is not None:
                prepared.clear()
    finally:
        _BATCH_METRICS.reset(metrics_token)
        if metrics is not None:
            _metric_emit(metrics)


@contextmanager
def prepared_content_member(cohort, member):
    """Bind one admitted native caller; its private source context stays local."""
    token = _PREPARED_COHORT.set((cohort, member))
    try:
        yield
    finally:
        _PREPARED_COHORT.reset(token)
