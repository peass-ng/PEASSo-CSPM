"""Offline dual-engine content detection and value-level, redacted correlation.

Only the collector process retains the random HMAC key. It links occurrences
within that collection and cannot link separate scans. An explicit collector
sink can retain encrypted private matches separately from this public result.
"""
from copy import deepcopy
from functools import lru_cache
from collections import OrderedDict
from contextlib import contextmanager
from concurrent.futures import Future, ThreadPoolExecutor
from contextvars import ContextVar
import hashlib
import base64
import hmac
import json
import os
import re
import secrets
import selectors
import shutil
import signal
import subprocess
import threading
import time
from .secret_scanning_batch import prepared_content_batch, prepared_output as _prepared_trufflehog_output

KINGFISHER_VERSION = '1.4.0'
TRUFFLEHOG_VERSION = '3.92.5'
_KEY = secrets.token_bytes(32)
# Why the last scan_content call in this context left an engine unavailable:
# engine, exception type and a fixed-vocabulary message only, never content.
UNAVAILABLE_REASONS = ContextVar('secret_engine_unavailable_reasons', default=())
_LOCK = threading.Lock()
_RESULT_LOCK = threading.Lock()
_RESULTS = OrderedDict()
MAX_INPUT = 64 * 1024 * 1024
MAX_OUTPUT = 4 * 1024 * 1024
MAX_FINDINGS = 5000
# Optional clear-text fields of a secret observation (see merge_leaks).
FOUND_VALUE_FIELDS = ('value', 'value_truncated', 'context')
# Longest a scanner process may queue for a slot when no collection lease
# bounds the wait; the run's own deadline only starts once it holds a slot.
MAX_SLOT_WAIT = 900


def _slot_count():
    try:
        cpus = len(os.sched_getaffinity(0))
    except (AttributeError, OSError):
        cpus = os.cpu_count() or 1
    return max(2, cpus)


# Every scanner process of this worker shares these slots. Unbounded, dozens
# of concurrent image jobs each started TruffleHog at once on a two-vCPU
# collector, so every wall-clock deadline (and its longer retry) measured the
# CPU queue instead of the scan, and a tiny payload missed it.
_SLOTS = threading.BoundedSemaphore(_slot_count())


def _after_fork():
    global _KEY, _LOCK, _RESULT_LOCK, _RESULTS, _SLOTS, _VERIFY_LOCK
    _KEY, _LOCK = secrets.token_bytes(32), threading.Lock()
    _RESULT_LOCK, _RESULTS = threading.Lock(), OrderedDict()
    _SLOTS = threading.BoundedSemaphore(_slot_count())
    _kingfisher.cache_clear()
    _VERIFY_LOCK = threading.Lock()
    _VERIFIED.clear()


if hasattr(os, 'register_at_fork'):
    os.register_at_fork(after_in_child=_after_fork)


def _fingerprint(value):
    # Exact bytes: no lowercasing, trimming, or fuzzy merging distinct secrets.
    return hmac.new(_KEY, value.encode('utf-8'), hashlib.sha256).hexdigest()


def _label(value):
    # Rule names are metadata, never trust arbitrary engine output as display text.
    return value if isinstance(value, str) and re.fullmatch(r'[A-Za-z0-9_.:/ -]{1,160}', value) else 'secret'


@lru_cache(maxsize=1)
def _kingfisher():
    from importlib.metadata import version
    from kingfisher_sdk import Rules, Scanner
    if version('kingfisher-secret-scanner') != KINGFISHER_VERSION:
        raise RuntimeError('unsupported scanner version')
    return Scanner(Rules(cache=False), dedup=False)


def _scan_kingfisher(payload, path, timeout):
    from kingfisher_sdk import ScanInput
    # Detection only: no Validator/Revoker imports, caches, remote enumeration.
    with _LOCK:
        findings = _kingfisher().scan_input(ScanInput(path, payload), timeout=timeout)
    result = []
    for finding in findings:
        if not finding.visible:
            continue
        location = finding.location
        result.append((finding.secret, finding.rule_id, location.get('line')))
        if len(result) > MAX_FINDINGS:
            raise ValueError('finding bound')
    return result


@contextmanager
def _scanner_slot():
    """Hold one scanner process slot; yield the collection lease, if any.

    The wait honors the worker's collection lease (or MAX_SLOT_WAIT without
    one) and never counts against the scanner's own deadline.
    """
    from .collection_lease import effective_deadline
    lease = effective_deadline(None)
    limit = time.monotonic() + MAX_SLOT_WAIT if lease is None else lease
    slots = _SLOTS
    while not slots.acquire(timeout=max(0, min(.1, limit - time.monotonic()))):
        if time.monotonic() >= limit:
            raise TimeoutError('scanner queue deadline' if lease is None else 'collection lease expired')
    try:
        yield lease
    finally:
        slots.release()


def _run(argv, payload, timeout):
    """Bound stdin, output and lifetime; discard tool stderr, including secrets."""
    with _scanner_slot() as lease:
        return _run_in_slot(argv, payload, timeout, lease)


def _run_in_slot(argv, payload, timeout, lease):
    if lease is not None and time.monotonic() >= lease:
        raise TimeoutError('collection lease expired')
    environment = {'PATH': os.defpath, 'HOME': '/nonexistent', 'NO_COLOR': '1',
                   'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': os.devnull}
    process = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                               stderr=subprocess.DEVNULL, env=environment,
                               start_new_session=True)
    output, offset = bytearray(), 0
    deadline = time.monotonic() + timeout
    # The lease, not this scan, ended: a longer retry could not help.
    expired = 'scanner deadline'
    if lease is not None and lease < deadline:
        deadline, expired = lease, 'collection lease expired'
    try:
        with selectors.DefaultSelector() as selector:
            for stream in (process.stdin, process.stdout):
                os.set_blocking(stream.fileno(), False)
            if payload:
                selector.register(process.stdin, selectors.EVENT_WRITE)
            else:
                process.stdin.close()
            selector.register(process.stdout, selectors.EVENT_READ)
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError(expired)
                for key, _ in selector.select(min(remaining, .1)):
                    if key.fileobj is process.stdin:
                        offset += os.write(process.stdin.fileno(), payload[offset:offset+65536])
                        if offset == len(payload):
                            selector.unregister(process.stdin)
                            process.stdin.close()
                    else:
                        chunk = os.read(process.stdout.fileno(), 65536)
                        if not chunk:
                            selector.unregister(process.stdout)
                        else:
                            output.extend(chunk)
                            if len(output) > MAX_OUTPUT:
                                from .secret_scanning_errors import ScannerStdoutBound
                                raise ScannerStdoutBound('scanner output bound')
            if process.wait(timeout=max(.001, deadline-time.monotonic())) != 0:
                raise RuntimeError('scanner failed')
        return bytes(output)
    finally:
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL)
        process.wait()
        process.stdout.close()
        if not process.stdin.closed:
            process.stdin.close()


# The first TruffleHog start in a fresh task pages its ~160 MiB binary in
# while image layers are streaming to disk; on a busy two-vCPU collector that
# took longer than a few seconds. The check runs once per binary, so a generous
# bound costs nothing when the start is fast. It is also the longest a content
# scan may run (scan_content), so a retried scan never meets a shorter check.
VERSION_CHECK_TIMEOUT = 60
_VERIFIED = {}
_VERIFY_LOCK = threading.Lock()


def _verified_trufflehog(executable, file_identity):
    key = (executable, file_identity)
    compatible = _VERIFIED.get(key)
    # One check at a time: concurrent first scans wait for its result instead
    # of each starting the cold binary and competing for the same slots.
    if compatible is None:
        with _VERIFY_LOCK:
            compatible = _VERIFIED.get(key)
            if compatible is None:
                version = _run([executable, '--version'], b'', VERSION_CHECK_TIMEOUT).decode('utf-8').strip()
                compatible = version == 'trufflehog ' + TRUFFLEHOG_VERSION
                _VERIFIED.clear()
                _VERIFIED[key] = compatible
    if not compatible:
        raise RuntimeError('unsupported scanner version')
    return executable


def _trufflehog():
    # Resolve the binary on every call, but run its version check once per
    # exact file: a scan can call this thousands of times, and an extra
    # process start for each content item doubled the detector cost.
    executable = shutil.which('trufflehog')
    if executable is None:
        raise RuntimeError('scanner unavailable')
    try:
        status = os.stat(executable)
    except OSError:
        raise RuntimeError('scanner unavailable') from None
    identity = (status.st_dev, status.st_ino, status.st_mtime_ns, status.st_ctime_ns, status.st_size)
    return _verified_trufflehog(executable, identity)


_trufflehog.cache_clear = _VERIFIED.clear


class _DetectorMatches(list):
    """Internal plaintext parser result; extra values redact, never identify."""
    def __init__(self):
        super().__init__()
        self.redaction_values = set()


def _complete_match_values(primary, full, *, rule):
    """Privacy redactions from a parsed offline result, not source provenance."""
    if not isinstance(full, str) or not full:
        return []
    values = [full]
    if rule.casefold() == 'aws' and full.startswith(primary + ':'):
        component = full[len(primary) + 1:]
        # The detector can decode the pair from base64. Redact its recognized
        # component even when those literal bytes are absent from the input.
        if re.fullmatch(r'[A-Za-z0-9/+=]{40}', component):
            values.append(component)
    return values


def _scan_trufflehog(payload, path, timeout):
    from .secret_scan_clean import known_clean, remember_clean
    output = _prepared_trufflehog_output(payload, path)
    if output is None and known_clean(payload):
        output = b''
    if output is None:
        output = _run([_trufflehog(), 'stdin', '--json', '--no-verification', '--no-update',
                       '--log-level=-1', '--concurrency=1', '--force-skip-archives',
                       '--no-verification-cache', '--fail-on-scan-errors'], payload, timeout)
    if not output:
        remember_clean(payload)
    result, full_matches, recovered_lines = _DetectorMatches(), [], {}
    for line in output.splitlines():
        row = json.loads(line)
        # RawV2 is a composite display representation for some detectors. Raw
        # is the primary matched value, shared with Kingfisher's secret field.
        value = row.get('Raw')
        if not isinstance(value, str) or not value or row.get('Verified') is not False:
            raise ValueError('invalid offline detector result')
        result.redaction_values.update(_complete_match_values(value, row.get('RawV2'),
            rule=_label(row.get('DetectorName', 'secret'))))
        if isinstance(row.get('RawV2'), str) and row['RawV2'] and row['RawV2'] != value:
            full_matches.append((value, row['RawV2'], row.get('DetectorName', 'secret')))
        # stdin metadata has no file line. Recover all exact plaintext
        # occurrences; decoded-only results have an explicitly unknown line.
        lines = recovered_lines.get(value)
        if lines is None:
            needle, start, counted, number = value.encode('utf-8'), 0, 0, 1
            lines = []
            while (position := payload.find(needle, start)) != -1:
                number += payload.count(b'\n', counted, position)
                lines.append(number)
                start, counted = position + len(needle), position
                if len(result) + len(lines) > MAX_FINDINGS:
                    raise ValueError('finding bound')
            recovered_lines[value] = lines = lines or [None]
        result.extend((value, row.get('DetectorName', 'secret'), number) for number in lines)
        if len(result) > MAX_FINDINGS:
            raise ValueError('finding bound')
    # Preserve additional credential components only after this offline engine
    # completed successfully. Public primary-value fingerprints stay unchanged.
    from peaso.secret_evidence import remember_full_match
    for primary, full, rule in full_matches:
        remember_full_match(primary, full, payload=payload, path=path, engine='trufflehog', rule=_label(rule))
    return result


def merge_leaks(rows):
    """Merge observations of one value, including different files/layers.

    A row may carry the found value in clear text (``value``, with
    ``value_truncated`` when bounded, and a ``context`` snippet); one
    fingerprint is one value, so the first supplied copy is kept.
    """
    merged, seen = {}, {}
    for row in rows:
        if (not isinstance(row, dict) or not {'fingerprint', 'detectors', 'locations'} <= set(row)
                or set(row) - {'fingerprint', 'detectors', 'locations', *FOUND_VALUE_FIELDS}):
            raise ValueError('invalid secret observation')
        ident = row['fingerprint']
        if not isinstance(ident, str) or re.fullmatch('[0-9a-f]{64}', ident) is None:
            raise ValueError('invalid secret fingerprint')
        if (any(not isinstance(row[field], str) or not row[field] for field in ('value', 'context') if field in row)
                or row.get('value_truncated', True) is not True):
            raise ValueError('invalid secret value')
        item = merged.setdefault(ident, {'fingerprint': ident, 'detectors': [], 'locations': []})
        for field in FOUND_VALUE_FIELDS:
            if field in row and field not in item:
                item[field] = row[field]
        unique = seen.setdefault(ident, {'detectors': set(), 'locations': set()})
        if not isinstance(row['detectors'], list) or not row['detectors'] or not isinstance(row['locations'], list) or not row['locations']:
            raise ValueError('missing detector or location')
        for detector in row['detectors']:
            if (not isinstance(detector, dict) or set(detector) != {'engine', 'rule'}
                    or detector['engine'] not in ('kingfisher', 'trufflehog')
                    or _label(detector['rule']) != detector['rule']):
                raise ValueError('invalid detector')
        for location in row['locations']:
            if (not isinstance(location, dict) or not {'path'} <= set(location)
                    or set(location) - {'path', 'line', 'layer', 'timestamp', 'resource_id', 'scope'}):
                raise ValueError('invalid location')
            for field, value in location.items():
                if field in ('line', 'timestamp'):
                    if type(value) is not int or value < (1 if field == 'line' else 0):
                        raise ValueError('invalid source position')
                elif not isinstance(value, str) or not value or len(value) > 4096:
                    raise ValueError('invalid source reference')
        for field in ('detectors', 'locations'):
            for value in row[field]:
                key = tuple(sorted(value.items()))
                if key not in unique[field]:
                    unique[field].add(key)
                    item[field].append(value)
    for row in merged.values():
        row['detectors'].sort(key=lambda d: (d['engine'], d['rule']))
        row['locations'].sort(key=lambda d: json.dumps(d, sort_keys=True))
    return [merged[key] for key in sorted(merged)]


def omit_free_text_metadata(value):
    """Omit arbitrary metadata in selected configuration projections.

    A later page can reveal a credential repeated in an earlier description or
    label. Drop those fields before caching without retaining a run-global raw
    secret set. Native identities and typed configuration fields are unchanged.
    This is not a guarantee for arbitrary encodings or secret-bearing identities.
    """
    if isinstance(value, list):
        return [omit_free_text_metadata(item) for item in value]
    if not isinstance(value, dict):
        return value
    removed = set(value) & {'description', 'descriptions', 'labels', 'annotations'}
    result = {key: omit_free_text_metadata(item) for key, item in value.items()
              if key not in removed and key != '_coverage'}
    if '_coverage' in value:
        from copy import deepcopy
        result['_coverage'] = deepcopy(value['_coverage'])
    if removed:
        coverage = result.setdefault('_coverage', {})
        if not isinstance(coverage, dict):
            coverage = result['_coverage'] = {}
        coverage.update({key: {'status': 'unknown', 'reason': 'free_text_not_retained'}
                         for key in removed})
    return result


def redact_matches(value, matches):
    """Return metadata unchanged: found secrets stay visible to the tenant.

    Administrators need each detected value and its location to rotate or
    remove it. Callers keep their own copy semantics: the result is a new
    container structure that shares only immutable leaves with the input.
    """
    def copy(original):
        if isinstance(original, dict):
            return {key: copy(member) for key, member in original.items()}
        if isinstance(original, list):
            return [copy(member) for member in original]
        return original

    return copy(value)


def scan_content(payload, path='content', *, timeout=15, _redact_values=None):
    """Both engines must succeed for a negative result to be complete."""
    if not isinstance(payload, bytes) or len(payload) > MAX_INPUT or not 0 < timeout <= 60:
        raise ValueError('content bound')
    cache_key = (hmac.new(_KEY, payload, hashlib.sha256).digest(),
                 hmac.new(_KEY, path.encode('utf-8'), hashlib.sha256).digest())
    with _RESULT_LOCK:
        cached = _RESULTS.get(cache_key)
    from .secret_evidence import batched, enabled as private_capture, remember, remember_public, match_context
    # Only clean outcomes are cached. A clean scan has no private side effect,
    # so reuse is exact with or without private evidence capture.
    if cached is not None:
        if _redact_values is not None:
            _redact_values(frozenset())
        return deepcopy(cached)
    observations, engines, matches_by_engine, known_values, reasons = [], [], [], set(), []
    # TruffleHog stays on the caller thread: prepared batch outputs are
    # context-local and full-match private evidence uses its source context.
    # Kingfisher has no capture side effects and retains its existing SDK lock.
    with ThreadPoolExecutor(max_workers=1, thread_name_prefix='peaso-secret') as executor:
        try:
            kingfisher = executor.submit(_scan_kingfisher, payload, path, timeout)
        except RuntimeError:
            kingfisher = Future()
            try:
                kingfisher.set_result(_scan_kingfisher(payload, path, timeout))
            except Exception as exc:
                kingfisher.set_exception(exc)
        trufflehog = Future()
        try:
            trufflehog.set_result(_scan_trufflehog(payload, path, timeout))
        except Exception as exc:
            trufflehog.set_exception(exc)
        for name, version, pending in (('kingfisher', KINGFISHER_VERSION, kingfisher),
                                       ('trufflehog', TRUFFLEHOG_VERSION, trufflehog)):
            try:
                matches = pending.result()
                for value, rule, line in matches:
                    if not isinstance(value, str) or not value:
                        raise ValueError('empty secret')
                    known_values.add(value)
                # Complete pairs/components must also be scrubbed from paths and
                # metadata when private persistence is disabled or reaches a bound.
                known_values.update(getattr(matches, 'redaction_values', ()))
                matches_by_engine.append((name, matches))
                engines.append({'engine': name, 'version': version, 'status': 'complete'})
            except Exception as exc:
                # No matched values, raw JSON or tracebacks escape.
                text = str(exc)
                reasons.append('_'.join([name, type(exc).__name__.lower()] +
                                        (text.split() if re.fullmatch(r'[a-z ]{1,60}', text) else [])))
                engines.append({'engine': name, 'version': version, 'status': 'unavailable'})
    UNAVAILABLE_REASONS.set(tuple(reasons))
    # Found values and their exact paths stay visible to the tenant. The
    # callback contract is kept, but there is nothing to redact.
    if _redact_values is not None:
        _redact_values(frozenset())
    fingerprints = {value: _fingerprint(value) for value in known_values}
    # Public-by-design browser keys are not leaks; each is recorded with why.
    from .secret_public_identifiers import public_client_identifiers
    public = public_client_identifiers(matches_by_engine, payload, path)
    capture = private_capture()
    observed, identifiers = {}, {}
    with batched():
        for name, matches in matches_by_engine:
            for value, rule, line in matches:
                if value in public:
                    row = identifiers.setdefault(value, {'value': value, 'kind': public[value]['id'],
                        'reason': public[value]['reason'], 'path': path, 'detectors': []})
                    detector = {'engine': name, 'rule': _label(rule)}
                    if detector not in row['detectors']:
                        row['detectors'].append(detector)
                    continue
                # Retain the actual match/value/line association with its canonical witness.
                if capture and value not in observed:
                    observed[value] = value.encode('utf-8') in payload
                    # The found value is published in clear text with its
                    # finding, with a short snippet of where it sits.
                    remember_public(value, fingerprints[value],
                                    match_context(payload, value) if observed[value] else None)
                remember(value, fingerprints[value], path=path, public_path=path, line=line, engine=name, rule=_label(rule),
                         observed_bytes=not capture or observed[value])
                observations.append({'fingerprint': fingerprints[value],
                    'detectors': [{'engine': name, 'rule': _label(rule)}],
                    'locations': [{'path': path, **({'line': line} if type(line) is int and line > 0 else {})}]})
    outcome = {'leaks': merge_leaks(observations), 'engines': engines,
               'complete': all(row['status'] == 'complete' for row in engines)}
    if identifiers:
        outcome['public_identifiers'] = [identifiers[value] for value in sorted(identifiers)]
    # Repeated logs/layers reuse only a complete, clean outcome. It holds no
    # raw content, path, secret or failed result.
    if outcome['complete'] and not outcome['leaks']:
        with _RESULT_LOCK:
            _RESULTS[cache_key] = deepcopy(outcome)
            while len(_RESULTS) > 4096:
                _RESULTS.popitem(last=False)
    return outcome
