"""Offline dual-engine content detection and value-level, redacted correlation.

Only the collector process retains the random HMAC key. It links occurrences
within that collection and cannot link separate scans. An explicit collector
sink can retain encrypted private matches separately from this public result.
"""
from copy import deepcopy
from functools import lru_cache
from collections import OrderedDict
from concurrent.futures import Future, ThreadPoolExecutor
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
_LOCK = threading.Lock()
_RESULT_LOCK = threading.Lock()
_RESULTS = OrderedDict()
MAX_INPUT = 64 * 1024 * 1024
MAX_OUTPUT = 4 * 1024 * 1024
MAX_FINDINGS = 5000


def _after_fork():
    global _KEY, _LOCK, _RESULT_LOCK, _RESULTS
    _KEY, _LOCK = secrets.token_bytes(32), threading.Lock()
    _RESULT_LOCK, _RESULTS = threading.Lock(), OrderedDict()
    _kingfisher.cache_clear()


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


def _run(argv, payload, timeout):
    """Bound stdin, output and lifetime; discard tool stderr, including secrets."""
    environment = {'PATH': os.defpath, 'HOME': '/nonexistent', 'NO_COLOR': '1',
                   'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': os.devnull}
    process = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                               stderr=subprocess.DEVNULL, env=environment,
                               start_new_session=True)
    output, offset = bytearray(), 0
    deadline = time.monotonic() + timeout
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
                    raise TimeoutError('scanner deadline')
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
                                raise ValueError('scanner output bound')
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


@lru_cache(maxsize=1)
def _trufflehog():
    executable = shutil.which('trufflehog')
    if executable is None:
        raise RuntimeError('scanner unavailable')
    version = _run([executable, '--version'], b'', 5).decode('utf-8').strip()
    if version != 'trufflehog ' + TRUFFLEHOG_VERSION:
        raise RuntimeError('unsupported scanner version')
    return executable


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
    """Merge already-redacted observations, including different files/layers."""
    merged, seen = {}, {}
    for row in rows:
        if not isinstance(row, dict) or set(row) != {'fingerprint', 'detectors', 'locations'}:
            raise ValueError('invalid secret observation')
        ident = row['fingerprint']
        if not isinstance(ident, str) or re.fullmatch('[0-9a-f]{64}', ident) is None:
            raise ValueError('invalid secret fingerprint')
        item = merged.setdefault(ident, {'fingerprint': ident, 'detectors': [], 'locations': []})
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
    from .secret_evidence import batched, enabled as private_capture, remember
    # Only clean outcomes are cached. A clean scan has no private side effect,
    # so reuse is exact with or without private evidence capture.
    if cached is not None:
        if _redact_values is not None:
            _redact_values(frozenset())
        return deepcopy(cached)
    observations, engines, matches_by_engine, known_values = [], [], [], set()
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
            except Exception:
                kingfisher.set_exception(RuntimeError('scanner unavailable'))
        trufflehog = Future()
        try:
            trufflehog.set_result(_scan_trufflehog(payload, path, timeout))
        except Exception:
            trufflehog.set_exception(RuntimeError('scanner unavailable'))
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
            except Exception:
                # No exception text, matched values, raw JSON or tracebacks escape.
                engines.append({'engine': name, 'version': version, 'status': 'unavailable'})
    # Found values and their exact paths stay visible to the tenant. The
    # callback contract is kept, but there is nothing to redact.
    if _redact_values is not None:
        _redact_values(frozenset())
    fingerprints = {value: _fingerprint(value) for value in known_values}
    capture = private_capture()
    observed = {}
    with batched():
        for name, matches in matches_by_engine:
            for value, rule, line in matches:
                # Retain the actual match/value/line association with its canonical witness.
                if capture and value not in observed:
                    observed[value] = value.encode('utf-8') in payload
                remember(value, fingerprints[value], path=path, public_path=path, line=line, engine=name, rule=_label(rule),
                         observed_bytes=not capture or observed[value])
                observations.append({'fingerprint': fingerprints[value],
                    'detectors': [{'engine': name, 'rule': _label(rule)}],
                    'locations': [{'path': path, **({'line': line} if type(line) is int and line > 0 else {})}]})
    outcome = {'leaks': merge_leaks(observations), 'engines': engines,
               'complete': all(row['status'] == 'complete' for row in engines)}
    # Repeated logs/layers reuse only a complete, clean outcome. It holds no
    # raw content, path, secret or failed result.
    if outcome['complete'] and not outcome['leaks']:
        with _RESULT_LOCK:
            _RESULTS[cache_key] = deepcopy(outcome)
            while len(_RESULTS) > 4096:
                _RESULTS.popitem(last=False)
    return outcome
