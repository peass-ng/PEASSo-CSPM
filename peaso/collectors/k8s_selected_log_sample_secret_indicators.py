"""Unregistered, bounded current-container log sampler; no production hook yet.

The caller must supply the existing authenticated API and bounded reader. The
existing transport deliberately rejects /log; admission needs the exact reviewed
path/query bridge described in the proposal, never a bypass of that transport.
"""

from peaso.secret_evidence import scan_with_source, target_source
from copy import deepcopy
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from functools import wraps
import http.client
import json
import logging
import re
import threading
import time
from urllib.parse import urlsplit, parse_qsl
from uuid import UUID, uuid4

from peaso.secret_scanning import _fingerprint, scan_content, merge_leaks
from . import k8s_literal_secret_indicators as literals

KIND = 'k8s_selected_log_samples'
CHECK = 'k8s.review.selected_container_logs.secret_indicators'
OPTION = 'selected_k8s_log_samples'
MARKER = 'SelectedKubernetesLogSampleSecretIndicators'
SCHEMA = 'k8s-selected-current-container-log-sample-v1'
MAX_LOG = 256 * 1024
MAX_POD = 2 * 1024 * 1024
MAX_TOTAL = 18 * 1024 * 1024  # Four targets, two bounded Pod reads and one log each.
MAX_SECONDS = 60
MAX_CALLS = 12
TAIL_LINES = 100
WINDOW_SECONDS = 3600
MAX_LEAKS = 256
MAX_LOCATIONS = 512
_LABEL = re.compile(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z')
_POD = re.compile(r'[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?\Z')
_TIME = re.compile(r'(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(?:\.(\d{1,9}))?(Z|[+-]\d\d:\d\d)\Z')


class Incomplete(ValueError):
    """Only fixed internal reasons, never response/error text."""


@contextmanager
def private_native_logs():
    """Suppress this read's SDK/urllib3 records, preserving other logging.

    No logger levels, handlers, process streams or global wire-debug settings
    are changed. Low-level http.client printing cannot be filtered and is
    separately rejected before I/O by _context.
    """
    owner = threading.get_ident()
    prefixes = ('kubernetes', 'urllib3', 'client')
    seeds = ('kubernetes.client.rest', 'kubernetes.client.api_client', 'client',
        'urllib3.connectionpool', 'urllib3.connection', 'urllib3.poolmanager', 'urllib3.util.retry')
    for name in seeds:
        logging.getLogger(name)
    loggers = [logging.getLogger(name) for name in list(logging.root.manager.loggerDict)
        if name.split('.')[0] in prefixes]
    handlers = set(logging.getLogger().handlers)
    for logger in loggers:
        handlers.update(logger.handlers)
    class Private(logging.Filter):
        def filter(self, record):
            return record.thread != owner or record.name.split('.')[0] not in prefixes
    guard = Private()
    for logger in loggers:
        logger.addFilter(guard)
    for handler in handlers:
        handler.addFilter(guard)
    try:
        yield
    finally:
        for logger in loggers:
            logger.removeFilter(guard)
        for handler in handlers:
            handler.removeFilter(guard)


def _private_read(function):
    @wraps(function)
    def wrapped(*args, **kwargs):
        with private_native_logs():
            return function(*args, **kwargs)
    return wrapped


def _wire_debug_enabled(manager):
    from urllib3.connection import HTTPConnection, HTTPSConnection
    if any(getattr(cls, 'debuglevel', 0) for cls in (
            http.client.HTTPConnection, http.client.HTTPSConnection, HTTPConnection, HTTPSConnection)):
        return True
    if getattr(manager, 'connection_pool_kw', {}).get('debuglevel'):
        return True
    pools = getattr(manager, 'pools', None)
    if pools is not None:
        with pools.lock:
            existing = list(pools._container.values())
        for connection_pool in existing:
            if getattr(connection_pool.ConnectionCls, 'debuglevel', 0):
                return True
            queue = getattr(connection_pool, 'pool', None)
            if queue is not None:
                with queue.mutex:
                    if any(getattr(connection, 'debuglevel', 0) for connection in queue.queue if connection is not None):
                        return True
    return False


def enabled(options):
    kinds = options.get('_content_secret_scan_kinds', [])
    return options.get('content_secret_scans') is True and isinstance(kinds, list) and KIND in kinds


def selected_targets(options, scopes):
    if 'content_secret_scans' in options and type(options['content_secret_scans']) is not bool:
        raise ValueError('content_secret_scans must be boolean')
    values = options.get(OPTION)
    if values is None and not enabled(options):
        return []
    if (not isinstance(scopes, list) or not 1 <= len(scopes) <= 4
            or any(not isinstance(s, str) or not _LABEL.fullmatch(s) for s in scopes)
            or len(set(scopes)) != len(scopes)
            or not isinstance(values, list) or not 1 <= len(values) <= 4):
        raise ValueError('log samples require 1–4 exact targets in explicit namespace scopes')
    seen, clusters = set(), set()
    for target in values:
        if not isinstance(target, dict) or set(target) != {'cluster_id', 'namespace', 'pod', 'container'}:
            raise ValueError('log sample selector must contain only cluster_id/namespace/pod/container')
        cluster, namespace, pod, container = (target[k] for k in ('cluster_id', 'namespace', 'pod', 'container'))
        if (not isinstance(cluster, str) or not 1 <= len(cluster) <= 512 or not cluster.isascii()
                or any(ord(c) < 33 or ord(c) > 126 for c in cluster)
                or not isinstance(namespace, str) or not _LABEL.fullmatch(namespace) or namespace not in scopes
                or not isinstance(pod, str) or not _POD.fullmatch(pod)
                or any(not _LABEL.fullmatch(label) for label in pod.split('.'))
                or not isinstance(container, str) or not _LABEL.fullmatch(container)):
            raise ValueError('invalid exact log sample selector or namespace scope')
        key = (cluster, namespace, pod, container)
        if key in seen:
            raise ValueError('duplicate log sample selector')
        seen.add(key)
        clusters.add(cluster)
    if len(clusters) != 1:
        raise ValueError('log sample targets must share one requested cluster')
    return deepcopy(values)


def identity(target):
    return KIND + ':' + _fingerprint(json.dumps(target, sort_keys=True, separators=(',', ':')))


def timestamp_ns(value):
    """RFC3339(Nano), retaining nanosecond bounds without float rounding."""
    if not isinstance(value, str) or (match := _TIME.fullmatch(value)) is None:
        raise Incomplete('invalid_timestamp')
    base, fraction, offset = match.groups()
    if offset != 'Z' and (int(offset[1:3]) > 23 or int(offset[4:]) > 59):
        raise Incomplete('invalid_timestamp')
    try:
        parsed = datetime.fromisoformat(base + ('+00:00' if offset == 'Z' else offset))
        epoch = parsed.astimezone(timezone.utc) - datetime(1970, 1, 1, tzinfo=timezone.utc)
    except ValueError:
        raise Incomplete('invalid_timestamp') from None
    return (epoch.days * 86400 + epoch.seconds) * 1_000_000_000 + int((fraction or '').ljust(9, '0'))


def request_spec(target, window_start):
    """Exact future transport allowlist; callers cannot add query options."""
    timestamp_ns(window_start)
    pod = '/api/v1/namespaces/' + target['namespace'] + '/pods/' + target['pod']
    return pod, pod + '/log', {
        'container': target['container'], 'follow': 'false', 'previous': 'false',
        'sinceTime': window_start, 'tailLines': str(TAIL_LINES),
        'limitBytes': str(MAX_LOG), 'timestamps': 'true',
        'insecureSkipTLSVerifyBackend': 'false',
    }


def allowed_request(path, query, grants):
    """Narrow proposal for the existing origin gate; grants are runtime-only.

    This does not authenticate or authorize a URL. The existing _BoundedPool
    checks method/origin/body/redirects first; only its path/query clause may
    consult this helper with the producer's exact in-memory request tuples.
    """
    try:
        pairs = parse_qsl(query, keep_blank_values=True, strict_parsing=True)
        if len({k for k, _ in pairs}) != len(pairs):
            return False
        return (path, tuple(sorted(pairs))) in grants
    except (ValueError, TypeError):
        return False


def _remaining(reader, state):
    reader.check_cancelled()
    remaining = state['deadline'] - time.monotonic()
    if remaining <= 0:
        raise Incomplete('deadline_exceeded')
    return min(remaining, 10)


def _context(api, cluster):
    from .k8s import _BoundedPool
    client = getattr(getattr(api, 'api', api), 'api_client', None)
    configuration = getattr(client, 'configuration', None)
    pool = getattr(getattr(client, 'rest_client', None), 'pool_manager', None)
    host = getattr(configuration, 'host', None)
    if (not isinstance(pool, _BoundedPool) or not pool.server or not isinstance(host, str)
            or urlsplit(host) != pool.server or pool.server.scheme != 'https'
            or pool.server.username is not None or pool.server.password is not None
            or pool.server.query or pool.server.fragment or configuration.verify_ssl is not True
            or not callable(getattr(client, 'update_params_for_auth', None))):
        raise Incomplete('authenticated_bounded_transport_required')
    if configuration.debug or _wire_debug_enabled(pool.pool):
        raise Incomplete('unsafe_native_wire_debug')
    headers = dict(getattr(client, 'default_headers', {}) or {})
    query = []
    client.update_params_for_auth(headers, query, ['BearerToken'])
    authorization = next((v for k, v in headers.items() if k.lower() == 'authorization'), None)
    mutual_tls = bool(getattr(configuration, 'cert_file', None) and getattr(configuration, 'key_file', None))
    if query or (not mutual_tls and (not isinstance(authorization, str) or not authorization.strip())):
        raise Incomplete('authenticated_bounded_transport_required')
    binding = _fingerprint(json.dumps([host, cluster, authorization,
        getattr(configuration, 'cert_file', None), getattr(configuration, 'key_file', None)]))
    return client, pool, host, headers, binding


@_private_read
def _read(reader, api, cluster, path, fields, state, *, log=False):
    client, pool, host, headers, binding = _context(api, cluster)
    if state.get('context') not in (None, binding):
        raise Incomplete('authentication_context_changed')
    state['context'] = binding
    # GKE rejects a text-only Accept header for Pod logs, then emits plaintext
    # after wildcard negotiation. The response media type is checked below.
    headers.update({'Accept': '*/*' if log else 'application/json', 'Accept-Encoding': 'identity'})
    maximum = MAX_LOG if log else MAX_POD
    response = None
    try:
        def native_request():
            if state['calls'] >= MAX_CALLS:
                raise Incomplete('native_call_limit')
            state['calls'] += 1
            try:
                return pool.request('GET', host.rstrip('/') + path, headers=headers, fields=fields,
                    preload_content=False, decode_content=False, timeout=_remaining(reader, state))
            except Exception:
                raise Incomplete('native_transport_unavailable') from None
        response = reader.call(native_request)
        if type(getattr(response, 'status', None)) is not int or response.status != 200:
            raise Incomplete('native_get_denied' if getattr(response, 'status', None) in (401, 403) else 'native_get_unavailable')
        media = response.headers.get('Content-Type', '').lower().replace(' ', '')
        if (response.headers.get('Content-Encoding', 'identity') != 'identity'
                or response.headers.get('Content-Range') is not None
                or media not in (('text/plain', 'text/plain;charset=utf-8') if log else ('application/json', 'application/json;charset=utf-8'))):
            raise Incomplete('unsupported_native_response')
        length = response.headers.get('Content-Length')
        if length is not None and (not isinstance(length, str) or not length.isascii() or not length.isdecimal()
                or len(length) > 10 or not 1 <= int(length) <= maximum):
            raise Incomplete('native_byte_limit')
        chunks, count = [], 0
        while True:
            _remaining(reader, state)
            chunk = response.read(min(16384, maximum + 1 - count))
            if not isinstance(chunk, bytes):
                raise Incomplete('malformed_native_stream')
            if not chunk:
                break
            count += len(chunk)
            state['bytes'] += len(chunk)
            if count > maximum or state['bytes'] > MAX_TOTAL:
                raise Incomplete('native_byte_limit')
            chunks.append(chunk)
        _remaining(reader, state)
        if not count or length is not None and count != int(length):
            raise Incomplete('empty_or_truncated_native_response')
        raw = b''.join(chunks)
        if log:
            return raw, count, binding
        try:
            value = json.loads(raw.decode('utf-8'), object_pairs_hook=literals._pairs,
                parse_constant=lambda _: (_ for _ in ()).throw(Incomplete('invalid_json_constant')))
        except (ValueError, UnicodeError, RecursionError):
            raise Incomplete('malformed_native_pod') from None
        return value, count, binding
    finally:
        if response is not None:
            try:
                response.close()
            finally:
                response.release_conn()
        if client is not None:
            client.last_response = None


def _pod_identity(value, target, end):
    """Only typed identity/status is retained, never Pod annotations or literals."""
    try:
        if (not isinstance(value, dict) or value.get('apiVersion') != 'v1' or value.get('kind') != 'Pod'
                or any(k in value for k in ('_partial', '_coverage', '_representation'))):
            raise Incomplete('unbound_native_pod')
        meta, spec, status = value['metadata'], value['spec'], value['status']
        if (meta['namespace'] != target['namespace'] or meta['name'] != target['pod']
                or meta.get('deletionTimestamp') is not None):
            raise Incomplete('unbound_native_pod')
        if not isinstance(spec['containers'], list) or not 1 <= len(spec['containers']) <= 256:
            raise Incomplete('malformed_native_pod')
        uid, version = meta['uid'], meta['resourceVersion']
        if (not isinstance(uid, str) or str(UUID(uid)) != uid or not isinstance(version, str)
                or not 1 <= len(version) <= 128 or not version.isascii()
                or any(ord(c) < 33 or ord(c) > 126 for c in version)):
            raise Incomplete('unbound_native_pod')
        created = timestamp_ns(meta['creationTimestamp'])
        matches, seen = [], set()
        for field, statuses in (('containers', 'containerStatuses'), ('initContainers', 'initContainerStatuses'),
                ('ephemeralContainers', 'ephemeralContainerStatuses')):
            containers = spec.get(field, [])
            if not isinstance(containers, list) or len(containers) > 256:
                raise Incomplete('malformed_native_container')
            for container in containers:
                name = container['name']
                if not isinstance(name, str) or not _LABEL.fullmatch(name) or name in seen:
                    raise Incomplete('ambiguous_native_container')
                seen.add(name)
                if name == target['container']:
                    entries = status[statuses]
                    if not isinstance(entries, list) or len(entries) > 256:
                        raise Incomplete('malformed_native_container')
                    entry, = [s for s in entries if s['name'] == name]
                    matches.append((field, entry))
        family, entry = matches[0] if len(matches) == 1 else (None, None)
        if entry is None:
            raise Incomplete('unbound_native_container')
        restart, container_id, state = entry['restartCount'], entry['containerID'], entry['state']
        if (type(restart) is not int or not 0 <= restart <= 2147483647 or not isinstance(container_id, str)
                or not 1 <= len(container_id) <= 512
                or not re.fullmatch(r'[a-z0-9][a-z0-9+.-]*://[A-Za-z0-9_.:-]+', container_id)
                or not isinstance(state, dict) or len(state) != 1):
            raise Incomplete('unbound_native_container')
        running = 'running' in state
        detail = state.get('running' if running else 'terminated')
        started = timestamp_ns(detail['startedAt'])
        finished = None if running else timestamp_ns(detail['finishedAt'])
        if (not created <= started <= end or finished is not None and not started <= finished <= end
                or not running and (type(detail.get('exitCode')) is not int
                    or detail.get('containerID', container_id) != container_id)):
            raise Incomplete('incoherent_container_time')
        return uid, version, family, restart, container_id, started, finished
    except (KeyError, TypeError, ValueError, AttributeError, IndexError):
        raise Incomplete('unbound_native_pod_or_container') from None


def _sample(raw, before, start, end):
    if len(raw) >= MAX_LOG or not raw.endswith(b'\n'):
        raise Incomplete('possibly_truncated_log_sample')
    try:
        text = raw.decode('utf-8')
    except UnicodeError:
        raise Incomplete('unsupported_log_encoding') from None
    if any(ord(c) < 32 and c not in '\t\r\n' for c in text):
        raise Incomplete('unsupported_log_encoding')
    lines = text.splitlines()
    if not 1 <= len(lines) <= TAIL_LINES:
        raise Incomplete('invalid_sample_line_count')
    timestamps, messages = [], []
    for line in lines:
        stamp, separator, message = line.partition(' ')
        observed = timestamp_ns(stamp)
        if (not separator or not message or not max(start, before[5]) <= observed <= end
                or before[6] is not None and observed > before[6]):
            raise Incomplete('unbound_log_sample_time')
        timestamps.append(observed)
        messages.append(message)
    return ('\n'.join(messages) + '\n').encode(), len(lines), min(timestamps), max(timestamps)


def collect(reader, api, options, scopes, cluster):
    """Return redacted indicators and an ephemeral union-redaction value ledger."""
    targets = selected_targets(options, scopes)
    authorized = enabled(options)
    now = datetime.now(timezone.utc)
    end = now.isoformat().replace('+00:00', 'Z')
    start = (now - timedelta(seconds=WINDOW_SECONDS)).isoformat().replace('+00:00', 'Z')
    capture = 'k8s-log-capture:' + str(uuid4())
    metadata = {KIND + '_authorized': authorized, KIND + '_selection': {
        scope: [identity(t) for t in targets if t['namespace'] == scope] for scope in scopes},
        KIND + '_receipts': [], KIND + '_capture': capture, KIND + '_window': [start, end],
        KIND + '_cluster_binding': _fingerprint(cluster or '')}
    matches = set()
    state = {'calls': 0, 'bytes': 0, 'deadline': time.monotonic() + MAX_SECONDS}
    client = getattr(getattr(api, 'api', api), 'api_client', None)
    pool = getattr(getattr(client, 'rest_client', None), 'pool_manager', None)
    prior_paths = getattr(pool, 'literal_paths', None)
    prior_grants = getattr(pool, 'selected_log_requests', frozenset())
    try:
        if prior_paths is not None and authorized:
            pool.literal_paths = frozenset(prior_paths) | frozenset(request_spec(t, start)[0] for t in targets)
            pool.selected_log_requests = frozenset((request_spec(t, start)[1], tuple(sorted(request_spec(t, start)[2].items()))) for t in targets)
        for scope in scopes:
            items = []
            for target in (t for t in targets if t['namespace'] == scope):
                ident = identity(target)
                marker = {'schema': SCHEMA, 'identity': ident, 'capture': capture, 'scope': scope,
                    'cluster_binding': metadata[KIND + '_cluster_binding'], 'complete': False,
                    'native_bound': False, 'reason': 'not_authorized', 'verification': 'not_attempted',
                    'source_requests': [], 'parts': [], 'leaks': [], 'lines': 0, 'sample_bytes': 0,
                    'first_ns': None, 'last_ns': None, 'uid_binding': None, 'version_binding': None,
                    'container_binding': None, 'context_binding': None}
                if authorized:
                    try:
                        if target['cluster_id'] != cluster:
                            raise Incomplete('cluster_identity_mismatch')
                        if reader.budget.max_items is not None and reader.total + len(items) >= reader.budget.max_items:
                            raise Incomplete('resource_limit')
                        pod_path, log_path, fields = request_spec(target, start)
                        first, n1, context = _read(reader, api, cluster, pod_path, {}, state)
                        before = _pod_identity(first, target, timestamp_ns(end))
                        raw, n2, log_context = _read(reader, api, cluster, log_path, fields, state, log=True)
                        payload, lines, earliest, latest = _sample(raw, before, timestamp_ns(start), timestamp_ns(end))
                        # Also inspect the ephemeral selected identity text so detected
                        # values repeated in other metadata are included in the union.
                        identity_bytes = json.dumps([target, before[:5]], ensure_ascii=True).encode()
                        payload += b'\n' + identity_bytes
                        outcome = scan_with_source(scan_content, payload, ident + '.log_sample',
                            timeout=max(0.001, _remaining(reader, state) / 2), _redact_values=matches.update, source=target_source(target, resource_id=ident, scope=scope, location_kind='log'))
                        _remaining(reader, state)
                        last, n3, last_context = _read(reader, api, cluster, pod_path, {}, state)
                        after = _pod_identity(last, target, timestamp_ns(end))
                        if before != after or context != log_context or context != last_context:
                            raise Incomplete('pod_or_container_changed')
                        leaks = merge_leaks(outcome['leaks'])
                        if len(leaks) > MAX_LEAKS or sum(len(l['locations']) for l in leaks) > MAX_LOCATIONS:
                            raise Incomplete('finding_limit')
                        refs = []
                        for ordinal, size in enumerate((n1, n2, n3), 1):
                            ref = 'k8s-log-read-' + str(len(metadata[KIND + '_receipts']) + 1)
                            metadata[KIND + '_receipts'].append({'id': ref, 'identity': ident, 'scope': scope,
                                'capture': capture, 'method': 'GET', 'route': 'exact_selected_current_log' if ordinal == 2 else 'exact_selected_pod',
                                'status': 200, 'bytes': size, 'ordinal': ordinal, 'context_binding': context,
                                'request_binding': _fingerprint(json.dumps([pod_path if ordinal != 2 else log_path,
                                    fields if ordinal == 2 else {}], sort_keys=True))})
                            refs.append(ref)
                        marker.update(complete=outcome['complete'], native_bound=True,
                            reason='complete' if outcome['complete'] else 'detectors_incomplete',
                            parts=[{'part': 'log_sample', 'bytes': len(payload), **{k: deepcopy(outcome[k]) for k in ('engines', 'complete')}}],
                            leaks=leaks, source_requests=refs, lines=lines, sample_bytes=n2, first_ns=earliest, last_ns=latest,
                            uid_binding=_fingerprint(before[0]), version_binding=_fingerprint(before[1]),
                            container_binding=_fingerprint(json.dumps(before[2:])), context_binding=context)
                    except Exception as exc:
                        marker['reason'] = str(exc) if type(exc) is Incomplete else 'native_inspection_unavailable'
                items.append({'id': ident, MARKER: marker})
            if items:
                reader.collections.append({'type': KIND, 'scope': scope, 'service': 'kubernetes',
                    'status': 'collected' if all(i[MARKER]['complete'] for i in items) else 'partial', 'items': items})
                reader.total += len(items)
        return metadata, matches
    finally:
        if prior_paths is not None:
            pool.literal_paths = prior_paths
            pool.selected_log_requests = prior_grants
        if client is not None:
            client.last_response = None


def finalize(scopes, collections, metadata, log_matches, literal_matches=None):
    """Future collect hook: union both ledgers BEFORE the existing final scrub."""
    values = set(log_matches) | set(literal_matches or ())
    try:
        return literals.redact_output(scopes, collections, metadata, values)
    finally:
        log_matches.clear()
        if literal_matches is not None:
            literal_matches.clear()
