"""Opt-in, transient application-message sampling. Root must install proposed hooks.

No raw response, payload, metadata, cursor or authentication header is cached.
Only detection runs; the API is read-only and credentials are never verified.
"""
from peaso.secret_evidence import scan_with_source
import json
import re
import time
from datetime import datetime, timedelta, timezone

from peaso.secret_scanning import scan_content, merge_leaks, prepared_content_batch

KIND = 'log_secret_sample'
OPERATION = 'application-log-secret-sample'
SCHEMA = 'gcp-application-log-secret-sample-v1'
URL = 'https://logging.googleapis.com/v2/entries:list'
# The 15-minute window is read to the end rather than sampled: each page is
# scanned and released before the next one is requested. These bounds only
# stop pathological projects; when one cuts the window the result stays
# incomplete (UNKNOWN), otherwise a fully read window is a real PASS/FAIL.
MAX_PAGE_BYTES = 16 * 1024 * 1024
MAX_MESSAGE_BYTES = 65536
MAX_SAMPLE_BYTES = 64 * 1024 * 1024
MAX_ENTRIES = 20000
MAX_PAGES = 100
PAGE_SIZE = 500
MAX_SECONDS = 600
SCOPE = re.compile(r'projects/(?:[a-z][a-z0-9-]{0,62}|[0-9]{1,20})')
PATH = re.compile(r'page/[1-9][0-9]{0,2}/message/[1-9][0-9]{0,2}/(?:textPayload|jsonPayload)|page/[1-9][0-9]{0,2}/empty')


def enabled(options):
    return (options.get('content_secret_scans') is True
            and isinstance(options.get('_content_secret_scan_kinds'), list)
            and KIND in options.get('_content_secret_scan_kinds', []))


def stamp(value):
    if not isinstance(value, str) or len(value) > 40:
        raise ValueError('timestamp')
    dt = datetime.fromisoformat(value.replace('Z', '+00:00'))
    if dt.tzinfo is None or dt.utcoffset() != timedelta(0):
        raise ValueError('timestamp')
    return dt


def body_for(scope, start, end, token=None, size=PAGE_SIZE):
    body = {'resourceNames': [scope], 'orderBy': 'timestamp desc', 'pageSize': size,
            'filter': f'timestamp >= "{start}" AND timestamp <= "{end}" AND (textPayload:* OR jsonPayload:*) AND NOT logName:"cloudaudit.googleapis.com"'}
    if token is not None:
        body['pageToken'] = token
    return body


def validate(method, url, params, body, scope):
    if (method != 'POST' or url != URL or params not in (None, {}) or not isinstance(scope, str)
            or not SCOPE.fullmatch(scope) or not isinstance(body, dict)
            or set(body) - {'resourceNames', 'filter', 'orderBy', 'pageSize', 'pageToken'}
            or type(body.get('pageSize')) is not int or not 1 <= body['pageSize'] <= PAGE_SIZE):
        raise ValueError('unbound request')
    match = re.fullmatch(r'timestamp >= "([^"]+)" AND timestamp <= "([^"]+)" AND \(textPayload:\* OR jsonPayload:\*\) AND NOT logName:"cloudaudit.googleapis.com"', body.get('filter', ''))
    if not match:
        raise ValueError('query')
    start, end = match.groups()
    first, last = stamp(start), stamp(end)
    if not timedelta(0) < last - first <= timedelta(hours=1) or last > datetime.now(timezone.utc):
        raise ValueError('window')
    token = body.get('pageToken')
    if token is not None and (not isinstance(token, str) or not token or len(token.encode()) > 4096):
        raise ValueError('cursor')
    if body != body_for(scope, start, end, token, body['pageSize']):
        raise ValueError('query')
    return first, last


def _json_shape(value, depth=0, budget=None):
    budget = [2048] if budget is None else budget
    budget[0] -= 1
    if depth > 12 or budget[0] < 0:
        raise ValueError('json bound')
    if isinstance(value, dict):
        for key, child in value.items():
            if not isinstance(key, str):
                raise ValueError('json key')
            _json_shape(child, depth + 1, budget)
    elif isinstance(value, list):
        for child in value:
            _json_shape(child, depth + 1, budget)
    elif value is not None and type(value) not in (str, bool, int, float):
        raise ValueError('json scalar')


def project_page(data, *, scope, first, last, page_size, page_number, check_cancelled, deadline=None,
                 remaining_bytes=MAX_SAMPLE_BYTES, remaining_entries=MAX_ENTRIES):
    """Consume native values in memory and return only a strict redacted protocol."""
    result = {'schema': SCHEMA, 'complete': False, 'entries': 0, 'bytes': 0, 'scans': [], 'leaks': []}
    cursor = None
    deadline = time.monotonic() + MAX_SECONDS if deadline is None else deadline
    try:
        if not isinstance(data, dict) or set(data) - {'entries', 'nextPageToken'}:
            raise ValueError('response shape')
        rows = data.get('entries', [])
        cursor = data.get('nextPageToken')
        if cursor is not None and (not isinstance(cursor, str) or not cursor or len(cursor.encode()) > 4096):
            raise ValueError('cursor')
        if not isinstance(rows, list) or len(rows) > min(page_size, remaining_entries):
            raise ValueError('entry bound')
        payloads = []
        for number, row in enumerate(rows, 1):
            if not isinstance(row, dict):
                raise ValueError('entry')
            name = row.get('logName')
            if (not isinstance(name, str) or not name.startswith(scope + '/logs/')
                    or 'cloudaudit.googleapis.com' in name or not first <= stamp(row.get('timestamp')) <= last):
                raise ValueError('unbound entry')
            if (not re.fullmatch(r'(?:[A-Za-z0-9_.-]|%[a-fA-F0-9]{2}){1,1536}', name[len(scope + '/logs/'):])
                    or 'split' in row or not isinstance(row.get('resource'), dict)
                    or not isinstance(row['resource'].get('type'), str) or not row['resource']['type']
                    or not isinstance(row['resource'].get('labels', {}), dict)):
                raise ValueError('incomplete or malformed entry')
            # Routed/aliased subjects are deliberately not inferred from labels.
            project = row.get('resource', {}).get('labels', {}).get('project_id')
            if project is not None and project != scope.split('/')[1]:
                raise ValueError('foreign subject')
            keys = set(row) & {'textPayload', 'jsonPayload', 'protoPayload'}
            if len(keys) != 1 or 'protoPayload' in keys:
                raise ValueError('unsupported payload')
            surface = next(iter(keys))
            value = row[surface]
            if surface == 'textPayload':
                if not isinstance(value, str):
                    raise ValueError('text')
                payload = value.encode('utf-8')
            else:
                if not isinstance(value, dict):
                    raise ValueError('json')
                _json_shape(value)
                payload = json.dumps(value, ensure_ascii=False, allow_nan=False, separators=(',', ':')).encode('utf-8')
            if len(payload) > MAX_MESSAGE_BYTES:
                raise ValueError('message bound')
            payloads.append((f'page/{page_number}/message/{number}/{surface}', payload, {'resource_id': name, 'scope': scope, 'source': json.dumps({k: row[k] for k in ('logName', 'timestamp', 'insertId') if k in row}), 'location_kind': 'log'}))
        if sum(len(payload) for _, payload, _ in payloads) > remaining_bytes:
            raise ValueError('sample byte bound')
        result['entries'] = len(rows)
        if not payloads:
            payloads = [(f'page/{page_number}/empty', b'', {})]
        check_cancelled()
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError('scan deadline')
        # Every validated message still enters the normal scanner with its
        # original source context. Only offline TruffleHog startup is shared.
        with prepared_content_batch([(payload, path) for path, payload, _ in payloads],
                                    timeout=min(10, remaining / 2)):
            for path, payload, source in payloads:
                check_cancelled()
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError('scan deadline')
                scan = scan_with_source(scan_content, payload, path, source=source, timeout=min(10, remaining / 2))
                result['bytes'] += len(payload)
                result['scans'].append({'path': path, 'complete': scan['complete'], 'engines': scan['engines']})
                result['leaks'] = merge_leaks(result['leaks'] + scan['leaks'])
                if len(result['leaks']) > 256 or sum(len(x['locations']) for x in result['leaks']) > 512:
                    raise ValueError('result bound')
        result['complete'] = all(s['complete'] is True for s in result['scans'])
    except Exception:
        # Never interpolate engine, HTTP, JSON, payload or cancellation errors.
        result['complete'] = False
    return result, cursor


def read_page(transport, method, url, *, params=None, body=None, scope=None):
    """Isolated pre-cache HTTP branch; root installs it before generic request logic."""
    from .gcp import ReadError
    response = None
    evidence, rid, failure_status = None, None, 'unavailable'
    try:
        first, last = validate(method, url, params, body, scope)
        if (not enabled(transport.options)
                or scope not in getattr(transport, '_log_secret_authorized_projects', set())):
            raise ValueError('disabled')
        transport.check_cancelled()
        page_number = getattr(transport, '_log_secret_page', {}).get(scope, 0) + 1
        if page_number > MAX_PAGES:
            raise ValueError('page limit')
        with transport.lock:
            if transport.max_calls is not None and transport.calls >= transport.max_calls:
                raise ValueError('call limit')
            transport.calls += 1
            if not hasattr(transport, '_log_secret_page'):
                transport._log_secret_page = {}
                transport._log_secret_deadlines = {}
                transport._log_secret_bytes = {}
                transport._log_secret_entries = {}
            deadline = transport._log_secret_deadlines.setdefault(scope, time.monotonic() + MAX_SECONDS)
            if time.monotonic() >= deadline:
                raise ValueError('sample deadline')
            transport._log_secret_page[scope] = page_number
            rid = 'request-' + str(len(transport.evidence) + 1)
            evidence = {'id': rid, 'scope': scope, 'method': method, 'url': URL,
                        'operation': OPERATION, 'status': 'incomplete',
                        'request': {k: v for k, v in body.items() if k != 'pageToken'}}
            transport.evidence.append(evidence)
        headers = dict(transport.credentials.headers())
        headers['Accept-Encoding'] = 'identity'
        from .gcp import native_header_session
        response = native_header_session(transport).request(method, URL, json=body, params=None,
            headers=headers, timeout=min(transport.timeout, max(.01, min(1, deadline - time.monotonic()))),
            allow_redirects=False, stream=True)
        evidence['http_status'] = response.status_code
        if response.status_code != 200:
            failure_status = 'denied' if response.status_code in (401, 403) else 'unavailable'
            evidence['status'] = failure_status
            raise ReadError('denied' if response.status_code in (401, 403) else 'unavailable', 'log_sample_http_failed')
        response_headers = {key.lower(): value for key, value in response.headers.items()}
        if response_headers.get('content-encoding', 'identity').strip().lower() != 'identity':
            raise ValueError('encoded response unsupported')
        length = response_headers.get('content-length')
        transfer = response_headers.get('transfer-encoding')
        if length is not None:
            if (transfer is not None or not isinstance(length, str)
                    or not re.fullmatch(r'[0-9]{1,9}', length) or int(length) > MAX_PAGE_BYTES):
                raise ValueError('response length')
            length = int(length)
        elif not isinstance(transfer, str) or transfer.strip().lower() != 'chunked':
            # Requests enforces chunk framing; unframed close-delimited responses
            # cannot prove that even syntactically valid JSON was not truncated.
            raise ValueError('response framing unavailable')
        raw = bytearray()
        for chunk in response.iter_content(chunk_size=16384):
            transport.check_cancelled()
            if time.monotonic() >= deadline or len(raw) + len(chunk) > MAX_PAGE_BYTES:
                raise ValueError('response limit')
            raw.extend(chunk)
        if length is not None and len(raw) != length:
            raise ValueError('response length mismatch')
        # Reject duplicate JSON keys and non-finite numbers rather than hide content.
        def pairs(values):
            out = {}
            for key, value in values:
                if key in out:
                    raise ValueError('duplicate JSON key')
                out[key] = value
            return out
        data = json.loads(raw, object_pairs_hook=pairs, parse_constant=lambda _: (_ for _ in ()).throw(ValueError('number')))
        del raw
        projected, cursor = project_page(data, scope=scope, first=first, last=last,
            page_size=body['pageSize'], page_number=page_number, check_cancelled=transport.check_cancelled,
            deadline=deadline, remaining_bytes=MAX_SAMPLE_BYTES - transport._log_secret_bytes.get(scope, 0),
            remaining_entries=MAX_ENTRIES - transport._log_secret_entries.get(scope, 0))
        del data
        transport._log_secret_bytes[scope] = transport._log_secret_bytes.get(scope, 0) + projected['bytes']
        transport._log_secret_entries[scope] = transport._log_secret_entries.get(scope, 0) + projected['entries']
        transport.check_cancelled()
        if time.monotonic() >= deadline:
            projected['complete'] = False
        evidence['status'] = 'collected' if projected['complete'] else 'incomplete'
        return {'page': projected, 'nextPageToken': cursor}, rid
    except Exception:
        error = ReadError(failure_status, 'log_sample_unavailable')
        if rid is not None:
            error.request_id = rid
        raise error from None
    finally:
        if response is not None:
            try:
                response.close()
            except Exception:
                pass


def scope_jobs(collector, scope):
    if KIND not in collector.needed:
        return []
    def fetch():
        from .gcp import ReadError
        if (not enabled(collector.options) or not SCOPE.fullmatch(scope)
                or scope not in collector.scopes):
            raise ReadError('unavailable', 'log_sample_not_enabled')
        with collector.transport.lock:
            if not hasattr(collector.transport, '_log_secret_authorized_projects'):
                collector.transport._log_secret_authorized_projects = set()
            collector.transport._log_secret_authorized_projects.add(scope)
        end = stamp(collector.read_time)
        start = end - timedelta(minutes=15)
        first, last = start.isoformat(), end.isoformat()
        marker = {'schema': SCHEMA, 'scope': scope, 'start': first, 'end': last,
                  'complete': False, 'entries': 0, 'bytes': 0, 'pages': 0, 'scans': [],
                  'leaks': [], 'verification': 'not_attempted'}
        item = {'name': scope + '/logSecretSamples/' + end.strftime('%Y%m%dT%H%M%S'), 'sample': marker}
        tokens, token, refs = set(), None, []
        deadline = time.monotonic() + MAX_SECONDS
        for _ in range(MAX_PAGES):
            data, rid = collector.read(URL, scope, method='POST', operation=OPERATION,
                body=body_for(scope, first, last, token))
            refs.append(rid)
            yield [], rid
            page = data['page']
            marker['pages'] += 1
            marker['entries'] += page['entries']
            marker['bytes'] += page['bytes']
            marker['scans'].extend(page['scans'])
            marker['leaks'] = merge_leaks(marker['leaks'] + page['leaks'])
            token = data['nextPageToken']
            if (not page['complete'] or marker['bytes'] > MAX_SAMPLE_BYTES or time.monotonic() > deadline
                    or len(marker['leaks']) > 256 or sum(len(x['locations']) for x in marker['leaks']) > 512):
                break
            if token is None:
                marker['complete'] = True
                break
            if token in tokens or marker['entries'] >= MAX_ENTRIES:
                break
            tokens.add(token)
        # Retain source receipts even if a later page cannot be read.
        item['_coverage'] = {'sample': {'status': 'collected', 'source_requests': refs}}
        yield [item], refs[-1]
    return [(KIND, scope, 'logging.googleapis.com', fetch)]
