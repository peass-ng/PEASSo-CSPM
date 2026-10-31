"""Native mock HTTP, real collector envelope, offline pinned detector receipts.

Shared adapter/dedup patterns attributed to test_gcp_function_secret_review_20261019.
No credentials are valid and no cloud or credential validation calls are made.
"""
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from importlib.metadata import version
import inspect
import json
import textwrap
from types import SimpleNamespace

import pytest
import requests
from peaso import secret_scanning as scanning
from peaso.secret_findings import deduplicate_secret_findings
from peaso.collectors import gcp
from peaso.collectors import gcp_log_secret_indicators as native
from peaso.checks import gcp_log_secret_review_20261019 as check

SCOPE = 'projects/review'
TOKEN = 'ghp_' + '7mQ2zR9wL4cV8nK1sF6aH3jP5uD0xB2yE9rT'
AUTH = 'Bearer SYNTHETIC_CALLER_AUTH_NEVER_STORE'
METADATA = 'UNTRUSTED_METADATA_NEVER_STORE'
END = datetime.now(timezone.utc) - timedelta(minutes=1)
START = END - timedelta(minutes=15)


def entry(value='public application status ready', surface='textPayload'):
    return {'logName': SCOPE + '/logs/' + METADATA, 'insertId': METADATA,
            'timestamp': (END - timedelta(minutes=1)).isoformat(),
            'resource': {'type': 'global', 'labels': {'project_id': 'review', 'other': METADATA}},
            surface: value}


@pytest.fixture(autouse=True)
def caches():
    scanning._RESULTS.clear()
    yield
    scanning._RESULTS.clear()


@pytest.fixture
def clean(monkeypatch):
    monkeypatch.setattr(scanning, '_scan_kingfisher', lambda *a: [])
    monkeypatch.setattr(scanning, '_scan_trufflehog', lambda *a: [])


class Response:
    def __init__(self, data, status=200):
        self.content = data if isinstance(data, bytes) else json.dumps(data).encode()
        self.status_code = status
        self.headers = {'Content-Length': str(len(self.content))}
        self.closed = False
    def iter_content(self, chunk_size):
        for i in range(0, len(self.content), chunk_size):
            yield self.content[i:i + chunk_size]
    def close(self):
        self.closed = True


@pytest.fixture
def harness(monkeypatch):
    def collect(pages, *, options=None, status=200, scopes=None, resolved_scopes=None, full_collect=False):
        options = {'inventories': [native.KIND], 'content_secret_scans': True,
                   '_content_secret_scan_kinds': [native.KIND], 'retries': 0, **(options or {})}
        transport = gcp.Transport(SimpleNamespace(headers=lambda: {'Authorization': AUTH}), options)
        responses = [Response(p, status) for p in pages]
        calls = []
        def request(method, url, **kwargs):
            assert kwargs.pop('headers') == {'Authorization': AUTH, 'Accept-Encoding': 'identity'}
            assert kwargs['stream'] is True and kwargs['allow_redirects'] is False
            calls.append({'method': method, 'url': url, **deepcopy(kwargs)})
            return responses[len(calls) - 1]
        monkeypatch.setattr(transport, '_session', lambda: SimpleNamespace(request=request))
        collector = gcp.GCPCollector({'options': options, 'auth': {}, 'scopes': [SCOPE] if scopes is None else scopes}, [native.KIND], transport=transport)
        collector.read_time = END.isoformat()
        if resolved_scopes is not None:
            collector.scopes = resolved_scopes
        if full_collect:
            snapshot = collector.collect()
            envelope = next(c for c in snapshot['collections'] if c['type'] == native.KIND)
        else:
            jobs = native.scope_jobs(collector, SCOPE)
            envelope = collector.envelope(*jobs[0])
        items = envelope['items']
        item = items[0] if items else {}
        index = {'context': {'provider': 'gcp', 'scope': SCOPE}, 'collections': {native.KIND: [envelope]}}
        return SimpleNamespace(item=item, index=index, envelope=envelope, transport=transport,
                               calls=calls, responses=responses, result=check.evaluate(item, index))
    return collect


def test_real_pinned_both_payloads_same_value_dedup_privacy(harness, monkeypatch, capsys):
    assert version('kingfisher-secret-scanner') == scanning.KINGFISHER_VERSION
    assert scanning._trufflehog()
    commands = []
    original = scanning._run
    def run(argv, payload, timeout):
        commands.append(argv)
        return original(argv, payload, timeout)
    monkeypatch.setattr(scanning, '_run', run)
    result = harness([{'entries': [entry('access_token=' + TOKEN)], 'nextPageToken': 'PRIVATE_CURSOR'},
                      {'entries': [entry({'password': TOKEN, 'copy': TOKEN}, 'jsonPayload')]}])
    assert result.result[0] == 'FAIL'
    leaks = result.result[1]['secret_leaks']
    assert len(leaks) == 1
    assert {d['engine'] for d in leaks[0]['detectors']} == {'kingfisher', 'trufflehog'}
    assert {loc['path'] for loc in leaks[0]['locations']} == {'page/1/message/1/textPayload', 'page/2/message/1/jsonPayload'}
    base = {'provider': 'gcp', 'check_id': check.CHECK_ID, 'scope': SCOPE,
            'resource_id': result.item['name'], 'status': 'FAIL', 'evidence': result.result[1]}
    other = dict(base, check_id='other.content.surface', resource_id='another-resource')
    findings = deduplicate_secret_findings([base, other])
    assert len(findings) == 1 and len(findings[0]['linked_check_ids']) == 2
    assert any('stdin' in argv for argv in commands)
    assert all({'--no-verification', '--no-update', '--no-verification-cache'} <= set(argv)
               for argv in commands if 'stdin' in argv)
    persisted = json.dumps([result.envelope, result.result, result.transport.evidence, result.transport.cache, findings]) + repr(scanning._RESULTS) + str(capsys.readouterr())
    assert all(secret not in persisted for secret in (TOKEN, AUTH, METADATA, 'PRIVATE_CURSOR'))
    assert not result.transport.cache and all(r.closed for r in result.responses)


def test_real_pinned_negative_is_sample_only(harness):
    result = harness([{'entries': [entry(), entry({'status': 'ready'}, 'jsonPayload')]}])
    assert result.result[0] == 'PASS'
    assert 'sampled returned' in result.result[1]['observed']
    assert 'other logs or history' in result.result[1]['observed']
    assert all(e['status'] == 'complete' for s in result.item['sample']['scans'] for e in s['engines'])


def test_empty_page_with_cursor_is_not_completion(harness, clean):
    result = harness([{'nextPageToken': 'cursor'}, {'entries': [entry()]}])
    assert result.result[0] == 'PASS' and len(result.calls) == 2
    assert result.item['sample']['entries'] == 1
    assert result.calls[1]['json']['pageToken'] == 'cursor'


def test_empty_sample_requires_both_tools(harness, clean, monkeypatch):
    assert harness([{}]).result[0] == 'PASS'
    scanning._RESULTS.clear()
    def fail(*args):
        raise RuntimeError(TOKEN)
    monkeypatch.setattr(scanning, '_scan_trufflehog', fail)
    assert harness([{}]).result[0] == 'UNKNOWN'


@pytest.mark.parametrize('options', [
    {'content_secret_scans': False},
    {'_content_secret_scan_kinds': []}, {'_content_secret_scan_kinds': ['log_entry']},
])
def test_opt_in_and_named_binding_required_before_auth_or_http(harness, options):
    result = harness([], options=options)
    assert result.result[0] == 'UNKNOWN' and result.calls == []


@pytest.mark.parametrize('value', ['true', 1])
def test_non_boolean_optin_rejected_before_credentials_or_http(monkeypatch, value):
    calls = []
    def forbidden(*args, **kwargs):
        calls.append(True)
        pytest.fail('invalid intake reached credentials or HTTP')
    monkeypatch.setattr(gcp, 'Credentials', forbidden)
    monkeypatch.setattr(gcp.Transport, '_session', forbidden)
    with pytest.raises(ValueError, match='^content_secret_scans must be a boolean$'):
        gcp.GCPCollector({'scopes': [SCOPE], 'options': {'content_secret_scans': value,
            'inventories': [native.KIND], '_content_secret_scan_kinds': [native.KIND]}}, [native.KIND])
    assert calls == []


@pytest.mark.parametrize('case', ['denied', 'server', 'truncated', 'oversize', 'duplicate_json', 'future',
    'foreign', 'numeric_alias', 'audit', 'proto', 'multiple_payloads', 'json_type', 'deep_json',
    'message_bytes', 'page_entries', 'malformed_resource'])
def test_native_unavailable_or_unsafe_never_clean(harness, clean, case):
    row = entry()
    page, status = {'entries': [row]}, 200
    if case == 'denied': page, status = {'error': {'message': TOKEN}}, 403
    if case == 'server': page, status = {'error': {'message': TOKEN}}, 500
    if case == 'truncated': page = ('{"entries":[' + TOKEN).encode()
    if case == 'oversize': page = b'x' * (native.MAX_PAGE_BYTES + 1)
    if case == 'duplicate_json': page = b'{"entries": [], "entries": []}'
    if case == 'future': row['timestamp'] = (END + timedelta(days=1)).isoformat()
    if case == 'foreign': row['logName'] = row['logName'].replace('/review/', '/other/')
    if case == 'numeric_alias': row['resource']['labels']['project_id'] = '123456'
    if case == 'audit': row['logName'] = SCOPE + '/logs/cloudaudit.googleapis.com%2Factivity'
    if case == 'proto': row['protoPayload'] = {}; del row['textPayload']
    if case == 'multiple_payloads': row['jsonPayload'] = {}
    if case == 'json_type': row['jsonPayload'] = []; del row['textPayload']
    if case == 'deep_json':
        value = {}
        for _ in range(15): value = {'nested': value}
        row['jsonPayload'] = value; del row['textPayload']
    if case == 'message_bytes': row['textPayload'] = 'é' * native.MAX_MESSAGE_BYTES
    if case == 'page_entries': page['entries'] = [row] * (native.PAGE_SIZE + 1)
    if case == 'malformed_resource': row['resource'] = []
    result = harness([page], status=status)
    assert result.result[0] == 'UNKNOWN'
    assert TOKEN not in json.dumps([result.envelope, result.transport.evidence, result.transport.cache])
    assert all(r.closed for r in result.responses)


@pytest.mark.parametrize('case', ['repeat', 'pages', 'entries'])
def test_pagination_limits_never_prove_absence(harness, clean, case):
    pages = [{'nextPageToken': 'repeat'}, {'nextPageToken': 'repeat'}]
    if case == 'pages': pages = [{'nextPageToken': str(i)} for i in range(3)]
    if case == 'entries': pages = [{'entries': [entry()] * 50, 'nextPageToken': str(i)} for i in range(2)]
    result = harness(pages)
    assert result.result[0] == 'UNKNOWN'
    assert len(result.calls) <= native.MAX_PAGES


@pytest.mark.parametrize('engine', ['kingfisher', 'trufflehog'])
def test_tool_failure_even_with_positive_other_engine_unknown(harness, monkeypatch, engine):
    monkeypatch.setattr(scanning, '_scan_kingfisher', lambda *a: [(TOKEN, 'synthetic', 1)])
    monkeypatch.setattr(scanning, '_scan_trufflehog', lambda *a: [(TOKEN, 'synthetic', 1)])
    def fail(*a): raise RuntimeError(TOKEN)
    monkeypatch.setattr(scanning, '_scan_' + engine, fail)
    result = harness([{'entries': [entry(TOKEN)]}])
    assert result.result[0] == 'UNKNOWN' and result.item['sample']['leaks']
    assert TOKEN not in json.dumps([result.envelope, result.transport.evidence])


@pytest.mark.parametrize('change', ['scope', 'provider', 'collection', 'duplicate', 'engines', 'counts', 'path', 'future'])
def test_callback_rejects_contradictory_or_unbound_proofs(harness, clean, change):
    result = harness([{'entries': [entry()]}])
    assert result.result[0] == 'PASS'
    if change == 'scope': result.index['context']['scope'] = 'projects/other'
    if change == 'provider': result.index['context']['provider'] = 'aws'
    if change == 'collection': result.envelope['status'] = 'partial'
    if change == 'duplicate': result.envelope['items'].append(deepcopy(result.item))
    if change == 'engines': result.item['sample']['scans'][0]['engines'].pop()
    if change == 'counts': result.item['sample']['entries'] += 1
    if change == 'path': result.item['sample']['scans'][0]['path'] = TOKEN
    if change == 'future': result.item['sample']['end'] = (END + timedelta(days=1)).isoformat()
    assert check.evaluate(result.item, result.index)[0] == 'UNKNOWN'


@pytest.mark.parametrize('change', ['url', 'method', 'scope', 'filter', 'resources', 'fields', 'future'])
def test_exact_read_query_bound_before_credentials(monkeypatch, change):
    transport = gcp.Transport(SimpleNamespace(headers=lambda: pytest.fail('credentials reached')), {
        'content_secret_scans': True, '_content_secret_scan_kinds': [native.KIND]})
    args = {'method': 'POST', 'url': native.URL, 'scope': SCOPE,
            'body': native.body_for(SCOPE, START.isoformat(), END.isoformat())}
    if change == 'url': args['url'] += '?key=unsafe'
    if change == 'method': args['method'] = 'GET'
    if change == 'scope': args['scope'] = 'projects/-'
    if change == 'filter': args['body']['filter'] = 'severity=ERROR'
    if change == 'resources': args['body']['resourceNames'] = [SCOPE, 'projects/other']
    if change == 'fields': args['body']['fields'] = 'entries.textPayload'
    if change == 'future': args['body'] = native.body_for(SCOPE, START.isoformat(), (END + timedelta(days=1)).isoformat())
    with pytest.raises(gcp.ReadError, match='log_sample_unavailable'):
        native.read_page(transport, **args)
    assert transport.cache == {} and transport.calls == 0


def test_cancellation_and_expired_scan_budget_unknown(harness, clean, monkeypatch):
    result = harness([{'entries': [entry()]}], options={'_cancel_check': lambda: True})
    assert result.result[0] == 'UNKNOWN' and not result.calls
    monkeypatch.setattr(native, 'MAX_SECONDS', 0)
    result = harness([{'entries': [entry()]}])
    assert result.result[0] == 'UNKNOWN' and not result.calls


def test_sample_byte_budget_prevents_additional_content_scan(harness, clean, monkeypatch):
    monkeypatch.setattr(native, 'MAX_SAMPLE_BYTES', 10)
    result = harness([{'entries': [entry('123456')], 'nextPageToken': 'next'},
                      {'entries': [entry('123456')]}])
    assert result.result[0] == 'UNKNOWN'
    assert len(result.item['sample']['scans']) == 1
    assert result.item['sample']['bytes'] == 6


def test_pagination_preserves_all_parameters_and_remaining_entry_bound(harness, clean, monkeypatch):
    monkeypatch.setattr(native, 'MAX_ENTRIES', 100)
    result = harness([{'entries': [entry()], 'nextPageToken': 'a'},
                      {'entries': [entry()] * 50, 'nextPageToken': 'b'},
                      {'entries': [entry()] * 50}])
    assert result.result[0] == 'UNKNOWN'  # last page cannot fit the remaining 49 slots
    requests = [{k: v for k, v in c['json'].items() if k != 'pageToken'} for c in result.calls]
    assert requests == [requests[0]] * 3
    assert len(result.item['sample']['scans']) == 51


def test_cancel_during_stream_and_network_error_discard_error_text(harness, clean, monkeypatch):
    original = Response.iter_content
    def canceled(self, chunk_size):
        yield b'{'
        raise RuntimeError(TOKEN)
    monkeypatch.setattr(Response, 'iter_content', canceled)
    result = harness([{'entries': [entry(TOKEN)]}])
    assert result.result[0] == 'UNKNOWN'
    assert TOKEN not in json.dumps([result.envelope, result.transport.evidence, result.transport.cache])
    assert result.envelope['source_requests'] == ['request-1']
    monkeypatch.setattr(Response, 'iter_content', original)
    result = harness([{'error': {'message': TOKEN}}], status=403)
    assert result.envelope['status'] == 'denied'
    assert result.transport.evidence[0]['status'] == 'denied'


def test_deadline_after_detector_work_is_unknown(harness, clean, monkeypatch):
    clock = [0.0]
    monkeypatch.setattr(native, 'time', SimpleNamespace(monotonic=lambda: clock[0]))
    original = native.scan_content
    def slow(*args, **kwargs):
        outcome = original(*args, **kwargs)
        clock[0] = native.MAX_SECONDS + 1
        return outcome
    monkeypatch.setattr(native, 'scan_content', slow)
    result = harness([{'entries': [entry()]}])
    assert result.result[0] == 'UNKNOWN'


def test_callback_never_accepts_missing_or_malformed_proofs():
    assert check.evaluate({}, {})[0] == 'UNKNOWN'
    assert check.evaluate(None, {})[0] == 'UNKNOWN'


@pytest.mark.parametrize('change', ['split', 'missing_resource', 'missing_type', 'empty_log', 'bad_log', 'nonfinite', 'missing_payload'])
def test_native_complete_message_shape_is_required(harness, clean, change):
    row = entry()
    if change == 'split': row['split'] = {'uid': METADATA, 'index': 0, 'totalSplits': 2}
    if change == 'missing_resource': del row['resource']
    if change == 'missing_type': del row['resource']['type']
    if change == 'empty_log': row['logName'] = SCOPE + '/logs/'
    if change == 'bad_log': row['logName'] += '%malformed'
    if change == 'nonfinite': row['jsonPayload'] = {'n': float('nan')}; del row['textPayload']
    if change == 'missing_payload': del row['textPayload']
    assert harness([{'entries': [row]}]).result[0] == 'UNKNOWN'


@pytest.mark.parametrize('scopes', [[], ['*'], ['organizations/1234'], ['projects/other']])
def test_discovery_does_not_authorize_application_content(harness, scopes):
    result = harness([], scopes=scopes, options={'all_projects': True})
    assert result.result[0] == 'UNKNOWN' and not result.calls


def test_valid_query_without_explicit_collector_authorization_reads_no_credentials():
    transport = gcp.Transport(SimpleNamespace(headers=lambda: pytest.fail('credentials reached')), {
        'content_secret_scans': True, '_content_secret_scan_kinds': [native.KIND]})
    with pytest.raises(gcp.ReadError):
        native.read_page(transport, 'POST', native.URL, scope=SCOPE,
            body=native.body_for(SCOPE, START.isoformat(), END.isoformat()))
    assert transport.calls == 0


def test_later_page_failure_keeps_safe_request_receipts(harness, clean, monkeypatch):
    original = Response.iter_content
    def denied_second(self, chunk_size):
        yield from original(self, chunk_size)
    # A network failure after the first completed page must retain its receipt.
    count = [0]
    def failing(self, chunk_size):
        count[0] += 1
        if count[0] == 2:
            raise RuntimeError(TOKEN)
        yield from denied_second(self, chunk_size)
    monkeypatch.setattr(Response, 'iter_content', failing)
    result = harness([{'nextPageToken': 'secret-cursor'}, {'entries': [entry()]}])
    assert result.result[0] == 'UNKNOWN'
    assert result.envelope['source_requests'] == ['request-1', 'request-2']
    assert TOKEN not in json.dumps([result.envelope, result.transport.evidence])


def test_response_close_error_never_escapes_as_raw_error(harness, clean, monkeypatch):
    def close(self):
        self.closed = True
        raise RuntimeError(TOKEN)
    monkeypatch.setattr(Response, 'close', close)
    result = harness([{'entries': [entry()]}])
    assert result.result[0] == 'PASS'
    assert TOKEN not in json.dumps([result.envelope, result.transport.evidence])


@pytest.mark.parametrize('case', ['short', 'long', 'invalid', 'negative', 'oversize', 'gzip', 'br', 'unframed', 'both', 'bad_transfer'])
def test_success_response_framing_cannot_hide_valid_json_truncation(harness, clean, monkeypatch, case):
    original = Response.__init__
    def initialize(self, *args, **kwargs):
        original(self, *args, **kwargs)
        if case == 'short': self.headers['Content-Length'] = str(len(self.content) + 1)
        if case == 'long': self.headers['Content-Length'] = str(len(self.content) - 1)
        if case == 'invalid': self.headers['Content-Length'] = TOKEN
        if case == 'negative': self.headers['Content-Length'] = '-1'
        if case == 'oversize': self.headers['Content-Length'] = str(native.MAX_PAGE_BYTES + 1)
        if case in ('gzip', 'br'): self.headers['Content-Encoding'] = case
        if case == 'unframed': self.headers = {}
        if case == 'both': self.headers['Transfer-Encoding'] = 'chunked'
        if case == 'bad_transfer': self.headers = {'Transfer-Encoding': 'gzip, chunked'}
    monkeypatch.setattr(Response, '__init__', initialize)
    result = harness([{'entries': [entry()]}])
    assert result.result[0] == 'UNKNOWN'
    assert TOKEN not in json.dumps([result.envelope, result.transport.evidence])


def test_identity_chunked_stream_requires_successful_transport_completion(harness, clean, monkeypatch):
    original = Response.__init__
    def initialize(self, *args, **kwargs):
        original(self, *args, **kwargs)
        self.headers = {'Transfer-Encoding': 'chunked', 'Content-Encoding': 'identity'}
    monkeypatch.setattr(Response, '__init__', initialize)
    assert harness([{'entries': [entry()]}]).result[0] == 'PASS'
    original_iter = Response.iter_content
    def truncated(self, chunk_size):
        yield from original_iter(self, chunk_size)
        # Requests raises ChunkedEncodingError even if partial bytes formed JSON.
        raise requests.exceptions.ChunkedEncodingError(TOKEN)
    monkeypatch.setattr(Response, 'iter_content', truncated)
    assert harness([{'entries': [entry()]}]).result[0] == 'UNKNOWN'


@pytest.mark.parametrize('terminated,expected', [(True, 'PASS'), (False, 'UNKNOWN')])
def test_real_requests_chunk_parser_rejects_missing_terminator_after_valid_json(harness, clean, monkeypatch, terminated, expected):
    # Real http.client -> urllib3 -> Requests parsing, entirely in memory.
    # The only difference is the HTTP chunk terminator, not JSON validity.
    import http.client
    import io
    import sys
    import urllib3
    def response(data, status=200):
        body = json.dumps(data).encode()
        wire = (b'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n' +
                format(len(body), 'x').encode() + b'\r\n' + body + b'\r\n' +
                (b'0\r\n\r\n' if terminated else b''))
        parsed = http.client.HTTPResponse(SimpleNamespace(makefile=lambda *args: io.BytesIO(wire)), method="POST")
        parsed.begin()
        result = requests.Response()
        result.status_code = status
        result.headers = requests.structures.CaseInsensitiveDict(parsed.getheaders())
        result.raw = urllib3.response.HTTPResponse(body=parsed, headers=result.headers,
            preload_content=False, decode_content=False, original_response=parsed)
        return result
    monkeypatch.setattr(sys.modules[__name__], 'Response', response)
    result = harness([{'entries': [entry()]}])
    assert result.result[0] == expected
    assert TOKEN not in json.dumps([result.envelope, result.transport.evidence])


def test_installed_production_collect_pipeline(harness, clean):
    result = harness([{'entries': [entry()]}], full_collect=True)
    assert result.result[0] == 'PASS'
    assert result.envelope['status'] == 'collected'
    assert len(result.calls) == 1 and not result.transport.cache


def test_discovered_project_authorized_by_resolved_collector_scope(harness, clean):
    result = harness([{'entries': [entry()]}], scopes=['*'],
                     resolved_scopes=[SCOPE], options={'all_projects': True})
    assert result.result[0] == 'PASS' and len(result.calls) == 1


@pytest.mark.parametrize('total', [150, 5000])
@pytest.mark.parametrize('secret_last', [False, True])
def test_whole_window_is_read_to_the_end(harness, monkeypatch, total, secret_last):
    found = lambda payload, *a: [(TOKEN, 'synthetic', 1)] if TOKEN.encode() in payload else []
    monkeypatch.setattr(scanning, '_scan_kingfisher', found)
    monkeypatch.setattr(scanning, '_scan_trufflehog', found)
    rows = [entry(f'request {i} handled ok') for i in range(total)]
    if secret_last:
        rows[-1] = entry('token=' + TOKEN)
    size = native.PAGE_SIZE
    chunks = [rows[i:i + size] for i in range(0, total, size)]
    pages = [{'entries': chunk, **({'nextPageToken': f'p{n}'} if n < len(chunks) - 1 else {})}
             for n, chunk in enumerate(chunks)]
    result = harness(pages)
    assert result.item['sample']['entries'] == total
    assert result.result[0] == ('FAIL' if secret_last else 'PASS')


def test_window_cut_by_entry_bound_is_unknown(harness, clean, monkeypatch):
    monkeypatch.setattr(native, 'MAX_ENTRIES', 100)
    result = harness([{'entries': [entry()] * 100, 'nextPageToken': 'more'}])
    assert result.result[0] == 'UNKNOWN'
