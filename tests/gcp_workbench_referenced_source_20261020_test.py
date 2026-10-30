"""Offline fake native HTTP -> new optional producer -> sealed pure consumer.

This file deliberately has no registration/import side effects on the engine.
"""
from copy import deepcopy
import http.client
import io
import json
import logging
from pathlib import Path
import socket
from types import SimpleNamespace
from urllib.parse import quote, urlsplit

import pytest
import requests
from peaso import secret_scanning as scanning
from peaso.collectors import gcp
from peaso.collectors import gcp_workbench_referenced_source_20261020 as source
from peaso.checks import gcp_workbench_referenced_source_20261020 as consumer

SCOPE = 'projects/review'
TOKEN = 'ghp_' + '7mQ2zR9wL4cV8nK1sF6aH3jP5uD0xB2yE9rT'
AUTH = 'inert-oauth-canary'
KIND = source.PROFILES['instance']['kind']
CHECK = source.PROFILES['instance']['check']


def target(field='gceSetup.metadata.post-startup-script'):
    return dict(resource=SCOPE + '/locations/us-central1-a/instances/review-instance', field=field,
                bucket='review-source', object='scripts/source.sh', generation='12345')


def native(t):
    _, map_name, key = t['field'].split('.')
    return {'name': t['resource'], 'id': '1234567890123456789', 'createTime': '2026-10-01T00:00:00Z',
            'gceSetup': {map_name: {key: 'gs://' + t['bucket'] + '/' + t['object']}, 'instanceId': '123456789'},
            'proxyUri': 'https://never-follow.invalid/private', 'state': 'ACTIVE'}


class Response:
    def __init__(self, data, headers=None):
        self.payload = json.dumps(data).encode() if isinstance(data, dict) else data
        self.status_code = 200
        self.headers = {'Content-Type': 'application/json', 'Content-Length': str(len(self.payload)), **(headers or {})}
        self.url = ''; self.history = []; self.raw = self; self.stream = io.BytesIO(self.payload); self.closed = False
    def read(self, size, *, decode_content):
        assert decode_content is False and 0 < size <= 16384
        return self.stream.read(size)
    def close(self): self.closed = True


@pytest.fixture(autouse=True)
def offline(monkeypatch):
    def blocked(*a, **k): pytest.fail('Live network/auth forbidden')
    for name in ('connect', 'connect_ex', 'sendto'): monkeypatch.setattr(socket.socket, name, blocked)
    for name in ('create_connection', 'getaddrinfo', 'gethostbyname', 'gethostbyname_ex'): monkeypatch.setattr(socket, name, blocked)
    monkeypatch.setattr(gcp, 'Credentials', blocked)
    monkeypatch.setattr(gcp.Transport, 'request', blocked)
    scanning._RESULTS.clear()
    yield
    scanning._RESULTS.clear()


def capture(monkeypatch, *, targets=None, payload=b'mode=ready\n', fault=None, real=False,
            absent=None, options=None, mutate_snapshot=None, token_change=False):
    targets = deepcopy(targets if targets is not None else [target()])
    opts = {'content_secret_scans': True, '_content_secret_scan_kinds': [KIND],
            '_workbench_source_named_checks': [CHECK], source.OPTION: targets, 'retries': 0, **(options or {})}
    source.selected_targets(opts, [SCOPE])  # Pure validation before constructing credentials.
    seen, calls, responses, sessions, auth = [], [], [], [], []
    if not real:
        def detector(raw, path, timeout):
            seen.append((path, timeout))
            return [(TOKEN, 'inert-github', 1)] if TOKEN.encode() in raw else []
        monkeypatch.setattr(scanning, '_scan_kingfisher', detector)
        monkeypatch.setattr(scanning, '_scan_trufflehog', detector)
    if absent:
        def unavailable(*a, **k): raise RuntimeError(TOKEN)
        monkeypatch.setattr(scanning, '_scan_' + absent, unavailable)
    def headers():
        auth.append(True)
        return {'Authorization': 'Bearer ' + (AUTH + 'changed' if token_change and len(auth) > 1 else AUTH)}
    transport = gcp.Transport(SimpleNamespace(headers=headers), opts)
    collector = SimpleNamespace(transport=transport, options=opts, scopes=[SCOPE], collections={})
    counts = {}
    def request(method, url, **kw):
        assert method == 'GET' and kw['stream'] is True and kw['allow_redirects'] is False
        assert kw['headers'] == {'Authorization': 'Bearer ' + AUTH, 'Accept': '*/*' if kw['params'].get('alt') == 'media' else 'application/json',
                                 'Accept-Encoding': 'identity', 'Cache-Control': 'no-store'}
        assert 0 < kw['timeout'] <= 20
        parsed = urlsplit(url)
        assert parsed.scheme == 'https' and not parsed.query and not parsed.fragment
        t = next((t for t in targets if url.endswith(t['resource'])), None)
        if parsed.netloc == 'cloudresourcemanager.googleapis.com':
            assert parsed.path == '/v3/' + SCOPE and kw['params'] == {'fields': 'name,projectId,state'}
            op = 'project'; data = {'name': 'projects/10001', 'projectId': 'review', 'state': 'ACTIVE'}
        elif parsed.netloc == 'notebooks.googleapis.com':
            assert t is not None and parsed.path == '/v2/' + t['resource'] and kw['params'] == {}
            op = 'reference'; data = native(t)
        else:
            assert parsed.netloc == 'storage.googleapis.com'
            if '/o/' not in parsed.path:
                t = next(t for t in targets if parsed.path == '/storage/v1/b/' + quote(t['bucket'], safe=''))
                assert kw['params'] == {'fields': 'name,projectNumber', 'projection': 'noAcl'}
                op = 'bucket'; data = {'name': t['bucket'], 'projectNumber': '10001'}
            else:
                t = next(t for t in targets if parsed.path == '/storage/v1/b/' + quote(t['bucket'], safe='') + '/o/' + quote(t['object'], safe=''))
                if kw['params'].get('alt') == 'media':
                    assert kw['params'] == {'alt': 'media', 'generation': t['generation'], 'ifGenerationMatch': t['generation']}
                    op = 'content'; data = payload
                else:
                    assert kw['params'] == {'fields': source.objects.FIELDS, 'projection': 'noAcl'}
                    op = 'latest'; data = {'bucket': t['bucket'], 'name': t['object'], 'generation': t['generation'],
                        'size': str(len(payload)), 'contentType': 'text/plain'}
        counts[op] = counts.get(op, 0) + 1
        resp = Response(data, {'Content-Type': 'text/plain', 'x-goog-generation': t['generation']} if op == 'content' else None)
        if fault: fault(op, counts[op], resp, data)
        resp.url = getattr(resp, 'final_url', requests.Request(method, url, params=kw['params']).prepare().url)
        calls.append((op, method, url, deepcopy(kw['params'])))
        responses.append(resp)
        return resp
    # Both old reviewed GCS reader and the new instance reader use this unchanged session contract.
    monkeypatch.setattr(source.git, '_session', lambda: SimpleNamespace(request=request, close=lambda: sessions.append(True)))
    items = source.collect_sources(collector, SCOPE)
    refs = [r for item in items for r in item[source.MARKER]['source_requests']]
    env = dict(type=KIND, scope=SCOPE, status='collected', items=items, source_requests=refs)
    snapshot = dict(metadata={'options': deepcopy(opts)}, collections=[env])
    if mutate_snapshot: mutate_snapshot(snapshot, collector)
    snapshot = source.final_snapshot(collector, snapshot)
    idx = dict(context=dict(provider='gcp', scope=SCOPE, metadata=snapshot['metadata']), collections={KIND: snapshot['collections']})
    results = [consumer.referenced_source(item, idx) for item in snapshot['collections'][0]['items']]
    return snapshot, results, SimpleNamespace(collector=collector, calls=calls, responses=responses, sessions=sessions, auth=auth, seen=seen, index=idx)


@pytest.mark.parametrize('field', sorted(source.FIELDS))
@pytest.mark.parametrize('hit', [False, True])
@pytest.mark.parametrize('real', [False, True])
def test_native_both_detectors_three_way(monkeypatch, field, hit, real):
    snap, rows, tr = capture(monkeypatch, targets=[target(field)], payload=('token=' + TOKEN).encode() if hit else b'mode=ready\n', real=real)
    assert {r[0] for r in rows} == {'FAIL' if hit else 'PASS'}, rows
    assert len(tr.calls) == 9 and all(r.closed for r in tr.responses) and len(tr.sessions) == 9
    assert [c[0] for c in tr.calls] == ['project', 'reference', 'bucket', 'latest', 'content', 'latest', 'reference', 'bucket', 'project']
    evidence = rows[0][1]
    assert evidence['executed_bytes_proven'] is False and evidence['complete'] is True
    assert evidence['credential_validation'] == 'not_attempted'
    assert {(e['engine'], e['version'], e['status']) for e in evidence['parts'][0]['engines']} == {
        ('kingfisher', '1.4.0', 'complete'), ('trufflehog', '3.92.5', 'complete')}
    if hit:
        leak, = evidence['secret_leaks']
        assert {d['engine'] for d in leak['detectors']} == {'kingfisher', 'trufflehog'}
    persisted = json.dumps([snap, rows, tr.collector.transport.evidence]) + repr(tr.collector.transport.cache) + repr(tr.collector.options)
    assert TOKEN not in persisted and AUTH not in persisted and 'gs://' not in persisted and 'source.sh' not in persisted
    assert not hasattr(tr.collector.transport, '_workbench_source_state')
    assert tr.collector.collections == {}  # No fabricated parents.


@pytest.mark.parametrize('engine', ['kingfisher', 'trufflehog'])
@pytest.mark.parametrize('hit', [False, True])
def test_unavailable_detector_not_clean(monkeypatch, engine, hit):
    _, rows, _ = capture(monkeypatch, absent=engine, payload=('token=' + TOKEN).encode() if hit else b'mode=ready\n')
    assert rows[0][0] == ('FAIL' if hit else 'UNKNOWN')


@pytest.mark.parametrize('op', ['project', 'reference', 'bucket', 'latest', 'content'])
@pytest.mark.parametrize('code', [401, 403, 404, 410, 429, 500])
def test_denied_unavailable(monkeypatch, op, code):
    def fault(operation, n, resp, data):
        if operation == op: resp.status_code = code; resp.stream = io.BytesIO(TOKEN.encode())
    snap, rows, tr = capture(monkeypatch, fault=fault)
    assert rows[0][0] == 'UNKNOWN' and not tr.seen
    assert TOKEN not in json.dumps([snap, rows]) and all(r.closed for r in tr.responses)


MUTATIONS = ['latest_before', 'latest_after', 'id_after', 'vm_after', 'created_after', 'reference_after',
    'foreign_resource', 'foreign_project', 'foreign_bucket', 'project_after', 'bucket_after', 'missing_id',
    'missing_reference', 'legacy_top_level', 'wrong_map', 'map_conflict', 'binary', 'archive', 'empty',
    'redirect', 'history', 'partial', 'duplicate_json', 'truncated', 'media_generation', 'encoding',
    'range', 'oversize', 'length_omitted', 'chunked', 'link', 'malformed_id', 'malformed_vm', 'malformed_time', 'system_map_only', 'behavior_after', 'behavior_conflict', 'behavior_invalid']


@pytest.mark.parametrize('mutation', MUTATIONS)
def test_native_identity_relationship_generation_framing(monkeypatch, mutation):
    payload = b'\x00\xff' if mutation == 'binary' else b'PK\x03\x04archive' if mutation == 'archive' else b'' if mutation == 'empty' else b'mode=ready\n'
    def fault(op, n, resp, data):
        if mutation in ('latest_before', 'latest_after') and op == 'latest' and n == (1 if mutation.endswith('before') else 2): data['generation'] = '54321'
        elif mutation == 'id_after' and op == 'reference' and n == 2: data['id'] += '1'
        elif mutation == 'vm_after' and op == 'reference' and n == 2: data['gceSetup']['instanceId'] += '1'
        elif mutation == 'created_after' and op == 'reference' and n == 2: data['createTime'] = '2026-10-02T00:00:00Z'
        elif mutation == 'reference_after' and op == 'reference' and n == 2: data['gceSetup']['metadata']['post-startup-script'] += '.other'
        elif mutation == 'foreign_resource' and op == 'reference': data['name'] = data['name'].replace('/review/', '/foreign/')
        elif mutation == 'foreign_project' and op == 'project': data['projectId'] = 'foreign'
        elif mutation == 'foreign_bucket' and op == 'bucket': data['projectNumber'] = '10002'
        elif mutation == 'project_after' and op == 'project' and n == 2: data['name'] = 'projects/10002'
        elif mutation == 'bucket_after' and op == 'bucket' and n == 2: data['name'] = 'foreign'
        elif mutation == 'missing_id' and op == 'reference': data.pop('id')
        elif mutation == 'missing_reference' and op == 'reference': data['gceSetup']['metadata'].clear()
        elif mutation == 'legacy_top_level' and op == 'reference': data['postStartupScript'] = data.pop('gceSetup')['metadata']['post-startup-script']
        elif mutation == 'system_map_only' and op == 'reference': data['gceSetup']['systemMetadata'] = data['gceSetup'].pop('metadata')
        elif mutation == 'wrong_map' and op == 'reference': data['metadata'] = data.pop('gceSetup')['metadata']
        elif mutation == 'map_conflict' and op == 'reference': data['gceSetup']['systemMetadata'] = {'post-startup-script': 'gs://foreign/other.sh'}
        elif mutation == 'redirect': resp.final_url = 'https://evil.invalid/' + TOKEN
        elif mutation == 'history': resp.history = [object()]
        elif mutation == 'partial' and op == 'reference': data['unreachable'] = ['zone']
        elif mutation == 'truncated': resp.headers['Content-Length'] = str(len(resp.payload) + 1)
        elif mutation == 'media_generation' and op == 'content': resp.headers['x-goog-generation'] = '54321'
        elif mutation == 'encoding': resp.headers['Content-Encoding'] = 'gzip'
        elif mutation == 'range': resp.headers['Content-Range'] = 'bytes 0-1/20'
        elif mutation == 'oversize': resp.headers['Content-Length'] = str(source.MAX_CONTENT + 1)
        elif mutation == 'length_omitted': resp.headers.pop('Content-Length')
        elif mutation == 'chunked': resp.headers['Transfer-Encoding'] = 'chunked'
        elif mutation == 'link': resp.headers['Link'] = 'https://evil.invalid/' + TOKEN
        elif mutation == 'malformed_id' and op == 'reference': data['id'] = ''
        elif mutation == 'malformed_vm' and op == 'reference': data['gceSetup']['instanceId'] = 1
        elif mutation == 'behavior_after' and op == 'reference' and n == 2: data['gceSetup']['metadata']['post-startup-script-behavior'] = 'run_every_start'
        elif mutation == 'behavior_conflict' and op == 'reference':
            data['gceSetup']['metadata']['post-startup-script-behavior'] = 'run_once'
            data['gceSetup']['systemMetadata'] = {'post-startup-script-behavior': 'run_every_start'}
        elif mutation == 'behavior_invalid' and op == 'reference': data['gceSetup']['metadata']['post-startup-script-behavior'] = 'execute_arbitrary'
        elif mutation == 'malformed_time' and op == 'reference': data['createTime'] = 'yesterday'
        if isinstance(data, dict):
            resp.payload = json.dumps(data).encode()
            if mutation == 'duplicate_json' and op == 'reference': resp.payload = resp.payload[:-1] + b', "id":"different"}'
            resp.stream = io.BytesIO(resp.payload)
            if mutation not in ('truncated', 'oversize', 'length_omitted'): resp.headers['Content-Length'] = str(len(resp.payload))
    _, rows, tr = capture(monkeypatch, fault=fault, payload=payload)
    assert rows[0][0] == 'UNKNOWN' and not tr.seen, (mutation, rows)
    assert all(r.closed for r in tr.responses)


@pytest.mark.parametrize('change', ['content_off', 'kind_absent', 'named_absent'])
def test_default_off_no_calls(monkeypatch, change):
    opts = {'content_secret_scans': False} if change == 'content_off' else {'_content_secret_scan_kinds': []} if change == 'kind_absent' else {'_workbench_source_named_checks': []}
    _, rows, tr = capture(monkeypatch, options=opts)
    assert rows == [] and not tr.calls and not tr.auth


@pytest.mark.parametrize('mutation', ['extra', 'legacy', 'url', 'foreign', 'no_generation', 'numeric_generation', 'traversal', 'query', 'duplicate', 'empty', 'five', 'unsupported_field', 'system_map_only', 'bad_scopes'])
def test_selection_rejected_preauth(mutation):
    t = target(); rows = [t]; scopes = [SCOPE]
    if mutation == 'extra': t['extra'] = True
    elif mutation == 'legacy': t['field'] = 'postStartupScript'
    elif mutation == 'url': t['object'] = 'https://evil.invalid/a.sh'
    elif mutation == 'foreign': t['resource'] = t['resource'].replace('/review/', '/foreign/')
    elif mutation == 'no_generation': t.pop('generation')
    elif mutation == 'numeric_generation': t['generation'] = 1
    elif mutation == 'traversal': t['object'] = '../file.sh'
    elif mutation == 'query': t['object'] = 'file.sh?generation=2'
    elif mutation == 'duplicate': rows *= 2
    elif mutation == 'empty': rows = []
    elif mutation == 'five': rows = [{**t, 'object': str(n) + '.sh'} for n in range(5)]
    elif mutation == 'unsupported_field': t['field'] = 'gceSetup.metadata.startup-script'
    elif mutation == 'system_map_only': t['field'] = 'gceSetup.systemMetadata.post-startup-script'
    elif mutation == 'bad_scopes': scopes = ['organizations/123']
    with pytest.raises(source.Incomplete):
        source.selected_targets({source.OPTION: rows}, scopes)


@pytest.mark.parametrize('mutation', ['capture', 'receipt', 'principal', 'foreign_envelope', 'missing_item', 'duplicate_item', 'engines', 'bound', 'operation', 'origin', 'association', 'selection', 'version', 'provenance_capture', 'foreign_type'])
def test_consumer_rejects_receipt_tamper(monkeypatch, mutation):
    snap, rows, tr = capture(monkeypatch)
    idx = tr.index; env = idx['collections'][KIND][0]; item = env['items'][0]; meta = idx['context']['metadata']
    ledger = meta['workbench_source_receipts']; marker = item[source.MARKER]
    if mutation == 'capture': meta['workbench_source_capture'] = 'a' * 32
    elif mutation == 'receipt': ledger.pop()
    elif mutation == 'principal': ledger[-1]['principal'] = 'a' * 64
    elif mutation == 'foreign_envelope': env['scope'] = 'projects/foreign'
    elif mutation == 'missing_item': env['items'] = []
    elif mutation == 'duplicate_item': env['items'].append(deepcopy(item))
    elif mutation == 'engines': marker['parts'][0]['engines'].pop()
    elif mutation == 'bound': ledger[-1]['bound'] = False
    elif mutation == 'operation': ledger[-1]['operation'] = 'reference_before'
    elif mutation == 'origin': ledger[-1]['origin'] = 'evil.invalid'
    elif mutation == 'association': marker['association'] = None
    elif mutation == 'selection': meta[KIND + '_selection'][SCOPE] = []
    elif mutation == 'version': marker['parts'][0]['engines'][0]['version'] = 'wrong'
    elif mutation == 'provenance_capture': item['_provenance']['capture'] = 'wrong'
    elif mutation == 'foreign_type': env['type'] = 'wrong'
    assert consumer.referenced_source(item, idx)[0] == 'UNKNOWN'


def test_real_shared_hmac_cross_reader(monkeypatch):
    snap, rows, _ = capture(monkeypatch, payload=('token=' + TOKEN).encode(), real=True)
    other = scanning.scan_content(('token=' + TOKEN).encode(), 'existing-reader')
    leak, = rows[0][1]['secret_leaks']
    other_leak, = other['leaks']
    assert leak['fingerprint'] == other_leak['fingerprint'] == scanning._fingerprint(TOKEN)
    assert len(scanning.merge_leaks([leak, other_leak])) == 1


@pytest.mark.parametrize('knob', ['http', 'https', 'urllib3', 'logging'])
def test_wire_debug_blocked(monkeypatch, knob):
    from urllib3.connection import HTTPSConnection
    if knob == 'http': monkeypatch.setattr(http.client.HTTPConnection, 'debuglevel', 1)
    elif knob == 'https': monkeypatch.setattr(http.client.HTTPSConnection, 'debuglevel', 1)
    elif knob == 'urllib3': monkeypatch.setattr(HTTPSConnection, 'debuglevel', 1)
    else: monkeypatch.setattr(logging.getLogger('urllib3.connectionpool'), 'level', logging.DEBUG)
    _, rows, tr = capture(monkeypatch)
    assert rows[0][0] == 'UNKNOWN' and not tr.auth and not tr.calls


def test_bounds_four_targets_and_call_limit(monkeypatch):
    targets = [{**target(), 'object': f'scripts/source{n}.sh', 'resource': target()['resource'] + str(n)} for n in range(4)]
    _, rows, tr = capture(monkeypatch, targets=targets)
    assert len(tr.calls) == 36 and all(r[0] == 'PASS' for r in rows)
    _, rows, tr = capture(monkeypatch, options={'max_calls': 4})
    assert len(tr.calls) == 4 and rows[0][0] == 'UNKNOWN'


def test_deadline_cancellation_and_principal(monkeypatch):
    for options in ({'deadline': 1}, {'_cancel_check': lambda: True}):
        _, rows, tr = capture(monkeypatch, options=options)
        assert rows[0][0] == 'UNKNOWN' and not tr.auth
    _, rows, tr = capture(monkeypatch, token_change=True)
    assert rows[0][0] == 'UNKNOWN' and len(tr.calls) == 1


def test_optional_native_identity_evidence_absence(monkeypatch):
    def fault(op, n, resp, data):
        if op == 'reference':
            data.pop('createTime'); data['gceSetup'].pop('instanceId')
            resp.payload = json.dumps(data).encode(); resp.stream = io.BytesIO(resp.payload)
            resp.headers['Content-Length'] = str(len(resp.payload))
    _, rows, _ = capture(monkeypatch, fault=fault)
    assert rows[0][0] == 'PASS'  # Actual documented Instance.id still binds incarnation.


@pytest.mark.parametrize('behavior', ['run_once', 'run_every_start', 'download_and_run_every_start'])
def test_current_behavior_is_bound_without_execution_claim(monkeypatch, behavior):
    def fault(op, n, resp, data):
        if op == 'reference':
            data['gceSetup']['metadata']['post-startup-script-behavior'] = behavior
            resp.payload = json.dumps(data).encode(); resp.stream = io.BytesIO(resp.payload)
            resp.headers['Content-Length'] = str(len(resp.payload))
    _, rows, _ = capture(monkeypatch, fault=fault)
    assert rows[0][0] == 'PASS' and rows[0][1]['executed_bytes_proven'] is False
    assert 'cached on the instance' in rows[0][1]['observed']


def test_complete_maps_agree_when_returned(monkeypatch):
    def fault(op, n, resp, data):
        if op == 'reference':
            data['gceSetup']['systemMetadata'] = deepcopy(data['gceSetup']['metadata'])
            resp.payload = json.dumps(data).encode(); resp.stream = io.BytesIO(resp.payload)
            resp.headers['Content-Length'] = str(len(resp.payload))
    _, rows, _ = capture(monkeypatch, fault=fault)
    assert rows[0][0] == 'PASS'


def test_partial_collection_never_clean_but_retains_bound_hit(monkeypatch):
    def partial(snapshot, collector): snapshot['collections'][0]['status'] = 'partial'
    _, rows, _ = capture(monkeypatch, mutate_snapshot=partial)
    assert rows[0][0] == 'UNKNOWN'
    _, rows, _ = capture(monkeypatch, mutate_snapshot=partial, payload=('token=' + TOKEN).encode())
    assert rows[0][0] == 'FAIL' and rows[0][1]['complete'] is False


def test_union_redaction_and_raw_target_removal(monkeypatch):
    def dirty(snapshot, collector):
        snapshot['metadata']['sibling'] = TOKEN
        collector.collections['metadata'] = TOKEN
        collector.transport.cache['metadata'] = TOKEN
        collector.transport.evidence.append({'error': TOKEN})
    snap, rows, tr = capture(monkeypatch, payload=('token=' + TOKEN).encode(), mutate_snapshot=dirty)
    assert rows[0][0] == 'FAIL'
    assert TOKEN in json.dumps([snap, rows, tr.collector.collections, tr.collector.transport.evidence, tr.collector.transport.cache])
    assert source.OPTION not in tr.collector.options and source.OPTION not in tr.collector.transport.options


def test_no_raw_metadata_or_source_cache(monkeypatch):
    _, _, tr = capture(monkeypatch)
    assert tr.collector.transport.cache == {} and tr.collector.transport.evidence == []
    assert all(r.closed for r in tr.responses) and not hasattr(tr.collector.transport, '_workbench_source_state')


def test_immutable_proposal():
    from tests.gcp_referenced_source_historical_compatibility_20261020 import proposal_boundary  # sealed bytes via reviewed epoch
    assert proposal_boundary('workbench') == {'current_id': CHECK, 'proposal_registration_delta': 0}
    receipt = json.loads((Path(__file__).resolve().parents[1] / 'peaso/checks/gcp_workbench_referenced_source_20261020_proposal.json').read_text())
    assert receipt['registration'] == 'unregistered_proposal_only' and receipt['live_cloud_collection'] is False
    assert receipt['original_execution_proven'] is False and receipt['test_result']['failed'] == 0


def test_durable_native_fixtures():
    path = Path(__file__).resolve().parents[1] / 'peaso/checks/gcp_workbench_referenced_source_20261020_native_cases.json'
    fixture = json.loads(path.read_text())
    assert fixture['provenance'] == 'offline_native_http_fixtures_not_live_cloud'
    for case in fixture['cases']:
        if case['binding_expected']:
            assert source.parse(case['target']) == SCOPE
            assert len(source.reference(case['instance'], case['target'])) == 64
        else:
            with pytest.raises(source.Incomplete):
                source.reference(case['instance'], case['target'])


def test_proposal_not_installed():
    from peaso import engine
    assert CHECK not in {c.id for c in engine._registry()}
