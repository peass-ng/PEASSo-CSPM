"""Independent native HTTP -> actual azure.collect -> public engine; candidate only."""
from copy import deepcopy
import base64
import inspect
import hashlib
import io
import json
import socket
from types import SimpleNamespace
from urllib.parse import urlsplit, parse_qs
import pytest
from peaso import engine, secret_scanning as scanning
from peaso.checks import Check
from peaso.collectors import azure, azure_devops_git_native as git
from peaso.collectors import azure_devops_selected_content_secret_indicators as source
from peaso.checks import azure_devops_selected_content_secret_review_20261020 as consumer

SCOPE = '/subscriptions/11111111-1111-1111-1111-111111111111'
TENANT = '22222222-2222-2222-2222-222222222222'
PID = '33333333-3333-3333-3333-333333333333'
RID = '44444444-4444-4444-4444-444444444444'
OTHER = '55555555-5555-5555-5555-555555555555'
COMMIT = 'a' * 40
ORG = 'selected-org'
TOKEN = 'ghp_' + '7mQ2zR9wL4cV8nK1sF6aH3jP5uD0xB2yE9rT'
AUTH = 'offline-devops-read-auth-canary'
CAPTURES = []


@pytest.fixture(autouse=True)
def offline(monkeypatch):
    def blocked(*args, **kwargs):
        pytest.fail('actual sockets/DNS/authentication discovery forbidden')
    for name in ('connect', 'connect_ex'):
        monkeypatch.setattr(socket.socket, name, blocked)
    for name in ('create_connection', 'getaddrinfo', 'gethostbyname', 'gethostbyname_ex'):
        monkeypatch.setattr(socket, name, blocked)
    monkeypatch.setattr(azure, 'credential_for', blocked)
    registered, = [c for c in engine._registry() if c.id == source.CHECK]
    assert inspect.unwrap(registered.evaluate) is consumer.evaluate
    assert registered.kind == source.KIND and registered.allow_incomplete_failure
    scanning._RESULTS.clear()
    yield
    scanning._RESULTS.clear()


def target(surface='git_file'):
    common = {'surface': surface, 'scope': SCOPE, 'organization': ORG, 'project_id': PID, 'commit': COMMIT}
    return {**common, **({'repository_id': RID, 'path': '/selected folder/file#one.txt'} if surface == 'git_file'
        else {'pipeline_id': 7, 'definition_revision': 3})}


def connector(targets, enabled=True, named=True, method='pat'):
    return {'provider': 'azure', 'scopes': [SCOPE], 'auth': {'method': 'token', 'tenant_id': TENANT,
        'arm_token': 'separate-arm-test-token', 'devops_credentials': [{'server': 'https://dev.azure.com/' + ORG,
        'method': method, 'token': AUTH}]}, 'options': {'retries': 0, 'content_secret_scans': enabled,
        '_content_secret_scan_kinds': [source.KIND] if named else [], source.OPTION: deepcopy(targets),
        'compliance_parameters': {'azure_devops_git': {'subscriptions': [{'scope': SCOPE,
            'organization': ORG, 'project_ids': [PID]}]}}}}


def item(path, text):
    data = text.encode()
    return {'path': path, 'commitId': COMMIT, 'gitObjectType': 'blob', 'isFolder': False,
        'isSymLink': False, 'contentMetadata': {'encoding': 65001, 'isBinary': False}, 'content': text,
        'objectId': hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest(),
        'url': 'https://evil.invalid/ignored/' + TOKEN}


class Response:
    def __init__(self, payload, status=200, headers=None):
        data = json.dumps(payload).encode() if isinstance(payload, dict) else payload
        self.stream = io.BytesIO(data); self.status = status; self.closed = False
        self.headers = {'Content-Type': 'application/json', 'Content-Length': str(len(data)), **(headers or {})}
    def getheader(self, name):
        return self.headers.get(name)
    def read(self, size):
        assert 0 < size <= 16384
        return self.stream.read(size)
    def close(self):
        self.closed = True


def collect(monkeypatch, surface='git_file', hit=False, *, real=False, mutation=None, fault=None,
            missing_engine=None, targets=None, native_text=None, variable=None, custom=None, method='pat'):
    selected = targets or [target(surface)]
    calls = []; responses = []; connections = []; scans = []
    text = native_text if native_text is not None else ('steps:\n- script: echo ' + (TOKEN if hit else 'ready') + '\n' if surface == 'pipeline' else (TOKEN if hit else 'mode=ready'))
    if not real:
        def runner(payload, path, timeout):
            scans.append(path)
            return [(TOKEN, 'github-pat', 1)] if TOKEN.encode() in payload else []
        monkeypatch.setattr(scanning, '_scan_kingfisher', runner)
        monkeypatch.setattr(scanning, '_scan_trufflehog', runner)
    if missing_engine:
        def broken(*args, **kwargs):
            raise TimeoutError(TOKEN)
        monkeypatch.setattr(scanning, '_scan_' + missing_engine, broken)
    class Transport:
        tenant = TENANT
        verified_tenant = OTHER if mutation == 'tenant' else TENANT
        def request(self, url, **kwargs):
            assert url == 'https://management.azure.com' + SCOPE + '?api-version=2022-12-01'
            return {'id': SCOPE if mutation != 'subscription' else '/subscriptions/' + OTHER,
                'tenantId': TENANT if mutation != 'subscription_tenant' else OTHER}
        def close(self):
            pass
    class Connection:
        sock = None
        def __init__(self, host, timeout):
            assert host == 'dev.azure.com' and 0 < timeout <= 10
            self.closed = False; connections.append(self)
        def set_debuglevel(self, value):
            assert value == 0
        def request(self, method_, path, body=None, headers=None):
            assert method_ == 'GET' and body is None
            expected_auth = 'Bearer ' + AUTH if method == 'bearer' else 'Basic ' + base64.b64encode((':' + AUTH).encode()).decode()
            assert headers['Authorization'] == expected_auth and headers['Accept-Encoding'] == 'identity'
            parsed = urlsplit(path); q = parse_qs(parsed.query)
            assert not parsed.scheme and not parsed.netloc and not parsed.fragment
            assert q['api-version'] == ['7.1']
            assert all(len(v) == 1 for v in q.values())
            path_ = parsed.path
            if path_ == '/' + ORG + '/' + PID + '/_apis/build/definitions/7':
                operation = 'definition'
                assert q == {'api-version': ['7.1'], 'revision': ['3']}
                data = {'id': 7, 'revision': 3, 'project': {'id': PID, 'state': 'wellFormed'},
                    'repository': {'id': RID, 'type': 'TfsGit', 'url': 'https://evil.invalid/' + TOKEN},
                    'process': {'type': 2, 'yamlFilename': 'azure-pipelines.yml'},
                    'variables': {'MODE': {'isSecret': False, 'value': variable if variable is not None else 'ready'}},
                    'variableGroups': []}
            elif path_ == '/' + ORG + '/' + PID + '/_apis/git/repositories/' + RID:
                operation = 'repository'; data = {'id': RID, 'project': {'id': PID, 'state': 'wellFormed'}, 'name': TOKEN}
                assert set(q) == {'api-version'}
            else:
                assert path_ == '/' + ORG + '/' + PID + '/_apis/git/repositories/' + RID + '/items'
                operation = 'item'; selected_path = selected[0]['path'] if surface == 'git_file' else '/azure-pipelines.yml'
                assert q == {'api-version': ['7.1'], 'path': [selected_path], 'includeContent': ['true'],
                    'includeContentMetadata': ['true'], 'recursionLevel': ['none'], 'resolveLfs': ['false'],
                    'download': ['false'], '$format': ['json'], 'versionDescriptor.version': [COMMIT],
                    'versionDescriptor.versionType': ['commit'], 'versionDescriptor.versionOptions': ['none']}
                data = item(selected_path, text)
            calls.append((method_, 'dev.azure.com', path, operation))
            if custom:
                data = custom(operation, deepcopy(data))
            if operation in ('definition', 'repository') and mutation in ('foreign_project', 'project_state', 'missing_project_id'):
                if mutation == 'foreign_project': data['project']['id'] = OTHER
                if mutation == 'project_state': data['project']['state'] = 'deleting'
                if mutation == 'missing_project_id': data['project'].pop('id')
            if operation == 'repository' and mutation in ('foreign_repo', 'foreign_repo_project'):
                if mutation == 'foreign_repo': data['id'] = OTHER
                if mutation == 'foreign_repo_project': data['project']['id'] = OTHER
            if operation == 'definition':
                if mutation == 'foreign_definition': data['id'] = 8
                if mutation == 'definition_revision': data['revision'] = 4
                if mutation == 'definition_bool': data['id'] = True
                if mutation == 'definition_project': data['project']['id'] = OTHER
                if mutation == 'github': data['repository']['type'] = 'GitHub'
                if mutation == 'yaml_missing': data['process'].pop('yamlFilename')
                if mutation == 'classic': data['process']['type'] = 1
                if mutation == 'variable_flag': data['variables']['MODE'].pop('isSecret')
                if mutation == 'variable_secret': data['variables']['MODE'] = {'isSecret': True, 'value': TOKEN}
                if mutation == 'variable_mask': data['variables']['MODE']['value'] = '***'
                if mutation == 'variable_reference': data['variables']['MODE']['value'] = '$(SECRET)'
                if mutation == 'groups': data['variableGroups'] = [{'id': 5, 'variables': {'protected': TOKEN}}]
                if mutation == 'variables_missing': data.pop('variables')
            if operation == 'item':
                field_values = {'foreign_commit': ('commitId', 'b' * 40), 'foreign_path': ('path', '/other'),
                    'folder': ('isFolder', True), 'symlink': ('isSymLink', True), 'type': ('gitObjectType', 'tree'),
                    'blob_mismatch': ('objectId', 'b' * 40), 'missing_content': ('content', None), 'empty': ('content', ''),
                    'unicode_error': ('content', '\ud800')}
                if mutation in field_values:
                    key, value = field_values[mutation]; data[key] = value
                if mutation == 'binary': data['contentMetadata']['isBinary'] = True
                if mutation == 'encoding': data['contentMetadata']['encoding'] = 1200
                if mutation == 'missing_metadata': data.pop('contentMetadata')
            self.response = Response(data)
            if fault and (operation == 'item' or fault.startswith('early_')):
                name = fault.removeprefix('early_')
                if name == 'denied': self.response = Response({'error': TOKEN}, 403)
                if name == 'redirect': self.response = Response(b'', 302, {'Location': 'https://evil.invalid/' + TOKEN})
                if name == 'continuation': self.response = Response(data, headers={'x-ms-continuationtoken': TOKEN})
                if name == 'gzip': self.response = Response(data, headers={'Content-Encoding': 'gzip'})
                if name == 'mime': self.response = Response(data, headers={'Content-Type': 'text/plain'})
                if name == 'truncated': self.response = Response(data, headers={'Content-Length': '99999'})
                if name == 'duplicate': self.response = Response(b'{"path":"x","path":"y"}')
                if name == 'oversize': self.response = Response(data, headers={'Content-Length': str(source.MAX_WIRE + 1)})
                if name == 'invalid_json': self.response = Response(b'{')
                if name == 'timeout': raise TimeoutError(TOKEN)
            responses.append(self.response)
        def getresponse(self):
            return self.response
        def close(self):
            self.closed = True
    monkeypatch.setattr(source.http.client, 'HTTPSConnection', Connection)
    c = custom_connector = connector(selected, method=method)
    if mutation == 'disabled': c['options']['content_secret_scans'] = False
    if mutation == 'unnamed': c['options']['_content_secret_scan_kinds'] = []
    if mutation == 'no_credential': c['auth'].pop('devops_credentials')
    if mutation == 'generic_budget': c['options']['max_calls'] = 2
    if mutation == 'wire_total': monkeypatch.setattr(source, 'MAX_TOTAL', 1)
    if mutation == 'call_cap': monkeypatch.setattr(source, 'MAX_CALLS', 1)
    if mutation == 'content_cap': monkeypatch.setattr(source, 'MAX_CONTENT', 2)
    if mutation == 'deadline': monkeypatch.setattr(source, 'MAX_SECONDS', 0)
    snapshot = azure.collect(c, [source.KIND], transport=Transport())
    import inspect, sys
    inputs = []; code = inspect.unwrap(consumer.evaluate).__code__
    prior_profile = sys.getprofile()
    def observe(frame, event, arg):
        if event == 'call' and frame.f_code is code:
            inputs.append({'item': deepcopy(frame.f_locals['item']), 'index': deepcopy(frame.f_locals['index'])})
    try:
        sys.setprofile(observe)
        results = engine.evaluate_snapshot(snapshot, checks=[source.CHECK])['findings']
    finally:
        sys.setprofile(prior_profile)
    return snapshot, results, SimpleNamespace(calls=calls, responses=responses, connections=connections, scans=scans, inputs=inputs)


def own(snapshot):
    return next(c for c in snapshot['collections'] if c['type'] == source.KIND)


@pytest.mark.parametrize('surface', ['git_file', 'pipeline'])
@pytest.mark.parametrize('hit', [False, True])
@pytest.mark.parametrize('method', ['pat', 'bearer'])
def test_native_selected_source(monkeypatch, surface, hit, method):
    snapshot, results, trace = collect(monkeypatch, surface, hit, method=method)
    assert [r['status'] for r in results] == ['FAIL' if hit else 'PASS'], results
    assert len(trace.calls) == (2 if surface == 'git_file' else 3)
    assert all(c.closed for c in trace.connections) and all(r.closed for r in trace.responses)
    persisted = json.dumps([snapshot, results, list(scanning._RESULTS.items())], default=lambda x: x.hex() if isinstance(x, bytes) else str(x))
    assert TOKEN not in persisted and AUTH not in persisted and 'mode=ready' not in persisted
    assert 'evil.invalid' not in persisted and 'selected folder' not in persisted
    if hit:
        leaks = own(snapshot)['items'][0][source.MARKER]['leaks']
        assert len(leaks) == 1 and {d['engine'] for d in leaks[0]['detectors']} == {'kingfisher', 'trufflehog'}
    CAPTURES.append({'surface': surface, 'hit': hit, 'snapshot': snapshot, 'findings': results, 'inputs': trace.inputs})


@pytest.mark.parametrize('surface', ['git_file', 'pipeline'])
@pytest.mark.parametrize('hit', [False, True])
def test_real_pinned_offline_engines(monkeypatch, surface, hit):
    snapshot, results, trace = collect(monkeypatch, surface, hit, real=True)
    assert [r['status'] for r in results] == ['FAIL' if hit else 'PASS'], results
    parts = own(snapshot)['items'][0][source.MARKER]['parts']
    assert all({e['status'] for e in p['engines']} == {'complete'} for p in parts)
    if hit:
        leak, = own(snapshot)['items'][0][source.MARKER]['leaks']
        assert {d['engine'] for d in leak['detectors']} == {'kingfisher', 'trufflehog'}
    CAPTURES.append({'surface': surface, 'hit': hit, 'real_engines': True, 'snapshot': snapshot, 'findings': results, 'inputs': trace.inputs})


@pytest.mark.parametrize('surface', ['git_file', 'pipeline'])
@pytest.mark.parametrize('mutation', ['tenant', 'subscription', 'subscription_tenant', 'foreign_project', 'project_state',
    'missing_project_id', 'foreign_repo', 'foreign_repo_project', 'foreign_commit', 'foreign_path', 'folder', 'symlink',
    'type', 'blob_mismatch', 'missing_content', 'empty', 'unicode_error', 'binary', 'encoding', 'missing_metadata',
    'no_credential', 'generic_budget', 'wire_total', 'call_cap', 'content_cap', 'deadline'])
def test_unbound_native_unknown(monkeypatch, surface, mutation):
    snapshot, results, _ = collect(monkeypatch, surface, True, mutation=mutation)
    assert results and all(r['status'] in ('UNKNOWN', 'DENIED') for r in results), results
    assert TOKEN not in json.dumps([snapshot, results])


@pytest.mark.parametrize('mutation', ['foreign_definition', 'definition_revision', 'definition_bool', 'definition_project',
    'github', 'yaml_missing', 'classic', 'variable_flag', 'variable_secret', 'variable_mask', 'variable_reference', 'groups', 'variables_missing'])
def test_pipeline_native_limits(monkeypatch, mutation):
    snapshot, results, _ = collect(monkeypatch, 'pipeline', mutation=mutation)
    assert [r['status'] for r in results] == ['UNKNOWN'], results
    assert TOKEN not in json.dumps([snapshot, results])


@pytest.mark.parametrize('surface', ['git_file', 'pipeline'])
@pytest.mark.parametrize('fault', ['denied', 'redirect', 'continuation', 'gzip', 'mime', 'truncated', 'duplicate', 'oversize', 'invalid_json', 'timeout', 'early_denied'])
def test_transport_failure(monkeypatch, surface, fault):
    snapshot, results, trace = collect(monkeypatch, surface, True, fault=fault)
    assert results and all(r['status'] in ('UNKNOWN', 'DENIED') for r in results), results
    assert all(c.closed for c in trace.connections)
    assert TOKEN not in json.dumps([snapshot, results])
    if fault == 'denied':
        CAPTURES.append({'surface': surface, 'native_failure': 'HTTP403', 'snapshot': snapshot, 'findings': results, 'inputs': trace.inputs})


@pytest.mark.parametrize('surface', ['git_file', 'pipeline'])
@pytest.mark.parametrize('hit', [False, True])
@pytest.mark.parametrize('missing', ['kingfisher', 'trufflehog'])
def test_incomplete_engine_retains_bound_hits(monkeypatch, surface, hit, missing):
    snapshot, results, _ = collect(monkeypatch, surface, hit, missing_engine=missing)
    assert [r['status'] for r in results] == ['FAIL' if hit else 'UNKNOWN'], results
    if hit:
        assert results[0]['evidence']['complete'] is False
        assert results[0]['evidence']['coverage'] == 'incomplete'
    assert TOKEN not in json.dumps([snapshot, results, list(scanning._RESULTS.items())], default=lambda x: x.hex() if isinstance(x, bytes) else str(x))


def test_same_secret_union_locations_and_metadata_redaction(monkeypatch):
    snapshot, results, _ = collect(monkeypatch, 'pipeline', True, variable=TOKEN)
    assert [r['status'] for r in results] == ['FAIL']
    leak, = own(snapshot)['items'][0][source.MARKER]['leaks']
    assert {loc['path'].rsplit('.', 1)[-1] for loc in leak['locations']} == {'selected-file', 'variable-1'}
    assert TOKEN not in json.dumps([snapshot, results, list(scanning._RESULTS.items())], default=lambda x: x.hex() if isinstance(x, bytes) else str(x))


@pytest.mark.parametrize('fault', ['denied', 'timeout', 'continuation'])
def test_completed_variable_hit_survives_yaml_failure(monkeypatch, fault):
    snapshot, results, _ = collect(monkeypatch, 'pipeline', variable=TOKEN, fault=fault)
    assert [r['status'] for r in results] == ['FAIL'], results
    assert results[0]['evidence']['complete'] is False


@pytest.mark.parametrize('text', ['steps:\n- template: other.yml', 'extends:\n  template: https://evil.invalid/x',
    'variables:\n- group: protected', 'steps:\n- script: echo $(SECRET)', 'resources:\n  repositories: []',
    'x: &a [1]\ny: *a', 'x: !!python/object:evil {}', 'x: ['])
@pytest.mark.parametrize('hit', [False, True])
def test_yaml_reference_or_unsupported_never_clean(monkeypatch, text, hit):
    snapshot, results, trace = collect(monkeypatch, 'pipeline', native_text=text + ('\n# ' + TOKEN if hit else ''))
    assert [r['status'] for r in results] == ['FAIL' if hit else 'UNKNOWN'], results
    assert len(trace.calls) == 3


@pytest.mark.parametrize('mutation', ['disabled', 'unnamed'])
def test_default_off_no_content_request(monkeypatch, mutation):
    _, results, trace = collect(monkeypatch, mutation=mutation)
    assert not trace.calls
    assert not any(r['status'] in ('PASS', 'FAIL') for r in results)


@pytest.mark.parametrize('field,value', [('commit', 'main'), ('commit', 'a'*41), ('path', '/a/../b'),
    ('path', '/a//b'), ('path', 'relative'), ('path', '/%2Fetc'), ('path', '/a\\b'), ('path', '/x\n'),
    ('organization', 'evil.invalid'), ('project_id', OTHER), ('scope', '/subscriptions/'+OTHER),
    ('repository_id', 'repo-name'), ('downloadUrl', 'https://evil.invalid/x')])
def test_exact_selection_grammar(field, value):
    t = target(); t[field] = value; c = connector([t])
    with pytest.raises(ValueError):
        source.selected_targets(c['options'], c['scopes'], c['auth'])


@pytest.mark.parametrize('field,value', [('pipeline_id', True), ('pipeline_id', 0), ('definition_revision', -1), ('definition_revision', 2**31)])
def test_pipeline_pin_grammar(field, value):
    t = target('pipeline'); t[field] = value; c = connector([t])
    with pytest.raises(ValueError): source.selected_targets(c['options'], c['scopes'], c['auth'])


@pytest.mark.parametrize('mutation', ['capture', 'scope', 'credential', 'customer', 'host', 'method', 'version', 'bytes',
    'bound', 'selection', 'engine_version', 'engine_duplicate', 'detector_unbound', 'location', 'duplicate_item', 'tenant'])
def test_consumer_rejects_forged_binding(monkeypatch, mutation):
    snapshot, _, _ = collect(monkeypatch, hit=True)
    c = own(snapshot); obj = c['items'][0]; m = obj[source.MARKER]; meta = snapshot['metadata']
    r = meta[source.KIND+'_receipts'][-1]
    if mutation == 'capture': m['capture'] += 'a'
    if mutation == 'scope': m['scope'] += '/other'
    if mutation == 'credential': obj['_provenance']['credential_context_id'] = 'foreign'
    if mutation == 'customer': c['_provenance']['customer_context_id'] = 'foreign'
    if mutation == 'host': r['host'] = 'evil.invalid'
    if mutation == 'method': r['method'] = 'POST'
    if mutation == 'version': r['version'] = '7.2'
    if mutation == 'bytes': r['bytes'] = source.MAX_WIRE+1
    if mutation == 'bound': r['bound'] = False
    if mutation == 'selection': meta[source.KIND+'_selection'][SCOPE] = []
    if mutation == 'engine_version': m['parts'][0]['engines'][0]['version'] = 'unknown'
    if mutation == 'engine_duplicate': m['parts'][0]['engines'][1] = deepcopy(m['parts'][0]['engines'][0])
    if mutation == 'detector_unbound': m['leaks'][0]['detectors'][0]['engine'] = 'unknown'
    if mutation == 'location': m['leaks'][0]['locations'][0]['path'] = 'foreign'
    if mutation == 'duplicate_item': c['items'].append(deepcopy(obj))
    if mutation == 'tenant': meta[source.KIND+'_tenant'] = OTHER
    index = {'context': {'provider': 'azure', 'scope': SCOPE, 'metadata': snapshot['metadata']}, 'collections': {source.KIND: [c]}}
    assert consumer.evaluate(obj, index)[0] == 'UNKNOWN'



@pytest.mark.parametrize('surface', ['git_file', 'pipeline'])
def test_both_engines_timeout_unknown(monkeypatch, surface):
    def broken(*args, **kwargs):
        raise TimeoutError(TOKEN)
    monkeypatch.setattr(scanning, '_scan_kingfisher', broken)
    monkeypatch.setattr(scanning, '_scan_trufflehog', broken)
    snapshot, results, _ = collect(monkeypatch, surface, True, real=True)
    assert [r['status'] for r in results] == ['UNKNOWN']
    assert TOKEN not in json.dumps([snapshot, results])


@pytest.mark.parametrize('surface', ['git_file', 'pipeline'])
@pytest.mark.parametrize('text', ['password=***', 'password=$(KEY)', '${{ variables.secret }}', '$[ variables.key ]'])
def test_literal_masks_and_references_are_not_clean(monkeypatch, surface, text):
    _, results, _ = collect(monkeypatch, surface, native_text=text)
    assert [r['status'] for r in results] == ['UNKNOWN']


@pytest.mark.parametrize('hit', [False, True])
def test_complete_hit_with_partial_inventory(monkeypatch, hit):
    snapshot, _, _ = collect(monkeypatch, hit=hit)
    c = own(snapshot); c['status'] = 'partial'; c['error'] = {'code': 'explicit_budget'}
    from peaso.snapshot import seal
    findings = engine.evaluate_snapshot(seal(snapshot), checks=[source.CHECK])['findings']
    assert not any(f['status'] == 'PASS' for f in findings)
    assert any(f['status'] == ('FAIL' if hit else 'UNKNOWN') for f in findings)
    if hit:
        assert all(f['evidence'].get('complete') is False for f in findings if f['status'] == 'FAIL')


def test_same_value_dedup_across_selected_surfaces(monkeypatch):
    # The same file and variable value in two selected surfaces yields one public finding.
    targets = [target('pipeline'), {**target('git_file'), 'path': '/azure-pipelines.yml'}]
    snapshot, findings, trace = collect(monkeypatch, 'pipeline', True, variable=TOKEN, targets=targets)
    assert len(own(snapshot)['items']) == 2 and len(trace.calls) == 5
    assert [f['status'] for f in findings] == ['FAIL'], findings
    leaks = findings[0]['evidence']['secret_leaks']
    assert len(leaks) == 1 and len(leaks[0]['locations']) >= 3


@pytest.mark.parametrize('mutation', ['duplicate', 'oversized', 'extra', 'credential_org', 'credential_method', 'nonboolean'])
def test_selection_and_auth_boundary(mutation):
    c = connector([target()])
    if mutation == 'duplicate': c['options'][source.OPTION] *= 2
    if mutation == 'oversized': c['options'][source.OPTION] *= 9
    if mutation == 'extra': c['options'][source.OPTION][0]['effective'] = True
    if mutation == 'credential_org': c['auth']['devops_credentials'][0]['server'] = 'https://dev.azure.com/foreign-org'
    if mutation == 'credential_method': c['auth']['devops_credentials'][0]['method'] = 'arm'
    if mutation == 'nonboolean': c['options']['content_secret_scans'] = 'true'
    with pytest.raises(ValueError): source.selected_targets(c['options'], c['scopes'], c['auth'])


@pytest.mark.parametrize('text', ['version https://git-lfs.github.com/spec/v1\noid sha256:abc\n', 'x'*262145])
def test_lfs_and_content_limits_not_followed(monkeypatch, text):
    snapshot, findings, trace = collect(monkeypatch, native_text=text)
    assert [f['status'] for f in findings] == ['UNKNOWN']
    assert len(trace.calls) == 2 and not trace.scans


def test_redaction_union_scrubs_sibling_metadata_and_locator(monkeypatch):
    # Root hook must run after the full native snapshot so mixed-inventory labels are scrubbed.
    snapshot, _, _ = collect(monkeypatch, hit=True)
    class Reader:
        devops_selected_redactions = {TOKEN}
        devops_selected_metadata = {}
    reader = Reader()
    snapshot['metadata']['other_label'] = 'prefix-' + TOKEN
    snapshot['metadata']['other_base64'] = base64.b64encode(TOKEN.encode()).decode()
    snapshot['collections'].append({'type': 'subscription', 'scope': SCOPE, 'service': 'Microsoft.Resources',
        'status': 'collected', 'items': [{'id': SCOPE + '/' + TOKEN, 'name': TOKEN}]})
    safe = source.final_snapshot(reader, snapshot)
    assert TOKEN in json.dumps(safe)  # found values stay visible
    assert not reader.devops_selected_redactions


def test_finding_budget_retains_completed_engine_counterexample(monkeypatch):
    text = '\n'.join('synthetic-secret-value-' + str(i) for i in range(257))
    def runner(payload, path, timeout):
        return [(value, 'bounded-test-rule', i+1) for i, value in enumerate(payload.decode().splitlines())]
    monkeypatch.setattr(scanning, '_scan_kingfisher', runner)
    monkeypatch.setattr(scanning, '_scan_trufflehog', runner)
    snapshot, findings, _ = collect(monkeypatch, real=True, native_text=text)
    assert len(findings) == 256 and all(f['status'] == 'FAIL' for f in findings)
    assert all(f['evidence']['complete'] is False for f in findings)
    leaks = own(snapshot)['items'][0][source.MARKER]['leaks']
    assert len(leaks) == 256 and all(l['detectors'] for l in leaks)
    assert 'synthetic-secret-value-' not in json.dumps([snapshot, findings])


def test_source_receipts_and_fixture_export():
    """Export safe current native observations for root's separate integration."""
    import inspect
    from pathlib import Path
    sources = []
    for fn in (source.enabled, source.path_valid, source.selected_targets, source.identity, source.route, source.remaining,
            source._pairs, source._read, source._yaml_complete, source._part, source._scan, source.collect,
            source.final_snapshot, consumer.evaluate, scanning.scan_content, scanning.merge_leaks):
        fn = inspect.unwrap(fn); body, line = inspect.getsourcelines(fn); path = Path(inspect.getsourcefile(fn)).resolve()
        assert path == Path(fn.__code__.co_filename).resolve()
        text = ''.join(body)
        sources.append({'symbol': fn.__module__+'.'+fn.__qualname__, 'path': str(path), 'line': line,
            'source': text, 'sha256': hashlib.sha256(text.encode()).hexdigest(),
            'module_sha256': hashlib.sha256(path.read_bytes()).hexdigest()})
    out = Path('/tmp/peasso-azure-source-review-20261020/devops-selected-content')
    out.mkdir(parents=True, exist_ok=True)
    (out/'sources.json').write_text(json.dumps(sources, indent=2)+'\n')
    (out/'native-captures.json').write_text(json.dumps(CAPTURES, indent=2)+'\n')
    assert TOKEN not in (out/'native-captures.json').read_text()
