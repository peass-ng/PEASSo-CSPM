"""Independent exact ARM wire responses -> collector -> registered pure engine."""
from copy import deepcopy
from tests.selected_secret_source_successors_20261020 import assert_source_receipt
import io
import json
from pathlib import Path
import socket
from types import SimpleNamespace
import pytest
from peaso import engine, secret_scanning as scanning
from peaso.collectors import azure
from peaso.collectors import azure_app_settings_secret_indicators as source
from peaso.checks import azure_app_settings_secret_review_20261020 as checks

SCOPE = '/subscriptions/11111111-1111-1111-1111-111111111111'
OTHER = '/subscriptions/33333333-3333-3333-3333-333333333333'
SITE = SCOPE + '/resourceGroups/review/providers/Microsoft.Web/sites/review-app'
SLOT = SITE + '/slots/staging'
TENANT = '22222222-2222-2222-2222-222222222222'
TOKEN = 'ghp_' + '7mQ2zR9wL4cV8nK1sF6aH3jP5uD0xB2yE9rT'
AUTH = 'synthetic-arm-canary'


@pytest.fixture(autouse=True)
def offline(monkeypatch):
    def blocked(*args, **kwargs):
        pytest.fail('actual socket/DNS/credential discovery is forbidden')
    monkeypatch.setattr(socket.socket, 'connect', blocked)
    monkeypatch.setattr(socket.socket, 'connect_ex', blocked)
    monkeypatch.setattr(socket, 'create_connection', blocked)
    monkeypatch.setattr(socket, 'getaddrinfo', blocked)
    monkeypatch.setattr(azure, 'credential_for', blocked)
    scanning._RESULTS.clear()
    yield
    scanning._RESULTS.clear()


def native(target=SITE, values=None):
    return {'id': target + '/config/appsettings', 'name': 'appsettings',
        'type': 'Microsoft.Web/sites/' + ('slots/' if '/slots/' in target else '') + 'config',
        'kind': 'functionapp', 'properties': {'Mode': 'ready = true'} if values is None else values}


class Response:
    def __init__(self, payload, status=200, headers=None):
        self.payload = json.dumps(payload).encode() if isinstance(payload, dict) else payload
        self.stream = io.BytesIO(self.payload)
        self.status, self.closed = status, False
        self.headers = {'Content-Type': 'application/json', 'Content-Length': str(len(self.payload)), **(headers or {})}
    def getheader(self, key):
        return self.headers.get(key)
    def read(self, size):
        assert 0 < size <= 16384
        return self.stream.read(size)
    def close(self):
        self.closed = True


def request(targets=None, **options):
    return {'connector': {'provider': 'azure', 'scopes': [SCOPE], 'auth': {'method': 'token', 'tenant_id': TENANT, 'arm_token': AUTH},
        'options': {'content_secret_scans': True, 'selected_azure_app_settings': targets or [SITE], 'retries': 0, **options}},
        'checks': [source.CHECK]}


def capture(monkeypatch, *, targets=None, data=None, identity=None, response=None, real=False, req=None, collect=True):
    targets = targets or [SITE]
    trace = SimpleNamespace(calls=[], responses=[], connections=[], scans=[], tokens=[])
    data = data if data is not None else {t: native(t) for t in targets}
    if not real:
        def detector(payload, path, timeout):
            trace.scans.append((bytes(payload), path, timeout))
            return [(TOKEN, 'github-pat', 1)] if TOKEN.encode() in payload else []
        monkeypatch.setattr(scanning, '_scan_kingfisher', detector)
        monkeypatch.setattr(scanning, '_scan_trufflehog', detector)
    class Transport:
        tenant = verified_tenant = TENANT
        def __init__(self, auth):
            pass
        def token(self, audience):
            assert audience == 'https://management.azure.com'
            trace.tokens.append(audience)
            return AUTH
        def request(self, *args, **kwargs):
            pytest.fail('generic ARM cache/enumeration cannot read selected content')
        def close(self):
            pass
    class Connection:
        sock = None
        def __init__(self, host, timeout):
            assert host == 'management.azure.com' and 0 < timeout <= 10
            trace.connections.append(self)
            self.closed = False
        def set_debuglevel(self, level):
            assert level == 0
        def request(self, method, route, body=None, headers=None):
            assert body is None and headers['Authorization'] == 'Bearer ' + AUTH
            assert headers['Accept-Encoding'] == 'identity'
            matches = [(t, operation) for t in targets for operation, verb, suffix in (
                ('identity', 'GET', ''), ('settings', 'POST', '/config/appsettings/list'))
                if method == verb and route == t + suffix + '?api-version=2025-03-01']
            assert len(matches) == 1, (method, route)
            t, operation = matches[0]
            trace.calls.append((method, 'management.azure.com', route))
            if response is not None and (not isinstance(response, tuple) or response[0] == operation):
                self.response = response[1] if isinstance(response, tuple) else response
            elif operation == 'identity':
                payload = {'id': t, 'name': t.rsplit('/',1)[1], 'type': 'Microsoft.Web/sites' + ('/slots' if '/slots/' in t else ''),
                    'kind': 'functionapp', 'properties': {'state': 'Running', 'neverRetain': TOKEN}}
                self.response = Response(identity if identity is not None else payload)
            else:
                self.response = Response(data[t])
            trace.responses.append(self.response)
        def getresponse(self):
            return self.response
        def close(self):
            self.closed = True
    monkeypatch.setattr(azure, 'AzureTransport', Transport)
    monkeypatch.setattr(source.http.client, 'HTTPSConnection', Connection)
    req = deepcopy(req if req is not None else request(targets))
    trace.req = req
    return (engine.collect_snapshot(req) if collect else req), trace


def findings(snapshot):
    return engine.evaluate_snapshot(snapshot, checks=[source.CHECK])['findings']


def index_of(snapshot, pos=0):
    collection = next(c for c in snapshot['collections'] if c['type'] == source.KIND)
    return collection['items'][pos], {'context': {'provider': 'azure', 'scope': collection['scope'], 'metadata': snapshot['metadata']},
        'collections': {source.KIND: [collection]}}


@pytest.mark.parametrize('target', [SITE, SLOT])
@pytest.mark.parametrize('positive', [False, True])
def test_native_collector_engine_and_opaque_retention(monkeypatch, target, positive):
    values = {'Mode': TOKEN if positive else 'ready = true'}
    snapshot, trace = capture(monkeypatch, targets=[target], data={target:native(target, values)})
    result = findings(snapshot)
    assert len(result) == 1 and result[0]['status'] == ('FAIL' if positive else 'PASS'), result
    item, index = index_of(snapshot)
    status, evidence = checks.evaluate(item, index)
    assert status == result[0]['status'] and evidence['complete'] is True
    assert evidence['coverage'] == 'selected_observed_literals_only'
    assert len(trace.scans) == 2 and len(trace.calls) == 2
    persisted = json.dumps([snapshot, result])
    assert all(value not in persisted for value in (TOKEN, AUTH, target, 'ready = true', 'neverRetain'))
    assert all(r.closed for r in trace.responses) and all(c.closed for c in trace.connections)


@pytest.mark.parametrize('target', [SITE, SLOT])
@pytest.mark.parametrize('positive', [False, True])
def test_real_dual_scanners(monkeypatch, target, positive):
    snapshot, trace = capture(monkeypatch, targets=[target], data={target:native(target, {'Token': TOKEN} if positive else {'Mode': 'ready = true'})}, real=True)
    result = findings(snapshot)
    assert len(result) == 1 and result[0]['status'] == ('FAIL' if positive else 'PASS'), result
    _, evidence = checks.evaluate(*index_of(snapshot))
    assert {(e['engine'], e['version'], e['status']) for e in evidence['parts'][0]['engines']} == {
        ('kingfisher', '1.4.0', 'complete'), ('trufflehog', '3.92.5', 'complete')}
    if positive:
        leak, = result[0]['evidence']['secret_leaks']
        assert {d['engine'] for d in leak['detectors']} == {'kingfisher', 'trufflehog'}
    assert TOKEN not in json.dumps([snapshot, result])
    assert all(r.closed for r in trace.responses)


@pytest.mark.parametrize('operation', ['identity', 'settings'])
@pytest.mark.parametrize('status', [201, 204, 206, 301, 307, 400, 401, 403, 404, 410, 429, 500])
def test_denied_deleted_partial_redirect_never_clean(monkeypatch, operation, status):
    snapshot, trace = capture(monkeypatch, response=(operation, Response({'error': {'message': TOKEN}},status)))
    assert {r['status'] for r in findings(snapshot)} == {'UNKNOWN'}
    assert not trace.scans and len(trace.calls) == (1 if operation == 'identity' else 2)
    assert TOKEN not in json.dumps(snapshot) and all(r.closed for r in trace.responses)


@pytest.mark.parametrize('identity', [
    {}, {'id': SITE}, {'id': SITE, 'type': 'Microsoft.Web/sites', 'properties': None},
    {'id': SITE+'/slots/foreign', 'type':'Microsoft.Web/sites/slots','properties':{}},
    {'id': SITE.replace(SCOPE, OTHER), 'type':'Microsoft.Web/sites','properties':{}},
    {'id': SITE, 'type':'Microsoft.Web/other','properties':{}},
])
def test_foreign_omitted_site_identity_never_reads_settings(monkeypatch, identity):
    snapshot, trace = capture(monkeypatch, identity=identity)
    assert {r['status'] for r in findings(snapshot)} == {'UNKNOWN'}
    assert len(trace.calls) == 1 and not trace.scans


@pytest.mark.parametrize('mutation', [
    lambda d:d.pop('id'), lambda d:d.update(id=OTHER+'/config/appsettings'),
    lambda d:d.pop('properties'), lambda d:d.update(properties={}),
    lambda d:d.update(properties={'Bad': None}), lambda d:d.update(properties={'Bad': {}}),
    lambda d:d.update(properties={'Bad': ''}), lambda d:d.update(properties={'Bad':'\x00'}),
    lambda d:d.update(properties={'Mode':'ready','mode':'conflicting'}),
    lambda d:d.update(type='Microsoft.Web/sites/configuration'), lambda d:d.update(name='foreign'),
    lambda d:d.update(nextLink='https://attacker.invalid/'+TOKEN),
    lambda d:d.update(properties={'Big':'x'*(source.MAX_VALUE+1)}),
    lambda d:d.update(properties={str(i):'x'*source.MAX_VALUE for i in range(5)}),
    lambda d:d.update(properties={str(i):'x' for i in range(source.MAX_SETTINGS+1)}),
    lambda d:d.update(properties={'Bad':'@Microsoft.KeyVault(SecretUri=https://attacker.invalid/secrets/fake)'}),
])
def test_omitted_unsupported_oversize_content_unknown(monkeypatch, mutation):
    data = native();mutation(data)
    snapshot, trace = capture(monkeypatch, data={SITE:data})
    assert {r['status'] for r in findings(snapshot)} == {'UNKNOWN'}
    assert not trace.scans and TOKEN not in json.dumps(snapshot)


@pytest.mark.parametrize('reference', [
    '@Microsoft.KeyVault(SecretUri=https://review-vault.vault.azure.net/secrets/example)',
    '@Microsoft.KeyVault(SecretUri=https://review-vault.vault.azure.net/secrets/example/abc123)',
    '@Microsoft.KeyVault(VaultName=review-vault;SecretName=example)',
    '@Microsoft.KeyVault(VaultName=review-vault;SecretName=example;SecretVersion=abc123)',
])
def test_keyvault_reference_excluded_no_dereference(monkeypatch, reference):
    snapshot, trace = capture(monkeypatch, data={SITE:native(values={'Reference':reference, 'Literal':'ready = true'})})
    assert findings(snapshot)[0]['status'] == 'PASS'
    _, evidence = checks.evaluate(*index_of(snapshot))
    assert evidence['literal_count'] == 1 and evidence['reference_count'] == 1
    assert len(trace.calls) == 2 and all(reference.encode() not in p for p, _, _ in trace.scans)
    assert reference not in json.dumps(snapshot)
    with monkeypatch.context() as patch:
        snapshot, trace = capture(patch, data={SITE:native(values={'Reference':reference})})
        assert findings(snapshot)[0]['status'] == 'UNKNOWN' and not trace.scans


@pytest.mark.parametrize('values', [None, [], {}, 'true', 1, True, [SITE]*2,
    [SITE.replace(SCOPE, OTHER)], [SITE+'?query=1'], [SITE+'#part'], [SITE+'/..'],
    [SITE+'%2Ffake'], ['https://management.azure.com'+SITE], [SITE.upper(),SITE], [SITE]*9])
def test_invalid_selection_before_credentials(monkeypatch, values):
    req = request();req['connector']['options'][source.OPTION] = values
    def forbidden(*a,**k):pytest.fail('invalid selection reached auth')
    monkeypatch.setattr(azure,'AzureTransport', forbidden)
    with pytest.raises(ValueError):engine.collect_snapshot(req)


@pytest.mark.parametrize('scopes', [[], ['*'], [OTHER], [SCOPE, SCOPE.upper()], ['https://management.azure.com'+SCOPE]])
def test_invalid_scope_before_credentials(monkeypatch, scopes):
    req = request();req['connector']['scopes']=scopes
    def forbidden(*a,**k):pytest.fail('invalid scope reached auth')
    monkeypatch.setattr(azure,'AzureTransport', forbidden)
    with pytest.raises(ValueError):engine.collect_snapshot(req)


@pytest.mark.parametrize('flag', [False, None])
def test_disabled_no_read(monkeypatch, flag):
    req=request();req['connector']['options'].pop('content_secret_scans')
    if flag is not None:req['connector']['options']['content_secret_scans']=flag
    snapshot,trace=capture(monkeypatch,req=req)
    assert not trace.calls and not trace.scans
    assert {r['status'] for r in findings(snapshot)} == {'UNKNOWN'}


def test_named_only_optin_cannot_be_forged(monkeypatch):
    req=request();req.pop('checks');req['categories']=['hardening']
    req['connector']['options']['inventories']=[source.KIND]
    req['connector']['options']['_content_secret_scan_kinds']=[source.KIND]
    snapshot,trace=capture(monkeypatch,req=req)
    assert not trace.calls and snapshot['metadata'][source.KIND+'_authorized'] is False
    assert source.KIND not in azure._selected({},None)
    assert source.KIND in engine.BULK_STREAM_TYPES['azure']


@pytest.mark.parametrize('failed', ['kingfisher','trufflehog'])
def test_each_scanner_failure_unknown(monkeypatch, failed):
    req,trace=capture(monkeypatch,collect=False)
    def unavailable(*a,**k):raise RuntimeError(TOKEN)
    monkeypatch.setattr(scanning,'_scan_'+failed,unavailable)
    snapshot=engine.collect_snapshot(req)
    assert findings(snapshot)[0]['status']=='UNKNOWN'
    assert TOKEN not in json.dumps(snapshot)


@pytest.mark.parametrize('headers', [
    {'Content-Length':'99999999'}, {'Content-Length':'0'}, {'Content-Length':'abc'},
    {'Content-Encoding':'gzip'}, {'Content-Type':'text/html'},
])
def test_wire_headers_partial_oversize_unknown(monkeypatch,headers):
    snapshot,trace=capture(monkeypatch,response=('settings',Response(native(),headers=headers)))
    assert findings(snapshot)[0]['status']=='UNKNOWN' and not trace.scans
    assert all(r.closed for r in trace.responses)


@pytest.mark.parametrize('raw', [b'{"properties":{},"properties":{}}',b'{"id":NaN}',b'not-json',b'\xff',b'{} trailing'])
def test_malformed_json_unknown(monkeypatch,raw):
    snapshot,trace=capture(monkeypatch,response=('settings',Response(raw)))
    assert findings(snapshot)[0]['status']=='UNKNOWN' and not trace.scans


@pytest.mark.parametrize('mutator', [
    lambda s,i:i[source.MARKER].update(complete=False),
    lambda s,i:i[source.MARKER].update(scope=OTHER),
    lambda s,i:i[source.MARKER].update(identity='foreign'),
    lambda s,i:i[source.MARKER].update(source_requests=[]),
    lambda s,i:i[source.MARKER]['parts'][0]['engines'].pop(),
    lambda s,i:i[source.MARKER]['parts'][0]['engines'][0].update(version='other'),
    lambda s,i:i[source.MARKER]['parts'][0].update(bytes=0),
    lambda s,i:i['_provenance'].update(credential_context_id='foreign'),
    lambda s,i:s['metadata'].update(context_binding='foreign'),
    lambda s,i:s['metadata'][source.KIND+'_receipts'][0].update(identity_bound=False),
    lambda s,i:s['metadata'][source.KIND+'_receipts'][1].update(method='GET'),
    lambda s,i:s['metadata'][source.KIND+'_selection'][SCOPE].append('foreign'),
    lambda s,i:s['collections'][0]['items'].append(deepcopy(i)),
    lambda s,i:s['collections'][0].update(status='partial'),
])
def test_pure_consumer_rejects_forged_incomplete_coherence(monkeypatch,mutator):
    snapshot,_=capture(monkeypatch);item,_=index_of(snapshot)
    mutator(snapshot,item)
    assert checks.evaluate(*index_of(snapshot))[0]=='UNKNOWN'


def test_cross_site_value_dedup_and_metadata_secret_redaction(monkeypatch):
    target=SITE.replace('/resourceGroups/review/', '/resourceGroups/'+TOKEN+'/')
    targets=[target,SLOT]
    snapshot,trace=capture(monkeypatch,targets=targets,data={t:native(t,{TOKEN:TOKEN}) for t in targets})
    result=findings(snapshot)
    assert len(result)==1 and result[0]['status']=='FAIL'
    leak,=result[0]['evidence']['secret_leaks']
    assert len(leak['locations'])==2 and {d['engine'] for d in leak['detectors']}=={'kingfisher','trufflehog'}
    assert TOKEN not in json.dumps([snapshot,result])
    assert len(trace.calls)==4


def test_real_runner_unverified_flags_and_cleanup(monkeypatch):
    calls=[];original=scanning._run
    def run(argv,payload,timeout):
        calls.append(list(argv));return original(argv,payload,timeout)
    monkeypatch.setattr(scanning,'_run',run)
    snapshot,trace=capture(monkeypatch,data={SITE:native(values={'Token':TOKEN})},real=True)
    assert findings(snapshot)[0]['status']=='FAIL'
    runs=[c for c in calls if 'stdin' in c]
    assert runs
    for argv in runs:
        assert {'stdin','--json','--no-verification','--no-update','--no-verification-cache','--force-skip-archives','--fail-on-scan-errors','--concurrency=1'}<=set(argv)
    assert all(r.closed for r in trace.responses) and all(c.closed for c in trace.connections)


def test_bounds_call_budget_deadline_and_total_wire(monkeypatch):
    for options in ({'max_calls':1},{'max_resources':1}):
        with monkeypatch.context() as patch:
            targets=[SITE,SLOT]
            snapshot,trace=capture(patch,targets=targets,req=request(targets,**options))
            assert {r['status'] for r in findings(snapshot)}=={'UNKNOWN'}
    with monkeypatch.context() as patch:
        patch.setattr(source,'MAX_TOTAL',1)
        snapshot,trace=capture(patch)
        assert findings(snapshot)[0]['status']=='UNKNOWN' and not trace.scans
    with monkeypatch.context() as patch:
        patch.setattr(source,'MAX_SECONDS',-1)
        snapshot,trace=capture(patch)
        assert findings(snapshot)[0]['status']=='UNKNOWN' and not trace.calls


def test_native_derived_fixture_receipt(monkeypatch):
    cases={}
    for status in ('PASS','FAIL','UNKNOWN'):
        with monkeypatch.context() as patch:
            values={'Mode':TOKEN} if status=='FAIL' else {'Mode':'ready = true'}
            snapshot,_=capture(patch,real=True,data={SITE:native(values=values)},response=('settings',Response({},403)) if status=='UNKNOWN' else None)
            assert findings(snapshot)[0]['status']==status
            item,index=index_of(snapshot)
            cases[status.lower()]=deepcopy(item)
            cases[status.lower()+'_index']=deepcopy(index)
    cases['index']=deepcopy(cases['pass_index'])
    cases['missing']={}
    cases['malformed']={source.MARKER:None}
    receipt=Path('/tmp/peasso-secret-surface-review-20261020/azure-app-settings/native-fixtures.json')
    receipt.parent.mkdir(parents=True,exist_ok=True)
    receipt.write_text(json.dumps({source.CHECK:cases},sort_keys=True,indent=2)+'\n')


def test_multiple_explicit_subscriptions_and_native_case_alias(monkeypatch):
    targets=[SITE.upper(),SLOT.replace(SCOPE,OTHER)]
    req=request(targets);req['connector']['scopes']=[SCOPE,OTHER]
    data={t:native(t) for t in targets}
    # ARM identity comparisons are case insensitive; routing retains exact input.
    for t in targets:data[t]['id']=data[t]['id'].lower()
    snapshot,trace=capture(monkeypatch,targets=targets,data=data,req=req)
    assert len(trace.calls)==4 and {r['status'] for r in findings(snapshot)}=={'PASS'}
    assert len(findings(snapshot))==2
    assert all(t not in json.dumps(snapshot) for t in targets)


def test_eight_selection_bound_and_no_implicit_slots(monkeypatch):
    targets=[SITE+'/slots/selected-'+str(i) for i in range(8)]
    snapshot,trace=capture(monkeypatch,targets=targets)
    assert len(trace.calls)==16 and len(findings(snapshot))==8
    assert {r['status'] for r in findings(snapshot)}=={'PASS'}
    assert {route.split('?')[0] for _,_,route in trace.calls}=={t+suffix for t in targets for suffix in ('','/config/appsettings/list')}


@pytest.mark.parametrize('flag',['true',1,{},None])
def test_public_boolean_strict_before_credentials(monkeypatch,flag):
    req=request(content_secret_scans=flag)
    with pytest.raises(ValueError):engine._request(req)


def test_missing_selected_targets_and_wildcard_scope_rejected(monkeypatch):
    # An absent selector means automatic native discovery (f1434b2a); an
    # explicit empty or malformed selector is still rejected.
    from peaso import content_scan_selection
    req=request();req['connector']['options'].pop(source.OPTION)
    engine._request(req)
    assert source.CHECK in content_scan_selection.configured_checks('azure',req['connector']['options'])['leaks']
    for value in ([],'x',['not-a-site']):
        req=request();req['connector']['options'][source.OPTION]=value
        with pytest.raises(ValueError):engine._request(req)
    req=request();req['connector']['scopes']=['*',SCOPE]
    with pytest.raises(ValueError):engine._request(req)


@pytest.mark.parametrize('key',['partial','_partial','hasMore','resultTruncated','continuationToken'])
def test_native_partial_markers_preserve_unknown(monkeypatch,key):
    data=native();data[key]=True
    snapshot,trace=capture(monkeypatch,data={SITE:data})
    assert findings(snapshot)[0]['status']=='UNKNOWN' and not trace.scans


def test_registered_native_derived_cases_and_no_numbered_requirements():
    from peaso.checks import CHECKS
    from peaso.checks.fixtures import CASES
    check, = [c for c in CHECKS if c.id == source.CHECK]
    assert check.kind == source.KIND and check.dependencies == [source.KIND] and check.severity == 'high'
    assert checks.DECLARATIONS[0]['finding_type'] == 'secrets' and checks.DECLARATIONS[0]['requirements'] == []
    cases=CASES[source.CHECK]
    for status in ('pass','fail','unknown'):
        assert check.evaluate(cases[status],cases[status+'_index'])[0] == status.upper()
    for shape in ('missing','malformed'):
        assert check.evaluate(cases[shape],cases['index'])[0] == 'UNKNOWN'


def test_current_source_admission_and_native_fixture_hashes():
    import hashlib
    import inspect
    path=Path('peaso/checks/azure_app_settings_secret_review_20261020_admission.json')
    admission=json.loads(path.read_text())
    assert admission['declarations']==checks.DECLARATIONS
    for name,expected in admission['source_hashes'].items():
        assert_source_receipt(name,expected)
    assert hashlib.sha256(Path(admission['fixture']['path']).read_bytes()).hexdigest()==admission['fixture']['sha256']
    assert admission['checks'][source.CHECK]['predicate_sha256']==hashlib.sha256(inspect.getsource(checks.evaluate).encode()).hexdigest()
