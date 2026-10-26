"""Independent native HTTP -> real AzureTransport/production collector/public engine.

Exact reviewed registry identities; no candidate hook or registry injection.
Native payloads remain independent of historical CASES. No live IO/auth.
"""
import base64
from copy import deepcopy
import hashlib
import inspect
import io
import json
import os
from pathlib import Path
import socket
import time
from types import SimpleNamespace
from urllib.parse import quote

import pytest
from peaso import checks, engine, secret_scanning as scanning
from peaso.collectors import azure
from peaso.collectors import azure_selected_declaration_secret_indicators as source
from peaso.checks import azure_selected_declaration_secret_review_20261020 as consumer

SCOPE = '/subscriptions/11111111-1111-1111-1111-111111111111'
FOREIGN = '/subscriptions/33333333-3333-3333-3333-333333333333'
TENANT = '22222222-2222-2222-2222-222222222222'
PRODUCTION_TYPES = tuple(azure.TYPES)
PREFIX = SCOPE + '/resourceGroups/review/providers/'
TOKEN = 'ghp_' + '7mQ2zR9wL4cV8nK1sF6aH3jP5uD0xB2yE9rT'
AUTH = 'offline-client-secret-never-export'
NATIVE = {
    'app_configuration': ('Microsoft.AppConfiguration/configurationStores/storeone', 'Microsoft.AppConfiguration/configurationStores'),
    'adf_pipeline': ('Microsoft.DataFactory/factories/factoryone/pipelines/selected', 'Microsoft.DataFactory/factories/pipelines'),
    'adf_dataflow': ('Microsoft.DataFactory/factories/factoryone/dataflows/selected', 'Microsoft.DataFactory/factories/dataflows'),
    'synapse': ('Microsoft.Synapse/workspaces/workspaceone/pipelines/selected', 'Microsoft.Synapse/workspaces/pipelines'),
}

def profile(surface): return 'data_factory' if surface.startswith('adf_') else surface

def target(surface):
    result = {'resource_id': PREFIX + NATIVE[surface][0]}
    if surface == 'app_configuration': result.update(key='App/Selected', label=None)
    return result


def native(surface, literal, selected):
    if surface == 'app_configuration':
        return {'key': selected['key'], 'label': selected['label'], 'etag': 'native-etag-1', 'value': literal,
            'content_type': None, 'locked': False, 'last_modified': '2026-10-20T00:00:00Z', 'tags': {}}
    props = ({'activities': [{'name': 'selected', 'type': 'SetVariable',
        'typeProperties': {'variableName': 'Mode', 'value': literal}}], 'variables': {'Mode': {'type': 'String', 'defaultValue': 'ready'}}}
        if surface != 'adf_dataflow' else {'type': 'MappingDataFlow', 'typeProperties': {'scriptLines': ["source(output(Mode as string)) ~> inline", literal], 'sources': [], 'sinks': [], 'transformations': []}})
    return {'id': selected['resource_id'], 'name': selected['resource_id'].rsplit('/', 1)[1],
        'type': NATIVE[surface][1], 'etag': 'native-etag-1', 'properties': props}


class Response:
    def __init__(self, payload, status=200, headers=None):
        self.raw = json.dumps(payload).encode() if isinstance(payload, dict) else payload
        self.stream = io.BytesIO(self.raw); self.status = status; self.closed = False; self.reads = 0
        self.headers = {'Content-Type': 'application/json', 'Content-Length': str(len(self.raw)), **(headers or {})}
    def getheader(self, name): return self.headers.get(name)
    def read(self, size):
        assert 0 < size <= 16384; self.reads += 1; return self.stream.read(size)
    def close(self): self.closed = True


def jwt(audience, tenant):
    def b64(value): return base64.urlsafe_b64encode(json.dumps(value).encode()).decode().rstrip('=')
    return b64({'alg': 'none'}) + '.' + b64({'aud': audience, 'tid': tenant, 'exp': int(time.time()) + 3600, 'oid': TENANT}) + '.offline'


@pytest.fixture(autouse=True)
def offline(monkeypatch):
    def blocked(*a, **kw): pytest.fail('live socket/DNS/default identity forbidden')
    for name in ('connect', 'connect_ex', 'sendto'): monkeypatch.setattr(socket.socket, name, blocked)
    for name in ('getaddrinfo', 'gethostbyname', 'gethostbyname_ex', 'create_connection'): monkeypatch.setattr(socket, name, blocked)
    monkeypatch.setattr(azure, 'credential_for', blocked)
    scanning._RESULTS.clear()
    for name, p in source.PROFILES.items():
        registered, = [check for check in engine._registry() if check.id == p['check']]
        assert inspect.unwrap(registered.evaluate) is consumer.EVALUATORS[name]
        assert registered.kind == p['kind'] and registered.allow_incomplete_failure
    yield
    scanning._RESULTS.clear()


def collect(monkeypatch, surface='app_configuration', literal='mode=ready', *, real=False, transform=None, fault=None,
            options=None, targets=None, scopes=None, missing_engine=None, claims_tenant=TENANT, claims_audience=None, named=True):
    scopes = scopes or [SCOPE]; targets = targets or [(surface, target(surface))]
    trace = SimpleNamespace(calls=[], responses=[], connections=[], tokens=[], scans=[], readers=[])
    if not real:
        def scan(raw, path, timeout):
            trace.scans.append((len(raw), path)); return [(TOKEN, 'github-pat', 1)] if TOKEN.encode() in raw else []
        monkeypatch.setattr(scanning, '_scan_kingfisher', scan); monkeypatch.setattr(scanning, '_scan_trufflehog', scan)
    if missing_engine:
        def unavailable(*a, **kw): raise RuntimeError(TOKEN)
        monkeypatch.setattr(scanning, '_scan_' + missing_engine, unavailable)
    class Credential:
        def get_token(self, scope):
            assert scope in ('https://management.azure.com/.default', 'https://azconfig.io/.default', 'https://dev.azuresynapse.net/.default')
            trace.tokens.append(scope)
            return SimpleNamespace(token=jwt(claims_audience or scope.removesuffix('/.default'), claims_tenant), expires_on=int(time.time()) + 3600)
        def close(self): pass
    # Real AzureTransport.token handles audience/tenant separation and caching.
    monkeypatch.setattr(azure, 'credential_for', lambda auth: Credential())
    class Connection:
        sock = None
        def __init__(self, host, timeout):
            assert host in ('management.azure.com', 'storeone.azconfig.io', 'workspaceone.dev.azuresynapse.net')
            assert 0 < timeout <= 10
            self.host = host; self.closed = False; trace.connections.append(self)
        def set_debuglevel(self, value): assert value == 0
        def request(self, method, path, body=None, headers=None):
            assert method == 'GET' and body is None
            assert headers['Accept-Encoding'] == 'identity' and headers['Content-Length'] == '0'
            assert headers['Authorization'].startswith('Bearer ') and 'offline' in headers['Authorization']
            operation = None; t = None; current_surface = None
            if self.host == 'management.azure.com' and path == SCOPE + '?api-version=2022-12-01':
                operation = 'subscription'; data = {'id': SCOPE, 'subscriptionId': SCOPE.rsplit('/',1)[1], 'tenantId': TENANT, 'state': 'Enabled'}
            else:
                for candidate_surface, candidate in targets:
                    rid = candidate['resource_id']
                    if candidate_surface == 'app_configuration':
                        if self.host == 'management.azure.com' and path == rid + '?api-version=2024-06-01':
                            operation = 'store'; data = {'id': rid, 'name': 'storeone', 'type': 'Microsoft.AppConfiguration/configurationStores', 'properties': {'endpoint': 'https://storeone.azconfig.io', 'provisioningState': 'Succeeded'}}
                        elif self.host == 'storeone.azconfig.io' and path == '/kv/' + quote(candidate['key'], safe='') + '?label=' + ('%00' if candidate['label'] is None else quote(candidate['label'], safe='')) + '&api-version=1.0':
                            operation = 'key_bound' if 'If-Match' in headers else 'key'
                            if operation == 'key_bound': assert headers['If-Match'] == '"native-etag-1"'
                            data = native(candidate_surface, literal, candidate)
                    elif candidate_surface == 'synapse':
                        wid = rid.rsplit('/pipelines/',1)[0]
                        if self.host == 'management.azure.com' and path == wid + '?api-version=2021-06-01':
                            operation = 'workspace'; data = {'id': wid, 'name': 'workspaceone', 'type': 'Microsoft.Synapse/workspaces', 'properties': {'connectivityEndpoints': {'dev': 'https://workspaceone.dev.azuresynapse.net'}, 'provisioningState': 'Succeeded'}}
                        elif self.host == 'workspaceone.dev.azuresynapse.net' and path == '/pipelines/selected?api-version=2020-12-01':
                            operation = 'pipeline'; data = native(candidate_surface, literal, candidate)
                    elif self.host == 'management.azure.com' and path == rid + '?api-version=2018-06-01':
                        operation = 'declaration'; data = native(candidate_surface, literal, candidate)
                    if operation:
                        t = candidate; current_surface = candidate_surface; break
            assert operation is not None, (self.host, path)
            trace.calls.append((method, self.host, path, operation))
            if transform: data = transform(current_surface or surface, operation, deepcopy(data))
            response = Response(data, headers={'ETag': '"native-etag-1"'} if operation in ('key','key_bound','declaration','pipeline') else {})
            if fault: response = fault(current_surface or surface, operation, response)
            self.response = response; trace.responses.append(response)
        def getresponse(self): return self.response
        def close(self): self.closed = True
    monkeypatch.setattr(source.http.client, 'HTTPSConnection', Connection)
    selected_options = {'content_secret_scans': True, 'retries': 0}
    for s, t in targets: selected_options.setdefault(source.PROFILES[profile(s)]['option'], []).append(t)
    selected_options.update(options or {})
    ids = list(dict.fromkeys(source.PROFILES[profile(s)]['check'] for s,t in targets)) if named else []
    original_init = azure._Reader.__init__
    def init(reader, *a, **kw):
        original_init(reader, *a, **kw); trace.readers.append(reader)
    monkeypatch.setattr(azure._Reader, '__init__', init)
    req = {'connector': {'provider': 'azure', 'scopes': scopes,
        'auth': {'method': 'client-secret', 'tenant_id': TENANT, 'client_id': TENANT, 'client_secret': AUTH}, 'options': selected_options}, 'checks': ids}
    if not named:
        # Admission-only branch: actual category planner and named-kind gate,
        # with a transport sentinel so unrelated metadata is never read.
        import peaso.collectors as collectors
        from peaso.snapshot import make_snapshot
        req['categories'] = ['hardening']
        def unnamed(connector, requirements=None):
            assert not (set(source.KINDS) & set(connector['options']['_content_secret_scan_kinds']))
            return make_snapshot('azure', scopes, [], metadata={})
        monkeypatch.setattr(collectors, 'collect_live', unnamed)
    snapshot = engine.collect_snapshot(req)
    rows = engine.evaluate_snapshot(snapshot, checks=req['checks'] if named else [source.PROFILES[profile(surface)]['check']])['findings']
    return snapshot, rows, trace


def own(snapshot, surface):
    kind = source.PROFILES[profile(surface)]['kind']
    return next(c for c in snapshot['collections'] if c['type'] == kind)


@pytest.mark.parametrize('surface', NATIVE)
@pytest.mark.parametrize('hit', [False, True])
def test_native_four_surfaces_public_engine(monkeypatch, surface, hit):
    snapshot, rows, trace = collect(monkeypatch, surface, TOKEN if hit else 'mode=ready')
    assert [r['status'] for r in rows] == ['FAIL' if hit else 'PASS'], rows
    assert len(trace.scans) == 2 and len(trace.calls) == {'app_configuration':4, 'adf_pipeline':2,'adf_dataflow':2,'synapse':3}[surface]
    assert TOKEN not in json.dumps([snapshot, rows]) and AUTH not in json.dumps(snapshot)
    assert target(surface)['resource_id'] not in json.dumps(snapshot)
    assert all(r.closed for r in trace.responses) and all(c.closed for c in trace.connections)
    assert trace.readers and not trace.readers[0].configuration_secret_redactions
    if os.environ.get('AZURE_DECLARATION_CAPTURE_DIR'):
        p = Path(os.environ['AZURE_DECLARATION_CAPTURE_DIR']); p.mkdir(parents=True, exist_ok=True)
        (p / (surface + ('-fail' if hit else '-pass') + '.json')).write_text(json.dumps({'surface':surface,'snapshot':snapshot,'findings':rows,'http':trace.calls},sort_keys=True,indent=2))


@pytest.mark.parametrize('surface', NATIVE)
@pytest.mark.parametrize('hit', [False, True])
def test_pinned_real_dual_engines_and_one_value_dedup(monkeypatch, surface, hit):
    snapshot, rows, trace = collect(monkeypatch, surface, TOKEN if hit else 'mode=ready', real=True)
    assert [r['status'] for r in rows] == ['FAIL' if hit else 'PASS'], rows
    marker = own(snapshot, surface)['items'][0][source.MARKER]
    assert {e['status']for e in marker['parts'][0]['engines']} == {'complete'}
    if hit:
        leak, = marker['leaks']; assert {d['engine']for d in leak['detectors']} == {'kingfisher','trufflehog'}
    if os.environ.get('AZURE_DECLARATION_CAPTURE_DIR'):
        p=Path(os.environ['AZURE_DECLARATION_CAPTURE_DIR']);p.mkdir(parents=True,exist_ok=True)
        (p/(surface+('-fail'if hit else'-pass')+'.json')).write_text(json.dumps({'surface':surface,'native_real_detectors':True,'snapshot':snapshot,'findings':rows,'http':trace.calls},sort_keys=True,indent=2))


@pytest.mark.parametrize('surface', NATIVE)
@pytest.mark.parametrize('mutation', ['denied','deleted','redirect','truncated','empty','partial','foreign','type','name','duplicate','wrong_version','encoding','etag_missing','etag_header','endpoint'])
def test_native_unavailable_identity_partial_matrix(monkeypatch, surface, mutation):
    final = 'key_bound' if surface == 'app_configuration' else 'pipeline' if surface == 'synapse' else 'declaration'
    def transform(s, op, data):
        if op == final:
            if mutation == 'partial': data['nextLink'] = 'https://evil.invalid/' + TOKEN
            if mutation == 'foreign':
                if surface == 'app_configuration': data['key'] = 'foreign'
                else: data['id'] = data['id'].replace(SCOPE,FOREIGN)
            if mutation == 'type':
                if surface == 'app_configuration': data['value'] = None
                else: data['type'] = 'Microsoft.Unrelated/resources'
            if mutation == 'name':
                if surface == 'app_configuration': data['label'] = 'foreign'
                else: data['name'] = 'foreign'
            if mutation == 'etag_missing': data.pop('etag',None)
        if mutation == 'endpoint' and op in ('store','workspace'):
            props = data['properties']
            if op == 'store': props['endpoint'] = 'https://evil.invalid/' + TOKEN
            else: props['connectivityEndpoints']['dev'] = 'https://evil.invalid/' + TOKEN
        if mutation == 'endpoint' and op == final and surface.startswith('adf_'): data['id'] += '-sibling'
        return data
    def fault(s, op, response):
        if op != final: return response
        if mutation in ('denied','deleted','redirect','wrong_version'): return Response({'error':TOKEN}, {'denied':403,'deleted':404,'redirect':302,'wrong_version':400}[mutation])
        if mutation == 'empty': return Response(b'')
        if mutation == 'duplicate': return Response(b'{"etag":"native-etag-1","etag":"'+TOKEN.encode()+b'"}')
        if mutation == 'truncated': response.headers['Content-Length'] = str(len(response.raw)+1)
        if mutation == 'encoding': response.headers['Content-Encoding'] = 'gzip'
        if mutation == 'etag_header': response.headers['ETag'] = '"different"'
        return response
    snapshot, rows, trace = collect(monkeypatch, surface, transform=transform, fault=fault)
    assert [r['status'] for r in rows] == ['UNKNOWN'], rows
    assert not trace.scans and TOKEN not in json.dumps([snapshot,rows])
    assert all(r.closed for r in trace.responses)
    if mutation == 'denied' and os.environ.get('AZURE_DECLARATION_CAPTURE_DIR'):
        p=Path(os.environ['AZURE_DECLARATION_CAPTURE_DIR']);p.mkdir(parents=True,exist_ok=True)
        (p/(surface+'-unknown.json')).write_text(json.dumps({'surface':surface,'snapshot':snapshot,'findings':rows,'http':trace.calls},sort_keys=True,indent=2))


@pytest.mark.parametrize('surface', NATIVE)
@pytest.mark.parametrize('missing_engine', ['kingfisher','trufflehog'])
@pytest.mark.parametrize('hit', [False,True])
def test_one_real_engine_missing_never_clean_and_trusted_hit_decisive(monkeypatch,surface,missing_engine,hit):
    snapshot,rows,_ = collect(monkeypatch,surface,TOKEN if hit else 'mode=ready',real=True,missing_engine=missing_engine)
    assert [r['status']for r in rows] == ['FAIL' if hit else 'UNKNOWN'],rows
    assert own(snapshot,surface)['items'][0][source.MARKER]['complete'] is False


@pytest.mark.parametrize('surface', NATIVE)
@pytest.mark.parametrize('mutation', ['flag','named','tenant','audience','subtenant','subscope','subdisabled'])
def test_authorization_scope_binding(monkeypatch,surface,mutation):
    def transform(s,op,data):
        if op == 'subscription':
            if mutation == 'subtenant':data['tenantId']=FOREIGN.rsplit('/',1)[1]
            if mutation == 'subscope':data['id']=FOREIGN
            if mutation == 'subdisabled':data['state']='Disabled'
        return data
    snapshot,rows,trace=collect(monkeypatch,surface,options={'content_secret_scans':False}if mutation=='flag' else None,
        named=mutation!='named',claims_tenant=FOREIGN.rsplit('/',1)[1]if mutation=='tenant'else TENANT,
        claims_audience='https://foreign.invalid'if mutation=='audience'else None,transform=transform)
    assert {r['status']for r in rows} == {'UNKNOWN'},rows
    assert not trace.scans
    if mutation in ('flag','named','tenant','audience'):assert not trace.calls


@pytest.mark.parametrize('surface',NATIVE)
@pytest.mark.parametrize('budget',['MAX_WIRE','MAX_TOTAL','MAX_CONTENT','MAX_CALLS','MAX_SECONDS','MAX_VALUES'])
def test_finite_budgets_never_clean(monkeypatch,surface,budget):
    monkeypatch.setattr(source,budget,0)
    _,rows,_=collect(monkeypatch,surface)
    assert {r['status']for r in rows}=={'UNKNOWN'}


@pytest.mark.parametrize('surface',['adf_pipeline','adf_dataflow','synapse'])
@pytest.mark.parametrize('hit',[False,True])
def test_public_literals_detected_while_protected_refs_excluded(monkeypatch,surface,hit):
    def transform(s,op,data):
        if op in ('declaration','pipeline'):
            if surface=='adf_dataflow':data['properties']['typeProperties']['sources']=[{'dataset':{'type':'DatasetReference','referenceName':TOKEN}}]
            else:data['properties']['parameters']={'Password':{'type':'SecureString','defaultValue':TOKEN},'Endpoint':{'type':'String','defaultValue':'@Microsoft.KeyVault(SecretUri=https://vault.invalid/secret)'}}
        return data
    snapshot,rows,_=collect(monkeypatch,surface,TOKEN if hit else 'mode=ready',transform=transform)
    assert {r['status']for r in rows}=={'FAIL'if hit else'UNKNOWN'},rows
    assert TOKEN not in json.dumps(snapshot)


@pytest.mark.parametrize('content_type',['application/vnd.microsoft.appconfig.keyvaultref+json;charset=utf-8','application/encrypted'])
def test_appconfig_secret_reference_not_read_or_claimed_leak(monkeypatch,content_type):
    def transform(s,op,data):
        if op=='key':data['content_type']=content_type;data['value']=TOKEN
        return data
    _,rows,trace=collect(monkeypatch,transform=transform)
    assert {r['status']for r in rows}=={'UNKNOWN'} and not trace.scans
    assert [c[-1]for c in trace.calls]==['subscription','store','key']


@pytest.mark.parametrize('change',['etag','value'])
def test_appconfig_second_read_etag_and_body_coherence(monkeypatch,change):
    def transform(s,op,data):
        if op=='key_bound':data[change]='changed'
        return data
    _,rows,trace=collect(monkeypatch,transform=transform)
    assert {r['status']for r in rows}=={'UNKNOWN'}and not trace.scans


def test_same_value_cross_three_profiles_dedup_and_union_redaction(monkeypatch):
    targets=[(s,target(s))for s in ('app_configuration','adf_pipeline','synapse')]
    snapshot,rows,_=collect(monkeypatch,literal=TOKEN,targets=targets,real=True)
    assert len(rows)==1 and {r['status']for r in rows}=={'FAIL'},rows
    assert sum(len(c['items'])for c in snapshot['collections']if c['type']in source.KINDS)==3
    fingerprints={l['fingerprint']for c in snapshot['collections']for i in c['items']for l in i.get(source.MARKER,{}).get('leaks',[])}
    assert len(fingerprints)==1 and TOKEN not in json.dumps([snapshot,rows])


@pytest.mark.parametrize('surface',NATIVE)
@pytest.mark.parametrize('bad',['empty','foreign','extra','url','duplicate','scope_duplicate'])
def test_pure_selector_rejects_without_auth(surface,bad):
    t=target(surface);p=profile(surface);scopes=[SCOPE];targets=[t]
    if bad=='empty':targets=[]
    if bad=='foreign':t['resource_id']=t['resource_id'].replace(SCOPE,FOREIGN)
    if bad=='extra':t['endpoint']='https://evil.invalid'
    if bad=='url':t['resource_id']='https://management.azure.com'+t['resource_id']
    if bad=='duplicate':targets=[t,deepcopy(t)]
    if bad=='scope_duplicate':scopes=[SCOPE,SCOPE.upper()]
    with pytest.raises(source.Incomplete):source.selected_targets({source.PROFILES[p]['option']:targets},scopes,p)


def test_reviewed_import_preserves_registered_identity_and_native_cases():
    from peaso.checks.fixtures import CASES
    assert set(source.KINDS) <= set(PRODUCTION_TYPES)
    for p in source.PROFILES.values():
        registered, = [check for check in checks.CHECKS if check.id == p['check']]
        assert inspect.unwrap(registered.evaluate) is consumer.EVALUATORS[next(name for name, detail in source.PROFILES.items() if detail is p)]
        assert all(branch in CASES[p['check']] for branch in ('pass','fail','unknown'))
    assert len(consumer.DECLARATIONS)==3 and all(d['ui_group']=='Secrets'and d['requirements']==[]for d in consumer.DECLARATIONS)


@pytest.mark.parametrize('surface',NATIVE)
@pytest.mark.parametrize('mutation',['selection','capture','scope','credential','customer','receipt','host_class','status','version','parts','duplicate','authorized'])
def test_consumer_rejects_unbound_or_forged_native_marker(monkeypatch,surface,mutation):
    snapshot,rows,_=collect(monkeypatch,surface)
    collection=own(snapshot,surface);item=deepcopy(collection['items'][0]);kind=source.PROFILES[profile(surface)]['kind']
    index={'context':{'provider':'azure','scope':SCOPE,'metadata':deepcopy(snapshot['metadata'])},'collections':{kind:[deepcopy(collection)]}}
    marker=item[source.MARKER];meta=index['context']['metadata']
    if mutation=='selection':meta[kind+'_selection'][SCOPE]=[]
    if mutation=='capture':marker['capture']='declaration-capture:'+'0'*32
    if mutation=='scope':item['_provenance']['scope']=FOREIGN
    if mutation=='credential':item['_provenance']['credential_context_id']='foreign'
    if mutation=='customer':item['_provenance']['customer_context_id']='foreign'
    if mutation=='receipt':meta[kind+'_receipts'][-1]['identity_bound']=False
    if mutation=='host_class':meta[kind+'_receipts'][-1]['host_class']='foreign'
    if mutation=='status':meta[kind+'_receipts'][-1]['status']='unavailable'
    if mutation=='version':marker['parts'][0]['engines'][0]['version']='invented'
    if mutation=='parts':marker['parts'][0]['complete']=False
    if mutation=='duplicate':index['collections'][kind][0]['items'].append(deepcopy(item))
    if mutation=='authorized':meta[kind+'_authorized']=False
    if mutation!='duplicate':index['collections'][kind][0]['items']=[item]
    assert consumer.EVALUATORS[profile(surface)](item,index)[0]=='UNKNOWN'


@pytest.mark.parametrize('surface',['adf_pipeline','synapse'])
@pytest.mark.parametrize('activities',[[],[None],[{'name':'selected','type':'SetVariable'}]])
def test_empty_or_malformed_native_activity_cannot_clean(monkeypatch,surface,activities):
    def transform(s,op,data):
        if op in('declaration','pipeline'):data['properties']['activities']=activities
        return data
    _,rows,trace=collect(monkeypatch,surface,transform=transform)
    assert {r['status']for r in rows}=={'UNKNOWN'}and not trace.scans


def test_appconfig_exact_key_label_case_sensitive_and_query_escaped(monkeypatch):
    t=target('app_configuration');t.update(key='App/Path ?#=',label='Production A&B')
    snapshot,rows,trace=collect(monkeypatch,targets=[('app_configuration',t)])
    assert {r['status']for r in rows}=={'PASS'}
    assert trace.calls[-1][2]=='/kv/App%2FPath%20%3F%23%3D?label=Production%20A%26B&api-version=1.0'
    other=deepcopy(t);other['key']=t['key'].lower()
    assert source.identity('app_configuration',t)!=source.identity('app_configuration',other)


def test_completed_hit_retained_under_finding_budget(monkeypatch):
    monkeypatch.setattr(source,'MAX_LEAKS',1)
    # Distinct raw values are produced only inside detector callbacks, no fixture/export values.
    second='ghp_'+'9hK3vP6xM7cQ2bL8nR4dF1sA0zJ5wT6uY7eC'
    def scan(raw,path,timeout):return[(TOKEN,'github-pat',1),(second,'github-pat',2)]
    # Hook after driver sets its own finite runner; use real=True to preserve ours.
    monkeypatch.setattr(scanning,'_scan_kingfisher',scan);monkeypatch.setattr(scanning,'_scan_trufflehog',scan)
    snapshot,rows,_=collect(monkeypatch,literal=TOKEN,real=True)
    assert {r['status']for r in rows}=={'FAIL'}
    marker=own(snapshot,'app_configuration')['items'][0][source.MARKER]
    assert len(marker['leaks'])==1 and marker['complete']is False
    assert TOKEN not in json.dumps(snapshot)and second not in json.dumps(snapshot)


@pytest.mark.parametrize('field,value',[('scriptLines',['mode=ready',None]),('sources',{}),('sinks',[None]),('transformations','unsupported')])
def test_malformed_dataflow_fields_do_not_make_clean(monkeypatch,field,value):
    def transform(s,op,data):
        if op=='declaration':data['properties']['typeProperties'][field]=value
        return data
    _,rows,trace=collect(monkeypatch,'adf_dataflow',transform=transform)
    assert {r['status']for r in rows}=={'UNKNOWN'}and not trace.scans


_NATIVE_FIXTURES = json.loads(Path('peaso/checks/azure_selected_declaration_secret_review_20261020_native_fixtures.json').read_text())
@pytest.mark.parametrize('capture',_NATIVE_FIXTURES['captures'],ids=lambda row:row['surface']+'-'+row['expected_status'])
def test_portable_actual_native_capture_replays_current_consumer(capture):
    p=profile(capture['surface']);inputs=capture['input']
    assert consumer.EVALUATORS[p](inputs['item'],inputs['index'])[0]==capture['expected_status']
    if capture['expected_status']!='UNKNOWN':assert capture['native_real_detectors']is True


@pytest.mark.parametrize('surface',NATIVE)
def test_new_actual_matches_scrub_late_mixed_metadata_and_cleanup(monkeypatch,surface):
    old=azure._Reader.metadata
    def metadata(reader):return{**old(reader),'independent_alias':{TOKEN:TOKEN}}
    monkeypatch.setattr(azure._Reader,'metadata',metadata)
    snapshot,rows,trace=collect(monkeypatch,surface,TOKEN,real=True)
    assert {r['status']for r in rows}=={'FAIL'}and TOKEN in json.dumps(snapshot)  # found values stay visible
    assert not trace.readers[0].configuration_secret_redactions


@pytest.mark.parametrize('surface',NATIVE)
def test_matched_value_union_overflow_withholds_raw_mixed_projection(monkeypatch,surface):
    from peaso.collectors import azure_selected_secret_integration_20261020 as union
    monkeypatch.setattr(union,'MAX_UNION_VALUES',0)
    snapshot,rows,trace=collect(monkeypatch,surface,TOKEN)
    assert {r['status']for r in rows}=={'FAIL'}  # no redaction budget applies to found values
    assert not trace.readers[0].configuration_secret_redactions


def test_secret_bearing_selected_key_never_exported(monkeypatch):
    t=target('app_configuration');t['key']=TOKEN
    snapshot,rows,_=collect(monkeypatch,literal=TOKEN,targets=[('app_configuration',t)],real=True)
    assert {r['status']for r in rows}=={'FAIL'}and TOKEN not in json.dumps([snapshot,rows])


def test_proposal_exact_current_sources_and_native_fixture_bytes():
    proposal=json.loads(Path('peaso/checks/azure_selected_declaration_secret_review_20261020_proposal.json').read_text())
    assert proposal['registration']=='unregistered_proposal_only'
    # The proposal remains an immutable historical admission input. Bind current source bytes separately.
    assert hashlib.sha256(Path('peaso/checks/azure_selected_declaration_secret_review_20261020_proposal.json').read_bytes()).hexdigest() == 'da9a3ad3926a86fa36302c11c8c41de016ec20f089d415910fc9c1f86955cd20'
    current_source_hashes = {
        'peaso/collectors/azure_selected_declaration_secret_indicators.py': '361844ed7f69dfa530d539e3e661d40cdb7e3f96a08aa1704b36f9b76d75ed18',
        'peaso/collectors/azure_selected_secret_integration_20261020.py': '7609b76c8b3e43e18c444b7d53815306b83a3e0c62b21ca44a19ffa895fbb7a1',
        'peaso/collectors/azure_selected_storage_secret_indicators.py': '4a090b1f8fe9da69de7e4aef9d467e01d421cc00febc0fc20ea978e1f1f00b63',
        'peaso/secret_scanning.py': 'bb45ff48726fd209bcb4201a9951a1b6d0d931cdf72aa8cb794dc9ebc0b92ec9'
    }
    for path, historical_digest in proposal['sources'].items():
        assert hashlib.sha256(Path(path).read_bytes()).hexdigest() == current_source_hashes.get(path, historical_digest), path
    fixture=proposal['fixture'];assert hashlib.sha256(Path(fixture['path']).read_bytes()).hexdigest()==fixture['sha256']
    assert {d['id']for d in proposal['checks']}=={d['id']for d in consumer.DECLARATIONS}
    for d in proposal['checks']:
        assert hashlib.sha256(inspect.getsource(consumer.EVALUATORS[d['profile']]).encode()).hexdigest()==d['predicate_sha256']
        assert hashlib.sha256(inspect.getsource(consumer._evaluate).encode()).hexdigest()==d['reachable_helper_sha256']
