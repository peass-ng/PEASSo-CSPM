"""Native HTTP -> actual Azure collector/token -> registered public Functions hooks.

Original162 proposal bytes are archived separately; provider responses/criteria
remain independent of CASES and frozen legacy captures keep their own predicate proof.
"""
import base64
from copy import deepcopy
import hashlib
import inspect
import io
import json
import logging
import os
from pathlib import Path
import socket
import threading
import time
from azure.core.credentials import AccessToken

import pytest

from peaso import checks, engine, secret_scanning
from peaso.collectors import azure
from peaso.collectors import azure_function_settings_declarations_20261020 as source
from peaso.checks import azure_function_settings_review_20261020 as consumers
from peaso.checks import azure_function_settings_runtime_consumer_20261020 as current_consumers
from peaso.snapshot import make_snapshot, seal, validate

SUB = '11111111-1111-1111-1111-111111111111'
TENANT = '22222222-2222-2222-2222-222222222222'
FOREIGN = '33333333-3333-3333-3333-333333333333'
SCOPE = '/subscriptions/' + SUB
SITE = SCOPE + '/resourceGroups/review/providers/Microsoft.Web/sites/selected-function'
CANARY = 'private-value-must-never-leave-native-projection'
CAPTURES = []


def jwt(tenant=TENANT, audience=source.ARM):
    body = {'tid': tenant, 'aud': audience, 'oid': FOREIGN, 'exp': int(time.time()) + 3600}
    part = base64.urlsafe_b64encode(json.dumps(body).encode()).decode().rstrip('=')
    return 'eyJhbGciOiJub25lIn0.' + part + '.offline-inert-signature'


class Credential:
    def __init__(self, tenant=TENANT, audience=source.ARM, fail=False):
        self.tenant, self.audience, self.fail, self.calls = tenant, audience, fail, []
    def close(self): pass
    def get_token(self, *scopes, **kwargs):
        assert scopes == (source.ARM + '/.default',) and not kwargs
        self.calls.append(scopes)
        logging.getLogger('azure.identity').debug(CANARY + ' token request')
        if self.fail: raise RuntimeError(CANARY)
        return AccessToken(jwt(self.tenant, self.audience), int(time.time()) + 3600)


def native_site(target=SITE, hosting='classic'):
    row = {'id': target, 'type': 'Microsoft.Web/sites', 'name': target.rsplit('/', 1)[1],
        'kind': 'functionapp,linux', 'properties': {'reserved': True,
            'siteConfig': {'linuxFxVersion': 'Python|3.12', 'windowsFxVersion': ''}, 'unretainedValue': CANARY}}
    if hosting == 'windows':
        row['kind'] = 'functionapp'; row['properties']['reserved'] = False
    elif hosting == 'container':
        row['kind'] += ',container'; row['properties']['siteConfig']['linuxFxVersion'] = 'DOCKER|private.example/image:tag'
    elif hosting == 'flex':
        row['properties']['functionAppConfig'] = {'runtime': {'name': 'python', 'version': '3.12'},
            'scaleAndConcurrency': {'instanceMemoryMB': 2048}}
    elif hosting == 'unknown': row['properties']['siteConfig'] = None
    elif hosting == 'not_function': row['kind'] = 'app,linux'
    elif hosting == 'workflow': row['kind'] = 'functionapp,workflowapp'
    elif hosting == 'unsupported': row['kind'] = 'functionapp,unknown-container-host'
    return row


def native_settings(values=None, target=SITE):
    return {'id': target + '/config/appsettings', 'type': 'Microsoft.Web/sites/config',
        'name': 'appsettings', 'kind': 'functionapp', 'properties': {
            'APPLICATIONINSIGHTS_CONNECTION_STRING': 'InstrumentationKey=00000000-0000-0000-0000-000000000001',
            'FUNCTIONS_EXTENSION_VERSION': '~4', 'PRIVATE_UNRELATED_SETTING': CANARY} if values is None else values}


class Response:
    def __init__(self, value, status=200, headers=None):
        self.raw = json.dumps(value).encode() if isinstance(value, (dict, list)) else value
        self.stream = io.BytesIO(self.raw); self.status = status; self.closed = False
        self.headers = {'Content-Type': 'application/json', 'Content-Length': str(len(self.raw)), **(headers or {})}
    def getheader(self, name): return self.headers.get(name)
    def read(self, size):
        assert 0 < size <= 16384
        return self.stream.read(size)
    def close(self): self.closed = True


class Wire:
    def __init__(self, targets, site=None, settings=None, fault=None):
        self.targets, self.site, self.settings, self.fault = targets, site, settings, fault
        self.calls, self.responses, self.connections = [], [], []
    def connection(self, host, timeout):
        assert host == source.HOST and 0 < timeout <= 10
        wire = self
        class Connection:
            sock = None
            def __init__(self): self.closed = False; self.debug = None
            def set_debuglevel(self, value): assert value == 0; self.debug = value
            def request(self, method, path, body=None, headers=None):
                assert self.debug == 0 and body is None
                assert set(headers) == {'Authorization','Accept','Accept-Encoding','Content-Length'}
                assert headers['Authorization'].startswith('Bearer ey') and headers['Content-Length'] == '0'
                assert headers['Accept'] == 'application/json' and headers['Accept-Encoding'] == 'identity'
                matches = [(target, op) for target in wire.targets for op, verb, route in (
                    ('subscription', 'GET', source._RESOURCE.fullmatch(target)[1] + '?api-version=' + source.SUB_VERSION),
                    ('site', 'GET', target + '?api-version=' + source.SITE_VERSION),
                    ('settings', 'POST', target + '/config/appsettings/list?api-version=' + source.SITE_VERSION))
                    if path == route and method == verb]
                assert matches, (method, path)
                target, op = matches[0]
                wire.calls.append((method, host, path, op))
                logging.getLogger('azure.core.pipeline.policies.http_logging_policy').debug(CANARY + path)
                payload = ({'id': source._RESOURCE.fullmatch(target)[1], 'subscriptionId': source._RESOURCE.fullmatch(target)[1].rsplit('/',1)[1],
                    'tenantId': TENANT, 'state': 'Enabled'} if op == 'subscription'
                    else deepcopy(wire.site if wire.site is not None else native_site(target)) if op == 'site'
                    else deepcopy(wire.settings if wire.settings is not None else native_settings(target=target)))
                result = wire.fault(op, payload) if wire.fault else payload
                if isinstance(result, Exception): raise result
                self.response = result if isinstance(result, Response) else Response(result)
                wire.responses.append(self.response)
            def getresponse(self): return self.response
            def close(self): self.closed = True
        result = Connection(); self.connections.append(result); return result


@pytest.fixture(autouse=True)
def offline(monkeypatch):
    def blocked(*args, **kwargs): raise AssertionError('Live network/authentication/detectors forbidden')
    for key in ('connect','connect_ex'): monkeypatch.setattr(socket.socket, key, blocked)
    for key in ('getaddrinfo','gethostbyname','create_connection'): monkeypatch.setattr(socket, key, blocked)
    monkeypatch.setattr(azure, 'credential_for', blocked)
    # Keep the admitted scanner callables intact while forbidding native tools.
    monkeypatch.setattr(secret_scanning.subprocess, 'Popen', blocked)
    for cid,name in zip(source.CHECKS,('telemetry','runtime')):
        actual,=[c for c in checks.CHECKS if c.id==cid]
        assert inspect.unwrap(actual.evaluate)is getattr(current_consumers,name)


@pytest.fixture(scope='session', autouse=True)
def captures():
    yield
    if folder := os.environ.get('FUNCTION_DECLARATION_RECEIPTS'):
        Path(folder).mkdir(parents=True, exist_ok=True)
        Path(folder, 'native-captures.json').write_text(json.dumps(CAPTURES, indent=2) + '\n')


def capture(monkeypatch, *, site=None, settings=None, fault=None, targets=None, selected=None, options=None, credential=None):
    targets = [SITE] if targets is None else targets
    selected = list(source.CHECKS) if selected is None else selected
    options = {'content_secret_scans': True, source.OPTION: targets, **(options or {})}
    scopes = list(dict.fromkeys(source._RESOURCE.fullmatch(t)[1] for t in targets if isinstance(t,str) and source._RESOURCE.fullmatch(t))) or [SCOPE]
    wire = Wire(targets, site=site, settings=settings, fault=fault)
    monkeypatch.setattr(source.http.client, 'HTTPSConnection', wire.connection)
    credential = credential or Credential()
    monkeypatch.setattr(azure,'credential_for',lambda auth:credential)
    snapshot = engine.collect_snapshot({'connector':{'provider':'azure','scopes':scopes,
        'auth':{'method':'client-secret','tenant_id':TENANT,'client_id':TENANT,'client_secret':'offline-functions'},
        'options':options},'checks':selected})
    validate(snapshot)
    report = engine.evaluate_snapshot(snapshot, checks=selected if selected else list(source.CHECKS))
    found = {f['check_id']: f for f in report['findings']}
    assert all(r.closed for r in wire.responses) and all(c.closed for c in wire.connections)
    assert CANARY not in json.dumps(snapshot) + json.dumps(report)
    assert 'InstrumentationKey=' not in json.dumps(snapshot)
    return snapshot, found, wire, credential


@pytest.mark.parametrize('version,expected', [('~4','PASS'),('~3','FAIL'),('~2','FAIL'),('~1','FAIL'),
    ('4.0.12345','FAIL'),('3.0.12345','FAIL'),('', 'FAIL'),(None,'FAIL'),('~5','UNKNOWN'),
    ('~4.0','UNKNOWN'),('4','UNKNOWN'),('~4 ','UNKNOWN'),('[REDACTED]','UNKNOWN'),('*****','UNKNOWN'),
    ('@Microsoft.KeyVault(SecretUri=https://review.vault.azure.net/secrets/runtime)','UNKNOWN')])
def test_native_runtime_channel_opposites(monkeypatch, version, expected):
    values = {'OTHER': CANARY}
    if version is not None: values['FUNCTIONS_EXTENSION_VERSION'] = version
    snapshot, found, wire, credential = capture(monkeypatch, settings=native_settings(values), selected=[source.RUNTIME])
    assert found[source.RUNTIME]['status'] == expected
    assert len(wire.calls) == 3 and len(credential.calls) == 1
    assert 'resolved host build' in found[source.RUNTIME]['evidence'].get('observed','') or expected == 'UNKNOWN'


@pytest.mark.parametrize('values,expected', [({},'FAIL'),({'APPLICATIONINSIGHTS_CONNECTION_STRING':''},'FAIL'),
    ({'APPINSIGHTS_INSTRUMENTATIONKEY':'   '},'FAIL'),({'APPLICATIONINSIGHTS_CONNECTION_STRING':'declaration'},'PASS'),
    ({'APPINSIGHTS_INSTRUMENTATIONKEY':'declaration'},'PASS'),
    ({'APPLICATIONINSIGHTS_CONNECTION_STRING':'declaration','APPINSIGHTS_INSTRUMENTATIONKEY':'declaration'},'PASS'),
    ({'APPLICATIONINSIGHTS_CONNECTION_STRING':'*****'},'UNKNOWN'),
    ({'APPLICATIONINSIGHTS_CONNECTION_STRING':'@Microsoft.KeyVault(SecretUri=https://review.vault.azure.net/secrets/key)'},'UNKNOWN'),
    ({'APPLICATIONINSIGHTS_CONNECTION_STRING':None},'UNKNOWN'),({'APPLICATIONINSIGHTS_CONNECTION_STRING':1},'UNKNOWN'),
    ({'applicationinsights_connection_string':'declaration'},'UNKNOWN')])
def test_native_telemetry_presence_opposites(monkeypatch, values, expected):
    snapshot, found, wire, credential = capture(monkeypatch, settings=native_settings(values), selected=[source.TELEMETRY])
    assert found[source.TELEMETRY]['status'] == expected
    assert len(wire.calls) == 3


@pytest.mark.parametrize('hosting,telemetry,runtime,reads', [('classic','PASS','PASS',3),('windows','PASS','PASS',3),
    ('container','PASS','NOT_APPLICABLE',3),('flex','PASS','NOT_APPLICABLE',3),
    ('not_function','NOT_APPLICABLE','NOT_APPLICABLE',2),('workflow','NOT_APPLICABLE','NOT_APPLICABLE',2),
    ('unknown','PASS','UNKNOWN',3),('unsupported','UNKNOWN','UNKNOWN',2)])
def test_native_hosting_applicability(monkeypatch, hosting, telemetry, runtime, reads):
    snapshot, found, wire, _ = capture(monkeypatch, site=native_site(hosting=hosting))
    assert (found[source.TELEMETRY]['status'],found[source.RUNTIME]['status']) == (telemetry,runtime)
    assert len(wire.calls) == reads
    CAPTURES.append({'case':'hosting_'+hosting,'snapshot':snapshot,'statuses':{k:v['status'] for k,v in found.items()},
        'requests':[{'method':m,'host':h,'operation':op,'request_digest':hashlib.sha256(p.encode()).hexdigest()} for m,h,p,op in wire.calls]})


@pytest.mark.parametrize('hosting', ['container','flex','not_function','workflow'])
def test_runtime_only_unsupported_hosts_never_read_settings(monkeypatch, hosting):
    _, found, wire, _ = capture(monkeypatch, site=native_site(hosting=hosting), selected=[source.RUNTIME])
    assert found[source.RUNTIME]['status'] == 'NOT_APPLICABLE'
    assert [c[3] for c in wire.calls] == ['subscription','site']


@pytest.mark.parametrize('operation', ['subscription','site','settings'])
@pytest.mark.parametrize('fault', ['denied','partial','redirect','bad_mime','gzip','truncated','duplicate','array','next','exception'])
def test_native_transport_faults_are_uncertain(monkeypatch, operation, fault):
    def mutate(op,payload):
        if op != operation: return payload
        if fault=='denied': return Response({'error':{'code':'Denied','message':CANARY}},403)
        if fault=='partial': return Response(payload,206)
        if fault=='redirect': return Response(payload,headers={'Location':'https://foreign.invalid/'+CANARY})
        if fault=='bad_mime': return Response(payload,headers={'Content-Type':'text/html'})
        if fault=='gzip': return Response(payload,headers={'Content-Encoding':'gzip'})
        if fault=='truncated': return Response(payload,headers={'Content-Length':'999999'})
        if fault=='duplicate': return Response(b'{"id":"a","id":"b"}')
        if fault=='array': return []
        if fault=='next': return {**payload,'nextLink':'https://foreign.invalid/'+CANARY}
        return RuntimeError(CANARY)
    _, found, _, _ = capture(monkeypatch, fault=mutate)
    assert {f['status'] for f in found.values()} == {'UNKNOWN'}


@pytest.mark.parametrize('fault', ['subscription_id','subscription_number','tenant','disabled_sub','site_id','site_type',
    'settings_id','settings_type','settings_name','settings_properties','site_properties','site_config','flex_config','reserved_conflict'])
def test_native_scope_type_and_shape_counterexamples(monkeypatch, fault):
    def mutate(op,p):
        if op=='subscription':
            if fault=='subscription_id': p['id']='/subscriptions/'+FOREIGN
            if fault=='subscription_number': p['subscriptionId']=FOREIGN
            if fault=='tenant': p['tenantId']=FOREIGN
            if fault=='disabled_sub': p['state']='Disabled'
        if op=='site':
            if fault=='site_id': p['id'] += '-foreign'
            if fault=='site_type': p['type']='Microsoft.Web/serverfarms'
            if fault=='site_properties': p.pop('properties')
            if fault=='site_config': p['properties']['siteConfig']=[]
            if fault=='flex_config': p['properties']['functionAppConfig']={}
            if fault=='reserved_conflict': p['properties']['reserved']=False
        if op=='settings':
            if fault=='settings_id': p['id']=p['id'].replace('/review/','/foreign/')
            if fault=='settings_type': p['type']='Microsoft.Web/sites/slots/config'
            if fault=='settings_name': p['name']='web'
            if fault=='settings_properties': p['properties']=None
        return p
    _, found, _, _ = capture(monkeypatch, fault=mutate)
    assert found[source.RUNTIME]['status']=='UNKNOWN'
    assert found[source.TELEMETRY]['status']==('PASS' if fault=='reserved_conflict' else 'UNKNOWN')


@pytest.mark.parametrize('check', source.CHECKS)
@pytest.mark.parametrize('fault',['capture','tenant','version','host','method','operation','status','bound','partial_collection',
    'selection','duplicate_row','identity','extra_native_payload','channel_type','declaration_value'])
def test_consumer_rejects_tampered_projection(monkeypatch, check, fault):
    snapshot, _, _, _ = capture(monkeypatch)
    m=snapshot['metadata'];collection=snapshot['collections'][0];item=collection['items'][0]
    marker=item[source.MARKER];receipt=m[source.KIND+'_receipts'][-1]
    if fault=='capture': marker['capture']='f'*32
    if fault=='tenant': item['_provenance']['tenant_id']=FOREIGN
    if fault=='version': receipt['api_version']='2020-01-01'
    if fault=='host': receipt['host']='foreign.invalid'
    if fault=='method': receipt['method']='PUT'
    if fault=='operation': receipt['operation']='listKeys'
    if fault=='status': receipt['status']='partial'
    if fault=='bound': receipt['identity_bound']=False
    if fault=='partial_collection': collection['status']='partial'
    if fault=='selection': m[source.KIND+'_selection'][SCOPE]=[]
    if fault=='duplicate_row': collection['items'].append(deepcopy(item))
    if fault=='identity': marker['identity'] += '0'
    if fault=='extra_native_payload': item['settings']={'raw':CANARY}
    if fault=='channel_type': marker['declarations']['channel']=True
    if fault=='declaration_value': marker['declarations']['connection_string']=CANARY
    result=engine.evaluate_snapshot(seal(snapshot),checks=[check])
    assert {f['status'] for f in result['findings']}=={'UNKNOWN'}


@pytest.mark.parametrize('targets',[[],[SITE]*2,[SITE+'/slots/staging'],['https://management.azure.com'+SITE],
    [SITE+'?x=1'],[SITE+'/../other'],[SITE+'%2Fother'],[SITE+'#fragment'],[SITE]*5,[None]])
def test_selectors_rejected_before_auth(monkeypatch, targets):
    credential=Credential()
    with pytest.raises(source.Incomplete,match='invalid_selection'):
        source.collect_proposal({'scopes':[SCOPE],'options':{'content_secret_scans':True,source.OPTION:targets}},list(source.CHECKS),credential=credential)
    assert not credential.calls


@pytest.mark.parametrize('named,flag', [([],True),(['*'],True),(['hacktricks'],True),([source.KIND],True),
    (list(source.CHECKS),False),([],False)])
def test_default_framework_inventory_and_flag_cannot_authorize_content(monkeypatch,named,flag):
    credential=Credential()
    snapshot=source.collect_proposal({'scopes':[SCOPE],'options':{'content_secret_scans':flag,source.OPTION:[SITE],
        '_content_secret_scan_kinds':[source.KIND],'inventories':[source.KIND]}},named,credential=credential)
    assert not credential.calls and snapshot['collections']==[]


@pytest.mark.parametrize('bad',['max_calls','setting_count','value_size','content_size','wire_size','total_size','deadline'])
def test_native_limits_prevent_clean_verdict(monkeypatch,bad):
    options={};values=None
    if bad=='max_calls':options['max_calls']=2
    if bad=='setting_count':values={str(i):'x' for i in range(source.MAX_SETTINGS+1)}
    if bad=='value_size':values={'OTHER':'x'*(source.MAX_VALUE+1)}
    if bad=='content_size':values={str(i):'x'*source.MAX_VALUE for i in range(5)}
    if bad=='wire_size':monkeypatch.setattr(source,'MAX_WIRE',80)
    if bad=='total_size':monkeypatch.setattr(source,'MAX_TOTAL',80)
    if bad=='deadline':options['collection_deadline_seconds']=1e-10
    if bad in('wire_size','total_size'):
        wire=Wire([SITE]);monkeypatch.setattr(source.http.client,'HTTPSConnection',wire.connection)
        snapshot=source.collect_proposal({'scopes':[SCOPE],'auth':{'tenant_id':TENANT},'options':{'content_secret_scans':True,source.OPTION:[SITE]}},list(source.CHECKS),credential=Credential())
        original,=snapshot['collections'];index={'context':{'provider':'azure','scope':SCOPE,'metadata':snapshot['metadata']},'collections':{source.KIND:[original]}}
        assert original['items'][0][source.MARKER]['complete']is False
        assert {fn(item,index)[0]for fn in(consumers.telemetry,consumers.runtime)for item in original['items']}=={'UNKNOWN'}
    else:
        _, found, _, _=capture(monkeypatch,settings=native_settings(values) if values is not None else None,options=options)
        assert {f['status'] for f in found.values()}=={'UNKNOWN'}


@pytest.mark.parametrize('credential',[Credential(audience='https://graph.microsoft.com'),Credential(tenant=FOREIGN),Credential(fail=True)])
def test_real_token_method_rejects_foreign_or_unavailable_auth(monkeypatch,credential,caplog):
    caplog.set_level(logging.DEBUG)
    _,found,wire,_=capture(monkeypatch,credential=credential)
    assert not wire.calls and {f['status'] for f in found.values()}=={'UNKNOWN'}
    assert CANARY not in caplog.text


def test_same_native_reads_satisfy_both_checks_without_detectors(monkeypatch,caplog):
    caplog.set_level(logging.DEBUG)
    _,found,wire,credential=capture(monkeypatch)
    assert {v['status'] for v in found.values()}=={'PASS'}
    assert len(wire.calls)==3 and len(credential.calls)==1
    assert CANARY not in caplog.text


def test_four_exact_targets_obey_call_cap(monkeypatch):
    targets=[SITE+str(i) for i in range(4)]
    snapshot,found,wire,_=capture(monkeypatch,targets=targets)
    assert len(wire.calls)==12 and all(f['status']=='PASS' for f in found.values())
    assert len(snapshot['collections'][0]['items'])==4
    assert len(engine.evaluate_snapshot(snapshot,checks=list(source.CHECKS))['findings'])==8


def test_log_filters_restore_and_other_thread_is_unaffected(caplog):
    caplog.set_level(logging.DEBUG)
    logger=logging.getLogger('azure.identity');before=list(logger.filters);level=logger.level
    with source.private_native_logs():
        logger.debug(CANARY)
        thread=threading.Thread(target=lambda:logger.debug('other-thread-visible'))
        thread.start();thread.join()
    assert CANARY not in caplog.text and 'other-thread-visible' in caplog.text
    assert logger.filters==before and logger.level==level


def test_final_union_scrubs_existing_matches_and_drops_transient_sets(monkeypatch):
    snapshot,_,_,_=capture(monkeypatch)
    reader=azure._Reader({})
    reader.collections=deepcopy(snapshot['collections'])
    reader.configuration_secret_redactions={CANARY}
    reader.function_declaration_metadata={source.KIND+'_safe_note':CANARY}
    snapshot['metadata']['other_surface_locator']=CANARY
    safe=source.final_snapshot(reader,snapshot)
    validate(safe)
    assert CANARY in json.dumps(safe)+json.dumps(reader.collections)
    assert not reader.configuration_secret_redactions


@pytest.mark.parametrize('target,scope,operation',[(SITE+'/slots/staging',SCOPE,'site'),
    ('https://foreign.invalid/',SCOPE,'settings'),(SITE,SCOPE,'listKeys'),(SITE,'/subscriptions/'+FOREIGN,'subscription')])
def test_transport_route_guard_precedes_token(target,scope,operation):
    credential=Credential();transport=azure.AzureTransport({'tenant_id':TENANT},credential=credential)
    reader=azure._Reader({})
    with pytest.raises(source.Incomplete,match='operation_forbidden'):
        source._read(reader,transport,target,scope,operation,{},[])
    assert not credential.calls


@pytest.mark.parametrize('empty',[None,''])
def test_runtime_source_omission_and_empty_remain_distinct(monkeypatch,empty):
    values={} if empty is None else {'FUNCTIONS_EXTENSION_VERSION':empty}
    snapshot,found,_,_=capture(monkeypatch,settings=native_settings(values),selected=[source.RUNTIME])
    facts=snapshot['collections'][0]['items'][0][source.MARKER]['declarations']
    assert facts['runtime_setting']==('absent' if empty is None else 'empty')
    assert facts['channel']=='absent' and found[source.RUNTIME]['status']=='FAIL'


@pytest.mark.parametrize('name,values,denied,expected',[
    ('pass', {'APPLICATIONINSIGHTS_CONNECTION_STRING':'configured declaration','FUNCTIONS_EXTENSION_VERSION':'~4'},False,'PASS'),
    ('fail', {},False,'FAIL'),
    ('unknown', {},True,'UNKNOWN')])
def test_native_triad_for_source_bound_cases(monkeypatch,name,values,denied,expected):
    def fault(op,payload):
        return Response({'error':{'code':'Denied'}},403) if denied and op=='settings' else payload
    snapshot,found,wire,_=capture(monkeypatch,settings=native_settings(values),fault=fault)
    assert {f['status'] for f in found.values()}=={expected}
    CAPTURES.append({'case':'triad_'+name,'snapshot':snapshot,'statuses':{k:v['status'] for k,v in found.items()},
        'requests':[{'method':m,'host':h,'operation':op,'request_digest':hashlib.sha256(p.encode()).hexdigest()} for m,h,p,op in wire.calls]})


@pytest.mark.parametrize('key,value',[('tenant_id',FOREIGN),('tenant_verified',False),
    ('credential_context_id','f'*32),('customer_context_id','scan-local:foreign')])
def test_projection_does_not_override_foreign_existing_context(monkeypatch,key,value):
    snapshot,_,_,_=capture(monkeypatch)
    snapshot['metadata'][key]=value
    findings=engine.evaluate_snapshot(seal(snapshot),checks=list(source.CHECKS))['findings']
    assert {f['status'] for f in findings}=={'UNKNOWN'}


def test_early_credential_rejection_has_safe_unknown_collection(monkeypatch,caplog):
    caplog.set_level(logging.DEBUG)
    def reject(auth):
        logging.getLogger('azure.identity').debug(CANARY)
        raise RuntimeError(CANARY)
    monkeypatch.setattr(azure,'credential_for',reject)
    snapshot=source.collect_proposal({'scopes':[SCOPE],'auth':{},'options':{'content_secret_scans':True,
        source.OPTION:[SITE]}},list(source.CHECKS))
    validate(snapshot)
    report=engine.evaluate_snapshot(snapshot,checks=list(source.CHECKS))
    assert {f['status'] for f in report['findings']}=={'UNKNOWN'}
    assert CANARY not in json.dumps(snapshot)+json.dumps(report)+caplog.text


def test_future_parent_hook_binds_actual_scan_context_without_nonce_guess(monkeypatch):
    wire=Wire([SITE]);monkeypatch.setattr(source.http.client,'HTTPSConnection',wire.connection)
    reader=azure._Reader({'retries':0,'concurrency':1});credential=Credential()
    transport=azure.AzureTransport({'tenant_id':TENANT},credential=credential)
    parent_capture='a'*32
    assert parent_capture != transport.ai_context_id
    source.collect(reader,transport,[SCOPE],[source.KIND],{'content_secret_scans':True,source.OPTION:[SITE]},
        named_checks=list(source.CHECKS),credential_context_id=parent_capture,
        customer_context_id='scan-local:'+parent_capture)
    snapshot=source.final_snapshot(reader,make_snapshot('azure',[SCOPE],reader.collections,metadata={
        'credential_context_id':parent_capture,'customer_context_id':'scan-local:'+parent_capture,
        'tenant_id':TENANT,'tenant_verified':True}))
    original,=snapshot['collections'];index={'context':{'provider':'azure','scope':SCOPE,'metadata':snapshot['metadata']},'collections':{source.KIND:[original]}}
    assert {fn(item,index)[0]for fn in(consumers.telemetry,consumers.runtime)for item in original['items']}=={'PASS'}
    assert len(wire.calls)==3
    transport.tokens.clear()


@pytest.mark.parametrize('name',[None,'foreign-function'])
def test_native_site_name_id_coherence(monkeypatch,name):
    site=native_site()
    if name is None: site.pop('name')
    else:site['name']=name
    _,found,_,_=capture(monkeypatch,site=site)
    assert {f['status'] for f in found.values()}=={'UNKNOWN'}


def test_other_OS_image_field_does_not_override_native_linux_stack(monkeypatch):
    site=native_site()
    site['properties']['siteConfig']['windowsFxVersion']='DOCKER|irrelevant-other-OS-image'
    _,found,_,_=capture(monkeypatch,site=site)
    assert found[source.RUNTIME]['status']=='PASS'
