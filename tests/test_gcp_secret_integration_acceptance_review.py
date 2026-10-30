"""Independent production-hook acceptance review; no cloud requests.

Known defects remain ordinary failing tests until root applies its own fixes.
Failure messages intentionally never print raw/encoded synthetic canaries.
"""
import base64
from copy import deepcopy
from datetime import datetime, timezone
import importlib
import io
import json
from pathlib import Path
from types import SimpleNamespace
import zipfile

import pytest
import requests

from peaso import engine, secret_scanning as scanning
from peaso import collectors
from peaso.checks import CHECKS
from peaso.collectors import gcp
from peaso.collectors import gcp_function_secret_indicators as functions
from peaso.collectors import gcp_configuration_secret_indicators as configurations
from peaso.collectors import gcp_log_secret_indicators as logs
from peaso.collectors import gcp_selected_object_secret_indicators as objects
from peaso.collectors import gcp_selected_archive_secret_indicators as archives
from peaso.checks import gcp_function_secret_partial_page_20261020 as function_check
from peaso.checks import gcp_configuration_secret_review_20261019 as configuration_checks
from peaso.checks import gcp_log_secret_review_20261019 as log_check
from peaso.checks import gcp_selected_object_secret_review_20261019 as object_check
from peaso.checks import gcp_selected_archive_secret_review_20261019 as archive_check
from peaso.secret_findings import deduplicate_secret_findings
from peaso.snapshot import make_snapshot

SCOPE = 'projects/review'
TOKEN = 'ghp_' + '7mQ2zR9wL4cV8nK1sF6aH3jP5uD0xB2yE9rT'
ENCODED = base64.b64encode(TOKEN.encode()).decode()
FUNCTION = SCOPE+'/locations/us-central1/functions/review'


def declarations():
    rows = {}
    for path in sorted(Path('peaso/checks').glob('gcp_*secret_review_20261019.py')):
        module = importlib.import_module('peaso.checks.'+path.stem)
        candidates = list(getattr(module, 'DECLARATIONS', {}).values())
        if hasattr(module, 'DECLARATION'): candidates.append(module.DECLARATION)
        for declaration in candidates:
            rows[declaration['id']] = {'declaration':deepcopy(declaration), 'path':str(path)}
    return rows


DECLARATIONS = declarations()
REGISTERED = {c.id:c for c in CHECKS if c.id in DECLARATIONS}


class Response:
    def __init__(self, data=None, *, payload=None, status=200, headers=None):
        self.payload = json.dumps(data).encode() if payload is None else payload
        self.data = data
        self.raw = SimpleNamespace(read=self.read)
        self.stream = io.BytesIO(self.payload)
        self.status_code = status
        self.headers = {'Content-Length':str(len(self.payload)), **(headers or {})}
        self.closed, self.reads = False, []
        self.history, self.url = [], None
    def json(self): return deepcopy(self.data)
    def read(self, size, *, decode_content):
        assert decode_content is False
        self.reads.append(size)
        return self.stream.read(size)
    def iter_content(self, chunk_size):
        for start in range(0,len(self.payload),chunk_size):
            self.reads.append(chunk_size)
            yield self.payload[start:start+chunk_size]
    def close(self): self.closed = True


def transport(monkeypatch, replies, *, kinds=(), enabled=True):
    options = {'content_secret_scans':enabled,'_content_secret_scan_kinds':list(kinds),'retries':0,'concurrency':1}
    auth, calls = [], []
    def headers():
        auth.append(True)
        return {'Authorization':'Bearer synthetic-native-auth'}
    t = gcp.Transport(SimpleNamespace(headers=headers, close=lambda:None), options)
    pending = list(replies)
    def request(method,url,**kw):
        calls.append((method,url,kw))
        assert kw.get('allow_redirects') is False
        reply = pending.pop(0)
        if reply.url is None:
            reply.url = requests.Request(method,url,params=kw.get('params')).prepare().url
        return reply
    monkeypatch.setattr(t,'_session',lambda:SimpleNamespace(request=request))
    return t,calls,auth


def index(kind,row,env=None):
    return {'context':{'provider':'gcp','scope':SCOPE},'collections':{kind:[env or {
        'scope':SCOPE,'status':'collected','items':[row]}]}}


def selected_options():
    return {'content_secret_scans':True,'dataflow_regions':['us-central1'],
        'batch_regions':['us-central1'],'dataproc_regions':['us-central1'],
        'selected_gcs_objects':[{'project_scope':SCOPE,'bucket':'review-bucket','object':'settings.env','generation':'123'}],
        'selected_gcs_archives':[{'project_scope':SCOPE,'bucket':'review-bucket','object':'settings.zip','generation':'123','format':'zip'}],
        'selected_artifact_files':[{'project_scope':SCOPE,'name':SCOPE+'/locations/us-central1/repositories/source/files/path%2Fsettings.env','sha256':'a'*64,'format':'utf8'}],
        'selected_artifact_images':['us-central1-docker.pkg.dev/review/images/app@sha256:'+'a'*64],
        'selected_dataform_files':[{'project_scope':SCOPE,'repository':SCOPE+'/locations/us-central1/repositories/review','path':'definitions/main.sqlx','commit_sha':'a'*40}],
        'selected_gke_clusters':[SCOPE+'/locations/us-central1/clusters/review'],
        'selected_appengine_versions':['apps/review/services/default/versions/review-v1'],
        'selected_cloudbuild_builds':[SCOPE+'/locations/us-central1/builds/review-build'],
        'selected_cloudbuild_artifact_builds':[SCOPE+'/locations/us-central1/builds/review-build'],
        'selected_clouddeploy_releases':[SCOPE+'/locations/us-central1/deliveryPipelines/review/releases/review-v1'],
        'selected_source_repository_files':[{'repository':SCOPE+'/repos/review',
            'commit':'a'*40,'paths':['config/review.txt']}]}


@pytest.fixture(autouse=True)
def cache():
    scanning._RESULTS.clear()
    yield
    scanning._RESULTS.clear()


@pytest.fixture
def clean(monkeypatch):
    monkeypatch.setattr(scanning,'_scan_kingfisher',lambda *a:[])
    monkeypatch.setattr(scanning,'_scan_trufflehog',lambda *a:[])


@pytest.mark.parametrize('check_id', sorted(REGISTERED))
def test_registered_named_check_alone_admits_only_its_kind(monkeypatch, check_id):
    captured=[]
    def collect(connector,requirements):
        captured.append(deepcopy(connector))
        return make_snapshot('gcp',[SCOPE],[],metadata={})
    monkeypatch.setattr(collectors,'collect_live',collect)
    engine.collect_snapshot({'connector':{'provider':'gcp','scopes':[SCOPE],'options':selected_options()},'checks':[check_id]})
    assert captured[0]['options']['_content_secret_scan_kinds'] == [REGISTERED[check_id].kind]


@pytest.mark.parametrize('selection', [{}, {'categories':['hardening']}, {'checks':[]}, {'categories':['compliance']}])
def test_category_default_or_empty_names_never_admit_content(monkeypatch,selection):
    captured=[]
    def collect(connector,requirements):
        captured.append(deepcopy(connector))
        return make_snapshot('gcp',[SCOPE],[],metadata={})
    monkeypatch.setattr(collectors,'collect_live',collect)
    options={'content_secret_scans':True,'_content_secret_scan_kinds':['function','artifact_image','log_secret_sample']}
    engine.collect_snapshot({'connector':{'provider':'gcp','scopes':[SCOPE],'options':options},**selection})
    assert captured[0]['options']['_content_secret_scan_kinds'] == []


@pytest.mark.parametrize('enabled,kinds', [(False,['function']), (True,[]), (False,[])])
def test_metadata_function_request_does_not_call_detectors_or_add_http(monkeypatch,enabled,kinds):
    monkeypatch.setattr(scanning,'_scan_kingfisher',lambda *a:pytest.fail('unexpected detector'))
    monkeypatch.setattr(scanning,'_scan_trufflehog',lambda *a:pytest.fail('unexpected detector'))
    raw={'name':FUNCTION,'serviceConfig':{'environmentVariables':{'PASSWORD':TOKEN}},'buildConfig':{}}
    t,calls,_=transport(monkeypatch,[Response(raw)],kinds=kinds,enabled=enabled)
    row,_=t.request('GET','https://cloudfunctions.googleapis.com/v2/'+FUNCTION,scope=SCOPE)
    assert len(calls)==1 and function_check.evaluate(row,index('function',row))[0]=='UNKNOWN'
    if TOKEN in json.dumps([row,t.evidence])+repr(t.cache): pytest.fail('raw literal persisted',pytrace=False)


@pytest.mark.parametrize('surface', ['function','instance'])
def test_detected_base64_metadata_recurrence_is_not_cached(monkeypatch,surface):
    # Real installed pinned tools, actual Transport.request pre-cache hook.
    if surface=='function':
        raw={'name':FUNCTION,'description':'encoded-copy='+ENCODED,
             'serviceConfig':{'environmentVariables':{'CONFIG':TOKEN}},'buildConfig':{}}
        url='https://cloudfunctions.googleapis.com/v2/'+FUNCTION
        evaluate=function_check.evaluate
    else:
        name=SCOPE+'/zones/us-central1-a/instances/review'
        raw={'name':'review','description':'encoded-copy='+ENCODED,
             'selfLink':'https://www.googleapis.com/compute/v1/'+name,
             'metadata':{'items':[{'key':'startup-script','value':'TOKEN='+TOKEN}]}}
        url='https://compute.googleapis.com/compute/v1/'+name
        evaluate=configuration_checks.instance
    t,_,_=transport(monkeypatch,[Response(raw)],kinds=[surface])
    row,_=t.request('GET',url,scope=SCOPE)
    assert evaluate(row,index(surface,row))[0]=='FAIL'
    serialized=json.dumps([row,t.evidence])+repr(t.cache)+repr(scanning._RESULTS)
    if TOKEN in serialized or ENCODED in serialized:
        pytest.fail('detected value persisted as an encoded metadata copy in production transport cache',pytrace=False)


@pytest.mark.parametrize('surface', ['function','instance'])
def test_plaintext_metadata_recurrence_is_redacted_and_coverage_invalidated(monkeypatch,surface):
    # Deterministic detector output isolates existing shared callback behavior.
    monkeypatch.setattr(scanning,'_scan_kingfisher',lambda payload,*a:[(TOKEN,'synthetic',1)] if TOKEN.encode() in payload else [])
    monkeypatch.setattr(scanning,'_scan_trufflehog',lambda *a:[])
    if surface=='function':
        raw={'name':FUNCTION,'description':'copy='+TOKEN,'serviceConfig':{'environmentVariables':{'CONFIG':TOKEN}},'buildConfig':{}}
        url='https://cloudfunctions.googleapis.com/v2/'+FUNCTION
    else:
        name=SCOPE+'/zones/us-central1-a/instances/review'
        raw={'name':'review','description':'copy='+TOKEN,'selfLink':'https://www.googleapis.com/compute/v1/'+name,
             'metadata':{'items':[{'key':'startup-script','value':TOKEN}]}}
        url='https://compute.googleapis.com/compute/v1/'+name
    t,_,_=transport(monkeypatch,[Response(raw)],kinds=[surface])
    row,_=t.request('GET',url,scope=SCOPE)
    assert row['_coverage']['description']['status']=='unknown'
    if TOKEN in json.dumps(row)+repr(t.cache): pytest.fail('plaintext metadata recurrence persisted',pytrace=False)


def object_fixture(monkeypatch, archive=False):
    target={'project_scope':SCOPE,'bucket':'review-bucket','object':'settings.zip' if archive else 'settings.env','generation':'123'}
    payload=b'STAGE=production\n'
    mime='text/plain'
    if archive:
        out=io.BytesIO()
        with zipfile.ZipFile(out,'w',compression=zipfile.ZIP_STORED) as z: z.writestr('config.env',payload)
        payload=out.getvalue();mime='application/zip';target['format']='zip'
    metadata={k:target[k] for k in ['bucket','generation']}
    metadata.update(name=target['object'],size=str(len(payload)),contentType=mime)
    replies=[Response(metadata),Response(payload=payload,headers={'Content-Type':mime,'X-Goog-Generation':'123'})]
    kind=archives.KIND if archive else objects.KIND
    t,calls,auth=transport(monkeypatch,replies,kinds=[kind])
    option=archives.OPTION if archive else objects.OPTION
    t.options.update({option:[target],'include_inherited':False})
    c=gcp.GCPCollector({'provider':'gcp','scopes':[SCOPE],'options':t.options},requirements=[kind,'project','bucket'],transport=t)
    c.collections[('project',SCOPE)]={'coverage_status':'collected','items':[{'name':'projects/123456789','projectId':'review'}]}
    c.collections[('bucket',SCOPE)]={'coverage_status':'collected','items':[{'name':'review-bucket','projectNumber':'123456789'}]}
    return c,kind,replies,calls,auth


@pytest.mark.parametrize('archive',[False,True])
def test_selected_object_item_links_metadata_and_media_receipts(monkeypatch,clean,archive):
    c,kind,replies,_,_=object_fixture(monkeypatch,archive)
    pages=archives.collection_pages if archive else objects.collection_pages
    env=c.envelope(kind,SCOPE,'storage',lambda:pages(c,SCOPE))
    row,=env['items']
    evaluate=archive_check.evaluate if archive else object_check.evaluate
    assert evaluate(row,index(kind,row,env))[0]=='PASS'
    refs={r['id'] for r in c.transport.evidence}
    assert len(refs)==2 and set(env['source_requests'])==refs and all(r.closed for r in replies)
    if not refs <= set(row['_provenance']['source_requests']):
        pytest.fail('item provenance omits native metadata identity/permission read while reporting complete content scan',pytrace=False)


def test_log_sample_item_links_every_native_page_receipt(monkeypatch,clean):
    stamp=datetime.now(timezone.utc).isoformat()
    entry={'logName':SCOPE+'/logs/application','timestamp':stamp,'textPayload':'STAGE=production',
           'resource':{'type':'global','labels':{'project_id':'review'}}}
    replies=[Response({'entries':[entry],'nextPageToken':'opaque-next'}),Response({'entries':[entry]})]
    t,_,_=transport(monkeypatch,replies,kinds=[logs.KIND])
    c=gcp.GCPCollector({'provider':'gcp','scopes':[SCOPE],'options':t.options},requirements=[logs.KIND],transport=t)
    jobs=logs.scope_jobs(c,SCOPE)
    env=c.envelope(*jobs[0])
    row,=env['items']
    assert log_check.evaluate(row,index(logs.KIND,row,env))[0]=='PASS'
    refs={r['id'] for r in t.evidence}
    assert len(refs)==2 and set(env['source_requests'])==refs
    if not refs <= set(row['_provenance']['source_requests']):
        pytest.fail('sample item provenance omits an earlier native page included in its complete negative',pytrace=False)


@pytest.mark.parametrize('error',['tool','mask','foreign'])
def test_actual_function_transport_cannot_clean_missing_tool_mask_or_foreign_subject(monkeypatch,clean,error):
    raw={'name':FUNCTION,'serviceConfig':{},'buildConfig':{}}
    params=None
    if error=='tool': monkeypatch.setattr(scanning,'_scan_trufflehog',lambda *a:(_ for _ in ()).throw(OSError(TOKEN)))
    if error=='mask': params={'fields':'name,serviceConfig,buildConfig'}
    if error=='foreign': raw['name']=FUNCTION.replace('/review/','/foreign/',1)
    t,_,_=transport(monkeypatch,[Response(raw)],kinds=['function'])
    row,_=t.request('GET','https://cloudfunctions.googleapis.com/v2/'+FUNCTION,scope=SCOPE,params=params)
    assert function_check.evaluate(row,index('function',row))[0]=='UNKNOWN'
    if TOKEN in json.dumps([row,t.evidence])+repr(t.cache): pytest.fail('detector exception content escaped',pytrace=False)


@pytest.mark.parametrize('code',[302,401,403])
def test_log_content_redirect_denied_response_closed_without_body_parse(monkeypatch,clean,code):
    reply=Response(payload=TOKEN.encode(),status=code,headers={'Location':'https://external.invalid'})
    t,calls,_=transport(monkeypatch,[reply],kinds=[logs.KIND])
    c=gcp.GCPCollector({'provider':'gcp','scopes':[SCOPE],'options':t.options},requirements=[logs.KIND],transport=t)
    env=c.envelope(*logs.scope_jobs(c,SCOPE)[0])
    assert env['status']!='collected' and reply.closed and len(calls)==1 and reply.reads==[]
    if TOKEN in json.dumps(env)+json.dumps(t.evidence)+repr(t.cache): pytest.fail('provider error content persisted',pytrace=False)


def test_selected_object_native_bearer_not_overridden_by_ambient_netrc(monkeypatch):
    # Real requests preparation, mocked send only: no socket/credential calls.
    c,_,_,_,_=object_fixture(monkeypatch)
    ambient=[]
    def netrc(url): ambient.append(url);return ('ambient-user','ambient-password')
    monkeypatch.setattr(requests.sessions,'get_netrc_auth',netrc)
    prepared=[]
    def send(request,**kw):
        prepared.append(request)
        response=requests.Response();response.status_code=403;response.url=request.url
        response._content=b'';response.headers={}
        return response
    monkeypatch.setattr(c.transport,'_session',gcp.Transport._session.__get__(c.transport,gcp.Transport))
    session=c.transport._session()
    monkeypatch.setattr(session,'send',send)
    state={'started':objects.time.monotonic(),'calls':0,'bytes':0}
    target=c.options[objects.OPTION][0]
    with pytest.raises(objects.Incomplete): objects._read(c.transport,state,target)
    assert len(prepared)==1
    if prepared[0].headers.get('Authorization')!='Bearer synthetic-native-auth':
        pytest.fail('ambient netrc credentials override explicit native bearer on content GET',pytrace=False)


def test_candidate_gke_native_reader_keeps_detected_value_in_reference_metadata(monkeypatch):
    from peaso.collectors import gcp_gke_literal_secret_indicators as bridge
    import ssl
    # Real pinned detector pair, exact native Pod/PodList and reader API seam.
    pod={'apiVersion':'v1','kind':'Pod','metadata':{'name':'review','namespace':'team',
        'uid':'00000000-0000-4000-8000-000000000001','resourceVersion':'101'},
        'spec':{'containers':[{'name':'main','env':[
            {'name':'CONFIG','value':TOKEN},
            {'name':TOKEN,'valueFrom':{'secretKeyRef':{'name':'managed-secret','key':'password'}}}]}]}}
    data={'apiVersion':'v1','kind':'PodList','metadata':{'resourceVersion':'100','continue':''},'items':[pod]}
    body=json.dumps(data).encode()
    response=SimpleNamespace(status=200,chunked=False)
    response.getheader=lambda key,default=None: str(len(body)) if key=='Content-Length' else default
    stream=io.BytesIO(body)
    response.read=stream.read
    response.read1=stream.read1
    response.close=lambda:None
    calls=[]
    class Connection:
        sock=None
        def __init__(self,*a,**kw): pass
        def request(self,method,path,headers):
            assert method=='GET' and path.startswith('/api/v1/namespaces/team/pods?')
            calls.append(path)
        def getresponse(self): return response
        def close(self): pass
    monkeypatch.setattr(bridge.http.client,'HTTPSConnection',Connection)
    t,_,_=transport(monkeypatch,[],kinds=[bridge.KIND])
    t.credentials.direct_token='synthetic-native-auth'
    binding={'selection':SCOPE+'/locations/us-central1/clusters/review','endpoint':'34.123.45.67',
             'ca_sha256':'a'*64,'context':ssl.create_default_context(),'source_requests':['request-cluster'],
             'namespace_mode':'selected','namespace_names':['team'],'namespace_requests':[]}
    budget={'deadline':bridge.time.monotonic()+60,'calls':0,'read_bytes':bridge.MAX_READ_BYTES,
            'scan_bytes':bridge.MAX_SCAN_BYTES,'resources':0}
    reader=bridge.Reader(SimpleNamespace(transport=t),binding,['team'],budget)
    projected,_=reader.read('/api/v1/namespaces/team/pods',{'limit':bridge.PAGE_SIZE})
    row,=projected['items']
    assert row[bridge.MARKER]['complete'] and row[bridge.MARKER]['leaks'] and len(calls)==1
    # Found values stay visible (73706ae8); only the connector's own credential stays out.
    assert TOKEN in json.dumps(row)
    assert 'synthetic-native-auth' not in json.dumps([row,t.evidence])+repr(scanning._RESULTS)


def test_candidate_dataflow_each_item_links_its_own_full_read_not_another_job(monkeypatch,clean):
    from peaso.collectors import gcp_job_literal_secret_indicators as jobs
    first='2026-10-19_00_00_00-1234567890123456789'
    second='2026-10-19_00_00_00-2234567890123456789'
    def row(identifier):
        return {'id':identifier,'name':'review-job','projectId':'review','location':'us-central1',
                'currentState':'JOB_STATE_RUNNING','environment':{'sdkPipelineOptions':{}}}
    replies=[Response({'jobs':[{k:v for k,v in row(i).items() if k!='environment'} for i in [first,second]]},headers={'Content-Type':'application/json'}),
             Response(row(first),headers={'Content-Type':'application/json'}),
             Response(row(second),headers={'Content-Type':'application/json'})]
    t,calls,_=transport(monkeypatch,[],kinds=[jobs.DATAFLOW])
    t.options.update(dataflow_regions=['us-central1'])
    c=gcp.GCPCollector({'provider':'gcp','scopes':[SCOPE],'options':t.options},requirements=['project'],transport=t)
    c.collections[('project',SCOPE)]={'coverage_status':'collected','items':[{'name':'projects/123456789','projectId':'review'}]}
    class Session:
        def request(self,method,url,**kw):
            assert method=='GET' and kw['allow_redirects'] is False and kw['stream'] is True
            assert self.trust_env is False and self.auth is None
            calls.append(url)
            reply=replies[len(calls)-1]
            reply.url=requests.Request('GET',url,params=kw['params']).prepare().url
            return reply
        def close(self): pass
    monkeypatch.setattr(requests,'Session',Session)
    env=c.envelope(jobs.DATAFLOW,SCOPE,'dataflow',lambda:jobs.collection_pages(c,SCOPE,jobs.DATAFLOW))
    assert len(env['items'])==2 and len(calls)==3
    assert all(r[jobs.MARKER]['complete'] for r in env['items'])
    refs=[e['id'] for e in t.evidence]
    first_id=jobs._identity(jobs.DATAFLOW,'review','us-central1',first)
    first_row=next(r for r in env['items'] if r['name']==first_id)
    retained=set(first_row['_provenance']['source_requests'])
    if not {refs[0],refs[1]} <= retained or refs[2] in retained:
        pytest.fail('first Dataflow item lacks its own FULL get receipt and is attributed to the other job get',pytrace=False)


@pytest.mark.parametrize('option', ['selected_gcs_objects','selected_gcs_archives','selected_artifact_images','selected_dataform_files'])
def test_hosted_selection_shapes_validated_without_credentials(option):
    from peaso.server.validation import validate_connector, OPTIONS
    from fastapi import HTTPException
    if option not in OPTIONS:
        pytest.skip('candidate not yet admitted to hosted intake')
    valid=selected_options()[option]
    validate_connector('gcp',{'method':'token','token':'synthetic-auth'},
                       {'content_secret_scans':True,option:valid},SimpleNamespace(auth_mode='cognito'),scopes=[SCOPE])
    with pytest.raises(HTTPException) as error:
        validate_connector('gcp',{'method':'token','token':'synthetic-auth'},
                           {'content_secret_scans':True,option:[{'url':'https://external.invalid'}]},
                           SimpleNamespace(auth_mode='cognito'),scopes=[SCOPE])
    assert error.value.status_code==422


def test_hosted_intake_rejects_forged_internal_planner_kind():
    from peaso.server.validation import validate_connector
    from fastapi import HTTPException
    with pytest.raises(HTTPException):
        validate_connector('gcp',{'method':'token','token':'synthetic-auth'},
                           {'content_secret_scans':True,'_content_secret_scan_kinds':['function']},
                           SimpleNamespace(auth_mode='cognito'),scopes=[SCOPE])


@pytest.mark.parametrize('method,url', [
    ('GET','https://secretmanager.googleapis.com/v1/projects/review/secrets/private/versions/latest:access'),
    ('POST','https://cloudkms.googleapis.com/v1/projects/review/locations/us-central1/keyRings/r/cryptoKeys/k:decrypt'),
    ('POST','https://run.googleapis.com/v2/projects/review/locations/us-central1/jobs/review:run'),
    ('GET','https://external.invalid/v1/projects/review'),
])
def test_shared_transport_rejects_sensitive_execution_and_external_reads_before_auth(monkeypatch,method,url):
    t,calls,auth=transport(monkeypatch,[],kinds=['function','workflow_source'])
    with pytest.raises(gcp.ReadError): t.request(method,url,scope=SCOPE)
    assert calls==auth==[]


def test_same_leak_across_actual_function_and_compute_hooks_remains_one_finding(monkeypatch):
    results=[]
    name=SCOPE+'/zones/us-central1-a/instances/review'
    for kind,url,raw,evaluate,cid in [
        ('function','https://cloudfunctions.googleapis.com/v2/'+FUNCTION,
         {'name':FUNCTION,'serviceConfig':{'environmentVariables':{'CONFIG':TOKEN}},'buildConfig':{}},function_check.evaluate,function_check.CHECK_ID),
        ('instance','https://compute.googleapis.com/compute/v1/'+name,
         {'name':'review','selfLink':'https://www.googleapis.com/compute/v1/'+name,'metadata':{'items':[{'key':'startup-script','value':TOKEN}]}},configuration_checks.instance,configurations.IDS['instance'])]:
        t,_,_=transport(monkeypatch,[Response(raw)],kinds=[kind])
        row,_=t.request('GET',url,scope=SCOPE)
        status,evidence=evaluate(row,index(kind,row))
        assert status=='FAIL'
        results.append({'provider':'gcp','scope':SCOPE,'check_id':cid,'resource_id':row['name'],
                        'native_resource_id':FUNCTION if kind=='function' else name,'status':status,'evidence':evidence,'frameworks':[],'finding_type':'secrets'})
    merged=deduplicate_secret_findings(results)
    assert len(merged)==1 and len(merged[0]['linked_check_ids'])==2
    leak,=merged[0]['evidence']['secret_leaks']
    assert {r['engine'] for r in leak['detectors']}=={'kingfisher','trufflehog'}
    assert len(leak['locations'])==2
    if TOKEN in json.dumps(merged): pytest.fail('dedup emitted raw literal',pytrace=False)


@pytest.mark.parametrize('check_id',sorted(REGISTERED))
def test_registered_secret_check_uses_existing_secrets_finding_type(check_id):
    finding=engine._finding(REGISTERED[check_id],'gcp',SCOPE,'synthetic-resource','native-gcp',
                            'UNKNOWN',{'observed':'Unassessed selected configuration.'})
    assert finding['finding_type']=='secrets'


@pytest.mark.parametrize('adapter_name',['object','archive','dataform','image','logs','workflow','appengine','jobs','gke'])
@pytest.mark.parametrize('gate',['disabled','unnamed'])
def test_all_content_acquisition_adapters_make_zero_extra_calls_without_both_gates(monkeypatch,adapter_name,gate):
    from peaso.collectors import gcp_dataform_secret_indicators as dataform
    from peaso.collectors import gcp_image_secret_indicators as images
    from peaso.collectors import gcp_additional_literal_secret_indicators as extra
    from peaso.collectors import gcp_job_literal_secret_indicators as jobs
    from peaso.collectors import gcp_gke_literal_secret_indicators as gke_bridge
    kinds=['function',*configurations.KINDS,objects.KIND,archives.KIND,dataform.KIND,
           'artifact_image',logs.KIND,*extra.KINDS,*jobs.KINDS,gke_bridge.KIND]
    t,calls,auth=transport(monkeypatch,[],kinds=kinds if gate=='disabled' else [],enabled=gate!='disabled')
    t.options.update(selected_options())
    t.options['content_secret_scans']=gate!='disabled'
    c=SimpleNamespace(options=t.options,scopes=[SCOPE],requested_scopes=[SCOPE],transport=t,
                      collections={},needed=set(kinds))
    def unexpected(*a,**k): pytest.fail('content acquisition occurred without both public and named gates')
    c.read=unexpected
    monkeypatch.setattr(scanning,'_scan_kingfisher',unexpected)
    monkeypatch.setattr(scanning,'_scan_trufflehog',unexpected)
    if adapter_name=='object': assert objects.collect_selected_objects(c,SCOPE)==[]
    if adapter_name=='archive': assert archives.collect_selected_archives(c,SCOPE)==[]
    if adapter_name=='dataform': assert dataform.collect_selected_files(c,SCOPE,reader_factory=unexpected)==[]
    if adapter_name=='image': assert images.enrich(c,reader_factory=unexpected) is None
    if adapter_name=='jobs': assert list(jobs.collection_pages(c,SCOPE,jobs.DATAFLOW,reader_factory=unexpected))==[]
    if adapter_name in ['logs','workflow','appengine','gke']:
        if adapter_name=='logs': pending=logs.scope_jobs(c,SCOPE)
        if adapter_name=='workflow': pending=extra.workflow_jobs(c,SCOPE)
        if adapter_name=='appengine': pending=extra.appengine_jobs(c)
        if adapter_name=='gke': pending=gke_bridge.dependent_jobs(c)
        for job in pending:
            try: list(job[3]())
            except gcp.ReadError: pass  # explicit unavailable, never a read or clean result
    assert calls==auth==[] and t.calls==0


def configuration_native(kind):
    region=SCOPE+'/locations/us-central1/'
    compute='https://compute.googleapis.com/compute/v1/'+SCOPE
    pair={'items':[{'key':'startup-script','value':TOKEN}]}
    if kind=='project': return compute,{'name':'review','commonInstanceMetadata':pair}
    if kind in ('instance','instance_template'):
        suffix='/zones/us-central1-a/instances/review' if kind=='instance' else '/global/instanceTemplates/review'
        row={'name':'review','selfLink':compute+suffix}
        row.update({'metadata':pair} if kind=='instance' else {'properties':{'metadata':pair}})
        return compute+suffix,row
    if kind in ('cloudrun_service','cloudrun_job'):
        name=region+('services/review' if kind=='cloudrun_service' else 'jobs/review')
        template={'containers':[{'env':[{'name':'CONFIG','value':TOKEN}]}]}
        return 'https://run.googleapis.com/v2/'+name,{'name':name,'template':template if kind=='cloudrun_service' else {'template':template}}
    uid='00000000-0000-4000-8000-000000000001'
    name=region+('triggers/' if kind=='cloudbuild_trigger' else 'builds/')+uid
    build={'steps':[{'name':'ubuntu','args':[TOKEN]}]}
    row={'id':uid,'resourceName':name,'build':build} if kind=='cloudbuild_trigger' else {'id':uid,'projectId':'review','name':name,**build}
    return 'https://cloudbuild.googleapis.com/v1/'+name,row


@pytest.mark.parametrize('kind',configurations.KINDS)
@pytest.mark.parametrize('gate',['disabled','unnamed'])
def test_all_seven_configuration_transport_hooks_default_off_without_extra_reads_or_values(monkeypatch,kind,gate):
    def unexpected(*a,**kw): pytest.fail('unselected configuration detector was invoked')
    monkeypatch.setattr(scanning,'_scan_kingfisher',unexpected)
    monkeypatch.setattr(scanning,'_scan_trufflehog',unexpected)
    url,raw=configuration_native(kind)
    t,calls,_=transport(monkeypatch,[Response(raw)],kinds=[kind] if gate=='disabled' else [],enabled=gate!='disabled')
    row,_=t.request('GET',url,scope=SCOPE)
    assert len(calls)==1 and configurations.MARKER not in row
    if TOKEN in json.dumps(row)+repr(t.cache)+json.dumps(t.evidence):
        pytest.fail('default configuration hook retained literal content',pytrace=False)


def test_detected_value_on_later_native_page_cannot_survive_in_earlier_page_metadata(monkeypatch):
    # Native functions.list pagination, actual Transport/cache/pages/envelope/finish.
    first={'name':FUNCTION+'-first','description':'copy='+TOKEN,'serviceConfig':{},'buildConfig':{}}
    second={'name':FUNCTION+'-second','serviceConfig':{'environmentVariables':{'CONFIG':TOKEN}},'buildConfig':{}}
    replies=[Response({'functions':[first],'nextPageToken':'opaque-next'}),Response({'functions':[second]})]
    t,calls,_=transport(monkeypatch,replies,kinds=['function'])
    c=gcp.GCPCollector({'provider':'gcp','scopes':[SCOPE],'options':t.options},requirements=['function'],transport=t)
    url='https://cloudfunctions.googleapis.com/v2/'+SCOPE+'/locations/-/functions'
    env=c.envelope('function',SCOPE,'cloudfunctions',lambda:c.pages(url,SCOPE,key='functions'))
    assert env['status']=='collected' and len(env['items'])==2 and len(calls)==2
    assert function_check.evaluate(env['items'][1],index('function',env['items'][1],env))[0]=='FAIL'
    c.collections[('function',SCOPE)]=env
    snapshot=c.finish()
    if TOKEN in json.dumps(snapshot)+repr(t.cache):
        pytest.fail('value detected on a later native page remains in an earlier page metadata snapshot/cache',pytrace=False)


def test_review_uses_workspace_production_sources_and_pinned_offline_engines():
    from importlib.metadata import version
    assert Path(gcp.__file__).resolve()==(Path.cwd()/'peaso/collectors/gcp.py').resolve()
    assert Path(scanning.__file__).resolve()==(Path.cwd()/'peaso/secret_scanning.py').resolve()
    assert version('kingfisher-secret-scanner')==scanning.KINGFISHER_VERSION=='1.4.0'
    assert scanning.TRUFFLEHOG_VERSION=='3.92.5' and scanning._trufflehog()


@pytest.mark.parametrize('field',['description','labels','annotations'])
def test_selected_run_configuration_free_text_is_omitted_across_native_pages(monkeypatch,field):
    # These fields exist on native GoogleCloudRunV2Service; lower-case label value
    # respects GCP label constraints while remaining a synthetic detector input.
    token=TOKEN.lower()
    prefix=SCOPE+'/locations/us-central1/services/'
    def service(name,value=None):
        return {'name':prefix+name,'ingress':'INGRESS_TRAFFIC_INTERNAL_ONLY',
                'template':{'serviceAccount':'worker@review.iam.gserviceaccount.com',
                    'containers':[{'image':'us-central1-docker.pkg.dev/review/images/app@sha256:'+'a'*64,
                                   'env':[] if value is None else [{'name':'CONFIG','value':value}]}]}}
    first=service('first')
    first[field]=token if field=='description' else {'copied':token}
    second=service('second',token)
    t,calls,_=transport(monkeypatch,[Response({'services':[first],'nextPageToken':'opaque-next'}),Response({'services':[second]})],kinds=['cloudrun_service'])
    c=gcp.GCPCollector({'provider':'gcp','scopes':[SCOPE],'options':t.options},requirements=['cloudrun_service'],transport=t)
    url='https://run.googleapis.com/v2/'+SCOPE+'/locations/us-central1/services'
    env=c.envelope('cloudrun_service',SCOPE,'run',lambda:c.pages(url,SCOPE,key='services'))
    assert env['status']=='collected' and len(calls)==2
    earlier,later=env['items']
    assert earlier['ingress']=='INGRESS_TRAFFIC_INTERNAL_ONLY'
    assert earlier['template']['serviceAccount']=='worker@review.iam.gserviceaccount.com'
    assert field not in earlier and earlier['_coverage'][field]=={'status':'unknown','reason':'free_text_not_retained'}
    assert configuration_checks.cloudrun_service(later,index('cloudrun_service',later,env))[0]=='FAIL'
    c.collections[('cloudrun_service',SCOPE)]=env
    if token in json.dumps(c.finish())+repr(t.cache):
        pytest.fail('opted-in Run configuration retained historical free-text metadata',pytrace=False)


def test_shared_free_text_projection_preserves_typed_facts_and_blocks_removed_fact_reads():
    from peaso.checks.facts import get,Unavailable
    raw={'name':FUNCTION,'description':'documentation','labels':{'purpose':'review'},
         'serviceConfig':{'ingressSettings':'ALLOW_INTERNAL_ONLY','serviceAccountEmail':'worker@review.iam.gserviceaccount.com'},
         'nested':[{'annotations':{'note':'documentation'},'enabled':True}],
         '_coverage':{'legacy':{'status':'unknown','reason':'preexisting'}}}
    projected=scanning.omit_free_text_metadata(raw)
    assert raw['description']=='documentation' and raw['labels']=={'purpose':'review'}  # clone
    assert get(projected,'name',str)==FUNCTION
    assert get(projected,'serviceConfig.ingressSettings',str)=='ALLOW_INTERNAL_ONLY'
    assert projected['_coverage']['legacy']==raw['_coverage']['legacy']
    assert projected['nested'][0]['enabled'] is True
    assert 'annotations' not in projected['nested'][0]
    for field in ['description','labels']:
        assert projected['_coverage'][field]=={'status':'unknown','reason':'free_text_not_retained'}
        with pytest.raises(Unavailable): get(projected,field)
