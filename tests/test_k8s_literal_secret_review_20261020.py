"""Independent exact native GET -> bounded Kubernetes collector -> public engine."""
from copy import deepcopy
from tests.selected_secret_source_successors_20261020 import assert_source_receipt, assert_callable_receipt
import base64
import io
import json
from pathlib import Path
import socket
from types import SimpleNamespace
from urllib.parse import urlsplit
import pytest
from kubernetes.client import ApiClient, Configuration
from peaso import engine, secret_scanning as scanning
from tests.pinned_secret_scanners import require_pinned_scanners
from peaso.collectors import k8s
from peaso.collectors import k8s_literal_secret_indicators as source
from peaso.checks import k8s_literal_secret_review_20261020 as checks

CLUSTER = 'review-cluster'
HOST = 'https://review-k8s.invalid:6443'
NS = 'team-a'
TOKEN = 'ghp_' + '7mQ2zR9wL4cV8nK1sF6aH3jP5uD0xB2yE9rT'
AUTH = 'synthetic-native-auth-canary'


@pytest.fixture(autouse=True)
def offline(monkeypatch):
    def blocked(*args, **kwargs):
        pytest.fail('live network/DNS/cloud auth is forbidden')
    monkeypatch.setattr(socket.socket, 'connect', blocked)
    monkeypatch.setattr(socket.socket, 'connect_ex', blocked)
    monkeypatch.setattr(socket, 'create_connection', blocked)
    monkeypatch.setattr(socket, 'getaddrinfo', blocked)
    from kubernetes import config
    monkeypatch.setattr(config, 'load_kube_config', blocked)
    monkeypatch.setattr(config, 'load_incluster_config', blocked)
    scanning._RESULTS.clear()
    yield
    scanning._RESULTS.clear()


def target(kind='Pod', name='review-pod', namespace=NS, cluster=CLUSTER):
    return {'cluster_id':cluster, 'namespace':namespace, 'kind':kind, 'name':name}


def route(t):
    return '/api/v1/namespaces/' + t['namespace'] + '/' + ('pods' if t['kind']=='Pod' else 'configmaps') + '/' + t['name']


def native(t=None, value='ready = true'):
    t = t or target()
    obj = {'apiVersion':'v1', 'kind':t['kind'], 'metadata':{'name':t['name'], 'namespace':t['namespace'],
        'uid':'7bc47700-1935-41a7-a928-9e49604eda26', 'resourceVersion':'207',
        'annotations':{'never-export':'opaque annotation'}, 'labels':{'app':'review'}}}
    if t['kind']=='Pod':
        obj['spec']={'containers':[{'name':'main', 'image':'example.invalid/unused:latest',
            'env':[{'name':'MODE', 'value':value}], 'command':['/bin/true'], 'args':['--mode=review']}]}
        obj['status']={'phase':'Running'}
    else:
        obj['data']={'MODE':value}
    return obj


class Response:
    def __init__(self, payload, status=200, headers=None):
        self.body=json.dumps(payload).encode() if isinstance(payload, (dict,list)) else payload
        self.stream=io.BytesIO(self.body)
        self.status, self.closed, self.released=status,False,False
        self.headers={'Content-Type':'application/json', 'Content-Length':str(len(self.body)), **(headers or {})}
    @property
    def data(self):
        pytest.fail('unbounded SDK response retention is forbidden')
    def read(self, size):
        assert 0 < size <= 16384
        return self.stream.read(size)
    def close(self): self.closed=True
    def release_conn(self): self.released=True


def request(targets=None, **options):
    return {'connector':{'provider':'k8s', 'scopes':list(dict.fromkeys(t['namespace'] for t in (targets or [target()]))),
        'auth':{'method':'token','server':HOST,'token':AUTH,'cluster_id':CLUSTER},
        'options':{'content_secret_scans':True,source.OPTION:targets or [target()], 'retries':0, **options}},
        'checks':[source.CHECK]}


def capture(monkeypatch, *, targets=None, documents=None, response=None, req=None, real=False, scanner=None, progress=False, extra_documents=None):
    targets=targets or [target()]
    documents=documents if documents is not None else {route(t):native(t) for t in targets}
    trace=SimpleNamespace(calls=[], scans=[], responses=[], progress=[], created=0)
    if not real:
        def detector(payload, path, timeout):
            trace.scans.append((bytes(payload),path,timeout))
            return scanner(payload,path,timeout) if scanner else ([(TOKEN,'github-pat',1)] if TOKEN.encode() in payload else [])
        monkeypatch.setattr(scanning,'_scan_kingfisher',detector)
        monkeypatch.setattr(scanning,'_scan_trufflehog',detector)
    class Pool:
        def request(self, method, url, **kwargs):
            parsed=urlsplit(url)
            assert method=='GET' and parsed.scheme=='https' and parsed.netloc=='review-k8s.invalid:6443'
            if extra_documents and parsed.path in extra_documents:
                assert not parsed.query and not parsed.fragment and kwargs['redirect'] is False and kwargs['retries'] is False
                assert kwargs['headers']['authorization']=='Bearer '+AUTH
                trace.calls.append((method,parsed.netloc,parsed.path))
                class MetadataResponse(Response):
                    @property
                    def data(self):return self.body
                result=MetadataResponse(extra_documents[parsed.path])
                trace.responses.append(result)
                return result
            assert not parsed.query and not parsed.fragment and parsed.path in {route(t) for t in targets}
            assert kwargs['headers']['authorization']=='Bearer '+AUTH
            assert kwargs['headers']['Accept-Encoding']=='identity'
            assert kwargs['redirect'] is False and kwargs['retries'] is False
            assert kwargs['preload_content'] is False and kwargs['decode_content'] is False
            assert 0 < kwargs['timeout'] <= 10 and kwargs.get('body') is None
            trace.calls.append((method,parsed.netloc,parsed.path))
            ordinal=sum(c[2]==parsed.path for c in trace.calls)
            if callable(response): result=response(parsed.path,ordinal)
            elif response is not None: result=response
            else:
                doc=documents[parsed.path]
                if callable(doc): doc=doc(ordinal)
                result=Response(doc)
            trace.responses.append(result)
            return result
    def new_api(auth):
        trace.created+=1
        configuration=Configuration()
        configuration.host=HOST
        configuration.api_key={'authorization':AUTH}
        configuration.api_key_prefix={'authorization':'Bearer'}
        client=ApiClient(configuration)
        # Actual SDK authentication refresh and the existing actual origin/path
        # gate are exercised; only the lowest network transport is synthetic.
        client.rest_client.pool_manager=Pool()
        api=k8s._wrap_client(client)
        api.close=lambda:None
        trace.api=api
        return api
    monkeypatch.setattr(k8s,'_new_api',new_api)
    req=deepcopy(req if req is not None else request(targets))
    if progress: req['connector']['options']['_progress_callback']=trace.progress.append
    trace.req=req
    return engine.collect_snapshot(req),trace


def findings(snapshot):
    return engine.evaluate_snapshot(snapshot,checks=[source.CHECK])['findings']


def item_index(snapshot,pos=0):
    own=next(c for c in snapshot['collections'] if c['type']==source.KIND)
    return own['items'][pos],{'context':{'provider':'k8s','scope':own['scope'],'metadata':snapshot['metadata']},
        'collections':{source.KIND:[own]}}


@pytest.mark.parametrize('kind',['Pod','ConfigMap'])
@pytest.mark.parametrize('positive',[False,True])
def test_native_dual_detection_and_no_raw_retention(monkeypatch,kind,positive):
    t=target(kind)
    snapshot,trace=capture(monkeypatch,targets=[t],documents={route(t):native(t,TOKEN if positive else 'ready = true')})
    results=findings(snapshot)
    assert len(results)==1 and results[0]['status']==('FAIL' if positive else 'PASS'),results
    status,evidence=checks.evaluate(*item_index(snapshot))
    assert status==results[0]['status'] and evidence['complete'] is True
    assert evidence['coverage']=='selected_observed_literals_only'
    assert len(trace.calls)==2 and len(trace.scans)==2
    persisted=json.dumps([snapshot,results,list(scanning._RESULTS.values())],default=str)
    assert all(value not in persisted for value in [TOKEN,AUTH,t['name'],'ready = true','opaque annotation','unused:latest'])
    assert all(r.closed and r.released for r in trace.responses)
    assert getattr(trace.api.api_client, 'last_response', None) is None
    assert trace.api.api_client.rest_client.pool_manager.literal_paths==frozenset()


@pytest.mark.parametrize('kind',['Pod','ConfigMap'])
@pytest.mark.parametrize('positive',[False,True])
def test_real_pinned_offline_detectors(monkeypatch,kind,positive):
    require_pinned_scanners()
    t=target(kind)
    snapshot,trace=capture(monkeypatch,targets=[t],documents={route(t):native(t,TOKEN if positive else 'ready = true')},real=True)
    result=findings(snapshot)
    assert {r['status'] for r in result}==({'FAIL'} if positive else {'PASS'}),result
    _,ev=checks.evaluate(*item_index(snapshot))
    assert {(e['engine'],e['version'],e['status']) for e in ev['parts'][0]['engines']}=={
        ('kingfisher','1.4.0','complete'),('trufflehog','3.92.5','complete')}
    if positive:
        leak,=result[0]['evidence']['secret_leaks']
        assert {d['engine'] for d in leak['detectors']}=={'kingfisher','trufflehog'}
    assert TOKEN not in json.dumps([snapshot,result]) and len(trace.calls)==2


@pytest.mark.parametrize('field',['containers','initContainers','ephemeralContainers'])
@pytest.mark.parametrize('location',['env','command','args'])
def test_all_selected_pod_literal_surfaces(monkeypatch,field,location):
    obj=native()
    container={'name':'inspected','image':'example.invalid/unused:latest'}
    container[location]=[{'name':'TOKEN','value':TOKEN}] if location=='env' else [TOKEN]
    if field=='ephemeralContainers': container['targetContainerName']='main'
    if field=='containers': obj['spec']['containers']=[container]
    else: obj['spec'][field]=[container]
    snapshot,trace=capture(monkeypatch,documents={route(target()):obj})
    assert {r['status'] for r in findings(snapshot)}=={'FAIL'}
    assert len(trace.calls)==2 and TOKEN not in json.dumps(snapshot)


@pytest.mark.parametrize('binary',[False,True])
def test_configmap_data_binarydata_and_keys(monkeypatch,binary):
    t=target('ConfigMap','review-map');obj=native(t)
    obj['data']={TOKEN:'ready'}
    if binary: obj['binaryData']={'extra':base64.b64encode(TOKEN.encode()).decode()}
    snapshot,trace=capture(monkeypatch,targets=[t],documents={route(t):obj})
    assert findings(snapshot)[0]['status']=='FAIL'
    assert TOKEN not in json.dumps(snapshot) and len(trace.calls)==2
    assert TOKEN.encode() in trace.scans[0][0]


def test_reference_sources_excluded_without_reads_or_expansion(monkeypatch):
    obj=native();c=obj['spec']['containers'][0]
    c['env'] += [{'name':'FROM_SECRET','valueFrom':{'secretKeyRef':{'name':'reference-secret','key':'password'}}},
        {'name':'FROM_CONFIG','valueFrom':{'configMapKeyRef':{'name':'reference-config','key':'key'}}},
        {'name':'POD_NAME','valueFrom':{'fieldRef':{'fieldPath':'metadata.name'}}}]
    c['envFrom']=[{'secretRef':{'name':'reference-secret'}}, {'configMapRef':{'name':'reference-config'}}]
    c['args']=['$(FROM_SECRET)']
    snapshot,trace=capture(monkeypatch,documents={route(target()):obj})
    assert findings(snapshot)[0]['status']=='PASS'
    _,ev=checks.evaluate(*item_index(snapshot))
    assert ev['reference_count']==5
    assert len(trace.calls)==2 and all(all(v not in p for v in (TOKEN.encode(),b'reference-secret',b'reference-config')) for p,_,_ in trace.scans)
    assert TOKEN not in json.dumps(snapshot)


@pytest.mark.parametrize('ordinal',[1,2])
@pytest.mark.parametrize('status',[201,204,206,301,307,400,401,403,404,410,429,500])
def test_denied_partial_redirect_deleted_never_clean(monkeypatch,ordinal,status):
    def response(path,n): return Response({'message':TOKEN},status) if n==ordinal else Response(native())
    snapshot,trace=capture(monkeypatch,response=response)
    assert {r['status'] for r in findings(snapshot)}=={'UNKNOWN'}
    assert not trace.scans and len(trace.calls)==ordinal
    assert TOKEN not in json.dumps(snapshot) and all(r.closed and r.released for r in trace.responses)


@pytest.mark.parametrize('mutate',[
    lambda o:o.pop('apiVersion'),lambda o:o.update(kind='Secret'),lambda o:o.update(items=[]),
    lambda o:o['metadata'].pop('uid'),lambda o:o['metadata'].update(uid=''),
    lambda o:o['metadata'].pop('resourceVersion'),lambda o:o['metadata'].update(resourceVersion=1),
    lambda o:o['metadata'].update(namespace='foreign'),lambda o:o['metadata'].update(name='foreign'),
    lambda o:o['metadata'].update(deletionTimestamp='2026-10-20T00:00:00Z'),
    lambda o:o['spec'].update(containers=None),lambda o:o['spec'].update(containers=[]),
    lambda o:o['spec']['containers'][0].update(args=TOKEN),
    lambda o:o['spec']['containers'][0].update(env=[{'name':'X','value':TOKEN,'valueFrom':{'secretKeyRef':{}}}]),
    lambda o:o['spec']['containers'][0].update(env=[{'name':'X','value':'x'},{'name':'X','value':'y'}]),
    lambda o:o['spec']['containers'][0].update(env=[{'name':'X','value':None}]),
    lambda o:o['spec']['containers'][0].update(command=['x'*(source.MAX_VALUE+1)]),
    lambda o:o['spec']['containers'][0].update(envFrom='bad'),
])
def test_native_identity_or_content_malformed_unresolved(monkeypatch,mutate):
    obj=native();mutate(obj)
    snapshot,trace=capture(monkeypatch,documents={route(target()):obj})
    assert {r['status'] for r in findings(snapshot)}=={'UNKNOWN'}
    assert not trace.scans and len(trace.calls)==1 and TOKEN not in json.dumps(snapshot)


@pytest.mark.parametrize('field',['uid','resourceVersion','name','namespace'])
def test_between_reads_changed_identity_unknown(monkeypatch,field):
    def document(n):
        obj=native()
        if n==2:obj['metadata'][field]='changed'
        return obj
    snapshot,trace=capture(monkeypatch,documents={route(target()):document})
    assert {r['status'] for r in findings(snapshot)}=={'UNKNOWN'}
    assert len(trace.calls)==2 and not trace.scans


def test_conflicting_same_version_content_unknown(monkeypatch):
    snapshot,trace=capture(monkeypatch,documents={route(target()):lambda n:native(value='one' if n==1 else 'two')})
    assert {r['status'] for r in findings(snapshot)}=={'UNKNOWN'} and not trace.scans


@pytest.mark.parametrize('change',[
    lambda d:d.update(data={}),lambda d:d.update(data={'X':''}),lambda d:d.update(data={'X':None}),
    lambda d:d.update(binaryData={'X':'not base64'}),
    lambda d:d.update(binaryData={'X':base64.b64encode(b'\xff\x00').decode()}),
    lambda d:d.update(binaryData={'MODE':base64.b64encode(b'duplicate').decode()}),
    lambda d:d.update(data={str(i):'x' for i in range(source.MAX_LITERALS+1)}),
    lambda d:d.update(data={str(i):'x'*source.MAX_VALUE for i in range(5)}),
])
def test_empty_unsupported_or_oversize_configmap_never_clean(monkeypatch,change):
    t=target('ConfigMap');obj=native(t);change(obj)
    snapshot,trace=capture(monkeypatch,targets=[t],documents={route(t):obj})
    assert {r['status'] for r in findings(snapshot)}=={'UNKNOWN'} and not trace.scans


@pytest.mark.parametrize('response',[
    Response(b'{"kind":"Pod","kind":"ConfigMap"}'),Response(b'not-json'),Response(b'[]'),
    Response(b'{}',headers={'Content-Encoding':'gzip'}),Response(b'{}',headers={'Content-Type':'text/html'}),
    Response(b'{}',headers={'Content-Length':'999'}),Response(b'{}',headers={'Content-Length':'0'}),
    Response(b'{}',headers={'Content-Length':str(source.MAX_WIRE+1)}),
    Response(b'x'*(source.MAX_WIRE+1),headers={'Content-Length':None}),
])
def test_native_wire_bounds_and_malformed_unknown(monkeypatch,response):
    snapshot,trace=capture(monkeypatch,response=response)
    assert {r['status'] for r in findings(snapshot)}=={'UNKNOWN'}
    assert not trace.scans and response.closed and response.released


@pytest.mark.parametrize('engine_name',['_scan_kingfisher','_scan_trufflehog'])
def test_one_detector_unavailable_cannot_clean(monkeypatch,engine_name):
    def unavailable(*args):raise RuntimeError(TOKEN)
    # capture installs controlled low-level engines first, then native pool's
    # response callback simulates a detector executable becoming unavailable.
    def response(path,n):
        monkeypatch.setattr(scanning,engine_name,unavailable)
        return Response(native(value=TOKEN))
    snapshot,trace=capture(monkeypatch,response=response)
    result=findings(snapshot)
    assert 'FAIL' in {r['status'] for r in result} and 'PASS' not in {r['status'] for r in result}
    failures=[r for r in result if r['status']=='FAIL']
    assert len(failures)==1 and failures[0]['evidence']['complete'] is False
    assert 'Coverage is incomplete' in failures[0]['evidence']['observed']
    assert any(c['status']=='partial' for c in snapshot['collections'])
    assert TOKEN not in json.dumps(snapshot) and not scanning._RESULTS


def test_exact_value_hmac_dedup_across_objects_and_adapters(monkeypatch):
    targets=[target(),target('ConfigMap','review-map')]
    snapshot,trace=capture(monkeypatch,targets=targets,documents={route(t):native(t,TOKEN) for t in targets})
    results=findings(snapshot)
    assert {r['status'] for r in results}=={'FAIL'} and len(results)==1
    assert len(results[0]['evidence']['secret_leaks'][0]['locations'])==2
    leaks=scanning.merge_leaks([l for r in results for l in r['evidence']['secret_leaks']])
    assert len(leaks)==1 and len(leaks[0]['locations'])==2
    another=scanning.scan_content(TOKEN.encode(), 'another-cloud-adapter', _redact_values=lambda _:None)
    assert another['leaks'][0]['fingerprint']==leaks[0]['fingerprint']==scanning._fingerprint(TOKEN)
    assert len(scanning.merge_leaks(leaks+another['leaks']))==1
    assert len(trace.calls)==4 and TOKEN not in json.dumps([snapshot,results])


def test_union_redaction_identity_names_locations_and_progress(monkeypatch):
    sensitive='sensitive-canary'
    t=target('ConfigMap',name=sensitive)
    t['cluster_id']=CLUSTER+'-'+sensitive
    req=request([t]);req['connector']['auth']['cluster_id']=t['cluster_id']
    def detector(payload,path,timeout):return [(sensitive,'test-canary',1)] if sensitive.encode() in payload else []
    snapshot,trace=capture(monkeypatch,targets=[t],req=req,scanner=detector,progress=True)
    assert {r['status'] for r in findings(snapshot)}=={'FAIL'}
    persisted=json.dumps([snapshot,findings(snapshot),trace.progress,scanning._RESULTS],default=str)
    # Found values stay visible, including the resource identities that carry them.
    assert sensitive in json.dumps(snapshot) and 'REDACTED' not in persisted
    assert sensitive not in repr(scanning._RESULTS)
    assert all(not e.get('scope') for e in trace.progress)


def test_detected_namespace_never_leaks_or_proves_clean(monkeypatch):
    t=target(namespace='sensitive-canary')
    def detector(payload,path,timeout):return [('sensitive-canary','test-canary',1)]
    snapshot,trace=capture(monkeypatch,targets=[t],scanner=detector,progress=True)
    # The namespace is a found value, so it stays visible in the snapshot.
    assert 'sensitive-canary' in json.dumps(snapshot)
    assert all(r['status']!='PASS' for r in findings(snapshot))


@pytest.mark.parametrize('mutate',[
    lambda r:r['connector']['options'].update(content_secret_scans='true'),
    lambda r:r['connector']['options'].update(selected_k8s_literal_resources=[]),
    lambda r:r['connector']['options'].update(selected_k8s_literal_resources=[target()]*9),
    lambda r:r['connector']['options'].update(selected_k8s_literal_resources=[target(),target()]),
    lambda r:r['connector']['options'].update(selected_k8s_literal_resources=[target(kind='Secret')]),
    lambda r:r['connector']['options'].update(selected_k8s_literal_resources=[target(namespace='foreign')]),
    lambda r:r['connector']['options'].update(selected_k8s_literal_resources=[target(name='../escape')]),
    lambda r:r['connector']['options'].update(selected_k8s_literal_resources=[target(name='https://foreign.invalid')]),
    lambda r:r['connector']['options'].update(selected_k8s_literal_resources=[{**target(),'extra':True}]),
    lambda r:r['connector']['options'].update(selected_k8s_literal_resources=[target(),target('ConfigMap',cluster='foreign')]),
    lambda r:r['connector'].update(scopes=['*',NS]),
])
def test_invalid_selection_rejected_before_auth_or_native_read(monkeypatch,mutate):
    req=request();mutate(req)
    def blocked(*args,**kwargs):pytest.fail('invalid selection must not authenticate')
    monkeypatch.setattr(k8s,'_new_api',blocked)
    with pytest.raises(ValueError):engine.collect_snapshot(req)


def test_cross_cluster_selection_rejected_without_native_read(monkeypatch):
    t=target(cluster='foreign-cluster')
    snapshot,trace=capture(monkeypatch,targets=[t])
    assert {r['status'] for r in findings(snapshot)}=={'UNKNOWN'}
    assert not trace.calls and not trace.scans


@pytest.mark.parametrize('flag',[False,None])
def test_disabled_never_reads_content(monkeypatch,flag):
    req=request()
    if flag is None:req['connector']['options'].pop('content_secret_scans')
    else:req['connector']['options']['content_secret_scans']=flag
    snapshot,trace=capture(monkeypatch,req=req)
    assert {r['status'] for r in findings(snapshot)}=={'UNKNOWN'}
    assert not trace.calls and not trace.scans


def test_spoofed_internal_kind_without_exact_named_check_has_no_admission(monkeypatch):
    req=request();req.pop('checks');req['categories']=['hardening']
    req['connector']['options']['_content_secret_scan_kinds']=[source.KIND]
    # Keep the test bounded to the one optional inventory after the actual
    # public engine gate computes and overwrites the untrusted internal option.
    import peaso.collectors
    monkeypatch.setattr(engine,'plan_collection',lambda _, **kwargs: [source.KIND])
    snapshot,trace=capture(monkeypatch,req=req)
    assert not trace.calls and not trace.scans
    assert snapshot['metadata'][source.KIND+'_authorized'] is False


@pytest.mark.parametrize('path',[
    '/api/v1/namespaces/team-a/pods/other','/api/v1/namespaces/team-a/secrets/value',
    '/api/v1/namespaces/team-a/pods/review-pod/log','/api/v1/namespaces/team-a/pods/review-pod/exec',
    '/api/v1/namespaces/team-a/pods/review-pod?watch=true',
])
def test_exact_literal_transport_rejects_other_paths(monkeypatch,path):
    class Pool:
        def request(self,*args,**kwargs):pytest.fail('forbidden path reached native transport')
    pool=k8s._BoundedPool(Pool(),HOST);pool.literal_paths=frozenset([route(target())])
    with pytest.raises(ValueError):pool.request('GET',HOST+path)


@pytest.mark.parametrize('method,url,kwargs',[
    ('POST',HOST+route(target()),{}),('GET','https://foreign.invalid'+route(target()),{}),
    ('GET',HOST+route(target()),{'body':'bad'}),
    ('GET',HOST+route(target()),{'fields':{'watch':'true'}}),
    ('GET',HOST+'/api/v1/namespaces/team-a/pods/%72eview-pod',{}),
])
def test_transport_method_origin_query_body_guard(method,url,kwargs):
    class Pool:
        def request(self,*args,**kw):pytest.fail('forbidden request reached transport')
    pool=k8s._BoundedPool(Pool(),HOST);pool.literal_paths=frozenset([route(target())])
    with pytest.raises(ValueError):pool.request(method,url,**kwargs)


@pytest.mark.parametrize('option,value',[('max_calls',1),('max_resources',0),('collection_deadline_seconds',0.000001)])
def test_explicit_shared_budgets_cannot_prove_clean(monkeypatch,option,value):
    req=request(**{option:value})
    if option=='max_resources' and value==0:
        with pytest.raises(ValueError):capture(monkeypatch,req=req)
    else:
        snapshot,trace=capture(monkeypatch,req=req)
        assert {r['status'] for r in findings(snapshot)}=={'UNKNOWN'}
        assert not trace.scans


def test_selected_partial_inventory_cannot_make_other_object_clean(monkeypatch):
    ts=[target(),target('ConfigMap','review-map')]
    def response(path,n):return Response({'message':TOKEN},403) if path==route(ts[1]) else Response(native(ts[0]))
    snapshot,trace=capture(monkeypatch,targets=ts,response=response)
    assert {r['status'] for r in findings(snapshot)}=={'UNKNOWN'}
    assert len(trace.calls)==3


@pytest.mark.parametrize('mutation',[
    lambda s:s['metadata'].update({source.KIND+'_authorized':False}),
    lambda s:s['metadata'][source.KIND+'_receipts'][0].update(method='POST'),
    lambda s:s['metadata'][source.KIND+'_receipts'][0].update(scope='foreign'),
    lambda s:s['metadata'][source.KIND+'_receipts'][0].update(identity='foreign'),
    lambda s:s['metadata'][source.KIND+'_receipts'][0].update(status=206),
    lambda s:s['metadata'][source.KIND+'_receipts'][0].update(bytes=0),
    lambda s:s['collections'][0]['items'][0][source.MARKER].update(cluster_binding='0'*64),
    lambda s:s['collections'][0]['items'][0][source.MARKER].update(complete=False),
    lambda s:s['collections'][0]['items'][0][source.MARKER]['parts'][0]['engines'].pop(),
    lambda s:s['metadata'][source.KIND+'_selection'][NS].append(source.KIND+':'+ '0'*64),
])
def test_tampered_binding_and_receipts_unknown(monkeypatch,mutation):
    snapshot,_=capture(monkeypatch);snapshot=deepcopy(snapshot);mutation(snapshot);snapshot.pop('snapshot_id',None)
    assert {r['status'] for r in findings(snapshot)}=={'UNKNOWN'}


@pytest.mark.parametrize('key',['partial','_partial','hasMore','continuationToken','remainingItemCount','_coverage'])
def test_native_partial_projection_markers_never_clean(monkeypatch,key):
    obj=native();obj[key]=True
    snapshot,trace=capture(monkeypatch,documents={route(target()):obj})
    assert {r['status'] for r in findings(snapshot)}=={'UNKNOWN'} and not trace.scans


def test_native_derived_fixture_receipt(monkeypatch):
    require_pinned_scanners()
    cases={}
    for status in ('PASS','FAIL','UNKNOWN'):
        with monkeypatch.context() as patch:
            snapshot,_=capture(patch,real=True,documents={route(target()):native(value=TOKEN if status=='FAIL' else 'ready = true')},
                response=Response({'message':'denied'},403) if status=='UNKNOWN' else None)
            assert {r['status'] for r in findings(snapshot)}=={status}
            item,index=item_index(snapshot)
            cases[status.lower()]=deepcopy(item)
            cases[status.lower()+'_index']=deepcopy(index)
    cases['index']=deepcopy(cases['pass_index'])
    cases['missing']={}
    cases['malformed']={source.MARKER:None}
    receipt=Path('/tmp/peasso-k8s-literal-20261020/native-fixtures.json')
    receipt.parent.mkdir(parents=True,exist_ok=True)
    receipt.write_text(json.dumps({source.CHECK:cases},sort_keys=True,indent=2)+'\n')


def test_authorized_optional_scan_does_not_capture_raw_identity_in_ai_cache(monkeypatch):
    from peaso.ai import access
    def forbidden(*args,**kwargs):pytest.fail('optional literal scan must not capture raw access identities')
    monkeypatch.setattr(access,'k8s',forbidden)
    snapshot,_=capture(monkeypatch)
    assert findings(snapshot)[0]['status']=='PASS'


def test_read_deadline_and_batch_total_byte_bound(monkeypatch):
    with monkeypatch.context() as patch:
        patch.setattr(source,'MAX_SECONDS',-1)
        snapshot,trace=capture(patch)
        assert {r['status'] for r in findings(snapshot)}=={'UNKNOWN'} and not trace.calls
    with monkeypatch.context() as patch:
        patch.setattr(source,'MAX_TOTAL',10)
        snapshot,trace=capture(patch)
        assert {r['status'] for r in findings(snapshot)}=={'UNKNOWN'} and not trace.scans


def test_eight_selected_objects_exact_sixteen_get_ceiling(monkeypatch):
    targets=[target('ConfigMap','map-'+str(i)) for i in range(8)]
    snapshot,trace=capture(monkeypatch,targets=targets)
    assert {r['status'] for r in findings(snapshot)}=={'PASS'} and len(trace.calls)==16


def test_actual_azure_adapter_and_k8s_share_exact_value_hmac(monkeypatch):
    from tests import test_azure_app_settings_secret_review_20261020 as arm
    snapshot,_=capture(monkeypatch,documents={route(target()):native(value=TOKEN)})
    k8s_leak=findings(snapshot)[0]['evidence']['secret_leaks'][0]
    with monkeypatch.context() as patch:
        azure_snapshot,_=arm.capture(patch,data={arm.SITE:arm.native(values={'Token':TOKEN})})
        azure_leak=arm.findings(azure_snapshot)[0]['evidence']['secret_leaks'][0]
    assert k8s_leak['fingerprint']==azure_leak['fingerprint']==scanning._fingerprint(TOKEN)
    assert len(scanning.merge_leaks([k8s_leak,azure_leak]))==1
    assert TOKEN not in json.dumps([snapshot,azure_snapshot])


def test_registered_native_cases_and_public_secrets_admission():
    from peaso.checks import CHECKS
    from peaso.checks.fixtures import CASES
    check,=[c for c in CHECKS if c.id==source.CHECK]
    assert check.kind==source.KIND and check.dependencies==[source.KIND] and check.severity=='high'
    assert checks.DECLARATIONS[0]['requirements']==[] and checks.DECLARATIONS[0]['finding_type']=='secrets'
    cases=CASES[source.CHECK]
    for status in ('pass','fail','unknown'):
        assert check.evaluate(cases[status],cases[status+'_index'])[0]==status.upper()
    for status in ('missing','malformed'):
        assert check.evaluate(cases[status],cases['index'])[0]=='UNKNOWN'
    public=check.public()
    assert public['finding_type']=='secrets'
    assert public['requirement_controls']==[]


def test_default_collection_planning_does_not_select_optional_kind():
    req={'connector':{'provider':'k8s','scopes':[NS],'options':{}}}
    assert source.KIND not in engine.plan_collection(req)


def test_current_admission_source_and_native_fixture_hashes():
    import hashlib
    import inspect
    admission=json.loads(Path('peaso/checks/k8s_literal_secret_review_20261020_admission.json').read_text())
    assert admission['declarations']==checks.DECLARATIONS
    for name,expected in admission['source_hashes'].items():
        assert_source_receipt(name,expected)
    assert hashlib.sha256(Path(admission['fixture']['path']).read_bytes()).hexdigest()==admission['fixture']['sha256']
    assert_callable_receipt('peaso/checks/k8s_literal_secret_review_20261020.py', 'evaluate', admission['checks'][source.CHECK]['predicate_sha256'], admission['source_hashes']['peaso/checks/k8s_literal_secret_review_20261020.py'])


def test_resource_limit_bounds_safe_rows_and_reads(monkeypatch):
    targets=[target(),target('ConfigMap','review-map')]
    snapshot,trace=capture(monkeypatch,targets=targets,req=request(targets,max_resources=1))
    assert sum(len(c['items']) for c in snapshot['collections'])==1
    assert len(trace.calls)==2 and {r['status'] for r in findings(snapshot)}=={'UNKNOWN'}


@pytest.mark.parametrize('source_value',[
    {'secretKeyRef':{}},{'configMapKeyRef':None},{'fieldRef':{}},{'resourceFieldRef':{}},
    {'secretKeyRef':{'name':'selected-secret','key':'key','optional':'true'}},
])
def test_malformed_reference_metadata_never_proves_clean(monkeypatch,source_value):
    obj=native();obj['spec']['containers'][0]['env'].append({'name':'REF','valueFrom':source_value})
    snapshot,trace=capture(monkeypatch,documents={route(target()):obj})
    assert {r['status'] for r in findings(snapshot)}=={'UNKNOWN'} and not trace.scans


def test_reference_only_pod_has_no_clean_literal_assessment(monkeypatch):
    obj=native();container=obj['spec']['containers'][0]
    container.pop('command');container.pop('args')
    container['env']=[{'name':'REF','valueFrom':{'secretKeyRef':{'name':'selected-secret','key':'key'}}}]
    snapshot,trace=capture(monkeypatch,documents={route(target()):obj})
    assert {r['status'] for r in findings(snapshot)}=={'UNKNOWN'} and not trace.scans


def test_detected_value_scrubs_other_native_inventory_before_snapshot_and_cache(monkeypatch):
    sensitive='sensitive-canary'
    t=target('ConfigMap','selected-config')
    req=request([t],inventories=[source.KIND,'pod'])
    pod=native(target(name=sensitive))
    listing='/api/v1/namespaces/'+NS+'/pods'
    def detector(payload,path,timeout):return [(sensitive,'test-canary',1)] if sensitive.encode() in payload else []
    snapshot,trace=capture(monkeypatch,targets=[t],req=req,documents={route(t):native(t,sensitive)},scanner=detector,
        extra_documents={listing:{'apiVersion':'v1','kind':'PodList','metadata':{'resourceVersion':'208'},'items':[pod]}})
    assert {r['status'] for r in findings(snapshot)}=={'FAIL'}
    assert len(trace.calls)==3 and trace.calls[-1][2]==listing
    assert sensitive not in json.dumps([snapshot,findings(snapshot)])
    assert getattr(trace.api.api_client,'last_response',None) is None
    assert all(r.closed and r.released for r in trace.responses)
