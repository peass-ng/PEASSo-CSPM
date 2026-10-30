"""Current native metadata LIST -> exact GET -> production collector/public engine.

Original proposal test source and139-case receipts are retained. Kind/planner/producer/registration/evaluator are the actual production paths;
there are no test-local integration hooks.
"""
from copy import deepcopy
import gzip
import io
import json
import os
from pathlib import Path
import socket
import sys
from urllib.parse import urlsplit

import pytest
import urllib3
import yaml
from kubernetes import client, config

from peaso import engine
import peaso.checks as registry
from peaso.collectors import k8s
from peaso.collectors import k8s_annotation_indicators_20261020 as authentication
from peaso.collectors import k8s_kubelet_configmap_indicators_20261020 as producer
from peaso.checks import k8s_kubelet_configmap_review_20261020 as candidate

CANARY='KUBELET-RAW-CONTENT-MUST-NOT-LEAVE-PROJECTION'
AUTH='inert-no-live-authentication'
RECEIPTS=[]
BASE={'apiVersion':'kubelet.config.k8s.io/v1beta1','kind':'KubeletConfiguration',
      'authorization':{'mode':'Webhook'},'authentication':{'anonymous':{'enabled':False},'x509':{'clientCAFile':'/fixture/'+CANARY}},
      'readOnlyPort':0,'rotateCertificates':True,'tlsCipherSuites':['TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256'],
      'tlsCertFile':'/fixture/'+CANARY,'tlsPrivateKeyFile':'/fixture/'+CANARY,'eventRecordQPS':50,
      'streamingConnectionIdleTimeout':'0s','unrelatedPrivateValue':CANARY}
PATHS={'authorization_mode':('authorization','mode'),'client_ca_configured':('authentication','x509','clientCAFile'),
       'anonymous_disabled':('authentication','anonymous','enabled'),'readonly_disabled':('readOnlyPort',),
       'client_rotation':('rotateCertificates',),'cipher_allowlist':('tlsCipherSuites',),
       'tls_files_configured':('tlsCertFile',),'event_qps_bounded':('eventRecordQPS',)}
BAD={'authorization_mode':'AlwaysAllow','client_ca_configured':'','anonymous_disabled':True,'readonly_disabled':10255,
     'client_rotation':False,'cipher_allowlist':['TLS_RSA_WITH_3DES_EDE_CBC_SHA'],'tls_files_configured':'','event_qps_bounded':0}


@pytest.fixture(autouse=True)
def offline(monkeypatch, request):
    def blocked(*a,**k):pytest.fail('socket/DNS/live authentication forbidden')
    for n in ('connect','connect_ex'):monkeypatch.setattr(socket.socket,n,blocked)
    for n in ('getaddrinfo','gethostbyname','gethostbyname_ex','create_connection'):monkeypatch.setattr(socket,n,blocked)
    for n in ('load_kube_config','load_incluster_config','new_client_from_config'):monkeypatch.setattr(config,n,blocked)
    # The source admission attests the live collector callable. Keep that
    # callable intact in its offline, fixture-only contract test.
    if request.node.name != 'test_admitted_native_successors_preserve_archived_contracts_and_proposals':
        monkeypatch.setattr(k8s,'_new_api',blocked)


@pytest.fixture(scope='session',autouse=True)
def save_receipts():
    yield
    directory=os.getenv('KUBELET_CM_RECEIPTS')
    if directory:
        p=Path(directory);p.mkdir(parents=True,exist_ok=True)
        (p/'receipts.json').write_text(json.dumps(RECEIPTS,separators=(',',':'))+'\n')


def native(config_value=None):
    return {'apiVersion':'v1','kind':'ConfigMap','metadata':{'namespace':'kube-system','name':'kubelet-config-1.34',
        'uid':'5ad23d49-d104-44dc-93a2-17ce6137e8bd','resourceVersion':'412',
        'annotations':{'kubectl.kubernetes.io/last-applied-configuration':CANARY}},
        'data':{'kubelet':yaml.safe_dump(BASE if config_value is None else config_value),'unrelated':CANARY},
        'binaryData':{'never':'bmV2ZXItcmVhZA=='}}


class Pool:
    def __init__(self,document,mode='normal',metadata_mutation=None):
        self.document=document;self.mode=mode;self.metadata_mutation=metadata_mutation;self.calls=[]
    def request(self,method,url,**kwargs):
        u=urlsplit(url);fields=dict(kwargs.get('fields')or{});headers=kwargs.get('headers',{})
        assert method=='GET' and u.scheme=='https' and u.netloc=='kubelet-declaration.invalid' and not u.query and not u.fragment
        assert kwargs.get('body') is None and kwargs['redirect'] is False and kwargs['retries'] is False
        accept=next((v for k,v in headers.items()if k.lower()=='accept'),None)
        detail='/configmaps/' in u.path
        assert accept==('application/json'if detail else'application/json;as=PartialObjectMetadataList;g=meta.k8s.io;v=v1')
        allowed = ['/api/v1/namespaces/kube-system/configmaps','/api/v1/configmaps',
            '/api/v1/namespaces/kube-system/configmaps/kubelet-config-1.34']
        if self.mode=='target_budget':allowed += ['/api/v1/namespaces/kube-system/configmaps/kubelet-config-'+str(n) for n in range(producer.MAX_TARGETS+1)]
        assert u.path in allowed
        self.calls.append({'method':method,'host':u.netloc,'path':u.path,'query':fields,'accept':accept})
        status=200;content_type='application/json'
        if (self.mode=='denied' and detail or self.mode=='list_denied' and not detail
                or fields.get('continue')=='denied-next'):
            status=403;doc={'apiVersion':'v1','kind':'Status','reason':'Forbidden','code':403,'message':CANARY}
        elif detail:
            doc=deepcopy(self.document)
            if self.mode=='target_budget':
                n=u.path.rsplit('-',1)[-1];doc['metadata'].update(name='kubelet-config-'+n,uid='uid-'+n)
            if self.mode=='http_partial':status=206
            if self.mode=='partial_representation':content_type='application/json;as=PartialObjectMetadata;g=meta.k8s.io;v=v1'
            if self.mode=='json_duplicate':
                return urllib3.response.HTTPResponse(body=io.BytesIO(b'{"kind":"ConfigMap","kind":"ConfigMap"}'),status=200,headers={'Content-Type':content_type},preload_content=False)
            if self.mode=='body_budget':
                return urllib3.response.HTTPResponse(body=io.BytesIO(b' '*(producer.MAX_PAGE_BYTES+1)),status=200,headers={'Content-Type':content_type},preload_content=False)
        else:
            meta=deepcopy(self.document['metadata']);meta.pop('annotations',None)
            # Discovery is independent native metadata: detail tampering cannot
            # alter the request parent/UID/version proof.
            meta.update(namespace='kube-system',name='kubelet-config-1.34',uid='5ad23d49-d104-44dc-93a2-17ce6137e8bd',resourceVersion='412')
            if self.metadata_mutation:self.metadata_mutation(meta)
            items=[{'apiVersion':'meta.k8s.io/v1','kind':'PartialObjectMetadata','metadata':meta}]
            items.append({'apiVersion':'meta.k8s.io/v1','kind':'PartialObjectMetadata','metadata':{
                'namespace':'kube-system','name':'application-settings','uid':'different-uid','resourceVersion':'410'}})
            if self.mode=='duplicate':items.append(deepcopy(items[0]))
            if self.mode=='unrelated_only':items=items[1:]
            if self.mode=='empty':items=[]
            doc={'apiVersion':'meta.k8s.io/v1','kind':'PartialObjectMetadataList','metadata':{'resourceVersion':'430'},'items':items}
            if self.mode=='partial':doc['metadata']['continue']='denied-next'
            if self.mode=='wrong_list_type':doc['kind']='ConfigMapList'
            if self.mode=='list_contains_data':items[0]['data']={'kubelet':CANARY}
            if self.mode=='target_budget':
                doc['items']=[{'metadata':{**meta,'name':'kubelet-config-'+str(n),'uid':'uid-'+str(n)}}for n in range(producer.MAX_TARGETS+1)]
            if self.mode=='many_pages':
                doc['items']=[];doc['metadata']['continue']='page-'+str(len(self.calls))
            if self.mode=='repeated_pages':
                doc['items']=[];doc['metadata']['continue']='same'
            if self.mode=='changing_list_version':
                if fields.get('continue'):doc['metadata']['resourceVersion']='431';doc['items']=[]
                else:doc['metadata']['continue']='next'
            if self.mode=='list_http_partial':status=206
        return urllib3.response.HTTPResponse(body=io.BytesIO(json.dumps(doc).encode()),status=status,
            headers={'Content-Type':content_type},preload_content=False)


def execute(monkeypatch,cid,*,variant='positive',mode='normal',yaml_text=None,mutate=None,metadata_mutation=None,
            options=None,scope='kube-system',authenticated=True,change_snapshot=None):
    field=candidate.SPECS[cid[len(candidate.PREFIX_ID):]][0];cfg=deepcopy(BASE)
    keys=PATHS[field];parent=cfg
    for k in keys[:-1]:parent=parent[k]
    if variant=='opposite':parent[keys[-1]]=BAD[field]
    if variant=='missing':parent.pop(keys[-1])
    if variant=='malformed':parent[keys[-1]]={'unsupported':CANARY}
    document=native(cfg)
    if yaml_text is not None:document['data']['kubelet']=yaml_text
    if mutate:mutate(document)
    configuration=client.Configuration();configuration.host='https://kubelet-declaration.invalid'
    configuration.api_key={'authorization':AUTH}if authenticated else{}
    configuration.api_key_prefix={'authorization':'Bearer'}if authenticated else{}
    sdk=client.ApiClient(configuration);pool=Pool(document,mode,metadata_mutation);sdk.rest_client.pool_manager=pool
    api=k8s._wrap_client(sdk)
    connector={'provider':'k8s','auth':{'cluster_id':'native-cluster'},'scopes':[scope],
        'options':{'concurrency':1,'retries':0,**(options or{})}}
    requirements=engine.plan_collection({'connector':connector,'checks':[cid]},_runtime_connector=connector)
    assert requirements==[producer.KIND]
    snapshot=k8s.collect(connector,requirements,api=api)
    if change_snapshot:
        change_snapshot(snapshot);snapshot.pop('snapshot_id')
    report=engine.evaluate_snapshot(snapshot,checks=[cid])
    statuses=sorted({f['status']for f in report['findings']})
    assert CANARY not in json.dumps(snapshot) and CANARY not in json.dumps(report)
    assert AUTH not in json.dumps(snapshot) and AUTH not in json.dumps(report)
    assert getattr(sdk,'last_response',None) is None
    assert not any(c['path'].endswith('/application-settings')for c in pool.calls)
    entry={'id':cid,'variant':variant,'mode':mode,'statuses':statuses,'requests':pool.calls,
        'collections':[{'type':c['type'],'scope':c['scope'],'status':c['status'],'error':c.get('error')}for c in snapshot['collections']]}
    RECEIPTS.append(entry)
    directory=os.getenv('KUBELET_CM_RECEIPTS')
    if directory and variant in ('positive','opposite','missing') and mode=='normal' and not mutate and yaml_text is None and not change_snapshot and not metadata_mutation and authenticated and scope=='kube-system' and not options:
        path=Path(directory)/(cid.rsplit('.',1)[-1]+'-'+variant+'.json.gz');path.parent.mkdir(parents=True,exist_ok=True)
        with gzip.GzipFile(filename=str(path),mode='wb',mtime=0)as out:out.write(json.dumps({'snapshot':snapshot,'report':report,'capture_scope':'current_production_snapshot_and_report'},separators=(',',':')).encode())
        entry['capture']=str(path)
    return statuses,snapshot,pool


@pytest.mark.parametrize('cid',candidate.IDS)
@pytest.mark.parametrize('variant,status',[('positive','PASS'),('opposite','FAIL'),('missing','UNKNOWN'),('malformed','UNKNOWN')])
def test_native_each_criterion_positive_opposite_missing_malformed(monkeypatch,cid,variant,status,request):
    statuses,snapshot,pool=execute(monkeypatch,cid,variant=variant)
    RECEIPTS[-1]['node']=request.node.nodeid
    assert statuses==[status],RECEIPTS[-1]
    assert len(pool.calls)==2


@pytest.mark.parametrize('cid',candidate.IDS)
@pytest.mark.parametrize('mode,status',[('denied','DENIED'),('list_denied','DENIED'),('partial','UNKNOWN'),('empty','UNKNOWN'),('unrelated_only','UNKNOWN')])
def test_native_each_criterion_denied_partial_no_declaration(monkeypatch,cid,mode,status,request):
    statuses,_,pool=execute(monkeypatch,cid,mode=mode)
    RECEIPTS[-1]['node']=request.node.nodeid
    assert statuses==[status],RECEIPTS[-1]
    if mode in ('empty','unrelated_only','list_denied'):assert len(pool.calls)==1


@pytest.mark.parametrize('mode',['http_partial','list_http_partial','partial_representation','wrong_list_type',
    'list_contains_data','duplicate','json_duplicate','repeated_pages','changing_list_version','body_budget'])
def test_native_representation_pagination_and_duplicate_guards(monkeypatch,mode):
    assert execute(monkeypatch,candidate.IDS[0],mode=mode)[0]==['UNKNOWN']


@pytest.mark.parametrize('key,value',[('namespace','foreign'),('name','kubelet-config-other'),('uid','foreign-uid'),('resourceVersion','413')])
def test_native_detail_matches_discovered_parent_and_revision(monkeypatch,key,value):
    assert execute(monkeypatch,candidate.IDS[0],mutate=lambda d:d['metadata'].update({key:value}))[0]==['UNKNOWN']


@pytest.mark.parametrize('key,value',[('kind','Secret'),('apiVersion','v2')])
def test_native_wrong_detail_type(monkeypatch,key,value):
    assert execute(monkeypatch,candidate.IDS[0],mutate=lambda d:d.update({key:value}))[0]==['UNKNOWN']


@pytest.mark.parametrize('key,value',[('namespace','foreign'),('uid',''),('resourceVersion',''),('name','../kubelet-config')])
def test_native_metadata_scope_and_identity_guards_before_detail_read(monkeypatch,key,value):
    statuses,_,pool=execute(monkeypatch,candidate.IDS[0],metadata_mutation=lambda m:m.update({key:value}))
    assert statuses==['UNKNOWN'] and len(pool.calls)==1


@pytest.mark.parametrize('text',[
    'x: &a {x: 1}\ny: *a', '!!python/object/apply:os.system [echo unsafe]', '!!set {a: null}',
    'apiVersion: kubelet.config.k8s.io/v1beta1\nkind: KubeletConfiguration\nreadOnlyPort: 0\nreadOnlyPort: 10255',
    'kind: KubeletConfiguration\napiVersion: kubelet.config.k8s.io/v1beta1\nunknownDate: 2026-10-20',
    '[]','', '---\na: 1\n---\nb: 2', 'x: '+ '['*14+'0'+']'*14,
    'x: ['+','.join('a'for _ in range(2200))+']', 'x: '+('a'*65536),
    'apiVersion: kubelet.config.k8s.io/v1alpha1\nkind: KubeletConfiguration\nreadOnlyPort: 0',
])
def test_native_yaml_safety_unknown_without_raw_error_or_export(monkeypatch,text):
    assert execute(monkeypatch,candidate.IDS[0],yaml_text=text)[0]==['UNKNOWN']


@pytest.mark.parametrize('suffix,field,value',[
    ('anonymous_disabled','authentication',{'anonymous':{'enabled':'false'}}),
    ('readonly_disabled','readOnlyPort',False),('readonly_disabled','readOnlyPort',-1),('readonly_disabled','readOnlyPort',65536),
    ('client_certificate_rotation','rotateCertificates','true'),
    ('event_qps_bounded','eventRecordQPS',True),('event_qps_bounded','eventRecordQPS',1.5),
    ('event_qps_bounded','eventRecordQPS',2147483648),('event_qps_bounded','eventRecordQPS',-1),
    ('explicit_cipher_allowlist','tlsCipherSuites',[]),('explicit_cipher_allowlist','tlsCipherSuites','TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256'),
    ('explicit_cipher_allowlist','tlsCipherSuites',['TLS_AES_128_GCM_SHA256']),
    ('explicit_cipher_allowlist','tlsCipherSuites',['future-unknown-enum']),
    ('client_ca_configured','authentication',{'x509':{'clientCAFile':None}}),
])
def test_native_documented_field_types_and_unsupported_defaults(monkeypatch,suffix,field,value):
    cfg={**deepcopy(BASE),field:value}
    assert execute(monkeypatch,candidate.PREFIX_ID+suffix,yaml_text=yaml.safe_dump(cfg))[0]==['UNKNOWN']


def test_correct_event_qps_field_ignores_unrelated_streaming_setting(monkeypatch):
    cfg={**deepcopy(BASE),'streamingConnectionIdleTimeout':'0s','eventRecordQPS':5}
    assert execute(monkeypatch,candidate.PREFIX_ID+'event_qps_bounded',yaml_text=yaml.safe_dump(cfg))[0]==['PASS']
    cfg.update(streamingConnectionIdleTimeout='4h',eventRecordQPS=0)
    assert execute(monkeypatch,candidate.PREFIX_ID+'event_qps_bounded',yaml_text=yaml.safe_dump(cfg))[0]==['FAIL']


@pytest.mark.parametrize('scope',['kube-system','*'])
def test_exact_selected_namespace_and_existing_wildcard_scope(monkeypatch,scope):
    statuses,_,pool=execute(monkeypatch,candidate.IDS[0],scope=scope)
    assert statuses==['PASS']
    assert pool.calls[0]['path']==('/api/v1/configmaps'if scope=='*'else'/api/v1/namespaces/kube-system/configmaps')


@pytest.mark.parametrize('options',[{'max_calls':1},{'max_pages':1},{'max_resources':1}])
def test_existing_reader_budgets_preserve_actual_collection_coverage(monkeypatch,options):
    mode='partial' if 'max_pages'in options else'normal'
    statuses,_,_=execute(monkeypatch,candidate.IDS[0],options=options,mode=mode)
    # A max_resources of one covers the one matching ConfigMap, so it is valid.
    assert statuses==(['PASS']if 'max_resources'in options else['UNKNOWN'])


def test_no_authenticated_collection_binding_is_unknown(monkeypatch):
    assert execute(monkeypatch,candidate.IDS[0],authenticated=False)[0]==['UNKNOWN']


@pytest.mark.parametrize('mutation',['context','digest','source','provenance','namespace','schema','value_type'])
def test_exported_projection_cannot_rebind_identity_context_or_safe_types(monkeypatch,mutation):
    def change(s):
        item=s['collections'][0]['items'][0];marker=item[producer.MARKER]
        if mutation=='context':s['metadata'][authentication.CONTEXT]['session']='0'*32
        if mutation=='digest':marker['identity_digest']='0'*64
        if mutation=='source':marker['source']['path']='/api/v1/namespaces/foreign/configmaps/kubelet-config-1.34'
        if mutation=='provenance':item['provenance']['uid']='foreign'
        if mutation=='namespace':item['metadata']['namespace']='foreign'
        if mutation=='schema':marker['schema']='customer-supplied'
        if mutation=='value_type':marker['indicators']['authorization_mode']['value']={}
    assert execute(monkeypatch,candidate.IDS[0],change_snapshot=change)[0]==['UNKNOWN']




@pytest.mark.parametrize('cipher',['TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256','TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256'])
def test_native_documented_chacha_aliases(monkeypatch,cipher):
    cfg={**deepcopy(BASE),'tlsCipherSuites':[cipher]}
    assert execute(monkeypatch,candidate.PREFIX_ID+'explicit_cipher_allowlist',yaml_text=yaml.safe_dump(cfg))[0]==['PASS']


@pytest.mark.parametrize('mode,maximum',[('target_budget',producer.MAX_TARGETS+1),('many_pages',producer.MAX_PAGES)])
def test_native_finite_target_and_page_budgets(monkeypatch,mode,maximum):
    statuses,_,pool=execute(monkeypatch,candidate.IDS[0],mode=mode)
    assert statuses==['UNKNOWN'] and len(pool.calls)==maximum


@pytest.mark.parametrize('missing',['data','kubelet'])
def test_missing_whole_native_configuration_not_clean(monkeypatch,missing):
    def change(d):
        if missing=='data':d.pop('data')
        else:d['data'].pop('kubelet')
    assert execute(monkeypatch,candidate.IDS[0],mutate=change)[0]==['UNKNOWN']
