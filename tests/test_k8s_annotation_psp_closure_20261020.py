"""Native SDK HTTP -> actual collector/planner -> public engine successor proof.

The five pure candidates are test-installed in place of their exact old IDs;
production registration, signed CASES and source admissions remain root-owned.
"""
from copy import deepcopy
from dataclasses import replace
import gzip
from hashlib import sha256
import io
import json
import os
from pathlib import Path
import socket
from urllib.parse import urlsplit

import pytest
import urllib3
from kubernetes import client, config

import peaso.checks as registry
from peaso import engine
from peaso.collectors import k8s
from peaso.collectors import k8s_annotation_indicators_20261020 as source
from peaso.collectors import k8s_legacy_psp_planner_20261020 as legacy
from peaso.checks import k8s_annotation_indicators_review_20261020 as candidate

AUTH = 'synthetic-inert-credential-context'
CANARY = 'ANNOTATION-CONTENT-MUST-NEVER-APPEAR-IN-EXPORT'
RECEIPTS = []


@pytest.fixture(autouse=True)
def offline(monkeypatch):
    def blocked(*args, **kwargs):pytest.fail('live socket/DNS/auth is forbidden')
    for name in ('connect','connect_ex'):monkeypatch.setattr(socket.socket,name,blocked)
    for name in ('getaddrinfo','gethostbyname','gethostbyname_ex','create_connection'):monkeypatch.setattr(socket,name,blocked)
    for name in ('load_kube_config','load_incluster_config','new_client_from_config'):monkeypatch.setattr(config,name,blocked)
    monkeypatch.setattr(k8s,'_new_api',blocked)


@pytest.fixture(scope='session',autouse=True)
def save_receipts():
    yield
    directory=os.getenv('K8S_ANNOTATION_RECEIPTS')
    if directory:
        p=Path(directory);p.mkdir(parents=True,exist_ok=True)
        (p/'receipts.json').write_text(json.dumps(RECEIPTS,separators=(',',':'))+'\n')


def native(kind='ingress',annotations=None):
    version,typ=source.TYPES[kind]
    return {'apiVersion':version,'kind':typ,'metadata':{'name':'owned-policy' if kind=='podsecuritypolicy' else 'owned-ingress',
        **({'namespace':'apps'}if kind=='ingress' else {}),'uid':'4b27b87e-3d46-4fbe-bbcb-5745ca8e08c3','resourceVersion':'270',
        'annotations':{} if annotations is None else deepcopy(annotations)},
        'spec':{'seLinux':{'rule':'RunAsAny'},'runAsUser':{'rule':'MustRunAsNonRoot'},'supplementalGroups':{'rule':'RunAsAny'},'fsGroup':{'rule':'RunAsAny'}} if kind=='podsecuritypolicy' else
        {'rules':[{'host':'example.test','http':{'paths':[{'path':'/','pathType':'Prefix','backend':{'service':{'name':'web','port':{'number':8080}}}}]}}]}}


def annotations_for(cid,positive):
    if cid==candidate.INGRESS_IDS[0]:return {} if positive else {'custom.example.test/server-snippet':CANARY+' # snippet'}
    if cid==candidate.INGRESS_IDS[1]:return {'custom.example.test/server-snippet':'location / { root /srv; } '+CANARY} if positive else {'custom.example.test/server-snippet':'alias /srv; '+CANARY}
    if cid==candidate.INGRESS_IDS[2]:return {'custom.example.test/server-snippet':'proxy_pass http://upstream; '+CANARY} if positive else {'custom.example.test/server-snippet':'content_by_lua_block {} '+CANARY}
    key='seccomp.security.alpha.kubernetes.io/defaultProfileName' if cid==candidate.PSP_IDS[0] else 'apparmor.security.beta.kubernetes.io/defaultProfileName'
    return {key:'runtime/default' if positive else 'unconfined', 'other.example.test/note':CANARY}


GVK={'namespace':('v1','Namespace'),'role':('rbac.authorization.k8s.io/v1','Role'),'clusterrole':('rbac.authorization.k8s.io/v1','ClusterRole'),
    'rolebinding':('rbac.authorization.k8s.io/v1','RoleBinding'),'clusterrolebinding':('rbac.authorization.k8s.io/v1','ClusterRoleBinding'),**source.TYPES}


def support(kind,scope='apps',grant=True):
    version,typ=GVK[kind]
    row={'apiVersion':version,'kind':typ,'metadata':{'name':scope if kind=='namespace' else 'deployer','uid':'native-'+kind+'-'+scope,'resourceVersion':'270'}}
    if kind in ('role','rolebinding'):row['metadata']['namespace']=scope
    if kind in ('role','clusterrole'):
        row['rules']=[{'apiGroups':[''],'resources':['pods'],'verbs':['create']}]
        if grant:row['rules'].append({'apiGroups':['policy'],'resources':['podsecuritypolicies'],'verbs':['use'],'resourceNames':['owned-policy']})
    if kind in ('rolebinding','clusterrolebinding'):
        row.update(roleRef={'apiGroup':'rbac.authorization.k8s.io','kind':'Role'if kind=='rolebinding'else'ClusterRole','name':'deployer'},
            subjects=[{'kind':'ServiceAccount','name':'deployer','namespace':scope}])
    return row


class Pool:
    def __init__(self,document,*,modern=False,mode='normal',fault=None,grant=True,scopes=('apps',),cluster_creator=False):
        self.doc,self.modern,self.mode,self.fault,self.grant,self.scopes=document,modern,mode,fault,grant,scopes
        self.calls=[]
        self.cluster_creator=cluster_creator
    def request(self,method,url,**kwargs):
        u=urlsplit(url);fields=dict(kwargs.get('fields')or{})
        assert method=='GET' and u.scheme=='https' and u.netloc=='native-k8s-closure.invalid' and not u.query and not u.fragment
        assert kwargs.get('body') is None and kwargs['redirect'] is False and kwargs['retries'] is False
        assert kwargs.get('headers',{}).get('authorization') in (None,'Bearer '+AUTH)
        path=u.path;self.calls.append({'method':method,'host':u.netloc,'path':path,'query':fields})
        kind=None
        if path.endswith('ingresses'):kind='ingress'
        elif path.endswith('podsecuritypolicies'):kind='podsecuritypolicy'
        else:
            for k,(endpoint,_)in k8s.ENDPOINTS.items():
                if path==endpoint or path.endswith('/'+endpoint.rsplit('/',1)[-1]):kind=k;break
        if path.startswith('/api/v1/namespaces/') and len(path.split('/'))==5:kind='namespace'
        denied=(self.mode=='denied' and kind in source.TYPES) or fields.get('continue')=='next' or (self.fault is not None and self.fault==kind)
        if self.mode=='discovery_denied' and path in ('/apis','/version'):denied=True
        if denied:
            doc={'apiVersion':'v1','kind':'Status','status':'Failure','reason':'Forbidden','code':403};status=403
        elif path=='/apis':
            groups=[] if self.modern else [{'name':'policy','versions':[{'groupVersion':'policy/v1beta1','version':'v1beta1'}]}]
            doc={'apiVersion':'v1','kind':'APIGroupList','groups':groups};status=200
        elif path=='/version':
            doc={'gitVersion':'v1.32.1'if self.modern else 'v1.24.17'};status=200
            if self.mode=='malformed_version':doc={'gitVersion':'not-a-version'}
            if self.mode=='malformed_prefixed_version':doc={'gitVersion':'v1.24.not-a-patch'}
        elif path=='/apis/policy/v1beta1':
            doc={'apiVersion':'v1','kind':'APIResourceList','groupVersion':'policy/v1beta1','resources':[{'name':'podsecuritypolicies','kind':'PodSecurityPolicy','namespaced':False,'verbs':['get','list']}]};status=200
        else:
            assert kind in GVK,(path,kind)
            namespace=path.split('/namespaces/')[1].split('/')[0] if '/namespaces/' in path else self.scopes[0]
            if kind in source.TYPES:items=[deepcopy(self.doc)]
            elif kind in ('clusterrole','clusterrolebinding'):items=[support(kind,self.scopes[0],self.grant)] if self.cluster_creator else []
            else:items=[support(kind,namespace,self.grant)]
            if self.mode=='empty' and kind in source.TYPES:items=[]
            if self.mode=='duplicate' and kind in source.TYPES:items*=2
            version,typ=GVK[kind]
            doc=items[0] if kind=='namespace' and '/namespaces/' in path else {'apiVersion':version,'kind':typ+'List','metadata':{'resourceVersion':'270'},'items':items}
            if self.mode=='partial' and kind in source.TYPES:doc['metadata']['continue']='next'
            if self.mode=='bounded_pages' and kind in source.TYPES:
                number=len([r for r in self.calls if r['path']==path])
                for row in doc['items']:row['metadata'].update(name='owned-'+str(number),uid='uid-'+str(number))
                doc['metadata']['continue']='page-'+str(number)
            status=200
        if self.mode=='http_partial' and kind in source.TYPES:status=206
        return urllib3.response.HTTPResponse(body=io.BytesIO(json.dumps(doc).encode()),status=status,
            headers={'Content-Type':'application/json;as=PartialObjectMetadataList;g=meta.k8s.io;v=v1'if self.mode=='partial_representation'and kind in source.TYPES else'application/json'},preload_content=False)


def execute(monkeypatch,cid,*,positive=True,mode='normal',mutate=None,change_snapshot=None,modern=False,
            options=None,authenticated=True,fault=None,grant=True,scopes=('apps',),install=True,cluster_creator=False):
    kind='ingress'if cid in candidate.INGRESS_IDS else 'podsecuritypolicy'
    doc=native(kind,annotations_for(cid,positive)if cid in candidate.IDS else {})
    if mutate:mutate(doc)
    arguments=[]
    if install and cid in candidate.IDS:
        def evaluate_candidate(item,index):
            arguments.append({'item':deepcopy(item),'index':deepcopy(dict(index))})
            return candidate.evaluate(cid,item,index)
        monkeypatch.setattr(registry,'CHECKS',[replace(c,evaluate=evaluate_candidate)if c.id==cid else c for c in registry.CHECKS])
    configuration=client.Configuration();configuration.host='https://native-k8s-closure.invalid'
    configuration.api_key={'authorization':AUTH}if authenticated else {};configuration.api_key_prefix={'authorization':'Bearer'}if authenticated else {}
    sdk=client.ApiClient(configuration);pool=Pool(doc,modern=modern,mode=mode,fault=fault,grant=grant,scopes=scopes,cluster_creator=cluster_creator);sdk.rest_client.pool_manager=pool
    api=k8s._wrap_client(sdk)
    connector={'provider':'k8s','auth':{'cluster_id':'bound-cluster'},'scopes':list(scopes),
        'options':{'concurrency':1,'retries':0,**(options or {})}}
    requirements=engine.plan_collection({'connector':connector,'checks':[cid]},_runtime_connector=connector)
    snapshot=k8s.collect(connector,requirements,api=api)
    if change_snapshot:
        change_snapshot(snapshot)
        snapshot.pop('snapshot_id')  # New valid container; exercise inner binding guards.
    report=engine.evaluate_snapshot(snapshot,checks=[cid]);statuses=sorted({f['status']for f in report['findings']})
    entry={'id':cid,'positive':positive,'mode':mode,'statuses':statuses,'requests':pool.calls,'requirements':requirements,
        'collections':[{'type':c['type'],'scope':c['scope'],'status':c['status'],'error':c.get('error')}for c in snapshot['collections']],
        'evidence':[f['evidence']for f in report['findings']]}
    directory=os.getenv('K8S_ANNOTATION_RECEIPTS')
    if directory and mode=='normal' and change_snapshot is None:
        p=Path(directory)/(sha256(json.dumps([cid,positive,modern,grant,list(scopes),len(RECEIPTS)]).encode()).hexdigest()[:20]+'.json.gz');p.parent.mkdir(parents=True,exist_ok=True)
        with gzip.GzipFile(filename=str(p),mode='wb',mtime=0)as f:f.write(json.dumps({'snapshot':snapshot,'report':report,'evaluator_arguments':arguments},separators=(',',':')).encode())
        entry['capture']=str(p);entry['capture_sha256']=sha256(p.read_bytes()).hexdigest()
    RECEIPTS.append(entry)
    assert CANARY not in json.dumps(snapshot) and AUTH not in json.dumps(snapshot)
    assert CANARY not in json.dumps(report) and AUTH not in json.dumps(report)
    return statuses,snapshot,pool,sdk


@pytest.mark.parametrize('cid',candidate.IDS)
@pytest.mark.parametrize('positive',[True,False])
def test_native_positive_opposite_redacted(monkeypatch,cid,positive,request):
    statuses,snapshot,pool,sdk=execute(monkeypatch,cid,positive=positive)
    RECEIPTS[-1]['node']=request.node.nodeid
    assert statuses==['PASS'if positive else'FAIL'],RECEIPTS[-1]
    assert pool.calls and sdk.last_response is None


@pytest.mark.parametrize('cid',candidate.IDS)
@pytest.mark.parametrize('mode',['denied','partial','duplicate','http_partial','partial_representation'])
def test_incomplete_native_never_clean(monkeypatch,cid,mode,request):
    statuses,_,_,_=execute(monkeypatch,cid,mode=mode)
    RECEIPTS[-1]['node']=request.node.nodeid
    assert 'PASS'not in statuses and 'FAIL'not in statuses,RECEIPTS[-1]


@pytest.mark.parametrize('cid',candidate.IDS)
@pytest.mark.parametrize('field',['uid','resourceVersion','name','annotations','wrong_type','wrong_namespace','oversize','too_many','customer_marker'])
def test_native_missing_malformed_identity_budget(monkeypatch,cid,field,request):
    def mutate(doc):
        if field in ('uid','resourceVersion','name'):doc['metadata'].pop(field)
        elif field=='annotations':doc['metadata']['annotations']=CANARY
        elif field=='wrong_type':doc.update(kind='Secret',apiVersion='v1')
        elif field=='wrong_namespace':doc['metadata']['namespace']='foreign'
        elif field=='oversize':doc['metadata']['annotations']={'custom/snippet':CANARY+'x'*source.MAX_ANNOTATION_BYTES}
        elif field=='too_many':doc['metadata']['annotations']={str(i):'x'for i in range(source.MAX_ANNOTATIONS+1)}
        else:doc[source.MARKER]={'status':'bound','flags':dict.fromkeys(source.FLAGS,False)}
    statuses,_,_,_=execute(monkeypatch,cid,mutate=mutate)
    RECEIPTS[-1]['node']=request.node.nodeid
    assert 'PASS'not in statuses and 'FAIL'not in statuses,RECEIPTS[-1]


@pytest.mark.parametrize('cid',candidate.IDS)
@pytest.mark.parametrize('field',['uid','resourceVersion','namespace','name','context','scope','path','flags','old_attestation','provenance_namespace','provenance_version'])
def test_exported_binding_tamper_unknown(monkeypatch,cid,field,request):
    kind='ingress'if cid in candidate.INGRESS_IDS else'podsecuritypolicy'
    def change(snapshot):
        own=next(c for c in snapshot['collections']if c['type']==kind);row=own['items'][0]
        if field in ('uid','resourceVersion','namespace','name'):row['metadata'][field]='changed'
        elif field=='context':snapshot['metadata'][source.CONTEXT]['session']='0'*32
        elif field=='scope':row[source.MARKER]['source']['scope']='foreign'
        elif field=='path':row[source.MARKER]['source']['path']='/api/v1/secrets'
        elif field=='flags':row[source.MARKER]['flags']['alias']='false'
        elif field=='provenance_namespace':row['provenance']['namespace']='foreign'
        elif field=='provenance_version':row['provenance']['apiVersion']='foreign/v1'
        else:row.pop(source.MARKER);row['provenance']['annotations_complete']=True
    statuses,_,_,_=execute(monkeypatch,cid,change_snapshot=change)
    RECEIPTS[-1]['node']=request.node.nodeid
    assert statuses==['UNKNOWN'],RECEIPTS[-1]


@pytest.mark.parametrize('cid',candidate.IDS)
def test_unconfigured_auth_context_unknown(monkeypatch,cid,request):
    statuses,_,_,_=execute(monkeypatch,cid,authenticated=False)
    RECEIPTS[-1]['node']=request.node.nodeid
    assert statuses==['UNKNOWN'],RECEIPTS[-1]


@pytest.mark.parametrize('cid',candidate.PSP_IDS)
def test_modern_psp_no_legacy_calls(monkeypatch,cid,request):
    statuses,_,pool,_=execute(monkeypatch,cid,modern=True)
    RECEIPTS[-1]['node']=request.node.nodeid
    assert statuses==['NOT_APPLICABLE'],RECEIPTS[-1]
    assert [c['path']for c in pool.calls]==['/apis','/version']


@pytest.mark.parametrize('grant',[True,False])
@pytest.mark.parametrize('scopes',[('apps',),('apps','team-b')])
def test_conditional_legacy_default_plan_decisive(monkeypatch,grant,scopes,request):
    statuses,snapshot,pool,_=execute(monkeypatch,legacy.CHECK,grant=grant,scopes=scopes)
    RECEIPTS[-1]['node']=request.node.nodeid
    assert statuses==['PASS'if grant else'FAIL'],RECEIPTS[-1]
    assert RECEIPTS[-1]['requirements']==['api_discovery']
    assert legacy.SUPPORT <= {c['type']for c in snapshot['collections']}
    assert sum(c['path']=='/apis/policy/v1beta1/podsecuritypolicies'for c in pool.calls)==1


def test_modern_binding_no_legacy_support(monkeypatch,request):
    statuses,snapshot,pool,_=execute(monkeypatch,legacy.CHECK,modern=True)
    RECEIPTS[-1]['node']=request.node.nodeid
    assert statuses==['NOT_APPLICABLE'],RECEIPTS[-1]
    assert [c['path']for c in pool.calls]==['/apis','/version']


@pytest.mark.parametrize('fault',sorted(legacy.SUPPORT))
def test_legacy_support_denial_unresolved(monkeypatch,fault,request):
    statuses,_,_,_=execute(monkeypatch,legacy.CHECK,fault=fault,cluster_creator=True)
    RECEIPTS[-1]['node']=request.node.nodeid
    assert statuses==['UNKNOWN'],RECEIPTS[-1]


@pytest.mark.parametrize('mode',['discovery_denied','malformed_version','malformed_prefixed_version'])
def test_unverified_version_does_not_add_support(monkeypatch,mode,request):
    statuses,_,pool,_=execute(monkeypatch,legacy.CHECK,mode=mode)
    RECEIPTS[-1]['node']=request.node.nodeid
    assert 'PASS'not in statuses
    assert not any(c['path'].endswith(('/roles','/clusterroles','/rolebindings','/clusterrolebindings','/podsecuritypolicies'))for c in pool.calls)


@pytest.mark.parametrize('cid',candidate.IDS+(legacy.CHECK,))
@pytest.mark.parametrize('options',[{'max_calls':1},{'max_pages':1},{'max_resources':1}])
def test_existing_collection_budgets_preserved(monkeypatch,cid,options,request):
    statuses,_,pool,_=execute(monkeypatch,cid,options=options,mode='partial')
    RECEIPTS[-1]['node']=request.node.nodeid
    if options=={'max_calls':1}:assert len(pool.calls)<=1
    assert 'PASS'not in statuses,RECEIPTS[-1]


@pytest.mark.parametrize('cid,value,wanted',[
    (candidate.INGRESS_IDS[1],'aliased harmless substring','FAIL'),
    (candidate.INGRESS_IDS[1],'ALIAS uppercase','PASS'),
    (candidate.INGRESS_IDS[1],'root /srv;','PASS'),
    (candidate.INGRESS_IDS[2],'https://kubernetes.io/docs','FAIL'),
    (candidate.INGRESS_IDS[2],'set_by_lua value;','FAIL'),
    (candidate.INGRESS_IDS[2],'LUA_UPPERCASE','PASS')])
def test_exact_historical_case_sensitive_pattern_criterion(monkeypatch,cid,value,wanted,request):
    def mutate(doc):doc['metadata']['annotations']={'custom/not-nginx-snippet':value+' '+CANARY}
    statuses,_,_,_=execute(monkeypatch,cid,mutate=mutate)
    RECEIPTS[-1]['node']=request.node.nodeid
    assert statuses==[wanted],RECEIPTS[-1]


@pytest.mark.parametrize('cid',candidate.IDS)
def test_native_omitted_typemeta_is_endpoint_bound(monkeypatch,cid,request):
    def mutate(doc):doc.pop('kind');doc.pop('apiVersion')
    statuses,_,_,_=execute(monkeypatch,cid,mutate=mutate)
    RECEIPTS[-1]['node']=request.node.nodeid
    assert statuses==['PASS'],RECEIPTS[-1]


@pytest.mark.parametrize('profile',['docker/default','runtime/default'])
def test_legacy_seccomp_recognized_profiles(monkeypatch,profile,request):
    def mutate(doc):doc['metadata']['annotations']={'seccomp.security.alpha.kubernetes.io/defaultProfileName':profile}
    statuses,_,_,_=execute(monkeypatch,candidate.PSP_IDS[0],mutate=mutate)
    RECEIPTS[-1]['node']=request.node.nodeid
    assert statuses==['PASS'],RECEIPTS[-1]


def test_legacy_selinux_positive_independent_of_default_profile(monkeypatch,request):
    def mutate(doc):doc['spec']['seLinux']={'rule':'MustRunAs'};doc['metadata']['annotations']={}
    statuses,_,_,_=execute(monkeypatch,candidate.PSP_IDS[1],mutate=mutate)
    RECEIPTS[-1]['node']=request.node.nodeid
    assert statuses==['PASS'],RECEIPTS[-1]


@pytest.mark.parametrize('modern',[True,False])
@pytest.mark.parametrize('grant',[True,False])
def test_public_collect_snapshot_runtime_handoff(monkeypatch,modern,grant,request):
    configuration=client.Configuration();configuration.host='https://native-k8s-closure.invalid'
    configuration.api_key={'authorization':AUTH};configuration.api_key_prefix={'authorization':'Bearer'}
    sdk=client.ApiClient(configuration);pool=Pool(native('podsecuritypolicy'),modern=modern,grant=grant);sdk.rest_client.pool_manager=pool
    monkeypatch.setattr(k8s,'_new_api',lambda auth:k8s._wrap_client(sdk))
    req={'connector':{'provider':'k8s','auth':{'cluster_id':'bound-cluster'},'scopes':['apps'],
        'options':{'concurrency':1,'retries':0}},'checks':[legacy.CHECK]}
    original=deepcopy(req)
    snapshot=engine.collect_snapshot(req)
    result=engine.evaluate_snapshot(snapshot,checks=[legacy.CHECK]);statuses=sorted({x['status']for x in result['findings']})
    RECEIPTS.append({'id':legacy.CHECK,'node':request.node.nodeid,'public_collect_snapshot':True,'modern':modern,'grant':grant,'statuses':statuses,'requests':pool.calls})
    assert statuses==['NOT_APPLICABLE'if modern else'PASS'if grant else'FAIL'],RECEIPTS[-1]
    assert req==original and legacy.OPTION not in json.dumps(snapshot)
    if modern:assert [r['path']for r in pool.calls]==['/apis','/version']
    else:assert legacy.SUPPORT <= {c['type']for c in snapshot['collections']}


@pytest.mark.parametrize('cid',candidate.IDS)
def test_bounded_wire_page_never_proves_clean(monkeypatch,cid,request):
    monkeypatch.setattr(source,'MAX_PAGE_BYTES',64)
    statuses,_,_,_=execute(monkeypatch,cid)
    RECEIPTS[-1]['node']=request.node.nodeid
    assert 'PASS'not in statuses and 'FAIL'not in statuses


def test_fixed_native_page_budget_no_extra_request(monkeypatch,request):
    statuses,_,pool,_=execute(monkeypatch,candidate.INGRESS_IDS[0],mode='bounded_pages')
    RECEIPTS[-1]['node']=request.node.nodeid
    assert len(pool.calls)==source.MAX_NATIVE_PAGES and statuses==['UNKNOWN'],RECEIPTS[-1]


@pytest.mark.parametrize('cid',candidate.PSP_IDS)
def test_conflicting_legacy_discovery_unknown(monkeypatch,cid,request):
    def change(snapshot):
        discovery=next(c for c in snapshot['collections']if c['type']=='api_discovery')
        discovery['items'][0]['podSecurityPolicyAdvertised']=False
    statuses,_,_,_=execute(monkeypatch,cid,change_snapshot=change)
    RECEIPTS[-1]['node']=request.node.nodeid
    assert statuses==['UNKNOWN'],RECEIPTS[-1]


@pytest.mark.parametrize('cid',candidate.PSP_IDS)
def test_operator_annotations_complete_is_not_native_proof(monkeypatch,cid,request):
    doc=native('podsecuritypolicy',annotations_for(cid,True))
    doc['_provenance']={'kubernetes_version':'v1.24.17'};doc['provenance']={'annotations_complete':True}
    statuses,_,pool,_=execute(monkeypatch,cid,options={'metadata_evidence':{'podsecuritypolicy':[doc]}})
    RECEIPTS[-1]['node']=request.node.nodeid
    assert statuses==['UNKNOWN']and not pool.calls,RECEIPTS[-1]


def test_unknown_selinux_strategy_is_unresolved(monkeypatch,request):
    def mutate(doc):doc['spec']['seLinux']['rule']='UnrecognizedFutureRule'
    statuses,_,_,_=execute(monkeypatch,candidate.PSP_IDS[1],mutate=mutate)
    RECEIPTS[-1]['node']=request.node.nodeid
    assert statuses==['UNKNOWN'],RECEIPTS[-1]
