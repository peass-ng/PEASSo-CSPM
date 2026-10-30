"""Independent Kubernetes HTTP -> official SDK -> collector -> public engine review.

Native inputs are built from API field contracts, never historical CASES. Tests
make no host requests, execute no commands and never read Secret contents.
"""
from copy import deepcopy
from hashlib import sha256
import inspect
import json
import os
from pathlib import Path
import socket
import sys
from urllib.parse import urlsplit

import pytest
import urllib3
from kubernetes import client, config

from peaso.checks import CHECKS
from peaso.collectors import k8s
from peaso.engine import evaluate_snapshot

QUEUE = json.loads((Path(__file__).resolve().parents[1] / 'docs/check-review/k8s-review-queue-20261020.json').read_text())
BATCHES = {b['name']: b['ids'] for b in QUEUE['batches'] if b['name'] in ('workloads_1', 'workloads_2', 'workloads_3')}
IDS = tuple(cid for rows in BATCHES.values() for cid in rows)
REGISTRY = {c.id: c for c in CHECKS if c.id in IDS}
CLOSED = {cid: inspect.getclosurevars(inspect.unwrap(c.evaluate)).nonlocals for cid, c in REGISTRY.items()}
KINDS = {'pod': ('v1', 'Pod', 'spec'), 'podtemplate': ('v1', 'PodTemplate', 'template.spec'),
         'replicationcontroller': ('v1', 'ReplicationController', 'spec.template.spec'),
         **{k: ('apps/v1', v, 'spec.template.spec') for k, v in [('deployment', 'Deployment'), ('daemonset', 'DaemonSet'), ('statefulset', 'StatefulSet'), ('replicaset', 'ReplicaSet')]},
         'job': ('batch/v1', 'Job', 'spec.template.spec'), 'cronjob': ('batch/v1', 'CronJob', 'spec.jobTemplate.spec.template.spec')}
POD_FIELDS = {'host_namespaces', 'host_network', 'pod_runtime_default_seccomp', 'explicit_serviceaccount'}
RESOURCE = {'cpu_limit', 'cpu_request', 'memory_limit', 'memory_request'}
PROBES = {'readiness_probe', 'liveness_probe'}
OMITTED = {'always_pull':'UNKNOWN','content_digest_or_always_pull':'UNKNOWN','pinned_image':'UNKNOWN',
 'container_runtime_default_seccomp':'FAIL','pod_runtime_default_seccomp':'FAIL','context_present':'FAIL',
 'cpu_limit':'FAIL','cpu_request':'FAIL','memory_limit':'FAIL','memory_request':'FAIL','declared_nonroot':'FAIL',
 'drop_all':'FAIL','drop_net_raw':'FAIL','explicit_serviceaccount':'FAIL','host_namespaces':'PASS','host_network':'PASS',
 'liveness_probe':'FAIL','readiness_probe':'FAIL','no_added_capabilities':'PASS','no_host_ports':'PASS',
 'no_sys_admin':'PASS','privilege_escalation':'FAIL','privileged':'PASS','readonly_root':'FAIL'}
CASES = []


@pytest.fixture(autouse=True)
def hard_network_auth_guard(monkeypatch):
    def blocked(*args, **kwargs):
        pytest.fail('live socket/DNS/auth was attempted')
    for name in ('connect', 'connect_ex'):
        monkeypatch.setattr(socket.socket, name, blocked)
    for name in ('getaddrinfo', 'gethostbyname', 'gethostbyname_ex', 'create_connection'):
        monkeypatch.setattr(socket, name, blocked)
    for name in ('load_kube_config', 'load_incluster_config', 'new_client_from_config'):
        monkeypatch.setattr(config, name, blocked)
    monkeypatch.setattr(k8s, '_new_api', blocked)


@pytest.fixture(scope='session', autouse=True)
def write_receipts():
    yield
    destination = os.environ.get('K8S_WORKLOAD_REVIEW_RECEIPTS')
    if destination:
        root = Path(destination); root.mkdir(parents=True, exist_ok=True)
        (root / 'native-cases.json').write_text(json.dumps(CASES, separators=(',', ':')) + '\n')


def configured(predicate, good=True):
    """Independent explicit field configurations; no production fixture import."""
    c = {'name':'application', 'image':'registry.example.test/team/web:2.1', 'imagePullPolicy':'Always'}
    s = {'containers':[c], 'restartPolicy':'Always', 'os':{'name':'linux'}}
    context = {'privileged':False,'allowPrivilegeEscalation':False,'readOnlyRootFilesystem':True,'runAsNonRoot':True}
    if predicate in ('privileged','privilege_escalation','readonly_root','declared_nonroot'):
        key = {'privileged':'privileged','privilege_escalation':'allowPrivilegeEscalation','readonly_root':'readOnlyRootFilesystem','declared_nonroot':'runAsNonRoot'}[predicate]
        c['securityContext'] = {key:context[key] if good else not context[key]}
    elif predicate == 'context_present':
        if good:c['securityContext'] = {'runAsUser':10001}
    elif predicate in ('container_runtime_default_seccomp','pod_runtime_default_seccomp'):
        (s if predicate.startswith('pod_') else c)['securityContext'] = {'seccompProfile':{'type':'RuntimeDefault' if good else 'Unconfined'}}
    elif predicate in ('drop_all','drop_net_raw','no_added_capabilities','no_sys_admin'):
        caps = {'drop':['ALL' if predicate == 'drop_all' else 'NET_RAW']} if predicate in ('drop_all','drop_net_raw') else {'add':[]}
        if not good:caps = {'drop':[]} if predicate in ('drop_all','drop_net_raw') else {'add':['NET_ADMIN' if predicate == 'no_added_capabilities' else 'SYS_ADMIN']}
        c['securityContext'] = {'capabilities':caps}
    elif predicate in RESOURCE:
        group='limits' if predicate.endswith('limit') else 'requests';field='cpu' if predicate.startswith('cpu') else 'memory'
        if good:c['resources']={group:{field:'250m' if field=='cpu' else '96Mi'}}
    elif predicate in PROBES:
        if good:c['readinessProbe' if predicate=='readiness_probe' else 'livenessProbe']={'httpGet':{'path':'/healthz','port':8080},'periodSeconds':7}
    elif predicate == 'no_host_ports':
        c['ports']=[{'name':'http','containerPort':8080,**({}if good else {'hostPort':8443})}]
    elif predicate == 'pinned_image':
        c['image']='registry.example.test/team/web:2.1' if good else 'registry.example.test/team/web:latest'
    elif predicate in ('always_pull','content_digest_or_always_pull'):
        c['imagePullPolicy']='Always' if good else 'IfNotPresent'
    elif predicate == 'explicit_serviceaccount':s['serviceAccountName']='application' if good else ''
    elif predicate == 'host_namespaces':s.update(hostPID=not good,hostIPC=False)
    elif predicate == 'host_network':s['hostNetwork']=not good
    else:raise AssertionError(predicate)
    return s


def native_object(kind, spec):
    version, typ, path=KINDS[kind]
    row={'apiVersion':version,'kind':typ,'metadata':{'name':'web','namespace':'apps','uid':'4cc0680f-482e-4acd-8a43-2c9eb3299fb8','resourceVersion':'921'}}
    target=row
    for part in path.split('.')[:-1]:target=target.setdefault(part,{})
    target[path.split('.')[-1]]=deepcopy(spec)
    if kind not in ('pod','podtemplate'):
        if kind not in ('job','cronjob'):
            row['spec']['selector']={'app':'web'} if kind=='replicationcontroller' else {'matchLabels':{'app':'web'}}
        if kind=='cronjob':row['spec']['schedule']='0 * * * *'
        template=row['spec']['jobTemplate']['spec']['template'] if kind=='cronjob' else row['spec']['template']
        template['metadata']={'labels':{'app':'web'}}
        if kind=='job':
            selector={'batch.kubernetes.io/controller-uid':row['metadata']['uid']}
            row['spec']['selector']={'matchLabels':selector}
            row['spec']['manualSelector']=False
            template['metadata']['labels'].update(selector)
        if kind in ('job','cronjob'):template['spec']['restartPolicy']='Never'
        if kind=='statefulset':row['spec']['serviceName']='web'
    return row


class Wire:
    def __init__(self, kind, row, mode):self.kind,self.row,self.mode,self.calls=kind,row,mode,[]
    def request(self, method, url, **kwargs):
        target=urlsplit(url)
        assert method=='GET' and target.scheme=='https' and target.netloc=='native-k8s.invalid'
        base,namespaced=k8s.ENDPOINTS[self.kind]
        expected=base.rsplit('/',1)[0]+'/namespaces/apps/'+base.rsplit('/',1)[1]
        assert target.path==expected and not target.query
        assert kwargs.get('body') is None and kwargs.get('redirect') is False and kwargs.get('retries') is False
        fields=dict(kwargs.get('fields')or{})
        assert fields.get('limit')==500 and set(fields)<={'limit','continue'}
        self.calls.append({'method':method,'host':target.netloc,'path':target.path,'query':fields})
        if self.mode=='denied' or fields.get('continue')=='next':
            return urllib3.response.HTTPResponse(body=json.dumps({'kind':'Status','apiVersion':'v1','status':'Failure','reason':'Forbidden','code':403}).encode(),status=403,headers={'Content-Type':'application/json'},preload_content=True)
        items=[] if self.mode=='empty' else [deepcopy(self.row)]
        if self.mode=='wrong_list_type':items='wrong'
        doc={'apiVersion':KINDS[self.kind][0],'kind':KINDS[self.kind][1]+'List','metadata':{'resourceVersion':'921',**({'continue':'next'}if self.mode=='partial' else {})},'items':items}
        if self.mode=='conflicting_list_gvk':doc.update(kind='SecretList',apiVersion='v9')
        if self.mode=='wrong_list_kind':doc['kind']='SecretList'
        if self.mode=='wrong_list_version':doc['apiVersion']='v9'
        if self.mode=='null_list_kind':doc['kind']=None
        if self.mode=='omitted_list_gvk':doc.pop('kind');doc.pop('apiVersion')
        return urllib3.response.HTTPResponse(body=json.dumps(doc).encode(),status=200,headers={'Content-Type':'application/json'},preload_content=True)


def run(cid, branch='positive', *, spec=None, alter=None, mode=None):
    kind=CLOSED[cid]['kind'];predicate=CLOSED[cid]['predicate']
    spec=configured(predicate,branch!='negative') if spec is None else deepcopy(spec)
    row=native_object(kind,spec)
    if alter:alter(row)
    mode=mode or branch
    wire=Wire(kind,row,mode)
    configuration=client.Configuration();configuration.host='https://native-k8s.invalid';configuration.api_key={}
    sdk=client.ApiClient(configuration)
    sdk.rest_client.pool_manager=wire
    api=k8s._wrap_client(sdk)
    connector={'provider':'k8s','auth':{'cluster_id':'native-workload-cluster'},'scopes':['apps'],'options':{'inventories':[kind],'workers':1,'page_size':500,'max_retries':0}}
    snap=k8s.collect(connector,api=api)
    captures=[]
    code=inspect.unwrap(REGISTRY[cid].evaluate).__code__
    def capture(frame,event,arg):
        if event=='call' and frame.f_code is code:
            captures.append({'item':deepcopy(frame.f_locals['item']),'index':deepcopy(dict(frame.f_locals['index']))})
    previous=sys.getprofile()
    if branch in ('positive','negative'):sys.setprofile(capture)
    try:output=evaluate_snapshot(snap,checks=[cid])
    finally:sys.setprofile(previous)
    findings=output['findings']
    statuses=sorted({x['status']for x in findings})
    receipt={'id':cid,'branch':branch,'statuses':statuses,'requests':wire.calls,'native_response_sha256':sha256(json.dumps(row,sort_keys=True).encode()).hexdigest(),'native_object':row,
             'collections':[{'type':x['type'],'scope':x['scope'],'status':x['status'],'error':x.get('error')}for x in snap['collections']], 'evidence':[x['evidence']for x in findings], 'evaluator_arguments':captures}
    if branch in ('positive','negative'):
        assert len(captures)==1
        replay=REGISTRY[cid].evaluate(captures[0]['item'],captures[0]['index'])
        assert replay[0] in statuses
    directory=os.environ.get('K8S_WORKLOAD_REVIEW_RECEIPTS')
    if directory:
        path=Path(directory)/(sha256((cid+branch).encode()).hexdigest()[:18]+'.snapshot.json');path.parent.mkdir(parents=True,exist_ok=True);path.write_text(json.dumps(snap,separators=(',',':'))+'\n');receipt['snapshot']=str(path)
    CASES.append(receipt)
    assert wire.calls
    return statuses,snap


@pytest.mark.parametrize('cid',IDS)
@pytest.mark.parametrize('branch',['positive','negative','missing_spec','malformed','omitted','denied','partial','foreign','empty','wrong_list_type'])
def test_each_native_workload(cid,branch,request):
    pred=CLOSED[cid]['predicate'];kind=CLOSED[cid]['kind'];spec=configured(pred)
    wanted={'positive':['PASS'],'negative':['FAIL'],'missing_spec':['UNKNOWN'],'malformed':['UNKNOWN'],'omitted':[OMITTED[pred]],'denied':['DENIED'],'partial':['PASS','UNKNOWN'],'foreign':['UNKNOWN'],'empty':['EMPTY'],'wrong_list_type':['UNKNOWN']}[branch]
    alter=None
    if branch=='negative':spec=configured(pred,False)
    if branch=='missing_spec':
        def alter(row):
            target=row
            for part in KINDS[kind][2].split('.')[:-1]:target=target[part]
            del target[KINDS[kind][2].split('.')[-1]]
    if branch=='foreign':alter=lambda row:row['metadata'].update(namespace='other')
    if branch=='malformed':
        if pred in POD_FIELDS:
            if pred=='host_namespaces':spec['hostPID']='false'
            elif pred=='host_network':spec['hostNetwork']='false'
            elif pred=='explicit_serviceaccount':spec['serviceAccountName']=42
            else:spec['securityContext']={'seccompProfile':{'type':42}}
        elif pred in RESOURCE:spec['containers'][0]['resources']=[]
        elif pred in PROBES:spec['containers'][0]['readinessProbe' if pred=='readiness_probe' else 'livenessProbe']=[]
        elif pred in ('pinned_image','always_pull','content_digest_or_always_pull'):spec['containers'][0]['image']=42
        elif pred=='no_host_ports':spec['containers'][0]['ports']='wrong'
        else:spec['containers'][0]['securityContext']=[]
    if branch=='omitted':
        container={'name':'application','image':'registry.example.test/team/web:2.1','imagePullPolicy':'Always'}
        if pred in ('always_pull','content_digest_or_always_pull','pinned_image'):
            container.pop('image')
        spec={'containers':[container],'os':{'name':'linux'}}
    statuses,snapshot=run(cid,branch,spec=spec,alter=alter)
    CASES[-1]['testnode']=request.node.nodeid
    if branch=='partial':
        assert snapshot['collections'][0]['status']=='partial'
        assert len(CASES[-1]['requests'])==2
    assert statuses==wanted,(cid,branch,statuses,CASES[-1])


@pytest.mark.parametrize('cid',IDS)
@pytest.mark.parametrize('edge',['conflicting_gvk','empty_containers','duplicate_names'])
def test_native_structural_counterexamples(cid,edge,request):
    pred=CLOSED[cid]['predicate'];spec=configured(pred);alter=None
    if edge=='conflicting_gvk':alter=lambda row:row.update(kind='Secret',apiVersion='v9')
    if edge=='empty_containers':spec['containers']=[]
    if edge=='duplicate_names':spec['containers'].append(deepcopy(spec['containers'][0]))
    statuses,_=run(cid,edge,spec=spec,alter=alter)
    CASES[-1]['testnode']=request.node.nodeid
    assert statuses==['UNKNOWN'],(cid,edge,statuses)


@pytest.mark.parametrize('kind',['pod','deployment','daemonset','statefulset','replicaset','replicationcontroller','job','cronjob','podtemplate'])
@pytest.mark.parametrize('predicate',['cpu_limit','cpu_request','memory_limit','memory_request','readiness_probe','liveness_probe'])
def test_native_container_class_applicability(kind,predicate,request):
    cid=next(cid for cid,v in CLOSED.items()if v['kind']==kind and v['predicate']==predicate)
    spec=configured(predicate)
    if predicate in PROBES:spec['initContainers']=[{'name':'setup','image':'busybox:1.37','imagePullPolicy':'IfNotPresent'}]
    if kind=='pod':spec['ephemeralContainers']=[{'name':'debugger','image':'busybox:1.37','imagePullPolicy':'IfNotPresent','targetContainerName':'application'}]
    statuses,_=run(cid,'native-applicability',spec=spec)
    CASES[-1]['testnode']=request.node.nodeid
    assert statuses==['PASS'],(kind,predicate,statuses)


@pytest.mark.parametrize('kind',KINDS)
@pytest.mark.parametrize('predicate',sorted(PROBES))
@pytest.mark.parametrize('edge',['null_probe','empty_probe','sidecar_missing_probe'])
def test_native_probe_contract(kind,predicate,edge,request):
    cid=next(cid for cid,v in CLOSED.items()if v['kind']==kind and v['predicate']==predicate)
    spec=configured(predicate);key='readinessProbe'if predicate=='readiness_probe'else'livenessProbe'
    if edge=='sidecar_missing_probe':spec['initContainers']=[{'name':'sidecar','image':'busybox:1.37','restartPolicy':'Always'}]
    else:spec['containers'][0][key]=None if edge=='null_probe'else{}
    statuses,_=run(cid,edge,spec=spec)
    CASES[-1]['testnode']=request.node.nodeid
    assert statuses==(['FAIL']if edge=='sidecar_missing_probe'else['UNKNOWN'])


@pytest.mark.parametrize('cid',[cid for cid,v in CLOSED.items() if v['predicate'] not in POD_FIELDS])
def test_native_init_container_opposite_configuration(cid,request):
    pred=CLOSED[cid]['predicate'];spec=configured(pred)
    init=deepcopy(configured(pred,False)['containers'][0]);init['name']='setup'
    if pred in PROBES:init['restartPolicy']='Always'
    spec['initContainers']=[init]
    statuses,_=run(cid,'init-opposite',spec=spec)
    CASES[-1]['testnode']=request.node.nodeid
    assert statuses==['FAIL']


@pytest.mark.parametrize('predicate',['always_pull','content_digest_or_always_pull'])
@pytest.mark.parametrize('mode,wanted',[('digest_if_not_present','PASS'),('digest_never','FAIL'),('malformed_digest','UNKNOWN'),('untagged_default','PASS'),('tagged_default','FAIL')])
def test_native_image_source_boundaries(predicate,mode,wanted,request):
    cid='k8s.ports.pod.'+predicate;spec=configured(predicate);c=spec['containers'][0]
    if mode.startswith('digest'):
        c.update(image='registry.example.test/team/web@sha256:'+'a'*64,imagePullPolicy='Never' if mode=='digest_never' else 'IfNotPresent')
    elif mode=='malformed_digest':c['image']='registry.example.test/team/web@sha256:invalid'
    else:
        c['image']='registry.example.test/team/web'if mode=='untagged_default'else'registry.example.test:5000/team/web:v3'
        c.pop('imagePullPolicy')
    statuses,_=run(cid,mode,spec=spec);CASES[-1]['testnode']=request.node.nodeid
    if predicate == 'always_pull' and mode in ('digest_if_not_present', 'untagged_default'):
        wanted = 'FAIL'  # Literal source policy; immutable-image intent has its own criterion.
    assert statuses==[wanted]


@pytest.mark.parametrize('predicate',sorted(RESOURCE))
@pytest.mark.parametrize('value,wanted',[('0','PASS'),('1e3','PASS'),('750m','PASS'),('1Mi','PASS'),('not-a-quantity','UNKNOWN'),(True,'UNKNOWN'),({},'UNKNOWN')])
def test_native_resource_declaration_grammar(predicate,value,wanted,request):
    cid='k8s.ports.pod.'+predicate;spec=configured(predicate)
    group='limits'if predicate.endswith('limit')else'requests';field='cpu'if predicate.startswith('cpu')else'memory'
    spec['containers'][0]['resources'][group][field]=value
    statuses,_=run(cid,'resource-grammar-'+str(value),spec=spec);CASES[-1]['testnode']=request.node.nodeid
    assert statuses==[wanted]


@pytest.mark.parametrize('cid',[cid for cid,v in CLOSED.items() if v['kind']=='pod' and v['predicate'] not in POD_FIELDS|RESOURCE|PROBES])
def test_native_ephemeral_security_opposite(cid,request):
    pred=CLOSED[cid]['predicate'];spec=configured(pred);e=deepcopy(configured(pred,False)['containers'][0]);e['name']='debugger';e['targetContainerName']='application'
    spec['ephemeralContainers']=[e]
    statuses,_=run(cid,'ephemeral-opposite',spec=spec);CASES[-1]['testnode']=request.node.nodeid
    assert statuses==['FAIL']


@pytest.mark.parametrize('cid',IDS)
def test_native_absent_typemeta_preserves_endpoint_and_uid(cid,request):
    def alter(row):row.pop('kind');row.pop('apiVersion')
    statuses,snap=run(cid,'omitted-typemeta',alter=alter)
    CASES[-1]['testnode']=request.node.nodeid
    assert statuses==['PASS']
    row=snap['collections'][0]['items'][0]
    assert row['provenance']['cluster_id']=='native-workload-cluster'
    assert row['provenance']['namespace']=='apps'
    assert row['provenance']['uid']=='4cc0680f-482e-4acd-8a43-2c9eb3299fb8'
    assert row['id'].endswith('/4cc0680f-482e-4acd-8a43-2c9eb3299fb8')


@pytest.mark.parametrize('kind',KINDS)
def test_native_conflicting_list_typemeta_is_untrusted(kind,request):
    cid=next(cid for cid,v in CLOSED.items()if v['kind']==kind)
    statuses,_=run(cid,'conflicting-list-gvk',mode='conflicting_list_gvk');CASES[-1]['testnode']=request.node.nodeid
    assert statuses==['UNKNOWN']


@pytest.mark.parametrize('kind',KINDS)
@pytest.mark.parametrize('mode,wanted',[('wrong_list_kind','UNKNOWN'),('wrong_list_version','UNKNOWN'),('null_list_kind','UNKNOWN'),('omitted_list_gvk','PASS')])
def test_native_list_typemeta_grammar(kind,mode,wanted,request):
    cid=next(cid for cid,v in CLOSED.items()if v['kind']==kind)
    statuses,_=run(cid,mode,mode=mode);CASES[-1]['testnode']=request.node.nodeid
    assert statuses==[wanted]


@pytest.mark.parametrize('predicate',['drop_net_raw','drop_all','privilege_escalation'])
def test_native_declaration_does_not_prove_effective_capability_restriction(predicate,request):
    kind='podtemplate'if predicate=='privilege_escalation'else'pod'
    cid=next(cid for cid,v in CLOSED.items()if v['predicate']==predicate and v['kind']==kind)
    spec=configured(predicate)
    caps=spec['containers'][0].setdefault('securityContext',{}).setdefault('capabilities',{})
    caps['add']=['NET_RAW'if predicate=='drop_net_raw'else'SYS_ADMIN']
    statuses,_=run(cid,'configuration-not-effective',spec=spec);CASES[-1]['testnode']=request.node.nodeid
    assert statuses==['PASS']


@pytest.mark.parametrize('kind',KINDS)
def test_native_default_serviceaccount_name_is_only_a_declaration(kind,request):
    cid=next(cid for cid,v in CLOSED.items()if v['kind']==kind and v['predicate']=='explicit_serviceaccount')
    spec=configured('explicit_serviceaccount');spec['serviceAccountName']='default'
    statuses,_=run(cid,'native-default-account',spec=spec);CASES[-1]['testnode']=request.node.nodeid
    assert statuses==['PASS']
