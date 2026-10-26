"""Named workload GETs -> real bounded SDK auth pool -> dual scan -> public engine.

Independent native fixtures. No cluster content, credentials, referenced Secret,
external verification, registry read or workload command is executed.
"""
from copy import deepcopy
from hashlib import sha256
import inspect
import io
import json
import os
from pathlib import Path
import socket
import sys
from types import SimpleNamespace
from urllib.parse import urlsplit

import pytest
from kubernetes import client, config

from peaso import engine, secret_scanning as scanning
from peaso.collectors import k8s
from peaso.collectors import k8s_literal_secret_indicators as source
from peaso.checks import CHECKS
from peaso.server.validation import validate_connector

HOST='https://selected-native.invalid:6443'
CLUSTER='selected-workload-native'
NS='review'
AUTH='inert-controller-test-auth'
TOKEN='ghp_'+'7mQ2zR9wL4cV8nK1sF6aH3jP5uD0xB2yE9rT'
CLEAN='plain-configuration-only'
# This independent table follows the actual native API, not production constants.
NATIVE={
 'Pod':('v1','pods','spec'), 'ConfigMap':('v1','configmaps',None),
 'Deployment':('apps/v1','deployments','spec.template.spec'),
 'DaemonSet':('apps/v1','daemonsets','spec.template.spec'),
 'StatefulSet':('apps/v1','statefulsets','spec.template.spec'),
 'ReplicaSet':('apps/v1','replicasets','spec.template.spec'),
 'Job':('batch/v1','jobs','spec.template.spec'),
 'CronJob':('batch/v1','cronjobs','spec.jobTemplate.spec.template.spec'),
 'ReplicationController':('v1','replicationcontrollers','spec.template.spec'),
 'PodTemplate':('v1','podtemplates','template.spec')}
CONTROLLERS=tuple(k for k in NATIVE if k not in ('Pod','ConfigMap'))
REGISTRY={c.id:c for c in CHECKS}
RECEIPTS=[]


@pytest.fixture(autouse=True)
def offline(monkeypatch):
 def blocked(*a,**k):pytest.fail('network/DNS/credential discovery forbidden')
 for key in ('connect','connect_ex'):monkeypatch.setattr(socket.socket,key,blocked)
 for key in ('create_connection','getaddrinfo','gethostbyname','gethostbyname_ex'):monkeypatch.setattr(socket,key,blocked)
 for key in ('load_kube_config','load_kube_config_from_dict','load_incluster_config','new_client_from_config'):monkeypatch.setattr(config,key,blocked)
 monkeypatch.setattr(k8s,'_new_api',blocked)
 scanning._RESULTS.clear()
 yield
 scanning._RESULTS.clear()


@pytest.fixture(scope='session',autouse=True)
def save():
 yield
 if os.environ.get('K8S_CONTROLLER_LITERAL_RECEIPTS'):
  p=Path(os.environ['K8S_CONTROLLER_LITERAL_RECEIPTS']);p.mkdir(parents=True,exist_ok=True)
  (p/'cases.json').write_text(json.dumps(RECEIPTS,separators=(',',':'))+'\n')


def target(kind,name='selected-object',namespace=NS,cluster=CLUSTER):
 return {'kind':kind,'name':name,'namespace':namespace,'cluster_id':cluster}


def route(t):
 version,plural,_=NATIVE[t['kind']]
 return ('/api/v1'if version=='v1'else'/apis/'+version)+'/namespaces/'+t['namespace']+'/'+plural+'/'+t['name']


def podspec(obj,kind):
 value=obj
 for part in NATIVE[kind][2].split('.'):value=value[part]
 return value


def native(t,leak=False):
 kind=t['kind'];version,_,path=NATIVE[kind]
 identity=sha256(json.dumps(t,sort_keys=True).encode()).hexdigest()
 obj={'apiVersion':version,'kind':kind,'metadata':{'namespace':t['namespace'],'name':t['name'],
   'uid':'bc07418f-cccf-47a8-aac9-'+identity[:12],'resourceVersion':str(1000+int(identity[:8],16)),
   'labels':{'private-to-scan':'unretained-label'},'annotations':{'private-to-scan':'unretained-annotation'}}}
 if kind=='ConfigMap':obj['data']={'MODE':TOKEN if leak else CLEAN}
 else:
  c={'name':'application','image':'example.invalid/unfetched:v2','env':[{'name':'MODE','value':TOKEN if leak else CLEAN}],
     'command':['literal-program-canary'],'args':['--mode=test']}
  spec={'containers':[c],'restartPolicy':'Never'if kind in ('Job','CronJob')else'Always'}
  at=obj
  for part in path.split('.')[:-1]:at=at.setdefault(part,{})
  at[path.split('.')[-1]]=spec
  if kind in ('Deployment','DaemonSet','StatefulSet','ReplicaSet'):obj['spec']['selector']={'matchLabels':{'app':'selected'}}
  if kind=='ReplicationController':obj['spec']['selector']={'app':'selected'}
  if kind=='StatefulSet':obj['spec']['serviceName']='selected'
  if kind=='CronJob':obj['spec']['schedule']='0 * * * *'
  if kind=='Job':
   labels={'batch.kubernetes.io/controller-uid':obj['metadata']['uid']}
   obj['spec']['selector']={'matchLabels':labels};obj['spec']['manualSelector']=False
   obj['spec']['template']['metadata']={'labels':labels}
  elif kind!='Pod':
   template=obj['template']if kind=='PodTemplate'else obj['spec']['jobTemplate']['spec']['template']if kind=='CronJob'else obj['spec']['template']
   template['metadata']={'labels':{'app':'selected'}}
 return obj


class Response:
 def __init__(self,document,status=200,headers=None):
  data=json.dumps(document).encode()if isinstance(document,(dict,list))else document
  self.stream=io.BytesIO(data);self.status=status;self.reads=0;self.closed=False;self.released=False
  self.headers={'Content-Type':'application/json','Content-Length':str(len(data)),**(headers or{})}
 @property
 def data(self):pytest.fail('raw SDK last_response retention forbidden')
 def read(self,size):
  assert 0<size<=16384;self.reads+=1;return self.stream.read(size)
 def close(self):self.closed=True
 def release_conn(self):self.released=True


def capture(monkeypatch,targets,*,documents=None,response=None,real=False,fail_engine=None,detected_values=None,req_change=None,options=None,branch='case',testnode='',observe=False):
 documents=documents or{route(t):native(t)for t in targets}
 trace=SimpleNamespace(calls=[],scans=[],responses=[],progress=[],created=0)
 if not real:
  for engine_name in ('kingfisher','trufflehog'):
   def detector(payload,path,timeout,engine_name=engine_name):
    trace.scans.append({'engine':engine_name,'bytes':len(payload),'path':path,'timeout':timeout})
    assert TOKEN not in path and 0<timeout<=30
    if engine_name==fail_engine:raise TimeoutError('private detector error '+TOKEN)
    rows=[]
    for value in (detected_values or{}).get(engine_name,[TOKEN]):
     start=0
     while (position:=payload.find(value.encode(),start))!=-1:
      rows.append((value,'offline-canary',payload[:position].count(b'\n')+1));start=position+len(value)
    return rows
   monkeypatch.setattr(scanning,'_scan_'+engine_name,detector)
 class Pool:
  def request(self,method,url,**kwargs):
   parsed=urlsplit(url)
   if not(method=='GET'and parsed.scheme=='https'and parsed.netloc=='selected-native.invalid:6443'
     and not parsed.query and not parsed.fragment and parsed.path in documents):pytest.fail('unselected HTTP request')
   assert kwargs.get('body')is None and not kwargs.get('fields')
   assert kwargs['headers']['authorization']=='Bearer '+AUTH
   assert kwargs['headers']['Accept']=='application/json'and kwargs['headers']['Accept-Encoding']=='identity'
   assert kwargs['redirect']is False and kwargs['retries']is False
   assert kwargs['preload_content']is False and kwargs['decode_content']is False and 0<kwargs['timeout']<=10
   trace.calls.append({'method':method,'host':parsed.netloc,'path_binding':source._fingerprint(parsed.path)})
   n=sum(c['path_binding']==source._fingerprint(parsed.path)for c in trace.calls)
   doc=documents[parsed.path]
   doc=doc(n)if callable(doc)else doc
   result=response(parsed.path,n,doc)if response else Response(doc)
   trace.responses.append(result);return result
 def make_api(auth):
  trace.created+=1
  cfg=client.Configuration();cfg.host=HOST;cfg.api_key={'authorization':AUTH};cfg.api_key_prefix={'authorization':'Bearer'}
  sdk=client.ApiClient(cfg);sdk.rest_client.pool_manager=Pool();trace.api=k8s._wrap_client(sdk)
  trace.api.close=lambda:None
  return trace.api
 monkeypatch.setattr(k8s,'_new_api',make_api)
 req={'connector':{'provider':'k8s','scopes':list(dict.fromkeys(t['namespace']for t in targets)),
   'auth':{'method':'token','server':HOST,'token':AUTH,'cluster_id':CLUSTER},
   'options':{'content_secret_scans':True,source.OPTION:targets,'retries':0,'_progress_callback':trace.progress.append,**(options or{})}},'checks':[source.CHECK]}
 if req_change:req_change(req)
 snapshot=engine.collect_snapshot(req)
 captures=[];code=inspect.unwrap(REGISTRY[source.CHECK].evaluate).__code__
 def profile(frame,event,arg):
  if event=='call'and frame.f_code is code:captures.append({'item':deepcopy(frame.f_locals['item']),'index':deepcopy(dict(frame.f_locals['index']))})
 previous=sys.getprofile()
 if observe:sys.setprofile(profile)
 try:result=engine.evaluate_snapshot(snapshot,checks=[source.CHECK])
 finally:sys.setprofile(previous)
 statuses=sorted({f['status']for f in result['findings']})
 persisted=json.dumps([snapshot,result,list(scanning._RESULTS.values()),trace.progress],default=str)
 assert all(s not in persisted for s in(TOKEN,AUTH,CLEAN,'literal-program-canary','unretained-label','unretained-annotation','unfetched:v2'))
 assert all(r.closed and r.released for r in trace.responses)
 if trace.created:
  assert getattr(trace.api.api_client,'last_response',None)is None
  assert trace.api.api_client.rest_client.pool_manager.literal_paths==frozenset()
 receipt={'kinds':[t['kind']for t in targets],'branch':branch,'node':testnode,'statuses':statuses,'calls':trace.calls,
  'collections':[{'type':c['type'],'scope_binding':source._fingerprint(c['scope']),'status':c['status']}for c in snapshot['collections']],
  'evaluator_arguments':captures,'detector_mode':'actual_pinned_offline'if real else'controlled_low_level_runner',
  'detector_calls':trace.scans,'actual_read_calls':sum(r.reads for r in trace.responses)}
 if os.environ.get('K8S_CONTROLLER_LITERAL_RECEIPTS'):
  root=Path(os.environ['K8S_CONTROLLER_LITERAL_RECEIPTS']);root.mkdir(exist_ok=True,parents=True)
  path=root/(sha256((testnode+branch).encode()).hexdigest()[:20]+'.json');path.write_text(json.dumps(snapshot,separators=(',',':'))+'\n');receipt['snapshot']=str(path)
 RECEIPTS.append(receipt)
 return snapshot,result,trace


@pytest.mark.parametrize('kind',NATIVE)
@pytest.mark.parametrize('leak',[False,True])
def test_named_native_dual_result(monkeypatch,kind,leak,request):
 t=target(kind);snap,result,trace=capture(monkeypatch,[t],documents={route(t):native(t,leak)},branch='detected'if leak else'clean',testnode=request.node.nodeid)
 assert {r['status']for r in result['findings']}==({'FAIL'}if leak else{'PASS'})
 assert len(trace.calls)==2 and len(trace.scans)==2
 assert all(source._path(t)==route(t)for t in[t])


@pytest.mark.parametrize('kind',NATIVE)
@pytest.mark.parametrize('leak',[False,True])
def test_real_pinned_offline_engines_per_kind(monkeypatch,kind,leak,request):
 t=target(kind);snap,result,trace=capture(monkeypatch,[t],documents={route(t):native(t,leak)},real=True,observe=True,branch='real-detected'if leak else'real-clean',testnode=request.node.nodeid)
 assert {r['status']for r in result['findings']}==({'FAIL'}if leak else{'PASS'})
 args,=RECEIPTS[-1]['evaluator_arguments']
 status,ev=REGISTRY[source.CHECK].evaluate(args['item'],args['index'])
 assert status==('FAIL'if leak else'PASS')
 assert {(e['engine'],e['version'],e['status'])for e in ev['parts'][0]['engines']}=={('kingfisher','1.4.0','complete'),('trufflehog','3.92.5','complete')}
 assert len(trace.calls)==2
 if leak:assert {d['engine']for d in ev['secret_leaks'][0]['detectors']}=={'kingfisher','trufflehog'}
 assert len(RECEIPTS[-1]['evaluator_arguments'])==1


@pytest.mark.parametrize('kind',CONTROLLERS)
@pytest.mark.parametrize('container_class',['containers','initContainers'])
@pytest.mark.parametrize('surface',['env','command','args'])
def test_controller_all_literal_paths(monkeypatch,kind,container_class,surface,request):
 t=target(kind);obj=native(t);spec=podspec(obj,kind)
 c={'name':'inspected','image':'unused:v1',surface:[{'name':'CANARY','value':TOKEN}]if surface=='env'else[TOKEN]}
 if container_class=='containers':spec[container_class]=[c]
 else:spec[container_class]=[c]
 snap,result,trace=capture(monkeypatch,[t],documents={route(t):obj},branch=container_class+'-'+surface,testnode=request.node.nodeid)
 assert {r['status']for r in result['findings']}=={'FAIL'}and len(trace.calls)==2


@pytest.mark.parametrize('kind',CONTROLLERS)
@pytest.mark.parametrize('fault',['version','kind','name','namespace','uid','resourceVersion','deleting','partial','wrong_path','malformed_parent','containers','container_name','duplicate_env','conflicting_reference'])
def test_native_identity_and_shape_uncertainty(monkeypatch,kind,fault,request):
 t=target(kind);obj=native(t,True);spec=podspec(obj,kind)
 if fault=='version':obj['apiVersion']='v1'
 if fault=='version'and NATIVE[kind][0]=='v1':obj['apiVersion']='apps/v1'
 if fault=='kind':obj['kind']='Secret'
 if fault in('name','namespace'):obj['metadata'][fault]='foreign'
 if fault in('uid','resourceVersion'):obj['metadata'].pop(fault)
 if fault=='deleting':obj['metadata']['deletionTimestamp']='2026-10-20T00:00:00Z'
 if fault=='partial':obj['_partial']=True
 if fault=='wrong_path':
  obj.pop('template'if kind=='PodTemplate'else'spec');obj['spec']={'containers':spec['containers']}
 if fault=='malformed_parent':obj['template'if kind=='PodTemplate'else'spec']=[]
 if fault=='containers':spec['containers']=[]
 if fault=='container_name':spec['containers'][0]['name']=''
 if fault=='duplicate_env':spec['containers'][0]['env']=[{'name':'X','value':TOKEN},{'name':'X','value':'other'}]
 if fault=='conflicting_reference':spec['containers'][0]['env']=[{'name':'X','value':TOKEN,'valueFrom':{'secretKeyRef':{'name':'unread','key':'unread'}}}]
 snap,result,trace=capture(monkeypatch,[t],documents={route(t):obj},branch=fault,testnode=request.node.nodeid)
 assert {r['status']for r in result['findings']}=={'UNKNOWN'}and len(trace.calls)==1 and not trace.scans


@pytest.mark.parametrize('kind',CONTROLLERS)
@pytest.mark.parametrize('status',[206,301,401,403,404,429,500])
def test_denied_partial_and_unavailable_get_never_clean(monkeypatch,kind,status,request):
 t=target(kind)
 snap,result,trace=capture(monkeypatch,[t],response=lambda p,n,d:Response({'message':TOKEN},status),branch='http-'+str(status),testnode=request.node.nodeid)
 assert {r['status']for r in result['findings']}=={'UNKNOWN'}and len(trace.calls)==1 and not trace.scans
 assert all(r.reads==0 for r in trace.responses)


@pytest.mark.parametrize('kind',CONTROLLERS)
@pytest.mark.parametrize('changed',['uid','resourceVersion','content'])
def test_two_reads_must_agree(monkeypatch,kind,changed,request):
 t=target(kind)
 def doc(n):
  obj=native(t)
  if n==2:
   if changed=='content':podspec(obj,kind)['containers'][0]['env'][0]['value']='changed'
   else:obj['metadata'][changed]='changed'
  return obj
 snap,result,trace=capture(monkeypatch,[t],documents={route(t):doc},branch='changed-'+changed,testnode=request.node.nodeid)
 assert {r['status']for r in result['findings']}=={'UNKNOWN'}and len(trace.calls)==2 and not trace.scans


@pytest.mark.parametrize('kind',CONTROLLERS)
@pytest.mark.parametrize('fail_engine',['kingfisher','trufflehog'])
@pytest.mark.parametrize('leak',[False,True])
def test_dual_runner_timeout_never_clean(monkeypatch,kind,fail_engine,leak,request):
 t=target(kind);snap,result,trace=capture(monkeypatch,[t],documents={route(t):native(t,leak)},fail_engine=fail_engine,branch='timeout-'+fail_engine+str(leak),testnode=request.node.nodeid)
 statuses={r['status']for r in result['findings']}
 assert ('FAIL'in statuses if leak else statuses=={'UNKNOWN'})and 'PASS'not in statuses and len(trace.scans)==2
 assert not scanning._RESULTS


@pytest.mark.parametrize('kind',CONTROLLERS)
def test_references_are_counted_not_dereferenced(monkeypatch,kind,request):
 # Secret references are counted and never read.
 t=target(kind);obj=native(t);c=podspec(obj,kind)['containers'][0]
 c['env'].append({'name':'FROM_SECRET','valueFrom':{'secretKeyRef':{'name':'unread-secret','key':'unread'}}})
 c['envFrom']=[{'secretRef':{'name':'unread-secret'}}]
 c['args']=['$(FROM_SECRET)']
 snap,result,trace=capture(monkeypatch,[t],documents={route(t):obj},branch='references',testnode=request.node.nodeid)
 assert {r['status']for r in result['findings']}=={'PASS'}and len(trace.calls)==2
 assert result['findings'][0]['evidence']['reference_count']==2


@pytest.mark.parametrize('kind',CONTROLLERS)
def test_referenced_configmap_is_read_and_clean_passes(monkeypatch,kind,request):
 t=target(kind);obj=native(t);c=podspec(obj,kind)['containers'][0]
 c['env'].append({'name':'FROM_SECRET','valueFrom':{'secretKeyRef':{'name':'unread-secret','key':'unread'}}})
 c['envFrom']=[{'configMapRef':{'name':'read-map'}}]
 cm=route(target('ConfigMap','read-map'))
 doc={'apiVersion':'v1','kind':'ConfigMap','metadata':{'namespace':NS,'name':'read-map','uid':'cm-uid','resourceVersion':'3'},
  'data':{'MODE':CLEAN}}
 snap,result,trace=capture(monkeypatch,[t],documents={route(t):obj,cm:doc},branch='references',testnode=request.node.nodeid)
 assert {r['status']for r in result['findings']}=={'PASS'}and len(trace.calls)==4
 assert sum(c['path_binding']==source._fingerprint(cm)for c in trace.calls)==2


def test_eight_controller_ceiling_and_one_leak_multiple_engines_locations(monkeypatch,request):
 ts=[target(k,'selected-'+str(i))for i,k in enumerate(CONTROLLERS)]
 docs={route(t):native(t,True)for t in ts}
 for t in ts:podspec(docs[route(t)],t['kind'])['containers'][0]['args']=[TOKEN,TOKEN]
 snap,result,trace=capture(monkeypatch,ts,documents=docs,branch='eight-controller-dedup',testnode=request.node.nodeid)
 finding,=result['findings'];leak,=finding['evidence']['secret_leaks']
 assert finding['status']=='FAIL'and len(trace.calls)==16
 assert len(leak['locations'])==24 and {d['engine']for d in leak['detectors']}=={'kingfisher','trufflehog'}


@pytest.mark.parametrize('kind',CONTROLLERS)
@pytest.mark.parametrize('fault',['foreign_namespace','foreign_cluster','disabled','unselected_check','call_limit'])
def test_selection_and_budget_boundaries(monkeypatch,kind,fault,request):
 t=target(kind)
 if fault=='foreign_cluster':t['cluster_id']='foreign-cluster'
 def change(req):
  if fault=='foreign_namespace':req['connector']['scopes']=['other']
  elif fault=='disabled':req['connector']['options']['content_secret_scans']=False
  elif fault=='unselected_check':req.pop('checks');req['categories']=['hardening'];req['connector']['options']['_content_secret_scan_kinds']=[source.KIND]
 opts={'max_calls':1}if fault=='call_limit'else{}
 if fault=='foreign_namespace':
  with pytest.raises(ValueError):capture(monkeypatch,[t],req_change=change,branch=fault,testnode=request.node.nodeid)
  return
 if fault=='unselected_check':monkeypatch.setattr(engine,'plan_collection',lambda _,**_runtime:[source.KIND])
 snap,result,trace=capture(monkeypatch,[t],req_change=change,options=opts,branch=fault,testnode=request.node.nodeid)
 assert {r['status']for r in result['findings']}=={'UNKNOWN'}
 assert len(trace.calls)==(1 if fault=='call_limit'else 0)
 assert not trace.scans


@pytest.mark.parametrize('kind',NATIVE)
def test_hosted_exact_selection_accepts_supported_kinds_without_auth(monkeypatch,kind):
 validate_connector('k8s',{}, {'content_secret_scans':True,source.OPTION:[target(kind)]},SimpleNamespace(auth_mode='local'),scopes=[NS])


@pytest.mark.parametrize('kind',['Secret','DeploymentList','deployment','Service','Node','Unknown',None,{},[]])
def test_other_kinds_rejected_before_native_auth(monkeypatch,kind):
 opts={'content_secret_scans':True,source.OPTION:[{**target('Pod'),'kind':kind}]}
 with pytest.raises(ValueError):source.selected_targets(opts,[NS])


@pytest.mark.parametrize('kind',CONTROLLERS)
@pytest.mark.parametrize('budget',['value','content','count','wire','total','deadline'])
def test_controller_byte_time_count_bounds(monkeypatch,kind,budget,request):
 t=target(kind);obj=native(t);response=None
 c=podspec(obj,kind)['containers'][0]
 if budget=='value':c['env'][0]['value']='x'*(source.MAX_VALUE+1)
 if budget=='content':c['env']=[{'name':'ITEM'+str(i),'value':'x'*source.MAX_VALUE}for i in range(5)]
 if budget=='count':c['env']=[{'name':'ITEM'+str(i),'value':'x'}for i in range(source.MAX_LITERALS+1)]
 if budget=='wire':response=lambda p,n,d:Response(d,headers={'Content-Length':str(source.MAX_WIRE+1)})
 if budget=='total':monkeypatch.setattr(source,'MAX_TOTAL',1)
 if budget=='deadline':monkeypatch.setattr(source,'MAX_SECONDS',-1)
 snap,result,trace=capture(monkeypatch,[t],documents={route(t):obj},response=response,branch='budget-'+budget,testnode=request.node.nodeid)
 assert {r['status']for r in result['findings']}=={'UNKNOWN'}and not trace.scans
 assert len(trace.calls)==(0 if budget=='deadline'else 1)


@pytest.mark.parametrize('kind',CONTROLLERS)
@pytest.mark.parametrize('suffix',['/status','/scale','/log','/exec','?watch=true','/../foreign','%2fextra'])
def test_controller_exact_transport_subresource_query_rejected(kind,suffix):
 t=target(kind)
 class Pool:
  def request(self,*a,**k):pytest.fail('unselected request reached wire')
 bounded=k8s._BoundedPool(Pool(),HOST);bounded.literal_paths=frozenset([route(t)])
 with pytest.raises(ValueError):bounded.request('GET',HOST+route(t)+suffix)


def test_union_redaction_includes_different_engines_and_selected_identity(monkeypatch,request):
 second='secondary-sensitive-canary'
 t=target('CronJob',name=second);obj=native(t,True)
 snap,result,trace=capture(monkeypatch,[t],documents={route(t):obj},detected_values={'kingfisher':[TOKEN],'trufflehog':[second]},branch='two-engine-union',testnode=request.node.nodeid)
 assert {r['status']for r in result['findings']}=={'FAIL'}and len(result['findings'])==2
 assert second not in json.dumps([snap,result,trace.progress,list(scanning._RESULTS.values())],default=str)
 assert len(trace.calls)==2 and len(trace.scans)==2


def test_real_dual_engines_merge_multiple_controller_locations(monkeypatch,request):
 ts=[target('Deployment','selected-one'),target('CronJob','selected-two')]
 docs={route(t):native(t,True)for t in ts}
 for t in ts:podspec(docs[route(t)],t['kind'])['containers'][0]['args']=[TOKEN,TOKEN]
 assert len({o['metadata']['uid']for o in docs.values()})==2
 snap,result,trace=capture(monkeypatch,ts,documents=docs,real=True,branch='real-multi-controller-dedup',testnode=request.node.nodeid)
 finding,=result['findings'];leak,=finding['evidence']['secret_leaks']
 assert finding['status']=='FAIL'and len(trace.calls)==4
 assert len(leak['locations'])>=6 and len({p['path']for p in leak['locations']})==2
 assert {d['engine']for d in leak['detectors']}=={'kingfisher','trufflehog'}
 for row in snap['collections'][0]['items']:
  assert {e['status']for e in row[source.MARKER]['parts'][0]['engines']}=={'complete'}


@pytest.mark.parametrize('kind',NATIVE)
@pytest.mark.parametrize('failed_engine',['kingfisher','trufflehog'])
def test_completed_engine_hit_survives_other_runner_timeout(monkeypatch,kind,failed_engine,request):
 t=target(kind);snap,result,trace=capture(monkeypatch,[t],documents={route(t):native(t,True)},fail_engine=failed_engine,observe=True,branch='completed-hit-'+failed_engine,testnode=request.node.nodeid)
 assert len(trace.calls)==2
 own=snap['collections'][0]
 marker=own['items'][0][source.MARKER]
 assert marker['complete']is False and marker['leaks']
 assert {e['status']for e in marker['parts'][0]['engines']}=={'complete','unavailable'}
 statuses={r['status']for r in result['findings']}
 assert 'FAIL'in statuses and 'PASS'not in statuses
 args,=RECEIPTS[-1]['evaluator_arguments']
 status,evidence=REGISTRY[source.CHECK].evaluate(args['item'],args['index'])
 assert status=='FAIL'and evidence['complete']is False
 assert any(c['status']=='partial'for c in result['coverage'])
 for finding in result['findings']:
  if finding['status']=='FAIL':
   assert finding['evidence']['complete']is False and finding['evidence']['coverage']=='incomplete'
   assert 'Coverage is incomplete' in finding['evidence']['observed']


@pytest.mark.parametrize('fault',['receipt_method','receipt_status','receipt_identity','receipt_ordinal','scope','uid_binding','version_binding','version','duplicate_engine','unavailable_hit','unknown_status','part_complete','part_bytes','marker_reason','selection','leak_path'])
def test_partial_positive_keeps_all_source_and_scanner_guards(monkeypatch,fault,request):
 t=target('CronJob');snap,_,_=capture(monkeypatch,[t],documents={route(t):native(t,True)},fail_engine='trufflehog',branch='tamper-'+fault,testnode=request.node.nodeid)
 snap=deepcopy(snap);snap.pop('snapshot_id',None)
 own=snap['collections'][0];m=own['items'][0][source.MARKER];receipt=snap['metadata'][source.KIND+'_receipts'][0]
 if fault=='receipt_method':receipt['method']='POST'
 if fault=='receipt_status':receipt['status']=206
 if fault=='receipt_identity':receipt['identity']='foreign'
 if fault=='receipt_ordinal':receipt['ordinal']=2
 if fault=='scope':m['scope']='foreign'
 if fault in('uid_binding','version_binding'):m.pop(fault)
 if fault=='version':m['parts'][0]['engines'][0]['version']='unknown'
 if fault=='duplicate_engine':m['parts'][0]['engines'][1]=deepcopy(m['parts'][0]['engines'][0])
 if fault=='unavailable_hit':m['leaks'][0]['detectors'][0]['engine']='trufflehog'
 if fault=='unknown_status':m['parts'][0]['engines'][1]['status']='maybe'
 if fault=='part_complete':m['parts'][0]['complete']=True
 if fault=='part_bytes':m['parts'][0]['bytes']=0
 if fault=='marker_reason':m['reason']='native_get_denied'
 if fault=='selection':snap['metadata'][source.KIND+'_selection'][NS].append(source.KIND+':'+'0'*64)
 if fault=='leak_path':m['leaks'][0]['locations'][0]['path']='unbound'
 result=engine.evaluate_snapshot(snap,checks=[source.CHECK]);statuses={r['status']for r in result['findings']}
 RECEIPTS[-1]['after_adversarial_tamper_statuses']=sorted(statuses)
 assert statuses=={'UNKNOWN'}


@pytest.mark.parametrize('failed_engine',['kingfisher','trufflehog'])
def test_actual_completed_pinned_engine_survives_other_unavailable(monkeypatch,failed_engine,request):
 def unavailable(*a,**k):raise TimeoutError('inert runner timeout')
 monkeypatch.setattr(scanning,'_scan_'+failed_engine,unavailable)
 t=target('CronJob');snap,result,_=capture(monkeypatch,[t],documents={route(t):native(t,True)},real=True,observe=True,branch='real-one-completed-'+failed_engine,testnode=request.node.nodeid)
 RECEIPTS[-1]['detector_mode']='actual_pinned_completed_engine_with_simulated_other_timeout'
 statuses={r['status']for r in result['findings']}
 assert 'FAIL'in statuses and 'PASS'not in statuses
 arg,=RECEIPTS[-1]['evaluator_arguments'];status,evidence=REGISTRY[source.CHECK].evaluate(arg['item'],arg['index'])
 assert status=='FAIL'and evidence['complete']is False and evidence['secret_leaks']
 for finding in result['findings']:
  if finding['status']=='FAIL':
   assert finding['evidence']['complete']is False and finding['evidence']['coverage']=='incomplete'
 assert {e['status']for e in evidence['parts'][0]['engines']}=={'complete','unavailable'}
 assert all(d['engine']!=failed_engine for l in evidence['secret_leaks']for d in l['detectors'])


@pytest.mark.parametrize('broken',['kingfisher','trufflehog'])
def test_malformed_runner_rows_cannot_be_a_completed_hit(monkeypatch,broken,request):
 t=target('CronJob')
 def response(p,n,d):
  monkeypatch.setattr(scanning,'_scan_'+broken,lambda *a:[(TOKEN,'canary',1),('invalid-row',)])
  other='trufflehog'if broken=='kingfisher'else'kingfisher'
  monkeypatch.setattr(scanning,'_scan_'+other,lambda *a:[])
  return Response(d)
 snap,result,_=capture(monkeypatch,[t],documents={route(t):native(t,True)},response=response,branch='malformed-runner-'+broken,testnode=request.node.nodeid)
 assert {r['status']for r in result['findings']}=={'UNKNOWN'}
 assert not snap['collections'][0]['items'][0][source.MARKER]['leaks']
 assert not scanning._RESULTS
