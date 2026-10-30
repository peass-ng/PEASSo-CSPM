"""Finite native AKS/HSM successor review; no CASES as provider inputs."""
from copy import deepcopy
from dataclasses import replace
import io,json,socket
from urllib.error import HTTPError
from urllib.parse import parse_qs,urlsplit
import pytest
from peaso import checks,engine
from peaso.checks import azure_hsm_audit_destination_review_20261020 as hsm
from peaso.collectors import azure,k8s
from tests.archived_check_contract import evaluate_snapshot,plan_collection

SUB='11111111-1111-1111-1111-111111111111';TENANT='22222222-2222-2222-2222-222222222222'
SCOPE='/subscriptions/'+SUB;BASE=SCOPE+'/resourceGroups/native/providers/'
HSM=BASE+'Microsoft.KeyVault/managedHSMs/nativehsm';DIAG=HSM+'/providers/Microsoft.Insights/diagnosticSettings/audit'
STORAGE=BASE+'Microsoft.Storage/storageAccounts/nativearchive';WORKSPACE=BASE+'Microsoft.OperationalInsights/workspaces/native-audit'
AKS=BASE+'Microsoft.ContainerService/managedClusters/nativeaks';HOST='nativeaks-123.hcp.eastus.azmk8s.io'
TOKEN='INERT_AUTH_SENTINEL';LITERAL='PRIVATE_LITERAL_SENTINEL_NOT_A_SECRET'
PRIV='azure_aks_cluster_7_2_1_6_93c4fab';NONROOT='azure_aks_cluster_aks_cluster_rbac_enabled_db12524'
DIAGNOSTIC='azure_aks_cluster_10_2_1_1_17_885658f'

@pytest.fixture(autouse=True)
def offline_registry(monkeypatch):
 attempts=[]
 def blocked(*a,**kw):attempts.append('network/auth');raise AssertionError('Finite review prohibits live IO')
 for name in ('create_connection','getaddrinfo','gethostbyname','gethostbyname_ex','gethostbyaddr','getnameinfo'):monkeypatch.setattr(socket,name,blocked)
 for name in ('connect','connect_ex','sendto'):monkeypatch.setattr(socket.socket,name,blocked)
 monkeypatch.setattr(azure,'credential_for',blocked)
 original=list(checks.CHECKS)
 if not any(c.id==hsm.CHECK for c in original):hsm.install(checks.register)
 yield
 checks.CHECKS[:]=original
 assert not attempts,attempts

class HSMHTTP:
 def __init__(self,mode):
  self.mode=mode;self.calls=[];self.errors=[]
  self.parent={'id':HSM,'name':'nativehsm','type':'Microsoft.KeyVault/managedHSMs','location':'eastus','sku':{'family':'B','name':'Standard_B1'},'properties':{'provisioningState':'Succeeded','enablePurgeProtection':True}}
  self.setting={'id':DIAG,'name':'audit','type':'Microsoft.Insights/diagnosticSettings','properties':{'workspaceId':WORKSPACE,'logs':[{'category':'AuditEvent','enabled':True}]}}
  self.categories=[{'id':HSM+'/providers/Microsoft.Insights/diagnosticSettingsCategories/AuditEvent','name':'AuditEvent','type':'Microsoft.Insights/diagnosticSettingsCategories','properties':{'categoryType':'Logs','categoryGroups':['allLogs','audit']}}]
  p=self.setting['properties'];log=p['logs'][0]
  if mode=='storage':p.pop('workspaceId');p['storageAccountId']=STORAGE
  if mode=='both':p['storageAccountId']=STORAGE
  if mode=='none':p.pop('workspaceId')
  if mode=='empty-workspace':p['workspaceId']=''
  if mode=='disabled':log['enabled']=False
  if mode=='other-category':log['category']='AllMetrics'
  if mode=='bad-enabled':log['enabled']='true'
  if mode=='omitted-enabled':log.pop('enabled')
  if mode=='bad-logs':p['logs']={}
  if mode=='omitted-logs':p.pop('logs')
  if mode=='bad-workspace':p['workspaceId']='https://native-audit.example/'
  if mode=='workspace-uuid':p['workspaceId']=TENANT
  if mode=='bad-workspace-type':p['workspaceId']=[WORKSPACE]
  if mode=='wrong-workspace-provider':p['workspaceId']=WORKSPACE.replace('Microsoft.OperationalInsights','MicrosoftXOperationalInsights')
  if mode=='cross-subscription-destination':p['workspaceId']=WORKSPACE.replace(SUB,'99999999-9999-9999-9999-999999999999')
  if mode=='unused-empty-storage':p['storageAccountId']=''
  if mode=='bad-storage-plus-valid-workspace':p['storageAccountId']='https://arbitrary.example'
  if mode=='eventhub-only':p.pop('workspaceId');p['eventHubAuthorizationRuleId']=BASE+'Microsoft.EventHub/namespaces/native/authorizationRules/native'
  if mode in ('allLogs','audit'):log.pop('category');log['categoryGroup']=mode
  if mode.startswith('group-'):log.pop('category');log['categoryGroup']='allLogs' if mode=='group-allLogs-no-membership' else 'audit'
  if mode=='group-no-membership':self.categories[0]['properties']['categoryGroups']=[]
  if mode in ('group-membership-omitted','group-allLogs-no-membership'):self.categories[0]['properties'].pop('categoryGroups')
  if mode in ('group-malformed-membership','group-allLogs-malformed-membership'):self.categories[0]['properties']['categoryGroups']='audit'
  if mode=='group-allLogs-malformed-membership':log['categoryGroup']='allLogs'
  if mode=='group-category-missing':self.categories=[]
  if mode=='group-wrong-category-type':self.categories[0]['properties']['categoryType']='Metrics'
  if mode=='group-foreign':self.categories[0]['id']=self.categories[0]['id'].replace('nativehsm','foreignhsm')
  if mode=='group-duplicate':self.categories*=2
  if mode=='explicit-with-group-denied':p['logs'].append({'categoryGroup':'audit','enabled':True})
  if mode=='both-selectors':log['categoryGroup']='allLogs'
  if mode=='no-selector':log.pop('category')
  if mode=='foreign-parent':self.parent['id']=HSM.replace(SUB,'99999999-9999-9999-9999-999999999999')
  if mode=='wrong-parent-type':self.parent['type']='Microsoft.KeyVault/vaults'
  if mode=='foreign-diagnostic':self.setting['id']=DIAG.replace('nativehsm','foreignhsm')
  if mode=='wrong-diagnostic-type':self.setting['type']='Microsoft.KeyVault/vaults'
 def open(self,request,timeout):
  try:
   response=self._open(request,timeout)
   response.status=200
   return response
  except AssertionError as exc:self.errors.append(str(exc));raise
 def _open(self,request,timeout):
  p=urlsplit(request.full_url);q=parse_qs(p.query);method=request.get_method()
  assert p.scheme=='https' and p.netloc=='management.azure.com' and timeout==20
  assert set(q)<={'api-version','page','$top'}
  self.calls.append({'method':method,'host':p.netloc,'path':p.path,'query':q})
  def denied():raise HTTPError(request.full_url,403,'denied',{},io.BytesIO(b'{"message":"PRIVATE_LITERAL_SENTINEL_NOT_A_SECRET"}'))
  if p.path=='/providers/Microsoft.ResourceGraph/resources':
   assert method=='POST' and q=={'api-version':['2022-10-01']} and json.loads(request.data)['subscriptions']==[SUB]
   value={'data':[{k:self.parent[k] for k in ('id','name','type','location')}],'resultTruncated':False}
  else:
   assert method=='GET' and request.data is None
   if p.path==SCOPE+'/providers/Microsoft.KeyVault/managedHSMs':
    assert q.get('api-version')==['2023-07-01']
    if self.mode=='parent-denied' or 'page' in q:denied()
    value={'value':[] if self.mode=='empty-parent' else [self.parent]}
    if self.mode=='parent-partial':value['nextLink']=azure.ARM+p.path+'?api-version=2023-07-01&page=2'
   elif p.path==SCOPE+'/resources':
    assert q.get('api-version')==['2021-04-01'];value={'value':[self.parent]}
   elif p.path==HSM+'/providers/Microsoft.Insights/diagnosticSettingsCategories':
    assert q.get('api-version')==['2021-05-01-preview']
    if self.mode in ('group-denied','explicit-with-group-denied') or 'page' in q:denied()
    if self.mode=='group-unsupported':raise HTTPError(request.full_url,404,'unsupported',{},io.BytesIO(b'{}'))
    value={'value':deepcopy(self.categories)}
    if self.mode=='group-partial':value['nextLink']=azure.ARM+p.path+'?api-version=2021-05-01-preview&page=2'
    if self.mode=='group-foreign-page':value['nextLink']=azure.ARM+p.path.replace('nativehsm','foreignhsm')+'?api-version=2021-05-01-preview&page=2'
   elif p.path==DIAG.rsplit('/',1)[0]:
    assert q.get('api-version')==['2021-05-01-preview']
    if self.mode=='diagnostic-denied' or 'page' in q:denied()
    rows=[] if self.mode=='empty-settings' else [deepcopy(self.setting)]
    if self.mode in ('duplicate','conflicting-duplicate'):
     other=deepcopy(self.setting)
     if self.mode=='conflicting-duplicate':other['properties']['logs'][0]['enabled']=False
     rows.append(other)
    value={'value':rows}
    if self.mode=='diagnostic-partial':value['nextLink']=azure.ARM+p.path+'?api-version=2021-05-01-preview&page=2'
   else:raise AssertionError('Unexpected native HSM route '+p.path)
  return io.BytesIO(json.dumps(value).encode())

def hsm_capture(monkeypatch,mode,record_property):
 http=HSMHTTP(mode);monkeypatch.setattr(azure,'build_opener',lambda *a:http)
 connector={'provider':'azure','scopes':[SUB],'auth':{'arm_token':TOKEN},'options':{'retries':0,'concurrency':1}}
 deps=plan_collection({'connector':connector,'checks':[hsm.CHECK]});assert deps==[projection.HSM_KIND,'managed_hsm']
 snapshot=azure.collect(connector,deps);before=deepcopy(snapshot)
 out=evaluate_snapshot(snapshot,checks=[hsm.CHECK],include_not_applicable=True);assert snapshot==before and not http.errors,http.errors
 rows=[f for f in out['findings'] if f['check_id']==hsm.CHECK]
 assert TOKEN not in json.dumps(snapshot) and LITERAL not in json.dumps(snapshot)
 record_property('native_hsm',json.dumps({'check_id':hsm.CHECK,'mode':mode,'statuses':[f['status'] for f in rows],'evidence':[f['evidence'] for f in rows],'calls':http.calls},sort_keys=True))
 return snapshot,rows,http

HSM_BRANCHES=[('workspace','PASS'),('storage','PASS'),('both','PASS'),('none','FAIL'),('empty-workspace','FAIL'),('disabled','FAIL'),('other-category','FAIL'),('empty-settings','FAIL'),('duplicate','PASS'),('conflicting-duplicate','UNKNOWN'),('bad-enabled','UNKNOWN'),('omitted-enabled','UNKNOWN'),('bad-logs','UNKNOWN'),('omitted-logs','UNKNOWN'),('bad-workspace','UNKNOWN'),('workspace-uuid','UNKNOWN'),('bad-workspace-type','UNKNOWN'),('wrong-workspace-provider','UNKNOWN'),('cross-subscription-destination','PASS'),('unused-empty-storage','PASS'),('bad-storage-plus-valid-workspace','UNKNOWN'),('eventhub-only','UNKNOWN'),('allLogs','PASS'),('audit','PASS'),('both-selectors','UNKNOWN'),('no-selector','UNKNOWN'),('foreign-parent','UNKNOWN'),('wrong-parent-type','UNKNOWN'),('foreign-diagnostic','UNKNOWN'),('wrong-diagnostic-type','UNKNOWN'),('parent-denied','DENIED'),('parent-partial','UNKNOWN'),('empty-parent','EMPTY'),('diagnostic-denied','UNKNOWN'),('diagnostic-partial','UNKNOWN'),('group-denied','UNKNOWN'),('group-partial','UNKNOWN'),('group-foreign-page','UNKNOWN'),('group-unsupported','UNKNOWN'),('group-category-missing','UNKNOWN'),('group-wrong-category-type','UNKNOWN'),('group-no-membership','FAIL'),('group-membership-omitted','UNKNOWN'),('group-malformed-membership','UNKNOWN'),('group-foreign','UNKNOWN'),('group-duplicate','UNKNOWN'),('explicit-with-group-denied','PASS'),('group-allLogs-no-membership','PASS'),('group-allLogs-malformed-membership','UNKNOWN')]
@pytest.mark.parametrize('mode,expected',HSM_BRANCHES)
def test_native_hsm_audit_destination(monkeypatch,mode,expected,record_property):
 _,rows,http=hsm_capture(monkeypatch,mode,record_property);assert {f['status'] for f in rows}=={expected},rows
 category_calls=[c for c in http.calls if c['path'].endswith('/diagnosticSettingsCategories')]
 if mode in ('workspace','storage','both','explicit-with-group-denied'):assert not category_calls
 if mode in ('allLogs','audit','group-no-membership'):assert len(category_calls)==1

@pytest.mark.parametrize('change',['source_operation','request_path','api_version','read_only','credential_context_id','customer_context_id','scope'])
def test_hsm_capture_source_must_bind(monkeypatch,change,record_property):
 snapshot,_,_=hsm_capture(monkeypatch,'workspace',record_property)
 parent=next(c['items'][0] for c in snapshot['collections'] if c['type']=='managed_hsm')
 parent['diagnosticSettings'][0]['_provenance'].pop(change,None)
 snapshot.pop('snapshot_id',None)
 out=evaluate_snapshot(snapshot,checks=[hsm.CHECK],include_not_applicable=True)
 assert {f['status'] for f in out['findings'] if f['check_id']==hsm.CHECK}=={'UNKNOWN'}

def test_hsm_native_la_only_exposes_storage_specific_scope(monkeypatch,record_property):
 from peaso.checks import azure_hsm_audit_review_20261020 as old
 snapshot,rows,http=hsm_capture(monkeypatch,'workspace',record_property)
 out=evaluate_snapshot(snapshot,checks=[old.CHECK],include_not_applicable=True)
 assert {f['status'] for f in out['findings'] if f['check_id']==old.CHECK}=={'FAIL'}
 assert {f['status'] for f in rows}=={'PASS'}
 assert all('/Microsoft.Storage/' not in c['path'] and '/Microsoft.OperationalInsights/' not in c['path'] for c in http.calls)

# A cryptographic CA fixture is reused, never provider response/CASES data.
from peaso.checks import azure_aks_legacy_projection_review_20261020 as bridge
from peaso.collectors import azure_aks_legacy_projection_review_20261020 as projection
from tests.test_peaso_azure_aks_workloads_native import ca


def kube_object(kind,name,namespace=None,uid=None,**data):
 meta={'name':name,'uid':uid or '33333333-3333-3333-3333-333333333333','resourceVersion':'41'}
 if namespace:meta['namespace']=namespace
 return {'apiVersion':'v1','kind':kind,'metadata':meta,**data}

class AKSHTTP:
 tenant=verified_tenant=TENANT
 def __init__(self,mode):
  self.mode=mode;self.calls=[];self.errors=[]
  self.parent={'id':AKS,'name':'nativeaks','type':'Microsoft.ContainerService/managedClusters','location':'eastus','properties':{'provisioningState':'Succeeded','fqdn':HOST,'kubernetesVersion':'1.32.0','agentPoolProfiles':[]}}
  self.namespaces=[kube_object('Namespace','kube-system',uid='44444444-4444-4444-4444-444444444444'),kube_object('Namespace','default',uid='55555555-5555-5555-5555-555555555555')]
  container={'name':'app','image':'registry.example/app:v1','securityContext':{'privileged':False,'runAsUser':1000},'env':[{'name':'PASSWORD','value':LITERAL}],'command':[LITERAL],'args':[LITERAL]}
  self.pods=[kube_object('Pod','app','default',spec={'os':{'name':'linux'},'containers':[container]})]
  spec=self.pods[0]['spec']
  if mode=='privileged':container['securityContext']['privileged']=True
  if mode=='root':container['securityContext']['runAsUser']=0
  if mode=='missing-uid-value':container['securityContext'].pop('runAsUser')
  if mode=='missing-privileged':container['securityContext'].pop('privileged')
  if mode=='missing-security':container.pop('securityContext')
  if mode=='pod-fallback':container['securityContext'].pop('runAsUser');spec['securityContext']={'runAsUser':1000}
  if mode=='container-override-root':spec['securityContext']={'runAsUser':1000};container['securityContext']['runAsUser']=0
  if mode=='bad-privileged':container['securityContext']['privileged']='false'
  if mode=='bad-runAsUser':container['securityContext']['runAsUser']=True
  if mode=='windows':
   spec['os']['name']='windows';container['securityContext']={}
  if mode=='os-omitted':spec.pop('os')
  if mode in ('init-privileged','ephemeral-privileged','init-root','ephemeral-root'):
   field='initContainers' if mode.startswith('init') else 'ephemeralContainers'
   spec[field]=[{'name':'helper','securityContext':{'privileged':mode.endswith('privileged'),'runAsUser':0 if mode.endswith('root') else 1000}}]
  if mode=='null-init':spec['initContainers']=None
  if mode=='missing-containers':spec.pop('containers')
  if mode=='empty-containers':spec['containers']=[]
  if mode=='duplicate-container':spec['initContainers']=[deepcopy(container)]
  if mode=='empty-pods':self.pods=[]
  if mode=='foreign-namespace':self.pods[0]['metadata']['namespace']='foreign'
  if mode=='missing-object-uid':self.pods[0]['metadata'].pop('uid')
  if mode=='duplicate-pod':self.pods*=2
  if mode=='duplicate-pod-name':self.pods.append(deepcopy(self.pods[0]));self.pods[1]['metadata']['uid']='66666666-6666-6666-6666-666666666666'
  if mode=='wrong-pod-kind':self.pods[0]['kind']='Service'
  if mode=='missing-item-type':self.pods[0].pop('kind');self.pods[0].pop('apiVersion')
  if mode=='duplicate-namespace':self.namespaces.append(deepcopy(self.namespaces[0]))
  if mode=='foreign-cluster':self.parent['id']=AKS.replace(SUB,'99999999-9999-9999-9999-999999999999')
  if mode=='foreign-endpoint':self.parent['properties']['fqdn']='foreign.example.org'
  self.categories=[{'id':AKS+'/providers/Microsoft.Insights/diagnosticSettingsCategories/'+name,'name':name,'type':'Microsoft.Insights/diagnosticSettingsCategories','properties':{'categoryType':'Logs','categoryGroups':['allLogs','audit']}} for name in ('kube-audit','kube-apiserver')]
  self.settings=[{'id':AKS+'/providers/Microsoft.Insights/diagnosticSettings/native','name':'native','type':'Microsoft.Insights/diagnosticSettings','properties':{'workspaceId':WORKSPACE,'logs':[{'category':'kube-audit','enabled':True},{'category':'kube-apiserver','enabled':True}]}}]
  if mode=='category-disabled':self.settings[0]['properties']['logs'][1]['enabled']=False
  if mode=='category-omitted':self.settings[0]['properties']['logs'].pop()
  if mode=='no-destination':self.settings[0]['properties'].pop('workspaceId')
  if mode=='all-logs':self.settings[0]['properties']['logs']=[{'categoryGroup':'allLogs','enabled':True}]
  if mode=='audit-group':self.settings[0]['properties']['logs']=[{'categoryGroup':'audit','enabled':True}]
  if mode=='unmapped-group':self.settings[0]['properties']['logs']=[{'categoryGroup':'unknown-group','enabled':True}]
  if mode=='empty-categories':self.categories=[]
  if mode=='foreign-category':self.categories[0]['id']=self.categories[0]['id'].replace('nativeaks','foreign')
  if mode=='malformed-category':self.categories[0]['properties']['categoryType']=None
  if mode=='foreign-setting':self.settings[0]['id']=self.settings[0]['id'].replace('nativeaks','foreign')
  if mode=='malformed-destination':self.settings[0]['properties']['workspaceId']='https://foreign.example.org'
  if mode=='eventhub-destination':self.settings[0]['properties'].pop('workspaceId');self.settings[0]['properties']['eventHubAuthorizationRuleId']=BASE+'Microsoft.EventHub/namespaces/native/authorizationRules/diagnostics'
 def request(self,url,*,body=None,audience=azure.ARM):
  try:return self._request(url,body=body,audience=audience)
  except AssertionError as exc:self.errors.append(str(exc));raise
 def _request(self,url,*,body=None,audience=azure.ARM):
  p=urlsplit(url);q=parse_qs(p.query);self.calls.append({'method':'POST' if body is not None else 'GET','host':p.netloc,'path':p.path,'query':q})
  assert p.scheme=='https' and p.netloc=='management.azure.com' and audience==azure.ARM
  if p.path=='/providers/Microsoft.ResourceGraph/resources':
   assert body is not None and q=={'api-version':['2022-10-01']} and body['subscriptions']==[SUB]
   return {'data':[{k:self.parent[k] for k in ('id','name','type','location')}],'resultTruncated':False}
  assert body is None
  if p.path in (SCOPE,'/subscriptions'):
   assert q=={'api-version':['2022-12-01']}
   sub={'id':SCOPE,'subscriptionId':SUB,'tenantId':'foreign' if self.mode=='foreign-tenant' else TENANT,'state':'Enabled'}
   return sub if p.path==SCOPE else {'value':[sub]}
  if p.path=='/tenants':assert q=={'api-version':['2022-12-01']};return {'value':[{'id':'/tenants/'+TENANT,'tenantId':TENANT}]}
  if p.path==SCOPE+'/providers/Microsoft.ContainerService/managedClusters':
   assert q.get('api-version')==['2024-05-01']
   if self.mode=='parent-denied' or q.get('page'):raise azure.AzureReadError('forbidden',403)
   rows=[] if self.mode=='empty-clusters' else [deepcopy(self.parent)]
   if self.mode=='duplicate-cluster':rows*=2
   result={'value':rows}
   if self.mode=='parent-partial':result['nextLink']=azure.ARM+p.path+'?api-version=2024-05-01&page=2'
   return result
  if p.path==SCOPE+'/providers/Microsoft.Kubernetes/connectedClusters':assert q=={'api-version':['2024-01-01']};return {'value':[]}
  if p.path==SCOPE+'/resources':assert q.get('api-version')==['2021-04-01'];return {'value':[deepcopy(self.parent)]}
  if p.path==AKS:
   assert q=={'api-version':['2024-05-01']}
   if self.mode=='get-denied':raise azure.AzureReadError('forbidden',403)
   return deepcopy(self.parent)
  if p.path==AKS+'/managedNamespaces':assert q=={'api-version':['2025-10-01']};return {'value':[]}
  for suffix,version,rows in (('diagnosticSettings','2021-05-01-preview',self.settings),('diagnosticSettingsCategories','2021-05-01-preview',self.categories)):
   expected=AKS+'/providers/Microsoft.Insights/'+suffix
   if p.path==expected:
    assert q.get('api-version')==[version]
    if self.mode==suffix+'-denied' or q.get('page'):raise azure.AzureReadError('forbidden',403)
    result={'value':deepcopy(rows)}
    if self.mode==suffix+'-partial':result['nextLink']=azure.ARM+expected+'?api-version='+version+'&page=2'
    if self.mode==suffix+'-foreign-page':result['nextLink']=azure.ARM+expected.replace('nativeaks','foreign')+'?api-version='+version+'&page=2'
    return result
  raise AssertionError('Unexpected native AKS ARM route '+p.path+' '+str(q))

class KubeHTTP:
 def __init__(self,arm):self.arm=arm;self.calls=[];self.closed=False;self.uid_reads=0
 def get_json(self,path,params):
  self.calls.append({'method':'GET','path':path,'params':deepcopy(params)});mode=self.arm.mode
  assert path in ('/api/v1/namespaces/kube-system','/api/v1/namespaces','/api/v1/pods')
  if path=='/api/v1/namespaces/kube-system':
   assert params=={};self.uid_reads+=1;row=deepcopy(self.arm.namespaces[0])
   if mode=='uid-changed' and self.uid_reads>1:row['metadata']['uid']='99999999-9999-9999-9999-999999999999'
   return row
  assert set(params)<={'limit','continue'} and type(params['limit']) is int
  if mode=='kubernetes-denied':raise azure.AzureReadError('forbidden',403)
  if mode=='namespace-denied' and path=='/api/v1/namespaces':raise azure.AzureReadError('forbidden',403)
  if mode=='pod-denied' and path=='/api/v1/pods':raise azure.AzureReadError('forbidden',403)
  if mode=='error-body' and path=='/api/v1/pods':raise ValueError(LITERAL)
  typ='NamespaceList' if path.endswith('namespaces') else 'PodList';rows=deepcopy(self.arm.namespaces if typ=='NamespaceList' else self.arm.pods);version='42' if typ=='NamespaceList' else '43';continuation=''
  if mode in ('namespace-paged','namespace-partial','namespace-version-changed') and typ=='NamespaceList':
   if params.get('continue'):
    assert params['continue']=='namespace-next'
    if mode=='namespace-partial':raise azure.AzureReadError('forbidden',403)
    rows=[]
    if mode=='namespace-version-changed':version='44'
   else:continuation='namespace-next'
  if mode in ('paged','partial','version-changed','repeated-token') and typ=='PodList':
   if params.get('continue'):
    assert params['continue']=='next'
    if mode=='partial':raise azure.AzureReadError('forbidden',403)
    rows=[]
    if mode=='version-changed':version='44'
    if mode=='repeated-token':continuation='next'
   else:continuation='next'
  if mode=='missing-list-version':version=None
  return {'apiVersion':'v1','kind':typ,'metadata':{'resourceVersion':version,'continue':continuation},'items':rows}
 def close(self):self.closed=True


def aks_capture(monkeypatch,ca,mode,cid,record_property,options=None,real_sdk=False):
 if cid in (PRIV,NONROOT):bridge.install_successors()
 elif cid==bridge.DIAGNOSTIC and not any(c.id==cid for c in checks.CHECKS):bridge.install_diagnostic(checks.register)
 arm=AKSHTTP(mode);apis=[];original_new_api=k8s._new_api
 def factory(context):
  assert context['method']=='token' and context['server']=='https://'+HOST and context['ca_cert_data']==ca and context['token']==TOKEN
  assert context['_disable_proxy'] is True
  if not real_sdk:api=KubeHTTP(arm)
  else:
   from urllib3.response import HTTPResponse
   api=original_new_api(context);stub=KubeHTTP(arm)
   bounded=api.api_client.rest_client.pool_manager
   assert isinstance(bounded,k8s._BoundedPool) and bounded.server.hostname==HOST
   assert api.api_client.configuration.verify_ssl is True and api.api_client.configuration.proxy is None
   class Pool:
    def request(self,method,url,**kwargs):
     target=urlsplit(url)
     assert method=='GET' and target.scheme=='https' and target.netloc==HOST
     assert kwargs['redirect'] is False and kwargs['retries'] is False
     params={key:value[0] for key,value in parse_qs(target.query).items()}
     params.update(dict(kwargs.get('fields') or []))
     if 'limit' in params:params['limit']=int(params['limit'])
     payload=stub.get_json(target.path,params)
     return HTTPResponse(body=io.BytesIO(json.dumps(payload).encode()),status=200,headers={'Content-Type':'application/json'},preload_content=False)
    def clear(self):pass
   bounded.pool=Pool();api.calls=stub.calls;api.closed=False;close=api.close
   def shutdown():
    api.closed=True;close()
   api.close=shutdown
  apis.append(api);return api
 monkeypatch.setattr(k8s,'_new_api',factory)
 auth={'aks_workloads':[{'cluster_id':AKS,'server':'https://'+HOST,'ca_cert_data':ca,'token':TOKEN}]}
 if mode=='no-credentials':auth={}
 if mode=='empty-clusters':auth={}
 connector={'provider':'azure','scopes':[SUB],'auth':auth,'options':{'concurrency':1,'retries':0,**(options or {})}}
 deps=plan_collection({'connector':connector,'checks':[cid]})
 snapshot=azure.collect(connector,deps,transport=arm);before=deepcopy(snapshot)
 out=evaluate_snapshot(snapshot,checks=[cid],include_not_applicable=True);assert snapshot==before and not arm.errors,arm.errors
 rows=[f for f in out['findings'] if f['check_id']==cid];assert rows
 assert all(api.closed for api in apis)
 encoded=json.dumps(snapshot);assert TOKEN not in encoded and LITERAL not in encoded
 record_property('native_aks',json.dumps({'check_id':cid,'mode':mode,'dependencies':deps,'statuses':[f['status'] for f in rows],'evidence':[f['evidence'] for f in rows],'arm_calls':arm.calls,'kubernetes_calls':[a.calls for a in apis]},sort_keys=True))
 return snapshot,rows,arm,apis

POD_BRANCHES=[('good','PASS','PASS'),('privileged','FAIL','PASS'),('root','PASS','FAIL'),('missing-uid-value','PASS','FAIL'),('missing-privileged','PASS','PASS'),('missing-security','PASS','FAIL'),('pod-fallback','PASS','PASS'),('container-override-root','PASS','FAIL'),('bad-privileged','UNKNOWN','PASS'),('bad-runAsUser','PASS','UNKNOWN'),('windows','PASS','UNKNOWN'),('os-omitted','PASS','UNKNOWN'),('init-privileged','FAIL','PASS'),('ephemeral-privileged','FAIL','PASS'),('init-root','PASS','FAIL'),('ephemeral-root','PASS','FAIL'),('null-init','UNKNOWN','UNKNOWN'),('missing-containers','UNKNOWN','UNKNOWN'),('empty-containers','UNKNOWN','UNKNOWN'),('duplicate-container','UNKNOWN','UNKNOWN'),('empty-pods','PASS','NOT_APPLICABLE'),('foreign-namespace','UNKNOWN','UNKNOWN'),('missing-object-uid','UNKNOWN','UNKNOWN'),('duplicate-pod','UNKNOWN','UNKNOWN'),('duplicate-pod-name','UNKNOWN','UNKNOWN'),('wrong-pod-kind','UNKNOWN','UNKNOWN'),('missing-item-type','PASS','PASS'),('duplicate-namespace','UNKNOWN','UNKNOWN'),('foreign-cluster','UNKNOWN','UNKNOWN'),('foreign-endpoint','UNKNOWN','UNKNOWN'),('foreign-tenant','UNKNOWN','UNKNOWN'),('no-credentials','UNKNOWN','UNKNOWN'),('parent-denied','UNKNOWN','UNKNOWN'),('parent-partial','UNKNOWN','UNKNOWN'),('duplicate-cluster','UNKNOWN','UNKNOWN'),('get-denied','UNKNOWN','UNKNOWN'),('empty-clusters','EMPTY','EMPTY'),('uid-changed','UNKNOWN','UNKNOWN'),('kubernetes-denied','UNKNOWN','UNKNOWN'),('namespace-denied','UNKNOWN','UNKNOWN'),('pod-denied','UNKNOWN','UNKNOWN'),('paged','PASS','PASS'),('partial','UNKNOWN','UNKNOWN'),('version-changed','UNKNOWN','UNKNOWN'),('repeated-token','UNKNOWN','UNKNOWN'),('missing-list-version','UNKNOWN','UNKNOWN')]
@pytest.mark.parametrize('mode,privileged,nonroot',POD_BRANCHES)
@pytest.mark.parametrize('cid',[PRIV,NONROOT])
def test_native_aks_source_bound_pod_bridge(monkeypatch,ca,mode,privileged,nonroot,cid,record_property):
 _,rows,_,_=aks_capture(monkeypatch,ca,mode,cid,record_property)
 if mode=='parent-denied':privileged=nonroot='DENIED'
 assert {f['status'] for f in rows}=={privileged if cid==PRIV else nonroot},rows

DIAGNOSTIC_BRANCHES=[('good','PASS'),('category-disabled','FAIL'),('category-omitted','FAIL'),('no-destination','FAIL'),('all-logs','PASS'),('audit-group','PASS'),('unmapped-group','UNKNOWN'),('empty-categories','UNKNOWN'),('foreign-category','UNKNOWN'),('malformed-category','UNKNOWN'),('foreign-setting','UNKNOWN'),('malformed-destination','UNKNOWN'),('eventhub-destination','PASS'),('diagnosticSettings-denied','UNKNOWN'),('diagnosticSettings-partial','UNKNOWN'),('diagnosticSettingsCategories-denied','UNKNOWN'),('diagnosticSettingsCategories-partial','UNKNOWN'),('diagnosticSettingsCategories-foreign-page','UNKNOWN'),('foreign-cluster','UNKNOWN')]
@pytest.mark.parametrize('mode,expected',DIAGNOSTIC_BRANCHES)
def test_native_aks_diagnostic_declaration_proposal(monkeypatch,ca,mode,expected,record_property):
 _,rows,_,apis=aks_capture(monkeypatch,ca,mode,bridge.DIAGNOSTIC,record_property)
 assert {f['status'] for f in rows}=={expected},rows
 assert not apis,'Diagnostic declarations must not request workload credentials or Kubernetes APIs'

@pytest.mark.parametrize('cid',[PRIV,NONROOT])
@pytest.mark.parametrize('change',['absent-projection','fake-legacy-flags','source-operation','write','credential','customer','scope','uid','page-count','page-version','page-incomplete','namespace-uid','server','ca','ARM-id','duplicate-row'])
def test_native_aks_bridge_never_uses_caller_completeness(monkeypatch,ca,cid,change,record_property):
 snapshot,_,_,_=aks_capture(monkeypatch,ca,'good',cid,record_property)
 own=next(c for c in snapshot['collections'] if c['type']==projection.KIND);row=own['items'][0]
 if change in ('absent-projection','fake-legacy-flags'):
  snapshot['collections'].remove(own)
  if change=='fake-legacy-flags':
   parent=next(c['items'][0] for c in snapshot['collections'] if c['type']=='aks_cluster')
   parent['podInventory']={'status':'collected','pagesComplete':True,'namespacesComplete':True,'clusterId':AKS,'resourceVersion':'invented','consistent':True,'fullPodRepresentation':True,'items':[]}
 elif change=='source-operation':row['_provenance']['source_operation']='caller-provided'
 elif change=='write':row['_provenance']['read_only']=False
 elif change in ('credential','customer'):row['_provenance'][change+'_context_id']='foreign'
 elif change=='scope':own['scope']=SCOPE.replace(SUB,'99999999-9999-9999-9999-999999999999')
 elif change=='uid':row['_provenance']['cluster_uid_after']='foreign-cluster'
 elif change=='page-count':row['native_list_pages']['/api/v1/pods'][0]['items']+=1
 elif change=='page-version':row['list_resource_versions']['/api/v1/pods']='invented'
 elif change=='page-incomplete':row['native_list_pages']['/api/v1/pods'][0]['continue']='not-finished'
 elif change=='namespace-uid':row['namespace_uids']['kube-system']='foreign-namespace'
 elif change=='server':row['server']='https://foreign.example.org'
 elif change=='ca':row['ca_sha256']=''
 elif change=='ARM-id':row['ARM_get']['id']=AKS+'foreign'
 else:own['items'].append(deepcopy(row))
 snapshot.pop('snapshot_id',None)
 out=evaluate_snapshot(snapshot,checks=[cid],include_not_applicable=True)
 assert {f['status'] for f in out['findings'] if f['check_id']==cid}=={'UNKNOWN'}

@pytest.mark.parametrize('cid',[PRIV,NONROOT])
@pytest.mark.parametrize('options',[{'max_calls':3},{'max_pages':1},{'max_resources':3},{'collection_deadline_seconds':0.000001},{'_cancel_check':lambda:True}])
def test_native_aks_bridge_limit_cannot_create_clean_pass(monkeypatch,ca,cid,options,record_property):
 mode='paged' if 'max_pages' in options else 'good'
 _,rows,_,_=aks_capture(monkeypatch,ca,mode,cid,record_property,options)
 assert {f['status'] for f in rows}<={'UNKNOWN','DENIED'},rows

@pytest.mark.parametrize('cid',[PRIV,NONROOT])
def test_native_error_body_is_not_retained(monkeypatch,ca,cid,record_property):
 _,rows,_,_=aks_capture(monkeypatch,ca,'error-body',cid,record_property)
 assert {f['status'] for f in rows}=={'UNKNOWN'}

@pytest.mark.parametrize('cid,mode',[(PRIV,'good'),(PRIV,'privileged'),(PRIV,'bad-privileged'),(NONROOT,'good'),(NONROOT,'root'),(NONROOT,'os-omitted'),(hsm.CHECK,'workspace'),(hsm.CHECK,'storage'),(hsm.CHECK,'disabled'),(hsm.CHECK,'bad-workspace'),(hsm.CHECK,'allLogs'),(hsm.CHECK,'audit'),(hsm.CHECK,'group-denied'),(bridge.DIAGNOSTIC,'good'),(bridge.DIAGNOSTIC,'category-disabled'),(bridge.DIAGNOSTIC,'foreign-setting')])
def test_native_public_evaluator_capture(monkeypatch,ca,cid,mode,record_property):
 if cid in (PRIV,NONROOT):bridge.install_successors()
 if cid==bridge.DIAGNOSTIC and not any(c.id==cid for c in checks.CHECKS):bridge.install_diagnostic(checks.register)
 original=next(c for c in checks.CHECKS if c.id==cid);captures=[]
 def capture(item,index):
  before=deepcopy((item,index));result=original.evaluate(item,index);assert (item,index)==before
  captures.append({'item':before[0],'index':before[1],'result':deepcopy(result)})
  return result
 monkeypatch.setattr(engine,'_registry',lambda:[replace(c,evaluate=capture) if c.id==cid else c for c in checks.CHECKS])
 if cid==hsm.CHECK:hsm_capture(monkeypatch,mode,record_property)
 else:aks_capture(monkeypatch,ca,mode,cid,record_property)
 assert captures
 record_property('native_consumer_capture',json.dumps({'check_id':cid,'mode':mode,'captures':captures},sort_keys=True))


def test_registered_frozen_diagnostic_is_not_satisfied_by_destination_existence(monkeypatch,ca,record_property):
 snapshot,_,_,_=aks_capture(monkeypatch,ca,'good',bridge.DIAGNOSTIC,record_property)
 out=evaluate_snapshot(snapshot,checks=[DIAGNOSTIC],include_not_applicable=True)
 assert {f['status'] for f in out['findings'] if f['check_id']==DIAGNOSTIC}=={'UNKNOWN'}
 assert 'usable' not in json.dumps(snapshot)
 record_property('native_legacy_diagnostic',json.dumps({'check_id':DIAGNOSTIC,'mode':'complete-native-declarations-without-effective-destination-fact',
  'statuses':[f['status'] for f in out['findings'] if f['check_id']==DIAGNOSTIC],
  'evidence':[f['evidence'] for f in out['findings'] if f['check_id']==DIAGNOSTIC]},sort_keys=True))


def test_projection_fixed_page_and_byte_bounds_are_source_derived(monkeypatch,ca,record_property):
 monkeypatch.setattr(projection,'MAX_PAGES',1)
 _,rows,_,_=aks_capture(monkeypatch,ca,'paged',PRIV,record_property)
 assert {f['status'] for f in rows}=={'UNKNOWN'}
 monkeypatch.setattr(projection,'MAX_BYTES',100)
 _,rows,_,_=aks_capture(monkeypatch,ca,'good',PRIV,record_property)
 assert {f['status'] for f in rows}=={'UNKNOWN'}



@pytest.mark.parametrize('cid',[PRIV,NONROOT])
@pytest.mark.parametrize('mode,expected',[('namespace-paged','PASS'),('namespace-partial','UNKNOWN'),('namespace-version-changed','UNKNOWN')])
def test_native_namespace_pagination_is_required(monkeypatch,ca,cid,mode,expected,record_property):
 _,rows,_,apis=aks_capture(monkeypatch,ca,mode,cid,record_property)
 assert {f['status'] for f in rows}=={expected}
 assert any(call['params'].get('continue')=='namespace-next' for api in apis for call in api.calls)


@pytest.mark.parametrize('field',['source_operation','request_path','api_version','read_only','credential_context_id','customer_context_id','scope'])
def test_native_hsm_group_source_context_is_required(monkeypatch,field,record_property):
 snapshot,_,_=hsm_capture(monkeypatch,'audit',record_property)
 row=next(c['items'][0] for c in snapshot['collections'] if c['type']==projection.HSM_KIND)
 row['_provenance'].pop(field,None);snapshot.pop('snapshot_id',None)
 out=evaluate_snapshot(snapshot,checks=[hsm.CHECK],include_not_applicable=True)
 assert {f['status'] for f in out['findings'] if f['check_id']==hsm.CHECK}=={'UNKNOWN'}


@pytest.mark.parametrize('cid,mode,expected',[(PRIV,'good','PASS'),(PRIV,'privileged','FAIL'),(NONROOT,'good','PASS'),(NONROOT,'root','FAIL')])
def test_actual_official_kubernetes_sdk_http_to_public_engine(monkeypatch,ca,cid,mode,expected,record_property):
 _,rows,_,apis=aks_capture(monkeypatch,ca,mode,cid,record_property,real_sdk=True)
 assert {f['status'] for f in rows}=={expected}
 assert apis and all(hasattr(api,'api_client') and isinstance(api.api_client.rest_client.pool_manager,k8s._BoundedPool) for api in apis)
