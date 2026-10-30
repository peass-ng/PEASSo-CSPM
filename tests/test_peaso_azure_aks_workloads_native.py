# Historical fixture contracts; current native admission is tested separately.
import copy,json
from datetime import datetime,timedelta,timezone
from types import SimpleNamespace
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes,serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from peaso.collectors import azure,k8s
from peaso.collectors import azure_aks_workloads_native as native
from tests.archived_check_contract import collect_snapshot, evaluate_snapshot
from peaso.server.validation import validate_connector
from tests.test_peaso_azure_bulk_native import Transport,parent,SUB,SCOPE,BASE,envelope
RID=BASE+'Microsoft.ContainerService/managedClusters/cluster';HOST='cluster-123.hcp.eastus.azmk8s.io';TOKEN='private-token-never-persist'
@pytest.fixture(scope='module')
def ca():
 key=rsa.generate_private_key(public_exponent=65537,key_size=2048);name=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'Fixture CA')]);now=datetime.now(timezone.utc)
 return x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key()).serial_number(1).not_valid_before(now-timedelta(days=1)).not_valid_after(now+timedelta(days=1)).add_extension(x509.BasicConstraints(ca=True,path_length=None),critical=True).sign(key,hashes.SHA256()).public_bytes(serialization.Encoding.PEM).decode()
def obj(kind,name,namespace=None,**data):
 meta={'name':name,'uid':kind+'-'+name,'resourceVersion':'42'}
 if namespace:meta['namespace']=namespace
 return {'apiVersion':'v1','kind':kind,'metadata':meta,**data}
def fixture(ca,mode='good'):
 policy={'subscriptions':[{'scope':SCOPE,'images':{'mode':'registries','allowed':['approved.example'],'immutableImages':False,'containerKinds':['containers','initContainers','ephemeralContainers']},'service_ports':{'cluster_id':RID,'evidence_ref':'owner-policy-v1','services':[{'namespace':'default','name':'app','allowed':[{'port':443,'protocol':'TCP'}]}]}}]}
 credentials=[{'cluster_id':RID,'server':'https://'+HOST,'ca_cert_data':ca,'token':TOKEN}]
 cluster=parent(RID,'Microsoft.ContainerService/managedClusters',{'provisioningState':'Succeeded','fqdn':HOST})
 routes={'/subscriptions':{'value':[{'id':SCOPE,'subscriptionId':SUB,'tenantId':Transport.tenant}]},SCOPE+'/providers/Microsoft.ContainerService/managedClusters':{'value':[copy.deepcopy(cluster)]},RID:cluster}
 routes[SCOPE]=routes['/subscriptions']['value'][0]
 namespaces=[obj('Namespace','kube-system'),obj('Namespace','default')]
 pod=obj('Pod','app','default',spec={'containers':[{'name':'app','image':'approved.example/app:v1','env':[{'name':'PASSWORD','value':'private-workload-literal'}]}]},status={})
 service=obj('Service','app','default',spec={'ports':[{'port':443}],'type':'ClusterIP'})
 responses={'/api/v1/namespaces':namespaces,'/api/v1/pods':[pod],'/api/v1/services':[service],'/api/v1/limitranges':[]}
 if mode=='arc_present':routes[SCOPE+'/providers/Microsoft.Kubernetes/connectedClusters']={'value':[parent(BASE+'Microsoft.Kubernetes/connectedClusters/arc','Microsoft.Kubernetes/connectedClusters',{})]}
 if mode=='arc_denied':routes[SCOPE+'/providers/Microsoft.Kubernetes/connectedClusters']=azure.AzureReadError('forbidden',403)
 if mode=='subscription_denied':routes['/subscriptions']=azure.AzureReadError('forbidden',403);routes[SCOPE]=azure.AzureReadError('forbidden',403)
 if mode in ('arm_paged','arm_partial','arm_foreign_page'):
  endpoint=SCOPE+'/providers/Microsoft.ContainerService/managedClusters'
  nextpath=endpoint.replace(SUB,'99999999-9999-9999-9999-999999999999')if mode=='arm_foreign_page'else endpoint
  def pages(query):
   if 'page'in query:
    if mode=='arm_partial':raise azure.AzureReadError('forbidden',403)
    return {'value':[]}
   return {'value':[copy.deepcopy(cluster)],'nextLink':azure.ARM+nextpath+'?api-version=2024-05-01&page=2'}
  routes[endpoint]=pages
 if mode=='wrong_get_name':cluster['name']='foreign'
 if mode=='conflicting_subscription':routes['/subscriptions']['value'].append({'id':SCOPE,'subscriptionId':SUB,'tenantId':'foreign'});routes[SCOPE]={**routes[SCOPE],'subscriptionId':'conflicting-selected-subscription'}
 if mode=='bad_image':pod['spec']['containers'][0]['image']='unapproved.example/app:v1'
 if mode=='bad_port':service['spec']['ports'][0]['port']=80
 if mode=='no_policy':policy=None
 if mode=='digest_missing':policy['subscriptions'][0]['images'].update(mode='digests',allowed=['sha256:'+'a'*64])
 if mode=='foreign_endpoint':cluster['properties']['fqdn']='other.example.net'
 if mode=='private_endpoint':cluster['properties']={'provisioningState':'Succeeded','privateFQDN':HOST}
 if mode=='wrong_get_id':cluster['id']=RID+'other'
 if mode=='wrong_get_type':cluster['type']='Microsoft.Kubernetes/connectedClusters'
 if mode=='foreign_parent':routes[SCOPE+'/providers/Microsoft.ContainerService/managedClusters']['value'][0]['id']=RID.replace(SUB,'99999999-9999-9999-9999-999999999999')
 if mode=='duplicate_parent':routes[SCOPE+'/providers/Microsoft.ContainerService/managedClusters']['value']*=2
 if mode=='no_credentials':credentials=[]
 if mode=='foreign_tenant':routes['/subscriptions']['value'][0]['tenantId']='foreign'
 if mode=='empty_clusters':routes[SCOPE+'/providers/Microsoft.ContainerService/managedClusters']['value']=[];credentials=[]
 if mode in('second_cluster','ambiguous_cluster_uid'):
  other=copy.deepcopy(cluster);other['id']=RID+'2';other['name']='cluster2';other['properties']['fqdn']='cluster2-123.hcp.eastus.azmk8s.io';routes[SCOPE+'/providers/Microsoft.ContainerService/managedClusters']['value'].append(other);routes[RID+'2']=other;credentials.append({**credentials[0],'cluster_id':RID+'2','server':'https://cluster2-123.hcp.eastus.azmk8s.io'})
 if mode=='foreign_namespace':pod['metadata']['namespace']='unknown'
 if mode=='missing_uid':pod['metadata'].pop('uid')
 if mode=='missing_version':pod['metadata'].pop('resourceVersion')
 if mode=='wrong_pod_type':pod['kind']='Service'
 if mode=='duplicate_pod':responses['/api/v1/pods']*=2
 if mode=='duplicate_namespace':namespaces.append(copy.deepcopy(namespaces[0]))
 class Api:
  def __init__(self):self.calls=[];self.closed=False;self.uid_calls=0;self.suffix=''
  def bound(self,value):
   value=copy.deepcopy(value)
   if 'uid'in value.get('metadata',{}):value['metadata']['uid']+=self.suffix
   return value
  def get_json(self,path,params):
   self.calls.append((path,copy.deepcopy(params)))
   if mode=='denied':raise azure.AzureReadError('forbidden',403)
   if mode=='unreachable':raise ConnectionError('unreachable')
   if path=='/api/v1/namespaces/kube-system':
    self.uid_calls+=1;value=copy.deepcopy(namespaces[0])
    if mode=='uid_changed'and self.uid_calls>1:value['metadata']['uid']='changed'
    if mode=='uid_malformed':value['metadata'].pop('uid')
    return self.bound(value)
   rows=[self.bound(x)for x in responses[path]];continuation=''
   if mode in ('paged','partial','version_changed','repeated_token','page_cap')and path=='/api/v1/pods':
    if params.get('continue'):
     if mode=='partial':raise azure.AzureReadError('forbidden',403)
     rows=[];continuation='next'if mode=='repeated_token'else''
    else:continuation='next'
   return {'apiVersion':'v1','kind':{'/api/v1/namespaces':'NamespaceList','/api/v1/pods':'PodList','/api/v1/services':'ServiceList','/api/v1/limitranges':'LimitRangeList'}[path],'metadata':{'resourceVersion':None if mode=='missing_list_version'else'43'if mode=='version_changed'and params.get('continue')else'42','continue':continuation},'items':rows}
  def close(self):self.closed=True
 options={'retries':0,'concurrency':1}
 if policy:options['compliance_parameters']={native.OPTION:policy}
 if mode=='page_cap':options['max_pages']=1
 if mode=='resource_cap':options['max_resources']=3
 if mode=='call_cap':options['max_calls']=3
 auth={'tenant_id':Transport.tenant,'arm_token':'explicit-arm-token'}
 if credentials:auth['aks_workloads']=credentials
 return routes,responses,options,auth,Api

def capture(monkeypatch,ca,mode='good',checks=None,hosted=False):
 routes,responses,options,auth,Api=fixture(ca,mode);arm=Transport(routes);arm.close=lambda:None
 if hosted:
  options['retries']=1
  validate_connector('azure',auth,options,SimpleNamespace(auth_mode='cognito'))
  options['hosted']=True
 if mode=='unverified_tenant':arm.verified_tenant=None
 apis=[];contexts=[]
 def new_api(context):contexts.append(copy.deepcopy(context));api=Api();api.suffix='-second'if context['server'].startswith('https://cluster2-')and mode!='ambiguous_cluster_uid'else'';apis.append(api);return api
 monkeypatch.setattr(azure,'AzureTransport',lambda auth:arm);monkeypatch.setattr(azure,'AzureTransportExposure',lambda auth:arm);monkeypatch.setattr(k8s,'_new_api',new_api)
 checks=checks or [native.IMAGES,native.PORTS]
 snapshot=collect_snapshot({'connector':{'provider':'azure','scopes':[SUB],'auth':auth,'options':options},'checks':checks});report=evaluate_snapshot(snapshot,checks=checks)
 assert TOKEN not in json.dumps(snapshot)and'private-workload-literal'not in json.dumps(snapshot)
 assert all(api.closed for api in apis)
 return snapshot,{f['check_id']:f['status']for f in report['findings']},arm,apis,contexts

@pytest.mark.parametrize('mode,images,ports',[
 ('good','PASS','PASS'),('private_endpoint','PASS','PASS'),('paged','PASS','PASS'),('bad_image','FAIL','PASS'),('bad_port','PASS','FAIL'),('no_policy','UNKNOWN','UNKNOWN'),('digest_missing','UNKNOWN','PASS'),('foreign_endpoint','UNKNOWN','UNKNOWN'),('wrong_get_id','UNKNOWN','UNKNOWN'),('wrong_get_type','UNKNOWN','UNKNOWN'),('foreign_parent','UNKNOWN','UNKNOWN'),('duplicate_parent','UNKNOWN','UNKNOWN'),('no_credentials','UNKNOWN','UNKNOWN'),('foreign_tenant','UNKNOWN','UNKNOWN'),('unverified_tenant','UNKNOWN','UNKNOWN'),('foreign_namespace','UNKNOWN','UNKNOWN'),('missing_uid','UNKNOWN','UNKNOWN'),('missing_version','UNKNOWN','UNKNOWN'),('wrong_pod_type','UNKNOWN','UNKNOWN'),('duplicate_pod','UNKNOWN','UNKNOWN'),('duplicate_namespace','UNKNOWN','UNKNOWN'),('denied','DENIED','DENIED'),('unreachable','UNKNOWN','UNKNOWN'),('uid_changed','UNKNOWN','UNKNOWN'),('uid_malformed','UNKNOWN','UNKNOWN'),('partial','UNKNOWN','UNKNOWN'),('version_changed','UNKNOWN','UNKNOWN'),('repeated_token','UNKNOWN','UNKNOWN'),('second_cluster','PASS','UNKNOWN'),('ambiguous_cluster_uid','UNKNOWN','UNKNOWN'),('page_cap','UNKNOWN','UNKNOWN'),('resource_cap','UNKNOWN','UNKNOWN'),('call_cap','UNKNOWN','UNKNOWN'),('missing_list_version','UNKNOWN','UNKNOWN'),('arc_present','UNKNOWN','UNKNOWN'),('arc_denied','UNKNOWN','UNKNOWN'),('subscription_denied','UNKNOWN','UNKNOWN'),('arm_paged','PASS','PASS'),('arm_partial','UNKNOWN','UNKNOWN'),('arm_foreign_page','UNKNOWN','UNKNOWN'),('wrong_get_name','UNKNOWN','UNKNOWN'),('conflicting_subscription','UNKNOWN','UNKNOWN')])
def test_public_native_pipeline(monkeypatch,ca,mode,images,ports):
 snapshot,status,arm,apis,contexts=capture(monkeypatch,ca,mode)
 assert status[native.IMAGES]==images and status[native.PORTS]==ports,(status,[c for c in snapshot['collections']if c['type']in native.NATIVE_TYPES])
 if mode in('foreign_endpoint','foreign_tenant','unverified_tenant','no_credentials','wrong_get_id','wrong_get_type','foreign_parent','duplicate_parent'):assert not contexts
 if contexts:assert all(c['_disable_proxy']is True and c['method']=='token'for c in contexts)
 if mode=='paged':assert any(p.get('continue')=='next'for api in apis for path,p in api.calls)
@pytest.mark.parametrize('method',['local','cognito'])
def test_hosted_normative_and_credential_roundtrip(monkeypatch,ca,method):
 _,_,options,auth,_=fixture(ca);options['retries']=1;validate_connector('azure',auth,options,SimpleNamespace(auth_mode=method))
 snapshot,status,_,_,contexts=capture(monkeypatch,ca,hosted=method=='cognito');assert all(c['_hosted']==(method=='cognito')for c in contexts);assert status=={native.IMAGES:'PASS',native.PORTS:'PASS'}
 assert snapshot['metadata']['sw22']['approved_service_ports']['evidence_ref']=='owner-policy-v1'
@pytest.mark.parametrize('server',['https://other.example.net:443','https://user@other.example.net','https://other.example.net/','https://other.example.net?x=1','https://other.example.net#f','http://other.example.net','https://OTHER.example.net','https://other.example.net.','https://xn--other.example.net','https://127.0.0.1','https://éxample.net','https://other.example.net?','https://other.example.net#','https://other.example.net\n'])
def test_invalid_origin_rejected_before_transport(monkeypatch,ca,server):
 _,_,options,auth,_=fixture(ca);auth['aks_workloads'][0]['server']=server
 monkeypatch.setattr(azure,'AzureTransport',lambda auth:pytest.fail('transport before normalization'));monkeypatch.setattr(azure,'AzureTransportExposure',lambda auth:pytest.fail('transport before normalization'))
 with pytest.raises(ValueError):azure.collect({'auth':auth,'options':options,'scopes':[SUB]},['pod'])
 for provider in ('azure','aws'):
  with pytest.raises(Exception):validate_connector(provider,auth,options,SimpleNamespace(auth_mode='local'))
@pytest.mark.parametrize('field,value',[('proxy','http://proxy'),('exec',{'command':'anything'}),('insecure-skip-tls-verify',True),('cluster_uid','fabricated'),('uid_verified',True)])
def test_no_observation_or_transport_override_inputs(ca,field,value):
 _,_,options,auth,_=fixture(ca);auth['aks_workloads'][0][field]=value
 with pytest.raises(ValueError):native.normalize(options,auth)
def test_real_client_disables_environment_proxy_and_redirects(monkeypatch,ca):
 from kubernetes import client
 monkeypatch.setenv('HTTPS_PROXY','http://ambient.example.net:8080');captured=[];original=client.ApiClient
 def factory(configuration):captured.append(configuration);return original(configuration)
 monkeypatch.setattr(client,'ApiClient',factory)
 api=k8s._new_api({'method':'token','server':'https://'+HOST,'token':TOKEN,'ca_cert_data':ca,'_disable_proxy':True})
 try:
  config=captured[0];assert config.verify_ssl is True and config.proxy is None and config.proxy_headers is None
  assert api.api_client.rest_client.pool_manager.__class__.__name__=='_BoundedPool'
 finally:api.close()


@pytest.mark.parametrize('field,value',[('ca_cert_data','not-a-certificate'),('ca_cert_data','-----BEGIN PRIVATE KEY-----'),('token','has whitespace'),('token',''),('cluster_id','arn:aws:eks:us-east-1:123456789012:cluster/example')])
def test_invalid_context_before_auth_transport(monkeypatch,ca,field,value):
 _,_,options,auth,_=fixture(ca);auth['aks_workloads'][0][field]=value
 monkeypatch.setattr(azure,'AzureTransport',lambda auth:pytest.fail('transport before input rejection'));monkeypatch.setattr(azure,'AzureTransportExposure',lambda auth:pytest.fail('transport before input rejection'))
 with pytest.raises(ValueError):azure.collect({'auth':auth,'options':options,'scopes':[SUB]},['pod'])

@pytest.mark.parametrize('owner_field',['pods','inventory_complete','cluster_uid','source_operation','approved'])
def test_owner_policy_cannot_claim_native_observations(ca,owner_field):
 _,_,options,auth,_=fixture(ca);options['compliance_parameters'][native.OPTION]['subscriptions'][0]['images'][owner_field]=True
 with pytest.raises(ValueError):native.normalize(options,auth)

def test_foreign_selected_subscription_before_transport(monkeypatch,ca):
 _,_,options,auth,_=fixture(ca)
 monkeypatch.setattr(azure,'AzureTransport',lambda auth:pytest.fail('transport before binding rejection'));monkeypatch.setattr(azure,'AzureTransportExposure',lambda auth:pytest.fail('transport before binding rejection'))
 with pytest.raises(ValueError):azure.collect({'auth':auth,'options':options,'scopes':['99999999-9999-9999-9999-999999999999']},['pod'])

def test_limit_range_is_actual_list_not_runtime_evidence(monkeypatch,ca):
 routes,_,options,auth,Api=fixture(ca);arm=Transport(routes);api=Api()
 monkeypatch.setattr(k8s,'_new_api',lambda auth:api)
 snapshot=azure.collect({'auth':auth,'options':options,'scopes':[SUB]},['limit_range'],transport=arm)
 assert envelope(snapshot,'limit_range')['status']=='empty'
 assert any(path=='/api/v1/limitranges'for path,_ in api.calls)
 assert not any(c['type']=='pod_runtime'and c['status']=='collected'for c in snapshot['collections'])

def test_only_images_selected_does_not_read_services(monkeypatch,ca):
 snapshot,status,_,apis,_=capture(monkeypatch,ca,checks=[native.IMAGES])
 assert status[native.IMAGES]=='PASS'
 assert all(path!='/api/v1/services'for api in apis for path,_ in api.calls)
 assert all(c['type']!='service'or c['status']=='not_collected'for c in snapshot['collections'])


def test_planner_parent_expansion_preserves_selection_and_explicit_inventories(ca):
 from tests.archived_check_contract import plan_collection
 from peaso.collectors.bulk_evidence import expand_native_requirements
 _,_,options,auth,_=fixture(ca)
 req=plan_collection({'connector':{'provider':'azure','scopes':[SUB],'auth':auth,'options':options},'checks':[native.IMAGES]})
 assert set(req)=={'kubernetes_scope','pod','aks_cluster','arc_kubernetes_cluster','subscription'}
 assert 'service'not in req and'pod_runtime'not in req
 assert expand_native_requirements('azure',{'service'})=={'service','aks_cluster','arc_kubernetes_cluster','subscription'}

@pytest.mark.parametrize('missing',['images','service_ports'])
def test_missing_one_policy_never_disables_other(monkeypatch,ca,missing):
 routes,_,options,auth,Api=fixture(ca);options['compliance_parameters'][native.OPTION]['subscriptions'][0].pop(missing)
 arm=Transport(routes);arm.close=lambda:None
 monkeypatch.setattr(azure,'AzureTransport',lambda auth:arm);monkeypatch.setattr(azure,'AzureTransportExposure',lambda auth:arm);monkeypatch.setattr(k8s,'_new_api',lambda auth:Api())
 snapshot=collect_snapshot({'connector':{'provider':'azure','scopes':[SUB],'auth':auth,'options':options},'checks':[native.IMAGES,native.PORTS]})
 status={f['check_id']:f['status']for f in evaluate_snapshot(snapshot,checks=[native.IMAGES,native.PORTS])['findings']}
 assert status[native.IMAGES]==('UNKNOWN'if missing=='images'else'PASS')
 assert status[native.PORTS]==('UNKNOWN'if missing=='service_ports'else'PASS')


def test_nested_auth_redaction_keeps_public_binding_and_removes_bearer(ca):
 from peaso.auth.secrets import credential_values,redact
 _,_,options,auth,_=fixture(ca)
 secrets=tuple(credential_values(auth))
 assert TOKEN in secrets and RID not in secrets
 public=redact({'cluster_id':RID,'token':TOKEN,'diagnostic':TOKEN},secrets)
 assert public['cluster_id']==RID and TOKEN not in json.dumps(public)
