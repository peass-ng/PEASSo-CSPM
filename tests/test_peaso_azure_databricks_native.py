"""Native Account/ARM joins and privacy, denial and complete-universe boundaries."""
import copy,json
from types import SimpleNamespace
import pytest
from fastapi import HTTPException
from peaso.collectors import azure,collect_live
from peaso.collectors import azure_databricks_native as native
from tests.archived_check_contract import collect_snapshot
from tests.test_peaso_azure_bulk_native import Transport,parent,SUB,SCOPE,BASE,verdict
CHECK='azure.cis.unity_catalog_configured_databricks'
ACCOUNT='33333333-3333-3333-3333-333333333333';META='44444444-4444-4444-4444-444444444444'
RID=BASE+'Microsoft.Databricks/workspaces/example';PATH='/api/2.0/accounts/'+ACCOUNT+'/workspaces';TOKEN='private-controlled-token'
def policy():return {'sw33':{'status':'collected','scope':SCOPE,'databricksAccount':{'accountId':ACCOUNT}}}
class API(Transport):
 def request_databricks(self,url):
  path=native.endpoint(url);self.calls.append(url);value=self.routes.get(path)
  if isinstance(value,Exception):raise value
  if value=={'httpStatus':404,'documentedNoAssignment':True}:return value.copy()
  return native.project_response(copy.deepcopy(value),path)
def capture(mode='good',via='direct'):
 raw=parent(RID,'Microsoft.Databricks/workspaces',{'workspaceId':'123','provisioningState':'Succeeded','clientSecret':TOKEN})
 arm=SCOPE+'/providers/Microsoft.Databricks/workspaces'
 row={'workspace_id':123,'account_id':ACCOUNT,'workspace_status':'RUNNING','cloud':'azure','azure_workspace_info':{'subscription_id':SUB,'resource_group':'rg'},'credentials_id':TOKEN}
 routes={arm:{'value':[raw]},RID:raw,PATH:[row],PATH+'/123':row,PATH+'/123/metastore':{'metastore_assignment':{'workspace_id':123,'metastore_id':META,'default_catalog_name':TOKEN}}}
 auth={'tenant_id':Transport.tenant,'databricks_account_token':TOKEN};p=policy();options={}
 if mode=='empty':routes[arm]={'value':[]};routes[PATH]=[]
 if mode=='missing_approval':p={}
 if mode=='foreign_approval':p['sw33']['scope']=SCOPE.replace(SUB,ACCOUNT)
 if mode=='missing_token':auth.pop('databricks_account_token')
 if mode=='assignment_absent':routes[PATH+'/123/metastore']={'httpStatus':404,'documentedNoAssignment':True}
 for key,path in [('denied',PATH),('assignment_denied',PATH+'/123/metastore'),('arm_denied',arm),('arm_get_denied',RID)]:
  if mode==key:routes[path]=azure.AzureReadError('forbidden',403)
 if mode=='arm_partial':routes[arm]={'value':[raw],'nextLink':azure.ARM+arm+'?api-version=2024-05-01&page=2'};options['max_pages']=1
 if mode=='list_object_partial':routes[PATH]={'workspaces':[row],'next_page_token':'unread'}
 if mode=='foreign_account':row['account_id']=META
 if mode=='foreign_rg':row['azure_workspace_info']['resource_group']='foreign'
 if mode=='foreign_sub':row['azure_workspace_info']['subscription_id']=META
 if mode=='foreign_cloud':row['cloud']='aws'
 if mode=='missing_cloud':row.pop('cloud')
 if mode=='missing_info':row.pop('azure_workspace_info')
 if mode=='non_running':row['workspace_status']='PROVISIONING'
 if mode=='duplicate_account':routes[PATH].append(copy.deepcopy(row))
 if mode=='missing_account_workspace':routes[PATH]=[]
 if mode=='extra_account_workspace':routes[PATH].append({**copy.deepcopy(row),'workspace_id':124})
 if mode=='arm_duplicate':routes[arm]['value']*=2
 if mode=='arm_list_conflict':routes[arm]['value'].append({**copy.deepcopy(raw),'properties':{'workspaceId':'999'}})
 if mode=='absence_workspace_denied':routes[PATH+'/123/metastore']={'httpStatus':404,'documentedNoAssignment':True};routes[PATH+'/123']=azure.AzureReadError('forbidden',403)
 if mode=='absence_workspace_changed':routes[PATH+'/123/metastore']={'httpStatus':404,'documentedNoAssignment':True};routes[PATH+'/123']={**copy.deepcopy(row),'workspace_status':'PROVISIONING'}
 if mode=='account_bool_id':row['workspace_id']=True
 if mode=='arm_id_changed':raw['id']=RID+'foreign'
 if mode=='arm_type_changed':raw['type']='Microsoft.Compute/virtualMachines'
 if mode=='arm_not_ready':raw['properties']['provisioningState']='Updating'
 if mode=='arm_workspace_id_missing':raw['properties'].pop('workspaceId')
 if mode=='arm_workspace_id_bool':raw['properties']['workspaceId']=True
 if mode=='assignment_wrong_id':routes[PATH+'/123/metastore']['metastore_assignment']['workspace_id']=456
 if mode=='opaque_metastore':routes[PATH+'/123/metastore']['metastore_assignment']['metastore_id']='opaque-native-metastore-id'
 if mode=='assignment_wrong_meta':routes[PATH+'/123/metastore']['metastore_assignment']['metastore_id']=''
 if mode=='assignment_missing_body':routes[PATH+'/123/metastore']={}
 if mode=='budget':options['max_calls']=1
 if mode=='other_subscription':routes[PATH].append({**copy.deepcopy(row),'workspace_id':999,'azure_workspace_info':{'subscription_id':META,'resource_group':'other'}})
 if mode=='sw33_siblings':
  table=BASE+'Microsoft.Network/routeTables/routes'
  p['sw33']['routeDestinations']={'routeTableIds':[table],'allowedDestinationCidrs':['10.0.0.0/8']}
  p['sw33']['classification']={'tagKey':'classification','assets':[]}
  p['sw33']['observed_at']='2026-10-15T00:00:00Z';p['sw33']['max_age_seconds']=86400
  routes[SCOPE+'/providers/Microsoft.Network/routeTables']={'value':[parent(table,'Microsoft.Network/routeTables',{'routes':[{'id':table+'/routes/approved','properties':{'addressPrefix':'10.0.0.0/24'}}]})]}
  listed=routes[SCOPE+'/providers/Microsoft.Network/routeTables']['value'][0]
  routes[table]=listed
  routes[SCOPE+'/resources']={'value':[raw,listed]}
  routes['/providers/Microsoft.ResourceGraph/resources']={'data':[raw,listed],'count':2,'totalRecords':2,'resultTruncated':'false'}
 connector={'provider':'azure','scopes':[SUB],'auth':auth,'options':{'retries':0,'compliance_policy':p,**options}};api=API(routes);old=azure.AzureTransport;old_exposure=azure.AzureTransportExposure;api.close=lambda:None
 try:
  if via=='direct':snap=azure.collect(connector,[native.KIND]+(['route_table']if mode=='sw33_siblings'else[]),transport=api)
  else:
   azure.AzureTransport=azure.AzureTransportExposure=lambda auth:api
   snap=collect_live(connector,[native.KIND]+(['route_table']if mode=='sw33_siblings'else[]))if via=='dispatcher'else collect_snapshot({'connector':connector,'checks':[CHECK]+(['azure_route_table_network_http_internet_access_restricted_5cd2484']if mode=='sw33_siblings'else[])})
 finally:azure.AzureTransport,azure.AzureTransportExposure=old,old_exposure
 assert TOKEN not in json.dumps(snap)
 return snap,api
GOOD=[('good','PASS'),('empty','PASS'),('assignment_absent','FAIL'),('other_subscription','PASS'),('opaque_metastore','PASS')]
BAD=['missing_approval','foreign_approval','missing_token','denied','assignment_denied','arm_denied','arm_get_denied','arm_partial','list_object_partial','foreign_account','foreign_rg','foreign_sub','foreign_cloud','missing_cloud','missing_info','non_running','duplicate_account','missing_account_workspace','extra_account_workspace','account_bool_id','arm_id_changed','arm_type_changed','arm_not_ready','arm_workspace_id_missing','arm_workspace_id_bool','assignment_wrong_id','assignment_wrong_meta','assignment_missing_body','budget','arm_duplicate','arm_list_conflict','absence_workspace_denied','absence_workspace_changed']
@pytest.mark.parametrize('mode,expected',GOOD+[(x,'DENIED'if x in('denied','assignment_denied','arm_get_denied','absence_workspace_denied')else'UNKNOWN')for x in BAD])
def test_native_account_workspace_to_signed_engine(mode,expected):
 snap,api=capture(mode);assert verdict(snap,CHECK)==expected
 if mode in('missing_token','missing_approval','foreign_approval'):assert not any(u.startswith(native.HOST)for u in api.calls)
@pytest.mark.parametrize('via',['dispatcher','planner'])
@pytest.mark.parametrize('mode,expected',[('good','PASS'),('assignment_absent','FAIL'),('assignment_denied','DENIED')])
def test_public_live_pipeline(via,mode,expected):assert verdict(capture(mode,via)[0],CHECK)==expected
@pytest.mark.parametrize('url',[native.HOST.replace('https','http')+PATH,native.HOST+':443'+PATH,native.HOST+'.evil'+PATH,'https://user@accounts.azuredatabricks.net'+PATH,native.HOST+PATH+'?token=secret',native.HOST+PATH+'#frag',native.HOST+PATH+'/',native.HOST+PATH+'/0/metastore',native.HOST+PATH+'/123/../metastore',native.HOST+PATH+'%2f123/metastore','https://accounts.azuredatabricks.net%2eevil'+PATH])
def test_foreign_endpoint_before_network(url):
 with pytest.raises(ValueError):native.request_metadata(url,{'databricks_account_token':TOKEN})
@pytest.mark.parametrize('value',[None,True,'','a\nb','x'*16385])
def test_typed_credential_cap(value):
 with pytest.raises(ValueError):native.validate_auth({'databricks_account_token':value})
def test_secret_redaction():
 from peaso.auth import redact
 from peaso.auth.secrets import credential_values
 assert redact({'databricks_account_token':TOKEN})['databricks_account_token']=='[REDACTED]'
 assert list(credential_values({'databricks_account_token':TOKEN}))==[TOKEN]
@pytest.mark.parametrize('extra',[{'metastore_id':META},{'status':'PASS'},{'workspaceIds':[123]},{'token':TOKEN}])
def test_owner_not_observations(extra):
 p=policy();p['sw33']['databricksAccount'].update(extra)
 with pytest.raises(ValueError):native.normalize({'compliance_policy':p})
def test_hosted_auth_policy_roundtrip():
 from peaso.server.validation import validate_connector
 auth={'method':'token','arm_token':'controlled-arm-token','databricks_account_token':TOKEN};settings=SimpleNamespace(auth_mode='cognito')
 validate_connector('azure',auth,{'compliance_policy':policy()},settings)
 with pytest.raises(HTTPException):validate_connector('azure',{**auth,'databricks_account_token':'x'*16385},{'compliance_policy':policy()},settings)
 p=policy();p['sw33']['databricksAccount']['metastore_id']=META
 with pytest.raises(HTTPException):validate_connector('azure',auth,{'compliance_policy':p},settings)

@pytest.mark.parametrize('kind',['list','assignment','get','oversize','duplicate_json','malformed_json','no_token','not_found_assignment','not_found_list','denied'])
def test_real_transport_metadata_only_bounds(monkeypatch,kind):
 from urllib.error import HTTPError
 events=[]
 path=PATH+'/123/metastore'if kind in('assignment','not_found_assignment')else PATH+'/123'if kind=='get'else PATH
 value={'workspace_id':123,'account_id':ACCOUNT,'workspace_status':'RUNNING','cloud':'azure','azure_workspace_info':{'subscription_id':SUB,'resource_group':'rg'},'credentials_id':TOKEN}
 payload={'metastore_assignment':{'workspace_id':123,'metastore_id':META,'privateToken':TOKEN}}if kind=='assignment'else value if kind=='get'else[value]
 body=json.dumps(payload).encode()
 if kind=='oversize':body=b' '* (native.MAX_RESPONSE_BYTES+1)
 if kind=='duplicate_json':body=b'[{"workspace_id":123,"workspace_id":456}]'
 if kind=='malformed_json':body=b'not-json'
 class Response:
  def __enter__(self):return self
  def __exit__(self,*args):return False
  def read(self,size):assert size==native.MAX_RESPONSE_BYTES+1;return body
 class Opener:
  def open(self,req,timeout):
   events.append(req.full_url);assert req.get_method()=='GET'and req.data is None and timeout==20
   assert req.get_header('Authorization')=='Bearer '+TOKEN
   if kind.startswith('not_found_'):raise HTTPError(req.full_url,404,'not found',{},None)
   if kind=='denied':raise HTTPError(req.full_url,403,'private response '+TOKEN,{},None)
   return Response()
 def opener(*handlers):
  assert any(isinstance(h,native.ProxyHandler)and h.proxies=={}for h in handlers)
  return Opener()
 monkeypatch.setattr(native,'build_opener',opener)
 if kind in('oversize','duplicate_json','malformed_json','no_token','not_found_list','denied'):
  with pytest.raises((ValueError,azure.AzureReadError)):native.request_metadata(native.HOST+path,{}if kind=='no_token'else{'databricks_account_token':TOKEN})
  if kind=='no_token':assert events==[]
 else:
  result=native.request_metadata(native.HOST+path,{'databricks_account_token':TOKEN});assert TOKEN not in json.dumps(result)
  if kind=='not_found_assignment':assert result=={'httpStatus':404,'documentedNoAssignment':True}

def test_redirect_is_rejected_without_followup():
 with pytest.raises(ValueError):native._NoRedirect().redirect_request(None,None,302,'',{},'https://foreign.example/')

def test_hosted_cannot_store_credential_as_option_or_policy():
 from peaso.server.validation import validate_connector
 settings=SimpleNamespace(auth_mode='cognito');auth={'method':'token','arm_token':'controlled-arm-token'}
 with pytest.raises(HTTPException):validate_connector('azure',auth,{'databricks_account_token':TOKEN},settings)

def test_real_api_connector_encrypts_and_redacts_account_token(tmp_path,caplog,monkeypatch):
 from tests.connector_access_receipts import checked_create, mock_access_pass
 mock_access_pass(monkeypatch)
 from fastapi.testclient import TestClient
 from peaso.server import create_app
 from peaso.server.config import Settings
 from tests.test_peaso_api import TestIdentities
 settings=Settings(state_dir=tmp_path/'state',identity_dir=tmp_path/'identity',local_token='controlled-local-api-token')
 with TestClient(create_app(settings,authenticator=TestIdentities()),base_url='http://127.0.0.1:8000')as client:
  client.headers['Authorization']='Bearer alice'
  response=client.post('/api/connectors',json=checked_create(client,{'name':'Databricks fixture','provider':'azure','scopes':[SUB],'auth':{'method':'token','arm_token':'controlled-arm-token','databricks_account_token':TOKEN},'options':{'compliance_policy':policy()}}))
  assert response.status_code==201,response.text
  assert TOKEN not in response.text and 'databricks_account_token'in response.json()['auth']['fields']
  assert TOKEN not in client.get('/api/connectors').text
  assert TOKEN not in client.get('/api/connectors/'+response.json()['id']).text
 assert TOKEN not in caplog.text
 assert TOKEN.encode()not in(settings.state_dir/'peaso.sqlite3').read_bytes()


@pytest.mark.parametrize('via',['direct','dispatcher','planner'])
def test_sw33_independent_owner_requirements_and_authority_survive_native_merge(via):
 snap,api=capture('sw33_siblings',via)
 sw33=snap['metadata']['compliance_policy']['sw33'];table=BASE+'Microsoft.Network/routeTables/routes'
 assert sw33['routeDestinations']=={'routeTableIds':[table],'allowedDestinationCidrs':['10.0.0.0/8']}
 assert sw33['classification']=={'tagKey':'classification','assets':[]}
 assert sw33['status']=='collected'and sw33['scope']==SCOPE
 assert sw33['observed_at']=='2026-10-15T00:00:00Z'and sw33['max_age_seconds']==86400
 assert verdict(snap,CHECK)=='PASS'
 assert verdict(snap,'azure_route_table_network_http_internet_access_restricted_5cd2484')=='PASS'
