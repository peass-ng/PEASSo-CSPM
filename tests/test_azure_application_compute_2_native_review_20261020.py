"""Independent native HTTP -> Azure collector -> public engine for exact38 IDs.
No CASES, historical favorable fixtures, credential grants or derived access flags.
"""
from copy import deepcopy
import json
import socket
from urllib.parse import urlsplit,parse_qs
import pytest
from peaso.checks import CHECKS
from peaso.collectors import azure
from tests.archived_check_contract import evaluate_snapshot
from peaso.snapshot import validate

SUB='11111111-1111-1111-1111-111111111111'
TENANT='22222222-2222-2222-2222-222222222222'
PRINCIPAL='abcdef12-3456-789a-bcde-f0123456789a'
SCOPE='/subscriptions/'+SUB
BASE=SCOPE+'/resourceGroups/native-app2/providers/'
SITE=BASE+'Microsoft.Web/sites/native-site'
SLOT=SITE+'/slots/staging'
VNET=BASE+'Microsoft.Network/virtualNetworks/native-vnet'
AUTO=BASE+'Microsoft.Automation/automationAccounts/native-account'
REGISTRY={c.id:c for c in CHECKS}
IDS=('azure.claude2.prowler_app_http_logs', 'azure.claude2.prowler_app_identity', 'azure.claude2.prowler_function_ftp_ftps_disabled', 'azure.claude2.prowler_function_identity', 'azure.claude2.prowler_function_identity_not_admin', 'azure.claude2.prowler_function_not_public', 'azure.claude2.prowler_function_vnet_integration', 'azure.claude2.vmss_encryption_at_host', 'azure.claude2.web_app_always_on', 'azure.claude2.web_app_authentication_enabled', 'azure.claude2.web_app_client_certificates', 'azure.claude2.web_app_diagnostic_http_log_category', 'azure.claude2.web_app_diagnostic_logs_enabled', 'azure.claude2.web_app_failed_request_tracing', 'azure.claude2.web_app_ftps_required', 'azure.claude2.web_app_health_check', 'azure.claude2.web_app_incoming_client_cert', 'azure.claude2.web_app_managed_identity', 'azure.claude2.web_app_register_with_entra', 'azure.claude2.web_app_remote_debugging_disabled', 'azure.claude2.web_app_slot_https_only', 'azure.claude2.web_app_vnet_connection', 'azure.disk.entra_export_auth', 'azure.disk.private_export', 'azure.gap.automation_account_encrypted_with_cmk', 'azure.htbp.acr.anonymous_pull_disabled', 'azure.htbp.appservice.ftp_basic_auth_disabled', 'azure.htbp.appservice.scm_basic_auth_disabled', 'azure.htbp.appservice.scm_site_restricted_like_main', 'azure.htbp.automation.webhook_expiry_bounded', 'azure.htbp.synapse.firewall_no_allow_all_internet', 'azure.port.databricks_workspace_deployed_in_custom_vnet', 'azure.port.databricks_workspace_no_public_ip_enabled', 'azure.port.databricks_workspace_public_network_access_disabled', 'azure.port.databricks_workspace_uses_private_endpoint', 'azure_pci_10_2_1_1_16', 'azure_pci_1_3_1_33', 'azure_synapse_workspace_1_2_8_29_fcdc827')
ENDPOINTS={
 'app_service':('Microsoft.Web/sites','2023-12-01',SITE),
 'container_registry':('Microsoft.ContainerRegistry/registries','2023-07-01',BASE+'Microsoft.ContainerRegistry/registries/nativeregistry'),
 'automation_account':('Microsoft.Automation/automationAccounts','2023-11-01',AUTO),
 'disk':('Microsoft.Compute/disks','2023-10-02',BASE+'Microsoft.Compute/disks/native-disk'),
 'databricks_workspace':('Microsoft.Databricks/workspaces','2024-05-01',BASE+'Microsoft.Databricks/workspaces/native-workspace'),
 'synapse_workspace':('Microsoft.Synapse/workspaces','2021-06-01',BASE+'Microsoft.Synapse/workspaces/native-synapse'),
 'container_group':('Microsoft.ContainerInstance/containerGroups','2023-05-01',BASE+'Microsoft.ContainerInstance/containerGroups/native-group'),
 'vm_scale_set':('Microsoft.Compute/virtualMachineScaleSets','2024-07-01',BASE+'Microsoft.Compute/virtualMachineScaleSets/native-scale'),
 'role_assignment':('Microsoft.Authorization/roleAssignments','2022-04-01',SCOPE+'/providers/Microsoft.Authorization/roleAssignments/33333333-3333-3333-3333-333333333333'),
}
# Independently enumerated documented metadata child operations, not runtime tables.
LISTS={
 'app_service':[('slots','2023-12-01'),('virtualNetworkConnections','2023-12-01')],
 'container_registry':[(x,'2023-07-01') for x in ('replications','tokens','scopeMaps','cacheRules')],
 'automation_account':[('variables','2023-11-01'),('webhooks','2015-10-31')],
 'synapse_workspace':[(x,'2021-06-01') for x in ('sqlPools','firewallRules','vulnerabilityAssessments')],
}
SINGLE=[('config/web','2023-12-01'),('config/logs','2023-12-01'),('config/authsettingsV2','2025-03-01'),('basicPublishingCredentialsPolicies/scm','2023-12-01'),('basicPublishingCredentialsPolicies/ftp','2023-12-01')]
UNRESOLVED_POSITIVE={'azure.gap.automation_account_encrypted_with_cmk','azure_pci_10_2_1_1_16'}

@pytest.fixture(autouse=True)
def no_live(monkeypatch):
 attempts=[]
 def blocked(*args,**kwargs):attempts.append('socket/DNS/auth');raise AssertionError('Native38 forbids real socket/DNS/auth')
 for name in ('create_connection','getaddrinfo','gethostbyname','gethostbyname_ex','gethostbyaddr','getnameinfo'):monkeypatch.setattr(socket,name,blocked)
 for name in ('connect','connect_ex','sendto'):monkeypatch.setattr(socket.socket,name,blocked)
 monkeypatch.setattr(azure,'credential_for',blocked);monkeypatch.setattr(azure,'AzureTransport',blocked)
 yield
 assert not attempts,attempts

def resource(rid,typ,props=None,**kw):return {'id':rid,'name':rid.rsplit('/',1)[-1],'type':typ,'location':'eastus','properties':{} if props is None else props,**kw}
def put(obj,path,value,remove=False):
 parts=path.split('.');target=obj
 for part in parts[:-1]:target=target[part]
 if remove:target.pop(parts[-1],None)
 else:target[parts[-1]]=deepcopy(value)

def native_case(cid,mode):
 kind=REGISTRY[cid].kind
 if kind=='app_service_slot':kind='app_service'
 typ,version,rid=ENDPOINTS[kind];obj=resource(rid,typ,{'provisioningState':'Succeeded'});others=[];children={};slug=cid.split('.')[-1]
 def scalar(target,path,good,bad):
  put(target,path,bad if mode=='bad' else good)
  return target,path
 if kind=='app_service':
  obj.update(kind='functionapp,linux' if 'prowler_function_' in slug else 'app')
  obj['properties'].update(reserved=False,publicNetworkAccess='Enabled',clientCertEnabled=True,clientCertMode='Required',virtualNetworkSubnetId=VNET+'/subnets/apps')
  if 'function' in obj['kind']:obj['properties']['reserved']=True
  obj['identity']={'type':'SystemAssigned','principalId':PRINCIPAL,'tenantId':TENANT}
  cfg=resource(SITE+'/config/web','Microsoft.Web/sites/config',{'alwaysOn':True,'healthCheckPath':'/health','remoteDebuggingEnabled':False,'ftpsState':'FtpsOnly','vnetName':None,'detailedErrorLoggingEnabled':True,'httpLoggingEnabled':True,'requestTracingEnabled':True,'ipSecurityRestrictions':[{'ipAddress':'10.0.0.0/8','action':'Allow','priority':100}],'ipSecurityRestrictionsDefaultAction':'Deny','scmIpSecurityRestrictionsUseMain':True,'scmIpSecurityRestrictions':[],'scmIpSecurityRestrictionsDefaultAction':'Allow'})
  children[SITE+'/config/web']=cfg
  children[SITE+'/config/logs']=resource(SITE+'/config/logs','Microsoft.Web/sites/config',{'failedRequestsTracing':{'enabled':True},'httpLogs':{'fileSystem':{'enabled':True}}})
  children[SITE+'/config/authsettingsV2']=resource(SITE+'/config/authsettingsV2','Microsoft.Web/sites/config',{'platform':{'enabled':True}})
  for name in ('scm','ftp'):children[SITE+'/basicPublishingCredentialsPolicies/'+name]=resource(SITE+'/basicPublishingCredentialsPolicies/'+name,'Microsoft.Web/sites/basicPublishingCredentialsPolicies',{'allow':False})
  children[SITE+'/slots']=[resource(SLOT,'Microsoft.Web/sites/slots',{'httpsOnly':True},kind='app')]
  children[SITE+'/virtualNetworkConnections']=[]
  logs=resource(SITE+'/providers/Microsoft.Insights/diagnosticSettings/native','Microsoft.Insights/diagnosticSettings',{'workspaceId':BASE+'Microsoft.OperationalInsights/workspaces/native-logs','logs':[{'category':'AppServiceHTTPLogs','enabled':True}]})
  children[SITE+'/providers/Microsoft.Insights/diagnosticSettings']=[logs]
  if slug=='prowler_function_identity_not_admin':
   ra=resource(ENDPOINTS['role_assignment'][2],'Microsoft.Authorization/roleAssignments',{'principalId':PRINCIPAL,'principalType':'ServicePrincipal','roleDefinitionId':SCOPE+'/providers/Microsoft.Authorization/roleDefinitions/acdd72a7-3385-48ef-bd42-f606fba81ae7','scope':SCOPE})
   others.append(ra);decision=scalar(ra,'properties.roleDefinitionId',ra['properties']['roleDefinitionId'],SCOPE+'/providers/Microsoft.Authorization/roleDefinitions/b24988ac-6180-42a0-ab88-20f7382dd24c')
  elif any(x in slug for x in ('identity','managed_identity','register_with_entra')):decision=scalar(obj,'identity.type','SystemAssigned','None')
  elif slug in ('prowler_app_http_logs','web_app_diagnostic_http_log_category'):decision=scalar(logs,'properties.logs',[{'category':'AppServiceHTTPLogs','enabled':True}],[{'category':'AppServiceHTTPLogs','enabled':False}])
  elif slug=='prowler_function_not_public':decision=scalar(obj,'properties.publicNetworkAccess','Disabled','Enabled')
  elif slug=='prowler_function_vnet_integration':decision=scalar(obj,'properties.virtualNetworkSubnetId',VNET+'/subnets/apps',None)
  elif slug=='web_app_vnet_connection':decision=scalar(obj,'properties.virtualNetworkSubnetId',VNET+'/subnets/apps',None)
  elif slug=='web_app_authentication_enabled':decision=scalar(children[SITE+'/config/authsettingsV2'],'properties.platform.enabled',True,False)
  elif slug=='web_app_failed_request_tracing':decision=scalar(children[SITE+'/config/logs'],'properties.failedRequestsTracing.enabled',True,False)
  elif slug=='web_app_slot_https_only':decision=scalar(children[SITE+'/slots'][0],'properties.httpsOnly',True,False)
  elif slug in ('web_app_client_certificates','web_app_incoming_client_cert'):decision=scalar(obj,'properties.clientCertEnabled',True,False)
  elif slug=='web_app_always_on':decision=scalar(cfg,'properties.alwaysOn',True,False)
  elif slug=='web_app_health_check':decision=scalar(cfg,'properties.healthCheckPath','/health',None)
  elif slug=='web_app_remote_debugging_disabled':decision=scalar(cfg,'properties.remoteDebuggingEnabled',False,True)
  elif slug=='web_app_diagnostic_logs_enabled':decision=scalar(cfg,'properties.httpLoggingEnabled',True,False)
  elif slug in ('web_app_ftps_required','prowler_function_ftp_ftps_disabled'):decision=scalar(cfg,'properties.ftpsState','Disabled' if slug.startswith('prowler') else 'FtpsOnly','AllAllowed')
  elif slug in ('ftp_basic_auth_disabled','scm_basic_auth_disabled'):
   name='ftp' if slug.startswith('ftp') else 'scm';decision=scalar(children[SITE+'/basicPublishingCredentialsPolicies/'+name],'properties.allow',False,True)
  elif slug=='scm_site_restricted_like_main':decision=scalar(cfg,'properties.scmIpSecurityRestrictionsUseMain',True,False)
  else:raise AssertionError(cid)
 elif kind=='disk':
  obj['properties'].update(diskState='Unattached',creationData={'createOption':'Empty'},diskSizeGB=32,publicNetworkAccess='Disabled',networkAccessPolicy='AllowPrivate',dataAccessAuthMode='AzureActiveDirectory')
  decision=scalar(obj,'properties.dataAccessAuthMode','AzureActiveDirectory','None') if slug=='entra_export_auth' else scalar(obj,'properties.networkAccessPolicy','AllowPrivate','AllowAll')
 elif kind=='container_registry':
  obj['sku']={'name':'Premium'};obj['properties'].update(adminUserEnabled=False,publicNetworkAccess='Enabled',anonymousPullEnabled=False,networkRuleSet={'defaultAction':'Deny','virtualNetworkRules':[],'ipRules':[]})
  decision=scalar(obj,'properties.anonymousPullEnabled',False,True)
 elif kind=='automation_account':
  obj['identity']={'type':'SystemAssigned','principalId':PRINCIPAL,'tenantId':TENANT}
  obj['properties']['encryption']={'keySource':'Microsoft.Keyvault','keyVaultProperties':{'keyName':'native-key','keyvaultUri':'https://native.vault.azure.net'},'identity':{'userAssignedIdentity':None}}
  hook=resource(AUTO+'/webhooks/native','Microsoft.Automation/automationAccounts/webhooks',{'isEnabled':True,'expiryTime':'2027-01-01T00:00:00Z','runbook':{'name':'native-runbook'},'uri':'https://ignored.webhook.azure.test/opaque'})
  children[AUTO+'/webhooks']=[hook]
  decision=scalar(obj,'properties.encryption.keySource','Microsoft.Keyvault','Microsoft.Automation') if slug=='automation_account_encrypted_with_cmk' else scalar(hook,'properties.expiryTime','2027-01-01T00:00:00Z','2037-01-01T00:00:00Z')
 elif kind=='databricks_workspace':
  obj['sku']={'name':'premium'};obj['properties'].update(managedResourceGroupId=SCOPE+'/resourceGroups/native-managed',parameters={'customVirtualNetworkId':{'type':'String','value':VNET},'enableNoPublicIp':{'type':'Bool','value':True}},publicNetworkAccess='Disabled',privateEndpointConnections=[resource(rid+'/privateEndpointConnections/native','Microsoft.Databricks/workspaces/privateEndpointConnections',{'privateLinkServiceConnectionState':{'status':'Approved'},'privateEndpoint':{'id':BASE+'Microsoft.Network/privateEndpoints/native'}})])
  if slug.endswith('custom_vnet'):
   decision=scalar(obj,'properties.parameters.customVirtualNetworkId',{'type':'String','value':VNET},None)
   if mode=='bad':obj['properties']['parameters'].pop('customVirtualNetworkId')
  elif slug.endswith('no_public_ip_enabled'):decision=scalar(obj,'properties.parameters.enableNoPublicIp.value',True,False)
  elif slug.endswith('public_network_access_disabled'):decision=scalar(obj,'properties.publicNetworkAccess','Disabled','Enabled')
  else:decision=scalar(obj,'properties.privateEndpointConnections',obj['properties']['privateEndpointConnections'],[])
 elif kind=='synapse_workspace':
  obj['properties'].update(defaultDataLakeStorage={'accountUrl':'https://native.dfs.core.windows.net','filesystem':'native'},publicNetworkAccess='Enabled',privateEndpointConnections=[resource(rid+'/privateEndpointConnections/native','Microsoft.Synapse/workspaces/privateEndpointConnections',{'privateLinkServiceConnectionState':{'status':'Approved'},'privateEndpoint':{'id':BASE+'Microsoft.Network/privateEndpoints/native'}})])
  children[rid+'/privateEndpointConnections']=deepcopy(obj['properties']['privateEndpointConnections'])
  eid=BASE+'Microsoft.Network/privateEndpoints/native'
  children[eid]=resource(eid,'Microsoft.Network/privateEndpoints',{'provisioningState':'Succeeded','privateLinkServiceConnections':[resource(eid+'/privateLinkServiceConnections/native','Microsoft.Network/privateEndpoints/privateLinkServiceConnections',{'privateLinkServiceId':rid,'groupIds':['sql'],'privateLinkServiceConnectionState':{'status':'Approved'}})]})
  children[rid+'/sqlPools']=[resource(rid+'/sqlPools/native','Microsoft.Synapse/workspaces/sqlPools',{'status':'Online'})]
  rule=resource(rid+'/firewallRules/native','Microsoft.Synapse/workspaces/firewallRules',{'startIpAddress':'10.0.0.1','endIpAddress':'10.0.0.255'})
  children[rid+'/firewallRules']=[rule]
  if cid=='azure.htbp.synapse.firewall_no_allow_all_internet':
   if mode=='bad':rule['properties'].update(startIpAddress='0.0.0.0',endIpAddress='255.255.255.255')
   decision=rule,'properties.startIpAddress'
  elif cid=='azure_pci_1_3_1_33':
   decision=children[rid+'/privateEndpointConnections'][0],'properties.privateEndpoint.id'
   if mode=='bad':children[rid+'/privateEndpointConnections']=[]
  else:decision=scalar(obj,'properties.publicNetworkAccess','Disabled','Enabled')
 elif kind=='container_group':
  obj['properties'].update(osType='Linux',instanceView={'state':'Running'},containers=[{'name':'native','properties':{'image':'mcr.microsoft.com/azuredocs/aci-helloworld','resources':{'requests':{'cpu':1,'memoryInGB':1}}}}],diagnostics={'logAnalytics':{'workspaceId':'44444444-4444-4444-4444-444444444444','logType':'ContainerInsights'}})
  decision=scalar(obj,'properties.diagnostics.logAnalytics.workspaceId','44444444-4444-4444-4444-444444444444','')
 elif kind=='vm_scale_set':
  obj['sku']={'capacity':1,'name':'Standard_D2s_v5'};obj['properties'].update(orchestrationMode='Uniform',virtualMachineProfile={'storageProfile':{'osDisk':{'osType':'Linux','managedDisk':{'storageAccountType':'Standard_LRS'}},'dataDisks':[]},'securityProfile':{'encryptionAtHost':True}})
  children[rid+'/virtualMachines']=[];decision=scalar(obj,'properties.virtualMachineProfile.securityProfile.encryptionAtHost',True,False)
 else:raise AssertionError(cid)
 if mode=='missing':put(*decision,None,remove=True)
 if mode=='malformed':put(*decision,[42])
 return kind,obj,others,children

class NativeHTTP:
 tenant=verified_tenant=TENANT
 def __init__(self,cid,mode,kind,obj,others,children):
  self.cid,self.mode,self.kind=cid,mode,kind;self.obj=obj;self.objects=[obj,*others];self.children=children;self.calls=[];self.errors=[]
 def request(self,url,*,body=None,audience=azure.ARM):
  p=urlsplit(url);q=parse_qs(p.query);method='POST' if body is not None else 'GET';self.calls.append({'method':method,'url':url,'body':deepcopy(body)})
  try:
   assert p.scheme=='https' and p.netloc=='management.azure.com' and not p.fragment and audience==azure.ARM
   path=p.path
   if path=='/providers/Microsoft.ResourceGraph/resources':
    assert method=='POST' and body['subscriptions']==[SUB] and q['api-version']==['2022-10-01'];return {'data':deepcopy(self.objects)}
   if path=='/providers/Microsoft.Management/managementGroups':
    assert method=='GET' and q['api-version']==['2020-05-01'];return {'value':[]}
   if path=='/providers/Microsoft.Authorization/roleAssignments':
    assert method=='GET' and q['api-version']==['2022-04-01'] and q['$filter']==['atScope()'];return {'value':[]}
   assert method=='GET' and path.startswith(SCOPE+'/')
   if path in self.children and '/providers/Microsoft.Network/privateEndpoints/' in path:
    assert q['api-version']==['2023-09-01'];value=self.children[path]
    if isinstance(value,Exception):raise value
    return deepcopy(value)
   if self.kind=='synapse_workspace' and path==self.obj['id']+'/privateEndpointConnections':
    assert q['api-version']==['2021-06-01']
    value=self.children.get(path,[])
    if isinstance(value,dict) and 'value' in value:
     if q.get('page')==['2']:raise azure.AzureReadError('forbidden',403)
     return deepcopy(value)
    return self.child(path,[])
   if path==SCOPE+'/resources':assert q['api-version']==['2021-04-01'];return {'value':deepcopy(self.objects)}
   for kind,(typ,version,rid) in ENDPOINTS.items():
    if path==SCOPE+'/providers/'+typ:
     assert q['api-version']==[version];rows=[r for r in self.objects if r['type'].casefold()==typ.casefold()]
     if kind==self.kind:
      if self.mode=='denied':raise azure.AzureReadError('forbidden',403)
      if self.mode=='empty':rows=[]
      if self.mode=='foreign':rows=deepcopy(rows);rows[0]['id']=rows[0]['id'].replace(SUB,'99999999-9999-9999-9999-999999999999')
      if self.mode=='wrong-parent-type':rows=deepcopy(rows);rows[0]['type']='Microsoft.Network/privateEndpoints'
      if self.mode=='partial':
       if q.get('page')==['2']:raise azure.AzureReadError('forbidden',403)
       return {'value':deepcopy(rows),'nextLink':azure.ARM+path+'?api-version='+version+'&page=2'}
     return {'value':deepcopy(rows)}
   for row in self.objects:
    kind=next(k for k,v in ENDPOINTS.items() if v[0].casefold()==row['type'].casefold())
    if path==row['id']:assert q['api-version']==[ENDPOINTS[kind][1]];return deepcopy(row)
    if path==row['id']+'/providers/Microsoft.Insights/diagnosticSettings':
     assert q['api-version']==['2021-05-01-preview'];return self.child(path,[])
    for suffix,version in LISTS.get(kind,[]):
     if path==row['id']+'/'+suffix:assert q['api-version']==[version];return self.child(path,[])
    if kind=='app_service':
     for suffix,version in SINGLE:
      if path==row['id']+'/'+suffix:
       assert q['api-version']==[version];value=self.children[path]
       if isinstance(value,Exception):raise value
       return deepcopy(value)
    if kind=='vm_scale_set' and path==row['id']+'/virtualMachines':assert q['api-version']==['2024-07-01'];return self.child(path,[])
   if path.endswith('/vulnerabilityAssessments') and '/sqlPools/' in path:
    assert q['api-version']==['2021-06-01'] and path.rsplit('/vulnerabilityAssessments',1)[0] in {r['id'] for r in self.children.get(ENDPOINTS['synapse_workspace'][2]+'/sqlPools',[])};return {'value':[]}
   raise AssertionError('Unexpected native route '+path)
  except azure.AzureReadError:raise
  except AssertionError as exc:self.errors.append(str(exc));raise
 def child(self,path,default):
  value=self.children.get(path,default)
  if isinstance(value,Exception):raise value
  return {'value':deepcopy(value)}

def run_case(cid,mode,record_property,mutate=None,options=None):
 kind,obj,others,children=native_case(cid,mode)
 if mutate:mutate(obj,others,children)
 api=NativeHTTP(cid,mode,kind,obj,others,children)
 snap=azure.collect({'provider':'azure','scopes':[SUB],'options':{'concurrency':1,'retries':0,**(options or {})}},list(REGISTRY[cid].dependencies),transport=api)
 assert not api.errors,api.errors
 assert validate(snap)==snap
 before=deepcopy(snap);report=evaluate_snapshot(snap,checks=[cid],include_not_applicable=True);assert snap==before
 rows=[r for r in report['findings'] if r['check_id']==cid];assert rows
 record_property('native_receipt',json.dumps({'id':cid,'mode':mode,'calls':api.calls,'statuses':[r['status'] for r in rows],'evidence':[r['evidence'] for r in rows],'primary_statuses':[c['status'] for c in snap['collections'] if c['type']==kind]},sort_keys=True))
 return snap,rows

@pytest.mark.parametrize('cid',IDS)
@pytest.mark.parametrize('mode',['good','bad','missing','malformed','denied','partial','foreign','empty'])
def test_native_per_id_matrix(cid,mode,record_property):
 snapshot,rows=run_case(cid,mode,record_property);statuses={r['status'] for r in rows}
 if mode=='good':assert statuses==({'UNKNOWN'} if cid in UNRESOLVED_POSITIVE else {'PASS'}),rows
 elif mode=='bad':assert statuses==({'UNKNOWN'} if cid in {'azure_pci_10_2_1_1_16'} else {'FAIL'}),rows
 elif mode in ('denied','foreign'):assert statuses<={'UNKNOWN','DENIED'},rows
 elif mode=='partial':assert any(c['status']=='partial' for c in snapshot['collections']) and statuses<={'UNKNOWN','PASS','FAIL'},rows
 elif mode=='empty':assert statuses<={'EMPTY','NOT_APPLICABLE','UNKNOWN'},rows
 else:assert statuses<={'UNKNOWN','FAIL'},rows


def test_native_health_check_empty_path_is_not_configured(record_property):
 cid='azure.claude2.web_app_health_check'
 def mutate(obj,others,children):children[SITE+'/config/web']['properties']['healthCheckPath']=''
 _,rows=run_case(cid,'good',record_property,mutate)
 assert {r['status'] for r in rows}=={'FAIL'},rows


def test_native_function_admin_principal_guid_case_is_insensitive(record_property):
 cid='azure.claude2.prowler_function_identity_not_admin'
 def mutate(obj,others,children):others[0]['properties']['principalId']=PRINCIPAL.upper()
 _,rows=run_case(cid,'bad',record_property,mutate)
 assert {r['status'] for r in rows}=={'FAIL'},rows


def test_native_expanded_world_ipv6_cannot_restrict_scm(record_property):
 cid='azure.htbp.appservice.scm_site_restricted_like_main'
 def mutate(obj,others,children):
  cfg=children[SITE+'/config/web']['properties'];cfg['scmIpSecurityRestrictionsUseMain']=False
  cfg['scmIpSecurityRestrictions']=[{'ipAddress':'0:0:0:0:0:0:0:0/0','action':'Allow','priority':100}]
  cfg['scmIpSecurityRestrictionsDefaultAction']='Deny'
 _,rows=run_case(cid,'good',record_property,mutate)
 assert {r['status'] for r in rows}=={'FAIL'},rows


def test_native_wrong_slot_route_cannot_prove_slot_https(record_property):
 cid='azure.claude2.web_app_slot_https_only'
 def mutate(obj,others,children):children[SITE+'/slots'][0]['id']=SITE+'/config/unrelated'
 _,rows=run_case(cid,'good',record_property,mutate)
 assert {r['status'] for r in rows}=={'UNKNOWN'},rows


@pytest.mark.parametrize('case,expected',[('wrong-type','UNKNOWN'),('foreign-parent','UNKNOWN'),('missing-properties','UNKNOWN'),('duplicate-identical','PASS'),('duplicate-conflicting','UNKNOWN')])
def test_native_slot_binding_and_duplicate_matrix(case,expected,record_property):
 cid='azure.claude2.web_app_slot_https_only'
 def mutate(obj,others,children):
  row=children[SITE+'/slots'][0]
  if case=='wrong-type':row['type']='Microsoft.Web/sites/config'
  elif case=='foreign-parent':row['id']=SITE+'-foreign/slots/staging'
  elif case=='missing-properties':row.pop('properties')
  elif case.startswith('duplicate'):
   duplicate=deepcopy(row)
   if case.endswith('conflicting'):duplicate['properties']['httpsOnly']=False
   children[SITE+'/slots'].append(duplicate)
 _,rows=run_case(cid,'good',record_property,mutate)
 assert {r['status'] for r in rows}=={expected},rows


@pytest.mark.parametrize('cid',[c for c in IDS if c.startswith('azure.claude2.') and REGISTRY[c].kind=='app_service'])
def test_native_app_kind_applicability(cid,record_property):
 def mutate(obj,others,children):
  obj['kind']='app' if 'prowler_function_' in cid else 'functionapp,linux';obj['properties']['reserved']=obj['kind'].startswith('function')
 _,rows=run_case(cid,'bad',record_property,mutate)
 assert {r['status'] for r in rows}=={'NOT_APPLICABLE'},rows


@pytest.mark.parametrize('cid',['azure.claude2.web_app_diagnostic_logs_enabled','azure.claude2.web_app_failed_request_tracing'])
@pytest.mark.parametrize('os,expected',[('linux','NOT_APPLICABLE'),('conflict','UNKNOWN'),('unreturned','UNKNOWN')])
def test_native_windows_iis_applicability(cid,os,expected,record_property):
 def mutate(obj,others,children):
  if os=='linux':obj['kind']='app,linux';obj['properties']['reserved']=True
  elif os=='conflict':obj['kind']='app,linux';obj['properties']['reserved']=False
  else:obj['properties'].pop('reserved')
 _,rows=run_case(cid,'bad',record_property,mutate)
 assert {r['status'] for r in rows}=={expected},rows


@pytest.mark.parametrize('source,expected',[('::/0','FAIL'),('0:0:0:0:0:0:0:0/0','FAIL'),('::/1','PASS'),('2001:db8::/32','PASS'),('0.0.0.0/0','FAIL'),('10.0.0.0/8','PASS')])
def test_native_scm_world_cidr_normalization(source,expected,record_property):
 cid='azure.htbp.appservice.scm_site_restricted_like_main'
 def mutate(obj,others,children):
  cfg=children[SITE+'/config/web']['properties'];cfg['scmIpSecurityRestrictionsUseMain']=False
  cfg['scmIpSecurityRestrictions']=[{'ipAddress':source,'action':'Allow','priority':100}];cfg['scmIpSecurityRestrictionsDefaultAction']='Deny'
 _,rows=run_case(cid,'good',record_property,mutate)
 assert {r['status'] for r in rows}=={expected},rows


@pytest.mark.parametrize('case,expected',[('sql','PASS'),('sqlOnDemand','FAIL'),('workspace-dev','FAIL'),('pe-denied','UNKNOWN'),('foreign-pe-id','UNKNOWN'),('foreign-type','UNKNOWN'),('foreign-target','UNKNOWN'),('foreign-scope','UNKNOWN'),('network-pending','UNKNOWN'),('missing-groups','UNKNOWN'),('manual-only','UNKNOWN'),('duplicate-link','UNKNOWN'),('workspace-pending','FAIL'),('child-denied','UNKNOWN'),('duplicate-child','UNKNOWN')])
def test_native_synapse_private_sql_exact_join_matrix(case,expected,record_property):
 cid='azure_pci_1_3_1_33';wid=ENDPOINTS['synapse_workspace'][2];eid=BASE+'Microsoft.Network/privateEndpoints/native'
 def mutate(obj,others,children):
  ep=children[eid];link=ep['properties']['privateLinkServiceConnections'][0]
  if case in ('sqlOnDemand','workspace-dev'):link['properties']['groupIds']=['sqlOnDemand' if case=='sqlOnDemand' else 'dev']
  elif case=='pe-denied':children[eid]=azure.AzureReadError('forbidden',403)
  elif case=='foreign-pe-id':ep['id']+='-foreign'
  elif case=='foreign-type':ep['type']='Microsoft.Network/networkInterfaces'
  elif case=='foreign-target':link['properties']['privateLinkServiceId']=wid+'-foreign'
  elif case=='foreign-scope':children[wid+'/privateEndpointConnections'][0]['properties']['privateEndpoint']['id']=eid.replace(SUB,'99999999-9999-9999-9999-999999999999')
  elif case=='network-pending':link['properties']['privateLinkServiceConnectionState']['status']='Pending'
  elif case=='missing-groups':link['properties'].pop('groupIds')
  elif case=='manual-only':ep['properties']['manualPrivateLinkServiceConnections']=ep['properties'].pop('privateLinkServiceConnections')
  elif case=='duplicate-link':ep['properties']['privateLinkServiceConnections'].append(deepcopy(link))
  elif case=='workspace-pending':children[wid+'/privateEndpointConnections'][0]['properties']['privateLinkServiceConnectionState']['status']='Pending'
  elif case=='child-denied':children[wid+'/privateEndpointConnections']=azure.AzureReadError('forbidden',403)
  elif case=='duplicate-child':children[wid+'/privateEndpointConnections'].append(deepcopy(children[wid+'/privateEndpointConnections'][0]))
 _,rows=run_case(cid,'good',record_property,mutate)
 assert {r['status'] for r in rows}=={expected},rows


@pytest.mark.parametrize('cid,suffix',[('azure.claude2.web_app_always_on','config/web'),('azure.claude2.web_app_authentication_enabled','config/authsettingsV2'),('azure.claude2.web_app_failed_request_tracing','config/logs'),('azure.htbp.appservice.scm_basic_auth_disabled','basicPublishingCredentialsPolicies/scm'),('azure.htbp.appservice.ftp_basic_auth_disabled','basicPublishingCredentialsPolicies/ftp'),('azure.claude2.prowler_app_http_logs','providers/Microsoft.Insights/diagnosticSettings'),('azure.claude2.web_app_slot_https_only','slots')])
@pytest.mark.parametrize('case',['denied','foreign'])
def test_native_app_deciding_child_unavailable(cid,suffix,case,record_property):
 def mutate(obj,others,children):
  path=SITE+'/'+suffix
  if case=='denied':children[path]=azure.AzureReadError('forbidden',403)
  else:
   row=children[path][0] if isinstance(children[path],list) else children[path];row['id']=row['id'].replace('native-site/','foreign-site/')
 _,rows=run_case(cid,'good',record_property,mutate)
 expected='DENIED' if cid=='azure.claude2.web_app_slot_https_only' and case=='denied' else 'UNKNOWN'
 assert {r['status'] for r in rows}=={expected},rows


@pytest.mark.parametrize('role',['8e3af657-a8ff-443c-a75c-2fe8c4bcb635','b24988ac-6180-42a0-ab88-20f7382dd24c','18d7d88d-d35e-4fb5-a5c3-7773c20a72d9','f58310d9-a9f6-439a-9e8d-f62e7b41a168'])
def test_native_function_direct_admin_role_case_matrix(role,record_property):
 cid='azure.claude2.prowler_function_identity_not_admin'
 def mutate(obj,others,children):
  others[0]['properties']['principalId']=PRINCIPAL.upper();others[0]['properties']['roleDefinitionId']=SCOPE+'/providers/Microsoft.Authorization/roleDefinitions/'+role.upper()
 _,rows=run_case(cid,'good',record_property,mutate)
 assert {r['status'] for r in rows}=={'FAIL'},rows


def test_native_synapse_child_pagination_denial_cannot_complete_join(record_property):
 cid='azure_pci_1_3_1_33';wid=ENDPOINTS['synapse_workspace'][2]
 def mutate(obj,others,children):
  path=wid+'/privateEndpointConnections';children[path]={'value':children[path],'nextLink':azure.ARM+path+'?api-version=2021-06-01&page=2'}
 _,rows=run_case(cid,'good',record_property,mutate)
 assert {r['status'] for r in rows}=={'UNKNOWN'},rows


def test_native_synapse_call_budget_cannot_clean_partial_join(record_property):
 snapshot,rows=run_case('azure_pci_1_3_1_33','good',record_property,options={'max_calls':5})
 assert snapshot['metadata']['calls']<=5
 assert {r['status'] for r in rows}<={'UNKNOWN','DENIED'},rows


@pytest.mark.parametrize('cid',['azure_pci_1_3_1_33','azure_synapse_workspace_1_2_8_29_fcdc827'])
def test_native_synapse_no_dedicated_pools_is_not_applicable(cid,record_property):
 def mutate(obj,others,children):children[obj['id']+'/sqlPools']=[]
 _,rows=run_case(cid,'good',record_property,mutate)
 assert {r['status'] for r in rows}=={'NOT_APPLICABLE'},rows




@pytest.mark.parametrize('cid',['azure.claude.acr_vnet_service_endpoint','azure.claude.acr_network_default_deny','azure.claude.acr_public_network_access_disabled'])
@pytest.mark.parametrize('rule_case',['single-world','split-world','restricted'])
def test_native_acr_auxiliary_world_ip_gap_witness(cid,rule_case,record_property):
 def mutate(obj,others,children):
  obj['properties']['publicNetworkAccess']='Enabled';obj['properties']['networkRuleBypassOptions']='AzureServices'
  nrs=obj['properties']['networkRuleSet'];nrs['virtualNetworkRules']=[{'action':'Allow','id':VNET+'/subnets/registry'}]
  values={'single-world':['0.0.0.0/0'],'split-world':['0.0.0.0/1','128.0.0.0/1'],'restricted':['203.0.113.0/24']}[rule_case]
  nrs['ipRules']=[{'action':'Allow','value':x} for x in values]
 _,rows=run_case(cid,'good',record_property,mutate)
 expected='FAIL' if cid.endswith('public_network_access_disabled') else 'PASS'
 assert {r['status'] for r in rows}=={expected},rows
 record_property('acr_proposal_witness',rule_case)


def test_native_synapse_dependency_is_explicit_and_narrow(record_property):
 from peaso.engine import plan_collection
 from peaso.collectors.azure_application_compute_2_native import KIND,required_types
 assert KIND in REGISTRY['azure_pci_1_3_1_33'].dependencies
 assert KIND in plan_collection({'provider':'azure','scopes':[SUB],'checks':['azure_pci_1_3_1_33']})
 assert KIND not in plan_collection({'provider':'azure','scopes':[SUB],'checks':['azure.htbp.synapse.firewall_no_allow_all_internet']})
 assert required_types({KIND})=={'synapse_workspace'} and required_types({'synapse_workspace'})==set()
 snapshot,rows=run_case('azure.htbp.synapse.firewall_no_allow_all_internet','good',record_property)
 assert not any(c['type']==KIND for c in snapshot['collections'])
 # The only matching private endpoint read is in the optional, explicit kind.
 assert not any('resolvedPrivateEndpoints' in row for c in snapshot['collections'] for row in c['items'])


def test_native_synapse_parent_type_must_bind_before_enrichment(record_property):
 _,rows=run_case('azure_pci_1_3_1_33','wrong-parent-type',record_property)
 assert {r['status'] for r in rows}=={'UNKNOWN'},rows


@pytest.mark.parametrize('cid',['azure.htbp.appservice.ftp_basic_auth_disabled','azure.htbp.appservice.scm_site_restricted_like_main','azure.htbp.synapse.firewall_no_allow_all_internet'])
def test_native_disabled_surface_applicability(cid,record_property):
 def mutate(obj,others,children):
  if cid.endswith('ftp_basic_auth_disabled'):children[SITE+'/config/web']['properties']['ftpsState']='Disabled'
  else:obj['properties']['publicNetworkAccess']='Disabled'
 _,rows=run_case(cid,'bad',record_property,mutate)
 assert {r['status'] for r in rows}=={'NOT_APPLICABLE'},rows
