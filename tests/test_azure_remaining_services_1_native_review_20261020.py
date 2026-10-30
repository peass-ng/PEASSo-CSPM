"""Exact60 independent native HTTP -> actual Azure collector -> public engine."""
from copy import deepcopy
from datetime import datetime, timezone
import json
import socket
from urllib.parse import urlsplit,parse_qs
import pytest
from peaso.checks import CHECKS
from peaso.collectors import azure
from tests.archived_check_contract import evaluate_snapshot

SUB='11111111-1111-1111-1111-111111111111';TENANT='22222222-2222-2222-2222-222222222222'
USER='33333333-3333-3333-3333-333333333333';KEY='44444444-4444-4444-4444-444444444444'
SCOPE='/subscriptions/'+SUB;BASE=SCOPE+'/resourceGroups/native/providers/'
OWNER='8e3af657-a8ff-443c-a75c-2fe8c4bcb635';READER='acdd72a7-3385-48ef-bd42-f606fba81ae7'
VNET=BASE+'Microsoft.Network/virtualNetworks/native';PE=BASE+'Microsoft.Network/privateEndpoints/native'
REGISTRY={c.id:c for c in CHECKS}
IDS=('azure.cis.agentless_discovery_kubernetes_component_status', 'azure.cis.auto_provision_vulnerability_assessment_machines', 'azure.cis.defender_external_attack_surface_monitoring_easm', 'azure.cis.guest_users_reviewed_monthly_basis', 'azure.cis.guest_users_reviewed_regular_basis', 'azure.cis.latest_os_patches_vms_applied', 'azure.cis.private_endpoint_should_mariadb_servers', 'azure.cis.public_network_access_should_mariadb_servers', 'azure.claude.bastion_host_exists', 'azure.claude.databox_edge_double_encryption', 'azure.claude.defender_default_initiative_no_disabled_effects', 'azure.claude.defender_default_policy_enforced', 'azure.claude.defender_iot_security_solution_enabled', 'azure.claude.disk_access_private_link', 'azure.claude.entra_auth_methods_strong_registration', 'azure.claude.entra_named_location_trusted', 'azure.claude.eventgrid_domain_managed_identity', 'azure.claude.eventgrid_domain_private_link', 'azure.claude.eventgrid_domain_public_access_disabled', 'azure.claude.eventgrid_topic_managed_identity', 'azure.claude.eventgrid_topic_private_link', 'azure.claude.eventhub_namespace_cmk', 'azure.claude.eventhub_namespace_logging', 'azure.claude.eventhub_namespace_private_link', 'azure.claude.eventhub_namespace_vnet_rule', 'azure.claude.fhir_cmk', 'azure.claude.fhir_private_link', 'azure.claude.frontdoor_waf_policy_linked', 'azure.claude.hdinsight_cmk', 'azure.claude.hdinsight_encryption_at_host', 'azure.claude.hdinsight_encryption_in_transit', 'azure.claude.hpc_cache_cmk', 'azure.claude.iam_custom_role_administers_locks', 'azure.claude.iam_disabled_user_no_owner', 'azure.claude.iam_disabled_user_no_role_assignment', 'azure.claude.iam_external_user_no_owner', 'azure.claude.iam_external_user_no_reader', 'azure.claude.iam_external_user_no_write', 'azure.claude.iam_no_custom_role', 'azure.claude.iam_subscription_owner_between_2_and_3', 'azure.claude.iam_subscription_owner_max_3', 'azure.claude.iam_subscription_owner_more_than_1', 'azure.claude.iot_hub_logging', 'azure.claude.iot_hub_private_link', 'azure.claude.keyvault_certificate_validity_12_months', 'azure.claude.kusto_cmk', 'azure.claude.kusto_disk_encryption', 'azure.claude.kusto_double_encryption', 'azure.claude.kusto_sku_with_sla', 'azure.claude.logic_app_workflow_diagnostic_logging', 'azure.claude.ml_workspace_cmk', 'azure.claude.mssql_managed_instance_tde_cmk', 'azure.claude.mssql_managed_instance_vulnerability_assessment', 'azure.claude.network_watcher_in_vnet_region', 'azure.claude.nic_no_public_ip', 'azure.claude.search_service_logging_enabled', 'azure.claude.search_service_replica_count_above_3', 'azure.claude.servicebus_namespace_local_auth_disabled', 'azure.claude.servicebus_namespace_logging_enabled', 'azure.claude.servicebus_namespace_network_restricted')
# Documented provider type/version routes, deliberately independent of runtime tables.
ENDPOINTS={
 'bastion_host':('Microsoft.Network/bastionHosts','2023-09-01'),
 'databox_edge_device':('Microsoft.DataBoxEdge/dataBoxEdgeDevices','2023-07-01'),
 'disk_access':('Microsoft.Compute/diskAccesses','2023-10-02'),
 'eventgrid_domain':('Microsoft.EventGrid/domains','2022-06-15'),
 'eventgrid_topic':('Microsoft.EventGrid/topics','2022-06-15'),
 'eventhub_namespace':('Microsoft.EventHub/namespaces','2024-01-01'),
 'healthcare_fhir_service':('Microsoft.HealthcareApis/services','2021-11-01'),
 'frontdoor':('Microsoft.Network/frontDoors','2021-06-01'),
 'hdinsight_cluster':('Microsoft.HDInsight/clusters','2021-06-01'),
 'hpc_cache':('Microsoft.StorageCache/caches','2024-03-01'),
 'iot_hub':('Microsoft.Devices/IotHubs','2023-06-30'),
 'iot_security_solution':('Microsoft.Security/iotSecuritySolutions','2019-08-01'),
 'kusto_cluster':('Microsoft.Kusto/clusters','2024-04-13'),
 'logic_app_workflow':('Microsoft.Logic/workflows','2019-05-01'),
 'ml_workspace':('Microsoft.MachineLearningServices/workspaces','2026-03-01'),
 'mssql_managed_instance':('Microsoft.Sql/managedInstances','2023-08-01'),
 'network_watcher':('Microsoft.Network/networkWatchers','2023-09-01'),
 'nic':('Microsoft.Network/networkInterfaces','2023-09-01'),
 'vnet':('Microsoft.Network/virtualNetworks','2023-09-01'),
 'search_service':('Microsoft.Search/searchServices','2023-11-01'),
 'servicebus_namespace':('Microsoft.ServiceBus/namespaces','2022-10-01-preview'),
 'mariadb_server':('Microsoft.DBforMariaDB/servers','2018-06-01'),
 'easm_workspace':('Microsoft.Easm/workspaces','2023-04-01-preview'),
 'aks_cluster':('Microsoft.ContainerService/managedClusters','2024-05-01'),
 'vm':('Microsoft.Compute/virtualMachines','2023-09-01'),
 'vault':('Microsoft.KeyVault/vaults','2023-07-01'),
 'arc_machine':('Microsoft.HybridCompute/machines','2024-07-10'),
 'security_pricing':('Microsoft.Security/pricings','2024-01-01'),
 'role_assignment':('Microsoft.Authorization/roleAssignments','2022-04-01'),
 'role_definition':('Microsoft.Authorization/roleDefinitions','2022-04-01'),
 'policy_assignment':('Microsoft.Authorization/policyAssignments','2023-04-01'),
}
SUB_TYPES={'security_pricing','role_assignment','role_definition','policy_assignment'}

@pytest.fixture(autouse=True)
def offline(monkeypatch):
 attempts=[]
 def blocked(*a,**kw):attempts.append('network/auth');raise AssertionError('Native60 prohibits live IO')
 for n in ('create_connection','getaddrinfo','gethostbyname','gethostbyname_ex','gethostbyaddr','getnameinfo'):monkeypatch.setattr(socket,n,blocked)
 for n in ('connect','connect_ex','sendto'):monkeypatch.setattr(socket.socket,n,blocked)
 monkeypatch.setattr(azure,'credential_for',blocked);monkeypatch.setattr(azure,'AzureTransport',blocked);monkeypatch.setattr(azure,'AzureTransportExposure',blocked)
 yield
 assert not attempts,attempts


def obj(kind,props=None,name='native',**kw):
 typ,_=ENDPOINTS[kind];rid=(SCOPE+'/providers/' if kind in SUB_TYPES else BASE)+typ+'/'+name
 return {'id':rid,'name':name,'type':typ,'location':'eastus','properties':{} if props is None else props,**kw}


def child(parent,segment,props,typ=None,name='native'):
 return {'id':parent['id']+'/'+segment+'/'+name,'name':name,'type':typ or parent['type']+'/'+segment,'properties':props}


def endpoint_connection(parent):return child(parent,'privateEndpointConnections',{'privateEndpoint':{'id':PE},'privateLinkServiceConnectionState':{'status':'Approved','description':'approved'}})


def put(row,path,value,remove=False):
 parts=path.split('.');p=row
 for k in parts[:-1]:p=p[k]
 if remove:p.pop(parts[-1],None)
 else:p[parts[-1]]=deepcopy(value)


def native_case(cid,mode):
 check=REGISTRY[cid];kind=check.kind;s=cid.rsplit('.',1)[-1];objects={};extras={};decision=None
 def add(kind,props=None,name='native',**kw):
  row=obj(kind,props,name,**kw);objects.setdefault(kind,[]).append(row);return row
 def scalar(row,path,good,bad):
  nonlocal decision
  put(row,path,bad if mode=='bad' else good);decision=(row,path)
 if cid.startswith('azure.claude.iam_'):
  assignment=add('role_assignment',{'scope':SCOPE,'roleDefinitionId':SCOPE+'/providers/Microsoft.Authorization/roleDefinitions/'+OWNER,'principalId':USER,'principalType':'User','condition':None,'conditionVersion':None},name=KEY)
  if 'subscription_owner_' in s:
   count=(4 if s.endswith('max_3') or s.endswith('between_2_and_3') else 1) if mode=='bad' else 2
   objects['role_assignment']=[{**deepcopy(assignment),'id':assignment['id'][:-36]+str(i+1).zfill(8)+'-3333-3333-3333-333333333333','properties':{**assignment['properties'],'principalId':str(i+1).zfill(8)+'-3333-3333-3333-333333333333'}} for i in range(count)]
   for role in objects['role_assignment']:role['name']=role['id'].rsplit('/',1)[-1]
   decision=objects['role_assignment'][0],'properties.principalId'
  elif s in ('iam_no_custom_role','iam_custom_role_administers_locks'):
   objects.pop('role_assignment')
   definition=add('role_definition',{'roleName':'Native role','type':'CustomRole','assignableScopes':[SCOPE],'permissions':[{'actions':['Microsoft.Authorization/locks/*'],'notActions':[],'dataActions':[],'notDataActions':[]}]},name=KEY)
   if s=='iam_no_custom_role':scalar(definition,'properties.type','BuiltInRole','CustomRole')
   else:scalar(definition,'properties.permissions',[{'actions':['Microsoft.Authorization/locks/*'],'notActions':[],'dataActions':[],'notDataActions':[]}],[{'actions':['Microsoft.Resources/subscriptions/resourceGroups/read'],'notActions':[],'dataActions':[],'notDataActions':[]}])
  else:
   if s.endswith('no_reader'):assignment['properties']['roleDefinitionId']=SCOPE+'/providers/Microsoft.Authorization/roleDefinitions/'+READER
   user={'id':USER,'accountEnabled':True,'userPrincipalName':'native@example.test','userType':'Member','createdDateTime':'2025-01-01T00:00:00Z'}
   if 'disabled_user' in s:scalar(user,'accountEnabled',True,False)
   else:scalar(user,'userType','Member','Guest')
   extras['/v1.0/users']={'value':[user]}
 elif kind in ('authentication_methods_policy','named_location'):
  if kind=='authentication_methods_policy':
   row={'id':'authenticationMethodsPolicy','registrationEnforcement':{'authenticationMethodsRegistrationCampaign':{'state':'enabled'}},'authenticationMethodConfigurations':[{'@odata.type':'#microsoft.graph.fido2AuthenticationMethodConfiguration','id':'Fido2','state':'enabled'}]}
   scalar(row,'registrationEnforcement.authenticationMethodsRegistrationCampaign.state','enabled','disabled');extras['/v1.0/policies/authenticationMethodsPolicy']=row
  else:
   row={'id':KEY,'@odata.type':'#microsoft.graph.ipNamedLocation','displayName':'Native network','isTrusted':True,'ipRanges':[{'@odata.type':'#microsoft.graph.iPv4CidrRange','cidrAddress':'203.0.113.0/24'}]}
   scalar(row,'isTrusted',True,False);extras['/v1.0/identity/conditionalAccess/namedLocations']={'value':[row]}
 elif kind=='key_vault_certificate_policy':
  row=add('vault',{'vaultUri':'https://native-vault.vault.azure.net','tenantId':TENANT,'enableRbacAuthorization':True})
  policy={'id':'https://native-vault.vault.azure.net/certificates/native/policy','x509_props':{'validity_months':12}}
  extras['/certificates']={'value':[{'id':'https://native-vault.vault.azure.net/certificates/native','attributes':{'enabled':True}}]};extras['/certificates/native/policy']=policy
  scalar(policy,'x509_props.validity_months',12,24)
 elif kind=='policy_assignment':
  row=add('policy_assignment',{'scope':SCOPE,'enforcementMode':'Default','policyDefinitionId':'/providers/Microsoft.Authorization/policySetDefinitions/1f3afdf9-d0c9-4c3d-847f-89da613e70a8','parameters':{'nativeEffect':{'value':'AuditIfNotExists'}},'notScopes':[],'resourceSelectors':[],'overrides':[]},name='SecurityCenterBuiltIn')
  if s.endswith('no_disabled_effects'):scalar(row,'properties.parameters',{'nativeEffect':{'value':'AuditIfNotExists'}},{'nativeEffect':{'value':'Disabled'}})
  else:scalar(row,'properties.enforcementMode','Default','DoNotEnforce')
 elif kind=='defender_pricing':
  row=add('aks_cluster',{'provisioningState':'Succeeded','kubernetesVersion':'1.32.0','agentPoolProfiles':[]})
  for plan in ('Containers','CloudPosture'):
   rid=row['id']+'/providers/Microsoft.Security/pricings/'+plan
   price={'id':rid,'name':plan,'type':'Microsoft.Security/pricings','properties':{'pricingTier':'Standard','inherited':'False','extensions':[{'name':'AgentlessDiscoveryForKubernetes','isEnabled':'True'}]}}
   extras[rid]=price
   if plan=='Containers':scalar(price,'properties.extensions',[{'name':'AgentlessDiscoveryForKubernetes','isEnabled':'True'}],[{'name':'AgentlessDiscoveryForKubernetes','isEnabled':'False'}])
   elif mode=='bad':price['properties']['extensions'][0]['isEnabled']='False'
 elif kind=='server_vulnerability_assessment_setting':
  row=add('security_pricing',{'pricingTier':'Standard','subPlan':'P2'},name='VirtualMachines');objects['arc_machine']=[]
  rid=SCOPE+'/providers/Microsoft.Security/serverVulnerabilityAssessmentsSettings/azureServersSetting'
  extras[rid]={'id':rid,'name':'azureServersSetting','type':'Microsoft.Security/serverVulnerabilityAssessmentsSettings','kind':'AzureServersSetting','properties':{'selectedProvider':'MdeTvm'}}
  scalar(row,'properties.pricingTier','Standard','Free')
 elif s=='latest_os_patches_vms_applied':
  row=add('vm',{'provisioningState':'Succeeded','hardwareProfile':{'vmSize':'Standard_D2s_v5'},'storageProfile':{'osDisk':{'osType':'Linux'}},'osProfile':{'linuxConfiguration':{'patchSettings':{'assessmentMode':'AutomaticByPlatform'}}}})
  iv={'patchStatus':{'availablePatchSummary':{'status':'Succeeded','lastModifiedTime':datetime.now(timezone.utc).isoformat(),'criticalAndSecurityPatchCount':0}},'statuses':[]}
  extras[row['id']+'/instanceView']=iv;scalar(iv,'patchStatus.availablePatchSummary.criticalAndSecurityPatchCount',0,2)
 else:
  row=add(kind,{'provisioningState':'Succeeded'})
  if kind in ('disk_access','eventgrid_domain','eventgrid_topic','eventhub_namespace','healthcare_fhir_service','iot_hub','mariadb_server'):
   row['properties']['privateEndpointConnections']=[endpoint_connection(row)]
  if kind in ('eventgrid_domain','eventgrid_topic'):
   row['identity']={'type':'SystemAssigned','principalId':USER,'tenantId':TENANT};row['properties']['publicNetworkAccess']='Disabled'
   if s.endswith('managed_identity'):scalar(row,'identity.type','SystemAssigned','None')
   elif s.endswith('public_access_disabled'):scalar(row,'properties.publicNetworkAccess','Disabled','Enabled')
   else:scalar(row,'properties.privateEndpointConnections',row['properties']['privateEndpointConnections'],[])
  elif kind in ('disk_access','iot_hub','eventhub_namespace'):
   if kind=='iot_hub':row['sku']={'name':'S1','tier':'Standard','capacity':1}
   if kind=='eventhub_namespace':row['sku']={'name':'Premium','tier':'Premium','capacity':1};row['properties']['encryption']={'keySource':'Microsoft.KeyVault','keyVaultProperties':[]}
   if s.endswith('cmk'):scalar(row,'properties.encryption.keySource','Microsoft.KeyVault','Microsoft.EventHub')
   elif s.endswith('vnet_rule'):
    r=child(row,'networkRuleSets',{'defaultAction':'Deny','publicNetworkAccess':'Enabled','virtualNetworkRules':[{'subnet':{'id':VNET+'/subnets/native'},'ignoreMissingVnetServiceEndpoint':False}],'ipRules':[]},name='default');extras[row['id']+'/networkRuleSets/default']=r
    scalar(r,'properties.virtualNetworkRules',r['properties']['virtualNetworkRules'],[])
   elif not s.endswith('logging'):scalar(row,'properties.privateEndpointConnections',row['properties']['privateEndpointConnections'],[])
  elif kind=='mariadb_server':
   row['properties']['publicNetworkAccess']='Disabled'
   if 'public_network' in s:scalar(row,'properties.publicNetworkAccess','Disabled','Enabled')
   else:scalar(row,'properties.privateEndpointConnections',row['properties']['privateEndpointConnections'],[])
  elif kind=='healthcare_fhir_service':
   row['kind']='fhir-R4';row['properties']['cosmosDbConfiguration']={'offerThroughput':400,'keyVaultKeyUri':'https://native-vault.vault.azure.net/keys/native/1234567890abcdef1234567890abcdef'}
   if s.endswith('cmk'):scalar(row,'properties.cosmosDbConfiguration.keyVaultKeyUri',row['properties']['cosmosDbConfiguration']['keyVaultKeyUri'],None)
   else:scalar(row,'properties.privateEndpointConnections',row['properties']['privateEndpointConnections'],[])
  elif kind=='hdinsight_cluster':
   row['properties'].update(clusterVersion='5.1',diskEncryptionProperties={'keyName':'native','vaultUri':'https://native-vault.vault.azure.net','keyVersion':'1234567890abcdef1234567890abcdef','encryptionAtHost':True},encryptionInTransitProperties={'isEncryptionInTransitEnabled':True})
   if s.endswith('cmk'):scalar(row,'properties.diskEncryptionProperties.keyName','native',None)
   elif s.endswith('host'):scalar(row,'properties.diskEncryptionProperties.encryptionAtHost',True,False)
   else:scalar(row,'properties.encryptionInTransitProperties.isEncryptionInTransitEnabled',True,False)
  elif kind=='hpc_cache':
   row['properties']['encryptionSettings']={'keyEncryptionKey':{'keyUrl':'https://native-vault.vault.azure.net/keys/native/1234567890abcdef1234567890abcdef','sourceVault':{'id':BASE+'Microsoft.KeyVault/vaults/native'}}}
   scalar(row,'properties.encryptionSettings',row['properties']['encryptionSettings'],None)
  elif kind=='kusto_cluster':
   row['sku']={'name':'Standard_E8ads_v5','tier':'Standard','capacity':2};row['properties'].update(keyVaultProperties={'keyName':'native','keyVaultUri':'https://native-vault.vault.azure.net','keyVersion':'1234567890abcdef1234567890abcdef'},enableDiskEncryption=True,enableDoubleEncryption=True)
   if s.endswith('cmk'):scalar(row,'properties.keyVaultProperties',row['properties']['keyVaultProperties'],None)
   elif s.endswith('sku_with_sla'):scalar(row,'sku.name','Standard_E8ads_v5','Dev(No SLA)_Standard_D11_v2')
   else:scalar(row,'properties.'+('enableDoubleEncryption' if 'double' in s else 'enableDiskEncryption'),True,False)
  elif kind=='ml_workspace':
   row['properties']['encryption']={'status':'Enabled','keyVaultProperties':{'keyIdentifier':'https://native-vault.vault.azure.net/keys/native','keyVaultArmId':BASE+'Microsoft.KeyVault/vaults/native'}}
   scalar(row,'properties.encryption.status','Enabled','Disabled')
  elif kind=='databox_edge_device':row['sku']={'name':'EdgePR_Base','tier':'Standard'};scalar(row,'sku.name','EdgePR_Base','Edge')
  elif kind=='frontdoor':
   endpoint=child(row,'frontendEndpoints',{'hostName':'native.azurefd.net','webApplicationFirewallPolicyLink':{'id':BASE+'Microsoft.Network/frontDoorWebApplicationFirewallPolicies/native'}})
   row['properties']['frontendEndpoints']=[endpoint];scalar(endpoint,'properties.webApplicationFirewallPolicyLink',endpoint['properties']['webApplicationFirewallPolicyLink'],None)
  elif kind=='nic':
   conf=child(row,'ipConfigurations',{'privateIPAddress':'10.0.0.4','privateIPAllocationMethod':'Dynamic','subnet':{'id':VNET+'/subnets/native'}})
   row['properties']['ipConfigurations']=[conf]
   if mode=='bad':conf['properties']['publicIPAddress']={'id':BASE+'Microsoft.Network/publicIPAddresses/native'}
   decision=row,'properties.ipConfigurations'
  elif kind=='vnet':
   row['properties'].update(addressSpace={'addressPrefixes':['10.0.0.0/16']},subnets=[],virtualNetworkPeerings=[])
   watcher=add('network_watcher',{'provisioningState':'Succeeded'});scalar(watcher,'location','eastus','westus')
  elif kind=='bastion_host':
   if mode=='bad':objects[kind]=[]
   decision=row,'id'
  elif kind=='iot_security_solution':
   row['properties'].update(status='Enabled',workspace=BASE+'Microsoft.OperationalInsights/workspaces/native',iotHubs=[]);objects['iot_hub']=[];scalar(row,'properties.status','Enabled','Disabled')
  elif kind=='easm_workspace':scalar(row,'properties.provisioningState','Succeeded','Failed')
  elif kind=='mssql_managed_instance':
   protector=child(row,'encryptionProtector',{'serverKeyType':'AzureKeyVault','uri':'https://native-vault.vault.azure.net/keys/native/version'},name='current')
   va=child(row,'vulnerabilityAssessments',{'recurringScans':{'isEnabled':True,'emails':[]}},name='default')
   extras[row['id']+'/encryptionProtector']=[protector];extras[row['id']+'/vulnerabilityAssessments']=[va]
   if s.endswith('tde_cmk'):scalar(protector,'properties.serverKeyType','AzureKeyVault','ServiceManaged')
   else:scalar(va,'properties.recurringScans.isEnabled',True,False)
  elif kind=='search_service':
   row['sku']={'name':'standard'};row['properties']['replicaCount']=4
   if s.endswith('replica_count_above_3'):scalar(row,'properties.replicaCount',4,3)
  elif kind=='servicebus_namespace':
   row['sku']={'name':'Premium','tier':'Premium','capacity':1};row['properties'].update(status='Active',disableLocalAuth=True,publicNetworkAccess='Enabled')
   nrs=child(row,'networkRuleSets',{'defaultAction':'Deny','publicNetworkAccess':'Enabled','trustedServiceAccessEnabled':False,'virtualNetworkRules':[],'ipRules':[{'action':'Allow','ipMask':'203.0.113.0/24'}]},name='default');extras[row['id']+'/networkRuleSets/default']=nrs
   if s.endswith('local_auth_disabled'):scalar(row,'properties.disableLocalAuth',True,False)
   elif s.endswith('network_restricted'):scalar(nrs,'properties.defaultAction','Deny','Allow')
  elif kind!='logic_app_workflow':raise AssertionError((cid,kind))
  if s.endswith('logging') or s.endswith('logging_enabled'):
   log=child(row,'providers/Microsoft.Insights/diagnosticSettings',{'workspaceId':BASE+'Microsoft.OperationalInsights/workspaces/native','logs':[{'category':'OperationalLogs','enabled':True}]},typ='Microsoft.Insights/diagnosticSettings')
   extras[row['id']+'/providers/Microsoft.Insights/diagnosticSettings']=[log];scalar(log,'properties.logs',[{'category':'OperationalLogs','enabled':True}],[{'category':'OperationalLogs','enabled':False}])
 if decision is not None and mode in ('missing','malformed'):put(*decision,None,remove=True) if mode=='missing' else put(*decision,[42])
 return objects,extras


class NativeHTTP:
 tenant=verified_tenant=TENANT
 def __init__(self,cid,mode,objects,extras):self.cid,self.mode,self.objects,self.extras=cid,mode,objects,extras;self.calls=[];self.errors=[];self.vaults=[]
 def allow_vault(self,uri):self.vaults.append(uri)
 def request(self,url,*,body=None,audience=azure.ARM):
  p=urlsplit(url);q=parse_qs(p.query);method='POST' if body is not None else 'GET';self.calls.append({'method':method,'url':url,'body':deepcopy(body),'audience':audience})
  try:
   assert p.scheme=='https' and not p.fragment and p.netloc in ('management.azure.com','graph.microsoft.com','native-vault.vault.azure.net')
   if p.netloc=='graph.microsoft.com':
    assert method=='GET' and audience==azure.GRAPH and p.path in (set(self.extras)|{'/v1.0/users','/v1.0/groups'})
    if self.mode=='denied':raise azure.AzureReadError('forbidden',403)
    result=deepcopy(self.extras.get(p.path,{'value':[]}))
    if self.mode=='foreign':
     for row in result.get('value',[result]):row['id']='/tenants/foreign/objects/invalid-native-id'
    if self.mode=='empty':return {'value':[]} if 'value' in result else {}
    if self.mode=='partial' and 'value' in result:
     if q.get('$skiptoken'):raise azure.AzureReadError('forbidden',403)
     result['@odata.nextLink']=azure.GRAPH+p.path+'?$skiptoken=next'
    elif self.mode=='partial':result.pop('authenticationMethodConfigurations',None)
    return result
   if p.netloc=='native-vault.vault.azure.net':
    assert method=='GET' and audience==azure.VAULT and q=={'api-version':['7.4']} and p.path in self.extras
    if self.mode=='denied':raise azure.AzureReadError('forbidden',403)
    return deepcopy(self.extras[p.path])
   assert audience==azure.ARM
   allrows=[r for rows in self.objects.values() for r in rows]
   if p.path=='/providers/Microsoft.ResourceGraph/resources':
    assert method=='POST' and q=={'api-version':['2022-10-01']} and body['subscriptions']==[SUB]
    assert body['query'].startswith('Resources | project ')
    return {'data':[{k:r[k] for k in ('id','name','type','location') if k in r} for r in allrows]}
   assert method=='GET'
   if p.path==SCOPE:return {'id':SCOPE,'subscriptionId':SUB,'tenantId':TENANT,'state':'Enabled'}
   if p.path=='/tenants':assert q.get('api-version')==['2022-12-01'];return {'value':[{'id':'/tenants/'+TENANT,'tenantId':TENANT}]}
   if p.path=='/providers/Microsoft.Management/managementGroups':assert q.get('api-version')==['2020-05-01'];return {'value':[]}
   if p.path in ('/providers/Microsoft.Authorization/roleAssignments','/providers/Microsoft.Authorization/roleDefinitions'):
    assert q.get('api-version')==['2022-04-01'];return {'value':[]}
   if p.path==SCOPE+'/resources':assert q.get('api-version')==['2021-04-01'];return {'value':deepcopy(allrows)}
   if p.path==SCOPE+'/resourcegroups':assert q.get('api-version')==['2021-04-01'];return {'value':[{'id':SCOPE+'/resourceGroups/native','name':'native','type':'Microsoft.Resources/resourceGroups','location':'eastus','properties':{'provisioningState':'Succeeded'}}]}
   # Exposure analysis also lists subscription NSGs and public IPs; this account has none.
   if p.path in (SCOPE+'/providers/Microsoft.Network/networkSecurityGroups',SCOPE+'/providers/Microsoft.Network/publicIPAddresses'):
    assert q.get('api-version')==['2023-09-01'];return {'value':[]}
   for kind,(typ,version) in ENDPOINTS.items():
    if p.path.casefold() in ((SCOPE+'/providers/'+typ).casefold(),(SCOPE+'/resourceGroups/native/providers/'+typ).casefold()):
     assert q.get('api-version')==[version],(kind,q,version)
     if self.mode=='denied':raise azure.AzureReadError('forbidden',403)
     if q.get('page')==['2']:raise azure.AzureReadError('forbidden',403)
     rows=deepcopy(self.objects.get(kind,[]))
     if self.mode=='empty':rows=[]
     if self.mode=='foreign':
      for r in rows:
       r['id']=r['id'].replace(SUB,'99999999-9999-9999-9999-999999999999')
       if kind=='role_definition':r['properties']['assignableScopes']=['/subscriptions/99999999-9999-9999-9999-999999999999']
     result={'value':rows}
     if self.mode=='partial':result['nextLink']=azure.ARM+p.path+'?api-version='+version+'&page=2'
     return result
    for row in self.objects.get(kind,[]):
     if p.path.casefold()==row['id'].casefold():
      assert q.get('api-version')==[version],(kind,q,version)
      return deepcopy(row)
     if p.path==row['id']+'/providers/Microsoft.Insights/diagnosticSettings':
      assert q.get('api-version')==['2021-05-01-preview'];return {'value':deepcopy(self.extras.get(p.path,[]))}
     if kind=='eventhub_namespace' and p.path in [row['id']+'/'+s for s in ('eventhubs','authorizationRules','disasterRecoveryConfigs')]:
      assert q.get('api-version')==['2024-01-01'];return {'value':[]}
     if kind=='eventhub_namespace' and p.path==row['id']+'/networkRuleSets/default':
      assert q.get('api-version')==['2024-01-01'];return deepcopy(self.extras.get(p.path,child(row,'networkRuleSets',{'virtualNetworkRules':[],'defaultAction':'Deny','ipRules':[],'publicNetworkAccess':'Enabled'},name='default')))
     if kind=='servicebus_namespace' and p.path==row['id']+'/networkRuleSets/default':assert q.get('api-version')==['2022-10-01-preview'];return deepcopy(self.extras[p.path])
     if kind=='ml_workspace' and p.path in [row['id']+'/'+s for s in ('privateEndpointConnections','onlineEndpoints')]:assert q.get('api-version')==['2024-04-01'];return {'value':[]}
     # Service Bus queue/topic and namespace SAS rule inventories: native empty lists.
     if kind=='servicebus_namespace' and p.path in [row['id']+'/'+s for s in ('queues','topics','AuthorizationRules')]:
      assert q.get('api-version')==['2024-01-01'];return {'value':[]}
     if kind=='mssql_managed_instance' and p.path in [row['id']+'/'+s for s in ('administrators','azureADOnlyAuthentications','encryptionProtector','vulnerabilityAssessments','databases')]:
      assert q.get('api-version')==['2021-11-01' if p.path.endswith('/databases') else '2023-08-01'];return {'value':deepcopy(self.extras.get(p.path,[]))}
     if kind=='aks_cluster' and p.path==row['id']+'/managedNamespaces':assert q.get('api-version')==['2025-10-01'];return {'value':[]}
     if kind=='vm' and p.path==row['id']+'/extensions':assert q.get('api-version')==['2023-09-01'];return {'value':[]}
     if kind=='vm' and p.path==row['id']+'/providers/Microsoft.GuestConfiguration/guestConfigurationAssignments':assert q.get('api-version')==['2024-04-05'];return {'value':[]}
     if kind=='vm' and p.path==row['id']+'/instanceView':assert q.get('api-version')==['2023-09-01'];return deepcopy(self.extras[p.path])
     if kind=='network_watcher' and p.path==row['id']+'/flowLogs':assert q.get('api-version')==['2023-09-01'];return {'value':[]}
   if p.path in self.extras:
    assert q.get('api-version')==['2024-01-01' if '/pricings/' in p.path else '2023-05-01'];return deepcopy(self.extras[p.path])
   raise AssertionError('Unexpected native route '+p.path+' '+str(q))
  except azure.AzureReadError:raise
  except AssertionError as exc:self.errors.append(str(exc));raise


def run_case(cid,mode,record_property,mutate=None,options=None):
 if 'guest_users_reviewed_' in cid:
  # Reuse the existing independently documented Graph hierarchy, not CASES or
  # collector output; its source hash is recorded in the review report.
  from tests.test_peaso_azure_access_reviews_native import API
  maps={'good':'complete','bad':'no_definitions','missing':'missing_decisions','malformed':'malformed_user','denied':'denied_users','partial':'partial_definitions','foreign':'foreign_tenant','empty':'empty_users'}
  api=API(maps[mode]);api.errors=[]
  if mode=='foreign':api.tenant=api.verified_tenant='99999999-9999-9999-9999-999999999999'
  original=api.request
  def request(url,*,body=None,audience=azure.ARM):
   p=urlsplit(url)
   allowed={'/subscriptions',SCOPE,'/v1.0/groups','/v1.0/users'}
   assert p.scheme=='https' and p.netloc in ('management.azure.com','graph.microsoft.com') and body is None
   assert p.path in allowed or p.path.startswith('/v1.0/identityGovernance/accessReviews/definitions')
   return original(url,body=body,audience=audience)
  api.request=request
 else:
  objects,extras=native_case(cid,mode)
  if mutate:mutate(objects,extras)
  api=NativeHTTP(cid,mode,objects,extras)
 connector={'provider':'azure','scopes':[SUB],'options':{'concurrency':1,'retries':0,**(options or {})}}
 snapshot=azure.collect(connector,REGISTRY[cid].dependencies,transport=api)
 assert not api.errors,api.errors
 before=deepcopy(snapshot);out=evaluate_snapshot(snapshot,checks=[cid],include_not_applicable=True);assert snapshot==before
 rows=[r for r in out['findings'] if r['check_id']==cid];assert rows
 calls=api.calls
 record_property('native_receipt',json.dumps({'check_id':cid,'mode':mode,'statuses':[r['status'] for r in rows],
    'evidence':[r['evidence'] for r in rows],'calls':calls,'envelopes':[{k:c[k] for k in ('type','scope','status')} for c in snapshot['collections']]},sort_keys=True))
 return snapshot,rows


@pytest.mark.parametrize('cid',IDS)
@pytest.mark.parametrize('mode',['good','bad','missing','malformed','denied','partial','foreign','empty'])
def test_native_per_id_matrix(cid,mode,record_property):
 snap,rows=run_case(cid,mode,record_property);states={r['status'] for r in rows}
 if mode=='good':assert states==({'UNKNOWN'} if cid=='azure.cis.private_endpoint_should_mariadb_servers' else {'PASS'}),rows
 elif mode=='bad':assert states==({'UNKNOWN'} if cid=='azure.cis.private_endpoint_should_mariadb_servers' or 'guest_users_reviewed_' in cid else {'FAIL'}),rows
 elif mode in ('denied','foreign'):assert states<={'UNKNOWN','DENIED'},rows
 elif mode=='partial':assert states<={'PASS','FAIL','UNKNOWN','DENIED'} and (any(c['status']=='partial' for c in snap['collections']) or cid=='azure.claude.entra_auth_methods_strong_registration'),rows
 elif mode=='empty':assert states<={'EMPTY','NOT_APPLICABLE','UNKNOWN','FAIL','PASS'},rows
 else:assert states<=({'UNKNOWN','FAIL','PASS'} if cid=='azure.claude.defender_default_initiative_no_disabled_effects' and mode=='missing' else {'UNKNOWN','FAIL'}),rows


@pytest.mark.parametrize('cid',['azure.claude.iam_subscription_owner_between_2_and_3','azure.claude.iam_subscription_owner_more_than_1'])
def test_native_owner_same_guid_case_does_not_create_second_owner(cid,record_property):
 def mutate(objects,extras):
  rows=objects['role_assignment'];rows[0]['properties']['principalId']='abcdef12-3456-789a-bcde-f0123456789a';rows[1]['properties']['principalId']=rows[0]['properties']['principalId'].upper()
 _,rows=run_case(cid,'good',record_property,mutate);assert {r['status'] for r in rows}=={'FAIL'},rows


@pytest.mark.parametrize('scope_prefix',['/SUBSCRIPTIONS/','/Subscriptions/'])
def test_native_foreign_authorization_scope_case_is_still_foreign(scope_prefix,record_property):
 def mutate(objects,extras):
  for row in objects['role_assignment']:
   foreign=scope_prefix+'99999999-9999-9999-9999-999999999999'
   row['id']=foreign+'/providers/Microsoft.Authorization/roleAssignments/'+row['name']
   row['properties']['scope']=foreign
 _,rows=run_case('azure.claude.iam_subscription_owner_max_3','good',record_property,mutate)
 assert {r['status'] for r in rows}=={'UNKNOWN'},rows


@pytest.mark.parametrize('source',['root','mg','subscription','descendant'])
def test_native_role_assignment_applicability_keeps_coherent_scoped_list_rows(source,record_property):
 cid='azure.claude.iam_subscription_owner_between_2_and_3'
 def mutate(objects,extras):
  parent={'root':'/','mg':'/providers/Microsoft.Management/managementGroups/native-parent','subscription':SCOPE,'descendant':SCOPE+'/resourceGroups/native'}[source]
  for row in objects['role_assignment']:
   row['id']=parent.rstrip('/')+'/providers/Microsoft.Authorization/roleAssignments/'+row['id'].rsplit('/',1)[-1]
   row['properties']['scope']=parent
 _,rows=run_case(cid,'good',record_property,mutate)
 assert {r['status'] for r in rows}==({'FAIL'} if source=='descendant' else {'PASS'}),rows


@pytest.mark.parametrize('assigned',['root','selected','descendant','mg','foreign'])
def test_native_cross_home_custom_definition_uses_actual_assignable_scopes(assigned,record_property):
 def mutate(objects,extras):
  row=objects['role_definition'][0];row['id']=row['id'].replace(SUB,'99999999-9999-9999-9999-999999999999')
  row['properties']['assignableScopes']=[{'root':'/','selected':SCOPE,'descendant':SCOPE+'/resourceGroups/native','mg':'/providers/Microsoft.Management/managementGroups/native-parent','foreign':'/subscriptions/99999999-9999-9999-9999-999999999999'}[assigned]]
 _,rows=run_case('azure.claude.iam_custom_role_administers_locks','good',record_property,mutate)
 assert {r['status'] for r in rows}==({'UNKNOWN'} if assigned=='foreign' else {'PASS'}),rows


@pytest.mark.parametrize('field,value',[('principalId',''),('principalId','00000000-0000-0000-0000-000000000000'),
 ('principalId',['invalid']),('roleDefinitionId','https://evil.example/'+OWNER),('scope','/subscriptions/foreign')])
def test_native_assignment_malformed_deciding_identity_is_unresolved(field,value,record_property):
 def mutate(objects,extras):objects['role_assignment'][0]['properties'][field]=value
 _,rows=run_case('azure.claude.iam_subscription_owner_between_2_and_3','good',record_property,mutate)
 assert {r['status'] for r in rows}=={'UNKNOWN'},rows


def test_native_iam_user_guid_case_coherent_join(record_property):
 def mutate(objects,extras):
  objects['role_assignment'][0]['properties']['principalId']='abcdef12-3456-789a-bcde-f0123456789a'
  extras['/v1.0/users']['value'][0]['id']='ABCDEF12-3456-789A-BCDE-F0123456789A'
  extras['/v1.0/users']['value'][0]['accountEnabled']=False
 _,rows=run_case('azure.claude.iam_disabled_user_no_owner','good',record_property,mutate)
 assert {r['status'] for r in rows}=={'FAIL'},rows


@pytest.mark.parametrize('cid',['azure.claude.frontdoor_waf_policy_linked','azure.claude.mssql_managed_instance_vulnerability_assessment'])
def test_native_field_survives_collector_and_default_child_casing(cid,record_property):
 _,rows=run_case(cid,'good',record_property);assert {r['status'] for r in rows}=={'PASS'},rows


@pytest.mark.parametrize('cid',IDS)
@pytest.mark.parametrize('mode',['good','bad'])
def test_native_current_consumer_capture(cid,mode,record_property,monkeypatch):
 """Export reviewable current inputs; historical CASES remain untouched."""
 from dataclasses import replace
 from peaso import engine
 original=REGISTRY[cid];captures=[]
 def capture(item,index):
  before=deepcopy((item,index));result=original.evaluate(item,index)
  assert (item,index)==before
  captures.append({'item':before[0],'index':before[1],'result':deepcopy(result)})
  return result
 monkeypatch.setattr(engine,'_registry',lambda:[replace(c,evaluate=capture) if c.id==cid else c for c in CHECKS])
 _,rows=run_case(cid,mode,record_property)
 assert captures
 record_property('native_current_consumer',json.dumps({'check_id':cid,'branch':mode,'captures':captures,
  'public_statuses':[r['status'] for r in rows],'origin':'independent native HTTP -> azure.collect -> public engine'},sort_keys=True))


def _proposed_lock_write_delete(permissions):
 """Unregistered review proposal: native declared control-plane operations only."""
 from fnmatch import fnmatchcase
 if not isinstance(permissions,list):raise ValueError('permission blocks unavailable')
 targets={'microsoft.authorization/locks/write','microsoft.authorization/locks/delete'};allowed=set()
 for block in permissions:
  if not isinstance(block,dict):raise ValueError('permission block malformed')
  actions=block.get('actions',[]);excluded=block.get('notActions',[])
  if not isinstance(actions,list) or not isinstance(excluded,list) or any(not isinstance(a,str) or not a for a in actions+excluded):raise ValueError('permission action list malformed')
  allowed.update(t for t in targets if any(fnmatchcase(t,a.casefold()) for a in actions) and not any(fnmatchcase(t,n.casefold()) for n in excluded))
 return allowed==targets




@pytest.mark.parametrize('cid,field',[
 ('azure.claude.frontdoor_waf_policy_linked','frontendEndpoints'),
 ('azure.claude.mssql_managed_instance_vulnerability_assessment','vulnerabilityAssessments'),
 ('azure.claude.mssql_managed_instance_tde_cmk','encryptionProtector')])
@pytest.mark.parametrize('fault',['foreign-child','wrong-type','duplicate-conflict'])
def test_native_deciding_child_identity_must_bind(cid,field,fault,record_property):
 def mutate(objects,extras):
  parent=objects[REGISTRY[cid].kind][0]
  rows=parent['properties'][field] if field=='frontendEndpoints' else extras[parent['id']+'/'+field]
  childrow=rows[0]
  if fault=='foreign-child':childrow['id']=childrow['id'].replace('/native/', '/foreign/',1)
  elif fault=='wrong-type':childrow['type']='Microsoft.Storage/storageAccounts'
  else:
   other=deepcopy(childrow)
   if field=='frontendEndpoints':other['properties']['webApplicationFirewallPolicyLink']=None
   elif field=='vulnerabilityAssessments':other['properties']['recurringScans']['isEnabled']=False
   else:other['properties']['serverKeyType']='ServiceManaged'
   rows.append(other)
 _,rows=run_case(cid,'good',record_property,mutate)
 assert {r['status'] for r in rows}=={'UNKNOWN'},rows
