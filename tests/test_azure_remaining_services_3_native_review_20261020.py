"""Independent bounded native HTTP -> Azure collector -> public engine,49 IDs."""
from copy import deepcopy
import io,json,socket,base64
from urllib.error import HTTPError
from urllib.parse import urlsplit,parse_qs
import pytest
from tests.azure_native_inventory_routes_20261020 import empty_inventory_versions,matches_empty_inventory_query
from peaso.collectors import azure
from tests.archived_check_contract import collect_snapshot,evaluate_snapshot,plan_collection

SUB='11111111-1111-1111-1111-111111111111';OTHER='99999999-9999-9999-9999-999999999999';TENANT='22222222-2222-2222-2222-222222222222'
def encoded(value):return base64.urlsafe_b64encode(json.dumps(value).encode()).decode().rstrip('=')
ARM_TOKEN=encoded({'alg':'none'})+'.'+encoded({'tid':TENANT,'aud':azure.ARM,'exp':4102444800})+'.inert-native-fixture'
SCOPE='/subscriptions/'+SUB;ROOT=SCOPE+'/resourceGroups/review/providers/'
SERVER=ROOT+'Microsoft.Sql/servers/sql';DB=SERVER+'/databases/app';VAULT=ROOT+'Microsoft.KeyVault/vaults/reviewvault';ORIGIN='https://reviewvault.vault.azure.net'
STORAGE=ROOT+'Microsoft.Storage/storageAccounts/reviewstorage';RECOVERY=ROOT+'Microsoft.RecoveryServices/vaults/recovery';BACKUP=ROOT+'Microsoft.DataProtection/backupVaults/backup'
APIM=ROOT+'Microsoft.ApiManagement/service/gateway';API=APIM+'/apis/orders';COMP=ROOT+'Microsoft.Insights/components/telemetry';WORKSPACE=ROOT+'Microsoft.OperationalInsights/workspaces/audit'
PROFILE=ROOT+'Microsoft.Cdn/profiles/edge';EP=PROFILE+'/afdEndpoints/site';GROUP=PROFILE+'/originGroups/main';DOMAIN=PROFILE+'/customDomains/site'
VM=ROOT+'Microsoft.Compute/virtualMachines/vm';NIC=ROOT+'Microsoft.Network/networkInterfaces/nic';SUBNET=ROOT+'Microsoft.Network/virtualNetworks/v/subnets/s'
from peaso.checks import CHECKS
REGISTRY={c.id:c for c in CHECKS}
ROSTER=('azure.port.apimanagement_service_with_virtual_network', 'azure.port.app_configuration_encryption_enabled', 'azure.port.app_configuration_private_link_used', 'azure.port.app_configuration_sku_standard', 'azure.port.data_factory_encrypted_with_cmk', 'azure.port.data_factory_public_network_access_disabled', 'azure.port.data_factory_uses_git_repository', 'azure.port.data_factory_uses_private_link', 'azure.port.keyvault_key_automatic_rotation_enabled', 'azure.port.keyvault_key_expiration_set', 'azure.port.keyvault_with_non_rbac_key_expiration_set', 'azure.port.keyvault_with_rbac_key_expiration_set', 'azure.port.search_service_public_network_access_disabled', 'azure.port.search_service_uses_managed_identity', 'azure.port.search_service_uses_private_link', 'azure.port.search_service_uses_sku_supporting_private_link', 'azure.sql.audit_retention', 'azure.sql.auditing', 'azure.sql.restrict_firewall', 'azure.sql.tde_enabled', 'azure.sql.threat_alerts_all', 'azure.sql.threat_detection', 'azure_aks_cluster_1_4_5_2_3ac7b3c', 'azure_aks_cluster_aks_cluster_rbac_enabled_c41a0cb', 'azure_api_management_10_3_1_3_8a50dc0', 'azure_api_management_appinsights_ensure_is_configured_42aac6a', 'azure_application_gateway_11_5_1_1_1_f56bdc2', 'azure_application_gateway_app_http_logs_enabled_2de0361', 'azure_devops_project_1_2_8_6_fb0e5a8', 'azure_directory_user_sqlserver_azuread_administrator_enabled_1a9c5cf', 'azure_disk_10_3_3_12_174f526', 'azure_firewall_policy_1_2_8_23_59ad733', 'azure_firewall_policy_1_2_8_24_cc7cb8a', 'azure_firewall_policy_1_2_8_42_cacbd9e', 'azure_firewall_policy_sqlserver_unrestricted_inbound_access_c12f86d', 'azure_frontdoor_1_2_5_4_ccc7b8f', 'azure_frontdoor_1_2_8_4_90159db', 'azure_frontdoor_app_ensure_http_is_redirected_to_https_517a3c9', 'azure_frontdoor_app_minimum_tls_version_12_0512053', 'azure_frontdoor_monitor_storage_account_with_activity_logs_is_private_d42518a', 'azure_frontdoor_network_http_internet_access_restricted_7004685', 'azure_log_analytics_workspace_monitor_diagnostic_setting_with_appropriate_categories_48f6b2b', 'azure_search_service_3_5_1_19_a3c75c0', 'azure_sql_database_sqlserver_azuread_administrator_enabled_4a039a9', 'azure_sql_server_sqlserver_unrestricted_inbound_access_9b32c6a', 'azure_storage_account_10_3_3_24_61d5e36', 'azure_storage_file_share_10_3_3_15_f2d7075', 'azure_storage_file_share_10_3_3_18_d67ab34', 'azure_vm_1_4_5_1_d40be43')
FD=tuple(c for c in ROSTER if REGISTRY[c].kind=='frontdoor_and_cdn_endpoint')
SNI='azure_frontdoor_1_2_5_4_ccc7b8f';ACCESS='azure_frontdoor_monitor_storage_account_with_activity_logs_is_private_d42518a'
KEYS=tuple(c for c in ROSTER if REGISTRY[c].kind=='key_metadata')
APIM_TRACE='azure_api_management_10_3_1_3_8a50dc0';APIM_AI='azure_api_management_appinsights_ensure_is_configured_42aac6a'
HOSTPID='azure_aks_cluster_1_4_5_2_3ac7b3c';READONLY='azure_aks_cluster_aks_cluster_rbac_enabled_c41a0cb';DEVOPS='azure_devops_project_1_2_8_6_fb0e5a8'
EDGE='azure_application_gateway_11_5_1_1_1_f56bdc2';GWLOG='azure_application_gateway_app_http_logs_enabled_2de0361';DIAG='azure_log_analytics_workspace_monitor_diagnostic_setting_with_appropriate_categories_48f6b2b'
DISK='azure_disk_10_3_3_12_174f526';BLOB='azure_storage_account_10_3_3_24_61d5e36';FILES='azure_storage_file_share_10_3_3_15_f2d7075';NETAPP='azure_storage_file_share_10_3_3_18_d67ab34';VMPUB='azure_vm_1_4_5_1_d40be43'
SQLADM='azure_sql_database_sqlserver_azuread_administrator_enabled_4a039a9';FLEXADM='azure_directory_user_sqlserver_azuread_administrator_enabled_1a9c5cf';FW='azure_firewall_policy_sqlserver_unrestricted_inbound_access_c12f86d';INGRESS='azure_sql_server_sqlserver_unrestricted_inbound_access_9b32c6a'
WAF='azure_frontdoor_1_2_8_4_90159db'
SCALARS={
 'azure.port.apimanagement_service_with_virtual_network':('properties.virtualNetworkType','External','None'),
 'azure.port.app_configuration_encryption_enabled':('properties.encryption.keyVaultProperties.keyIdentifier',ORIGIN+'/keys/key/version1',None),
 'azure.port.app_configuration_sku_standard':('sku.name','standard','free'),
 'azure.port.data_factory_encrypted_with_cmk':('properties.encryption.vaultBaseUrl',ORIGIN,None),
 'azure.port.data_factory_public_network_access_disabled':('properties.publicNetworkAccess','Disabled','Enabled'),
 'azure.port.data_factory_uses_git_repository':('properties.repoConfiguration.repositoryName','factory-config',None),
 'azure.port.search_service_public_network_access_disabled':('properties.publicNetworkAccess','Disabled','Enabled'),
 'azure.port.search_service_uses_managed_identity':('identity.type','SystemAssigned','None'),
 'azure.port.search_service_uses_sku_supporting_private_link':('sku.name','standard','free'),
 'azure.sql.audit_retention':('properties.retentionDays',90,30),
 'azure.sql.auditing':('properties.state','Enabled','Disabled'),
 'azure.sql.threat_detection':('properties.state','Enabled','Disabled'),
 'azure.sql.threat_alerts_all':('properties.disabledAlerts',[],['Sql_Injection']),
 'azure.sql.tde_enabled':('properties.state','Enabled','Disabled'),
 'azure_search_service_3_5_1_19_a3c75c0':('properties.encryptionWithCmk.enforcement','Enabled','Disabled'),
}
PRIVATE={'azure.port.app_configuration_private_link_used','azure.port.data_factory_uses_private_link','azure.port.search_service_uses_private_link'}

def arm(rid,props=None,**extra):
 p=rid.split('/providers/',1)[1].split('/');typ='/'.join([p[0],*p[1::2]])
 return {'id':rid,'name':p[-1],'type':typ,'location':'eastus','properties':{}if props is None else props,**extra}

def assign(row,path,value,missing=False):
 p=path.split('.')
 for k in p[:-1]:row=row.setdefault(k,{})
 if missing:row.pop(p[-1],None)
 else:row[p[-1]]=deepcopy(value)

def case(cid,mode):
 kind=REGISTRY[cid].kind
 family='vault'if cid in KEYS else'sql_server'if kind in('sql_audit','sql_security','sql_firewall_rule','sql_tde')or cid in(SQLADM,FW,INGRESS)else'mysql_flexible_server'if cid==FLEXADM else'cdn_profile'if cid in FD or cid==WAF else'storage_account'if cid in(BLOB,FILES,NETAPP)else'vm'if cid==VMPUB else'disk'if cid==DISK else'aks_cluster'if cid in(HOSTPID,READONLY)else'api_management'if cid in(APIM_TRACE,APIM_AI)else'application_gateway'if cid in(EDGE,GWLOG)else'vault'if cid==DIAG else'api_management'if cid==DEVOPS else kind
 if cid==SNI:family='frontdoor'
 ep,version=azure.ENDPOINTS[family]
 rid={'vault':VAULT,'sql_server':SERVER,'api_management':APIM,'cdn_profile':PROFILE,'vm':VM,'storage_account':STORAGE}.get(family,ROOT+ep+'/review')
 props={'provisioningState':'Succeeded'}
 if family=='vault':props.update(vaultUri=ORIGIN+'/',tenantId=TENANT,sku={'family':'A','name':'standard'},accessPolicies=[],enableRbacAuthorization='non_rbac'not in cid)
 if family=='api_management':props.update(virtualNetworkType='External',publisherName='Review',publisherEmail='review@example.invalid')
 if family=='app_configuration':props.update(encryption={'keyVaultProperties':{'keyIdentifier':ORIGIN+'/keys/key/version1'}},publicNetworkAccess='Disabled')
 if family=='data_factory':props.update(publicNetworkAccess='Disabled',encryption={'vaultBaseUrl':ORIGIN,'keyName':'key','keyVersion':'version1'},repoConfiguration={'type':'FactoryVSTSConfiguration','accountName':'review','projectName':'review','repositoryName':'factory-config','collaborationBranch':'main','rootFolder':'/'})
 if family=='search_service':props.update(publicNetworkAccess='Disabled',replicaCount=1,partitionCount=1,encryptionWithCmk={'enforcement':'Enabled','encryptionComplianceStatus':'Compliant'})
 if family=='sql_server':props.update(version='12.0',publicNetworkAccess='Enabled')
 if family=='mysql_flexible_server':props.update(version='8.0.21',network={'publicNetworkAccess':'Enabled'})
 if family=='storage_account':props.update(primaryEndpoints={'blob':'https://reviewstorage.blob.core.windows.net/'},allowSharedKeyAccess=False,publicNetworkAccess='Disabled')
 if family=='vm':props.update(networkProfile={'networkInterfaces':[{'id':NIC}]},storageProfile={'osDisk':{'osType':'Linux','managedDisk':{'id':ROOT+'Microsoft.Compute/disks/os'}},'dataDisks':[]},osProfile={'computerName':'review','adminUsername':'review'})
 if family=='disk':props.update(diskSizeGB=32,creationData={'createOption':'Empty'},diskState='Unattached')
 if family=='aks_cluster':props.update(fqdn='review-123.hcp.eastus.azmk8s.io',kubernetesVersion='1.32.4',enableRBAC=True)
 if family=='application_gateway':props.update(frontendIPConfigurations=[{'id':rid+'/frontendIPConfigurations/private','name':'private','properties':{'privateIPAddress':'10.0.0.4','privateIPAllocationMethod':'Static','subnet':{'id':SUBNET}}}],gatewayIPConfigurations=[],httpListeners=[],requestRoutingRules=[],backendAddressPools=[],backendHttpSettingsCollection=[])
 if family=='firewall_policy':props.update(threatIntelMode='Deny',basePolicy=None)
 if family=='web_application_firewall_policy':props.update(policySettings={'state':'Enabled','mode':'Prevention'},customRules=[],managedRules={'managedRuleSets':[{'ruleSetType':'OWASP','ruleSetVersion':'3.2'}]})
 if family=='frontdoor':
  domain=arm(rid+'/frontendEndpoints/site',{'hostName':'review.example.invalid','customHttpsProvisioningState':'Enabled','customHttpsConfiguration':{'certificateSource':'AzureKeyVault','protocolType':'ServerNameIndication','minimumTlsVersion':'1.2'}})
  rule=arm(rid+'/routingRules/main',{'enabledState':'Enabled','acceptedProtocols':['Http','Https'],'patternsToMatch':['/*'],'frontendEndpoints':[{'id':domain['id']}],'routeConfiguration':{'@odata.type':'#Microsoft.Azure.FrontDoor.Models.FrontdoorRedirectConfiguration','redirectProtocol':'HttpsOnly'}})
  props.update(frontendEndpoints=[domain],routingRules=[rule],backendPools=[])
 parent=arm(rid,props,etag='W/"native-review-v1"')
 if family in('app_configuration','search_service'):parent['sku']={'name':'standard'}
 if family=='search_service':parent['identity']={'type':'SystemAssigned','principalId':TENANT,'tenantId':TENANT}
 if family=='storage_account':parent.update(kind='StorageV2',sku={'name':'Standard_LRS'})
 if family=='cdn_profile':parent['sku']={'name':'Premium_AzureFrontDoor'}
 def pe(parent):return arm(parent+'/privateEndpointConnections/private',{'privateEndpoint':{'id':ROOT+'Microsoft.Network/privateEndpoints/private'},'privateLinkServiceConnectionState':{'status':'Approved'}})
 if cid in PRIVATE:props['privateEndpointConnections']=[pe(rid)]
 db=arm(DB,{'status':'Online','collation':'SQL_Latin1_General_CP1_CI_AS'})
 auditing=arm(SERVER+'/auditingSettings/default',{'state':'Enabled','retentionDays':90,'storageEndpoint':'https://reviewstorage.blob.core.windows.net','isAzureMonitorTargetEnabled':False})
 security=arm(SERVER+'/securityAlertPolicies/Default',{'state':'Enabled','disabledAlerts':[],'emailAccountAdmins':True})
 firewall=arm(rid+'/firewallRules/internal',{'startIpAddress':'10.0.0.1','endIpAddress':'10.0.0.254'})
 tde=arm(DB+'/transparentDataEncryption/current',{'state':'Enabled'})
 admins=[arm(rid+'/administrators/ActiveDirectory',{'administratorType':'ActiveDirectory','sid':TENANT,'tenantId':TENANT,'login':'review','principalType':'User','objectId':TENANT})]
 key={'kid':ORIGIN+'/keys/metadata','attributes':{'enabled':True,'exp':2000000000,'created':1700000000,'updated':1700000000}}
 rotation={'id':ORIGIN+'/keys/metadata/rotationpolicy','lifetimeActions':[{'action':{'type':'Rotate'},'trigger':{'timeAfterCreate':'P90D'}}],'attributes':{'created':1700000000,'updated':1700000000,'expiryTime':'P2Y'}}
 routes={};versions={}
 def put(path,data,v=None):routes[path]=data;versions[path]=v or version
 def listing(path,rows,v=None):put(path,{'value':rows},v)
 # Real native parent field collection and GET both bind the same typed identity.
 listing(SCOPE+'/providers/'+ep,[parent]);put(rid,parent)
 for field,segment,v in azure.EMBEDDED_LISTS.get(family,()):listing(rid+'/'+segment,[],v)
 for field,segment,v in azure.EMBEDDED_SINGLETONS.get(family,()):put(rid+'/'+segment,arm(rid+'/'+segment,{}),v)
 # Current App Configuration exposure inventories: NSP associations and Event Grid
 # subscriptions are separate read-only child LISTs; the reviewed store declares none.
 if family=='app_configuration':listing(rid+'/networkSecurityPerimeterConfigurations',[],'2025-08-01-preview');listing(rid+'/providers/Microsoft.EventGrid/eventSubscriptions',[],'2025-02-15')
 # Flexible-server child LISTs keep their own API version after the parent GET moved on.
 child_versions={rid+'/'+segment:v for field,segment,v in azure.EMBEDDED_LISTS.get(family,())}
 for path,row in [(SERVER+'/auditingSettings',auditing),(SERVER+'/securityAlertPolicies',security),(rid+'/firewallRules',firewall),(rid+'/administrators',admins[0])]:listing(path,[row],'2023-08-01'if family=='sql_server'else child_versions.get(path,version))
 listing(SERVER+'/databases',[db],'2023-08-01');put(DB,db,'2023-08-01');put(tde['id'],tde,'2023-08-01')
 for field,segment,v in azure.EMBEDDED_LISTS.get('sql_database',()):listing(DB+'/'+segment,[],v)
 listing(DB+'/providers/Microsoft.Insights/diagnosticSettings',[],'2021-05-01-preview')
 if family=='mysql_flexible_server':listing(rid+'/administrators',admins,child_versions[rid+'/administrators'])
 diag=arm(rid+'/providers/Microsoft.Insights/diagnosticSettings/audit',{'workspaceId':WORKSPACE,'logs':[{'category':'AuditEvent','enabled':True}]});diag['type']='Microsoft.Insights/diagnosticSettings'
 listing(rid+'/providers/Microsoft.Insights/diagnosticSettings',[diag],'2021-05-01-preview')
 put(diag['id'],diag,'2021-05-01-preview')
 cat={'id':rid+'/providers/Microsoft.Insights/diagnosticSettingsCategories/AuditEvent','name':'AuditEvent','type':'Microsoft.Insights/diagnosticSettingsCategories','properties':{'categoryType':'Logs','categoryGroups':['audit','allLogs']}}
 listing(rid+'/providers/Microsoft.Insights/diagnosticSettingsCategories',[cat],'2021-05-01-preview')
 put(cat['id'],cat,'2021-05-01-preview')
 if cid==ACCESS:
  cat['id']=rid+'/providers/Microsoft.Insights/diagnosticSettingsCategories/FrontDoorAccessLog';cat['name']='FrontDoorAccessLog'
  put(cat['id'],cat,'2021-05-01-preview');diag['properties']['logs']=[{'category':'FrontDoorAccessLog','enabled':True}]
 if cid==GWLOG:
  cat['id']=rid+'/providers/Microsoft.Insights/diagnosticSettingsCategories/ApplicationGatewayAccessLog';cat['name']='ApplicationGatewayAccessLog';put(cat['id'],cat,'2021-05-01-preview')
  diag['properties']['logs']=[{'category':'ApplicationGatewayAccessLog','enabled':True}]
  listing(SCOPE+'/providers/'+azure.ENDPOINTS['log_analytics_workspace'][0],[arm(WORKSPACE,{'customerId':TENANT})],azure.ENDPOINTS['log_analytics_workspace'][1])
  listing(WORKSPACE+'/providers/Microsoft.Insights/diagnosticSettings',[],'2021-05-01-preview')
 put(WORKSPACE,arm(WORKSPACE,{'customerId':TENANT}),'2023-09-01')
 # Metadata-only native children selected by APIM; no logger credentials or traces.
 if family=='api_management':
  logger=arm(APIM+'/loggers/applicationinsights',{'loggerType':'applicationInsights','resourceId':COMP,'isBuffered':True})
  api=arm(API,{'type':'http','protocols':['https'],'isCurrent':True,'isOnline':True,'apiRevision':'1'})
  diagnostic=arm(APIM+'/diagnostics/applicationinsights',{'loggerId':logger['id'],'sampling':{'samplingType':'fixed','percentage':100},'alwaysLog':'allErrors'})
  for path,rows in [(APIM+'/apis',[api]),(APIM+'/loggers',[logger]),(APIM+'/diagnostics',[diagnostic]),(API+'/diagnostics',[]),(API+'/revisions',[{'apiId':API,'isOnline':True,'isCurrent':True}]),(APIM+'/workspaces',[]),(API+'/operations',[])]:listing(path,rows,'2024-05-01')
  put(API,api,'2024-05-01');listing(SCOPE+'/providers/Microsoft.Insights/components',[arm(COMP,{'ApplicationId':'telemetry','Application_Type':'web'})],azure.ENDPOINTS['application_insights'][1])
  listing(COMP+'/providers/Microsoft.Insights/diagnosticSettings',[],'2021-05-01-preview')
 if family=='firewall_policy':
  group=arm(rid+'/ruleCollectionGroups/main',{'priority':100,'ruleCollections':[{'name':'internal','priority':100,'ruleCollectionType':'FirewallPolicyFilterRuleCollection','action':{'type':'Allow'},'rules':[{'name':'dns','ruleType':'NetworkRule','ipProtocols':['UDP'],'sourceAddresses':['10.0.0.0/24'],'destinationAddresses':['10.1.0.4'],'destinationPorts':['53']}]}]})
  listing(rid+'/ruleCollectionGroups',[group],'2023-09-01');put(group['id'],group,'2023-09-01')
 # Independent native edge route declaration, including real per-child URLs.
 if family=='cdn_profile':
  endpoint=arm(EP,{'hostName':'review.azurefd.net','enabledState':'Enabled','deploymentStatus':'Succeeded'})
  group=arm(GROUP,{'healthProbeSettings':{'probeProtocol':'Https'}})
  origin=arm(GROUP+'/origins/main',{'hostName':'backend.example.invalid','enabledState':'Enabled'})
  domain=arm(DOMAIN,{'hostName':'review.example.invalid','domainValidationState':'Approved','provisioningState':'Succeeded','deploymentStatus':'Succeeded','tlsSettings':{'certificateType':'ManagedCertificate','minimumTlsVersion':'TLS12','cipherSuiteSetType':'TLS12_2023'}})
  route=arm(EP+'/routes/main',{'supportedProtocols':['Http','Https'],'enabledState':'Enabled','forwardingProtocol':'HttpsOnly','httpsRedirect':'Enabled','patternsToMatch':['/*'],'customDomains':[{'id':DOMAIN}],'linkToDefaultDomain':'Enabled','ruleSets':[],'originGroup':{'id':GROUP}})
  policy=arm(PROFILE+'/securityPolicies/waf',{'parameters':{'type':'WebApplicationFirewall','wafPolicy':{'id':ROOT+'Microsoft.Network/frontdoorWebApplicationFirewallPolicies/waf'},'associations':[{'domains':[{'id':DOMAIN},{'id':EP}],'patternsToMatch':['/*']}]}})
  for path,rows in [(PROFILE+'/afdEndpoints',[endpoint]),(PROFILE+'/customDomains',[domain]),(PROFILE+'/securityPolicies',[policy]),(PROFILE+'/originGroups',[group]),(EP+'/routes',[route]),(GROUP+'/origins',[origin])]:
   listing(path,rows,'2026-07-01'if path.endswith('/originGroups')else'2025-04-15')
   for row in rows:put(row['id'],row,versions[path])
  parent_waf=arm(ROOT+'Microsoft.Network/frontdoorWebApplicationFirewallPolicies/waf',{'policySettings':{'enabledState':'Enabled','mode':'Prevention'},'managedRules':{'managedRuleSets':[{'ruleSetType':'Microsoft_DefaultRuleSet','ruleSetVersion':'2.1'}]},'customRules':{'rules':[]}},sku={'name':'Premium_AzureFrontDoor'})
  listing(SCOPE+'/providers/'+azure.ENDPOINTS['frontdoor_waf_policy'][0],[parent_waf],azure.ENDPOINTS['frontdoor_waf_policy'][1]);put(parent_waf['id'],parent_waf,azure.ENDPOINTS['frontdoor_waf_policy'][1])
  listing(parent_waf['id']+'/providers/Microsoft.Insights/diagnosticSettings',[],'2021-05-01-preview')
 if family=='vm':
  nic=arm(NIC,{'ipConfigurations':[{'id':NIC+'/ipConfigurations/private','name':'private','properties':{'privateIPAddress':'10.0.0.4','subnet':{'id':SUBNET}}}]})
  listing(SCOPE+'/providers/Microsoft.Network/networkInterfaces',[nic],azure.ENDPOINTS['nic'][1]);put(NIC,nic,azure.ENDPOINTS['nic'][1])
  put(VM+'/instanceView',{'statuses':[{'code':'PowerState/running'}]},'2023-09-01')
  listing(NIC+'/providers/Microsoft.Insights/diagnosticSettings',[],'2021-05-01-preview')
 # Native storage/data-protection links; explicit configured selection only.
 if cid in(DISK,BLOB,FILES,NETAPP):
  listing(SCOPE+'/providers/Microsoft.NetApp/netAppAccounts',[],'2026-01-01')
  vault=arm(BACKUP,{'storageSettings':[{'datastoreType':'VaultStore','type':'LocallyRedundant'}]},identity={'type':'SystemAssigned'})
  listing(SCOPE+'/providers/Microsoft.DataProtection/backupVaults',[vault],'2025-07-01');put(BACKUP,vault,'2025-07-01')
  instance=arm(BACKUP+'/backupInstances/protected',{'objectType':'BackupInstance','currentProtectionState':'ProtectionConfigured','dataSourceInfo':{'resourceID':rid,'resourceType':ep,'datasourceType':'Microsoft.Compute/disks'if cid==DISK else'Microsoft.Storage/storageAccounts/blobServices','objectType':'Datasource','resourceLocation':'eastus'},'policyInfo':{'policyId':BACKUP+'/backupPolicies/policy','policyParameters':{'backupDatasourceParametersList':[{'objectType':'BlobBackupDatasourceParameters','containersList':['archive']}]}}})
  listing(BACKUP+'/backupInstances',[instance],'2025-07-01')
  if cid!=DISK:
   listing(STORAGE+'/blobServices/default/containers',[arm(STORAGE+'/blobServices/default/containers/archive',{'publicAccess':'None'})],'2023-05-01')
   listing(STORAGE+'/fileServices/default/shares',[arm(STORAGE+'/fileServices/default/shares/archive',{'accessTier':'Hot','enabledProtocols':'SMB','shareQuota':100})],'2023-05-01')
  rv=arm(RECOVERY,{},sku={'name':'Standard'});listing(SCOPE+'/providers/Microsoft.RecoveryServices/vaults',[rv],azure.ENDPOINTS['recovery_vault'][1]);put(RECOVERY,rv,azure.ENDPOINTS['recovery_vault'][1])
  protected=arm(RECOVERY+'/backupFabrics/Azure/protectionContainers/StorageContainer;Storage;review;reviewstorage/protectedItems/AzureFileShare;archive',{'protectedItemType':'AzureFileShareProtectedItem','protectionState':'Protected','sourceResourceId':STORAGE,'friendlyName':'archive','policyId':RECOVERY+'/backupPolicies/daily'})
  pol=arm(RECOVERY+'/backupPolicies/daily',{'backupManagementType':'AzureStorage','workLoadType':'AzureFileShare','retentionPolicy':{'retentionPolicyType':'LongTermRetentionPolicy'}})
  for path,rows in [(RECOVERY+'/backupProtectedItems',[protected]),(RECOVERY+'/backupPolicies',[pol]),(RECOVERY+'/backupJobs',[])]:listing(path,rows,azure.ENDPOINTS['recovery_vault'][1])
  for parent_id in(RECOVERY,*[STORAGE+'/'+s+'/default'for s in('blobServices','fileServices','queueServices','tableServices')]):
   listing(parent_id+'/providers/Microsoft.Insights/diagnosticSettings',[],'2021-05-01-preview')
 target=parent;path=None;good=bad=None
 if cid in SCALARS:
  path,good,bad=SCALARS[cid]
  target=auditing if kind=='sql_audit'else security if kind=='sql_security'else tde if kind=='sql_tde'else parent
 elif cid in PRIVATE:target=props['privateEndpointConnections'][0];path,good,bad='properties.privateLinkServiceConnectionState.status','Approved','Pending'
 elif cid in KEYS:
  if 'rotation'in cid:target=rotation;path,good,bad='lifetimeActions',[{'action':{'type':'Rotate'},'trigger':{'timeAfterCreate':'P90D'}}],[{'action':{'type':'Notify'},'trigger':{'timeBeforeExpiry':'P30D'}}]
  else:target=key;path,good,bad='attributes.exp',2000000000,None
 elif cid=='azure.sql.restrict_firewall':
  target=firewall;path,good,bad='properties.endIpAddress','10.0.0.254','255.255.255.255'
  if mode=='negative':firewall['properties']['startIpAddress']='0.0.0.0'
 elif cid in(FW,INGRESS):target=firewall;path,good,bad='properties.endIpAddress','10.0.0.254','255.255.255.255';firewall['properties']['startIpAddress']='10.0.0.1'if mode!='negative'else'0.0.0.0'
 elif cid in(SQLADM,FLEXADM):target=admins[0];path,good,bad='properties.administratorType','ActiveDirectory','SQL'
 elif cid==APIM_AI:target=diagnostic;path,good,bad='properties.sampling.percentage',100,0
 elif cid==APIM_TRACE:target=diagnostic;path,good,bad='properties.sampling.percentage',100,0
 elif cid in FD:
  if cid==SNI:target=domain;path,good,bad='properties.customHttpsConfiguration.certificateSource','AzureKeyVault','FrontDoor'
  elif cid==ACCESS:target=diag;path,good,bad='properties.logs',[{'category':'FrontDoorAccessLog','enabled':True}],[{'category':'FrontDoorAccessLog','enabled':False}]
  elif 'minimum_tls'in cid:target=domain;path,good,bad='properties.tlsSettings.cipherSuiteSetType','TLS12_2023','TLS10_2019'
  elif 'internet_access'in cid:target=route;path,good,bad='properties.forwardingProtocol','HttpsOnly','HttpOnly'
  else:target=route;path,good,bad='properties.httpsRedirect','Enabled','Disabled'
 elif cid in(DISK,BLOB):target=instance;path,good,bad='properties.currentProtectionState','ProtectionConfigured','ProtectionStopped'
 elif cid in(FILES,NETAPP):target=protected;path,good,bad='properties.protectionState','Protected','ProtectionStopped'
 elif cid==VMPUB:target=nic;path,good,bad='properties.ipConfigurations',[{'id':NIC+'/ipConfigurations/private','name':'private','properties':{'privateIPAddress':'10.0.0.4'}}],[{'id':NIC+'/ipConfigurations/public','name':'public','properties':{'publicIPAddress':{'id':ROOT+'Microsoft.Network/publicIPAddresses/public'}}}]
 elif cid==WAF:target=parent_waf;path,good,bad='properties.policySettings.enabledState','Enabled','Disabled'
 elif cid==EDGE:
  target=parent;path='properties.frontendIPConfigurations';good=deepcopy(props['frontendIPConfigurations']);bad=deepcopy(good)
  public_id=ROOT+'Microsoft.Network/publicIPAddresses/public';bad[0]['properties']['publicIPAddress']={'id':public_id}
  if mode=='negative':
   public=arm(public_id,{'ipAddress':'20.0.0.1','publicIPAllocationMethod':'Static'},etag='W/"native-public-v1"',sku={'name':'Standard'})
   listing(SCOPE+'/providers/'+azure.ENDPOINTS['public_ip'][0],[public],azure.ENDPOINTS['public_ip'][1]);put(public_id,public,azure.ENDPOINTS['public_ip'][1]);listing(public_id+'/providers/Microsoft.Insights/diagnosticSettings',[],'2021-05-01-preview')
 elif family=='firewall_policy':
  target=group;path,good,bad='properties.ruleCollections',group['properties']['ruleCollections'],[]
 elif family=='web_application_firewall_policy':path,good,bad='properties.managedRules.managedRuleSets',[{'ruleSetType':'OWASP','ruleSetVersion':'3.2'}],[]
 if cid==DIAG:target=diag;path,good,bad='properties.logs',[{'category':'AuditEvent','enabled':True}],[{'category':'AuditEvent','enabled':False}]
 if cid==GWLOG:target=diag;path,good,bad='properties.logs',[{'category':'ApplicationGatewayAccessLog','enabled':True}],[{'category':'ApplicationGatewayAccessLog','enabled':False}]
 if path:assign(target,path,{'malformed':True}if mode=='malformed'else bad if mode=='negative'else good,mode=='missing')
 if cid in KEYS and mode=='negative'and'rotation'not in cid:key['attributes'].pop('exp',None)
 if cid==APIM_TRACE and mode=='negative':routes[APIM+'/diagnostics']={'value':[]}
 if cid in(SQLADM,FLEXADM)and mode=='negative':routes[rid+'/administrators']={'value':[]}
 if mode=='empty':routes[SCOPE+'/providers/'+ep]={'value':[]}
 index=[]
 for typ,v in azure.ENDPOINTS.values():
  data=routes.get(SCOPE+'/providers/'+typ,{})
  index.extend(deepcopy(data.get('value',[])))
 if mode=='foreign':parent['id']=rid.replace(SUB,OTHER)
 if mode=='wrong_type':parent['type']='Microsoft.Unrelated/resources'
 if mode=='wrong_type'and cid==DIAG:
  for native in index:native['type']='Microsoft.Unrelated/resources'
 if mode=='foreign'and cid==DIAG:
  for native in index:native['id']=native['id'].replace(SUB,OTHER)
 # The native database administrator reader keeps its own reviewed server GET
 # version while the inventory parent GET moved on; both read the same server.
 from peaso.collectors.azure_database_native import SOURCES as DATABASE_SOURCES
 alternate={rid:DATABASE_SOURCES[family][1]}if family in DATABASE_SOURCES else{}
 return {'family':family,'endpoint':ep,'version':version,'parent':parent,'rid':rid,'routes':routes,'versions':versions,'alternate':alternate,'key':key,'rotation':rotation,'deciding':path,'index':index}

class NativeHTTP:
 def __init__(self,cid,mode='positive',mutate=None):
  self.cid=cid;self.mode=mode;self.d=case(cid,mode);self.calls=[];self.unexpected=[]
  if mutate:mutate(self.d)
 def open(self,request,timeout):
  try:
   response=self._open(request,timeout)
   response.status=200
   return response
  except HTTPError:raise
  except Exception as exc:self.unexpected.append((request.full_url,type(exc).__name__+': '+str(exc)));raise
 def _open(self,request,timeout):
  d=self.d;p=urlsplit(request.full_url);q=parse_qs(p.query);path=p.path;method=request.get_method()
  assert timeout==20 and p.scheme=='https'and p.netloc in('management.azure.com','reviewvault.vault.azure.net')
  assert set(q)<={'api-version','$top','$expand','$select','$filter','page','databaseState','includePending','includeConsistencyToken'}and len(q.get('api-version',[]))==1
  self.calls.append({'method':method,'host':p.netloc,'path':path,'query':q})
  def denied():raise HTTPError(request.full_url,403,'offline denied',{},io.BytesIO(b'{}'))
  if self.mode=='denied'or'page'in q:denied()
  if method=='POST':
   assert path=='/providers/Microsoft.ResourceGraph/resources'and q['api-version'][0]in('2022-10-01','2024-04-01')and json.loads(request.data)['subscriptions']==[SUB]
   value={'data':d['index'],'resultTruncated':False}
  else:
   assert method=='GET'and request.data is None
   if p.netloc=='reviewvault.vault.azure.net':
    assert q['api-version']==['2025-07-01']and path in('/keys','/keys/metadata/rotationpolicy')
    if self.mode=='child_denied':denied()
    value={'value':deepcopy(d.get('key_rows',[d['key']]))}if path=='/keys'else deepcopy(d['rotation'])
    if self.mode=='child_partial'and path=='/keys':value['nextLink']=ORIGIN+'/keys?api-version=2025-07-01&page=2'
   elif path in('/subscriptions',SCOPE):
    value={'id':SCOPE,'subscriptionId':SUB,'tenantId':TENANT,'state':'Enabled'}
    if path=='/subscriptions':value={'value':[value]}
   elif path==SCOPE+'/resources':
    assert q['api-version']==['2021-04-01'];value={'value':d['index']}
   elif path in d['routes']:
    assert q['api-version']in([d['versions'][path]],[d['alternate'].get(path)]),(path,q,d['versions'][path])
    child_path=path.startswith(d['rid']+'/')or path==BACKUP+'/backupInstances'
    if self.mode=='child_denied'and child_path:denied()
    value=deepcopy(d['routes'][path])
    if self.mode=='partial'and path==SCOPE+'/providers/'+d['endpoint']:value['nextLink']=azure.ARM+path+'?api-version='+d['version']+'&page=2'
    if self.mode=='child_partial'and'value'in value and child_path:value['nextLink']=azure.ARM+path+'?api-version='+d['versions'][path]+'&page=2'
   elif path==SCOPE+'/providers/Microsoft.Network/locations/westcentralus/serviceTags':
    assert q['api-version']==['2025-09-01'];value={'value':[]}
   elif path in(SCOPE+'/providers/Microsoft.Authorization/locks',SCOPE+'/resourceGroups/review/providers/Microsoft.Authorization/locks',STORAGE+'/providers/Microsoft.Authorization/locks'):
    assert q['api-version']==['2016-09-01'];value={'value':[]}
   elif path in empty_inventory_versions(SCOPE):
    assert matches_empty_inventory_query(SCOPE,path,q);value={'value':[]}
   else:
    endpoints={SCOPE+'/providers/'+ep:v for ep,v in azure.ENDPOINTS.values()};endpoints[SCOPE+'/resourcegroups']='2021-04-01'
    assert path in endpoints,('UNDECLARED native fixture route',path);assert q['api-version']==[endpoints[path]]
    value={'value':[]}
  return io.BytesIO(json.dumps(value).encode())

@pytest.fixture(autouse=True)
def offline(monkeypatch):
 def blocked(*a,**kw):raise AssertionError('Network/DNS/auth forbidden')
 for obj,names in((socket,('getaddrinfo','create_connection')),(socket.socket,('connect','connect_ex')),(azure,('credential_for',))):
  for n in names:monkeypatch.setattr(obj,n,blocked)

def capture(monkeypatch,cid,mode='positive',mutate=None):
 http=NativeHTTP(cid,mode,mutate);monkeypatch.setattr(azure,'build_opener',lambda *a:http)
 connector={'provider':'azure','scopes':[SUB],'auth':{'method':'token','arm_token':ARM_TOKEN,'vault_token':'fixture-inert','tenant_id':TENANT},'options':{'retries':0,'concurrency':1}}
 snapshot=collect_snapshot({'connector':connector,'checks':[cid]})
 findings=evaluate_snapshot(snapshot,checks=[cid],include_not_applicable=True)['findings']
 assert not http.unexpected,http.unexpected
 assert findings,(cid,snapshot)
 return findings,snapshot,http

UNRESOLVED={HOSTPID,READONLY,DEVOPS}

def expected(cid,mode):
 kind=REGISTRY[cid].kind;scope=REGISTRY[cid].target=='scope'
 if mode in('foreign','wrong_type','malformed'):return 'UNKNOWN'
 if mode=='denied':return 'UNKNOWN'if cid in FD or cid in(READONLY,DEVOPS,INGRESS)else'DENIED'
 if mode=='empty':
  if cid==DEVOPS:return 'UNKNOWN'
  if cid==GWLOG:return 'NOT_APPLICABLE'  # Complete empty AppGateway universe; L4 LB HTTP logs excluded.
  if cid in(READONLY,SQLADM,NETAPP,VMPUB):return 'PASS'
  return 'NOT_APPLICABLE'if scope else'EMPTY'
 if cid in UNRESOLVED:return 'UNKNOWN'
 if cid==EDGE:return 'UNKNOWN'if mode in('partial','missing','negative')else'NOT_APPLICABLE'
 if cid==APIM_TRACE:return 'FAIL'if mode=='negative'else'UNKNOWN'
 if mode=='partial':
  if kind in('firewall_policy','web_application_firewall_policy'):return 'UNKNOWN'
  if cid in KEYS:return 'UNKNOWN'if 'with_'in cid else'PASS'
  if kind in('sql_audit','sql_security','sql_firewall_rule','sql_tde')or cid==DIAG:return 'PASS'
  return 'UNKNOWN'if scope or cid in FD or cid==APIM_AI else'PASS,UNKNOWN'
 if mode in('child_partial','child_denied'):
  if cid==SNI:return 'PASS'
  if cid==WAF:return 'UNKNOWN'
  if cid in KEYS:return ('UNKNOWN'if'rotation'in cid else'PASS,UNKNOWN')if mode=='child_partial'else'DENIED'
  if kind in('sql_audit','sql_security','sql_firewall_rule'):return 'PASS,UNKNOWN'if mode=='child_partial'else'DENIED'
  if kind=='sql_tde':return 'PASS'if mode=='child_partial'else'DENIED'
  if cid in(DIAG,GWLOG):return 'DENIED'if cid==DIAG or mode=='child_denied'else'UNKNOWN'
  if cid==FILES:return 'UNKNOWN'
  if cid in(DISK,BLOB,NETAPP):return 'DENIED'if mode=='child_denied'else'UNKNOWN'
  if cid in FD or cid in(APIM_AI,SQLADM,FLEXADM,FW,INGRESS)or kind=='firewall_policy':return 'UNKNOWN'
  return 'PASS'
 if mode=='missing':
  if cid==WAF:return 'PASS'  # Documented enabledState default on actual native full GET.
  if cid==ACCESS:return 'FAIL'  # Actual full GET omitted logs normalizes empty enabled exports.
  if cid in KEYS or kind=='web_application_firewall_policy':return 'FAIL'
  return 'UNKNOWN'
 return 'FAIL'if mode=='negative'else'PASS'

@pytest.mark.parametrize('cid',ROSTER)
@pytest.mark.parametrize('mode',('positive','negative','missing','malformed','denied','partial','empty','foreign','wrong_type','child_denied','child_partial'))
def test_native_matrix(monkeypatch,cid,mode,record_property):
 findings,snapshot,http=capture(monkeypatch,cid,mode)
 actual=','.join(sorted({f['status']for f in findings}));want=expected(cid,mode)
 record_property('check_id',cid);record_property('mode',mode);record_property('actual',actual);record_property('expected',want)
 if mode=='positive':record_property('native_capture',json.dumps({'http':http.calls,'collections':[{'type':c['type'],'scope':c['scope'],'status':c['status']}for c in snapshot['collections']]}))
 assert actual==want,findings

@pytest.fixture(scope='module')
def native_ca():
 from datetime import datetime,timezone
 from cryptography import x509
 from cryptography.hazmat.primitives import hashes,serialization
 from cryptography.hazmat.primitives.asymmetric import rsa
 from cryptography.x509.oid import NameOID
 key=rsa.generate_private_key(public_exponent=65537,key_size=2048);name=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'Offline native review CA')])
 return x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key()).serial_number(49).not_valid_before(datetime(2025,1,1,tzinfo=timezone.utc)).not_valid_after(datetime(2030,1,1,tzinfo=timezone.utc)).add_extension(x509.BasicConstraints(ca=True,path_length=None),critical=True).sign(key,hashes.SHA256()).public_bytes(serialization.Encoding.PEM).decode()

@pytest.mark.parametrize('cid',(HOSTPID,READONLY))
@pytest.mark.parametrize('variant,want',(('positive','PASS'),('negative','FAIL'),('missing_flag','PASS'),('malformed_flag','UNKNOWN'),('denied_workload','DENIED'),('partial_workload','UNKNOWN'),('foreign_namespace','UNKNOWN'),('wrong_native_kind','UNKNOWN'),('missing_uid','UNKNOWN'),('foreign_arm_endpoint','UNKNOWN')))
def test_explicit_aks_native_http(monkeypatch,native_ca,cid,variant,want,record_property):
 from urllib3 import PoolManager
 from urllib3.response import HTTPResponse
 from peaso.collectors.azure_aks_workloads_native import WORKLOADS
 http=NativeHTTP(cid);rid=http.d['rid'];host=http.d['parent']['properties']['fqdn'];calls=[];unexpected=[]
 if variant=='foreign_arm_endpoint':http.d['parent']['properties']['fqdn']='foreign.hcp.eastus.azmk8s.io'
 monkeypatch.setattr(azure,'build_opener',lambda *a:http)
 def obj(kind,name,namespace=None,version='v1'):
  r={'apiVersion':version,'kind':kind,'metadata':{'name':name,'uid':kind+'-'+name,'resourceVersion':'42'}}
  if namespace:r['metadata']['namespace']=namespace
  return r
 namespaces=[obj('Namespace','kube-system'),obj('Namespace','default')]
 def fake_pool(self,method,url,**kwargs):
  try:
   p=urlsplit(url);q=parse_qs(p.query);assert method=='GET'and p.scheme=='https'and p.hostname==host and p.port in(None,443)
   assert set(q)<={'limit','continue','resourceVersion','resourceVersionMatch','timeoutSeconds'}
   calls.append({'method':method,'host':p.netloc,'path':p.path,'query':q})
   if p.path=='/api/v1/namespaces/kube-system':value=namespaces[0]
   elif p.path=='/api/v1/namespaces':value={'apiVersion':'v1','kind':'NamespaceList','metadata':{'resourceVersion':'42'},'items':namespaces}
   else:
    schemas={v[0]:(k,v[1],v[2],v[3])for k,v in WORKLOADS.items()};schemas['/api/v1/pods']=('pod','Pod','v1','spec')if cid==HOSTPID else schemas['/api/v1/pods']
    assert p.path in schemas,p.path
    kind,typ,version,specpath=schemas[p.path]
    if variant=='denied_workload':return HTTPResponse(status=403,body=b'{}',headers={'Content-Type':'application/json'})
    if q.get('continue'):return HTTPResponse(status=403,body=b'{}',headers={'Content-Type':'application/json'})
    row=obj(typ,'app','foreign'if variant=='foreign_namespace'else'default',version);spec={'containers':[{'name':'app','securityContext':{'readOnlyRootFilesystem':True}}]}
    if cid==HOSTPID:spec['hostPID']=variant=='negative'
    elif variant=='negative':spec['containers'][0]['securityContext']['readOnlyRootFilesystem']=False
    field='hostPID'if cid==HOSTPID else'readOnlyRootFilesystem';target=spec if cid==HOSTPID else spec['containers'][0]['securityContext']
    if variant=='missing_flag':target.pop(field,None)
    if variant=='malformed_flag':target[field]='false'
    if variant=='wrong_native_kind':row['kind']='Service'
    if variant=='missing_uid':row['metadata'].pop('uid')
    node=row
    for part in specpath.split('.')[:-1]:node=node.setdefault(part,{})
    node[specpath.split('.')[-1]]=spec
    value={'apiVersion':version,'kind':typ+'List','metadata':{'resourceVersion':'42'},'items':[row]}
    if variant=='partial_workload':value['metadata']['continue']='next'
   return HTTPResponse(status=200,body=json.dumps(value).encode(),headers={'Content-Type':'application/json'})
  except Exception as exc:unexpected.append((url,type(exc).__name__+': '+str(exc)));raise
 monkeypatch.setattr(PoolManager,'request',fake_pool)
 auth={'method':'token','arm_token':ARM_TOKEN,'tenant_id':TENANT,'aks_workloads':[{'cluster_id':rid,'server':'https://'+host,'ca_cert_data':native_ca,'token':'inert-kubernetes-review'}]}
 snapshot=collect_snapshot({'connector':{'provider':'azure','scopes':[SUB],'auth':auth,'options':{'retries':0,'concurrency':1}},'checks':[cid]})
 findings=evaluate_snapshot(snapshot,checks=[cid],include_not_applicable=True)['findings']
 assert not http.unexpected,http.unexpected
 assert not unexpected,unexpected
 actual=','.join(sorted({f['status']for f in findings}));want='FAIL'if cid==READONLY and variant=='missing_flag'else'UNKNOWN'if variant=='denied_workload'else want
 record_property('check_id',cid);record_property('mode','aks_http_'+variant);record_property('actual',actual);record_property('expected',want);record_property('native_http',json.dumps(calls))
 assert actual==want,findings

@pytest.mark.parametrize('cid',('azure.port.app_configuration_encryption_enabled','azure.port.data_factory_public_network_access_disabled','azure.port.search_service_public_network_access_disabled'))
def test_native_same_subscription_wrong_parent_kind_is_not_selected_service(monkeypatch,cid,record_property):
 def mutate(d):
  d['parent']['id']=ROOT+'Microsoft.Unrelated/resources/review'
  path=d['parent']['id']+'/providers/Microsoft.Insights/diagnosticSettings';d['routes'][path]={'value':[]};d['versions'][path]='2021-05-01-preview'
 findings,snapshot,http=capture(monkeypatch,cid,mutate=mutate)
 actual=','.join(sorted({f['status']for f in findings}));record_property('check_id',cid);record_property('mode','native_parent_id_type_conflict');record_property('actual',actual);record_property('expected','UNKNOWN')
 assert actual=='UNKNOWN',findings

@pytest.mark.parametrize('cid',tuple(sorted(PRIVATE)))
def test_native_private_link_child_cannot_belong_to_foreign_service(monkeypatch,cid,record_property):
 def mutate(d):d['parent']['properties']['privateEndpointConnections'][0]['id']=d['parent']['properties']['privateEndpointConnections'][0]['id'].replace(SUB,OTHER)
 findings,snapshot,http=capture(monkeypatch,cid,mutate=mutate)
 actual=','.join(sorted({f['status']for f in findings}));record_property('check_id',cid);record_property('mode','foreign_native_private_connection');record_property('actual',actual);record_property('expected','UNKNOWN')
 assert actual=='UNKNOWN',findings

@pytest.mark.parametrize('variant,want',(('clean_accessible','PASS'),('userinfo','FAIL'),('denied','DENIED'),('foreign_project','UNKNOWN'),('missing_urls','UNKNOWN')))
def test_explicit_devops_metadata_http(monkeypatch,variant,want,record_property):
 from peaso.collectors import azure_devops_git_native as native
 from peaso.engine import collect_snapshot as current_collect, evaluate_snapshot as current_evaluate
 current_id="azure.review.devops.visible_clone_urls_without_userinfo"
 record_property("historical_id",DEVOPS)
 record_property("criterion","API-visible clone URLs only; no hidden-repository completeness claim")
 project='33333333-3333-3333-3333-333333333333';repo='44444444-4444-4444-4444-444444444444';calls=[];unexpected=[]
 class Response(io.BytesIO):
  headers={}
  status=200
 class Http:
  def open(self,request,timeout):
   try:
    p=urlsplit(request.full_url);q=parse_qs(p.query);path=p.path
    assert request.get_method()=='GET'and p.scheme=='https'and p.netloc=='dev.azure.com'and 0<timeout<=20
    assert q.get('api-version')==['7.1']and set(q)<={'api-version','stateFilter','$top','includeHidden','includeAllUrls'}
    paths=['/revieworg/_apis/projects','/revieworg/_apis/projects/'+project,'/revieworg/'+project+'/_apis/git/repositories','/revieworg/'+project+'/_apis/git/repositories/'+repo]
    assert path in paths,path;calls.append({'method':'GET','host':p.netloc,'path':path,'query':q})
    if variant=='denied':raise HTTPError(request.full_url,403,'offline denied',{},io.BytesIO(b'{}'))
    pr={'id':project,'name':'review','state':'wellFormed'}
    repository={'id':repo,'name':'review','project':{'id':OTHER if variant=='foreign_project'else project},'remoteUrl':'https://user:fixture@dev.azure.com/revieworg/review/_git/review'if variant=='userinfo'else'https://dev.azure.com/revieworg/review/_git/review','validRemoteUrls':[]}
    if variant=='missing_urls':repository.pop('validRemoteUrls')
    if path==paths[0]:
     assert q['stateFilter']==['all']and q['$top']==['100'];value={'count':1,'value':[pr]}
    elif path==paths[1]:value=pr
    elif path==paths[2]:
     assert q['includeHidden']==['true']and q['includeAllUrls']==['true'];value={'count':1,'value':[repository]}
    else:value=repository
    return Response(json.dumps(value).encode())
   except HTTPError:raise
   except Exception as exc:unexpected.append((request.full_url,type(exc).__name__+': '+str(exc)));raise
 h=NativeHTTP(DEVOPS);monkeypatch.setattr(azure,'build_opener',lambda *a:h);monkeypatch.setattr(native,'build_opener',lambda *a:Http())
 selector={'subscriptions':[{'scope':SCOPE,'organization':'revieworg','project_ids':[project]}]}
 connector={'provider':'azure','scopes':[SUB],'auth':{'method':'token','arm_token':ARM_TOKEN,'tenant_id':TENANT,'devops_credentials':[{'server':'https://dev.azure.com/revieworg','method':'bearer','token':'inert-review'}]},'options':{'retries':0,'concurrency':1,'compliance_parameters':{'azure_devops_git':selector}}}
 snapshot=current_collect({'connector':connector,'checks':[current_id]});findings=current_evaluate(snapshot,checks=[current_id],include_not_applicable=True)['findings']
 assert not unexpected,unexpected
 assert 'user:fixture'not in json.dumps(snapshot)
 actual=','.join(sorted({f['status']for f in findings}));record_property('check_id',current_id);record_property('mode','devops_http_'+variant);record_property('actual',actual);record_property('expected',want);record_property('native_http',json.dumps(calls))
 assert actual==want,findings

@pytest.mark.parametrize('cid',tuple(sorted(KEYS)))
@pytest.mark.parametrize('variant',('foreign_key_origin','conflicting_key_identity'))
def test_native_key_identity_conflicts_cannot_be_clean(monkeypatch,cid,variant,record_property):
 def mutate(d):
  if variant=='foreign_key_origin':d['key']['kid']='https://foreign.vault.azure.net/keys/metadata'
  else:
   other=deepcopy(d['key']);other['attributes']['exp']=None;d['key_rows']=[other,deepcopy(d['key'])]
 findings,snapshot,http=capture(monkeypatch,cid,mutate=mutate)
 actual=','.join(sorted({f['status']for f in findings}));record_property('check_id',cid);record_property('mode',variant);record_property('actual',actual);record_property('expected','UNKNOWN')
 assert actual=='UNKNOWN',findings

@pytest.mark.parametrize('cid',('azure.port.keyvault_with_rbac_key_expiration_set','azure.port.keyvault_with_non_rbac_key_expiration_set'))
def test_other_native_key_authorization_mode_is_excluded(monkeypatch,cid,record_property):
 def mutate(d):d['parent']['properties']['enableRbacAuthorization']=not d['parent']['properties']['enableRbacAuthorization']
 findings,snapshot,http=capture(monkeypatch,cid,mutate=mutate)
 actual=','.join(sorted({f['status']for f in findings}));record_property('check_id',cid);record_property('mode','opposite_native_rbac');record_property('actual',actual);record_property('expected','NOT_APPLICABLE')
 assert actual=='NOT_APPLICABLE',findings

@pytest.mark.parametrize('cid',('azure.port.keyvault_key_automatic_rotation_enabled',GWLOG))
@pytest.mark.parametrize('variant',('missing_parent_nonce','foreign_child_nonce','foreign_child_scope'))
def test_scope_alias_requires_actual_capture_binding(monkeypatch,cid,variant,record_property):
 from peaso.snapshot import make_snapshot
 findings,snapshot,http=capture(monkeypatch,cid);collections=deepcopy(snapshot['collections'])
 parent_type='vault'if cid in KEYS else'application_gateway';child_type='key_rotation_policy'if cid in KEYS else'diagnostic_setting'
 parent=next(c for c in collections if c['type']==parent_type);child=next(c for c in collections if c['type']==child_type and c['items'])
 if variant=='missing_parent_nonce':parent['items'][0]['_provenance'].pop('credential_context_id',None)
 elif variant=='foreign_child_nonce':child['_provenance']['credential_context_id']='f'*32
 else:child['scope']=child['scope'].replace(SUB,OTHER)
 snap=make_snapshot('azure',snapshot['scopes'],collections,metadata=snapshot['metadata'],created_at=snapshot['created_at'])
 findings=evaluate_snapshot(snap,checks=[cid],include_not_applicable=True)['findings'];actual=','.join(sorted({f['status']for f in findings}))
 record_property('check_id',cid);record_property('mode',variant);record_property('actual',actual);record_property('expected','UNKNOWN')
 assert actual=='UNKNOWN',findings

@pytest.mark.parametrize('cid',tuple(sorted(KEYS)))
def test_identical_native_key_repeat_is_safe(monkeypatch,cid,record_property):
 def mutate(d):d['key_rows']=[deepcopy(d['key']),deepcopy(d['key'])]
 findings,snapshot,http=capture(monkeypatch,cid,mutate=mutate);actual=','.join(sorted({f['status']for f in findings}))
 record_property('check_id',cid);record_property('mode','identical_key_repeat');record_property('actual',actual);record_property('expected','PASS')
 assert actual=='PASS',findings

@pytest.mark.parametrize('cid',tuple(sorted(PRIVATE)))
@pytest.mark.parametrize('variant,want',(('identical','PASS'),('conflict','UNKNOWN'),('wrong_child_type','UNKNOWN')))
def test_private_connection_native_consistency(monkeypatch,cid,variant,want,record_property):
 def mutate(d):
  rows=d['parent']['properties']['privateEndpointConnections'];other=deepcopy(rows[0])
  if variant=='wrong_child_type':rows[0]['type']='Microsoft.Unrelated/resources'
  else:
   if variant=='conflict':other['properties']['privateLinkServiceConnectionState']['status']='Rejected'
   rows.append(other)
 findings,snapshot,http=capture(monkeypatch,cid,mutate=mutate);actual=','.join(sorted({f['status']for f in findings}))
 record_property('check_id',cid);record_property('mode','native_private_'+variant);record_property('actual',actual);record_property('expected',want)
 assert actual==want,findings

@pytest.mark.parametrize('cid',tuple(c for c in ROSTER if c.startswith('azure.sql.')))
@pytest.mark.parametrize('variant',('wrong_native_type','wrong_native_child_segment'))
def test_core_sql_native_deciding_child_identity(monkeypatch,cid,variant,record_property):
 def mutate(d):
  kind=REGISTRY[cid].kind
  path=DB+'/transparentDataEncryption/current'if kind=='sql_tde'else SERVER+'/'+{'sql_audit':'auditingSettings','sql_security':'securityAlertPolicies','sql_firewall_rule':'firewallRules'}[kind]
  row=d['routes'][path]if kind=='sql_tde'else d['routes'][path]['value'][0]
  if variant=='wrong_native_type':row['type']='Microsoft.Unrelated/resources'
  else:row['id']=SERVER+'/unrelated/default'
 findings,snapshot,http=capture(monkeypatch,cid,mutate=mutate);actual=','.join(sorted({f['status']for f in findings}))
 record_property('check_id',cid);record_property('mode','sql_child_'+variant);record_property('actual',actual);record_property('expected','UNKNOWN')
 assert actual=='UNKNOWN',findings
