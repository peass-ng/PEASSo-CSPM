"""Finite independent native HTTP bytes -> Azure collector -> public engine,51 IDs.

No historical CASES, approvals, synthetic completeness or effective-access facts.
"""
from copy import deepcopy
from datetime import datetime,timezone
import base64
import io
import json
import socket
from pathlib import Path
from urllib.error import HTTPError
from urllib.parse import parse_qs,urlsplit
import pytest
from tests.azure_native_inventory_routes_20261020 import empty_inventory_versions,matches_empty_inventory_query
from peaso.checks import CHECKS
from peaso.collectors import azure,azure_sql_ltr_native
# Retired Single Server witnesses remain explicitly replayable in tests;
# the unmodified product engine rejects those IDs for automatic scans.
from tests.archived_check_contract import evaluate_snapshot,plan_collection

SUB='11111111-1111-1111-1111-111111111111'
OTHER='99999999-9999-9999-9999-999999999999'
TENANT='22222222-2222-2222-2222-222222222222'
SCOPE='/subscriptions/'+SUB
RG=SCOPE+'/resourceGroups/review'
SERVER=RG+'/providers/Microsoft.Sql/servers/reviewsql'
DATABASE=SERVER+'/databases/app'
VAULT=RG+'/providers/Microsoft.KeyVault/vaults/reviewvault'
ORIGIN='https://reviewvault.vault.azure.net'
SUBNET=RG+'/providers/Microsoft.Network/virtualNetworks/v/subnets/s'
STORAGE=RG+'/providers/Microsoft.Storage/storageAccounts/archive'
REGISTRY={c.id:c for c in CHECKS}
ROSTER=('azure.claude.recovery_vault_has_protected_items', 'azure.claude.recovery_vault_managed_identity', 'azure.claude.recovery_vault_private_endpoint_backup', 'azure.claude.recovery_vault_private_endpoint_site_recovery', 'azure.claude.sql_database_va_findings_resolved', 'azure.claude.sql_server_entra_admin', 'azure.claude.sql_server_minimal_tls_12', 'azure.claude.sql_server_private_link', 'azure.claude.sql_server_vnet_rules', 'azure.claude.sql_server_vulnerability_assessment_enabled', 'azure.claude.sql_tde_protector_cmk', 'azure.claude.sql_va_notify_admins', 'azure.claude.sql_va_recurring_scans', 'azure.claude.sql_va_report_emails', 'azure.claude.sql_va_reports_configured', 'azure.claude2.sql_server_threat_detection_all_alerts', 'azure.gap.postgres_db_server_log_duration_on', 'azure.gap.postgresql_server_infrastructure_encryption_enabled', 'azure.gap.sql_database_long_term_geo_redundant_backup_enabled', 'azure.htbp.keyvault.template_deployment_disabled', 'azure.htbp.postgresql.password_auth_disabled', 'azure.htbp.redis.access_key_auth_disabled', 'azure.htbp.sql.entra_only_authentication', 'azure.other.backup_immutability_30', 'azure.port.cosmosdb_account_uses_private_link', 'azure.port.cosmosdb_account_virtual_network_filter_enabled', 'azure.port.keyvault_logging_enabled', 'azure.port.keyvault_public_network_access_disabled', 'azure.port.keyvault_secret_expiration_set', 'azure.port.keyvault_vault_private_link_used', 'azure.port.keyvault_vault_recoverable', 'azure.port.keyvault_with_non_rbac_secret_expiration_set', 'azure.port.keyvault_with_rbac_secret_expiration_set', 'azure.port.redis_cache_in_virtual_network', 'azure.port.redis_cache_min_tls_1_2', 'azure.port.redis_cache_no_basic_sku', 'azure.port.redis_cache_ssl_enabled', 'azure.port.redis_cache_uses_private_link', 'azure.sql.minimum_tls', 'azure.sql.no_public_network', 'azure.vault.approved_private_endpoint', 'azure.vault.default_deny', 'azure.vault.no_public_network', 'azure.vault.purge_protection', 'azure.vault.rbac', 'azure.vault.secret_expiration', 'azure.vault.soft_delete', 'azure_cosmos_account_10_2_1_1_13_5c115b0', 'azure_recovery_vault_10_3_3_1_1f42f66', 'azure_sql_database_sqlserver_tde_encryption_enabled_c4383b5', 'azure_vault_3_7_1_2_532ecd2')

SCALARS={
 'azure.claude.recovery_vault_managed_identity':('identity',{'type':'SystemAssigned','principalId':TENANT,'tenantId':TENANT},{'type':'None'}),
 'azure.claude.recovery_vault_private_endpoint_backup':('properties.privateEndpointStateForBackup','Enabled','None'),
 'azure.claude.recovery_vault_private_endpoint_site_recovery':('properties.privateEndpointStateForSiteRecovery','Enabled','None'),
 'azure.claude.sql_server_minimal_tls_12':('properties.minimalTlsVersion','1.2','1.1'),
 'azure.sql.minimum_tls':('properties.minimalTlsVersion','1.2','1.1'),
 'azure.sql.no_public_network':('properties.publicNetworkAccess','Disabled','Enabled'),
 'azure.htbp.keyvault.template_deployment_disabled':('properties.enabledForTemplateDeployment',False,True),
 'azure.htbp.postgresql.password_auth_disabled':('properties.authConfig.passwordAuth','Disabled','Enabled'),
 'azure.htbp.redis.access_key_auth_disabled':('properties.disableAccessKeyAuthentication',True,False),
 'azure.port.cosmosdb_account_virtual_network_filter_enabled':('properties.isVirtualNetworkFilterEnabled',True,False),
 'azure.port.keyvault_public_network_access_disabled':('properties.networkAcls.defaultAction','Deny','Allow'),
 'azure.port.keyvault_vault_private_link_used':('properties.networkAcls.defaultAction','Deny','Allow'),
 'azure.port.keyvault_vault_recoverable':('properties.enablePurgeProtection',True,False),
 'azure.vault.default_deny':('properties.networkAcls.defaultAction','Deny','Allow'),
 'azure.vault.no_public_network':('properties.publicNetworkAccess','Disabled','Enabled'),
 'azure.vault.purge_protection':('properties.enablePurgeProtection',True,False),
 'azure.vault.rbac':('properties.enableRbacAuthorization',True,False),
 'azure.vault.soft_delete':('properties.enableSoftDelete',True,False),
 'azure.port.redis_cache_in_virtual_network':('properties.subnetId',SUBNET,None),
 'azure.port.redis_cache_min_tls_1_2':('properties.minimumTlsVersion','1.2','1.1'),
 'azure.port.redis_cache_no_basic_sku':('properties.sku.name','Premium','Basic'),
 'azure.port.redis_cache_ssl_enabled':('properties.enableNonSslPort',False,True),
 'azure.vault.approved_private_endpoint':('properties.networkAcls.defaultAction','Deny','Allow'),
}
PRIVATE_LINK={'azure.claude.sql_server_private_link','azure.port.cosmosdb_account_uses_private_link','azure.port.redis_cache_uses_private_link'}
SECRET_IDS={c for c in ROSTER if REGISTRY[c].kind=='secret_metadata'}
VA_IDS={c for c in ROSTER if REGISTRY[c].kind=='sql_vulnerability_assessment'}
CERT='azure_vault_3_7_1_2_532ecd2'
MONGO='azure_cosmos_account_10_2_1_1_13_5c115b0'
IMMUTABLE='azure.other.backup_immutability_30'
TDE='azure_sql_database_sqlserver_tde_encryption_enabled_c4383b5'
PITR='azure_recovery_vault_10_3_3_1_1f42f66'
LTR='azure.gap.sql_database_long_term_geo_redundant_backup_enabled'
LEGACY='azure.gap.postgresql_server_infrastructure_encryption_enabled'
PUBLIC_CERTIFICATES=json.loads((Path(__file__).parent/'fixtures/azure_database_crypto_backup_2_public_certificates_20261020.json').read_text())['certificates']


def assign(row,path,value,omit=False):
    parts=path.split('.')
    for part in parts[:-1]:row=row.setdefault(part,{})
    if omit:row.pop(parts[-1],None)
    else:row[parts[-1]]=deepcopy(value)


def native_case(cid,mode):
    kind=REGISTRY[cid].kind
    pk='vault'if kind in ('secret_metadata','key_vault_certificate')else'sql_server'if kind in ('sql_database','sql_encryption_protector','sql_vulnerability_assessment')else'postgresql_single_server'if cid==LEGACY else kind
    ep,version=azure.ENDPOINTS[pk];rid=RG+'/providers/'+ep+'/'+('reviewvault'if pk=='vault'else'reviewsql'if pk=='sql_server'else'review')
    p={'provisioningState':'Succeeded'}
    if pk=='sql_server':p.update(minimalTlsVersion='1.2',publicNetworkAccess='Disabled',version='12.0')
    if pk=='vault':p.update(vaultUri=ORIGIN+'/',tenantId=TENANT,sku={'family':'A','name':'standard'},accessPolicies=[],enableRbacAuthorization=True,enablePurgeProtection=True,enableSoftDelete=True,enabledForTemplateDeployment=False,networkAcls={'defaultAction':'Deny','bypass':'None'},publicNetworkAccess='Disabled')
    if pk=='redis_cache':p.update(sku={'name':'Premium','family':'P','capacity':1},minimumTlsVersion='1.2',enableNonSslPort=False,disableAccessKeyAuthentication=True,subnetId=SUBNET,redisVersion='6.0')
    if pk=='recovery_vault':p.update(privateEndpointStateForBackup='Enabled',privateEndpointStateForSiteRecovery='Enabled',securitySettings={'immutabilitySettings':{'state':'Locked'}})
    if pk=='postgresql_flexible_server':p.update(version='16',authConfig={'activeDirectoryAuth':'Enabled','passwordAuth':'Disabled'},network={'publicNetworkAccess':'Disabled'})
    if pk=='postgresql_single_server':p.update(version='11',infrastructureEncryption='Enabled')
    if pk=='cosmos_account':p.update(databaseAccountOfferType='Standard',publicNetworkAccess='Enabled',isVirtualNetworkFilterEnabled=True,capabilities=[{'name':'EnableMongo'}])
    item={'id':rid,'name':rid.rsplit('/',1)[-1],'type':ep,'location':'eastus','properties':p}
    if pk=='recovery_vault':item.update(sku={'name':'Standard'},identity={'type':'SystemAssigned','principalId':TENANT,'tenantId':TENANT})
    pe={'id':rid+'/privateEndpointConnections/pe','name':'pe','type':ep+'/privateEndpointConnections','properties':{'privateEndpoint':{'id':RG+'/providers/Microsoft.Network/privateEndpoints/pe'},'privateLinkServiceConnectionState':{'status':'Approved'}}}
    if pk in ('sql_server','vault','redis_cache','cosmos_account'):p['privateEndpointConnections']=[pe]
    def child(segment,name,props,parent=rid,parenttype=ep):return {'id':parent+'/'+segment+'/'+name,'name':name,'type':parenttype+'/'+segment,'properties':props}
    db={'id':DATABASE,'name':'app','type':'Microsoft.Sql/servers/databases','location':'eastus','kind':'v12.0,user','sku':{'name':'S0','tier':'Standard'},'properties':{'status':'Online','collation':'SQL_Latin1_General_CP1_CI_AS'}}
    va=child('vulnerabilityAssessments','default',{'storageContainerPath':'https://archive.blob.core.windows.net/va','recurringScans':{'isEnabled':True,'emailSubscriptionAdmins':True,'emails':['audit@example.com']}})
    express=child('sqlVulnerabilityAssessments','default',{'state':'Enabled'})
    protector=child('encryptionProtector','current',{'serverKeyType':'AzureKeyVault','uri':ORIGIN+'/keys/database/version1'})
    admins=[child('administrators','ActiveDirectory',{'administratorType':'ActiveDirectory','azureADOnlyAuthentication':True,'sid':TENANT,'tenantId':TENANT,'login':'database-admin'})]
    adonly=[child('azureADOnlyAuthentications','Default',{'azureADOnlyAuthentication':True})]
    vnet=[child('virtualNetworkRules','client',{'virtualNetworkSubnetId':SUBNET,'state':'Ready','ignoreMissingVnetServiceEndpoint':False})]
    alert=[child('securityAlertPolicies','Default',{'state':'Enabled','disabledAlerts':[],'emailAccountAdmins':True})]
    scans=[child('vulnerabilityAssessments/default/scans','scan1',{'state':'Passed','scanId':'scan1','startTime':'2026-10-18T00:00:00Z','endTime':'2026-10-18T00:01:00Z','errors':[],'numberOfFailedSecurityChecks':0},parent=DATABASE,parenttype='Microsoft.Sql/servers/databases')]
    scans[0]['type']='Microsoft.Sql/servers/databases/vulnerabilityAssessments/scans'
    tde=child('transparentDataEncryption','current',{'state':'Enabled'},parent=DATABASE,parenttype='Microsoft.Sql/servers/databases')
    strpolicy=child('backupShortTermRetentionPolicies','default',{'retentionDays':7,'diffBackupIntervalInHours':12},parent=DATABASE,parenttype='Microsoft.Sql/servers/databases')
    ltrpolicy=child('backupLongTermRetentionPolicies','default',{'weeklyRetention':'P4W','monthlyRetention':'PT0S','yearlyRetention':'PT0S','weekOfYear':0},parent=DATABASE,parenttype='Microsoft.Sql/servers/databases')
    ltrpath=SCOPE+'/providers/Microsoft.Sql/locations/eastus/longTermRetentionServers/reviewsql/longTermRetentionDatabases/app/longTermRetentionBackups'
    ltr=[{'id':ltrpath+'/guid;131637960820000000;Hot','name':'guid;131637960820000000;Hot','type':azure_sql_ltr_native.NATIVE_TYPE,'properties':{'serverName':'reviewsql','databaseName':'app','databaseDeletionTime':None,'backupTime':'2026-10-18T00:00:00Z','backupExpirationTime':'2026-11-18T00:00:00Z','backupStorageRedundancy':'Geo'}}]
    cfg=[child('configurations','log_duration',{'value':'on'})]
    secret={'id':ORIGIN+'/secrets/metadata','attributes':{'enabled':True,'exp':2000000000,'created':1700000000,'updated':1700000000}}
    # Public certificate metadata only; private key and secret IDs are never requested.
    cert={'id':ORIGIN+'/certificates/certificate/version1','cer':PUBLIC_CERTIFICATES['rsa2048'],'attributes':{'enabled':True,'exp':2000000000,'created':1700000000,'updated':1700000000}}
    diag=[{'id':rid+'/providers/Microsoft.Insights/diagnosticSettings/logs','name':'logs','type':'Microsoft.Insights/diagnosticSettings','properties':{'workspaceId':RG+'/providers/Microsoft.OperationalInsights/workspaces/audit','storageAccountId':STORAGE,'logs':[{'categoryGroup':'audit','enabled':True},{'categoryGroup':'allLogs','enabled':True},{'category':'DataPlaneRequests','enabled':True}]}}]
    categories=[{'id':rid+'/providers/Microsoft.Insights/diagnosticSettingsCategories/'+n,'name':n,'type':'Microsoft.Insights/diagnosticSettingsCategories','properties':{'categoryType':'Logs','categoryGroups':['audit','allLogs']}}for n in ('MongoRequests','DataPlaneRequests')]
    policy=child('backupPolicies','daily',{'backupManagementType':'AzureIaasVM','policyType':'V1','timeZone':'UTC','instantRpRetentionRangeInDays':2,'schedulePolicy':{'schedulePolicyType':'SimpleSchedulePolicy','scheduleRunFrequency':'Daily','scheduleRunTimes':['2026-10-18T03:00:00Z']},'retentionPolicy':{'retentionPolicyType':'LongTermRetentionPolicy','dailySchedule':{'retentionTimes':['2026-10-18T03:00:00Z'],'retentionDuration':{'count':30,'durationType':'Days'}}}})
    protected=[{'id':rid+'/backupFabrics/Azure/protectionContainers/IaasVMContainer;iaasvmcontainerv2;review;vm/protectedItems/VM;iaasvmcontainerv2;review;vm','name':'VM;iaasvmcontainerv2;review;vm','type':'Microsoft.RecoveryServices/vaults/backupFabrics/protectionContainers/protectedItems','properties':{'protectedItemType':'Microsoft.Compute/virtualMachines','protectionState':'Protected','policyId':policy['id'],'sourceResourceId':RG+'/providers/Microsoft.Compute/virtualMachines/vm'}}]
    data={'kind':kind,'parentkind':pk,'endpoint':ep,'version':version,'rid':rid,'item':item,'db':db,'va':va,'express':express,'protector':protector,'admins':admins,'adonly':adonly,'vnet':vnet,'alert':alert,'scans':scans,'tde':tde,'strpolicy':strpolicy,'ltrpolicy':ltrpolicy,'ltrpath':ltrpath,'ltr':ltr,'configurations':cfg,'secret':secret,'certificate':cert,'diagnostics':diag,'categories':categories,'backupPolicies':[policy],'backupProtectedItems':protected}
    negative=mode=='negative';missing=mode=='missing';malformed=mode=='malformed';target=item;path=None;good=None;bad=None
    if cid in SCALARS:path,good,bad=SCALARS[cid]
    elif cid in PRIVATE_LINK:path,good,bad='properties.privateEndpointConnections',[pe],[]
    elif cid in SECRET_IDS:
        p['enableRbacAuthorization']='non_rbac'not in cid;target=secret;path,good,bad='attributes.exp',2000000000,None
    elif cid=='azure.claude.recovery_vault_has_protected_items':target=data;path,good,bad='backupProtectedItems',protected,[]
    elif cid=='azure.claude.sql_database_va_findings_resolved':
        target=scans[0];path,good,bad='properties.numberOfFailedSecurityChecks',0,5
        if negative:scans[0]['properties']['state']='Failed'
    elif cid=='azure.claude.sql_server_entra_admin':target=data;path,good,bad='admins',admins,[]
    elif cid=='azure.htbp.sql.entra_only_authentication':target=adonly[0];path,good,bad='properties.azureADOnlyAuthentication',True,False
    elif cid=='azure.claude.sql_server_vnet_rules':target=data;path,good,bad='vnet',vnet,[]
    elif cid in VA_IDS:
        target=va
        if cid.endswith('vulnerability_assessment_enabled'):path,good,bad='properties.storageContainerPath',va['properties']['storageContainerPath'],'';express['properties']['state']='Disabled'if negative else'Enabled'
        elif cid.endswith('notify_admins'):path,good,bad='properties.recurringScans.emailSubscriptionAdmins',True,False
        elif cid.endswith('recurring_scans'):path,good,bad='properties.recurringScans.isEnabled',True,False
        else:path,good,bad='properties.recurringScans.emails',['audit@example.com'],[];va['properties']['recurringScans']['emailSubscriptionAdmins']=False
    elif cid=='azure.claude.sql_tde_protector_cmk':target=protector;path,good,bad='properties.serverKeyType','AzureKeyVault','ServiceManaged'
    elif cid=='azure.claude2.sql_server_threat_detection_all_alerts':target=alert[0];path,good,bad='properties.disabledAlerts',[],['Sql_Injection']
    elif cid=='azure.gap.postgres_db_server_log_duration_on':target=cfg[0];path,good,bad='properties.value','on','off'
    elif cid==LEGACY:path,good,bad='properties.infrastructureEncryption','Enabled','Disabled'
    elif cid==LTR:target=ltr[0];path,good,bad='properties.backupStorageRedundancy','Geo','Local'
    elif cid==PITR:target=strpolicy;path,good,bad='properties.retentionDays',7,0
    elif cid==TDE:target=tde;path,good,bad='properties.state','Enabled','Disabled'
    elif cid==IMMUTABLE:path,good,bad='properties.securitySettings.immutabilitySettings.state','Locked','Unlocked'
    elif cid==MONGO:target=diag[0];path,good,bad='properties.logs',[{'category':'DataPlaneRequests','enabled':True}],[{'category':'DataPlaneRequests','enabled':False}]
    elif cid=='azure.port.keyvault_logging_enabled':target=diag[0];path,good,bad='properties.logs',diag[0]['properties']['logs'],[{'categoryGroup':'allLogs','enabled':True}]
    elif cid==CERT:target=cert;path,good,bad='cer',PUBLIC_CERTIFICATES['rsa2048'],PUBLIC_CERTIFICATES['rsa1024']
    else:raise AssertionError('unaccounted '+cid)
    assign(target,path,{'malformed':True}if malformed else bad if negative else good,omit=missing)
    if cid in SECRET_IDS and negative:secret['attributes'].pop('exp',None)
    data['deciding']=path;return data


def child_version(d,tail):
    # Child list routes use the collector's own per-child API version.
    for _,path,version in azure.EMBEDDED_LISTS.get(d['parentkind'],()):
        if path==tail:return version
    return d['version']


class NativeHTTP:
    def __init__(self,cid,mode,mutate=None):
        self.cid=cid;self.mode=mode;self.d=native_case(cid,mode);self.calls=[];self.unexpected=[]
        if mutate:mutate(self.d)
    def open(self,request,timeout):
        try:
            response=self._open(request,timeout)
            response.status=200
            return response
        except HTTPError:raise
        except Exception as exc:self.unexpected.append((request.full_url,type(exc).__name__+': '+str(exc)));raise
    def _open(self,request,timeout):
        d=self.d;rid=d['rid'];p=urlsplit(request.full_url);q=parse_qs(p.query);path=p.path;method=request.get_method()
        assert p.scheme=='https'and p.netloc in ('management.azure.com','reviewvault.vault.azure.net')and timeout==20
        assert set(q)<={'api-version','$top','$expand','$select','$filter','page','databaseState','includePending'}and len(q.get('api-version',[]))==1
        self.calls.append({'method':method,'host':p.netloc,'path':path,'query':q})
        def deny():raise HTTPError(request.full_url,403,'fixture denied',{},io.BytesIO(b'{}'))
        if self.mode=='denied':deny()
        if method=='POST':
            assert p.netloc=='management.azure.com'and path=='/providers/Microsoft.ResourceGraph/resources'and q['api-version']==['2022-10-01'];assert json.loads(request.data)['subscriptions']==[SUB]
            value={'data':[d['item']],'resultTruncated':False}
        else:
            assert method=='GET'and request.data is None
            if p.netloc=='reviewvault.vault.azure.net':
                assert q['api-version']==['2025-07-01']
                assert path in ('/secrets','/certificates','/certificates/certificate')
                if self.mode=='child_denied'or 'page'in q:deny()
                if path=='/certificates/certificate':value=deepcopy(d['certificate'])
                else:value={'value':[d['secret']]if path=='/secrets'else[{'id':ORIGIN+'/certificates/certificate','attributes':{'enabled':True}}]}
                if self.mode=='child_partial'and'value'in value:value['nextLink']=ORIGIN+path+'?api-version=2025-07-01&page=2'
                if self.mode=='wrong_type'and path=='/secrets':value['value'][0]['id']=ORIGIN+'/keys/metadata'
            elif path==SCOPE:value={'id':SCOPE,'subscriptionId':SUB,'tenantId':TENANT,'state':'Enabled'}
            elif path==SCOPE+'/resources':
                assert q['api-version']==['2021-04-01'];value={'value':[d['item']]}
            elif path==SCOPE+'/providers/'+d['endpoint']:
                assert q['api-version']==[d['version']]
                if 'page'in q:deny()
                values=[]if self.mode=='empty'else[deepcopy(d['item'])]
                if self.mode=='foreign'and values:values[0]['id']=rid.replace(SUB,OTHER)
                if self.mode=='wrong_type'and values:values[0]['type']='Microsoft.Compute/virtualMachines'
                value={'value':values}
                if self.mode=='parent_partial':value['nextLink']=azure.ARM+path+'?api-version='+d['version']+'&page=2'
            elif path==rid:
                assert q['api-version']==[d['version']];value=deepcopy(d['item'])
                if self.mode=='wrong_type':value['type']='Microsoft.Compute/virtualMachines'
            elif path==DATABASE:
                assert q['api-version']==['2023-08-01'];value=deepcopy(d['db'])
            elif path==d['ltrpath']:
                assert q['api-version']==['2023-08-01']and q.get('databaseState')==['Live']
                if self.mode=='child_denied'or 'page'in q:deny()
                value={'value':deepcopy(d['ltr'])}
                if self.mode=='child_partial':value['nextLink']=azure.ARM+path+'?api-version=2023-08-01&databaseState=Live&page=2'
            elif path.startswith(rid+'/')or path.startswith(DATABASE+'/'):
                dbchild=path.startswith(DATABASE+'/');tail=path[len(DATABASE)+1:]if dbchild else path[len(rid)+1:]
                expected='2021-05-01-preview'if tail.startswith('providers/Microsoft.Insights/')else'2023-08-01-preview'if tail=='sqlVulnerabilityAssessments/default'else child_version(d,tail)
                assert q['api-version']==[expected]
                if self.mode=='child_denied'or 'page'in q:deny()
                singleton={'vulnerabilityAssessments/default':'va','sqlVulnerabilityAssessments/default':'express','encryptionProtector/current':'protector','transparentDataEncryption/current':'tde'}
                lists={'databases':[d['db']],'administrators':d.get('admins'),'azureADOnlyAuthentications':d['adonly'],'privateEndpointConnections':d['item']['properties'].get('privateEndpointConnections',[]),'virtualNetworkRules':d.get('vnet'),'securityAlertPolicies':d['alert'],'firewallRules':[],
                    'configurations':d['configurations'],'vulnerabilityAssessments/default/scans':d['scans'],
                    'backupShortTermRetentionPolicies':[d['strpolicy']],'backupLongTermRetentionPolicies':[d['ltrpolicy']],
                    'restorePoints':[],'providers/Microsoft.Insights/diagnosticSettings':d['diagnostics'],
                    'providers/Microsoft.Insights/diagnosticSettingsCategories':d['categories'],'backupPolicies':d['backupPolicies'],'backupProtectedItems':d.get('backupProtectedItems'),'backupJobs':[]}
                assert tail in singleton or tail in lists,tail
                if tail in singleton:value=deepcopy(d[singleton[tail]])
                else:
                    value={'value':deepcopy(lists[tail])}
                    if self.mode=='child_partial':value['nextLink']=azure.ARM+path+'?api-version='+expected+'&page=2'
            elif path==SCOPE+'/providers/Microsoft.Network/locations/westcentralus/serviceTags':
                assert q['api-version']==['2025-09-01'];value={'value':[]}
            elif path in empty_inventory_versions(SCOPE):
                assert matches_empty_inventory_query(SCOPE,path,q);value={'value':[]}
            else:
                endpoints={SCOPE+'/providers/'+ep:version for ep,version in azure.ENDPOINTS.values()};endpoints[SCOPE+'/resourcegroups']='2021-04-01'
                assert path in endpoints,path;assert q['api-version']==[endpoints[path]]
                value={'value':[]}
        return io.BytesIO(json.dumps(value).encode())


@pytest.fixture(autouse=True)
def offline(monkeypatch):
    def blocked(*a,**kw):raise AssertionError('Network/DNS/auth forbidden')
    for obj,names in ((socket,('getaddrinfo','create_connection')),(socket.socket,('connect','connect_ex')),(azure,('credential_for',))):
        for name in names:monkeypatch.setattr(obj,name,blocked)


def capture(monkeypatch,cid,mode='positive',mutate=None):
    http=NativeHTTP(cid,mode,mutate);monkeypatch.setattr(azure,'build_opener',lambda *a:http)
    connector={'provider':'azure','scopes':[SUB],'auth':{'method':'token','arm_token':'fixture-inert','vault_token':'fixture-inert'},'options':{'concurrency':1,'retries':0}}
    required=plan_collection({'connector':connector,'checks':[cid]});snapshot=azure.collect(connector,required)
    findings=evaluate_snapshot(snapshot,checks=[cid],include_not_applicable=True)['findings']
    assert not http.unexpected,http.unexpected
    assert findings,(cid,snapshot)
    assert not any('/secrets/'in c['path']or 'listKeys'in c['path']for c in http.calls)
    return findings,snapshot,http


def child_decides(cid):
    return cid in SECRET_IDS or cid in VA_IDS or cid in (CERT,MONGO,IMMUTABLE,TDE,PITR,LTR,'azure.claude.sql_server_entra_admin','azure.htbp.sql.entra_only_authentication','azure.claude.sql_server_vnet_rules','azure.claude.sql_database_va_findings_resolved','azure.claude.sql_tde_protector_cmk','azure.claude2.sql_server_threat_detection_all_alerts','azure.gap.postgres_db_server_log_duration_on','azure.port.keyvault_logging_enabled','azure.claude.recovery_vault_has_protected_items')


def expected(cid,mode):
    if mode=='denied':return 'UNKNOWN'if cid==CERT else'DENIED'
    if mode=='empty':return 'NOT_APPLICABLE'if REGISTRY[cid].target=='scope'else'EMPTY'
    if mode in ('foreign','wrong_type','malformed'):return 'UNKNOWN'
    if cid==CERT and mode in ('child_denied','child_partial'):return 'DENIED'if mode=='child_denied'else'UNKNOWN'
    if mode=='parent_partial':
        if cid in SECRET_IDS:return 'UNKNOWN'if 'with_'in cid else'PASS'
        if cid=='azure.claude.sql_database_va_findings_resolved':return 'PASS'
        return 'UNKNOWN'if REGISTRY[cid].target=='scope'or cid==IMMUTABLE else'PASS,UNKNOWN'
    if mode in ('child_denied','child_partial'):
        if cid==TDE:return 'UNKNOWN'
        if cid in SECRET_IDS:return 'DENIED'if mode=='child_denied'else'PASS,UNKNOWN'
        if mode=='child_denied'and(cid in VA_IDS or cid in ('azure.claude.sql_database_va_findings_resolved','azure.claude.sql_tde_protector_cmk',LTR,PITR)):return 'DENIED'
        if mode=='child_partial'and(cid in VA_IDS or cid=='azure.claude.sql_tde_protector_cmk'):return 'PASS'
        return 'UNKNOWN'if child_decides(cid)else'PASS'
    if mode=='missing':
        if cid in SECRET_IDS:return 'FAIL'
        if cid in ('azure.claude.sql_server_vulnerability_assessment_enabled','azure.claude2.sql_server_threat_detection_all_alerts'):return 'PASS'
        if cid=='azure.htbp.keyvault.template_deployment_disabled':return 'PASS'  # documented false default
        if cid=='azure.claude.recovery_vault_managed_identity':return 'FAIL'  # native no identity declaration
        if cid in ('azure.port.keyvault_vault_recoverable','azure.vault.purge_protection'):return 'FAIL'  # documented default: purge protection off
        return 'UNKNOWN'
    return 'FAIL'if mode=='negative'else'PASS'


@pytest.mark.parametrize('cid',ROSTER)
@pytest.mark.parametrize('mode',('positive','negative','missing','malformed','denied','empty','foreign','wrong_type','parent_partial','child_denied','child_partial'))
def test_native_matrix(monkeypatch,cid,mode,record_property):
    findings,snapshot,http=capture(monkeypatch,cid,mode)
    actual={f['status']for f in findings};want=expected(cid,mode)
    record_property('check_id',cid);record_property('mode',mode);record_property('actual',','.join(sorted(actual)));record_property('expected',want)
    if mode=='positive':record_property('native_capture',json.dumps({'http':http.calls,'collections':[{'type':c['type'],'scope':c['scope'],'status':c['status']}for c in snapshot['collections']]}))
    assert actual==set(want.split(',')),findings

@pytest.mark.parametrize('state,count,want',(('Passed',0,'PASS'),('Failed',5,'FAIL'),('FailedToRun',0,'UNKNOWN'),('InProgress',0,'UNKNOWN'),('Unexpected',0,'UNKNOWN')))
def test_native_va_scan_execution_state(monkeypatch,state,count,want,record_property):
    cid='azure.claude.sql_database_va_findings_resolved'
    def mutate(d):
        d['scans'][0]['properties'].update(state=state,numberOfFailedSecurityChecks=count)
        if state=='FailedToRun':d['scans'][0]['properties']['errors']=[{'code':'StorageNotFound','message':'Storage not found'}]
    findings,snapshot,http=capture(monkeypatch,cid,mutate=mutate)
    record_property('check_id',cid);record_property('mode','scan_state_'+state);record_property('actual',','.join(sorted({f['status']for f in findings})));record_property('expected',want)
    assert {f['status']for f in findings}=={want},findings

@pytest.mark.parametrize('version,want',(('1.0','FAIL'),('1.1','FAIL'),('1.2','PASS'),('1.3','UNKNOWN'),('Future','UNKNOWN'),('None','UNKNOWN')))
def test_explicit_sql_tls_versions(monkeypatch,version,want,record_property):
    cid='azure.sql.minimum_tls'
    def mutate(d):d['item']['properties']['minimalTlsVersion']=version
    findings,snapshot,http=capture(monkeypatch,cid,mutate=mutate)
    record_property('check_id',cid);record_property('mode','tls_'+version);record_property('actual',','.join(sorted({f['status']for f in findings})));record_property('expected',want)
    assert {f['status']for f in findings}=={want},findings

@pytest.mark.parametrize('cid,target',(('azure.claude.sql_database_va_findings_resolved','scans'),('azure.claude.sql_tde_protector_cmk','protector'),('azure.claude.sql_server_vulnerability_assessment_enabled','va')))
@pytest.mark.parametrize('variant',('foreign_same_parent_route','wrong_native_child_type'))
def test_exact_sql_native_child_contract(monkeypatch,cid,target,variant,record_property):
    def mutate(d):
        row=d[target][0]if isinstance(d[target],list)else d[target]
        if variant=='foreign_same_parent_route':row['id']=(DATABASE if target=='scans'else SERVER)+'/unrelated/default'
        else:row['type']='Microsoft.Unrelated/resources'
    findings,snapshot,http=capture(monkeypatch,cid,mutate=mutate)
    record_property('check_id',cid);record_property('mode',variant);record_property('actual',','.join(sorted({f['status']for f in findings})));record_property('expected','UNKNOWN')
    assert {f['status']for f in findings}=={'UNKNOWN'},findings

@pytest.mark.parametrize('cid',tuple(sorted(SECRET_IDS)))
def test_native_secret_explicitly_disabled_applicability(monkeypatch,cid,record_property):
    def mutate(d):d['secret']['attributes']['enabled']=False;d['secret']['attributes'].pop('exp',None)
    findings,snapshot,http=capture(monkeypatch,cid,mutate=mutate)
    want='PASS'if cid.startswith('azure.port.')else'NOT_APPLICABLE'
    record_property('check_id',cid);record_property('mode','disabled_secret')
    assert {f['status']for f in findings}=={want},findings

@pytest.mark.parametrize('cid,target',(('azure.claude.sql_server_entra_admin','admins'),('azure.claude.sql_server_vnet_rules','vnet'),('azure.claude2.sql_server_threat_detection_all_alerts','alert')))
def test_sql_child_native_type_is_not_parent_prefix_alone(monkeypatch,cid,target,record_property):
    def mutate(d):d[target][0]['type']='Microsoft.Unrelated/resources'
    findings,snapshot,http=capture(monkeypatch,cid,mutate=mutate)
    record_property('check_id',cid);record_property('mode','wrong_sql_child_type');record_property('actual',','.join(sorted({f['status']for f in findings})));record_property('expected','UNKNOWN')
    assert {f['status']for f in findings}=={'UNKNOWN'},findings

@pytest.mark.parametrize('cid',tuple(sorted(SECRET_IDS)))
@pytest.mark.parametrize('variant',('foreign_secret_origin','foreign_vault_uri','wrong_native_secret_kind'))
def test_native_secret_source_binding(monkeypatch,cid,variant,record_property):
    def mutate(d):
        if variant=='foreign_secret_origin':d['secret']['id']='https://foreign.vault.azure.net/secrets/metadata'
        elif variant=='foreign_vault_uri':d['item']['properties']['vaultUri']='https://foreign.vault.azure.net/'
        else:d['secret']['id']=ORIGIN+'/keys/metadata'
    findings,snapshot,http=capture(monkeypatch,cid,mutate=mutate)
    record_property('check_id',cid);record_property('mode',variant);record_property('actual',','.join(sorted({f['status']for f in findings})));record_property('expected','UNKNOWN')
    assert {f['status']for f in findings}=={'UNKNOWN'},findings

@pytest.mark.parametrize('cid',('azure.port.keyvault_with_non_rbac_secret_expiration_set','azure.port.keyvault_with_rbac_secret_expiration_set'))
def test_opposite_native_vault_authorization_is_excluded(monkeypatch,cid,record_property):
    def mutate(d):d['item']['properties']['enableRbacAuthorization']=not d['item']['properties']['enableRbacAuthorization']
    findings,snapshot,http=capture(monkeypatch,cid,mutate=mutate)
    record_property('check_id',cid);record_property('mode','opposite_native_authorization');record_property('actual',','.join(sorted({f['status']for f in findings})));record_property('expected','NOT_APPLICABLE')
    assert {f['status']for f in findings}=={'NOT_APPLICABLE'},findings

@pytest.mark.parametrize('cid',('azure.port.keyvault_logging_enabled',MONGO))
@pytest.mark.parametrize('variant',('foreign_diag_parent','wrong_diag_type','wrong_diag_child_segment','conflicting_diag_identity'))
def test_diagnostic_native_child_binding(monkeypatch,cid,variant,record_property):
    def mutate(d):
        row=d['diagnostics'][0]
        if variant=='foreign_diag_parent':row['id']=row['id'].replace(SUB,OTHER)
        elif variant=='wrong_diag_type':row['type']='Microsoft.Unrelated/settings'
        elif variant=='wrong_diag_child_segment':row['id']=d['rid']+'/arbitrary/logs'
        else:
            bad=deepcopy(row);bad['properties']['logs']=[{'category':'Other','enabled':True}];d['diagnostics'].append(bad)
    findings,snapshot,http=capture(monkeypatch,cid,mutate=mutate)
    record_property('check_id',cid);record_property('mode',variant);record_property('actual',','.join(sorted({f['status']for f in findings})));record_property('expected','UNKNOWN')
    assert {f['status']for f in findings}=={'UNKNOWN'},findings

@pytest.mark.parametrize('cid',tuple(sorted(PRIVATE_LINK)))
@pytest.mark.parametrize('status,want',(('Pending','FAIL'),('Rejected','FAIL'),('Future','UNKNOWN')))
def test_native_private_endpoint_approval_states(monkeypatch,cid,status,want,record_property):
    def mutate(d):d['item']['properties']['privateEndpointConnections'][0]['properties']['privateLinkServiceConnectionState']['status']=status
    findings,snapshot,http=capture(monkeypatch,cid,mutate=mutate)
    record_property('check_id',cid);record_property('mode','private_endpoint_'+status);record_property('actual',','.join(sorted({f['status']for f in findings})));record_property('expected',want)
    assert {f['status']for f in findings}=={want},findings

@pytest.mark.parametrize('state,count,want',(('Failed',0,'UNKNOWN'),('Passed',3,'UNKNOWN')))
def test_native_scan_state_count_must_be_coherent(monkeypatch,state,count,want,record_property):
    cid='azure.claude.sql_database_va_findings_resolved'
    def mutate(d):d['scans'][0]['properties'].update(state=state,numberOfFailedSecurityChecks=count)
    findings,snapshot,http=capture(monkeypatch,cid,mutate=mutate)
    record_property('check_id',cid);record_property('mode','incoherent_'+state);record_property('actual',','.join(sorted({f['status']for f in findings})));record_property('expected',want)
    assert {f['status']for f in findings}=={want},findings

@pytest.mark.parametrize('cid',tuple(sorted(PRIVATE_LINK)))
def test_native_private_endpoint_cannot_belong_to_foreign_parent(monkeypatch,cid,record_property):
    def mutate(d):d['item']['properties']['privateEndpointConnections'][0]['id']=d['item']['properties']['privateEndpointConnections'][0]['id'].replace(SUB,OTHER)
    findings,snapshot,http=capture(monkeypatch,cid,mutate=mutate)
    record_property('check_id',cid);record_property('mode','foreign_embedded_private_endpoint');record_property('actual',','.join(sorted({f['status']for f in findings})));record_property('expected','UNKNOWN')
    assert {f['status']for f in findings}=={'UNKNOWN'},findings

@pytest.mark.parametrize('variant,want',(('rsa2048','PASS'),('rsa1024','FAIL'),('ec256','NOT_APPLICABLE'),('unreadable','UNKNOWN'),('foreign_current_version','UNKNOWN')))
def test_actual_issued_public_certificate_key(monkeypatch,variant,want,record_property):
    def mutate(d):
        if variant=='foreign_current_version':d['certificate']['id']='https://foreign.vault.azure.net/certificates/certificate/version1'
        else:d['certificate']['cer']=PUBLIC_CERTIFICATES.get(variant,'not-base64')
    findings,snapshot,http=capture(monkeypatch,CERT,mutate=mutate)
    record_property('check_id',CERT);record_property('mode','issued_key_'+variant);record_property('actual',','.join(sorted({f['status']for f in findings})));record_property('expected',want)
    assert {f['status']for f in findings}=={want},findings

@pytest.mark.parametrize('cid',('azure.port.keyvault_logging_enabled',MONGO))
def test_identical_native_diagnostic_repeat_is_safe(monkeypatch,cid,record_property):
    def mutate(d):d['diagnostics'].append(deepcopy(d['diagnostics'][0]))
    findings,snapshot,http=capture(monkeypatch,cid,mutate=mutate)
    record_property('check_id',cid);record_property('mode','identical_diag_repeat');record_property('actual',','.join(sorted({f['status']for f in findings})));record_property('expected','PASS')
    assert {f['status']for f in findings}=={'PASS'},findings

@pytest.mark.parametrize('count,unit,want',((29,'Days','FAIL'),(30,'Days','PASS'),(31,'Days','PASS'),(4,'Weeks','FAIL'),(5,'Weeks','PASS'),(1,'Months','UNKNOWN'),(2,'Months','PASS'),(30,'Future','UNKNOWN')))
def test_actual_backup_policy_retention_units(monkeypatch,count,unit,want,record_property):
    def mutate(d):d['backupPolicies'][0]['properties']['retentionPolicy']['dailySchedule']['retentionDuration'].update(count=count,durationType=unit)
    findings,snapshot,http=capture(monkeypatch,IMMUTABLE,mutate=mutate)
    record_property('check_id',IMMUTABLE);record_property('mode','retention_'+str(count)+'_'+unit);record_property('actual',','.join(sorted({f['status']for f in findings})));record_property('expected',want)
    assert {f['status']for f in findings}=={want},findings

@pytest.mark.parametrize('variant',('enhanced_schedule','non_utc','archive_tiering','foreign_policy_assignment'))
def test_unsupported_backup_policy_cannot_be_clean(monkeypatch,variant,record_property):
    def mutate(d):
        p=d['backupPolicies'][0]['properties']
        if variant=='enhanced_schedule':p['schedulePolicy']['schedulePolicyType']='SimpleSchedulePolicyV2'
        elif variant=='non_utc':p['timeZone']='Pacific Standard Time'
        elif variant=='archive_tiering':p['tieringPolicy']={'ArchivedRP':{'tieringMode':'TierAfter','duration':90,'durationType':'Days'}}
        else:d['backupProtectedItems'][0]['properties']['policyId']=d['backupPolicies'][0]['id'].replace(SUB,OTHER)
    findings,snapshot,http=capture(monkeypatch,IMMUTABLE,mutate=mutate)
    record_property('check_id',IMMUTABLE);record_property('mode',variant);record_property('actual',','.join(sorted({f['status']for f in findings})));record_property('expected','UNKNOWN')
    assert {f['status']for f in findings}=={'UNKNOWN'},findings

@pytest.mark.parametrize('cid',('azure.port.keyvault_with_rbac_secret_expiration_set','azure.port.keyvault_logging_enabled'))
@pytest.mark.parametrize('variant',('parent_nonce_missing','parent_nonce_foreign','duplicate_parent_envelope','parent_native_id_foreign'))
def test_same_capture_vault_parent_proof_is_required(monkeypatch,cid,variant,record_property):
    from peaso.snapshot import make_snapshot
    findings,snapshot,http=capture(monkeypatch,cid)
    collections=deepcopy(snapshot['collections'])
    parent=next(c for c in collections if c['type']=='vault');row=parent['items'][0]
    if variant=='parent_nonce_missing':row['_provenance'].pop('credential_context_id',None)
    elif variant=='parent_nonce_foreign':row['_provenance']['credential_context_id']='f'*32
    elif variant=='duplicate_parent_envelope':
        collections.append(deepcopy(parent))
        with pytest.raises(ValueError,match='duplicate collection type/scope'):
            make_snapshot('azure',snapshot['scopes'],collections,metadata=snapshot['metadata'],created_at=snapshot['created_at'])
        record_property('check_id',cid);record_property('mode',variant);record_property('actual','REJECTED');record_property('expected','REJECTED')
        return
    else:row['id']=row['id'].replace(SUB,OTHER)
    changed=make_snapshot('azure',snapshot['scopes'],collections,metadata=snapshot['metadata'],created_at=snapshot['created_at'])
    findings=evaluate_snapshot(changed,checks=[cid],include_not_applicable=True)['findings']
    record_property('check_id',cid);record_property('mode',variant);record_property('actual',','.join(sorted({f['status']for f in findings})));record_property('expected','UNKNOWN')
    assert {f['status']for f in findings}=={'UNKNOWN'},findings
