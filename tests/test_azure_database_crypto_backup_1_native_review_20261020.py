"""Independent native JSON/HTTP -> Azure collector -> public engine database/crypto review.

No CASES, fabricated representation markers, customer approvals or effective claims.
"""
from copy import deepcopy
import io
import json
import socket
from urllib.error import HTTPError
from urllib.parse import parse_qs, urlsplit
import pytest
from tests.azure_native_inventory_routes_20261020 import empty_inventory_versions,matches_empty_inventory_query
from peaso.collectors import azure
# Explicit historical HSM replay remains test-only after root archived its
# obsolete retention criterion; all active IDs use the unchanged public engine.
from tests.archived_check_contract import evaluate_snapshot, plan_collection
from peaso.checks import CHECKS

SUB = "11111111-1111-1111-1111-111111111111"
TENANT = "22222222-2222-2222-2222-222222222222"
OTHER = "99999999-9999-9999-9999-999999999999"
SCOPE = "/subscriptions/" + SUB
RG = SCOPE + "/resourceGroups/review"
VAULT = RG + "/providers/Microsoft.KeyVault/vaults/reviewvault"
ORIGIN = "https://reviewvault.vault.azure.net"
SUBNET = RG + "/providers/Microsoft.Network/virtualNetworks/v/subnets/s"
STORAGE = RG + "/providers/Microsoft.Storage/storageAccounts/archive"
PRIVATE = "MUST_NOT_EXPORT_PASSWORD"
REGISTRY = {c.id:c for c in CHECKS}
ROSTER = ('azure.cis.enforce_ssl_connection_mysql_server', 'azure.cis.legacy_infrastructure_double_encryption_postgresql_single_server', 'azure.cis.mysql_flexible_cmk', 'azure.cis.mysql_single_audit_log_enabled', 'azure.cis.mysql_single_audit_log_events_connection', 'azure.cis.postgresql_single_connection_throttling', 'azure.cis.postgresql_single_log_checkpoints', 'azure.cis.postgresql_single_log_connections', 'azure.cis.postgresql_single_log_disconnections', 'azure.cis.postgresql_single_log_retention_days', 'azure.cis.postgresql_single_no_azure_services_rule', 'azure.cis.postgresql_single_ssl_enforcement', 'azure.cis.public_network_access_should_mysql_servers', 'azure.cis.public_network_access_should_postgresql_servers', 'azure.claude.cosmos_automatic_failover', 'azure.claude.cosmos_cmk', 'azure.claude.cosmos_continuous_backup', 'azure.claude.cosmos_cors_no_wildcard', 'azure.claude.cosmos_key_based_metadata_write_disabled', 'azure.claude.cosmos_local_auth_disabled', 'azure.claude.cosmos_minimum_tls12', 'azure.claude.cosmos_network_restricted', 'azure.claude.cosmos_private_endpoint_present', 'azure.claude.cosmos_public_network_access_disabled', 'azure.claude.cosmos_public_network_access_restricted', 'azure.claude.cosmos_virtual_network_filter', 'azure.claude.cosmos_vnet_service_endpoint', 'azure.claude.keyvault_audit_and_alllogs_groups', 'azure.claude.keyvault_audit_logging', 'azure.claude.keyvault_firewall_ip_rules', 'azure.claude.keyvault_key_automatic_rotation_after_create', 'azure.claude.keyvault_key_expiration_set', 'azure.claude.keyvault_key_rotation_policy', 'azure.claude.keyvault_non_rbac_key_expiration_set', 'azure.claude.keyvault_non_rbac_secret_expiration_set', 'azure.claude.keyvault_private_endpoint_exists', 'azure.claude.keyvault_private_endpoint_only_access', 'azure.claude.keyvault_rbac_key_expiration_set', 'azure.claude.keyvault_rbac_secret_expiration_set', 'azure.claude.keyvault_vnet_service_endpoint', 'azure.claude.managed_hsm_audit_logging', 'azure.claude.managed_hsm_purge_protection', 'azure.claude.mysql_flexible_audit_log_connection', 'azure.claude.mysql_flexible_audit_log_enabled', 'azure.claude.mysql_flexible_geo_redundant_backup', 'azure.claude.mysql_flexible_high_availability', 'azure.claude.mysql_flexible_min_tls_12', 'azure.claude.mysql_flexible_secure_transport', 'azure.claude.postgresql_flexible_connection_throttling', 'azure.claude.postgresql_flexible_entra_authentication', 'azure.claude.postgresql_flexible_geo_redundant_backup', 'azure.claude.postgresql_flexible_high_availability', 'azure.claude.postgresql_flexible_log_checkpoints', 'azure.claude.postgresql_flexible_log_connections', 'azure.claude.postgresql_flexible_log_disconnections', 'azure.claude.postgresql_flexible_log_retention_over_3_days', 'azure.claude.postgresql_flexible_no_azure_services_rule', 'azure.claude.postgresql_flexible_no_zero_address_rule', 'azure.claude.postgresql_flexible_secure_transport', 'azure.claude.recovery_vault_backup_retention_30_days')

SCALARS = {
 "enforce_ssl_connection_mysql_server": ("properties.sslEnforcement", "Enabled", "Disabled"),
 "legacy_infrastructure_double_encryption_postgresql_single_server": ("properties.infrastructureEncryption", "Enabled", "Disabled"),
 "postgresql_single_ssl_enforcement": ("properties.sslEnforcement", "Enabled", "Disabled"),
 "public_network_access_should_mysql_servers": ("properties.network.publicNetworkAccess", "Disabled", "Enabled"),
 "public_network_access_should_postgresql_servers": ("properties.network.publicNetworkAccess", "Disabled", "Enabled"),
 "cosmos_automatic_failover": ("properties.enableAutomaticFailover", True, False),
 "cosmos_continuous_backup": ("properties.backupPolicy.type", "Continuous", "Periodic"),
 "cosmos_key_based_metadata_write_disabled": ("properties.disableKeyBasedMetadataWriteAccess", True, False),
 "cosmos_local_auth_disabled": ("properties.disableLocalAuth", True, False),
 "cosmos_minimum_tls12": ("properties.minimalTlsVersion", "Tls12", "Tls11"),
 "cosmos_public_network_access_disabled": ("properties.publicNetworkAccess", "Disabled", "Enabled"),
 "cosmos_public_network_access_restricted": ("properties.publicNetworkAccess", "SecuredByPerimeter", "Enabled"),
 "cosmos_virtual_network_filter": ("properties.isVirtualNetworkFilterEnabled", True, False),
 "cosmos_cmk": ("properties.keyVaultKeyUri", ORIGIN+"/keys/data", None),
 "cosmos_cors_no_wildcard": ("properties.cors", [{"allowedOrigins":"https://app.example.com"}], [{"allowedOrigins":"*"}]),
 "cosmos_vnet_service_endpoint": ("properties.virtualNetworkRules", [{"id":SUBNET,"ignoreMissingVNetServiceEndpoint":False}], []),
 "keyvault_firewall_ip_rules": ("properties.networkAcls.ipRules", [{"value":"203.0.113.8/32"}], []),
 "keyvault_vnet_service_endpoint": ("properties.networkAcls.defaultAction", "Deny", "Allow"),
 "keyvault_private_endpoint_only_access": ("properties.publicNetworkAccess", "Disabled", "Enabled"),
 "managed_hsm_purge_protection": ("properties.enablePurgeProtection", True, False),
 "mysql_flexible_geo_redundant_backup": ("properties.backup.geoRedundantBackup", "Enabled", "Disabled"),
 "postgresql_flexible_geo_redundant_backup": ("properties.backup.geoRedundantBackup", "Enabled", "Disabled"),
 "mysql_flexible_high_availability": ("properties.highAvailability.mode", "ZoneRedundant", "Disabled"),
 "postgresql_flexible_high_availability": ("properties.highAvailability.mode", "ZoneRedundant", "Disabled"),
 "postgresql_flexible_entra_authentication": ("properties.authConfig.activeDirectoryAuth", "Enabled", "Disabled"),
}
PARAMETERS = {
 "mysql_single_audit_log_enabled": ("audit_log_enabled","ON","OFF"),
 "mysql_single_audit_log_events_connection": ("audit_log_events","CONNECTION,DDL","DDL,DML"),
 "postgresql_single_connection_throttling": ("connection_throttling","ON","OFF"),
 "postgresql_single_log_checkpoints": ("log_checkpoints","ON","OFF"),
 "postgresql_single_log_connections": ("log_connections","on","off"),
 "postgresql_single_log_disconnections": ("log_disconnections","on","off"),
 "postgresql_single_log_retention_days": ("log_retention_days","7","3"),
 "mysql_flexible_audit_log_enabled": ("audit_log_enabled","ON","OFF"),
 "mysql_flexible_audit_log_connection": ("audit_log_events","CONNECTION,DDL","DDL,DML"),
 "mysql_flexible_min_tls_12": ("tls_version","TLSv1.2,TLSv1.3","TLSv1.1,TLSv1.2"),
 "mysql_flexible_secure_transport": ("require_secure_transport","ON","OFF"),
 "postgresql_flexible_secure_transport": ("require_secure_transport","on","off"),
 "postgresql_flexible_connection_throttling": ("connection_throttle.enable","on","off"),
 "postgresql_flexible_log_checkpoints": ("log_checkpoints","on","off"),
 "postgresql_flexible_log_connections": ("log_connections","on","off"),
 "postgresql_flexible_log_disconnections": ("log_disconnections","on","off"),
 "postgresql_flexible_log_retention_over_3_days": ("logfiles.retention_days","7","3"),
}


def assign(row, path, value, omit=False):
    bits=path.split('.')
    for bit in bits[:-1]: row=row.setdefault(bit,{})
    if omit: row.pop(bits[-1],None)
    else: row[bits[-1]]=deepcopy(value)


def native_case(cid, mode):
    kind=REGISTRY[cid].kind
    parentkind="vault" if kind in ("key_vault_key","secret_metadata") else kind
    endpoint, version=azure.ENDPOINTS[parentkind]
    rid=RG+"/providers/"+endpoint+"/"+("reviewvault" if parentkind=="vault" else "review")
    pe={"id":rid+"/privateEndpointConnections/pe","type":endpoint+"/privateEndpointConnections",
        "properties":{"privateEndpoint":{"id":RG+"/providers/Microsoft.Network/privateEndpoints/pe"},
        "privateLinkServiceConnectionState":{"status":"Approved"}}}
    item={"id":rid,"type":endpoint,"name":rid.rsplit('/',1)[-1],"location":"eastus","sku":{"name":"Standard_D2ds_v4","tier":"GeneralPurpose"},
        "properties":{"provisioningState":"Succeeded","version":"16","administratorLoginPassword":PRIVATE,
        "sslEnforcement":"Enabled","infrastructureEncryption":"Enabled","databaseAccountOfferType":"Standard",
        "publicNetworkAccess":"Enabled","network":{"publicNetworkAccess":"Enabled"},
        "enableAutomaticFailover":True,"locations":[{"locationName":"East US","failoverPriority":0},{"locationName":"West US","failoverPriority":1}],
        "backupPolicy":{"type":"Continuous","continuousModeProperties":{"tier":"Continuous7Days"}},
        "disableKeyBasedMetadataWriteAccess":True,"disableLocalAuth":True,"minimalTlsVersion":"Tls12",
        "keyVaultKeyUri":ORIGIN+"/keys/data","cors":[{"allowedOrigins":"https://app.example.com"}],
        "isVirtualNetworkFilterEnabled":False,"ipRules":[{"ipAddressOrRange":"203.0.113.4"}],
        "virtualNetworkRules":[{"id":SUBNET,"ignoreMissingVNetServiceEndpoint":False}],
        "privateEndpointConnections":[pe],"vaultUri":ORIGIN+"/","enableRbacAuthorization":True,
        "enablePurgeProtection":True,"networkAcls":{"defaultAction":"Deny","bypass":"None","ipRules":[{"value":"203.0.113.8/32"}],"virtualNetworkRules":[{"id":SUBNET}]},
        "dataEncryption":{"type":"AzureKeyVault","primaryKeyURI":ORIGIN+"/keys/data/abcdef","primaryUserAssignedIdentityId":RG+"/providers/Microsoft.ManagedIdentity/userAssignedIdentities/crypto"},
        "backup":{"geoRedundantBackup":"Enabled","backupRetentionDays":7},"highAvailability":{"mode":"ZoneRedundant","state":"Healthy"},
        "authConfig":{"activeDirectoryAuth":"Enabled","passwordAuth":"Disabled","tenantId":TENANT}}}
    # Each response carries only fields exposed by its own native API family.
    fields = {
        'mysql_single_server': {'provisioningState','version','sslEnforcement'},
        'postgresql_single_server': {'provisioningState','version','sslEnforcement','infrastructureEncryption'},
        'mysql_flexible_server': {'provisioningState','version','network','dataEncryption','backup','highAvailability'},
        'postgresql_flexible_server': {'provisioningState','version','network','backup','highAvailability','authConfig'},
        'cosmos_account': {'provisioningState','databaseAccountOfferType','publicNetworkAccess','enableAutomaticFailover','locations','backupPolicy','disableKeyBasedMetadataWriteAccess','disableLocalAuth','minimalTlsVersion','keyVaultKeyUri','cors','isVirtualNetworkFilterEnabled','ipRules','virtualNetworkRules','privateEndpointConnections'},
        'vault': {'provisioningState','vaultUri','enableRbacAuthorization','enablePurgeProtection','networkAcls','publicNetworkAccess','privateEndpointConnections'},
        'managed_hsm': {'provisioningState','enablePurgeProtection','networkAcls','publicNetworkAccess','privateEndpointConnections'},
        'recovery_vault': {'provisioningState'},
    }[parentkind]
    item['properties']={k:v for k,v in item['properties'].items() if k in fields}
    if parentkind=='mysql_single_server':item['properties']['version']='5.7'
    elif parentkind=='postgresql_single_server':item['properties']['version']='11'
    elif parentkind=='mysql_flexible_server':item['properties']['version']='8.0.21'
    if parentkind in ('vault','cosmos_account'):item.pop('sku')
    elif parentkind=='managed_hsm':item['sku']={'family':'B','name':'Standard_B1'}
    elif parentkind=='recovery_vault':item['sku']={'name':'Standard'}
    elif parentkind.endswith('single_server'):item['sku']={'name':'GP_Gen5_2','tier':'GeneralPurpose','capacity':2,'family':'Gen5'}
    item['properties']['administratorLoginPassword']=PRIVATE  # hostile credential-echo sanitization probe
    if parentkind in ('vault','managed_hsm'):
        item['properties']['tenantId']=TENANT
    if parentkind=='vault':item['properties'].update(sku={'family':'A','name':'standard'},accessPolicies=[])
    def child(segment,name,props):
        return {"id":rid+"/"+segment+"/"+name,"name":name,"type":endpoint+"/"+segment,"properties":props}
    params={n:g for n,g,b in PARAMETERS.values()};params['audit_log_enabled']='ON'
    if parentkind.startswith('postgresql_single'):params.update({'log_checkpoints':'ON','connection_throttling':'ON'})
    configs=[child('configurations',n,{'value':v}) for n,v in params.items()]
    fw=[child('firewallRules','client',{'startIpAddress':'203.0.113.4','endIpAddress':'203.0.113.4'})]
    admins=[child('administrators',TENANT,{'administratorType':'ActiveDirectory','principalType':'User','tenantId':TENANT,'objectId':TENANT,'sid':TENANT})]
    diagnostics=[{'id':rid+'/providers/Microsoft.Insights/diagnosticSettings/logs','type':'Microsoft.Insights/diagnosticSettings','name':'logs','properties':{'storageAccountId':STORAGE,'logs':[
        {'category':'AuditEvent','enabled':True,'retentionPolicy':{'enabled':True,'days':365}},
        {'categoryGroup':'audit','enabled':True},{'categoryGroup':'allLogs','enabled':True}]}}]
    policies=[child('backupPolicies','daily',{'backupManagementType':'AzureIaasVM','policyType':'V1','schedulePolicy':{'schedulePolicyType':'SimpleSchedulePolicy','scheduleRunFrequency':'Daily','scheduleRunTimes':['2026-10-19T03:00:00Z']},
        'retentionPolicy':{'retentionPolicyType':'LongTermRetentionPolicy','dailySchedule':{'retentionTimes':['2026-10-19T03:00:00Z'],'retentionDuration':{'count':30,'durationType':'Days'}}}})]
    key={'kid':ORIGIN+'/keys/data','attributes':{'enabled':True,'exp':2000000000,'created':1700000000,'updated':1700000000}}
    secret={'id':ORIGIN+'/secrets/metadata','attributes':deepcopy(key['attributes'])}
    rotation={'id':ORIGIN+'/keys/data/rotationpolicy','lifetimeActions':[{'trigger':{'timeAfterCreate':'P90D'},'action':{'type':'Rotate'}}],'attributes':{'expiryTime':'P2Y','created':1700000000,'updated':1700000000}}
    slug=cid.split('.',2)[-1]
    missing=mode=='missing';negative=mode=='negative';malformed=mode=='malformed'
    deciding=None
    if slug in SCALARS:
        deciding,g,b=SCALARS[slug];assign(item,deciding, {'malformed':True} if malformed else b if negative else g,omit=missing)
    elif slug in PARAMETERS:
        n,g,b=PARAMETERS[slug];row=next(c for c in configs if c['name']==n);deciding='configurations.'+n
        if missing:configs.remove(row)
        else:row['properties']['value']={'malformed':True} if malformed else b if negative else g
    elif slug=='mysql_flexible_cmk':
        deciding='properties.dataEncryption';assign(item,deciding,{'malformed':True} if malformed else {'type':'SystemManaged'} if negative else item['properties']['dataEncryption'],omit=missing)
    elif slug=='cosmos_network_restricted':
        deciding='properties.ipRules';assign(item,deciding,{'malformed':True} if malformed else [] if negative else item['properties']['ipRules'],omit=missing)
    elif 'private_endpoint' in slug:
        deciding='properties.privateEndpointConnections';assign(item,deciding,{'malformed':True} if malformed else [] if negative else [pe],omit=missing)
    elif slug in ('postgresql_single_no_azure_services_rule','postgresql_flexible_no_azure_services_rule','postgresql_flexible_no_zero_address_rule'):
        deciding='firewallRules';
        if missing:fw=[]
        elif malformed:fw[0]['properties']['startIpAddress']={}
        elif negative:fw[0]['properties'].update(startIpAddress='0.0.0.0',endIpAddress='0.0.0.0')
    elif slug in ('keyvault_audit_logging','keyvault_audit_and_alllogs_groups','managed_hsm_audit_logging'):
        deciding='diagnosticSettings'
        if missing:diagnostics=[]
        elif negative:
            for log in diagnostics[0]['properties']['logs']:log['enabled']=False
        elif malformed:diagnostics[0]['properties']['logs']={}
    elif 'expiration_set' in slug:
        deciding='properties.attributes.exp'
        item['properties']['enableRbacAuthorization']='non_rbac' not in slug
        for obj in (key,secret):
            if missing or negative:obj['attributes'].pop('exp',None)
            else:obj['attributes']['exp']={} if malformed else None if negative else 2000000000
    elif slug in ('keyvault_key_rotation_policy','keyvault_key_automatic_rotation_after_create'):
        deciding='properties.rotationPolicy'
        if missing:rotation.pop('lifetimeActions',None)
        elif negative:rotation['lifetimeActions']=[{'trigger':{'timeBeforeExpiry':'P30D'},'action':{'type':'Notify'}}]
        elif malformed:rotation['lifetimeActions']={}
    elif slug=='recovery_vault_backup_retention_30_days':
        deciding='backupPolicies.retentionPolicy.dailySchedule.retentionDuration'
        if missing:policies=[]
        else:policies[0]['properties']['retentionPolicy']['dailySchedule']['retentionDuration']['count']={} if malformed else 7 if negative else 30
    else:raise AssertionError('Unaccounted ID '+cid)
    return {'kind':kind,'parentkind':parentkind,'rid':rid,'version':version,'endpoint':endpoint,'item':item,'configurations':configs,'firewallRules':fw,'administrators':admins,'diagnosticSettings':diagnostics,'backupPolicies':policies,'key':key,'secret':secret,'rotation':rotation,'deciding':deciding}


class NativeHTTP:
    def __init__(self,cid,mode,mutate=None):
        self.cid,self.mode=cid,mode;self.data=native_case(cid,mode);self.calls=[];self.unexpected=[]
        if mutate:mutate(self.data)
    def open(self,request,timeout):
        try:
            response=self._open(request,timeout)
            response.status=200
            return response
        except AssertionError as exc:self.unexpected.append((request.full_url,str(exc)));raise
    def _open(self,request,timeout):
        p=urlsplit(request.full_url);q=parse_qs(p.query);d=self.data;rid=d['rid'];path=p.path
        assert p.scheme=='https' and p.netloc in ('management.azure.com','reviewvault.vault.azure.net')
        assert timeout==20
        method=request.get_method();self.calls.append({'method':method,'host':p.netloc,'path':path,'query':q})
        def deny():raise HTTPError(request.full_url,403,'fixture denied',{},io.BytesIO(b'{}'))
        assert set(q)<={'api-version','$expand','$top','$filter','$select','page'} and len(q.get('api-version',[]))==1
        if self.mode=='denied':deny()
        if method=='POST':
            assert p.netloc=='management.azure.com' and path=='/providers/Microsoft.ResourceGraph/resources' and q['api-version']==['2022-10-01']
            body=json.loads(request.data);assert body['subscriptions']==[SUB] and isinstance(body['query'],str)
            value={'data':[d['item']],'count':1,'resultTruncated':False}
        else:
            assert method=='GET' and request.data is None
            if p.netloc=='reviewvault.vault.azure.net':
                assert q['api-version']==['2025-07-01']
                assert path in ('/keys','/secrets','/keys/data/rotationpolicy')
                if self.mode=='child_denied' or 'page' in q:deny()
                value=d['rotation'] if path.endswith('rotationpolicy') else {'value':[d['key'] if path=='/keys' else d['secret']]}
                if self.mode=='child_empty' and 'value' in value:value={'value':[]}
                if self.mode=='child_partial' and 'value' in value:value={**value,'nextLink':ORIGIN+path+'?api-version=2025-07-01&page=2'}
                if self.mode=='foreign_child':
                    value=deepcopy(value)
                    if path=='/keys':value['value'][0]['kid']=value['value'][0]['kid'].replace('reviewvault','foreignvault')
                    elif path=='/secrets':value['value'][0]['id']=value['value'][0]['id'].replace('reviewvault','foreignvault')
                    else:value['id']=value['id'].replace('reviewvault','foreignvault')
            elif path==SCOPE:
                value={'id':SCOPE,'subscriptionId':SUB,'tenantId':TENANT,'state':'Enabled'}
            elif path==SCOPE+'/resources':value={'value':[d['item']]}
            elif path==SCOPE+'/providers/'+d['endpoint']:
                assert q['api-version']==[d['version']]
                if 'page' in q:deny()
                value={'value':[] if self.mode=='empty' else [deepcopy(d['item'])]}
                if self.mode=='foreign':value['value'][0]['id']=rid.replace(SUB,OTHER)
                if self.mode=='wrong_type':value['value'][0]['type']='Microsoft.Compute/virtualMachines'
                if self.mode=='parent_partial':value['nextLink']=azure.ARM+path+'?api-version='+d['version']+'&page=2'
            elif path==rid:
                assert q['api-version']==[d['version']];value=deepcopy(d['item'])
                if self.mode=='detail_denied':deny()
                if self.mode=='wrong_type':value['type']='Microsoft.Compute/virtualMachines'
            elif path.startswith(rid+'/'):
                field=path[len(rid)+1:]
                assert field in ('configurations','firewallRules','administrators','backupPolicies','backupProtectedItems','backupJobs','providers/Microsoft.Insights/diagnosticSettings','providers/Microsoft.Insights/diagnosticSettingsCategories')
                expected='2021-05-01-preview' if field.startswith('providers/Microsoft.Insights/') else d['version']
                assert q['api-version']==[expected]
                if self.mode=='child_denied' or 'page' in q and self.mode not in ('child_identical_repeat','child_conflicting_repeat'):deny()
                field='diagnosticSettings' if field=='providers/Microsoft.Insights/diagnosticSettings' else field
                value={'value':deepcopy(d.get(field,[]))}
                if self.mode=='child_empty':value={'value':[]}
                if self.mode=='child_partial':value['nextLink']=azure.ARM+path+'?api-version='+expected+'&page=2'
                if self.mode in ('child_identical_repeat','child_conflicting_repeat') and 'page' not in q:
                    value['nextLink']=azure.ARM+path+'?api-version='+expected+'&page=2'
                if self.mode=='child_conflicting_repeat' and 'page' in q and field=='configurations':
                    name=PARAMETERS[self.cid.split('.',2)[-1]][0]
                    next(r for r in value['value'] if r['name']==name)['properties']['value']=PARAMETERS[self.cid.split('.',2)[-1]][2]
                if self.mode=='foreign_child' and value['value']:
                    value['value'][0]['id']=value['value'][0]['id'].replace('/review/','/sibling/') if '/review/' in value['value'][0]['id'] else rid+'/sibling/child'
            else:
                ancillary=empty_inventory_versions(SCOPE)
                allowed={SCOPE+'/providers/'+endpoint for endpoint,version in azure.ENDPOINTS.values()}
                allowed|={SCOPE+'/resourcegroups',SCOPE+'/providers/Microsoft.Network/locations/eastus/serviceTags',SCOPE+'/providers/Microsoft.Network/locations/westcentralus/serviceTags'}
                allowed.update(ancillary)
                assert path in allowed,path
                if path in ancillary:assert matches_empty_inventory_query(SCOPE,path,q)
                value={'value':[]}
        return io.BytesIO(json.dumps(value).encode())


@pytest.fixture(autouse=True)
def offline(monkeypatch):
    def blocked(*args,**kwargs):raise AssertionError('Network/DNS/auth blocked')
    for name in ('create_connection','getaddrinfo'):monkeypatch.setattr(socket,name,blocked)
    for name in ('connect','connect_ex'):monkeypatch.setattr(socket.socket,name,blocked)
    monkeypatch.setattr(azure,'credential_for',blocked)


def capture(monkeypatch,cid,mode='positive',mutate=None):
    http=NativeHTTP(cid,mode,mutate);monkeypatch.setattr(azure,'build_opener',lambda *args:http)
    connector={'provider':'azure','scopes':[SUB],'auth':{'method':'token','arm_token':'fixture-inert','vault_token':'fixture-inert'},'options':{'concurrency':1,'retries':0}}
    required=plan_collection({'connector':connector,'checks':[cid]})
    snapshot=azure.collect(connector,required)
    findings=evaluate_snapshot(snapshot,checks=[cid],include_not_applicable=True)['findings']
    assert not http.unexpected,http.unexpected
    assert PRIVATE not in json.dumps(snapshot)
    assert findings, (cid,snapshot)
    return findings,snapshot,http


def expected(cid,mode):
    if mode=='denied':return 'DENIED'
    if mode=='empty':return 'EMPTY'
    if mode in ('foreign','wrong_type','malformed'):return 'UNKNOWN'
    # Diagnostic-settings storage retention ceased applying on 2025-09-30.
    # A legacy field cannot establish this current retention contract.
    if cid=='azure.claude.managed_hsm_audit_logging' and mode in ('positive','parent_partial','child_denied','child_partial'):return 'UNKNOWN'
    if mode=='parent_partial':
        if REGISTRY[cid].kind in ('key_vault_key','secret_metadata'):return 'PASS'
        return 'UNKNOWN' if cid.startswith('azure.cis.') and REGISTRY[cid].kind.endswith('single_server') else 'PASS,UNKNOWN'
    if mode=='child_denied':
        if REGISTRY[cid].kind in ('key_vault_key','secret_metadata'):return 'DENIED'
        return 'UNKNOWN' if needs_children(cid) else 'PASS'
    if mode=='child_partial':
        if 'expiration_set' in cid:return 'PASS,UNKNOWN'
        return 'UNKNOWN' if needs_children(cid) else 'PASS'
    if mode=='missing':
        slug=cid.split('.',2)[-1]
        if slug in ('postgresql_single_connection_throttling','postgresql_single_log_checkpoints','mysql_single_audit_log_events_connection'):return 'FAIL'
        if 'no_azure_services_rule' in slug or 'no_zero_address_rule' in slug:return 'PASS'
        if slug=='postgresql_flexible_connection_throttling':return 'NOT_APPLICABLE'
        if slug=='recovery_vault_backup_retention_30_days':return 'FAIL'
        if slug in ('cosmos_cmk','cosmos_private_endpoint_present','keyvault_firewall_ip_rules','keyvault_audit_logging','keyvault_audit_and_alllogs_groups','managed_hsm_audit_logging'):return 'FAIL'
        if 'expiration_set' in slug:return 'FAIL'  # absent optional exp on complete metadata means no configured expiry
        if 'rotation' in slug:return 'FAIL'  # GET policy with omitted optional lifetimeActions has no Rotate action
        return 'UNKNOWN'
    return 'FAIL' if mode=='negative' else 'PASS'


def needs_children(cid):
    slug=cid.split('.',2)[-1]
    return slug in PARAMETERS or any(s in slug for s in ('no_azure_services_rule','no_zero_address_rule','audit_logging','alllogs_groups','expiration_set','key_rotation','rotation_after_create','retention_30_days','entra_authentication'))


@pytest.mark.parametrize('cid',ROSTER)
@pytest.mark.parametrize('mode',('positive','negative','missing','malformed','denied','empty','foreign','wrong_type','parent_partial','child_denied','child_partial'))
def test_native_matrix(monkeypatch,cid,mode,record_property):
    findings,snapshot,http=capture(monkeypatch,cid,mode)
    statuses={f['status'] for f in findings}
    record_property('check_id',cid);record_property('mode',mode)
    record_property('actual',','.join(sorted(statuses)));record_property('expected',expected(cid,mode))
    record_property('native_capture',json.dumps({'collections':[{'type':c['type'],'scope':c['scope'],'status':c['status']} for c in snapshot['collections']],'http':http.calls},sort_keys=True))
    assert statuses==set(expected(cid,mode).split(',')),findings

# These are distinct producer/join witnesses, not generic registry fixtures.
CHILD_IDS=tuple(c for c in ROSTER if needs_children(c))

@pytest.mark.parametrize('cid',CHILD_IDS)
def test_native_foreign_child(monkeypatch,cid,record_property):
    findings,snapshot,http=capture(monkeypatch,cid,'foreign_child')
    actual={f['status'] for f in findings}
    record_property('check_id',cid);record_property('mode','foreign_child');record_property('actual',','.join(sorted(actual)));record_property('expected','UNKNOWN')
    assert actual=={'UNKNOWN'},findings

@pytest.mark.parametrize('cid',tuple(c for c in ROSTER if c.split('.',2)[-1] in PARAMETERS))
def test_conflicting_configuration_identity(monkeypatch,cid,record_property):
    name=PARAMETERS[cid.split('.',2)[-1]][0]
    def mutate(d):
        row=deepcopy(next(r for r in d['configurations'] if r['name']==name));row['properties']['value']=PARAMETERS[cid.split('.',2)[-1]][2];d['configurations'].append(row)
    findings,snapshot,http=capture(monkeypatch,cid,mutate=mutate)
    actual={f['status'] for f in findings}
    record_property('check_id',cid);record_property('mode','duplicate_configuration');record_property('actual',','.join(sorted(actual)));record_property('expected','UNKNOWN')
    assert actual=={'UNKNOWN'},findings

@pytest.mark.parametrize('cid',tuple(c for c in ROSTER if 'expiration_set' in c))
@pytest.mark.parametrize('variant',('disabled','other_authorization','missing_enabled'))
def test_expiration_applicability(monkeypatch,cid,variant,record_property):
    def mutate(d):
        for obj in (d['key'],d['secret']):
            if variant=='disabled':obj['attributes']['enabled']=False
            elif variant=='missing_enabled':obj['attributes'].pop('enabled')
        if variant=='other_authorization':d['item']['properties']['enableRbacAuthorization']=not d['item']['properties']['enableRbacAuthorization']
    findings,snapshot,http=capture(monkeypatch,cid,mutate=mutate)
    want='UNKNOWN' if variant=='missing_enabled' else 'PASS' if variant=='other_authorization' and cid.endswith('keyvault_key_expiration_set') else 'NOT_APPLICABLE'
    actual={f['status'] for f in findings};record_property('check_id',cid);record_property('mode',variant);record_property('actual',','.join(sorted(actual)));record_property('expected',want)
    assert actual=={want},findings

@pytest.mark.parametrize('engine',('mysql','postgresql'))
@pytest.mark.parametrize('mode',('SameZone','Burstable','unknown'))
def test_native_high_availability_applicability(monkeypatch,engine,mode,record_property):
    cid='azure.claude.'+engine+'_flexible_high_availability'
    def mutate(d):
        d['item']['properties']['highAvailability']['mode']='Unexpected' if mode=='unknown' else 'Disabled' if mode=='Burstable' else mode
        if mode=='Burstable':d['item']['sku']['tier']='Burstable'
    findings,snapshot,http=capture(monkeypatch,cid,mutate=mutate)
    want={'unknown':'UNKNOWN','Burstable':'NOT_APPLICABLE','SameZone':'PASS'}[mode]
    record_property('check_id',cid);record_property('mode',mode)
    assert {f['status'] for f in findings}=={want},findings

@pytest.mark.parametrize('variant,expected_status',(('weeks', 'PASS'),('unknown_unit','UNKNOWN'),('missing_unit','UNKNOWN'),('bool_count','UNKNOWN'),('negative_count','UNKNOWN'),('no_daily','NOT_APPLICABLE')))
def test_backup_native_duration_unit(monkeypatch,variant,expected_status,record_property):
    cid='azure.claude.recovery_vault_backup_retention_30_days'
    def mutate(d):
        policy=d['backupPolicies'][0]['properties']['retentionPolicy'];duration=policy['dailySchedule']['retentionDuration']
        if variant=='weeks':duration.update(count=5,durationType='Weeks')
        if variant=='unknown_unit':duration['durationType']='Invalid'
        if variant=='missing_unit':duration.pop('durationType')
        if variant=='bool_count':duration['count']=True
        if variant=='negative_count':duration['count']=-1
        if variant=='no_daily':policy.pop('dailySchedule')
    findings,snapshot,http=capture(monkeypatch,cid,mutate=mutate)
    actual={f['status'] for f in findings};record_property('check_id',cid);record_property('mode',variant);record_property('actual',','.join(sorted(actual)));record_property('expected',expected_status)
    assert actual=={expected_status},findings

@pytest.mark.parametrize('cid',('azure.claude.postgresql_flexible_no_azure_services_rule','azure.claude.postgresql_flexible_no_zero_address_rule'))
def test_disabled_network_overrides_denied_firewall(monkeypatch,cid,record_property):
    def mutate(d):d['item']['properties']['network']['publicNetworkAccess']='Disabled'
    findings,snapshot,http=capture(monkeypatch,cid,'child_denied',mutate)
    record_property('check_id',cid);record_property('mode','disabled_pna_override')
    assert {f['status'] for f in findings}=={'PASS'},findings

@pytest.mark.parametrize('cid',('azure.claude.cosmos_private_endpoint_present','azure.claude.keyvault_private_endpoint_exists'))
def test_connection_presence_is_not_approval(monkeypatch,cid,record_property):
    def mutate(d):d['item']['properties']['privateEndpointConnections'][0]['properties']['privateLinkServiceConnectionState']['status']='Pending'
    findings,snapshot,http=capture(monkeypatch,cid,mutate=mutate)
    record_property('check_id',cid);record_property('mode','pending_presence_only')
    assert {f['status'] for f in findings}=={'PASS'},findings

@pytest.mark.parametrize('cid',tuple(c for c in ROSTER if c.split('.',2)[-1] in PARAMETERS))
@pytest.mark.parametrize('variant',('wrong_child_segment','contradictory_name','wrong_child_type'))
def test_parameter_native_parent_binding(monkeypatch,cid,variant,record_property):
    name=PARAMETERS[cid.split('.',2)[-1]][0]
    def mutate(d):
        row=next(r for r in d['configurations'] if r['name']==name)
        if variant=='wrong_child_segment':row['id']=d['rid']+'/firewallRules/'+name
        if variant=='contradictory_name':row['id']=d['rid']+'/configurations/other'
        if variant=='wrong_child_type':row['type']='Microsoft.Compute/virtualMachines'
    findings,snapshot,http=capture(monkeypatch,cid,mutate=mutate)
    actual={f['status'] for f in findings};record_property('check_id',cid);record_property('mode',variant);record_property('actual',','.join(sorted(actual)));record_property('expected','UNKNOWN')
    assert actual=={'UNKNOWN'},findings

@pytest.mark.parametrize('cid',tuple(c for c in ROSTER if c.split('.',2)[-1] in PARAMETERS))
@pytest.mark.parametrize('mode,want',(('child_identical_repeat','PASS'),('child_conflicting_repeat','UNKNOWN')))
def test_native_configuration_repeats_across_pages(monkeypatch,cid,mode,want,record_property):
    findings,snapshot,http=capture(monkeypatch,cid,mode)
    record_property('check_id',cid);record_property('mode',mode)
    assert {f['status'] for f in findings}=={want},findings

@pytest.mark.parametrize('cid',('azure.claude.keyvault_key_expiration_set','azure.claude.keyvault_rbac_secret_expiration_set'))
@pytest.mark.parametrize('uri',('https://foreignvault.vault.azure.net/','https://reviewvault.vault.azure.net.evil.example/','https://reviewvault.vault.azure.net:8443/','https://user@reviewvault.vault.azure.net/','http://reviewvault.vault.azure.net/'))
def test_metadata_endpoint_is_selected_native_vault(monkeypatch,cid,uri,record_property):
    def mutate(d):d['item']['properties']['vaultUri']=uri
    findings,snapshot,http=capture(monkeypatch,cid,mutate=mutate)
    record_property('check_id',cid);record_property('mode','unbound_vault_endpoint')
    assert {f['status'] for f in findings}=={'UNKNOWN'},findings
    assert not any(call['host']!='management.azure.com' for call in http.calls)

@pytest.mark.parametrize('count,unit,want',((4,'Weeks','FAIL'),(5,'Weeks','PASS'),(1,'Months','UNKNOWN'),(2,'Months','PASS'),(1,'Years','PASS'),(29,'Days','FAIL'),(30,'Days','PASS')))
def test_backup_threshold_in_native_units(monkeypatch,count,unit,want,record_property):
    cid='azure.claude.recovery_vault_backup_retention_30_days'
    def mutate(d):d['backupPolicies'][0]['properties']['retentionPolicy']['dailySchedule']['retentionDuration'].update(count=count,durationType=unit)
    findings,snapshot,http=capture(monkeypatch,cid,mutate=mutate)
    record_property('check_id',cid);record_property('mode','duration_'+str(count)+'_'+unit)
    assert {f['status'] for f in findings}=={want},findings

@pytest.mark.parametrize('kind',('mysql_single_server','postgresql_single_server','mysql_flexible_server','postgresql_flexible_server','cosmos_account','vault','managed_hsm','recovery_vault'))
@pytest.mark.parametrize('variant,want',(('name_absent','PASS'),('name_contradicts','UNKNOWN')))
def test_native_parent_redundant_name_coherence(monkeypatch,kind,variant,want,record_property):
    cid=next(c for c in ROSTER if REGISTRY[c].kind==kind and not c.endswith('managed_hsm_audit_logging'))
    def mutate(d):
        if variant=='name_absent':d['item'].pop('name')
        else:d['item']['name']='sibling'
    findings,snapshot,http=capture(monkeypatch,cid,mutate=mutate)
    record_property('check_id',cid);record_property('mode',variant)
    assert {f['status'] for f in findings}=={want},findings

from pathlib import Path
CURRENT_OVERLAY=json.loads((Path(__file__).parent/'fixtures'/'azure_database_crypto_backup_1_native_current_20261020.json').read_text())


@pytest.mark.parametrize('variant',('modern_no_retention','disabled_retention'))
def test_hsm_audit_archive_without_retention_proof(monkeypatch,variant,record_property):
    cid='azure.claude.managed_hsm_audit_logging'
    def mutate(d):
        log=d['diagnosticSettings'][0]['properties']['logs'][0]
        if variant=='modern_no_retention':log.pop('retentionPolicy')
        else:log['retentionPolicy']['enabled']=False
    findings,snapshot,http=capture(monkeypatch,cid,mutate=mutate)
    actual={f['status'] for f in findings};record_property('check_id',cid);record_property('mode',variant);record_property('actual',','.join(sorted(actual)));record_property('expected','UNKNOWN')
    assert actual=={'UNKNOWN'},findings


def test_hsm_legacy_retention_is_not_current_retention_proof(monkeypatch,record_property):
    cid='azure.claude.managed_hsm_audit_logging'
    findings,snapshot,http=capture(monkeypatch,cid)
    record_property('check_id',cid);record_property('mode','deprecated_retention');record_property('actual',','.join(sorted({f['status']for f in findings})));record_property('expected','UNKNOWN')
    assert {f['status']for f in findings}=={'UNKNOWN'},findings

@pytest.mark.parametrize('slug',('postgresql_single_connection_throttling','postgresql_single_log_checkpoints'))
def test_legacy_postgres_native_lowercase_boolean_parameter(monkeypatch,slug,record_property):
    cid='azure.cis.'+slug
    def mutate(d):
        name=PARAMETERS[slug][0]
        next(r for r in d['configurations']if r['name']==name)['properties']['value']='on'
    findings,snapshot,http=capture(monkeypatch,cid,mutate=mutate)
    record_property('check_id',cid);record_property('mode','native_lowercase_on');record_property('actual',','.join(sorted({f['status']for f in findings})));record_property('expected','PASS')
    assert {f['status']for f in findings}=={'PASS'},findings
