"""Independent native Azure response contracts; no cloud/auth/socket access."""
from tests import archived_check_contract as archived
import hashlib
import io
import json
import os
import socket
from copy import deepcopy
from datetime import datetime,timedelta,timezone
from pathlib import Path
from urllib.parse import urlsplit,parse_qs
import pytest
from tests.azure_native_inventory_routes_20261020 import empty_inventory_versions,matches_empty_inventory_query
from peaso import engine
from peaso.collectors import azure
from peaso.checks import CHECKS

SUB='11111111-1111-1111-1111-111111111111'
TENANT='22222222-2222-2222-2222-222222222222'
OTHER='99999999-9999-9999-9999-999999999999'
USER='33333333-3333-3333-3333-333333333333'
SCOPE='/subscriptions/'+SUB
RG=SCOPE+'/resourceGroups/review'
VNET=RG+'/providers/Microsoft.Network/virtualNetworks/native'
SUBNET=VNET+'/subnets/workload'
SQL=RG+'/providers/Microsoft.Sql/servers/native'
DB=SQL+'/databases/application'
STORAGE=RG+'/providers/Microsoft.Storage/storageAccounts/reviewnative'
WORKSPACE=RG+'/providers/Microsoft.OperationalInsights/workspaces/native'
PE=RG+'/providers/Microsoft.Network/privateEndpoints/native'
REAL_TRANSPORT=azure.AzureTransportExposure
RECEIPTS=[]

@pytest.fixture(autouse=True)
def offline(monkeypatch):
    def blocked(*a,**k):pytest.fail('socket/DNS/credential discovery is forbidden')
    for key in ('connect','connect_ex'):monkeypatch.setattr(socket.socket,key,blocked)
    for key in ('getaddrinfo','gethostbyname','gethostbyname_ex','create_connection'):monkeypatch.setattr(socket,key,blocked)
    monkeypatch.setattr(azure,'credential_for',blocked)
    monkeypatch.setattr(azure,'urlopen',blocked)
    monkeypatch.setattr(azure.time,'sleep',lambda seconds:None)

@pytest.fixture(scope='session',autouse=True)
def receipts():
    yield
    if folder:=os.environ.get('AZURE_REMAINING2_RECEIPTS'):
        Path(folder).mkdir(parents=True,exist_ok=True)
        Path(folder,'native-cases.json').write_text(json.dumps(RECEIPTS,indent=2)+'\n')

ROSTER=['azure.claude.servicebus_namespace_private_link', 'azure.claude.servicebus_premium_namespace_cmk', 'azure.claude.servicebus_premium_namespace_vnet_rules', 'azure.claude.servicefabric_cluster_encrypt_and_sign', 'azure.claude.servicefabric_cluster_entra_auth', 'azure.claude.signalr_service_no_free_tier', 'azure.claude.signalr_service_private_link', 'azure.claude.spring_cloud_service_vnet_injection', 'azure.claude.sql_audit_retention_over_90', 'azure.claude.sql_audit_storage_retention_90', 'azure.claude.sql_database_long_term_retention', 'azure.claude.sql_firewall_no_full_range', 'azure.claude.sql_firewall_no_internet_or_azure_services', 'azure.claude.storage_container_no_public_access', 'azure.claude.storage_encryption_scope_cmk', 'azure.claude.storage_sync_private_link', 'azure.claude.stream_analytics_job_logging_enabled', 'azure.claude.subscription_diagnostic_setting_any_categories', 'azure.claude.subscription_diagnostic_setting_categories', 'azure.claude.subscription_diagnostic_setting_exists', 'azure.claude.vnet_gateway_entra_only', 'azure.claude.vnet_gateway_no_basic_sku', 'azure.claude.vnet_peering_connected', 'azure.claude.waf_policy_bot_protection', 'azure.claude.waf_policy_request_body_inspection', 'azure.claude2.apim_consumption_client_certificate', 'azure.claude2.app_service_environment_internal_encryption', 'azure.claude2.app_service_plan_minimum_sku', 'azure.claude2.application_insights_configured', 'azure.claude2.application_insights_public_access_blocked', 'azure.claude2.application_insights_workspace_based', 'azure.claude2.automation_variable_encrypted', 'azure.claude2.batch_account_customer_managed_key', 'azure.claude2.batch_account_managed_identity', 'azure.claude2.batch_account_resource_logs', 'azure.claude2.entra_user_mfa_registered', 'azure.claude2.vnet_with_app_gateway_ddos_protection', 'azure.gap.arc_kubernetes_cluster_azure_defender_extension_installed', 'azure.gap.machine_learning_workspace_private_link_used', 'azure.gap.monitor_log_cluster_encrypted_with_cmk', 'azure.gap.monitor_log_cluster_infrastructure_encryption_enabled', 'azure.gap.monitor_log_profile_enabled_for_all_categories', 'azure.gap.monitor_log_profile_retention_365_days', 'azure.gap.stream_analytics_job_encrypted_with_cmk', 'azure.gap.web_pub_sub_private_link_used', 'azure.htbp.appconfig.local_auth_disabled', 'azure.htbp.batch.shared_key_auth_disabled', 'azure.htbp.entra.temporary_access_pass_one_time', 'azure.htbp.eventgrid.domain_local_auth_disabled', 'azure.htbp.eventgrid.topic_local_auth_disabled', 'azure.htbp.eventhub.local_auth_disabled', 'azure.htbp.iothub.local_auth_disabled', 'azure.htbp.logicapp.request_trigger_caller_restricted', 'azure.htbp.search.api_key_auth_disabled', 'azure.htbp.signalr.local_auth_disabled', 'azure.htbp.webpubsub.local_auth_disabled', 'azure.network.ddos_configured', 'azure.network.nic_no_ip_forwarding', 'azure.other.access_analysis_coverage', 'azure.other.entra_app_secret_age_90']
REGISTRY={c.id:c for c in CHECKS}
UNPRODUCED={'azure.gap.monitor_log_cluster_encrypted_with_cmk','azure.gap.stream_analytics_job_encrypted_with_cmk','azure.other.access_analysis_coverage'}

def resource(rid,typ,props=None,**extra):
    return {'id':rid,'name':rid.rsplit('/',1)[-1],'type':typ,'location':'eastus','properties':{'provisioningState':'Succeeded',**(props or {})},**extra}

def native(cid,opposite=False):
    kind=REGISTRY[cid].kind
    data={SCOPE:{'id':SCOPE,'subscriptionId':SUB,'tenantId':TENANT,'state':'Enabled'},
          '/tenants':{'value':[{'id':'/tenants/'+TENANT,'tenantId':TENANT}]},
          '/subscriptions':{'value':[{'id':SCOPE,'subscriptionId':SUB,'tenantId':TENANT,'state':'Enabled'}]}}
    rows={}
    def parent(k,p=None,**extra):
        typ=azure.ENDPOINTS[k][0];rid=RG+'/providers/'+typ+'/native'
        row=resource(rid,typ,p,**extra);rows[k]=row
        data[SCOPE+'/providers/'+typ]={'value':[row]};data[rid]=row
        return row
    def child(parent_row,field,typ,p=None,name='native',version='2023-09-01'):
        row=resource(parent_row['id']+'/'+field+'/'+name,typ,p)
        data[parent_row['id']+'/'+field]={'value':[row]};data[row['id']]=row
        return row
    # Actual ARM parent contracts. Independent of runtime CASES.
    sb=parent('servicebus_namespace',{'status':'Active','publicNetworkAccess':'Enabled','minimumTlsVersion':'1.2',
        'encryption':{'keySource':'Microsoft.KeyVault','keyVaultProperties':[{'keyName':'native','keyVaultUri':'https://reviewnative.vault.azure.net','keyVersion':'abc'}]}},
        sku={'name':'Premium','tier':'Premium','capacity':1})
    data[sb['id']+'/networkRuleSets/default']=resource(sb['id']+'/networkRuleSets/default','Microsoft.ServiceBus/namespaces/networkRuleSets',
        {'publicNetworkAccess':'Enabled','defaultAction':'Deny','ipRules':[],'virtualNetworkRules':[{'subnet':{'id':SUBNET},'ignoreMissingVnetServiceEndpoint':False}]})
    fabric=parent('service_fabric_cluster',{'reliabilityLevel':'Silver','upgradeMode':'Automatic',
        'fabricSettings':[{'name':'Security','parameters':[{'name':'ClusterProtectionLevel','value':'EncryptAndSign'}]}],
        'azureActiveDirectory':{'tenantId':TENANT,'clusterApplication':USER,'clientApplication':'44444444-4444-4444-4444-444444444444'}})
    signal=parent('signalr_service',{'disableLocalAuth':True,'publicNetworkAccess':'Disabled'},sku={'name':'Standard_S1','tier':'Standard','capacity':1})
    spring=parent('spring_cloud_service',{'networkProfile':{'serviceRuntimeSubnetId':SUBNET,'appSubnetId':VNET+'/subnets/apps'}},
        sku={'name':'S0','tier':'Standard','capacity':1})
    sql=parent('sql_server',{'version':'12.0','fullyQualifiedDomainName':'reviewnative.database.windows.net'})
    # Keep authoritative standard server/database identities throughout joins.
    rows['sql_server']=sql
    database=child(sql,'databases','Microsoft.Sql/servers/databases',{'status':'Online'},'application')
    audit=child(sql,'auditingSettings','Microsoft.Sql/servers/auditingSettings',{'state':'Enabled','retentionDays':365,'storageEndpoint':'https://reviewnative.blob.core.windows.net/'},'default')
    firewall=child(sql,'firewallRules','Microsoft.Sql/servers/firewallRules',{'startIpAddress':'203.0.113.10','endIpAddress':'203.0.113.10'})
    ltr=child(database,'backupLongTermRetentionPolicies','Microsoft.Sql/servers/databases/backupLongTermRetentionPolicies',{'weeklyRetention':'P4W','monthlyRetention':'P12M','yearlyRetention':'P5Y','weekOfYear':1},'default')
    store=parent('storage_account',{'primaryEndpoints':{'blob':'https://reviewnative.blob.core.windows.net/'},'encryption':{'keySource':'Microsoft.Keyvault'}})
    store['id']=STORAGE;data[STORAGE]=store
    blob=resource(STORAGE+'/blobServices/default','Microsoft.Storage/storageAccounts/blobServices')
    data[blob['id']]=blob
    container=child(blob,'containers','Microsoft.Storage/storageAccounts/blobServices/containers',{'publicAccess':'None'},'content')
    scope=child(store,'encryptionScopes','Microsoft.Storage/storageAccounts/encryptionScopes',{'source':'Microsoft.KeyVault','state':'Enabled','keyVaultProperties':{'keyUri':'https://reviewnative.vault.azure.net/keys/native/abc'}})
    sync=parent('storage_sync_service',{'incomingTrafficPolicy':'AllowVirtualNetworksOnly'})
    stream=parent('stream_analytics_job',{'jobType':'Cloud','jobState':'Running','outputErrorPolicy':'Stop','eventsOutOfOrderPolicy':'Adjust','compatibilityLevel':'1.2'})
    waf=parent('web_application_firewall_policy',{'policySettings':{'state':'Enabled','mode':'Prevention','requestBodyCheck':True},
        'managedRules':{'managedRuleSets':[{'ruleSetType':'Microsoft_BotManagerRuleSet','ruleSetVersion':'1.1','ruleGroupOverrides':[]}]}})
    apim=parent('api_management',{'enableClientCertificate':True},sku={'name':'Consumption','capacity':0})
    ase=parent('app_service_environment',{'clusterSettings':[{'name':'InternalEncryption','value':'true'}]})
    plan=parent('app_service_plan',{'reserved':False},sku={'name':'P1v3','tier':'PremiumV3','size':'P1v3','family':'Pv3','capacity':1})
    insights=parent('application_insights',{'Application_Type':'web','WorkspaceResourceId':WORKSPACE,
        'publicNetworkAccessForIngestion':'Disabled','publicNetworkAccessForQuery':'Disabled','IngestionMode':'LogAnalytics'},kind='web')
    site=parent('app_service',{'state':'Running','enabled':True},kind='app')
    auto=parent('automation_account',{'state':'Ok','sku':{'name':'Basic'}})
    variable=child(auto,'variables','Microsoft.Automation/automationAccounts/variables',{'isEncrypted':True,'description':'native metadata only'})
    data[auto['id']+'/webhooks']={'value':[]}
    batch=parent('batch_account',{'allowedAuthenticationModes':['AAD','TaskAuthenticationToken'],'poolAllocationMode':'BatchService',
        'encryption':{'keySource':'Microsoft.KeyVault','keyVaultProperties':{'keyIdentifier':'https://reviewnative.vault.azure.net/keys/native/abc'}}},
        identity={'type':'SystemAssigned','principalId':USER,'tenantId':TENANT})
    vnet=parent('vnet',{'enableDdosProtection':True,'ddosProtectionPlan':{'id':RG+'/providers/Microsoft.Network/ddosProtectionPlans/native'},
        'subnets':[resource(SUBNET,'Microsoft.Network/virtualNetworks/subnets',{'addressPrefix':'10.0.1.0/24'})],
        'virtualNetworkPeerings':[resource(VNET+'/virtualNetworkPeerings/native','Microsoft.Network/virtualNetworks/virtualNetworkPeerings',
           {'peeringState':'Connected','remoteVirtualNetwork':{'id':VNET+'peer'},'allowVirtualNetworkAccess':True})]})
    vnet['id']=VNET;data[VNET]=vnet
    gateway=parent('application_gateway',{'sku':{'name':'Standard_v2','tier':'Standard_v2','capacity':2},
        'gatewayIPConfigurations':[resource(RG+'/providers/Microsoft.Network/applicationGateways/native/gatewayIPConfigurations/native',
           'Microsoft.Network/applicationGateways/gatewayIPConfigurations',{'subnet':{'id':SUBNET}})]})
    nic=parent('nic',{'enableIPForwarding':False,'ipConfigurations':[]})
    arc=parent('arc_kubernetes_cluster',{'connectivityStatus':'Connected','agentPublicKeyCertificate':''})
    extension=resource(arc['id']+'/providers/Microsoft.KubernetesConfiguration/extensions/native','Microsoft.KubernetesConfiguration/extensions',
        {'extensionType':'microsoft.azuredefender.kubernetes','provisioningState':'Succeeded','releaseTrain':'Stable','autoUpgradeMinorVersion':True})
    data[arc['id']+'/providers/Microsoft.KubernetesConfiguration/extensions']={'value':[extension]};data[extension['id']]=extension
    ml=parent('ml_workspace',{'publicNetworkAccess':'Disabled'})
    # Exact workspace-scoped Machine Learning compute List; no compute children.
    data[ml['id']+'/computes']={'value':[]}
    cluster=parent('log_analytics_cluster',{'isDoubleEncryptionEnabled':True,
        'keyVaultProperties':{'keyVaultUri':'https://reviewnative.vault.azure.net','keyName':'native','keyVersion':'abc'}},
        sku={'name':'CapacityReservation','capacity':100},identity={'type':'SystemAssigned','principalId':USER,'tenantId':TENANT})
    pub=parent('web_pubsub',{'disableLocalAuth':True,'publicNetworkAccess':'Disabled'},sku={'name':'Standard_S1','tier':'Standard','capacity':1})
    appconfig=parent('app_configuration',{'disableLocalAuth':True},sku={'name':'standard'})
    domain=parent('eventgrid_domain',{'disableLocalAuth':True})
    topic=parent('eventgrid_topic',{'disableLocalAuth':True})
    eventhub=parent('eventhub_namespace',{'disableLocalAuth':True},sku={'name':'Premium','tier':'Premium','capacity':1})
    iot=parent('iot_hub',{'disableLocalAuth':True,'disableDeviceSAS':True,'disableModuleSAS':True},sku={'name':'S1','tier':'Standard','capacity':1})
    workflow=parent('logic_app_workflow',{'state':'Enabled','definition':{'$schema':'https://schema.management.azure.com/providers/Microsoft.Logic/schemas/2016-06-01/workflowdefinition.json#',
        'contentVersion':'1.0.0.0','triggers':{'request':{'type':'Request','kind':'Http','inputs':{'schema':{}}}},'actions':{},'outputs':{}},
        'accessControl':{'triggers':{'allowedCallerIpAddresses':[{'addressRange':'203.0.113.0/24'}]}}})
    search=parent('search_service',{'disableLocalAuth':True,'replicaCount':1,'partitionCount':1},sku={'name':'standard'})
    pricing=resource(SCOPE+'/providers/Microsoft.Security/pricings/CloudPosture','Microsoft.Security/pricings',{'pricingTier':'Standard','extensions':[]})
    data[SCOPE+'/providers/Microsoft.Security/pricings']={'value':[pricing]};data[pricing['id']]=pricing
    rg={'id':RG,'name':'review','type':'Microsoft.Resources/resourceGroups','location':'eastus','properties':{'provisioningState':'Succeeded'}}
    data[SCOPE+'/resourcegroups']={'value':[rg]};data[RG]=rg
    vpn=resource(RG+'/providers/Microsoft.Network/virtualNetworkGateways/native','Microsoft.Network/virtualNetworkGateways',
        {'gatewayType':'Vpn','vpnType':'RouteBased','sku':{'name':'VpnGw1','tier':'VpnGw1','capacity':2},
         'vpnClientConfiguration':{'vpnAuthenticationTypes':['AAD'],'aadTenant':'https://login.microsoftonline.com/'+TENANT+'/',
             'aadAudience':USER,'aadIssuer':'https://sts.windows.net/'+TENANT+'/'}})
    data[RG+'/providers/Microsoft.Network/virtualNetworkGateways']={'value':[vpn]};data[vpn['id']]=vpn
    profile=resource(SCOPE+'/providers/Microsoft.Insights/logprofiles/default','Microsoft.Insights/logProfiles',
        {'categories':['Write','Delete','Action'],'locations':['global','eastus'],'storageAccountId':STORAGE,'serviceBusRuleId':None,'retentionPolicy':{'enabled':True,'days':365}})
    data[SCOPE+'/providers/Microsoft.Insights/logProfiles']={'value':[profile]};data[profile['id']]=profile
    diagnostic=resource(SCOPE+'/providers/Microsoft.Insights/diagnosticSettings/native','Microsoft.Insights/diagnosticSettings',
        {'storageAccountId':STORAGE,'workspaceId':WORKSPACE,'logs':[{'category':c,'enabled':True} for c in ('Administrative','Security','Alert','Policy')],'metrics':[]})
    data[SCOPE+'/providers/Microsoft.Insights/diagnosticSettings']={'value':[diagnostic]}
    for k,parent_row in rows.items():
        rid=parent_row['id']
        log=resource(rid+'/providers/Microsoft.Insights/diagnosticSettings/native','Microsoft.Insights/diagnosticSettings',
            {'workspaceId':WORKSPACE,'logs':[{'category':'Execution' if k=='stream_analytics_job' else 'ServiceLog' if k=='batch_account' else 'Audit','enabled':True}],'metrics':[]})
        data[rid+'/providers/Microsoft.Insights/diagnosticSettings']={'value':[log]}
        if k in ('servicebus_namespace','signalr_service','storage_sync_service','ml_workspace','web_pubsub'):
            connection=resource(rid+'/privateEndpointConnections/native',parent_row['type']+'/privateEndpointConnections',
               {'privateEndpoint':{'id':PE},'privateLinkServiceConnectionState':{'status':'Approved','description':'native'},'provisioningState':'Succeeded'})
            data[rid+'/privateEndpointConnections']={'value':[connection]}
            parent_row['properties']['privateEndpointConnections']=[connection]
    now=datetime.now(timezone.utc)
    data['/v1.0/reports/authenticationMethods/userRegistrationDetails']={'value':[{'id':USER,'userPrincipalName':'review@example.test','isMfaRegistered':True,'isMfaCapable':True}]}
    data['/v1.0/policies/authenticationMethodsPolicy']={'id':'authenticationMethodsPolicy','displayName':'Authentication Methods Policy',
        'policyMigrationState':'migrationComplete','authenticationMethodConfigurations':[{'id':'TemporaryAccessPass',
        '@odata.type':'#microsoft.graph.temporaryAccessPassAuthenticationMethodConfiguration','state':'enabled','isUsableOnce':True,
        'minimumLifetimeInMinutes':10,'maximumLifetimeInMinutes':60,'defaultLifetimeInMinutes':60,'defaultLength':8,
        'includeTargets':[{'id':'all_users','targetType':'group'}],'excludeTargets':[]}]}
    data['/v1.0/applications']={'value':[{'id':USER,'appId':'44444444-4444-4444-4444-444444444444','displayName':'native application',
       'passwordCredentials':[{'keyId':'55555555-5555-5555-5555-555555555555','displayName':'metadata','startDateTime':(now-timedelta(days=30)).isoformat(),
           'endDateTime':(now+timedelta(days=60)).isoformat()}],'keyCredentials':[]}]}
    # Optional child metadata is explicitly denied unless its actual native DTO is supplied above.
    for row in rows.values():
        for field in ('privateEndpointConnections','managedNamespaces','networkRuleSets','extensions','configuration','configurations'):
            data.setdefault(row['id']+'/'+field,azure.AzureReadError('unrelated_metadata_denied',403))
    # Explicit optional metadata requests: denial conveys no invented child fact.
    for row in list(rows.values())+[database,blob,profile]:
        rid=row['id']
        data.setdefault(rid+'/providers/Microsoft.Insights/diagnosticSettings',azure.AzureReadError('optional_diagnostics_denied',403))
        for path in ('administrators','virtualNetworkRules','securityAlertPolicies','vulnerabilityAssessments/default',
                     'sqlVulnerabilityAssessments/default','encryptionProtector/current','backupShortTermRetentionPolicies',
                     'longTermRetentionBackups','restorePoints','vulnerabilityAssessments/default/scans',
                     'slots','virtualNetworkConnections','config/web','config/authsettingsV2','config/logs',
                     'basicPublishingCredentialsPolicies/scm','basicPublishingCredentialsPolicies/ftp',
                     'eventhubs','authorizationRules','disasterRecoveryConfigs','networkRuleSets/default',
                     'providers/Microsoft.EventGrid/eventSubscriptions','localUsers',
                     # Later native child reads: Service Bus SAS rules and entities, Entra-only SQL
                     # authentication, ML online endpoints, Stream Analytics outputs,
                     # Web PubSub hubs and shared private links, and perimeter associations.
                     'AuthorizationRules','queues','topics','azureADOnlyAuthentications','onlineEndpoints','outputs','hubs',
                     'sharedPrivateLinkResources',
                     'networkSecurityPerimeterConfigurations'):
            data.setdefault(rid+'/'+path,azure.AzureReadError('optional_metadata_denied',403))
    # A successful native subscription resource index contains only resources in
    # this independent finite account, never synthetic coverage/provenance flags.
    selected=set(REGISTRY[cid].dependencies)|{kind}
    parent_for={'storage_container':'storage_account','storage_encryption_scope':'storage_account',
                'sql_database_ltr_policy':'sql_server','sql_audit':'sql_server','sql_firewall_rule':'sql_server',
                'automation_variable':'automation_account','vnet_peering':'vnet'}
    selected|={parent_for[k] for k in list(selected) if k in parent_for}
    if cid=='azure.claude2.application_insights_configured':selected|={'application_insights','app_service'}
    data[SUBNET]=vnet['properties']['subnets'][0]
    data[VNET+'/virtualNetworkPeerings/native']=vnet['properties']['virtualNetworkPeerings'][0]
    data[STORAGE+'/providers/Microsoft.Authorization/locks']=azure.AzureReadError('locks_not_required',403)
    data[SCOPE+'/resources']={'value':[row for k,row in rows.items() if k in selected]}
    for endpoint,version in azure.ENDPOINTS.values():
        data.setdefault(SCOPE+'/providers/'+endpoint,azure.AzureReadError('optional_parent_denied',403))
    for path in empty_inventory_versions(SCOPE):
        data.setdefault(path,{'value':[]})
    data[SCOPE+'/providers/Microsoft.Network/locations/westcentralus/serviceTags']=azure.AzureReadError('service_tags_not_required',403)
    data[RG+'/providers/Microsoft.Authorization/locks']=azure.AzureReadError('locks_not_required',403)
    # Per-resource-group VPN connection lists are optional; denial invents no connection.
    data.setdefault(RG+'/providers/Microsoft.Network/connections',azure.AzureReadError('optional_vpn_connections_denied',403))
    data[SCOPE+'/providers/Microsoft.Authorization/locks']=azure.AzureReadError('locks_not_required',403)
    for service in ('blobServices','queueServices','tableServices','fileServices'):
        data.setdefault(STORAGE+'/'+service+'/default',azure.AzureReadError('optional_storage_service_denied',403))
        data.setdefault(STORAGE+'/'+service+'/default/providers/Microsoft.Insights/diagnosticSettings',azure.AzureReadError('optional_storage_service_diagnostics_denied',403))
    if opposite:
        def p(k):return rows[k]['properties']
        if cid=='azure.claude.servicebus_premium_namespace_cmk':p('servicebus_namespace')['encryption']['keySource']='Microsoft.ServiceBus'
        if cid=='azure.claude.servicebus_premium_namespace_vnet_rules':data[sb['id']+'/networkRuleSets/default']['properties']['virtualNetworkRules']=[]
        if cid=='azure.claude.servicefabric_cluster_encrypt_and_sign':p('service_fabric_cluster')['fabricSettings'][0]['parameters'][0]['value']='Sign'
        if cid=='azure.claude.servicefabric_cluster_entra_auth':p('service_fabric_cluster').pop('azureActiveDirectory')
        if cid=='azure.claude.signalr_service_no_free_tier':signal['sku']={'name':'Free_F1','tier':'Free','capacity':1}
        if cid=='azure.claude.spring_cloud_service_vnet_injection':p('spring_cloud_service')['networkProfile'].pop('serviceRuntimeSubnetId')
        if cid in ('azure.claude.sql_audit_retention_over_90','azure.claude.sql_audit_storage_retention_90'):audit['properties']['retentionDays']=30
        if cid=='azure.claude.sql_database_long_term_retention':
            for key in ('weeklyRetention','monthlyRetention','yearlyRetention'):ltr['properties'][key]='PT0S'
        if cid in ('azure.claude.sql_firewall_no_full_range','azure.claude.sql_firewall_no_internet_or_azure_services'):firewall['properties'].update(startIpAddress='0.0.0.0',endIpAddress='255.255.255.255')
        if cid=='azure.claude.storage_container_no_public_access':container['properties']['publicAccess']='Blob'
        if cid=='azure.claude.storage_encryption_scope_cmk':scope['properties']['source']='Microsoft.Storage'
        if cid=='azure.claude.storage_sync_private_link':p('storage_sync_service')['incomingTrafficPolicy']='AllowAllTraffic'
        if 'private_link' in cid:
            for k in ('servicebus_namespace','signalr_service','ml_workspace','web_pubsub'):
                for c in data[rows[k]['id']+'/privateEndpointConnections']['value']:c['properties']['privateLinkServiceConnectionState']['status']='Rejected'
        if cid in ('azure.claude.stream_analytics_job_logging_enabled','azure.claude2.batch_account_resource_logs'):
            row=stream if cid.startswith('azure.claude.') else batch
            for log in data[row['id']+'/providers/Microsoft.Insights/diagnosticSettings']['value'][0]['properties']['logs']:log['enabled']=False
        if cid=='azure.claude.subscription_diagnostic_setting_exists':data[SCOPE+'/providers/Microsoft.Insights/diagnosticSettings']['value']=[]
        if cid in ('azure.claude.subscription_diagnostic_setting_any_categories','azure.claude.subscription_diagnostic_setting_categories'):diagnostic['properties']['logs'][0]['enabled']=False
        if cid=='azure.claude.vnet_gateway_entra_only':vpn['properties']['vpnClientConfiguration']['vpnAuthenticationTypes']=['AAD','Certificate']
        if cid=='azure.claude.vnet_gateway_no_basic_sku':vpn['properties']['sku']={'name':'Basic','tier':'Basic','capacity':1}
        if cid=='azure.claude.vnet_peering_connected':p('vnet')['virtualNetworkPeerings'][0]['properties']['peeringState']='Disconnected'
        if cid=='azure.claude.waf_policy_bot_protection':p('web_application_firewall_policy')['managedRules']['managedRuleSets']=[]
        if cid=='azure.claude.waf_policy_request_body_inspection':p('web_application_firewall_policy')['policySettings']['requestBodyCheck']=False
        if cid=='azure.claude2.apim_consumption_client_certificate':p('api_management')['enableClientCertificate']=False
        if cid=='azure.claude2.app_service_environment_internal_encryption':p('app_service_environment')['clusterSettings'][0]['value']='false'
        if cid=='azure.claude2.app_service_plan_minimum_sku':plan['sku']={'name':'B1','tier':'Basic','capacity':1}
        if cid=='azure.claude2.application_insights_configured':data[SCOPE+'/providers/Microsoft.Insights/components']['value']=[]
        if cid=='azure.claude2.application_insights_public_access_blocked':p('application_insights')['publicNetworkAccessForQuery']='Enabled'
        if cid=='azure.claude2.application_insights_workspace_based':p('application_insights')['WorkspaceResourceId']=None
        if cid=='azure.claude2.automation_variable_encrypted':variable['properties']['isEncrypted']=False
        if cid=='azure.claude2.batch_account_customer_managed_key':p('batch_account')['encryption']['keySource']='Microsoft.Batch'
        if cid=='azure.claude2.batch_account_managed_identity':batch['identity']={'type':'None'}
        if cid=='azure.claude2.entra_user_mfa_registered':data['/v1.0/reports/authenticationMethods/userRegistrationDetails']['value'][0]['isMfaRegistered']=False
        if cid in ('azure.claude2.vnet_with_app_gateway_ddos_protection','azure.network.ddos_configured'):p('vnet')['enableDdosProtection']=False
        if cid=='azure.network.nic_no_ip_forwarding':p('nic')['enableIPForwarding']=True
        if cid=='azure.gap.arc_kubernetes_cluster_azure_defender_extension_installed':extension['properties']['provisioningState']='Failed'
        if cid=='azure.gap.monitor_log_cluster_encrypted_with_cmk':p('log_analytics_cluster')['keyVaultProperties']=None
        if cid=='azure.gap.monitor_log_cluster_infrastructure_encryption_enabled':p('log_analytics_cluster')['isDoubleEncryptionEnabled']=False
        if cid=='azure.gap.monitor_log_profile_enabled_for_all_categories':profile['properties']['categories']=['Write']
        if cid=='azure.gap.monitor_log_profile_retention_365_days':profile['properties']['retentionPolicy']['days']=30
        if cid.startswith('azure.htbp.') and ('local_auth_disabled' in cid or cid=='azure.htbp.search.api_key_auth_disabled'):
            for row in rows.values():
                if 'disableLocalAuth' in row['properties']:row['properties']['disableLocalAuth']=False
        if cid=='azure.htbp.batch.shared_key_auth_disabled':p('batch_account')['allowedAuthenticationModes']=['SharedKey','AAD']
        if cid=='azure.htbp.entra.temporary_access_pass_one_time':data['/v1.0/policies/authenticationMethodsPolicy']['authenticationMethodConfigurations'][0]['isUsableOnce']=False
        if cid=='azure.htbp.logicapp.request_trigger_caller_restricted':p('logic_app_workflow').pop('accessControl')
        if cid=='azure.other.access_analysis_coverage':pricing['properties']['pricingTier']='Free'
        if cid=='azure.other.entra_app_secret_age_90':data['/v1.0/applications']['value'][0]['passwordCredentials'][0]['startDateTime']=(now-timedelta(days=100)).isoformat()
    return data

class Wire:
    def __init__(self,data,mode):self.data=data;self.mode=mode;self.calls=[]
    def open(self,request,timeout):
        u=urlsplit(request.full_url);q=parse_qs(u.query)
        def require(ok):
            if not ok:pytest.fail('HTTP method/host/path/body contract violated: '+request.full_url)
        require(u.scheme=='https' and u.netloc in ('management.azure.com','graph.microsoft.com') and timeout==20)
        require(request.get_header('Authorization')=='Bearer offline-native')
        if u.path=='/providers/Microsoft.ResourceGraph/resources':
            require(request.get_method()=='POST' and u.netloc=='management.azure.com')
            b=json.loads(request.data);require(set(b)=={'subscriptions','query','options'} and b['subscriptions']==[SUB])
            require(b['query'] in ('Resources | project id, type, name, location, tags, identity, properties, subscriptionId, resourceGroup | order by id asc',
                "resourcecontainers | where type =~ 'microsoft.resources/subscriptions' | project id, properties | order by id asc"))
            self.calls.append({'method':'POST','host':u.netloc,'path':u.path,'query':q,'body':b})
            raise azure.AzureReadError('optional_resource_graph_denied',403)
        require(request.get_method()=='GET' and request.data is None)
        if u.netloc=='management.azure.com':require(bool(q.get('api-version')))
        self.calls.append({'method':'GET','host':u.netloc,'path':u.path,'query':q,'body':None})
        ancillary=empty_inventory_versions(SCOPE)
        if u.path in ancillary:require(matches_empty_inventory_query(SCOPE,u.path,q))
        if u.path==RG+'/providers/Microsoft.MachineLearningServices/workspaces/native/computes':
            require(q in ({'api-version':['2024-04-01']},{'api-version':['2024-04-01'],'$skiptoken':['next']}))
        if u.path not in self.data:pytest.fail('Unexpected native HTTP path: '+u.path)
        value=self.data[u.path]
        if isinstance(value,BaseException):raise value
        if self.mode=='denied':raise azure.AzureReadError('native_read_not_authorized',403)
        body=deepcopy(value)
        if self.mode=='empty' and 'value'in body:body['value']=[]
        if self.mode=='partial' and 'value'in body and u.path!=SCOPE+'/resources':
            if '$skiptoken'in q:raise azure.AzureReadError('continuation_not_authorized',403)
            body['@odata.nextLink' if u.netloc=='graph.microsoft.com' else 'nextLink']=request.full_url+'&$skiptoken=next'
        if self.mode in ('omitted','malformed','wrong_type','foreign'):
            rows=body.get('value',[body])
            for row in rows:
                if not isinstance(row,dict):continue
                if self.mode=='omitted':
                    if u.netloc=='management.azure.com':
                        for key in list(row):
                            if key not in ('id','name','type','location'):row.pop(key)
                    else:
                        for key in list(row):
                            if key!='id':row.pop(key)
                if self.mode=='malformed':
                    if u.netloc=='management.azure.com':row.update(properties=[],sku=[],identity=[])
                    else:
                        for key in list(row):
                            if key!='id':row[key]=42
                if self.mode=='wrong_type':
                    if u.netloc=='management.azure.com' and '/providers/'in row.get('id',''):row['type']='Microsoft.Unrelated/resources'
                    elif u.netloc=='graph.microsoft.com':
                        if 'isMfaRegistered' in row:row['isMfaRegistered']='true'
                        if 'authenticationMethodConfigurations' in row:row['authenticationMethodConfigurations']='invalid'
                        if 'passwordCredentials' in row:row['passwordCredentials']='invalid'
                if self.mode=='foreign' and isinstance(row.get('id'),str):row['id']=row['id'].replace(SUB,OTHER) if u.netloc=='management.azure.com' else row['id']+'invalid'
        response=io.BytesIO(json.dumps(body).encode())
        response.status=200
        return response

def capture(monkeypatch,cid,branch='positive',data=None):
    data=native(cid,branch=='opposite') if data is None else data
    wire=Wire(data,'normal' if branch in ('positive','opposite') else branch)
    monkeypatch.setattr(azure,'build_opener',lambda *a:wire)
    transport=object.__new__(REAL_TRANSPORT);transport.tenant=transport.verified_tenant=TENANT;transport.owned=False;transport.credential=None
    transport.token=lambda audience:'offline-native' if audience in (azure.ARM,azure.GRAPH) else pytest.fail('unexpected credential audience')
    monkeypatch.setattr(azure,'AzureTransportExposure',lambda auth:transport)
    options={'retries':0,'concurrency':1}
    if cid=='azure.claude.servicebus_namespace_private_link':
        # This fixture proves the selected native setting, not the separate
        # full Network view. Keep unrelated inventory responses unimplemented.
        options['inventories']=['servicebus_namespace']
        plan=archived.plan_collection({'connector':{'provider':'azure','scopes':[SUB],
            'auth':{'tenant_id':TENANT},'options':options},'checks':[cid]})
        assert plan==['servicebus_namespace']
    snapshot=archived.collect_snapshot({'connector':{'provider':'azure','scopes':[SUB],'auth':{'tenant_id':TENANT},'options':options},'checks':[cid]})
    findings=archived.evaluate_snapshot(snapshot,checks=[cid])['findings']
    serial={k:({'error':str(v)} if isinstance(v,BaseException) else v)for k,v in data.items()}
    digest=hashlib.sha256(json.dumps(serial,sort_keys=True).encode()).hexdigest()
    node=os.environ.get('PYTEST_CURRENT_TEST','').split(' (')[0]
    entry={'id':cid,'branch':branch,'testnode':node,'native_sha256':digest,'statuses':sorted({f['status']for f in findings}),'requests':wire.calls,'findings':findings}
    RECEIPTS.append(entry)
    if folder:=os.environ.get('AZURE_REMAINING2_RECEIPTS'):
        Path(folder).mkdir(parents=True,exist_ok=True)
        path=Path(folder,cid+'.'+branch+'.'+digest[:12]+'.snapshot.json');path.write_text(json.dumps(snapshot,separators=(',',':'))+'\n');entry['snapshot']=str(path)
    assert wire.calls
    return snapshot,findings,wire

@pytest.mark.parametrize('cid',ROSTER)
@pytest.mark.parametrize('branch',['positive','opposite','omitted','denied','partial','empty','malformed','foreign','wrong_type'])
def test_native_contract(monkeypatch,cid,branch):
    _,findings,_=capture(monkeypatch,cid,branch)
    states={f['status']for f in findings}
    if branch=='positive':assert states==({'UNKNOWN'} if cid in UNPRODUCED else {'PASS'}),(cid,branch,findings)
    elif branch=='opposite':assert states==({'UNKNOWN'} if cid=='azure.gap.stream_analytics_job_encrypted_with_cmk' else {'FAIL'}),(cid,branch,findings)
    elif branch=='malformed' and cid in {'azure.claude.subscription_diagnostic_setting_exists','azure.claude2.application_insights_configured'}:assert states=={'PASS'}
    elif branch in ('malformed','foreign','wrong_type'):assert 'PASS'not in states,(cid,branch,findings)
    elif branch=='denied':assert states<={'DENIED','UNKNOWN'},(cid,branch,findings)
    elif branch=='omitted' and cid in {'azure.claude.subscription_diagnostic_setting_exists','azure.claude2.application_insights_configured'}:assert states=={'PASS'}
    elif branch=='omitted':assert 'PASS'not in states,(cid,branch,findings)
    elif branch in ('empty','partial') and cid=='azure.htbp.entra.temporary_access_pass_one_time':assert states=={'PASS'} # singleton GET has no collection continuation
    elif branch=='empty' and cid=='azure.other.entra_app_secret_age_90':assert states=={'PASS'} # complete zero-app inventory
    elif branch=='empty':assert states<={'EMPTY','NOT_APPLICABLE','UNKNOWN','FAIL','DENIED'},(cid,branch,findings)
    else:assert 'UNKNOWN'in states or states<={'DENIED','FAIL','EMPTY','NOT_APPLICABLE'},(cid,branch,findings)

@pytest.mark.parametrize('ranges,expected',[
    ([], 'PASS'), # native Only other Logic Apps option
    ([{'addressRange':'0.0.0.0/0'}],'FAIL'),
    ([{'addressRange':'0.0.0.0-255.255.255.255'}],'FAIL'),
    ([{'addressRange':'0.0.0.0/1'},{'addressRange':'128.0.0.0/1'}],'FAIL'),
    ([{'addressRange':'203.0.113.10-203.0.113.20'}],'PASS'),
    ([{'addressRange':'not-an-address'}],'UNKNOWN'),
    ([{}],'UNKNOWN'),
    ([{'addressRange':None}],'UNKNOWN'),
])
def test_logic_caller_union(monkeypatch,ranges,expected):
    cid='azure.htbp.logicapp.request_trigger_caller_restricted';data=native(cid)
    rid=RG+'/providers/Microsoft.Logic/workflows/native'
    data[rid]['properties']['accessControl']['triggers']['allowedCallerIpAddresses']=ranges
    _,findings,_=capture(monkeypatch,cid,'logic-union-'+hashlib.sha256(str(ranges).encode()).hexdigest()[:8],data)
    assert {f['status'] for f in findings}=={expected}

@pytest.mark.parametrize('case,expected',[('other_parameter','FAIL'),('duplicate','UNKNOWN'),('aad_empty','UNKNOWN')])
def test_fabric_exact_fields(monkeypatch,case,expected):
    cid='azure.claude.servicefabric_cluster_'+('entra_auth' if case=='aad_empty' else 'encrypt_and_sign')
    data=native(cid);rid=RG+'/providers/Microsoft.ServiceFabric/clusters/native';p=data[rid]['properties']
    if case=='aad_empty':p['azureActiveDirectory']={}
    else:
        params=p['fabricSettings'][0]['parameters']
        if case=='other_parameter':
            params[0]['value']='Sign';params.append({'name':'SettingsX509StoreName','value':'EncryptAndSign'})
        else:params.append({'name':'ClusterProtectionLevel','value':'Sign'})
    _,findings,_=capture(monkeypatch,cid,'fabric-'+case,data)
    assert {f['status'] for f in findings}=={expected}

@pytest.mark.parametrize('cid,k',[('azure.claude.servicebus_namespace_private_link','Microsoft.ServiceBus/namespaces'),
    ('azure.claude.signalr_service_private_link','Microsoft.SignalRService/SignalR'),
    ('azure.claude.storage_sync_private_link','Microsoft.StorageSync/storageSyncServices'),
    ('azure.gap.machine_learning_workspace_private_link_used','Microsoft.MachineLearningServices/workspaces'),
    ('azure.gap.web_pub_sub_private_link_used','Microsoft.SignalRService/WebPubSub')])
def test_private_endpoint_child_identity(monkeypatch,cid,k):
    data=native(cid);rid=RG+'/providers/'+azure.ENDPOINTS[REGISTRY[cid].kind][0]+'/native';rows=data[rid+'/privateEndpointConnections']['value']
    rows[0]['id']=rows[0]['id'].replace(SUB,OTHER)
    _,findings,_=capture(monkeypatch,cid,'foreign-child',data)
    assert 'PASS' not in {f['status'] for f in findings}

@pytest.mark.parametrize('cid', ['azure.claude.servicebus_namespace_private_link','azure.claude.signalr_service_private_link','azure.claude.storage_sync_private_link'])
@pytest.mark.parametrize('edge,expected',[('same_duplicate','PASS'),('conflicting_duplicate','UNKNOWN'),('missing_id','UNKNOWN'),('wrong_child_type','UNKNOWN'),('empty_children','FAIL'),('pending','FAIL')])
def test_private_link_native_guard(monkeypatch,cid,edge,expected):
    data=native(cid);rid=RG+'/providers/'+azure.ENDPOINTS[REGISTRY[cid].kind][0]+'/native'
    children=data[rid]['properties']['privateEndpointConnections']
    if edge in ('same_duplicate','conflicting_duplicate'):
        children.append(deepcopy(children[0]))
        if edge=='conflicting_duplicate':children[1]['properties']['privateLinkServiceConnectionState']['status']='Rejected'
    elif edge=='missing_id':children[0].pop('id')
    elif edge=='wrong_child_type':children[0]['type']='Microsoft.Unrelated/resources'
    elif edge=='empty_children':children.clear()
    elif edge=='pending':children[0]['properties']['privateLinkServiceConnectionState']['status']='Pending'
    _,findings,_=capture(monkeypatch,cid,'private-'+edge,data)
    assert {f['status'] for f in findings}=={expected}

@pytest.mark.parametrize('cid,days,expected',[
    ('azure.claude.sql_audit_retention_over_90',0,'PASS'),
    ('azure.claude.sql_audit_retention_over_90',90,'FAIL'),
    ('azure.claude.sql_audit_retention_over_90',91,'PASS'),
    ('azure.claude.sql_audit_storage_retention_90',0,'PASS'),
    ('azure.claude.sql_audit_storage_retention_90',90,'PASS'),
    ('azure.claude.sql_audit_storage_retention_90',89,'FAIL'),
])
def test_native_audit_boundary(monkeypatch,cid,days,expected):
    data=native(cid);data[SQL+'/auditingSettings/default']['properties']['retentionDays']=days
    _,findings,_=capture(monkeypatch,cid,'audit-days-'+str(days),data)
    assert {f['status'] for f in findings}=={expected}

@pytest.mark.parametrize('edge',['duplicate','foreign_child','dot_segment'])
@pytest.mark.parametrize('cid',['azure.claude.vnet_gateway_entra_only','azure.claude.vnet_gateway_no_basic_sku'])
def test_gateway_native_join_edges(monkeypatch,cid,edge):
    data=native(cid);rows=data[RG+'/providers/Microsoft.Network/virtualNetworkGateways']['value']
    if edge=='duplicate':rows.append(deepcopy(rows[0]))
    elif edge=='foreign_child':rows[0]['id']=rows[0]['id'].replace('/resourceGroups/review/','/resourceGroups/foreign/')
    else:rows[0]['id']=rows[0]['id'].rsplit('/',1)[0]+'/..'
    _,findings,_=capture(monkeypatch,cid,'gateway-'+edge,data)
    assert 'PASS' not in {f['status'] for f in findings}

@pytest.mark.parametrize('cid',['azure.claude.subscription_diagnostic_setting_exists','azure.claude.subscription_diagnostic_setting_categories','azure.claude.subscription_diagnostic_setting_any_categories'])
def test_subscription_diagnostic_duplicate(monkeypatch,cid):
    data=native(cid);rows=data[SCOPE+'/providers/Microsoft.Insights/diagnosticSettings']['value'];rows.append(deepcopy(rows[0]))
    _,findings,_=capture(monkeypatch,cid,'duplicate-diagnostic',data)
    assert 'PASS' not in {f['status'] for f in findings}
