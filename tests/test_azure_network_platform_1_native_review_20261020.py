"""Independent finite native Azure HTTP fixtures, with live network/auth blocked."""
import json
import ast
import gzip
import hashlib
import os
import socket
from pathlib import Path
import pytest
from tests.azure_native_inventory_routes_20261020 import empty_inventory_versions,matches_empty_inventory_query
from peaso.collectors import azure
from peaso.collectors import azure_identity_enforcement_review_20261020 as identity_native

SUB='11111111-1111-1111-1111-111111111111'
TENANT='22222222-2222-2222-2222-222222222222'
SCOPE='/subscriptions/'+SUB
RECEIPTS=[]

@pytest.fixture(scope='session',autouse=True)
def write_native_receipts():
    yield
    folder=os.environ.get('AZURE_NETWORK_REVIEW_RECEIPTS')
    if folder:
        Path(folder).mkdir(parents=True,exist_ok=True)
        Path(folder,'native-cases.json').write_text(json.dumps(RECEIPTS,indent=2)+'\n')

@pytest.fixture(autouse=True)
def offline(monkeypatch):
    def blocked(*args,**kwargs):pytest.fail('socket/DNS/auth discovery is forbidden')
    for attr in ('connect','connect_ex'):monkeypatch.setattr(socket.socket,attr,blocked)
    for attr in ('getaddrinfo','gethostbyname','gethostbyname_ex','create_connection'):monkeypatch.setattr(socket,attr,blocked)
    monkeypatch.setattr(azure,'credential_for',blocked)
    monkeypatch.setattr(azure,'urlopen',blocked)
    monkeypatch.setattr(azure.time,'sleep',lambda seconds:None)

_HISTORICAL_TRANSPORT=azure.AzureTransport
_EXPOSURE_TRANSPORT=azure.AzureTransportExposure

@pytest.fixture(autouse=True)
def exposure_transport_seam(monkeypatch):
    # collect() constructs AzureTransportExposure; keep this module's
    # AzureTransport replacements (fakes and guards) authoritative for it.
    def construct(*args,**kwargs):
        current=azure.AzureTransport
        return (_EXPOSURE_TRANSPORT if current is _HISTORICAL_TRANSPORT else current)(*args,**kwargs)
    monkeypatch.setattr(azure,'AzureTransportExposure',construct)

@pytest.mark.parametrize('kind',['vnet',identity_native.KIND])
@pytest.mark.parametrize('mode',['constructor_denied','hosted_missing','hosted_ambient','hosted_file'])
def test_early_auth_rejection_never_invokes_native_tail(monkeypatch,kind,mode):
    def rejected(*args,**kwargs):raise azure.AzureReadError('explicit_credential_rejected',401)
    def unexpected(*args,**kwargs):pytest.fail('rejected authentication must not reach transport/native producer')
    monkeypatch.setattr(identity_native,'collect',unexpected)
    monkeypatch.setattr(azure,'AzureTransport',rejected if mode=='constructor_denied' else unexpected)
    auth={'tenant_id':TENANT,'client_secret':'AUTH_CANARY_NEVER_RETAIN'};options={'retries':0}
    if mode=='hosted_missing':auth={'tenant_id':TENANT};options['hosted']=True
    if mode=='hosted_ambient':auth['method']='managed-identity';options['hosted']=True
    if mode=='hosted_file':auth['certificate_path']='/must-not-read.pem';options['hosted']=True
    result=azure.collect({'scopes':[SUB],'auth':auth,'options':options},[kind])
    assert result['collections']
    assert {c['status'] for c in result['collections']}==({'denied'} if mode=='constructor_denied' else {'malformed'})
    assert 'AUTH_CANARY_NEVER_RETAIN' not in json.dumps(result)

ROSTER=['azure.aks.api_server_restricted', 'azure.aks.auto_upgrade', 'azure.aks.azure_rbac', 'azure.aks.defender_monitoring', 'azure.aks.network_policy', 'azure.aks.no_local_accounts', 'azure.aks.private_cluster', 'azure.aks.rbac', 'azure.claude.aks_authorized_ip_ranges', 'azure.claude.aks_azure_policy_addon', 'azure.claude.aks_container_insights_logging', 'azure.claude.aks_disk_encryption_set', 'azure.claude.aks_encryption_at_host', 'azure.claude.aks_http_application_routing_disabled', 'azure.claude.aks_max_pods_at_least_50', 'azure.claude.aks_network_plugin_azure', 'azure.claude.aks_network_policy_configured', 'azure.claude.aks_node_public_ip_disabled', 'azure.claude.aks_paid_sku_tier', 'azure.claude.aks_secret_store_rotation', 'azure.claude.aks_version_not_cve_2019_9946', 'azure.claude.flow_log_enabled', 'azure.claude.flow_log_traffic_analytics', 'azure.claude.gateway_subnet_no_nsg', 'azure.claude.network_watcher_flow_logs_retention_90', 'azure.claude.network_watcher_flow_logs_traffic_analytics', 'azure.claude.subnet_nsg_associated', 'azure.claude2.aks_azure_monitor_metrics_enabled', 'azure.claude2.aks_private_cluster_nodes_without_public_ip', 'azure.claude2.app_gateway_http2_enabled', 'azure.claude2.app_gateway_min_tls_12', 'azure.claude2.app_gateway_waf_enabled', 'azure.claude2.app_gateway_waf_mode_specified', 'azure.claude2.nsg_flow_logs_to_log_analytics', 'azure.claude2.vnet_flow_log_retention_90', 'azure.claude2.vnet_flow_logs_to_log_analytics', 'azure.network.load_balancer_standard', 'azure.network.public_ip_standard', 'azure_aks_cluster_10_2_1_1_17_885658f', 'azure_aks_cluster_7_2_1_6_93c4fab', 'azure_aks_cluster_aks_cluster_rbac_enabled_db12524', 'azure_application_gateway_app_ensure_http_is_redirected_to_https_1099ad7', 'azure_cdn_profile_10_3_4_1_4e40487', 'azure_cdn_profile_1_2_8_5_ed953a0']

from copy import deepcopy
from urllib.parse import urlsplit,parse_qs
import io
from peaso import engine
from peaso.checks import CHECKS
REGISTRY={c.id:c for c in CHECKS}
REAL_TRANSPORT=azure.AzureTransport
OTHER='99999999-9999-9999-9999-999999999999'
RG=SCOPE+'/resourceGroups/review'
AKS=RG+'/providers/Microsoft.ContainerService/managedClusters/native'
VNET=RG+'/providers/Microsoft.Network/virtualNetworks/native'
SUBNET=VNET+'/subnets/workload'
NSG=RG+'/providers/Microsoft.Network/networkSecurityGroups/native'
WATCHER=RG+'/providers/Microsoft.Network/networkWatchers/native'
FLOW=WATCHER+'/flowLogs/native'
WORKSPACE=RG+'/providers/Microsoft.OperationalInsights/workspaces/native'
AGW=RG+'/providers/Microsoft.Network/applicationGateways/native'
WAF=RG+'/providers/Microsoft.Network/ApplicationGatewayWebApplicationFirewallPolicies/native'
CDN=RG+'/providers/Microsoft.Cdn/profiles/native'
POOL=CDN+'/originGroups/native'
ORIGIN=POOL+'/origins/native'
ENDPOINT=CDN+'/afdEndpoints/native'
ROUTE=ENDPOINT+'/routes/native'
DOMAIN=CDN+'/customDomains/native'
ACCOUNT=RG+'/providers/Microsoft.Storage/storageAccounts/reviewnative'
CONTAINER=ACCOUNT+'/blobServices/default/containers/content'
PRINCIPAL='33333333-3333-3333-3333-333333333333'
ASSIGN='88888888-8888-8888-8888-888888888888'
DATA_READER='2a2b9908-6ea1-4ae2-8e65-a410df84e7d1'


def resource(rid,typ,props,**extra):
    return {'id':rid,'name':rid.rsplit('/',1)[-1],'type':typ,'location':'eastus','properties':props,**extra}


def base_native(cid,opposite=False):
    aks=resource(AKS,'Microsoft.ContainerService/managedClusters',{
        'provisioningState':'Succeeded','kubernetesVersion':'1.33.1','enableRBAC':True,'disableLocalAccounts':True,
        'aadProfile':{'managed':True,'enableAzureRBAC':True,'tenantID':TENANT},
        'apiServerAccessProfile':{'enablePrivateCluster':True,'enablePrivateClusterPublicFQDN':False},
        'privateFQDN':'native-123.privatelink.eastus.azmk8s.io',
        'autoUpgradeProfile':{'upgradeChannel':'stable'},
        'securityProfile':{'defender':{'securityMonitoring':{'enabled':True},'logAnalyticsWorkspaceResourceId':WORKSPACE}},
        'networkProfile':{'networkPlugin':'azure','networkPolicy':'calico','networkDataplane':'azure','loadBalancerSku':'standard'},
        'agentPoolProfiles':[{'name':'systempool','mode':'System','count':3,'vmSize':'Standard_DS2_v2','osType':'Linux',
          'type':'VirtualMachineScaleSets','enableEncryptionAtHost':True,'enableNodePublicIP':False,'maxPods':110}],
        'diskEncryptionSetID':RG+'/providers/Microsoft.Compute/diskEncryptionSets/native',
        'addonProfiles':{'azurepolicy':{'enabled':True},'omsagent':{'enabled':True,'config':{'logAnalyticsWorkspaceResourceID':WORKSPACE}},
          'httpApplicationRouting':{'enabled':False},'azureKeyvaultSecretsProvider':{'enabled':True,'config':{'enableSecretRotation':'true','rotationPollInterval':'2m'}}},
        'azureMonitorProfile':{'metrics':{'enabled':True}}},sku={'name':'Base','tier':'Standard'})
    if cid in ('azure.aks.api_server_restricted','azure.claude.aks_authorized_ip_ranges'):
        aks['properties']['apiServerAccessProfile']={'enablePrivateCluster':False,'authorizedIPRanges':['203.0.113.0/24']};aks['properties'].pop('privateFQDN')
    vnet=resource(VNET,'Microsoft.Network/virtualNetworks',{'provisioningState':'Succeeded','addressSpace':{'addressPrefixes':['10.0.0.0/16']},
       'subnets':[resource(SUBNET,'Microsoft.Network/virtualNetworks/subnets',{'provisioningState':'Succeeded','addressPrefix':'10.0.1.0/24','networkSecurityGroup':{'id':NSG}})],'virtualNetworkPeerings':[]})
    if cid=='azure.claude.gateway_subnet_no_nsg':
        child=vnet['properties']['subnets'][0];child.update(id=VNET+'/subnets/GatewaySubnet',name='GatewaySubnet');child['properties'].pop('networkSecurityGroup')
    watcher=resource(WATCHER,'Microsoft.Network/networkWatchers',{'provisioningState':'Succeeded'})
    flow=resource(FLOW,'Microsoft.Network/networkWatchers/flowLogs',{'provisioningState':'Succeeded','enabled':True,'targetResourceId':VNET,
       'storageId':ACCOUNT,'format':{'type':'JSON','version':2},'retentionPolicy':{'enabled':True,'days':90},
       'flowAnalyticsConfiguration':{'networkWatcherFlowAnalyticsConfiguration':{'enabled':True,'workspaceId':PRINCIPAL,
          'workspaceResourceId':WORKSPACE,'workspaceRegion':'eastus','trafficAnalyticsInterval':60}}})
    waf=resource(WAF,'Microsoft.Network/ApplicationGatewayWebApplicationFirewallPolicies',{'provisioningState':'Succeeded',
       'policySettings':{'state':'Enabled','mode':'Prevention'},'managedRules':{'managedRuleSets':[{'ruleSetType':'OWASP','ruleSetVersion':'3.2'}]}})
    agw=resource(AGW,'Microsoft.Network/applicationGateways',{'provisioningState':'Succeeded','enableHttp2':True,
       'sku':{'name':'WAF_v2','tier':'WAF_v2','capacity':2},'sslPolicy':{'policyType':'Predefined','policyName':'AppGwSslPolicy20220101'},
       'firewallPolicy':{'id':WAF},'webApplicationFirewallConfiguration':None,
       'httpListeners':[resource(AGW+'/httpListeners/http','Microsoft.Network/applicationGateways/httpListeners',{'protocol':'Http'}),
          resource(AGW+'/httpListeners/https','Microsoft.Network/applicationGateways/httpListeners',{'protocol':'Https'})],
       'requestRoutingRules':[resource(AGW+'/requestRoutingRules/redirect','Microsoft.Network/applicationGateways/requestRoutingRules',{
          'ruleType':'Basic','httpListener':{'id':AGW+'/httpListeners/http'},'redirectConfiguration':{'id':AGW+'/redirectConfigurations/https'}})],
       'redirectConfigurations':[resource(AGW+'/redirectConfigurations/https','Microsoft.Network/applicationGateways/redirectConfigurations',{
          'redirectType':'Permanent','targetListener':{'id':AGW+'/httpListeners/https'},'includePath':True,'includeQueryString':True})],
       'urlPathMaps':[]})
    cdn=resource(CDN,'Microsoft.Cdn/profiles',{'provisioningState':'Succeeded'},sku={'name':'Premium_AzureFrontDoor'},
        identity={'type':'SystemAssigned','principalId':PRINCIPAL,'tenantId':TENANT})
    domain=resource(DOMAIN,'Microsoft.Cdn/profiles/customDomains',{'hostName':'native.example.test','provisioningState':'Succeeded',
       'deploymentStatus':'Succeeded','domainValidationState':'Approved','tlsSettings':{'certificateType':'CustomerCertificate','minimumTlsVersion':'TLS12'}})
    group=resource(POOL,'Microsoft.Cdn/profiles/originGroups',{'provisioningState':'Succeeded','healthProbeSettings':{'probeProtocol':'Https'},
       'authentication':{'type':'SystemAssignedIdentity','scope':'https://storage.azure.com/.default','tokenDestinationHeader':'Authorization'}})
    origin=resource(ORIGIN,'Microsoft.Cdn/profiles/originGroups/origins',{'hostName':'reviewnative.blob.core.windows.net','enabledState':'Enabled','sharedPrivateLinkResource':None,'provisioningState':'Succeeded'})
    endpoint=resource(ENDPOINT,'Microsoft.Cdn/profiles/afdEndpoints',{'hostName':'native.azurefd.net','enabledState':'Enabled','provisioningState':'Succeeded','deploymentStatus':'Succeeded'})
    route=resource(ROUTE,'Microsoft.Cdn/profiles/afdEndpoints/routes',{'originGroup':{'id':POOL},'originPath':'/content',
       'supportedProtocols':['Https'],'forwardingProtocol':'HttpsOnly','httpsRedirect':'Enabled','enabledState':'Enabled',
       'patternsToMatch':['/*'],'ruleSets':[],'customDomains':[{'id':DOMAIN}],'linkToDefaultDomain':'Disabled','provisioningState':'Succeeded','deploymentStatus':'Succeeded'})
    role=resource(CONTAINER+'/providers/Microsoft.Authorization/roleAssignments/'+ASSIGN,'Microsoft.Authorization/roleAssignments',{
       'principalId':PRINCIPAL,'principalType':'ServicePrincipal','scope':CONTAINER,
       'roleDefinitionId':SCOPE+'/providers/Microsoft.Authorization/roleDefinitions/'+DATA_READER,'condition':None})
    data={'/tenants':{'value':[{'id':'/tenants/'+TENANT,'tenantId':TENANT,'tenantCategory':'Home'}]},
      SCOPE:{'id':SCOPE,'subscriptionId':SUB,'tenantId':TENANT,'state':'Enabled'},
      SCOPE+'/providers/Microsoft.ContainerService/managedClusters':{'value':[aks]},AKS:aks,AKS+'/managedNamespaces':{'value':[]},
      SCOPE+'/providers/Microsoft.Network/virtualNetworks':{'value':[vnet]},VNET:vnet,
      SCOPE+'/providers/Microsoft.Network/networkSecurityGroups':{'value':[resource(NSG,'Microsoft.Network/networkSecurityGroups',{'provisioningState':'Succeeded','securityRules':[],'defaultSecurityRules':[],'subnets':[{'id':SUBNET}],'networkInterfaces':[]})]},
      SCOPE+'/providers/Microsoft.Network/networkWatchers':{'value':[watcher]},WATCHER:watcher,WATCHER+'/flowLogs':{'value':[flow]},FLOW:flow,
      SCOPE+'/providers/Microsoft.Network/applicationGateways':{'value':[agw]},AGW:agw,
      SCOPE+'/providers/Microsoft.Network/ApplicationGatewayWebApplicationFirewallPolicies':{'value':[waf]},WAF:waf,
      SCOPE+'/providers/Microsoft.Network/loadBalancers':{'value':[resource(RG+'/providers/Microsoft.Network/loadBalancers/native','Microsoft.Network/loadBalancers',{'provisioningState':'Succeeded'},sku={'name':'Standard','tier':'Regional'})]},
      SCOPE+'/providers/Microsoft.Network/publicIPAddresses':{'value':[resource(RG+'/providers/Microsoft.Network/publicIPAddresses/native','Microsoft.Network/publicIPAddresses',{'provisioningState':'Succeeded','publicIPAddressVersion':'IPv4','publicIPAllocationMethod':'Static'},sku={'name':'Standard','tier':'Regional'})]},
      SCOPE+'/providers/Microsoft.Cdn/profiles':{'value':[cdn]},CDN:cdn,
      CDN+'/customDomains':{'value':[domain]},DOMAIN:domain,CDN+'/afdEndpoints':{'value':[endpoint]},ENDPOINT:endpoint,
      ENDPOINT+'/routes':{'value':[route]},ROUTE:route,CDN+'/securityPolicies':{'value':[]},
      CDN+'/originGroups':{'value':[group]},POOL:group,POOL+'/origins':{'value':[origin]},ORIGIN:origin,
      CDN+'/providers/Microsoft.Insights/diagnosticSettingsCategories':{'value':[]},
      CDN+'/providers/Microsoft.Insights/diagnosticSettings':{'value':[]},
      SCOPE+'/providers/Microsoft.Storage/storageAccounts':{'value':[resource(ACCOUNT,'Microsoft.Storage/storageAccounts',{'provisioningState':'Succeeded','primaryEndpoints':{'blob':'https://reviewnative.blob.core.windows.net/'}})]},
      CONTAINER:resource(CONTAINER,'Microsoft.Storage/storageAccounts/blobServices/containers',{'publicAccess':'None','provisioningState':'Succeeded'}),
      CONTAINER+'/providers/Microsoft.Authorization/denyAssignments':{'value':[]},
      CONTAINER+'/providers/Microsoft.Authorization/roleAssignments':{'value':[role]},
      SCOPE+'/providers/Microsoft.Authorization/roleDefinitions/'+DATA_READER:resource(SCOPE+'/providers/Microsoft.Authorization/roleDefinitions/'+DATA_READER,'Microsoft.Authorization/roleDefinitions',{
         'type':'BuiltInRole','permissions':[{'actions':[],'notActions':[],'dataActions':['Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read'],'notDataActions':[]}]})}
    data[NSG]=data[SCOPE+'/providers/Microsoft.Network/networkSecurityGroups']['value'][0]
    for child in vnet['properties']['subnets']:data[child['id']]=child
    for value in list(data.values()):
        if isinstance(value,dict) and isinstance(value.get('value'),list):
            for row in value['value']:
                if isinstance(row,dict) and isinstance(row.get('id'),str) and '/providers/' in row['id']:
                    data.setdefault(row['id'],row)
    parent_types={'Microsoft.ContainerService/managedClusters','Microsoft.Network/virtualNetworks','Microsoft.Network/networkSecurityGroups','Microsoft.Network/networkWatchers','Microsoft.Network/applicationGateways','Microsoft.Network/ApplicationGatewayWebApplicationFirewallPolicies','Microsoft.Network/loadBalancers','Microsoft.Network/publicIPAddresses','Microsoft.Cdn/profiles','Microsoft.Storage/storageAccounts'}
    data[SCOPE+'/resources']={'value':[{k:r[k] for k in ('id','name','type','location') if k in r} for r in list(data.values()) if isinstance(r,dict) and r.get('type') in parent_types]}
    for value in list(data.values()):
        if isinstance(value,dict) and isinstance(value.get('id'),str) and '/providers/' in value['id']:
            data.setdefault(value['id']+'/providers/Microsoft.Insights/diagnosticSettings',{'value':[]})
    if cid=='azure.claude.aks_network_policy_configured':
        for path in [SCOPE+'/resourcegroups',SCOPE+'/providers/Microsoft.Compute/virtualMachines',SCOPE+'/providers/Microsoft.Kubernetes/connectedClusters',
            SCOPE+'/providers/Microsoft.Network/networkInterfaces',SCOPE+'/providers/Microsoft.Network/natGateways',
            SCOPE+'/providers/Microsoft.Network/privateEndpoints',SCOPE+'/providers/Microsoft.Network/routeTables',
            SCOPE+'/providers/Microsoft.Network/firewallPolicies',SCOPE+'/providers/Microsoft.Network/locations/eastus/serviceTags',SCOPE+'/providers/Microsoft.Network/locations/westcentralus/serviceTags']:
            data[path]=azure.AzureReadError('auxiliary_inventory_not_authorized',403)
    for path in empty_inventory_versions(SCOPE):
        data.setdefault(path,{'value':[]})
    # No DiagnosticSettings_List rows on the four native storage services.
    for service in ('blobServices','fileServices','queueServices','tableServices'):
        data.setdefault(ACCOUNT+'/'+service+'/default/providers/Microsoft.Insights/diagnosticSettings',{'value':[]})
    # The existing native container DTO is also returned by its parent LIST.
    data.setdefault(ACCOUNT+'/blobServices/default/containers',{'value':[data[CONTAINER]]})
    data.setdefault(ACCOUNT+'/fileServices/default/shares',{'value':[]})
    # These native child LISTs carry no encryption scopes, local users or
    # Event Grid subscriptions in the independent account fixture.
    for suffix in ('encryptionScopes','localUsers','providers/Microsoft.EventGrid/eventSubscriptions'):
        data.setdefault(ACCOUNT+'/'+suffix,{'value':[]})
    # A denied/partial subscription index makes the collector enumerate its
    # finite declared ARM parent LIST endpoints. Unconfigured services are
    # explicitly denied; unknown paths and every detail URL still fail below.
    for endpoint,version in azure.ENDPOINTS.values():
        path=SCOPE+('/'if endpoint=='resourcegroups'else'/providers/')+endpoint
        data.setdefault(path,azure.AzureReadError('auxiliary_parent_inventory_not_authorized',403))
    for owner in (SCOPE,RG,ACCOUNT):
        data.setdefault(owner+'/providers/Microsoft.Authorization/locks',azure.AzureReadError('auxiliary_lock_inventory_not_authorized',403))
    if opposite:opposite_native(cid,data)
    return data


def opposite_native(cid,d):
    p=d[AKS]['properties']
    fields={'azure.aks.azure_rbac':('aadProfile','enableAzureRBAC'),'azure.aks.defender_monitoring':('securityProfile','defender','securityMonitoring','enabled'),
      'azure.aks.no_local_accounts':('disableLocalAccounts',),'azure.aks.private_cluster':('apiServerAccessProfile','enablePrivateCluster'),'azure.aks.rbac':('enableRBAC',),
      'azure.claude2.aks_azure_monitor_metrics_enabled':('azureMonitorProfile','metrics','enabled')}
    if cid in fields:
        ref=p
        for k in fields[cid][:-1]:ref=ref[k]
        ref[fields[cid][-1]]=False
    if cid=='azure.aks.auto_upgrade':p['autoUpgradeProfile']['upgradeChannel']='none'
    if cid in ('azure.aks.api_server_restricted','azure.claude.aks_authorized_ip_ranges'):p['apiServerAccessProfile']['authorizedIPRanges']=[]
    if cid in ('azure.aks.network_policy','azure.claude.aks_network_policy_configured'):p['networkProfile']['networkPolicy']='none'
    for slug,name in [('aks_azure_policy_addon','azurepolicy'),('aks_container_insights_logging','omsagent'),('aks_secret_store_rotation','azureKeyvaultSecretsProvider')]:
        if cid=='azure.claude.'+slug:p['addonProfiles'][name]['enabled']=False
    if cid=='azure.claude.aks_http_application_routing_disabled':p['addonProfiles']['httpApplicationRouting']['enabled']=True
    if cid=='azure.claude.aks_disk_encryption_set':p.pop('diskEncryptionSetID')
    if cid=='azure.claude.aks_encryption_at_host':p['agentPoolProfiles'][0]['enableEncryptionAtHost']=False
    if cid=='azure.claude.aks_node_public_ip_disabled':p['agentPoolProfiles'][0]['enableNodePublicIP']=True
    if cid=='azure.claude.aks_max_pods_at_least_50':p['agentPoolProfiles'][0]['maxPods']=30
    if cid=='azure.claude.aks_network_plugin_azure':p['networkProfile']['networkPlugin']='kubenet'
    if cid=='azure.claude.aks_paid_sku_tier':d[AKS]['sku']['tier']='Free'
    if cid=='azure.claude.aks_version_not_cve_2019_9946':p['kubernetesVersion']='1.13.4'
    if cid=='azure.claude2.aks_private_cluster_nodes_without_public_ip':p['agentPoolProfiles'][0]['enableNodePublicIP']=True
    if cid=='azure.claude2.app_gateway_http2_enabled':d[AGW]['properties']['enableHttp2']=False
    if cid=='azure.claude2.app_gateway_min_tls_12':d[AGW]['properties']['sslPolicy']={'policyType':'Predefined','policyName':'AppGwSslPolicy20170401'}
    if cid in ('azure.claude2.app_gateway_waf_enabled','azure.claude2.app_gateway_waf_mode_specified'):
        d[AGW]['properties']['firewallPolicy']=None
        d[AGW]['properties']['sku']={'name':'Standard_v2','tier':'Standard_v2','capacity':2}
    if cid in ('azure.claude.flow_log_enabled','azure.claude.network_watcher_flow_logs_traffic_analytics'):d[FLOW]['properties']['enabled']=False
    if cid in ('azure.claude.flow_log_traffic_analytics',):d[FLOW]['properties']['flowAnalyticsConfiguration']['networkWatcherFlowAnalyticsConfiguration']['enabled']=False
    if cid in ('azure.claude.network_watcher_flow_logs_retention_90','azure.claude2.vnet_flow_log_retention_90'):d[FLOW]['properties']['retentionPolicy']['days']=30
    if cid in ('azure.claude2.nsg_flow_logs_to_log_analytics','azure.claude2.vnet_flow_logs_to_log_analytics'):d[FLOW]['properties']['flowAnalyticsConfiguration']['networkWatcherFlowAnalyticsConfiguration'].pop('workspaceId')
    if cid in ('azure.claude.subnet_nsg_associated','azure.claude.gateway_subnet_no_nsg'):
        s=d[VNET]['properties']['subnets'][0]['properties']
        if cid.endswith('gateway_subnet_no_nsg'):s['networkSecurityGroup']={'id':NSG}
        else:s.pop('networkSecurityGroup')
    if cid in ('azure.network.load_balancer_standard','azure.network.public_ip_standard'):
        typ='loadBalancers' if 'load_balancer' in cid else 'publicIPAddresses';d[SCOPE+'/providers/Microsoft.Network/'+typ]['value'][0]['sku']['name']='Basic'
    if cid=='azure_application_gateway_app_ensure_http_is_redirected_to_https_1099ad7':
        rule=d[AGW]['properties']['requestRoutingRules'][0]['properties'];rule.pop('redirectConfiguration');rule['backendAddressPool']={'id':AGW+'/backendAddressPools/native'};rule['backendHttpSettings']={'id':AGW+'/backendHttpSettingsCollection/native'}
    if cid=='azure_cdn_profile_1_2_8_5_ed953a0':d[DOMAIN]['properties']['tlsSettings']['certificateType']='ManagedCertificate'
    if cid=='azure_cdn_profile_10_3_4_1_4e40487':d[POOL]['properties']['authentication']=None


class NativeWire:
    def __init__(self,data,mode='normal'):self.data=data;self.mode=mode;self.calls=[]
    def open(self,request,timeout):
        parts=urlsplit(request.full_url);q=parse_qs(parts.query)
        def require(value):
            if not value:pytest.fail('native method/host/path/body contract violated: '+request.full_url)
        require(parts.scheme=='https' and parts.netloc=='management.azure.com')
        require(request.get_header('Authorization')=='Bearer offline-wire-native')
        if parts.path=='/providers/Microsoft.ResourceGraph/resources':
            require(request.get_method()=='POST' and timeout==20)
            body=json.loads(request.data)
            require(set(body)=={'subscriptions','query','options'} and body['subscriptions']==[SUB])
            # The storage ancestor query is a separate, read-only ARG contract.
            # This fixture does not authorize management-group ancestry reads.
            if q=={'api-version':['2024-04-01']}:
                require(body['query']=="resourcecontainers | where type =~ 'microsoft.resources/subscriptions' | project id, properties | order by id asc")
                require(body['options']=={'resultFormat':'objectArray','$top':1000})
                self.calls.append({'method':'POST','host':parts.netloc,'path':parts.path,'query':q,'body':body})
                raise azure.AzureReadError('optional_subscription_ancestry_not_authorized',403)
            require(body['query']=='Resources | project id, type, name, location, tags, identity, properties, subscriptionId, resourceGroup | order by id asc')
            require(body['options']=={'resultFormat':'objectArray','$top':1000} and q=={'api-version':['2022-10-01']})
            self.calls.append({'method':'POST','host':parts.netloc,'path':parts.path,'query':q,'body':body})
            raise azure.AzureReadError('optional_resource_graph_inventory_not_authorized',403)
        if parts.path==VNET+'/listNetworkManagerEffectiveSecurityAdminRules':
            require(request.get_method()=='POST' and json.loads(request.data)=={} and 0<timeout<=20)
            require(q=={'api-version':['2025-05-01']})
            self.calls.append({'method':'POST','host':parts.netloc,'path':parts.path,'query':q,'body':{}})
            raise azure.AzureReadError('auxiliary_read_only_query_not_authorized',403)
        require(request.get_method()=='GET' and request.data is None and timeout==20 and bool(q.get('api-version')))
        self.calls.append({'method':'GET','host':parts.netloc,'path':parts.path,'query':q,'body':None})
        ancillary=empty_inventory_versions(SCOPE)
        if parts.path in ancillary:require(matches_empty_inventory_query(SCOPE,parts.path,q))
        if parts.path in {ACCOUNT+'/'+service+'/default/providers/Microsoft.Insights/diagnosticSettings' for service in ('blobServices','fileServices','queueServices','tableServices')}:
            require(q in ({'api-version':['2021-05-01-preview']},{'api-version':['2021-05-01-preview'],'$skiptoken':['next']}))
        parents={SCOPE+('/'if endpoint=='resourcegroups'else'/providers/')+endpoint:version for endpoint,version in azure.ENDPOINTS.values()}
        if parts.path in parents and parts.path not in ancillary:require(q.get('api-version')==[parents[parts.path]])
        if parts.path in {owner+'/providers/Microsoft.Authorization/locks' for owner in (SCOPE,RG,ACCOUNT)}:
            require(q=={'api-version':['2016-09-01']})
        if parts.path in {ACCOUNT+'/blobServices/default/containers',ACCOUNT+'/fileServices/default/shares'}:
            require(q in ({'api-version':['2023-05-01']},{'api-version':['2023-05-01'],'$skiptoken':['next']}))
        children={ACCOUNT+'/encryptionScopes':'2023-05-01',ACCOUNT+'/localUsers':'2023-05-01',
                  ACCOUNT+'/providers/Microsoft.EventGrid/eventSubscriptions':'2022-06-15'}
        if parts.path in children:
            version=children[parts.path]
            require(q in ({'api-version':[version]},{'api-version':[version],'$skiptoken':['next']}))
        if parts.path not in self.data:pytest.fail('Unexpected native HTTP path: '+parts.path)
        if self.mode=='denied':raise azure.AzureReadError('forbidden',403)
        if isinstance(self.data[parts.path],BaseException):raise self.data[parts.path]
        body=deepcopy(self.data[parts.path])
        if self.mode=='empty' and 'value' in body:body['value']=[]
        if self.mode=='omitted':
            if 'value' in body:body['value']=[{k:v for k,v in r.items() if k in ('id','name','type')} for r in body['value']]
            else:body={k:v for k,v in body.items() if k in ('id','name','type')}
        if self.mode=='partial' and 'value' in body:
            if '$skiptoken' in q:raise azure.AzureReadError('forbidden',403)
            body['nextLink']=request.full_url+('&' if parts.query else '?')+'$skiptoken=next'
        if self.mode=='foreign' and 'value' in body:
            for row in body['value']:
                if isinstance(row.get('id'),str):row['id']=row['id'].replace(SUB,OTHER)
        if self.mode=='malformed':
            rows=body.get('value',[body])
            for row in rows:
                if isinstance(row,dict) and '/providers/' in row.get('id',''):
                    row.update(properties=[],sku=[],identity=[])
        response=io.BytesIO(json.dumps(body).encode())
        response.status=200
        return response


def capture(monkeypatch,cid,branch='positive',data=None):
    from peaso.collectors import azure_nsg_ingress_native
    wire=NativeWire(base_native(cid,branch=='opposite') if data is None else data,'normal' if branch in ('positive','opposite') else branch)
    monkeypatch.setattr(azure,'build_opener',lambda *args:wire)
    monkeypatch.setattr(azure_nsg_ingress_native,'build_opener',lambda *args:wire)
    transport=object.__new__(REAL_TRANSPORT);transport.tenant=transport.verified_tenant=TENANT;transport.owned=False;transport.credential=None
    transport.token=lambda audience:'offline-wire-native' if audience==azure.ARM else pytest.fail('Unexpected credential audience')
    monkeypatch.setattr(azure,'AzureTransport',lambda auth:transport)
    snapshot=engine.collect_snapshot({'connector':{'provider':'azure','scopes':[SUB],'auth':{'tenant_id':TENANT},'options':{'retries':0,'concurrency':1}},'checks':[cid]})
    findings=engine.evaluate_snapshot(snapshot,checks=[cid])['findings']
    assert wire.calls
    native={k:({'error':str(v)} if isinstance(v,BaseException) else v) for k,v in wire.data.items()}
    native_sha=hashlib.sha256(json.dumps(native,sort_keys=True).encode()).hexdigest()
    RECEIPTS.append({'check_id':cid,'branch':branch,'testnode':os.environ.get('PYTEST_CURRENT_TEST','').split(' (')[0],'native_sha256':native_sha,
        'statuses':sorted({f['status'] for f in findings}),'requests':wire.calls,
        'findings':[{'resource':f.get('resource'),'status':f['status'],'evidence':f.get('evidence')} for f in findings]})
    folder=os.environ.get('AZURE_NETWORK_REVIEW_RECEIPTS')
    if folder and branch=='positive':
        key=cid.replace('/','_')+'.native-'+native_sha[:12];Path(folder).mkdir(parents=True,exist_ok=True)
        Path(folder,key+'.snapshot.json').write_text(json.dumps(snapshot,indent=2)+'\n')
    return snapshot,findings,wire

UNPRODUCED={'azure_aks_cluster_10_2_1_1_17_885658f','azure_aks_cluster_7_2_1_6_93c4fab','azure_aks_cluster_aks_cluster_rbac_enabled_db12524'}

ARCHIVED_AKS_SCOPE_ID='azure_aks_cluster_10_2_1_1_17_885658f'
ARCHIVED_AKS_SCOPE_PREDECESSOR='tests/fixtures/azure_archived_aks_scope_predecessor_20261020.json.gz'
ARCHIVED_AKS_SCOPE_PREDECESSOR_SHA256='969398a8c234647b5818f0d82285602dc921c953fda0ea70af78faf36628572d'


def _archived_aks_scope_inputs():
    root=Path(__file__).resolve().parents[1]
    packed=(root/ARCHIVED_AKS_SCOPE_PREDECESSOR).read_bytes()
    assert hashlib.sha256(packed).hexdigest()==ARCHIVED_AKS_SCOPE_PREDECESSOR_SHA256
    retained=json.loads(gzip.decompress(packed))
    assert retained['exact_check_id']==ARCHIVED_AKS_SCOPE_ID
    previous=retained['predecessor_test']
    assert previous['path']=='tests/test_azure_network_platform_1_native_review_20261020.py'
    assert hashlib.sha256(previous['text'].encode()).hexdigest()==previous['sha256']=='8292c2eafd4278fbd8020d1650ffaa4d112b329f9967e57193663cc42e3baf23'
    return root,retained


def _assert_archived_aks_scope_rejection(monkeypatch,cid):
    """Only this reviewed archived ID tests scope rejection instead of a verdict."""
    if cid!=ARCHIVED_AKS_SCOPE_ID:
        raise ValueError('archived AKS scope compatibility applies only to '+ARCHIVED_AKS_SCOPE_ID)
    from peaso import collectors
    from peaso.checks import native_only
    from peaso.collectors import azure_nsg_ingress_native
    root,retained=_archived_aks_scope_inputs()
    expected=retained['exclusion']
    assert native_only.exclusions()[cid]==expected
    assert json.loads((root/'peaso/checks/native_only.json').read_bytes())['checks'][cid]==expected
    assert expected['disposition']=='unsupported_exact_contract'
    assert expected['source']==retained['review']['path']
    reviewed=(root/expected['source']).read_bytes()
    assert hashlib.sha256(reviewed).hexdigest()==retained['review']['sha256']
    contract,=[row for row in json.loads(reviewed)['per_id']if row['id']==cid]
    assert contract==retained['review']['contract']
    assert 'Legacy usable destination boolean has no defined native metadata proof.' in contract['proof_limits']
    source=(root/'peaso/checks/compliance_new_sw30.py').read_text()
    node=next(n for n in ast.parse(source).body if isinstance(n,ast.FunctionDef)and n.name=='diagnostics')
    body=''.join(source.splitlines(keepends=True)[node.lineno-1:node.end_lineno])
    assert body==contract['before_function']['body']==contract['after_function']['body']
    assert hashlib.sha256(body.encode()).hexdigest()==contract['after_function']['sha256']
    assert cid in ROSTER and cid in REGISTRY
    checks_before=tuple(map(id,CHECKS));exclusions_before=deepcopy(native_only.exclusions())
    attempted=[]
    def forbidden(*args,**kwargs):
        attempted.append('transport/network/auth entrypoint')
        pytest.fail('archived public selection must reject before transport/network/auth')
    with monkeypatch.context() as guard:
        for owner,names in ((collectors,('collect_live',)),(azure,('collect','AzureTransport','build_opener','credential_for','urlopen')),
                            (azure_nsg_ingress_native,('build_opener',)),
                            (socket,('create_connection','getaddrinfo','gethostbyname','gethostbyname_ex')),
                            (socket.socket,('connect','connect_ex','sendto'))):
            for name in names:guard.setattr(owner,name,forbidden)
        active={check.id for check in engine._registry()}
        assert cid not in active and expected['native_alternative'] in active
        assert cid not in {row['id']for row in engine.get_catalog()['checks']}
        catalog=json.loads((root/'peaso/rulepacks/native_catalog.json').read_bytes())
        assert cid not in {row['id']for row in catalog['checks']}
        assert cid in {row['id']for row in catalog['archived_checks']}
        assert catalog['excluded_controls'][cid]==expected
        request={'connector':{'provider':'azure','scopes':[SUB],'auth':{'tenant_id':TENANT}},'checks':[cid]}
        message='check requires external policy or manual evidence and is not available for automated scans: '+cid
        for select in (lambda:engine._selection('azure',None,[cid],None),
                       lambda:engine.plan_collection(deepcopy(request)),
                       lambda:engine.collect_snapshot(deepcopy(request))):
            with pytest.raises(ValueError) as rejected:select()
            assert str(rejected.value)==message
        assert attempted==[]
    assert tuple(map(id,CHECKS))==checks_before
    assert native_only.exclusions()==exclusions_before


def test_archived_aks_scope_preserves_exact_native_predecessor_assertions_and_roster():
    root,retained=_archived_aks_scope_inputs()
    before=ast.parse(retained['predecessor_test']['text'])
    after=ast.parse((root/retained['predecessor_test']['path']).read_text())
    old={n.name:n for n in before.body if isinstance(n,ast.FunctionDef)and n.name.startswith('test_')}
    new={n.name:n for n in after.body if isinstance(n,ast.FunctionDef)and n.name.startswith('test_')}
    assert set(old)<=set(new)
    gate=ast.parse('if cid==ARCHIVED_AKS_SCOPE_ID:\n _assert_archived_aks_scope_rejection(monkeypatch,cid)\n return\n').body[0]
    for name,node in old.items():
        current=new[name]
        assert ast.dump(node.args)==ast.dump(current.args)
        assert [ast.dump(n)for n in node.decorator_list]==[ast.dump(n)for n in current.decorator_list]
        assert [ast.dump(n)for n in ast.walk(node)if isinstance(n,ast.Assert)]==[ast.dump(n)for n in ast.walk(current)if isinstance(n,ast.Assert)]
        restored=deepcopy(current)
        if name in ('test_each_assigned_native_contract','test_wrong_native_resource_type_cannot_establish_configuration'):
            assert sum(ast.dump(n)==ast.dump(gate)for n in restored.body)==1
            restored.body=[n for n in restored.body if ast.dump(n)!=ast.dump(gate)]
        assert ast.dump(restored)==ast.dump(node)
    # All native fixture builders, transports, capture helpers and module-level
    # rosters/expected inputs remain exact; only the two test entrypoints route
    # this archived ID to its current exclusion contract.
    for node in before.body:
        if (isinstance(node,(ast.ClassDef,ast.Assign,ast.AnnAssign))
                or isinstance(node,ast.FunctionDef)and not node.name.startswith('test_')):
            assert any(ast.dump(node)==ast.dump(current)for current in after.body)


@pytest.mark.parametrize('cid',[ARCHIVED_AKS_SCOPE_ID+'_unreviewed','azure_aks_cluster_10_2_1_1_17_885658f_extra'])
def test_archived_aks_scope_successor_does_not_accept_other_ids(monkeypatch,cid):
    with pytest.raises(ValueError,match='archived AKS scope compatibility applies only to '+ARCHIVED_AKS_SCOPE_ID):
        _assert_archived_aks_scope_rejection(monkeypatch,cid)
    with pytest.raises(ValueError,match='^unknown check ID for selected provider$'):
        engine.plan_collection({'connector':{'provider':'azure','scopes':[SUB]},'checks':[cid]})


@pytest.mark.parametrize('cid',ROSTER)
@pytest.mark.parametrize('branch',['positive','opposite','omitted','empty','denied','partial','foreign','malformed'])
def test_each_assigned_native_contract(monkeypatch,cid,branch):
    if cid==ARCHIVED_AKS_SCOPE_ID:
        _assert_archived_aks_scope_rejection(monkeypatch,cid)
        return
    _,findings,_=capture(monkeypatch,cid,branch)
    states={f['status'] for f in findings}
    if cid in UNPRODUCED and branch in ('positive','opposite'):expected={'UNKNOWN'}
    elif branch=='positive':expected={'PASS'}
    elif branch=='opposite':expected={'FAIL'}
    elif branch=='denied':expected={'DENIED'}
    elif branch=='empty':expected={'NOT_APPLICABLE'} if cid in {'azure.claude2.nsg_flow_logs_to_log_analytics','azure.claude2.vnet_flow_logs_to_log_analytics','azure_cdn_profile_10_3_4_1_4e40487','azure_cdn_profile_1_2_8_5_ed953a0'} else {'EMPTY'}
    elif branch=='partial':
        if cid in {'azure.claude.gateway_subnet_no_nsg','azure.claude.subnet_nsg_associated'}:expected={'PASS'}
        elif cid in UNPRODUCED or cid.startswith('azure_cdn_profile_') or cid in {'azure.claude.network_watcher_flow_logs_retention_90','azure.claude.network_watcher_flow_logs_traffic_analytics','azure.claude2.app_gateway_waf_enabled','azure.claude2.app_gateway_waf_mode_specified','azure.claude2.nsg_flow_logs_to_log_analytics','azure.claude2.vnet_flow_logs_to_log_analytics','azure_application_gateway_app_ensure_http_is_redirected_to_https_1099ad7'}:expected={'UNKNOWN'}
        else:expected={'PASS','UNKNOWN'}
    else:expected={'UNKNOWN'}
    assert states==expected,(cid,branch,findings)

@pytest.mark.parametrize('cid',['azure.aks.api_server_restricted','azure.claude.aks_authorized_ip_ranges'])
def test_public_aks_universal_authorized_range_is_not_restricted(monkeypatch,cid):
    d=base_native(cid);d[AKS]['properties']['apiServerAccessProfile']['authorizedIPRanges']=['0.0.0.0/0']
    _,f,_=capture(monkeypatch,cid,data=d);assert {r['status'] for r in f}=={'FAIL'},f


def test_disabled_native_waf_policy_does_not_enable_gateway_waf(monkeypatch):
    cid='azure.claude2.app_gateway_waf_enabled';d=base_native(cid);d[WAF]['properties']['policySettings']['state']='Disabled'
    _,f,_=capture(monkeypatch,cid,data=d);assert {r['status'] for r in f}=={'FAIL'},f


@pytest.mark.parametrize('cid',['azure.claude2.nsg_flow_logs_to_log_analytics','azure.claude2.vnet_flow_logs_to_log_analytics'])
@pytest.mark.parametrize('mode',['flow_disabled','analytics_disabled'])
def test_disabled_native_flow_or_analytics_cannot_prove_log_delivery_configuration(monkeypatch,cid,mode):
    d=base_native(cid)
    if mode=='flow_disabled':d[FLOW]['properties']['enabled']=False
    else:d[FLOW]['properties']['flowAnalyticsConfiguration']['networkWatcherFlowAnalyticsConfiguration']['enabled']=False
    _,f,_=capture(monkeypatch,cid,data=d);assert {r['status'] for r in f}=={'FAIL'},f

@pytest.mark.parametrize('cid',['azure.claude2.nsg_flow_logs_to_log_analytics','azure.claude2.vnet_flow_logs_to_log_analytics'])
def test_foreign_subscription_flow_target_does_not_cover_selected_network(monkeypatch,cid):
    d=base_native(cid);d[FLOW]['properties']['targetResourceId']=VNET.replace(SUB,OTHER)
    _,f,_=capture(monkeypatch,cid,data=d);assert {r['status'] for r in f}=={'FAIL'},f

@pytest.mark.parametrize('cid',['azure.aks.api_server_restricted','azure.claude.aks_authorized_ip_ranges'])
def test_split_native_ipv4_authorized_ranges_covering_universe_are_not_restricted(monkeypatch,cid):
    d=base_native(cid);d[AKS]['properties']['apiServerAccessProfile']['authorizedIPRanges']=['0.0.0.0/1','128.0.0.0/1']
    _,f,_=capture(monkeypatch,cid,data=d);assert {r['status'] for r in f}=={'FAIL'},f

@pytest.mark.parametrize('cid',['azure.aks.api_server_restricted','azure.claude.aks_authorized_ip_ranges'])
@pytest.mark.parametrize('ranges,expected',[
    (['0.0.0.0/32'],'PASS'),(['203.0.113.0/25','203.0.113.128/25'],'PASS'),
    (['::/1','8000::/1'],'FAIL'),(['0.0.0.0/0','203.0.113.0/24'],'FAIL'),
    (['garbage'],'UNKNOWN'),([True],'UNKNOWN'),({'denied':True},'UNKNOWN')])
def test_authorized_range_grammar_and_union(monkeypatch,cid,ranges,expected):
    d=base_native(cid);d[AKS]['properties']['apiServerAccessProfile']['authorizedIPRanges']=ranges
    _,f,_=capture(monkeypatch,cid,data=d);assert {r['status'] for r in f}=={expected},f

@pytest.mark.parametrize('mode',['missing','denied','foreign','unknown_state','malformed_ref'])
def test_waf_policy_requires_exact_available_unique_native_join(monkeypatch,mode):
    cid='azure.claude2.app_gateway_waf_enabled';d=base_native(cid)
    path=SCOPE+'/providers/Microsoft.Network/ApplicationGatewayWebApplicationFirewallPolicies'
    if mode=='missing':d[path]['value']=[]
    if mode=='denied':d[path]=azure.AzureReadError('policy_not_authorized',403)
    if mode=='foreign':d[AGW]['properties']['firewallPolicy']['id']=WAF.replace(SUB,OTHER)
    if mode=='unknown_state':d[WAF]['properties']['policySettings']['state']='invalid'
    if mode=='malformed_ref':d[AGW]['properties']['firewallPolicy']={'id':True}
    _,f,_=capture(monkeypatch,cid,data=d);assert {r['status'] for r in f}<={'UNKNOWN','DENIED'},f

def test_identical_waf_list_repeat_resolves_same_authoritative_get(monkeypatch):
    cid='azure.claude2.app_gateway_waf_enabled';d=base_native(cid)
    d[SCOPE+'/providers/Microsoft.Network/ApplicationGatewayWebApplicationFirewallPolicies']['value'].append(deepcopy(d[WAF]))
    _,f,_=capture(monkeypatch,cid,data=d);assert {r['status'] for r in f}=={'PASS'},f

@pytest.mark.parametrize('cid',ROSTER)
def test_wrong_native_resource_type_cannot_establish_configuration(monkeypatch,cid):
    d=base_native(cid)
    for value in d.values():
        if isinstance(value,dict) and '/providers/' in value.get('id',''):
            value['type']='Microsoft.Unrelated/resources'
    if cid==ARCHIVED_AKS_SCOPE_ID:
        _assert_archived_aks_scope_rejection(monkeypatch,cid)
        return
    _,f,_=capture(monkeypatch,cid,data=d)
    assert {r['status'] for r in f}<={'UNKNOWN','DENIED','EMPTY','NOT_APPLICABLE'},f

@pytest.mark.parametrize('enabled,expected',[(True,'PASS'),(False,'FAIL')])
def test_inline_waf_native_configuration_stays_decisive(monkeypatch,enabled,expected):
    cid='azure.claude2.app_gateway_waf_enabled';d=base_native(cid);p=d[AGW]['properties'];p['firewallPolicy']=None
    p['webApplicationFirewallConfiguration']={'enabled':enabled,'firewallMode':'Prevention','ruleSetType':'OWASP','ruleSetVersion':'3.2'}
    _,f,_=capture(monkeypatch,cid,data=d);assert {r['status'] for r in f}=={expected},f

@pytest.mark.parametrize('mode,expected',[('Detection','PASS'),('unrecognizedMode','UNKNOWN')])
def test_native_waf_mode_enum_is_distinct_from_policy_enabled_state(monkeypatch,mode,expected):
    cid='azure.claude2.app_gateway_waf_mode_specified';d=base_native(cid);d[WAF]['properties']['policySettings']['mode']=mode
    _,f,_=capture(monkeypatch,cid,data=d);assert {r['status'] for r in f}=={expected},f

@pytest.mark.parametrize('cid',['azure.claude2.nsg_flow_logs_to_log_analytics','azure.claude2.vnet_flow_logs_to_log_analytics'])
@pytest.mark.parametrize('mode',['unresolved_local_target','malformed_target','missing_enabled','malformed_enabled','analytics_flag_malformed','malformed_workspace','subnet_target'])
def test_flow_analytics_exact_native_target_and_flags(monkeypatch,cid,mode):
    d=base_native(cid);p=d[FLOW]['properties'];c=p['flowAnalyticsConfiguration']['networkWatcherFlowAnalyticsConfiguration'];expected='UNKNOWN'
    if mode=='unresolved_local_target':p['targetResourceId']=VNET+'-not-in-inventory'
    if mode=='malformed_target':p['targetResourceId']=VNET+'/not-a-native-child'
    if mode=='missing_enabled':p.pop('enabled')
    if mode=='malformed_enabled':p['enabled']='true'
    if mode=='analytics_flag_malformed':c['enabled']='true'
    if mode=='malformed_workspace':c['workspaceId']=True
    if mode=='subnet_target':p['targetResourceId']=SUBNET;expected='PASS'
    _,f,_=capture(monkeypatch,cid,data=d);assert {r['status'] for r in f}=={expected},f

@pytest.mark.parametrize('cid',['azure.claude2.vnet_flow_log_retention_90','azure.claude.network_watcher_flow_logs_retention_90'])
@pytest.mark.parametrize('days,expected',[(0,'PASS'),(89,'FAIL'),(90,'PASS'),(True,'UNKNOWN')])
def test_native_flow_retention_boundaries(monkeypatch,cid,days,expected):
    d=base_native(cid);d[FLOW]['properties']['retentionPolicy']['days']=days
    _,f,_=capture(monkeypatch,cid,data=d);assert {r['status'] for r in f}=={expected},f

@pytest.mark.parametrize('policy,expected',[('AppGwSslPolicy20150501','FAIL'),('AppGwSslPolicy20170401','FAIL'),
    ('AppGwSslPolicy20220101','PASS'),('unrecognizedDefault','UNKNOWN'),(None,'UNKNOWN')])
def test_native_reported_default_tls_policy_is_resolved_without_guessing(monkeypatch,policy,expected):
    cid='azure.claude2.app_gateway_min_tls_12';d=base_native(cid);p=d[AGW]['properties'];p.pop('sslPolicy')
    if policy is not None:p['defaultPredefinedSslPolicy']=policy
    _,f,_=capture(monkeypatch,cid,data=d);assert {r['status'] for r in f}=={expected},f

@pytest.mark.parametrize('cid',['azure.claude.aks_encryption_at_host','azure.claude.aks_node_public_ip_disabled','azure.claude.aks_max_pods_at_least_50','azure.claude2.aks_private_cluster_nodes_without_public_ip'])
@pytest.mark.parametrize('mode',['empty_pools','missing_pool_fact','mixed_pool_fact'])
def test_native_node_pool_inventory_quantifiers(monkeypatch,cid,mode):
    d=base_native(cid);p=d[AKS]['properties'];key={'azure.claude.aks_encryption_at_host':'enableEncryptionAtHost',
        'azure.claude.aks_node_public_ip_disabled':'enableNodePublicIP','azure.claude.aks_max_pods_at_least_50':'maxPods',
        'azure.claude2.aks_private_cluster_nodes_without_public_ip':'enableNodePublicIP'}[cid]
    expected='UNKNOWN'
    if mode=='empty_pools':
        p['agentPoolProfiles']=[]
        if cid=='azure.claude2.aks_private_cluster_nodes_without_public_ip':expected='FAIL'
    if mode=='missing_pool_fact':
        p['agentPoolProfiles'][0].pop(key)
        # ARM explicitly defaults enableNodePublicIP to false. Host encryption
        # requires an affirmative declaration; maxPods has no inferred value.
        if key=='enableNodePublicIP':expected='PASS'
        elif key=='enableEncryptionAtHost':expected='FAIL'
    if mode=='mixed_pool_fact':
        other=deepcopy(p['agentPoolProfiles'][0]);other['name']='second';other[key]=False if key=='enableEncryptionAtHost' else True if key=='enableNodePublicIP' else 30
        p['agentPoolProfiles'].append(other)
        expected='PASS' if cid=='azure.claude2.aks_private_cluster_nodes_without_public_ip' else 'FAIL'
    _,f,_=capture(monkeypatch,cid,data=d);assert {r['status'] for r in f}=={expected},f

@pytest.mark.parametrize('cid,rid',[
    ('azure.aks.rbac',AKS),('azure.claude2.app_gateway_http2_enabled',AGW),
    ('azure.claude2.app_gateway_waf_enabled',WAF),('azure.claude.network_watcher_flow_logs_retention_90',WATCHER)])
@pytest.mark.parametrize('mode',['wrong_type','wrong_id','properties_type','denied'])
def test_authoritative_get_cannot_rebind_or_mistype_listed_native_resource(monkeypatch,cid,rid,mode):
    d=base_native(cid);detail=deepcopy(d[rid]);d[rid]=detail
    # A documented list reference may require an individual authoritative GET.
    for response in d.values():
        if isinstance(response,dict) and 'value' in response:
            response['value']=[{k:v for k,v in r.items() if k in ('id','name','type','location')} if r.get('id')==rid else r for r in response['value']]
    if mode=='wrong_type':detail['type']='Microsoft.Unrelated/resources'
    if mode=='wrong_id':detail['id']=rid+'-other'
    if mode=='properties_type':detail['properties']=[]
    if mode=='denied':d[rid]=azure.AzureReadError('detail_not_authorized',403)
    _,f,_=capture(monkeypatch,cid,data=d);assert {r['status'] for r in f}<={'UNKNOWN','DENIED'},f

@pytest.mark.parametrize('cid,rid',[
    ('azure.claude.subnet_nsg_associated',SUBNET),('azure.claude.flow_log_enabled',FLOW),
    ('azure.claude.network_watcher_flow_logs_traffic_analytics',FLOW)])
def test_native_child_type_must_match_declared_parent_child_kind(monkeypatch,cid,rid):
    d=base_native(cid);d[rid]['type']='Microsoft.Unrelated/resources'
    _,f,_=capture(monkeypatch,cid,data=d);assert {r['status'] for r in f}<={'UNKNOWN','DENIED'},f

@pytest.mark.parametrize('kind',['resource_group','monitor_log_profile','automation_account'])
@pytest.mark.parametrize('mode',['exact','case_alias','omitted','null','empty','wrong','nonstr'])
def test_generic_arm_present_type_guard_and_documented_exceptions(monkeypatch,kind,mode):
    endpoint,version=azure.ENDPOINTS[kind]
    rid=RG if kind=='resource_group' else SCOPE+'/providers/Microsoft.Insights/logprofiles/default' if kind=='monitor_log_profile' else RG+'/providers/'+endpoint+'/native'
    expected_type='Microsoft.Resources/resourceGroups' if kind=='resource_group' else endpoint
    props={'provisioningState':'Succeeded'}
    if kind=='monitor_log_profile':props={'categories':['Write','Delete','Action'],'locations':['global','eastus'],'storageAccountId':ACCOUNT,'retentionPolicy':{'enabled':True,'days':365}}
    if kind=='automation_account':props={'state':'Ok','sku':{'name':'Basic'}}
    row=resource(rid,expected_type,props)
    if mode=='case_alias':row['type']=expected_type.swapcase()
    if mode=='omitted':row.pop('type')
    if mode=='null':row['type']=None
    if mode=='empty':row['type']=''
    if mode=='wrong':row['type']='Microsoft.Unrelated/resources'
    if mode=='nonstr':row['type']=True
    path=SCOPE+('/resourcegroups' if kind=='resource_group' else '/providers/'+endpoint)
    d={path:{'value':[row]},rid:row,rid+'/providers/Microsoft.Insights/diagnosticSettings':{'value':[]}}
    if kind=='automation_account':
        for child in ('variables','webhooks'):d[rid+'/'+child]=azure.AzureReadError('unrelated_child_metadata_not_authorized',403)
    wire=NativeWire(d);monkeypatch.setattr(azure,'build_opener',lambda *a:wire)
    transport=object.__new__(REAL_TRANSPORT);transport.tenant=transport.verified_tenant=TENANT;transport.owned=False;transport.credential=None
    transport.token=lambda audience:'offline-wire-native' if audience==azure.ARM else pytest.fail('unexpected audience')
    result=azure.collect({'scopes':[SUB],'auth':{'tenant_id':TENANT},'options':{'retries':0,'concurrency':1}},[kind],transport=transport)
    rows=[c for c in result['collections'] if c['type']==kind and c['scope']==SCOPE]
    valid=mode in ('exact','case_alias','omitted') or kind=='monitor_log_profile' and mode=='empty'
    assert len(rows)==1
    assert rows[0]['status']=='collected' if valid else rows[0]['status'] in ('malformed','partial')
    if valid and mode=='omitted':assert 'type' not in rows[0]['items'][0]
    assert any(c['path']==path and c['method']=='GET' for c in wire.calls)
