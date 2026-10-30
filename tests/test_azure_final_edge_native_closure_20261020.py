"""Finite closure witnesses using native HTTP, real collectors and public engine."""
from copy import deepcopy
import io,json,socket
from urllib.error import HTTPError
from urllib.parse import urlsplit,parse_qs
import pytest
from peaso.collectors import azure
from tests.archived_check_contract import collect_snapshot,evaluate_snapshot
from tests import test_azure_remaining_services_3_native_review_20261020 as prior

SUB,SCOPE,ROOT=prior.SUB,prior.SCOPE,prior.ROOT
GWLOG,NETAPP,VMPUB,FLEXADM,FW,INGRESS=prior.GWLOG,prior.NETAPP,prior.VMPUB,prior.FLEXADM,prior.FW,prior.INGRESS
arm=prior.arm

@pytest.fixture(autouse=True)
def offline(monkeypatch):
 def blocked(*a,**kw):raise AssertionError('network/DNS/auth forbidden')
 for obj,names in((socket,('getaddrinfo','create_connection')),(socket.socket,('connect','connect_ex')),(azure,('credential_for',))):
  for name in names:monkeypatch.setattr(obj,name,blocked)

class HTTP(prior.NativeHTTP):
 def __init__(self,cid,mutate=None):
  super().__init__(cid,'positive',mutate);self.denied=set();self.partial=set()
 def _open(self,request,timeout):
  p=urlsplit(request.full_url);q=parse_qs(p.query)
  if p.path in self.denied or 'page'in q:
   self.calls.append({'method':request.get_method(),'host':p.netloc,'path':p.path,'query':q})
   assert request.get_method()=='GET'and p.netloc=='management.azure.com'and p.scheme=='https'
   raise HTTPError(request.full_url,403,'fixture denied',{},io.BytesIO(b'{}'))
  result=super()._open(request,timeout)
  if p.path in self.partial:
   data=json.load(result);assert isinstance(data.get('value'),list)
   data['nextLink']=azure.ARM+p.path+'?api-version='+q['api-version'][0]+'&page=2'
   return io.BytesIO(json.dumps(data).encode())
  return result

def put(d,path,value,version):d['routes'][path]=value;d['versions'][path]=version

def collect(monkeypatch,cid,http):
 monkeypatch.setattr(azure,'build_opener',lambda *a:http)
 connector={'provider':'azure','scopes':[SUB],'auth':{'method':'token','arm_token':prior.ARM_TOKEN,'vault_token':'inert','tenant_id':prior.TENANT},'options':{'retries':0,'concurrency':1}}
 snapshot=collect_snapshot({'connector':connector,'checks':[cid]})
 findings=evaluate_snapshot(snapshot,checks=[cid],include_not_applicable=True)['findings']
 assert not http.unexpected,http.unexpected
 assert findings
 return snapshot,findings

def assert_status(cid,mode,snapshot,findings,http,want,record_property):
 actual=','.join(sorted({f['status']for f in findings}))
 for key,value in [('check_id',cid),('mode',mode),('actual',actual),('expected',want),('native_http',json.dumps(http.calls))]:record_property(key,value)
 assert actual==want,findings

@pytest.mark.parametrize('mode,want',[('empty','FAIL'),('positive','PASS'),('denied','DENIED'),('partial','UNKNOWN'),('foreign','UNKNOWN'),('wrong_type','UNKNOWN'),('conflict','UNKNOWN')])
def test_gateway_native_empty_diagnostic_list(monkeypatch,mode,want,record_property):
 h=HTTP(GWLOG);d=h.d;path=d['rid']+'/providers/Microsoft.Insights/diagnosticSettings';diag=d['routes'][path]['value'][0]
 if mode=='empty':d['routes'][path]={'value':[]}
 if mode=='denied':h.denied.add(path)
 if mode=='partial':h.partial.add(path)
 if mode=='foreign':diag['id']=diag['id'].replace(SUB,prior.OTHER)
 if mode=='wrong_type':diag['type']='Microsoft.Network/loadBalancers'
 if mode=='conflict':
  other=deepcopy(diag);other['properties']['logs'][0]['enabled']=False;d['routes'][path]['value'].append(other)
 snapshot,findings=collect(monkeypatch,GWLOG,h)
 assert_status(GWLOG,mode,snapshot,findings,h,want,record_property)
 if mode=='empty':
  env=next(c for c in snapshot['collections']if c['type']=='diagnostic_setting'and c['scope']==d['rid'])
  assert env['status']=='empty'and env['items']==[]
  assert env['_provenance']['source_operation']=='DiagnosticSettings_List'
  assert env['_provenance']['request_path']==path
  assert env['_provenance']['api_version']=='2021-05-01-preview'
  assert env['_provenance']['credential_context_id']==snapshot['metadata']['credential_context_id']


def family_fixture(cid,family,mode):
 h=HTTP(cid);d=h.d
 # Remove previous nonempty family, retaining genuine provider-empty alternatives.
 for k in ('sql_server','mysql_flexible_server','postgresql_flexible_server','vm','nic','vm_scale_set','storage_account'):
  ep,v=azure.ENDPOINTS[k];put(d,SCOPE+'/providers/'+ep,{'value':[]},v)
 ep,version=azure.ENDPOINTS.get(family,(None,None))
 if family=='netapp':
  account=ROOT+'Microsoft.NetApp/netAppAccounts/account';pool=account+'/capacityPools/pool';volume=pool+'/volumes/volume';policy=account+'/backupPolicies/daily';vault=account+'/backupVaults/vault'
  values=[(SCOPE+'/providers/Microsoft.NetApp/netAppAccounts',[arm(account,{'provisioningState':'Succeeded'})]),(account+'/capacityPools',[arm(pool,{'size':4398046511104,'serviceLevel':'Standard'})]),(pool+'/volumes',[arm(volume,{'provisioningState':'Succeeded','usageThreshold':107374182400,'creationToken':'volume','serviceLevel':'Standard','subnetId':prior.SUBNET,'dataProtection':{'backup':{'backupPolicyId':policy,'backupVaultId':vault,'policyEnforced':True}}})]),(account+'/backupPolicies',[arm(policy,{'enabled':True,'dailyBackupsToKeep':7})]),(account+'/backupVaults',[arm(vault,{'provisioningState':'Succeeded'})])]
  for path,rows in values:put(d,path,{'value':rows},'2026-01-01')
  target=d['routes'][pool+'/volumes']['value'][0];deciding=pool+'/volumes'
  if mode=='opposite':target['properties']['dataProtection']['backup']['policyEnforced']=False
  if mode=='missing':target['properties'].pop('dataProtection')
  if mode=='foreign_join':target['properties']['dataProtection']['backup']['backupPolicyId']=policy.replace('/account/','/sibling/')
 elif family=='vm_scale_set':
  rid=ROOT+ep+'/scale';ip={'name':'private','properties':{'subnet':{'id':prior.SUBNET},'primary':True}}
  parent=arm(rid,{'provisioningState':'Succeeded','orchestrationMode':'Uniform','upgradePolicy':{'mode':'Manual'},'virtualMachineProfile':{'networkProfile':{'networkInterfaceConfigurations':[{'name':'nic','properties':{'primary':True,'ipConfigurations':[ip]}}]}}},sku={'name':'Standard_D2s_v5','tier':'Standard','capacity':1})
  put(d,SCOPE+'/providers/'+ep,{'value':[parent]},version);put(d,rid,parent,version)
  # No instances yet: the instance, instance NIC and instance public IP lists are native-empty.
  for field,segment,v in azure.EMBEDDED_LISTS['vm_scale_set']:put(d,rid+'/'+segment,{'value':[]},v)
  put(d,rid+'/providers/Microsoft.Insights/diagnosticSettings',{'value':[]},'2021-05-01-preview')
  target=parent;deciding=SCOPE+'/providers/'+ep
  if mode=='opposite':ip['properties']['publicIPAddressConfiguration']={'name':'public','properties':{'idleTimeoutInMinutes':4,'publicIPAddressVersion':'IPv4'}}
  if mode=='missing':parent['properties']['virtualMachineProfile']['networkProfile'].pop('networkInterfaceConfigurations')
 else:
  rid=ROOT+ep+'/flex';props={'version':'8.0.21'if family=='mysql_flexible_server'else'16','network':{'publicNetworkAccess':'Enabled'},'authConfig':{'activeDirectoryAuth':'Enabled','passwordAuth':'Disabled','tenantId':prior.TENANT}}
  # The inventory LIST uses the current parent version; the native database
  # reader's Servers_Get keeps its own reviewed version.
  from peaso.collectors import azure_database_native
  parent=arm(rid,props);put(d,SCOPE+'/providers/'+ep,{'value':[parent]},version);put(d,rid,parent,azure_database_native.SOURCES[family][1])
  for field,segment,v in azure.EMBEDDED_LISTS.get(family,()):put(d,rid+'/'+segment,{'value':[]},v)
  for field,segment,v in azure.EMBEDDED_SINGLETONS.get(family,()):put(d,rid+'/'+segment,arm(rid+'/'+segment,{}),v)
  put(d,rid+'/providers/Microsoft.Insights/diagnosticSettings',{'value':[]},'2021-05-01-preview')
  adminid=rid+'/administrators/'+('ActiveDirectory'if family=='mysql_flexible_server'else prior.TENANT)
  admin=arm(adminid,{'administratorType':'ActiveDirectory','sid':prior.TENANT,'objectId':prior.TENANT,'principalType':'User','tenantId':prior.TENANT,'login':'review'})
  rule=arm(rid+'/firewallRules/private',{'startIpAddress':'10.0.0.1','endIpAddress':'10.0.0.254'})
  # Child lists keep their own native API versions, independent of the parent GET.
  child={segment:v for field,segment,v in azure.EMBEDDED_LISTS.get(family,())}
  put(d,rid+'/administrators',{'value':[admin]},child['administrators']);put(d,rid+'/firewallRules',{'value':[rule]},child['firewallRules'])
  target=admin if cid==FLEXADM else rule;deciding=rid+('/administrators'if cid==FLEXADM else'/firewallRules')
  if mode=='opposite':
   if cid==FLEXADM:put(d,deciding,{'value':[]},child['administrators'])
   else:rule['properties'].update(startIpAddress='0.0.0.0',endIpAddress='255.255.255.255')
  if mode=='missing':
   if cid==FLEXADM:admin['properties'].pop('tenantId')
   else:rule['properties'].pop('endIpAddress')
  if mode=='foreign_join':
   if cid==FLEXADM:admin['properties']['tenantId']=prior.OTHER
   else:target['id']=target['id'].replace('/flex/','/sibling/')
 if mode=='denied':h.denied.add(deciding)
 if mode=='partial':h.partial.add(deciding)
 # Native resource discovery remains an independent pristine typed response.
 d['index']=[]
 for typ,v in azure.ENDPOINTS.values():d['index'].extend(deepcopy(d['routes'].get(SCOPE+'/providers/'+typ,{}).get('value',[])))
 if mode=='wrong_type':target['type']='Microsoft.Unrelated/resources'
 if mode=='wrong_name':target['name']='contradictory-native-name'
 if mode=='foreign':target['id']=target['id'].replace(SUB,prior.OTHER)
 return h

BRANCHES=[(NETAPP,'netapp'),(VMPUB,'vm_scale_set'),(FLEXADM,'mysql_flexible_server'),(FLEXADM,'postgresql_flexible_server'),(FW,'mysql_flexible_server'),(FW,'postgresql_flexible_server'),(INGRESS,'mysql_flexible_server'),(INGRESS,'postgresql_flexible_server')]
@pytest.mark.parametrize('cid,family,mode,want',[(cid,family,mode,want)for cid,family in BRANCHES for mode,want in [('positive','PASS'),('opposite','FAIL'),('denied','UNKNOWN'),('partial','UNKNOWN'),('wrong_type','UNKNOWN'),('wrong_name','UNKNOWN'),('foreign','UNKNOWN'),('missing','UNKNOWN'),('foreign_join','UNKNOWN')]if not(family=='vm_scale_set'and mode in('foreign_join','wrong_name'))])
def test_nonempty_previously_unexecuted_native_branches(monkeypatch,cid,family,mode,want,record_property):
 h=family_fixture(cid,family,mode);snapshot,findings=collect(monkeypatch,cid,h)
 if family=='netapp'and mode=='missing':want='FAIL' # Native optional protection omission declares no backup.
 if mode=='denied'and family in('netapp','vm_scale_set'):want='DENIED'
 if mode=='foreign_join'and family=='netapp':want='FAIL' # Native declaration references an unassigned policy, a precise configuration failure.
 assert_status(cid,family+'_'+mode,snapshot,findings,h,want,record_property)

EDGE=prior.EDGE
PIP=ROOT+'Microsoft.Network/publicIPAddresses/edge'
GW=ROOT+'Microsoft.Network/applicationGateways/gateway'
WAF=ROOT+'Microsoft.Network/ApplicationGatewayWebApplicationFirewallPolicies/waf'
WEAK=ROOT+'Microsoft.Network/ApplicationGatewayWebApplicationFirewallPolicies/weak'

def edge_fixture(family,mode):
 h=HTTP(EDGE if family in('gateway','ip','load_balancer')else prior.SNI if family=='classic'else prior.WAF);d=h.d
 if family in('gateway','ip','load_balancer'):
  put(d,SCOPE+'/providers/Microsoft.Network/applicationGateways',{'value':[]},'2023-09-01')
  p=arm(PIP,{'publicIPAllocationMethod':'Static','ipAddress':'20.0.0.4','ddosSettings':{'protectionMode':'Enabled'}},etag='W/"pip-v1"',sku={'name':'Standard'})
  put(d,SCOPE+'/providers/Microsoft.Network/publicIPAddresses',{'value':[p]},'2023-09-01');put(d,PIP,p,'2023-09-01')
  put(d,PIP+'/providers/Microsoft.Insights/diagnosticSettings',{'value':[]},'2021-05-01-preview')
  if family!='ip':
   rid=GW if family=='gateway'else ROOT+'Microsoft.Network/loadBalancers/lb'
   front=arm(rid+'/frontendIPConfigurations/public',{'publicIPAddress':{'id':PIP}})
   props={'provisioningState':'Succeeded','frontendIPConfigurations':[front]}
   if family=='gateway':
    port=arm(rid+'/frontendPorts/http',{'port':80});listener=arm(rid+'/httpListeners/public',{'frontendIPConfiguration':{'id':front['id']},'frontendPort':{'id':port['id']},'protocol':'Http'})
    rule=arm(rid+'/requestRoutingRules/main',{'priority':100,'ruleType':'Basic','httpListener':{'id':listener['id']},'backendAddressPool':{'id':rid+'/backendAddressPools/backend'},'backendHttpSettings':{'id':rid+'/backendHttpSettingsCollection/http'}})
    props.update(frontendPorts=[port],httpListeners=[listener],requestRoutingRules=[rule],urlPathMaps=[],firewallPolicy={'id':WAF},gatewayIPConfigurations=[arm(rid+'/gatewayIPConfigurations/subnet',{'subnet':{'id':prior.SUBNET}})])
   parent=arm(rid,props,etag='W/"edge-v1"',sku={'name':'WAF_v2'if family=='gateway'else'Standard','tier':'WAF_v2'if family=='gateway'else'Regional'})
   typ=azure.ENDPOINTS['application_gateway'if family=='gateway'else'load_balancer'][0]
   put(d,SCOPE+'/providers/'+typ,{'value':[parent]},'2023-09-01');put(d,rid,parent,'2023-09-01')
   put(d,rid+'/providers/Microsoft.Insights/diagnosticSettings',{'value':[]},'2021-05-01-preview')
   if family=='gateway':
    for policy,state in((WAF,'Prevention'),(WEAK,'Detection')):
     raw=arm(policy,{'provisioningState':'Succeeded','resourceState':'Enabled','policySettings':{'state':'Enabled','mode':state},'customRules':[],'managedRules':{'managedRuleSets':[{'ruleSetType':'OWASP','ruleSetVersion':'3.2'}]}})
     put(d,policy,raw,'2024-05-01')
    if mode=='waf_detection':d['routes'][WAF]['properties']['policySettings']['mode']='Detection'
    if mode=='no_waf':props.pop('firewallPolicy')
    if mode=='listener_override':listener['properties']['firewallPolicy']={'id':WEAK}
    if mode in('path_override','foreign_path'):
     pm=arm(rid+'/urlPathMaps/main',{'defaultBackendAddressPool':{'id':rid+'/backendAddressPools/backend'},'pathRules':[arm(rid+'/urlPathMaps/main/pathRules/admin',{'paths':['/admin/*'],'firewallPolicy':{'id':WEAK},'backendAddressPool':{'id':rid+'/backendAddressPools/backend'}})]})
     props['urlPathMaps']=[pm];rule['properties'].update(ruleType='PathBasedRouting',urlPathMap={'id':pm['id']})
     if mode=='foreign_path':pm['properties']['pathRules'][0]['id']=pm['properties']['pathRules'][0]['id'].replace(SUB,prior.OTHER)
    if mode=='invalid_port':port['properties']['port']=0
    if mode=='foreign_listener':listener['properties']['frontendIPConfiguration']['id']=front['id'].replace(SUB,prior.OTHER)
    if mode=='rewrite':rule['properties']['rewriteRuleSet']={'id':rid+'/rewriteRuleSets/dynamic'}
    if mode=='wrong_waf_type':d['routes'][WAF]['type']='Microsoft.Network/frontDoorWebApplicationFirewallPolicies'
    if mode=='denied':h.denied.update((WAF,WAF.casefold()))
    if mode=='inherited':
     p['properties']['ddosSettings']['protectionMode']='VirtualNetworkInherited';vid=prior.SUBNET.rsplit('/',2)[0];plan=ROOT+'Microsoft.Network/ddosProtectionPlans/plan'
     vnet=arm(vid,{'enableDdosProtection':True,'ddosProtectionPlan':{'id':plan},'provisioningState':'Succeeded','subnets':[],'virtualNetworkPeerings':[]},etag='W/"vnet-v1"')
     put(d,vid,vnet,'2023-09-01');put(d,SCOPE+'/providers/Microsoft.Network/virtualNetworks',{'value':[vnet]},'2023-09-01')
     for field,seg,v in azure.EMBEDDED_LISTS.get('vnet',()):put(d,vid+'/'+seg,{'value':[]},v)
     put(d,vid+'/providers/Microsoft.Insights/diagnosticSettings',{'value':[]},'2021-05-01-preview')
     put(d,plan,arm(plan,{'provisioningState':'Succeeded'}),'2023-09-01')
  if mode=='ddos_disabled':p['properties']['ddosSettings']['protectionMode']='Disabled'
 else:
  # Actual native classic Front Door / modern AFD declared WAF association.
  rid=d['rid'];fw=ROOT+'Microsoft.Network/frontDoorWebApplicationFirewallPolicies/waf'
  raw=arm(fw,{'provisioningState':'Succeeded','resourceState':'Enabled','policySettings':{'enabledState':'Enabled','mode':'Prevention'},'customRules':{'rules':[]},'managedRules':{'managedRuleSets':[{'ruleSetType':'Microsoft_DefaultRuleSet','ruleSetVersion':'2.1'}]}},sku={'name':'Premium_AzureFrontDoor'})
  put(d,fw,raw,'2022-05-01')
  if family=='classic':d['parent']['properties']['frontendEndpoints'][0]['properties']['webApplicationFirewallPolicyLink']={'id':fw}
  if mode=='waf_detection':raw['properties']['policySettings']['mode']='Detection'
  if mode=='no_waf':
   if family=='classic':d['parent']['properties']['frontendEndpoints'][0]['properties'].pop('webApplicationFirewallPolicyLink')
   else:d['routes'][rid+'/securityPolicies']['value']=[]
  if mode=='wrong_waf_type':raw['type']='Microsoft.Network/ApplicationGatewayWebApplicationFirewallPolicies'
  if mode=='denied':h.denied.update((fw,fw.casefold()))
  if mode=='partial':h.partial.add(rid+'/securityPolicies'if family=='afd'else SCOPE+'/providers/Microsoft.Network/frontDoors')
  if mode=='foreign_domain'and family=='afd':d['routes'][prior.EP+'/routes']['value'][0]['properties']['customDomains'][0]['id']=prior.DOMAIN.replace(SUB,prior.OTHER)
  if mode=='rewrite'and family=='afd':d['routes'][prior.EP+'/routes']['value'][0]['properties']['ruleSets']=[{'id':rid+'/ruleSets/dynamic'}]
  if mode=='partial_pattern'and family=='afd':d['routes'][rid+'/securityPolicies']['value'][0]['properties']['parameters']['associations'][0]['patternsToMatch']=['/admin/*']
  if mode=='unsupported_sku'and family=='afd':d['parent']['sku']['name']='Future_AzureFrontDoor'
 # Strict native path aliases cover ARM's documented case-insensitive identity.
 for path in list(d['routes']):
  d['routes'].setdefault(path.casefold(),d['routes'][path]);d['versions'].setdefault(path.casefold(),d['versions'][path])
 if family in('classic','afd'):
  d['routes'][fw.casefold()]=raw;d['versions'][fw.casefold()]='2022-05-01'
 d['index']=[]
 for typ,v in azure.ENDPOINTS.values():d['index'].extend(deepcopy(d['routes'].get(SCOPE+'/providers/'+typ,{}).get('value',[])))
 return h

EDGE_CASES=[(family,mode,want)for family in('gateway','ip','load_balancer','classic','afd')for mode,want in[('positive','PASS'),('ddos_disabled','FAIL')]if mode!='ddos_disabled'or family in('gateway','ip','load_balancer')]
EDGE_CASES += [('gateway',m,w)for m,w in [('waf_detection','FAIL'),('no_waf','FAIL'),('listener_override','FAIL'),('path_override','FAIL'),('foreign_path','UNKNOWN'),('invalid_port','UNKNOWN'),('foreign_listener','UNKNOWN'),('rewrite','UNKNOWN'),('wrong_waf_type','UNKNOWN'),('denied','UNKNOWN'),('inherited','PASS')]]
EDGE_CASES += [(family,m,w)for family in('classic','afd')for m,w in [('waf_detection','FAIL'),('no_waf','FAIL'),('wrong_waf_type','UNKNOWN'),('denied','UNKNOWN'),('partial','UNKNOWN')]]
EDGE_CASES += [('afd',m,'UNKNOWN')for m in('foreign_domain','rewrite','partial_pattern','unsupported_sku')]
@pytest.mark.parametrize('family,mode,want',EDGE_CASES)
def test_actual_declared_public_ddos_waf_native(monkeypatch,family,mode,want,record_property):
 h=edge_fixture(family,mode);snapshot,findings=collect(monkeypatch,EDGE,h)
 if mode=='denied':want='DENIED'
 if family=='afd'and mode=='rewrite':want='PASS' # Native WAF runs before Front Door rule sets.
 assert_status(EDGE,family+'_'+mode,snapshot,findings,h,want,record_property)

@pytest.mark.parametrize('mutation',('operation','api_version','request_path','credential','scope','duplicate'))
def test_empty_diagnostic_collection_receipt_is_not_caller_assertion(monkeypatch,mutation,record_property):
 h=HTTP(GWLOG);d=h.d;path=d['rid']+'/providers/Microsoft.Insights/diagnosticSettings';d['routes'][path]={'value':[]}
 snapshot,findings=collect(monkeypatch,GWLOG,h)
 assert {f['status']for f in findings}=={'FAIL'}
 env=next(c for c in snapshot['collections']if c['type']=='diagnostic_setting'and c['scope']==d['rid'])
 if mutation=='operation':env['_provenance']['source_operation']='caller-empty'
 if mutation=='api_version':env['_provenance']['api_version']='2099-01-01'
 if mutation=='request_path':env['_provenance']['request_path']=path.replace('/review/','/foreign/')
 if mutation=='credential':env['_provenance']['credential_context_id']='0'*32
 if mutation=='scope':env['scope']=env['scope'].replace(SUB,prior.OTHER)
 if mutation=='duplicate':
  snapshot['collections'].append(deepcopy(env))
  with pytest.raises(ValueError):evaluate_snapshot(snapshot,checks=[GWLOG])
  record_property('check_id',GWLOG);record_property('mode','empty_receipt_duplicate');record_property('actual','REJECTED');record_property('expected','REJECTED');return
 from peaso.snapshot import make_snapshot
 snapshot=make_snapshot('azure',snapshot['scopes'],snapshot['collections'],metadata=snapshot['metadata'],created_at=snapshot['created_at'])
 findings=evaluate_snapshot(snapshot,checks=[GWLOG],include_not_applicable=True)['findings']
 assert_status(GWLOG,'empty_receipt_'+mutation,snapshot,findings,h,'UNKNOWN',record_property)

@pytest.mark.parametrize('variant,want',[('clean_accessible','PASS'),('userinfo','FAIL'),('denied','DENIED'),('foreign_project','UNKNOWN'),('missing_urls','UNKNOWN')])
def test_visible_devops_proposal_actual_http_only(monkeypatch,variant,want,record_property):
 # The reviewed visible-URL criterion is registered now. Exercise its real
 # scheduler and dependencies without replacing the archived broad evaluator.
 record_property('candidate_id','azure.review.devops.visible_clone_urls_without_userinfo')
 record_property('candidate_only','registered_visible_url_scope')
 prior.test_explicit_devops_metadata_http(monkeypatch,variant,want,record_property)
 # Public engine invocation used a temporary pure candidate implementation;
 # no check ID is installed or canonical admission changed by this test.

@pytest.mark.parametrize('variant,want',[('positive','PASS'),('negative','FAIL'),('child_denied','UNKNOWN'),('child_partial','UNKNOWN'),('foreign','UNKNOWN'),('wrong_type','UNKNOWN')])
def test_existing_configured_apim_is_useful_tracing_alternative(monkeypatch,variant,want,record_property):
 cid=prior.APIM_AI
 findings,snapshot,h=prior.capture(monkeypatch,cid,variant)
 actual=','.join(sorted({f['status']for f in findings}))
 for key,value in[('check_id',cid),('mode','declared_apim_'+variant),('actual',actual),('expected',want),('native_http',json.dumps(h.calls))]:record_property(key,value)
 assert actual==want,findings

@pytest.mark.parametrize('variant,want',[('positive','UNKNOWN'),('negative','FAIL')])
def test_functional_apim_predecessor_does_not_invent_usability(monkeypatch,variant,want,record_property):
 findings,snapshot,h=prior.capture(monkeypatch,prior.APIM_TRACE,variant)
 assert_status(prior.APIM_TRACE,'functional_apim_'+variant,snapshot,findings,h,want,record_property)

@pytest.mark.parametrize('mode,want',[('prevention','PASS'),('detection','FAIL'),('disabled','FAIL'),('missing_enabled','UNKNOWN'),('malformed_mode','UNKNOWN'),('listener_override','FAIL'),('path_override','FAIL'),('foreign_selection','UNKNOWN')])
def test_native_inline_waf_exact_unregistered_successor(monkeypatch,mode,want,record_property):
 from dataclasses import replace
 from peaso import checks
 from peaso.checks import azure_public_edge_config_review_20261020 as proposal
 h=edge_fixture('gateway','positive');d=h.d;parent=d['routes'][GW];props=parent['properties'];props.pop('firewallPolicy')
 config={'enabled':True,'firewallMode':'Prevention','ruleSetType':'OWASP','ruleSetVersion':'3.2'};props['webApplicationFirewallConfiguration']=config
 if mode=='detection':config['firewallMode']='Detection'
 if mode=='disabled':config['enabled']=False
 if mode=='missing_enabled':config.pop('enabled')
 if mode=='malformed_mode':config['firewallMode']='FutureMode'
 if mode=='listener_override':props['httpListeners'][0]['properties']['firewallPolicy']={'id':WEAK}
 if mode=='path_override':
  pm=arm(GW+'/urlPathMaps/inline',{'defaultBackendAddressPool':{'id':GW+'/backendAddressPools/backend'},'pathRules':[arm(GW+'/urlPathMaps/inline/pathRules/admin',{'paths':['/admin/*'],'firewallPolicy':{'id':WEAK},'backendAddressPool':{'id':GW+'/backendAddressPools/backend'}})]})
  props['urlPathMaps']=[pm];props['requestRoutingRules'][0]['properties'].update(ruleType='PathBasedRouting',urlPathMap={'id':pm['id']})
 # Current admitted callback is decisive for native inline declarations.
 snapshot,old=collect(monkeypatch,EDGE,h)
 assert {f['status']for f in old}==({'PASS'} if mode=='foreign_selection' else {want})
 if mode=='foreign_selection':
  from peaso.snapshot import make_snapshot
  binding=next(row for c in snapshot['collections']if c['type']=='public_edge_binding'for row in c['items']if row['resource_kind']=='application_gateway')
  binding['declared_waf_selections'][0]['parent_id']=GW.replace(SUB,prior.OTHER)
  snapshot=make_snapshot('azure',snapshot['scopes'],snapshot['collections'],metadata=snapshot['metadata'],created_at=snapshot['created_at'])
 n=next(i for i,c in enumerate(checks.CHECKS)if c.id==EDGE);original=checks.CHECKS[n];checks.CHECKS[n]=replace(original,evaluate=proposal.evaluate)
 try:findings=evaluate_snapshot(snapshot,checks=[EDGE],include_not_applicable=True)['findings']
 finally:checks.CHECKS[n]=original
 record_property('candidate_only','inline_native_successor_unregistered')
 assert_status(EDGE,'inline_'+mode,snapshot,findings,h,want,record_property)

@pytest.mark.parametrize('family',('classic','afd'))
def test_real_empty_edge_endpoint_lists_keep_independent_ip_result(monkeypatch,family,record_property):
 h=edge_fixture(family,'positive');d=h.d
 if family=='classic':d['parent']['properties'].update(frontendEndpoints=[],routingRules=[],backendPools=[])
 else:put(d,d['rid']+'/afdEndpoints',{'value':[]},'2025-04-15')
 pip=arm(PIP,{'ddosSettings':{'protectionMode':'Enabled'}},etag='W/"ip-empty-edge"')
 put(d,SCOPE+'/providers/Microsoft.Network/publicIPAddresses',{'value':[pip]},'2023-09-01');put(d,PIP,pip,'2023-09-01')
 put(d,PIP+'/providers/Microsoft.Insights/diagnosticSettings',{'value':[]},'2021-05-01-preview')
 d['index'].append(deepcopy(pip))
 snapshot,findings=collect(monkeypatch,EDGE,h)
 assert_status(EDGE,family+'_true_empty_endpoints_with_protected_ip',snapshot,findings,h,'PASS',record_property)

@pytest.mark.parametrize('mode',('empty','health_log'))
def test_actual_load_balancer_health_log_is_not_fictional_http_log(monkeypatch,mode,record_property):
 h=HTTP(GWLOG);d=h.d
 put(d,SCOPE+'/providers/Microsoft.Network/applicationGateways',{'value':[]},'2023-09-01')
 rid=ROOT+'Microsoft.Network/loadBalancers/health';parent=arm(rid,{'frontendIPConfigurations':[]},etag='W/"lb-health"',sku={'name':'Standard'})
 put(d,SCOPE+'/providers/Microsoft.Network/loadBalancers',{'value':[parent]},'2023-09-01');put(d,rid,parent,'2023-09-01')
 category={'id':rid+'/providers/Microsoft.Insights/diagnosticSettingsCategories/LoadBalancerHealthEvent','name':'LoadBalancerHealthEvent','type':'Microsoft.Insights/diagnosticSettingsCategories','properties':{'categoryType':'Logs','categoryGroups':['allLogs']}}
 diag=arm(rid+'/providers/Microsoft.Insights/diagnosticSettings/health',{'workspaceId':prior.WORKSPACE,'logs':[{'category':'LoadBalancerHealthEvent','enabled':True}]});diag['type']='Microsoft.Insights/diagnosticSettings'
 put(d,rid+'/providers/Microsoft.Insights/diagnosticSettingsCategories',{'value':[category]},'2021-05-01-preview')
 put(d,rid+'/providers/Microsoft.Insights/diagnosticSettings',{'value':[]if mode=='empty'else[diag]},'2021-05-01-preview')
 d['index']=[deepcopy(parent)]
 snapshot,findings=collect(monkeypatch,GWLOG,h)
 assert_status(GWLOG,'native_lb_'+mode,snapshot,findings,h,'NOT_APPLICABLE',record_property)

@pytest.mark.parametrize('mode,want',[('positive','PASS'),('empty_diagnostics','FAIL'),('disabled_log','FAIL'),('no_gateways','NOT_APPLICABLE'),('load_balancer_only','NOT_APPLICABLE'),('denied','UNKNOWN'),('partial','UNKNOWN')])
def test_gateway_logging_exact_unregistered_applicability_successor(monkeypatch,mode,want,record_property):
 from dataclasses import replace
 from peaso import checks
 from peaso.checks import azure_gateway_logging_review_20261020 as proposal
 h=HTTP(GWLOG);d=h.d;path=d['rid']+'/providers/Microsoft.Insights/diagnosticSettings'
 if mode=='empty_diagnostics':d['routes'][path]={'value':[]}
 if mode=='disabled_log':d['routes'][path]['value'][0]['properties']['logs'][0]['enabled']=False
 if mode in('no_gateways','load_balancer_only'):d['routes'][SCOPE+'/providers/Microsoft.Network/applicationGateways']={'value':[]}
 if mode=='load_balancer_only':
  rid=ROOT+'Microsoft.Network/loadBalancers/only';lb=arm(rid,{'frontendIPConfigurations':[]},etag='W/"lb-only"')
  put(d,SCOPE+'/providers/Microsoft.Network/loadBalancers',{'value':[lb]},'2023-09-01');put(d,rid,lb,'2023-09-01')
  put(d,rid+'/providers/Microsoft.Insights/diagnosticSettings',{'value':[]},'2021-05-01-preview')
  category={'id':rid+'/providers/Microsoft.Insights/diagnosticSettingsCategories/LoadBalancerHealthEvent','name':'LoadBalancerHealthEvent','type':'Microsoft.Insights/diagnosticSettingsCategories','properties':{'categoryType':'Logs','categoryGroups':['allLogs']}}
  put(d,rid+'/providers/Microsoft.Insights/diagnosticSettingsCategories',{'value':[category]},'2021-05-01-preview');d['index'].append(deepcopy(lb))
 if mode=='denied':h.denied.add(path)
 if mode=='partial':h.partial.add(path)
 snapshot,original_findings=collect(monkeypatch,GWLOG,h)
 n=next(i for i,c in enumerate(checks.CHECKS)if c.id==GWLOG);original=checks.CHECKS[n]
 checks.CHECKS[n]=replace(original,kind='application_gateway',declared_dependencies=proposal.DEPENDENCIES,empty_applicability_dependencies=proposal.EMPTY_APPLICABILITY_DEPENDENCIES,evaluate=proposal.evaluate)
 try:findings=evaluate_snapshot(snapshot,checks=[GWLOG],include_not_applicable=True)['findings']
 finally:checks.CHECKS[n]=original
 if mode=='denied':want='DENIED'
 record_property('candidate_only','appgateway_http_logging_applicability_unregistered')
 assert_status(GWLOG,'appgateway_candidate_'+mode,snapshot,findings,h,want,record_property)
