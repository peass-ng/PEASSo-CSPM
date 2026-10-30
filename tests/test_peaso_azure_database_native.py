"""Actual SQL/MySQL/PostgreSQL REST shapes through native capture and engine."""
import copy
import json
from urllib.parse import urlsplit
import pytest
from peaso.collectors import azure, collect_live
from peaso.engine import evaluate_snapshot
SUB='/subscriptions/11111111-1111-1111-1111-111111111111'
TENANT='22222222-2222-2222-2222-222222222222'
PID='33333333-3333-3333-3333-333333333333'
PROVIDERS={'sql':'Microsoft.Sql/servers','mysql':'Microsoft.DBforMySQL/flexibleServers','postgres':'Microsoft.DBforPostgreSQL/flexibleServers'}
IDS=['azure_firewall_policy_sqlserver_unrestricted_inbound_access_c12f86d','azure_sql_server_sqlserver_unrestricted_inbound_access_9b32c6a','azure_directory_user_sqlserver_azuread_administrator_enabled_1a9c5cf']
class Denied(RuntimeError):status=403

def capture(monkeypatch,kind='mysql',mode='ok',allow_azure=False,selected_check=None,**limits):
 rid=SUB+'/resourceGroups/rg/providers/'+PROVIDERS[kind]+'/db'
 mode_value='Disabled'if mode=='private'else'Enabled'
 props={'publicNetworkAccess':mode_value}if kind=='sql'else{'network':{'publicNetworkAccess':mode_value}}
 if kind=='postgres':props['authConfig']={'activeDirectoryAuth':'Disabled'if mode=='auth_disabled'else'Enabled'}
 if mode=='missing_mode':props={}
 if mode=='missing_auth'and kind=='postgres':props.pop('authConfig')
 raw={'id':rid,'type':PROVIDERS[kind],'properties':props}
 addresses=('8.8.8.8','8.8.8.8')if mode=='public_range'else('0.0.0.0','255.255.255.255')if mode=='full_range'else('0.0.0.0','0.0.0.0')if mode=='azure_zero'else('10.0.0.1','10.0.0.255')
 firewall={'id':rid+'/firewallRules/rule','properties':{'startIpAddress':addresses[0],'endIpAddress':addresses[1]}}
 if mode=='reversed':firewall['properties'].update(startIpAddress='10.0.0.255',endIpAddress='10.0.0.1')
 if mode=='foreign_firewall':firewall['id']=rid+'other/firewallRules/rule'
 admin={'id':rid+'/administrators/'+('ActiveDirectory'if kind=='mysql'else PID),'properties':{'sid'if kind=='mysql'else'objectId':PID,'tenantId':TENANT,'login':'SECRET_MUST_NOT_ESCAPE'}}
 if kind=='mysql':admin['properties']['administratorType']='ActiveDirectory'
 else:admin['properties']['principalType']='User'
 if mode=='foreign_admin':admin['id']=rid+'other/administrators/'+PID
 if mode=='mismatched_admin_identity':admin['id']=rid+'/administrators/44444444-4444-4444-4444-444444444444'
 if mode=='foreign_tenant':admin['properties']['tenantId']='44444444-4444-4444-4444-444444444444'
 if mode=='malformed_principal':admin['properties']['sid'if kind=='mysql'else'objectId']='not-a-guid'
 class Transport:
  tenant=verified_tenant=TENANT
  calls=[]
  def close(self):pass
  def request(self,url,*,body=None,audience=azure.ARM):
   assert audience==azure.ARM
   assert body is None or urlsplit(url).path.casefold()=='/providers/microsoft.resourcegraph/resources'
   self.calls.append((url,body));path=urlsplit(url).path
   if path.casefold()=='/providers/microsoft.resourcegraph/resources':
    return {'data':[]if mode=='empty'else[raw],'resultTruncated':False}
   if path.casefold()==(SUB+'/resources').casefold():
    return {'value':[]if mode=='empty'else[raw]}
   if path==SUB:
    if mode=='subscription_denied':raise Denied('SECRET_MUST_NOT_ESCAPE')
    return {'id':SUB,'tenantId':TENANT if mode!='foreign_subscription_tenant' else '44444444-4444-4444-4444-444444444444'}
   if path.casefold()==rid.casefold():
    if mode=='detail_denied':raise Denied('SECRET_MUST_NOT_ESCAPE')
    return dict(raw,id=rid+'other')if mode=='foreign_detail'else raw
   for provider in PROVIDERS.values():
    if path.casefold()==(SUB+'/providers/'+provider).casefold():
     if mode=='inventory_denied'and provider==PROVIDERS[kind]:raise Denied('SECRET_MUST_NOT_ESCAPE')
     return {'value':[raw]if provider==PROVIDERS[kind]and mode!='empty'else[]}
   if path.casefold()==(rid+'/firewallRules').casefold():
    if mode=='firewall_denied':raise Denied('SECRET_MUST_NOT_ESCAPE')
    value=[]if mode=='empty_firewall'else[firewall]
    if mode=='duplicate_firewall':value*=2
    return {'value':value,'nextLink':'https://evil.test/next'}if mode=='partial_firewall'else{'value':value}
   if path.casefold()==(rid+'/administrators').casefold():
    if mode=='admin_denied':raise Denied('SECRET_MUST_NOT_ESCAPE')
    return {'value':[]if mode=='no_admin'else[admin]}
   return {'value':[]}
 transport=Transport();monkeypatch.setattr(azure,'AzureTransport',lambda auth:transport);monkeypatch.setattr(azure,'AzureTransportExposure',lambda auth:transport)
 connector={'provider':'azure','scopes':[SUB],'auth':{'method':'token','arm_token':'fixture'},'options':{'retries':0,**limits,'compliance_policy':{'sw15':{'status':'collected','scope':SUB,'allowAzureServices':allow_azure}}}}
 if selected_check:
  from peaso.engine import collect_snapshot
  snapshot=collect_snapshot({'connector':connector,'checks':[selected_check]})
 else:
  snapshot=collect_live(connector,['mysql_postgresql_sql_server'])
 assert 'SECRET_MUST_NOT_ESCAPE'not in json.dumps(snapshot)
 findings=evaluate_snapshot(snapshot,checks=IDS)['findings']
 return {cid:[f for f in findings if f['check_id']==cid][-1]['status']for cid in IDS},snapshot,transport

@pytest.mark.parametrize('kind',['sql','mysql','postgres'])
@pytest.mark.parametrize('mode,firewall,ingress',[('ok','PASS','PASS'),('empty_firewall','PASS','PASS'),('full_range','FAIL','FAIL'),('public_range','PASS','FAIL'),('azure_zero','FAIL','FAIL'),('private','PASS','PASS'),('missing_mode','UNKNOWN','UNKNOWN'),('reversed','UNKNOWN','UNKNOWN'),('foreign_firewall','UNKNOWN','UNKNOWN'),('duplicate_firewall','UNKNOWN','UNKNOWN'),('partial_firewall','UNKNOWN','UNKNOWN'),('firewall_denied','UNKNOWN','UNKNOWN'),('detail_denied','UNKNOWN','UNKNOWN'),('foreign_detail','UNKNOWN','UNKNOWN'),('inventory_denied','DENIED','UNKNOWN')])
def test_native_firewalls_and_effective_ingress(monkeypatch,kind,mode,firewall,ingress):
 statuses,_,_=capture(monkeypatch,kind,mode)
 assert statuses[IDS[0]]==firewall
 assert statuses[IDS[1]]==ingress

@pytest.mark.parametrize('kind',['mysql','postgres'])
@pytest.mark.parametrize('mode,expected',[('ok','PASS'),('no_admin','FAIL'),('foreign_admin','UNKNOWN'),('foreign_tenant','UNKNOWN'),('malformed_principal','UNKNOWN'),('admin_denied','UNKNOWN'),('subscription_denied','UNKNOWN'),('foreign_subscription_tenant','UNKNOWN'),('mismatched_admin_identity','UNKNOWN')])
def test_actual_provider_administrator_fields(monkeypatch,kind,mode,expected):
 statuses,_,_=capture(monkeypatch,kind,mode)
 assert statuses[IDS[2]]==expected

@pytest.mark.parametrize('kind',['sql','mysql','postgres'])
def test_azure_service_sentinel_approval_affects_hygiene_only(monkeypatch,kind):
 statuses,_,_=capture(monkeypatch,kind,'azure_zero',allow_azure=True)
 assert statuses[IDS[0]]=='PASS'
 assert statuses[IDS[1]]=='FAIL'

def test_postgres_disabled_auth_fails_even_with_registered_admin(monkeypatch):
 statuses,_,_=capture(monkeypatch,'postgres','auth_disabled')
 assert statuses[IDS[2]]=='FAIL'

def test_no_unsupported_mysql_authconfig_is_invented(monkeypatch):
 statuses,snapshot,_=capture(monkeypatch,'mysql')
 assert statuses[IDS[2]]=='PASS'
 mysql,=[c for c in snapshot['collections']if c['type']=='mysql_flexible_server']
 assert 'authConfig'not in mysql['items'][0]['properties']


def test_postgres_missing_auth_setting_stays_unknown(monkeypatch):
 statuses,_,_=capture(monkeypatch,'postgres','missing_auth')
 assert statuses[IDS[2]]=='UNKNOWN'

@pytest.mark.parametrize('kind',['sql','mysql','postgres'])
def test_resource_budget_cannot_create_false_positive(monkeypatch,kind):
 statuses,snapshot,_=capture(monkeypatch,kind,max_resources=1)
 assert statuses[IDS[1]]not in ('PASS','EMPTY','NOT_APPLICABLE')
 composite,=[c for c in snapshot['collections']if c['type']=='mysql_postgresql_sql_server']
 assert composite['status']not in('collected','empty')


@pytest.mark.parametrize('kind',['mysql','postgres'])
def test_selected_admin_check_reads_only_required_provider_inventories(monkeypatch,kind):
 statuses,snapshot,transport=capture(monkeypatch,kind,selected_check=IDS[2])
 assert statuses[IDS[2]]=='PASS'
 assert not any('/providers/Microsoft.Sql/servers'in url for url,_ in transport.calls)
 assert not any(c['type']=='mysql_postgresql_sql_server'for c in snapshot['collections'])

@pytest.mark.parametrize('kind',['sql','mysql','postgres'])
def test_selected_firewall_check_activates_native_proof_without_extra_dependency(monkeypatch,kind):
 statuses,snapshot,_=capture(monkeypatch,kind,selected_check=IDS[0])
 assert statuses[IDS[0]]=='PASS'
 assert not any(c['type']=='mysql_postgresql_sql_server'for c in snapshot['collections'])
