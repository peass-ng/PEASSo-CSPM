"""Actual API shapes through collect_live and the public engine."""
import copy, json
from datetime import datetime, timedelta, timezone
from urllib.parse import urlsplit
import pytest
from peaso.collectors import azure, collect_live
from tests.archived_check_contract import evaluate_snapshot
SUB='/subscriptions/11111111-1111-1111-1111-111111111111'
TENANT='22222222-2222-2222-2222-222222222222'
USER='33333333-3333-3333-3333-333333333333'
GROUP='44444444-4444-4444-4444-444444444444'
MI=SUB+'/resourceGroups/rg/providers/Microsoft.Sql/managedInstances/main'
VM=SUB+'/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/main'
WORKSPACE=SUB+'/resourceGroups/rg/providers/Microsoft.OperationalInsights/workspaces/main'
MEMBER='azure_directory_user_10_6_3_21_d013932'
ADMIN='azure_sql_database_sqlserver_azuread_administrator_enabled_4a039a9'
INTUNE='azure.cis.intune_logs_captured_sent_log_analytics'
PATCH='azure.gap.compute_vm_system_updates_installed'
IDS=[MEMBER,ADMIN,INTUNE,PATCH]
class Denied(RuntimeError): status=403

def capture(monkeypatch,mode='ok',selected=None):
 stamp=(datetime.now(timezone.utc)-timedelta(seconds=2)).isoformat()
 policy={'status':'collected','scope':SUB,'checks':{PATCH:{'maxReportAgeSeconds':3600,'requirePciCompliance':mode=='pci'}},'sw16':{INTUNE:{'status':'collected','scope':'/tenants/'+TENANT,'requiredIntuneCategories':['AuditLogs'],'approvedWorkspaceIds':[WORKSPACE]}}}
 if mode=='foreign_policy':policy['sw16'][INTUNE]['scope']='/tenants/'+GROUP
 class Transport:
  tenant=verified_tenant=TENANT
  def __init__(self):self.calls=[]
  def close(self):pass
  def request(self,url,*,body=None,audience=azure.ARM):
   self.calls.append(url);path=urlsplit(url).path.casefold()
   if audience==azure.GRAPH:
    if path=='/v1.0/users':
     if mode=='users_denied':raise Denied('SECRET_MUST_NOT_ESCAPE')
     return {'value':[{'id':USER,'accountEnabled':True,'userType':'Member'}]}
    if path==('/v1.0/users/'+USER+'/transitivememberof'):
     if mode=='membership_denied':raise Denied('SECRET_MUST_NOT_ESCAPE')
     rows=[]if mode=='no_groups'else[{'id':GROUP,'@odata.type':'#microsoft.graph.group'}]
     if mode=='missing_type':rows[0].pop('@odata.type')
     if mode=='duplicate_group':rows+=copy.deepcopy(rows)
     value={'value':rows}
     if mode=='partial_membership':value['@odata.nextLink']='https://evil.test/next'
     return value
    return {'value':[]}
   if path=='/subscriptions':return {'value':[{'id':SUB,'subscriptionId':SUB.rsplit('/',1)[-1],'tenantId':TENANT,'state':'Enabled'}]}
   if path==SUB.casefold():return {'id':SUB,'subscriptionId':SUB.rsplit('/',1)[-1],'tenantId':TENANT,'state':'Enabled'}
   if path==VM.casefold():return {'id':VM,'type':'Microsoft.Compute/virtualMachines','properties':{'storageProfile':{'osDisk':{'osType':'Linux'}}}}
   if path==(SUB+'/providers/Microsoft.Sql/managedInstances').casefold():
    if mode=='mi_denied':raise Denied('SECRET_MUST_NOT_ESCAPE')
    return {'value':[{'id':MI,'properties':{}}]}
   if path==(MI+'/administrators').casefold():
    if mode=='admin_denied':raise Denied('SECRET_MUST_NOT_ESCAPE')
    row={'id':MI+'/administrators/ActiveDirectory','properties':{'administratorType':'ActiveDirectory','sid':GROUP,'tenantId':TENANT,'login':'SECRET_MUST_NOT_ESCAPE'}}
    if mode=='foreign_admin':row['id']=MI+'other/administrators/ActiveDirectory'
    if mode=='foreign_admin_tenant':row['properties']['tenantId']=GROUP
    if mode=='bad_sid':row['properties']['sid']='bad'
    return {'value':[]if mode=='no_admin'else[row]}
   if path==(SUB+'/providers/Microsoft.Compute/virtualMachines').casefold():return {'value':[{'id':VM,'properties':{'storageProfile':{'osDisk':{'osType':'Linux'}}}}]}
   if path==(VM+'/instanceView').casefold():
    if mode=='patch_denied':raise Denied('SECRET_MUST_NOT_ESCAPE')
    return {'patchStatus':{'availablePatchSummary':{'status':'Succeeded','lastModifiedTime':'2000-01-01T00:00:00Z'if mode=='stale_patch'else stamp,'criticalAndSecurityPatchCount':3 if mode=='patches_pending'else 0}}}
   parent='/providers/microsoft.intune'
   if path==parent+'/diagnosticsettingscategories':
    if mode=='categories_denied':raise Denied('SECRET_MUST_NOT_ESCAPE')
    return {'value':[{'id':parent+'/diagnosticSettingsCategories/AuditLogs','name':'AuditLogs','properties':{'categoryType':'Logs'}}]}
   if path==parent+'/diagnosticsettings':
    if mode=='intune_denied':raise Denied('SECRET_MUST_NOT_ESCAPE')
    return {'value':[]if mode=='no_route'else[{'id':parent+'/diagnosticSettings/main'}]}
   if path==parent+'/diagnosticsettings/main':return {'id':parent+'/diagnosticSettings/main','properties':{'workspaceId':WORKSPACE,'logs':[{'category':'AuditLogs','enabled':mode!='route_disabled'}]}}
   if path==WORKSPACE.casefold():
    if mode=='workspace_denied':raise Denied('SECRET_MUST_NOT_ESCAPE')
    return {'id':WORKSPACE+'other'if mode=='foreign_workspace'else WORKSPACE,'properties':{}}
   return {'value':[]}
 transport=Transport();monkeypatch.setattr(azure,'AzureTransport',lambda auth:transport);monkeypatch.setattr(azure,'AzureTransportExposure',lambda auth:transport)
 connector={'provider':'azure','scopes':[SUB],'auth':{'method':'token','arm_token':'fixture','graph_token':'fixture'},'options':{'retries':0,'compliance_policy':policy}}
 if selected:
  from tests.archived_check_contract import collect_snapshot
  snapshot=collect_snapshot({'connector':connector,'checks':[selected]})
 else:
  snapshot=collect_live(connector,['directory_user_group_membership','sql_database','sql_server','mssql_managed_instance','sql_managed_instance_administrator','intune_diagnostic_setting','vm'])
 assert 'SECRET_MUST_NOT_ESCAPE'not in json.dumps(snapshot)
 result=evaluate_snapshot(snapshot,checks=IDS)
 findings={cid:[f for f in result['findings']if f['check_id']==cid][-1]for cid in IDS}
 return findings,snapshot,transport

@pytest.mark.parametrize('mode,changed,expected',[
 ('ok',None,None),('no_groups',MEMBER,'FAIL'),('membership_denied',MEMBER,'DENIED'),('partial_membership',MEMBER,'UNKNOWN'),('missing_type',MEMBER,'UNKNOWN'),('duplicate_group',MEMBER,'UNKNOWN'),('users_denied',MEMBER,'DENIED'),
 ('no_admin',ADMIN,'FAIL'),('admin_denied',ADMIN,'DENIED'),('mi_denied',ADMIN,'DENIED'),('foreign_admin',ADMIN,'UNKNOWN'),('foreign_admin_tenant',ADMIN,'UNKNOWN'),('bad_sid',ADMIN,'UNKNOWN'),
 ('no_route',INTUNE,'FAIL'),('route_disabled',INTUNE,'FAIL'),('intune_denied',INTUNE,'DENIED'),('categories_denied',INTUNE,'DENIED'),('workspace_denied',INTUNE,'DENIED'),('foreign_workspace',INTUNE,'UNKNOWN'),('foreign_policy',INTUNE,'UNKNOWN'),
 ('patches_pending',PATCH,'FAIL'),('stale_patch',PATCH,'UNKNOWN'),('patch_denied',PATCH,'UNKNOWN'),('pci',PATCH,'UNKNOWN')])
def test_actual_api_to_engine(monkeypatch,mode,changed,expected):
 findings,_,_=capture(monkeypatch,mode)
 statuses={cid:f['status']for cid,f in findings.items()}
 assert statuses=={cid:expected if cid==changed else'PASS'for cid in IDS},findings

@pytest.mark.parametrize('tamper',['credential','customer','tenant','unverified','foreign_binding','kind','scope'])
@pytest.mark.parametrize('cid,kind',[(MEMBER,'directory_user_group_membership'),(INTUNE,'intune_diagnostic_setting')])
def test_tenant_anchor_requires_actual_matching_native_collection(monkeypatch,tamper,cid,kind):
 _,snapshot,_=capture(monkeypatch)
 collection=next(c for c in snapshot['collections']if c['type']==kind)
 if tamper=='credential':collection['_provenance']['credential_context_id']='foreign'
 elif tamper=='customer':collection['_provenance']['customer_context_id']='foreign'
 elif tamper=='tenant':collection['_provenance']['tenant_id']=GROUP
 elif tamper=='unverified':snapshot['metadata']['tenant_verified']=False
 elif tamper=='foreign_binding':snapshot['metadata']['subscription_tenants']={SUB:GROUP}
 elif tamper=='kind':collection['type']='directory_user_and_group'
 elif tamper=='scope':collection['scope']='/tenants/'+GROUP
 snapshot.pop('snapshot_id',None)  # Rebuild an imported snapshot to exercise authority checks, beyond the digest.
 findings=evaluate_snapshot(snapshot,checks=[cid])['findings']
 assert findings and all(f['status']=='UNKNOWN'for f in findings),findings

@pytest.mark.parametrize('cid',IDS)
def test_selected_runtime_planner_reads_actual_dependency_path(monkeypatch,cid):
 findings,snapshot,transport=capture(monkeypatch,selected=cid)
 assert findings[cid]['status']=='PASS',findings[cid]
 calls='\n'.join(transport.calls).casefold()
 if cid==MEMBER:
  assert '/transitivememberof'in calls and '/microsoft.intune/'not in calls and '/managedinstances/'not in calls
 elif cid==INTUNE:
  assert '/microsoft.intune/'in calls and '/transitivememberof'not in calls
 elif cid==ADMIN:
  assert '/administrators?'in calls and '/transitivememberof'not in calls
 elif cid==PATCH:
  assert '/instanceview?'in calls and '/transitivememberof'not in calls
