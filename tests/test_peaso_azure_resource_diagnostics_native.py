"""Native ARM diagnostic metadata through the frozen registry and snapshot engine."""
import copy,json
from urllib.parse import urlsplit,parse_qs
import pytest
from peaso.collectors import azure,collect_live
from peaso.collectors.azure_resource_diagnostics_native import CHECK
from peaso.engine import evaluate_snapshot,plan_collection
from tests.test_peaso_azure_bulk_native import Transport,SCOPE,SUB,BASE,parent
RESOURCE=BASE+'Microsoft.KeyVault/vaults/vault'
WORKSPACE=BASE+'Microsoft.OperationalInsights/workspaces/logs'
CATS=RESOURCE+'/providers/Microsoft.Insights/diagnosticSettingsCategories'
SETTINGS=RESOURCE+'/providers/Microsoft.Insights/diagnosticSettings'
LIST=SCOPE+'/resources'
class API(Transport):
 def request(self,url,*,body=None,audience=azure.ARM):
  assert body is None and audience==azure.ARM
  assert urlsplit(url).hostname=='management.azure.com'
  return super().request(url,body=body,audience=audience)
def fixture(mode):
 cat={'id':CATS+'/AuditEvent','name':'AuditEvent','type':'Microsoft.Insights/diagnosticSettingsCategories','properties':{'categoryType':'Logs','categoryGroups':['audit','allLogs']}}
 log={'category':'AuditEvent','enabled':True,'retentionPolicy':{'enabled':False,'days':0}}
 props={'logs':[log],'workspaceId':WORKSPACE,'storageAccountId':None,'eventHubAuthorizationRuleId':''}
 setting=parent(SETTINGS+'/route','Microsoft.Insights/diagnosticSettings',props)
 resources=[parent(RESOURCE,'Microsoft.KeyVault/vaults',{'unused':'PRIVATE_MARKER'})]
 r={LIST:{'value':resources},CATS:{'value':[cat]},SETTINGS:{'value':[setting]},WORKSPACE:parent(WORKSPACE,'Microsoft.OperationalInsights/workspaces',{'customerId':'PRIVATE_MARKER','retentionInDays':30})}
 if mode=='group':log.pop('category');log['categoryGroup']='allLogs'
 if mode=='no_groups':cat['properties'].pop('categoryGroups')
 if mode=='disabled':log['enabled']=False
 if mode=='missing_settings':r[SETTINGS]={'value':[]}
 if mode=='missing_workspace':props.pop('workspaceId')
 if mode=='workspace_not_found':r[WORKSPACE]=azure.AzureReadError('ResourceNotFound',404)
 if mode=='workspace_unknown404':r[WORKSPACE]=azure.AzureReadError('NotFound',404)
 if mode=='resource_limit':resources.append(parent(RESOURCE+'second','Microsoft.KeyVault/vaults',{}))
 if mode=='empty_resources':r[LIST]={'value':[]}
 if mode=='no_categories':r[CATS]={'value':[]}
 if mode=='metrics_only':cat['properties']['categoryType']='Metrics'
 if mode=='missing_logs':props.pop('logs')
 if mode=='unknown_group':log.pop('category');log['categoryGroup']='unknown'
 if mode=='unknown_category':log['category']='unknown'
 if mode=='malformed_enabled':log['enabled']='true'
 if mode=='malformed_groups':cat['properties']['categoryGroups']='audit'
 if mode=='unresolved_storage_children':resources[0]=parent(BASE+'Microsoft.Storage/storageAccounts/store','Microsoft.Storage/storageAccounts',{})
 if mode=='unmapped_resource':resources[0]=parent(BASE+'Microsoft.Network/networkWatchers/watcher','Microsoft.Network/networkWatchers',{})
 if mode in ('unmapped_nested','nested_type_id_mismatch'):
  resources[0]=parent(BASE+'Microsoft.Compute/virtualMachines/vm/extensions/ext','Microsoft.Compute/virtualMachines/extensions',{})
  if mode=='nested_type_id_mismatch':resources[0]['type']='Microsoft.Compute/virtualMachines/runCommands'
 if mode in ('unmapped_extension','extension_type_id_mismatch'):
  resources[0]=parent(BASE+'Microsoft.Compute/virtualMachines/vm/providers/Microsoft.Authorization/locks/lock','Microsoft.Authorization/locks',{})
  if mode=='extension_type_id_mismatch':resources[0]['type']='Microsoft.Authorization/roleAssignments'
 if mode=='resource_type_id_mismatch':resources[0]['type']='Microsoft.OperationalInsights/workspaces'
 if mode=='foreign_resource':resources[0]['id']=RESOURCE.replace(SUB,'99999999-9999-9999-9999-999999999999')
 if mode=='foreign_category':cat['id']=CATS.replace('/vault/','/foreign/')+'/AuditEvent'
 if mode=='foreign_setting':setting['id']=SETTINGS.replace('/vault/','/foreign/')+'/route'
 if mode=='foreign_workspace':r[WORKSPACE]['id']=WORKSPACE+'foreign'
 if mode=='wrong_workspace_type':r[WORKSPACE]['type']='Microsoft.Storage/storageAccounts'
 if mode=='foreign_workspace_scope':props['workspaceId']=WORKSPACE.replace(SUB,'99999999-9999-9999-9999-999999999999')
 if mode=='traversal_workspace':props['workspaceId']=WORKSPACE+'/../other'
 if mode=='query_workspace':props['workspaceId']=WORKSPACE+'?token=PRIVATE_MARKER'
 if mode=='unsupported_sink':props['storageAccountId']=BASE+'Microsoft.Storage/storageAccounts/store'
 if mode=='duplicate_resource':resources*=2
 if mode=='duplicate_category':r[CATS]['value']*=2
 if mode=='duplicate_setting':r[SETTINGS]['value']*=2
 if mode=='category_id_name_mismatch':cat['name']='other'
 if mode=='resource_denied':r[LIST]=azure.AzureReadError('forbidden',403)
 if mode=='categories_denied':r[CATS]=azure.AzureReadError('forbidden',403)
 if mode=='settings_denied':r[SETTINGS]=azure.AzureReadError('forbidden',403)
 if mode=='workspace_denied':r[WORKSPACE]=azure.AzureReadError('forbidden',403)
 if mode=='unsupported_discovery':r[CATS]=azure.AzureReadError('ResourceTypeNotSupported',400)
 if mode in ('resource_second_page','resource_partial','resource_page_limit'):
  r[LIST]=lambda q:({'value':resources}if mode!='resource_partial'else azure.AzureReadError('forbidden',403))if'page'in q else{'value':[],'nextLink':azure.ARM+LIST+'?page=2'}
 if mode in ('category_second_page','category_partial','category_duplicate_page'):
  r[CATS]=lambda q:({'value':[cat]}if mode!='category_partial'else azure.AzureReadError('forbidden',403))if'page'in q else{'value':[cat]if mode=='category_duplicate_page'else[],'nextLink':azure.ARM+CATS+'?page=2'}
 if mode in ('settings_second_page','settings_partial','settings_duplicate_page'):
  r[SETTINGS]=lambda q:({'value':[setting]}if mode!='settings_partial'else azure.AzureReadError('forbidden',403))if'page'in q else{'value':[setting]if mode=='settings_duplicate_page'else[],'nextLink':azure.ARM+SETTINGS+'?page=2'}
 if mode=='foreign_continuation':r[CATS]={'value':[cat],'nextLink':'https://evil.invalid'+CATS+'?page=2'}
 return r

def capture(mode):
 api=API(fixture(mode));connector={'provider':'azure','scopes':[SUB],'options':{'retries':0,'max_pages':1 if mode=='resource_page_limit'else 5,**({'max_resources':1}if mode=='resource_limit'else{})}}
 requirements=plan_collection({'connector':connector,'checks':[CHECK]})
 assert 'resource_diagnostic_setting'in requirements
 snap=azure.collect(connector,requirements,transport=api)
 result=evaluate_snapshot(snap,checks=[CHECK],include_not_applicable=True)['findings']
 assert len(result)==1,result
 assert 'PRIVATE_MARKER'not in json.dumps(snap)
 return result[0],snap,api

@pytest.mark.parametrize('mode,expected',[
 ('good','PASS'),('group','PASS'),('no_groups','PASS'),('disabled','FAIL'),('missing_settings','FAIL'),('missing_workspace','FAIL'),('workspace_not_found','UNKNOWN'),
 ('empty_resources','NOT_APPLICABLE'),('no_categories','NOT_APPLICABLE'),('metrics_only','NOT_APPLICABLE'),
 ('resource_second_page','PASS'),('category_second_page','PASS'),('settings_second_page','PASS'),
 ('unresolved_storage_children','UNKNOWN'),('unmapped_resource','UNKNOWN'),('unmapped_nested','UNKNOWN'),('unmapped_extension','UNKNOWN'),('nested_type_id_mismatch','UNKNOWN'),('extension_type_id_mismatch','UNKNOWN'),('resource_type_id_mismatch','UNKNOWN'),('foreign_resource','UNKNOWN'),('foreign_category','UNKNOWN'),('foreign_setting','UNKNOWN'),('foreign_workspace','UNKNOWN'),('wrong_workspace_type','UNKNOWN'),('foreign_workspace_scope','UNKNOWN'),('traversal_workspace','UNKNOWN'),('query_workspace','UNKNOWN'),('unsupported_sink','UNKNOWN'),
 ('duplicate_resource','UNKNOWN'),('duplicate_category','UNKNOWN'),('duplicate_setting','UNKNOWN'),('category_id_name_mismatch','UNKNOWN'),('category_duplicate_page','UNKNOWN'),('settings_duplicate_page','UNKNOWN'),
 ('missing_logs','UNKNOWN'),('unknown_group','UNKNOWN'),('unknown_category','UNKNOWN'),('malformed_enabled','UNKNOWN'),('malformed_groups','UNKNOWN'),('foreign_continuation','UNKNOWN'),('unsupported_discovery','UNKNOWN'),('workspace_unknown404','UNKNOWN'),
 ('resource_denied','DENIED'),('categories_denied','DENIED'),('settings_denied','DENIED'),('workspace_denied','DENIED'),('resource_partial','DENIED'),('category_partial','DENIED'),('settings_partial','DENIED'),('resource_page_limit','UNKNOWN'),('resource_limit','UNKNOWN')])
def test_actual_arm_shapes_to_frozen_engine(mode,expected):
 finding,snapshot,api=capture(mode)
 assert finding['status']==expected,finding
 assert all('listKeys'not in url and 'secrets/'not in url for url in api.calls)
def test_collect_live_registry_dispatch(monkeypatch):
 api=API(fixture('good'));monkeypatch.setattr(azure,'AzureTransport',lambda auth:api);monkeypatch.setattr(azure,'AzureTransportExposure',lambda auth:api);api.close=lambda:None
 connector={'provider':'azure','scopes':[SUB],'options':{'retries':0}}
 snapshot=collect_live(connector,requirements=['resource_diagnostic_setting'])
 assert evaluate_snapshot(snapshot,checks=[CHECK])['findings'][0]['status']=='PASS'

@pytest.mark.parametrize('mode',['unmapped_resource','unmapped_nested','unmapped_extension'])
def test_valid_unmapped_resource_is_unknown_not_malformed(mode):
 _,snapshot,_=capture(mode)
 collection=next(c for c in snapshot['collections']if c['type']=='resource_diagnostic_setting')
 assert collection['status']=='unknown'
 assert collection['error']['code']=='diagnostic_resource_type_unmapped'
 assert collection['items']==[]

@pytest.mark.parametrize('mode',['nested_type_id_mismatch','extension_type_id_mismatch'])
def test_divergent_nested_type_and_identity_remains_malformed(mode):
 _,snapshot,_=capture(mode)
 collection=next(c for c in snapshot['collections']if c['type']=='resource_diagnostic_setting')
 assert collection['status']=='malformed'
 assert collection['items']==[]
