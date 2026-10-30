"""Native monitor metadata is useful inventory, never fabricated behavior proof."""
import copy,json
from urllib.parse import urlsplit,parse_qs
import pytest
from peaso.collectors import azure,collect_live
from peaso.collectors.azure_monitor_inventory_native import SPECS,GAPS
from tests.archived_check_contract import evaluate_snapshot, collect_snapshot
from tests.test_peaso_azure_bulk_native import Transport,parent,SUB,SCOPE,BASE,envelope,verdict

CHECKS={'data_collection_rule':['azure.other.monitor_stream_auth','azure.other.metric_ingestion_rate_alert'],
        'dashboard':['azure.other.monitor_dashboard_access']}

def capture(kind,mode='good',via='native'):
 typ,version=SPECS[kind];rid=BASE+typ+'/example';path=SCOPE+'/providers/'+typ
 props={'provisioningState':'Succeeded','privateExtra':'private-marker'}
 if kind=='data_collection_rule':props.update(immutableId='dcr-native',streamDeclarations={'Custom-Event':{'columns':[{'name':'message','type':'string','privateExtra':'private-marker'}]}},dataFlows=[{'streams':['Custom-Event'],'destinations':['native-workspace'],'outputStream':'Custom-Output','transformKql':'private-marker'}],dataSources={'extensions':[{'extensionSettings':{'accessToken':'private-marker'}}]})
 else:props.update(lenses=[{'order':0,'parts':[{'metadata':{'inputs':[{'value':'private-marker'}]}}]}],metadata={'public':True,'effectiveAccess':{'viewers':['arbitrary']}})
 raw=parent(rid,typ,props);listed=parent(rid,typ,{'native_list_only':True})
 routes={path:{'value':[listed]},rid:raw}
 if mode=='empty':routes[path]={'value':[]}
 if mode=='denied':routes[path]=azure.AzureReadError('forbidden',403)
 if mode=='get_denied':routes[rid]=azure.AzureReadError('forbidden',403)
 if mode=='spoofed_behavior':raw.update(effectiveAccess={'viewers':[],'public_share_enabled':False,'ancestor_scopes_complete':True,'role_definitions_complete':True,'conditions_resolved':True,'transitive_groups_complete':True,'alternate_sharing_complete':True},streamInventory=[],metricSources=[])
 if mode=='wrong_subscription':listed['id']=rid.replace(SUB,'99999999-9999-9999-9999-999999999999')
 if mode=='wrong_type':listed['type']='Microsoft.Storage/storageAccounts'
 if mode=='wrong_get_id':raw['id']=rid+'other';raw['name']='exampleother'
 if mode=='wrong_get_type':raw['type']='Microsoft.Storage/storageAccounts'
 if mode=='wrong_name':listed['name']='unrelated'
 if mode=='path_escape':listed['id']=rid+'/../foreign'
 if mode=='duplicate':routes[path]['value']*=2
 if mode=='missing_properties':raw.pop('properties')
 if mode=='malformed_properties':raw['properties']=[]
 if mode=='missing_columns'and kind=='data_collection_rule':raw['properties']['streamDeclarations']['Custom-Event']['columns']='not-columns'
 if mode in('paged','partial','cross_scope_page'):
  next_path=path if mode!='cross_scope_page'else path.replace(SUB,'99999999-9999-9999-9999-999999999999')
  next_url=azure.ARM+next_path+'?api-version='+version+'&$skiptoken=next'
  def pages(q):
   if '$skiptoken'in q:
    if mode=='partial':raise azure.AzureReadError('forbidden',403)
    return {'value':[]}
   return {'value':[listed],'nextLink':next_url}
  routes[path]=pages
  if mode=='cross_scope_page':routes[next_path]={'value':[]}
 api=Transport(routes);original=copy.deepcopy(routes);connector={'provider':'azure','scopes':[SUB],'options':{'retries':0},'auth':{'tenant_id':Transport.tenant}}
 if via=='native':snapshot=azure.collect(connector,[kind],transport=api)
 else:
  # Use the public dispatcher/planner while preserving the real native collector.
  old=azure.AzureTransportExposure
  api.close=lambda:None
  try:
   azure.AzureTransportExposure=lambda auth:api
   snapshot=collect_live(connector,[kind])if via=='dispatcher'else collect_snapshot({'connector':connector,'checks':CHECKS[kind]})
  finally:azure.AzureTransportExposure=old
 assert 'private-marker'not in json.dumps(snapshot)
 collection=envelope(snapshot,kind)
 if mode in('good','paged'):
  assert any(urlsplit(u).path==rid for u in api.calls)
  row=collection['items'][0]
  assert row['_provenance']['representation']=='projected_native_metadata'
  assert set(row['_coverage'])==set(GAPS[kind])
  assert all(v['status']=='not_collected'for v in row['_coverage'].values())
  assert 'effectiveAccess'not in row and 'streamInventory'not in row and 'metricSources'not in row
  assert raw==original[rid]
 return snapshot,api,collection

@pytest.mark.parametrize('kind',list(SPECS))
@pytest.mark.parametrize('mode,status',[('good','collected'),('paged','collected'),('empty','empty'),('denied','denied'),('get_denied','denied'),('partial','partial'),('cross_scope_page','partial'),('wrong_subscription','malformed'),('wrong_type','malformed'),('wrong_get_id','malformed'),('wrong_get_type','malformed'),('wrong_name','malformed'),('path_escape','malformed'),('duplicate','malformed'),('missing_properties','malformed'),('malformed_properties','malformed')])
def test_exact_native_inventory_boundaries(kind,mode,status):
 snapshot,api,c=capture(kind,mode)
 assert c['status']==status,(c,api.calls)
 assert set(c['semantic_coverage'])==set(GAPS[kind])
 if mode=='cross_scope_page':assert all('99999999-9999-9999-9999-999999999999'not in url for url in api.calls)

@pytest.mark.parametrize('kind',list(SPECS))
def test_native_metadata_cannot_pass_behavioral_control(kind):
 snapshot,_,_=capture(kind)
 for check in CHECKS[kind]:assert verdict(snapshot,check)=='UNKNOWN'

def test_native_malformed_declared_columns_fail_closed():
 assert capture('data_collection_rule','missing_columns')[2]['status']=='malformed'


@pytest.mark.parametrize('kind',list(SPECS))
@pytest.mark.parametrize('via',['dispatcher','planner'])
def test_public_live_pipeline_keeps_semantic_unknown(kind,via):
 snapshot,_,collection=capture(kind,via=via)
 assert collection['status']=='collected'
 assert snapshot['metadata']['tenant_id']==Transport.tenant
 assert snapshot['metadata']['tenant_verified']is True
 for check in CHECKS[kind]:assert verdict(snapshot,check)=='UNKNOWN'


@pytest.mark.parametrize('kind',list(SPECS))
def test_arm_metadata_cannot_inject_effective_or_behavioral_flags(kind):
 snapshot,_,collection=capture(kind,'spoofed_behavior')
 row=collection['items'][0]
 assert not set(row).intersection({'effectiveAccess','streamInventory','metricSources'})
 for check in CHECKS[kind]:assert verdict(snapshot,check)=='UNKNOWN'

@pytest.mark.parametrize('kind',list(SPECS))
def test_empty_native_inventory_does_not_fabricate_policy_or_not_applicability(kind):
 snapshot,_,collection=capture(kind,'empty')
 assert collection['status']=='empty'and collection['items']==[]
 for check in CHECKS[kind]:assert verdict(snapshot,check)=='UNKNOWN'
