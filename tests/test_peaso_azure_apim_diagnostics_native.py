# Historical fixture contracts; current native admission is tested separately.
"""Native built-in APIM Azure Monitor logger plus source-bound sink aggregates."""
import copy
from datetime import datetime, timedelta, timezone
import json
from urllib.parse import urlsplit
import pytest
from peaso.collectors import azure, collect_live
from peaso.collectors.azure_apim_diagnostics_native import HTTP_ID, VERBOSE_ID, METHODS_ID, IDS
from tests.archived_check_contract import evaluate_snapshot

SUB='/subscriptions/11111111-1111-1111-1111-111111111111'
SERVICE=SUB+'/resourceGroups/rg/providers/Microsoft.ApiManagement/service/gateway'
API=SERVICE+'/apis/orders'
LOGGER=SERVICE+'/loggers/azuremonitor'
WORKSPACE=SUB+'/resourceGroups/rg/providers/Microsoft.OperationalInsights/workspaces/security'
WGUID='33333333-3333-3333-3333-333333333333'
SETTING=SERVICE+'/providers/Microsoft.Insights/diagnosticSettings/security'
class Denied(RuntimeError):status=403

def capture(monkeypatch,mode='ok',selected_check=None):
 now=datetime.now(timezone.utc);stamp=(now-timedelta(seconds=10)).isoformat()
 window={'start':(now-timedelta(hours=1)).isoformat(),'end':(now-timedelta(seconds=1)).isoformat()}
 if mode=='future_window':window['end']=(now+timedelta(hours=1)).isoformat()
 checks=[{'check_id':cid,'resource_id':SERVICE,'status':'collected','window':window.copy(),**({'requiredApiIds':[API]}if cid==VERBOSE_ID else {'minimumSamplingPercentage':50}if cid==HTTP_ID else{})}for cid in IDS]
 if mode=='foreign_required_api':checks[1]['requiredApiIds']=[API+'other']
 if mode=='duplicate_policy':checks+=copy.deepcopy(checks)
 policy={'status':'collected','scope':SUB+'other'if mode=='foreign_policy'else SUB,'checks':checks}
 props={'loggerId':LOGGER,'verbosity':'information'if mode=='information'else'verbose'if mode=='verbose'else'error','sampling':{'samplingType':'fixed','percentage':0 if mode in('zero_sampling','all_errors')else 100},'frontend':{'request':{'body':{'bytes':0}},'response':{'body':{'bytes':0}}},'backend':{'request':{'body':{'bytes':0}},'response':{'body':{'bytes':0}}}}
 if mode=='all_errors':props['alwaysLog']='allErrors'
 if mode=='missing_sampling':props.pop('sampling')
 if mode=='missing_capture':props.pop('frontend')
 diagnostic={'id':SERVICE+'/diagnostics/azuremonitor','properties':props}
 route={'id':SETTING,'properties':{'workspaceId':WORKSPACE,'logAnalyticsDestinationType':'Dedicated','logs':[{'category':'GatewayLogs','enabled':True}]}}
 if mode=='route_disabled':route['properties']['logs'][0]['enabled']=False
 if mode=='malformed_route':route['properties']['logs'][0]['enabled']='true'
 if mode=='legacy_table':route['properties']['logAnalyticsDestinationType']='AzureDiagnostics'
 if mode=='foreign_route':route['id']=SERVICE+'other/providers/Microsoft.Insights/diagnosticSettings/security'
 if mode=='foreign_workspace':route['properties']['workspaceId']=WORKSPACE.replace('/subscriptions/11111111','/subscriptions/aaaaaaaa')
 api={'id':API,'properties':{'protocols':['https'],'isCurrent':True,'isOnline':True,'apiRevision':'1'}}
 if mode=='missing_revision':api['properties'].pop('apiRevision')
 class Transport:
  tenant=verified_tenant='22222222-2222-2222-2222-222222222222'
  calls=[]
  def close(self):pass
  def request(self,url,*,body=None,audience=azure.ARM):
   self.calls.append((url,body,audience));path=urlsplit(url).path
   if audience==azure.LOGS:
    assert '/v1/workspaces/'+WGUID+'/query'==path
    assert '_ResourceId =~ '+json.dumps(SERVICE.casefold())in body['query']
    assert 'ApiId =~ "orders"'in body['query'] and 'ApiRevision == "1"'in body['query']
    assert 'hash_sha256(tostring(CorrelationId))'in body['query']
    assert 'RequestBody'not in body['query'] and 'RequestHeaders'not in body['query']
    if mode=='logs_denied':raise Denied('SECRET_MUST_NOT_ESCAPE')
    value={'tables':[{'columns':[{'name':name,'type':kind}for name,kind in [('event_count','long'),('last_ingested_at','datetime'),('last_event_at','datetime'),('receipt_ids','dynamic')]],'rows':[[0,None,None,[]]if mode=='no_traffic'else[7,stamp,stamp,['a'*64]]]}]}
    if mode=='partial_logs':value['error']={'code':'PartialError','message':'SECRET_MUST_NOT_ESCAPE'}
    if mode=='bad_hash':value['tables'][0]['rows'][0][3]=['raw-SECRET_MUST_NOT_ESCAPE']
    if mode=='old_receipt':value['tables'][0]['rows'][0][1]='2000-01-01T00:00:00Z'
    return value
   assert audience==azure.ARM
   if path.casefold()=='/providers/microsoft.resourcegraph/resources':return {'data':[{'id':SERVICE,'type':'Microsoft.ApiManagement/service','properties':{}}]}
   if path.casefold()==(SUB+'/resources').casefold():return {'value':[{'id':SERVICE,'type':'Microsoft.ApiManagement/service','properties':{}}]}
   if path.casefold()==(SERVICE+'/workspaces').casefold():
    if mode=='workspace_denied':raise Denied('SECRET_MUST_NOT_ESCAPE')
    return {'value':[{'id':SERVICE+'/workspaces/team'}]if mode=='workspace_present'else[]}
   if path.casefold()==(SUB+'/providers/Microsoft.ApiManagement/service').casefold():
    return {'value':[{'id':SERVICE,'type':'Microsoft.ApiManagement/service','properties':{}}]}
   if path.casefold()==(SERVICE+'/apis').casefold():return {'value':[api]}
   if path.casefold()==(API+'/revisions').casefold():
    value={'value':[{'apiId':API,'isOnline':True,'isCurrent':True}]}
    if mode=='partial_revisions':value['nextLink']='https://evil.test/next'
    return value
   if path.casefold()==(SERVICE+'/loggers').casefold():
    return {'value':[]if mode=='missing_logger'else[{'id':LOGGER,'properties':{'loggerType':'applicationInsights'if mode=='unsupported_logger'else'azureMonitor','credentials':{'key':'SECRET_MUST_NOT_ESCAPE'}}}]}
   if path.casefold()==(SERVICE+'/diagnostics').casefold():return {'value':[]if mode=='no_diagnostic'else[diagnostic]}
   if path.casefold()==(API+'/diagnostics').casefold():
    if mode=='diagnostic_denied':raise Denied('SECRET_MUST_NOT_ESCAPE')
    return {'value':[]}
   if path.casefold()==(API+'/operations').casefold():
    if mode=='operation_denied':raise Denied('SECRET_MUST_NOT_ESCAPE')
    return {'value':[]if mode=='no_operations'else[{'id':API+('other'if mode=='foreign_operation'else'')+'/operations/read','properties':{'method':'GET','urlTemplate':'SECRET_MUST_NOT_ESCAPE'}}]}
   if path.casefold()==(SERVICE+'/providers/Microsoft.Insights/diagnosticSettings').casefold():
    if mode=='route_denied':raise Denied('SECRET_MUST_NOT_ESCAPE')
    return {'value':[]if mode=='no_route'else[route,copy.deepcopy(route)]if mode=='duplicate_route'else[route]}
   if path.casefold()==WORKSPACE.casefold():return {'id':WORKSPACE+'other'if mode=='wrong_workspace_get'else WORKSPACE,'properties':{'customerId':WGUID}}
   return {'value':[]}
 transport=Transport();monkeypatch.setattr(azure,'AzureTransportExposure',lambda auth:transport)
 connector={'provider':'azure','scopes':[SUB],'auth':{'method':'token','arm_token':'fixture','logs_token':'fixture'},'options':{'retries':0,'compliance_policy':{'sw24':policy}}}
 if selected_check:
  from tests.archived_check_contract import collect_snapshot
  snapshot=collect_snapshot({'connector':connector,'checks':[selected_check]})
 else:
  snapshot=collect_live(connector,['azure_sw24_evidence'])
 assert 'SECRET_MUST_NOT_ESCAPE'not in json.dumps(snapshot)
 findings=evaluate_snapshot(snapshot,checks=list(IDS))['findings']
 statuses={cid:[f for f in findings if f['check_id']==cid][-1]['status']for cid in IDS}
 return statuses,snapshot,transport

@pytest.mark.parametrize('mode,http,verbose,methods',[
 ('ok','PASS','PASS','PASS'),('no_diagnostic','FAIL','FAIL','FAIL'),('missing_logger','FAIL','FAIL','FAIL'),
 ('information','PASS','FAIL','PASS'),('verbose','PASS','PASS','FAIL'),('zero_sampling','FAIL','FAIL','FAIL'),
 ('all_errors','FAIL','PASS','FAIL'),('missing_sampling','UNKNOWN','UNKNOWN','UNKNOWN'),
 ('missing_capture','UNKNOWN','UNKNOWN','PASS'),('no_route','FAIL','FAIL','FAIL'),('route_disabled','FAIL','FAIL','FAIL'),
 ('route_denied','UNKNOWN','UNKNOWN','UNKNOWN'),('malformed_route','UNKNOWN','UNKNOWN','UNKNOWN'),
 ('logs_denied','UNKNOWN','PASS','UNKNOWN'),('no_traffic','UNKNOWN','PASS','UNKNOWN'),
 ('unsupported_logger','UNKNOWN','UNKNOWN','UNKNOWN'),('wrong_workspace_get','UNKNOWN','UNKNOWN','UNKNOWN'),
 ('foreign_route','UNKNOWN','UNKNOWN','UNKNOWN'),('duplicate_route','UNKNOWN','UNKNOWN','UNKNOWN'),
 ('foreign_workspace','UNKNOWN','UNKNOWN','UNKNOWN'),('legacy_table','UNKNOWN','UNKNOWN','UNKNOWN'),
 ('diagnostic_denied','UNKNOWN','UNKNOWN','UNKNOWN'),('partial_revisions','UNKNOWN','UNKNOWN','UNKNOWN'),
 ('no_operations','PASS','PASS','NOT_APPLICABLE'),('operation_denied','PASS','PASS','UNKNOWN'),('foreign_operation','PASS','PASS','UNKNOWN'),
 ('missing_revision','UNKNOWN','PASS','UNKNOWN'),('partial_logs','UNKNOWN','PASS','UNKNOWN'),('bad_hash','UNKNOWN','PASS','UNKNOWN'),
 ('old_receipt','UNKNOWN','PASS','UNKNOWN'),('future_window','UNKNOWN','PASS','UNKNOWN'),
 ('foreign_policy','UNKNOWN','UNKNOWN','UNKNOWN'),('duplicate_policy','UNKNOWN','UNKNOWN','UNKNOWN'),
 ('foreign_required_api','PASS','UNKNOWN','PASS'),('workspace_present','UNKNOWN','PASS','UNKNOWN'),('workspace_denied','UNKNOWN','PASS','UNKNOWN')])
def test_native_apim_diagnostics_and_actual_receipts(monkeypatch,mode,http,verbose,methods):
 statuses,_,_=capture(monkeypatch,mode)
 assert statuses=={HTTP_ID:http,VERBOSE_ID:verbose,METHODS_ID:methods}

def test_native_builtin_logger_has_no_invented_credentials_usability(monkeypatch):
 statuses,snapshot,transport=capture(monkeypatch)
 assert all(value=='PASS'for value in statuses.values())
 assert 'credentials_usable'not in json.dumps(snapshot)
 native,=[c for c in snapshot['collections']if c['type']=='apim_native']
 assert native['items'][0]['loggers'][0]['properties']=={'loggerType':'azureMonitor'}
 assert any(audience==azure.LOGS for _,_,audience in transport.calls)


def test_selected_configuration_only_control_performs_no_sink_query(monkeypatch):
 statuses,_,transport=capture(monkeypatch,selected_check=VERBOSE_ID)
 assert statuses[VERBOSE_ID]=='PASS'
 assert not any(audience==azure.LOGS or '/operations?'in url or '/workspaces?'in url for url,_,audience in transport.calls)

def test_same_native_receipt_query_is_cached_across_two_controls(monkeypatch):
 statuses,_,transport=capture(monkeypatch)
 assert statuses[HTTP_ID]==statuses[METHODS_ID]=='PASS'
 assert sum(audience==azure.LOGS for _,_,audience in transport.calls)==1


@pytest.mark.parametrize('mutation',['configuration','read_only','query_hash','policy_hash','customer','foreign_api','future_receipt','negative_count','invalid_hash','foreign_route','duplicate_row'])
def test_native_evidence_cannot_replay_foreign_or_changed_binding(monkeypatch,mutation):
 _,snapshot,_=capture(monkeypatch)
 from peaso.snapshot import make_snapshot
 collection,=[c for c in snapshot['collections']if c['type']=='azure_sw24_evidence']
 row=collection['items'][0]
 for observed in row['observations']:
  if mutation=='query_hash':observed['query_sha256']='0'*64
  if mutation=='policy_hash':observed['policy_sha256']='0'*64
  if mutation=='customer':observed['customer_id']='44444444-4444-4444-4444-444444444444'
  if mutation=='foreign_api':observed['api_id']=API+'other'
  if mutation=='future_receipt':observed['last_ingested_at']='2099-01-01T00:00:00Z'
  if mutation=='negative_count':observed['event_count']=-1
  if mutation=='invalid_hash':observed['receipt_ids']=['raw-request-id']
 if mutation=='configuration':row['configuration_sha256']='0'*64
 if mutation=='read_only':row['_provenance']['read_only']=False
 if mutation=='foreign_route':row['routes'][0]['id']=SERVICE+'other/providers/Microsoft.Insights/diagnosticSettings/security'
 if mutation=='duplicate_row':collection['items'].append(copy.deepcopy(row))
 snapshot=make_snapshot('azure',snapshot['scopes'],snapshot['collections'],metadata=snapshot['metadata'],created_at=snapshot['created_at'])
 findings=evaluate_snapshot(snapshot,checks=list(IDS))['findings']
 statuses={cid:[f for f in findings if f['check_id']==cid][-1]['status']for cid in IDS}
 assert statuses[HTTP_ID]==statuses[METHODS_ID]=='UNKNOWN'
 if mutation in('configuration','read_only','foreign_route','duplicate_row'):assert statuses[VERBOSE_ID]=='UNKNOWN'
 else:assert statuses[VERBOSE_ID]=='PASS'
