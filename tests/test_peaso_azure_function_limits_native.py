"""ARM-shaped collect_live -> frozen engine; no cloud calls or active probes."""
import copy,importlib.util,json,sys
from pathlib import Path
from urllib.parse import urlsplit
import pytest
from peaso.collectors import azure,collect_live
from tests.archived_check_contract import evaluate_snapshot
CID='azure.other.function_invoke_rate_limit'
SUB='/subscriptions/11111111-1111-1111-1111-111111111111';ROOT=SUB+'/resourceGroups/rg/providers/'
SITE=ROOT+'Microsoft.Web/sites/fixture';SERVICE=ROOT+'Microsoft.ApiManagement/service/gateway';API=SERVICE+'/apis/example';OP=API+'/operations/invoke';FUNCTION=SITE+'/functions/invoke'
POLICY={'status':'collected','scope':SUB,'observationStart':'2026-10-01T00:00:00Z','observationEnd':'2026-11-01T00:00:00Z','maxCalls':2,'maxRenewalPeriodSeconds':60,'stableCounterKeys':['caller']}
XML='<policies><inbound/><backend><forward-request/></backend><outbound/><on-error/></policies>'
class Denied(Exception):status_code=403

def capture(monkeypatch,mode='no_limit',**limits):
 site={'id':SITE,'name':'fixture','type':'Microsoft.Web/sites','kind':'functionapp,linux','properties':{'defaultHostName':'fixture.azurewebsites.net'}}
 function={'id':FUNCTION,'type':'Microsoft.Web/sites/functions','properties':{'function_app_id':SITE,'isDisabled':False,'invoke_url_template':'https://fixture.azurewebsites.net/api/invoke','config':{'bindings':[{'type':'httpTrigger','direction':'in','methods':['get']}],'DO_NOT_RETAIN':'SENSITIVE_PAYLOAD'}}}
 api={'id':API,'properties':{'protocols':['https'],'apiRevision':'1','isCurrent':True,'isOnline':True,'serviceUrl':'https://fixture.azurewebsites.net/api'}}
 operation={'id':OP,'type':'Microsoft.ApiManagement/service/apis/operations','properties':{'method':'GET','urlTemplate':'/invoke'}}
 xml=XML
 if mode=='configured_limit':xml=XML.replace('<inbound/>','<inbound><rate-limit-by-key calls="2" renewal-period="60" counter-key="caller"/></inbound>')
 if mode=='inheritance':xml=XML.replace('<inbound/>','<inbound><base/></inbound>')
 if mode=='rewrite':xml=XML.replace('<inbound/>','<inbound><rewrite-uri template="/other"/></inbound>')
 if mode=='expression':xml=XML.replace('<inbound/>','<inbound><set-header name="key"><value>@(context.Variables["SENSITIVE_PAYLOAD"])</value></set-header></inbound>')
 if mode=='masked_xml':xml='<!DOCTYPE policies>'+XML
 if mode=='foreign_function':function['properties']['function_app_id']=SITE+'foreign'
 if mode=='foreign_origin':function['properties']['invoke_url_template']='https://foreign.azurewebsites.net/api/invoke'
 if mode=='dynamic_route':operation['properties']['urlTemplate']='/{name}'
 if mode=='foreign_operation':operation['id']=API+'foreign/operations/invoke'
 if mode=='unmapped_method':function['properties']['config']['bindings'][0]['methods'].append('post')
 class Transport:
  tenant=verified_tenant='aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'
  def __init__(self):self.calls=[]
  def close(self):pass
  def request(self,url,*,body=None,audience=azure.ARM):
   assert audience==azure.ARM and url.startswith(azure.ARM+'/');assert body is None or '/resourcegraph/'in url.casefold()
   self.calls.append((url,body));path=urlsplit(url).path
   if '/resourcegraph/'in path.casefold():return {'data':[],'resultTruncated':False}
   if path==SUB+'/providers/Microsoft.Web/sites':
    if mode=='denied_sites':raise Denied('SENSITIVE_PAYLOAD')
    return {'value':[site]}
   if path==SUB+'/providers/Microsoft.ApiManagement/service':return {'value':[{'id':SERVICE,'name':'gateway','type':'Microsoft.ApiManagement/service','properties':{}}]}
   if path==SITE:return copy.deepcopy(site)
   if path==SITE+'/functions':
    if mode=='denied_functions':raise Denied('SENSITIVE_PAYLOAD')
    if mode=='partial_functions':return {'value':[function],'nextLink':'https://foreign.example/next'}
    return {'value':[]if mode=='empty_functions'else([function,function]if mode=='duplicate_functions'else[function])}
   if path==SITE+'/slots':return {'value':[{'id':SITE+'/slots/production'}]if mode=='slots'else[]}
   if path==SERVICE+'/workspaces':return {'value':[{'id':SERVICE+'/workspaces/workspace'}]if mode=='workspaces'else[]}
   if path==SERVICE+'/apis':return {'value':[api]}
   if path==API:return copy.deepcopy(api)
   if path==API+'/revisions':
    if mode=='denied_revisions':raise Denied('SENSITIVE_PAYLOAD')
    return {'value':[{'apiId':API,'isOnline':True,'isCurrent':True}]}
   if path==API+'/operations':return {'value':[operation,operation]if mode=='duplicate_operations'else[operation]}
   if path==OP+'/policies/policy':
    if mode=='denied_policy':raise Denied('SENSITIVE_PAYLOAD')
    return {'id':OP+('/policies/foreign'if mode=='foreign_policy'else'/policies/policy'),'properties':{'format':'rawxml','value':xml}}
   return {'value':[]}
 t=Transport();monkeypatch.setattr(azure,'AzureTransport',lambda auth:t);monkeypatch.setattr(azure,'AzureTransportExposure',lambda auth:t)
 policy=copy.deepcopy(POLICY)
 if mode=='foreign_approval':policy['scope']='/subscriptions/foreign'
 if mode=='forged_observations':policy['operations_complete']=True
 options={'retries':0,'concurrency':1,'compliance_policy':{'sw15':policy},**limits}
 if mode=='missing_approval':options.pop('compliance_policy')
 try:
  snapshot=collect_live({'provider':'azure','scopes':[SUB],'auth':{'method':'token','arm_token':'fixture'},'options':options},['function_app'])
 except ValueError:
  if mode in ('foreign_approval','forged_observations'):
   assert t.calls==[], 'invalid owner policy must fail before API calls'
  raise
 assert 'SENSITIVE_PAYLOAD'not in json.dumps(snapshot)
 report=evaluate_snapshot(snapshot,checks=[CID]);findings=[f for f in report['findings']if f['check_id']==CID]
 assert len(findings)==1
 return findings[0]['status'],snapshot,t

@pytest.mark.parametrize('mode,expected', [('denied_sites','UNKNOWN'),('duplicate_functions','UNKNOWN'),('duplicate_operations','UNKNOWN'),('denied_revisions','UNKNOWN'),('no_limit','FAIL'),('configured_limit','UNKNOWN'),('inheritance','UNKNOWN'),('rewrite','UNKNOWN'),('expression','UNKNOWN'),('masked_xml','UNKNOWN'),('foreign_function','UNKNOWN'),('foreign_origin','UNKNOWN'),('dynamic_route','UNKNOWN'),('foreign_operation','UNKNOWN'),('unmapped_method','UNKNOWN'),('denied_functions','UNKNOWN'),('partial_functions','UNKNOWN'),('empty_functions','UNKNOWN'),('slots','UNKNOWN'),('workspaces','UNKNOWN'),('denied_policy','UNKNOWN'),('foreign_policy','UNKNOWN'),('foreign_approval','REJECTED_INPUT'),('forged_observations','REJECTED_INPUT'),('missing_approval','UNKNOWN')])
def test_actual_arm_shapes_to_engine(monkeypatch,mode,expected):
 if expected=='REJECTED_INPUT':
  with pytest.raises(ValueError):capture(monkeypatch,mode)
  return
 status,snapshot,t=capture(monkeypatch,mode);assert status==expected
 if mode=='missing_approval':assert not any('/functions?'in u or '/operations?'in u for u,b in t.calls)
 if mode=='no_limit':
  assert any('/functions?api-version=2025-03-01'in u for u,b in t.calls)
  assert any('/policies/policy?format=rawxml'in u for u,b in t.calls)
  fact=next(c for c in snapshot['collections']if c['type']=='function_app')['items'][0]['invocationEvidence']
  assert fact['operations'][0]['function_id']==FUNCTION
  assert 'probe'not in fact['operations'][0]


def test_explicit_resource_budget_cannot_produce_compliance(monkeypatch):
 status,snapshot,t=capture(monkeypatch,max_resources=4);assert status=='UNKNOWN'

@pytest.mark.parametrize('value',[None,[],False,'invalid',{'sw15':[]},{'sw15':{'stableCounterKeys':[{}]}}])
def test_malformed_policy_never_creates_approval(value):
 from peaso.collectors import azure_function_limits_native as helper
 assert helper.owner_policy({'compliance_policy':value},[SUB])is None
 assert helper.required_types({'function_app'},{'compliance_policy':value})>= {'app_service'}
