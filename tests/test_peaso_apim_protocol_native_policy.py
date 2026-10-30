# Historical fixture contracts; current native admission is tested separately.
"""Synthetic native-shaped collect->signed public evaluator boundaries."""
import copy
from datetime import datetime,timedelta,timezone
from urllib.parse import urlsplit
import pytest
from peaso.collectors import azure
from tests.archived_check_contract import collect_snapshot, evaluate_snapshot
from peaso.collectors.azure_apim_protocol_policy import CID,SPEC
S='/subscriptions/11111111-1111-1111-1111-111111111111'
T='22222222-2222-2222-2222-222222222222'
P=S+'/resourceGroups/rg/providers/Microsoft.ApiManagement/service/main'
A=P+'/apis/orders'
@pytest.mark.parametrize('mode,expected',[
 ('ok','PASS'),('http','FAIL'),('extra','FAIL'),('empty','FAIL'),('unknown','UNKNOWN'),
 ('missing','UNKNOWN'),('no-policy','UNKNOWN'),('expired','UNKNOWN'),('scope','UNKNOWN'),
 ('spec','UNKNOWN'),('foreign-rule','UNKNOWN'),('contradiction','UNKNOWN'),('duplicate','UNKNOWN'),
 ('case-duplicate','UNKNOWN'),('foreign-api','UNKNOWN'),('partial','UNKNOWN'),('denied','UNKNOWN'),
 ('revision-get','PASS'),('no-apis','NOT_APPLICABLE'),('conflicting-duplicate','UNKNOWN'),('revision-duplicate','UNKNOWN')])
def test_public_native_protocol_policy(monkeypatch,mode,expected):
 now=datetime.now(timezone.utc)
 rules={A:{'expected_endpoint_type':'https','forbidden_protocols':['http']}}
 if mode=='revision-get':rules[A+';rev=2']=copy.deepcopy(rules[A])
 if mode=='no-apis':rules={}
 pol={'status':'collected','scope':S,'authorized_by':'synthetic-owner','document_id':'synthetic-policy',
      'observed_at':(now-timedelta(hours=1)).isoformat(),'expires_at':(now+timedelta(hours=1)).isoformat(),
      'apim_protocols':{P:{'proposed_spec_sha256':SPEC,'apis':rules}}}
 if mode=='expired':pol['expires_at']=(now-timedelta(minutes=1)).isoformat()
 if mode=='scope':pol['scope']=S+'foreign'
 if mode=='spec':pol['apim_protocols'][P]['proposed_spec_sha256']='0'*64
 if mode=='foreign-rule':rules[A+'foreign']=rules.pop(A)
 if mode=='contradiction':rules[A]['forbidden_protocols']+=['https']
 if mode=='case-duplicate':rules[A.upper()]=copy.deepcopy(rules[A])
 values={'http':['http'],'extra':['http','https'],'empty':[],'unknown':['ftp']}.get(mode,['https'])
 raw={'id':A,'properties':{'protocols':values,'isCurrent':True}}
 if mode=='missing':del raw['properties']['protocols']
 if mode=='foreign-api':raw['id']=P+'foreign/apis/orders'
 rows=[]if mode=='no-apis'else[raw]
 if mode=='duplicate':rows.append(copy.deepcopy(raw))
 if mode=='conflicting-duplicate':rows.append({'id':A,'properties':{'protocols':['http']}})
 before=copy.deepcopy(rows)
 class Denied(RuntimeError):status=403
 class Transport:
  tenant=verified_tenant=T
  def __init__(self):self.calls=[]
  def close(self):pass
  def request(self,url,*,body=None,audience=azure.ARM):
   self.calls.append(url);assert body is None and audience==azure.ARM
   path=urlsplit(url).path.casefold()
   sub={'id':S,'subscriptionId':S.split('/')[-1],'tenantId':T,'state':'Enabled'}
   parent={'id':P,'type':'Microsoft.ApiManagement/service','properties':{}}
   if path=='/subscriptions':return{'value':[sub]}
   if path==S.casefold():return sub
   if path==(S+'/providers/Microsoft.ApiManagement/service').casefold():return{'value':[parent]}
   if path==P.casefold():return parent
   if path==(P+'/apis').casefold():return{'value':copy.deepcopy(rows),**({'nextLink':'https://foreign.invalid/next'}if mode=='partial'else{})}
   if path==(A+'/revisions').casefold():
    if mode=='denied':raise Denied('INERT-SECRET')
    rev=[{'apiId':A,'isOnline':True,'isCurrent':True}]
    if mode=='revision-duplicate':rev.append(copy.deepcopy(rev[0]))
    if mode=='revision-get':rev.append({'apiId':A+';rev=2','isOnline':True,'isCurrent':False})
    return{'value':rev}
   if path==(A+';rev=2').casefold():return{'id':A+';rev=2','properties':{'protocols':['https']}}
   return{'value':[]}
 transport=Transport();monkeypatch.setattr(azure,'AzureTransport',lambda auth:transport);monkeypatch.setattr(azure,'AzureTransportExposure',lambda auth:transport)
 connector={'provider':'azure','scopes':[S],'auth':{'method':'token','arm_token':'INERT-TOKEN'},
            'options':{'retries':0,'compliance_policy':{}if mode=='no-policy'else{'sw23':pol}}}
 original=copy.deepcopy(connector)
 snapshot=collect_snapshot({'connector':connector,'checks':[CID]})
 result=[f for f in evaluate_snapshot(snapshot,checks=[CID])['findings']if f['check_id']==CID]
 assert len(result)==1 and result[0]['status']==expected,result
 assert rows==before and connector==original
 assert 'INERT-TOKEN'not in str(snapshot)and'INERT-SECRET'not in str(snapshot)
 assert any(urlsplit(u).path.casefold()==(P+'/apis').casefold()for u in transport.calls)
 for c in snapshot['collections']:
  if c['type']=='apim_api_evidence'and c['status']=='collected':
   assert all(r['_provenance']['captured_at']==snapshot['created_at']for r in c['items'])
 if mode=='revision-get':assert any(urlsplit(u).path.casefold()==(A+';rev=2').casefold()for u in transport.calls)

def test_conflicting_diagnostic_ids_reach_public_engine_as_unknown():
 import importlib.util
 from pathlib import Path
 spec=importlib.util.spec_from_file_location('protocol_regression_apim_fixtures',Path(__file__).with_name('test_azure_apim_native.py'))
 fixtures=importlib.util.module_from_spec(spec);spec.loader.exec_module(fixtures)
 pages=fixtures._pages()
 rows=pages[fixtures.API+'/diagnostics'+fixtures.VERSION]['value']
 contradicting=copy.deepcopy(rows[0]);contradicting['properties']['sampling']['percentage']=0
 rows.append(contradicting)
 snapshot,_,_,_=fixtures._produce(pages)
 findings=[f for f in evaluate_snapshot(snapshot,checks=[fixtures.CHECK.INSIGHTS_ID])['findings']if f['check_id']==fixtures.CHECK.INSIGHTS_ID]
 assert len(findings)==1 and findings[0]['status']=='UNKNOWN',findings

def test_projection_is_inert_for_unrelated_inventory():
 from types import SimpleNamespace
 from peaso.collectors.azure_apim_protocol_policy import project
 reader=SimpleNamespace(collections=[])
 assert project(reader,[S],{'nsg'},{},'native-original-clock')=='native-original-clock'
 assert reader.collections==[]

# V2: present native totals are promises about all pages, not page lengths.
_ABSENT=object()
_COUNT_CASES=[
 ('optional-absent',_ABSENT,'PASS'),('exact-one',1,'PASS'),('truncated-total',2,'UNKNOWN'),
 ('zero-with-row',0,'UNKNOWN'),('negative',-1,'UNKNOWN'),('bool-true',True,'UNKNOWN'),
 ('bool-false',False,'UNKNOWN'),('null',None,'UNKNOWN'),('string','1','UNKNOWN'),
 ('float',1.0,'UNKNOWN'),('object',{},'UNKNOWN'),('array',[],'UNKNOWN')]
@pytest.mark.parametrize('segment',['apis','revisions'])
@pytest.mark.parametrize('label,count,expected',_COUNT_CASES,ids=[v[0]for v in _COUNT_CASES])
def test_present_count_types_and_terminal_totals(monkeypatch,segment,label,count,expected):
 path=P+'/apis'if segment=='apis'else A+'/revisions'
 class Patch:
  def setattr(self,module,name,factory):
   def wrapped(auth):
    delegate=factory(auth)
    class Proxy:
     def __getattr__(self,key):return getattr(delegate,key)
     def request(self,url,**kwargs):
      value=delegate.request(url,**kwargs)
      if urlsplit(url).path.casefold()==path.casefold()and count is not _ABSENT:value['count']=copy.deepcopy(count)
      return value
    return Proxy()
   monkeypatch.setattr(module,name,wrapped)
 test_public_native_protocol_policy(Patch(),'ok',expected)

_PAGE_CASES=[
 ('stable',1,1,'PASS'),('first-only',1,_ABSENT,'PASS'),('last-only',_ABSENT,1,'PASS'),
 ('absent-both',_ABSENT,_ABSENT,'PASS'),('changed-total',2,1,'UNKNOWN'),
 ('changed-zero',0,1,'UNKNOWN'),('stable-truncated',2,2,'UNKNOWN'),('last-null',1,None,'UNKNOWN')]
@pytest.mark.parametrize('segment',['apis','revisions'])
@pytest.mark.parametrize('label,first,last,expected',_PAGE_CASES,ids=[v[0]for v in _PAGE_CASES])
def test_count_total_across_pages(monkeypatch,segment,label,first,last,expected):
 from urllib.parse import parse_qs
 path=P+'/apis'if segment=='apis'else A+'/revisions'
 class Patch:
  def setattr(self,module,name,factory):
   def wrapped(auth):
    delegate=factory(auth)
    class Proxy:
     def __getattr__(self,key):return getattr(delegate,key)
     def request(self,url,**kwargs):
      value=delegate.request(url,**kwargs)
      if urlsplit(url).path.casefold()==path.casefold():
       terminal='v2countpage'in parse_qs(urlsplit(url).query)
       count=last if terminal else first
       if not terminal:value={'value':[],'nextLink':azure.ARM+path+'?api-version=2024-05-01&v2countpage=2'}
       if count is not _ABSENT:value['count']=copy.deepcopy(count)
      return value
    return Proxy()
   monkeypatch.setattr(module,name,wrapped)
 test_public_native_protocol_policy(Patch(),'ok',expected)

def test_page_cap_never_turns_declared_total_into_complete_inventory():
 from peaso.collectors.azure import _Reader
 from peaso.collectors.azure_apim_native import _read,_api
 reader=_Reader({'max_pages':1,'retries':0})
 def request(url,**kwargs):
  return{'count':2,'value':[{'id':A,'properties':{'protocols':['https']}}],
         'nextLink':azure.ARM+P+'/apis?api-version=2024-05-01&page=2'}
 value=_read(reader,request,P,'apis',_api)
 assert value['status']=='partial'and value['error']['code']=='page_limit'

@pytest.mark.parametrize('placement',['first','last','both'])
def test_total_counts_rows_across_nonempty_pages(placement):
 from peaso.collectors.azure import _Reader
 from peaso.collectors.azure_apim_native import _read,_api
 from urllib.parse import parse_qs
 reader=_Reader({'retries':0})
 def request(url,**kwargs):
  terminal='countpage'in parse_qs(urlsplit(url).query)
  value={'value':[{'id':A+';rev=2'if terminal else A,'properties':{'protocols':['https']}}]}
  if not terminal:value['nextLink']=azure.ARM+P+'/apis?api-version=2024-05-01&countpage=2'
  if placement=='both'or placement==('last'if terminal else'first'):value['count']=2
  return value
 value=_read(reader,request,P,'apis',_api)
 assert value['status']=='collected'and len(value['items'])==2

def test_explicit_zero_count_accepts_complete_empty_result():
 from peaso.collectors.azure import _Reader
 from peaso.collectors.azure_apim_native import _read,_api
 reader=_Reader({'retries':0})
 value=_read(reader,lambda *a,**k:{'count':0,'value':[]},P,'apis',_api)
 assert value['status']=='empty'and value['items']==[]

# V3: service-relative apiId is an actual ARM revision LIST representation.
_REAL_REVISION_ROW={'id':'/apis/owned-protocol;rev=1/revisions/owned-protocol;rev=1',
                    'apiId':'/apis/owned-protocol;rev=1','isOnline':True,'isCurrent':True}

def test_actual_relative_revision_row_is_bound_to_exact_service_without_mutation():
 from peaso.collectors.azure import _Reader
 from peaso.collectors.azure_apim_native import _read,_revision
 parent=P+'/apis/owned-protocol';raw=copy.deepcopy(_REAL_REVISION_ROW);before=copy.deepcopy(raw)
 reader=_Reader({'retries':0})
 value=_read(reader,lambda *a,**k:{'count':1,'value':[raw]},parent,'revisions',_revision,response_id='apiId')
 assert value['status']=='collected'and value['items'][0]['id']==parent+';rev=1'
 assert value['items'][0]['isOnline']is True and value['items'][0]['isCurrent']is True
 assert raw==before

@pytest.mark.parametrize('rid',[
 '/apis/other;rev=1','//apis/orders;rev=1','apis/orders;rev=1',
 '/apis/orders/../other','/apis/../orders','/apis/orders;rev=1?x=1',
 '/apis/orders;rev=1#fragment','/apis/%6frders;rev=1','/apis/orders;rev=%31',
 '/apis/orders;rev=1%2fother','/apis/orders;rev=1/revisions/one',
 '/apis/orders;rev=1;extra=2','/apis/orders;rev=', '/apis/orders;rev=../x',
 '/apis/orders;rev=1\\other','/apis/orders;rev=1\n',None,False,
 P+'foreign/apis/orders;rev=1',S+'foreign/resourceGroups/rg/providers/Microsoft.ApiManagement/service/main/apis/orders;rev=1',
 A+';rev=1?x=1',A+';rev=%31'])
def test_relative_revision_rejects_foreign_or_ambiguous_identity(rid):
 from peaso.collectors.azure_apim_native import _revision_id
 with pytest.raises(ValueError):_revision_id(rid,A)

@pytest.mark.parametrize('rid',[A,A+';rev=2','/apis/orders','/apis/orders;rev=2'])
def test_absolute_and_relative_revision_spellings_share_same_bound_identity(rid):
 from peaso.collectors.azure_apim_native import _revision_id
 expected=A+';rev=2'if';rev='in rid else A
 assert _revision_id(rid,A)==expected

@pytest.mark.parametrize('parent',[
 'https://foreign.invalid/apis/orders',P+'foreign/../main/apis/orders',
 P+'/apis/%6frders',P+'/apis/orders?x=1',P+'//apis/orders',None])
def test_relative_revision_requires_verified_unambiguous_ARM_parent(parent):
 from peaso.collectors.azure_apim_native import _revision_id
 with pytest.raises(ValueError):_revision_id('/apis/orders;rev=1',parent)

def test_relative_and_absolute_duplicate_revision_aliases_stay_unresolved():
 from peaso.collectors.azure import _Reader
 from peaso.collectors.azure_apim_native import _read,_revision
 reader=_Reader({'retries':0})
 rows=[{'apiId':'/apis/orders;rev=1','isOnline':True,'isCurrent':True},
       {'apiId':A+';rev=1','isOnline':True,'isCurrent':True}]
 value=_read(reader,lambda *a,**k:{'count':2,'value':rows},A,'revisions',_revision,response_id='apiId')
 assert value['status']not in ('collected','empty')

def test_relative_native_rows_do_not_weaken_total_count_reconciliation():
 from peaso.collectors.azure import _Reader
 from peaso.collectors.azure_apim_native import _read,_revision
 reader=_Reader({'retries':0})
 value=_read(reader,lambda *a,**k:{'count':2,'value':[copy.deepcopy(_REAL_REVISION_ROW)]},P+'/apis/owned-protocol','revisions',_revision,response_id='apiId')
 assert value['status']not in ('collected','empty')

@pytest.mark.parametrize('mode,expected',[('https','PASS'),('http','FAIL'),('missing-revision-approval','UNKNOWN')])
def test_actual_relative_revision_shape_through_public_collection_and_signed_engine(monkeypatch,mode,expected):
 api=P+'/apis/owned-protocol';revision=api+';rev=1';now=datetime.now(timezone.utc)
 rule={'expected_endpoint_type':'https','forbidden_protocols':['http']}
 rules={api:copy.deepcopy(rule),revision:copy.deepcopy(rule)}
 if mode=='missing-revision-approval':rules.pop(revision)
 owner={'status':'collected','scope':S,'authorized_by':'synthetic-owned-fixture-criteria','document_id':'synthetic-v3-rule-register',
        'observed_at':(now-timedelta(hours=1)).isoformat(),'expires_at':(now+timedelta(hours=1)).isoformat(),
        'apim_protocols':{P:{'proposed_spec_sha256':SPEC,'apis':rules}}}
 raw=copy.deepcopy(_REAL_REVISION_ROW);before=copy.deepcopy(raw)
 class Transport:
  tenant=verified_tenant=T
  def __init__(self):self.calls=[]
  def close(self):pass
  def request(self,url,*,body=None,audience=azure.ARM):
   self.calls.append(url);assert body is None and audience==azure.ARM
   path=urlsplit(url).path.casefold();sub={'id':S,'subscriptionId':S.split('/')[-1],'tenantId':T,'state':'Enabled'}
   parent={'id':P,'type':'Microsoft.ApiManagement/service','properties':{}}
   if path=='/subscriptions':return{'value':[sub]}
   if path==S.casefold():return sub
   if path==(S+'/providers/Microsoft.ApiManagement/service').casefold():return{'value':[parent]}
   if path==P.casefold():return parent
   if path==(P+'/apis').casefold():return{'count':1,'value':[{'id':api,'properties':{'protocols':['https'],'isCurrent':True}}]}
   if path==(api+'/revisions').casefold():return{'count':1,'value':[copy.deepcopy(raw)]}
   if path==revision.casefold():return{'id':revision,'properties':{'protocols':['http'if mode=='http'else'https'],'isCurrent':True}}
   return{'count':0,'value':[]}
 transport=Transport();monkeypatch.setattr(azure,'AzureTransport',lambda auth:transport);monkeypatch.setattr(azure,'AzureTransportExposure',lambda auth:transport)
 connector={'provider':'azure','scopes':[S],'auth':{'method':'token','arm_token':'INERT-TOKEN'},
            'options':{'retries':0,'compliance_policy':{'sw23':owner}}};original=copy.deepcopy(connector)
 snapshot=collect_snapshot({'connector':connector,'checks':[CID]})
 findings=[f for f in evaluate_snapshot(snapshot,checks=[CID])['findings']if f['check_id']==CID]
 assert len(findings)==1 and findings[0]['status']==expected,findings
 assert raw==before and connector==original and'INERT-TOKEN'not in str(snapshot)
 assert any(urlsplit(url).path.casefold()==revision.casefold()for url in transport.calls)
 assert all('foreign.invalid'not in url for url in transport.calls)

# V4: native current revision GET may return the base API identity.
@pytest.mark.parametrize('mode,expected',[
 ('https','PASS'),('http','FAIL'),('no-policy','UNKNOWN'),('missing-revision-approval','UNKNOWN'),
 ('foreign-service','UNKNOWN'),('foreign-api','UNKNOWN'),('relative-body','UNKNOWN'),
 ('other-revision-body','UNKNOWN'),('query-body','UNKNOWN'),('encoded-body','UNKNOWN'),
 ('get-revision-mismatch','UNKNOWN'),('get-revision-missing','UNKNOWN'),
 ('get-revision-int','UNKNOWN'),('get-revision-bool','UNKNOWN'),('get-revision-null','UNKNOWN'),
 ('get-current-false','UNKNOWN'),('get-current-missing','UNKNOWN'),('get-current-int','UNKNOWN'),
 ('base-revision-mismatch','UNKNOWN'),('base-revision-missing','UNKNOWN'),
 ('base-revision-int','UNKNOWN'),('base-current-false','UNKNOWN'),('base-current-int','UNKNOWN'),
 ('base-current-missing','UNKNOWN'),('list-current-false','UNKNOWN'),
 ('list-offline','UNKNOWN'),('list-two-current','UNKNOWN'),('list-total-short','UNKNOWN'),
 ('missing-base','UNKNOWN'),('get-props-null','UNKNOWN'),('get-id-null','UNKNOWN'),
 ('exact-id-noncurrent','PASS')])
def test_current_base_id_alias_collect_to_signed_engine(monkeypatch,mode,expected):
 api=P+'/apis/owned-protocol';revision=api+';rev=1';now=datetime.now(timezone.utc)
 rule={'expected_endpoint_type':'https','forbidden_protocols':['http']}
 rules={api:copy.deepcopy(rule),revision:copy.deepcopy(rule)}
 if mode=='missing-revision-approval':rules.pop(revision)
 owner={'status':'collected','scope':S,'authorized_by':'synthetic-owned-fixture-criteria','document_id':'synthetic-v4-rule-register',
        'observed_at':(now-timedelta(hours=1)).isoformat(),'expires_at':(now+timedelta(hours=1)).isoformat(),
        'apim_protocols':{P:{'proposed_spec_sha256':SPEC,'apis':rules}}}
 listed={'id':api,'properties':{'protocols':['https'],'apiRevision':'1','isCurrent':True}}
 returned={'id':api,'properties':{'protocols':['http'if mode=='http'else'https'],'apiRevision':'1','isCurrent':True}}
 revrows=[dict(copy.deepcopy(_REAL_REVISION_ROW),apiRevision='1')]
 replacements={'foreign-service':P+'foreign/apis/owned-protocol','foreign-api':P+'/apis/foreign',
               'relative-body':'/apis/owned-protocol','other-revision-body':api+';rev=2',
               'query-body':api+'?x=1','encoded-body':api.replace('owned','%6fwned'),'get-id-null':None}
 if mode in replacements:returned['id']=replacements[mode]
 for prefix,row in [('get',returned),('base',listed)]:
  if mode==prefix+'-revision-mismatch':row['properties']['apiRevision']='2'
  if mode==prefix+'-revision-missing':row['properties'].pop('apiRevision')
  if mode==prefix+'-revision-int':row['properties']['apiRevision']=1
  if mode==prefix+'-revision-bool':row['properties']['apiRevision']=True
  if mode==prefix+'-revision-null':row['properties']['apiRevision']=None
  if mode==prefix+'-current-false':row['properties']['isCurrent']=False
  if mode==prefix+'-current-int':row['properties']['isCurrent']=1
  if mode==prefix+'-current-missing':row['properties'].pop('isCurrent')
 if mode=='list-current-false':revrows[0]['isCurrent']=False
 if mode=='list-offline':revrows[0]['isOnline']=False
 if mode=='list-two-current':revrows.append({'apiId':'/apis/owned-protocol;rev=2','isOnline':False,'isCurrent':True})
 if mode=='missing-base':listed={'id':api+';rev=2','properties':{'protocols':['https'],'apiRevision':'2','isCurrent':False}}
 if mode=='get-props-null':returned['properties']=None
 if mode=='exact-id-noncurrent':returned['id']=revision;returned['properties']['isCurrent']=False;revrows[0]['isCurrent']=False
 source=copy.deepcopy((listed,returned,revrows))
 class Transport:
  tenant=verified_tenant=T
  def __init__(self):self.calls=[]
  def close(self):pass
  def request(self,url,*,body=None,audience=azure.ARM):
   self.calls.append(url);assert body is None and audience==azure.ARM
   path=urlsplit(url).path.casefold();sub={'id':S,'subscriptionId':S.split('/')[-1],'tenantId':T,'state':'Enabled'}
   parent={'id':P,'type':'Microsoft.ApiManagement/service','properties':{}}
   if path=='/subscriptions':return{'value':[sub]}
   if path==S.casefold():return sub
   if path==(S+'/providers/Microsoft.ApiManagement/service').casefold():return{'value':[parent]}
   if path==P.casefold():return parent
   if path==(P+'/apis').casefold():return{'count':1,'value':[listed]}
   if path==(api+'/revisions').casefold():return{'count':2 if mode=='list-total-short'else len(revrows),'value':revrows}
   if path==revision.casefold():return returned
   return{'count':0,'value':[]}
 transport=Transport();monkeypatch.setattr(azure,'AzureTransport',lambda auth:transport);monkeypatch.setattr(azure,'AzureTransportExposure',lambda auth:transport)
 connector={'provider':'azure','scopes':[S],'auth':{'method':'token','arm_token':'INERT-TOKEN'},
            'options':{'retries':0,'compliance_policy':{}if mode=='no-policy'else{'sw23':owner}}};before=copy.deepcopy(connector)
 snapshot=collect_snapshot({'connector':connector,'checks':[CID]})
 findings=[f for f in evaluate_snapshot(snapshot,checks=[CID])['findings']if f['check_id']==CID]
 assert len(findings)==1 and findings[0]['status']==expected,findings
 assert (listed,returned,revrows)==source and connector==before and 'INERT-TOKEN'not in str(snapshot)
 facts=next(c for c in snapshot['collections']if c['type']=='apim_native')['items'][0]
 if mode in ('https','http','no-policy','missing-revision-approval'):
  hydrated=next(a for a in facts['apis']if a['id']==revision)
  assert hydrated['_provenance']['native_response_id']==api
  assert hydrated['_provenance']['requested_api_id']==revision
  assert hydrated['_provenance']['identity_binding']=='current_revision_LIST_and_base_API_LIST'
  assert facts['_coverage']['revisions']['status']=='collected'
 elif mode not in ('list-offline','exact-id-noncurrent'):
  assert facts['_coverage']['revisions']['status']=='partial'
 assert all('foreign.invalid'not in url for url in transport.calls)


# Hosted intake criteria: portable installed imports, isolated names.
from types import SimpleNamespace as HOSTED_SimpleNamespace
from peaso.server import native_policy_validation as HOSTED_native

HOSTED_S='/subscriptions/11111111-1111-1111-1111-111111111111'

HOSTED_P=HOSTED_S+'/resourceGroups/owned/providers/Microsoft.ApiManagement/service/owned'

HOSTED_A=HOSTED_P+'/apis/owned-protocol'

HOSTED_SPEC='0d01a758e49f3c58bbb3c169ba87576979a3bfe01c97bc33859ee849b8d45f78'

def HOSTED_policy():
    now=datetime.now(timezone.utc)
    return {'status':'collected','scope':HOSTED_S,'authorized_by':'owned-lab-reviewer','document_id':'owned-lab-protocol-register',
            'observed_at':(now-timedelta(minutes=1)).isoformat(),'expires_at':(now+timedelta(hours=1)).isoformat(),
            'apim_protocols':{HOSTED_P:{'proposed_spec_sha256':HOSTED_SPEC,'apis':{HOSTED_A:{'expected_endpoint_type':'https','forbidden_protocols':['http']},HOSTED_A+';rev=1':{'expected_endpoint_type':'https','forbidden_protocols':['http']}}}}}

@pytest.mark.parametrize('path',['intake','cognito'])
def test_HOSTED_accepted_owner_requirements(path):
    value=HOSTED_policy();before=copy.deepcopy(value)
    if path=='intake':HOSTED_native.azure_detection({'sw23':value})
    else:
        from peaso.server.validation import validate_connector
        validate_connector('azure',{'method':'token','arm_token':'INERT-OFFLINE'}, {'compliance_policy':{'sw23':value}},HOSTED_SimpleNamespace(auth_mode='cognito'))
    assert value==before

@pytest.mark.parametrize('mode',['foreign-scope','foreign-api','root-observation','snapshot','api-observation','service-evidence','expired','future','unaware','missing-owner','missing-document','missing-date','duplicate-services','duplicate-apis','spec','unknown-protocol','duplicate-protocol','contradiction','string-forbidden','rule-list','empty-services','encoded-api','path-traversal','huge-map','oversize','depth','existing-namespace-unknown'])
@pytest.mark.parametrize('path',['intake','cognito'])
def test_HOSTED_rejected_owner_inputs(mode,path):
    value=HOSTED_policy();service=value['apim_protocols'][HOSTED_P];rules=service['apis'];rule=rules[HOSTED_A]
    if mode=='foreign-scope':value['scope']=HOSTED_S[:-1]+'2'
    elif mode=='foreign-api':rules[HOSTED_A.replace('/owned-protocol','/elsewhere/owned-protocol')]=rules.pop(HOSTED_A)
    elif mode=='root-observation':value['protocols']=['https']
    elif mode=='snapshot':value['collections']=[]
    elif mode=='api-observation':rule['protocols']=['https']
    elif mode=='service-evidence':service['source_requests']=[]
    elif mode=='expired':value['expires_at']=(datetime.now(timezone.utc)-timedelta(seconds=1)).isoformat()
    elif mode=='future':value['observed_at']=(datetime.now(timezone.utc)+timedelta(minutes=1)).isoformat()
    elif mode=='unaware':value['observed_at']='2026-10-15T12:00:00'
    elif mode=='missing-owner':value.pop('authorized_by')
    elif mode=='missing-document':value['document_id']=' '
    elif mode=='missing-date':value.pop('expires_at')
    elif mode=='duplicate-services':value['apim_protocols'][HOSTED_P.upper()]=copy.deepcopy(service)
    elif mode=='duplicate-apis':rules[HOSTED_A.upper()]=copy.deepcopy(rule)
    elif mode=='spec':service['proposed_spec_sha256']='0'*64
    elif mode=='unknown-protocol':rule['expected_endpoint_type']='ftp'
    elif mode=='duplicate-protocol':rule['forbidden_protocols']=['http','http']
    elif mode=='contradiction':rule['forbidden_protocols']=['https']
    elif mode=='string-forbidden':rule['forbidden_protocols']='http'
    elif mode=='rule-list':rules[HOSTED_A]=[]
    elif mode=='empty-services':value['apim_protocols']={}
    elif mode=='encoded-api':rules[HOSTED_A+'%2fescape']=rules.pop(HOSTED_A)
    elif mode=='path-traversal':rules[HOSTED_P+'/apis/..']=rules.pop(HOSTED_A)
    elif mode=='huge-map':value['apim_protocols']={str(n):{}for n in range(257)}
    elif mode=='oversize':value['document_id']='x'*50001
    elif mode=='depth':
        obj={};value['injected']=obj
        for _ in range(16):obj['x']={};obj=obj['x']
    if path=='intake':
        with pytest.raises((ValueError,TypeError)):HOSTED_native.azure_detection({'unknown'if mode=='existing-namespace-unknown'else'sw23':value})
    else:
        from peaso.server.validation import validate_connector
        from fastapi import HTTPException
        with pytest.raises(HTTPException) as error:
            validate_connector('azure',{'method':'token','arm_token':'INERT-OFFLINE'}, {'compliance_policy':{'unknown'if mode=='existing-namespace-unknown'else'sw23':value}},HOSTED_SimpleNamespace(auth_mode='cognito'))
        assert error.value.status_code==422

@pytest.mark.parametrize("provider", ["aws", "gcp", "k8s"])
def test_HOSTED_wrong_provider_rejected(provider):
    from peaso.server.validation import validate_connector
    from fastapi import HTTPException
    with pytest.raises(HTTPException) as error:
        validate_connector(provider, {}, {"compliance_policy": {"sw23": HOSTED_policy()}}, HOSTED_SimpleNamespace(auth_mode="cognito"))
    assert error.value.status_code == 422

@pytest.mark.parametrize("mode", ["rg-dot", "rg-dot-dot", "revision-dot-dot"])
@pytest.mark.parametrize("path", ["intake", "cognito"])
def test_HOSTED_strict_path_successor_boundary(mode, path):
    value = HOSTED_policy()
    service = value["apim_protocols"].pop(HOSTED_P)
    if mode.startswith("rg-"):
        segment = "." if mode == "rg-dot" else ".."
        changed_parent = HOSTED_P.replace("/resourceGroups/owned/", "/resourceGroups/" + segment + "/")
        service["apis"] = {key.replace(HOSTED_P, changed_parent): rule for key, rule in service["apis"].items()}
    else:
        changed_parent = HOSTED_P
        service["apis"][HOSTED_A + ";rev=.."] = service["apis"].pop(HOSTED_A + ";rev=1")
    value["apim_protocols"][changed_parent] = service
    if path == "intake":
        with pytest.raises(ValueError):
            HOSTED_native.azure_detection({"sw23": value})
    else:
        from peaso.server.validation import validate_connector
        from fastapi import HTTPException
        with pytest.raises(HTTPException) as error:
            validate_connector("azure", {"method": "token", "arm_token": "INERT-OFFLINE"},
                               {"compliance_policy": {"sw23": value}}, HOSTED_SimpleNamespace(auth_mode="cognito"))
        assert error.value.status_code == 422
