"""Public native Git pipeline, secret-free assessments and exact URL semantics."""
import copy,json
from types import SimpleNamespace
from urllib.parse import urlsplit,parse_qs
import pytest
from fastapi import HTTPException
from peaso.collectors import azure,collect_live
from peaso.collectors import azure_devops_git_native as native
from peaso.azure_devops_git_policy import normalize,assess_urls,evaluate_project
from peaso.engine import collect_snapshot
from peaso.server.validation import validate_connector
from tests.test_peaso_azure_bulk_native import Transport,SUB,SCOPE,verdict
CHECK='azure_devops_project_1_2_8_6_fb0e5a8'
PID='33333333-3333-3333-3333-333333333333';RID='44444444-4444-4444-4444-444444444444'
OTHER='55555555-5555-5555-5555-555555555555';TOKEN='private-devops-test-token'
URL='https://example.org/repo';SERVER='https://dev.azure.com/own-org'
def options():return {'retries':0,'compliance_parameters':{'azure_devops_git':{'subscriptions':[{'scope':SCOPE,'organization':'own-org','project_ids':[PID]}]}}}
def auth():return {'tenant_id':Transport.tenant,'devops_credentials':[{'server':SERVER,'method':'pat','token':TOKEN}]}
def capture(monkeypatch,mode='good',via='direct',url=URL,visibility=None):
 p={'id':PID,'state':'wellFormed'};repo={'id':RID,'project':{'id':PID},'remoteUrl':url,'validRemoteUrls':[url],'description':TOKEN}
 if visibility is not None:p['visibility']=visibility
 routes={'/own-org/_apis/projects':{'count':1,'value':[p]},'/own-org/_apis/projects/'+PID:p,'/own-org/'+PID+'/_apis/git/repositories':{'count':1,'value':[repo]},'/own-org/'+PID+'/_apis/git/repositories/'+RID:repo}
 o=options();a=auth();calls=[]
 if mode=='no_policy':o={};a.pop('devops_credentials')
 if mode=='no_credential':a.pop('devops_credentials')
 if mode=='missing_project':routes['/own-org/_apis/projects']={'count':0,'value':[]}
 if mode=='extra_visible':routes['/own-org/_apis/projects']={'count':2,'value':[p,{'id':OTHER,'state':'wellFormed'}]}
 if mode=='project_duplicate':routes['/own-org/_apis/projects']={'count':2,'value':[p,p]}
 if mode=='project_get_foreign':routes['/own-org/_apis/projects/'+PID]={'id':OTHER,'state':'wellFormed'}
 if mode=='project_not_ready':p['state']='deleting'
 if mode=='repo_foreign':repo['project']['id']=OTHER
 if mode=='repo_get_foreign':routes['/own-org/'+PID+'/_apis/git/repositories/'+RID]={**repo,'id':OTHER}
 if mode=='repo_duplicate':routes['/own-org/'+PID+'/_apis/git/repositories']={'count':2,'value':[repo,repo]}
 if mode=='empty':routes['/own-org/'+PID+'/_apis/git/repositories']={'count':0,'value':[]}
 if mode=='missing_urls':repo.pop('validRemoteUrls')
 if mode=='get_omits_urls':routes['/own-org/'+PID+'/_apis/git/repositories/'+RID]={k:v for k,v in repo.items()if k!='validRemoteUrls'}
 if mode=='repo_denied':routes['/own-org/'+PID+'/_apis/git/repositories']=azure.AzureReadError('forbidden',403)
 if mode=='projects_denied':routes['/own-org/_apis/projects']=azure.AzureReadError('forbidden',403)
 if mode=='budget':o['max_calls']=2
 if mode in ('paging','partial','repeated','page_cap'):o['max_pages']=1 if mode=='page_cap' else 4
 def read(url,credential,state):
  path=native.endpoint(url,'own-org');calls.append(url);q=parse_qs(urlsplit(url).query)
  assert credential['token']==TOKEN
  response=routes.get(path)
  if isinstance(response,Exception):raise response
  continuation=None
  if path=='/own-org/_apis/projects'and mode in ('paging','partial','repeated','page_cap'):
   if 'continuationToken'not in q:response={'count':0,'value':[]};continuation='1'
   elif mode=='partial':raise azure.AzureReadError('forbidden',403)
   elif mode=='repeated':response={'count':0,'value':[]};continuation='1'
  if mode=='repo_continuation'and path.endswith('/repositories'):continuation='1'
  return native.project_response(copy.deepcopy(response),path,continuation)
 monkeypatch.setattr(native,'request_metadata',read)
 arm=Transport({'/subscriptions/'+SUB:{'id':SCOPE,'tenantId':Transport.tenant,'state':'Enabled'}})
 if mode=='tenant_mismatch':arm.verified_tenant=OTHER
 original=azure.collect
 def collect(connector,requirements=None):return original(connector,requirements,transport=arm)
 connector={'provider':'azure','scopes':[SUB],'auth':a,'options':o}
 if via=='direct':snapshot=collect(connector,['subscription','devops_project'])
 else:
  monkeypatch.setattr(azure,'collect',collect)
  if via=='dispatcher':snapshot=collect_live(connector,['subscription','devops_project'])
  else:snapshot=collect_snapshot({'provider':'azure','connector':connector,'checks':[CHECK]})
 return snapshot,calls

def planner_rejects_manual_control(monkeypatch,via,**kwargs):
 if via!='planner':return False
 from peaso.checks.native_only import exclusions
 from peaso.checks.catalog import manual_requirement_ids
 assert CHECK in set(exclusions())|set(manual_requirement_ids('azure'))
 with pytest.raises(ValueError,match='requires external policy or manual evidence'):
  capture(monkeypatch,via=via,**kwargs)
 return True

@pytest.mark.parametrize('via',['direct','dispatcher','planner'])
def test_public_native_git_pipeline(monkeypatch,via):
 if planner_rejects_manual_control(monkeypatch,via):return
 s,c=capture(monkeypatch,via=via);assert verdict(s,CHECK)=='UNKNOWN';assert len(c)==4
 assert all('api-version=7.1'in u for u in c)
 assert TOKEN not in json.dumps(s)and URL not in json.dumps(s)


@pytest.mark.parametrize('visibility,expected',[('public','FAIL'),('private','PASS'),(None,'UNKNOWN')])
def test_devops_project_visibility_is_native_exposure(monkeypatch,visibility,expected):
 from peaso.analysis.internet_exposure import assess
 from peaso.snapshot import resources
 snapshot,_=capture(monkeypatch,visibility=visibility)
 project=next(c for c in snapshot['collections']if c['type']=='devops_project')['items'][0]
 assert project['visibility']==visibility
 row=next(r for r in assess(snapshot,resources(snapshot))if r.resource['type']=='devops_project')
 assert row.verdict()==expected
 if visibility=='public':assert row.data_exposure and row.authenticated is False

@pytest.mark.parametrize('mode,expected',[(m,'UNKNOWN')for m in ['no_policy','no_credential','missing_project','project_duplicate','project_get_foreign','project_not_ready','repo_foreign','repo_get_foreign','repo_duplicate','missing_urls','repo_denied','projects_denied','budget','partial','repeated','page_cap','repo_continuation','tenant_mismatch']]+[('empty','UNKNOWN'),('extra_visible','UNKNOWN'),('get_omits_urls','UNKNOWN'),('paging','UNKNOWN')])
def test_pipeline_native_bounds(monkeypatch,mode,expected):
 s,_=capture(monkeypatch,mode);assert verdict(s,CHECK)==('DENIED' if mode in ('projects_denied','partial') else expected)
 assert TOKEN not in json.dumps(s)

@pytest.mark.parametrize('url,expected',[
 ('https://alice:low-entropy-password@example.org/repo','FAIL'),('https://alice@example.org/repo','FAIL'),
 ('http://example.org/repo','UNKNOWN'),('ssh://example.org/repo','UNKNOWN'),('ssh://git@example.org/repo','FAIL'),
 ('git@example.org:repo','UNKNOWN'),('https://user@example.org:0/repo','UNKNOWN'),('https://user@example.org:bad/repo','UNKNOWN'),('file:///repo','UNKNOWN'),('http://[bad','UNKNOWN')])
def test_exact_frozen_url_semantics_and_no_secret_hash(monkeypatch,url,expected):
 s,_=capture(monkeypatch,url=url);assert verdict(s,CHECK)==expected
 serialized=json.dumps(s);assert url not in serialized and 'low-entropy-password'not in serialized
 import hashlib
 assert hashlib.sha256(url.encode()).hexdigest()not in serialized

@pytest.mark.parametrize('mode',['local','cognito'])
@pytest.mark.parametrize('mutation',['observation','foreign_provider','unknown_auth','malformed_server','scope','duplicate','bool_project'])
def test_typed_local_hosted_input(mode,mutation):
 o=options();a=auth();provider='azure'
 if mutation=='observation':o['compliance_parameters']['azure_devops_git']['subscriptions'][0]['complete']=True
 if mutation=='foreign_provider':provider='aws'
 if mutation=='unknown_auth':a['devops_credentials'][0]['organization']='own-org'
 if mutation=='malformed_server':a['devops_credentials'][0]['server']+='@evil.example'
 if mutation=='scope':o['compliance_parameters']['azure_devops_git']['subscriptions'][0]['scope']='*'
 if mutation=='duplicate':a['devops_credentials']*=2
 if mutation=='bool_project':o['compliance_parameters']['azure_devops_git']['subscriptions'][0]['project_ids']=[True]
 with pytest.raises(HTTPException):validate_connector(provider,a,o,SimpleNamespace(auth_mode=mode))

@pytest.mark.parametrize('mode',['local','cognito'])
def test_valid_intake_and_credential_redaction(mode):
 a=auth();a.update(method='token',arm_token='explicit-arm-token')
 o=options();o.pop('retries');validate_connector('azure',a,o,SimpleNamespace(auth_mode=mode))
 from peaso.auth.secrets import credential_values
 values=credential_values(a)
 assert TOKEN in values and SERVER not in values and 'own-org'not in values

@pytest.mark.parametrize('url',[SERVER+'@evil.example/_apis/projects?api-version=7.1',SERVER+'/_apis/projects?api-version=7.1&stateFilter=all&$top=100&nextLink=x','http://dev.azure.com/own-org/_apis/projects?api-version=7.1',SERVER+'/_apis/projects?api-version=7.1&stateFilter=all&$top=100&continuationToken=-1'])
def test_transport_rejects_nonfixed_paths(url):
 with pytest.raises(ValueError):native.endpoint(url,'own-org')

def test_malformed_native_marker_cannot_fall_back(monkeypatch):
 s,_=capture(monkeypatch);c=next(c for c in s['collections']if c['type']=='devops_project')
 p=c['items'][0];p['_provenance']['native_devops_git_schema']=True
 with pytest.raises(Exception):evaluate_project(p,SCOPE,[PID])

@pytest.mark.parametrize('mode',['good','limit','total','redirect','duplicate','continuation','forbidden'])
def test_actual_http_request_projection_and_bounds(monkeypatch,mode):
 import io
 from urllib.error import HTTPError
 repo={'id':RID,'project':{'id':PID},'remoteUrl':'https://user:guessable@example.org/repo','validRemoteUrls':['ssh://git@example.org/repo']}
 raw=json.dumps({'count':1,'value':[repo]}).encode();state={'bytes':0};observed=[]
 if mode=='limit':raw=b'x'*(native.MAX_BYTES+1)
 if mode=='duplicate':raw=b'{"count":0,"count":1,"value":[]}'
 if mode=='total':state['bytes']=native.MAX_TOTAL_BYTES
 class Response(io.BytesIO):headers={'x-ms-continuationtoken':'1'}if mode=='continuation'else{}
 class Opener:
  def open(self,request,timeout):
   observed.append(request);assert request.method=='GET'and timeout<=20
   if mode=='redirect':raise ValueError('DevOps redirect rejected')
   if mode=='forbidden':raise HTTPError(request.full_url,403,'provider-message-containing-secret',{},None)
   return Response(raw)
 def build(*handlers):
  assert handlers[0].proxies=={}and isinstance(handlers[1],native._NoRedirect)
  return Opener()
 monkeypatch.setattr(native,'build_opener',build)
 url=SERVER+'/'+PID+'/_apis/git/repositories?api-version=7.1&includeHidden=true&includeAllUrls=true'
 if mode=='good':
  out=native.request_metadata(url,auth()['devops_credentials'][0],state)
  assert out['items'][0]['url_assessments']['items'][0]['userinfo_present']is True
  assert 'guessable'not in json.dumps(out)and TOKEN not in json.dumps(out)
 else:
  with pytest.raises(Exception):native.request_metadata(url,auth()['devops_credentials'][0],state)
 if mode=='total':assert not observed
 else:assert observed and observed[0].get_header('Authorization').startswith('Basic ')

@pytest.mark.parametrize('mutation',['schema','operations','readonly','scope','project','capture','count','index','bool','extra','missing','coverage_bool'])
def test_native_exact_proof_and_assessment_tamper_rejected(monkeypatch,mutation):
 s,_=capture(monkeypatch);p=next(c for c in s['collections']if c['type']=='devops_project')['items'][0]
 p=copy.deepcopy(p);proof=p['_provenance'];facts=p['repositories'][0]['url_assessments']
 if mutation=='schema':proof['native_devops_git_schema']=True
 if mutation=='operations':proof['source_operations']=['invented']
 if mutation=='readonly':proof['read_only']=False
 if mutation=='scope':proof['owner_scope']='/subscriptions/'+OTHER
 if mutation=='project':proof['project_id']=OTHER
 if mutation=='capture':proof['capture_id']='not-native-uuid'
 if mutation=='count':facts['valid_remote_urls_count']=2
 if mutation=='index':facts['items'][0]['index']=True
 if mutation=='bool':facts['items'][0]['userinfo_present']='false'
 if mutation=='extra':facts['items'][0]['observed_url']='forged'
 if mutation=='missing':facts.pop('items')
 if mutation=='coverage_bool':p['_coverage']['repositories']['api_pages_complete']=1
 from peaso.checks.facts import Unavailable
 with pytest.raises(Unavailable):evaluate_project(p,SCOPE,[PID])

@pytest.mark.parametrize('urls,expected',[
 (['https://a.example','ssh://git@a.example'],'FAIL'),
 (['git@a.example:path','https://user:secret@a.example'],'UNKNOWN'),
 (['https://user:secret@a.example','git@a.example:path'],'FAIL')])
def test_ordered_legacy_decisions_preserved_without_values(monkeypatch,urls,expected):
 s,_=capture(monkeypatch,url=urls[0]);p=next(c for c in s['collections']if c['type']=='devops_project')['items'][0]
 p['repositories'][0]['url_assessments']=assess_urls({'remoteUrl':urls[0],'validRemoteUrls':urls[1:]})
 assert evaluate_project(p,SCOPE,[PID])=={'PASS':None,'FAIL':True,'UNKNOWN':None}[expected]

@pytest.mark.parametrize('cap',['calls','deadline','repos'])
def test_native_internal_budgets_do_not_claim_completion(monkeypatch,cap):
 if cap=='calls':monkeypatch.setattr(native,'MAX_CALLS',2)
 if cap=='deadline':monkeypatch.setattr(native,'MAX_SECONDS',-1)
 if cap=='repos':monkeypatch.setattr(native,'MAX_REPOS',0)
 s,_=capture(monkeypatch);assert verdict(s,CHECK)=='UNKNOWN'
 assert not any(c['status']=='empty'for c in s['collections']if c['type']=='devops_project')

def test_endpoint_auth_origin_literal_dots_required():
 a=auth();a['devops_credentials'][0]['server']='https://devXazureXcom/own-org'
 with pytest.raises(ValueError):normalize(options(),a)

@pytest.mark.parametrize('via',['direct','dispatcher','planner'])
def test_native_verified_userinfo_counterexample_public_pipeline(monkeypatch,via):
 if planner_rejects_manual_control(monkeypatch,via,url='https://owned-user:guessable@example.org/repo'):return
 s,_=capture(monkeypatch,via=via,url='https://owned-user:guessable@example.org/repo')
 assert verdict(s,CHECK)=='FAIL'
 p=next(c for c in s['collections']if c['type']=='devops_project')['items'][0]
 assert p['_coverage']['repositories']=={'status':'partial','reason':'repository_authorization_universe_unverified','api_pages_complete':True}
 assert 'guessable'not in json.dumps(s)

@pytest.mark.parametrize('mode',['good','empty','extra_visible','get_omits_urls'])
def test_native_clean_or_empty_never_proves_repository_universe(monkeypatch,mode):
 s,_=capture(monkeypatch,mode=mode)
 assert verdict(s,CHECK)=='UNKNOWN'
 p=next(c for c in s['collections']if c['type']=='devops_project')['items'][0]
 assert p['_coverage']['repositories']['status']=='partial'
 assert p['_coverage']['repositories']['reason']=='repository_authorization_universe_unverified'
 assert p['_coverage']['repositories']['api_pages_complete']is True


@pytest.mark.parametrize('via',['direct','dispatcher','planner'])
def test_sw32_git_union_normative_options_survive_public_native_pipeline(monkeypatch,via):
 import sys
 combined=options();combined['retries']=1
 criteria={'status':'collected','scope':SCOPE,'later_stage_deployment_limit':0,'acr_max_untagged_days':30}
 combined['compliance_policy']={'sw32':criteria}
 credentials=auth();credentials.update(method='token',arm_token='controlled-arm-token')
 for mode in ['local','cognito']:
  validate_connector('azure',credentials,combined,SimpleNamespace(auth_mode=mode))
 monkeypatch.setattr(sys.modules[__name__],'options',lambda:copy.deepcopy(combined))
 if planner_rejects_manual_control(monkeypatch,via,url='https://explicit-user:private-password@example.org/repo'):return
 snapshot,_=capture(monkeypatch,via=via,url='https://explicit-user:private-password@example.org/repo')
 assert verdict(snapshot,CHECK)=='FAIL'
 assert snapshot['metadata']['compliance_policy']['sw32']==criteria
 assert 'private-password'not in json.dumps(snapshot)and TOKEN not in json.dumps(snapshot)
