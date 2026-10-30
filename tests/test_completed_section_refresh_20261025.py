"""Explicit completed native refresh: same row, capability proof and source/lease fences."""
import copy,json,threading,time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import pytest
from peaso.server import scan_resume as resume
from peaso.snapshot import make_snapshot
from peaso.storage.artifacts import FileArtifacts,job_prefix
from peaso.storage.sqlite import SQLiteStore,StoreError

@pytest.fixture(params=['sqlite','dynamodb'])
def store(request,tmp_path):
 if request.param=='sqlite':yield SQLiteStore(tmp_path/'state');return
 import boto3,moto
 from peaso.storage.dynamodb import DynamoStore
 with moto.mock_aws():
  client=boto3.client('dynamodb',region_name='us-east-1');client.create_table(TableName='refresh',KeySchema=[{'AttributeName':'PK','KeyType':'HASH'},{'AttributeName':'SK','KeyType':'RANGE'}],AttributeDefinitions=[{'AttributeName':'PK','AttributeType':'S'},{'AttributeName':'SK','AttributeType':'S'}],BillingMode='PAY_PER_REQUEST')
  original=client.transact_write_items;lock=threading.Lock()
  def atomic(**kwargs):
   with lock:return original(**kwargs)
  client.transact_write_items=atomic
  yield DynamoStore('refresh',client)

def setup(store,tmp_path,*,provider='gcp',complete=False,damaged=False):
 artifacts=FileArtifacts(tmp_path/'artifacts');scope='projects/owned-project' if provider=='gcp' else '/subscriptions/00000000-0000-0000-0000-000000000001';scopes=[scope]
 connector=store.add_connector('owner',{'provider':provider,'scopes':scopes,'input_mode':'live'},'sealed-auth')
 connector=store.connector('owner',connector['id'])
 checks=[spec[0] for spec in resume._REFRESH_SPECS[provider].values()]
 now=time.time();job=store.enqueue('owner',{'connector_id':connector['id'],'checks':[],'categories':['hardening','network'],'content_checks':checks,'ai_enabled':True},limit=4,timeout=3600,now=now)
 store.admit('owner',job['id'],now=now+1);claim=store.claim('collector',tenant='owner',ident=job['id'],now=now+2)
 base={'type':'vpc','scope':scope,'status':'collected','items':[{'id':'native-ordinary'}]}
 image_rows=[{'type':kind,'scope':scope,'status':'collected','items':[{'id':'selected-immutable-image',marker:{'status':'PASS' if complete else 'UNKNOWN','complete':complete}}]} for _,kind,marker in resume._REFRESH_SPECS[provider].values()]
 snapshot=make_snapshot(provider,scopes,[base,*image_rows],metadata={'collection_plan':{'requirements':['vpc']}})
 batch=make_snapshot(provider,scopes,[base],metadata={'requested_scopes':scopes,'incremental':{'sequence':1,'phase':'collecting','batch_revisions':[1]}})
 batchref=artifacts.put('owner',job['id'],'snapshot',batch)
 assert store.record_checkpoint('owner',job['id'],claim['owner'],1,batchref,kind='__checkpoint_batch__',scope='1',now=now+3)
 if damaged:snapshot=make_snapshot(provider,scopes,[{'type':'azure_storage_selected_source','scope':scope,'status':'unknown','items':[]}],metadata={'azure_storage_selected_source_redaction_complete':False})
 snapref=artifacts.put('owner',job['id'],'snapshot',snapshot)
 # Complete one independent AI stage to test preservation of its row/inputs.
 assert store.claim_stage('owner',job['id'],'network',1,'d'*32,120,now=now+3)
 stage_ref=artifacts.put('owner',job['id'],'ai-review',{'stage':'network','data_revision':1,'result':{'status':'completed'}})
 assert store.finish_stage('owner',job['id'],'network',1,'d'*32,stage_ref,now=now+4)
 assert store.finish(job['id'],claim['owner'],'collected',snapref,now=now+5)
 analyzer=store.claim('analyzer',tenant='owner',ident=job['id'],now=now+6)
 digest='sha256:'+'a'*64
 observation={'provider':provider,'scope':scope,'asset_id':'owned-image','asset_kind':'image','scan':{'status':'PASS','complete':True,'scan_complete':True,'coverage_status':'COMPLETE','database':{'fresh':True},'findings':[],'image':{'provider':provider,'scope':scope,'manifest_digest':digest,'config_digest':digest,'immutable_reference':'example.test/repo@'+digest}}}
 projection=artifacts.put('owner',job['id'],'detail',{'schema':'peaso-immutable-image-observations-v1','scan_id':job['id'],'observations':[observation] if complete else []})
 reportref=artifacts.put('owner',job['id'],'report',{'bundle_version':1,'summary':{'provider':provider,'scopes':scopes,'snapshot_id':snapshot['snapshot_id'],'snapshot_metadata':snapshot['metadata']},'image_vulnerability_scan':{'selected':True,'artifact':projection},'ai':{'status':'completed','stage_inputs':{'network':['original']}}})
 assert store.finish(job['id'],analyzer['owner'],'completed',reportref,now=now+7)
 return artifacts,store.job('owner',job['id']),connector,claim

def grant(store,artifacts,row,sections=None):return resume.prove_section_refresh(row,store,artifacts,sections or ['images','leaks'])

def test_same_row_preserves_results_selectors_ai_and_fences_prior_owner(store,tmp_path):
 artifacts,row,connector,old=setup(store,tmp_path);before=copy.deepcopy(row);stages=store.stage_results('owner',row['id']);usage=store.usage('owner',time.time())
 result=store.resume_job('owner',row['id'],connector,refresh=grant(store,artifacts,row))
 after=store.job('owner',row['id']);assert result['id']==row['id'] and after['status']=='queued' and after['resume_attempt']==1
 for key in ['created','data','snapshot','report','checkpoint_sequence','partial_snapshot','partial_report']:
  assert after.get(key)==before.get(key)
 assert store.stage_results('owner',row['id'])==stages and store.usage('owner',time.time())==usage
 assert not store.heartbeat(row['id'],old['owner']) and not store.finish(row['id'],old['owner'],'collected',row['snapshot'])
 assert resume.section_refresh_payload(after)['sections']==['images','leaks']
 assert 'native_refresh' not in store.public_job(after)

def test_two_proven_requests_queue_exactly_once(store,tmp_path):
 artifacts,row,connector,_=setup(store,tmp_path);grants=[grant(store,artifacts,row),grant(store,artifacts,row)]
 def run(token):
  try:return store.resume_job('owner',row['id'],connector,refresh=token)
  except StoreError as error:return error.status
 with ThreadPoolExecutor(max_workers=2) as pool:results=list(pool.map(run,grants))
 assert sum(isinstance(value,dict) for value in results)==1 and 409 in results
 assert store.job('owner',row['id'])['resume_attempt']==1

def test_missing_or_replayed_proof_and_normal_completed_resume_reject(store,tmp_path):
 artifacts,row,connector,_=setup(store,tmp_path)
 for token in [None,{},'untrusted-plan']:
  with pytest.raises(StoreError) as error:store.resume_job('owner',row['id'],connector,refresh=token)
  assert error.value.status==409
 token=grant(store,artifacts,row);store.resume_job('owner',row['id'],connector,refresh=token)
 with pytest.raises(StoreError):store.resume_job('owner',row['id'],connector,refresh=token)
 with pytest.raises(StoreError):grant(store,artifacts,store.job('owner',row['id']))

@pytest.mark.parametrize('change',['connector','snapshot','report','checkpoint','selector','owner'])
def test_proof_bound_to_source_and_identity(store,tmp_path,change):
 artifacts,row,connector,_=setup(store,tmp_path);token=grant(store,artifacts,row);bad=dict(row)
 if change=='connector':bad['connector']='changed-frozen-source'
 elif change=='snapshot':bad['snapshot']=job_prefix('owner',row['id'])+'snapshot/other'
 elif change=='report':bad['report']=job_prefix('owner',row['id'])+'report/other'
 elif change=='checkpoint':bad['checkpoint_sequence']+=1
 elif change=='selector':bad['data']='{}'
 else:bad['tenant']='other'
 with pytest.raises(StoreError):resume.consume_section_refresh(token,bad)

def test_connector_revision_change_conflicts_before_queue(store,tmp_path):
 artifacts,row,connector,_=setup(store,tmp_path);token=grant(store,artifacts,row)
 store.update_connector('owner',connector['id'],{},'rotated-auth')
 with pytest.raises(StoreError):store.resume_job('owner',row['id'],connector,refresh=token)
 assert store.job('owner',row['id'])['status']=='completed'

def test_healthy_section_not_originally_selected_and_foreign_sources_reject(store,tmp_path):
 artifacts,row,connector,_=setup(store,tmp_path,complete=True)
 with pytest.raises(StoreError):grant(store,artifacts,row)
 bad=dict(row,data=json.dumps({'content_checks':[]}))
 with pytest.raises(StoreError):grant(store,artifacts,bad)
 bad=dict(row,snapshot=job_prefix('other',row['id'])+'snapshot/foreign')
 with pytest.raises((StoreError,ValueError)):grant(store,artifacts,bad)

@pytest.mark.parametrize('body',[{}, {'sections':[]},{'sections':['network']},{'sections':['images','images']},{'sections':['images'],'checks':['arbitrary']}])
def test_explicit_body_is_small_closed_contract(body):
 with pytest.raises(StoreError):resume.requested_refresh_sections(body)

def test_claimed_proof_restores_azure_as_partial_facts_and_never_forges_context(store,tmp_path):
 artifacts,row,connector,_=setup(store,tmp_path,provider='azure',damaged=True)
 store.resume_job('owner',row['id'],connector,refresh=grant(store,artifacts,row));queued=store.job('owner',row['id']);entries=store.checkpoint_collections('owner',row['id'])
 plan,prior,revisions=resume.validate_claimed_section_refresh(queued,entries,artifacts,{'provider':'azure','scopes':json.loads(connector['data'])['scopes']})
 native=next(c for c in prior['collections'] if c['type']=='vpc');assert native['items']==[{'id':'native-ordinary'}] and native['status']=='partial'
 assert native['error']['code']=='recovered_collector_context_unavailable'
 assert 'credential_context_id' not in prior['metadata'] and 'context_binding' not in prior['metadata']
 assert prior['metadata']['native_refresh']['restored_native_context']=='partial'
 assert revisions[('vpc',native['scope'])]==1

def test_claimed_fences_and_targeted_request_preserve_original_selection(store,tmp_path):
 artifacts,row,connector,_=setup(store,tmp_path);store.resume_job('owner',row['id'],connector,refresh=grant(store,artifacts,row));queued=store.job('owner',row['id']);entries=store.checkpoint_collections('owner',row['id']);native={'provider':'gcp','scopes':json.loads(connector['data'])['scopes'],'auth':{'token':'synthetic-never-output'},'options':{'content_secret_scans':True,'image_vulnerability_scans':True}}
 plan,prior,revisions=resume.validate_claimed_section_refresh(queued,entries,artifacts,native)
 original={'connector':native,'content_checks':['unrelated'],'categories':['hardening'],'frameworks':['framework'],'checks':['ordinary'],'leaks_enabled':True,'images_enabled':True}
 before=copy.deepcopy(original);narrow=resume.section_refresh_collection_request(original,plan)
 assert original==before and narrow['connector']['auth']==native['auth'] and narrow['connector']['scopes']==native['scopes']
 assert narrow['content_checks']==plan['checks'] and narrow['categories']==[] and narrow['checks']==[] and narrow['frameworks']==[]
 assert 'leaks_enabled' not in narrow and 'images_enabled' not in narrow
 for key,value in [('id','other'),('tenant','other'),('resume_attempt',99),('snapshot','other'),('data','{}')]:
  bad={**queued,key:value}
  with pytest.raises(ValueError):resume.validate_claimed_section_refresh(bad,entries,artifacts,native)
 with pytest.raises(ValueError):resume.validate_claimed_section_refresh(queued,entries,artifacts,{**native,'scopes':['projects/foreign']})


def test_api_eligibility_never_downloads_native_snapshot_or_checkpoint(store,tmp_path,monkeypatch):
 artifacts,row,_,_=setup(store,tmp_path)
 def forbidden(*args):raise AssertionError('Unbounded artifact.get must never run inside API proof')
 monkeypatch.setattr(artifacts,'get',forbidden)
 token=grant(store,artifacts,row)
 assert resume.consume_section_refresh(token,row)['manifest_sha256']

@pytest.mark.parametrize('variant',['wire','expansion','depth','duplicate','invalid-json','foreign-projection'])
def test_bounded_manifest_failure_is_controlled_and_does_not_queue(store,tmp_path,variant):
 import gzip
 artifacts,row,connector,_=setup(store,tmp_path);target=artifacts.root/row['report']
 if variant=='wire':target.write_bytes(b' '*(4*1024*1024+1))
 elif variant=='expansion':target.write_bytes(gzip.compress(b' '*(8*1024*1024+1)))
 elif variant=='depth':target.write_text('{"a":'+'['*60+'0'+']'*60+'}')
 elif variant=='duplicate':target.write_text('{"summary":1,"summary":2}')
 elif variant=='invalid-json':target.write_bytes(b'{')
 else:
  value=json.loads(target.read_text());value['image_vulnerability_scan']['artifact']=job_prefix('other',row['id'])+'detail-'+'d'*32+'.json';target.write_text(json.dumps(value))
 with pytest.raises(StoreError) as error:grant(store,artifacts,row)
 assert error.value.status==409 and store.job('owner',row['id'])['status']=='completed'
 assert store.job('owner',row['id'])['resume_attempt']==0


def test_bounded_s3_stream_and_gzip_bomb_close_body_without_unbounded_read(tmp_path):
 import gzip,io
 from peaso.storage.artifacts import S3Artifacts
 class Body(io.BytesIO):
  requested=[]
  def read(self,n=-1):
   assert 0<n<=65536
   self.requested.append(n);return super().read(n)
 body=Body(gzip.compress(b' '*(8*1024*1024+1)))
 class Client:
  def get_object(self,**kwargs):return {'Body':body,'ContentLength':len(body.getvalue())}
 artifacts=S3Artifacts('owned',Client());reference=job_prefix('owner','e'*32)+'report-'+'f'*32+'.json'
 with pytest.raises(ValueError):resume._refresh_manifest_json(artifacts,'owner',reference)
 assert body.closed and body.requested


def test_worker_rejects_clean_native_despite_incomplete_projection(store,tmp_path):
 artifacts,row,connector,_=setup(store,tmp_path,complete=True)
 manifest=artifacts.get('owner',row['report']);projection=artifacts.root/manifest['image_vulnerability_scan']['artifact'];value=json.loads(projection.read_text());value['observations']=[];projection.write_text(json.dumps(value))
 store.resume_job('owner',row['id'],connector,refresh=grant(store,artifacts,row))
 with pytest.raises(ValueError,match='Full native section proof'):
  resume.validate_claimed_section_refresh(store.job('owner',row['id']),store.checkpoint_collections('owner',row['id']),artifacts,{'provider':'gcp','scopes':json.loads(connector['data'])['scopes']})




def test_actual_api_route_dispatches_only_after_bounded_proof_and_compatible_auth(store,tmp_path):
 import ast,types
 from fastapi import HTTPException
 artifacts,row,connector,_=setup(store,tmp_path)
 source=Path(__file__).parent/'sources/peaso/server/app.py'
 if not source.exists():
  import peaso.server.app as module
  source=Path(module.__file__)
 tree=ast.parse(source.read_text());node=next(n for n in ast.walk(tree) if isinstance(n,ast.FunctionDef) and n.name=='resume_scan');node.decorator_list=[];node.args.defaults=[ast.Constant(None)];ast.fix_missing_locations(node)
 dispatched=[];validations=[]
 env={'store':store,'artifacts':artifacts,'cipher':types.SimpleNamespace(decrypt=lambda value:{'auth':{'token':'synthetic'},'options':{}}),'validate_connector':lambda *args,**kwargs:validations.append(True),'settings':None,'dispatcher':types.SimpleNamespace(dispatch=lambda tenant,job:dispatched.append(job['id'])),'public_scan':store.public_job,'json':json,'HTTPException':HTTPException,'__package__':'peaso.server'}
 exec(compile(ast.Module(body=[node],type_ignores=[]),str(source),'exec'),env)
 endpoint=env['resume_scan'];user=types.SimpleNamespace(tenant_id='owner')
 original=(artifacts.root/row['report']).read_bytes();(artifacts.root/row['report']).write_bytes(b' '*(4*1024*1024+1))
 with pytest.raises(StoreError):endpoint(row['id'],{'sections':['images','leaks']},user)
 assert not dispatched and not validations and store.job('owner',row['id'])['status']=='completed'
 (artifacts.root/row['report']).write_bytes(original)
 result=endpoint(row['id'],{'sections':['images','leaks']},user)
 assert result['id']==row['id'] and dispatched==[row['id']] and validations==[True]
