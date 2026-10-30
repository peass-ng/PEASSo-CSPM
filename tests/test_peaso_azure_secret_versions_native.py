"""ARM current metadata plus data-plane LIST only, through the actual engine."""
import copy
from datetime import datetime, timezone
import json
from urllib.parse import urlsplit
import pytest
from peaso.collectors import azure, collect_live, azure_sw15_policy
from tests.archived_check_contract import evaluate_snapshot
from peaso.snapshot import make_snapshot
SUB='/subscriptions/11111111-1111-1111-1111-111111111111'
VAULT=SUB+'/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/fixturevault'
SECRET=VAULT+'/secrets/password'
ORIGIN='https://fixturevault.vault.azure.net'
URI=ORIGIN+'/secrets/password'
CURRENT=URI+'/version-current'
CID='azure_vault_keyvault_non_rbac_secret_expiration_set_a4923d7'
POLICY={'status':'collected','scope':SUB,'maxDaysSinceRotation':90}
class Denied(Exception):status_code=403

def capture(monkeypatch,mode='recent',*,policy=None,requirements=None,**limits):
 now=int(datetime.now(timezone.utc).timestamp());created=now-(100 if mode in('old','newer_disabled')else 1)*86400
 attributes={'enabled':mode!='disabled','created':created,'updated':created}
 vault={'id':VAULT,'type':'Microsoft.KeyVault/vaults','name':'fixturevault','properties':{'vaultUri':ORIGIN,'enableRbacAuthorization':True}}
 metadata={'id':URI,'attributes':attributes}
 versions=[{'id':URI+'/version-old','attributes':{'enabled':False,'created':now-200*86400}}, {'id':CURRENT,'attributes':{**attributes,'recoveryLevel':'Recoverable+Purgeable'}}]
 if mode=='newer_disabled':versions.append({'id':URI+'/version-new-disabled','attributes':{'enabled':False,'created':now}})
 if mode=='foreign_version':versions[0]['id']='https://foreign.vault.azure.net/secrets/password/version-old'
 if mode=='duplicate_versions':versions.append(copy.deepcopy(versions[1]))
 if mode=='case_duplicate_versions':versions.append({**versions[1],'id':versions[1]['id'].upper()})
 arm={'id':SECRET,'type':'Microsoft.KeyVault/vaults/secrets','name':'password','properties':{'secretUri':URI,'secretUriWithVersion':CURRENT,'attributes':copy.deepcopy(attributes)}}
 if mode=='arm_id_case':arm['id']=SECRET.upper()
 if mode=='foreign_arm_id':arm['id']=VAULT+'/secrets/foreign'
 if mode=='foreign_parent':arm['id']=VAULT+'foreign/secrets/password'
 if mode=='foreign_name':arm['name']='foreign'
 if mode=='foreign_type':arm['type']='Microsoft.Web/sites'
 if mode=='foreign_base':arm['properties']['secretUri']='https://foreign.vault.azure.net/secrets/password'
 if mode=='version_for_other_name':arm['properties']['secretUriWithVersion']=ORIGIN+'/secrets/foreign/version-current'
 if mode=='version_for_other_vault':arm['properties']['secretUriWithVersion']='https://foreign.vault.azure.net/secrets/password/version-current'
 if mode=='version_case_differs':arm['properties']['secretUriWithVersion']=URI+'/VERSION-CURRENT'
 if mode=='version_trailing':arm['properties']['secretUriWithVersion']=CURRENT+'/'
 if mode=='version_query':arm['properties']['secretUriWithVersion']=CURRENT+'?api-version=evil'
 if mode=='missing_pointer':arm['properties'].pop('secretUriWithVersion')
 if mode=='missing_created':arm['properties']['attributes'].pop('created')
 if mode=='conflicting_created':arm['properties']['attributes']['created']-=86400
 if mode=='conflicting_enabled':arm['properties']['attributes']['enabled']=not attributes['enabled']
 if mode=='unexpected_value':arm['properties']['value']='DO_NOT_PERSIST_SECRET'
 class Transport:
  tenant=verified_tenant='aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'
  def __init__(self):self.calls=[];self.arm_gets=0;self.allowed=[]
  def allow_vault(self,uri):self.allowed.append(uri)
  def close(self):pass
  def request(self,url,*,body=None,audience=azure.ARM):
   self.calls.append((url,audience,body));path=urlsplit(url).path
   assert body is None or path.casefold()=='/providers/microsoft.resourcegraph/resources'
   if audience==azure.VAULT:
    assert url.startswith(ORIGIN+'/')
    assert path in('/secrets','/secrets/password/versions'),'GetSecret/value is forbidden'
    if mode=='vault_denied':raise Denied('DO_NOT_PERSIST_SECRET')
    if path=='/secrets':return {'value':[copy.deepcopy(metadata)]}
    if mode=='versions_denied':raise Denied('DO_NOT_PERSIST_SECRET')
    if mode=='versions_partial':return {'value':[versions[0]],'nextLink':'https://foreign.example/next'}
    if mode=='versions_empty':return {'value':[]}
    return {'value':copy.deepcopy(versions)}
   assert audience==azure.ARM and url.startswith(azure.ARM+'/')
   if path.casefold()=='/providers/microsoft.resourcegraph/resources':return {'data':[],'resultTruncated':False}
   if path==SUB+'/providers/Microsoft.KeyVault/vaults':return {'value':[vault]}
   if path==VAULT:return copy.deepcopy(vault)
   if path==SECRET:
    self.arm_gets+=1
    if mode=='arm_denied':raise Denied('DO_NOT_PERSIST_SECRET')
    value=copy.deepcopy(arm)
    if mode=='changed_current'and self.arm_gets>1:value['properties']['secretUriWithVersion']=URI+'/another-version'
    if mode=='changed_attributes'and self.arm_gets>1:value['properties']['attributes']['updated']+=1
    return value
   return {'value':[]}
 transport=Transport();monkeypatch.setattr(azure,'AzureTransportExposure',lambda auth:transport)
 options={'retries':0,'concurrency':1,'compliance_policy':{'sw15':copy.deepcopy(POLICY if policy is None else policy)},**limits}
 if mode=='missing_policy':options.pop('compliance_policy')
 if mode=='foreign_policy':options['compliance_policy']['sw15']['scope']='/subscriptions/22222222-2222-2222-2222-222222222222'
 try:
  snapshot=collect_live({'provider':'azure','scopes':[SUB],'auth':{'method':'token','arm_token':'fixture','vault_token':'fixture-vault'},'options':options},requirements or['key_vault_secret'])
 except ValueError:
  if mode=='foreign_policy':assert transport.calls==[], 'foreign owner policy must fail before API calls'
  raise
 assert 'DO_NOT_PERSIST_SECRET'not in json.dumps(snapshot)
 statuses=[f['status']for f in evaluate_snapshot(snapshot,checks=[CID])['findings']if f['check_id']==CID]
 assert len(statuses)==1
 return statuses[0],snapshot,transport

@pytest.mark.parametrize('mode,expected', [('arm_id_case','PASS'),('recent','PASS'),('old','FAIL'),('newer_disabled','FAIL'),('disabled','NOT_APPLICABLE'),('foreign_version','UNKNOWN'),('duplicate_versions','UNKNOWN'),('case_duplicate_versions','UNKNOWN'),('foreign_arm_id','UNKNOWN'),('foreign_parent','UNKNOWN'),('foreign_name','UNKNOWN'),('foreign_type','UNKNOWN'),('foreign_base','UNKNOWN'),('version_for_other_name','UNKNOWN'),('version_for_other_vault','UNKNOWN'),('version_case_differs','UNKNOWN'),('version_trailing','UNKNOWN'),('version_query','UNKNOWN'),('missing_pointer','UNKNOWN'),('missing_created','UNKNOWN'),('conflicting_created','UNKNOWN'),('conflicting_enabled','UNKNOWN'),('unexpected_value','UNKNOWN'),('vault_denied','DENIED'),('versions_denied','UNKNOWN'),('versions_partial','UNKNOWN'),('versions_empty','UNKNOWN'),('arm_denied','UNKNOWN'),('changed_current','UNKNOWN'),('changed_attributes','UNKNOWN'),('missing_policy','UNKNOWN'),('foreign_policy','REJECTED_INPUT')])
def test_native_current_version_to_engine(monkeypatch,mode,expected):
 if expected=='REJECTED_INPUT':
  with pytest.raises(ValueError):capture(monkeypatch,mode)
  return
 status,snapshot,transport=capture(monkeypatch,mode);assert status==expected
 if mode=='recent':
  assert transport.arm_gets==2
  record=next(c for c in snapshot['collections']if c['type']=='key_vault_secret')['items'][0]
  assert record['currentVersion']['id']==CURRENT
  assert record['currentVersion']['_provenance']['endpoint']=='arm/secrets/get'
  assert record['currentVersion']['_provenance']['request_uri']==azure.ARM+SECRET
  assert record['armCurrentMetadataBefore']['properties']==record['armCurrentMetadata']['properties']

@pytest.mark.parametrize('damage',['boolean_alias','missing_before','partial_before','partial_after','foreign_proof','trailing_request','source_operation','api_version','wrong_current_binding','before_conflict','attributes_conflict','attributes_source','stale','future'])
def test_engine_independently_rechecks_arm_provenance(monkeypatch,damage):
 _,snapshot,_=capture(monkeypatch)
 item=next(c for c in snapshot['collections']if c['type']=='key_vault_secret')['items'][0]
 if damage=='boolean_alias':item['currentVersion']['_provenance']['read_only']=1
 if damage=='missing_before':item.pop('armCurrentMetadataBefore')
 if damage=='partial_before':item['_coverage']['armCurrentMetadataBefore']['status']='partial'
 if damage=='partial_after':item['_coverage']['armCurrentMetadata']['status']='partial'
 if damage=='foreign_proof':item['armCurrentMetadata']['parent_id']=VAULT+'foreign'
 if damage=='trailing_request':item['currentVersion']['_provenance']['request_uri']+='/'
 if damage=='source_operation':item['armCurrentMetadata']['_provenance']['source_operation']='Secrets_List'
 if damage=='api_version':item['armCurrentMetadata']['_provenance']['api_version']='2025-07-01'
 if damage=='wrong_current_binding':item['currentVersion']['id']=URI+'/version-old'
 if damage=='before_conflict':item['armCurrentMetadataBefore']['properties']['secretUriWithVersion']=URI+'/version-old'
 if damage=='attributes_conflict':item['armCurrentMetadata']['properties']['attributes']['enabled']=False
 if damage=='attributes_source':item['currentVersion']['_provenance']['attributes_source_operation']='Secrets_Get'
 if damage=='stale':item['armCurrentMetadata']['_provenance']['observed_at']='2000-01-01T00:00:00Z'
 if damage=='future':item['armCurrentMetadata']['_provenance']['observed_at']='2099-01-01T00:00:00Z'
 snapshot=make_snapshot(snapshot['provider'],snapshot['scopes'],snapshot['collections'],metadata=snapshot['metadata'],created_at=snapshot['created_at'])
 assert next(f for f in evaluate_snapshot(snapshot,checks=[CID])['findings']if f['check_id']==CID)['status']=='UNKNOWN'

def test_shared_secret_family_reads_current_only_twice(monkeypatch):
 status,snapshot,transport=capture(monkeypatch,requirements=['key_vault_secret','vault_secret'])
 assert status=='PASS'and transport.arm_gets==2
 assert {'key_vault_secret','vault_secret'}<={c['type']for c in snapshot['collections']}

def test_denied_secret_metadata_parent_propagates_to_both_current_secret_kinds(monkeypatch):
 status,snapshot,_=capture(monkeypatch,'vault_denied',requirements=['key_vault_secret','vault_secret'])
 assert status=='DENIED'
 for kind in ('key_vault_secret','vault_secret'):
  collection=next(c for c in snapshot['collections']if c['type']==kind)
  assert collection['status']=='denied'
  assert collection['error']['code']=='403'
  assert collection['items']==[]

def test_explicit_budget_stays_unknown(monkeypatch):
 status,_,_=capture(monkeypatch,max_resources=2);assert status=='UNKNOWN'

@pytest.mark.parametrize('raw',[None,[],False,'invalid',{'status':'collected','scope':SUB},dict(POLICY,operations_complete=True),dict(POLICY,allowAzureServices='true'),dict(POLICY,maxDaysSinceRotation=True)])
def test_common_policy_rejects_malformed_or_observation_fields(raw):
 with pytest.raises(ValueError):azure_sw15_policy.normalize({'compliance_policy':{'sw15':raw}},[SUB])

def test_policy_absence_preserves_other_namespaces():
 assert azure_sw15_policy.normalize({'compliance_policy':{'sw18':{'status':'unknown'}}},[SUB])is None


def test_mixed_firewall_function_rotation_roundtrips(monkeypatch):
 import test_peaso_azure_function_limits_native as function
 import test_peaso_azure_database_native as database
 mixed={**function.POLICY,**POLICY,'allowAzureServices':True}
 assert azure_sw15_policy.normalize({'compliance_policy':{'sw15':mixed}},[SUB])==mixed
 assert function.capture(monkeypatch,compliance_policy={'sw15':mixed})[0]=='FAIL'
 status,snapshot,_=capture(monkeypatch,policy=mixed)
 assert status=='PASS'and snapshot['metadata']['compliance_policy']['sw15']==mixed
 original=azure.collect
 def with_mixed(connector,requirements=None,**kwargs):
  connector=copy.deepcopy(connector);connector['options']['compliance_policy']['sw15']=copy.deepcopy(mixed)
  return original(connector,requirements,**kwargs)
 monkeypatch.setattr(azure,'collect',with_mixed)
 statuses,snapshot,_=database.capture(monkeypatch,'sql','azure_zero',allow_azure=True)
 assert statuses[database.IDS[0]]=='PASS'
 assert snapshot['metadata']['compliance_policy']['sw15']==mixed

@pytest.fixture(scope='module')
def legacy_data_plane_results():
 # Draft modules must never enter the ordinary test process's module cache.
 import os
 from pathlib import Path
 import subprocess
 import sys
 root=Path(__file__).resolve().parents[1]
 script="""
import json
from tests.compliance_draft_isolation import staged_registry
with staged_registry(['compliance_new_sw15']):
 from tests import test_peaso_compliance_new_sw15 as legacy
results={}
for number in (2,9):
 for fail in (False,True):
  cid=legacy.sw.IDS[number]
  row,collections=legacy.fixture(cid,fail=fail)
  results[f'{number}:{fail}']=legacy.evaluate(cid,row,collections)[0]
print(json.dumps(results))
"""
 env={**os.environ,'PYTHONPATH':str(root),'PYTHONDONTWRITEBYTECODE':'1'}
 result=subprocess.run([sys.executable,'-B','-c',script],cwd=root,env=env,
                       capture_output=True,text=True,check=True,timeout=180)
 return json.loads(result.stdout)

@pytest.mark.parametrize('number',[2,9])
@pytest.mark.parametrize('fail',[False,True])
def test_original_data_plane_reviewed_fixture_branch_retained(number,fail,legacy_data_plane_results):
 assert legacy_data_plane_results[f'{number}:{fail}']==('FAIL'if fail else'PASS')
