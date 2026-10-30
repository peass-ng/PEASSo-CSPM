# Historical fixture contracts; current native admission is tested separately.
"""Service-complete native ARM child joins through frozen SW13/SW23."""
import copy,json
from datetime import datetime,timezone,timedelta
from urllib.parse import urlsplit
import pytest
from peaso.collectors import azure,collect_live,azure_storage_recovery_metadata_native as native
from tests.archived_check_contract import evaluate_snapshot, plan_collection
from tests.test_peaso_azure_bulk_native import Transport,parent,routes,SCOPE,SUB,BASE,STORAGE
VAULT=BASE+'Microsoft.RecoveryServices/vaults/vault'
PROTECTED=VAULT+'/backupFabrics/Azure/protectionContainers/storagecontainer;storage;rg;account/protectedItems/azurefileshare;share'
POINT=PROTECTED+'/recoveryPoints/123456'
CONTAINER=STORAGE+'/blobServices/default/containers/container'
POLICY=CONTAINER+'/immutabilityPolicies/default'


def review():
 now=datetime.now(timezone.utc)
 return {'compliance_parameters':{'azure_storage_recovery':{'scope':SCOPE,'status':'collected','authorized_by':'fixture-security-owner','document_id':'review-2026','observed_at':(now-timedelta(hours=1)).isoformat(),'expires_at':(now+timedelta(days=1)).isoformat(),'controls':{'defaultImmutability':{'accountIds':[STORAGE]},'recoveryPointRetention':{'minRetentionDays':30}}}}}


def storage_case(mode='good'):
 policy={'state':'Locked','immutabilityPeriodSinceCreationInDays':30}
 ap={'immutableStorageWithVersioning':{'enabled':True,'immutabilityPolicy':copy.deepcopy(policy)}}
 cp={'immutableStorageWithVersioning':{'enabled':True},'hasImmutabilityPolicy':False,'deleted':False}
 if mode=='time_policy':
  ap['immutableStorageWithVersioning']={'enabled':False};cp.update(immutableStorageWithVersioning={'enabled':False},hasImmutabilityPolicy=True)
 if mode in('container_policy','container_disabled_override'):
  cp['hasImmutabilityPolicy']=True
  if mode=='container_disabled_override':policy['state']='Disabled'
 if mode in('embedded_matching','embedded_conflict','embedded_presence_conflict'):
  cp['hasImmutabilityPolicy']=mode!='embedded_presence_conflict'
  cp['immutabilityPolicy']={'properties':{**policy,'immutabilityPeriodSinceCreationInDays':7 if mode=='embedded_conflict'else 30}}
 if mode=='absent':ap['immutableStorageWithVersioning']={'enabled':False};cp['immutableStorageWithVersioning']={'enabled':False}
 if mode=='disabled':ap['immutableStorageWithVersioning']['immutabilityPolicy']['state']='Disabled'
 if mode=='missing_account_mode':ap.pop('immutableStorageWithVersioning')
 if mode=='missing_container_mode':cp.pop('immutableStorageWithVersioning')
 if mode=='missing_presence':cp.pop('hasImmutabilityPolicy')
 if mode=='migration':cp['immutableStorageWithVersioning']['migrationState']='InProgress'
 if mode=='conflicting_modes':cp['immutableStorageWithVersioning']['enabled']=False
 if mode=='malformed_days':ap['immutableStorageWithVersioning']['immutabilityPolicy']['immutabilityPeriodSinceCreationInDays']=True
 if mode=='deleted':cp['deleted']=True
 r=routes('storage_account',STORAGE,ap)
 r[STORAGE+'/blobServices/default/containers']={'value':[parent(CONTAINER,'Microsoft.Storage/storageAccounts/blobServices/containers',{})]}
 r[CONTAINER]=parent(CONTAINER,'Microsoft.Storage/storageAccounts/blobServices/containers',cp)
 r[POLICY]=parent(POLICY,'Microsoft.Storage/storageAccounts/blobServices/containers/immutabilityPolicies',policy)
 if mode=='no_containers':r[STORAGE+'/blobServices/default/containers']={'value':[]}
 if mode=='foreign_container':r[STORAGE+'/blobServices/default/containers']['value'][0]['id']=CONTAINER.replace('/account/','/foreign/')
 if mode=='duplicate_container':r[STORAGE+'/blobServices/default/containers']['value']*=2
 if mode=='wrong_container_get':r[CONTAINER]['id']=CONTAINER+'foreign'
 if mode=='wrong_container_type':r[CONTAINER]['type']='Microsoft.Storage/storageAccounts/fileServices/shares'
 if mode=='wrong_account_get':r[STORAGE]['id']=STORAGE+'foreign'
 if mode=='policy_get_denied':
  cp['hasImmutabilityPolicy']=True;r[POLICY]=azure.AzureReadError('forbidden',403)
 if mode=='container_get_denied':r[CONTAINER]=azure.AzureReadError('forbidden',403)
 if mode=='list_denied':r[STORAGE+'/blobServices/default/containers']=azure.AzureReadError('forbidden',403)
 if mode in('second_page','partial_page','conflicting_page'):
  listpath=STORAGE+'/blobServices/default/containers';summary=parent(CONTAINER,'Microsoft.Storage/storageAccounts/blobServices/containers',{})
  r[listpath]=lambda q:({'value':[summary]}if mode!='partial_page'else azure.AzureReadError('forbidden',403))if'page'in q else{'value':[summary]if mode=='conflicting_page'else[],'nextLink':azure.ARM+listpath+'?page=2'}
 return r


def point_case(mode='good'):
 now=datetime.now(timezone.utc);created=now-timedelta(days=1);expiry=created+timedelta(days=7 if mode=='short'else 30)
 p={'protectionState':'Protected','backupManagementType':'AzureStorage','workloadType':'AzureFileShare','protectedItemType':'AzureFileShareProtectedItem'}
 r=routes('recovery_vault',VAULT,{})
 r[VAULT+'/backupProtectedItems']={'value':[parent(PROTECTED,'Microsoft.RecoveryServices/vaults/backupFabrics/protectionContainers/protectedItems',p)]}
 props={'objectType':'AzureFileShareRecoveryPoint','recoveryPointTime':created.isoformat(),'recoveryPointProperties':{'expiryTime':expiry.isoformat(),'isSoftDeleted':False},'fileShareSnapshotUri':'private-marker'}
 r[PROTECTED+'/recoveryPoints']={'value':[{'id':POINT}]}
 r[POINT]=parent(POINT,'Microsoft.RecoveryServices/vaults/backupFabrics/protectionContainers/protectedItems/recoveryPoints',props)
 if mode=='unsupported_vm':p.update(backupManagementType='AzureIaasVM',workloadType='VM',protectedItemType='Microsoft.Compute/virtualMachines')
 if mode=='unsupported_point':props['objectType']='IaasVMRecoveryPoint'
 if mode=='stopped':p['protectionState']='ProtectionStopped'
 if mode=='unknown_state':p['protectionState']='Unknown'
 if mode=='empty_points':r[PROTECTED+'/recoveryPoints']={'value':[]}
 if mode=='soft_deleted':props['recoveryPointProperties']['isSoftDeleted']=True
 if mode=='conflicting_soft':props['isSoftDeleted']=True
 if mode=='missing_soft':props['recoveryPointProperties'].pop('isSoftDeleted')
 if mode=='missing_expiry':props['recoveryPointProperties'].pop('expiryTime')
 if mode=='timezone_missing':props['recoveryPointProperties']['expiryTime']='2026-11-01T00:00:00'
 if mode=='expiry_before_created':props['recoveryPointProperties']['expiryTime']=(created-timedelta(days=1)).isoformat()
 if mode=='future_created':props['recoveryPointTime']=(now+timedelta(days=1)).isoformat()
 if mode=='foreign_point':r[PROTECTED+'/recoveryPoints']['value'][0]['id']=POINT.replace('/azurefileshare;share/','/foreign/')
 if mode=='wrong_get':r[POINT]['id']=POINT+'foreign'
 if mode=='wrong_type':r[POINT]['type']='Microsoft.Storage/storageAccounts/blobServices/containers'
 if mode=='duplicate_point':r[PROTECTED+'/recoveryPoints']['value']*=2
 if mode=='get_denied':r[POINT]=azure.AzureReadError('forbidden',403)
 if mode=='list_denied':r[PROTECTED+'/recoveryPoints']=azure.AzureReadError('forbidden',403)
 if mode=='protected_denied':r[VAULT+'/backupProtectedItems']=azure.AzureReadError('forbidden',403)
 if mode in('second_page','partial_page'):
  path=PROTECTED+'/recoveryPoints'
  r[path]=lambda q:({'value':[{'id':POINT}]}if mode=='second_page'else azure.AzureReadError('forbidden',403))if'page'in q else{'value':[],'nextLink':azure.ARM+path+'?page=2'}
 return r


def capture(which,mode='good',options=None,planned=False):
 check=native.IMMUTABLE if which=='storage'else native.POINTS
 kind='storage_immutability_evidence'if which=='storage'else'backup_recovery_point'
 api=Transport(storage_case(mode)if which=='storage'else point_case(mode))
 c={'provider':'azure','scopes':[SUB],'options':{'retries':0,**(review()if options is None else options)}}
 kinds=plan_collection({'connector':c,'checks':[check]})if planned else[kind]
 original=azure.collect
 with pytest.MonkeyPatch.context()as m:
  m.setattr(azure,'collect',lambda c,k:original(c,k,transport=api))
  snapshot=collect_live(c,kinds)
 findings=evaluate_snapshot(snapshot,checks=[check],include_not_applicable=True)['findings']
 if mode=='wrong_account_get':assert findings and all(f['status']=='UNKNOWN'for f in findings),findings
 else:assert len(findings)==1,findings
 assert 'private-marker'not in json.dumps(snapshot)
 assert all('listKeys'not in url and'keyAndSecret'not in url for url in api.calls)
 return findings[0],snapshot,api


@pytest.mark.parametrize('mode,status',[
 ('good','PASS'),('time_policy','PASS'),('container_policy','PASS'),('container_disabled_override','FAIL'),('absent','FAIL'),('disabled','FAIL'),('no_containers','NOT_APPLICABLE'),('second_page','PASS'),
 ('embedded_matching','PASS'),('embedded_conflict','UNKNOWN'),('embedded_presence_conflict','UNKNOWN'),
 ('missing_account_mode','UNKNOWN'),('missing_container_mode','UNKNOWN'),('missing_presence','UNKNOWN'),('migration','UNKNOWN'),('conflicting_modes','UNKNOWN'),('malformed_days','UNKNOWN'),('deleted','UNKNOWN'),('foreign_container','UNKNOWN'),('duplicate_container','UNKNOWN'),('wrong_container_get','UNKNOWN'),('wrong_container_type','UNKNOWN'),('wrong_account_get','UNKNOWN'),('policy_get_denied','UNKNOWN'),('container_get_denied','UNKNOWN'),('list_denied','UNKNOWN'),('partial_page','UNKNOWN'),('conflicting_page','UNKNOWN')])
def test_actual_storage_default_inheritance_to_frozen_sw23(mode,status):
 f,s,a=capture('storage',mode)
 assert f['status']==status,f
 if mode in('policy_get_denied','container_get_denied','list_denied','partial_page'):
  assert next(c for c in s['collections']if c['type']=='storage_immutability_evidence')['status']=='denied'
 if status=='PASS':
  ev=next(c for c in s['collections']if c['type']=='storage_immutability_evidence')['items'][0]
  assert ev['_provenance']['captured_at']==s['created_at']
  assert ev['_provenance']['policy_approved']is True
  expected='container_time'if mode=='time_policy'else'container_version_default'if mode in('container_policy','embedded_matching')else'account_version_default'
  assert ev['payload']['containers']['items'][0]['effective_default_policy']['source_kind']==expected


@pytest.mark.parametrize('mode,status',[
 ('good','PASS'),('short','FAIL'),('second_page','PASS'),('stopped','NOT_APPLICABLE'),
 ('unsupported_vm','UNKNOWN'),('unsupported_point','UNKNOWN'),('unknown_state','UNKNOWN'),('empty_points','UNKNOWN'),('soft_deleted','UNKNOWN'),('conflicting_soft','UNKNOWN'),('missing_soft','UNKNOWN'),('missing_expiry','UNKNOWN'),('timezone_missing','UNKNOWN'),('expiry_before_created','UNKNOWN'),('future_created','UNKNOWN'),('foreign_point','UNKNOWN'),('wrong_get','UNKNOWN'),('wrong_type','UNKNOWN'),('duplicate_point','UNKNOWN'),('get_denied','UNKNOWN'),('list_denied','UNKNOWN'),('protected_denied','UNKNOWN'),('partial_page','UNKNOWN')])
def test_actual_file_share_recovery_point_expiry_to_frozen_sw13(mode,status):
 f,s,a=capture('points',mode)
 assert f['status']==status,f
 if mode in('get_denied','list_denied','partial_page'):
  assert next(c for c in s['collections']if c['type']=='backup_recovery_point')['status']=='denied'
 if mode=='protected_denied':
  assert next(c for c in s['collections']if c['type']=='backup_protected_item')['status']=='denied'
 if mode=='unsupported_vm':assert not any('/recoveryPoints'in url for url in a.calls)
 if status=='PASS':
  point=next(c for c in s['collections']if c['type']=='backup_recovery_point')['items'][0]
  assert point['properties']['isSoftDeleted']is False
  assert point['_provenance']['field_mapping']['properties.isSoftDeleted']=='properties.recoveryPointProperties.isSoftDeleted'


@pytest.mark.parametrize('which',['storage','points'])
def test_missing_or_expired_owner_review_never_becomes_policy_approval(which):
 # The registered storage successor evaluates the native default retention
 # policy itself (no owner review input); recovery points still need review.
 expected='PASS'if which=='storage'else'UNKNOWN'
 kind='storage_immutability_evidence'
 opts=review();p=opts['compliance_parameters']['azure_storage_recovery'];p['observed_at']=(datetime.now(timezone.utc)-timedelta(days=2)).isoformat();p['expires_at']=(datetime.now(timezone.utc)-timedelta(days=1)).isoformat()
 for options in ({},opts):
  f,s,_=capture(which,options=options)
  assert f['status']==expected,f
  if which=='storage':assert all(row['_provenance']['policy_approved']is False for c in s['collections']if c['type']==kind for row in c['items'])


@pytest.mark.parametrize('which',['storage','points'])
def test_real_engine_planner_produces_native_supported_positive(which):
 assert capture(which,planned=True)[0]['status']=='PASS'


@pytest.mark.parametrize('mode',['local','cognito'])
@pytest.mark.parametrize('which',['storage','points'])
def test_provider_bound_intake_to_real_native_pipeline(mode,which):
 from types import SimpleNamespace
 from peaso.server.validation import validate_connector
 opts=review()
 validate_connector('azure',{'method':'token','arm_token':'fixture'},opts,SimpleNamespace(auth_mode=mode))
 assert capture(which,options=opts,planned=True)[0]['status']=='PASS'

@pytest.mark.parametrize('mode',['local','cognito'])
@pytest.mark.parametrize('provider',['aws','gcp','k8s'])
def test_provider_bound_intake_rejects_foreign_before_auth_return(mode,provider):
 from types import SimpleNamespace
 from fastapi import HTTPException
 from peaso.server.validation import validate_connector
 with pytest.raises(HTTPException):validate_connector(provider,{},review(),SimpleNamespace(auth_mode=mode))

@pytest.mark.parametrize('mutation',['completion','observations','foreign_account','duplicate_account','bool_retention','unknown_control','timezone'])
def test_intake_rejects_observation_injection_and_unsafe_normative_shapes(mutation):
 from types import SimpleNamespace
 from fastapi import HTTPException
 from peaso.server.validation import validate_connector
 opts=review();r=opts['compliance_parameters']['azure_storage_recovery']
 if mutation=='completion':r['complete']=True
 if mutation=='observations':r['controls']['recoveryPointRetention']['expiryTime']='2099-01-01T00:00:00Z'
 if mutation=='foreign_account':r['controls']['defaultImmutability']['accountIds']=[STORAGE.replace(SUB,'99999999-9999-9999-9999-999999999999')]
 if mutation=='duplicate_account':r['controls']['defaultImmutability']['accountIds']*=2
 if mutation=='bool_retention':r['controls']['recoveryPointRetention']['minRetentionDays']=True
 if mutation=='unknown_control':r['controls']['defaultImmutability']['effective']=True
 if mutation=='timezone':r['observed_at']='2026-01-01T00:00:00'
 with pytest.raises(HTTPException):validate_connector('azure',{},opts,SimpleNamespace(auth_mode='cognito'))

@pytest.mark.parametrize('authority',['same','foreign','stale','denied'])
def test_shallow_bulk_merge_preserves_sibling_policy_and_authority(authority):
 opts=review();r=opts['compliance_parameters']['azure_storage_recovery']
 sibling='azure|cis|another_recovery_control'
 prior={k:v for k,v in r.items()if k!='controls'}
 prior['checks']={sibling:{'criticalProtectedItemIds':['explicit-owner-reference']}}
 if authority=='foreign':prior['scope']='/subscriptions/99999999-9999-9999-9999-999999999999'
 if authority=='stale':prior['expires_at']=(datetime.now(timezone.utc)-timedelta(minutes=1)).isoformat()
 if authority=='denied':prior['status']='denied'
 original=copy.deepcopy(prior);opts['compliance_policy']={'sw13':prior,'sw23':{'untouched':True}}
 f,s,_=capture('points',options=opts)
 assert f['status']==('PASS'if authority=='same'else'UNKNOWN')
 actual=s['metadata']['compliance_policy']['sw13']
 for key in original:
  if key!='checks':assert actual[key]==original[key]
 assert actual['checks'][sibling]==original['checks'][sibling]
 assert s['metadata']['compliance_policy']['sw23']=={'untouched':True}
 assert opts['compliance_policy']['sw13']==original

@pytest.mark.parametrize('mode',['local','cognito'])
def test_combined_mfa_intake_cannot_be_rebound_by_subscription_retention(mode):
 from types import SimpleNamespace
 from peaso.server.validation import validate_connector
 opts=review();r=opts['compliance_parameters']['azure_storage_recovery']
 prior={k:v for k,v in r.items()if k!='controls'}
 prior['scope']='/tenants/11111111-2222-3333-4444-555555555555'
 prior['checks']={'azure|cis|multifactor_authentication_policy_exists_users':{'userScope':'all','requiredApplications':['All'],'requiredClientAppTypes':['all']}}
 opts['compliance_policy']={'sw13':copy.deepcopy(prior)}
 validate_connector('azure',{'method':'token','arm_token':'fixture'},opts,SimpleNamespace(auth_mode=mode))
 f,s,_=capture('points',options=opts,planned=True)
 assert f['status']=='UNKNOWN'
 assert s['metadata']['compliance_policy']['sw13']==prior
 assert native.POINTS.replace('.','|')not in prior['checks']
