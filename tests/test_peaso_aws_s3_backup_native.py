"""Real botocore response shapes through collect_live and the frozen predicate."""
import copy
from datetime import datetime,timezone
import pytest
from test_peaso_aws_bulk_inventory import sdk,ACCOUNT,REGION
from peaso.collectors import aws,collect_live
from peaso.collectors import aws_s3_backup_native as native
from peaso.engine import evaluate_snapshot,plan_collection
CHECK='aws.pci.s3.bucket_backup_plan';KIND='s3_backup_plan_coverage';BUCKET='owned-fixture-bucket';ARN='arn:aws:s3:::'+BUCKET
PID='11111111-1111-1111-1111-111111111111';SID='22222222-2222-2222-2222-222222222222';PLAN=f'arn:aws:backup:{REGION}:{ACCOUNT}:backup-plan:'+PID

def capture(sdk,monkeypatch,mode='good'):
 session,add=sdk;sts=add('sts');ec2=add('ec2');s3=add('s3');backup=add('backup')
 sts.add_response('get_caller_identity',{'Account':ACCOUNT,'Arn':f'arn:aws:iam::{ACCOUNT}:user/fixture','UserId':'fixture'}, {})
 regions=[{'RegionName':REGION,'OptInStatus':'opt-in-not-required'}]
 if mode=='duplicate_region':regions*=2
 if mode=='disabled_region':regions.append({'RegionName':'us-west-2','OptInStatus':'not-opted-in'})
 if mode in ('second_region_denied','second_region_good','cross_region','west_positive','eu_cross_region'):regions.append({'RegionName':'eu-west-1'if mode=='eu_cross_region'else'us-west-2','OptInStatus':'opt-in-not-required'})
 if mode!='restricted':
  if mode=='region_denied':ec2.add_client_error('describe_regions','UnauthorizedOperation',http_status_code=403,expected_params={'AllRegions':True})
  else:ec2.add_response('describe_regions',{'Regions':regions},{'AllRegions':True})
 s3.add_response('list_buckets',{'Buckets':[{'Name':BUCKET,'CreationDate':datetime.now(timezone.utc)}]}, {})
 if mode=='location_denied':s3.add_client_error('get_bucket_location','AccessDenied',http_status_code=403,expected_params={'Bucket':BUCKET})
 else:s3.add_response('get_bucket_location',{'LocationConstraint':'us-west-2'}if mode in('cross_region','west_positive')else{'LocationConstraint':'EU'}if mode=='eu_cross_region'else{'LocationConstraint':'ap-south-1'}if mode=='home_unproved'else{},{'Bucket':BUCKET})
 for operation in ('get_public_access_block','get_bucket_policy_status','get_bucket_policy','get_bucket_encryption','get_bucket_versioning','get_bucket_acl','get_bucket_ownership_controls','get_bucket_logging','get_bucket_lifecycle_configuration','get_bucket_notification_configuration','get_bucket_replication','get_object_lock_configuration','get_bucket_tagging'):
  # The bucket policy read pins the scanned account as expected bucket owner.
  s3.add_response(operation,{'TagSet':[]}if operation=='get_bucket_tagging'else{}, {'Bucket':BUCKET,**({'ExpectedBucketOwner':ACCOUNT}if operation=='get_bucket_policy'else{})})
 if mode not in ('restricted','region_denied','duplicate_region'):
  if mode in('west_positive','eu_cross_region'):backup.add_response('list_backup_plans',{'BackupPlansList':[]},{})
  plan_arn=PLAN.replace(REGION,'us-west-2')if mode=='west_positive'else PLAN
  summary={'BackupPlanId':PID,'BackupPlanArn':plan_arn,'VersionId':'current'}
  if mode=='foreign_plan':summary['BackupPlanArn']=PLAN.replace(ACCOUNT,'999999999999')
  if mode=='wrong_plan_type':summary['BackupPlanArn']=PLAN.replace(':backup-plan:',':restore-testing-plan:')
  response={'BackupPlansList':[]if mode=='empty'else[summary]}
  if mode=='plans_partial':response['NextToken']='more'
  if mode=='plans_duplicate':response['BackupPlansList']*=2
  if mode=='plans_denied':backup.add_client_error('list_backup_plans','AccessDeniedException',http_status_code=403,expected_params={})
  else:
   backup.add_response('list_backup_plans',{'BackupPlansList':[],'NextToken':'more'}if mode=='plans_second_page'else response,{})
   if mode=='plans_second_page':backup.add_response('list_backup_plans',response,{'NextToken':'more'})
  if mode not in ('empty','plans_denied','plans_partial','foreign_plan','wrong_plan_type'):
   current={'BackupPlanId':PID,'BackupPlanArn':plan_arn,'VersionId':'other'if mode=='stale_version'else'current','BackupPlan':{'BackupPlanName':'owned','Rules':[{'RuleName':'daily','TargetBackupVaultName':'owned','ScheduleExpression':'cron(0 5 ? * * *)'}]}}
   if mode=='missing_schedule':current['BackupPlan']['Rules'][0].pop('ScheduleExpression')
   if mode=='get_plan_denied':backup.add_client_error('get_backup_plan','AccessDeniedException',http_status_code=403,expected_params={'BackupPlanId':PID})
   else:backup.add_response('get_backup_plan',current,{'BackupPlanId':PID})
   if mode not in ('get_plan_denied','stale_version','missing_schedule'):
    listed={'BackupSelectionsList':[{'SelectionId':SID,'BackupPlanId':PID,'SelectionName':'s3','IamRoleArn':f'arn:aws:iam::{ACCOUNT}:role/backup'}]}
    if mode=='selections_partial':listed['NextToken']='more'
    backup.add_response('list_backup_selections',{'BackupSelectionsList':[],'NextToken':'more'}if mode=='selections_second_page'else listed,{'BackupPlanId':PID})
    if mode=='selections_second_page':backup.add_response('list_backup_selections',listed,{'BackupPlanId':PID,'NextToken':'more'})
    if mode!='selections_partial':
     selected={'SelectionName':'s3','IamRoleArn':f'arn:aws:iam::{ACCOUNT}:role/backup','Resources':['arn:aws:s3:::different'if mode=='missing'else ARN]}
     if mode=='wildcard':selected['Resources']=['arn:aws:s3:::*']
     if mode=='excluded':selected['NotResources']=[ARN]
     if mode=='conditions':selected['Conditions']={'StringEquals':[{'ConditionKey':'aws:ResourceTag/env','ConditionValue':'production'}]}
     if mode=='tags':selected['ListOfTags']=[{'ConditionType':'STRINGEQUALS','ConditionKey':'env','ConditionValue':'production'}]
     if mode=='implicit_all':selected.pop('Resources')
     if mode=='explicit_empty':selected['Resources']=[]
     response={'BackupPlanId':PID,'SelectionId':'foreign'if mode=='foreign_selection'else SID,'BackupSelection':selected}
     if mode=='get_selection_denied':backup.add_client_error('get_backup_selection','AccessDeniedException',http_status_code=403,expected_params={'BackupPlanId':PID,'SelectionId':SID})
     else:backup.add_response('get_backup_selection',response,{'BackupPlanId':PID,'SelectionId':SID})
  if mode in('second_region_good','cross_region'):backup.add_response('list_backup_plans',{'BackupPlansList':[]},{})
  if mode=='second_region_denied':backup.add_client_error('list_backup_plans','AccessDeniedException',http_status_code=403,expected_params={})
 monkeypatch.setattr(aws,'_session',lambda auth,region:(session,'fixture-pinned'))
 connector={'provider':'aws','scopes':[ACCOUNT],'options':{'service_concurrency':1,'retry_attempts':1,'max_pages':2 if mode in ('plans_second_page','selections_second_page')else 1,**({'regions':[REGION]}if mode=='restricted'else{})}}
 snap=collect_live(connector,plan_collection({'connector':connector,'checks':[CHECK]}));findings=evaluate_snapshot(snap,checks=[CHECK])['findings']
 target=[r for r in findings if r['scope']==ACCOUNT+'/global']
 assert len(target)==1,findings
 for stub in(sts,ec2,s3,backup):stub.assert_no_pending_responses()
 return target[0],snap

@pytest.mark.parametrize('mode,status',[
 ('west_positive','PASS'),('eu_cross_region','FAIL'),('home_unproved','UNKNOWN'),('cross_region','FAIL'),('location_denied','UNKNOWN'),('implicit_all','UNKNOWN'),('explicit_empty','UNKNOWN'),('good','PASS'),('plans_second_page','PASS'),('selections_second_page','PASS'),('second_region_good','PASS'),('disabled_region','PASS'),('missing','FAIL'),('excluded','FAIL'),('empty','FAIL'),('wildcard','UNKNOWN'),('conditions','UNKNOWN'),('tags','UNKNOWN'),
 ('restricted','UNKNOWN'),('region_denied','UNKNOWN'),('duplicate_region','UNKNOWN'),('plans_denied','UNKNOWN'),('plans_partial','UNKNOWN'),
 ('get_plan_denied','UNKNOWN'),('foreign_plan','UNKNOWN'),('wrong_plan_type','UNKNOWN'),('stale_version','UNKNOWN'),('missing_schedule','UNKNOWN'),('selections_partial','UNKNOWN'),
 ('foreign_selection','UNKNOWN'),('get_selection_denied','UNKNOWN'),('second_region_denied','UNKNOWN'),('plans_duplicate','UNKNOWN')])
def test_actual_sdk_collector_to_signed_engine(sdk,monkeypatch,mode,status):
 finding,snap=capture(sdk,monkeypatch,mode);assert finding['status']==status,finding
 if mode in ('plans_denied','get_plan_denied','get_selection_denied','second_region_denied'):
  col=next(c for c in snap['collections']if c['type']==KIND)
  assert col['status']=='denied' and col['items']==[]
 if mode in ('good','plans_second_page','selections_second_page','second_region_good','disabled_region'):
  col=next(c for c in snap['collections']if c['type']==KIND)
  assert col['scope']==ACCOUNT+'/global' and col['items'][0]['AllEnabledRegionsCollected']is True
  assert col['items'][0]['Selections'][0]['Resources']==[ARN]
  assert col['items'][0]['_provenance']['regions']==[REGION,'us-west-2']if mode=='second_region_good'else col['items'][0]['_provenance']['regions']==[REGION]

def test_registry_action_mapping_and_no_permission_expansion():
 assert aws.SPECS[KIND]==('backup','list_backup_plans','BackupPlansList')
 assert KIND in aws.GLOBAL_TYPES and aws.FETCHERS[KIND]is native.coverage
 assert native.READ_ACTIONS<=aws.READ_ACTIONS
 assert native.READ_ACTIONS=={('ec2','describe_regions'),('backup','list_backup_plans'),('backup','get_backup_plan'),('backup','list_backup_selections'),('backup','get_backup_selection'),('s3','list_buckets'),('s3','get_bucket_location')}


@pytest.mark.parametrize('plan_id,selection_id,status',[
 ('aws/efs/73d922fb-9312-3a70-99c3-e69367f9fdad',SID,'PASS'),
 ('QWxwaGEvQmV0YQ==','c2VsZWN0aW9uL2lk==','PASS'),
])
def test_native_managed_and_opaque_ids_preserve_exact_joins(sdk,monkeypatch,plan_id,selection_id,status):
 monkeypatch.setitem(globals(),'PID',plan_id)
 monkeypatch.setitem(globals(),'SID',selection_id)
 monkeypatch.setitem(globals(),'PLAN',f'arn:aws:backup:{REGION}:{ACCOUNT}:backup-plan:'+plan_id)
 finding,snapshot=capture(sdk,monkeypatch,'good')
 assert finding['status']==status

@pytest.mark.parametrize('plan_id',['aws/efs/../foreign','plan\nforeign','foreign:plan','/foreign','plan?x=1'])
def test_unsafe_native_plan_ids_cannot_form_aggregate(sdk,plan_id):
 from types import SimpleNamespace
 session,_=sdk
 def pages(session,service,region,operation,expression,**kwargs):
  if operation=='list_buckets':return aws.ReadResult([{'Name':BUCKET}],'collected')
  assert operation=='list_backup_plans'
  return aws.ReadResult([{'BackupPlanId':plan_id,'BackupPlanArn':f'arn:aws:backup:{REGION}:{ACCOUNT}:backup-plan:'+plan_id}],'collected')
 requests=SimpleNamespace(backup_region_discovery={ACCOUNT:aws.ReadResult([{'RegionName':REGION,'OptInStatus':'opt-in-not-required'}],'collected')},pages=pages)
 got=native.coverage(requests,session,REGION,ACCOUNT)
 assert got.status=='malformed'and got.items==[]

@pytest.mark.parametrize('selection_id',['selection\nforeign','../foreign','foreign:selection','/foreign'])
def test_unsafe_native_selection_ids_cannot_form_aggregate(sdk,selection_id):
 from types import SimpleNamespace
 session,_=sdk
 def pages(session,service,region,operation,expression,**kwargs):
  if operation=='list_buckets':return aws.ReadResult([{'Name':BUCKET}],'collected')
  if operation=='list_backup_plans':return aws.ReadResult([{'BackupPlanId':PID,'BackupPlanArn':PLAN}],'collected')
  assert operation=='list_backup_selections'
  return aws.ReadResult([{'SelectionId':selection_id}],'collected')
 def detail(session,service,region,operation,**kwargs):
  assert operation=='get_backup_plan'
  return {'collection_status':'collected','BackupPlanId':PID,'BackupPlanArn':PLAN,'VersionId':'current','BackupPlan':{'Rules':[{'RuleName':'daily','ScheduleExpression':'cron(0 5 ? * * *)'}]}}
 requests=SimpleNamespace(backup_region_discovery={ACCOUNT:aws.ReadResult([{'RegionName':REGION,'OptInStatus':'opt-in-not-required'}],'collected')},pages=pages,detail=detail)
 got=native.coverage(requests,session,REGION,ACCOUNT)
 assert got.status=='malformed'and got.items==[]

@pytest.mark.parametrize('mode',['foreign_plan','wrong_plan_type','foreign_selection','stale_version'])
def test_managed_plan_ids_keep_existing_foreign_and_version_guards(sdk,monkeypatch,mode):
 plan_id='aws/efs/73d922fb-9312-3a70-99c3-e69367f9fdad'
 monkeypatch.setitem(globals(),'PID',plan_id)
 monkeypatch.setitem(globals(),'PLAN',f'arn:aws:backup:{REGION}:{ACCOUNT}:backup-plan:'+plan_id)
 finding,snapshot=capture(sdk,monkeypatch,mode)
 assert finding['status']=='UNKNOWN'


@pytest.mark.parametrize('selector,mixed,expected',[(
 'Conditions',None,'UNKNOWN'),('ListOfTags',None,'UNKNOWN'),
 ('Conditions','literal','PASS'),('ListOfTags','literal','PASS'),
 ('Conditions','miss','UNKNOWN'),('ListOfTags','miss','UNKNOWN')])
def test_native_empty_resource_conditional_selection_remains_uncertain_without_blocking_literal(sdk,monkeypatch,selector,mixed,expected):
 session,add=sdk
 second_id='33333333-3333-3333-3333-333333333333'
 def wrapped_add(service):
  stub=add(service)
  if service!='backup':return stub
  original=stub.add_response
  def response(operation,value,params=None):
   value=copy.deepcopy(value)
   if operation=='list_backup_selections'and mixed:
    value['BackupSelectionsList'].append({'SelectionId':second_id,'BackupPlanId':PID,'SelectionName':'s3literal','IamRoleArn':f'arn:aws:iam::{ACCOUNT}:role/backup'})
   if operation=='get_backup_selection':
    literal=copy.deepcopy(value)
    value['BackupSelection'].pop('Resources')
    value['BackupSelection'][selector]=({'StringEquals':[{'ConditionKey':'aws:ResourceTag/aws:elasticfilesystem:default-backup','ConditionValue':'enabled'}]}if selector=='Conditions'else[{'ConditionType':'STRINGEQUALS','ConditionKey':'aws:elasticfilesystem:default-backup','ConditionValue':'enabled'}])
    original(operation,value,params)
    if mixed:
     literal['SelectionId']=second_id
     literal['BackupSelection']['Resources']=[ARN if mixed=='literal'else'arn:aws:s3:::different']
     original(operation,literal,{'BackupPlanId':PID,'SelectionId':second_id})
    return
   original(operation,value,params)
  monkeypatch.setattr(stub,'add_response',response)
  return stub
 finding,snapshot=capture((session,wrapped_add),monkeypatch)
 assert finding['status']==expected
 collection=next(c for c in snapshot['collections']if c['type']==KIND)
 assert collection['status']=='collected'
 rows=collection['items'][0]['Selections']
 assert rows[0]['Resources']==[]and rows[0][selector]
 assert len(rows)==(2 if mixed else 1)
