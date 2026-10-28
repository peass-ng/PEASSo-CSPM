"""Native SDK policy shapes, authorization and ownership reach the signed check."""
import copy,json
import pytest
from test_peaso_aws_bulk_inventory import sdk,ACCOUNT,REGION
from peaso.collectors import aws,collect_live
from peaso.collectors import aws_resource_policy_native as native
from peaso.snapshot import make_snapshot
from peaso.engine import evaluate_snapshot,plan_collection

@pytest.fixture(autouse=True)
def isolate_original_four_families(monkeypatch):
 # This suite exercises the original SDK contracts. Extended discovery and
 # default combined dispatch are tested separately with every recipe.
 monkeypatch.setattr(native, 'extended_policies', lambda *args: aws.ReadResult([], 'empty'))
KIND='aws_resource_policy';CHECK='aws_cis_aws_resource_policy_unrestricted_principal';SCOPE=ACCOUNT+'/'+REGION
ARNS={s:f'arn:aws:{s}:{REGION}:{ACCOUNT}:'+tail for s,tail in [('sns','fixture'),('sqs','fixture'),('lambda','function:fixture'),('ecr','repository/fixture')]}
URL=f'https://sqs.{REGION}.amazonaws.com/{ACCOUNT}/fixture'
def document(arn,mode='public'):
 statement={'Effect':'Allow','Principal':'*','Action':'*','Resource':arn}
 if mode=='private':statement['Principal']={'AWS':f'arn:aws:iam::{ACCOUNT}:root'}
 if mode=='condition':statement['Condition']={'StringEquals':{'aws:SourceAccount':ACCOUNT}}
 if mode=='deny':statement['Effect']='Deny'
 return {'Version':'2012-10-17','Statement':[statement]}

def setup(sdk,service,mode='public'):
 session,add=sdk;stubs={s:add(s)for s in ['sns','sqs','lambda','ecr']};source={'sns':{'TopicArn':ARNS['sns']},'lambda':{'FunctionArn':ARNS['lambda'],'FunctionName':'fixture','Environment':{'Variables':{'PRIVATE_VALUE':'DO_NOT_RETAIN'}}},'ecr':{'repositoryArn':ARNS['ecr'],'repositoryName':'fixture','registryId':ACCOUNT},'sqs':URL}[service]
 if mode=='foreign':source=source.replace(ACCOUNT,'999999999999')if isinstance(source,str)else{k:(v.replace(ACCOUNT,'999999999999')if isinstance(v,str)else v)for k,v in source.items()}
 if mode=='url_host':source=URL.replace('amazonaws.com','attacker.invalid')
 if mode=='url_query':source=URL+'?next=evil'
 if mode=='url_http':source=URL.replace('https:','http:')
 for s,op,key in [('sns','list_topics','Topics'),('sqs','list_queues','QueueUrls'),('lambda','list_functions','Functions'),('ecr','describe_repositories','repositories')]:
  params={'MaxResults':1000}if s=='sqs'else{}
  response={key:[source]if s==service else[]}
  if mode=='duplicate'and s==service:response[key]*=2
  if mode=='truncated'and s==service:response['NextToken'if s in ('sns','sqs')else'NextMarker'if s=='lambda'else'nextToken']='more'
  if mode=='list_denied'and s==service:stubs[s].add_client_error(op,'AccessDeniedException',expected_params=params)
  else:
   if mode=='pagination'and s==service:
    token='NextToken'if s in ('sns','sqs')else'NextMarker'if s=='lambda'else'nextToken'
    stubs[s].add_response(op,{key:[],token:'more'},params)
    params={**params,('Marker'if s=='lambda'else token):'more'}
   stubs[s].add_response(op,response,params)
 if mode in ('foreign','url_host','url_query','url_http','list_denied'):return session,stubs
 arn=ARNS[service];raw=json.dumps(document(arn,mode))
 operation={'sns':'get_topic_attributes','sqs':'get_queue_attributes','lambda':'get_policy','ecr':'get_repository_policy'}[service]
 params={'sns':{'TopicArn':arn},'sqs':{'QueueUrl':URL,'AttributeNames':['All']},'lambda':{'FunctionName':'fixture'},'ecr':{'repositoryName':'fixture'}}[service]
 if mode=='detail_denied':stubs[service].add_client_error(operation,'AccessDeniedException',http_status_code=403,expected_params=params)
 elif mode=='missing_policy'and service in ('lambda','ecr'):stubs[service].add_client_error(operation,'ResourceNotFoundException'if service=='lambda'else'RepositoryPolicyNotFoundException',http_status_code=404,expected_params=params)
 elif mode=='not_found':stubs[service].add_client_error(operation,'ResourceNotFoundException',http_status_code=404,expected_params=params)
 else:
  response={'sns':{'Attributes':{'TopicArn':arn,'Owner':ACCOUNT,'Policy':raw}},'sqs':{'Attributes':{'QueueArn':arn,'Policy':raw}},'lambda':{'Policy':raw,'RevisionId':'revision'},'ecr':{'registryId':ACCOUNT,'repositoryName':'fixture','policyText':raw}}[service]
  if mode=='malformed':
   if service in ('sns','sqs'):response['Attributes']['Policy']='{bad'
   else:response['Policy'if service=='lambda'else'policyText']='{bad'
  if mode=='missing_policy':response['Attributes'].pop('Policy')
  if mode=='wrong_detail':
   if service=='sns':response['Attributes']['TopicArn']=arn.replace(ACCOUNT,'999999999999')
   elif service=='sqs':response['Attributes']['QueueArn']=arn.replace(ACCOUNT,'999999999999')
   elif service=='ecr':response['registryId']='999999999999'
  stubs[service].add_response(operation,response,params)
 return session,stubs

def verdict(read):
 snapshot=make_snapshot('aws',[SCOPE],[{'type':KIND,'scope':SCOPE,'service':'aws','status':read.status,'items':read.items,**({'error':read.error}if read.error else{})}])
 return evaluate_snapshot(snapshot,checks=[CHECK])['findings'],snapshot

@pytest.mark.parametrize('service',['sns','sqs','lambda','ecr'])
@pytest.mark.parametrize('mode,status',[('public','FAIL'),('private','PASS'),('condition','PASS'),('deny','PASS'),('malformed','UNKNOWN'),('detail_denied','DENIED'),('list_denied','DENIED'),('foreign','UNKNOWN'),('duplicate','UNKNOWN'),('truncated','UNKNOWN')])
def test_sdk_shapes_are_scoped_and_fail_closed(sdk,service,mode,status):
 session,stubs=setup(sdk,service,mode);read=native.policies(aws.Requests({'max_pages':1,'retry_attempts':1}),session,REGION,ACCOUNT);findings,snapshot=verdict(read)
 if mode=='public':
  assert read.items[0]['_provenance']['owner_account']==ACCOUNT
  assert read.items[0]['_provenance']['families']==[service+'-base']
 if mode in ('duplicate','truncated'):
  assert {f['status'] for f in findings} == {'FAIL','UNKNOWN'},findings
 else:
  assert findings and all(f['status']==status for f in findings),findings
 assert 'DO_NOT_RETAIN'not in json.dumps(snapshot)
 for stub in stubs.values():stub.assert_no_pending_responses()

@pytest.mark.parametrize('service',['sns','sqs','lambda','ecr'])
def test_typed_policy_absence_is_not_synthetic_pass(sdk,service):
 session,stubs=setup(sdk,service,'missing_policy');read=native.policies(aws.Requests({}),session,REGION,ACCOUNT);findings,_=verdict(read)
 assert all(f['status']!='PASS'for f in findings)
 assert read.status==('malformed'if service=='sns'else'empty')
 for stub in stubs.values():stub.assert_no_pending_responses()

@pytest.mark.parametrize('mode',['url_host','url_query','url_http'])
def test_queue_urls_cannot_redirect_reads_or_cross_account(sdk,mode):
 session,stubs=setup(sdk,'sqs',mode);read=native.policies(aws.Requests({}),session,REGION,ACCOUNT)
 assert read.status=='malformed'and not read.items
 for stub in stubs.values():stub.assert_no_pending_responses()

@pytest.mark.parametrize('service',['sns','sqs','ecr'])
def test_detail_identity_must_match_requested_resource(sdk,service):
 session,stubs=setup(sdk,service,'wrong_detail');read=native.policies(aws.Requests({}),session,REGION,ACCOUNT)
 assert read.status=='malformed'and not read.items
 for stub in stubs.values():stub.assert_no_pending_responses()

def test_live_dispatcher_and_signed_check_are_connected(sdk,monkeypatch):
 session,stubs=setup(sdk,'sns','public');_,add=sdk;sts=add('sts');sts.add_response('get_caller_identity',{'Account':ACCOUNT,'Arn':f'arn:aws:iam::{ACCOUNT}:user/fixture','UserId':'fixture'}, {})
 monkeypatch.setattr(aws,'_session',lambda auth,region:(session,'fixture-pinned'))
 connector={'provider':'aws','scopes':[SCOPE],'options':{'service_concurrency':1,'retry_attempts':1}}
 snapshot=collect_live(connector,plan_collection({'connector':connector,'checks':[CHECK]}));findings=evaluate_snapshot(snapshot,checks=[CHECK])['findings']
 assert any(f['status']=='FAIL'and f['scope']==SCOPE for f in findings),findings
 assert next(c for c in snapshot['collections']if c['type']==KIND and c['scope']==SCOPE)['status']=='collected'
 for stub in [sts,*stubs.values()]:stub.assert_no_pending_responses()

def test_actions_are_existing_exact_metadata_grants():
 from scripts.peaso_deploy_customer_policy import build_policy,split_policy,iam_action
 granted={a for d in split_policy(build_policy())for s in d['Statement']for a in([s['Action']]if isinstance(s['Action'],str)else s['Action'])}
 assert native.READ_ACTIONS<=aws.READ_ACTIONS
 assert {iam_action(*pair)for pair in native.READ_ACTIONS}<=granted
 assert aws.FETCHERS[KIND]is native.policies

@pytest.mark.parametrize('service',['sns','sqs','lambda','ecr'])
def test_successful_second_page_reaches_engine(sdk,service):
 session,stubs=setup(sdk,service,'pagination');read=native.policies(aws.Requests({'max_pages':2}),session,REGION,ACCOUNT);findings,_=verdict(read)
 assert read.status=='collected'and len(read.items)==1 and findings[0]['status']=='FAIL'
 for stub in stubs.values():stub.assert_no_pending_responses()

@pytest.mark.parametrize('service',['sns','sqs','lambda','ecr'])
def test_full_scan_base_enricher_reuses_native_policy_request_cache(sdk,monkeypatch,service):
 session,stubs=setup(sdk,service,'public');requests=aws.Requests({});read=native.policies(requests,session,REGION,ACCOUNT);assert read.status=='collected'
 before=requests.calls;extra=0
 if service=='lambda':
  stubs[service].add_client_error('get_function_url_config','ResourceNotFoundException',expected_params={'FunctionName':'fixture'});extra=1
 if service=='ecr':
  stubs[service].add_client_error('get_lifecycle_policy','LifecyclePolicyNotFoundException',expected_params={'repositoryName':'fixture'});extra=1
 monkeypatch.setattr(aws,'ENRICHERS',{})
 kind,item={'sns':('sns_topic',{'TopicArn':ARNS['sns']}),'sqs':('sqs_queue',URL),'lambda':('lambda_function',{'FunctionArn':ARNS['lambda'],'FunctionName':'fixture'}),'ecr':('ecr_repository',{'repositoryArn':ARNS['ecr'],'repositoryName':'fixture','registryId':ACCOUNT})}[service]
 aws._enrich(requests,session,REGION,kind,[item],account=ACCOUNT,partition='aws')
 assert requests.calls==before+extra
 for stub in stubs.values():stub.assert_no_pending_responses()
