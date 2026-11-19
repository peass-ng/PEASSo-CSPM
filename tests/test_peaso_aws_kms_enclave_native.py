"""AWS-documented KMS CloudTrail shapes, pre-cache privacy and signed evaluation."""
from datetime import datetime,timedelta,timezone
import copy,json
import pytest
from test_peaso_aws_bulk_inventory import sdk,ACCOUNT,REGION
from peaso.collectors import aws,collect_live
from peaso.collectors import aws_kms_enclave_native as native
from tests.archived_check_contract import evaluate_snapshot, plan_collection
from peaso.snapshot import make_snapshot
NOW=datetime(2026,10,15,tzinfo=timezone.utc);TIME=NOW-timedelta(minutes=5);ID='11111111-1111-1111-1111-111111111111';PCR='ab'*48;CHECK='aws.pci.kms.enclave_attestation_events';KIND='cloudtrail_event';SCOPE=ACCOUNT+'/'+REGION

def event(mode='good'):
 recipient={'attestationDocumentModuleId':'i-0123456789abcdef0-enc0123456789abcdef','attestationDocumentEnclaveImageDigest':PCR}
 payload={'eventID':ID,'eventName':'Decrypt','eventTime':TIME.isoformat(),'eventSource':'kms.amazonaws.com','awsRegion':REGION,'eventType':'AwsApiCall','recipientAccountId':ACCOUNT,'userIdentity':{'accessKeyId':'DO_NOT_RETAIN'},'requestParameters':{'CiphertextBlob':'DO_NOT_RETAIN'},'responseElements':{'Plaintext':'DO_NOT_RETAIN'},'additionalEventData':{'recipient':recipient}}
 if mode=='debug':recipient['attestationDocumentEnclaveImageDigest']='0'*96
 if mode=='bad_pcr':recipient['attestationDocumentEnclaveImageDigest']='not-a-hash'
 if mode=='missing_pcr':recipient.pop('attestationDocumentEnclaveImageDigest')
 if mode=='foreign':payload['recipientAccountId']='999999999999'
 if mode=='foreign_region':payload['awsRegion']='us-west-2'
 if mode=='mismatched_id':payload['eventID']='22222222-2222-2222-2222-222222222222'
 if mode=='mismatched_name':payload['eventName']='GenerateRandom'
 if mode=='mismatched_source':payload['eventSource']='secretsmanager.amazonaws.com'
 if mode=='bad_module':recipient['attestationDocumentModuleId']='i-foreign-invalid'
 if mode=='unknown_pcr':recipient['attestationDocumentEnclavePCR9']=PCR
 if mode=='extra_pcr':recipient['attestationDocumentEnclavePCR1']=PCR
 if mode=='conflicting_pcr0':recipient['attestationDocumentEnclavePCR0']='cd'*48
 if mode=='no_recipient':payload.pop('additionalEventData')
 if mode=='no_actor':payload.pop('userIdentity')
 if mode=='tpm':payload['additionalEventData']['recipient']={'attestationDocumentModuleId':'i-0123456789abcdef0-tpm0123456789abcdef','attestationDocumentNitroTPMPCR4':'cd'*32}
 if mode=='out_of_window':payload['eventTime']=(NOW-timedelta(days=2)).isoformat()
 if mode=='bad_timezone':payload['eventTime']=TIME.replace(tzinfo=None).isoformat()
 raw='{bad'if mode=='bad_json'else json.dumps(payload)
 if mode=='duplicate_json_key':raw=raw.replace('"recipientAccountId":','"recipientAccountId":"999999999999","recipientAccountId":')
 return {'EventId':ID,'EventName':'Decrypt','EventTime':NOW-timedelta(days=2)if mode=='out_of_window'else TIME,'EventSource':'kms.amazonaws.com','CloudTrailEvent':raw}

def read(sdk,mode='good'):
 session,add=sdk;stub=add('cloudtrail');requests=aws.Requests({'max_pages':1 if mode=='truncated'else 2,'retry_attempts':1},sleep=lambda _:None);requests.observed_at=NOW
 params={'LookupAttributes':[{'AttributeKey':'EventName','AttributeValue':'Decrypt'}],'StartTime':NOW-timedelta(minutes=1440),'EndTime':NOW}
 if mode=='denied':stub.add_client_error('lookup_events','AccessDeniedException',expected_params=params)
 else:
  response={'Events':[]if mode=='empty'else[event(mode)]}
  if mode=='duplicate_id':response['Events']*=2
  if mode=='truncated':response['NextToken']='more'
  if mode=='pagination':stub.add_response('lookup_events',{'Events':[],'NextToken':'more'},params);params={**params,'NextToken':'more'}
  stub.add_response('lookup_events',response,params)
 if mode in ('good','pagination','no_actor','debug','extra_pcr','empty','no_recipient','tpm'):
  for operation in sorted(native.OPERATIONS-{'Decrypt'}):stub.add_response('lookup_events',{'Events':[]},{'LookupAttributes':[{'AttributeKey':'EventName','AttributeValue':operation}],'StartTime':NOW-timedelta(minutes=1440),'EndTime':NOW})
 result=native.events(requests,session,REGION,ACCOUNT);stub.assert_no_pending_responses();return result,requests

def snapshot(read,golden=None):
 metadata={'parameters':{'approved_golden_pcrs':{'PCR0':[PCR]}if golden is None else golden}}
 return make_snapshot('aws',[SCOPE],[{'type':KIND,'scope':SCOPE,'service':'cloudtrail','status':read.status,'items':[{**row,'id':row['EventId']}for row in read.items],**({'error':read.error}if read.error else{})}],metadata=metadata)

@pytest.mark.parametrize('mode,status',[('good','PASS'),('pagination','PASS'),('no_actor','PASS'),('debug','FAIL'),('extra_pcr','UNKNOWN')])
def test_documented_metadata_reaches_predicate_without_payload_values(sdk,mode,status):
 result,requests=read(sdk,mode);snap=snapshot(result);findings=evaluate_snapshot(snap,checks=[CHECK])['findings'];assert len(findings)==1 and findings[0]['status']==status,findings
 assert 'DO_NOT_RETAIN'not in json.dumps(snap)
 for future in requests._cache.values():assert 'DO_NOT_RETAIN'not in json.dumps(future.result(),default=str)
 assert requests.calls==(6 if mode=='pagination'else 5)

@pytest.mark.parametrize('mode',['bad_pcr','missing_pcr','foreign','foreign_region','mismatched_id','mismatched_name','mismatched_source','bad_module','unknown_pcr','conflicting_pcr0','out_of_window','bad_timezone','bad_json','duplicate_json_key','duplicate_id','truncated','denied'])
def test_unbound_partial_or_malformed_events_never_become_pass(sdk,mode):
 result,_=read(sdk,mode);assert result.status not in('collected','empty')and result.items==[]
 assert all(f['status']not in('PASS','FAIL')for f in evaluate_snapshot(snapshot(result),checks=[CHECK])['findings'])

@pytest.mark.parametrize('mode',['empty','no_recipient','tpm'])
def test_no_enclave_events_is_not_a_golden_image_pass(sdk,mode):
 result,_=read(sdk,mode);assert result.status=='empty'and result.items==[]
 assert all(f['status']!='PASS'for f in evaluate_snapshot(snapshot(result),checks=[CHECK])['findings'])

@pytest.mark.parametrize('golden',[{}, {'PCR0':['cd'*48]}, {'PCR0':[PCR],'PCR1':[PCR]}])
def test_owner_policy_absent_or_mismatched_is_not_automatically_trusted(sdk,golden):
 result,_=read(sdk);findings=evaluate_snapshot(snapshot(result,golden),checks=[CHECK])['findings'];assert findings[0]['status']==('FAIL'if golden=={'PCR0':['cd'*48]}else'UNKNOWN')

def test_actual_collect_live_dispatches_exact_existing_metadata_read(sdk,monkeypatch):
 session,add=sdk;ec2=add('ec2');ec2.add_response('describe_instances',{'Reservations':[{'OwnerId':ACCOUNT,'Instances':[{'InstanceId':'i-0123456789abcdef0','EnclaveOptions':{'Enabled':True}}]}]},{'Filters':[{'Name':'enclave-options.enabled','Values':['true']}]});sts=add('sts');logs=add('cloudtrail');sts.add_response('get_caller_identity',{'Account':ACCOUNT,'Arn':f'arn:aws:iam::{ACCOUNT}:user/fixture','UserId':'fixture'},{});logs.add_response('lookup_events',{'Events':[event()]},{'LookupAttributes':[{'AttributeKey':'EventName','AttributeValue':'Decrypt'}],'StartTime':NOW-timedelta(minutes=1440),'EndTime':NOW})
 original=aws.Requests.__init__
 for operation in sorted(native.OPERATIONS-{'Decrypt'}):logs.add_response('lookup_events',{'Events':[]},{'LookupAttributes':[{'AttributeKey':'EventName','AttributeValue':operation}],'StartTime':NOW-timedelta(minutes=1440),'EndTime':NOW})
 def initialized(self,*a,**kw):kw['sleep']=lambda _:None;original(self,*a,**kw);self.observed_at=NOW
 monkeypatch.setattr(aws.Requests,'__init__',initialized);monkeypatch.setattr(aws,'_session',lambda auth,region:(session,'fixture-pinned'))
 connector={'provider':'aws','scopes':[SCOPE],'options':{'service_concurrency':1,'compliance_parameters':{'approved_golden_pcrs':{'PCR0':[PCR]}}}}
 captured=collect_live(connector,plan_collection({'connector':connector,'checks':[CHECK]}));findings=evaluate_snapshot(captured,checks=[CHECK])['findings'];assert any(f['status']=='PASS'for f in findings),findings
 assert 'DO_NOT_RETAIN'not in json.dumps(captured);sts.assert_no_pending_responses();logs.assert_no_pending_responses()

def test_native_enclave_consumer_uses_existing_grant_in_default_plan():
 from scripts.peaso_deploy_customer_policy import iam_action,build_policy,split_policy
 assert iam_action('cloudtrail','lookup_events')in{a for d in split_policy(build_policy())for s in d['Statement']for a in([s['Action']]if isinstance(s['Action'],str)else s['Action'])}
 connector={'provider':'aws','scopes':[SCOPE],'options':{}}
 assert KIND in plan_collection({'connector':connector,'checks':[CHECK]})
 assert KIND in plan_collection({'connector':connector})
 assert KIND in plan_collection({'connector':{**connector,'options':{'collect_all':True}}})

@pytest.mark.parametrize('attributes',[[{'AttributeKey':'EventSource','AttributeValue':'kms.amazonaws.com'}],[{'AttributeKey':'EventName','AttributeValue':'Decrypt','extra':'bad'}],[{'AttributeKey':'EventName','AttributeValue':'ArbitraryDecrypt'}]])
def test_arbitrary_event_queries_stay_rejected_before_any_client(monkeypatch,attributes):
 requests=aws.Requests({});monkeypatch.setattr(requests,'client',lambda *args:pytest.fail('unapproved query constructed client'))
 with pytest.raises(aws.ReadFailure,match='undeclared_activity_event_query'):requests.call(object(),'cloudtrail',REGION,'lookup_events',LookupAttributes=attributes,StartTime=TIME,EndTime=NOW)
 assert requests.calls==0

@pytest.mark.parametrize('mode',['bad_pcr','bad_json','mismatched_source'])
def test_failed_projection_future_never_retains_payload_tracebacks(sdk,mode):
 _,requests=read(sdk,mode)
 for future in requests._cache.values():
  error=future.exception();assert error is not None and error.__traceback__ is None and error.__context__ is None and'DO_NOT_RETAIN'not in str(error)

def test_enclave_query_names_do_not_change_existing_activity_projection():
 assert not native.OPERATIONS&set(aws.activity_event_names(REGION))
