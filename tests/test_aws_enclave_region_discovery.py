"""Enclave applicability gates native history; synthetic SDK evidence only."""
import copy
import threading
from types import SimpleNamespace
import pytest
from peaso.collectors import aws, aws_kms_enclave_native as native
from peaso.checks.aws_enclave_debug_review_20261019 import evaluate_empty_inventory
from test_peaso_aws_bulk_inventory import sdk, ACCOUNT, REGION
from test_peaso_aws_kms_enclave_native import NOW

FILTER={'Filters':[{'Name':'enclave-options.enabled','Values':['true']}]}
PARENT={'OwnerId':ACCOUNT,'Instances':[{'InstanceId':'i-0123456789abcdef0','EnclaveOptions':{'Enabled':True}}]}

@pytest.mark.parametrize('mode',['empty','denied','truncated','foreign','malformed','duplicate'])
def test_unconfigured_or_incomplete_discovery_never_starts_history(sdk,monkeypatch,mode):
 session,add=sdk;ec2=add('ec2');request=aws.Requests({'max_pages':1,'retry_attempts':1},sleep=lambda _:None);request.observed_at=NOW
 if mode=='denied':ec2.add_client_error('describe_instances','AccessDeniedException',expected_params=FILTER)
 else:
  row=copy.deepcopy(PARENT)
  if mode=='foreign':row['OwnerId']='999999999999'
  if mode=='malformed':row['Instances'][0]['EnclaveOptions']={}
  if mode=='duplicate':row['Instances']*=2
  data={'Reservations':[] if mode=='empty' else [row]}
  if mode=='truncated':data['NextToken']='more'
  ec2.add_response('describe_instances',data,FILTER)
 monkeypatch.setattr(native,'events',lambda *args:pytest.fail('History read without complete applicable discovery'))
 result=native.applicable_events(request,session,REGION,ACCOUNT)
 assert request.calls==1
 if mode=='empty':
  assert result.status=='empty'
  collection={'type':'cloudtrail_event','scope':ACCOUNT+'/'+REGION,'status':'empty','items':[],'error':result.error}
  status,evidence=evaluate_empty_inventory({'provider':'aws','scope':ACCOUNT+'/'+REGION},collection)
  assert status=='NOT_APPLICABLE' and evidence['history_collected']is False
  status,_=evaluate_empty_inventory({'provider':'aws','scope':'999999999999/'+REGION},collection)
  assert status=='UNKNOWN'
 else:assert result.status not in ('collected','empty')
 ec2.assert_no_pending_responses()


def test_paginated_discovery_finds_parent_on_later_page_before_history(sdk,monkeypatch):
 session,add=sdk;ec2=add('ec2')
 ec2.add_response('describe_instances',{'Reservations':[],'NextToken':'more'},FILTER)
 ec2.add_response('describe_instances',{'Reservations':[PARENT]},{**FILTER,'NextToken':'more'})
 sentinel=aws.ReadResult([{'EventId':'synthetic'}]);calls=[]
 monkeypatch.setattr(native,'events',lambda *args:(calls.append(args[2:])or sentinel))
 result=native.applicable_events(aws.Requests({}),session,REGION,ACCOUNT)
 assert result is sentinel and calls==[(REGION,ACCOUNT)]
 ec2.assert_no_pending_responses()


def test_all_history_mode_retains_historical_and_cross_account_use_without_ec2(monkeypatch):
 sentinel=aws.ReadResult([],'empty')
 monkeypatch.setattr(native,'discover_region',lambda *args:pytest.fail('Explicit all-history mode must not require current EC2 parents'))
 monkeypatch.setattr(native,'events',lambda *args:sentinel)
 assert native.applicable_events(aws.Requests({'enclave_history_mode':'all'}),object(),REGION,ACCOUNT)is sentinel


def test_account_region_discovery_overlaps_and_only_candidates_read_history(monkeypatch):
 barrier=threading.Barrier(3);session=object();calls=[]
 request=SimpleNamespace(max_calls=None,observed_at=NOW)
 def discover(request,session,region,account):
  barrier.wait(timeout=5)
  candidate=region in ('us-east-1','eu-west-1')
  return aws.ReadResult([{'InstanceId':'i-0123456789abcdef0'}]if candidate else [],'collected'if candidate else'empty',{'code':'configured'if candidate else'no_current_enclave_enabled_instances'})
 monkeypatch.setattr(native,'discover_region',discover)
 regions=['us-east-1','us-west-2','eu-west-1']
 evidence=native.discover_accounts(request,[(session,{'Account':ACCOUNT})],{ACCOUNT:regions})
 assert {x['region']for x in evidence if x['candidate']}=={'us-east-1','eu-west-1'}
 monkeypatch.setattr(native,'events',lambda request,session,region,account:(calls.append(region)or aws.ReadResult([],'empty')))
 for region in regions:native.applicable_events(request,session,region,ACCOUNT)
 assert calls==['us-east-1','eu-west-1']


def test_public_collector_runs_candidate_regions_together_with_one_service_worker(monkeypatch):
 import boto3
 from botocore.stub import Stubber
 from contextlib import ExitStack
 from peaso.collectors import collect_live
 from peaso.engine import plan_collection,evaluate_snapshot
 regions=['us-east-1','us-west-2'];session=boto3.Session(aws_access_key_id='fixture',aws_secret_access_key='fixture',region_name=REGION)
 clients={};barrier=threading.Barrier(2);visited=[]
 with ExitStack()as stack:
  sts=session.client('sts',region_name=REGION);clients['sts',REGION]=sts
  stub=stack.enter_context(Stubber(sts));stub.add_response('get_caller_identity',{'Account':ACCOUNT,'Arn':f'arn:aws:iam::{ACCOUNT}:user/fixture','UserId':'fixture'}, {})
  for region in regions:
   ec2=session.client('ec2',region_name=region);clients['ec2',region]=ec2
   stub=stack.enter_context(Stubber(ec2));stub.add_response('describe_instances',{'Reservations':[PARENT]},FILTER)
  monkeypatch.setattr(aws.Requests,'client',lambda self,s,service,region:clients[service,region])
  monkeypatch.setattr(aws,'_session',lambda auth,region:(session,'synthetic-region-overlap'))
  def history(requests,session,region,account):
   visited.append(region);barrier.wait(timeout=5);return aws.ReadResult([],'empty')
  monkeypatch.setattr(native,'events',history)
  check='aws.review.kms.enclave_debug_measurements'
  connector={'provider':'aws','scopes':[ACCOUNT+'/'+r for r in regions],'options':{'service_concurrency':1,'activity_concurrency':2}}
  captured=collect_live(connector,plan_collection({'connector':connector,'checks':[check]}))
  rows=evaluate_snapshot(captured,checks=[check])['findings']
  assert sorted(visited)==sorted(regions)
  assert rows and all(r['status']=='EMPTY'for r in rows)
  assert {c['scope']for c in captured['collections']if c['type']=='cloudtrail_event'}=={ACCOUNT+'/'+r for r in regions}
  assert len(captured['metadata']['enclave_region_discovery'])==2


@pytest.mark.parametrize('provider,mode',[('aws','bogus'),('aws',True),('gcp','auto')])
def test_invalid_enclave_mode_rejected_at_hosted_boundary(provider,mode):
 from peaso.server.validation import validate_connector
 from fastapi import HTTPException
 with pytest.raises(HTTPException)as exc:
  validate_connector(provider,{}, {'enclave_history_mode':mode},object())
 assert exc.value.status_code==422
