"""Focused portable candidate tests; fixture JSON is generated via actual AWS enrichers."""
import copy
import json
from pathlib import Path

import pytest
from peaso.checks import CHECKS, evaluate_check, next20_aws as CANDIDATE
from peaso.checks.facts import MemoIndex
from peaso.engine import _selection, CATEGORIES
from tests.archived_check_contract import evaluate_snapshot
from peaso.collectors import aws

FIX=json.loads((Path(__file__).parent/'fixtures/next20_aws.json').read_text())['fixtures']
EXPECTED={
 'aws_backup_plan_rule_required_frequency':'a066b3c973571b3d1df8aa9871dba4858a8c9c4c707897639d99e116ec71d1ea',
 'aws_cis_elbv2_only_tls_listeners':'231d76c0f4c55afb1796004b6ab2070eff65c74e39b84e4ca4406585b52e3396',
}

@pytest.mark.parametrize('check_id',list(EXPECTED))
def test_registration_and_signed_digest(check_id):
    assert CANDIDATE.PROPOSED_SPEC_SHA256[check_id]==EXPECTED[check_id]
    assert sum(check.id==check_id for check in CHECKS)==1


@pytest.mark.parametrize('check_id',list(EXPECTED))
@pytest.mark.parametrize('case,expected',[('pass','PASS'),('fail','FAIL'),('unknown','UNKNOWN'),('denied','UNKNOWN'),('partial','UNKNOWN'),('malformed','UNKNOWN'),('foreign_scope','UNKNOWN')])
def test_snapshot_cases(check_id,case,expected):
    fixture=FIX[check_id][case]
    status,evidence=evaluate_check(check_id,fixture['item'],MemoIndex(copy.deepcopy(fixture['index'])))
    assert status==expected,(check_id,case,evidence)
    assert isinstance(evidence,dict)

def test_redirect_without_approved_policy_is_unknown():
    fixture=FIX['aws_cis_elbv2_only_tls_listeners']['unknown']
    assert evaluate_check('aws_cis_elbv2_only_tls_listeners',fixture['item'],MemoIndex(fixture['index']))[0]=='UNKNOWN'

def test_internal_alb_http_is_fail_under_signed_listener_scope():
    fixture=copy.deepcopy(FIX['aws_cis_elbv2_only_tls_listeners']['fail'])
    fixture['item']['Scheme']='internal'
    fixture['index']['load_balancer'][0]['data']=copy.deepcopy(fixture['item'])
    fixture['index']['collections']['load_balancer'][0]['items']=[copy.deepcopy(fixture['item'])]
    assert evaluate_check('aws_cis_elbv2_only_tls_listeners',fixture['item'],MemoIndex(fixture['index']))[0]=='FAIL'

def test_public_nlb_tcp_is_fail():
    fixture=copy.deepcopy(FIX['aws_cis_elbv2_only_tls_listeners']['fail'])
    item=fixture['item']; item['Type']='network'
    item['LoadBalancerArn']=item['LoadBalancerArn'].replace('loadbalancer/app/','loadbalancer/net/')
    listener=item['Listeners']['items'][0]
    listener['ListenerArn']=listener['ListenerArn'].replace('listener/app/','listener/net/')
    listener['Protocol']='TCP'
    fixture['index']['load_balancer'][0]['data']=copy.deepcopy(item)
    fixture['index']['collections']['load_balancer'][0]['items']=[copy.deepcopy(item)]
    assert evaluate_check('aws_cis_elbv2_only_tls_listeners',item,MemoIndex(fixture['index']))[0]=='FAIL'

def test_internal_nlb_tcp_is_fail():
    fixture=copy.deepcopy(FIX['aws_cis_elbv2_only_tls_listeners']['fail'])
    item=fixture['item']; item['Type']='network'; item['Scheme']='internal'
    item['LoadBalancerArn']=item['LoadBalancerArn'].replace('loadbalancer/app/','loadbalancer/net/')
    listener=item['Listeners']['items'][0]
    listener['ListenerArn']=listener['ListenerArn'].replace('listener/app/','listener/net/')
    listener['Protocol']='TCP'
    fixture['index']['load_balancer'][0]['data']=copy.deepcopy(item)
    fixture['index']['collections']['load_balancer'][0]['items']=[copy.deepcopy(item)]
    assert evaluate_check('aws_cis_elbv2_only_tls_listeners',item,MemoIndex(fixture['index']))[0]=='FAIL'

def test_unrelated_gateway_lb_does_not_poison_alb_inventory():
    fixture=copy.deepcopy(FIX['aws_cis_elbv2_only_tls_listeners']['pass'])
    gateway={'LoadBalancerArn':fixture['item']['LoadBalancerArn'].replace('loadbalancer/app/','loadbalancer/gwy/'),'Type':'gateway'}
    fixture['index']['load_balancer'].append({'provider':'aws','type':'load_balancer','scope':'123456789012/eu-west-1','data':gateway})
    fixture['index']['collections']['load_balancer'][0]['items'].append(gateway)
    assert evaluate_check('aws_cis_elbv2_only_tls_listeners',fixture['item'],MemoIndex(fixture['index']))[0]=='PASS'

def test_backup_missing_policy_is_unknown():
    fixture=copy.deepcopy(FIX['aws_backup_plan_rule_required_frequency']['pass'])
    fixture['index']['context']['metadata'].pop('compliance_policy')
    assert evaluate_check('aws_backup_plan_rule_required_frequency',fixture['item'],MemoIndex(fixture['index']))[0]=='UNKNOWN'

def test_backup_every_rule_quantifier():
    fixture=copy.deepcopy(FIX['aws_backup_plan_rule_required_frequency']['pass'])
    second=copy.deepcopy(FIX['aws_backup_plan_rule_required_frequency']['fail']['item']['Plan']['BackupPlan']['Rules'][0])
    fixture['item']['Plan']['BackupPlan']['Rules'].append(second)
    fixture['index']['backup_plan'][0]['data']=copy.deepcopy(fixture['item'])
    fixture['index']['collections']['backup_plan'][0]['items']=[copy.deepcopy(fixture['item'])]
    status,evidence=evaluate_check('aws_backup_plan_rule_required_frequency',fixture['item'],MemoIndex(fixture['index']))
    assert status=='FAIL' and evidence['failed_rules']==[2]

def test_lb_index_is_memoized_once_per_scope():
    fixture=FIX['aws_cis_elbv2_only_tls_listeners']['pass']
    index=MemoIndex(copy.deepcopy(fixture['index']))
    for _ in range(3):
        assert evaluate_check('aws_cis_elbv2_only_tls_listeners',fixture['item'],index)[0]=='PASS'
    assert ('next20_aws_lb_by_arn',) in index.memo
    assert len(index.memo)==3  # authority, complete inventory, and one LB identity map

@pytest.mark.parametrize('check_id,helper',[
    ('aws_cis_elbv2_only_tls_listeners','_lb_by_arn')])
def test_identity_join_scans_once_per_immutable_scope(monkeypatch,check_id,helper):
    fixture=FIX[check_id]['pass']; index=MemoIndex(copy.deepcopy(fixture['index']))
    original=getattr(CANDIDATE,helper); calls=[]
    def counted(index):
        calls.append(1)
        return original(index)
    monkeypatch.setattr(CANDIDATE,helper,counted)
    for _ in range(5):
        assert evaluate_check(check_id,fixture['item'],index)[0]=='PASS'
    assert len(calls)==1

def test_main_aws_dispatcher_to_snapshot_to_listener_check(monkeypatch):
    # The main load_balancer kind dispatches elbv2:DescribeLoadBalancers; the
    # separate load_balancer_v2 extension is not involved in this path.
    import boto3
    from botocore.stub import Stubber
    session=boto3.Session(aws_access_key_id='inert',aws_secret_access_key='inert',region_name='eu-west-1')
    sts=session.client('sts'); elb=session.client('elbv2')
    account='123456789012'; lb=FIX['aws_cis_elbv2_only_tls_listeners']['pass']['item']
    identity={'Account':account,'Arn':f'arn:aws:iam::{account}:user/reviewer','UserId':'AIDAREVIEWER'}
    with Stubber(sts) as sts_stub, Stubber(elb) as elb_stub:
        sts_stub.add_response('get_caller_identity',identity,{})
        elb_stub.add_response('describe_load_balancers',{'LoadBalancers':[{'LoadBalancerArn':lb['LoadBalancerArn'],
            'Type':'application','Scheme':'internet-facing'}]}, {})
        elb_stub.add_response('describe_load_balancer_attributes',{'Attributes':[]},{'LoadBalancerArn':lb['LoadBalancerArn']})
        elb_stub.add_response('describe_listeners',{'Listeners':lb['Listeners']['items']},{'LoadBalancerArn':lb['LoadBalancerArn']})
        clients={'sts':sts,'elbv2':elb}
        monkeypatch.setattr(aws.Requests,'client',lambda self,session,service,region:clients[service])
        monkeypatch.setattr(aws,'_session',lambda auth,region:(session,'fixture'))
        snapshot=aws.collect({'provider':'aws','scopes':[account],'auth':{'profile':'fixture'},
            'options':{'regions':['eu-west-1'],'inventories':['load_balancer']}},['load_balancer'])
        envelope=next(c for c in snapshot['collections'] if c['type']=='load_balancer' and c['scope']==account+'/eu-west-1')
        assert envelope['status']=='collected' and envelope['items'][0]['Listeners']['collection_status']=='collected'
        assert aws.SPECS['load_balancer'][:2]==('elbv2','describe_load_balancers')
        report=evaluate_snapshot(snapshot,checks=['aws_cis_elbv2_only_tls_listeners'])
        matching=[f for f in report['findings'] if f['check_id']=='aws_cis_elbv2_only_tls_listeners']
        assert len(matching)==1 and matching[0]['status']=='PASS'
        sts_stub.assert_no_pending_responses(); elb_stub.assert_no_pending_responses()
