"""Directed Classic ELB native configuration tests with inert SDK-shaped reads only."""
import copy
from datetime import datetime, timezone
import pytest
from botocore.exceptions import ClientError
from peaso.collectors import aws, collect_live
from peaso.collectors.aws_classic_elb_policies_native import enrich
from tests.archived_check_contract import evaluate_snapshot
from peaso.snapshot import make_snapshot
from elb_native_policy_fixture import bind_policy_sources
from peaso.checks import evaluate_check

ACCOUNT='123456789012'
REGION='us-east-1'
SCOPE=ACCOUNT+'/'+REGION
CUSTOM='aws.pci.classic_elb.custom_ssl_policy'
PREDEFINED='aws.pci.classic_elb.predefined_ssl_policy'
STAMP='2026-10-12T00:00:00+00:00'
POLICY={'PolicyName':'ELBSecurityPolicy-inert','PolicyTypeName':'SSLNegotiationPolicyType',
        'PolicyAttributeDescriptions':[{'AttributeName':'Protocol-TLSv1.2','AttributeValue':'true'}]}
ROW={'LoadBalancerName':'elb','ListenerDescriptions':[{'Listener':{'Protocol':'HTTPS','LoadBalancerPort':443},'PolicyNames':[POLICY['PolicyName']]}]}

class Session:
    region_name=REGION
    def __init__(self, mode='good', tls=True, two=False):self.mode=mode;self.tls=tls;self.two=two;self.calls=[]
    def client(self,service,region_name=None,config=None):
        outer=self
        class Client:
            def can_paginate(self,operation):return False
            def __getattr__(self,op):
                def call(**args):
                    outer.calls.append((service,op,copy.deepcopy(args)))
                    if (service,op)==('sts','get_caller_identity'):
                        return {'Account':ACCOUNT,'Arn':'arn:aws:iam::'+ACCOUNT+':role/inert','UserId':'INERT'}
                    assert service=='elb'
                    if op=='describe_load_balancers':
                        row=copy.deepcopy(ROW)
                        if not outer.tls:row['ListenerDescriptions'][0]['Listener']['Protocol']='HTTP'
                        if outer.mode=='implicit_default':row['ListenerDescriptions'][0]['PolicyNames']=[]
                        if outer.mode=='nonssl_optional':row['ListenerDescriptions'][0]['PolicyNames'].append('cookie')
                        return {'LoadBalancerDescriptions':[row, {**copy.deepcopy(row),'LoadBalancerName':'elb2'}] if outer.two else [row]}
                    if op=='describe_load_balancer_attributes':return {'LoadBalancerAttributes':{}}
                    if op=='describe_instance_health':return {'InstanceStates':[]}
                    assert op=='describe_load_balancer_policies'
                    if outer.mode=='denied' and args:
                        raise ClientError({'Error':{'Code':'AccessDenied','Message':'inert'}},op)
                    if outer.mode=='catalog_denied' and not args:
                        raise ClientError({'Error':{'Code':'AccessDenied','Message':'inert'}},op)
                    policies=[copy.deepcopy(POLICY)]
                    if outer.mode=='nonssl_optional':policies.append({'PolicyName':'cookie','PolicyTypeName':'AppCookieStickinessPolicyType'})
                    if outer.mode=='ssl_missing_attributes':policies[0].pop('PolicyAttributeDescriptions')
                    if outer.mode=='ssl_empty_attributes':policies[0]['PolicyAttributeDescriptions']=[]
                    if outer.mode=='mismatch' and args:policies[0]['PolicyAttributeDescriptions'][0]['AttributeValue']='false'
                    if outer.mode=='catalog_mismatch' and not args:policies[0]['PolicyAttributeDescriptions'][0]['AttributeValue']='false'
                    if outer.mode=='missing' and args:policies=[]
                    if outer.mode=='duplicate' and args:policies*=2
                    if outer.mode=='partial' and args:return {'PolicyDescriptions':policies,'NextMarker':'inert'}
                    return {'PolicyDescriptions':policies}
                return call
        return Client()


def normal(monkeypatch,mode='good',tls=True,two=False):
    session=Session(mode,tls,two)
    monkeypatch.setattr(aws,'_session',lambda auth,region:(session,'inert-sdk-stub'))
    snapshot=collect_live({'provider':'aws','scopes':[SCOPE],'auth':{},'options':{'regions':[REGION],
        'inventories':['classic_elb'],'retry_attempts':1,'compliance_parameters':{'classic_elb_custom_ssl_policy':{'Protocol-TLSv1.2':'true'}}}},['classic_elb'])
    return snapshot,session


def findings(snapshot,cids=(CUSTOM,PREDEFINED)):
    report=evaluate_snapshot(snapshot,checks=list(cids))
    return {cid:[f['status'] for f in report['findings'] if f['check_id']==cid] for cid in cids}


def test_normal_collect_live_positive_and_cached_catalog(monkeypatch):
    snap,session=normal(monkeypatch,two=True)
    assert findings(snap)=={CUSTOM:['PASS','PASS'],PREDEFINED:['PASS','PASS']}
    catalog=[x for x in session.calls if x[1]=='describe_load_balancer_policies' and not x[2]]
    details=[x for x in session.calls if x[1]=='describe_load_balancer_policies' and x[2]]
    assert len(catalog)==1 and len(details)==2
    assert all(x[2]['PolicyNames']==[POLICY['PolicyName']] for x in details)
    assert len([x for x in session.calls if x[1]=='describe_instance_health'])==2
    assert all(c['items'][0]['InstanceHealth']['collection_status']=='collected'
               for c in snap['collections'] if c['type']=='classic_load_balancer')
    assert 'PolicyOrigin' not in str(snap)


@pytest.mark.parametrize('mode,custom,predefined',[
    ('mismatch','FAIL','FAIL'),('catalog_mismatch','PASS','FAIL'),('denied','UNKNOWN','UNKNOWN'),
    ('catalog_denied','PASS','UNKNOWN'),('missing','UNKNOWN','UNKNOWN'),('duplicate','UNKNOWN','UNKNOWN'),
    ('partial','UNKNOWN','UNKNOWN')])
def test_normal_collect_live_policy_boundaries(monkeypatch,mode,custom,predefined):
    snap,_=normal(monkeypatch,mode)
    assert findings(snap)=={CUSTOM:[custom],PREDEFINED:[predefined]}


def test_no_tls_has_no_policy_or_catalog_reads(monkeypatch):
    snap,session=normal(monkeypatch,tls=False)
    assert findings(snap)=={CUSTOM:['NOT_APPLICABLE'],PREDEFINED:['NOT_APPLICABLE']}
    assert not any(x[1]=='describe_load_balancer_policies' for x in session.calls)


def direct(row,cid=CUSTOM):
    facts={'context':{'provider':'aws','scope':SCOPE,'created_at':STAMP,'metadata':{'parameters':{
        'classic_elb_custom_ssl_policy':{'Protocol-TLSv1.2':'true'}}}},'collections':{'classic_elb':[
        {'type':'classic_elb','scope':SCOPE,'status':'collected','items':[copy.deepcopy(row)]}]},
        'classic_elb':[{'type':'classic_elb','scope':SCOPE,'data':copy.deepcopy(row)}]}
    return evaluate_check(cid,row,facts)[0]


@pytest.mark.parametrize('change',['account','region','capture','request','duplicate_attributes','missing_source','unknown_type'])
def test_bound_source_authority_rejected(change):
    row=bind_policy_sources({**ROW,'PolicyDescriptions':[POLICY]})
    detail=row['SSLPolicyDetails']; provenance=detail['_provenance']
    if change=='account':provenance['account_id']='999999999999'
    if change=='region':provenance['region']='eu-west-1'
    if change=='capture':provenance['captured_at']='2026-10-11T00:00:00Z'
    if change=='request':provenance['request']['LoadBalancerName']='foreign'
    if change=='duplicate_attributes':detail['PolicyDescriptions'][0]['PolicyAttributeDescriptions']*=2
    if change=='missing_source':row.pop('SSLPolicyDetails')
    if change=='unknown_type':detail['PolicyDescriptions'][0]['PolicyTypeName']='FuturePolicyType'
    for cid in (CUSTOM,PREDEFINED):assert direct(row,cid)=='UNKNOWN'


def test_catalog_source_not_a_policy_name_prefix():
    row=bind_policy_sources({**ROW,'PolicyDescriptions':[POLICY]},catalog=[])
    assert direct(row,PREDEFINED)=='FAIL'
    row['SSLPolicyCatalog']['_provenance']['request']={'LoadBalancerName':'elb'}
    assert direct(row,PREDEFINED)=='UNKNOWN'


def test_implicit_default_without_policy_reference_stays_unknown(monkeypatch):
    snap,session=normal(monkeypatch,mode='implicit_default')
    assert findings(snap)=={CUSTOM:['UNKNOWN'],PREDEFINED:['UNKNOWN']}
    assert not any(x[1]=='describe_load_balancer_policies' for x in session.calls)


@pytest.mark.parametrize('mode,expected',[('nonssl_optional','PASS'),('ssl_missing_attributes','UNKNOWN'),('ssl_empty_attributes','UNKNOWN')])
def test_native_optional_nonssl_and_missing_ssl_attributes(monkeypatch,mode,expected):
    snap,_=normal(monkeypatch,mode=mode)
    assert findings(snap)=={CUSTOM:[expected],PREDEFINED:[expected]}


def test_renamed_equivalent_predefined_configuration_is_unresolved():
    row = copy.deepcopy(ROW)
    row['ListenerDescriptions'][0]['PolicyNames'] = ['customer-policy']
    renamed = {**copy.deepcopy(POLICY), 'PolicyName': 'customer-policy'}
    row = bind_policy_sources({**row, 'PolicyDescriptions': [renamed]}, catalog=[POLICY])
    assert direct(row, PREDEFINED) == 'UNKNOWN'
    assert direct(row, CUSTOM) == 'PASS'


def test_known_predefined_mismatch_survives_unresolved_renamed_peer():
    row = copy.deepcopy(ROW)
    row['ListenerDescriptions'][0]['PolicyNames'] = ['customer-policy']
    row['ListenerDescriptions'].append({'Listener': {'Protocol': 'HTTPS', 'LoadBalancerPort': 8443},
                                       'PolicyNames': ['different-policy']})
    renamed = {**copy.deepcopy(POLICY), 'PolicyName': 'customer-policy'}
    different = {'PolicyName': 'different-policy', 'PolicyTypeName': POLICY['PolicyTypeName'],
                 'PolicyAttributeDescriptions': [{'AttributeName': 'Protocol-TLSv1.2', 'AttributeValue': 'false'}]}
    row = bind_policy_sources({**row, 'PolicyDescriptions': [renamed, different]}, catalog=[POLICY])
    assert direct(row, PREDEFINED) == 'FAIL'
