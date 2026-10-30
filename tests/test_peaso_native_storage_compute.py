import copy
from datetime import datetime,timezone
import json
from pathlib import Path
import boto3
from botocore.stub import Stubber
import pytest
from peaso.checks import evaluate_check
from peaso.checks.native_storage_compute import SPECS,EMR_IDS
from peaso.checks.fixtures import CASES
from peaso.collectors import aws,aws_privesc_facts,aws_facts_data_identity,azure
from peaso.engine import evaluate_snapshot
from peaso.snapshot import make_snapshot
from tests.test_peaso_collectors_azurek8s import FakeAzure


@pytest.mark.parametrize('ident',SPECS)
def test_signed_native_cases_and_projection_account_boundaries(ident):
    cases=CASES[ident]
    for label in ('pass','fail','unknown'):
        data=copy.deepcopy(cases[label]);index=copy.deepcopy(cases[label+'_index']);before=copy.deepcopy((data,index))
        assert evaluate_check(ident,data,index)[0]==label.upper()
        assert (data,index)==before
    data=copy.deepcopy(cases['pass']);facts=copy.deepcopy(cases['pass_index']);env=next(iter(facts['collections'].values()))[0];env['scope']='foreign'
    assert evaluate_check(ident,data,facts)[0]=='UNKNOWN'


def test_botocore_master_pagination_producer_to_real_emr_engine():
    scope='123456789012/us-east-1';arn='arn:aws:elasticmapreduce:us-east-1:123456789012:cluster/j-QA'
    session=boto3.Session(aws_access_key_id='fake',aws_secret_access_key='fake',region_name='us-east-1');client=session.client('emr')
    requests=aws.Requests({});requests.client=lambda *args:client
    summary={'Id':'j-QA','ClusterArn':arn,'Status':{'State':'WAITING'}}
    with Stubber(client)as stub:
        stub.add_response('describe_cluster',{'Cluster':{'Id':'j-QA','ClusterArn':arn,'Status':{'State':'WAITING'}}},{'ClusterId':'j-QA'})
        stub.add_response('list_instances',{'Instances':[{'Id':'ci-QA','Ec2InstanceId':'i-0123456789abcdef0'}],'Marker':'next'},{'ClusterId':'j-QA','InstanceGroupTypes':['MASTER'],'InstanceStates':['RUNNING']})
        stub.add_response('list_instances',{'Instances':[]},{'ClusterId':'j-QA','InstanceGroupTypes':['MASTER'],'InstanceStates':['RUNNING'],'Marker':'next'})
        row=aws_privesc_facts.ENRICHERS['emr_cluster'](requests,session,'us-east-1',[summary])[0];stub.assert_no_pending_responses()
    instance={'InstanceId':'i-0123456789abcdef0','State':{'Name':'running'},'NetworkInterfaces':[{'Ipv6Addresses':[]}]}
    cols=[{'type':'emr_cluster','scope':scope,'service':'emr','status':'collected','items':[row]}, {'type':'instance','scope':scope,'service':'ec2','status':'collected','items':[instance]}]
    for public,expected in ((None,'PASS'),('203.0.113.2','FAIL')):
        if public:instance['PublicIpAddress']=public
        snap=make_snapshot('aws',[scope],cols);report=evaluate_snapshot(snap,checks=sorted(EMR_IDS))
        assert len(report['findings'])==4 and {f['status']for f in report['findings']}=={expected}
    row['MasterInstances']['PrimaryEc2InstanceId']='i-foreign';report=evaluate_snapshot(make_snapshot('aws',[scope],cols),checks=['aws_fedramp_emr_master_no_public_ip']);assert report['findings'][0]['status']=='UNKNOWN'


def test_efs_real_projection_omission_default_and_incomplete_coverage():
    ident='aws_nist_efs_access_point_enforce_root_directory';cases=CASES[ident];raw=copy.deepcopy(cases['pass']);raw.pop('_provenance')
    projected=aws_facts_data_identity.ENRICHERS['efs_access_point'](None,None,None,[raw])[0]
    facts=copy.deepcopy(cases['pass_index']);facts['efs_access_point'][0]['data']=projected;facts['collections']['efs_access_point'][0]['items']=[projected]
    assert evaluate_check(ident,projected,facts)[0]=='PASS'
    projected.pop('RootDirectory');assert evaluate_check(ident,projected,facts)[0]=='FAIL'
    projected['_coverage']={'RootDirectory':{'status':'not_collected'}};assert evaluate_check(ident,projected,facts)[0]=='UNKNOWN'


def test_sql_and_managed_instance_native_gets_to_real_engine():
    scope='/subscriptions/11111111-1111-1111-1111-111111111111';server=scope+'/resourceGroups/rg/providers/Microsoft.Sql/servers/s';managed=scope+'/resourceGroups/rg/providers/Microsoft.Sql/managedInstances/m';db=server+'/databases/app';mi=managed+'/databases/app'
    state={'value':'Enabled'}
    def response(url,body,audience):
        if '/transparentDataEncryption/current?'in url:
            rid=url.split('https://management.azure.com',1)[1].split('?',1)[0]
            return {'id':rid,'properties':{'state':state['value']}}
        if '/databases?'in url:return {'value':[{'id':mi if managed in url else db,'name':'app','properties':{'status':'Online'}}]}
        if '/providers/Microsoft.Sql/servers?'in url:return {'value':[{'id':server,'type':'Microsoft.Sql/servers','properties':{}}]}
        if '/providers/Microsoft.Sql/managedInstances?'in url:return {'value':[{'id':managed,'type':'Microsoft.Sql/managedInstances','properties':{}}]}
        if body:return {'data':[]}
        if url.startswith('https://management.azure.com'+scope+'/resourceGroups/rg/providers/Microsoft.Sql/'):
            return {'id':url.split('https://management.azure.com',1)[1].split('?',1)[0],'properties':{}}
        return {'value':[]}
    ident='azure_sql_database_sqlserver_tde_encryption_enabled_c4383b5'
    for expected in ('PASS','FAIL'):
        snap=azure.collect({'provider':'azure','scopes':[scope]},['sql_database_inventory','sql_tde_inventory','managed_instance_database','managed_instance_tde'],transport=FakeAzure(response))
        report=evaluate_snapshot(snap,checks=[ident]);assert len(report['findings'])==1
        assert report['findings'][0]['status']==expected,report['findings'][0]
        state['value']='Disabled'


def test_complete_empty_sql_native_collection_is_not_applicable_and_partial_stays_unknown():
    scope='/subscriptions/11111111-1111-1111-1111-111111111111'
    def response(url,body,audience):
        return {'data':[]} if body else {'value':[]}
    kinds=['sql_database_inventory','sql_tde_inventory','managed_instance_database','managed_instance_tde']
    snapshot=azure.collect({'provider':'azure','scopes':[scope]},kinds,transport=FakeAzure(response))
    ident='azure_sql_database_sqlserver_tde_encryption_enabled_c4383b5'
    report=evaluate_snapshot(snapshot,checks=[ident])
    assert [f['status']for f in report['findings']]==['NOT_APPLICABLE']
    for kind in kinds:
        partial=copy.deepcopy(snapshot)
        partial.pop('snapshot_id',None)
        next(c for c in partial['collections']if c['type']==kind)['status']='not_collected'
        assert [f['status']for f in evaluate_snapshot(partial,checks=[ident])['findings']]==['UNKNOWN']
