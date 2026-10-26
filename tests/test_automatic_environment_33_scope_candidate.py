"""Registered 33-workload and denied-scope witness in the admitted merge copy."""
from pathlib import Path
import runpy


def test_registered_automatic_environment_33_scope_and_denied_sibling():
    root = Path(__file__).resolve().parents[1]
    runpy.run_path(str(root / 'scripts/verify_automatic_batch_consumer_candidate.py'))


"""Real aws.collect assembly with fake SDK responses; no cloud access or scanners."""
import ast
import os
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace
import pytest
from peaso import checks  # initialize source admission before collector test doubles
from peaso.collectors import aws
from peaso.collectors import aws_lambda_environment_secret_indicators as lam
from peaso.collectors import aws_selected_configuration_secret_indicators as config
from peaso import secret_scanning_batch
from peaso.snapshot import validate

ACCOUNT='123456789012'
REGIONS=['us-east-1','us-west-2']
SCOPES=[ACCOUNT+'/'+region for region in REGIONS]
PARENTS={'lambda_function','codebuild_project','ecs_task_definition','batch_job_definition','amplify_app','glue_job'}
UUID='00000000-0000-4000-8000-000000000001'

class _AutomaticOwnerFakeSDK:
    def __init__(self,service,region,state):
        self.service,self.region,self.state=service,region,state
        self.meta=SimpleNamespace(endpoint_url=f'https://{service}.{region}.amazonaws.com')
    def can_paginate(self,operation):return False
    def __getattr__(self,operation):
        def native(**kwargs):
            self.state['calls'].append((self.service,self.region,operation,deepcopy(kwargs)))
            meta={'HTTPStatusCode':200,'RequestId':UUID}
            if (self.service,operation)==('sts','get_caller_identity'):
                return {'Account':ACCOUNT,'Arn':f'arn:aws:iam::{ACCOUNT}:user/offline','UserId':'AIDASYNTHETIC','ResponseMetadata':meta}
            inventory={('lambda','list_functions'):('lambda_function','Functions'),
                ('codebuild','list_projects'):('codebuild_project','projects'),
                ('ecs','list_task_definitions'):('ecs_task_definition','taskDefinitionArns'),
                ('batch','describe_job_definitions'):('batch_job_definition','jobDefinitions'),
                ('amplify','list_apps'):('amplify_app','apps'),('glue','get_jobs'):('glue_job','Jobs')}
            if (self.service,operation) in inventory:
                kind,key=inventory[self.service,operation]
                if self.region==REGIONS[1] and kind==self.state['denied_parent']:
                    raise aws.ReadFailure('denied','AccessDenied')
                count=self.state['counts'][self.region]
                rows=[]
                if kind=='lambda_function':
                    rows=[{'FunctionName':f'function{i:02}','FunctionArn':f'arn:aws:lambda:{self.region}:{ACCOUNT}:function:function{i:02}'} for i in range(count[0])]
                elif kind=='codebuild_project':rows=[f'project{i:02}' for i in range(count[1])]
                return {key:rows,'ResponseMetadata':meta}
            if (self.service,operation)==('lambda','get_function_configuration'):
                arn=kwargs['FunctionName'];assert arn.startswith(f'arn:aws:lambda:{self.region}:{ACCOUNT}:function:')
                return {'FunctionArn':arn,'FunctionName':arn.rsplit(':',1)[1],'Version':'$LATEST','RevisionId':UUID,
                    'State':'Active','LastUpdateStatus':'Successful','Environment':{'Variables':{'APP_MODE':'offline-safe'}},'ResponseMetadata':meta}
            if (self.service,operation)==('codebuild','batch_get_projects'):
                arn=kwargs['names'][0];assert arn.startswith(f'arn:aws:codebuild:{self.region}:{ACCOUNT}:project/')
                return {'projects':[{'name':arn.rsplit('/',1)[1],'arn':arn,
                    'environment':{'environmentVariables':[{'name':'APP_MODE','value':'offline-safe','type':'PLAINTEXT'}]}}], 'ResponseMetadata':meta}
            raise AssertionError('Unexpected fake SDK operation: '+self.service+':'+operation)
        return native

@pytest.fixture
def collect_offline(monkeypatch):
    session=SimpleNamespace(region_name=REGIONS[0],get_partition_for_region=lambda region:'aws')
    monkeypatch.setattr(aws,'_session',lambda auth,region:(session,'fake-native-sdk'))
    for parent in PARENTS:
        monkeypatch.delitem(aws.FETCHERS,parent,raising=False)
        monkeypatch.delitem(aws.ENRICHERS,parent,raising=False)
    def parent_projection(requests,session,region,kind,items,**kwargs):
        assert kind in PARENTS
        return [deepcopy(item) if isinstance(item,dict) else {aws._NATIVE_IDS.get(kind,'Name'):item} for item in items]
    monkeypatch.setattr(aws,'_enrich',parent_projection)
    # Scanner execution is unrelated to ownership. Keep real target authorization,
    # SDK request routing, native identity/profile projection, receipts and batching.
    outcome={'complete':True,'engines':[{'engine':'offline-scanner','version':'1','status':'complete'}],'leaks':[]}
    monkeypatch.setattr(lam,'scan_content',lambda *a,**kw:deepcopy(outcome))
    monkeypatch.setattr(config,'scan_content',lambda *a,**kw:deepcopy(outcome))
    monkeypatch.setattr(secret_scanning_batch,'_volatile_shm_available',lambda *a:False)
    def run(counts,denied_parent=None):
        state={'counts':dict(zip(REGIONS,counts)),'denied_parent':denied_parent,'calls':[]}
        clients={}
        def client(requests,current,service,region,**kwargs):
            assert current is session
            return clients.setdefault((service,region),_AutomaticOwnerFakeSDK(service,region,state))
        monkeypatch.setattr(aws.Requests,'client',client)
        events=[]
        snap=aws.collect({'provider':'aws','scopes':SCOPES,'options':{
            'service_concurrency':1,'scope_concurrency':1,'region_concurrency':1,
            'content_secret_scans':True,'_content_secret_scan_kinds':[lam.KIND,config.KIND],
            '_collection_callback':lambda collection:events.append(deepcopy(collection))}},
            requirements=[lam.KIND,config.KIND])
        assert validate(snap)==snap
        keys=[(c['type'],c['scope']) for c in snap['collections']]
        assert len(keys)==len(set(keys))
        for kind in [lam.KIND,config.KIND]:
            assert {c['scope'] for c in snap['collections'] if c['type']==kind}==set(SCOPES)
            assert not any(c['type']==kind for c in events) # raw auto batches stay deferred
            assert all(c.get('error',{}).get('code')!='inventory_not_requested' for c in snap['collections'] if c['type']==kind)
        return snap,state
    return run

def rows(snap,kind,scope):return next(c for c in snap['collections'] if c['type']==kind and c['scope']==scope)

def test_populated_scopes_keep_every_bounded_native_read(collect_offline):
    snap,state=collect_offline([(lam.MAX_TARGETS+1,config.MAX_TARGETS+1)]*2)
    for scope in SCOPES:
        for source in [lam,config]:
            collection=rows(snap,source.KIND,scope)
            assert collection['status']=='collected'
            assert len(collection['items'])==source.MAX_TARGETS+1
            assert all(item[source.MARKER]['complete'] is True for item in collection['items'])
            batches=[b for b in snap['metadata']['automatic_workload_environment_batches'][source.KIND] if b['scope']==scope]
            assert [len(b['ids']) for b in batches]==[source.MAX_TARGETS,1]
    selected=[c for c in state['calls'] if c[2] in {'get_function_configuration','batch_get_projects'}]
    assert len(selected)==2*(lam.MAX_TARGETS+config.MAX_TARGETS+2)

def test_complete_zero_targets_keep_both_scopes_empty(collect_offline):
    snap,state=collect_offline([(0,0),(0,0)])
    for scope in SCOPES:
        for kind in [lam.KIND,config.KIND]:assert rows(snap,kind,scope)['status']=='empty'
    assert not any(c[2] in {'get_function_configuration','batch_get_projects'} for c in state['calls'])

def test_mixed_populated_and_empty_scope_is_not_global_empty_decision(collect_offline):
    snap,_=collect_offline([(lam.MAX_TARGETS+1,config.MAX_TARGETS+1),(0,0)])
    for kind in [lam.KIND,config.KIND]:
        assert rows(snap,kind,SCOPES[0])['status']=='collected'
        assert rows(snap,kind,SCOPES[1])['status']=='empty'

@pytest.mark.parametrize('denied_parent',sorted(PARENTS))
def test_denied_source_keeps_exact_scope_unknown_and_clean_sibling(collect_offline,denied_parent):
    snap,_=collect_offline([(lam.MAX_TARGETS+1,config.MAX_TARGETS+1),(0,0)],denied_parent)
    affected=lam.KIND if denied_parent=='lambda_function' else config.KIND
    other=config.KIND if affected==lam.KIND else lam.KIND
    missing=rows(snap,affected,SCOPES[1])
    assert missing['status']=='unknown' and missing['error']['code']=='source_inventory_incomplete'
    assert rows(snap,denied_parent,SCOPES[1])['status']=='denied'
    assert rows(snap,denied_parent,SCOPES[1])['error']['code']=='AccessDenied'
    assert rows(snap,other,SCOPES[1])['status']=='empty'
    assert rows(snap,affected,SCOPES[0])['status']=='collected'
