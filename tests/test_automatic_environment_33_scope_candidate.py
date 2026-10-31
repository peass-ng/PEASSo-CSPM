"""Registered 33-workload and denied-scope witness in the admitted merge copy."""
from pathlib import Path
import runpy


def test_registered_automatic_environment_33_scope_and_denied_sibling():
    root = Path(__file__).resolve().parents[1]
    runpy.run_path(str(root / 'tests/automatic_batch_consumer_candidate.py'))


"""Real aws.collect assembly with fake SDK responses; no cloud access or scanners."""
import ast
import hashlib
import os
import threading
import time
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace
import pytest
from peaso import checks  # initialize source admission before collector test doubles
from peaso import engine, secret_evidence, secret_scanning, secret_scan_clean
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
POSITIVE='ghp_'+'7mQ2zR9wL4cV8nK1sF6aH3jP5uD0xB2yE9rT'

class _AutomaticOwnerFakeSDK:
    def __init__(self,service,region,state):
        self.service,self.region,self.state=service,region,state
        self.meta=SimpleNamespace(endpoint_url=f'https://{service}.{region}.amazonaws.com')
    def can_paginate(self,operation):return False
    def __getattr__(self,operation):
        def native(**kwargs):
            self.state['calls'].append((self.service,self.region,operation,deepcopy(kwargs)))
            meta={'HTTPStatusCode':200,'RequestId':UUID}
            if (self.service,operation)==('logs','describe_log_groups'):
                held=self.state.get('held_ordinary')
                if held is not None:
                    held[0].set()
                    if not held[1].wait(10):raise TimeoutError('ordinary_read_timeout')
                return {'logGroups':[],'ResponseMetadata':meta}
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
                if self.state.get('content_started') is not None:self.state['content_started'].set()
                arn=kwargs['FunctionName'];assert arn.startswith(f'arn:aws:lambda:{self.region}:{ACCOUNT}:function:')
                return {'FunctionArn':arn,'FunctionName':arn.rsplit(':',1)[1],'Version':'$LATEST','RevisionId':UUID,
                    'State':'Active','LastUpdateStatus':'Successful','Environment':{'Variables':{'APP_MODE':'offline-safe'}},'ResponseMetadata':meta}
            if (self.service,operation)==('codebuild','batch_get_projects'):
                arn=kwargs['names'][0];assert arn.startswith(f'arn:aws:codebuild:{self.region}:{ACCOUNT}:project/')
                if self.state.get('denied_selected') and arn.endswith('/project16'):
                    raise aws.ReadFailure('denied','AccessDenied')
                positive=self.state.get('positive') and arn.endswith('/project00')
                return {'projects':[{'name':arn.rsplit('/',1)[1],'arn':arn,
                    'environment':{'environmentVariables':[{'name':'TOKEN' if positive else 'APP_MODE',
                        'value':POSITIVE if positive else 'offline-safe','type':'PLAINTEXT'}]}}], 'ResponseMetadata':meta}
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
    real_scan=secret_scanning.scan_content
    monkeypatch.setattr(config,'scan_content',lambda *a,**kw:deepcopy(outcome))
    def run(counts,denied_parent=None,held_ordinary=None,content_started=None,workers=1,
            shm_available=False,positive=False,real_scanner=False,denied_selected=False):
        monkeypatch.setattr(secret_scanning_batch,'_volatile_shm_available',lambda *a:shm_available)
        monkeypatch.setattr(config,'scan_content',real_scan if real_scanner else lambda *a,**kw:deepcopy(outcome))
        state={'counts':dict(zip(REGIONS,counts)),'denied_parent':denied_parent,'calls':[],
            'positive':positive,'denied_selected':denied_selected,
            'held_ordinary':held_ordinary,'content_started':content_started}
        clients={}
        def client(requests,current,service,region,**kwargs):
            assert current is session
            return clients.setdefault((service,region),_AutomaticOwnerFakeSDK(service,region,state))
        monkeypatch.setattr(aws.Requests,'client',client)
        events=[]
        snap=aws.collect({'provider':'aws','scopes':SCOPES,'options':{
            'service_concurrency':workers,'scope_concurrency':1,'region_concurrency':1,
            'content_secret_scans':True,'_content_secret_scan_kinds':[lam.KIND,config.KIND],
            '_collection_callback':lambda collection:events.append(deepcopy(collection))}},
            requirements=[lam.KIND,config.KIND]+(['log_group'] if held_ordinary is not None else []))
        assert validate(snap)==snap
        keys=[(c['type'],c['scope']) for c in snap['collections']]
        assert len(keys)==len(set(keys))
        for kind in [lam.KIND,config.KIND]:
            assert {c['scope'] for c in snap['collections'] if c['type']==kind}==set(SCOPES)
            assert not any(c['type']==kind for c in events) # raw auto batches stay deferred
            assert all(c.get('error',{}).get('code')!='inventory_not_requested' for c in snap['collections'] if c['type']==kind)
        return snap,state
    return run

def test_content_starts_while_ordinary_read_is_held(collect_offline,monkeypatch):
    ordinary_started,release=threading.Event(),threading.Event()
    content_started=threading.Event()
    owners=[]
    original=aws.Requests.call
    def traced(self,session,service,region,operation,**kwargs):
        if (service,operation) in {('logs','describe_log_groups'),
                ('lambda','get_function_configuration')}:
            owners.append((service,self,getattr(self,'automatic_workload_environment_active',False)))
        return original(self,session,service,region,operation,**kwargs)
    monkeypatch.setattr(aws.Requests,'call',traced)
    result=[]
    thread=threading.Thread(target=lambda:result.append(collect_offline(
        [(1,1),(0,0)],held_ordinary=(ordinary_started,release),
        content_started=content_started)),daemon=True)
    thread.start()
    try:
        assert ordinary_started.wait(5)
        assert content_started.wait(5)
        ordinary=next(owner for service,owner,_ in owners if service=='logs')
        content=next(owner for service,owner,_ in owners if service=='lambda')
        assert ordinary is not content
        assert getattr(ordinary,'automatic_workload_environment_active',False) is False
        assert getattr(ordinary,'automatic_workload_environment_issues',{})=={}
        assert any(active is True for service,_,active in owners if service=='lambda')
        assert ordinary._cache is content._cache
        assert ordinary._canonical_wrappers is content._canonical_wrappers
    finally:
        release.set()
        thread.join(15)
    assert not thread.is_alive() and result

def test_configuration_preparation_crosses_native_batches_without_changing_source_order(
        collect_offline, monkeypatch):
    before,_=collect_offline([(0,33),(0,0)],workers=4)
    prepared=[]
    monkeypatch.setattr('peaso.secret_scanning._trufflehog',lambda:'/offline/scanner')
    def prepare(items,timeout):
        prepared.append((tuple(path for _,path in items),sum(len(payload)for payload,_ in items)))
        return {item:b'' for item in items}
    monkeypatch.setattr(secret_scanning_batch,'_prepare_trufflehog_batch',prepare)
    after,_=collect_offline([(0,33),(0,0)],workers=4,shm_available=True)
    assert max(len(paths)for paths,_ in prepared)>config.MAX_TARGETS
    assert max(len(paths)for paths,_ in prepared)<=2048
    assert all(size<=16*1024*1024 for _,size in prepared)
    def digest(snapshot):
        items=rows(snapshot,config.KIND,SCOPES[0])['items']
        payload=[(item['id'],item[config.MARKER]['complete'],
            item[config.MARKER]['engines'],item[config.MARKER]['leaks']) for item in items]
        return hashlib.sha256(repr(payload).encode()).hexdigest()
    assert digest(before)==digest(after)
    assert [len(b['ids']) for b in after['metadata']['automatic_workload_environment_batches'][config.KIND]
            if b['scope']==SCOPES[0]]==[16,16,1]

def test_positive_configuration_source_and_private_value_survive_streamed_batches(collect_offline):
    def run(shm_available):
        with secret_scan_clean._LOCK:
            secret_scan_clean._CLEAN.clear()
        with secret_scanning._RESULT_LOCK:
            secret_scanning._RESULTS.clear()
        with secret_evidence.capture(secret_evidence.EphemeralCipher(),tenant='fixed',
                scan_id='0'*32,selected_checks={config.CHECK}) as sink:
            snap,_=collect_offline([(0,17),(0,0)],workers=4,
                shm_available=shm_available,positive=True,real_scanner=True)
            findings=engine.evaluate_snapshot(snap,checks=[config.CHECK])['findings']
            private=sorted((sink.load(fp) for fp in sink.records),key=lambda row:row['fingerprint'])
        return snap,findings,private
    before,old_findings,old_private=run(False)
    after,new_findings,new_private=run(True)
    assert old_findings==new_findings
    assert old_private==new_private
    assert any(row['value']==POSITIVE and any(loc.get('resource_id','').endswith('/project00')
        for loc in row['locations']) for row in new_private)
    assert [item['id'] for item in rows(before,config.KIND,SCOPES[0])['items']]==[
        item['id'] for item in rows(after,config.KIND,SCOPES[0])['items']]

def test_dense_preparation_fallback_and_denied_batch_keep_later_evidence(
        collect_offline,monkeypatch):
    baseline,_=collect_offline([(0,33),(0,0)],workers=4,denied_selected=True)
    monkeypatch.setattr('peaso.secret_scanning._trufflehog',lambda:'/offline/scanner')
    calls=[]
    def dense(items,timeout):
        calls.append(len(items))
        return None
    monkeypatch.setattr(secret_scanning_batch,'_prepare_trufflehog_batch',dense)
    candidate,_=collect_offline([(0,33),(0,0)],workers=4,
        shm_available=True,denied_selected=True)
    assert max(calls)>config.MAX_TARGETS
    def proof(snapshot):
        return [(item['id'],item[config.MARKER]['complete'],item[config.MARKER]['leaks'])
            for item in rows(snapshot,config.KIND,SCOPES[0])['items']]
    assert proof(baseline)==proof(candidate)
    assert proof(candidate)[16][1] is False
    assert proof(candidate)[17][1] is True

def test_expired_earlier_native_batch_does_not_poison_later_batch(collect_offline,monkeypatch):
    monkeypatch.setattr('peaso.secret_scanning._trufflehog',lambda:'/offline/scanner')
    monkeypatch.setattr(secret_scanning_batch,'_prepare_trufflehog_batch',
        lambda items,timeout:{item:b'' for item in items})
    original=config.collect_selected
    expired=[]
    def settle(requests,session,region,caller,options,scopes,**kwargs):
        result=original(requests,session,region,caller,options,scopes,**kwargs)
        if kwargs.get('deferred_window') is not None and not expired:
            requests.configuration_content_state['deadline']=time.monotonic()-1
            expired.append(True)
        return result
    monkeypatch.setattr(config,'collect_selected',settle)
    snapshot,_=collect_offline([(0,33),(0,0)],workers=4,shm_available=True)
    markers=[item[config.MARKER] for item in rows(snapshot,config.KIND,SCOPES[0])['items']]
    assert expired and all(marker['complete'] is False for marker in markers[:16])
    assert all(marker['complete'] is True for marker in markers[16:])

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
