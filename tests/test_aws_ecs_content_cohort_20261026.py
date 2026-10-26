"""Exact per-target association and bounded ECS preparation; no cloud I/O."""
import threading, time
from pathlib import Path
from types import SimpleNamespace
import pytest
from peaso import secret_scanning_batch as batch, secret_scanning as scanner
from peaso.collectors import aws_selected_configuration_secret_indicators as registered

source=registered
A='123456789012';R='us-east-1';S=A+'/'+R
CALLER={'Account':A,'Arn':'arn:aws:iam::'+A+':user/readonly','UserId':'synthetic'}

def target(i, surface='ecs_environment'):
    service,kind=('ecs','task-definition/') if surface=='ecs_environment' else ('codebuild','project/')
    return {'surface':surface,'scope':S,'resource_id':f'arn:aws:{service}:{R}:{A}:{kind}fixture{i}'+(':1'if service=='ecs'else'')}

class Reader:
    def __init__(self,targets, *,workers=8,max_calls=None,denied=(),delay=0):
        self._lock=threading.RLock();self.workers=workers;self.max_calls=max_calls;self.deadline=time.monotonic()+5
        self.cancel_event=threading.Event();self.calls=[];self.outputs=[];self.denied=set(denied);self.delay=delay
        self.configuration_content_state={'deadline':self.deadline,'bytes':0,'responses':0,'attempts':0}
        self.configuration_content_sessions={};self.configuration_content_metadata={source.KIND+'_principals':{}}
        self.configuration_content_approved={}
        for t in targets:
            s,o,a=source.route(t);loc=source.opaque_arguments(a)['request_locator']
            self.configuration_content_approved[(s,o,R,loc)]={'id':source.identity(t),'scope':S,'capture':'synthetic-capture'}
    def check_deadline(self):
        if time.monotonic()>=self.deadline:raise TimeoutError('synthetic_deadline')
    def call(self,session,service,region,operation,**args):
        self.check_deadline();name=args.get('taskDefinition',args.get('names',[''])[0]);ident=next(v['id']for (s,o,r,k),v in self.configuration_content_approved.items()if s==service and source.opaque_arguments({k:v for k,v in args.items()if k!='_metadata_profile'})['request_locator']==k)
        with self._lock:
            self.calls.append(ident)
            self.configuration_content_state['attempts']+=1
        if ident in self.denied:raise PermissionError('synthetic_denied')
        time.sleep(self.delay)
        path=ident+'.content';payload=ident.encode()
        out=batch.prepared_output(payload,path)
        if out is None:out=b'serial:'+payload
        with self._lock:self.outputs.append((ident,out))
        return {'id':ident,'payload_digest':out.hex()}

def run(reader,targets):
    options={'content_secret_scans':True,'_content_secret_scan_kinds':[source.KIND],source.OPTION:targets}
    return source.collect_selected(reader,object(),R,CALLER,options,[S])

@pytest.fixture
def prepared(monkeypatch):
    calls=[]
    monkeypatch.setattr(batch,'_volatile_shm_available',lambda size:True)
    monkeypatch.setattr(scanner,'_trufflehog',lambda:'synthetic-pinned')
    def prepare(items,timeout):
        assert 0<timeout<=30;assert len(items)<=8
        calls.append(tuple(items));return {item:b'out:'+item[0]for item in items}
    monkeypatch.setattr(batch,'_prepare_trufflehog_batch',prepare)
    return calls

@pytest.mark.parametrize('count',[2,8,16])
def test_all_versions_order_source_binding_and_bounded_batches(prepared,count):
    ts=[target(i)for i in range(count)];r=Reader(ts);result=run(r,ts)
    expected=[source.identity(t)for t in ts]
    assert [v['id']for v in result.items]==expected
    assert sorted(r.calls)==sorted(expected) and len(r.calls)==count
    assert all(out==b'out:'+ident.encode()for ident,out in r.outputs)
    assert len(prepared)==(count+3)//4 and sum(map(len,prepared))==count
    assert max(map(len,prepared))<=4

@pytest.mark.parametrize('control',['single_worker','global_call_cap','no_tmpfs'])
def test_existing_serial_controls_do_not_start_preparation(monkeypatch,prepared,control):
    ts=[target(i)for i in range(8)];r=Reader(ts,workers=1 if control=='single_worker' else 8,max_calls=10 if control=='global_call_cap'else None)
    if control=='no_tmpfs':monkeypatch.setattr(batch,'_volatile_shm_available',lambda size:False)
    assert len(run(r,ts).items)==8;assert not prepared
    assert all(out.startswith(b'serial:')for _,out in r.outputs)

@pytest.mark.parametrize('workers',[2,4,8])
def test_non_ecs_mixed_scope_and_order_preserved(prepared,workers):
    ts=[target(0),target(1),target(2,'codebuild_environment'),target(3),target(4)]
    r=Reader(ts,workers=workers);out=run(r,ts)
    assert [v['id']for v in out.items]==[source.identity(t)for t in ts]
    assert len(prepared)==2
    assert dict(r.outputs)[source.identity(ts[2])].startswith(b'serial:')

def test_failed_native_peer_finishes_without_hiding_other_outputs(monkeypatch,prepared):
    from peaso.collectors import workload_environment_discovery as discovery
    monkeypatch.setattr(discovery,'record_denial',lambda *a,**k:None)
    monkeypatch.setattr(source,'base',lambda info,requests,locator:{'scope':S,'capture':'synthetic','complete':False})
    ts=[target(i)for i in range(8)];r=Reader(ts,denied={source.identity(ts[3])})
    out=run(r,ts);assert [v['id']for v in out.items]==[source.identity(t)for t in ts]
    assert out.items[3][source.MARKER]['complete']is False
    assert len(r.outputs)==7 and sum(map(len,prepared))==7

@pytest.mark.parametrize('workers',[2,4,8])
def test_failed_preparation_fallback_remains_serial_and_bound(monkeypatch,prepared,workers):
    active=maximum=0;lock=threading.Lock();seen=[]
    monkeypatch.setattr(batch,'_prepare_trufflehog_batch',lambda *a:None)
    def fallback(argv,payload,timeout):
        nonlocal active,maximum
        assert '--no-verification'in argv and '--fail-on-scan-errors'in argv
        with lock:active+=1;maximum=max(maximum,active);seen.append(timeout)
        time.sleep(.002)
        with lock:active-=1
        return b'fallback:'+payload
    monkeypatch.setattr(scanner,'_run',fallback)
    ts=[target(i)for i in range(8)];r=Reader(ts,workers=workers);out=run(r,ts)
    assert len(out.items)==8 and maximum==1 and len(seen)==8
    assert all(0<t<=5 for t in seen)

@pytest.mark.parametrize('workers',[2,4,8])
def test_expired_deadline_keeps_all_targets_unresolved_and_no_preparation(monkeypatch,prepared,workers):
    from peaso.collectors import workload_environment_discovery as discovery
    monkeypatch.setattr(discovery,'record_denial',lambda *a,**k:None)
    monkeypatch.setattr(source,'base',lambda info,requests,locator:{'scope':S,'capture':'synthetic','complete':False})
    ts=[target(i)for i in range(16)];r=Reader(ts,workers=workers);deadline=time.monotonic()-1
    r.deadline=deadline;r.configuration_content_state['deadline']=deadline
    out=run(r,ts)
    assert len(out.items)==16 and all(row[source.MARKER]['complete']is False for row in out.items)
    assert not r.calls and not prepared
    assert r.deadline==deadline and r.configuration_content_state['deadline']==deadline

def test_pool_creation_failure_keeps_original_serial_path(monkeypatch,prepared):
    import concurrent.futures
    def unavailable(**kw):raise RuntimeError('synthetic unavailable')
    monkeypatch.setattr(concurrent.futures,'ThreadPoolExecutor',unavailable)
    ts=[target(i)for i in range(8)];r=Reader(ts)
    assert len(run(r,ts).items)==8 and not prepared
    assert all(out.startswith(b'serial:')for _,out in r.outputs)

@pytest.mark.parametrize('workers',[2,4])
def test_smaller_worker_pools_flush_without_deadlock_and_keep_exact_order(prepared,workers):
    ts=[target(i)for i in range(16)];r=Reader(ts,workers=workers)
    started=time.monotonic();out=run(r,ts)
    assert time.monotonic()-started<4
    assert [row['id']for row in out.items]==[source.identity(t)for t in ts]
    assert sorted(r.calls)==sorted(source.identity(t)for t in ts)
    assert len(r.outputs)==16 and all(value==b'out:'+ident.encode()for ident,value in r.outputs)
    assert sum(map(len,prepared))==16
    assert max(map(len,prepared))<=workers

@pytest.mark.parametrize('case',['near_byte_bound','oversized_response','near_call_bound'])
def test_binding_budget_keeps_earlier_positive_and_same_later_unknowns(monkeypatch,prepared,case):
    from peaso.collectors import workload_environment_discovery as discovery
    monkeypatch.setattr(discovery,'record_denial',lambda *a,**k:None)
    monkeypatch.setattr(source,'base',lambda info,requests,locator:{'scope':S,'capture':'synthetic','complete':False})
    ts=[target(i)for i in range(4)]
    class BudgetReader(Reader):
        def call(self,session,service,region,operation,**args):
            self.check_deadline();ident=next(v['id']for (s,o,r,k),v in self.configuration_content_approved.items()if s==service and source.opaque_arguments({k:v for k,v in args.items()if k!='_metadata_profile'})['request_locator']==k)
            index=[source.identity(t)for t in ts].index(ident)
            source.before_request(self)
            size=(source.MAX_RESPONSE+1 if case=='oversized_response'and index==1 else source.MAX_RESPONSE//2)
            with self._lock:self.calls.append(ident)
            # Same fixed per-response ceiling/order as project_response.
            if size>source.MAX_RESPONSE:raise ValueError('response_bound')
            with self._lock:
                state=self.configuration_content_state
                state['responses']+=1;state['bytes']+=size
                if state['responses']>source.MAX_CALLS or state['bytes']>source.MAX_TOTAL:raise ValueError('total_response_bound')
            path=ident+'.content';payload=ident.encode();batch.prepared_output(payload,path)
            return {'id':ident,'complete':True,'positive':index==0}
    def measured(workers):
        r=BudgetReader(ts,workers=workers)
        if case=='near_byte_bound':r.configuration_content_state['bytes']=source.MAX_TOTAL-source.MAX_RESPONSE//2
        if case=='near_call_bound':r.configuration_content_state['attempts']=source.MAX_CALLS-1
        result=run(r,ts)
        return result.items,dict(r.configuration_content_state),list(r.calls)
    serial,serial_state,serial_calls=measured(1)
    parallel,parallel_state,parallel_calls=measured(8)
    assert serial==parallel and serial_calls==parallel_calls
    assert serial[0]['positive']is True
    serial_state.pop('deadline');parallel_state.pop('deadline')
    assert serial_state==parallel_state
    if case!='oversized_response':assert not prepared

def test_concurrent_invocations_cannot_double_admit_shared_byte_allowance(monkeypatch,prepared):
    from concurrent.futures import ThreadPoolExecutor
    from peaso.collectors import workload_environment_discovery as discovery
    monkeypatch.setattr(discovery,'record_denial',lambda *a,**k:None)
    monkeypatch.setattr(source,'base',lambda info,requests,locator:{'scope':S,'capture':'synthetic','complete':False})
    ts=[target(i)for i in range(8)];entered=threading.Event();release=threading.Event()
    def prepare(items,timeout):
        entered.set();assert release.wait(2)
        return {item:b'out:'+item[0]for item in items}
    monkeypatch.setattr(batch,'_prepare_trufflehog_batch',prepare)
    class SharedReader(Reader):
        def call(self,session,service,region,operation,**args):
            source.before_request(self)
            ident=next(v['id']for (s,o,r,k),v in self.configuration_content_approved.items()if s==service and source.opaque_arguments({k:v for k,v in args.items()if k!='_metadata_profile'})['request_locator']==k)
            with self._lock:
                self.calls.append(ident);state=self.configuration_content_state
                state['responses']+=1;state['bytes']+=source.MAX_RESPONSE
                if state['bytes']>source.MAX_TOTAL:raise ValueError('total_response_bound')
            output=batch.prepared_output(ident.encode(),ident+'.content')
            return {'id':ident,'complete':True,'positive':ident==source.identity(ts[0])}
    r=SharedReader(ts)
    with ThreadPoolExecutor(2)as pool:
        first=pool.submit(run,r,ts[:4]);assert entered.wait(1)
        second=pool.submit(run,r,ts[4:]);time.sleep(.025)
        assert len(r.calls)==4
        release.set();a=first.result(timeout=2);b=second.result(timeout=2)
    assert all(row['complete']is True for row in a.items)
    assert a.items[0]['positive']is True
    assert all(row[source.MARKER]['complete']is False for row in b.items)
    assert r.configuration_content_state['attempts']==8
    assert r.configuration_content_state['responses']==8
    assert r.configuration_content_state['bytes']==source.MAX_RESPONSE*8
