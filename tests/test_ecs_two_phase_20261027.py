"""Canonical two-phase candidate against the retained pre-two-phase module."""
import copy,importlib.util,json,threading,time
from concurrent.futures import Future
from pathlib import Path
import pytest
from peaso import secret_scanning as scanner,secret_scanning_batch as batch,secret_scan_clean as clean
from peaso.collectors import aws_selected_configuration_secret_indicators as candidate
P=Path(__file__).parent
ROOT=P.parent
# The comparison baseline is the retained pre-two-phase module; every candidate
# call uses the actual canonical production module.
_spec=importlib.util.spec_from_file_location('peaso.collectors._ecs_two_phase_retained_baseline',
    P/'ecs_selected_configuration_retained_baseline_20261027.py')
baseline=importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(baseline)
A='123456789012';R='us-east-1';S=A+'/'+R
CALLER={'Account':A,'Arn':f'arn:aws:iam::{A}:user/fixture','UserId':'fixture'}
TOKEN='ghp_'+'7mQ2zR9wL4cV8nK1sF6aH3jP5uD0xB2yE9rT'

def target(i):return {'surface':'ecs_environment','scope':S,'resource_id':f'arn:aws:ecs:{R}:{A}:task-definition/fixture-{i}:1'}
def same(old,new):
    # The candidate also names why an unreadable row has no assessment; the
    # retained baseline predates that field.
    strip=lambda items:[{**i,candidate.MARKER:{k:v for k,v in i[candidate.MARKER].items() if k!='reason'}} for i in items]
    return strip(old)==strip(new)
def clear():
    with scanner._RESULT_LOCK:scanner._RESULTS.clear()
    with clean._LOCK:clean._CLEAN.clear()

class Reader:
    def __init__(self,module,targets,*,workers=8,denied=(),oversized=(),delay=None):
        self.module=module;self._lock=threading.RLock();self.workers=workers;self.max_calls=None
        self.deadline=time.monotonic()+120;self.cancel_event=threading.Event()
        self.content_secret_scans=True;self.content_secret_scan_kinds=frozenset({module.KIND})
        self.options={'content_secret_scans':True,'_content_secret_scan_kinds':[module.KIND],module.OPTION:targets}
        module.initialize(self,self.options,[S]);self.configuration_content_metadata[module.KIND+'_capture']='configuration-capture:'+'a'*32
        self.denied=set(denied);self.oversized=set(oversized);self.delay=delay or{}
        self.calls=[];self._cache={};self.cached_by_index={};self.cache_samples=[];self.scan_seen_before_late=False
        # Real Requests owns one scan-local raw read cache that canonical wrappers bind to.
        from peaso.collectors.aws_request_pool import RawReadCache
        self.raw_reads=RawReadCache()
    def check_deadline(self):
        if self.cancel_event.is_set()or time.monotonic()>=self.deadline:raise TimeoutError('fixture_deadline')
    def call(self,session,service,region,operation,**kwargs):
        m=self.module;args={k:v for k,v in kwargs.items()if k!='_metadata_profile'}
        m.before_request(self)
        arn=args['taskDefinition'];i=int(arn.split('fixture-')[1].split(':')[0])
        with self._lock:self.calls.append(i)
        time.sleep(self.delay.get(i,0))
        if i in self.denied:
            from peaso.collectors.aws import ReadFailure
            raise ReadFailure('denied','AccessDenied')
        self.check_deadline()
        text=TOKEN if i==0 else f'ordinary-{i}'
        if i in self.oversized:text='x'*(m.MAX_RESPONSE+1)
        response={'taskDefinition':{'taskDefinitionArn':arn,'family':'fixture-'+str(i),'revision':1,'status':'ACTIVE','containerDefinitions':[{'name':'app','environment':[{'name':'MODE','value':text}]}]},'ResponseMetadata':{'HTTPStatusCode':200,'RequestId':'fixture-request-'+str(i)}}
        result=m.project_response(response,service,operation,args,request_context=(self,session),region=region)
        # Match real Requests.call: the Future owns the safe projected original,
        # while the reader receives its independent deep copy.
        from peaso.collectors.aws import _safe
        result=_safe(result)
        f=Future();f.set_result(result)
        with self._lock:
            key=(id(session),service,region,operation,json.dumps(m.opaque_arguments(args),sort_keys=True),m.PROFILE)
            self._cache[key]=f;self.cached_by_index[i]=f
            sample=json.dumps(result,sort_keys=True)
            self.cache_samples.append(sample)
            assert TOKEN not in sample and 'containerDefinitions'not in sample
        return copy.deepcopy(result)

def run(module,targets,**kwargs):
    r=Reader(module,targets,**kwargs);out=module.collect_selected(r,object(),R,CALLER,r.options,[S]);return r,out

@pytest.fixture
def native_fakes(monkeypatch):
    calls=[]
    monkeypatch.setattr(batch,'_volatile_shm_available',lambda size:True)
    monkeypatch.setattr(scanner,'_trufflehog',lambda:'fixture-pinned')
    monkeypatch.setattr(scanner,'_scan_kingfisher',lambda payload,path,timeout:[(TOKEN,'synthetic',1)]if TOKEN.encode()in payload else[])
    def prepare(items,timeout):
        # Combined ECS windows are bounded at 60 s; single groups at 30 s.
        assert 0<timeout<=60
        calls.append(tuple(items));return{item:b''for item in items}
    monkeypatch.setattr(batch,'_prepare_trufflehog_batch',prepare)
    clear();return calls


def test_sixteen_native_responses_preserve_five_admissions_but_prepare_once(native_fakes):
    ts=[target(i)for i in range(16)]
    r,a=run(baseline,ts);old=list(native_fakes);native_fakes.clear();clear()
    q,b=run(candidate,ts);new=list(native_fakes)
    assert same(a.items,b.items)
    assert sorted(r.calls)==sorted(q.calls)==list(range(16))
    assert [len(g)for g in old]==[4,3,3,3,3]
    assert [len(g)for g in new]==[16]
    assert {k:v for k,v in r.configuration_content_state.items()if k!='deadline'}=={k:v for k,v in q.configuration_content_state.items()if k!='deadline'}
    assert b.items[0][candidate.MARKER]['leaks']
    assert all(f.result()[candidate.MARKER]==b.items[i][candidate.MARKER]for i,f in q.cached_by_index.items())
    assert not any(t.name=='ecs-content-preparation'for t in threading.enumerate())


def test_large_failure_reuses_original_group_boundaries_exact_once(native_fakes,monkeypatch):
    calls=[]
    def prepare(items,timeout):
        calls.append(len(items))
        if len(items)>4:raise ValueError('fixture_output_bound')
        return{item:b''for item in items}
    monkeypatch.setattr(batch,'_prepare_trufflehog_batch',prepare)
    r,result=run(candidate,[target(i)for i in range(16)])
    assert calls==[16,4,3,3,3,3]
    assert len(result.items)==16 and result.items[0][candidate.MARKER]['leaks']
    assert all(x[candidate.MARKER]['complete']for x in result.items)


def test_denied_and_oversized_rows_do_not_displace_earlier_positive(native_fakes):
    ts=[target(i)for i in range(16)]
    r,a=run(baseline,ts,denied={5},oversized={9});native_fakes.clear();clear()
    q,b=run(candidate,ts,denied={5},oversized={9})
    assert same(a.items,b.items) and a.items[0][baseline.MARKER]['leaks']
    assert a.items[5][baseline.MARKER]['complete']is False
    assert a.items[9][baseline.MARKER]['complete']is False
    assert sorted(r.calls)==sorted(q.calls)==list(range(16))
    assert {k:v for k,v in r.configuration_content_state.items()if k!='deadline'}=={k:v for k,v in q.configuration_content_state.items()if k!='deadline'}

def test_one_second_gather_is_not_repeated_for_slow_later_groups(native_fakes,monkeypatch):
    consumed=threading.Event();original=candidate._complete_content
    def finish(*a,**k):
        value=original(*a,**k)
        if a[1]['id']==candidate.identity(target(0)):consumed.set()
        return value
    monkeypatch.setattr(candidate,'_complete_content',finish)
    ts=[target(i)for i in range(16)]
    r=Reader(candidate,ts,delay={4:1.15,7:1.15})
    begin=time.monotonic();out=candidate.collect_selected(r,object(),R,CALLER,r.options,[S]);elapsed=time.monotonic()-begin
    assert consumed.is_set()and out.items[0][candidate.MARKER]['leaks']
    assert elapsed<2.9  # two native waits; no repeated1s detector gathering.
    assert len(native_fakes)>=2
    assert sum(map(len,native_fakes))==16


def test_late_native_deadline_keeps_already_consumed_earlier_positive(native_fakes,monkeypatch):
    # Exercise the phase itself under a tight existing lease; production's
    # ample-headroom eligibility gate is tested separately below.
    monkeypatch.setattr(candidate,'_defer_ecs_content',lambda r,ts,w,session:candidate._DeferredEcsContent(r,ts,session))
    ts=[target(i)for i in range(16)]
    r=Reader(candidate,ts,delay={4:2.7});r.deadline=time.monotonic()+2.3
    out=candidate.collect_selected(r,object(),R,CALLER,r.options,[S])
    assert out.items[0][candidate.MARKER]['leaks']
    assert out.items[0][candidate.MARKER]['complete']is True
    assert out.items[4][candidate.MARKER]['complete']is False
    assert not any(t.name=='ecs-content-preparation'for t in threading.enumerate())


def test_short_existing_deadline_uses_original_cohorts(native_fakes):
    ts=[target(i)for i in range(16)];r=Reader(candidate,ts);r.deadline=time.monotonic()+5
    result=candidate.collect_selected(r,object(),R,CALLER,r.options,[S])
    assert len(result.items)==16 and[len(g)for g in native_fakes]==[4,3,3,3,3]


@pytest.mark.parametrize('kind',['near_bytes','near_calls'])
def test_shared_binding_budget_and_first_positive_match_original(native_fakes,monkeypatch,kind):
    monkeypatch.setattr(scanner,'_run',lambda *a,**k:b'')
    ts=[target(i)for i in range(16)]
    def go(m):
        clear();r=Reader(m,ts)
        if kind=='near_bytes':r.configuration_content_state['bytes']=m.MAX_TOTAL-500
        else:r.configuration_content_state['attempts']=m.MAX_CALLS-1
        out=m.collect_selected(r,object(),R,CALLER,r.options,[S])
        return r,out
    r,a=go(baseline);q,b=go(candidate)
    assert same(a.items,b.items) and a.items[0][baseline.MARKER]['leaks']
    assert r.calls==q.calls
    assert {k:v for k,v in r.configuration_content_state.items()if k!='deadline'}=={k:v for k,v in q.configuration_content_state.items()if k!='deadline'}


def test_consumer_error_is_not_retried_and_markers_join_before_return(native_fakes,monkeypatch):
    original=candidate._complete_content;seen=[]
    def finish(requests,info,*a,**k):
        seen.append(info['id'])
        if info['id']==candidate.identity(target(5)):raise ValueError('fixture_consumer_failure')
        return original(requests,info,*a,**k)
    monkeypatch.setattr(candidate,'_complete_content',finish)
    r,out=run(candidate,[target(i)for i in range(16)])
    assert len(seen)==len(set(seen))==16
    assert out.items[0][candidate.MARKER]['leaks']
    assert out.items[5][candidate.MARKER]['complete']is False
    assert all(f.result()[candidate.MARKER]==out.items[i][candidate.MARKER]for i,f in r.cached_by_index.items())
    frozen=copy.deepcopy(out.items);time.sleep(.05);assert out.items==frozen
    assert not any(t.name=='ecs-content-preparation'for t in threading.enumerate())

def test_changed_future_binding_never_promotes_or_overwrites_another_capture(native_fakes,monkeypatch):
    original=candidate._complete_content
    def finish(requests,info,*a,**k):
        result=original(requests,info,*a,**k)
        if info['id']==candidate.identity(target(0)):
            requests.cached_by_index[0].result()[candidate.MARKER]['capture']='unrelated-capture'
        return result
    monkeypatch.setattr(candidate,'_complete_content',finish)
    r,out=run(candidate,[target(i)for i in range(16)])
    assert out.items[0][candidate.MARKER]['complete']is False
    assert out.items[0][candidate.MARKER]['leaks']  # genuine owned-source positive retained.
    assert r.cached_by_index[0].result()[candidate.MARKER]['capture']=='unrelated-capture'
    assert all(row[candidate.MARKER]['complete']for row in out.items[1:])


def test_consumer_never_inherits_another_threads_private_source_context(native_fakes):
    from peaso import secret_evidence as evidence
    ts=[target(i)for i in range(16)]
    def go(module):
        clear();cipher=evidence.EphemeralCipher()
        with evidence.capture(cipher,tenant='fixture',scan_id='a'*32)as sink:
            with evidence.source_context(resource_id='unrelated-outer-source',scope='other-account/other-region'):
                r,out=run(module,ts)
        private=[cipher.decrypt(v)for v in sink.records.values()]
        assert private
        locations=[loc for value in private for loc in value.get('locations',[])]
        assert locations and all(loc['resource_id']==ts[0]['resource_id']and loc['scope']==S for loc in locations)
        return out.items,private
    a,pa=go(baseline);b,pb=go(candidate)
    assert a==b and pa==pb

@pytest.mark.parametrize('surface',list(baseline.SURFACES))
@pytest.mark.parametrize('positive',[False,True])
def test_non_deferred_native_surface_projection_is_unchanged(native_fakes,monkeypatch,surface,positive):
    from types import SimpleNamespace
    fixtures_path=P/'ecs_two_phase_native_surface_fixtures_20261027.py'
    spec=importlib.util.spec_from_file_location('_selected_native_fixtures',fixtures_path)
    fixtures=importlib.util.module_from_spec(spec);spec.loader.exec_module(fixtures)
    t,responses=fixtures.native(surface,positive)
    monkeypatch.setattr(scanner,'_run',lambda *a,**k:b'')
    def project(module):
        clear();r=SimpleNamespace(_lock=threading.RLock(),deadline=None,check_deadline=lambda:None,content_secret_scans=True,content_secret_scan_kinds=frozenset({module.KIND}))
        options={'content_secret_scans':True,'_content_secret_scan_kinds':[module.KIND],module.OPTION:[t]}
        module.initialize(r,options,[S]);r.configuration_content_metadata[module.KIND+'_capture']='configuration-capture:'+'a'*32
        session=object();r.configuration_content_sessions[id(session)]={'account':A,'partition':'aws','principal':'fixture-principal'}
        outputs=[]
        for i,response in enumerate(responses):
            service,operation,args=module.route(t,ownership=surface=='ssm_document'and i==0)
            outputs.append(module.project_response(copy.deepcopy(response),service,operation,args,request_context=(r,session),region=R))
        return outputs,{k:v for k,v in r.configuration_content_state.items()if k!='deadline'}
    assert project(baseline)==project(candidate)

@pytest.mark.parametrize('workers',[2,4])
def test_native_group_admission_order_is_preserved_at_smaller_worker_counts(native_fakes,workers):
    targets=[target(i)for i in range(16)]
    r,a=run(baseline,targets,workers=workers);old=list(native_fakes);native_fakes.clear();clear()
    q,b=run(candidate,targets,workers=workers)
    assert same(a.items,b.items)
    assert len(r.calls)==len(q.calls)==16
    assert sorted(r.calls)==sorted(q.calls)==list(range(16))
    assert {k:v for k,v in r.configuration_content_state.items()if k!='deadline'}=={k:v for k,v in q.configuration_content_state.items()if k!='deadline'}
    assert len(native_fakes)==1 and len(native_fakes[0])==16
    assert len(old)>1
