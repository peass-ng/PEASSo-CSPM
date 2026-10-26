"""Finite native HTTP through real engine/collector and both pinned offline scanners."""
from copy import deepcopy
from tests.shared_admission_epoch_compatibility_20261020 import snapshot_cases, active_shared, source_at_epoch, sealed_ast
from dataclasses import replace
import hashlib
import http.client
import inspect
import io
import json
import logging
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import quote, urlsplit
import pytest
import requests
from fastapi import HTTPException
from peaso import checks, engine, secret_scanning as scanning
from peaso.checks import fixtures
from peaso.checks import gcp_dataflow_batch_source_runtime_admission_20261020 as admission
from peaso.checks import gcp_dataflow_batch_source_runtime_consumer_20261020 as consumer
from peaso.checks import gcp_dataflow_batch_shared_hook_successor_20261020 as shared
from peaso.collectors import gcp
from peaso.collectors import gcp_dataflow_batch_source_runtime_20261020 as runtime
from peaso.server.validation import OPTIONS, validate_connector
from tests import gcp_dataflow_referenced_source_20261020_test as df
from tests import gcp_batch_referenced_source_20261020_test as bt

SCOPE, TOKEN, AUTH = df.SCOPE, df.TOKEN, df.AUTH
PROOF_LABEL = 'hacktricks-cspm-' + 'a' * 20


@pytest.fixture(autouse=True)
def offline(monkeypatch):
    yield from df.offline.__wrapped__(monkeypatch)


def target(profile):
    return df.target() if profile == 'dataflow' else bt.target()


def capture(monkeypatch, profile='dataflow', *, payload=b'mode=ready\n', targets=None, fault=None,
            absent=None, named=True, options=None, scopes=None, request_fields=None, proof=None,
            mutate_snapshot=None, normal_metadata=False, combined=False):
    p = runtime.PROFILES[profile]; source = p['source']
    targets = deepcopy(targets if targets is not None else [target(profile)])
    scopes = scopes or [SCOPE]
    opts = dict(content_secret_scans=True, retries=0, concurrency=1, metrics_scopes=False, include_inherited=False,
                **{source.OPTION: targets})
    opts.update(options or {})
    additional='batch' if profile=='dataflow' else 'dataflow'
    all_targets=targets+[target(additional)] if combined else targets
    if combined:opts[runtime.PROFILES[additional]['source'].OPTION]=[target(additional)]
    calls, responses, sessions, auth, collectors, metadata_calls, credential_constructions = [], [], [], [], [], [], []
    if absent:
        def unavailable(*a, **k): raise RuntimeError(TOKEN)
        if absent=='kingfisher':
            import kingfisher_sdk
            monkeypatch.setattr(kingfisher_sdk.Scanner,'scan_input',unavailable)
        else:
            scanning._trufflehog.cache_clear()
            original_which=scanning.shutil.which
            monkeypatch.setattr(scanning.shutil,'which',lambda name,*a,**k:None if name=='trufflehog' else original_which(name,*a,**k))
    def headers():
        auth.append(True)
        return {'Authorization': 'Bearer ' + AUTH}
    original_progress=gcp.GCPCollector.progress
    def progress(self,*args,**kwargs):
        if not collectors or collectors[-1] is not self:collectors.append(self)
        return original_progress(self,*args,**kwargs)
    monkeypatch.setattr(gcp.GCPCollector,'progress',progress)
    def credentials(*a,**k):
        credential_constructions.append(True)
        return SimpleNamespace(headers=headers,method='offline-native-test',close=lambda:None)
    monkeypatch.setattr(gcp,'Credentials',credentials)
    if mutate_snapshot:
        import peaso.snapshot as snapshot_module
        original_make=snapshot_module.make_snapshot
        def make(*args,**kwargs):
            snapshot=original_make(*args,**kwargs);mutate_snapshot(snapshot,collectors[-1]);return snapshot
        monkeypatch.setattr(snapshot_module,'make_snapshot',make)
    if proof is not None or normal_metadata:
        def metadata(self, method, url, **kw):
            metadata_calls.append(url)
            assert method == 'GET'
            if url == 'https://cloudresourcemanager.googleapis.com/v3/' + SCOPE:
                return dict(name='projects/10001', projectId='review', state='ACTIVE',
                            labels={PROOF_LABEL:'approved' if proof else 'denied'}), 'native-proof'
            assert normal_metadata and (url.startswith('https://dataflow.googleapis.com/') or url.startswith('https://batch.googleapis.com/'))
            return {'jobs': []}, 'native-jobs-metadata'
        monkeypatch.setattr(gcp.Transport, 'request', metadata)
    counts = {}
    def request(method, url, **kw):
        assert method == 'GET' and kw['stream'] is True and kw['allow_redirects'] is False
        assert kw['headers']['Authorization'] == 'Bearer ' + AUTH
        assert kw['headers']['Accept-Encoding'] == 'identity' and kw['headers']['Cache-Control'] == 'no-store'
        assert 0 < kw['timeout'] <= 20
        parsed = urlsplit(url)
        assert parsed.scheme == 'https' and not parsed.query and not parsed.fragment
        if parsed.netloc == 'cloudresourcemanager.googleapis.com':
            scope = parsed.path.removeprefix('/v3/')
            assert scope in scopes and kw['params'] == {'fields':'name,projectId,state'}
            op = 'project'; data = dict(name='projects/10001', projectId=scope.split('/')[1], state='ACTIVE')
        elif parsed.netloc in ('dataflow.googleapis.com','batch.googleapis.com'):
            t = next(t for t in all_targets if parsed.path.endswith('/' + t['resource']))
            native_profile='dataflow' if parsed.netloc=='dataflow.googleapis.com' else 'batch'
            op = 'reference'
            if native_profile == 'dataflow':
                assert kw['params'] == {'view':'JOB_VIEW_ALL'}
                data = df.native(t, payload);data['projectId']=df.source.parse(t).split('/')[1]
            else:
                assert kw['params'] == {}
                data = json.loads(bt.NATIVE.read_text())
                data['name'] = t['resource'].replace(bt.source.parse(t),'projects/10001',1)
                data['taskGroups'][0]['name'] = data['name'] + '/taskGroups/group0'
                data['taskGroups'][0]['taskSpec']['volumes'][0]['gcs']['remotePath']=t['bucket']+'/code/'
        else:
            assert parsed.netloc == 'storage.googleapis.com'
            t = next(t for t in all_targets if parsed.path == '/storage/v1/b/' + quote(t['bucket'],safe='') + ('/o/'+quote(t['object'],safe='') if '/o/' in parsed.path else ''))
            if '/o/' not in parsed.path:
                assert kw['params'] == {'fields':'name,projectNumber','projection':'noAcl'}
                op = 'bucket';data = dict(name=t['bucket'],projectNumber='10001')
            elif kw['params'].get('alt') == 'media':
                assert parsed.path.endswith('/o/' + quote(t['object'],safe=''))
                assert kw['params'] == dict(generation=t['generation'],ifGenerationMatch=t['generation'],alt='media')
                op = 'content';data = payload
            else:
                assert kw['params'] == {'fields':source.objects.FIELDS,'projection':'noAcl'}
                op = 'latest';data = dict(bucket=t['bucket'],name=t['object'],generation=t['generation'],size=str(len(payload)),contentType='text/plain')
        counts[op] = counts.get(op,0)+1
        response = df.Response(data,headers={'Content-Type':'text/plain','x-goog-generation':t['generation']} if op=='content' else None)
        if fault:fault(op,counts[op],data,response)
        if isinstance(data,dict):
            response.payload=json.dumps(data).encode();response.stream=io.BytesIO(response.payload);response.headers['Content-Length']=str(len(response.payload))
        response.url=getattr(response,'final_url',requests.Request(method,url,params=kw['params']).prepare().url)
        calls.append((op,method,url,deepcopy(kw['params'])));responses.append(response)
        return response
    monkeypatch.setattr(requests,'Session',lambda:SimpleNamespace(request=request,close=lambda:sessions.append(True),cookies=SimpleNamespace(clear=lambda:None)))
    if not named:opts.setdefault('inventories',[p['kind']])
    connector=dict(provider='gcp',scopes=scopes,options=opts)
    if proof is not None:
        from peaso.gcp_platform import PLATFORM_PROJECT, PLATFORM_EMAIL
        connector['auth']=dict(method='platform-service-account',project_proof_label=PROOF_LABEL,
            sa_json={'project_id':PLATFORM_PROJECT,'client_email':PLATFORM_EMAIL,'private_key':'inert-key'})
    req={'connector':connector}
    if named:req['checks']=[p['check']]+([runtime.PROFILES[additional]['check']] if combined else [])
    req.update(request_fields or {})
    snapshot=engine.collect_snapshot(req)
    findings=engine.evaluate_snapshot(snapshot,checks=[p['check']]+([runtime.PROFILES[additional]['check']] if combined else []))['findings']
    collector=collectors[-1] if collectors else SimpleNamespace(transport=None,options=opts,collections={})
    return snapshot,findings,SimpleNamespace(collector=collector,calls=calls,responses=responses,sessions=sessions,auth=auth,metadata_calls=metadata_calls,credential_constructions=credential_constructions)


def native_index(snapshot, profile, scope=SCOPE):
    p=runtime.PROFILES[profile]
    own,=[c for c in snapshot['collections'] if c['type']==p['kind'] and c['scope']==scope]
    return own,dict(context=dict(provider='gcp',scope=scope,metadata=snapshot['metadata']),collections={p['kind']:[own]})


@pytest.mark.parametrize('profile',['dataflow','batch'])
@pytest.mark.parametrize('hit',[False,True])
def test_actual_native_pinned_detectors(monkeypatch,profile,hit):
    snap,rows,trace=capture(monkeypatch,profile,payload=('token='+TOKEN).encode() if hit else b'mode=ready\n')
    assert {r['status'] for r in rows}=={'FAIL' if hit else 'PASS'},rows
    p=runtime.PROFILES[profile];own,index=native_index(snap,profile)
    status,evidence=getattr(consumer,profile+'_source')(own['items'][0],index)
    assert status==('FAIL' if hit else 'PASS') and evidence['complete'] is True
    assert evidence['executed_bytes_proven'] is False and evidence['credential_validation']=='not_attempted'
    assert evidence['parts'][0]['engines']==[dict(engine='kingfisher',version='1.4.0',status='complete'),dict(engine='trufflehog',version='3.92.5',status='complete')]
    if hit:
        leak,=evidence['secret_leaks'];assert leak['fingerprint']==scanning._fingerprint(TOKEN)
        assert {d['engine'] for d in leak['detectors']}=={'kingfisher','trufflehog'}
    assert len(trace.calls)==9 and len(trace.sessions)==9 and all(r.closed for r in trace.responses)
    retained=json.dumps([snap,rows,trace.collector.transport.evidence])+repr(trace.collector.transport.cache)+repr(trace.collector.options)+repr(trace.collector.collections)
    assert TOKEN not in retained and AUTH not in retained and target(profile)['object'] not in retained
    assert p['source'].OPTION not in trace.collector.options and not hasattr(trace.collector.transport,runtime.STATE)


@pytest.mark.parametrize('profile',['dataflow','batch'])
@pytest.mark.parametrize('hit',[False,True])
@pytest.mark.parametrize('absent',['kingfisher','trufflehog'])
def test_detector_unavailable_partial_hit(monkeypatch,profile,hit,absent):
    snap,rows,_=capture(monkeypatch,profile,payload=('token='+TOKEN).encode() if hit else b'mode=ready\n',absent=absent)
    assert {r['status'] for r in rows}=={'FAIL' if hit else 'UNKNOWN'}
    own,index=native_index(snap,profile);_,details=getattr(consumer,profile+'_source')(own['items'][0],index)
    assert details['complete'] is False


@pytest.mark.parametrize('profile',['dataflow','batch'])
@pytest.mark.parametrize('fault_name',['identity','reference','foreign','bucket','generation','incarnation','partial','denied','truncated','redirect','media_generation'])
def test_invalid_native_never_clean_pass(monkeypatch,profile,fault_name):
    def fault(op,n,data,resp):
        if op=='reference':
            if fault_name=='identity':data.pop('createTime' if profile=='dataflow' else 'uid',None)
            if fault_name=='reference':
                if profile=='dataflow':data['environment']['workerPools'][0]['packages'][0]['location']='storage.googleapis.com/foreign/wrong'
                else:data['taskGroups'][0]['taskSpec']['runnables'][0]['script']['path']='/foreign/script.sh'
            if fault_name=='foreign':data['projectId' if profile=='dataflow' else 'name']='foreign'
            if fault_name=='incarnation' and n==2:data['createTime' if profile=='dataflow' else 'uid']='changed'
            if fault_name=='partial':data['nextPageToken']='never-follow'
            if fault_name=='denied':resp.status_code=403
        if op=='bucket' and fault_name=='bucket':data['projectNumber']='10002'
        if op=='latest' and fault_name=='generation' and n==2:data['generation']='54321'
        if op=='content' and fault_name=='truncated':resp.stream=io.BytesIO(payload_short:=b'x')
        if op=='content' and fault_name=='media_generation':resp.headers['x-goog-generation']='54321'
        if fault_name=='redirect':resp.final_url='https://evil.invalid/private'
    _,rows,trace=capture(monkeypatch,profile,fault=fault)
    assert {r['status'] for r in rows}=={'UNKNOWN'}
    assert all(r.closed for r in trace.responses)


@pytest.mark.parametrize('profile',['dataflow','batch'])
@pytest.mark.parametrize('mode',['category','framework','inventory','default','private_spoof','flag_false'])
def test_default_off_no_content_auth(monkeypatch,profile,mode):
    p=runtime.PROFILES[profile]
    opts={runtime.NAMED:[p['check']],runtime.GRANT:{profile:{'seal':'spoof'}},'_content_secret_scan_kinds':[p['kind']]}
    if mode=='flag_false':opts['content_secret_scans']=False
    fields={'categories':['exposure']} if mode=='category' else {'frameworks':['hacktricks']} if mode=='framework' else {}
    _,rows,trace=capture(monkeypatch,profile,named=mode=='flag_false',options=opts,request_fields=fields)
    assert not trace.calls and not trace.auth and not trace.credential_constructions
    assert {r['status'] for r in rows}<={'UNKNOWN','EMPTY'}


@pytest.mark.parametrize('profile',['dataflow','batch'])
@pytest.mark.parametrize('tamper',['selector','scope','flag','profile','serialized'])
def test_opaque_grant_exact_selector_scope(monkeypatch,profile,tamper):
    p=runtime.PROFILES[profile];opts={p['source'].OPTION:[target(profile)],'content_secret_scans':True,'_content_secret_scan_kinds':[p['kind']]}
    runtime.issue_engine_grants(opts,[SCOPE],[p['check']])
    scopes=[SCOPE]
    if tamper=='selector':opts[p['source'].OPTION][0]['object']='other.sh'
    if tamper=='scope':scopes=['projects/foreign']
    if tamper=='flag':opts['content_secret_scans']=False
    if tamper=='profile':opts[runtime.GRANT]={('batch' if profile=='dataflow' else 'dataflow'):opts[runtime.GRANT][profile]}
    if tamper=='serialized':opts[runtime.GRANT]={profile:{'seal':'spoof'}}
    if tamper=='scope':
        with pytest.raises(ValueError):runtime.authorize_collector(opts,scopes)
    else:assert not runtime.authorize_collector(opts,scopes)


@pytest.mark.parametrize('profile',['dataflow','batch'])
@pytest.mark.parametrize('mode',['local','cognito'])
def test_hosted_public_option(profile,mode):
    p=runtime.PROFILES[profile];assert p['source'].OPTION in OPTIONS
    validate_connector('gcp',{'method':'token','token':AUTH},{'content_secret_scans':True,p['source'].OPTION:[target(profile)]},SimpleNamespace(auth_mode=mode),scopes=[SCOPE])


@pytest.mark.parametrize('profile',['dataflow','batch'])
@pytest.mark.parametrize('bad',['empty','duplicate','five','foreign','generation','extra','provider','private','boolean'])
def test_hosted_engine_preauth_reject(profile,bad):
    p=runtime.PROFILES[profile];t=target(profile);targets=[t];provider='gcp';extra={}
    if bad=='empty':targets=[]
    if bad=='duplicate':targets*=2
    if bad=='five':targets=[{**t,'resource':t['resource']+str(n)} for n in range(5)]
    if bad=='foreign':t['resource']=t['resource'].replace('/review/','/foreign/')
    if bad=='generation':t['generation']='0'
    if bad=='extra':t['extra']=True
    if bad=='provider':provider='azure'
    if bad=='private':extra[runtime.GRANT]={}
    if bad=='boolean':extra['content_secret_scans']='true'
    opts={'content_secret_scans':True,p['source'].OPTION:targets,**extra}
    with pytest.raises(HTTPException) as exc:validate_connector(provider,{},opts,SimpleNamespace(auth_mode='cognito' if bad=='private' else 'local'),scopes=[SCOPE])
    assert exc.value.status_code==422
    if bad!='private':
        with pytest.raises(ValueError):engine._request({'connector':{'provider':provider,'scopes':[SCOPE],'options':opts},'checks':[p['check']] if provider=='gcp' else []})


@pytest.mark.parametrize('profile',['dataflow','batch'])
@pytest.mark.parametrize('approved',[True,False])
def test_shared_sa_proof_gate(monkeypatch,profile,approved):
    _,rows,trace=capture(monkeypatch,profile,proof=approved)
    assert trace.metadata_calls==['https://cloudresourcemanager.googleapis.com/v3/'+SCOPE]
    assert len(trace.calls)==(9 if approved else 0)
    assert {r['status'] for r in rows}==({'PASS'} if approved else {'DENIED'})


@pytest.mark.parametrize('profile',['dataflow','batch'])
@pytest.mark.parametrize('logger',['urllib3','urllib3.connectionpool','requests'])
def test_unsafe_wire_debug_precedes_auth(monkeypatch,profile,logger):
    old=logging.getLogger(logger).level
    try:
        logging.getLogger(logger).setLevel(logging.DEBUG)
        _,rows,trace=capture(monkeypatch,profile)
        assert not trace.auth and not trace.calls and {r['status'] for r in rows}=={'UNKNOWN'}
    finally:logging.getLogger(logger).setLevel(old)


@pytest.mark.parametrize('profile',['dataflow','batch'])
def test_metadata_only_never_reads_source(monkeypatch,profile):
    _,_,trace=capture(monkeypatch,profile,named=False,normal_metadata=True,
        options={'inventories':[profile+'_job']},request_fields={'checks':[]})
    assert not trace.calls and not trace.auth


@pytest.mark.parametrize('profile',['dataflow','batch'])
def test_shared_union_retained_tuple_keys_and_options(monkeypatch,profile):
    other='other-ephemeral-native-match'
    def seed(snapshot,collector):
        import threading
        for name in ('_workbench_source_state','_dataproc_source_state'):
            setattr(collector.transport,name,dict(redactions={other},items={},lock=threading.RLock()))
        for value in (TOKEN,other):
            snapshot['metadata'][value]=value;collector.options[value]=value
            collector.transport.cache[(value,'nested')]={value:value};collector.transport.evidence.append({value:value})
            collector.collections[('prior',value)]={'items':[{'name':value}]}
    snap,rows,trace=capture(monkeypatch,profile,payload=('token='+TOKEN).encode(),mutate_snapshot=seed)
    retained=json.dumps([snap,rows,trace.collector.transport.evidence])+repr(trace.collector.transport.cache)+repr(trace.collector.options)+repr(trace.collector.collections)
    assert TOKEN in retained and other in retained  # found values stay visible
    assert not hasattr(trace.collector.transport,runtime.STATE) and not hasattr(trace.collector.transport,'_batch_source_redactions')


@pytest.mark.parametrize('profile',['dataflow','batch'])
@pytest.mark.parametrize('hit',[False,True])
@pytest.mark.parametrize('tamper',['version','closing_request','provenance','complete'])
def test_actual_selected_sibling_closure(monkeypatch,profile,hit,tamper):
    p=runtime.PROFILES[profile];targets=[target(profile),{**target(profile),'resource':target(profile)['resource']+'-second'}]
    snap,rows,_=capture(monkeypatch,profile,targets=targets,payload=('token='+TOKEN).encode() if hit else b'mode=ready\n')
    assert {r['status'] for r in rows}=={'FAIL' if hit else 'PASS'}
    own,index=native_index(snap,profile);first,second=own['items'];native=second[p['marker']]
    marker=native if profile=='dataflow' else native[bt.source.MARKER]
    if tamper=='version':marker['parts'][0]['engines'][0]['version']='0.0.0'
    if tamper=='complete':marker['native_complete']=False
    if tamper=='provenance':second['_provenance']['scope']='projects/foreign'
    if tamper=='closing_request':
        ledger=index['context']['metadata'][p['kind']+'_captures'][SCOPE]['receipts']
        next(r for r in ledger if r['identity']==second['name'] and r['operation']=='project_after')['request']='a'*64
    fn=getattr(consumer,profile+'_source');assert fn(second,index)[0]=='UNKNOWN'
    status,details=fn(first,index)
    assert status==('FAIL' if hit else 'UNKNOWN') and details['complete'] is False


def test_atomic_guard_native_cases_idempotent():
    receipt,cases,declarations=admission.reviewed_inputs();before=tuple(checks.CHECKS)
    admission.install();admission.install()
    assert tuple(checks.CHECKS)==before and set(cases)==set(runtime.CHECKS)
    for meta,fn in declarations:
        actual,=[c for c in checks.CHECKS if c.id==meta['id']]
        assert inspect.unwrap(actual.evaluate) is fn and actual.allow_incomplete_failure


@pytest.mark.parametrize('tamper',['consumer','parser','authorization','grant'])
def test_guard_rejects_executing_replacement(monkeypatch,tamper):
    fn={'consumer':consumer._evaluate,'parser':df.source.inspect_payload,'authorization':runtime.authorize_collector,'grant':runtime._Grant.__init__}[tamper]
    monkeypatch.setattr(fn,'__code__',(lambda *args,**kwargs:None).__code__)
    with pytest.raises(RuntimeError):admission.reviewed_inputs()


def test_guards_package_only(monkeypatch):
    original_read=Path.read_bytes;original_text=Path.read_text;root=Path(__file__).resolve().parents[1]
    def bound(path):assert path.resolve().is_relative_to(root/'peaso')
    def read(path,*args,**kw):bound(path);return original_read(path,*args,**kw)
    def text(path,*args,**kw):bound(path);return original_text(path,*args,**kw)
    monkeypatch.setattr(Path,'read_bytes',read);monkeypatch.setattr(Path,'read_text',text)
    admission.reviewed_inputs();active_shared().reviewed_inputs()


def test_exact_combined_shared_delta():
    active_shared().reviewed_inputs();receipt=shared.reviewed_delta()
    with pytest.raises(RuntimeError,match="^Workbench shared successor changed non-Workbench source$"):shared.reviewed_inputs()
    with pytest.raises(RuntimeError):shared.predecessor.reviewed_inputs()
    for name,row in receipt['shared_functions'].items():
        module=engine if name.startswith('engine.') else __import__('peaso.server.validation',fromlist=['validate_connector'])
        source=source_at_epoch(getattr(module,name.split('.')[1]),name,row['current_sha256'])
        for addition in row['exact_additions']:
            assert 'selected_job' in addition or 'gcp.review.dataflow' in addition
            source=source.replace(addition,'',1)
        assert hashlib.sha256(source.encode()).hexdigest()==row['predecessor']['sha256']


@pytest.mark.parametrize('profile',['dataflow','batch'])
def test_foreign_scope_does_not_poison_current_capture(monkeypatch,profile):
    snap,rows,_=capture(monkeypatch,profile);own,index=native_index(snap,profile)
    index['collections'][runtime.PROFILES[profile]['kind']].append({'scope':'projects/foreign','status':'partial','items':[{}]})
    assert getattr(consumer,profile+'_source')(own['items'][0],index)[0]=='PASS'


@pytest.mark.parametrize('branch',['pass','fail','unknown'])
def test_actual_k8s_opaque_grant_compatibility(monkeypatch,branch):
    from tests import test_k8s_selected_metadata_production_20261020 as native
    (status,evidence),trace,_,_=native.capture(monkeypatch,positive=branch=='fail',status=403 if branch=='unknown' else 200)
    assert status==branch.upper() and {r['status'] for r in trace.findings}=={status}
    assert shared.original.reviewed_inputs is active_shared().reviewed_inputs


@pytest.mark.parametrize('hit',[False,True])
def test_actual_workbench_opaque_grant_compatibility(monkeypatch,hit):
    from tests import test_gcp_workbench_source_runtime_20261020 as native
    snap,rows,trace=native.capture(monkeypatch,real=True,payload=('token='+TOKEN).encode() if hit else b'mode=ready\n')
    assert {r['status'] for r in rows}=={'FAIL' if hit else 'PASS'} and len(trace.calls)==9
    assert TOKEN not in json.dumps([snap,rows])


@pytest.mark.parametrize('hit',[False,True])
@pytest.mark.parametrize('malformed',['null','missing','list'])
def test_batch_new_successor_preserves_bound_hit_with_malformed_sibling(monkeypatch,hit,malformed):
    from peaso.checks import gcp_batch_referenced_source_20261020 as sealed
    targets=[bt.target(),{**bt.target(),'resource':bt.target()['resource']+'-second'}]
    snap,rows,_=capture(monkeypatch,'batch',targets=targets,payload=('token='+TOKEN).encode() if hit else b'mode=ready\n')
    own,index=native_index(snap,'batch');first,second=own['items'];p=runtime.PROFILES['batch']
    if malformed=='missing':second[p['marker']].pop(bt.source.MARKER)
    else:second[p['marker']][bt.source.MARKER]=None if malformed=='null' else []
    status,details=consumer.batch_source(first,index)
    assert status==('FAIL' if hit else 'UNKNOWN') and details['complete'] is False
    assert consumer.batch_source(second,index)[0]=='UNKNOWN'
    native_capture={**index['context']['metadata'][p['kind']+'_captures'][SCOPE], 'items':[r[p['marker']] for r in own['items']]}
    if malformed in ('null','list'):
        assert sealed.evaluate(first[p['marker']],native_capture,SCOPE)[0]=='UNKNOWN'  # Preserved original red behavior.
    import ast
    before=inspect.getsource(sealed._evaluate)
    after=inspect.getsource(consumer.batch._evaluate)
    delta="complete = m['complete'] and all(isinstance(r.get(source.MARKER), dict) and r[source.MARKER].get('complete') is True for r in items)"
    restored=after.replace(delta,"complete = m['complete'] and all(r.get(source.MARKER, {}).get('complete') is True for r in items)",1)
    assert restored==before and ast.dump(ast.parse(restored))==ast.dump(ast.parse(before))


@pytest.mark.parametrize('tamper',['consumer_alias','producer_alias','scanner_alias','profile'])
def test_import_binding_guard_rejects_drift(monkeypatch,tamper):
    if tamper=='consumer_alias':monkeypatch.setattr(consumer.batch,'predecessor',SimpleNamespace(source=bt.source,_hex=lambda _:True))
    if tamper=='producer_alias':monkeypatch.setattr(runtime,'dataflow',SimpleNamespace(**vars(df.source)))
    if tamper=='scanner_alias':monkeypatch.setattr(bt.source,'scan_content',lambda *a,**k:dict(complete=True,leaks=[],engines=[]))
    if tamper=='profile':monkeypatch.setitem(runtime.PROFILES['dataflow'],'kind','batch_selected_mounted_script_source')
    with pytest.raises(RuntimeError):admission.reviewed_inputs()


@pytest.mark.parametrize('collision',['metadata','evaluator','fixture'])
def test_atomic_collision_keeps_both_controls(monkeypatch,collision):
    monkeypatch.setattr(checks,'CHECKS',list(checks.CHECKS));monkeypatch.setattr(fixtures,'CASES',snapshot_cases(fixtures.CASES))
    ident=runtime.CHECKS[1];position=next(i for i,c in enumerate(checks.CHECKS) if c.id==ident)
    if collision=='metadata':checks.CHECKS[position]=replace(checks.CHECKS[position],severity='low')
    if collision=='evaluator':checks.CHECKS[position]=replace(checks.CHECKS[position],evaluate=lambda *a:('PASS',{}))
    if collision=='fixture':fixtures.CASES[ident]={'changed':True}
    before=tuple(checks.CHECKS);previous=snapshot_cases(fixtures.CASES)
    with pytest.raises(RuntimeError,match='collision'):admission.install()
    assert tuple(checks.CHECKS)==before and fixtures.CASES==previous


def test_atomic_second_registration_rolls_back_first(monkeypatch):
    monkeypatch.setattr(checks,'CHECKS',[c for c in checks.CHECKS if c.id not in runtime.CHECKS])
    monkeypatch.setattr(fixtures,'CASES',{k:v for k,v in fixtures.CASES.items() if k not in runtime.CHECKS})
    before=tuple(checks.CHECKS);previous=snapshot_cases(fixtures.CASES);original=checks.register
    def register(ident,*args,**kwargs):
        if ident==runtime.CHECKS[1]:raise RuntimeError('injected registration failure')
        return original(ident,*args,**kwargs)
    monkeypatch.setattr(checks,'register',register)
    with pytest.raises(RuntimeError,match='injected'):admission.install()
    assert tuple(checks.CHECKS)==before and fixtures.CASES==previous


@pytest.mark.parametrize('hit',[False,True])
def test_both_controls_native_shared_hmac_and_union(monkeypatch,hit):
    snap,rows,trace=capture(monkeypatch,combined=True,payload=('token='+TOKEN).encode() if hit else b'mode=ready\n')
    assert len(trace.calls)==18
    assert set().union(*(set(r.get('linked_check_ids',[r['check_id']])) for r in rows))==set(runtime.CHECKS)
    for profile in runtime.PROFILES:
        own,index=native_index(snap,profile)
        assert getattr(consumer,profile+'_source')(own['items'][0],index)[0]==('FAIL' if hit else 'PASS')
    assert {r['status'] for r in rows}=={'FAIL' if hit else 'PASS'}
    assert {c['type'] for c in snap['collections']}==runtime.KINDS
    if hit:
        leaks=[r['evidence']['secret_leaks'] for r in rows]
        assert len(rows)==1 and all(len(l)==1 and l[0]['fingerprint']==scanning._fingerprint(TOKEN) for l in leaks)
        assert len(leaks[0][0]['locations'])==2
    assert TOKEN not in json.dumps([snap,rows]) and not hasattr(trace.collector.transport,runtime.STATE)


@pytest.mark.parametrize('profile',['dataflow','batch'])
def test_actual_cross_scope_capture_isolation(monkeypatch,profile):
    second={**target(profile),'resource':target(profile)['resource'].replace('/review/','/second/')+'-second','bucket':'second-source'}
    def fault(op,n,data,response):
        if op=='reference' and (data.get('projectId')=='second' or data.get('name','').endswith('-second')):
            data.pop('createTime' if profile=='dataflow' else 'uid',None)
    snap,rows,trace=capture(monkeypatch,profile,targets=[target(profile),second],scopes=[SCOPE,'projects/second'],fault=fault)
    current=[r for r in rows if r['scope']==SCOPE];foreign=[r for r in rows if r['scope']=='projects/second']
    assert {r['status'] for r in current}=={'PASS'} and {r['status'] for r in foreign}=={'UNKNOWN'}
    own,index=native_index(snap,profile)
    assert getattr(consumer,profile+'_source')(own['items'][0],index)[0]=='PASS'


@pytest.mark.parametrize('profile',['dataflow','batch'])
def test_http_debug_refused_before_content_token(monkeypatch,profile):
    monkeypatch.setattr(http.client.HTTPConnection,'debuglevel',1)
    _,rows,trace=capture(monkeypatch,profile)
    assert not trace.calls and not trace.auth and {r['status'] for r in rows}=={'UNKNOWN'}


@pytest.mark.parametrize('profile',['dataflow','batch'])
@pytest.mark.parametrize('forged',[None,True,'engine',{'seal':'spoof'}])
def test_direct_collector_never_constructs_credentials_for_spoofed_grant(profile,forged):
    p=runtime.PROFILES[profile]
    collector=gcp.GCPCollector({'provider':'gcp','scopes':[SCOPE],'options':{
        'content_secret_scans':True,p['source'].OPTION:[target(profile)],runtime.GRANT:{profile:forged},
        runtime.NAMED:[p['check']],'_content_secret_scan_kinds':[p['kind']]}},requirements=[p['kind']])
    try:
        assert not collector.needed and collector.collect()['collections']==[] and collector.transport is None
    finally:collector.hydration_pool.shutdown(wait=True)


@pytest.mark.parametrize('profile',['dataflow','batch'])
@pytest.mark.parametrize('limit',[('max_calls',4),('max_resources',1)])
def test_collector_budget_never_invents_clean_coverage(monkeypatch,profile,limit):
    opts={limit[0]:limit[1]}
    targets=[target(profile),{**target(profile),'resource':target(profile)['resource']+'-second'}]
    snap,rows,trace=capture(monkeypatch,profile,targets=targets,options=opts)
    assert {r['status'] for r in rows}=={'UNKNOWN'}
    if limit[0]=='max_calls':assert len(trace.calls)<=4


@pytest.mark.parametrize('name',['__init__','envelope','dependent_jobs','finish','collect'])
def test_exact_gcp_added_dispatch_rejects_other_source_change(monkeypatch,name):
    receipt=admission.reviewed_inputs()[0];original=inspect.getsource;function=getattr(gcp.GCPCollector,name)
    def altered(fn):
        return original(fn)+'\n# unrelated unreviewed branch\n' if fn is function else original(fn)
    monkeypatch.setattr(inspect,'getsource',altered)
    with pytest.raises(RuntimeError,match='non-selected-source branch'):
        admission._gcp_delta(Path(__file__).resolve().parents[1],receipt)
