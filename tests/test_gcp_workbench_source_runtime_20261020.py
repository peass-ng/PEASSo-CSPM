"""Actual native Workbench HTTP through engine, GCPCollector and package admission."""
from copy import deepcopy
from tests.shared_admission_epoch_compatibility_20261020 import snapshot_cases, active_shared, source_at_epoch, sealed_ast
from dataclasses import replace
import ast
import gzip
import hashlib
import inspect
import io
import json
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import quote, urlsplit
import pytest
import requests
from fastapi import HTTPException
from peaso import checks, engine, secret_scanning as scanning
from peaso.checks import fixtures
from peaso.checks import gcp_workbench_source_runtime_admission_20261020 as admission
from peaso.checks import gcp_workbench_shared_hook_successor_20261020 as shared
from peaso.checks import gcp_dataflow_batch_shared_hook_successor_20261020 as combined_shared
from peaso.collectors import gcp
from peaso.collectors import gcp_workbench_source_runtime_20261020 as runtime
from peaso.collectors import gcp_workbench_referenced_source_20261020 as source
from peaso.server.validation import OPTIONS, validate_connector
from tests import gcp_workbench_referenced_source_20261020_test as predecessor

SCOPE, TOKEN, AUTH = predecessor.SCOPE, predecessor.TOKEN, predecessor.AUTH
KIND, CHECK = runtime.KIND, runtime.CHECK
PROOF_LABEL = 'hacktricks-cspm-' + 'a' * 20
Response, target, native = predecessor.Response, predecessor.target, predecessor.native


@pytest.fixture(autouse=True)
def offline(monkeypatch):
    yield from predecessor.offline.__wrapped__(monkeypatch)


def capture(monkeypatch, *, targets=None, payload=b'mode=ready\n', fault=None, real=False,
            absent=None, options=None, mutate_snapshot=None, token_change=False, named=True, request_fields=None, proof=None, normal_metadata=False):
    targets = deepcopy(targets if targets is not None else [target()])
    opts = {'content_secret_scans': True, '_content_secret_scan_kinds': [KIND],
            '_workbench_source_named_checks': [CHECK], source.OPTION: targets, 'retries': 0, 'concurrency': 1, 'metrics_scopes': False, 'include_inherited': False, **(options or {})}
    source.selected_targets(opts, [SCOPE])  # Pure validation before constructing credentials.
    seen, calls, responses, sessions, auth = [], [], [], [], []
    if not real:
        def detector(raw, path, timeout):
            seen.append((path, timeout))
            return [(TOKEN, 'inert-github', 1)] if TOKEN.encode() in raw else []
        monkeypatch.setattr(scanning, '_scan_kingfisher', detector)
        monkeypatch.setattr(scanning, '_scan_trufflehog', detector)
    if absent:
        def unavailable(*a, **k): raise RuntimeError(TOKEN)
        monkeypatch.setattr(scanning, '_scan_' + absent, unavailable)
    def headers():
        auth.append(True)
        return {'Authorization': 'Bearer ' + (AUTH + 'changed' if token_change and len(auth) > 1 else AUTH)}
    transports, collectors, native_metadata_calls = [], [], []
    original_init = gcp.Transport.__init__
    def initialize(self, *args, **kwargs):
        original_init(self, *args, **kwargs); transports.append(self)
    monkeypatch.setattr(gcp.Transport, '__init__', initialize)
    original_collector = gcp.GCPCollector.__init__
    def initialize_collector(self, *args, **kwargs):
        original_collector(self, *args, **kwargs); collectors.append(self)
    monkeypatch.setattr(gcp.GCPCollector, '__init__', initialize_collector)
    monkeypatch.setattr(gcp, 'Credentials', lambda *a, **k: SimpleNamespace(headers=headers, method='offline-native-test', close=lambda: None))
    if mutate_snapshot:
        original_final = runtime.final_snapshot
        def final(collector, snapshot):
            mutate_snapshot(snapshot, collector)
            return original_final(collector, snapshot)
        monkeypatch.setattr(runtime, 'final_snapshot', final)
    if proof is not None or normal_metadata:
        def metadata_request(self, method, url, **kw):
            assert method == 'GET'
            native_metadata_calls.append(url)
            if url == 'https://cloudresourcemanager.googleapis.com/v3/' + SCOPE:
                return dict(name='projects/10001', projectId='review', state='ACTIVE',
                            labels={PROOF_LABEL: 'approved' if proof else 'denied'}), 'native-project-proof'
            assert normal_metadata and url == 'https://notebooks.googleapis.com/v2/' + SCOPE + '/locations/-/instances'
            return {'instances': [native(targets[0])]}, 'native-instance-metadata'
        monkeypatch.setattr(gcp.Transport, 'request', metadata_request)
    counts = {}
    def request(method, url, **kw):
        assert method == 'GET' and kw['stream'] is True and kw['allow_redirects'] is False
        assert kw['headers'] == {'Authorization': 'Bearer ' + AUTH, 'Accept': '*/*' if kw['params'].get('alt') == 'media' else 'application/json',
                                 'Accept-Encoding': 'identity', 'Cache-Control': 'no-store'}
        assert 0 < kw['timeout'] <= 20
        parsed = urlsplit(url)
        assert parsed.scheme == 'https' and not parsed.query and not parsed.fragment
        t = next((t for t in targets if url.endswith(t['resource'])), None)
        if parsed.netloc == 'cloudresourcemanager.googleapis.com':
            assert parsed.path == '/v3/' + SCOPE and kw['params'] == {'fields': 'name,projectId,state'}
            op = 'project'; data = {'name': 'projects/10001', 'projectId': 'review', 'state': 'ACTIVE'}
        elif parsed.netloc == 'notebooks.googleapis.com':
            assert t is not None and parsed.path == '/v2/' + t['resource'] and kw['params'] == {}
            op = 'reference'; data = native(t)
        else:
            assert parsed.netloc == 'storage.googleapis.com'
            if '/o/' not in parsed.path:
                t = next(t for t in targets if parsed.path == '/storage/v1/b/' + quote(t['bucket'], safe=''))
                assert kw['params'] == {'fields': 'name,projectNumber', 'projection': 'noAcl'}
                op = 'bucket'; data = {'name': t['bucket'], 'projectNumber': '10001'}
            else:
                t = next(t for t in targets if parsed.path == '/storage/v1/b/' + quote(t['bucket'], safe='') + '/o/' + quote(t['object'], safe=''))
                if kw['params'].get('alt') == 'media':
                    assert kw['params'] == {'alt': 'media', 'generation': t['generation'], 'ifGenerationMatch': t['generation']}
                    op = 'content'; data = payload
                else:
                    assert kw['params'] == {'fields': source.objects.FIELDS, 'projection': 'noAcl'}
                    op = 'latest'; data = {'bucket': t['bucket'], 'name': t['object'], 'generation': t['generation'],
                        'size': str(len(payload)), 'contentType': 'text/plain'}
        counts[op] = counts.get(op, 0) + 1
        resp = Response(data, {'Content-Type': 'text/plain', 'x-goog-generation': t['generation']} if op == 'content' else None)
        if fault: fault(op, counts[op], resp, data)
        resp.url = getattr(resp, 'final_url', requests.Request(method, url, params=kw['params']).prepare().url)
        calls.append((op, method, url, deepcopy(kw['params'])))
        responses.append(resp)
        return resp
    # Both old reviewed GCS reader and the new instance reader use this unchanged session contract.
    monkeypatch.setattr(source.git, '_session', lambda: SimpleNamespace(request=request, close=lambda: sessions.append(True)))
    if not named:
        opts.setdefault('inventories', [KIND])
    connector = {'provider': 'gcp', 'scopes': [SCOPE], 'options': opts}
    if proof is not None:
        from peaso.gcp_platform import PLATFORM_PROJECT, PLATFORM_EMAIL
        connector['auth'] = dict(method='platform-service-account', project_proof_label=PROOF_LABEL,
            sa_json={'project_id': PLATFORM_PROJECT, 'client_email': PLATFORM_EMAIL, 'private_key': 'inert-key'})
    request_body = {'connector': connector}
    if named: request_body['checks'] = [CHECK]
    request_body.update(request_fields or {})
    snap = engine.collect_snapshot(request_body)
    rows = engine.evaluate_snapshot(snap, checks=[CHECK])['findings']
    transport = transports[-1] if transports else SimpleNamespace(cache={}, options=opts, evidence=[])
    collector = collectors[-1] if collectors else SimpleNamespace(transport=transport, options=opts, collections={})
    return snap, rows, SimpleNamespace(collector=collector, calls=calls, responses=responses, sessions=sessions,
        auth=auth, seen=seen, native_metadata_calls=native_metadata_calls)


@pytest.mark.parametrize('field', sorted(source.FIELDS))
@pytest.mark.parametrize('hit', [False, True])
@pytest.mark.parametrize('real', [False, True])
def test_engine_native_pass_fail_both_pinned_detectors(monkeypatch, field, hit, real):
    snap, rows, trace = capture(monkeypatch, targets=[target(field)], payload=('token=' + TOKEN).encode() if hit else b'mode=ready\n', real=real)
    assert {r['status'] for r in rows} == {'FAIL' if hit else 'PASS'}, rows
    assert snap['metadata']['collection_plan']['requirements'] == [KIND]
    assert len(trace.calls) == 9 and all(r.closed for r in trace.responses)
    from peaso.checks import gcp_workbench_source_runtime_consumer_20261020 as candidate
    own, = [c for c in snap['collections'] if c['type'] == KIND]
    idx = {'context': {'provider': 'gcp', 'scope': SCOPE, 'metadata': snap['metadata']}, 'collections': {KIND: [own]}}
    native_status, native_evidence = candidate.referenced_source(own['items'][0], idx)
    assert native_status == ('FAIL' if hit else 'PASS')
    assert native_evidence['executed_bytes_proven'] is False
    assert rows[0]['evidence']['credential_validation'] == 'not_attempted'
    assert {(e['engine'],e['version'],e['status']) for e in native_evidence['parts'][0]['engines']} == {
        ('kingfisher','1.4.0','complete'),('trufflehog','3.92.5','complete')}
    persisted = json.dumps([snap, rows, trace.collector.transport.cache, trace.collector.transport.evidence]) + repr(trace.collector.options)
    assert all(v not in persisted for v in (TOKEN, AUTH, 'gs://', 'scripts/source.sh'))
    assert runtime.GRANT not in trace.collector.options
    assert not hasattr(trace.collector.transport, '_workbench_source_state')


@pytest.mark.parametrize('engine_name', ['kingfisher','trufflehog'])
@pytest.mark.parametrize('hit', [False,True])
def test_engine_incomplete_detector_branches(monkeypatch, engine_name, hit):
    _, rows, _ = capture(monkeypatch, absent=engine_name, payload=('token='+TOKEN).encode() if hit else b'mode=ready\n')
    assert {r['status'] for r in rows} == {'FAIL' if hit else 'UNKNOWN'}


@pytest.mark.parametrize('mutation', ['id','reference','generation','foreign_instance','foreign_bucket','legacy','system_only','behavior','partial','truncated','denied','redirect'])
def test_engine_native_unknown_brackets(monkeypatch, mutation):
    def fault(op,n,resp,data):
        if op=='reference':
            if mutation=='id':data.pop('id')
            if mutation=='reference':data['gceSetup']['metadata'].clear()
            if mutation=='foreign_instance':data['name']=data['name'].replace('/review/','/foreign/')
            if mutation=='legacy':data['postStartupScript']=data.pop('gceSetup')['metadata']['post-startup-script']
            if mutation=='system_only':data['gceSetup']['systemMetadata']=data['gceSetup'].pop('metadata')
            if mutation=='behavior' and n==2:data['gceSetup']['metadata']['post-startup-script-behavior']='run_every_start'
            if mutation=='partial':data['unreachable']=['zone']
            if mutation=='denied':resp.status_code=403
        if mutation=='generation' and op=='latest' and n==2:data['generation']='54321'
        if mutation=='foreign_bucket' and op=='bucket':data['projectNumber']='10002'
        if mutation=='redirect':resp.final_url='https://evil.invalid/private'
        if isinstance(data,dict):
            resp.payload=json.dumps(data).encode();resp.stream=io.BytesIO(resp.payload);resp.headers['Content-Length']=str(len(resp.payload))
        if mutation=='truncated':resp.headers['Content-Length']=str(len(resp.payload)+1)
    snap, rows, trace = capture(monkeypatch,fault=fault)
    assert {r['status'] for r in rows} == {'UNKNOWN'}
    assert not trace.seen and all(r.closed for r in trace.responses)


@pytest.mark.parametrize('mode',['category','framework','inventory','default','private_spoof','flag_false'])
def test_engine_authorization_default_off(monkeypatch,mode):
    options={runtime.NAMED:[CHECK],runtime.GRANT:{'seal':'spoof'},'_content_secret_scan_kinds':[KIND]}
    fields={'categories':['exposure']} if mode=='category' else {'frameworks':['hacktricks']} if mode=='framework' else {}
    if mode=='flag_false':options['content_secret_scans']=False
    _,rows,trace=capture(monkeypatch,named=mode=='flag_false',options=options,request_fields=fields)
    assert not trace.calls and not trace.auth
    assert {r['status'] for r in rows}<={'UNKNOWN','EMPTY'}


@pytest.mark.parametrize('forged', [None, {'seal':'spoof'}, 'named', True])
def test_direct_collector_cannot_forge_engine_grant(forged):
    options={'content_secret_scans':True,source.OPTION:[target()],runtime.NAMED:[CHECK],
             runtime.GRANT:forged,'_content_secret_scan_kinds':[KIND]}
    collector=gcp.GCPCollector({'provider':'gcp','scopes':[SCOPE],'options':options},requirements=[KIND])
    try:
        assert not collector.needed
        assert collector.collect()['collections']==[] and collector.transport is None
    finally:collector.hydration_pool.shutdown(wait=True)


@pytest.mark.parametrize('mutation',['target','scope','flag'])
def test_issued_grant_bound_to_actual_selection(mutation):
    opts={'content_secret_scans':True,source.OPTION:[target()],'_content_secret_scan_kinds':[KIND]}
    runtime.issue_engine_grant(opts,[SCOPE],[CHECK])
    if mutation=='target':opts[source.OPTION][0]['object']='different.sh'
    if mutation=='scope':scopes=['projects/foreign']
    else:scopes=[SCOPE]
    if mutation=='flag':opts['content_secret_scans']=False
    if mutation=='scope':
        with pytest.raises(ValueError):runtime.authorize_collector(opts,scopes)
    else:assert not runtime.authorize_collector(opts,scopes)


@pytest.mark.parametrize('mode',['local','cognito'])
@pytest.mark.parametrize('field',sorted(source.FIELDS))
def test_hosted_option_admits_only_public_selection(mode,field):
    assert source.OPTION in OPTIONS
    validate_connector('gcp',{'method':'token','token':AUTH},
        {'content_secret_scans':True,source.OPTION:[target(field)]},SimpleNamespace(auth_mode=mode),scopes=[SCOPE])


@pytest.mark.parametrize('fault',['empty','duplicate','five','foreign','legacy','system_map','generation','url','extra','wrong_provider','wrong_scope','private_grant','boolean'])
def test_hosted_and_engine_reject_invalid_preauth(fault):
    t=target();rows=[t];scopes=[SCOPE];provider='gcp';extra={}
    if fault=='empty':rows=[]
    if fault=='duplicate':rows*=2
    if fault=='five':rows=[{**t,'object':str(n)+'.sh'} for n in range(5)]
    if fault=='foreign':t['resource']=t['resource'].replace('/review/','/foreign/')
    if fault=='legacy':t['field']='postStartupScript'
    if fault=='system_map':t['field']='gceSetup.systemMetadata.post-startup-script'
    if fault=='generation':t['generation']='0'
    if fault=='url':t['object']='https://evil.invalid/script.sh'
    if fault=='extra':t['extra']=True
    if fault=='wrong_provider':provider='azure'
    if fault=='wrong_scope':scopes=['projects/foreign']
    if fault=='private_grant':extra[runtime.GRANT]={}
    if fault=='boolean':extra['content_secret_scans']='true'
    opts={'content_secret_scans':True,source.OPTION:rows,**extra}
    with pytest.raises(HTTPException) as exc:
        validate_connector(provider,{},opts,SimpleNamespace(auth_mode='cognito' if fault=='private_grant' else 'local'),scopes=scopes)
    assert exc.value.status_code==422
    if fault!='private_grant':
        with pytest.raises(ValueError):engine._request({'connector':{'provider':provider,'scopes':scopes,'options':opts},'checks':[CHECK] if provider=='gcp' else []})


@pytest.mark.parametrize('approved',[True,False])
def test_existing_hosted_project_proof_gate_precedes_private_reads(monkeypatch,approved):
    snap,rows,trace=capture(monkeypatch,proof=approved)
    assert trace.native_metadata_calls==['https://cloudresourcemanager.googleapis.com/v3/'+SCOPE]
    if approved:assert len(trace.calls)==9 and {r['status'] for r in rows}=={'PASS'}
    else:assert not trace.calls and {r['status'] for r in rows}<={'DENIED','UNKNOWN'}


def test_normal_workbench_metadata_never_reads_source(monkeypatch):
    _,_,trace=capture(monkeypatch,named=False,normal_metadata=True,
        options={'inventories':['workbench_instance']},request_fields={'checks':['gcp.review.workbench.public_ip_disabled']})
    assert trace.native_metadata_calls and not trace.calls and not trace.auth and not trace.seen


def test_workbench_dataproc_union_exchanged_before_cleanup(monkeypatch):
    other='other-value-that-must-not-survive'
    def seed(snapshot,collector):
        collector.transport._dataproc_source_state={'redactions':{other},'items':{},'lock':__import__('threading').RLock()}
        for value in (TOKEN,other):
            snapshot['metadata'][value]=value
            collector.options[value]=value
            collector.transport.cache[value]=value
            collector.transport.evidence.append({'value':value})
            collector.collections[('previous',value)]={'items':[{'name':value}]}
    snap,rows,trace=capture(monkeypatch,payload=('token='+TOKEN).encode(),mutate_snapshot=seed)
    assert {r['status'] for r in rows}=={'FAIL'}
    persisted=json.dumps([snap,rows,trace.collector.transport.cache,trace.collector.transport.evidence])+repr(trace.collector.collections)+repr(trace.collector.options)
    assert TOKEN in persisted and other in persisted  # found values stay visible
    assert not hasattr(trace.collector.transport,'_workbench_source_state')
    assert not hasattr(trace.collector.transport,'_dataproc_source_state')


@pytest.mark.parametrize('hit',[False,True])
@pytest.mark.parametrize('mutation',['version','receipt_binding','native_complete','provenance_scope'])
def test_actual_selected_sibling_independently_validated(monkeypatch,hit,mutation):
    from peaso.checks import gcp_workbench_source_runtime_consumer_20261020 as candidate
    targets=[target(),{**target(),'resource':target()['resource']+'-second'}]
    snap,rows,trace=capture(monkeypatch,targets=targets,real=True,payload=('token='+TOKEN).encode() if hit else b'echo ready\n')
    assert len(trace.calls)==18 and {r['status'] for r in rows}=={'FAIL' if hit else 'PASS'}
    envelope=snap['collections'][0];first,second=envelope['items']
    if mutation=='version':second[source.MARKER]['parts'][0]['engines'][0]['version']='0.0.0'
    elif mutation=='native_complete':second[source.MARKER]['native_complete']=False
    elif mutation=='provenance_scope':second['_provenance']['scope']='projects/foreign'
    else:
        receipt=next(r for r in snap['metadata']['workbench_source_receipts'] if r['identity']==second['name'])
        receipt['bound']=False
    index={'context':{'provider':'gcp','scope':SCOPE,'metadata':snap['metadata']},'collections':{KIND:[envelope]}}
    assert candidate.referenced_source(second,index)[0]=='UNKNOWN'
    status,evidence=candidate.referenced_source(first,index)
    assert status==('FAIL' if hit else 'UNKNOWN') and evidence['complete'] is False
    if mutation=='version':
        old_status,old_evidence=predecessor.consumer.referenced_source(first,index)
        assert old_status==('FAIL' if hit else 'PASS') and old_evidence['complete'] is True


def test_foreign_scope_incompleteness_does_not_contaminate_selected_scope(monkeypatch):
    from peaso.checks import gcp_workbench_source_runtime_consumer_20261020 as candidate
    snap,rows,_=capture(monkeypatch)
    envelope=snap['collections'][0];item=envelope['items'][0]
    index={'context':{'provider':'gcp','scope':SCOPE,'metadata':snap['metadata']},'collections':{KIND:[envelope,
        {'type':KIND,'scope':'projects/foreign','status':'partial','items':[{}]}]}}
    status,evidence=candidate.referenced_source(item,index)
    assert status=='PASS' and evidence['complete'] is True


def test_atomic_admission_idempotence_and_public_cases(monkeypatch):
    from tests.current_runtime_admission_inputs_20261022 import current_inputs
    from peaso.rawv2_private_source_successor_20261021 import install_admission
    monkeypatch.setattr(checks,'CHECKS',list(checks.CHECKS));monkeypatch.setattr(fixtures,'CASES',dict(fixtures.CASES))
    before=list(checks.CHECKS);receipt,cases,declarations=current_inputs(admission)
    install_admission('gcp_workbench_source_runtime_admission_20261020')
    assert checks.CHECKS==before and set(cases)=={CHECK}
    meta,function=declarations[0]
    actual,=[c for c in engine._registry() if c.id==CHECK]
    assert inspect.unwrap(actual.evaluate) is function and actual.allow_incomplete_failure
    for branch in ('pass','fail','unknown','missing','malformed'):
        case=cases[CHECK];idx=case.get(branch+'_index',case['index'])
        assert function(case[branch],idx)[0]==(branch.upper() if branch in ('pass','fail') else 'UNKNOWN')


@pytest.mark.parametrize('collision',['metadata','evaluator','fixture'])
def test_atomic_admission_collision_retains_registry(monkeypatch,collision):
    from peaso.rawv2_private_source_successor_20261021 import install_admission
    monkeypatch.setattr(checks,'CHECKS',list(checks.CHECKS));monkeypatch.setattr(fixtures,'CASES',dict(fixtures.CASES))
    pos=next(i for i,c in enumerate(checks.CHECKS) if c.id==CHECK)
    if collision=='metadata':checks.CHECKS[pos]=replace(checks.CHECKS[pos],severity='low')
    elif collision=='evaluator':checks.CHECKS[pos]=replace(checks.CHECKS[pos],evaluate=lambda *args:('PASS',{}))
    else:fixtures.CASES[CHECK]={'changed':True}
    before=list(checks.CHECKS);prior=snapshot_cases(fixtures.CASES)
    with pytest.raises(RuntimeError,match='collision'):install_admission('gcp_workbench_source_runtime_admission_20261020')
    assert checks.CHECKS==before and fixtures.CASES==prior


@pytest.mark.parametrize('kind',['consumer_body','row_body','adapter_body'])
def test_guard_checks_executing_code_not_only_source_hash(monkeypatch,kind):
    from peaso.rawv2_private_source_successor_20261021 import install_admission
    from peaso.checks import gcp_workbench_source_runtime_consumer_20261020 as candidate
    function=candidate.referenced_source if kind=='consumer_body' else candidate._evaluate_row if kind=='row_body' else runtime.authorize_collector
    monkeypatch.setattr(function,'__code__',(lambda *args,**kwargs:('PASS',{})).__code__)
    with pytest.raises(RuntimeError,match='executing runtime callable changed'):
        install_admission('gcp_workbench_source_runtime_admission_20261020')


def test_runtime_guards_never_load_tests_or_docs(monkeypatch):
    from peaso.rawv2_private_source_successor_20261021 import install_admission
    original_bytes,original_text=Path.read_bytes,Path.read_text
    root=Path(__file__).resolve().parents[1]
    def check(path):
        assert not path.resolve().is_relative_to(root/'tests') and not path.resolve().is_relative_to(root/'docs')
    def read_bytes(path,*args,**kwargs):check(path);return original_bytes(path,*args,**kwargs)
    def read_text(path,*args,**kwargs):check(path);return original_text(path,*args,**kwargs)
    monkeypatch.setattr(Path,'read_bytes',read_bytes);monkeypatch.setattr(Path,'read_text',read_text)
    install_admission('gcp_workbench_source_runtime_admission_20261020');active_shared().reviewed_inputs()
    assert shared.original.reviewed_inputs is active_shared().reviewed_inputs


def test_exact_shared_source_successor_preserves_original_red():
    archived=Path('tests/fixtures/gcp_workbench_shared_hook_test_pre_combined_20261020.json.gz').read_bytes()
    assert hashlib.sha256(archived).hexdigest()=='524884353022cda92cc1bcae034cd988e145a0e9875a0489fd2f25854ea19bf3'
    history=json.loads(gzip.decompress(archived))
    assert history['sources'][history['source']]['sha256']=='32d98b1df43130d6edbae8140c20fd3cc5c2ac6e56a44ab562fd927f32227d45'
    for entry in history['sources'].values():
        assert hashlib.sha256(entry['content'].encode()).hexdigest()==entry['sha256']
        assert len(entry['content'].encode())==entry['bytes']
    assert history['baseline_gate']['passed']==601 and history['baseline_gate']['failed']==6
    assert len(history['baseline_gate']['failed_nodes'])==6
    with pytest.raises(RuntimeError):shared.PREDECESSOR_REVIEWED_INPUTS()
    with pytest.raises(RuntimeError,match='^metadata predecessor source changed$'):shared.reviewed_inputs()
    with pytest.raises(RuntimeError, match="^metadata predecessor source changed$"):
        combined_shared.reviewed_inputs()
    active_shared().reviewed_inputs()
    receipt=combined_shared.reviewed_delta();accepted=shared.reviewed_delta()
    assert set(receipt['shared_functions'])=={'engine._request','engine.collect_snapshot','validation.validate_connector'}
    for name,row in receipt['shared_functions'].items():
        owner,attribute=name.split('.')
        module=engine if owner=='engine' else __import__('peaso.server.validation',fromlist=['validate_connector'])
        restored=source_at_epoch(getattr(module,attribute),name,row['current_sha256'])
        assert hashlib.sha256(restored.encode()).hexdigest()==row['current_sha256']
        for addition in row['exact_additions']:
            assert ('dataflow' in addition.lower() or 'batch' in addition.lower()) and 'k8s' not in addition.lower()
            assert restored.count(addition)==1
            restored=restored.replace(addition,'',1)
        assert hashlib.sha256(restored.encode()).hexdigest()==row['predecessor']['sha256']==accepted['shared_functions'][name]['current_sha256']
        assert sealed_ast(ast.parse(restored))==row['predecessor_ast']
        prior=accepted['shared_functions'][name]
        for addition in prior['exact_additions']:
            assert 'workbench' in addition.lower() and 'k8s' not in addition.lower()
            assert restored.count(addition)==1
            restored=restored.replace(addition,'',1)
        assert hashlib.sha256(restored.encode()).hexdigest()==prior['predecessor']['sha256']
        assert sealed_ast(ast.parse(restored))==prior['predecessor_ast']


@pytest.mark.parametrize('name',['engine._request','engine.collect_snapshot','validation.validate_connector'])
def test_shared_successor_rejects_extra_non_workbench_source(monkeypatch,name):
    receipt=active_shared().reviewed_delta();historical=shared.reviewed_delta()['shared_functions'][name]['predecessor']
    module=engine if name.startswith('engine.') else __import__('peaso.server.validation',fromlist=['validate_connector'])
    fn=getattr(module,name.split('.')[1]);original=inspect.getsource
    root=Path(__file__).resolve().parents[1]
    active_shared().check_shared(fn,historical,name,root,{},receipt)
    def source_text(function):
        text=original(function)
        return text+'\n# unreviewed K8s or other change\n' if function is fn else text
    with monkeypatch.context() as patch:
        patch.setattr(inspect,'getsource',source_text)
        with pytest.raises(RuntimeError,match='source changed'):
            active_shared().check_shared(fn,historical,name,root,{},receipt)
    active_shared().check_shared(fn,historical,name,root,{},receipt)


def test_sealed_proposal_bytes_remain_unchanged():
    from peaso.checks.gcp_workbench_referenced_source_20261020_proposal import validate_proposal
    from peaso.rawv2_private_source_successor_20261021 import install_admission
    with pytest.raises(ValueError, match='^proposal file changed: peaso/collectors/gcp_workbench_referenced_source_20261020.py$'):
        validate_proposal()
    install_admission('gcp_workbench_source_runtime_admission_20261020')
    receipt=json.loads(Path('peaso/checks/gcp_workbench_referenced_source_20261020_proposal.json').read_bytes())
    assert receipt['registration']=='unregistered_proposal_only'
    assert not {'peaso/engine.py','peaso/collectors/gcp.py','peaso/checks/__init__.py','peaso/server/validation.py'}&set(receipt['files'])


@pytest.mark.parametrize('kind',sorted(shared.original.prepared.producer.NATIVE_KINDS))
def test_all_selected_k8s_metadata_paths_disjoint_from_network_router(kind):
    from peaso.collectors import k8s_network_extensions as network
    source=shared.original.prepared.producer
    actual=source._path({'kind':kind,'namespace':'review','name':'selected-name'})
    assert network.match(actual) is None
    assert network.match(actual.rsplit('/',1)[0]) is None
    assert network.match(actual.replace('/review/','/other-namespace/')) is None


@pytest.mark.parametrize('tamper',['matcher','map','reader_call'])
def test_disjoint_network_bridge_rejects_hostile_runtime_change(monkeypatch,tamper):
    from peaso.collectors import k8s_network_extensions as network
    with pytest.raises(RuntimeError, match="^metadata predecessor source changed$"):
        combined_shared.reviewed_inputs()
    active_shared().reviewed_inputs()
    reasons={'matcher':'metadata runtime executing callable changed',
             'map':'metadata network router map changed',
             'reader_call':'metadata predecessor callable replacement'}
    with monkeypatch.context() as patch:
        if tamper=='matcher':patch.setattr(network,'match',lambda path:'forged-reader')
        elif tamper=='map':patch.setattr(network,'RESOURCES',{})
        else:patch.setattr(shared.original.k8s.K8sReader,'call',lambda *args,**kwargs:{})
        with pytest.raises(RuntimeError,match=reasons[tamper]):active_shared().reviewed_inputs()
    with pytest.raises(RuntimeError, match="^metadata predecessor source changed$"):
        combined_shared.reviewed_inputs()
    active_shared().reviewed_inputs()


def test_verified_successor_entrypoint_routes_immutable_k8s_grants():
    assert shared.original.reviewed_inputs is active_shared().reviewed_inputs
    assert combined_shared.predecessor is shared and combined_shared.original is shared.original
    shared.original.reviewed_inputs()
    with pytest.raises(RuntimeError,match='^metadata predecessor source changed$'):shared.reviewed_inputs()
    assert inspect.getsource(shared.original.runtime.authorize).count('k8s_selected_metadata_runtime_admission_20261020')==1
    assert inspect.getsource(shared.original.runtime.collect).count('k8s_selected_metadata_runtime_admission_20261020')==1


@pytest.mark.parametrize('branch',['pass','fail','unknown'])
def test_existing_k8s_engine_native_capture_through_verified_successor(monkeypatch,branch):
    from tests import test_k8s_selected_metadata_production_20261020 as k8s_native
    (status,evidence),trace,_,_=k8s_native.capture(monkeypatch,positive=branch=='fail',status=403 if branch=='unknown' else 200)
    assert status==branch.upper() and len(trace.calls)==(1 if branch=='unknown' else 2)
    assert {finding['status'] for finding in trace.findings}=={status}
    assert all(response.closed and response.released for response in trace.responses)
    assert k8s_native.TOKEN not in json.dumps([trace.snapshot,trace.findings])
    assert shared.original.reviewed_inputs is active_shared().reviewed_inputs


def test_successor_alias_substitution_is_rejected(monkeypatch):
    with pytest.raises(RuntimeError, match="^metadata predecessor source changed$"):
        combined_shared.reviewed_inputs()
    active_shared().reviewed_inputs()
    with monkeypatch.context() as patch:
        patch.setattr(shared.original,'reviewed_inputs',lambda:None)
        with pytest.raises(RuntimeError,match='metadata runtime successor alias replaced'):active_shared().reviewed_inputs()
    assert shared.original.reviewed_inputs is active_shared().reviewed_inputs
    with pytest.raises(RuntimeError, match="^metadata predecessor source changed$"):
        combined_shared.reviewed_inputs()
    active_shared().reviewed_inputs()


@pytest.mark.parametrize('helper',['check_shared','prepared_inputs','reviewed_inputs'])
def test_shared_successor_helper_replacement_rejected(monkeypatch,helper):
    monkeypatch.setattr(shared,helper,lambda *args,**kwargs:None)
    with pytest.raises(RuntimeError,match='successor callable replaced'):shared.reviewed_delta()


@pytest.mark.parametrize('tamper',['receipt','fixture','producer','consumer','adapter'])
def test_workbench_guard_rejects_package_source_drift(monkeypatch,tamper):
    from peaso.rawv2_private_source_successor_20261021 import install_admission
    from peaso.private_secret_source_epoch_20261021 import AdmissionError
    from tests.current_runtime_admission_inputs_20261022 import alter_exact_source_read
    receipt_path=Path('peaso/checks/gcp_workbench_source_runtime_admission_20261020.json')
    receipt=json.loads(receipt_path.read_text())
    paths={'receipt':str(receipt_path),'fixture':receipt['fixture']['path'],
        'producer':'peaso/collectors/gcp_workbench_referenced_source_20261020.py',
        'consumer':'peaso/checks/gcp_workbench_source_runtime_consumer_20261020.py',
        'adapter':'peaso/collectors/gcp_workbench_source_runtime_20261020.py'}
    hits=alter_exact_source_read(monkeypatch, paths[tamper])
    expected=((AdmissionError,'current source mismatch') if tamper=='producer'
              else (AdmissionError,'unreviewed predecessor request') if tamper in ('consumer','adapter')
              else (RuntimeError,'changed'))
    with pytest.raises(expected[0],match=expected[1]):
        install_admission('gcp_workbench_source_runtime_admission_20261020')
    assert hits
