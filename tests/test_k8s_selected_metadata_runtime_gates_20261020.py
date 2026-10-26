"""Atomic/current-source, hosted preauth, default-off and union-privacy gates."""
from copy import deepcopy
from dataclasses import replace
import gzip
import json
from pathlib import Path
import shutil
import socket
from types import SimpleNamespace
import pytest
from fastapi import HTTPException
from peaso import checks,engine
from peaso.checks import fixtures
from peaso.checks import k8s_selected_metadata_runtime_admission_20261020 as admission
from peaso.checks import k8s_annotation_native_admission_20261020 as annotation
from peaso.checks import k8s_kubelet_configmap_admission_20261020 as configmaps
from peaso.collectors import k8s
from peaso.server.validation import validate_connector
from tests.test_k8s_selected_metadata_production_20261020 import (
    offline,capture,source,runtime,consumer,NS,CLUSTER,HOST,TOKEN,native_document,Response)


def request(**options):
    t={'cluster_id':CLUSTER,'namespace':NS,'kind':'Pod','name':'metadata-object'}
    return {'connector':{'provider':'k8s','scopes':[NS],
        'auth':{'method':'token','server':HOST,'token':'inert-auth-canary','cluster_id':CLUSTER},
        'options':{'content_secret_scans':True,source.OPTION:[t],**options}},'checks':[source.CHECK]}


def current():return next(c for c in checks.CHECKS if c.id==source.CHECK)


def isolate(monkeypatch):
    monkeypatch.setattr(checks,'CHECKS',[c for c in checks.CHECKS if c.id!=source.CHECK])
    monkeypatch.setattr(fixtures,'CASES',{key:value for key,value in fixtures.CASES.items()if key!=source.CHECK})
    monkeypatch.setattr(admission,'_INSTALLED',())


def test_exact_one_registered_check_case_and_prior_thirteen_preserved():
    old=current();before=deepcopy(fixtures.CASES)
    admission.install();admission.install();annotation.install();configmaps.install()
    assert current()is old and fixtures.CASES==before
    assert sum(c.id==source.CHECK for c in checks.CHECKS)==1
    assert current().evaluate.__wrapped__ is consumer.evaluate and current().allow_incomplete_failure
    assert current().dependencies==[source.KIND]and len([c for c in checks.CHECKS if c.id in annotation.IDS+configmaps.IDS])==13


def test_default_plan_exclusion_and_exact_named_requirement():
    req=request();assert engine.plan_collection(req)==[source.KIND]
    req.pop('checks');assert source.KIND not in engine.plan_collection(req)
    assert source.KIND in engine.BULK_STREAM_TYPES['k8s']and source.KIND not in k8s.ENDPOINTS


@pytest.mark.parametrize('fault',['missing','empty','extra','foreign_scope','duplicate','secret_kind','traversal'])
def test_preauth_rejection_precedes_sdk_or_credential_creation(monkeypatch,fault):
    req=request();targets=req['connector']['options'][source.OPTION]
    if fault=='missing':req['connector']['options'].pop(source.OPTION)
    elif fault=='empty':targets.clear()
    elif fault=='extra':targets[0]['path']='/anywhere'
    elif fault=='foreign_scope':targets[0]['namespace']='foreign'
    elif fault=='duplicate':targets.append(deepcopy(targets[0]))
    elif fault=='secret_kind':targets[0]['kind']='Secret'
    else:targets[0]['name']='object/log'
    monkeypatch.setattr(k8s,'_new_api',lambda *a:pytest.fail('invalid target reached authentication'))
    with pytest.raises(ValueError):engine.collect_snapshot(req)


@pytest.mark.parametrize('fault',['provider','namespace','private_option','secret_kind'])
def test_hosted_validator_rejects_wrong_scope_or_internal_grant(monkeypatch,fault):
    monkeypatch.setattr(socket,'getaddrinfo',lambda *a,**kw:[(socket.AF_INET,socket.SOCK_STREAM,6,'',('8.8.8.8',6443))])
    req=request();options=req['connector']['options'];provider='k8s';scopes=[NS]
    if fault=='provider':provider='azure'
    elif fault=='namespace':scopes=['foreign']
    elif fault=='private_option':options[runtime.GRANT]={'token':'forged'}
    else:options[source.OPTION][0]['kind']='Secret'
    with pytest.raises(HTTPException)as error:validate_connector(provider,req['connector']['auth'],options,SimpleNamespace(auth_mode='cognito'),scopes=scopes)
    assert error.value.status_code==422


def test_hosted_valid_selector_uses_existing_inline_auth_boundary(monkeypatch):
    monkeypatch.setattr(socket,'getaddrinfo',lambda *a,**kw:[(socket.AF_INET,socket.SOCK_STREAM,6,'',('8.8.8.8',6443))])
    req=request();validate_connector('k8s',req['connector']['auth'],req['connector']['options'],SimpleNamespace(auth_mode='cognito'),scopes=[NS])
    # Actual collection is separate: a hosted connector still uses its existing
    # bounded authenticated SDK origin; no hosted DNS/network is contacted here.


@pytest.mark.parametrize('forged',[None,True,{'token':'forged'},'k8s_selected_metadata'])
def test_kind_selector_and_spoofed_grant_cannot_authorize(monkeypatch,forged):
    (status,_),trace,_,index=capture(monkeypatch,named=False,options={runtime.GRANT:forged,'_content_secret_scan_kinds':[source.KIND]})
    # Capture maps legacy private kind to named=True, so remove its private-kind
    # input: only the public request named bit controls actual authorization.
    assert status=='UNKNOWN'and not trace.calls


def test_request_grant_is_bound_to_exact_selection_and_scope():
    opts=deepcopy(request()['connector']['options']);runtime.authorize(opts,[NS],[source.CHECK])
    assert runtime.enabled(opts,[NS])and runtime.enabled(opts)
    opts[source.OPTION][0]['name']='changed'
    assert not runtime.enabled(opts,[NS])
    opts=deepcopy(request()['connector']['options']);runtime.authorize(opts,[NS],[source.CHECK])
    assert not runtime.enabled(opts,['foreign'])


@pytest.mark.parametrize('stage',['registration','fixture'])
def test_atomic_failure_rolls_back_without_partial_case_or_check(monkeypatch,stage):
    isolate(monkeypatch);before=tuple(checks.CHECKS);cases=dict(fixtures.CASES)
    if stage=='registration':
        class Broken(list):
            def append(self,value):raise RuntimeError('injected registration')
        monkeypatch.setattr(checks,'CHECKS',Broken(checks.CHECKS))
    else:
        class Broken(dict):
            def __setitem__(self,key,value):
                if key==source.CHECK:raise RuntimeError('injected fixture')
                super().__setitem__(key,value)
        monkeypatch.setattr(fixtures,'CASES',Broken(fixtures.CASES))
    with pytest.raises(RuntimeError,match='injected'):admission.install()
    assert tuple(checks.CHECKS)==before and fixtures.CASES==cases and admission._INSTALLED==()


@pytest.mark.parametrize('fault',['duplicate','case','alias','title','wrapper','kind'])
def test_collision_or_installed_metadata_drift_is_never_replaced(monkeypatch,fault):
    old=current();monkeypatch.setattr(checks,'CHECKS',list(checks.CHECKS));monkeypatch.setattr(fixtures,'CASES',deepcopy(fixtures.CASES))
    if fault=='duplicate':checks.CHECKS.append(old)
    elif fault=='case':fixtures.CASES[source.CHECK]['pass'].clear()
    elif fault=='alias':monkeypatch.setattr(checks,'CHECK_ALIASES',{**checks.CHECK_ALIASES,'foreign':source.CHECK})
    elif fault=='title':checks.CHECKS[checks.CHECKS.index(old)]=replace(old,title='changed')
    elif fault=='wrapper':monkeypatch.setattr(old.evaluate,'__wrapped__',lambda *a:('PASS',{}))
    else:monkeypatch.setattr(k8s,'TYPES',k8s.TYPES+(source.KIND,))
    before=tuple(checks.CHECKS);cases=deepcopy(fixtures.CASES)
    with pytest.raises(RuntimeError):admission.install()
    assert tuple(checks.CHECKS)==before and fixtures.CASES==cases


def packaged_root(tmp_path):
    root=Path(__file__).resolve().parents[1];receipt=json.loads((root/'peaso/checks'/admission.RECEIPT).read_bytes())
    old=json.loads((root/'peaso/checks'/admission.prepared.RECEIPT).read_bytes())
    paths=set(receipt['sources'])|set(old['sources'])|{r['path']for r in receipt['fixtures']}|{r['path']for r in receipt['functions'].values()}|{r['path']for r in old['functions'].values()}|{'peaso/checks/'+admission.RECEIPT,'peaso/checks/'+admission.prepared.RECEIPT}
    for relative in paths:
        assert relative.startswith('peaso/')
        p=tmp_path/relative;p.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(root/relative,p)
    return receipt


def test_runtime_admission_has_no_tests_or_docs_filesystem_dependency(tmp_path):
    receipt=packaged_root(tmp_path)
    assert not(tmp_path/'tests').exists()and not(tmp_path/'docs').exists()
    assert admission.reviewed_inputs(tmp_path)[2]['id']==source.CHECK
    assets=json.loads(gzip.decompress((tmp_path/'peaso/checks'/admission.ASSETS).read_bytes()))
    assert all(not name.endswith('.py')and not name.endswith('.md')for name in assets)
    assert all(row['path'].startswith('peaso/checks/')for row in receipt['fixtures'])


@pytest.mark.parametrize('fault',['source','native','assets','cases','shared'])
def test_runtime_packaged_source_or_native_data_drift_is_rejected(tmp_path,fault):
    packaged_root(tmp_path)
    names={'source':'peaso/collectors/k8s_selected_metadata_runtime_20261020.py','native':'peaso/checks/k8s_selected_metadata_runtime_native_20261020.json.gz',
        'assets':'peaso/checks/'+admission.ASSETS,'cases':'peaso/checks/'+admission.CASES,'shared':'peaso/collectors/k8s.py'}
    p=tmp_path/names[fault]
    if fault=='shared':p.write_text(p.read_text().replace('    options, auth = dict(connector.get("options", {})), connector.get("auth", {})','    options, auth = dict(connector.get("options", {})), connector.get("auth", {})\n    # unreviewed exact delta',1))
    else:
        with p.open('ab')as stream:stream.write(b'\n')
    with pytest.raises(RuntimeError):admission.reviewed_inputs(tmp_path)


@pytest.mark.parametrize('fault',['token','class','check','kind','option','code'])
def test_runtime_capability_or_callable_drift_fails_closed(monkeypatch,fault):
    if fault=='token':monkeypatch.setattr(runtime,'_TOKEN',object())
    elif fault=='class':monkeypatch.setattr(runtime,'_Grant',type('Fake',(),{}))
    elif fault=='check':monkeypatch.setattr(runtime,'CHECK','foreign')
    elif fault=='kind':monkeypatch.setattr(runtime,'KIND','pod')
    elif fault=='option':monkeypatch.setattr(runtime,'OPTION','inventories')
    else:monkeypatch.setattr(runtime.enabled,'__code__',(lambda *a,**kw:True).__code__)
    with pytest.raises(RuntimeError):admission.reviewed_inputs()


def test_final_union_scrubs_all_three_ledgers_before_clearing():
    values=['first-private-value','second-private-value','third-private-value'];ledgers=[{value}for value in values]
    scopes,rows,metadata=runtime.finalize(['team-a'],[{'id':values[0],'location':values[1]}],{values[2]:values},*ledgers)
    assert not any(ledgers)and all(value in json.dumps([scopes,rows,metadata])for value in values)


def test_actual_three_reader_native_pipeline_unions_values_before_snapshot(monkeypatch):
    from datetime import datetime,timedelta,timezone
    from urllib.parse import urlsplit,parse_qs
    from kubernetes.client import ApiClient,Configuration
    from peaso import secret_scanning
    from peaso.collectors import k8s_literal_secret_indicators as literals
    from peaso.collectors import k8s_selected_log_sample_secret_indicators as logs
    from tests import test_k8s_selected_log_sample_secret_review_20261020 as log_wire
    values=[TOKEN,TOKEN.replace('7mQ2','8nR3'),TOKEN.replace('7mQ2','9pS4')]
    t={'cluster_id':CLUSTER,'namespace':NS,'kind':'Pod','name':'metadata-object'}
    log_target={'cluster_id':CLUSTER,'namespace':NS,'pod':t['name'],'container':'app'}
    doc=log_wire.pod(log_target);doc['metadata']['annotations']={'example.test/token':values[0]}
    doc['spec']['containers'][0]['env']=[{'name':'TOKEN','value':values[1]}]
    path=source._path(t);calls=[];responses=[]
    class Pool:
        def request(self,method,url,**kw):
            parsed=urlsplit(url);assert method=='GET'and parsed.scheme=='https'and parsed.netloc==urlsplit(HOST).netloc
            assert kw['headers']['authorization']=='Bearer inert-auth-canary'
            assert kw['redirect']is False and kw['retries']is False and kw['preload_content']is False
            assert kw.get('body')is None
            calls.append(parsed.path)
            if parsed.path==path:
                assert not parsed.query;result=log_wire.Response(deepcopy(doc))
            else:
                assert parsed.path==path+'/log'
                assert not parsed.query
                query=kw['fields'];assert query==logs.request_spec(log_target,query['sinceTime'])[2]
                assert query['container']=='app'and query['tailLines']=='100'
                assert query['follow']=='false'and query['previous']=='false'and query['timestamps']=='true'
                assert query['limitBytes']==str(logs.MAX_LOG)and isinstance(query['sinceTime'],str)
                stamp=(datetime.now(timezone.utc)-timedelta(seconds=5)).isoformat().replace('+00:00','Z')
                result=log_wire.Response((stamp+' '+values[2]+'\n').encode(),log=True)
            responses.append(result);return result
    def api(auth):
        cfg=Configuration();cfg.host=HOST;cfg.api_key={'authorization':'inert-auth-canary'};cfg.api_key_prefix={'authorization':'Bearer'}
        client=ApiClient(cfg);client.rest_client.pool_manager=Pool();return k8s._wrap_client(client)
    monkeypatch.setattr(k8s,'_new_api',api)
    req=request(**{literals.OPTION:[t],logs.OPTION:[log_target]});req['checks']+=[literals.CHECK,logs.CHECK]
    snapshot=engine.collect_snapshot(req);findings=engine.evaluate_snapshot(snapshot,checks=req['checks'])['findings']
    assert {f['status']for f in findings}=={'FAIL'},[(f['check_id'],f['status'],f.get('evidence'))for f in findings]
    assert {f['check_id']for f in findings}==set(req['checks'])
    assert len(calls)==7 and calls.count(path+'/log')==1 and calls.count(path)==6
    serialized=json.dumps([snapshot,findings,list(secret_scanning._RESULTS.values())])
    assert all(value not in serialized for value in values)
    assert all(response.closed and response.released for response in responses)
    leaks=[leak for f in findings for leak in f.get('evidence',{}).get('secret_leaks',[])]
    # Public grouping can expose one redacted leak per finding instead.
    fingerprints={leak['fingerprint']for leak in leaks}|{f['evidence'].get('fingerprint')for f in findings if f.get('evidence',{}).get('fingerprint')}
    assert len(fingerprints)==3
