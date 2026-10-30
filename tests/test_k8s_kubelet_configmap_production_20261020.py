"""Production kind/collector/registry/public-engine proof; no integration hooks."""
from copy import deepcopy
from dataclasses import replace
import importlib.util
import json
from pathlib import Path
import socket
import sys

import pytest
from kubernetes import client,config

from peaso import engine
import peaso.checks as registry
from peaso.checks import fixtures
from tests.aws_k8s_current_native_inputs_20261020 import case_state, replace_registry_checks
from peaso.checks import k8s_kubelet_configmap_source_successor_20261021 as successor
from peaso.checks import k8s_kubelet_configmap_review_20261020 as candidate
from peaso.collectors import k8s
from peaso.collectors import k8s_kubelet_configmap_indicators_20261020 as producer

admission = sys.modules[successor.PRIVATE_NAME]

_path=Path(__file__).with_name('test_k8s_kubelet_configmap_native_review_20261020.py')
_spec=importlib.util.spec_from_file_location('verified_kubelet_configmap_wire',_path)
wire=importlib.util.module_from_spec(_spec);_spec.loader.exec_module(wire)
CAPTURES=[]


@pytest.fixture(autouse=True)
def offline(monkeypatch):
    def blocked(*a,**k):pytest.fail('network/DNS/live authentication forbidden')
    for n in ('connect','connect_ex'):monkeypatch.setattr(socket.socket,n,blocked)
    for n in ('getaddrinfo','gethostbyname','gethostbyname_ex','create_connection'):monkeypatch.setattr(socket,n,blocked)
    for n in ('load_kube_config','load_incluster_config','new_client_from_config'):monkeypatch.setattr(config,n,blocked)


@pytest.fixture(scope='session',autouse=True)
def capture_receipts():
    yield
    import os
    if os.getenv('KUBELET_CM_PRODUCTION_RECEIPTS'):
        directory=Path(os.environ['KUBELET_CM_PRODUCTION_RECEIPTS']);directory.mkdir(parents=True,exist_ok=True)
        (directory/'production-captures.json').write_text(json.dumps(CAPTURES,separators=(',',':'))+'\n')


def run_native(cid,variant='positive',*,mode='normal',scope='kube-system',options=None,mutate=None):
    field=candidate.SPECS[cid[len(candidate.PREFIX_ID):]][0];cfg=deepcopy(wire.BASE)
    parent=cfg;keys=wire.PATHS[field]
    for key in keys[:-1]:parent=parent[key]
    if variant=='opposite':parent[keys[-1]]=wire.BAD[field]
    if variant=='missing':parent.pop(keys[-1])
    document=wire.native(cfg)
    if mutate:mutate(document)
    configuration=client.Configuration();configuration.host='https://kubelet-declaration.invalid'
    configuration.api_key={'authorization':wire.AUTH};configuration.api_key_prefix={'authorization':'Bearer'}
    sdk=client.ApiClient(configuration);pool=wire.Pool(document,mode);sdk.rest_client.pool_manager=pool
    api=k8s._wrap_client(sdk)
    connector={'provider':'k8s','auth':{'cluster_id':'native-cluster'},'scopes':[scope],
        'options':{'concurrency':1,'retries':0,**(options or{})}}
    required=engine.plan_collection({'connector':connector,'checks':[cid]},_runtime_connector=connector)
    assert required==[producer.KIND] and producer.KIND not in k8s.ENDPOINTS
    snapshot=k8s.collect(connector,required,api=api)
    report=engine.evaluate_snapshot(snapshot,checks=[cid])
    statuses=sorted({f['status']for f in report['findings']})
    assert wire.CANARY not in json.dumps(snapshot) and wire.CANARY not in json.dumps(report)
    assert wire.AUTH not in json.dumps(snapshot) and wire.AUTH not in json.dumps(report)
    assert getattr(sdk,'last_response',None) is None
    assert not any(r['path'].endswith('/application-settings')for r in pool.calls)
    CAPTURES.append({'id':cid,'variant':variant,'mode':mode,'statuses':statuses,'http':pool.calls,'snapshot':snapshot,'report':report})
    return statuses,snapshot,pool


@pytest.mark.parametrize('cid',candidate.IDS)
@pytest.mark.parametrize('variant,status',[('positive','PASS'),('opposite','FAIL'),('missing','UNKNOWN')])
def test_production_native_all_eight_statuses(cid,variant,status):
    assert run_native(cid,variant)[0]==[status]


@pytest.mark.parametrize('cid',candidate.IDS)
@pytest.mark.parametrize('mode,status',[('denied','DENIED'),('partial','UNKNOWN')])
def test_production_denied_partial_never_clean(cid,mode,status):
    assert run_native(cid,mode=mode)[0]==[status]


@pytest.mark.parametrize('mode',['empty','unrelated_only','wrong_list_type','duplicate','partial_representation'])
def test_production_empty_wrong_representation_and_duplicate_unknown(mode):
    assert run_native(candidate.IDS[0],mode=mode)[0]==['UNKNOWN']


@pytest.mark.parametrize('key,value',[('namespace','foreign'),('name','kubelet-config-other'),('uid','foreign-uid'),('resourceVersion','413')])
def test_production_native_metadata_detail_identity_join(key,value):
    assert run_native(candidate.IDS[0],mutate=lambda d:d['metadata'].update({key:value}))[0]==['UNKNOWN']


@pytest.mark.parametrize('scope',['kube-system','*'])
def test_production_existing_selected_scope_and_metadata_only_routing(scope):
    statuses,_,pool=run_native(candidate.IDS[0],scope=scope)
    assert statuses==['PASS'] and len(pool.calls)==2
    assert pool.calls[0]['accept']=='application/json;as=PartialObjectMetadataList;g=meta.k8s.io;v=v1'
    assert pool.calls[1]['accept']=='application/json' and '/kubelet-config-'in pool.calls[1]['path']


def test_production_reader_call_budget_stops_detail():
    statuses,_,pool=run_native(candidate.IDS[0],options={'max_calls':1})
    assert statuses==['UNKNOWN'] and len(pool.calls)==1


def test_registered_eight_metadata_cases_idempotence_and_no_old_case_mutation():
    before=tuple(registry.CHECKS);old_cases=case_state({k:v for k,v in fixtures.CASES.items()if k not in candidate.IDS})
    admission.install();admission.install()
    assert all(a is b for a,b in zip(before,registry.CHECKS))
    assert case_state({k:v for k,v in fixtures.CASES.items()if k not in candidate.IDS})==old_cases
    receipt,cases,_=admission.reviewed_inputs()
    for cid in candidate.IDS:
        check,=[c for c in registry.CHECKS if c.id==cid]
        assert getattr(check.evaluate,admission.MARK)==cid
        assert admission._metadata(check)==receipt['metadata'][cid]
        assert fixtures.CASES[cid]==cases[cid]


@pytest.mark.parametrize('module',[producer,candidate,admission])
def test_dedicated_source_drift_rejected(monkeypatch,module):
    path=Path(module.__file__);actual=Path.read_bytes
    monkeypatch.setattr(Path,'read_bytes',lambda p:actual(p)+b'\n# unreviewed'if p.resolve()==path.resolve()else actual(p))
    with pytest.raises(RuntimeError,match='source changed'):admission.install()


@pytest.mark.parametrize('function',[producer.pages,producer.parse_yaml,producer._DistinctLoader.construct_mapping,candidate.evaluate,candidate.evaluate_for])
def test_actual_executing_producer_and_consumer_code_tamper_rejected(function):
    old=function.__code__
    try:
        function.__code__=old.replace(co_consts=old.co_consts+('unreviewed',))
        with pytest.raises(RuntimeError,match='code changed'):admission.install()
    finally:function.__code__=old


@pytest.mark.parametrize('layer',['safe','checked','leaf'])
def test_actual_registered_wrapper_and_factory_code_tamper(layer):
    check=next(c for c in registry.CHECKS if c.id==candidate.IDS[0]);safe=check.evaluate
    checked=admission.proof._bindings(safe)['checked'];leaf=admission.proof._bindings(checked)['function']
    function={'safe':safe,'checked':checked,'leaf':leaf}[layer];old=function.__code__
    try:
        function.__code__=old.replace(co_consts=old.co_consts+('unreviewed',))
        with pytest.raises(RuntimeError):admission.install()
    finally:function.__code__=old


def test_native_fixture_drift_rejected(monkeypatch):
    receipt,_,_=admission.reviewed_inputs();path=Path(receipt['fixture']['path']);actual=Path.read_bytes
    monkeypatch.setattr(Path,'read_bytes',lambda p:b'{}'if p.resolve()==path.resolve()else actual(p))
    with pytest.raises(RuntimeError,match='native fixtures changed'):admission.install()


def test_missing_receipt_fields_rejected(monkeypatch):
    actual=Path.read_text
    monkeypatch.setattr(Path,'read_text',lambda p,*a,**k:'{}'if p.name==admission.RECEIPT else actual(p,*a,**k))
    with pytest.raises(RuntimeError,match='Unrecognized'):admission.install()


def absent(monkeypatch):
    replace_registry_checks(monkeypatch, [c for c in registry.CHECKS if c.id not in candidate.IDS])
    monkeypatch.setattr(fixtures,'CASES',{k:deepcopy(v)for k,v in fixtures.CASES.items()if k not in candidate.IDS})


def test_transaction_rolls_back_register_failure_after_three_additions(monkeypatch):
    absent(monkeypatch);before=tuple(registry.CHECKS);cases=case_state(fixtures.CASES);register=registry.register
    def failing(*a,**k):
        install=register(*a,**k)
        def decorate(function):
            result=install(function)
            if a[0]==candidate.IDS[2]:raise RuntimeError('injected registration failure')
            return result
        return decorate
    monkeypatch.setattr(registry,'register',failing)
    with pytest.raises(RuntimeError,match='injected registration failure'):admission.install()
    assert tuple(registry.CHECKS)==before and case_state(fixtures.CASES)==cases


def test_transaction_rolls_back_cases_write_failure(monkeypatch):
    absent(monkeypatch);before=tuple(registry.CHECKS);cases=case_state(fixtures.CASES)
    class Broken(dict):
        def __setitem__(self,key,value):
            if key==candidate.IDS[2]:raise RuntimeError('injected fixture write failure')
            return super().__setitem__(key,value)
    monkeypatch.setattr(fixtures,'CASES',Broken(fixtures.CASES))
    with pytest.raises(RuntimeError,match='injected fixture write failure'):admission.install()
    assert tuple(registry.CHECKS)==before and case_state(fixtures.CASES)==cases


def test_partial_registration_collision_preserves_state(monkeypatch):
    first=next(c for c in registry.CHECKS if c.id==candidate.IDS[0])
    absent(monkeypatch);registry.CHECKS.append(first);before=tuple(registry.CHECKS)
    with pytest.raises(RuntimeError,match='registration collision'):admission.install()
    assert tuple(registry.CHECKS)==before


def test_factory_check_id_tamper_rejected(monkeypatch):
    first=next(c for c in registry.CHECKS if c.id==candidate.IDS[0]);safe=first.evaluate
    checked=admission.proof._bindings(safe)['checked'];leaf=admission.proof._bindings(checked)['function']
    cell=leaf.__closure__[0];old=cell.cell_contents
    try:
        cell.cell_contents=candidate.IDS[1]
        with pytest.raises(RuntimeError,match='factory closure'):admission.install()
    finally:cell.cell_contents=old


def test_empty_inventory_callback_cannot_be_replaced_with_clean_pass(monkeypatch):
    safe=next(c for c in registry.CHECKS if c.id==candidate.IDS[0]).evaluate
    monkeypatch.setattr(safe,'evaluate_empty_inventory',lambda *args:('PASS',{}))
    with pytest.raises(RuntimeError,match='empty callback changed'):admission.install()
