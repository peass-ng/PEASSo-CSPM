"""Production kind/collector/registry/public-engine proof; no integration hooks."""
from copy import deepcopy
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
from tests.aws_k8s_current_native_inputs_20261020 import replace_registry_checks
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


@pytest.mark.parametrize('function',[producer.pages,producer.parse_yaml,producer._DistinctLoader.construct_mapping,candidate.evaluate,candidate.evaluate_for])
def test_actual_executing_producer_and_consumer_code_tamper_rejected(function):
    old=function.__code__
    try:
        function.__code__=old.replace(co_consts=old.co_consts+('unreviewed',))
        with pytest.raises(RuntimeError,match='code changed'):admission.install()
    finally:function.__code__=old


def absent(monkeypatch):
    replace_registry_checks(monkeypatch, [c for c in registry.CHECKS if c.id not in candidate.IDS])
    monkeypatch.setattr(fixtures,'CASES',{k:deepcopy(v)for k,v in fixtures.CASES.items()if k not in candidate.IDS})


