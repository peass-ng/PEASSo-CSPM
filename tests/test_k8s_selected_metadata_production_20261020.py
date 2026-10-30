"""Sealed native roster through installed engine/collector, no registry/type bridge."""
from copy import deepcopy
import json
from pathlib import Path
from types import FunctionType,SimpleNamespace
from urllib.parse import urlsplit
import pytest
from kubernetes.client import ApiClient,Configuration
from peaso import engine,checks,secret_scanning
from peaso.collectors import k8s
from peaso.collectors import k8s_selected_metadata_runtime_20261020 as runtime
from peaso.checks import k8s_selected_metadata_secret_review_20261020 as consumer
from tests import test_k8s_selected_metadata_secret_review_20261020 as predecessor

source=predecessor.source
TOKEN=predecessor.TOKEN
HOST=predecessor.HOST
CLUSTER=predecessor.CLUSTER
NS=predecessor.NS
Response=predecessor.Response
offline=predecessor.offline


def native_document(kind,positive=False,field='annotations'):
    container={'name':'app','image':'registry.invalid/metadata-fixture:1'}
    template={'metadata':{'labels':{'app':'review'}},'spec':{'containers':[container]}}
    d={'apiVersion':source.NATIVE_KINDS[kind][0],'kind':kind,'metadata':{'name':'metadata-object','namespace':NS,
        'uid':'ab0f560d-2502-4b6f-964b-49c86704bfd0','resourceVersion':'21',
        'labels':{'app':'review'},'annotations':{'example.test/note':'reviewed metadata'}}}
    if kind=='Pod':d['spec']={'containers':[container]}
    elif kind=='ConfigMap':d['data']={'public':'ordinary unselected value'}
    elif kind=='PodTemplate':d['template']=deepcopy(template)
    elif kind=='Job':
        d['spec']={'template':deepcopy(template)};d['spec']['template']['spec']['restartPolicy']='Never'
    elif kind=='CronJob':
        d['spec']={'schedule':'0 * * * *','jobTemplate':{'spec':{'template':deepcopy(template)}}}
        d['spec']['jobTemplate']['spec']['template']['spec']['restartPolicy']='Never'
    elif kind=='ReplicationController':d['spec']={'selector':{'app':'review'},'template':deepcopy(template)}
    else:
        d['spec']={'selector':{'matchLabels':{'app':'review'}},'template':deepcopy(template)}
        if kind=='StatefulSet':d['spec']['serviceName']='metadata-service'
    if positive:d['metadata'][field]['example.test/content']=TOKEN
    return d


def unavailable_engine(monkeypatch,name):
    if name=='kingfisher':
        import kingfisher_sdk
        monkeypatch.setattr(kingfisher_sdk.Scanner,'scan_input',lambda *a,**kw:(_ for _ in()).throw(RuntimeError(TOKEN)))
    else:
        import shutil
        secret_scanning._trufflehog.cache_clear();old=shutil.which
        monkeypatch.setattr(shutil,'which',lambda name,*a,**kw:None if name=='trufflehog'else old(name,*a,**kw))


def capture(monkeypatch,*,kind='Pod',positive=False,field='annotations',mutate=None,status=200,real=False,
            options=None,api_setup=None,scanner=None,response_factory=None,targets=None,scopes=None,cluster=CLUSTER,extra=None,
            named=True,extra_checks=(),extra_documents=None):
    selected=targets or[{'cluster_id':CLUSTER,'namespace':NS,'kind':kind,'name':'metadata-object'}]
    documents={}
    for t in selected:
        d=native_document(t['kind'],positive,field);d['metadata'].update(namespace=t['namespace'],name=t['name'])
        documents[source._path(t)]=d
    trace=SimpleNamespace(calls=[],scans=[],responses=[],documents=documents,document=next(iter(documents.values())),progress=[],created=0)
    if scanner is not None:
        unavailable_engine(monkeypatch,'kingfisher');unavailable_engine(monkeypatch,'trufflehog')
    class Pool:
        def request(self,method,url,**kwargs):
            parsed=urlsplit(url)
            assert method=='GET'and parsed.scheme=='https'and parsed.netloc==urlsplit(HOST).netloc
            assert not parsed.query and not parsed.fragment
            assert kwargs['headers']['authorization']=='Bearer inert-auth-canary'
            assert kwargs['redirect']is False and kwargs['retries']is False
            assert kwargs['preload_content']is False and kwargs['decode_content']is False
            assert kwargs.get('body')is None and 0<kwargs['timeout']<=10
            trace.calls.append((method,url))
            if parsed.path in documents:
                data=deepcopy(documents[parsed.path])
                if mutate:data=mutate(data,len(trace.calls))
                response=response_factory(data,status)if response_factory else Response(data,status)
            elif extra_documents and parsed.path in extra_documents:
                data=extra_documents[parsed.path];response=data()if callable(data)else Response(deepcopy(data))
            else:raise AssertionError('unselected native path')
            trace.responses.append(response);return response
    def new_api(auth):
        trace.created+=1;cfg=Configuration();cfg.host=HOST
        cfg.api_key={'authorization':'inert-auth-canary'};cfg.api_key_prefix={'authorization':'Bearer'}
        client=ApiClient(cfg);client.rest_client.pool_manager=Pool();api=k8s._wrap_client(client)
        if api_setup:api_setup(api)
        trace.client=client;trace.api=api;return api
    monkeypatch.setattr(k8s,'_new_api',new_api)
    opts={'content_secret_scans':True,source.OPTION:selected,'retries':0,**(options or{})}
    # The sealed bridge's private-kind scenarios denote named vs unnamed input.
    if '_content_secret_scan_kinds'in opts:
        named=named and source.KIND in opts.pop('_content_secret_scan_kinds')
    req={'connector':{'provider':'k8s','scopes':scopes or[NS],
        'auth':{'method':'token','server':HOST,'token':'inert-auth-canary','cluster_id':cluster},'options':opts},
        'checks':([source.CHECK]if named else[])+list(extra_checks)}
    if not named:opts['inventories']=[source.KIND]
    snapshot=engine.collect_snapshot(req)
    own,=[row for row in snapshot['collections']if row['type']==source.KIND]
    index={'context':{'provider':'k8s','scope':own['scope'],'metadata':snapshot['metadata']},'collections':{source.KIND:[own]}}
    item=own['items'][0]if own['items']else{}
    result=consumer.evaluate(item,index)
    findings=engine.evaluate_snapshot(snapshot,checks=[source.CHECK])['findings']
    expected={result[0],'UNKNOWN'}if result[0]=='FAIL'and own['status']=='partial'else{result[0]}
    assert findings and {f['status']for f in findings}==expected
    assert TOKEN not in json.dumps([snapshot,findings,list(secret_scanning._RESULTS.values())])
    assert all(r.closed and r.released for r in trace.responses)
    if hasattr(trace,'client'):assert getattr(trace.client,'last_response',None)is None
    trace.snapshot=snapshot;trace.findings=findings
    # Retain no source text in production. Test trace records safe part counts;
    # the real engines, rather than a detector replacement, decide each result.
    return result,trace,item,index


# Preserve native assertions/parameter roster, changing only its collect bridge.
# The four predecessor engine-unavailable cases are restated below using actual
# SDK/binary unavailability, since production admission rejects detector swaps.
_EXCLUDED={'test_native_sdk_to_public_proposed_check','test_one_engine_unavailable_cannot_clean_but_trusted_hit_survives',
           'test_optional_and_cluster_boundary_before_native_calls'}
_globals={**vars(predecessor),'capture':capture,'__name__':__name__}
for _name,_fn in vars(predecessor).items():
    if _name.startswith('test_')and _name not in _EXCLUDED:
        _copy=FunctionType(_fn.__code__,_globals,_name,_fn.__defaults__,_fn.__closure__)
        _copy.__dict__.update(_fn.__dict__);_copy.__module__=__name__;globals()[_name]=_copy



# Production validates every selected-content option before any reader runs;
# the registry-image reader's own fail-closed Incomplete may reject the
# non-boolean flag first. Either reader's rejection is the same boundary.
@pytest.mark.parametrize('fault',['false_flag','integer_flag','no_named_kind','foreign_cluster'])
def test_optional_and_cluster_boundary_before_native_calls(monkeypatch,fault):
    from peaso.collectors import k8s_selected_registry_image_20261021 as registry_image
    options={'content_secret_scans':False}if fault=='false_flag'else{'content_secret_scans':1}if fault=='integer_flag'else{'_content_secret_scan_kinds':[]}if fault=='no_named_kind'else{}
    if fault=='integer_flag':
        with pytest.raises((source.Incomplete,registry_image.Incomplete),match='invalid_selection'):capture(monkeypatch,options=options)
        return
    (status,_),trace,_,_=capture(monkeypatch,options=options,cluster='foreign'if fault=='foreign_cluster'else CLUSTER)
    assert status=='UNKNOWN'and not trace.calls and not trace.scans


@pytest.mark.parametrize('engine',['kingfisher','trufflehog'])
@pytest.mark.parametrize('positive',[False,True])
def test_actual_unavailable_engine_cannot_clean_and_trusted_peer_hit_survives(monkeypatch,engine,positive):
    unavailable_engine(monkeypatch,engine)
    (status,evidence),trace,_,_=capture(monkeypatch,positive=positive)
    assert status==('FAIL'if positive else'UNKNOWN')and len(trace.calls)==2
    if positive:assert evidence['complete']is False and len(evidence['secret_leaks'])==1


@pytest.mark.parametrize('branch',['pass','fail','unknown'])
def test_actual_installed_public_native_branch(monkeypatch,branch):
    (status,_),trace,_,_=capture(monkeypatch,positive=branch=='fail',status=403 if branch=='unknown'else 200)
    assert status==branch.upper()and len(trace.calls)==(1 if branch=='unknown'else 2)
    assert [c.id for c in checks.CHECKS].count(source.CHECK)==1
