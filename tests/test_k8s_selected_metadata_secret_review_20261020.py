"""Actual SDK auth/bounded native responses; optional proposal, no shared hooks."""
from copy import deepcopy
import json
import os
from pathlib import Path
import socket
from types import SimpleNamespace
from urllib.parse import urlsplit
import pytest
from kubernetes.client import ApiClient,Configuration
from peaso import secret_scanning
from peaso import engine,checks
from peaso.snapshot import make_snapshot
from peaso.collectors import k8s
from peaso.collectors import k8s_selected_metadata_secret_indicators_20261020 as source
from peaso.checks import k8s_selected_metadata_secret_review_20261020 as consumer
from tests.test_k8s_literal_secret_review_20261020 import Response,TOKEN

HOST='https://metadata-k8s.invalid:6443'
CLUSTER='metadata-review'
NS='team-a'


@pytest.fixture(autouse=True)
def offline(monkeypatch):
    def block(*a,**kw):raise AssertionError('network and external authentication forbidden')
    for owner,names in((socket,('create_connection','getaddrinfo','gethostbyname','gethostbyname_ex')),(socket.socket,('connect','connect_ex','sendto'))):
        for name in names:monkeypatch.setattr(owner,name,block)
    from kubernetes import config
    monkeypatch.setattr(config,'load_kube_config',block)
    monkeypatch.setattr(config,'load_incluster_config',block)
    secret_scanning._RESULTS.clear()
    yield
    secret_scanning._RESULTS.clear()


def capture(monkeypatch,*,kind='Pod',positive=False,field='annotations',mutate=None,status=200,real=False,options=None,api_setup=None,scanner=None,response_factory=None,targets=None,scopes=None,cluster=CLUSTER,extra=None):
    target={'cluster_id':CLUSTER,'namespace':NS,'kind':kind,'name':'metadata-object'}
    document={'apiVersion':source.NATIVE_KINDS[kind][0],'kind':kind,'metadata':{'name':target['name'],
        'namespace':NS,'uid':'ab0f560d-2502-4b6f-964b-49c86704bfd0','resourceVersion':'21',
        'labels':{'app':'review'},'annotations':{'example.test/note':'reviewed metadata'}}}
    container={'name':'app','image':'registry.invalid/metadata-fixture:1'}
    template={'metadata':{'labels':{'app':'review'}},'spec':{'containers':[container]}}
    if kind=='Pod':document['spec']={'containers':[container]}
    elif kind=='ConfigMap':document['data']={'public':'ordinary unselected value'}
    elif kind=='PodTemplate':document['template']=deepcopy(template)
    elif kind=='Job':
        document['spec']={'template':deepcopy(template)}
        document['spec']['template']['spec']['restartPolicy']='Never'
    elif kind=='CronJob':
        document['spec']={'schedule':'0 * * * *','jobTemplate':{'spec':{'template':deepcopy(template)}}}
        document['spec']['jobTemplate']['spec']['template']['spec']['restartPolicy']='Never'
    elif kind=='ReplicationController':document['spec']={'selector':{'app':'review'},'template':deepcopy(template)}
    else:
        document['spec']={'selector':{'matchLabels':{'app':'review'}},'template':deepcopy(template)}
        if kind=='StatefulSet':document['spec']['serviceName']='metadata-service'
    if positive:document['metadata'][field]['example.test/content']=TOKEN
    selected=targets or [target]
    documents={}
    for chosen in selected:
        d=deepcopy(document);d.update(apiVersion=source.NATIVE_KINDS[chosen['kind']][0],kind=chosen['kind'])
        d['metadata'].update(namespace=chosen['namespace'],name=chosen['name'])
        documents[source._path(chosen)]=d
    trace=SimpleNamespace(calls=[],scans=[],responses=[],document=document,documents=documents)
    if not real:
        def detect(payload,path,timeout):
            trace.scans.append(bytes(payload))
            return scanner(payload,path,timeout)if scanner else[(TOKEN,'github-pat',1)]if TOKEN.encode()in payload else[]
        monkeypatch.setattr(secret_scanning,'_scan_kingfisher',detect)
        monkeypatch.setattr(secret_scanning,'_scan_trufflehog',detect)
    class Pool:
        def request(self,method,url,**kwargs):
            assert method=='GET'and urlsplit(url).scheme=='https'and urlsplit(url).netloc==urlsplit(HOST).netloc
            assert urlsplit(url).query==''and urlsplit(url).path in documents
            assert kwargs['headers']['authorization']=='Bearer inert-auth-canary'
            assert kwargs['redirect']is False and kwargs['retries']is False
            assert kwargs['preload_content']is False and kwargs['decode_content']is False
            assert not kwargs.get('body')
            trace.calls.append((method,url));data=deepcopy(documents[urlsplit(url).path])
            if mutate:data=mutate(data,len(trace.calls))
            response=response_factory(data,status)if response_factory else Response(data,status);trace.responses.append(response);return response
    configuration=Configuration();configuration.host=HOST
    configuration.api_key={'authorization':'inert-auth-canary'};configuration.api_key_prefix={'authorization':'Bearer'}
    client=ApiClient(configuration);client.rest_client.pool_manager=Pool();api=k8s._wrap_client(client)
    if api_setup:api_setup(api)
    opts={'content_secret_scans':True,'_content_secret_scan_kinds':[source.KIND],source.OPTION:selected,'retries':0,**(options or{})}
    reader=k8s.K8sReader(opts)
    try:
        metadata,matches=source.collect(reader,api,opts,scopes or [NS],cluster)
        scopes,collections,metadata=source.redact_output(scopes or [NS],reader.collections,metadata,matches)
        assert not matches and all(r.closed and r.released for r in trace.responses)
        if extra:
            metadata,matches=extra(metadata,matches,reader)
            _,collections,metadata=source.redact_output(scopes or [NS],collections,metadata,matches)
        own,=collections;index={'context':{'provider':'k8s','scope':NS,'metadata':metadata},'collections':{source.KIND:[own]}}
        item=own['items'][0]if own['items']else{}
        result=consumer.evaluate(item,index)
        assert TOKEN not in json.dumps({'metadata':metadata,'collections':collections,'result':result})
        return result,trace,item,index
    finally:client.close()


@pytest.mark.parametrize('kind',list(source.NATIVE_KINDS))
@pytest.mark.parametrize('positive',[False,True])
def test_ten_exact_native_kinds_detect_only_selected_metadata(monkeypatch,kind,positive):
    (status,evidence),trace,_,_=capture(monkeypatch,kind=kind,positive=positive)
    assert status==('FAIL'if positive else'PASS')and len(trace.calls)==2
    assert evidence['coverage']=='selected_object_metadata_only'
    if positive:
        assert len(evidence['secret_leaks'])==1
        assert {d['engine']for d in evidence['secret_leaks'][0]['detectors']}=={'kingfisher','trufflehog'}


@pytest.mark.parametrize('field',['labels','annotations'])
@pytest.mark.parametrize('positive',[False,True])
def test_pinned_real_offline_detectors(monkeypatch,field,positive):
    (status,evidence),trace,_,_=capture(monkeypatch,field=field,positive=positive,real=True)
    assert status==('FAIL'if positive else'PASS')and len(trace.calls)==2
    assert {e['status']for e in evidence['parts'][0]['engines']}=={'complete'}


@pytest.mark.parametrize('status',[401,403,206,302,500])
def test_noncomplete_native_response_cannot_claim_clean(monkeypatch,status):
    (result,_),trace,_,_=capture(monkeypatch,status=status)
    assert result=='UNKNOWN'and len(trace.calls)==1 and not trace.scans


@pytest.mark.parametrize('field',['uid','resourceVersion','annotations'])
def test_changed_second_read_never_scans(monkeypatch,field):
    def mutate(d,ordinal):
        if ordinal==2:d['metadata'][field]={'example.test/changed':'yes'}if field=='annotations'else'changed'
        return d
    (status,_),trace,_,_=capture(monkeypatch,mutate=mutate)
    assert status=='UNKNOWN'and len(trace.calls)==2 and not trace.scans


@pytest.mark.parametrize('fault',['number','map','key','label','large','none','deleted','identity'])
def test_malformed_or_unavailable_metadata_never_claims_clean(monkeypatch,fault):
    def mutate(d,_):
        if fault=='number':d['metadata']['annotations']['count']=True
        elif fault=='map':d['metadata']['annotations']=[]
        elif fault=='key':d['metadata']['annotations']={'bad/key/extra':'text'}
        elif fault=='label':d['metadata']['labels']['app']='contains whitespace'
        elif fault=='large':d['metadata']['annotations']['large']='a'*(source.MAX_VALUE+1)
        elif fault=='none':d['metadata'].pop('labels');d['metadata'].pop('annotations')
        elif fault=='deleted':d['metadata']['deletionTimestamp']='2026-10-20T09:00:00Z'
        else:d['metadata']['name']='foreign'
        return d
    (status,_),trace,_,_=capture(monkeypatch,mutate=mutate)
    assert status=='UNKNOWN'and not trace.scans


def test_configuration_and_references_are_outside_metadata_criterion(monkeypatch):
    def mutate(d,_):
        d['spec']={'containers':[{'name':'app','env':[{'name':'CREDENTIAL','value':TOKEN}],
            'envFrom':[{'secretRef':{'name':'never-follow'}}]}]}
        d['data']={'not-selected':TOKEN};return d
    (status,_),trace,_,_=capture(monkeypatch,mutate=mutate)
    assert status=='PASS'and len(trace.calls)==2 and all(TOKEN.encode()not in p for p in trace.scans)


def test_ordinary_kind_cannot_authorize_new_metadata_namespace(monkeypatch):
    (status,_),trace,_,_=capture(monkeypatch,options={'_content_secret_scan_kinds':['k8s_selected_literals']})
    assert status=='UNKNOWN'and not trace.calls and not trace.scans


def test_global_reader_budget_is_observed(monkeypatch):
    (status,_),trace,_,_=capture(monkeypatch,options={'max_calls':1})
    assert status=='UNKNOWN'and len(trace.calls)==1 and not trace.scans


@pytest.mark.parametrize('fault',['authorization','schema','source','provider','completion'])
def test_missing_capture_facts_cannot_supply_decisive_metadata_result(monkeypatch,fault):
    _,_,item,index=capture(monkeypatch)
    if fault=='authorization':index['context']['metadata'][source.KIND+'_authorized']=False
    elif fault=='schema':item[source.MARKER]['schema']='k8s-selected-literal-secrets-v1'
    elif fault=='source':item[source.MARKER]['source_requests']=[]
    elif fault=='provider':index['context']['provider']='azure'
    else:item[source.MARKER]['parts'][0]['complete']=False
    assert consumer.evaluate(item,index)[0]=='UNKNOWN'


@pytest.mark.parametrize('branch',['pass','fail','unknown'])
def test_native_sdk_to_public_proposed_check(monkeypatch,branch):
    result,_,item,index=capture(monkeypatch,real=True,positive=branch=='fail',status=403 if branch=='unknown' else 200)
    d=consumer.DECLARATION
    # The proposal stays immutable; execute its now-admitted production check.
    registered,=[c for c in checks.CHECKS if c.id==d['id']]
    import inspect
    assert inspect.unwrap(registered.evaluate) is consumer.evaluate
    assert registered.kind==source.KIND and registered.dependencies==d['dependencies']
    assert registered.allow_incomplete_failure
    snapshot=make_snapshot('k8s',[NS],index['collections'][source.KIND],metadata=index['context']['metadata'])
    report=engine.evaluate_snapshot(snapshot,checks=[d['id']])
    findings=[f for f in report['findings']if f['check_id']==d['id']]
    assert findings and {f['status']for f in findings}=={result[0]}=={branch.upper()}
    assert TOKEN not in json.dumps(report)
    if directory:=os.environ.get('K8S_METADATA_NATIVE_RECEIPTS'):
        path=Path(directory);path.mkdir(parents=True,exist_ok=True)
        (path/(branch+'.json')).write_text(json.dumps({'snapshot':snapshot,'item':item,'index':index,'findings':findings},indent=2)+'\n')




@pytest.mark.parametrize('debug',['http_class','https_class','urllib3_class','pool'])
def test_wire_debug_fails_before_sensitive_native_read(monkeypatch,debug):
    import http.client
    from urllib3.connection import HTTPConnection
    def setup(api):
        # Configuration.debug=False resets stdlib debuglevel; set the actual
        # configured wire state only after SDK construction, before any read.
        if debug=='http_class':monkeypatch.setattr(http.client.HTTPConnection,'debuglevel',1)
        elif debug=='https_class':monkeypatch.setattr(http.client.HTTPSConnection,'debuglevel',1)
        elif debug=='urllib3_class':monkeypatch.setattr(HTTPConnection,'debuglevel',1)
        elif debug=='pool':
            getattr(getattr(api,'api',api),'api_client').rest_client.pool_manager.pool.connection_pool_kw={'debuglevel':1}
    (status,_),trace,_,_=capture(monkeypatch,positive=True,api_setup=setup)
    assert status=='UNKNOWN' and not trace.calls and not trace.scans


@pytest.mark.parametrize('fault',['apiVersion','kind','namespace','missing_uid','missing_rv','partial','duplicate_map','long_prefix','too_many'])
def test_native_gvk_identity_and_complete_map_required(monkeypatch,fault):
    def mutate(d,_):
        if fault=='apiVersion':d['apiVersion']='apps/v1'
        elif fault=='kind':d['kind']='Secret'
        elif fault=='namespace':d['metadata']['namespace']='foreign'
        elif fault=='missing_uid':d['metadata'].pop('uid')
        elif fault=='missing_rv':d['metadata'].pop('resourceVersion')
        elif fault=='partial':d['_partial']=True
        elif fault=='duplicate_map':d['metadata']['annotations']={'key':['nested']}
        elif fault=='long_prefix':d['metadata']['annotations']={'a'*254+'/key':'literal'}
        else:d['metadata']['annotations']={'key'+str(n):'literal'for n in range(source.MAX_LITERALS+1)}
        return d
    (status,_),trace,_,_=capture(monkeypatch,mutate=mutate)
    assert status=='UNKNOWN'and not trace.scans


@pytest.mark.parametrize('fault',['false_flag','integer_flag','no_named_kind','foreign_cluster'])
def test_optional_and_cluster_boundary_before_native_calls(monkeypatch,fault):
    options={'content_secret_scans':False}if fault=='false_flag'else{'content_secret_scans':1}if fault=='integer_flag'else{'_content_secret_scan_kinds':[]}if fault=='no_named_kind'else{}
    if fault=='integer_flag':
        with pytest.raises(source.Incomplete):capture(monkeypatch,options=options)
        return
    (status,_),trace,_,_=capture(monkeypatch,options=options,cluster='foreign'if fault=='foreign_cluster'else CLUSTER)
    assert status=='UNKNOWN'and not trace.calls and not trace.scans


@pytest.mark.parametrize('fault',['name_path','namespace_path','kind_secret','extra_field','duplicate','nine','cross_scope','mixed_cluster'])
def test_exact_selector_validation_never_widens_authorization(fault):
    t={'cluster_id':CLUSTER,'namespace':NS,'kind':'Pod','name':'selected'};targets=[t];scopes=[NS]
    if fault=='name_path':t['name']='selected/log'
    if fault=='namespace_path':t['namespace']='*'
    if fault=='kind_secret':t['kind']='Secret'
    if fault=='extra_field':t['path']='/anything'
    if fault=='duplicate':targets=[t,deepcopy(t)]
    if fault=='nine':targets=[{**t,'name':'selected-'+str(i)}for i in range(9)]
    if fault=='cross_scope':scopes=['foreign']
    if fault=='mixed_cluster':targets=[t,{**t,'cluster_id':'other','name':'other'}]
    with pytest.raises(source.Incomplete):source.selected_targets({'content_secret_scans':True,'_content_secret_scan_kinds':[source.KIND],source.OPTION:targets},scopes)


@pytest.mark.parametrize('engine',['kingfisher','trufflehog'])
@pytest.mark.parametrize('positive',[False,True])
def test_one_engine_unavailable_cannot_clean_but_trusted_hit_survives(monkeypatch,engine,positive):
    def setup(api):
        def unavailable(*a):raise RuntimeError(TOKEN)
        monkeypatch.setattr(secret_scanning,'_scan_'+engine,unavailable)
    (status,evidence),trace,_,_=capture(monkeypatch,positive=positive,api_setup=setup)
    assert status==('FAIL'if positive else'UNKNOWN')and len(trace.calls)==2
    if positive:assert evidence['complete']is False and len(evidence['secret_leaks'])==1
    assert TOKEN not in json.dumps(secret_scanning._RESULTS,default=str)


def test_eight_selected_resources_same_value_hmac_dedup_without_raw_cache(monkeypatch):
    targets=[{'cluster_id':CLUSTER,'namespace':NS,'kind':'Pod','name':'selected-'+str(i)}for i in range(8)]
    (status,_),trace,_,index=capture(monkeypatch,positive=True,targets=targets)
    assert status=='FAIL'and len(trace.calls)==16
    outcomes=[consumer.evaluate(item,index)for item in index['collections'][source.KIND][0]['items']]
    leaks=secret_scanning.merge_leaks([leak for _,evidence in outcomes for leak in evidence['secret_leaks']])
    assert len(leaks)==1 and len(leaks[0]['locations'])==8
    assert TOKEN not in json.dumps(index)+str(secret_scanning._RESULTS)


@pytest.mark.parametrize('identity',['uid','resourceVersion','annotation_key','label_key'])
def test_secret_in_identity_or_metadata_key_is_never_exported(monkeypatch,identity):
    def mutate(d,_):
        if identity in('uid','resourceVersion'):d['metadata'][identity]=TOKEN
        elif identity=='annotation_key':d['metadata']['annotations'][TOKEN]='literal'
        else:d['metadata']['labels'][TOKEN]='literal'
        return d
    (status,evidence),trace,item,index=capture(monkeypatch,mutate=mutate)
    assert status=='FAIL'and len(evidence['secret_leaks'])==1
    assert TOKEN not in json.dumps([item,index,evidence])+str(secret_scanning._RESULTS)


@pytest.mark.parametrize('fault',['duplicate','compressed','truncated','oversized','text','wrong_origin'])
def test_native_wire_representation_and_origin_fail_closed(monkeypatch,fault):
    def response(data,status):
        raw=json.dumps(data).encode();headers={}
        if fault=='duplicate':raw=raw.replace(b'"kind": "Pod"',b'"kind": "Secret", "kind": "Pod"')
        elif fault=='compressed':headers['Content-Encoding']='gzip'
        elif fault=='truncated':headers['Content-Length']=str(len(raw)+1)
        elif fault=='oversized':headers['Content-Length']=str(source.predecessor.MAX_WIRE+1)
        elif fault=='text':headers['Content-Type']='text/plain'
        return Response(raw,status,headers)
    def setup(api):
        if fault=='wrong_origin':getattr(getattr(api,'api',api),'api_client').configuration.host='https://foreign.invalid'
    (status,_),trace,_,_=capture(monkeypatch,response_factory=response,api_setup=setup)
    assert status=='UNKNOWN'and not trace.scans
    if fault=='wrong_origin':assert not trace.calls


def test_response_and_scanner_exceptions_do_not_retain_secret_text(monkeypatch):
    def unavailable(*args):raise ValueError(TOKEN)
    (status,evidence),trace,item,index=capture(monkeypatch,scanner=unavailable)
    assert status=='UNKNOWN'and TOKEN not in json.dumps([evidence,item,index])+str(secret_scanning._RESULTS)


def test_selected_path_authorization_restored_after_collection(monkeypatch):
    seen=[]
    def setup(api):
        pool=getattr(getattr(api,'api',api),'api_client').rest_client.pool_manager
        pool.literal_paths=frozenset({'/previous/reviewed/path'});seen.append(pool)
    capture(monkeypatch,api_setup=setup)
    assert seen[0].literal_paths==frozenset({'/previous/reviewed/path'})


@pytest.mark.parametrize('positive',[False,True])
def test_resource_cap_preserves_independently_bound_hit_but_never_clean(monkeypatch,positive):
    targets=[{'cluster_id':CLUSTER,'namespace':NS,'kind':'Pod','name':'selected-'+str(i)}for i in range(2)]
    (status,evidence),trace,_,_=capture(monkeypatch,positive=positive,targets=targets,options={'max_resources':1})
    assert status==('FAIL'if positive else'UNKNOWN') and len(trace.calls)==2
    if positive:assert evidence['complete']is False


@pytest.mark.parametrize('fault',['forged_reason','missing_reason','foreign_identity','unselected_identity','duplicate_identity','duplicate_selection','missing_receipts','missing_authorization','foreign_scope','wrong_cluster'])
def test_partial_hit_fallback_rejects_unbound_or_ambiguous_evidence(monkeypatch,fault):
    targets=[{'cluster_id':CLUSTER,'namespace':NS,'kind':'Pod','name':'selected-'+str(i)}for i in range(2)]
    _,_,item,index=capture(monkeypatch,positive=True,targets=targets,options={'max_resources':1})
    item=deepcopy(item);index=deepcopy(index);own=index['collections'][source.KIND][0];own['items'][0]=item
    if fault=='forged_reason':own['error']['code']='forged_partial'
    elif fault=='missing_reason':own.pop('error')
    elif fault=='foreign_identity':item['id']='foreign:identity'
    elif fault=='unselected_identity':item['id']=source.KIND+':'+'0'*64
    elif fault=='duplicate_identity':own['items'].append(deepcopy(item))
    elif fault=='duplicate_selection':index['context']['metadata'][source.KIND+'_selection'][NS]=[item['id'],item['id']]
    elif fault=='missing_receipts':index['context']['metadata'][source.KIND+'_receipts']=[]
    elif fault=='missing_authorization':index['context']['metadata'].pop(source.KIND+'_authorized')
    elif fault=='foreign_scope':index['context']['scope']='foreign'
    else:index['context']['metadata'][source.KIND+'_cluster_binding']='foreign'
    retained=deepcopy(index)
    assert consumer.evaluate(item,index)[0]=='UNKNOWN'
    assert index==retained


def test_partial_hit_fallback_keeps_original_selection_and_native_proofs(monkeypatch):
    targets=[{'cluster_id':CLUSTER,'namespace':NS,'kind':'Pod','name':'selected-'+str(i)}for i in range(2)]
    _,_,item,index=capture(monkeypatch,positive=True,targets=targets,options={'max_resources':1})
    retained=deepcopy(index)
    assert consumer.evaluate(item,index)[0]=='FAIL'
    assert index==retained and len(index['context']['metadata'][source.KIND+'_selection'][NS])==2
    assert len(index['collections'][source.KIND][0]['items'])==1


def test_metadata_and_installed_literal_adapter_share_exact_value_hmac(monkeypatch):
    from tests import test_k8s_literal_secret_review_20261020 as literals
    (status,evidence),_,_,_=capture(monkeypatch,positive=True)
    metadata_fingerprint=evidence['secret_leaks'][0]['fingerprint']
    snapshot,_=literals.capture(monkeypatch,documents={literals.route(literals.target()):literals.native(value=TOKEN)})
    findings=literals.findings(snapshot)
    leaks=[leak for finding in findings for leak in finding['evidence'].get('secret_leaks',[])]
    assert status=='FAIL'and leaks and {leak['fingerprint']for leak in leaks}=={metadata_fingerprint}


def test_missing_enable_flag_is_disabled_without_selector_sweep():
    assert not source.enabled({'_content_secret_scan_kinds':[source.KIND]})
    assert source.selected_targets({},[NS])==[]
