"""Independent botocore Stubber -> safe native profile -> collector -> engine."""
from copy import deepcopy
from contextlib import ExitStack
import json
import socket
from types import SimpleNamespace
from urllib.parse import quote
import boto3
from botocore.stub import Stubber
import pytest
from peaso import engine,secret_scanning as scanning
from peaso.collectors import aws
from peaso.collectors import aws_lambda_environment_secret_indicators as source
from peaso.checks import aws_lambda_environment_secret_review_20261020 as checks

ACCOUNT='123456789012';REGION='us-east-1';SCOPE=ACCOUNT+'/'+REGION
FUNCTION='arn:aws:lambda:'+REGION+':'+ACCOUNT+':function:AuditFunction'
TOKEN='ghp_'+'7mQ2zR9wL4cV8nK1sF6aH3jP5uD0xB2yE9rT'
CALLER={'Account':ACCOUNT,'Arn':'arn:aws:iam::'+ACCOUNT+':user/reviewer','UserId':'AIDAREVIEWER'}
REVISION='11111111-1111-4111-8111-111111111111'
REQUEST_ID='22222222-2222-4222-8222-222222222222'


@pytest.fixture(autouse=True)
def offline(monkeypatch):
    def blocked(*a,**k):pytest.fail('actual sockets/DNS/default credential acquisition forbidden')
    for n in ('connect','connect_ex'):monkeypatch.setattr(socket.socket,n,blocked)
    for n in ('create_connection','getaddrinfo'):monkeypatch.setattr(socket,n,blocked)
    monkeypatch.setattr(aws,'_session',blocked)
    monkeypatch.setenv('AWS_EC2_METADATA_DISABLED','true')
    monkeypatch.setenv('AWS_SHARED_CREDENTIALS_FILE','/nonexistent/lambda-environment-review')
    monkeypatch.setenv('AWS_CONFIG_FILE','/nonexistent/lambda-environment-review')
    scanning._RESULTS.clear()
    yield
    scanning._RESULTS.clear()


def native(arn=FUNCTION,variables=None):
    return {'FunctionArn':arn,'FunctionName':arn.rsplit(':',1)[1],'Version':'$LATEST','RevisionId':REVISION,
        'State':'Active','LastUpdateStatus':'Successful','Runtime':'python3.12','Description':'never-retain '+TOKEN,
        'Environment':{'Variables':{'Mode':'ready = true'} if variables is None else variables},
        'ResponseMetadata':{'HTTPStatusCode':200,'RequestId':REQUEST_ID,'HTTPHeaders':{'x-echo':TOKEN}}}


def request(targets=None,**options):
    return {'connector':{'provider':'aws','scopes':[SCOPE],'auth':{'method':'access_keys','aws_access_key_id':'offline-key','aws_secret_access_key':'offline-secret'},
        'options':{'content_secret_scans':True,source.OPTION:targets or [FUNCTION],'retry_attempts':1,**options}},'checks':[source.CHECK]}


def capture(monkeypatch,*,targets=None,responses=None,error=None,caller=None,real=False,req=None,collect=True):
    targets=targets or [FUNCTION];responses=responses if responses is not None else {t:native(t) for t in targets}
    trace=SimpleNamespace(readers=[],calls=[],scans=[],clients={})
    session=boto3.Session(aws_access_key_id='offline-native-key',aws_secret_access_key='offline-native-secret',region_name=REGION)
    sts=session.client('sts',region_name=REGION);lam=session.client('lambda',region_name=REGION)
    trace.clients={'sts':sts,'lambda':lam};trace.session=session
    if not real:
        def detector(payload,path,timeout):
            trace.scans.append((bytes(payload),path,timeout))
            return [(TOKEN,'github-pat',1)] if TOKEN.encode() in payload else []
        monkeypatch.setattr(scanning,'_scan_kingfisher',detector);monkeypatch.setattr(scanning,'_scan_trufflehog',detector)
    original=aws.Requests.__init__
    def init(self,*a,**k):original(self,*a,**k);trace.readers.append(self)
    monkeypatch.setattr(aws.Requests,'__init__',init)
    def client(self,selected,service,region,**kwargs):
        assert selected is session and region==REGION and service in trace.clients
        if kwargs:assert kwargs=={'_metadata_profile':source.PROFILE}
        return trace.clients[service]
    monkeypatch.setattr(aws.Requests,'client',client)
    monkeypatch.setattr(aws,'_session',lambda auth,region:(session,'fixture-pinned'))
    def before(params,model,context,**kwargs):
        assert model.name=='GetFunctionConfiguration' and set(params)=={'FunctionName'} and params['FunctionName'] in targets
        # Validate the actual SDK serializer's method, trusted native host and
        # exact native ARN route, independently of our projection implementation.
        route=lam._convert_to_request_dict(params,model,endpoint_url=lam.meta.endpoint_url)
        assert route['method']=='GET' and route['url']=='https://lambda.'+REGION+'.amazonaws.com/2015-03-31/functions/'+quote(params['FunctionName'],safe='')+'/configuration'
        trace.calls.append((model.name,deepcopy(params),route['method'],route['url']))
    lam.meta.events.register('before-parameter-build.lambda.GetFunctionConfiguration',before)
    req=deepcopy(req if req is not None else request(targets));trace.req=req
    def run():
        with ExitStack() as stack:
            st=stack.enter_context(Stubber(sts));lt=stack.enter_context(Stubber(lam))
            st.add_response('get_caller_identity',caller or CALLER,{})
            enabled=req['connector']['options'].get('content_secret_scans') is True and source.CHECK in req.get('checks',[])
            if enabled and source.MAX_SECONDS>0 and (caller or CALLER)['Account']==ACCOUNT:
                for t in targets:
                    if error:
                        code,status=error
                        lt.add_client_error('get_function_configuration',service_error_code=code,service_message=TOKEN,http_status_code=status,expected_params={'FunctionName':t})
                    else:lt.add_response('get_function_configuration',responses[t],{'FunctionName':t})
            snapshot=engine.collect_snapshot(req)
            st.assert_no_pending_responses();lt.assert_no_pending_responses()
        return snapshot
    trace.run=run
    return (run() if collect else req),trace


def findings(snapshot):return engine.evaluate_snapshot(snapshot,checks=[source.CHECK])['findings']


def index_of(snapshot):
    own=next(c for c in snapshot['collections'] if c['type']==source.KIND and c['scope']==SCOPE)
    return own['items'][0],{'context':{'provider':'aws','scope':SCOPE,'metadata':snapshot['metadata']},'collections':{
        source.KIND:[own],'aws_account':[c for c in snapshot['collections'] if c['type']=='aws_account']}}


def retained(reader):
    results=[]
    for f in reader._cache.values():
        if f.exception() is None:results.append(f.result())
        else:
            assert f.exception().__traceback__ is None
            results.append({'status':f.exception().status,'code':f.exception().code})
    return json.dumps([list(reader._cache),results,reader.lambda_environment_metadata],default=str)


@pytest.mark.parametrize('positive',[False,True])
def test_native_collector_engine_and_hidden_cache(monkeypatch,positive):
    snapshot,trace=capture(monkeypatch,responses={FUNCTION:native(variables={'Token':TOKEN} if positive else {'Mode':'ready = true'})})
    result=findings(snapshot)
    assert len(result)==1 and result[0]['status']==('FAIL' if positive else 'PASS'),result
    status,evidence=checks.evaluate(*index_of(snapshot))
    assert status==result[0]['status'] and evidence['coverage']=='selected_observed_literal_environment_only'
    assert len(trace.calls)==1 and len(trace.scans)==2
    exported=json.dumps([snapshot,result])+retained(trace.readers[0])
    for value in (TOKEN,FUNCTION,'AuditFunction',REVISION,REQUEST_ID,'ready = true','offline-native-secret'):assert value not in exported
    assert trace.readers[0].calls==2


@pytest.mark.parametrize('positive',[False,True])
def test_real_both_pinned_detectors(monkeypatch,positive):
    snapshot,_=capture(monkeypatch,responses={FUNCTION:native(variables={'Token':TOKEN} if positive else None)},real=True)
    result=findings(snapshot)
    assert len(result)==1 and result[0]['status']==('FAIL' if positive else 'PASS'),result
    _,evidence=checks.evaluate(*index_of(snapshot))
    assert {(e['engine'],e['version'],e['status']) for e in evidence['engines']}=={
        ('kingfisher','1.4.0','complete'),('trufflehog','3.92.5','complete')}
    if positive:assert {d['engine'] for d in result[0]['evidence']['secret_leaks'][0]['detectors']}=={'kingfisher','trufflehog'}
    assert TOKEN not in json.dumps([snapshot,result])


@pytest.mark.parametrize('error', [('AccessDeniedException',403),('ExpiredTokenException',403),('ResourceNotFoundException',404),('TooManyRequestsException',429),('ServiceException',500),(TOKEN,400)])
def test_native_denied_deleted_error_bodies_and_codes_not_retained(monkeypatch,error):
    snapshot,trace=capture(monkeypatch,error=error)
    assert {f['status'] for f in findings(snapshot)}=={'UNKNOWN'} and not trace.scans
    assert TOKEN not in json.dumps(snapshot)+retained(trace.readers[0])


@pytest.mark.parametrize('mutate',[
    lambda r:r.update(FunctionArn=FUNCTION.replace(ACCOUNT,'000000000000')),
    lambda r:r.update(FunctionName='foreign'),lambda r:r.update(FunctionArn=FUNCTION+':1'),
    lambda r:r.pop('FunctionArn'),lambda r:r.pop('FunctionName'),lambda r:r.update(Version='1'),lambda r:r.pop('Version'),
    lambda r:r.pop('RevisionId'),lambda r:r.update(RevisionId=TOKEN),
    lambda r:r.update(State='Pending'),lambda r:r.pop('State'),lambda r:r.update(LastUpdateStatus='InProgress'),
    lambda r:r.pop('LastUpdateStatus'),lambda r:r.pop('Environment'),lambda r:r.update(Environment={}),
    lambda r:r.update(Environment={'Error':{'ErrorCode':'KMSAccessDeniedException','Message':TOKEN}}),
    lambda r:r.update(Environment={'Variables':{'Token':TOKEN},'Error':{'ErrorCode':'KMSAccessDeniedException','Message':TOKEN}}),
    lambda r:r.update(Environment={'Variables':{}}),lambda r:r.update(Environment={'Variables':{'Mode':''}}),
    lambda r:r.update(Environment={'Variables':{'Bad':'\x00'}}),lambda r:r.update(Environment={'Variables':{'Bad':'x'*4097}}),
    lambda r:r.update(Environment={'Variables':{'Bad':'x'*4096}}),
    lambda r:r.update(Environment={'Variables':{'A':'value'}}),
    lambda r:r.update(Environment={'Variables':{str(i)+'Name':'value' for i in range(129)}}),
    lambda r:r.pop('ResponseMetadata'),lambda r:r['ResponseMetadata'].update(HTTPStatusCode=206),
    lambda r:r['ResponseMetadata'].pop('RequestId'),lambda r:r['ResponseMetadata'].update(RequestId=TOKEN),
    lambda r:r.update(Description='x'*(source.MAX_RESPONSE+1)),
])
def test_native_malformed_foreign_partial_omitted_oversize_never_clean(monkeypatch,mutate):
    raw=native();mutate(raw)
    snapshot,trace=capture(monkeypatch,responses={FUNCTION:raw})
    assert findings(snapshot)[0]['status']=='UNKNOWN' and not trace.scans
    assert TOKEN not in json.dumps(snapshot)+retained(trace.readers[0])


@pytest.mark.parametrize('targets',[None,[],{},'function',[FUNCTION,FUNCTION],[FUNCTION+':$LATEST'],[FUNCTION+':1'],['AuditFunction'],
    [FUNCTION.replace(ACCOUNT,'000000000000')],[FUNCTION.replace(REGION,'us-west-2')],
    [FUNCTION+'?query=1'],['https://lambda.amazonaws.com/'+FUNCTION],['arn:aws-cn:lambda:'+REGION+':'+ACCOUNT+':function:AuditFunction'],[FUNCTION]*9])
def test_selection_rejected_before_credentials(monkeypatch,targets):
    req=request();req['connector']['options'][source.OPTION]=targets
    with pytest.raises(ValueError):engine.collect_snapshot(req)


@pytest.mark.parametrize('scopes',[[],['*'],[ACCOUNT],[SCOPE,SCOPE],['000000000000/'+REGION]])
def test_explicit_native_scope_required(monkeypatch,scopes):
    req=request();req['connector']['scopes']=scopes
    with pytest.raises(ValueError):engine.collect_snapshot(req)


@pytest.mark.parametrize('flag',[False,None])
def test_disabled_reads_no_function_configuration(monkeypatch,flag):
    req=request();req['connector']['options'].pop('content_secret_scans')
    if flag is not None:req['connector']['options']['content_secret_scans']=flag
    snapshot,trace=capture(monkeypatch,req=req)
    assert not trace.calls and not trace.scans and {f['status'] for f in findings(snapshot)}=={'UNKNOWN'}


def test_named_check_required_and_internal_optin_overwritten(monkeypatch):
    req=request();req.pop('checks');req['categories']=['hardening'];req['connector']['options'].update(inventories=[source.KIND],_content_secret_scan_kinds=[source.KIND])
    snapshot,trace=capture(monkeypatch,req=req)
    assert not trace.calls and snapshot['metadata'][source.KIND+'_authorized'] is False
    assert source.KIND in engine.BULK_STREAM_TYPES['aws']


@pytest.mark.parametrize('failed',['kingfisher','trufflehog'])
def test_one_engine_unavailable_never_clean(monkeypatch,failed):
    req,trace=capture(monkeypatch,collect=False)
    def unavailable(*a,**k):raise ImportError(TOKEN)
    monkeypatch.setattr(scanning,'_scan_'+failed,unavailable)
    snapshot=trace.run()
    assert findings(snapshot)[0]['status']=='UNKNOWN' and TOKEN not in json.dumps(snapshot)+retained(trace.readers[0])


def test_secret_bearing_function_name_and_variable_key_are_opaque(monkeypatch):
    target=FUNCTION.replace('AuditFunction',TOKEN)
    snapshot,trace=capture(monkeypatch,targets=[target],responses={target:native(target,{TOKEN:TOKEN})})
    assert findings(snapshot)[0]['status']=='FAIL'
    assert TOKEN not in json.dumps(snapshot)+retained(trace.readers[0])
    assert all(TOKEN not in path for _,path,_ in trace.scans)


@pytest.mark.parametrize('mutate',[
    lambda s,i:i[source.MARKER].update(complete=False),lambda s,i:i[source.MARKER].update(version='1'),
    lambda s,i:i[source.MARKER].update(scope='000000000000/'+REGION),lambda s,i:i[source.MARKER].update(revision=None),
    lambda s,i:i[source.MARKER]['engines'].pop(),lambda s,i:i[source.MARKER]['engines'][0].update(version='unknown'),
    lambda s,i:i[source.MARKER]['request'].update(method='POST'),lambda s,i:i[source.MARKER]['request'].update(native_request=None),
    lambda s,i:i['_provenance'].update(capture='foreign'),lambda s,i:s['metadata'][source.KIND+'_selection'][SCOPE].clear(),
    lambda s,i:next(c for c in s['collections'] if c['type']==source.KIND and c['scope']==SCOPE).update(status='partial'),
    lambda s,i:s['metadata']['caller_identities'][0].update(Account='000000000000'),
])
def test_pure_consumer_provenance_and_completeness_guards(monkeypatch,mutate):
    snapshot,_=capture(monkeypatch);item,_=index_of(snapshot);mutate(snapshot,item)
    assert checks.evaluate(*index_of(snapshot))[0]=='UNKNOWN'


def test_eight_exact_functions_dedup_across_observed_assets(monkeypatch):
    targets=[FUNCTION+str(i) for i in range(8)]
    snapshot,trace=capture(monkeypatch,targets=targets,responses={t:native(t,{'Token':TOKEN}) for t in targets})
    result=findings(snapshot)
    assert len(trace.calls)==8 and len(result)==1 and result[0]['status']=='FAIL'
    assert len(result[0]['evidence']['secret_leaks'][0]['locations'])==8
    assert TOKEN not in json.dumps([snapshot,result])+retained(trace.readers[0])


def test_shared_response_total_and_deadline_preserve_unknown(monkeypatch):
    with monkeypatch.context() as patch:
        patch.setattr(source,'MAX_RESPONSE_TOTAL',1)
        snapshot,trace=capture(patch)
        assert findings(snapshot)[0]['status']=='UNKNOWN' and not trace.scans
    with monkeypatch.context() as patch:
        patch.setattr(source,'MAX_SECONDS',0)
        snapshot,trace=capture(patch)
        assert findings(snapshot)[0]['status']=='UNKNOWN' and not trace.calls


def test_actual_scanner_runner_is_unverified(monkeypatch):
    calls=[];original=scanning._run
    def run(argv,payload,timeout):calls.append(list(argv));return original(argv,payload,timeout)
    monkeypatch.setattr(scanning,'_run',run)
    snapshot,_=capture(monkeypatch,responses={FUNCTION:native(variables={'Token':TOKEN})},real=True)
    assert findings(snapshot)[0]['status']=='FAIL'
    runs=[a for a in calls if 'stdin' in a or 'filesystem' in a];assert runs
    for a in runs:assert {'--no-verification','--no-update','--no-verification-cache','--force-skip-archives','--fail-on-scan-errors','--concurrency=1'}<=set(a)


def test_native_derived_fixture_receipt(monkeypatch, tmp_path):
    cases={}
    for state in ('pass','fail','unknown'):
        with monkeypatch.context() as patch:
            snapshot,_=capture(patch,responses={FUNCTION:native(variables={'Token':TOKEN} if state=='fail' else None)},error=('AccessDeniedException',403) if state=='unknown' else None,real=True)
            assert findings(snapshot)[0]['status']==state.upper()
            item,index=index_of(snapshot);cases[state]=deepcopy(item);cases[state+'_index']=deepcopy(index)
    cases.update(index=deepcopy(cases['pass_index']),missing={},malformed={source.MARKER:None})
    (tmp_path/'native-fixtures.json').write_text(json.dumps({source.CHECK:cases},sort_keys=True,indent=2)+'\n')


def test_optional_client_timeout_and_cache_namespace_preserve_metadata_defaults():
    calls=[]
    class Session:
        def client(self,service,region_name,config):
            calls.append((service,region_name,config));return SimpleNamespace()
    session=Session();requests=aws.Requests({'read_timeout':120,'connect_timeout':30})
    metadata=requests.client(session,'lambda',REGION)
    content=requests.client(session,'lambda',REGION,_metadata_profile=source.PROFILE)
    assert metadata is not content and requests.client(session,'lambda',REGION,_metadata_profile=source.PROFILE) is content
    assert (calls[0][2].connect_timeout,calls[0][2].read_timeout)==(30,120)
    assert (calls[1][2].connect_timeout,calls[1][2].read_timeout)==(3,5)
    assert calls[1][2].retries=={'total_max_attempts':1,'mode':'standard'}


@pytest.mark.parametrize('profile_first',[False,True])
def test_native_profile_cache_isolation_and_redacted_replay(monkeypatch,profile_first):
    session=boto3.Session(aws_access_key_id='offline-key',aws_secret_access_key='offline-secret',region_name=REGION)
    client=session.client('lambda',region_name=REGION)
    requests=aws.Requests({'content_secret_scans':True,'retry_attempts':1})
    requests.content_secret_scan_kinds=frozenset({source.KIND})
    source.initialize(requests,{source.OPTION:[FUNCTION],'content_secret_scans':True,'_content_secret_scan_kinds':[source.KIND]},[SCOPE])
    requests.lambda_environment_sessions[id(session)]={'account':ACCOUNT,'partition':'aws'}
    monkeypatch.setattr(requests,'client',lambda *a,**k:client)
    def detector(payload,path,timeout):return [(TOKEN,'github-pat',1)] if TOKEN.encode() in payload else []
    monkeypatch.setattr(scanning,'_scan_kingfisher',detector);monkeypatch.setattr(scanning,'_scan_trufflehog',detector)
    raw=native(variables={'Token':TOKEN});raw.pop('Description');raw['ResponseMetadata']['HTTPHeaders']={}
    with Stubber(client) as stub:
        for _ in range(2):stub.add_response('get_function_configuration',raw,{'FunctionName':FUNCTION})
        def read(profile):return requests.call(session,'lambda',REGION,'get_function_configuration',**({'_metadata_profile':source.PROFILE} if profile else {}),FunctionName=FUNCTION)
        first=read(profile_first);second=read(not profile_first)
        content=first if profile_first else second;metadata=second if profile_first else first
        assert metadata['Environment']['Variables']=={'Token':None}
        assert content[source.MARKER]['complete'] is True and len(content[source.MARKER]['leaks'])==1
        assert read(True)==content
        assert requests.calls==2 and requests.cache_hits==1
        stub.assert_no_pending_responses()
    assert TOKEN not in retained(requests)
    keys=[key for key in requests._cache if key[4]==source.PROFILE or source.PROFILE in key]
    assert len(keys)==1 and FUNCTION not in repr(keys)


@pytest.mark.parametrize('flag',['true',1,{},None])
def test_public_flag_type_rejected_before_credentials(monkeypatch,flag):
    req=request(content_secret_scans=flag)
    with pytest.raises(ValueError):engine.collect_snapshot(req)


def test_caller_account_contradiction_never_reads_function(monkeypatch):
    caller={'Account':'000000000000','Arn':'arn:aws:iam::000000000000:user/reviewer','UserId':'AIDAREVIEWER'}
    snapshot,trace=capture(monkeypatch,caller=caller)
    assert not trace.calls and {f['status'] for f in findings(snapshot)}=={'UNKNOWN'}


def test_native_aws_cross_surface_value_dedup(monkeypatch):
    from tests import test_aws_codecommit_path_redaction_fix_20261020 as code
    from peaso.secret_findings import deduplicate_secret_findings
    with monkeypatch.context() as patch:
        snapshot,_=capture(patch,responses={FUNCTION:native(variables={'Token':TOKEN})})
        lambda_findings=findings(snapshot)
    with monkeypatch.context() as patch:
        def detector(payload,path,timeout):return [(TOKEN,'github-pat',1)] if TOKEN.encode() in payload else []
        patch.setattr(scanning,'_scan_kingfisher',detector);patch.setattr(scanning,'_scan_trufflehog',detector)
        requests,session,stub=code.clients()
        with stub:
            code.repo(stub);code.folder(stub,files=['/selected.txt']);code.file(stub,'/selected.txt',('token='+TOKEN).encode())
            sample=code.adapter.scan_repository(requests,session,REGION,code.REPO)
            stub.assert_no_pending_responses()
        status,_,report=code.evaluate(sample)
        assert status=='FAIL'
    merged=deduplicate_secret_findings(lambda_findings+report['findings'])
    assert len(merged)==1 and set(merged[0]['linked_check_ids'])=={source.CHECK,code.consumer.IDS['repository']}
    assert len(merged[0]['evidence']['secret_leaks'][0]['locations'])==2 and TOKEN not in json.dumps(merged)


def test_registered_real_native_cases():
    from peaso.checks import CHECKS
    from peaso.checks.fixtures import CASES
    check,=[c for c in CHECKS if c.id==source.CHECK]
    assert check.kind==source.KIND and check.dependencies==['aws_account',source.KIND] and check.severity=='high'
    assert checks.DECLARATIONS[0]['finding_type']=='secrets' and checks.DECLARATIONS[0]['requirements']==[]
    cases=CASES[source.CHECK]
    for state in ('pass','fail','unknown'):assert check.evaluate(cases[state],cases[state+'_index'])[0]==state.upper()
    for shape in ('missing','malformed'):assert check.evaluate(cases[shape],cases['index'])[0]=='UNKNOWN'
