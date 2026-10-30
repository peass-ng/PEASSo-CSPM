"""Production optional S3 admission/permissions and actual SDK DEBUG boundaries."""
from copy import deepcopy
from tests.shared_admission_epoch_compatibility_20261020 import active_shared
import base64,hashlib,inspect,io,json,logging,socket,zipfile
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import urlsplit,parse_qs
import boto3
from botocore.awsrequest import AWSResponse
import pytest
from fastapi import HTTPException
from peaso import engine,secret_scanning as scan
from peaso.collectors import aws,aws_lambda_environment_secret_indicators as lambda_native,aws_selected_configuration_secret_indicators as configuration_native
from peaso.collectors import aws_s3_selected_source_secret_indicators as s3
from peaso.checks import CHECKS, fixtures
from peaso.checks import aws_s3_selected_source_secret_review_20261020 as consumer
from peaso.server.validation import OPTIONS,validate_connector
from scripts import peaso_deploy_customer_policy as policy
from peaso.private_secret_source_epoch_20261021 import AdmissionError

ACCOUNT='123456789012';REGION='us-east-1';SCOPE=ACCOUNT+'/'+REGION
CANARY='ghp_'+'7mQ2zR9wL4cV8nK1sF6aH3jP5uD0xB2yE9rT'
AUTH='synthetic-debug-auth-canary'
ARN='arn:aws:lambda:'+REGION+':'+ACCOUNT+':function:review'
PROJECT='arn:aws:codebuild:'+REGION+':'+ACCOUNT+':project/review'
REQID='11111111-1111-4111-8111-111111111111'
SCRATCH=Path('/tmp/peasso-secret-surface-review-20261020/aws-s3-production')

@pytest.fixture(autouse=True)
def offline(monkeypatch):
    def blocked(*a,**k):raise AssertionError('socket/DNS/auth discovery forbidden')
    for n in('connect','connect_ex'):monkeypatch.setattr(socket.socket,n,blocked)
    for n in('create_connection','getaddrinfo','gethostbyname','gethostbyname_ex'):monkeypatch.setattr(socket,n,blocked)
    monkeypatch.setattr(aws,'_session',blocked);monkeypatch.setenv('AWS_EC2_METADATA_DISABLED','true')
    scan._RESULTS.clear();yield;scan._RESULTS.clear()

class Raw:
    def __init__(self,b):self.b=io.BytesIO(b)
    def stream(self,amt=1024,decode_content=False):
        while part:=self.b.read(amt):yield part
    def read(self,amt=None):return self.b.read(amt)
    def close(self):self.b.close()


def debug_native(monkeypatch,profile,error=False):
    from peaso.collectors import aws_lambda_environment_secret_indicators as lam
    from peaso.collectors import aws_selected_configuration_secret_indicators as config
    from peaso.collectors import aws_code_log_content_indicators as code
    from peaso.collectors import aws_package_content_indicators as package
    options={'content_secret_scans':True,'retry_attempts':1,'_content_secret_scan_kinds':[lam.KIND,config.KIND],
        lam.OPTION:[ARN],config.OPTION:[{'surface':'codebuild_environment','scope':SCOPE,'resource_id':PROJECT}]}
    reader=aws.Requests(options);reader.content_secret_scan_kinds=frozenset(options['_content_secret_scan_kinds'])
    lam.initialize(reader,options,[SCOPE]);config.initialize(reader,options,[SCOPE])
    for name in('_scan_kingfisher','_scan_trufflehog'):
        monkeypatch.setattr(scan,name,lambda data,path,timeout:[(CANARY,'github-pat',1)]if CANARY.encode()in data else[])
    zipped=io.BytesIO()
    with zipfile.ZipFile(zipped,'w',compression=zipfile.ZIP_DEFLATED)as z:z.writestr('selected.py',CANARY)
    archive=zipped.getvalue();location='https://awslambda-review.s3.'+REGION+'.amazonaws.com/package?X-Amz-Signature='+CANARY
    class Download:
        status=200;headers={'Content-Length':str(len(archive))}
        def __init__(self):self.raw=io.BytesIO(archive)
        def __enter__(self):return self
        def __exit__(self,*a):self.raw.close()
        def geturl(self):return location
        def read(self,n):assert 0<n<=65536;return self.raw.read(n)
    class Opener:
        def open(self,url,timeout):assert url==location and 0<timeout<=3;return Download()
    monkeypatch.setattr(package,'build_opener',lambda *a:Opener())
    session=boto3.Session(aws_access_key_id='AKIAOFFLINEONLYTEST12',aws_secret_access_key='offline-key',aws_session_token=AUTH,region_name=REGION)
    original=session.client;calls=[]
    def client(service,**kw):
        sdk=original(service,**kw)
        def send(request,**kwargs):
            parsed=urlsplit(request.url);headers={k.lower():v.decode()if isinstance(v,bytes)else v for k,v in request.headers.items()}
            assert request.method in('POST','GET')and parsed.scheme=='https'and parsed.netloc==service+'.'+REGION+'.amazonaws.com'
            assert not parsed.fragment
            assert parse_qs(parsed.query)==({'Qualifier':['1']}if service=='lambda'and profile=='package'else{})
            assert 'authorization'in headers
            native_headers={'x-amzn-requestid':REQID,'x-amz-request-id':REQID};status=200
            if service=='sts':
                assert request.method=='POST'and parsed.path=='/'
                args=parse_qs(request.body.decode()if isinstance(request.body,bytes)else request.body)
                action=args['Action'][0];assert action in('GetCallerIdentity','AssumeRole')
                if action=='GetCallerIdentity':
                    raw=(f'<GetCallerIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><GetCallerIdentityResult><Arn>arn:aws:iam::{ACCOUNT}:user/review</Arn><UserId>AIDAREVIEW</UserId><Account>{ACCOUNT}</Account></GetCallerIdentityResult><ResponseMetadata><RequestId>{REQID}</RequestId></ResponseMetadata></GetCallerIdentityResponse>').encode()
                else:
                    raw=(f'<AssumeRoleResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><AssumeRoleResult><Credentials><AccessKeyId>ASIAOFFLINEONLYTEST12</AccessKeyId><SecretAccessKey>{CANARY}</SecretAccessKey><SessionToken>{AUTH}</SessionToken><Expiration>2026-10-21T00:00:00Z</Expiration></Credentials><AssumedRoleUser><AssumedRoleId>AROAEXAMPLE:review</AssumedRoleId><Arn>arn:aws:sts::{ACCOUNT}:assumed-role/review/review</Arn></AssumedRoleUser></AssumeRoleResult><ResponseMetadata><RequestId>{REQID}</RequestId></ResponseMetadata></AssumeRoleResponse>').encode()
                if error and profile in('sts_identity','sts_exchange'):
                    status=403;raw=(f'<ErrorResponse><Error><Code>AccessDenied</Code><Message>{CANARY}</Message></Error><RequestId>{REQID}</RequestId></ErrorResponse>').encode()
                native_headers['content-type']='text/xml'
            else:
                if service=='lambda':
                    assert request.method=='GET'and parsed.path.startswith(('/2015-03-31/functions/','/2015-03-31/functions/'))
                    if parsed.path.endswith('/configuration'):
                        data={'FunctionName':'review','FunctionArn':ARN,'Version':'$LATEST','RevisionId':REQID,'State':'Active','LastUpdateStatus':'Successful','Environment':{'Variables':{'TOKEN':CANARY}}}
                    else:
                        assert 'Qualifier=1'not in parsed.path
                        data={'Configuration':{'FunctionArn':ARN,'Version':'1','PackageType':'Zip','CodeSize':len(archive),'CodeSha256':base64.b64encode(hashlib.sha256(archive).digest()).decode()},'Code':{'RepositoryType':'S3','Location':location}}
                elif service=='codebuild':
                    assert request.method=='POST'and parsed.path=='/'
                    data={'projects': [{'name':'review','arn':PROJECT,'description':CANARY,'environment':{'environmentVariables':[{'name':'TOKEN','value':CANARY,'type':'PLAINTEXT'}]}}]}if profile=='configuration'else{'projects':['plain-project']}
                elif service=='codecommit':
                    assert request.method=='POST'and parsed.path=='/'
                    data={'commitId':'a'*40,'blobId':'b'*40,'filePath':'/selected.py','fileMode':'NORMAL','fileSize':len(CANARY),'fileContent':base64.b64encode(CANARY.encode()).decode()}
                else:raise AssertionError('undeclared native service')
                if error:status=403;data={'__type':'AccessDeniedException','message':CANARY}
                raw=json.dumps(data).encode();native_headers['content-type']='application/x-amz-json-1.1'
            calls.append((service,request.method,status));return AWSResponse(request.url,status,native_headers,Raw(raw))
        sdk._endpoint.http_session.send=send;return sdk
    monkeypatch.setattr(session,'client',client)
    # Initialize selectors from an actual native STS read before observing the
    # selected call; no fabricated native caller/completeness marker.
    caller=None
    if profile in('lambda','configuration'):caller=reader.call(session,'sts',REGION,'get_caller_identity')
    records=[]
    class Memory(logging.Handler):
        def emit(self,r):records.append(r.getMessage())
    handler=Memory();saved=[]
    for name in('botocore.auth','botocore.endpoint','botocore.parsers','botocore.hooks'):
        logger=logging.getLogger(name);saved.append((logger,logger.level,logger.propagate,list(logger.filters)));logger.setLevel(logging.DEBUG);logger.propagate=False;logger.addHandler(handler)
    result=None;failure=None
    try:
        try:
            if profile=='lambda':result=lam.collect_selected(reader,session,REGION,caller,options,[SCOPE]).items
            elif profile=='configuration':result=config.collect_selected(reader,session,REGION,caller,options,[SCOPE]).items
            elif profile=='code_log':result=reader.call(session,'codecommit',REGION,'get_file',_metadata_profile=code.PROFILE,_projection_context={'remaining_bytes':code.MAX_BYTES},repositoryName='review',commitSpecifier='a'*40,filePath='/selected.py')
            elif profile=='package':result=reader.call(session,'lambda',REGION,'get_function',_metadata_profile=package.PROFILE,FunctionName=ARN,Qualifier='1')
            elif profile=='sts_exchange':result=reader.call(session,'sts',REGION,'assume_role',_uncached_credential_exchange=True,RoleArn='arn:aws:iam::'+ACCOUNT+':role/review',RoleSessionName='review')
            elif profile=='sts_identity':result=reader.call(session,'sts',REGION,'get_caller_identity')
            else:result=reader.call(session,'codebuild',REGION,'list_projects')
        except aws.ReadFailure as exc:failure=(exc.status,exc.code)
        emitted=bool(records);leaked=any(value in row for row in records for value in(CANARY,AUTH));records.clear()
    finally:
        for logger,level,propagate,filters in saved:
            logger.removeHandler(handler);logger.setLevel(level);logger.propagate=propagate;assert logger.filters==filters
    retained=[]
    for future in reader._cache.values():
        exc=future.exception()
        if exc is None:retained.append(future.result())
        else:
            assert exc.__traceback__ is None;retained.append((exc.status,exc.code))
    assert CANARY not in json.dumps(retained,default=str)and AUTH not in json.dumps(retained,default=str)
    if profile!='ordinary':assert not leaked
    else:assert emitted
    return result,failure,calls,reader

@pytest.mark.parametrize('profile',['lambda','configuration','code_log','package','sts_identity','sts_exchange'])
@pytest.mark.parametrize('error',[False,True])
def test_native_sdk_profile_debug_success_and_denied(monkeypatch,profile,error):
    result,failure,calls,reader=debug_native(monkeypatch,profile,error)
    assert calls and calls[-1][2]==(403 if error else 200)
    if not error:
        assert result is not None and failure is None
        if profile=='lambda':assert result[0][lambda_native.MARKER]['complete']is True
        if profile=='configuration':assert result[0][configuration_native.MARKER]['complete']is True
        if profile=='code_log':assert result['value']['readable']and result['value']['scanner_complete']
        if profile=='package':assert result['PackageSecretIndicators']['NativeResponseComplete']is True
    if profile=='sts_exchange':assert not reader._cache


def test_ordinary_metadata_logging_remains_available(monkeypatch):debug_native(monkeypatch,'ordinary')


def selection():return {'scope':SCOPE,'bucket':'selected-source-review','key':'script.py','format':'text'}

def test_exact_one_registered_check_and_native_cases_idempotence():
    registered,=[c for c in CHECKS if c.id==s3.CHECK]
    assert inspect.unwrap(registered.evaluate)is consumer.evaluate
    assert registered.kind==s3.KIND and registered.allow_incomplete_failure and registered.severity=='high'
    before=tuple(CHECKS);case=deepcopy(fixtures.CASES[s3.CHECK]);active_shared().install_s3()
    assert tuple(CHECKS)==before and fixtures.CASES[s3.CHECK]==case
    cases=active_shared().s3_reviewed_inputs()[s3.CHECK]
    assert {consumer.evaluate(cases[b],cases[b+'_index'])[0]for b in('pass','fail','unknown')}=={'PASS','FAIL','UNKNOWN'}




def test_registry_install_failure_rolls_back_only_new_check(monkeypatch):
    from peaso import checks
    before=tuple(CHECKS);case=deepcopy(fixtures.CASES[s3.CHECK]);original=checks.register
    CHECKS[:]=[c for c in CHECKS if c.id!=s3.CHECK];fixtures.CASES.pop(s3.CHECK)
    without=tuple(CHECKS)
    def broken(*a,**k):
        decorate=original(*a,**k)
        def apply(fn):decorate(fn);raise RuntimeError('synthetic registration interruption')
        return apply
    monkeypatch.setattr(checks,'register',broken)
    try:
        with pytest.raises(RuntimeError,match='registration interruption'):active_shared().install_s3()
        assert tuple(CHECKS)==without and s3.CHECK not in fixtures.CASES
    finally:CHECKS[:]=before;fixtures.CASES[s3.CHECK]=case


def test_optional_s3_descriptors_never_expand_default_metadata_role():
    new=set(policy.OPTIONAL_S3_SOURCE_READ_REFERENCES)
    assert new=={('s3','head_object'),('s3','get_object')}
    assert new<=aws.READ_ACTIONS and new<=policy.UNGRANTED_CONTENT_OPERATIONS
    assert {policy.iam_action(*op)for op in new}=={'s3:GetObject'}
    assert policy.OPTIONAL_S3_SOURCE_VERSION_PERMISSION[0]=='s3:GetObjectVersion'
    assert ('s3','get_object_version')not in aws.READ_ACTIONS
    assert policy.build_policy(aws.READ_ACTIONS)==policy.build_policy(aws.READ_ACTIONS-new)
    current=policy.build_policy()
    default_reads=aws.READ_ACTIONS|policy.PRESERVED_TEMPLATE_READ_ACTIONS
    assert current==policy.build_policy(default_reads)==policy.build_policy(default_reads-new)
    actions={action for row in current['Statement'] for action in (row['Action'] if isinstance(row['Action'],list) else [row['Action']])}
    assert not {'s3:GetObject','s3:GetObjectVersion'}&actions


@pytest.mark.parametrize('operation',['get_object','head_object','get_object_version','delete_object','create_session'])
def test_no_generic_or_unknown_s3_operation_fallback(operation):
    reader=aws.Requests({'content_secret_scans':True})
    with pytest.raises(aws.ReadFailure):reader.call(object(),'s3',REGION,operation,Bucket='selected-source-review',Key='script.py')
    with pytest.raises(aws.ReadFailure,match='uninitialized'):
        reader.call(object(),'s3',REGION,operation,_metadata_profile=s3.PROFILE)
    assert not reader._cache and reader.calls==0


@pytest.mark.parametrize('version',[None,'null','existing-version'])
def test_hosted_exact_current_and_optional_version_selector(version):
    target=selection()
    if version is not None:target['version_id']=version
    assert s3.OPTION in OPTIONS
    validate_connector('aws',{'method':'access_keys','aws_access_key_id':'AKIAOFFLINEONLYTEST12','aws_secret_access_key':'offline-key'}, {'content_secret_scans':True,s3.OPTION:[target]},SimpleNamespace(auth_mode='cognito'),scopes=[SCOPE])


@pytest.mark.parametrize('fault',['empty','scalar','many','duplicate','foreign','directory','endpoint','url','format','version','missing_scopes','wrong_provider','internal_kind'])
def test_hosted_selector_boundary_before_auth(fault):
    t=selection();targets=[t];scopes=[SCOPE];provider='aws';options={'content_secret_scans':True}
    if fault=='empty':targets=[]
    if fault=='scalar':targets=t
    if fault=='many':targets=[{**t,'key':str(i)}for i in range(5)]
    if fault=='duplicate':targets=[t,t]
    if fault=='foreign':t['scope']='999999999999/'+REGION
    if fault=='directory':t['bucket']='directory--az1--x-s3'
    if fault=='endpoint':t['endpoint_url']='https://foreign.invalid'
    if fault=='url':t['key']='https://foreign.invalid/script'
    if fault=='format':t['format']='auto'
    if fault=='version':t['version_id']=''
    if fault=='missing_scopes':scopes=[]
    if fault=='wrong_provider':provider='gcp'
    if fault=='internal_kind':options['_content_secret_scan_kinds']=[s3.KIND]
    options[s3.OPTION]=targets
    with pytest.raises(HTTPException)as exc:validate_connector(provider,{},options,SimpleNamespace(auth_mode='cognito'if fault=='internal_kind'else'local'),scopes=scopes)
    assert exc.value.status_code==422


def request(named=True,**options):
    result={'connector':{'provider':'aws','scopes':[SCOPE],'auth':{},'options':{'content_secret_scans':True,s3.OPTION:[selection()],**options}}}
    if named:result['checks']=[s3.CHECK]
    else:result['categories']=['exposure']
    return result


def test_default_plan_excludes_s3_while_named_dependency_is_supported():
    assert s3.KIND in engine.plan_collection(request())
    assert s3.KIND not in engine.plan_collection({'connector':{'provider':'aws','scopes':[SCOPE]}})


@pytest.mark.parametrize('mode',['inventory','collect_all'])
def test_public_internal_kind_spoof_is_overwritten_by_named_selection(monkeypatch,mode):
    from peaso import collectors
    req=request(False,_content_secret_scan_kinds=[s3.KIND])
    req['connector']['options'].update({'inventories':[s3.KIND]}if mode=='inventory'else{'collect_all':True})
    class Captured(Exception):pass
    def capture(connector,requirements):
        assert s3.KIND not in connector['options']['_content_secret_scan_kinds']
        raise Captured()
    monkeypatch.setattr(collectors,'collect_live',capture)
    with pytest.raises(Captured):engine.collect_snapshot(req)
