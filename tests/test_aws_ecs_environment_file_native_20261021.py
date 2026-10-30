"""Exact ECS and bounded S3 profile dispatch with native SDK-shaped responses."""
from copy import deepcopy
import io
import json
from pathlib import Path
import threading
from types import SimpleNamespace
from urllib.parse import quote
import pytest
import botocore.response
from botocore.response import StreamingBody
from botocore.client import BaseClient
from peaso import secret_scanning as scanning
from peaso.collectors.aws import Requests as NativeDispatch, ReadFailure
from peaso.collectors import aws_ecs_environment_file_secret_indicators as ECS
from peaso.collectors import aws_s3_selected_source_secret_indicators as S3
from peaso.checks import aws_ecs_environment_file_secret_review_20261021 as check
checkns={'evaluate':check.evaluate}
ACCOUNT='123456789012';REGION='us-east-1';SCOPE=ACCOUNT+'/'+REGION
TARGET={'scope':SCOPE,'task_definition_arn':f'arn:aws:ecs:{REGION}:{ACCOUNT}:task-definition/app:7',
        'container':'api','environment_file_arn':'arn:aws:s3:::selected-env-bucket/prod/app.env'}
S3TARGET=ECS.source_target(TARGET)
OPTIONS={'content_secret_scans':True,'_content_secret_scan_kinds':[ECS.KIND],ECS.OPTION:[TARGET],S3.OPTION:[S3TARGET]}
def response(files=None):
    return {'ResponseMetadata':{'HTTPStatusCode':200,'RequestId':'request-123'},
        'taskDefinition':{'taskDefinitionArn':TARGET['task_definition_arn'],'status':'ACTIVE','family':'app','revision':7,
            'containerDefinitions':[{'name':'api','environmentFiles':files if files is not None else [{'type':'s3','value':TARGET['environment_file_arn']}]}]}}
iso=SimpleNamespace(ACCOUNT=ACCOUNT,REGION=REGION,SCOPE=SCOPE,TARGET=TARGET,OPTIONS=OPTIONS,ReadFailure=ReadFailure,response=response)

TOKEN='ghp_'+'7mQ2zR9wL4cV8nK1sF6aH3jP5uD0xB2yE9rT'
ETAG='"stable-etag"'
ACCOUNT=iso.ACCOUNT;REGION=iso.REGION;SCOPE=iso.SCOPE;TARGET=iso.TARGET

class Raw:
    def __init__(self,data):self.stream=io.BytesIO(data);self.closed=False;self.reads=[]
    def read(self,n=None):
        assert isinstance(n,int) and 0<n<=16384
        self.reads.append(n);return self.stream.read(n)
    def close(self):self.closed=True
class Events:
    def __init__(self):self.handlers={}
    def register(self,event,handler,unique_id):self.handlers[unique_id]=handler
    def unregister(self,event,unique_id):self.handlers.pop(unique_id,None)
    def emit(self,request):
        for handler in self.handlers.values():handler(request)
class FakeClient(BaseClient):
    def __init__(self,service,reader):
        self.service=service;self.reader=reader;self.meta=SimpleNamespace(endpoint_url=f'https://{service}.{REGION}.amazonaws.com',
            region_name=REGION,service_model=SimpleNamespace(service_name=service,service_id=SimpleNamespace(hyphenize=lambda:service)),events=Events())
        self._endpoint=SimpleNamespace(host=self.meta.endpoint_url,http_session=SimpleNamespace(send=lambda request,**kw:SimpleNamespace(raw=Raw(request.data))))
    def _native(self,operation,args):
        self.reader.trace.append((self.service,operation,dict(args)))
        if self.service=='ecs':
            self.reader.ecs_reads+=1
            if self.reader.cancel_after_ecs and self.reader.ecs_reads==2:raise iso.ReadFailure('not_collected','collection_cancelled')
            result=iso.response()
            if self.reader.ecs_drift and self.reader.ecs_reads==2:
                result['taskDefinition']['containerDefinitions'][0]['environmentFiles'][0]['value']='arn:aws:s3:::selected-env-bucket/changed.env'
            if self.reader.ecs_revision_drift and self.reader.ecs_reads==2:result['taskDefinition']['revision']=8
            return result
        phase={('sts','get_caller_identity'):'caller',('s3','get_bucket_location'):'location',
            ('s3','head_object'):'head_after' if args.get('IfMatch') else 'head_before',('s3','get_object'):'get'}[(self.service,operation)]
        if self.reader.denied_phase==phase:raise iso.ReadFailure('denied','AccessDenied')
        method='POST' if self.service=='sts' else 'HEAD' if operation=='head_object' else 'GET'
        path='/' if self.service=='sts' else '/'+args['Bucket']+('/'+quote(args['Key'],safe='/~') if 'Key' in args else '')
        query='?location=' if phase=='location' else ''
        headers={} if self.service=='sts' else {'x-amz-expected-bucket-owner':self.reader.owner_override or ACCOUNT}
        if 'IfMatch' in args:headers['If-Match']=args['IfMatch']
        data=self.reader.payload if phase=='get' else b''
        request=SimpleNamespace(method=method,url=self.meta.endpoint_url+path+query,headers=headers,data=data)
        self.meta.events.emit(request)
        native=self._endpoint.http_session.send(request)
        meta={'ResponseMetadata':{'HTTPStatusCode':200,'RequestId':'request-'+phase.replace('_','-')}}
        if phase=='caller':return {**meta,'Account':ACCOUNT,'Arn':f'arn:aws:iam::{ACCOUNT}:user/offline','UserId':'offline-user'}
        if phase=='location':return {**meta,'LocationConstraint':REGION}
        etag='"drifted-etag"' if phase=='head_after' and self.reader.etag_drift else ETAG
        item={**meta,'ETag':etag,'ContentLength':len(self.reader.payload)}
        if phase=='get':item['Body']=StreamingBody(native.raw,len(data))
        return item
    def describe_task_definition(self,**kw):return self._native('describe_task_definition',kw)
    def get_caller_identity(self,**kw):return self._native('get_caller_identity',kw)
    def get_bucket_location(self,**kw):return self._native('get_bucket_location',kw)
    def head_object(self,**kw):return self._native('head_object',kw)
    def get_object(self,**kw):return self._native('get_object',kw)
class Reader(NativeDispatch):
    def __init__(self,payload,**faults):
        self.content_secret_scans=True;self.content_secret_scan_kinds={ECS.KIND}
        self.calls=0;self.max_calls=100;self._lock=threading.RLock();self.timeout=10;self.connect_timeout=3
        self.deadline=None;self.cancel_event=None;self.trace=[];self.ecs_reads=0;self.payload=payload
        self.etag_drift=faults.get('etag_drift',False);self.ecs_drift=faults.get('ecs_drift',False)
        self.ecs_revision_drift=faults.get('ecs_revision_drift',False)
        self.denied_phase=faults.get('denied_phase');self.owner_override=faults.get('owner_override')
        self.cancel_after_ecs=faults.get('cancel_after_ecs',False)
        self.clients={service:FakeClient(service,self) for service in ('ecs','s3','sts')}
        # Requests.__init__ owns the scan-local native read cache; this
        # hand-built dispatcher must carry the same per-scan cache state.
        from peaso.collectors.aws_request_pool import RawReadCache
        self.raw_reads=RawReadCache()
    def check_deadline(self):
        if self.cancel_event and self.cancel_event.is_set():raise iso.ReadFailure('not_collected','collection_cancelled')
    def client(self,session,service,region,*,_metadata_profile=None):
        assert region==REGION and _metadata_profile in ('aws-selected-configuration-content-v1','aws-selected-s3-source-content-v1')
        return self.clients[service]

def evaluate_run(payload,**faults):
    options=deepcopy(iso.OPTIONS)
    reader=Reader(payload,**faults)
    S3.initialize(reader,options,[SCOPE]);ECS.initialize(reader,options,[SCOPE])
    items=ECS.collect_selected(reader,object(),REGION,{'Account':ACCOUNT},options,[SCOPE]).items
    meta={**reader.s3_source_metadata,**reader.ecs_envfile_metadata}
    index={'context':{'provider':'aws','scope':SCOPE,'metadata':meta},
        'collections':{ECS.KIND:[{'scope':SCOPE,'service':'ecs','status':'collected','items':items}]}}
    status,evidence=checkns['evaluate'](items[0],index)
    return reader,items[0],status,evidence

@pytest.fixture(autouse=True)
def offline(monkeypatch):
    import socket
    def blocked(*args,**kwargs):raise AssertionError('network forbidden')
    monkeypatch.setattr(socket.socket,'connect',blocked)
    monkeypatch.setattr(socket,'getaddrinfo',blocked)
    monkeypatch.setattr(botocore.response,'set_socket_timeout',lambda raw,seconds:assert_timeout(seconds))
    trace=[]
    def detector(data,path,timeout):
        trace.append(path)
        return [(TOKEN,'github-pat',1)] if TOKEN.encode() in data else []
    monkeypatch.setattr(scanning,'_scan_kingfisher',detector)
    monkeypatch.setattr(scanning,'_scan_trufflehog',detector)
    scanning._RESULTS.clear()
    yield trace
    scanning._RESULTS.clear()

def assert_timeout(value):assert 0<value<=5

def test_full_producer_positive_and_clean(offline):
    for payload,expected in [(TOKEN.encode(),'FAIL'),(b'mode=ready','PASS')]:
        reader,item,status,evidence=evaluate_run(payload)
        assert status==expected,(status,evidence,reader.trace,item[ECS.MARKER],reader.s3_source_metadata)
        assert reader.ecs_reads==2 and len(reader.trace)==7
        with pytest.raises(iso.ReadFailure,match='ecs_environment_file_call_bound'):
            reader.call(object(),'ecs',REGION,'describe_task_definition',_metadata_profile=ECS.PROFILE,
                _projection_context={'target':TARGET},taskDefinition=TARGET['task_definition_arn'])
        assert reader.ecs_reads==2
        assert [operation for service,operation,_ in reader.trace]==['describe_task_definition','get_caller_identity','get_bucket_location','head_object','get_object','head_object','describe_task_definition']
        assert len(offline)>=2 and item[ECS.MARKER]['association_coherent'] is True
        assert len(reader.s3_source_metadata[S3.KIND+'_receipts'])==5
        if expected=='FAIL':
            assert TOKEN not in json.dumps([item,evidence,reader.s3_source_metadata])
            assert len(evidence['secret_leaks'])==1 and len(evidence['secret_leaks'][0]['detectors'])==2
        else:assert evidence['complete'] is True

def test_full_producer_owner_etag_and_ecs_drift(offline):
    for fault in ({'owner_override':'000000000000'},{'etag_drift':True},{'ecs_drift':True},{'ecs_revision_drift':True}):
        reader,item,status,evidence=evaluate_run(b'mode=ready',**fault)
        assert status=='UNKNOWN',(fault,status,evidence)
        assert item[ECS.MARKER]['association_coherent'] is not True or item[ECS.MARKER]['s3_item'][S3.MARKER]['complete'] is False
    reader,item,status,evidence=evaluate_run(TOKEN.encode(),ecs_drift=True)
    assert status=='UNKNOWN' and item[ECS.MARKER]['association_coherent'] is False

def test_full_producer_denied_cancel_and_delegated_scope(offline):
    for fault in ({'denied_phase':'get'},{'cancel_after_ecs':True}):
        reader,item,status,evidence=evaluate_run(b'mode=ready',**fault)
        assert status=='UNKNOWN' and reader.ecs_envfile_grants=={}
    options=deepcopy(iso.OPTIONS)
    options[S3.OPTION].append({'scope':SCOPE,'bucket':'extra-bucket','key':'other.env','format':'text'})
    with pytest.raises(ValueError,match='extra_s3_selection'):
        ECS.selected_targets(options,[SCOPE])
    reader=Reader(b'mode=ready');S3.initialize(reader,iso.OPTIONS,[SCOPE]);ECS.initialize(reader,iso.OPTIONS,[SCOPE])
    extra={'scope':SCOPE,'bucket':'extra-bucket','key':'other.env','format':'text'}
    reader.s3_source_metadata[S3.KIND+'_selection'][SCOPE].append(S3.identity(extra))
    marker={'identity':S3.identity(extra),'capture':reader.s3_source_metadata[S3.KIND+'_capture']}
    with pytest.raises(S3.Incomplete,match='grant_unbound'):
        S3.validate_request(reader,object(),'s3',REGION,'head_object',
            {'Bucket':'extra-bucket','Key':'other.env','ExpectedBucketOwner':ACCOUNT},
            {'target':extra,'phase':'head_before','marker':marker})
    assert reader.trace==[]

def test_disabled_zero_io(offline):
    options={**iso.OPTIONS,'content_secret_scans':False}
    reader=Reader(b'mode=ready');reader.content_secret_scans=False
    out=ECS.collect_selected(reader,object(),REGION,{'Account':ACCOUNT},options,[SCOPE])
    assert out.status=='not_collected' and reader.trace==[]


def test_registered_behavior_cases_are_actual_native_capture():
    from copy import deepcopy
    from peaso.checks import CHECKS
    from peaso.checks.fixtures import CASES
    selected, = [c for c in CHECKS if c.id == ECS.CHECK]
    case = CASES[selected.id]
    before = deepcopy(case)
    for branch in ('pass', 'fail', 'unknown', 'missing'):
        result, evidence = selected.evaluate(case[branch], case[branch+'_index'])
        assert result == (branch.upper() if branch != 'missing' else 'UNKNOWN')
        assert TOKEN not in repr(evidence)
    assert case == before
