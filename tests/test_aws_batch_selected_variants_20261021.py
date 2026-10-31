"""Exact candidate functions, offline SDK response -> selected producer -> public check."""
import ast
import base64
from contextlib import nullcontext
from copy import deepcopy
from datetime import date, datetime
import hashlib
import importlib.util
import json
import math
from pathlib import Path
import re
import sys
import threading
import time
from types import ModuleType, SimpleNamespace
from uuid import uuid4
from urllib.parse import urlsplit
import pytest
import boto3
import botocore.session
from botocore.stub import Stubber

ROOT=Path(__file__).resolve().parents[1]
CANDIDATE=ROOT/'peaso/collectors/aws_selected_configuration_secret_indicators.py'
TOKEN='ghp_'+'7mQ2zR9wL4cV8nK1sF6aH3jP5uD0xB2yE9rT'
ACCOUNT='123456789012';REGION='us-east-1';SCOPE=ACCOUNT+'/'+REGION
ARN=f'arn:aws:batch:{REGION}:{ACCOUNT}:job-definition/AuditJob:3'


def modules(monkeypatch):
    from peaso.collectors import aws_selected_configuration_secret_indicators as selected
    from peaso.checks import aws_selected_configuration_secret_review_20261020 as check
    from peaso import secret_scanning as scanning
    scanning._RESULTS.clear()
    def detector(payload,path,timeout):
        return [(TOKEN,'github-pat',1)] if TOKEN.encode() in payload else []
    monkeypatch.setattr(scanning,'_scan_kingfisher',detector)
    monkeypatch.setattr(scanning,'_scan_trufflehog',detector)
    return selected,check,scanning


def row(variant='classic',value=TOKEN):
    env=[{'name':'CREDENTIAL','value':value}]
    base={'jobDefinitionArn':ARN,'jobDefinitionName':'AuditJob','revision':3,'status':'ACTIVE','type':'container',
          'platformCapabilities':['EC2']}
    if variant=='classic':base['containerProperties']={'environment':env,'command':['echo',value]}
    elif variant=='ecs':base['ecsProperties']={'taskProperties':[{'containers':[{'name':'main','image':'public.ecr.aws/example/app:latest','environment':env,'command':['echo',value]}]}]}
    elif variant=='eks':
        base['containerOrchestrationType']='EKS'
        base['eksProperties']={'podProperties':{'containers':[{'name':'main','image':'public.ecr.aws/example/app:latest','env':env,'args':[value]}],
                                               'initContainers':[{'name':'setup','image':'public.ecr.aws/example/app:latest','command':['echo',value]}]}}
    elif variant=='node':
        base['nodeProperties']={'numNodes':2,'mainNode':0,'nodeRangeProperties':[
          {'targetNodes':'0:1','container':{'environment':env,'command':['echo',value]}},
          {'targetNodes':'1','ecsProperties':{'taskProperties':[{'containers':[{'name':'sidecar','image':'public.ecr.aws/example/app:latest','environment':env}]}]}}]}
    elif variant=='node_eks':
        base['containerOrchestrationType']='EKS'
        base['nodeProperties']={'numNodes':2,'mainNode':0,'nodeRangeProperties':[
          {'targetNodes':'0:1','eksProperties':{'podProperties':{'containers':[{'name':'main','image':'public.ecr.aws/example/app:latest','env':env,'args':[value]}]}}}]}
    return base


def run(monkeypatch,variant='classic',value=TOKEN,mutate=None,*,disabled=False,denied=False,cancelled=False):
    source,check,scanning=modules(monkeypatch)
    target={'surface':'batch_environment','scope':SCOPE,'resource_id':ARN}
    options={'content_secret_scans':not disabled,'_content_secret_scan_kinds':[source.KIND],source.OPTION:[target]}
    session=object();calls=[]
    class Requests:
        def __init__(self):
            self._lock=threading.RLock();self.content_secret_scans=not disabled
            self.content_secret_scan_kinds=[source.KIND]
            source.initialize(self,options,[SCOPE])
        def check_deadline(self):
            if cancelled:raise ValueError('cancelled')
        def call(self,selected,service,region,operation,_metadata_profile=None,**args):
            assert selected is session and (service,region,operation)==('batch',REGION,'describe_job_definitions')
            assert _metadata_profile==source.PROFILE and args=={'jobDefinitions':[ARN]}
            source.before_request(self);source.validate_request(service,operation,args,request_context=(self,session),region=region)
            calls.append((service,operation,deepcopy(args)))
            if denied:raise ReadFailure('unknown','denied')
            native={'jobDefinitions':[row(variant,value)],'ResponseMetadata':{'HTTPStatusCode':200,'RequestId':'11111111-1111-4111-8111-111111111111'}}
            if mutate:mutate(native['jobDefinitions'][0])
            item=source.project_response(native,service,operation,args,request_context=(self,session),region=region)
            item.update(AccountId=ACCOUNT,Region=REGION)
            return item
    ReadFailure=sys.modules['peaso.collectors.aws'].ReadFailure
    requests=Requests()
    caller={'Account':ACCOUNT,'Arn':f'arn:aws:iam::{ACCOUNT}:user/reviewer','UserId':'AIDATEST'}
    result=source.collect_selected(requests,session,REGION,caller,options,[SCOPE])
    if not result.items:return result.status,None,calls,scanning
    item=result.items[0]
    metadata=deepcopy(requests.configuration_content_metadata)
    metadata.update(caller_identities=[caller])
    index={'context':{'provider':'aws','scope':SCOPE,'metadata':metadata},'collections':{
        source.KIND:[{'scope':SCOPE,'status':'collected','account_id':ACCOUNT,'items':[item]}],
        'aws_account':[{'scope':ACCOUNT+'/global','status':'collected','account_id':ACCOUNT,'global':True,'items':[caller]}]}}
    status,evidence=check.evaluate(item,index)
    assert TOKEN not in json.dumps(item,default=str)
    assert TOKEN not in json.dumps(evidence,default=str)
    return status,evidence,calls,scanning


@pytest.mark.parametrize('variant',['classic','ecs','eks','node','node_eks'])
def test_positive_and_clean(monkeypatch,variant):
    status,evidence,calls,_=run(monkeypatch,variant)
    assert status=='FAIL' and len(calls)==1
    assert len(evidence['secret_leaks'])==1 and len(evidence['secret_leaks'][0]['detectors'])==2
    status,evidence,calls,_=run(monkeypatch,variant,'production')
    assert status=='PASS' and len(calls)==1 and evidence['literal_count']>=1


def test_deregistered_revision_is_still_reviewed(monkeypatch):
    # INACTIVE revisions stay readable with their literals, so they get an assessment.
    inactive=lambda r:r.update(status='INACTIVE')
    status,evidence,calls,_=run(monkeypatch,mutate=inactive)
    assert status=='FAIL' and len(calls)==1
    status,evidence,calls,_=run(monkeypatch,value='production',mutate=inactive)
    assert status=='PASS'


def test_unusable_definition_unknown_names_its_cause(monkeypatch):
    status,evidence,_,_=run(monkeypatch,mutate=lambda r:r.update(revision=4))
    assert status=='UNKNOWN' and evidence['reason']=='batch_identity'


@pytest.mark.parametrize('change',[lambda r:r.update(jobDefinitionArn=ARN.replace(ACCOUNT,'000000000000')),
                                  lambda r:r.update(revision=4),lambda r:r.update(status='DELETED'),
                                  lambda r:r.update(type='multinode'),lambda r:r.update(ecsProperties={'taskProperties':[]}),
                                  lambda r:r.update(platformCapabilities=['UNKNOWN']),
                                  lambda r:r['containerProperties'].update(environmentFiles=[]),
                                  lambda r:r['containerProperties']['environment'][0].update(valueFrom='arn:aws:ssm:...'),
                                  lambda r:r['containerProperties'].update(envFrom=[]),
                                  lambda r:r['containerProperties'].update(command=[TOKEN]*(257))])
def test_fail_closed(monkeypatch,change):
    status,evidence,calls,_=run(monkeypatch,mutate=change)
    assert status=='UNKNOWN' and len(calls)==1


def test_union_conflict(monkeypatch):
    status,evidence,calls,_=run(monkeypatch,'node',mutate=lambda r:r['nodeProperties']['nodeRangeProperties'].append(
        {'targetNodes':'0:1','container':{'environment':[{'name':'DUP','value':TOKEN}]}}))
    assert status=='UNKNOWN' and len(calls)==1


def test_node_range_outside_declared_nodes(monkeypatch):
    status,_,calls,_=run(monkeypatch,'node',mutate=lambda r:r['nodeProperties']['nodeRangeProperties'][0].update(targetNodes='0:5'))
    assert status=='UNKNOWN' and len(calls)==1


@pytest.mark.parametrize('state',['denied','cancelled','disabled'])
def test_read_failures(monkeypatch,state):
    status,evidence,calls,_=run(monkeypatch,**{state:True})
    assert status in ('UNKNOWN','not_collected')
    assert len(calls)==(1 if state=='denied' else 0)


@pytest.mark.parametrize('variant',['classic','ecs','eks','node','node_eks'])
def test_real_sdk_response_shape(variant):
    session=boto3.Session(aws_access_key_id='offline',aws_secret_access_key='offline',region_name=REGION)
    client=session.client('batch',region_name=REGION)
    native={'jobDefinitions':[row(variant)],'ResponseMetadata':{'HTTPStatusCode':200,'RequestId':'11111111-1111-4111-8111-111111111111'}}
    with Stubber(client) as stub:
        stub.add_response('describe_job_definitions',native,{'jobDefinitions':[ARN]})
        assert client.describe_job_definitions(jobDefinitions=[ARN])['jobDefinitions'][0]['jobDefinitionArn']==ARN
        stub.assert_no_pending_responses()


def test_literal_byte_bound_and_envfrom(monkeypatch):
    status,_,calls,_=run(monkeypatch,mutate=lambda r:r['containerProperties']['environment'][0].update(value='x'*(1024*1024+1)))
    assert status=='UNKNOWN' and len(calls)==1
    status,_,calls,_=run(monkeypatch,'eks',mutate=lambda r:r['eksProperties']['podProperties'].update(envFrom=[]))
    assert status=='UNKNOWN' and len(calls)==1


def test_describe_schema_has_no_environment_files():
    model=botocore.session.get_session().get_service_model('batch').operation_model('DescribeJobDefinitions')
    shape=model.output_shape.members['jobDefinitions'].member
    seen=set();names=set()
    def visit(item):
        if item.name in seen:return
        seen.add(item.name)
        for name,child in getattr(item,'members',{}).items():
            names.add(name);visit(child)
        if hasattr(item,'member'):visit(item.member)
        if hasattr(item,'value'):visit(item.value)
    visit(shape)
    assert 'environmentFiles' not in names
    assert {'containerProperties','ecsProperties','eksProperties','nodeProperties','environment','command','args','env'}<=names
