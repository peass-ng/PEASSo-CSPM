"""Bounded EC2 user-data SDK projection, optional offline engines and deduplication."""
import base64
import json
from copy import deepcopy

import boto3
from botocore.stub import Stubber
import pytest
from peaso import secret_scanning as scanning
from peaso.checks import evaluate_check
from peaso.collectors.aws import Requests, _enrich, _project_user_data_indicators
from peaso.engine import collect_snapshot, evaluate_snapshot
from peaso.snapshot import make_snapshot

CID='aws_cis_ec2_userdata_embedded_secrets'
INSTANCE='i-0123456789abcdef0'
SCOPE='123456789012/us-east-1'
TOKEN='ghp_'+'7mQ2zR9wL4cV8nK1sF6aH3jP5uD0xB2yE9rT'


def indexed(row):
    return {'context': {'provider':'aws','scope':SCOPE},
            'collections': {'instance':[{'type':'instance','scope':SCOPE,'status':'collected','items':[row]}]},
            'instance':[{'type':'instance','scope':SCOPE,'data':row}]}


@pytest.mark.parametrize('mode,expected',[('both','FAIL'),('one','FAIL'),('unavailable','UNKNOWN'),('clean','PASS')])
def test_detector_results_do_not_turn_incomplete_negatives_into_pass(monkeypatch,mode,expected):
    scanning._RESULTS.clear()
    def engine(name):
        def scan(payload,path,timeout):
            if mode=='unavailable' or mode=='one' and name=='trufflehog':raise RuntimeError('private scanner failure')
            return [] if mode=='clean' else [(TOKEN,'GitHub',1)]
        return scan
    monkeypatch.setattr(scanning,'_scan_kingfisher',engine('kingfisher'))
    monkeypatch.setattr(scanning,'_scan_trufflehog',engine('trufflehog'))
    projected=_project_user_data_indicators({'InstanceId':INSTANCE,'UserData':{'Value':base64.b64encode(TOKEN.encode()).decode()}},INSTANCE,dual_scanner=True)
    row={'InstanceId':INSTANCE,'UserDataSecretIndicators':projected['UserDataSecretIndicators']}
    status,evidence=evaluate_check(CID,row,indexed(row));assert status==expected
    assert TOKEN not in json.dumps((projected,evidence))
    if expected=='FAIL':
        assert len(evidence['secret_leaks'])==1
        assert len(evidence['secret_leaks'][0]['detectors'])==(2 if mode=='both' else 1)
    scanning._RESULTS.clear()


@pytest.mark.parametrize('named',[True,False])
def test_engine_requires_named_userdata_check_even_when_content_option_is_true(monkeypatch,named):
    seen={}
    def collect(connector,requirements):
        seen.update(connector['options'])
        return make_snapshot('aws',[SCOPE],[])
    monkeypatch.setattr('peaso.collectors.collect_live',collect)
    request={'connector':{'provider':'aws','options':{'content_secret_scans':True}}}
    if named:request['checks']=[CID]
    collect_snapshot(request)
    assert ('instance' in seen['_content_secret_scan_kinds']) is named


@pytest.mark.parametrize('enabled,named',[(False,False),(False,True),(True,False)])
def test_sdk_default_or_unselected_userdata_never_invokes_engines(monkeypatch,enabled,named):
    def forbidden(*a,**k):raise AssertionError('external scanner called without named opt-in')
    monkeypatch.setattr(scanning,'scan_content',forbidden)
    sdk_chain(enabled,named,'#!/bin/sh\necho safe')


def sdk_chain(enabled,named,text,instances=(INSTANCE,)):
    session=boto3.Session(aws_access_key_id='fixture',aws_secret_access_key='fixture',region_name='us-east-1')
    client=session.client('ec2');requests=Requests({'content_secret_scans':enabled,'retry_attempts':1,'service_concurrency':1});requests.content_secret_scan_kinds={'instance'} if named else set()
    requests._clients[(id(session),'ec2','us-east-1')]=client
    # Stubber answers FIFO per client; per-instance reads run concurrently since 4aeec06e,
    # so one worker keeps the queued order (ordered_map assigns identical rows serially).
    with Stubber(client) as stub:
        for identity in instances:
            stub.add_response('describe_instance_attribute',{'InstanceId':identity,'UserData':{'Value':base64.b64encode(text.encode()).decode()}},{'InstanceId':identity,'Attribute':'userData'})
            stub.add_response('describe_instance_attribute',{'InstanceId':identity,'DisableApiTermination':{'Value':True}},{'InstanceId':identity,'Attribute':'disableApiTermination'})
        rows=_enrich(requests,session,'us-east-1','instance',[{'InstanceId':identity} for identity in instances],account='123456789012',partition='aws')
        stub.assert_no_pending_responses()
    snapshot=make_snapshot('aws',[SCOPE],[{'type':'instance','scope':SCOPE,'service':'ec2','status':'collected','items':rows}]);report=evaluate_snapshot(snapshot,checks=[CID])
    for future in requests._cache.values():
        if future.exception() is None:assert TOKEN not in json.dumps(future.result(),default=str)
    assert TOKEN not in json.dumps((snapshot,report),default=str)
    return report


def test_real_offline_tools_sdk_snapshot_and_duplicate_instances_yield_one_leak():
    pytest.importorskip('kingfisher_sdk')
    assert scanning._trufflehog()
    scanning._RESULTS.clear()
    report=sdk_chain(True,True,'#!/bin/sh\ngithub_token='+TOKEN+'\n',instances=(INSTANCE,'i-11111111111111111'))
    leaks=[f for f in report['findings'] if f.get('secret_fingerprint')]
    assert len(leaks)==1
    assert {d['engine'] for d in leaks[0]['evidence']['secret_leaks'][0]['detectors']}=={'kingfisher','trufflehog'}
    assert len(leaks[0]['evidence']['secret_leaks'][0]['locations'])==2
    assert leaks[0]['linked_check_ids']==[CID]
    scanning._RESULTS.clear()


@pytest.mark.parametrize('engines,complete', [([], True), ([{'engine':'kingfisher','status':'complete'}]*2, True),
    ([{'engine':'kingfisher','status':'unavailable'},{'engine':'trufflehog','status':'complete'}], True)])
def test_malformed_detector_coverage_cannot_pass(engines,complete):
    projected=_project_user_data_indicators({'InstanceId':INSTANCE},INSTANCE)
    projected['UserDataSecretIndicators']['ContentScan']={'leaks':[],'engines':engines,'complete':complete}
    row={'InstanceId':INSTANCE,'UserDataSecretIndicators':projected['UserDataSecretIndicators']}
    assert evaluate_check(CID,row,indexed(row))[0]=='UNKNOWN'
