"""Public default-planner -> SDK -> frozen review behavior; synthetic data only."""
from datetime import timedelta
import json
import pytest
from peaso.collectors import aws, collect_live
from peaso.collectors import aws_kms_enclave_native as native
from peaso.engine import plan_collection, evaluate_snapshot
from test_peaso_aws_bulk_inventory import sdk, ACCOUNT, REGION
from test_peaso_aws_kms_enclave_native import NOW, TIME, event

CHECK = 'aws.review.kms.enclave_debug_measurements'
KIND = 'cloudtrail_event'
SCOPE = ACCOUNT + '/' + REGION

@pytest.mark.parametrize('mode,expected', [('debug','FAIL'), ('normal','PASS'), ('empty','EMPTY'), ('not_configured','NOT_APPLICABLE')])
def test_default_request_reaches_current_public_review_without_named_checks(sdk, monkeypatch, mode, expected):
    session, add = sdk
    sts, trail, ec2 = add('sts'), add('cloudtrail'), add('ec2')
    ec2.add_response('describe_instances', {'Reservations': [] if mode == 'not_configured' else [{'OwnerId':ACCOUNT, 'Instances':[{'InstanceId':'i-0123456789abcdef0','EnclaveOptions':{'Enabled':True}}]}]}, {'Filters':[{'Name':'enclave-options.enabled','Values':['true']}]})
    sts.add_response('get_caller_identity', {'Account': ACCOUNT, 'Arn': f'arn:aws:iam::{ACCOUNT}:user/fixture', 'UserId': 'fixture'}, {})
    value = event()
    payload = json.loads(value['CloudTrailEvent'])
    recipient = payload['additionalEventData']['recipient']
    pcr = '0' * 96 if mode == 'debug' else 'ab' * 48
    recipient['attestationDocumentEnclaveImageDigest'] = pcr
    recipient['attestationDocumentEnclavePCR1'] = pcr
    recipient['attestationDocumentEnclavePCR2'] = pcr
    value['CloudTrailEvent'] = json.dumps(payload)
    for operation in ([] if mode == 'not_configured' else sorted(native.OPERATIONS)):
        trail.add_response('lookup_events', {'Events': [value] if operation == 'Decrypt' and mode != 'empty' else []},
            {'LookupAttributes': [{'AttributeKey':'EventName','AttributeValue':operation}], 'StartTime': NOW-timedelta(minutes=1440), 'EndTime': NOW})
    original = aws.Requests.__init__
    def initialized(self,*a,**kw):
        kw['sleep'] = lambda _: None
        original(self,*a,**kw); self.observed_at = NOW
    monkeypatch.setattr(aws.Requests,'__init__',initialized)
    monkeypatch.setattr(aws,'_session',lambda auth,region:(session,'synthetic-default-review'))
    # Bound the SDK fixture to this native dependency, preserving the unfiltered
    # production selection/planner path that omitted it in hosted default scans.
    monkeypatch.setattr(aws,'AWS_TYPES',[KIND])
    monkeypatch.setattr(aws,'SPECS',{KIND:('cloudtrail','lookup_events','Events')})
    request = {'connector': {'provider':'aws','scopes':[SCOPE], 'options': {'service_concurrency':1}}}
    plan = plan_collection(request)
    assert KIND in plan
    captured = collect_live(request['connector'], plan)
    rows = evaluate_snapshot(captured,checks=[CHECK])['findings']
    assert len(rows) == 1 and rows[0]['status'] == expected, rows
    assert 'DO_NOT_RETAIN' not in json.dumps(captured)
    sts.assert_no_pending_responses();trail.assert_no_pending_responses();ec2.assert_no_pending_responses()
