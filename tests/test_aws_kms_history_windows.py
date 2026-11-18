"""Complete synthetic SDK history under latency, pagination and boundary overlap."""
from datetime import timedelta
import copy
import json
import threading
import boto3
import pytest
from botocore.exceptions import ClientError
from peaso.collectors import aws, aws_kms_enclave_native as native
from peaso.engine import evaluate_snapshot
from test_peaso_aws_kms_enclave_native import NOW, ACCOUNT, REGION, event, snapshot

CHECK = 'aws.review.kms.enclave_debug_measurements'


def sdk_history(monkeypatch, mode='normal', synchronize=False):
    session = boto3.Session(aws_access_key_id='synthetic', aws_secret_access_key='synthetic', region_name=REGION)
    client = session.client('cloudtrail')
    requests = aws.Requests({'retry_attempts': 1}, sleep=lambda _: None)
    requests.observed_at = NOW
    boundary = NOW - timedelta(hours=12)
    lock, barrier = threading.Lock(), threading.Barrier(4)
    calls, active = [], {'now': 0, 'peak': 0, 'chunk_calls': 0}

    def response(operation, arguments):
        assert operation == 'LookupEvents'
        lower, upper = arguments['StartTime'], arguments['EndTime']
        name = arguments['LookupAttributes'][0]['AttributeValue']
        with lock:
            calls.append(copy.deepcopy(arguments))
            chunk = lower != NOW-timedelta(days=1) or upper != NOW
            if chunk:
                active['chunk_calls'] += 1
                active['now'] += 1
                active['peak'] = max(active['peak'], active['now'])
            first = chunk and active['chunk_calls'] <= 4
        try:
            if synchronize and first:
                barrier.wait(timeout=5)
            if mode == 'empty':
                return {'Events': []}
            inside = lower < boundary < upper if mode == 'exclusive_endpoints' else lower <= boundary <= upper
            selected = name == 'Decrypt' and inside
            right_slice = lower + (upper-lower)/2 > boundary
            if not selected and not (mode == 'outside_slice' and name == 'Decrypt' and lower == NOW-timedelta(days=1)):
                return {'Events': []}
            if mode == 'denied' and right_slice:
                raise ClientError({'Error': {'Code': 'AccessDeniedException', 'Message': 'synthetic denied'}}, operation)
            if mode != 'sparse' and not arguments.get('NextToken'):
                return {'Events': [], 'NextToken': 'synthetic-page-two'}
            value = event()
            payload = json.loads(value['CloudTrailEvent'])
            payload['eventTime'] = boundary.isoformat()
            payload['additionalEventData']['recipient'].update({
                'attestationDocumentEnclaveImageDigest': '0'*96 if mode == 'debug' else 'ab'*48,
                'attestationDocumentEnclavePCR1': '0'*96 if mode == 'debug' else 'ab'*48,
                'attestationDocumentEnclavePCR2': '0'*96 if mode == 'debug' else 'ab'*48})
            if mode == 'conflicting_boundary' and right_slice:
                payload['additionalEventData']['recipient']['attestationDocumentEnclaveImageDigest'] = 'cd'*48
            value.update(EventTime=boundary, CloudTrailEvent=json.dumps(payload))
            return {'Events': [value, copy.deepcopy(value)] if mode == 'duplicate_in_page' else [value]}
        finally:
            with lock:
                if chunk:
                    active['now'] -= 1

    monkeypatch.setattr(client, '_make_api_call', response)
    monkeypatch.setattr(aws.Requests, 'client', lambda *args, **kwargs: client)
    return requests, session, calls, active


@pytest.mark.parametrize('mode,expected', [('normal', 'PASS'), ('debug', 'FAIL'), ('exclusive_endpoints', 'PASS')])
def test_full_day_parallel_paginated_sdk_history_reaches_frozen_review(monkeypatch, mode, expected):
    requests, session, calls, active = sdk_history(monkeypatch, mode, synchronize=True)
    result = native.events(requests, session, REGION, ACCOUNT)
    assert active['peak'] > 1, 'independent histories must overlap network waits'
    assert result.status == 'collected' and len(result.items) == 1
    row = result.items[0]
    assert row['_provenance']['window_start'] == (NOW-timedelta(days=1)).isoformat()
    assert row['_provenance']['window_end'] == NOW.isoformat()
    for operation in native.OPERATIONS:
        windows = sorted({(r['StartTime'], r['EndTime']) for r in calls
                          if r['LookupAttributes'][0]['AttributeValue'] == operation})
        assert (len(windows) > 1) if operation == 'Decrypt' else (len(windows) == 1)
        if operation == 'Decrypt':
            windows = [window for window in windows if window != (NOW-timedelta(days=1), NOW)]
        assert windows[0][0] == NOW-timedelta(days=1) and windows[-1][1] == NOW
        assert all(left[1] > right[0] for left, right in zip(windows, windows[1:])), 'no internal boundary gap under exclusive endpoints'
        assert all(NOW-timedelta(days=1) <= lower < upper <= NOW for lower, upper in windows)
    findings = evaluate_snapshot(snapshot(result), checks=[CHECK])['findings']
    assert len(findings) == 1 and findings[0]['status'] == expected
    assert 'DO_NOT_RETAIN' not in json.dumps(snapshot(result))
    for future in requests._cache.values():
        assert 'DO_NOT_RETAIN' not in json.dumps(future.result(), default=str)


@pytest.mark.parametrize('mode', ['denied', 'outside_slice', 'duplicate_in_page', 'conflicting_boundary'])
def test_one_bad_slice_never_becomes_complete_or_a_security_verdict(monkeypatch, mode):
    requests, session, _, _ = sdk_history(monkeypatch, mode)
    result = native.events(requests, session, REGION, ACCOUNT)
    assert result.status not in ('empty', 'collected') and result.items == []
    assert all(row['status'] not in ('PASS', 'FAIL')
               for row in evaluate_snapshot(snapshot(result), checks=[CHECK])['findings'])


@pytest.mark.parametrize('mode,expected', [('empty', 'empty'), ('sparse', 'collected')])
def test_short_histories_keep_one_read_per_operation(monkeypatch, mode, expected):
    requests, session, calls, active = sdk_history(monkeypatch, mode)
    result = native.events(requests, session, REGION, ACCOUNT)
    assert result.status == expected
    assert active['chunk_calls'] == 0
    for operation in native.OPERATIONS:
        operation_calls = [r for r in calls if r['LookupAttributes'][0]['AttributeValue'] == operation]
        assert len(operation_calls) == 1
        assert operation_calls[0]['StartTime'] == NOW-timedelta(days=1)
        assert operation_calls[0]['EndTime'] == NOW
