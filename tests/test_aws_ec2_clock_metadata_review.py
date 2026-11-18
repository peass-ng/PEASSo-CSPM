from datetime import datetime, timedelta, timezone
from copy import deepcopy

import boto3
from botocore.stub import Stubber
import pytest

from peaso.collectors import aws, aws_ec2_clock_metadata as clock
from peaso.engine import evaluate_snapshot
from peaso.snapshot import make_snapshot

ACCOUNT = '123456789012'
SCOPE = ACCOUNT + '/us-east-1'
INSTANCE = 'i-0123456789abcdef0'
CHECK = 'aws_ec2_instance_time_offset_monitored'


@pytest.mark.parametrize('offset,expected', [(10, 'PASS'), (2000, 'FAIL'), (-2000, 'FAIL')])
def test_native_metric_requests_through_registered_consumer(offset, expected):
    client = boto3.client('cloudwatch', region_name='us-east-1',
                          aws_access_key_id='testing', aws_secret_access_key='testing')
    request = aws.Requests({'retry_attempts': 1})
    request.client = lambda *args: client
    now = request.observed_at
    parameters = dict(Namespace='CWAgent', MetricName='time_offset',
        Dimensions=[{'Name': 'InstanceId', 'Value': INSTANCE}], StartTime=(now-timedelta(days=1)).replace(second=0, microsecond=0),
        EndTime=now, Period=300, Statistics=['Minimum', 'Maximum'], Unit='Milliseconds')
    response = {'Label': 'time_offset', 'Datapoints': [{'Timestamp': now-timedelta(minutes=5),
        'Minimum': min(0, offset), 'Maximum': max(0, offset), 'Unit': 'Milliseconds'}]}
    with Stubber(client) as stub:
        stub.add_response('get_metric_statistics', response, parameters)
        items = clock.enrich(request, object(), 'us-east-1', [{'InstanceId': INSTANCE, 'State': {'Name': 'running'}}])
        stub.assert_no_pending_responses()
    snapshot = make_snapshot('aws', [SCOPE], [{'type': 'instance', 'scope': SCOPE, 'status': 'collected', 'items': items}])
    result = evaluate_snapshot(snapshot, checks=[CHECK])
    assert [f['status'] for f in result['findings']] == [expected]
    assert request.calls == 1
    assert ('cloudwatch', 'get_metric_statistics') in aws.READ_ACTIONS
    assert 'peaso.collectors.aws_ec2_clock_metadata' in aws.EXTENSION_MODULES


def test_empty_denied_and_wrong_metric_never_fabricate_offset():
    now = datetime.now(timezone.utc)
    for response, status in [({'collection_status': 'denied'}, 'denied'),
                             ({'collection_status': 'collected', 'Label': 'time_offset', 'Datapoints': []}, 'empty'),
                             ({'collection_status': 'collected', 'Label': 'different', 'Datapoints': []}, 'malformed')]:
        sample = clock._sample(response, INSTANCE, now-timedelta(days=1), now)
        assert sample['collection_status'] == status
        assert 'ValueMilliseconds' not in sample


@pytest.mark.parametrize('change', ['future', 'unit', 'nan', 'boolean', 'inverted'])
def test_invalid_datapoints_are_not_accepted(change):
    now = datetime.now(timezone.utc)
    row = {'Timestamp': now-timedelta(minutes=5), 'Minimum': 1, 'Maximum': 2, 'Unit': 'Milliseconds'}
    if change == 'future': row['Timestamp'] = now+timedelta(minutes=1)
    if change == 'unit': row['Unit'] = 'Seconds'
    if change == 'nan': row['Maximum'] = float('nan')
    if change == 'boolean': row['Maximum'] = True
    if change == 'inverted': row['Minimum'] = 3
    raw = {'collection_status': 'collected', 'Label': 'time_offset', 'Datapoints': [row]}
    assert clock._sample(raw, INSTANCE, now-timedelta(days=1), now)['collection_status'] == 'malformed'


def test_nonrunning_instance_never_reads_metric():
    class Requests:
        def detail(self, *args, **kwargs):
            raise AssertionError('stopped instance should not trigger telemetry')
    items = [{'InstanceId': INSTANCE, 'State': {'Name': 'stopped'}}]
    before = deepcopy(items)
    assert clock.enrich(Requests(), object(), 'us-east-1', items) == before
    assert items == before


def test_native_empty_day_is_a_monitoring_failure_without_fabricating_an_offset():
    now = datetime.now(timezone.utc)
    empty = clock._sample({'collection_status': 'collected', 'Label': 'time_offset', 'Datapoints': []}, INSTANCE, now-timedelta(days=1), now)
    def assess(sample):
        snapshot = make_snapshot('aws', [SCOPE], [{'type': 'instance', 'scope': SCOPE, 'status': 'collected',
            'items': [{'InstanceId': INSTANCE, 'State': {'Name': 'running'}, 'TimeOffset': sample}]}], created_at=now.isoformat())
        return evaluate_snapshot(snapshot, checks=[CHECK])['findings'][0]
    finding = assess(empty)
    assert finding['status'] == 'FAIL' and finding['evidence']['monitored'] is False
    assert 'ValueMilliseconds' not in empty
    empty['InstanceId'] = 'i-fffffffffffffffff'
    assert assess(empty)['status'] == 'UNKNOWN'
