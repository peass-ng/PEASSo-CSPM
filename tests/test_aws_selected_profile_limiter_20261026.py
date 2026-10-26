"""Selected configuration reads share the scan's native endpoint admission."""
from concurrent.futures import ThreadPoolExecutor
import threading
import time

import boto3
import botocore.client
from botocore.exceptions import ClientError

from peaso.collectors import aws, aws_request_pool, aws_selected_configuration_secret_indicators as selected


def test_selected_ecs_burst_is_limited_and_keeps_projected_output(monkeypatch):
    region, account = 'us-east-1', '123456789012'
    targets = [
        {'surface': 'ecs_environment', 'scope': account + '/' + region,
         'resource_id': f'arn:aws:ecs:{region}:{account}:task-definition/Family{i}:3'}
        for i in range(12)
    ]
    options = {'content_secret_scans': True, '_content_secret_scan_kinds': [selected.KIND],
               selected.OPTION: targets, 'deadline_seconds': 10}
    requests = aws.Requests(options, sleep=lambda _: None)
    requests.content_secret_scan_kinds = frozenset({selected.KIND})
    selected.initialize(requests, options, [account + '/' + region])
    session = boto3.Session(aws_access_key_id='AKIDEXAMPLE', aws_secret_access_key='example', region_name=region)
    requests.configuration_content_sessions[id(session)] = {
        'account': account, 'partition': 'aws', 'principal': 'test-principal'}
    requests.raw_reads.limiter = aws_request_pool.AdaptiveLimiter(initial=3, maximum=2, cooldown=0.01)
    monkeypatch.setattr(selected, 'scan_content', lambda payload, path, **_: {
        'complete': True, 'engines': {}, 'leaks': []})

    lock = threading.Lock()
    active = peak = throttles = 0

    def transport(client, operation, arguments):
        nonlocal active, peak, throttles
        assert operation == 'DescribeTaskDefinition'
        with lock:
            active += 1
            peak = max(peak, active)
            over_quota = active > 2
            if over_quota:
                throttles += 1
        try:
            time.sleep(0.006)
            if over_quota:
                raise ClientError({'Error': {'Code': 'ThrottlingException', 'Message': 'quota'},
                                   'ResponseMetadata': {'HTTPStatusCode': 429}}, operation)
            arn = arguments['taskDefinition']
            return {'ResponseMetadata': {'HTTPStatusCode': 200, 'RequestId': 'offline-request-1'},
                    'taskDefinition': {'taskDefinitionArn': arn, 'family': arn.split('/')[-1].split(':')[0],
                                       'revision': 3, 'status': 'ACTIVE',
                                       'containerDefinitions': [{'name': 'app', 'environment': [
                                           {'name': 'MODE', 'value': 'production'}]}]}}
        finally:
            with lock:
                active -= 1

    monkeypatch.setattr(botocore.client.BaseClient, '_make_api_call', transport)

    def read(target):
        service, operation, arguments = selected.route(target)
        return requests.call(session, service, region, operation,
                             _metadata_profile=selected.PROFILE, **arguments)

    with ThreadPoolExecutor(max_workers=12) as executor:
        output = list(executor.map(read, targets))

    assert [item['id'] for item in output] == [selected.identity(target) for target in targets]
    assert all(item[selected.MARKER]['status'] == 'collected' and
               item[selected.MARKER]['complete'] is True and
               item[selected.MARKER]['literal_count'] == 1 for item in output)
    assert 2 <= peak <= 3
    assert 1 <= throttles <= 2
    assert requests.raw_reads.limiter.throttles == throttles
    assert requests.raw_reads.limiter.waits > 0
    assert requests.calls == len(targets) + throttles
    # The first retry stays in bfa18228's original three-attempt budget.
    assert requests.throttle_retries == 0
