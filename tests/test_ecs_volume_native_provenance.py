"""Directed registered ECS check and inert SDK collector tests; no cloud credentials."""
from __future__ import annotations
import copy

import pytest
import boto3
from botocore.stub import Stubber
from peaso.checks import evaluate_check
from peaso.collectors.aws import ReadResult
from peaso.collectors.aws_facts_compute_edge import _ecs_service

ACCOUNT = '123456789012'
REGION = 'us-east-1'
SCOPE = ACCOUNT + '/' + REGION
CLUSTER = f'arn:aws:ecs:{REGION}:{ACCOUNT}:cluster/c'
SERVICE = f'arn:aws:ecs:{REGION}:{ACCOUNT}:service/c/s'
TASK = f'arn:aws:ecs:{REGION}:{ACCOUNT}:task-definition/t:1'
CHECK = 'aws_g6_ecs_fargate_storage_encryption'


class Requests:
    def __init__(self, client): self.client = client
    def pages(self, session, service, region, operation, expression, **kwargs):
        assert service == 'ecs' and region == REGION
        rows = getattr(self.client, operation)(**kwargs)[expression]
        return ReadResult(rows, 'collected' if rows else 'empty')
    def call(self, session, service, region, operation, **kwargs):
        assert service == 'ecs' and region == REGION
        return getattr(self.client, operation)(**kwargs)


def collect(native=None, *, denied=False, duplicate=False, omitted=False, missing=False):
    client = boto3.client('ecs', region_name=REGION, aws_access_key_id='stub', aws_secret_access_key='stub')
    row = copy.deepcopy(native) if native is not None else {
        'serviceArn': SERVICE, 'clusterArn': CLUSTER, 'taskDefinition': TASK,
        'deployments': [{'status': 'PRIMARY', 'taskDefinition': TASK}]}
    with Stubber(client) as stub:
        stub.add_response('list_clusters', {'clusterArns': [CLUSTER]}, {})
        stub.add_response('list_services', {'serviceArns': [SERVICE]}, {'cluster': CLUSTER})
        if denied:
            stub.add_client_error('describe_services', 'AccessDeniedException', expected_params={'cluster': CLUSTER, 'services': [SERVICE]})
        else:
            stub.add_response('describe_services', {'services': [] if omitted or missing else ([row, copy.deepcopy(row)] if duplicate else [row]),
                               'failures': [{'arn': SERVICE, 'reason': 'MISSING'}] if missing else []},
                              {'cluster': CLUSTER, 'services': [SERVICE]})
        result = _ecs_service(Requests(client), None, REGION, ACCOUNT)
        stub.assert_no_pending_responses()
    return result


def deployment(*, name=None, encrypted=True, task=TASK):
    record = {'status': 'PRIMARY', 'taskDefinition': task}
    if name is not None:
        record['volumeConfigurations'] = [{'name': name, 'managedEBSVolume': {
            'roleArn': f'arn:aws:iam::{ACCOUNT}:role/ecsInfrastructureRole', 'encrypted': encrypted}}]
    return record


def native(*, deployments=None, service=SERVICE, cluster=CLUSTER, task=TASK):
    return {'serviceArn': service, 'clusterArn': cluster, 'taskDefinition': task,
            'deployments': deployments if deployments is not None else [deployment()]}


def facts(service_rows, *, volumes=None, efs=None, service_status='collected', outer=TASK, inner=TASK,
          detail_status='collected'):
    subject = {'clusterArn': CLUSTER}
    definition = {'taskDefinitionArn': outer, 'Definition': {'collection_status': detail_status,
                  'taskDefinition': {'taskDefinitionArn': inner, 'volumes': volumes if volumes is not None else []}}}
    groups = {'ecs_cluster': [subject], 'ecs_service': service_rows, 'ecs_task_definition': [definition],
              'efs_file_system': efs or []}
    idx = {'context': {'provider': 'aws', 'scope': SCOPE}, 'collections': {}}
    for kind, rows in groups.items():
        status = service_status if kind == 'ecs_service' else ('collected' if rows else 'empty')
        idx['collections'][kind] = [{'type': kind, 'scope': SCOPE, 'status': status, 'items': rows}]
        idx[kind] = [{'type': kind, 'scope': SCOPE, 'data': row} for row in rows]
    return subject, idx


def verdict(collection, **kwargs):
    subject, idx = facts(collection.items, service_status=collection.status, **kwargs)
    return evaluate_check(CHECK, subject, idx)[0]


def test_sdk_shaped_primary_omission_pass_and_launch_missing_unknown():
    got = collect()
    assert got.status == 'collected'
    row = got.items[0]
    assert row['volumeConfigurations'] == []
    assert row['_coverage']['volumeConfigurations']['native_member_present'] is False
    assert verdict(got) == 'PASS'
    assert verdict(got, volumes=[{'name': 'data', 'configuredAtLaunch': True}]) == 'UNKNOWN'


def test_sdk_shaped_ebs_efs_and_exact_name_join():
    volume = [{'name': 'data', 'configuredAtLaunch': True}]
    assert verdict(collect(native(deployments=[deployment(name='data', encrypted=True)])), volumes=volume) == 'PASS'
    assert verdict(collect(native(deployments=[deployment(name='data', encrypted=False)])), volumes=volume) == 'FAIL'
    assert verdict(collect(native(deployments=[deployment(name='other')])), volumes=volume) == 'UNKNOWN'
    efs_volume = [{'name': 'efs', 'efsVolumeConfiguration': {'fileSystemId': 'fs-123'}}]
    got = collect()
    assert verdict(got, volumes=efs_volume, efs=[{'FileSystemId': 'fs-123', 'Encrypted': True}]) == 'PASS'
    assert verdict(got, volumes=efs_volume, efs=[{'FileSystemId': 'fs-123', 'Encrypted': False}]) == 'FAIL'
    assert verdict(got, volumes=efs_volume) == 'UNKNOWN'


def test_denied_null_and_nested_fact_coverage_remain_unknown():
    assert verdict(collect(denied=True)) == 'UNKNOWN'
    got = collect()
    for broken in (
        [{'name': 'data', 'configuredAtLaunch': None}],
        [{'name': 'data', '_coverage': {'configuredAtLaunch': {'status': 'denied'}}}],
        [{'name': 'efs', '_coverage': {'efsVolumeConfiguration': {'status': 'denied'}}}],
    ):
        assert verdict(got, volumes=broken) == 'UNKNOWN'
    row = copy.deepcopy(got.items[0])
    row['_coverage']['volumeConfigurations']['status'] = 'denied'
    assert verdict(ReadResult([row], 'collected')) == 'UNKNOWN'
    row = copy.deepcopy(got.items[0])
    row['volumeConfigurations'] = None
    assert verdict(ReadResult([row], 'collected')) == 'UNKNOWN'


def test_collector_never_overwrites_selected_denied_nested_marker():
    class DecoratedRequests:
        def pages(self, session, service, region, operation, expression, **kwargs):
            if operation == 'list_clusters': return ReadResult([CLUSTER], 'collected')
            if operation == 'list_services': return ReadResult([SERVICE], 'collected')
            raise AssertionError(operation)
        def call(self, session, service, region, operation, **kwargs):
            row = native()
            row['deployments'][0]['_coverage'] = {'volumeConfigurations': {'status': 'denied'}}
            return {'services': [row], 'failures': []}
    got = _ecs_service(DecoratedRequests(), None, REGION, ACCOUNT)
    assert got.status == 'collected'
    assert 'volumeConfigurations' not in got.items[0]
    assert verdict(got) == 'UNKNOWN'
    class ServiceMarkedRequests(DecoratedRequests):
        def call(self, session, service, region, operation, **kwargs):
            row = native()
            row['_coverage'] = {'deployments': {'status': 'denied'}}
            return {'services': [row], 'failures': []}
    got = _ecs_service(ServiceMarkedRequests(), None, REGION, ACCOUNT)
    assert 'volumeConfigurations' not in got.items[0]
    assert verdict(got) == 'UNKNOWN'


def test_foreign_duplicate_stale_task_and_rolling_remain_unknown():
    foreign = collect(native(service=SERVICE.replace(ACCOUNT, '999999999999')))
    assert foreign.status == 'malformed' and verdict(foreign) == 'UNKNOWN'
    duplicate = collect(duplicate=True)
    assert duplicate.status == 'malformed' and not duplicate.items and verdict(duplicate) == 'UNKNOWN'
    assert verdict(collect(), outer=TASK.replace(ACCOUNT, '999999999999')) == 'UNKNOWN'
    assert verdict(collect(), inner=TASK.replace(ACCOUNT, '999999999999')) == 'UNKNOWN'
    assert verdict(collect(), inner=TASK.replace(REGION, 'eu-west-1')) == 'UNKNOWN'
    assert verdict(collect(), detail_status='denied') == 'UNKNOWN'
    subject, idx = facts(collect().items)
    idx['ecs_task_definition'][0]['data']['Definition']['taskDefinition']['_coverage'] = {
        'taskDefinitionArn': {'status': 'denied'}}
    assert evaluate_check(CHECK, subject, idx)[0] == 'UNKNOWN'
    assert verdict(collect(native(deployments=[deployment(task=TASK.replace('t:1', 't:2'))]))) == 'UNKNOWN'
    extra = {'status': 'ACTIVE', 'taskDefinition': TASK.replace('t:1', 't:2'), 'runningCount': 1, 'pendingCount': 0}
    assert verdict(collect(native(deployments=[deployment(), extra]))) == 'UNKNOWN'
    extra.pop('runningCount')
    assert verdict(collect(native(deployments=[deployment(), extra]))) == 'UNKNOWN'


def test_listed_service_requires_response_or_explicit_missing_failure():
    incomplete = collect(omitted=True)
    assert incomplete.status == 'partial' and incomplete.items == []
    assert verdict(incomplete) == 'UNKNOWN'
    deleted = collect(missing=True)
    assert deleted.status == 'empty' and deleted.items == []
    assert verdict(deleted) == 'PASS'


@pytest.mark.parametrize("encrypted,expected", [(True, "PASS"), (False, "FAIL"), (None, "UNKNOWN")])
def test_current_service_revision_native_volume_binding(encrypted, expected):
    from types import SimpleNamespace
    from peaso.snapshot import freeze
    revision = f'arn:aws:ecs:{REGION}:{ACCOUNT}:service-revision/c/s/123'
    class NativeRequests:
        def pages(self, session, service, region, operation, expression, **kwargs):
            return ReadResult([CLUSTER] if operation == 'list_clusters' else [SERVICE], 'collected')
        def call(self, session, service, region, operation, **kwargs):
            if operation == 'describe_services':
                return {'services': [{'serviceArn': SERVICE, 'clusterArn': CLUSTER, 'taskDefinition': TASK,
                    'currentServiceRevisions': [{'arn': revision, 'requestedTaskCount': 1, 'runningTaskCount': 1, 'pendingTaskCount': 0}]}], 'failures': []}
            assert operation == 'describe_service_revisions' and kwargs == {'serviceRevisionArns': [revision]}
            if encrypted is None:
                raise PermissionError('native detail unavailable')
            return {'serviceRevisions': [{'serviceRevisionArn': revision, 'serviceArn': SERVICE, 'clusterArn': CLUSTER,
                'taskDefinition': TASK, 'volumeConfigurations': [{'name': 'data', 'managedEBSVolume': {'encrypted': encrypted}}]}], 'failures': []}
    session = SimpleNamespace(get_partition_for_region=lambda _: 'aws')
    captured = _ecs_service(NativeRequests(), session, REGION, ACCOUNT)
    captured.items = freeze(captured.items)
    assert verdict(captured, volumes=[{'name': 'data', 'configuredAtLaunch': True}]) == expected
