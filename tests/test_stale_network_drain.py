"""Only a durable newer final Network revision may stop an owned review."""
import json
import threading
from types import SimpleNamespace

import boto3
import pytest

from peaso import progressive_analyzer as watcher
from peaso.storage.sqlite import SQLiteStore
from peaso.storage.dynamodb import DynamoStore, attrs
from tests.test_progressive_analyzer_20261022 import FakeArtifacts, FakeStore

TENANT, SCAN = 'tenant-a', 'a' * 32


def _job():
    return dict(id=SCAN, tenant=TENANT, connector_id='connector', data='{}',
                connector=json.dumps({'data': {'provider': 'k8s'}}), status='collecting',
                created=1000, deadline=2000, owner='owner-1', lease=1500, history=[])


@pytest.mark.parametrize('section,phase,stale', [
    ({'status': 'complete', 'data_revision': 2}, 'analyzing', True),
    ({'status': 'complete', 'data_revision': 1}, 'analyzing', False),
    ({'status': 'complete', 'data_revision': 0}, 'analyzing', False),
    ({'status': 'running', 'data_revision': 2}, 'analyzing', False),
    ({'status': 'complete', 'data_revision': True}, 'analyzing', False),
    ({'status': 'complete', 'data_revision': '2'}, 'analyzing', False),
    ({}, 'analyzing', False),
    ({'status': 'complete', 'data_revision': 2}, 'collecting', False),
    ({'status': 'complete', 'data_revision': 2}, 'unavailable', False),
])
def test_durable_revision_stops_only_stale_child_and_drains_before_final(
        monkeypatch, section, phase, stale):
    store, artifacts = FakeStore(), FakeArtifacts()
    artifacts.values['report-json']['publication']['sections']['network'] = {
        'status': 'complete', 'data_revision': 1}
    final_snapshot = {'metadata': {'sections': {'network': section}},
                      'resources': [{'id': 'full-final-only-resource'}]}
    artifacts.values['final-snapshot'] = final_snapshot
    artifacts.values['final-report'] = {'publication': {
        'state': 'partial', 'phase': phase, 'sections': {'network': section}}}
    if phase == 'unavailable':
        del artifacts.values['final-report']
    tasks, abandoned, finished = [], [], []
    original_finish = store.finish_stage
    def finish(*args):
        finished.append(args)
        return original_finish(*args)
    store.finish_stage = finish
    def abandon(tenant, ident, stage, revision, owner):
        assert not tasks[0].alive and tasks[0].closed
        assert store.leases[stage] == (revision, owner)
        abandoned.append((stage, revision))
        del store.leases[stage]
        return True
    store.abandon_stage = abandon

    class Task:
        def __init__(self, *args):
            self.process = self
            self.alive, self.closed, self.stops, self.ready = True, False, 0, False
            self.kills = 0
            tasks.append(self)
        def start(self): pass
        def request_stop(self): self.stops += 1
        def poll(self):
            # A late result/EOF must not bypass cancellation cleanup.
            return 'late-stale-result' if self.ready else watcher._PENDING
        def is_alive(self): return self.alive
        def close(self): self.closed = True
        def join(self, timeout=None): pass
        def kill(self):
            self.kills += 1
            self.alive = False

    def final(*args, stage_poll=None):
        assert len(tasks) == 1
        task = tasks[0]
        control = dict(store.row, status='analyzing')
        event = {'report_ref': 'final-report', 'snapshot_ref': 'final-snapshot'}
        # A newer collecting checkpoint alone cannot authorize cancellation.
        assert not stage_poll(control)
        assert task.stops == 0
        assert not stage_poll(control, native_checkpoint=event)
        assert task.stops == int(stale)
        task.ready = True
        if stale:
            assert not stage_poll(control, native_checkpoint=event)
            assert not abandoned and not task.closed
            assert task.stops == 1  # signal once, keep ownership while draining
        task.alive = False
        assert stage_poll(control, native_checkpoint=event)
        assert task.closed
        assert abandoned == ([('network', 1)] if stale else [])
        assert len(finished) == (0 if stale else 1)
        if stale:
            # No stale result can enter final reuse; full final input is intact.
            from peaso.worker import _reusable_stages
            assert _reusable_stages(artifacts, 'tenant', {'network': section},
                                    store.stage_results('tenant', 'scan')) == {}
        assert artifacts.get('tenant', 'final-snapshot') == final_snapshot
        store.row['status'] = 'completed'

    worker = SimpleNamespace(role='analyzer', store=store, artifacts=artifacts,
        settings=SimpleNamespace(lease_seconds=30), stopping=threading.Event(), run_once=final)
    # Launch exactly one progressive call, then enter final handoff.
    def start(task):
        store.row['status'] = 'collected'
    monkeypatch.setattr(Task, 'start', start)
    monkeypatch.setattr(watcher, '_StageProcess', Task)
    assert watcher.run_progressive(worker, 'tenant', 'scan', poll_seconds=0) == 'completed'
    assert len(tasks) == 1
    assert tasks[0].kills == 0


def exercise_abandon(store):
    owner, foreign = '2' * 32, '3' * 32
    assert store.claim_stage(TENANT, SCAN, 'network', 1, owner, 30, now=1100)
    assert not store.abandon_stage(TENANT, SCAN, 'network', 1, foreign)
    assert not store.abandon_stage(TENANT, SCAN, 'network', 0, owner)
    assert store.abandon_stage(TENANT, SCAN, 'network', 1, owner)
    assert not store.abandon_stage(TENANT, SCAN, 'network', 1, owner)
    assert not store.stage_results(TENANT, SCAN)
    # An expired cancelled claim cannot relaunch the obsolete revision.
    assert not store.claim_stage(TENANT, SCAN, 'network', 1, foreign, 30, now=1200)
    assert store.claim_stage(TENANT, SCAN, 'network', 2, foreign, 30, now=1200)
    # Delayed old-child cleanup cannot delete a newer owner's claim.
    assert not store.abandon_stage(TENANT, SCAN, 'network', 1, owner)
    assert store.heartbeat_stage(TENANT, SCAN, 'network', 2, foreign, 30, now=1201)


def test_sqlite_abandon_fenced_and_no_same_revision_replay(tmp_path):
    store = SQLiteStore(tmp_path)
    with store.transaction() as db:
        row = _job()
        keys = ('id', 'tenant', 'connector_id', 'data', 'connector', 'status',
                'created', 'deadline', 'owner', 'lease', 'history')
        db.execute('INSERT INTO jobs(' + ','.join(keys) + ') VALUES(?,?,?,?,?,?,?,?,?,?,?)',
                   tuple(json.dumps(row[k]) if k == 'history' else row[k] for k in keys))
    exercise_abandon(store)


def test_dynamo_abandon_fenced_and_no_same_revision_replay():
    moto = pytest.importorskip('moto')
    with moto.mock_aws():
        client = boto3.client('dynamodb', region_name='us-east-1')
        client.create_table(TableName='stale-stage', KeySchema=[
            {'AttributeName': 'PK', 'KeyType': 'HASH'}, {'AttributeName': 'SK', 'KeyType': 'RANGE'}],
            AttributeDefinitions=[{'AttributeName': k, 'AttributeType': 'S'} for k in ('PK', 'SK')],
            BillingMode='PAY_PER_REQUEST')
        store = DynamoStore('stale-stage', client)
        store.clock = lambda: 1100
        client.put_item(TableName=store.table, Item=attrs(dict(store.key(TENANT, 'job', SCAN), **_job())))
        exercise_abandon(store)


@pytest.mark.parametrize('code,expected', [(None, True), ('ConditionalCheckFailedException', False)])
def test_dynamo_abandon_request_is_exact_owner_revision_running_condition(code, expected):
    from botocore.stub import Stubber
    client = boto3.client('dynamodb', region_name='us-east-1',
                          aws_access_key_id='inert', aws_secret_access_key='inert')
    store = DynamoStore('stale-stage', client)
    owner = '2' * 32
    parameters = dict(TableName=store.table, Key=attrs(store._stage_key(TENANT, SCAN, 'network')),
        UpdateExpression='SET #status=:cancelled,#owner=:null,lease=:null,result_ref=:null',
        ConditionExpression='data_revision=:revision AND #status=:running AND #owner=:owner',
        ExpressionAttributeNames={'#status': 'status', '#owner': 'owner'},
        ExpressionAttributeValues=attrs({':revision': 1, ':running': 'running',
            ':cancelled': 'cancelled', ':owner': owner, ':null': None}))
    with Stubber(client) as stub:
        if code:
            stub.add_client_error('update_item', service_error_code=code, expected_params=parameters)
        else:
            stub.add_response('update_item', {}, parameters)
        assert store.abandon_stage(TENANT, SCAN, 'network', 1, owner) is expected
        stub.assert_no_pending_responses()
