"""Calendar behavior and real SQLite/DynamoDB adapter dispatch, without cloud calls."""
from datetime import datetime
import json
import threading
from types import SimpleNamespace

import pytest
from pydantic import ValidationError
from fastapi.testclient import TestClient

from peaso.scheduling import next_run
from peaso.server.models import ScheduleCreate
from peaso.storage.sqlite import SQLiteStore
from peaso.worker import Worker
from peaso.server.config import Settings
from peaso.server import create_app
from test_peaso_api import TestIdentities


def stamp(value):
    return datetime.fromisoformat(value.replace('Z', '+00:00')).timestamp()


@pytest.mark.parametrize('data,after,expected', [
    ({'timezone': 'UTC', 'rules': [{'frequency': 'daily', 'time': '09:30'}]}, '2026-10-19T09:29:59Z', '2026-10-19T09:30:00Z'),
    ({'timezone': 'UTC', 'rules': [{'frequency': 'daily', 'time': '09:30'}]}, '2026-10-19T09:30:00Z', '2026-10-20T09:30:00Z'),
    ({'timezone': 'Europe/Madrid', 'rules': [{'frequency': 'weekly', 'time': '09:00', 'weekdays': [0, 2, 4]}]}, '2026-10-19T08:00:00Z', '2026-10-21T07:00:00Z'),
    ({'timezone': 'UTC', 'rules': [{'frequency': 'monthly', 'time': '12:15', 'day_of_month': 31}]}, '2026-01-31T12:15:00Z', '2026-02-28T12:15:00Z'),
    ({'timezone': 'UTC', 'rules': [{'frequency': 'monthly', 'time': '12:15', 'day_of_month': 31}]}, '2028-02-01T00:00:00Z', '2028-02-29T12:15:00Z'),
    ({'timezone': 'UTC', 'rules': [{'frequency': 'monthly', 'time': '00:00', 'day_of_month': 1}]}, '2026-12-31T23:59:59Z', '2027-01-01T00:00:00Z'),
    # Spring gap02:30 advances to03:30; autumn02:30 is the first occurrence only.
    ({'timezone': 'Europe/Madrid', 'rules': [{'frequency': 'daily', 'time': '02:30'}]}, '2026-03-28T23:00:00Z', '2026-03-29T01:30:00Z'),
    ({'timezone': 'Europe/Madrid', 'rules': [{'frequency': 'daily', 'time': '02:30'}]}, '2026-10-24T22:00:00Z', '2026-10-25T00:30:00Z'),
    ({'timezone': 'Europe/Madrid', 'rules': [{'frequency': 'daily', 'time': '02:30'}]}, '2026-10-25T00:30:00Z', '2026-10-26T01:30:00Z'),
    ({'timezone': 'Asia/Kolkata', 'rules': [{'frequency': 'daily', 'time': '00:15'}]}, '2026-10-19T18:30:00Z', '2026-10-19T18:45:00Z'),
])
def test_calendar_wall_clock_and_boundaries(data, after, expected):
    assert next_run(data, stamp(after)) == stamp(expected)


def test_union_deduplicates_matching_rules_and_keeps_later_rules():
    data = {'timezone': 'UTC', 'rules': [
        {'frequency': 'daily', 'time': '09:00'},
        {'frequency': 'weekly', 'weekdays': [0], 'time': '09:00'},
        {'frequency': 'monthly', 'day_of_month': 19, 'time': '16:30'},
    ]}
    assert next_run(data, stamp('2026-10-19T08:00:00Z')) == stamp('2026-10-19T09:00:00Z')
    assert next_run(data, stamp('2026-10-19T09:00:00Z')) == stamp('2026-10-19T16:30:00Z')


@pytest.mark.parametrize('patch', [
    {'rules': []}, {'rules': [{'frequency': 'hourly', 'time': '09:00'}]},
    {'rules': [{'frequency': 'daily', 'time': '25:00'}]},
    {'rules': [{'frequency': 'weekly', 'time': '09:00', 'weekdays': []}]},
    {'rules': [{'frequency': 'weekly', 'time': '09:00', 'weekdays': [1, 1]}]},
    {'rules': [{'frequency': 'weekly', 'time': '09:00', 'weekdays': [7]}]},
    {'rules': [{'frequency': 'weekly', 'time': '09:00', 'weekdays': [True]}]},
    {'rules': [{'frequency': 'monthly', 'time': '09:00', 'day_of_month': 0}]},
    {'rules': [{'frequency': 'monthly', 'time': '09:00', 'day_of_month': 32}]},
    {'rules': [{'frequency': 'daily', 'time': '09:00', 'day_of_month': 1}]},
    {'rules': [{'frequency': 'daily', 'time': '09:00'}] * 21},
    {'timezone': 'Not/A_Zone'}, {'timezone': '../etc/passwd'},
])
def test_invalid_calendar_input_cannot_be_saved(patch):
    with pytest.raises(ValidationError):
        ScheduleCreate(connector_id='fixture', **patch)


@pytest.fixture(params=['sqlite', 'dynamodb'])
def store(request, tmp_path):
    if request.param == 'sqlite':
        yield SQLiteStore(tmp_path/'state')
    else:
        moto = pytest.importorskip('moto')
        import boto3
        from peaso.storage.dynamodb import DynamoStore
        with moto.mock_aws():
            client = boto3.client('dynamodb', region_name='us-east-1')
            client.create_table(TableName='calendar', KeySchema=[{'AttributeName': 'PK', 'KeyType': 'HASH'}, {'AttributeName': 'SK', 'KeyType': 'RANGE'}],
                AttributeDefinitions=[{'AttributeName': 'PK', 'AttributeType': 'S'}, {'AttributeName': 'SK', 'AttributeType': 'S'}], BillingMode='PAY_PER_REQUEST')
            instance = DynamoStore('calendar', client)
            yield instance


def pin_clock(store, now):
    # Jobs carry a retention TTL; read them at the fixture's date, not the wall clock.
    if hasattr(store, 'clock'):
        store.clock = lambda: now


def new_schedule(store):
    connector = store.add_connector('alice', {'provider': 'aws', 'name': 'Calendar'}, 'ciphertext')
    data = {'connector_id': connector['id'], 'ai_enabled': False, 'timezone': 'UTC', 'rules': [
        {'frequency': 'daily', 'time': '09:00'}, {'frequency': 'daily', 'time': '17:00'}]}
    item = store.add_schedule('alice', data, stamp('2026-10-19T09:00:00Z'))
    return item, data


def test_both_storage_adapters_dispatch_and_advance_to_next_calendar_rule(store):
    item, data = new_schedule(store)
    now = stamp('2026-10-19T09:00:35Z')
    pin_clock(store, now)
    due = store.due_schedules(now)[0]
    job = store.trigger_schedule(due, limit=10, now=now)
    assert job['connector_id'] == data['connector_id']
    store.trigger_schedule(due, limit=10, now=now)
    assert len(store.jobs('alice')) == 1
    saved = store.schedules('alice')[0]
    assert saved['next_run_at'] == '2026-10-19T17:00:00+00:00'
    assert saved['rules'] == data['rules']
    assert store.schedules('bob') == []


def test_both_storage_adapters_coalesce_missed_runs_and_preserve_calendar_on_quota_failure(store):
    item, data = new_schedule(store)
    now = stamp('2026-10-23T12:00:00Z')
    pin_clock(store, now)
    due = store.due_schedules(now)[0]
    # Fill the current weekly quota before the delayed schedule is dispatched.
    store.enqueue('alice', {'connector_id': data['connector_id']}, limit=1, now=now)
    assert store.trigger_schedule(due, limit=1, now=now) is None
    saved = store.schedules('alice')[0]
    assert saved['next_run_at'] == '2026-10-23T17:00:00+00:00'
    assert saved['last_error'] == 'Weekly scan quota exhausted'
    assert len(store.jobs('alice')) == 1


def test_edit_and_resume_recalculate_the_upcoming_run_in_both_adapters(store, monkeypatch):
    item, data = new_schedule(store)
    now = stamp('2026-10-19T12:00:00Z')
    monkeypatch.setattr('time.time', lambda: now)
    changed = store.update_schedule('alice', item['id'], {'rules': [{'frequency': 'weekly', 'weekdays': [2], 'time': '11:00'}]})
    assert changed['next_run_at'] == '2026-10-21T11:00:00+00:00'
    store.update_schedule('alice', item['id'], {}, enabled=False)
    monkeypatch.setattr('time.time', lambda: stamp('2026-10-22T12:00:00Z'))
    resumed = store.update_schedule('alice', item['id'], {}, enabled=True)
    assert resumed['next_run_at'] == '2026-10-28T11:00:00+00:00'


def test_calendar_api_create_edit_reload_and_tenant_boundaries(tmp_path, monkeypatch):
    settings = Settings(state_dir=tmp_path/'state', identity_dir=tmp_path/'identity', local_token='calendar-fixture-token-12345678')
    monkeypatch.setattr('time.time', lambda: stamp('2026-10-19T08:00:00Z'))
    with TestClient(create_app(settings, authenticator=TestIdentities()), base_url='http://127.0.0.1') as client:
        client.headers['Authorization'] = 'Bearer alice'
        connector = client.post('/api/connectors', json={'name': 'Calendar', 'provider': 'aws', 'options': {'demo': True}}).json()
        data = {'connector_id': connector['id'], 'ai_enabled': False, 'timezone': 'UTC', 'rules': [
            {'frequency': 'daily', 'time': '09:00'}, {'frequency': 'monthly', 'time': '18:30', 'day_of_month': 31}]}
        response = client.post('/api/schedules', json=data)
        assert response.status_code == 201, response.text
        saved = response.json()
        assert saved['next_run_at'] == '2026-10-19T09:00:00+00:00'
        assert client.get('/api/schedules').json()['items'][0]['rules'] == saved['rules']
        response = client.patch('/api/schedules/'+saved['id'], json={'rules': [{'frequency': 'weekly', 'weekdays': [4], 'time': '10:00'}]})
        assert response.status_code == 200 and response.json()['next_run_at'] == '2026-10-23T10:00:00+00:00'
        client.headers['Authorization'] = 'Bearer bob'
        assert client.get('/api/schedules').json()['items'] == []
        assert client.patch('/api/schedules/'+saved['id'], json={'enabled': False}).status_code == 404


def test_local_scheduler_still_ticks_while_collection_is_busy():
    worker = object.__new__(Worker)
    worker.role = 'collector'
    worker.stopping = threading.Event()
    tick = threading.Event()
    collecting = threading.Event()
    worker.schedule_tick = lambda: tick.set() if collecting.wait(2) else None
    def busy_collection():
        collecting.set()
        assert tick.wait(2), 'The scheduler must not wait for the scan to finish'
        worker.stopping.set()
        return True
    worker.run_once = busy_collection
    worker.run()
    assert tick.is_set()


def test_hosted_scheduler_handler_dispatches_calendar_occurrence(store, tmp_path, monkeypatch):
    from peaso.server import scheduler_handler
    from peaso.storage.runtime import WorkflowDispatcher
    item, data = new_schedule(store)
    now = stamp('2026-10-19T09:00:20Z')
    monkeypatch.setattr('time.time', lambda: now)
    pin_clock(store, now)
    worker = Worker('collector', Settings(state_dir=tmp_path/'worker-state', identity_dir=tmp_path/'identity'),
        store=store, artifacts=SimpleNamespace(), authenticator=SimpleNamespace(is_paid=lambda tenant: True))
    # The scheduler now checks actual saved credentials before dispatch. Keep
    # this calendar-only fixture offline and encrypted with its worker's key.
    store.update_connector('alice', data['connector_id'], {'input_mode': 'demo'},
        worker.cipher.encrypt({'auth': {}, 'options': {'demo': True}}))
    dispatched = []
    monkeypatch.setattr(scheduler_handler, 'Worker', lambda role: worker)
    monkeypatch.setattr(WorkflowDispatcher, 'dispatch', lambda self, tenant, job: dispatched.append((tenant, job['id'])) or True)
    result = scheduler_handler.handler({}, None)
    assert result['scheduled'] == 1
    assert len(store.jobs('alice')) == 1
    assert len(set(dispatched)) == 1
    assert store.schedules('alice')[0]['next_run_at'] == '2026-10-19T17:00:00+00:00'
