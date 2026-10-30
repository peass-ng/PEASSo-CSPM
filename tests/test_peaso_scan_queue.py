"""Durable queue admission and execution clocks on both storage adapters."""
from concurrent.futures import ThreadPoolExecutor
import time
from types import SimpleNamespace

import pytest

from peaso.storage.sqlite import SQLiteStore


@pytest.fixture(params=["sqlite", "dynamodb"])
def store(request, tmp_path):
    if request.param == "sqlite":
        yield SQLiteStore(tmp_path)
        return
    boto3 = pytest.importorskip("boto3")
    moto = pytest.importorskip("moto")
    from peaso.storage.dynamodb import DynamoStore
    with moto.mock_aws():
        client = boto3.client("dynamodb", region_name="us-east-1")
        client.create_table(TableName="queue", KeySchema=[{"AttributeName": "PK", "KeyType": "HASH"},
                                                    {"AttributeName": "SK", "KeyType": "RANGE"}],
                            AttributeDefinitions=[{"AttributeName": "PK", "AttributeType": "S"},
                                                  {"AttributeName": "SK", "AttributeType": "S"}],
                            BillingMode="PAY_PER_REQUEST")
        yield DynamoStore("queue", _SerializedClient(client))


class _SerializedClient:
    """Apply each request atomically, as the DynamoDB service does.

    moto's transact_write_items snapshots and restores whole tables without a
    lock, so a concurrently cancelled transaction can roll back another
    thread's committed write. Serializing requests keeps every racing call
    (and the store's own retry logic) while removing that emulator-only race.
    """

    def __init__(self, client):
        import threading
        self._client, self._lock = client, threading.RLock()

    def __getattr__(self, name):
        value = getattr(self._client, name)
        if not callable(value) or name.startswith("_"):
            return value
        def call(*args, **kwargs):
            with self._lock:
                return value(*args, **kwargs)
        return call


def jobs(store, now, count=11):
    connectors = {tenant: store.add_connector(tenant, {"provider": "aws"}, "inert")
                  for tenant in ("alice", "bob")}
    return [(tenant := ("alice" if index % 2 else "bob"),
             store.enqueue(tenant, {"connector_id": connectors[tenant]["id"]},
                           limit=20, timeout=120, now=now + index / 1000))
            for index in range(count)]


def test_eleven_requests_queue_then_get_full_execution_window(store):
    now = time.time()
    entries = jobs(store, now)
    for tenant, job in entries[:10]:
        assert store.admit(tenant, job["id"], now=now + 10)
    tenant, waiting = entries[10]
    assert not store.admit(tenant, waiting["id"], now=now + 10)
    assert store.job(tenant, waiting["id"])["status"] == "queued"
    assert sum(store.job(owner, job["id"]).get("admitted_at") is not None for owner, job in entries) == 10
    first_tenant, first = entries[0]
    store.cancel(first_tenant, first["id"])
    assert store.admit(tenant, waiting["id"], now=now + 80)
    admitted = store.job(tenant, waiting["id"])
    assert admitted["deadline"] == pytest.approx(now + 200)
    assert store.usage("alice") + store.usage("bob") == 11


def test_waiting_expires_at_one_hour_without_using_execution_deadline(store):
    now = time.time()
    tenant, job = jobs(store, now, 1)[0]
    assert not store.expire_job(tenant, job["id"], now + 3599)
    assert store.expire_job(tenant, job["id"], now + 3600)
    final = store.public_job(store.job(tenant, job["id"]))
    assert final["status"] == final["error_code"] == "queue_exhausted"
    assert final["error"].startswith("Queue exhausted")
    assert not store.admit(tenant, job["id"], now=now + 3601)


def test_racing_admissions_do_not_oversubscribe_or_double_reserve(store):
    now = time.time()
    entries = jobs(store, now, 11)
    with ThreadPoolExecutor(max_workers=11) as pool:
        list(pool.map(lambda pair: store.admit(pair[0], pair[1]["id"], now=now + 1), entries))
    assert sum(store.job(tenant, job["id"]).get("admitted_at") is not None for tenant, job in entries) <= 10
    # The scheduler submits in FIFO order while independent retries race on
    # each job. Every successful retry must map to the same durable admission.
    for tenant, job in entries[:10]:
        with ThreadPoolExecutor(max_workers=4) as pool:
            assert any(pool.map(lambda _: store.admit(tenant, job["id"], now=now + 1), range(4)))
    tenant, eleventh = entries[10]
    with ThreadPoolExecutor(max_workers=8) as pool:
        assert not any(pool.map(lambda _: store.admit(tenant, eleventh["id"], now=now + 2), range(8)))
    if hasattr(store, "client"):
        from peaso.storage.dynamodb import attrs, row
        item = store.client.get_item(TableName=store.table, Key=attrs({"PK": "GLOBAL", "SK": "SCAN_CAPACITY"}))["Item"]
        assert row(item)["active_count"] == 10


def test_cancel_and_stale_progress_are_fenced(store):
    now = time.time()
    tenant, job = jobs(store, now, 1)[0]
    assert store.admit(tenant, job["id"], now=now + 1)
    claim = store.claim("collector", now=now + 2, tenant=tenant, ident=job["id"])
    assert claim
    assert store.record_progress(job["id"], claim["owner"], {"phase": "collecting", "scope": "private", "completed": 1}, now=now + 3)
    assert "scope" not in store.public_job(store.job(tenant, job["id"]))["progress_details"]
    store.cancel(tenant, job["id"])
    assert not store.record_progress(job["id"], claim["owner"], {"phase": "collecting"}, now=now + 4)
    assert not store.finish(job["id"], claim["owner"], "failed", now=now + 4)


def test_schedule_occurrence_waits_without_spending_execution_budget(store):
    now = time.time()
    entries = jobs(store, now)
    for tenant, job in entries[:10]:
        assert store.admit(tenant, job["id"], now=now + 1)
    connector_id = store.connectors("alice")[0]["id"]
    store.add_schedule("alice", {"connector_id": connector_id, "interval_hours": 168}, now + 10)
    due = store.due_schedules(now + 10)
    assert len(due) == 1
    scheduled = store.trigger_schedule(due[0], limit=20, timeout=120, now=now + 10)
    assert scheduled["status"] == "queued"
    assert not store.admit("alice", scheduled["id"], now=now + 10)
    assert store.job("alice", scheduled["id"])["deadline"] == pytest.approx(now + 3610)
    first_tenant, first = entries[0]
    store.cancel(first_tenant, first["id"])
    # The older unscheduled eleventh request gets the newly released slot.
    waiting_tenant, waiting = entries[10]
    assert store.admit(waiting_tenant, waiting["id"], now=now + 11)
    store.cancel(waiting_tenant, waiting["id"])
    assert store.admit("alice", scheduled["id"], now=now + 12)
    assert store.job("alice", scheduled["id"])["deadline"] == pytest.approx(now + 132)


@pytest.mark.parametrize("store", ["dynamodb"], indirect=True)
def test_reconcile_recovers_workflow_failure_after_terminal_write(store):
    now = time.time()
    tenant, job = jobs(store, now, 1)[0]
    assert store.admit(tenant, job["id"], now=now + 1)
    # Step Functions marks failure directly. The scheduler must release the
    # durable reservation even if the worker never reaches finish().
    from peaso.storage.dynamodb import attrs, row
    store.client.update_item(TableName=store.table, Key=attrs(store.key(tenant, "job", job["id"])),
                             UpdateExpression="SET #status=:failed",
                             ExpressionAttributeNames={"#status": "status"},
                             ExpressionAttributeValues=attrs({":failed": "failed"}))
    store.reconcile_admissions(now + 2)
    item = store.client.get_item(TableName=store.table, Key=attrs({"PK": "GLOBAL", "SK": "SCAN_CAPACITY"}))["Item"]
    assert row(item)["active_count"] == 0
    assert not store.release_admission(tenant, job["id"])


def test_dispatcher_starts_only_admitted_executions_once(store):
    from peaso.storage.runtime import WorkflowDispatcher
    class AlreadyExists(Exception):
        pass
    class Client:
        exceptions = SimpleNamespace(ExecutionAlreadyExists=AlreadyExists)
        def __init__(self):
            self.names = set()
        def start_execution(self, *, stateMachineArn, name, input):
            assert stateMachineArn == "fixture-workflow"
            if name in self.names:
                raise AlreadyExists()
            self.names.add(name)
    now = time.time()
    entries = jobs(store, now)
    client = Client()
    dispatcher = WorkflowDispatcher(arn="fixture-workflow", client=client, store=store)
    for tenant, job in entries[:10]:
        assert dispatcher.dispatch(tenant, dict(job, ai_enabled=False))
    tenant, queued = entries[10]
    assert not dispatcher.dispatch(tenant, dict(queued, ai_enabled=False))
    first_tenant, first = entries[0]
    assert dispatcher.dispatch(first_tenant, dict(first, ai_enabled=False))
    assert len(client.names) == 10
