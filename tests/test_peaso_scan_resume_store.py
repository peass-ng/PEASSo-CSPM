"""Same-row scan resume and fencing on both durable adapters."""
import time
import threading
from concurrent.futures import ThreadPoolExecutor

import pytest

from peaso.storage.artifacts import job_prefix
from peaso.storage.sqlite import SQLiteStore, StoreError


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
        client.create_table(TableName="resume", KeySchema=[{"AttributeName": "PK", "KeyType": "HASH"},
                                                     {"AttributeName": "SK", "KeyType": "RANGE"}],
                            AttributeDefinitions=[{"AttributeName": "PK", "AttributeType": "S"},
                                                  {"AttributeName": "SK", "AttributeType": "S"}],
                            BillingMode="PAY_PER_REQUEST")
        yield DynamoStore("resume", client)


def prepared(store, now, *, checkpoint=True, snapshot=True):
    tenant = "owner"
    connector = store.add_connector(tenant, {"provider": "aws", "scopes": ["123456789012/us-east-1"],
                                            "options": {}, "input_mode": "live"}, "old-sealed-auth")
    job = store.enqueue(tenant, {"connector_id": connector["id"], "checks": ["example"]},
                        limit=2, timeout=120, now=now)
    assert store.admit(tenant, job["id"], now=now + 1)
    claim = store.claim("collector", now=now + 2, tenant=tenant, ident=job["id"])
    if checkpoint:
        assert store.record_checkpoint(tenant, job["id"], claim["owner"], 1,
                                       job_prefix(tenant, job["id"]) + "snapshot/prior",
                                       kind="instance", scope="123456789012/us-east-1", now=now + 3)
    artifact = job_prefix(tenant, job["id"]) + "snapshot/final" if snapshot and checkpoint else None
    assert store.finish(job["id"], claim["owner"], "credentials_expired", artifact=artifact, now=now + 4)
    return tenant, connector, job, claim


def test_resume_preserves_row_checkpoint_and_fences_old_owner(store):
    now = time.time()
    tenant, connector, job, old_claim = prepared(store, now)
    before = store.job(tenant, job["id"])
    assert store.public_job(before)["resumable"] is True
    store.update_connector(tenant, connector["id"], {}, "new-sealed-auth")
    current = store.connector(tenant, connector["id"])
    if hasattr(store, "client"):
        # Moto's in-process transaction emulator is not itself thread-safe.
        # Serialize the emulated writes as DynamoDB does for conditional items.
        lock = threading.Lock()
        transact = store.client.transact_write_items
        def serialized(**kwargs):
            with lock:
                return transact(**kwargs)
        store.client.transact_write_items = serialized
    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(store.resume_job, tenant, job["id"], current, now + 5)
                   for _ in range(2)]
        outcomes = []
        for future in futures:
            try:
                outcomes.append(future.result())
            except StoreError as exc:
                outcomes.append(exc.status)
    assert sum(isinstance(value, dict) for value in outcomes) == 1
    assert 409 in outcomes
    resumed = store.job(tenant, job["id"])
    assert resumed["status"] == "queued" and resumed["id"] == job["id"]
    assert resumed["created"] == before["created"]
    assert resumed["data"] == before["data"]
    assert resumed["checkpoint_sequence"] == before["checkpoint_sequence"]
    assert store.checkpoint_collections(tenant, job["id"])
    assert resumed["resume_attempt"] == 1
    assert resumed.get("admitted_at") is None
    assert store.usage(tenant, now) == 1
    assert not store.heartbeat(job["id"], old_claim["owner"], now=now + 6)
    assert not store.finish(job["id"], old_claim["owner"], "collected", now=now + 6)
    assert not store.public_job(resumed)["resumable"]


def test_resume_rejects_missing_work_and_changed_connector(store):
    now = time.time()
    tenant, connector, job, _ = prepared(store, now, checkpoint=False)
    assert store.public_job(store.job(tenant, job["id"]))["resumable"] is False
    with pytest.raises(StoreError) as exc:
        store.resume_job(tenant, job["id"], store.connector(tenant, connector["id"]), now + 5)
    assert exc.value.status == 409
    tenant, connector, job, _ = prepared(store, now + 10)
    stale = store.connector(tenant, connector["id"])
    store.update_connector(tenant, connector["id"], {}, "replacement")
    with pytest.raises(StoreError) as exc:
        store.resume_job(tenant, job["id"], stale, now + 15)
    assert exc.value.status == 409


def test_checkpoint_without_sealed_native_plan_is_not_resumable(store):
    now = time.time()
    tenant, connector, job, _ = prepared(store, now, snapshot=False)
    assert store.checkpoint_collections(tenant, job["id"])
    assert store.public_job(store.job(tenant, job["id"]))["resumable"] is False
    with pytest.raises(StoreError) as exc:
        store.resume_job(tenant, job["id"], store.connector(tenant, connector["id"]), now + 5)
    assert exc.value.status == 409


def test_resumed_scan_reenters_fifo_without_changing_creation_time(store):
    now = time.time()
    tenant, connector, first, _ = prepared(store, now)
    second = store.enqueue(tenant, {"connector_id": connector["id"], "checks": ["later"]},
                           limit=3, timeout=120, now=now + 5)
    before = store.job(tenant, first["id"])
    store.resume_job(tenant, first["id"], store.connector(tenant, connector["id"]), now + 6)
    after = store.job(tenant, first["id"])
    assert after["created"] == before["created"]
    assert float(after["queued_at"]) == pytest.approx(now + 6)
    assert [row["id"] for row in store.queued_jobs()] == [second["id"], first["id"]]
    assert not store.admit(tenant, first["id"], now=now + 7)
    assert store.admit(tenant, second["id"], now=now + 7)


def test_old_dynamo_reservation_release_cannot_free_resumed_capacity(tmp_path):
    boto3 = pytest.importorskip("boto3")
    moto = pytest.importorskip("moto")
    from peaso.storage.dynamodb import DynamoStore, attrs, row
    with moto.mock_aws():
        client = boto3.client("dynamodb", region_name="us-east-1")
        client.create_table(TableName="fenced_resume", KeySchema=[{"AttributeName": "PK", "KeyType": "HASH"},
                                                      {"AttributeName": "SK", "KeyType": "RANGE"}],
                            AttributeDefinitions=[{"AttributeName": "PK", "AttributeType": "S"},
                                                  {"AttributeName": "SK", "AttributeType": "S"}],
                            BillingMode="PAY_PER_REQUEST")
        store = DynamoStore("fenced_resume", client)
        now = time.time()
        tenant, connector, job, old_claim = prepared(store, now)
        store.resume_job(tenant, job["id"], store.connector(tenant, connector["id"]), now + 5)
        assert store.admit(tenant, job["id"], now=now + 6)
        assert not store.finish(job["id"], old_claim["owner"], "completed", now=now + 7)
        assert store.release_admission(tenant, job["id"], 0) is False
        assert store.job(tenant, job["id"])["admitted_at"] is not None
        client.put_item(TableName="fenced_resume", Item=attrs(dict(
            store._reservation_key(tenant, job["id"], 0), kind="scan_reservation",
            id=job["id"], tenant=tenant, attempt=0)))
        client.update_item(TableName="fenced_resume", Key=attrs({"PK": "GLOBAL", "SK": "SCAN_CAPACITY"}),
                           UpdateExpression="ADD active_count :one",
                           ExpressionAttributeValues=attrs({":one": 1}))
        store.reconcile_admissions(now=now + 7)
        assert store.release_admission(tenant, job["id"], 0) is False
        assert store.job(tenant, job["id"])["admitted_at"] is not None
        capacity = client.get_item(TableName="fenced_resume", Key=attrs({"PK": "GLOBAL", "SK": "SCAN_CAPACITY"}))
        assert row(capacity["Item"])["active_count"] == 1
        assert store.release_admission(tenant, job["id"], 1) is True
        assert store.release_admission(tenant, job["id"], 1) is False
        capacity = client.get_item(TableName="fenced_resume", Key=attrs({"PK": "GLOBAL", "SK": "SCAN_CAPACITY"}))
        assert row(capacity["Item"])["active_count"] == 0


def test_dynamo_reconcile_admissions_queries_reservations_without_table_scan():
    boto3 = pytest.importorskip("boto3")
    moto = pytest.importorskip("moto")
    from peaso.storage.dynamodb import DynamoStore, attrs, row
    with moto.mock_aws():
        client = boto3.client("dynamodb", region_name="us-east-1")
        client.create_table(TableName="reconcile", KeySchema=[{"AttributeName": "PK", "KeyType": "HASH"},
                                                    {"AttributeName": "SK", "KeyType": "RANGE"}],
                            AttributeDefinitions=[{"AttributeName": "PK", "AttributeType": "S"},
                                                  {"AttributeName": "SK", "AttributeType": "S"}],
                            BillingMode="PAY_PER_REQUEST")

        class NoScanClient:
            forbid_scan = False

            def __getattr__(self, name):
                if name == "scan" and self.forbid_scan:
                    raise AssertionError("reconcile_admissions must not scan the table")
                return getattr(client, name)

        guarded = NoScanClient()
        store = DynamoStore("reconcile", guarded)
        now = time.time()
        tenant = "owner"
        connector = store.add_connector(tenant, {"provider": "aws", "scopes": ["123456789012/us-east-1"],
                                                "options": {}, "input_mode": "live"}, "sealed-auth")
        job = store.enqueue(tenant, {"connector_id": connector["id"], "checks": ["example"]},
                            limit=2, timeout=120, now=now)
        assert store.admit(tenant, job["id"], now=now + 1)
        # An orphaned reservation whose job no longer exists frees its capacity.
        client.put_item(TableName="reconcile", Item=attrs(dict(
            store._reservation_key(tenant, "missing-job", 0), kind="scan_reservation",
            id="missing-job", tenant=tenant, attempt=0)))
        client.update_item(TableName="reconcile", Key=attrs({"PK": "GLOBAL", "SK": "SCAN_CAPACITY"}),
                           UpdateExpression="ADD active_count :one",
                           ExpressionAttributeValues=attrs({":one": 1}))
        guarded.forbid_scan = True
        store.reconcile_admissions(now=now + 3)
        orphan = client.get_item(TableName="reconcile", Key=attrs(store._reservation_key(tenant, "missing-job", 0)))
        assert "Item" not in orphan
        live = client.get_item(TableName="reconcile", Key=attrs(store._reservation_key(tenant, job["id"], 0)))
        assert "Item" in live
        capacity = client.get_item(TableName="reconcile", Key=attrs({"PK": "GLOBAL", "SK": "SCAN_CAPACITY"}))
        assert row(capacity["Item"])["active_count"] == 1
        # A past-deadline admitted job is still expired by the reconcile pass.
        store.reconcile_admissions(now=now + 10_000)
        assert store.job(tenant, job["id"])["status"] == "timed_out"
