"""Sealed resume, expiry classification and native call avoidance."""
import json
from types import SimpleNamespace

from peaso.collectors.resume import checkpoint_with_reuse, merge, partition
from peaso.snapshot import make_snapshot
from peaso.worker import Worker, _expired_snapshot
from peaso.server.config import Settings
from peaso.storage.artifacts import FileArtifacts
from peaso.storage.runtime import WorkflowDispatcher
from test_peaso_aws_bulk_inventory import sdk


SCOPE = "123456789012/us-east-1"


def envelope(kind, status="collected", *, error=None):
    row = {"type": kind, "scope": SCOPE, "service": "ec2", "status": status,
           "items": [{"InstanceId": "i-saved"}] if status == "collected" else []}
    if error:
        row["error"] = error
    return row


def test_explicit_expiry_is_distinct_from_access_denial():
    assert _expired_snapshot({"collections": [envelope("instance", "denied", error={"code": "ExpiredToken"})]})
    assert not _expired_snapshot({"collections": [envelope("instance", "denied", error={"code": "AccessDenied"})]})


def test_native_resume_omits_settled_kind_from_sdk_calls(monkeypatch):
    from peaso.collectors import aws, collect_live
    prior = make_snapshot("aws", [SCOPE], [envelope("instance"),
        envelope("bucket", "denied", error={"code": "ExpiredToken"})])
    connector = {"provider": "aws", "scopes": [SCOPE], "auth": {}, "options": {}}
    remaining, saved = partition(connector, ["instance", "bucket"], prior)
    assert remaining == ["bucket"] and [row["type"] for row in saved] == ["instance"]

    class FakeSDK:
        calls = []

        def list_resources(self, kind):
            self.calls.append(kind)
            return []

    sdk = FakeSDK()

    def native_collect(connector, requirements):
        return make_snapshot("aws", [SCOPE], [
            {"type": kind, "scope": SCOPE, "service": "ec2", "status": "empty",
             "items": sdk.list_resources(kind)} for kind in requirements])

    monkeypatch.setattr(aws, "collect", native_collect)
    current = collect_live(connector, remaining)
    final = merge(current, saved, prior)
    assert sdk.calls == ["bucket"]
    assert {row["type"]: row["status"] for row in final["collections"]} == {
        "instance": "collected", "bucket": "empty"}
    assert next(row for row in final["collections"] if row["type"] == "instance")["items"] == [{"InstanceId": "i-saved"}]


def test_real_aws_fetcher_skips_settled_sdk_operation(monkeypatch, sdk):
    from test_peaso_aws_bulk_inventory import ACCOUNT, REGION
    from peaso.collectors import aws, collect_live, aws_bulk_inventory
    session, add = sdk
    stub = add("ce")
    stub.add_response("get_anomaly_subscriptions", {"AnomalySubscriptions": []}, {})
    scope = ACCOUNT + "/" + REGION
    prior = make_snapshot("aws", [scope], [
        {"type": "cost_anomaly_monitor", "scope": scope, "status": "empty", "items": []},
        {"type": "cost_anomaly_subscription", "scope": scope, "status": "denied",
         "items": [], "error": {"code": "ExpiredToken"}}])
    connector = {"provider": "aws", "scopes": [scope], "auth": {}, "options": {}}
    remaining, saved = partition(connector,
        ["cost_anomaly_monitor", "cost_anomaly_subscription"], prior)
    requests = aws.Requests({})

    def native_collect(connector, requirements):
        rows = []
        for kind in requirements:
            read = aws_bulk_inventory.FETCHERS[kind](requests, session, REGION, ACCOUNT)
            rows.append({"type": kind, "scope": scope, "status": read.status, "items": read.items})
        return make_snapshot("aws", [scope], rows)

    monkeypatch.setattr(aws, "collect", native_collect)
    result = merge(collect_live(connector, remaining), saved, prior)
    assert remaining == ["cost_anomaly_subscription"]
    assert requests.calls == 1
    assert {row["type"]: row["status"] for row in result["collections"]} == {
        "cost_anomaly_monitor": "empty", "cost_anomaly_subscription": "empty"}
    stub.assert_no_pending_responses()


def test_resume_retains_evidence_when_collector_marks_reused_inventory_not_requested():
    regional_settings = dict(envelope("ec2_regional_settings"),
        items=[{"SnapshotBlockPublicAccessState": "unblocked"}])
    prior = make_snapshot("aws", [SCOPE], [regional_settings])
    remaining, saved = partition({"provider": "aws", "scopes": [SCOPE]},
                                 ["ec2_regional_settings", "instance"], prior)
    assert remaining == ["instance"]

    placeholder = envelope("ec2_regional_settings", "not_collected", error={"code": "inventory_not_requested"})
    observed = envelope("instance", "empty")
    received = []
    checkpoint = checkpoint_with_reuse(received.append, saved)
    checkpoint(placeholder)
    checkpoint(observed)
    assert received == [observed]

    resumed = merge(make_snapshot("aws", [SCOPE], [placeholder, observed]), saved, prior)
    assert next(row for row in resumed["collections"] if row["type"] == "ec2_regional_settings")["items"] == regional_settings["items"]

    denied = envelope("ec2_regional_settings", "denied", error={"code": "AccessDenied"})
    checkpoint(denied)
    assert received[-1] == denied
    retried = merge(make_snapshot("aws", [SCOPE], [denied]), saved, prior)
    assert retried["collections"][0]["status"] == "denied"


def test_analyzer_only_resume_reuses_snapshot_without_child(tmp_path):
    job = {"id": "a" * 32, "tenant": "owner", "owner": "current-owner",
           "data": json.dumps({"checks": ["original"]}), "resume_phase": "analyzer",
           "snapshot": "sealed-original-snapshot"}

    class Store:
        claims = []
        finished = []

        def claim(self, role, lease, **kwargs):
            self.claims.append(role)
            return job

        def finish(self, *args, **kwargs):
            self.finished.append((args, kwargs))
            return True

    store = Store()
    settings = Settings(state_dir=tmp_path / "state", identity_dir=tmp_path / "identity")
    worker = Worker("collector", settings, store=store,
                    artifacts=FileArtifacts(tmp_path / "artifacts"), authenticator=object())
    assert worker.run_once("owner", job["id"])
    assert store.claims == ["collector"]
    assert store.finished == [((job["id"], "current-owner", "collected", "sealed-original-snapshot"), {})]


def test_hosted_retry_uses_fresh_attempt_name_on_same_scan():
    ident = "a" * 32

    class Store:
        admissions = 0

        def admit(self, tenant, scan):
            self.admissions += 1
            return True

        def job(self, tenant, scan):
            return {"id": ident, "status": "queued", "resume_attempt": 2}

    class Client:
        class exceptions:
            class ExecutionAlreadyExists(Exception):
                pass

        names = []

        def start_execution(self, **kwargs):
            self.names.append(kwargs["name"])
            if len(self.names) == 1:
                raise RuntimeError("transient dispatch failure")

    store, client = Store(), Client()
    dispatcher = WorkflowDispatcher("arn:aws:states:us-east-1:123456789012:stateMachine:scan",
                                    client=client, store=store)
    job = {"id": ident, "ai_enabled": False}
    assert dispatcher.dispatch("owner", job) is False
    assert dispatcher.dispatch("owner", job) is True
    assert store.admissions == 2
    assert client.names == ["scan-" + ident + "-r2"] * 2
