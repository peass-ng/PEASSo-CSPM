"""A scan whose connector credential is rejected fails as credentials_invalid on every provider."""
import json

import pytest

from peaso.credential_health import credentials_rejected, nothing_readable, provider_read
from peaso.snapshot import make_snapshot


def _denied(kind, error):
    return {"type": kind, "scope": "*", "service": "svc", "status": "denied", "items": [], "error": error}


# One dead-credential collection shape per provider, as recorded by real collectors.
DEAD = {
    "gcp": _denied("access_approval_request", {"code": "credential_refresh_failed", "kind": "denied"}),
    "aws": _denied("iam_user", {"code": "InvalidClientTokenId", "kind": "ClientError"}),
    "azure": _denied("subscription", {"code": "read_failed", "kind": "ClientAuthenticationError"}),
    "k8s": _denied("pod", {"code": "401", "kind": "RuntimeError"}),
}
# Envelopes that exist even when nothing was read from the provider.
DERIVED = {
    "gcp": {"type": "gcp_v4_workload_facts", "scope": "projects/p", "service": "derived-gcp-metadata",
            "status": "collected", "source_requests": ["local:gcp_v4_workload_facts"],
            "items": [{"_resource_id": "projects/p"}]},
    "k8s": {"type": "network_interface", "scope": "*", "service": "kubernetes", "status": "partial",
            "items": [], "error": {"code": "source_inventory_incomplete"}},
}


@pytest.mark.parametrize("provider", sorted(DEAD))
def test_rejected_credential_with_only_derived_envelopes_is_credentials_invalid(provider):
    rows = [DEAD[provider], *DERIVED.values()]
    snapshot = make_snapshot(provider, ["*"], rows)
    assert nothing_readable(snapshot)
    assert credentials_rejected(snapshot)


@pytest.mark.parametrize("provider", sorted(DEAD))
def test_one_real_provider_read_keeps_the_scan(provider):
    real = {"type": "project", "scope": "projects/p", "service": "resourcemanager", "status": "empty", "items": []}
    snapshot = make_snapshot(provider, ["*"], [DEAD[provider], real])
    assert not nothing_readable(snapshot)
    assert not credentials_rejected(snapshot)


def test_permission_denial_alone_is_not_a_rejected_credential():
    snapshot = make_snapshot("gcp", ["*"], [_denied("bucket", {"code": "api_error", "http_status": 403, "kind": "denied"})])
    assert nothing_readable(snapshot)
    assert not credentials_rejected(snapshot)


def test_http_401_and_additional_errors_name_a_rejected_credential():
    gcp = make_snapshot("gcp", ["*"], [_denied("bucket", {"code": "api_error", "http_status": 401})])
    azure = make_snapshot("azure", ["*"], [_denied("vm", {"code": "read_failed", "additional_errors": [
        {"code": "InvalidAuthenticationToken"}]})])
    assert credentials_rejected(gcp) and credentials_rejected(azure)


def test_provider_read_ignores_local_and_itemless_partial_envelopes():
    assert not provider_read(DERIVED["gcp"])
    assert not provider_read(DERIVED["k8s"])
    assert provider_read({"status": "partial", "items": [{"id": 1}]})
    assert provider_read({"status": "collected", "items": [], "source_requests": ["local:x", "request-1"]})


def test_cli_scan_of_dead_gcp_key_with_derived_facts_exits_nonzero(tmp_path, capsys):
    from peaso.cli import main
    path = tmp_path / "snap.json"
    path.write_text(json.dumps(make_snapshot("gcp", ["projects/p"], [DEAD["gcp"], DERIVED["gcp"]])))
    assert main(["scan", "--snapshot", str(path), "-o", str(tmp_path / "r.json"), "--quiet"]) == 3
    assert "credential_refresh_failed" in capsys.readouterr().err


@pytest.mark.parametrize("provider", sorted(DEAD))
def test_hosted_collector_fails_dead_credential_scan_as_credentials_invalid(tmp_path, monkeypatch, provider):
    import peaso.engine
    from peaso import worker

    class Pipe:
        sent = None

        def send(self, value):
            Pipe.sent = value

        def close(self):
            pass
    snapshot = make_snapshot(provider, ["*"], [DEAD[provider], *DERIVED.values()])
    monkeypatch.setattr(peaso.engine, "collect_snapshot", lambda request: snapshot)
    monkeypatch.setattr(worker.os, "dup2", lambda *a: None)
    monkeypatch.setattr(worker, "_verify_aws_credentials", lambda connector: None)
    request = {"artifact_config": {"mode": "file", "root": str(tmp_path)}, "tenant_id": "t", "scan_id": "0" * 32,
               "connector": {"provider": provider, "auth": {}}}
    worker._process("collector", request, Pipe())
    assert Pipe.sent[:2] == (False, "credentials_invalid")


class _ClientError(Exception):
    def __init__(self, code, operation):
        super().__init__(code)
        self.response = {"Error": {"Code": code}}
        self.operation_name = operation


@pytest.mark.parametrize("code, operation, rejected", [
    ("InvalidClientTokenId", "GetCallerIdentity", True),
    ("SignatureDoesNotMatch", "GetCallerIdentity", True),
    ("AccessDenied", "AssumeRole", True),
    ("AccessDenied", "GetCallerIdentity", False),
    ("Throttling", "GetCallerIdentity", False),
])
def test_aws_preflight_classifies_authentication_refusals(code, operation, rejected):
    from peaso.worker import _rejected_exception
    assert _rejected_exception(_ClientError(code, operation)) is rejected


def test_aws_preflight_raises_credential_invalid(monkeypatch):
    from peaso import worker
    import peaso.collectors.aws as aws

    class Client:
        def get_caller_identity(self):
            raise _ClientError("InvalidClientTokenId", "GetCallerIdentity")

    class Session:
        def client(self, *a, **k):
            return Client()
    monkeypatch.setattr(aws, "_session", lambda auth, region: (Session(), None))
    with pytest.raises(worker.CredentialInvalid):
        worker._verify_aws_credentials({"provider": "aws", "auth": {}, "options": {}})


@pytest.fixture(params=["sqlite", "dynamodb"])
def store(request, tmp_path):
    from peaso.storage import SQLiteStore
    if request.param == "sqlite":
        yield SQLiteStore(tmp_path / "state")
        return
    moto = pytest.importorskip("moto")
    boto3 = pytest.importorskip("boto3")
    from peaso.storage.dynamodb import DynamoStore
    with moto.mock_aws():
        client = boto3.client("dynamodb", region_name="us-east-1")
        client.create_table(TableName="peaso", BillingMode="PAY_PER_REQUEST",
                            KeySchema=[{"AttributeName": "PK", "KeyType": "HASH"}, {"AttributeName": "SK", "KeyType": "RANGE"}],
                            AttributeDefinitions=[{"AttributeName": name, "AttributeType": "S"} for name in ["PK", "SK"]])
        yield DynamoStore("peaso", client)


def test_store_publishes_credentials_invalid_code_and_message(store, tmp_path):
    from peaso.auth import CredentialCipher
    from peaso.storage.sqlite import INVALID_CREDENTIALS_FAILURE
    connector = store.add_connector("alice", {"provider": "gcp"},
                                    CredentialCipher(tmp_path / "identity").encrypt({"auth": {}, "options": {}}))
    job = store.enqueue("alice", {"connector_id": connector["id"]})
    assert store.admit("alice", job["id"])
    claim = store.claim("collector", tenant="alice", ident=job["id"])
    assert store.finish(job["id"], claim["owner"], "failed", error_code="credentials_invalid")
    public = store.public_job(store.job("alice", job["id"]))
    assert public["status"] == "failed"
    assert public["error_code"] == "credentials_invalid"
    assert public["error"] == INVALID_CREDENTIALS_FAILURE
    assert public["error_stage"] == "collector"
