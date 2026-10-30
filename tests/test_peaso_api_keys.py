"""Read-only account API keys across the local and hosted metadata stores."""
import hashlib
import time
from datetime import datetime, timedelta, timezone

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

from peaso.auth import Identity
from peaso.auth.api_keys import mint_key
from peaso.server import create_app
from peaso.server.config import Settings
from peaso.storage import FileArtifacts, SQLiteStore, StoreError


class Users:
    def authenticate(self, header):
        if header == "Bearer alice":
            return Identity("alice")
        if header == "Bearer bob":
            return Identity("bob")
        raise HTTPException(401, "Invalid authentication")


@pytest.fixture(params=["sqlite", "dynamodb"])
def environment(request, tmp_path):
    settings = Settings(state_dir=tmp_path / "state", identity_dir=tmp_path / "identity")
    if request.param == "sqlite":
        store = SQLiteStore(settings.state_dir)
        yield settings, store
        return
    moto = pytest.importorskip("moto")
    boto3 = pytest.importorskip("boto3")
    from peaso.storage.dynamodb import DynamoStore
    with moto.mock_aws():
        client = boto3.client("dynamodb", region_name="us-east-1")
        client.create_table(TableName="keys", KeySchema=[{"AttributeName": "PK", "KeyType": "HASH"}, {"AttributeName": "SK", "KeyType": "RANGE"}], AttributeDefinitions=[{"AttributeName": "PK", "AttributeType": "S"}, {"AttributeName": "SK", "AttributeType": "S"}], BillingMode="PAY_PER_REQUEST")
        yield settings, DynamoStore("keys", client)


@pytest.fixture
def client(environment, tmp_path):
    settings, store = environment
    app = create_app(settings, store=store, authenticator=Users(), artifacts=FileArtifacts(tmp_path / "artifacts"))
    with TestClient(app, base_url="http://127.0.0.1:8000") as result:
        yield result, store


def headers(token):
    return {"Authorization": "Bearer " + token}


def create_key(client, name="external", expires_at=None):
    response = client.post("/api/api-keys", headers=headers("alice"), json={"name": name, "expires_at": expires_at})
    assert response.status_code == 201, response.text
    return response.json()


def test_key_lifecycle_read_contract_and_tenant_isolation(client):
    http, store = client
    alice = store.add_connector("alice", {"name": "Alice", "provider": "aws", "auth": {}, "scopes": [], "options": {}}, http.app.state.cipher.encrypt({"auth": {"token": "private-secret"}}))
    bob = store.add_connector("bob", {"name": "Bob", "provider": "aws", "auth": {}, "scopes": [], "options": {}}, http.app.state.cipher.encrypt({"auth": {"token": "other-private"}}))
    created = create_key(http)
    token = created.pop("key")
    assert token.startswith("hacktricks_cspm_") and len(token) == 92
    persisted = store.api_key(created["id"])
    assert persisted["secret_sha256"] == hashlib.sha256(token.encode()).hexdigest()
    assert token not in repr(persisted)
    own = http.get("/api/me", headers=headers(token))
    assert own.status_code == 200 and own.json()["tenant_id"] == "alice"
    assert own.json()["plan"] == "free"
    connectors = http.get("/api/connectors", headers=headers(token))
    assert connectors.status_code == 200
    assert [row["id"] for row in connectors.json()["items"]] == [alice["id"]]
    assert bob["id"] not in connectors.text and "private-secret" not in connectors.text
    assert http.get("/api/connectors/" + bob["id"], headers=headers(token)).status_code == 404
    assert http.get("/api/catalog", headers=headers(token)).status_code == 200
    assert http.get("/api/scans", headers=headers(token)).status_code == 200
    assert http.get("/api/api-keys", headers=headers(token)).status_code == 403
    assert http.post("/api/api-keys", headers=headers(token), json={"name": "nested"}).status_code == 403
    assert http.post("/api/scans", headers=headers(token), json={"connector_id": alice["id"]}).status_code == 403
    assert http.post("/api/connectors", headers=headers(token), json={}).status_code == 403
    assert http.delete("/api/connectors/" + alice["id"], headers=headers(token)).status_code == 403
    assert store.usage("alice") == 0
    listed = http.get("/api/api-keys", headers=headers("alice"))
    assert listed.status_code == 200 and listed.json()["items"][0]["id"] == created["id"]
    for secret in ("secret_sha256", "cognito_username", token, "private-secret"):
        assert secret not in listed.text
    assert http.delete("/api/api-keys/" + created["id"], headers=headers("bob")).status_code == 404
    assert http.delete("/api/api-keys/" + created["id"], headers=headers("alice")).status_code == 204
    assert http.get("/api/me", headers=headers(token)).status_code == 401
    assert http.get("/api/me", headers=headers("alice")).status_code == 200


def test_expiry_pagination_and_key_limit(client):
    http, store = client
    expiry = (datetime.now(timezone.utc) + timedelta(seconds=60)).isoformat()
    first = create_key(http, "first", expiry)
    second = create_key(http, "second")
    page = http.get("/api/api-keys?limit=1", headers=headers("alice")).json()
    assert len(page["items"]) == 1 and page["next_cursor"]
    following = http.get("/api/api-keys?limit=1&after=" + page["next_cursor"], headers=headers("alice")).json()
    assert len(following["items"]) == 1 and following["items"][0]["id"] != page["items"][0]["id"]
    assert http.post("/api/api-keys", headers=headers("alice"), json={"name": "past", "expires_at": "2020-01-01T00:00:00Z"}).status_code == 422
    assert http.get("/api/me", headers=headers(first["key"])).status_code == 200
    # Expiry is checked on every request, even after a previously successful read.
    if isinstance(store, SQLiteStore):
        with store.transaction() as db:
            db.execute("UPDATE api_keys SET expires_at=? WHERE id=?", (time.time() - 1, first["id"]))
    else:
        from peaso.storage.dynamodb import attrs
        store.client.update_item(TableName=store.table, Key=attrs(store.key("alice", "api_key", first["id"])), UpdateExpression="SET expires_at=:past", ExpressionAttributeValues=attrs({":past": time.time() - 1}))
    assert http.get("/api/me", headers=headers(first["key"])).status_code == 401
    for i in range(18):
        create_key(http, f"extra {i}")
    assert http.post("/api/api-keys", headers=headers("alice"), json={"name": "over cap"}).status_code == 429
    assert http.delete("/api/api-keys/" + second["id"], headers=headers("alice")).status_code == 204
    assert create_key(http, "replacement")["id"]


def test_external_reads_owned_findings_inventory_coverage_and_reports(client):
    http, store = client
    cipher = http.app.state.cipher
    artifacts = http.app.state.artifacts
    connector = store.add_connector("alice", {"provider": "aws", "name": "Inventory", "options": {}, "input_mode": "offline_snapshot"}, cipher.encrypt({"auth": {}, "options": {}}))
    job = store.enqueue("alice", {"connector_id": connector["id"]}, now=time.time(), timeout=900)
    # Collectors claim only scans that hold one of the durable scan slots.
    assert store.admit("alice", job["id"])
    collected = store.claim("collector", tenant="alice", ident=job["id"])
    assert collected and store.finish(job["id"], collected["owner"], "collected", "fixture-snapshot")
    analyzing = store.claim("analyzer", tenant="alice", ident=job["id"])
    assert analyzing
    finding = {"id": "f-1", "check_id": "fixture-check", "title": "Fixture finding", "category": "network",
               "provider": "aws", "service": "s3", "resource_id": "r-1", "scope": "111111111111",
               "severity": "high", "status": "fail", "evidence": {"source": "fixture"}}
    lower = dict(finding, id="f-2", title="Lower priority", severity="low")
    bundle = {"provider": "aws", "findings": [finding, lower], "coverage": [{"status": "collected", "scope": "111111111111"}],
              "resources": [{"id": "r-1", "native_id": "bucket-1", "type": "bucket", "scope": "111111111111", "data": {"Name": "bucket-1"}}],
              "graphs": {"network": {"nodes": [], "edges": []}, "iam": {"nodes": [], "edges": []}}}
    reference = artifacts.put("alice", job["id"], "report", bundle)
    assert store.finish(job["id"], analyzing["owner"], "completed", reference)
    key = create_key(http)["key"]
    route = f"/api/scans/{job['id']}"
    first = http.get(route + "/findings?sort_by=severity&offset=0&limit=1", headers=headers(key)).json()
    second = http.get(route + "/findings?sort_by=severity&offset=1&limit=1", headers=headers(key)).json()
    assert first["total"] == 2 and first["has_more"] is True and first["items"][0]["id"] == "f-1"
    assert second["items"][0]["id"] == "f-2" and second["has_more"] is False
    assert http.get(route + "/findings/f-1", headers=headers(key)).json()["evidence"]["source"] == "fixture"
    assert http.get(route + "/coverage", headers=headers(key)).json()["items"][0]["status"] == "collected"
    assert http.get(route + "/summary", headers=headers(key)).status_code == 200
    assert http.get(route + "/graphs/network", headers=headers(key)).status_code == 200
    assert http.get(route + "/graphs/iam", headers=headers(key)).status_code == 200
    inventory = http.get(route + "/resources?offset=0&limit=1", headers=headers(key)).json()
    assert inventory["total"] == 1 and inventory["items"][0]["id"] == "r-1"
    assert "data" not in inventory["items"][0]
    assert http.get(route + "/resources/r-1", headers=headers(key)).json()["data"]["Name"] == "bucket-1"
    assert http.get(route + "/report?format=json", headers=headers(key)).json()["resources"][0]["id"] == "r-1"
    assert http.get(route + "/report?format=markdown", headers=headers(key)).status_code == 200
    for suffix in ("/findings", "/coverage", "/resources", "/report", "/graphs/network", "/graphs/iam"):
        assert http.get(route + suffix, headers=headers("bob")).status_code == 404


def test_token_parser_bounded_and_constant_time_digest():
    from peaso.auth.api_keys import active, matches, parse_key
    key_id, token, digest = mint_key()
    assert parse_key(token) == key_id and matches(token, digest)
    assert parse_key(token + "x") is None
    assert not matches(token[:-1] + ("a" if token[-1] != "a" else "b"), digest)
    assert not active({"expires_at": "malformed", "revoked_at": None})
    assert not active({"expires_at": "NaN", "revoked_at": None})


def test_dynamodb_scan_uses_second_page_cursor_once():
    from peaso.storage.dynamodb import DynamoStore, attrs

    class PagedClient:
        calls = []
        def scan(self, **kwargs):
            self.calls.append(kwargs)
            if len(self.calls) == 1:
                assert "ExclusiveStartKey" not in kwargs
                return {"Items": [attrs({"id": "first"})], "LastEvaluatedKey": attrs({"PK": "first", "SK": "job/1"})}
            assert kwargs["ExclusiveStartKey"] == attrs({"PK": "first", "SK": "job/1"})
            return {"Items": [attrs({"id": "second"})]}

    service = PagedClient()
    assert [item["id"] for item in DynamoStore("fixture", service)._scan("job")] == ["first", "second"]
    assert len(service.calls) == 2


def test_hosted_disabled_identity_and_cookie_csrf(tmp_path):
    import jwt
    from types import SimpleNamespace
    from unittest.mock import Mock
    from cryptography.hazmat.primitives.asymmetric import rsa
    from peaso.auth import Authenticator

    settings = Settings(state_dir=tmp_path / "state", identity_dir=tmp_path / "identity", auth_mode="cognito",
                        issuer="https://cognito-idp.us-east-1.amazonaws.com/existing_pool", audience="existing_client",
                        origins=("https://cspm.hacktricks.wiki",))
    signing = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    jwks, cognito, entitlements = Mock(), Mock(), Mock()
    jwks.get_signing_key_from_jwt.return_value = SimpleNamespace(key=signing.public_key())
    cognito.admin_get_user.return_value = {"Enabled": True, "UserAttributes": [
        {"Name": "sub", "Value": "alice"}, {"Name": "email", "Value": "live-alice@example.test"},
        {"Name": "email_verified", "Value": "true"}, {"Name": "name", "Value": "Live Alice"}]}
    entitlements.paid.return_value = False
    auth = Authenticator(settings, cognito=cognito, jwks=jwks, entitlements=entitlements)
    claims = {"iss": settings.issuer, "aud": settings.audience, "sub": "alice", "cognito:username": "alice-name",
              "email": "forged@example.test", "name": "Forged display",
              "token_use": "id", "iat": int(time.time()), "exp": int(time.time()) + 600}
    jwt_token = jwt.encode(claims, signing, algorithm="RS256")
    cognito.initiate_auth.return_value = {"AuthenticationResult": {"IdToken": jwt_token}}
    store = SQLiteStore(settings.state_dir)
    with TestClient(create_app(settings, store=store, authenticator=auth, artifacts=FileArtifacts(tmp_path / "artifacts")),
                    base_url="https://cspm.hacktricks.wiki") as http:
        http.cookies.set("__Secure-ht_refresh", "refresh-fixture")
        assert http.post("/api/api-keys", json={"name": "no-origin"}).status_code == 403
        created = http.post("/api/api-keys", headers={"Origin": "https://cspm.hacktricks.wiki"}, json={"name": "session"})
        assert created.status_code == 201, created.text
        key = created.json()["key"]
        assert store.api_key(created.json()["id"])["cognito_username"] == "alice-name"
        account = http.get("/api/me", headers=headers(key))
        assert account.status_code == 200 and account.json()["email"] == "live-alice@example.test"
        assert account.json()["name"] == "Live Alice" and "forged@example.test" not in account.text
        session_account = http.get("/api/me", headers=headers(jwt_token))
        assert session_account.json()["email"] == "live-alice@example.test"
        assert cognito.admin_get_user.call_args.kwargs["Username"] == "alice-name"
        cognito.admin_get_user.return_value["Enabled"] = False
        assert http.get("/api/me", headers=headers(key)).status_code == 401
        assert http.get("/api/me", headers=headers(jwt_token)).status_code == 401
