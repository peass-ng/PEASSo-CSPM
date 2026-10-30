"""Candidate dual-store tests for the reviewed temporary QA authority."""
import time
from unittest.mock import Mock

import pytest

from peaso.auth.admin_qa import AUTHORITY, active_grant
from peaso.auth.identity import Authenticator
from peaso.server.config import Settings
from peaso.storage import SQLiteStore, StoreError


NOW = 2000000000
POOL = "us-east-1_reviewedpool"
CLIENT = "reviewedclient"
SUB = "subject-1"
EMAIL = "qa@example.test"
ACTOR = "arn:aws:sts::111122223333:assumed-role/reviewed-operator/session"


def grant(**updates):
    value = {"tenant": SUB, "cognito_subject": SUB, "cognito_pool_id": POOL,
             "cognito_client_id": CLIENT, "verified_email": EMAIL,
             "authority": AUTHORITY, "actor": ACTOR, "reason": "bounded acceptance run",
             "audit_id": "a" * 32, "issued_at": NOW, "hard_expires_at": NOW + 3600}
    return {**value, **updates}


@pytest.fixture(params=["sqlite", "dynamodb"])
def store(request, tmp_path):
    if request.param == "sqlite":
        yield SQLiteStore(tmp_path / "state")
        return
    boto3 = pytest.importorskip("boto3")
    moto = pytest.importorskip("moto")
    from peaso.storage.dynamodb import DynamoStore
    with moto.mock_aws():
        client = boto3.client("dynamodb", region_name="us-east-1")
        client.create_table(TableName="qa", KeySchema=[{"AttributeName": "PK", "KeyType": "HASH"},
                                                        {"AttributeName": "SK", "KeyType": "RANGE"}],
                            AttributeDefinitions=[{"AttributeName": "PK", "AttributeType": "S"},
                                                  {"AttributeName": "SK", "AttributeType": "S"}],
                            BillingMode="PAY_PER_REQUEST")
        result = DynamoStore("qa", client)
        result.clock = lambda: NOW
        yield result


def test_issue_lookup_revoke_and_tenant_binding(store):
    value = grant()
    store.issue_admin_qa_grant(SUB, value, now=NOW + 1)
    current = store.get_admin_qa_grant(SUB)
    assert active_grant(current, tenant=SUB, pool_id=POOL, client_id=CLIENT,
                        attributes={"sub": SUB, "email": EMAIL, "email_verified": "true"}, now=NOW + 2)
    assert store.get_admin_qa_grant("other") is None
    for change in ({"sub": "other"}, {"email": "forged@example.test"}, {"email_verified": "false"}):
        attrs = {"sub": SUB, "email": EMAIL, "email_verified": "true", **change}
        assert not active_grant(current, tenant=SUB, pool_id=POOL, client_id=CLIENT,
                                attributes=attrs, now=NOW + 2)
    assert not active_grant(current, tenant=SUB, pool_id="other", client_id=CLIENT,
                            attributes={"sub": SUB, "email": EMAIL, "email_verified": "true"}, now=NOW + 2)
    with pytest.raises(StoreError):
        store.issue_admin_qa_grant(SUB, grant(audit_id="b" * 32), now=NOW + 2)
    with pytest.raises(StoreError):
        store.revoke_admin_qa_grant(SUB, "b" * 32, ACTOR, "wrong grant", now=NOW + 2)
    store.revoke_admin_qa_grant(SUB, value["audit_id"], ACTOR, "acceptance complete", now=NOW + 3)
    revoked = store.get_admin_qa_grant(SUB)
    assert revoked["revoked_at"] == NOW + 3
    assert not active_grant(revoked, tenant=SUB, pool_id=POOL, client_id=CLIENT,
                            attributes={"sub": SUB, "email": EMAIL, "email_verified": "true"}, now=NOW + 4)
    with pytest.raises(StoreError):
        store.revoke_admin_qa_grant(SUB, value["audit_id"], ACTOR, "repeat", now=NOW + 4)


@pytest.mark.parametrize("change", [
    {"hard_expires_at": NOW + 86401}, {"hard_expires_at": NOW},
    {"verified_email": "forged@example.test"}, {"authority": "stripe"},
    {"issued_at": True}, {"audit_id": "bad"}, {"reason": ""},
])
def test_invalid_or_expired_grant_fails_closed(change):
    value = grant(**change)
    assert not active_grant(value, tenant=SUB, pool_id=POOL, client_id=CLIENT,
                            attributes={"sub": SUB, "email": EMAIL, "email_verified": "true"}, now=NOW + 2)


def test_expired_and_error_store_cannot_create_paid_authority(tmp_path):
    settings = Settings(state_dir=tmp_path / "state", identity_dir=tmp_path / "identity",
                        auth_mode="cognito", issuer="https://cognito-idp.us-east-1.amazonaws.com/" + POOL,
                        audience=CLIENT)
    cognito = Mock()
    cognito.admin_get_user.return_value = {"Enabled": True, "UserAttributes": [
        {"Name": "sub", "Value": SUB}, {"Name": "email", "Value": EMAIL},
        {"Name": "email_verified", "Value": "true"}]}
    auth = Authenticator(settings, cognito=cognito, jwks=Mock(), entitlements=Mock(paid=Mock(return_value=False)))
    auth.plan_authority = Mock(plan=Mock(return_value="free"))
    auth.store = Mock()
    auth.store.get_admin_qa_grant.return_value = grant(issued_at=1, hard_expires_at=10)
    assert auth.is_paid(SUB) is False  # Expired at the actual wall clock.
    auth.store.get_admin_qa_grant.side_effect = RuntimeError("Dynamo unavailable")
    assert auth.is_paid(SUB) is False


def test_reissue_preserves_prior_audit_events_and_expiry_is_fail_closed(store):
    with pytest.raises(StoreError):
        store.issue_admin_qa_grant(SUB, grant(hard_expires_at=NOW + 86401), now=NOW + 2)
    first = grant()
    store.issue_admin_qa_grant(SUB, first, now=NOW + 1)
    attrs = {"sub": SUB, "email": EMAIL, "email_verified": "true"}
    assert not active_grant(store.get_admin_qa_grant(SUB), tenant=SUB, pool_id=POOL,
                            client_id=CLIENT, attributes=attrs, now=NOW + 3600)
    store.revoke_admin_qa_grant(SUB, first["audit_id"], ACTOR, "reviewed cleanup", now=NOW + 3601)
    second = grant(audit_id="b" * 32, issued_at=NOW + 3602, hard_expires_at=NOW + 7202)
    predecessor = store.get_admin_qa_grant(SUB)
    store.issue_admin_qa_grant(SUB, second, now=NOW + 3603,
                               expected_predecessor={"audit_id": first["audit_id"], "rev": predecessor["rev"]})
    assert store.get_admin_qa_grant(SUB)["audit_id"] == second["audit_id"]
    with pytest.raises(StoreError):
        store.issue_admin_qa_grant(SUB, grant(audit_id="c" * 32, issued_at=NOW + 3604,
                                             hard_expires_at=NOW + 7204), now=NOW + 3605,
                                   expected_predecessor={"audit_id": first["audit_id"], "rev": predecessor["rev"]})
    if isinstance(store, SQLiteStore):
        with store.connect() as db:
            assert db.execute("SELECT COUNT(*) FROM admin_qa_grant_events WHERE tenant=?", (SUB,)).fetchone()[0] == 3
    else:
        assert len(store._query(SUB, "admin_qa_grant_event")) == 3


def test_disabled_live_identity_cannot_use_active_grant(store, tmp_path):
    actual = time.time()
    value = grant(issued_at=actual - 2, hard_expires_at=actual + 3600,
                  audit_id="d" * 32)
    store.issue_admin_qa_grant(SUB, value, now=actual)
    settings = Settings(state_dir=tmp_path / "state", identity_dir=tmp_path / "identity",
                        auth_mode="cognito", issuer="https://cognito-idp.us-east-1.amazonaws.com/" + POOL,
                        audience=CLIENT)
    cognito = Mock()
    cognito.admin_get_user.return_value = {"Enabled": True, "UserAttributes": [
        {"Name": "sub", "Value": SUB}, {"Name": "email", "Value": EMAIL},
        {"Name": "email_verified", "Value": "true"}]}
    auth = Authenticator(settings, cognito=cognito, jwks=Mock(), entitlements=Mock())
    auth.plan_authority = Mock(plan=Mock(return_value="free"))
    auth.store = store
    paid, source, expiry = auth.entitlement(SUB)
    assert paid is True and source == AUTHORITY and expiry == value["hard_expires_at"]
    enabled = cognito.admin_get_user.return_value
    cognito.admin_get_user.side_effect = [enabled, {**enabled, "Enabled": False}]
    with pytest.raises(Exception) as raced:
        auth.entitlement(SUB)
    assert getattr(raced.value, "status_code", None) == 401
    cognito.admin_get_user.side_effect = None
    cognito.admin_get_user.return_value["Enabled"] = False
    with pytest.raises(Exception) as error:
        auth.entitlement(SUB)
    assert getattr(error.value, "status_code", None) == 401


@pytest.mark.parametrize("extra", ["PK", "SK", "kind", "rev", "revoked_at"])
def test_issue_rejects_reserved_or_revocation_fields(store, extra):
    with pytest.raises(StoreError):
        store.issue_admin_qa_grant(SUB, grant(**{extra: None}), now=NOW + 1)
    assert store.get_admin_qa_grant(SUB) is None


@pytest.mark.parametrize("revocation", [None, False, 0, "invalid"])
def test_nonrevoked_or_malformed_marker_does_not_authorize_repeat_issue(store, revocation):
    first = grant()
    store.issue_admin_qa_grant(SUB, first, now=NOW + 1)
    if isinstance(store, SQLiteStore):
        import json
        with store.transaction() as db:
            row = db.execute("SELECT record FROM admin_qa_grants WHERE tenant=?", (SUB,)).fetchone()
            value = json.loads(row["record"])
            value["revoked_at"] = revocation
            db.execute("UPDATE admin_qa_grants SET record=? WHERE tenant=?",
                       (json.dumps(value, sort_keys=True, separators=(",", ":")), SUB))
    else:
        from peaso.storage.dynamodb import attrs
        store.client.update_item(TableName=store.table,
                                 Key=attrs(store.key(SUB, "entitlement", "admin_qa")),
                                 UpdateExpression="SET revoked_at=:null",
                                 ExpressionAttributeValues=attrs({":null": revocation}))
    previous = store.get_admin_qa_grant(SUB)
    assert previous["revoked_at"] == revocation
    with pytest.raises(StoreError):
        store.issue_admin_qa_grant(SUB, grant(audit_id="b" * 32,
                                             issued_at=NOW + 2, hard_expires_at=NOW + 3602),
                                   now=NOW + 3,
                                   expected_predecessor={"audit_id": first["audit_id"], "rev": previous["rev"]})
    assert store.get_admin_qa_grant(SUB)["audit_id"] == first["audit_id"]


def test_operator_manifest_preimage_and_live_account_email_guards(tmp_path):
    import hashlib
    import json
    from scripts.peaso_test_resources.hosted_admin_qa_grant import load_manifest, live_identity
    value = {"account": "111122223333", "region": "us-east-1", "table": "hacktricks-cspm",
             "pool_id": POOL, "client_id": CLIENT, "cognito_username": "qa-user",
             "subject": SUB, "verified_email": EMAIL, "reason": "bounded acceptance run",
             "audit_id": "e" * 32, "issued_at": NOW, "hard_expires_at": NOW + 3600,
             "operator_role_prefix": "arn:aws:sts::111122223333:assumed-role/reviewed-operator/",
             "ledger_dir": str(tmp_path / "private")}
    path = tmp_path / "operator.private.json"
    path.write_text(json.dumps(value))
    path.chmod(0o600)
    sha = hashlib.sha256(path.read_bytes()).hexdigest()
    assert load_manifest(path, sha) == value
    with pytest.raises(RuntimeError):
        load_manifest(path, "0" * 64)
    path.chmod(0o644)
    with pytest.raises(RuntimeError):
        load_manifest(path, sha)
    path.chmod(0o600)
    session = Mock()
    sts, cognito = Mock(), Mock()
    session.client.side_effect = lambda name: {"sts": sts, "cognito-idp": cognito}[name]
    sts.get_caller_identity.return_value = {"Account": "111122223333", "Arn": ACTOR}
    cognito.admin_get_user.return_value = {"Enabled": True, "UserAttributes": [
        {"Name": "sub", "Value": SUB}, {"Name": "email", "Value": EMAIL},
        {"Name": "email_verified", "Value": "true"}]}
    cognito.describe_user_pool_client.return_value = {"UserPoolClient": {"UserPoolId": POOL,
                                                                           "ClientId": CLIENT}}
    assert live_identity(session, value) == ACTOR
    sts.get_caller_identity.return_value["Account"] = "000000000000"
    with pytest.raises(RuntimeError):
        live_identity(session, value)
    sts.get_caller_identity.return_value["Account"] = "111122223333"
    cognito.admin_get_user.return_value["UserAttributes"][1]["Value"] = "other@example.test"
    with pytest.raises(RuntimeError):
        live_identity(session, value)


def test_user_session_and_read_only_api_key_share_live_grant_then_revoke(store, tmp_path):
    import jwt
    from types import SimpleNamespace
    from cryptography.hazmat.primitives.asymmetric import rsa
    from fastapi.testclient import TestClient
    from peaso.server import create_app
    from peaso.storage import FileArtifacts

    actual = time.time()
    value = grant(issued_at=actual - 2, hard_expires_at=actual + 3600,
                  audit_id="f" * 32)
    store.issue_admin_qa_grant(SUB, value, now=actual)
    settings = Settings(state_dir=tmp_path / "state", identity_dir=tmp_path / "identity",
                        auth_mode="cognito", issuer="https://cognito-idp.us-east-1.amazonaws.com/" + POOL,
                        audience=CLIENT, origins=("https://cspm.hacktricks.wiki",))
    signing = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    jwks, cognito, entitlements = Mock(), Mock(), Mock()
    jwks.get_signing_key_from_jwt.return_value = SimpleNamespace(key=signing.public_key())
    def user(*, UserPoolId, Username):
        subject, email = (SUB, EMAIL) if Username == "qa-user" else ("other", "other@example.test")
        return {"Enabled": True, "UserAttributes": [
            {"Name": "sub", "Value": subject}, {"Name": "email", "Value": email},
            {"Name": "email_verified", "Value": "true"}]}
    cognito.admin_get_user.side_effect = user
    entitlements.paid.return_value = False
    auth = Authenticator(settings, cognito=cognito, jwks=jwks, entitlements=entitlements)
    auth.plan_authority = Mock(plan=Mock(return_value="free"))
    def token(subject, username):
        claims = {"iss": settings.issuer, "aud": settings.audience, "sub": subject,
                  "cognito:username": username, "token_use": "id",
                  "iat": int(actual), "exp": int(actual) + 600,
                  "custom:plan": "pentester", "paid": True}
        return jwt.encode(claims, signing, algorithm="RS256")
    alice, bob = token(SUB, "qa-user"), token("other", "other-user")
    app = create_app(settings, store=store, authenticator=auth,
                     artifacts=FileArtifacts(tmp_path / "artifacts"))
    with TestClient(app, base_url="https://cspm.hacktricks.wiki") as http:
        created = http.post("/api/api-keys", headers={"Authorization": "Bearer " + alice},
                            json={"name": "readonly-qa"})
        assert created.status_code == 201, created.text
        key = created.json()["key"]
        for credential in (alice, key):
            profile = http.get("/api/me", headers={"Authorization": "Bearer " + credential})
            assert profile.status_code == 200
            assert profile.json()["plan"] == "paid" and profile.json()["weekly_limit"] == 10
            assert profile.json()["plan_source"] == AUTHORITY
            assert profile.json()["plan_expires_at"] == value["hard_expires_at"]
            assert "audit_id" not in profile.text and "actor" not in profile.text
        assert http.post("/api/api-keys", headers={"Authorization": "Bearer " + key},
                         json={"name": "forbidden"}).status_code == 403
        bob_profile = http.get("/api/me", headers={"Authorization": "Bearer " + bob})
        assert bob_profile.status_code == 200 and bob_profile.json()["weekly_limit"] == 1
        store.revoke_admin_qa_grant(SUB, value["audit_id"], ACTOR,
                                    "QA acceptance complete", now=actual + 1)
        for credential in (alice, key):
            profile = http.get("/api/me", headers={"Authorization": "Bearer " + credential})
            assert profile.status_code == 200
            assert profile.json()["plan"] == "free" and profile.json()["weekly_limit"] == 1
            assert profile.json()["plan_source"] == "protected_tools_plan"
        cognito.admin_get_user.side_effect = lambda **kw: {**user(**kw), "Enabled": False}
        assert http.get("/api/me", headers={"Authorization": "Bearer " + alice}).status_code == 401
        assert http.get("/api/me", headers={"Authorization": "Bearer " + key}).status_code == 401


