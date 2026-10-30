import hashlib
from pathlib import Path
import copy
import time
from types import SimpleNamespace
from unittest.mock import Mock
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import HTTPException
from fastapi.testclient import TestClient
from peaso.auth import Authenticator
from peaso.auth.billing import ProtectedToolsPlan, StripeEntitlements
from peaso.server import create_app
from peaso.server.config import Settings


@pytest.fixture
def cognito_settings(tmp_path):
    return Settings(state_dir=tmp_path / "state", identity_dir=tmp_path / "identity", auth_mode="cognito", issuer="https://cognito-idp.us-east-1.amazonaws.com/existing_pool", audience="existing_client", origins=("https://cspm.hacktricks.wiki",))


def jwt_auth(settings):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    jwks = Mock()
    jwks.get_signing_key_from_jwt.return_value = SimpleNamespace(key=key.public_key())
    cognito = Mock()
    cognito.admin_get_user.return_value = {"Enabled": True, "UserAttributes": [{"Name": "sub", "Value": "alice"}, {"Name": "custom:plan", "Value": "pentester"}]}
    entitlements = Mock()
    entitlements.paid.return_value = False
    auth = Authenticator(settings, cognito=cognito, jwks=jwks, entitlements=entitlements)
    claims = {"iss": settings.issuer, "aud": settings.audience, "sub": "alice", "token_use": "id", "iat": int(time.time()), "exp": int(time.time()) + 600, "custom:plan": "pentester", "paid": True}
    return auth, key, claims


def test_cognito_claims_cannot_self_grant_paid(cognito_settings):
    auth, key, claims = jwt_auth(cognito_settings)
    user = auth.authenticate("Bearer " + jwt.encode(claims, key, algorithm="RS256"))
    assert user.tenant_id == "alice" and user.weekly_limit == 1
    auth.entitlements.paid.return_value = True
    assert auth.authenticate("Bearer " + jwt.encode(claims, key, algorithm="RS256")).weekly_limit == 10
    auth.cognito.admin_get_user.return_value["UserAttributes"][0]["Value"] = "bob"
    with pytest.raises(HTTPException):
        auth.authenticate("Bearer " + jwt.encode(claims, key, algorithm="RS256"))


def test_subject_bound_protected_tools_plan_controls_quota(cognito_settings):
    auth, key, claims = jwt_auth(cognito_settings)
    auth.cognito.list_user_pool_clients.return_value = {"UserPoolClients": [
        {"UserPoolId": "existing_pool", "ClientId": "existing_client"},
    ]}
    auth.cognito.describe_user_pool_client.return_value = {"UserPoolClient": {
        "UserPoolId": "existing_pool", "ClientId": "existing_client", "WriteAttributes": ["email"],
    }}
    auth.plan_authority = ProtectedToolsPlan(auth.cognito, "existing_pool", "existing_client")
    claims["custom:plan"] = "free"
    with TestClient(create_app(cognito_settings, authenticator=auth), base_url="https://cspm.hacktricks.wiki") as client:
        client.headers["Authorization"] = "Bearer " + jwt.encode(claims, key, algorithm="RS256")
        paid = client.get("/api/me")
        assert paid.status_code == 200
        assert paid.json()["tenant_id"] == "alice"
        assert paid.json()["plan"] == "paid" and paid.json()["weekly_limit"] == 10
        # A live protected free plan takes precedence over a stale Stripe cache.
        auth.cognito.admin_get_user.return_value["UserAttributes"][1]["Value"] = "free"
        auth.entitlements.paid.return_value = True
        free = client.get("/api/me")
        assert free.status_code == 200
        assert free.json()["plan"] == "free" and free.json()["weekly_limit"] == 1


def test_unsafe_tools_client_cannot_make_forged_plan_paid(cognito_settings):
    auth, key, claims = jwt_auth(cognito_settings)
    auth.cognito.list_user_pool_clients.return_value = {"UserPoolClients": [
        {"UserPoolId": "existing_pool", "ClientId": "existing_client"},
    ]}
    auth.cognito.describe_user_pool_client.return_value = {"UserPoolClient": {
        "UserPoolId": "existing_pool", "ClientId": "existing_client", "WriteAttributes": ["custom:plan"],
    }}
    token = "Bearer " + jwt.encode(claims, key, algorithm="RS256")
    assert auth.authenticate(token).weekly_limit == 1
    auth.entitlements.paid.return_value = True
    assert auth.authenticate(token).weekly_limit == 10  # Independent verified-billing fallback.
    auth.cognito.admin_get_user.return_value["Enabled"] = False
    with pytest.raises(HTTPException):
        auth.authenticate(token)


@pytest.mark.parametrize("email,verification,expected_email,expected_verified", [
    ("alice@example.com", "false", "alice@example.com", False),
    ("alice@example.com", "true", "alice@example.com", True),
    ("invalid-address", "true", None, None),
    ("alice@example.com", "unexpected", "alice@example.com", False),
])
def test_me_displays_only_live_subject_profile_without_granting_paid(
    cognito_settings, email, verification, expected_email, expected_verified,
):
    auth, key, claims = jwt_auth(cognito_settings)
    claims.update(email="forged@example.com", email_verified=True, **{"custom:plan": "pentester"})
    auth.cognito.admin_get_user.return_value["UserAttributes"].extend([
        {"Name": "email", "Value": email},
        {"Name": "email_verified", "Value": verification},
    ])
    with TestClient(create_app(cognito_settings, authenticator=auth), base_url="https://cspm.hacktricks.wiki") as client:
        client.headers["Authorization"] = "Bearer " + jwt.encode(claims, key, algorithm="RS256")
        response = client.get("/api/me")
    assert response.status_code == 200
    profile = response.json()
    assert profile.get("email") == expected_email
    assert profile.get("email_verified") == expected_verified
    assert profile["tenant_id"] == "alice"
    assert profile["plan"] == "free" and profile["weekly_limit"] == 1


def test_disabled_identity_rejected_even_with_cached_paid(cognito_settings):
    auth, key, claims = jwt_auth(cognito_settings)
    auth.store = Mock()
    auth.store.get_entitlement.return_value = True
    auth.cognito.admin_get_user.return_value["Enabled"] = False
    with pytest.raises(HTTPException) as error:
        auth.authenticate("Bearer " + jwt.encode(claims, key, algorithm="RS256"))
    assert error.value.status_code == 401
    auth.store.get_entitlement.assert_not_called()


def test_deleted_identity_rejected_before_paid_cache(cognito_settings):
    auth, key, claims = jwt_auth(cognito_settings)
    auth.store = Mock()
    auth.store.get_entitlement.return_value = True
    deleted = RuntimeError("inert private provider error")
    deleted.response = {"Error": {"Code": "UserNotFoundException"}}
    auth.cognito.admin_get_user.side_effect = deleted
    with pytest.raises(HTTPException) as error:
        auth.authenticate("Bearer " + jwt.encode(claims, key, algorithm="RS256"))
    assert error.value.status_code == 401
    assert "private provider" not in error.value.detail
    auth.store.get_entitlement.assert_not_called()


@pytest.mark.parametrize("change", [{"iss": "https://evil.invalid"}, {"aud": "other-client"}, {"exp": 1}, {"token_use": "access"}, {"iat": int(time.time()) + 3600}])
def test_cognito_invalid_issuer_audience_expiry_use(cognito_settings, change):
    auth, key, claims = jwt_auth(cognito_settings)
    claims.update(change)
    with pytest.raises(HTTPException) as error:
        auth.authenticate("Bearer " + jwt.encode(claims, key, algorithm="RS256"))
    assert error.value.status_code == 401


def test_cognito_signature_and_unsigned_token(cognito_settings):
    auth, key, claims = jwt_auth(cognito_settings)
    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    for token in (jwt.encode(claims, other, algorithm="RS256"), jwt.encode(claims, "", algorithm="none")):
        with pytest.raises(HTTPException):
            auth.authenticate("Bearer " + token)


def test_existing_refresh_cookie_and_origin_csrf(cognito_settings):
    auth, key, claims = jwt_auth(cognito_settings)
    auth.cognito.initiate_auth.return_value = {"AuthenticationResult": {"IdToken": jwt.encode(claims, key, algorithm="RS256")}}
    with TestClient(create_app(cognito_settings, authenticator=auth), base_url="https://cspm.hacktricks.wiki") as client:
        client.cookies.set("__Secure-ht_refresh", "refresh-fixture")
        assert client.get("/api/me").status_code == 200
        assert client.post("/api/connectors", json={"name": "x", "provider": "aws", "auth": {}}).status_code == 403
        auth.cognito.initiate_auth.assert_called_with(ClientId=cognito_settings.audience, AuthFlow="REFRESH_TOKEN_AUTH", AuthParameters={"REFRESH_TOKEN": "refresh-fixture"})


def billing_fixture():
    attributes = {"email": "alice@example.com", "email_verified": "true", "custom:stripe_customer_id": "cus_fixture", "custom:plan": "pentester"}
    customer = {"id": "cus_fixture", "email": "alice@example.com", "metadata": {"source": "hacktricks-tools", "user_email": "alice@example.com"}}
    subscription = {"id": "sub_fixture", "customer": "cus_fixture", "status": "active", "metadata": {"source": "hacktricks-tools"}, "items": {"data": [{"price": {"id": "price_verified"}}]}}
    session = Mock()
    replies = [Mock(), Mock()]
    replies[0].json.return_value = customer
    replies[1].json.return_value = {"data": [subscription], "has_more": False}
    session.get.side_effect = replies
    return attributes, customer, subscription, StripeEntitlements(secret="stripe-fixture", price="price_verified", session=session)


def test_stripe_live_verified_entitlement():
    attributes, _, _, billing = billing_fixture()
    assert billing.paid(attributes)
    assert billing.session.get.call_count == 2


@pytest.mark.parametrize("change", ["unverified", "customer_email", "customer_metadata_email", "customer_source", "subscription_source", "subscription_customer", "subscription_status", "subscription_price"])
def test_stripe_flags_and_customer_links_cannot_forge_paid(change):
    attributes, customer, subscription, billing = billing_fixture()
    if change == "unverified": attributes["email_verified"] = "false"
    if change == "customer_email": customer["email"] = "bob@example.com"
    if change == "customer_metadata_email": customer["metadata"]["user_email"] = "bob@example.com"
    if change == "customer_source": customer["metadata"]["source"] = "other"
    if change == "subscription_source": subscription["metadata"]["source"] = "other"
    if change == "subscription_customer": subscription["customer"] = "cus_other"
    if change == "subscription_status": subscription["status"] = "cancelled"
    if change == "subscription_price": subscription["items"]["data"][0]["price"]["id"] = "price_other"
    assert not billing.paid(attributes)


@pytest.mark.parametrize("provider,auth,options", [
    ("aws", {"method": "profile", "profile": "/etc/passwd"}, {}),
    ("aws", {"method": "container"}, {}),
    ("aws", {"method": "access_keys", "aws_access_key_id": "fixture", "aws_secret_access_key": "fixture"}, {"endpoint_url": "http://169.254.169.254"}),
    ("aws", {"method": "access_keys", "aws_access_key_id": "fixture", "aws_secret_access_key": "fixture"}, {"hosted": False}),
    ("gcp", {"method": "service-account", "service_account_file": "/etc/passwd"}, {}),
    ("gcp", {"sa_json": {"type": "service_account", "token_uri": "http://169.254.169.254"}}, {}),
    ("azure", {"method": "workload-identity", "token_file": "/etc/passwd"}, {}),
    ("k8s", {"kubeconfig": "/etc/passwd"}, {}),
    ("k8s", {"server": "https://127.0.0.1", "token": "secret-fixture"}, {}),
    ("aws", {}, {"demo": True}),
    ("aws", {}, {"snapshot": {}}),
])
def test_hosted_unsafe_fields_rejected_before_persistence_and_quota(cognito_settings, provider, auth, options):
    authenticator, key, claims = jwt_auth(cognito_settings)
    with TestClient(create_app(cognito_settings, authenticator=authenticator), base_url="https://cspm.hacktricks.wiki") as client:
        client.headers["Authorization"] = "Bearer " + jwt.encode(claims, key, algorithm="RS256")
        value = client.post("/api/connectors", json={"name": "hostile", "provider": provider, "auth": auth, "options": options})
        assert value.status_code == 422, value.text
        assert client.get("/api/connectors").json() == {"items": []}
        assert client.get("/api/me").json()["weekly_used"] == 0




def test_customer_credentials_preserve_existing_role_chain_external_id(cognito_settings):
    from peaso.server.validation import validate_connector
    auth = {"method": "assume_role", "aws_access_key_id": "customer-fixture", "aws_secret_access_key": "customer-secret-fixture", "role_chain": [{"role_arn": "arn:aws:iam::123456789012:role/CustomerAudit", "external_id": "customer-existing-id", "role_session_name": "customer-audit"}]}
    validate_connector("aws", auth, {}, cognito_settings)
    assert auth["role_chain"][0]["external_id"] == "customer-existing-id"
    assert auth["method"] == "assume_role" and auth["aws_secret_access_key"] == "customer-secret-fixture"
    unlisted = {"method": "assume_role", "role_arn": "arn:aws:iam::123456789012:role/Unlisted"}
    validate_connector("aws", unlisted, {}, cognito_settings)
    assert unlisted["external_id"].startswith("hacktricks-cspm-")


@pytest.mark.parametrize("bad_auth", [
    {"method": "assume_role", "assume_roles": [{"role_arn": "arn:aws:iam::111122223333:role/Internal"}]},
    {"method": "assume_role", "assume_roles": [{"role_arn": "arn:aws:iam::444455556666:role/Internal"}]},
    {"method": "access_keys", "aws_access_key_id": "customer-fixture", "aws_secret_access_key": "customer-secret-fixture",
     "assume_roles": [{"role_arn": "arn:aws:iam::111122223333:role/Internal"}]},
    {"method": "assume_role", "assume_roles": [{"role_arn": "arn:aws:iam::123456789012:role/ReadOnly", "external_id": "chosen-id"}]},
    {"method": "assume_role", "assume_roles": [{"role_arn": "arn:aws:iam::123456789012:role/Bad*"}]},
    {"method": "assume_role", "assume_roles": [{"role_arn": f"arn:aws:iam::{i:012d}:role/ReadOnly"} for i in range(51)]},
])
def test_hosted_platform_target_validation(cognito_settings, bad_auth):
    from peaso.server.validation import validate_connector
    with pytest.raises(HTTPException) as error:
        validate_connector("aws", bad_auth, {}, cognito_settings)
    assert error.value.status_code == 422


def test_coverage_api_exposes_duplicate_role_skip_without_changing_account_collection(tmp_path):
    from peaso.auth import Identity
    from peaso.storage import SQLiteStore, FileArtifacts
    from peaso.storage.reports import publish_report

    account = "222233334444"
    second = f"arn:aws:iam::{account}:role/RoleB"
    settings = Settings(state_dir=tmp_path / "state", identity_dir=tmp_path / "identity",
        local_token="source52-coverage-token-0123456789")
    store = SQLiteStore(settings.state_dir)
    artifacts = FileArtifacts(settings.state_dir / "artifacts")
    connector = store.add_connector("alice", {"provider": "aws"}, "encrypted")
    job = store.enqueue("alice", {"connector_id": connector["id"]})
    collector = store.claim("collector")
    store.finish(job["id"], collector["owner"], "collected", artifacts.put("alice", job["id"], "snapshot", {}))
    analyzer = store.claim("analyzer")
    report = {"schema_version": "1.0", "provider": "aws", "snapshot_id": "fixture",
        "created_at": "2026-10-11T00:00:00Z", "scopes": [f"{account}/us-east-1"],
        "resources": [], "findings": [], "graphs": {"network": {"nodes": [], "edges": []},
            "iam": {"nodes": [], "edges": []}},
        "coverage": [{"level": "collection", "type": "vpc", "scope": f"{account}/us-east-1",
            "status": "collected", "resource_count": 1}],
        "snapshot_metadata": {"scan_coverage": [{"level": "credential_target", "scope": account,
            "account": account, "role_arn": second, "status": "not_collected",
            "code": "duplicate_account_target", "error_code": "duplicate_account_target"}]},
        "stats": {"finding_count": 0, "resource_count": 1}}
    reference = publish_report(artifacts, "alice", job["id"], report)
    store.finish(job["id"], analyzer["owner"], "completed", reference)

    class FixedIdentity:
        def authenticate(self, value):
            return Identity("alice")

    with TestClient(create_app(settings, store=store, artifacts=artifacts,
            authenticator=FixedIdentity()), base_url="http://127.0.0.1") as client:
        result = client.get(f"/api/scans/{job['id']}/coverage")
        assert result.status_code == 200
        assert result.json()["items"] == [report["coverage"][0], report["snapshot_metadata"]["scan_coverage"][0]]
        assert result.json()["total"] == 2
        assert client.get(f"/api/scans/{job['id']}/coverage?offset=1&limit=1").json()["items"] == [
            report["snapshot_metadata"]["scan_coverage"][0]]
        assert client.get(f"/api/scans/{job['id']}/summary").json()["coverage_count"] == 2
