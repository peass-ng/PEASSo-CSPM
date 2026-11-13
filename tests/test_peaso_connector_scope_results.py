"""Discovery boundaries and per-scope access results; no live credentials."""
import base64
import json
from types import SimpleNamespace
from concurrent.futures import ThreadPoolExecutor

import pytest
from fastapi.testclient import TestClient

from peaso.server.access_check import check_access
from peaso.server.config import Settings
from peaso.storage import SQLiteStore


def test_azure_subscription_discovery_pages_and_separates_denials(monkeypatch):
    first, second = "11111111-1111-1111-1111-111111111111", "22222222-2222-2222-2222-222222222222"
    calls = []
    class Transport:
        def __init__(self, auth): pass
        def request(self, url, **kwargs):
            calls.append(url)
            if url.endswith("subscriptions?api-version=2022-12-01"):
                return {"value": [{"subscriptionId": first}], "nextLink": "https://management.azure.com/subscriptions?api-version=2022-12-01&skip=1"}
            if "skip=1" in url:
                return {"value": [{"subscriptionId": second}]}
            if f"/subscriptions/{second}?" in url:
                raise PermissionError("denied")
            return {}
        def token(self, audience): raise PermissionError("Graph denied")
        def close(self): pass
    monkeypatch.setattr("peaso.collectors.azure.AzureTransport", Transport)
    result = check_access("azure", {"client_id": "fixture"}, ["*"], {}, Settings())
    assert result["scope_summary"] == {"unit": "subscriptions", "total": 2, "accessible": 1, "blocked": 1, "warning": 1, "not_checked": 0}
    rows = {row["scope"]: row for row in result["scope_results"]}
    assert rows[first]["status"] == "warning"
    assert any("role assignments" in issue["message"] for issue in rows[first]["issues"])
    assert rows[second]["status"] == "blocked"
    assert "Cannot read this subscription" in rows[second]["issues"][0]["message"]
    assert any("skip=1" in url for url in calls)


def test_azure_discovery_rejects_foreign_continuation_before_request(monkeypatch):
    calls = []
    class Transport:
        def __init__(self, auth): pass
        def request(self, url, **kwargs):
            calls.append(url)
            return {"value": [], "nextLink": "https://foreign.invalid/steal"}
        def token(self, audience): raise PermissionError
        def close(self): pass
    monkeypatch.setattr("peaso.collectors.azure.AzureTransport", Transport)
    result = check_access("azure", {}, [], {}, Settings())
    assert result["status"] == "blocked"
    assert len(calls) == 1 and "foreign.invalid" not in calls[0]


def test_azure_compares_authenticated_object_with_read_roles(monkeypatch):
    subscription = "11111111-1111-1111-1111-111111111111"
    object_id = "22222222-2222-2222-2222-222222222222"
    payload = base64.urlsafe_b64encode(json.dumps({"oid": object_id}).encode()).decode().rstrip("=")
    token = "header." + payload + ".signature"
    assigned = ["acdd72a7-3385-48ef-bd42-f606fba81ae7", "39bc4728-0917-49c7-9d2c-d95423bc2eb4"]
    class Transport:
        def __init__(self, auth): pass
        def request(self, url, **kwargs):
            if "/roleAssignments?" in url:
                return {"value": [{"properties": {"principalId": object_id,
                    "roleDefinitionId": "/providers/Microsoft.Authorization/roleDefinitions/" + role}}
                    for role in assigned]}
            return {}
        def token(self, audience): return token
        def close(self): pass
    monkeypatch.setattr("peaso.collectors.azure.AzureTransport", Transport)
    assert check_access("azure", {"method": "token"}, [subscription], {}, Settings())["status"] == "pass"
    assigned.pop()
    warning = check_access("azure", {"method": "token"}, [subscription], {}, Settings())
    assert warning["status"] == "warning"
    assert any("Security Reader" in issue["message"] and "Defender for Cloud" in issue["message"]
               for issue in warning["issues"])


def test_gcp_customer_credentials_discover_only_allowed_projects_and_keep_project_failures(monkeypatch):
    import requests
    class Credentials:
        def __init__(self, *args, **kwargs): pass
        def headers(self): return {"Authorization": "fixture"}
        def close(self): pass
    class Response:
        def __init__(self, value): self.value = value
        def raise_for_status(self): pass
        def json(self): return self.value
    calls = []
    def get(url, **kwargs):
        calls.append(url)
        if url.endswith("projects:search"):
            return Response({"projects": [{"projectId": name} for name in ("customer-one", "customer-two", "excluded-project")]})
        return Response({"projectId": url.rsplit("/", 1)[-1]})
    def post(url, **kwargs):
        if url.endswith(":getIamPolicy"):
            return Response({"bindings": [{"role": role, "members": ["serviceAccount:reader@identity.iam.gserviceaccount.com"]}
                                          for role in ("roles/viewer", "roles/iam.securityReviewer", "roles/cloudasset.viewer",
                                                       "roles/serviceusage.serviceUsageConsumer", "roles/logging.privateLogViewer",
                                                       "roles/securitycenter.findingsViewer", "roles/recommender.viewer")]})
        return Response({"permissions": kwargs["json"]["permissions"] if "customer-one" in url else []})
    monkeypatch.setattr("peaso.collectors.gcp.Credentials", Credentials)
    monkeypatch.setattr(requests, "get", get)
    monkeypatch.setattr(requests, "post", post)
    result = check_access("gcp", {"method": "service-account", "sa_json": {"client_email": "reader@identity.iam.gserviceaccount.com"}}, ["*"],
        {"all_projects": True, "allowed_projects": ["customer-one", "projects/customer-two"]}, Settings())
    assert result["scope_summary"]["total"] == 2
    assert result["scope_summary"]["accessible"] == 2
    rows = {row["scope"]: row for row in result["scope_results"]}
    assert rows["customer-one"]["status"] == "pass"
    assert rows["customer-two"]["status"] == "blocked"
    assert not any(url.endswith("/excluded-project") for url in calls)


def test_shared_gcp_discovery_never_loads_credentials(monkeypatch):
    monkeypatch.setattr("peaso.gcp_platform.load_service_account", lambda *args: pytest.fail("Shared credentials must not be loaded for discovery"))
    result = check_access("gcp", {"method": "platform-service-account"}, ["*"], {"all_projects": True}, Settings())
    assert result["status"] == "blocked"
    assert not result["principals"]


def test_kubernetes_discovery_and_denials_are_namespace_specific(monkeypatch):
    calls = []
    class Response:
        def __init__(self, data): self.data = json.dumps(data).encode()
        def close(self): pass
        def release_conn(self): pass
    class Client:
        rest_client = SimpleNamespace(pool_manager=SimpleNamespace())
        def call_api(self, path, method, **kwargs):
            calls.append((path, method, kwargs.get("body")))
            if method == "GET":
                if path.startswith("/api/v1/namespaces?"):
                    if "continue=" in path:
                        return Response({"items": [{"metadata": {"name": "production"}}]})
                    return Response({"items": [{"metadata": {"name": "default"}}], "metadata": {"continue": "next"}})
                if path.endswith("/production"):
                    raise PermissionError("denied")
                return Response({"metadata": {"name": "default"}})
            attrs = kwargs["body"]["spec"]["resourceAttributes"]
            return Response({"status": {"allowed": attrs["resource"] != "secrets"}})
    monkeypatch.setattr("peaso.collectors.k8s._new_api", lambda auth: SimpleNamespace(api_client=Client()))
    result = check_access("k8s", {"server": "https://cluster.example"}, ["*"], {}, Settings())
    assert result["scope_summary"] == {"unit": "namespaces", "total": 2, "accessible": 1, "blocked": 1, "warning": 1, "not_checked": 0}
    rows = {row["scope"]: row for row in result["scope_results"]}
    assert rows["default"]["status"] == "warning"
    assert rows["production"]["status"] == "blocked"
    assert all(body["spec"]["resourceAttributes"].get("namespace") == "default" for _, method, body in calls
               if method == "POST" and body["spec"]["resourceAttributes"]["resource"] in {"pods", "roles", "rolebindings", "deployments", "secrets"})
    assert not any(method == "GET" and path.endswith("/secrets") for path, method, _ in calls)


def test_workspace_external_ids_are_persistent_distinct_and_race_safe(tmp_path):
    store = SQLiteStore(tmp_path)
    with ThreadPoolExecutor(max_workers=8) as pool:
        values = list(pool.map(store.workspace_external_id, ["workspace-a"] * 16))
    assert len(set(values)) == 1
    first = values[0]
    assert first.startswith("hacktricks-cspm-ws-") and len(first.removeprefix("hacktricks-cspm-ws-")) == 64
    assert SQLiteStore(tmp_path).workspace_external_id("workspace-a") == first
    assert store.workspace_external_id("workspace-b") != first


def test_workspace_role_setup_cannot_be_replayed_or_forged_across_workspaces(tmp_path, monkeypatch):
    from peaso.server import create_app
    from tests.test_peaso_workspaces import WorkspaceIdentities
    settings = Settings(auth_mode="cognito", state_dir=tmp_path / "state", identity_dir=tmp_path / "identity")
    store = SQLiteStore(settings.state_dir)
    seen = []
    monkeypatch.setattr("peaso.server.access_check.check_access", lambda *args, **kwargs: seen.append(args) or {"status": "pass", "issues": [], "principals": []})
    with TestClient(create_app(settings, store=store, authenticator=WorkspaceIdentities())) as client:
        headers = {"Authorization": "Bearer owner"}
        workspaces = [client.post("/api/workspaces", headers=headers, json={"name": name}).json()["id"] for name in ("Team Alpha", "Team Bravo")]
        def prepare(workspace):
            return client.post("/api/connectors/prepare", headers=headers | {"X-Workspace-Id": workspace}, json={"provider": "aws", "method": "assume_role"})
        first, second = [prepare(workspace).json() for workspace in workspaces]
        assert first["external_id"] != second["external_id"]
        assert prepare(workspaces[0]).json()["external_id"] == first["external_id"]
        assert client.post(f"/api/workspaces/{workspaces[0]}/invitations", headers=headers,
                           json={"email": "writer@example.com", "role": "write"}).status_code == 201
        writer = {"Authorization": "Bearer writer", "X-Workspace-Id": workspaces[0]}
        assert client.post(f"/api/workspaces/invitations/{workspaces[0]}/accept", headers={"Authorization": "Bearer writer"}).status_code == 200
        assert client.post("/api/connectors/prepare", headers=writer,
                           json={"provider": "aws", "method": "assume_role"}).json()["external_id"] == first["external_id"]
        body = {"name": "Audit", "provider": "aws", "scopes": ["123456789012"], "options": {},
            "auth": {"method": "assume_role", "role_arn": "arn:aws:iam::123456789012:role/Audit"}, "prepared_id": first["prepared_id"]}
        rejected = client.post("/api/connectors/check-access", headers=headers | {"X-Workspace-Id": workspaces[1]}, json=body)
        assert rejected.status_code == 422 and not seen
        accepted = client.post("/api/connectors/check-access", headers=headers | {"X-Workspace-Id": workspaces[0]}, json=body)
        assert accepted.status_code == 200 and seen[-1][1]["external_id"] == first["external_id"]
        body.pop("prepared_id")
        body["auth"]["external_id"] = second["external_id"]
        assert client.post("/api/connectors/check-access", headers=headers | {"X-Workspace-Id": workspaces[0]}, json=body).status_code == 422
        assert len(seen) == 1
        # An existing/made-up connector ID must never turn client auth into trusted server auth.
        body["connector_id"] = "missing-connector"
        assert client.post("/api/connectors/check-access", headers=headers | {"X-Workspace-Id": workspaces[0]}, json=body).status_code == 404
        body.pop("connector_id")
        body["auth"].pop("external_id")
        body["prepared_id"] = first["prepared_id"]
        body["check_token"] = client.post("/api/connectors/check-access", headers=headers | {"X-Workspace-Id": workspaces[0]}, json=body).json()["check_token"]
        saved = client.post("/api/connectors", headers=headers | {"X-Workspace-Id": workspaces[0]}, json=body)
        assert saved.status_code == 201
        connector_id = saved.json()["id"]
        body.pop("prepared_id")
        body["connector_id"] = connector_id
        body["auth"]["external_id"] = second["external_id"]
        assert client.post("/api/connectors/check-access", headers=headers | {"X-Workspace-Id": workspaces[0]}, json=body).status_code == 422
        assert client.post("/api/connectors/check-access", headers=headers | {"X-Workspace-Id": workspaces[1]}, json=body).status_code == 404
        body["auth"] = {}
        assert client.post("/api/connectors/check-access", headers=headers | {"X-Workspace-Id": workspaces[0]}, json=body).status_code == 200
        assert seen[-1][1]["external_id"] == first["external_id"]
        replacement_auth = {"method": "assume_role", "role_arn": "arn:aws:iam::123456789012:role/Audit"}
        replacement_check = client.post("/api/connectors/check-access", headers=headers | {"X-Workspace-Id": workspaces[0]}, json={
            "name": "Audit", "provider": "aws", "scopes": ["123456789012"], "options": {},
            "auth": replacement_auth, "prepared_id": first["prepared_id"], "connector_id": connector_id})
        assert replacement_check.status_code == 200
        replaced = client.patch("/api/connectors/" + connector_id, headers=headers | {"X-Workspace-Id": workspaces[0]}, json={
            "auth": replacement_auth, "prepared_id": first["prepared_id"],
            "check_token": replacement_check.json()["check_token"]})
        assert replaced.status_code == 200
        assert replaced.json()["onboarding"]["external_id"] == first["external_id"]


def test_dynamodb_external_id_allocation_keeps_the_atomic_winner(monkeypatch):
    import boto3
    from botocore.stub import Stubber
    from peaso.storage.dynamodb import DynamoStore, attrs
    client = boto3.client("dynamodb", region_name="us-east-1", aws_access_key_id="inert", aws_secret_access_key="inert")
    store = DynamoStore("metadata", client)
    key = attrs(store.key("workspace-a", "aws_external_id", "workspace"))
    monkeypatch.setattr("secrets.token_urlsafe", lambda size: "x" * 64)
    candidate = "hacktricks-cspm-ws-" + "x" * 64
    winner = "hacktricks-cspm-ws-" + "y" * 64
    with Stubber(client) as stub:
        stub.add_response("get_item", {}, {"TableName": "metadata", "Key": key, "ConsistentRead": True})
        stub.add_client_error("put_item", service_error_code="ConditionalCheckFailedException", expected_params={
            "TableName": "metadata", "Item": attrs(dict(store.key("workspace-a", "aws_external_id", "workspace"), external_id=candidate, kind="aws_external_id", rev=0)),
            "ConditionExpression": "attribute_not_exists(PK)"})
        stub.add_response("get_item", {"Item": attrs({"external_id": winner})}, {"TableName": "metadata", "Key": key, "ConsistentRead": True})
        assert store.workspace_external_id("workspace-a") == winner
        stub.assert_no_pending_responses()


def test_aws_account_results_include_denied_targets_and_selected_scope(monkeypatch):
    import boto3
    one, two = "123456789012", "210987654321"
    assumptions = []
    class Session:
        def __init__(self, account=None): self.account = account
        def client(self, service, **kwargs): return self
        def assume_role(self, **kwargs):
            assumptions.append(kwargs["RoleArn"])
            account = kwargs["RoleArn"].split(":")[4]
            if account == two: raise PermissionError("denied")
            return {"Credentials": {"AccessKeyId": account, "SecretAccessKey": "inert", "SessionToken": "inert"}}
        def get_caller_identity(self): return {"Account": self.account, "Arn": f"arn:aws:iam::{self.account}:role/Audit"}
        def list_attached_role_policies(self, **kwargs):
            return {"AttachedPolicies": [{"PolicyArn": "arn:aws:iam::aws:policy/" + name}
                    for name in ("ReadOnlyAccess", "SecurityAudit", "IAMAccessAnalyzerFullAccess")]}
        def __getattr__(self, name): return lambda **kwargs: {}
    monkeypatch.setattr("peaso.collectors.aws._session", lambda auth, region: (Session(), region))
    monkeypatch.setattr(boto3, "Session", lambda **kwargs: Session(kwargs["aws_access_key_id"]))
    result = check_access("aws", {"method": "access_keys", "aws_access_key_id": "inert", "aws_secret_access_key": "inert",
        "assume_roles": [{"role_arn": f"arn:aws:iam::{one}:role/Audit"}, {"role_arn": f"arn:aws:iam::{one}:role/Skipped"}, {"role_arn": f"arn:aws:iam::{two}:role/Audit"}]},
        [one + "/us-east-1", one + "/eu-west-1", two], {"include_source_account": False}, Settings())
    assert assumptions == [f"arn:aws:iam::{one}:role/Audit", f"arn:aws:iam::{two}:role/Audit"]
    assert result["scope_summary"]["total"] == 2
    assert result["scope_summary"]["accessible"] == 1
    rows = {row["scope"]: row for row in result["scope_results"]}
    assert rows[one]["status"] == "pass"
    assert rows[two]["status"] == "blocked" and rows[two]["issues"]


def test_shared_gcp_keeps_connector_approval_proof_during_access_checks(monkeypatch):
    import requests
    from peaso.gcp_platform import PLATFORM_EMAIL, PLATFORM_PROJECT
    class Credentials:
        def __init__(self, *args, **kwargs): pass
        def headers(self): return {}
        def close(self): pass
    class Response:
        def raise_for_status(self): pass
        def json(self):
            return {"name": "projects/123456789", "projectId": "customer-project", "state": "ACTIVE",
                    "labels": {"hacktricks-cspm-11111111111111111111": "approved"}}
    monkeypatch.setattr("peaso.gcp_platform.load_service_account", lambda *args: {"project_id": PLATFORM_PROJECT, "client_email": PLATFORM_EMAIL})
    monkeypatch.setattr("peaso.collectors.gcp.Credentials", Credentials)
    monkeypatch.setattr(requests, "get", lambda *args, **kwargs: Response())
    monkeypatch.setattr(requests, "post", lambda *args, **kwargs: pytest.fail("Wrong workspace proof must prevent permission probes"))
    result = check_access("gcp", {"method": "platform-service-account", "project_proof_label": "hacktricks-cspm-00000000000000000000"},
                          ["customer-project"], {}, Settings())
    assert result["status"] == "blocked"
    assert result["scope_summary"]["accessible"] == 0
    assert "approval label" in result["scope_results"][0]["issues"][0]["message"]


def test_aws_organization_discovery_is_paginated_and_respects_account_selection(monkeypatch):
    import boto3
    selected, excluded = "210987654321", "123456789012"
    pages, assumed = [], []
    class Session:
        def __init__(self, account=None): self.account = account
        def client(self, service, **kwargs): return self
        def list_accounts(self, **kwargs):
            pages.append(kwargs.get("NextToken"))
            if kwargs.get("NextToken"):
                return {"Accounts": [{"Id": selected, "State": "ACTIVE"}]}
            return {"Accounts": [{"Id": excluded, "State": "ACTIVE"}], "NextToken": "next"}
        def assume_role(self, **kwargs):
            assumed.append(kwargs["RoleArn"])
            return {"Credentials": {"AccessKeyId": selected, "SecretAccessKey": "inert", "SessionToken": "inert"}}
        def get_caller_identity(self): return {"Account": self.account, "Arn": f"arn:aws:iam::{self.account}:role/Audit"}
        def __getattr__(self, name): return lambda **kwargs: {}
    monkeypatch.setattr("peaso.collectors.aws._session", lambda auth, region: (Session(), region))
    monkeypatch.setattr(boto3, "Session", lambda **kwargs: Session(kwargs["aws_access_key_id"]))
    result = check_access("aws", {"method": "access_keys", "aws_access_key_id": "inert", "aws_secret_access_key": "inert"},
                          [selected], {"organization_role_name": "Audit", "include_source_account": False}, Settings())
    assert pages == [None, "next"]
    assert assumed == [f"arn:aws:iam::{selected}:role/Audit"]
    assert result["scope_summary"]["total"] == result["scope_summary"]["accessible"] == 1
    assert result["scope_results"][0]["scope"] == selected
