"""Default and selected API pipeline acceptance with offline provider evidence."""
import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

from peaso.auth import Identity
from peaso.server import create_app
from peaso.server.config import Settings
from peaso.snapshot import make_snapshot
from peaso.worker import Worker


class FixtureIdentities:
    def authenticate(self, authorization):
        if authorization not in ("Bearer fixture-owner", "Bearer fixture-other"):
            raise HTTPException(401, "Fixture authentication required")
        return Identity(authorization.split()[-1])

    def is_paid(self, tenant):
        return False


# The worker's public identity adapter accepts only canonical native scopes;
# Kubernetes contexts are trusted by exact connector membership instead.
SCOPES = {"aws": "123456789012/us-east-1", "gcp": "projects/fixture",
          "azure": "/subscriptions/fixture", "k8s": "fixture"}


def native_snapshot(provider):
    kinds = {"aws": ("vpc", {"VpcId": "vpc-fixture", "CidrBlock": "10.0.0.0/16"}),
             "gcp": ("network", {"id": "123", "name": "fixture", "selfLink": "https://www.googleapis.com/compute/v1/projects/fixture/global/networks/fixture", "autoCreateSubnetworks": False}),
             "azure": ("vnet", {"id": "/subscriptions/fixture/resourceGroups/fixture/providers/Microsoft.Network/virtualNetworks/fixture", "properties": {"addressSpace": {"addressPrefixes": ["10.0.0.0/16"]}, "subnets": []}}),
             "k8s": ("namespace", {"metadata": {"name": "fixture", "uid": "namespace-fixture", "labels": {}}})}
    kind, item = kinds[provider]
    scope = SCOPES[provider]
    return make_snapshot(provider, [scope], [{"type": kind, "scope": scope, "service": kind,
        "status": "collected", "items": [item]}], created_at="2026-10-10T00:00:00+00:00")


@pytest.mark.parametrize("provider", ["aws", "azure", "gcp", "k8s"])
@pytest.mark.parametrize("selectors", [{}, {"categories": ["hardening", "network"]}], ids=["default", "native"])
def test_native_pipeline_publishes_and_isolates_reports(tmp_path, provider, selectors):
    settings = Settings(state_dir=tmp_path / "state", identity_dir=tmp_path / "identity",
                        local_token="native-fixture-token-0123456789abcdef")
    app = create_app(settings, authenticator=FixtureIdentities())
    with TestClient(app, base_url="http://127.0.0.1:8000") as client:
        client.headers["Authorization"] = "Bearer fixture-owner"
        connector = client.post("/api/connectors", json={"name": "Native fixture", "provider": provider,
            "auth": {}, "scopes": [SCOPES[provider]], "options": {"snapshot": native_snapshot(provider)}})
        assert connector.status_code == 201, connector.text
        # Empty selectors exercise the production API default, including all analyses.
        scan = client.post("/api/scans", json={"ai_enabled": False, "connector_id": connector.json()["id"], **selectors})
        assert scan.status_code == 201, scan.text
        ident = scan.json()["id"]
        assert Worker("collector", settings).run_once()
        collected = client.get(f"/api/scans/{ident}").json()
        assert collected["status"] == "collected", collected
        assert Worker("analyzer", settings).run_once()
        status = client.get(f"/api/scans/{ident}").json()
        assert status["status"] == "completed", status
        report = client.get(f"/api/scans/{ident}/report")
        assert report.status_code == 200, report.text
        assert report.json()["provider"] == provider
        assert report.json()["input_mode"] == "offline_snapshot"
        assert client.get(f"/api/scans/{ident}/report?format=markdown").status_code == 200
        graph = client.get(f"/api/scans/{ident}/graphs/network?max_nodes=500")
        assert graph.status_code == 200 and graph.json()["nodes"]
        client.headers["Authorization"] = "Bearer fixture-other"
        for suffix in ("", "/report", "/graphs/network"):
            assert client.get(f"/api/scans/{ident}{suffix}").status_code == 404
