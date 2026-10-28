"""User assigned identity federation grants external workload token exchange."""
from peaso.analysis.internet_exposure import federated_findings
from peaso.analysis.trust import azure_federated_credential
from peaso.collectors import azure
from peaso.snapshot import resources


SCOPE = "/subscriptions/11111111-1111-1111-1111-111111111111"
IDENTITY = SCOPE + "/resourceGroups/rg/providers/Microsoft.ManagedIdentity/userAssignedIdentities/worker"
FIC = IDENTITY + "/federatedIdentityCredentials/repo"
ISSUER = "https://token.actions.githubusercontent.com"


def test_preview_list_preserves_flexible_expression_and_detects_external_trust():
    expression = {"languageVersion": 1, "value": "claims['sub'] matches 'repo:org/app:ref:refs/heads/*' and claims['repository_id'] eq '123'"}
    class Transport:
        tenant = verified_tenant = None
        def __init__(self): self.urls = []
        def request(self, url, *, body=None, audience=azure.ARM):
            self.urls.append(url)
            if body is not None:
                return {"data": []}
            if "/federatedIdentityCredentials?" in url:
                assert url.endswith("api-version=2025-05-31-preview")
                return {"value": [{"id": FIC, "name": "repo",
                    "type": "Microsoft.ManagedIdentity/userAssignedIdentities/federatedIdentityCredentials",
                    "properties": {"issuer": ISSUER, "audiences": ["api://AzureADTokenExchange"],
                                   "claimsMatchingExpression": expression}}]}
            if "/providers/Microsoft.ManagedIdentity/userAssignedIdentities?" in url:
                return {"value": [{"id": IDENTITY, "name": "worker", "type": "Microsoft.ManagedIdentity/userAssignedIdentities",
                                   "properties": {"principalId": "11111111-2222-3333-4444-555555555555"}}]}
            return {"value": []}
    transport = Transport()
    snapshot = azure.collect({"scopes": [SCOPE], "auth": {}, "options": {"concurrency": 1, "retries": 0}},
                             requirements=["managed_identity_federated_credential"], transport=transport)
    selected = next(c for c in snapshot["collections"] if c["type"] == "managed_identity_federated_credential")
    assert selected["status"] == "collected" and selected["items"][0]["properties"]["claimsMatchingExpression"] == expression
    assert len(transport.urls) == len(set(transport.urls))
    found = federated_findings(snapshot, resources(snapshot))
    assert len(found) == 1 and found[0]["status"] == "FAIL"
    assert found[0]["title"] == "External workload can exchange tokens for a managed identity"
    assert found[0]["evidence"]["external_issuer_trust"] is True


def test_owned_aks_issuer_and_incomplete_aks_inventory():
    own = "https://oidc.prod-aks.azure.com/tenant/issuer"
    resource = {"type": "managed_identity_federated_credential", "data": {"properties": {
        "issuer": own, "subject": "system:serviceaccount:app:worker", "audiences": ["api://AzureADTokenExchange"]}}}
    complete = {"provider": "azure", "collections": [{"type": "aks_cluster", "status": "collected", "items": [
        {"properties": {"oidcIssuerProfile": {"issuerURL": own}}}]}]}
    assert azure_federated_credential(complete, resource)[0] == "PASS"
    missing = {"provider": "azure", "collections": [{"type": "aks_cluster", "status": "denied", "items": []}]}
    assert azure_federated_credential(missing, resource)[0] == "UNKNOWN"
    foreign = {"provider": "azure", "collections": [{"type": "aks_cluster", "status": "empty", "items": []}]}
    assert azure_federated_credential(foreign, resource)[0] == "FAIL"
