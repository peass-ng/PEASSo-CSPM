"""Azure collector reads backing the HackTricks Cloud Best Practices checks: names/flags only, explicit coverage."""
import json
from urllib.parse import urlsplit

from peaso.collectors import azure
from peaso.snapshot import resources, validate
from peaso.analysis.internet_exposure import federated_findings

from test_peaso_collectors_azure_perf import FakeAzure, ReadError, rows

SUB = "/subscriptions/sub-a"
RG = SUB + "/resourceGroups/rg/providers"
SITE = RG + "/Microsoft.Web/sites/app"
AUTO = RG + "/Microsoft.Automation/automationAccounts/auto"


def test_site_basic_auth_policies_and_scm_use_main_are_embedded():
    def handler(url, body, audience):
        path = urlsplit(url).path
        if path == SUB + "/providers/Microsoft.Web/sites":
            return {"value": [{"id": SITE, "name": "app", "properties": {}}]}
        if path == SITE + "/config/web":
            return {"id": SITE + "/config/web", "properties": {"scmIpSecurityRestrictionsUseMain": False, "publishingPassword": "INERT_PRIVATE"}}
        if path == SITE + "/basicPublishingCredentialsPolicies/scm":
            return {"id": SITE + "/basicPublishingCredentialsPolicies/scm", "name": "scm", "properties": {"allow": True, "extra": "x"}}
        if path == SITE + "/basicPublishingCredentialsPolicies/ftp":
            raise ReadError(403)
        if path.startswith(SITE + "/config/"):
            return {"id": SITE + path[len(SITE):], "properties": {}}
        return {"value": []}
    snapshot = azure.collect({"scopes": ["sub-a"]}, ["app_service"], transport=FakeAzure(handler))
    assert validate(snapshot) == snapshot
    site = rows(snapshot, "app_service")[0]["items"][0]
    assert site["scmBasicAuthPolicy"]["properties"] == {"allow": True}
    assert site["configuration"]["properties"]["scmIpSecurityRestrictionsUseMain"] is False
    assert "ftpBasicAuthPolicy" not in site and site["_coverage"]["ftpBasicAuthPolicy"]["status"] == "denied"
    assert "INERT_PRIVATE" not in json.dumps(snapshot)


def test_automation_webhooks_keep_trigger_metadata_never_uri_or_parameters():
    def handler(url, body, audience):
        path = urlsplit(url).path
        if path == SUB + "/providers/Microsoft.Automation/automationAccounts":
            return {"value": [{"id": AUTO, "name": "auto", "properties": {}}]}
        if path == AUTO + "/webhooks":
            return {"value": [{"id": AUTO + "/webhooks/hook", "name": "hook", "properties": {
                "isEnabled": True, "expiryTime": "2036-01-01T00:00:00+00:00", "creationTime": "2026-01-01T00:00:00+00:00",
                "uri": "https://x.webhook.azure-automation.net/webhooks?token=INERT_PRIVATE", "parameters": {"p": "INERT_PRIVATE"},
                "runOn": "hybrid-group", "runbook": {"name": "rb", "secret": "INERT_PRIVATE"}}}]}
        return {"value": []}
    snapshot = azure.collect({"scopes": ["sub-a"]}, ["automation_account"], transport=FakeAzure(handler))
    assert validate(snapshot) == snapshot
    account = rows(snapshot, "automation_account")[0]["items"][0]
    hook = account["webhooks"][0]
    assert hook["properties"] == {"isEnabled": True, "expiryTime": "2036-01-01T00:00:00+00:00", "creationTime": "2026-01-01T00:00:00+00:00",
                                  "runOn": "hybrid-group", "runbook": {"name": "rb"}}
    assert account["_coverage"]["webhooks"]["status"] == "collected"
    assert "INERT_PRIVATE" not in json.dumps(snapshot)


def _directory(handler_extra):
    def handler(url, body, audience):
        assert audience == azure.GRAPH
        path = urlsplit(url).path
        result = handler_extra(url, path)
        if result is not None:
            return result
        return {"value": []}
    return FakeAzure(handler)


def test_service_principal_credentials_and_sso_mode_are_selected_without_secrets():
    calls = []
    def extra(url, path):
        calls.append(url)
        if path == "/v1.0/servicePrincipals":
            assert "passwordCredentials,keyCredentials,preferredSingleSignOnMode" in url
            return {"value": [{"id": "sp", "appId": "a", "preferredSingleSignOnMode": None,
                               "passwordCredentials": [{"keyId": "k", "endDateTime": "2027-01-01T00:00:00Z", "hint": "INE", "secretText": "INERT_PRIVATE"}],
                               "keyCredentials": []}]}
    snapshot = azure.collect({"scopes": ["sub-a"]}, ["directory_service_principal"], transport=_directory(extra))
    sp = rows(snapshot, "directory_service_principal")[0]["items"][0]
    assert sp["passwordCredentials"] == [{"keyId": "k", "endDateTime": "2027-01-01T00:00:00Z"}]
    assert "INERT_PRIVATE" not in json.dumps(snapshot) and '"INE"' not in json.dumps(snapshot)


def test_application_federated_credentials_per_app_with_denied_coverage():
    def extra(url, path):
        if path == "/v1.0/applications":
            return {"value": [{"id": "app1", "appId": "a1"}, {"id": "app2", "appId": "a2"}]}
        if path == "/beta/applications/app1/federatedIdentityCredentials":
            assert "claimsMatchingExpression" in url
            return {"value": [{"id": "f1", "name": "gh", "issuer": "https://token.actions.githubusercontent.com",
                               "subject": "repo:o/r:pull_request", "audiences": ["api://AzureADTokenExchange"], "description": "d"},
                              {"id": "f2", "name": "gh-flex", "issuer": "https://token.actions.githubusercontent.com",
                               "subject": None, "audiences": ["api://AzureADTokenExchange"],
                               "claimsMatchingExpression": {"languageVersion": 1,
                                   "value": "claims['sub'] matches 'repo:o/r:ref:refs/heads/*' and claims['repository_id'] eq '123'"},
                               "description": "INERT_PRIVATE"}]}
        if path == "/beta/applications/app2/federatedIdentityCredentials":
            raise ReadError(403)
    snapshot = azure.collect({"scopes": ["sub-a"]}, ["directory_federated_credential"], transport=_directory(extra))
    assert validate(snapshot) == snapshot
    tenant = "/tenants/tenant-a/applications/"
    first = rows(snapshot, "directory_federated_credential", tenant + "app1")[0]
    assert first["status"] == "collected"
    fic = first["items"][0]
    assert fic["id"] == "applications/app1/federatedIdentityCredentials/f1" and fic["appId"] == "a1"
    assert fic["subject"] == "repo:o/r:pull_request" and "description" not in fic
    flex = first["items"][1]
    assert flex["claimsMatchingExpression"] == {"languageVersion": 1,
        "value": "claims['sub'] matches 'repo:o/r:ref:refs/heads/*' and claims['repository_id'] eq '123'"}
    assert "INERT_PRIVATE" not in json.dumps(snapshot)
    reviews = federated_findings(snapshot, resources(snapshot))
    flex_review = next(row for row in reviews if row["evidence"].get("claims_matching_expression"))
    assert flex_review["status"] == "MANUAL"
    assert rows(snapshot, "directory_federated_credential", tenant + "app2")[0]["status"] == "denied"


def test_federated_credentials_unknown_when_application_inventory_denied():
    def extra(url, path):
        if path == "/v1.0/applications":
            raise ReadError(403)
    snapshot = azure.collect({"scopes": ["sub-a"]}, ["directory_federated_credential"], transport=_directory(extra))
    row = rows(snapshot, "directory_federated_credential")
    assert len(row) == 1 and row[0]["status"] not in ("collected", "empty", "partial") and row[0]["items"] == []


def test_managed_identity_flexible_credential_uses_expression_capable_child_version():
    parent = RG + "/Microsoft.ManagedIdentity/userAssignedIdentities/identity"
    def handler(url, body, audience):
        path = urlsplit(url).path
        if path == SUB + "/providers/Microsoft.ManagedIdentity/userAssignedIdentities":
            return {"value": [{"id": parent, "name": "identity",
                               "type": "Microsoft.ManagedIdentity/userAssignedIdentities", "properties": {}}]}
        if path == parent + "/federatedIdentityCredentials":
            assert "api-version=2025-05-31-preview" in url
            return {"value": [{"id": path + "/flex", "name": "flex", "properties": {
                "issuer": "https://token.actions.githubusercontent.com", "subject": None,
                "audiences": ["api://AzureADTokenExchange"],
                "claimsMatchingExpression": {"languageVersion": 1,
                    "value": "claims['sub'] matches 'repo:o/r:ref:refs/heads/*' and claims['repository_id'] eq '123'"}}}]}
        return {"value": []}
    snapshot = azure.collect({"scopes": ["sub-a"]}, ["managed_identity_federated_credential"],
                             transport=FakeAzure(handler))
    assert validate(snapshot) == snapshot
    fic = rows(snapshot, "managed_identity_federated_credential")[0]["items"][0]
    assert fic["properties"]["claimsMatchingExpression"]["languageVersion"] == 1


def test_cba_trust_store_drops_certificates():
    def extra(url, path):
        if path == "/v1.0/organization":
            return {"value": [{"id": "org"}]}
        if path == "/v1.0/organization/org/certificateBasedAuthConfiguration":
            return {"value": [{"id": "cba", "certificateAuthorities": [{"isRootAuthority": True, "certificate": "INERT_PRIVATE",
                                                                        "issuer": "CN=Root", "issuerSki": "AB", "certificateRevocationListUrl": None}]}]}
    snapshot = azure.collect({"scopes": ["sub-a"]}, ["directory_cba_configuration"], transport=_directory(extra))
    assert validate(snapshot) == snapshot
    item = rows(snapshot, "directory_cba_configuration")[0]["items"][0]
    assert item["certificateAuthorities"] == [{"isRootAuthority": True, "issuer": "CN=Root", "issuerSki": "AB", "certificateRevocationListUrl": None}]
    assert "INERT_PRIVATE" not in json.dumps(snapshot)


def test_web_pubsub_is_listed_like_signalr():
    assert azure.ENDPOINTS["web_pubsub"][0] == "Microsoft.SignalRService/webPubSub"
    assert azure.ENDPOINTS["signalr_service"] == ("Microsoft.SignalRService/signalR", "2024-03-01")
