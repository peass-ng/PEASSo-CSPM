"""Sentinel source control exposes deployment trust metadata safely."""

from peaso.analysis.internet_exposure import assess
from peaso.collectors import azure, azure_sentinel_source_control_exposure as native
from peaso.snapshot import make_snapshot, resources

SUB = "00000000-0000-0000-0000-000000000001"
TENANT = "00000000-0000-0000-0000-000000000002"
FOREIGN = "00000000-0000-0000-0000-000000000003"
WORKSPACE = "/subscriptions/" + SUB + "/resourceGroups/rg/providers/Microsoft.OperationalInsights/workspaces/soc"
RID = WORKSPACE + "/providers/Microsoft.SecurityInsights/sourcecontrols/repo"


def _scan(*, repo="Github", principal_tenant=TENANT, federation=True):
    raw = {"id": RID, "type": "Microsoft.SecurityInsights/SourceControls",
           "properties": {"displayName": "PRIVATE_NAME", "repoType": repo,
               "contentTypes": ["AnalyticsRule", "Workbook"],
               "repository": {"url": "https://github.com/org/private-repo?token=PRIVATE_QUERY"},
               "repositoryAccess": {"token": "PRIVATE_PAT", "state": "PRIVATE_STATE"},
               "servicePrincipal": {"tenantId": principal_tenant},
               "workloadIdentityFederation": {"tenantId": principal_tenant,
                   "issuer": "https://token.actions.githubusercontent.com",
                   "subject": "repo:org/private-repo:ref:refs/heads/main"} if federation else None}}

    class Reader:
        collections = [{"type": "sentinel_workspace", "scope": "/subscriptions/" + SUB,
                        "status": "collected", "items": [{"id": WORKSPACE}]}]

        def pages(self, request, url):
            yield request(url)["value"]

        def run(self, jobs):
            for kind, scope, service, fetch in jobs:
                self.collections.append({"type": kind, "scope": scope, "service": service,
                                         "status": "collected", "items": [item for page in fetch() for item in page]})

    calls = []

    def request(url):
        calls.append(url)
        assert url == "https://management.azure.com" + WORKSPACE + "/providers/Microsoft.SecurityInsights/sourcecontrols?api-version=2025-09-01"
        return {"value": [raw]}

    reader = Reader()
    native.collect(reader, request, {native.KIND})
    assert len(calls) == 1
    assert "PRIVATE" not in str(reader.collections[-1]) and "org/private-repo" not in str(reader.collections[-1])
    snap = make_snapshot("azure", ["/subscriptions/" + SUB], reader.collections,
                         metadata={"tenant_id": TENANT, "tenant_verified": True})
    return next(a for a in assess(snap, resources(snap)) if a.resource["type"] == native.KIND)


def test_github_federation_and_foreign_principal():
    result = _scan()
    assert result.verdict() == "FAIL"
    assert any(step["layer"] == "github_workflow_federation" for step in result.path)
    result = _scan(principal_tenant=FOREIGN, federation=False)
    assert result.verdict() == "FAIL"
    assert result.external_ids == [FOREIGN]


def test_local_repository_credential_holders_unresolved():
    assert _scan(repo="AzureDevOps", federation=False).verdict() == "UNKNOWN"


def test_selected_source_control_includes_workspace():
    selected = azure._selected({"inventories": [native.KIND]}, None)
    assert "log_analytics_workspace" in selected
