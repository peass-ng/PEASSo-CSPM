"""Azure Lighthouse scoped delegated access from expanded assignments."""

from urllib.parse import urlsplit

from peaso.analysis.internet_exposure import assess, coverage_findings
from peaso.collectors import azure
from peaso.snapshot import make_snapshot, resources
from tests.test_peaso_azure_bulk_native import SCOPE, SUB, Transport, parent

GROUP = SCOPE + "/resourceGroups/rg"
ASSIGNMENT = GROUP + "/providers/Microsoft.ManagedServices/registrationAssignments/assign"
OWNER = "22222222-2222-2222-2222-222222222222"
FOREIGN = "33333333-3333-3333-3333-333333333333"


def assignment(managing=FOREIGN, grants=None, eligible=None):
    return parent(ASSIGNMENT, "Microsoft.ManagedServices/registrationAssignments", {
        "provisioningState": "Succeeded",
        "registrationDefinitionId": SCOPE + "/providers/Microsoft.ManagedServices/registrationDefinitions/def",
        "registrationDefinition": {"properties": {
            "managedByTenantId": managing, "manageeTenantId": OWNER,
            "provisioningState": "Succeeded",
            "authorizations": ([{"principalId": "person", "roleDefinitionId": "reader"}]
                               if grants is None else grants),
            "eligibleAuthorizations": [] if eligible is None else eligible,
        }},
    })


def test_lighthouse_collects_subscription_and_group_assignments_once():
    paths = {
        SCOPE: {"id": SCOPE, "subscriptionId": SUB, "tenantId": OWNER},
        SCOPE + "/resourcegroups": {"value": [parent(GROUP, "Microsoft.Resources/resourceGroups", {})]},
        SCOPE + "/providers/Microsoft.ManagedServices/registrationAssignments": {"value": []},
        GROUP + "/providers/Microsoft.ManagedServices/registrationAssignments": {
            "value": [assignment()]},
    }
    api = Transport(paths)
    snapshot = azure.collect({"scopes": [SUB], "options": {"retries": 0}},
                             ["lighthouse_assignment"], transport=api)
    rows = [row for row in snapshot["collections"] if row["type"] == "lighthouse_assignment"]
    assert len(rows) == 2 and {row["scope"] for row in rows} == {SCOPE, GROUP}
    expected = set(paths) | {"/providers/Microsoft.ResourceGraph/resources"}
    assert {urlsplit(url).path for url in api.calls} == expected
    assert len(api.calls) == len(expected)
    assert snapshot["metadata"]["subscription_tenants"][SCOPE] == OWNER


def test_lighthouse_foreign_active_and_eligible_only_decisions():
    def decision(item, metadata=None):
        snapshot = make_snapshot("azure", [SCOPE], [{"type": "lighthouse_assignment",
            "scope": GROUP, "service": "Microsoft.ManagedServices", "status": "collected",
            "items": [item]}], metadata={"subscription_tenants": {SCOPE: OWNER}} if metadata is None else metadata)
        rows = assess(snapshot, resources(snapshot))
        assert len(rows) == 1
        return rows[0]

    active = decision(assignment())
    assert active.verdict() == "FAIL" and active.external_ids == [FOREIGN]
    assert decision(assignment(managing=OWNER)).verdict() == "PASS"
    assert decision(assignment(grants=[], eligible=[])).verdict() == "PASS"
    assert decision(assignment(grants=[], eligible=[{
        "principalId": "person", "roleDefinitionId": "reader"}])).verdict() == "UNKNOWN"
    assert decision(assignment(), metadata={}).verdict() == "UNKNOWN"


def test_missing_resource_group_list_keeps_lighthouse_scope_coverage_unknown():
    snapshot = make_snapshot("azure", [SCOPE], [
        {"type": "resource_group", "scope": SCOPE, "service": "Microsoft.Resources",
         "status": "denied", "items": []},
        {"type": "lighthouse_assignment", "scope": SCOPE,
         "service": "Microsoft.ManagedServices", "status": "empty", "items": []},
    ])
    findings = coverage_findings(snapshot, resources(snapshot))
    assert len(findings) == 1 and findings[0]["status"] == "UNKNOWN"
