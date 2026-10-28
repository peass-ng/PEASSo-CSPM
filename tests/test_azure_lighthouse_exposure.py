"""Azure Lighthouse assignments bind a foreign tenant to active scoped roles."""
from peaso.analysis.internet_exposure import assess
from peaso.collectors import azure
from peaso.collectors.azure_lighthouse_native import KIND
from peaso.snapshot import resources


SUB = "/subscriptions/11111111-1111-1111-1111-111111111111"
GROUP = SUB + "/resourceGroups/rg"
OWNER = "33333333-3333-3333-3333-333333333333"
FOREIGN = "22222222-2222-2222-2222-222222222222"
DEFINITION = SUB + "/providers/Microsoft.ManagedServices/registrationDefinitions/44444444-4444-4444-4444-444444444444"
ROLE = "55555555-5555-5555-5555-555555555555"
PRINCIPAL = "66666666-6666-6666-6666-666666666666"
ARM = "https://management.azure.com"


def _assignment(scope, tenant=FOREIGN, *, eligible=False, missing_definition=False):
    assignment_id = scope + "/providers/Microsoft.ManagedServices/registrationAssignments/77777777-7777-7777-7777-777777777777"
    role = {"principalId": PRINCIPAL, "roleDefinitionId": ROLE, "principalIdDisplayName": "secret-do-not-copy"}
    props = {"registrationDefinitionId": DEFINITION, "provisioningState": "Succeeded"}
    if not missing_definition:
        props["registrationDefinition"] = {"id": DEFINITION, "type": "Microsoft.ManagedServices/registrationDefinitions",
                                            "properties": {"managedByTenantId": tenant, "manageeTenantId": OWNER,
                                                           "provisioningState": "Succeeded",
                                                           "authorizations": [] if eligible else [role],
                                                           "eligibleAuthorizations": [role] if eligible else []}}
    return {"id": assignment_id, "name": assignment_id.rsplit("/", 1)[-1],
            "type": "Microsoft.ManagedServices/registrationAssignments", "properties": props}


def _scan(*, sub_assignment=None, group_assignment=None):
    group = {"id": GROUP, "name": "rg", "type": "Microsoft.Resources/resourceGroups", "properties": {"provisioningState": "Succeeded"}}
    class Transport:
        tenant = verified_tenant = OWNER
        def __init__(self): self.calls = []
        def request(self, url, *, body=None, audience=azure.ARM):
            self.calls.append(url)
            if body is not None:
                return {"data": []}
            assert url.startswith(ARM)
            path = url[len(ARM):].split("?", 1)[0]
            if path == SUB + "/resourcegroups":
                return {"value": [group]}
            if path == SUB + "/providers/Microsoft.ManagedServices/registrationAssignments":
                assert "$expandRegistrationDefinition=true" in url
                return {"value": [sub_assignment] if sub_assignment else []}
            if path == GROUP + "/providers/Microsoft.ManagedServices/registrationAssignments":
                assert "$expandRegistrationDefinition=true" in url
                return {"value": [group_assignment] if group_assignment else []}
            raise AssertionError(url)
    transport = Transport()
    snapshot = azure.collect({"scopes": [SUB], "auth": {}, "options": {"concurrency": 1, "retries": 0}},
                             requirements=[KIND], transport=transport)
    return snapshot, transport


def test_active_foreign_subscription_delegation_and_rg_discovery():
    snapshot, transport = _scan(sub_assignment=_assignment(SUB), group_assignment=_assignment(GROUP))
    results = assess(snapshot, resources(snapshot))
    assert len(results) == 2 and all(result.verdict() == "FAIL" for result in results)
    assert all(result.external_ids == [FOREIGN] for result in results)
    assert len(transport.calls) == len(set(transport.calls)) == snapshot["metadata"]["calls"]
    assert "secret-do-not-copy" not in repr(snapshot)


def test_jit_and_missing_definition_remain_unresolved():
    snapshot, _ = _scan(sub_assignment=_assignment(SUB, eligible=True),
                        group_assignment=_assignment(GROUP, missing_definition=True))
    assert [result.verdict() for result in assess(snapshot, resources(snapshot))] == ["UNKNOWN", "UNKNOWN"]


def test_same_tenant_assignment_does_not_create_foreign_trust():
    snapshot, _ = _scan(sub_assignment=_assignment(SUB, tenant=OWNER))
    result, = assess(snapshot, resources(snapshot))
    assert result.verdict() == "PASS" and result.external_ids == []
