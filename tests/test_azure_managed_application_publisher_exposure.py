"""Managed Application publisher access is a tenant-boundary exposure."""

from peaso.analysis.internet_exposure import assess
from peaso.collectors import azure, azure_swc
from peaso.snapshot import make_snapshot, resources


SCOPE = "/subscriptions/00000000-0000-0000-0000-000000000001"
RID = SCOPE + "/resourceGroups/rg/providers/Microsoft.Solutions/applications/app"
GROUP = SCOPE + "/resourceGroups/managed"
OWNER = "00000000-0000-0000-0000-000000000010"
PUBLISHER = "00000000-0000-0000-0000-000000000020"


def _raw(*, publisher=PUBLISHER, mode="Managed", jit=None, grants=True):
    return {"id": RID, "name": "app", "type": "Microsoft.Solutions/applications",
            "kind": "MarketPlace", "properties": {"provisioningState": "Succeeded",
                "managedResourceGroupId": GROUP, "publisherTenantId": publisher,
                "managementMode": mode,
                "authorizations": [{"principalId": "publisher-principal",
                                    "roleDefinitionId": "publisher-role", "extra": "discard"}] if grants else [],
                "jitAccessPolicy": jit, "parameters": {"password": "must-not-persist"},
                "outputs": {"secret": "must-not-persist"}}}


def _result(raw):
    item = azure_swc.list_detail(raw, "managed_application")
    snap = make_snapshot("azure", [SCOPE], [{"type": "managed_application", "scope": SCOPE,
        "service": "Microsoft.Solutions", "status": "collected", "items": [item]}],
        metadata={"tenant_id": OWNER, "tenant_verified": True})
    return next(a for a in assess(snap, resources(snap)) if a.resource["type"] == "managed_application"), item


def test_foreign_publisher_grant_and_safe_projection():
    row, item = _result(_raw())
    assert row.verdict() == "FAIL" and row.external_ids == [PUBLISHER]
    assert row.path[-1]["managed_resource_group_id"] == GROUP
    assert "must-not-persist" not in str(item)
    assert "extra" not in str(item)
    assert azure.ENDPOINTS["managed_application"] == ("Microsoft.Solutions/applications", "2019-07-01")


def test_publisher_access_modes_and_jit_uncertainty():
    assert _result(_raw(publisher=OWNER))[0].verdict() == "PASS"
    assert _result(_raw(mode="Unmanaged"))[0].verdict() == "PASS"
    assert _result(_raw(grants=False))[0].verdict() == "FAIL"
    assert _result(_raw(jit={"jitAccessEnabled": True, "jitApprovalMode": "ManualApprove"}))[0].verdict() == "FAIL"
    assert _result(_raw(jit={"jitApprovalMode": "ManualApprove"}))[0].verdict() == "FAIL"


def test_owner_unknown_does_not_guess_externality():
    item = azure_swc.list_detail(_raw(), "managed_application")
    snap = make_snapshot("azure", [SCOPE], [{"type": "managed_application", "scope": SCOPE,
        "service": "Microsoft.Solutions", "status": "collected", "items": [item]}])
    assert next(a for a in assess(snap, resources(snap)) if a.resource["type"] == "managed_application").verdict() == "UNKNOWN"


def test_jit_requests_are_read_once_per_resource_group_without_credentials():
    first = azure_swc.list_detail(_raw(jit={"jitAccessEnabled": True}), "managed_application")
    second = {**first, "id": RID[:-3] + "two", "name": "two"}
    calls = []
    request_row = {"id": SCOPE + "/resourceGroups/rg/providers/Microsoft.Solutions/jitRequests/request",
                   "type": "Microsoft.Solutions/jitRequests", "properties": {
                       "applicationResourceId": RID, "publisherTenantId": PUBLISHER,
                       "jitRequestState": "Approved", "provisioningState": "Succeeded",
                       "jitSchedulingPolicy": {"startTime": "2026-10-28T08:00:00Z",
                                               "duration": "PT1H", "type": "Once"},
                       "createdBy": {"secret": "must-not-persist"}}}

    def request(url, **kwargs):
        calls.append(url)
        return {"value": [request_row]}

    azure._collect_managed_application_jit(azure._Reader({}), request,
                                           [("managed_application", first), ("managed_application", second)])
    assert len(calls) == 1
    assert [row["id"] for row in first["jitRequests"]] == [request_row["id"]]
    assert second["jitRequests"] == []
    assert "must-not-persist" not in str(first)
