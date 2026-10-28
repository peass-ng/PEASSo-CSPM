"""Cross-tenant policy reads are cached and inherited partner trust is assessed."""

from types import SimpleNamespace

from peaso.analysis.internet_exposure import assess
from peaso.collectors import azure
from peaso.collectors import azure_cross_tenant_policy_native as policies
from peaso.snapshot import make_snapshot, resources


TENANT = "00000000-0000-0000-0000-000000000001"
PARTNER = "00000000-0000-0000-0000-000000000002"
SCOPE = "/tenants/" + TENANT


def _default():
    return {"isServiceDefault": True, "inboundTrust": {
        "isMfaAccepted": False, "isCompliantDeviceAccepted": False,
        "isHybridAzureADJoinedDeviceAccepted": False},
        "description": "must-not-persist"}


def _partner(*, sync=True, mfa=True):
    return {"tenantId": PARTNER, "inboundTrust": {"isMfaAccepted": mfa},
            "identitySynchronization": {"userSyncInbound": {"isSyncAllowed": sync}},
            "description": "must-not-persist"}


def _assess(default, partner):
    rows = [{"type": policies.DEFAULT, "scope": SCOPE, "status": "collected", "items": [
                policies.project(policies.DEFAULT, default, TENANT)]},
            {"type": policies.PARTNER, "scope": SCOPE, "status": "collected", "items": [
                policies.project(policies.PARTNER, partner, TENANT)]}]
    snap = make_snapshot("azure", [SCOPE], rows)
    return {a.resource["type"]: a for a in assess(snap, resources(snap))}


def test_partner_sync_and_trusted_external_mfa():
    results = _assess(_default(), _partner())
    assert results[policies.PARTNER].verdict() == "FAIL"
    assert results[policies.PARTNER].external_ids == [PARTNER]
    assert results[policies.DEFAULT].verdict() == "UNKNOWN"


def test_inbound_block_and_inherited_default():
    blocked = {"isServiceDefault": False, "b2bCollaborationInbound": {
        "usersAndGroups": {"accessType": "blocked", "targets": [
            {"target": "AllUsers", "targetType": "user"}]},
        "applications": {"accessType": "blocked", "targets": [
            {"target": "AllApplications", "targetType": "application"}]}}}
    blocked["b2bDirectConnectInbound"] = blocked["b2bCollaborationInbound"]
    assert _assess(blocked, _partner(sync=False, mfa=False))[policies.PARTNER].verdict() == "PASS"
    assert _assess(_default(), _partner(sync=False, mfa=True))[policies.PARTNER].verdict() == "FAIL"


def test_one_default_get_and_partner_list_with_safe_projection():
    reader = azure._Reader({})
    calls = []

    def request(url, **kwargs):
        calls.append(url)
        return {"value": [_partner()]} if "partners" in url else _default()

    policies.collect(reader, request, set(policies.KINDS), SimpleNamespace(tenant=TENANT))
    assert len(calls) == 2
    assert {row["type"] for row in reader.collections} == policies.KINDS
    assert "must-not-persist" not in str(reader.collections)
    assert all(row["status"] == "collected" for row in reader.collections)
