"""Recovery Services vault public and private access gates."""

from peaso.analysis.internet_exposure import assess
from peaso.snapshot import make_snapshot, resources


SCOPE = "/subscriptions/00000000-0000-0000-0000-000000000001"
VAULT = SCOPE + "/resourceGroups/rg/providers/Microsoft.RecoveryServices/vaults/v"
FOREIGN = "/subscriptions/00000000-0000-0000-0000-000000000002/resourceGroups/x/providers/Microsoft.Network/privateEndpoints/p"


def _finding(access, links):
    snap = make_snapshot("azure", [SCOPE], [{"type": "recovery_vault", "scope": SCOPE,
        "service": "Microsoft.RecoveryServices", "status": "collected", "items": [{
            "id": VAULT, "properties": {"provisioningState": "Succeeded",
                                         "publicNetworkAccess": access,
                                         "privateEndpointConnections": links}}]}])
    return next(a for a in assess(snap, resources(snap)) if a.resource["type"] == "recovery_vault")


def test_public_gate_and_foreign_private_link():
    assert _finding("Enabled", []).verdict() == "FAIL"
    assert _finding("Disabled", []).verdict() == "PASS"
    link = {"properties": {"provisioningState": "Succeeded", "privateEndpoint": {"id": FOREIGN},
                           "privateLinkServiceConnectionState": {"status": "Approved"}}}
    row = _finding("Disabled", [link])
    assert row.verdict() == "FAIL" and row.external_ids == [FOREIGN]
    assert _finding(None, []).verdict() == "UNKNOWN"
