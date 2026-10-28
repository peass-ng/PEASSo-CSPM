"""Domain Services public LDAPS is joined to collected NSG paths."""

import pytest

from peaso.analysis.internet_exposure import assess
from peaso.collectors import azure
from peaso.collectors import azure_domain_services_native as domains
from peaso.snapshot import make_snapshot, resources


SUB = "/subscriptions/00000000-0000-0000-0000-000000000001"
RID = SUB + "/resourceGroups/rg/providers/Microsoft.AAD/domainServices/example.test"
SUBNET = SUB + "/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/vnet/subnets/aadds"
NSG = SUB + "/resourceGroups/rg/providers/Microsoft.Network/networkSecurityGroups/nsg"


def _raw(ldaps="Enabled", external="Enabled", recipients=None, trusts=None):
    return {"id": RID, "name": "example.test", "type": "Microsoft.AAD/domainServices",
            "properties": {"domainName": "example.test",
                "ldapsSettings": {"ldaps": ldaps, "externalAccess": external,
                                  "pfxCertificate": "must-not-persist", "pfxCertificatePassword": "must-not-persist"},
                "replicaSets": [{"subnetId": SUBNET, "externalAccessIpAddress": "8.8.8.8",
                                 "domainControllerIpAddress": ["10.0.0.4"], "serviceStatus": "Running"}],
                "notificationSettings": {"additionalRecipients": recipients or []},
                "resourceForestSettings": {"settings": trusts or []},
                "privateData": "must-not-persist"}}


def _assessment(raw, *, nsg=False, subnet=True):
    projected = domains.project(raw, SUB)
    collections = [{"type": domains.KIND, "scope": SUB, "service": "Microsoft.AAD",
                    "status": "collected", "items": [projected]},
                   {"type": "subnet", "scope": SUB, "service": "Microsoft.Network",
                    "status": "collected", "items": [{"id": SUBNET, "properties": {
                        "networkSecurityGroup": {"id": NSG} if nsg else None}}] if subnet else []},
                   {"type": "directory_domain", "scope": SUB, "service": "Microsoft.Graph",
                    "status": "collected", "items": [{"id": "example.test", "isVerified": True}]}]
    if nsg:
        collections.append({"type": "nsg", "scope": SUB, "service": "Microsoft.Network",
                            "status": "collected", "items": [{"id": NSG, "properties": {
                                "securityRules": []}}]})
    snap = make_snapshot("azure", [SUB], collections)
    return next(a for a in assess(snap, resources(snap)) if a.resource["type"] == domains.KIND), projected


def test_public_ldaps_and_secret_free_projection():
    row, projected = _assessment(_raw())
    assert row.verdict() == "FAIL"
    assert row.addresses == ["8.8.8.8"]
    assert row.ports == {"tcp": ((636, 636),)}
    assert "must-not-persist" not in str(projected)


def test_disabled_nsg_denied_and_missing_subnet():
    assert _assessment(_raw(external="Disabled"))[0].verdict() == "PASS"
    assert _assessment(_raw(), nsg=True)[0].verdict() == "PASS"
    assert _assessment(_raw(), subnet=False)[0].verdict() == "UNKNOWN"


def test_off_domain_recipients_and_forest_trust_are_recorded_without_overclaim():
    raw = _raw(external="Disabled", recipients=["ops@partner.example"],
               trusts=[{"trustedDomainFqdn": "partner.example", "trustDirection": "Bidirectional",
                        "trustPassword": "must-not-persist"}])
    row, projected = _assessment(raw)
    assert row.verdict() == "UNKNOWN"
    assert row.external_ids == ["ops@partner.example", "partner.example"]
    assert "must-not-persist" not in str(projected)


def test_foreign_resource_rejected_and_one_subscription_list():
    with pytest.raises(ValueError):
        domains.project({**_raw(), "id": "/subscriptions/other" + RID}, SUB)
    reader = azure._Reader({})
    calls = []

    def request(url, **kwargs):
        calls.append(url)
        return {"value": [_raw()]}

    domains.collect(reader, request, [SUB], {domains.KIND})
    assert len(calls) == 1
    assert calls[0].endswith("/providers/Microsoft.AAD/domainServices?api-version=2022-12-01")
    assert reader.collections[0]["status"] == "collected"
