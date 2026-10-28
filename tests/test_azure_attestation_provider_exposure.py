"""Attestation API exposure and secret-free ARM projection."""

import pytest

from peaso.analysis.internet_exposure import assess
from peaso.collectors import azure
from peaso.collectors import azure_attestation_native as attestation
from peaso.snapshot import make_snapshot, resources


SCOPE = "/subscriptions/00000000-0000-0000-0000-000000000001"
RID = SCOPE + "/resourceGroups/rg/providers/Microsoft.Attestation/attestationProviders/provider"


def _raw(access="Enabled", status="Ready", trust="AAD"):
    return {"id": RID, "name": "provider", "type": "Microsoft.Attestation/attestationProviders",
            "location": "westeurope", "properties": {
                "status": status, "trustModel": trust, "publicNetworkAccess": access,
                "attestUri": "https://provider.eus.attest.azure.net/private?sig=must-not-persist",
                "tpmAttestationAuthentication": "Disabled",
                "policySigningCertificates": {"keys": [{"d": "must-not-persist"}]}}}


def _assessment(raw):
    row = attestation.project(raw, SCOPE)
    snap = make_snapshot("azure", [SCOPE], [{"type": attestation.KIND, "scope": SCOPE,
        "service": "Microsoft.Attestation", "status": "collected", "items": [row]}])
    result = next(a for a in assess(snap, resources(snap)) if a.resource["type"] == attestation.KIND)
    return result, row


def test_public_endpoint_and_secret_free_projection():
    result, row = _assessment(_raw())
    assert result.verdict() == "FAIL"
    assert result.addresses == ["provider.eus.attest.azure.net"]
    assert result.ports == {"tcp": ((443, 443),)}
    assert "must-not-persist" not in str(row)
    assert "policySigningCertificates" not in str(row)


def test_disabled_unknown_and_isolated_signer_gap():
    assert _assessment(_raw(access="Disabled"))[0].verdict() == "PASS"
    assert _assessment(_raw(access=None))[0].verdict() == "UNKNOWN"
    assert _assessment(_raw(status="NotReady"))[0].verdict() == "UNKNOWN"
    isolated = _assessment(_raw(trust="Isolated"))[0]
    assert isolated.verdict() == "FAIL"
    assert any("private-key holders" in gap["reason"] for gap in isolated.unresolved)


def test_foreign_identity_rejected_and_one_subscription_list():
    with pytest.raises(ValueError):
        attestation.project({**_raw(), "id": "/subscriptions/other" + RID}, SCOPE)
    reader = azure._Reader({})
    calls = []

    def request(url, **kwargs):
        calls.append(url)
        return {"value": [_raw()]}

    attestation.collect(reader, request, [SCOPE], {attestation.KIND})
    assert len(calls) == 1
    assert calls[0].endswith("/providers/Microsoft.Attestation/attestationProviders?api-version=2021-06-01")
    assert reader.collections[0]["status"] == "collected"
