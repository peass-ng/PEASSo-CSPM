"""Native Azure Attestation public endpoint and safe GET evidence."""

import json
from urllib.parse import urlsplit

import pytest

from peaso.analysis.internet_exposure import assess
from peaso.collectors import azure
from peaso.snapshot import make_snapshot, resources
from tests.test_peaso_azure_bulk_native import SCOPE, SUB, Transport, parent

RID = SCOPE + "/resourceGroups/rg/providers/Microsoft.Attestation/attestationProviders/provider"
URI = "https://provider.eus.attest.azure.net"


def decision(properties, *, full=True):
    item = parent(RID, "Microsoft.Attestation/attestationProviders", properties)
    if full:
        item["_provenance"] = {"representation": "full", "source_operation": "get"}
    snapshot = make_snapshot("azure", [SCOPE], [{"type": "attestation_provider", "scope": SCOPE,
        "service": "attestation", "status": "collected", "items": [item]}])
    before = repr(snapshot)
    rows = assess(snapshot, resources(snapshot))
    assert repr(snapshot) == before and len(rows) == 1
    return rows[0]


def test_public_attestation_provider_and_tpm_authentication():
    props = {"publicNetworkAccess": "Enabled", "status": "Ready", "attestUri": URI,
             "tpmAttestationAuthentication": "Disabled"}
    row = decision(props)
    assert row.verdict() == "FAIL"
    assert row.ports == {"tcp": ((443, 443),)}
    assert row.addresses == ["provider.eus.attest.azure.net"]
    assert row.authenticated is False
    assert any(step["layer"] == "tpm_authentication" for step in row.path)
    assert decision({**props, "tpmAttestationAuthentication": "Enabled"}).authenticated is True


def test_closed_and_unresolved_attestation_provider():
    base = {"status": "Ready", "attestUri": URI}
    closed = decision({**base, "publicNetworkAccess": "Disabled"})
    assert closed.verdict() == "PASS" and closed.ports == {}
    assert decision({**base, "publicNetworkAccess": "Enabled"}, full=False).verdict() == "UNKNOWN"
    assert decision(base).verdict() == "UNKNOWN"
    assert decision({**base, "publicNetworkAccess": "Enabled", "status": "NotReady"}).verdict() == "UNKNOWN"
    assert decision({**base, "publicNetworkAccess": "Enabled", "attestUri": "http://bad.example"}).verdict() == "UNKNOWN"


def test_collector_uses_one_full_get_and_omits_private_signing_keys():
    endpoint = "Microsoft.Attestation/attestationProviders"
    listing = parent(RID, endpoint, {"publicNetworkAccess": "Enabled"})
    detail = parent(RID, endpoint, {"publicNetworkAccess": "Enabled", "status": "Ready",
        "attestUri": URI, "tpmAttestationAuthentication": "Disabled", "trustModel": "Isolated",
        "policySigningCertificates": {"keys": [{"d": "private-marker", "p": "private-marker",
            "q": "private-marker", "n": "public-modulus"}]}})
    api = Transport({SCOPE + "/providers/" + endpoint: {"value": [listing]}, RID: detail})
    snapshot = azure.collect({"scopes": [SUB], "options": {"retries": 0}},
                             ["attestation_provider"], transport=api)
    collection = next(c for c in snapshot["collections"] if c["type"] == "attestation_provider")
    item = collection["items"][0]
    assert item["_provenance"]["representation"] == "full"
    assert item["properties"] == {**{key: detail["properties"][key] for key in
                                  ("status", "attestUri", "publicNetworkAccess",
                                   "tpmAttestationAuthentication", "trustModel")},
                                  "attestHost": "provider.eus.attest.azure.net"}
    assert "private-marker" not in json.dumps(snapshot)
    assert sum(urlsplit(url).path == RID for url in api.calls) == 1
    assert sum(urlsplit(url).path == SCOPE + "/providers/" + endpoint for url in api.calls) == 1
    assert assess(snapshot, resources(snapshot))[0].verdict() == "FAIL"
