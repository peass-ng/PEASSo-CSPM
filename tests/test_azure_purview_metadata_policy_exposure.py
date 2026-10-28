"""Classic Purview collection grants expose catalog metadata to foreign users."""

import threading

import pytest

from peaso.analysis.internet_exposure import assess
from peaso.collectors import azure, azure_purview_metadata_policy_native as native
from peaso.snapshot import make_snapshot, resources

TENANT = "00000000-0000-0000-0000-000000000001"
GUEST = "00000000-0000-0000-0000-000000000002"
GROUP = "00000000-0000-0000-0000-000000000003"
POLICY = "00000000-0000-0000-0000-000000000004"
RID = "/subscriptions/" + TENANT + "/resourceGroups/rg/providers/Microsoft.Purview/accounts/catalog"


def _policy(principal=GUEST, attr="principal.microsoft.id"):
    return {"id": POLICY, "properties": {"collection": {"referenceName": "catalog"},
            "description": "PRIVATE_DESCRIPTION", "attributeRules": [{
                "id": "purviewmetadatarole_builtin_purview-reader:catalog",
                "dnfCondition": [[{"attributeName": attr, "attributeValueIncludedIn": [principal]}]]}]}}


def _collect(raw):
    class Reader:
        collections = [{"type": "purview_account", "scope": "/subscriptions/" + TENANT,
                        "status": "collected", "items": [{"id": RID}]}]

        def pages(self, request, url, **kwargs):
            assert url == "https://catalog.purview.azure.com/policyStore/metadataPolicies?api-version=2021-07-01-preview"
            assert kwargs == {"audience": native.AUDIENCE, "key": "values"}
            yield request(url)["values"]

        def run(self, jobs):
            for kind, scope, service, fetch in jobs:
                self.collections.append({"type": kind, "scope": scope, "service": service,
                                         "status": "collected", "items": [item for page in fetch() for item in page]})

    class Transport:
        def allow_purview(self, name):
            assert name == "catalog"

    reader = Reader()
    calls = []

    def request(url):
        calls.append(url)
        return {"values": [raw]}

    native.collect(reader, request, Transport(), {native.KIND})
    assert len(calls) == 1
    return reader.collections[-1]


def _assess(raw):
    row = _collect(raw)
    assert "PRIVATE_DESCRIPTION" not in str(row)
    collections = [row, {"type": "directory_user", "scope": "/tenants/" + TENANT,
                         "status": "collected", "items": [{"id": GUEST, "userType": "Guest"}]},
                   {"type": "directory_service_principal", "scope": "/tenants/" + TENANT,
                    "status": "empty", "items": []}]
    snap = make_snapshot("azure", ["/subscriptions/" + TENANT], collections,
                         metadata={"tenant_id": TENANT, "tenant_verified": True})
    return next(a for a in assess(snap, resources(snap)) if a.resource["type"] == native.KIND)


def test_direct_guest_catalog_reader_is_exposed():
    result = _assess(_policy())
    assert result.verdict() == "FAIL"
    assert result.external_ids == [GUEST]
    assert result.data_exposure is True


def test_group_grant_remains_unknown():
    assert _assess(_policy(GROUP, "principal.microsoft.groups")).verdict() == "UNKNOWN"


def test_conditional_direct_grant_remains_unknown():
    raw = _policy()
    raw["properties"]["attributeRules"][0]["dnfCondition"][0].append(
        {"attributeName": "principal.network.location", "attributeValueIncludes": "private"})
    assert _assess(raw).verdict() == "UNKNOWN"


def test_selected_policy_reads_account_and_directory_once():
    selected = azure._selected({"inventories": [native.KIND]}, None)
    assert {"purview_account", "directory_user", "directory_group", "directory_service_principal"} <= selected


def test_transport_rejects_unbound_purview_host_and_other_paths():
    transport = object.__new__(azure.AzureTransport)
    transport.lock = threading.Lock()
    transport.purview_hosts = set()
    transport.allow_purview("catalog")
    with pytest.raises(azure.AzureReadError):
        transport._raw_response("https://other.purview.azure.com/policyStore/metadataPolicies", None,
                                native.AUDIENCE, False, None)
    with pytest.raises(azure.AzureReadError):
        transport._raw_response("https://catalog.purview.azure.com/other", None,
                                native.AUDIENCE, False, None)
