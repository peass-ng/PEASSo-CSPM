"""Foreign Unified Catalog governance-role grants are native exposure evidence."""

from types import SimpleNamespace
from urllib.parse import parse_qs, urlsplit
import threading

import pytest

from peaso.analysis.internet_exposure import assess
from peaso.collectors import azure, azure_purview_unified_policy_native as native
from peaso.snapshot import make_snapshot, resources

TENANT = "00000000-0000-0000-0000-000000000001"
GUEST = "00000000-0000-0000-0000-000000000002"
POLICY = "00000000-0000-0000-0000-000000000003"
ENTITY = "00000000-0000-0000-0000-000000000004"
GROUP = "00000000-0000-0000-0000-000000000005"


def _policy(role="business-domain-reader", principal=GUEST, attr="principal.microsoft.id"):
    return {"id": POLICY, "properties": {"description": "PRIVATE_DESCRIPTION",
            "entity": {"type": "BusinessDomainReference", "referenceName": ENTITY},
            "attributeRules": [{"id": "purviewdatagovernancerole_builtin_" + role + ":" + ENTITY,
                                "dnfCondition": [[{"attributeName": attr,
                                                   "attributeValueIncludedIn": [principal]},
                                                  {"attributeName": "derived.purview.role",
                                                   "attributeValueIncludes": "purviewdatagovernancerole_builtin_" + role}]]}]}}


def _collect(policy, *, paged=False):
    class Reader:
        budget = SimpleNamespace(max_pages=4)
        collections = []

        def check_cancelled(self):
            pass

        def call(self, request, url, *, audience):
            assert audience == "https://purview.azure.net"
            return request(url)

        def run(self, jobs):
            for kind, scope, service, fetch in jobs:
                self.collections.append({"type": kind, "scope": scope, "service": service,
                                         "status": "collected", "items": [item for page in fetch() for item in page]})

    calls = []

    def request(url):
        calls.append(url)
        assert urlsplit(url).hostname == "api.purview-service.microsoft.com"
        assert urlsplit(url).path == "/datagovernance/catalog/policies"
        query = parse_qs(urlsplit(url).query)
        assert query["api-version"] == [native.VERSION]
        if paged and "skipToken" not in query:
            return {"values": [], "skipToken": "second-page"}
        if paged:
            assert query["skipToken"] == ["second-page"]
        return {"values": [policy]}

    reader = Reader()
    native.collect(reader, request, {native.KIND}, "/tenants/" + TENANT)
    assert len(calls) == (2 if paged else 1)
    return reader.collections[-1]


def _assess(policy, *, group_member=False, paged=False):
    row = _collect(policy, paged=paged)
    assert "PRIVATE_DESCRIPTION" not in str(row)
    collections = [row, {"type": "directory_user", "scope": "/tenants/" + TENANT,
                         "status": "collected", "items": [{"id": GUEST, "userType": "Guest"}]},
                   {"type": "directory_service_principal", "scope": "/tenants/" + TENANT,
                    "status": "empty", "items": []}]
    if group_member:
        collections.extend([{"type": "directory_group", "scope": "/tenants/" + TENANT,
                             "status": "collected", "items": [{"id": GROUP}]},
                            {"type": "directory_membership", "scope": "/tenants/" + TENANT + "/groups/" + GROUP,
                             "status": "collected", "items": [{"id": GUEST}]}])
    snap = make_snapshot("azure", ["/subscriptions/" + TENANT], collections,
                         metadata={"tenant_id": TENANT, "tenant_verified": True})
    return next(a for a in assess(snap, resources(snap)) if a.resource["type"] == native.KIND)


def test_foreign_business_domain_reader_on_second_page():
    result = _assess(_policy(), paged=True)
    assert result.verdict() == "FAIL"
    assert result.external_ids == [GUEST]
    assert result.data_exposure is True


def test_unrecognized_role_stays_unknown():
    assert _assess(_policy("unsupported-role")).verdict() == "UNKNOWN"


def test_observed_foreign_group_member_is_exposed():
    result = _assess(_policy(principal=GROUP, attr="principal.microsoft.groups"), group_member=True)
    assert result.verdict() == "FAIL"
    assert result.external_ids == [GUEST]


def test_selected_unified_policy_reads_directory():
    selected = azure._selected({"inventories": [native.KIND]}, None)
    assert {"directory_user", "directory_group", "directory_service_principal", "directory_membership"} <= selected


def test_transport_rejects_other_unified_catalog_routes():
    transport = object.__new__(azure.AzureTransport)
    transport.lock = threading.Lock()
    transport.purview_hosts = set()
    with pytest.raises(azure.AzureReadError):
        transport._raw_response("https://api.purview-service.microsoft.com/datagovernance/catalog/secrets",
                                None, "https://purview.azure.net", False, None)
