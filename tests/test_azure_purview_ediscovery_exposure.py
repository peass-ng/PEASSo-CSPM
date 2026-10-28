"""Purview eDiscovery case membership grants access to case data."""

from peaso.analysis.internet_exposure import assess
from peaso.collectors import azure, azure_purview_ediscovery_native as native
from peaso.snapshot import make_snapshot, resources

TENANT = "00000000-0000-0000-0000-000000000001"
GUEST = "00000000-0000-0000-0000-000000000002"
CASE = "00000000-0000-0000-0000-000000000003"
ROLE = "00000000-0000-0000-0000-000000000004"


def _scan(*, recipient="user", member=GUEST, case_status="active", directory_status="collected"):
    class Reader:
        collections = []

        def pages(self, request, url, **kwargs):
            assert kwargs == {"audience": native.GRAPH, "next_key": "@odata.nextLink"}
            yield request(url)["value"]

        def run(self, jobs):
            for kind, scope, service, fetch in jobs:
                self.collections.append({"type": kind, "scope": scope, "service": service,
                                         "status": "collected", "items": [item for page in fetch() for item in page]})

    calls = []

    def request(url):
        calls.append(url)
        assert url.startswith("https://graph.microsoft.com/v1.0/security/cases/ediscoveryCases")
        if url.endswith("/caseMembers"):
            return {"value": [{"id": member, "recipientType": recipient,
                               "displayName": "PRIVATE_NAME", "smtpAddress": "private@example.com"}]}
        return {"value": [{"id": CASE, "status": case_status,
                           "displayName": "PRIVATE_CASE", "description": "PRIVATE_DESCRIPTION"}]}

    reader = Reader()
    native.collect(reader, request, {native.CASES, native.MEMBERS}, "/tenants/" + TENANT)
    assert len(calls) == 2
    assert "PRIVATE" not in str(reader.collections)
    collections = reader.collections + [{"type": "directory_user", "scope": "/tenants/" + TENANT,
                                        "status": directory_status,
                                        "items": [{"id": GUEST, "userType": "Guest"}] if directory_status == "collected" else []}]
    snap = make_snapshot("azure", ["/subscriptions/" + TENANT], collections,
                         metadata={"tenant_id": TENANT, "tenant_verified": True})
    return next(a for a in assess(snap, resources(snap)) if a.resource["type"] == native.MEMBERS)


def test_active_case_direct_guest_member():
    result = _scan()
    assert result.verdict() == "FAIL"
    assert result.external_ids == [GUEST]
    assert result.data_exposure is True


def test_role_group_and_inactive_case_unresolved():
    assert _scan(recipient="roleGroup", member=ROLE).verdict() == "UNKNOWN"
    assert _scan(case_status="closed").verdict() == "UNKNOWN"
    assert _scan(directory_status="denied").verdict() == "UNKNOWN"


def test_selected_members_include_case_and_directory():
    selected = azure._selected({"inventories": [native.MEMBERS]}, None)
    assert {native.CASES, "directory_user"} <= selected
