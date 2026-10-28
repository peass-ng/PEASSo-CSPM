"""Fabric admin workspace inventory and member-only role reads stay distinct."""

from types import SimpleNamespace

from peaso.analysis.internet_exposure import assess
from peaso.collectors import azure, azure_fabric_workspace_native as native
from peaso.snapshot import make_snapshot, resources

TENANT = "00000000-0000-0000-0000-000000000001"
WORKSPACE = "00000000-0000-0000-0000-000000000002"
GUEST = "00000000-0000-0000-0000-000000000003"


def _scan(*, denied=False, principal_type="User"):
    class Reader:
        def __init__(self):
            self.collections = []
            self.budget = SimpleNamespace(max_pages=None)

        def check_cancelled(self):
            pass

        def call(self, request, url, *, audience):
            assert audience == native.AUDIENCE
            return request(url)

        def run(self, jobs):
            for kind, scope, service, fetch in jobs:
                self.collections.append({"type": kind, "scope": scope, "service": service,
                                         "status": "collected", "items": [item for page in fetch() for item in page]})

    calls = []

    def request(url):
        calls.append(url)
        if url == native.BASE + "/admin/workspaces":
            return {"workspaces": [{"id": WORKSPACE, "name": "PRIVATE_WORKSPACE", "state": "Active"}]}
        assert url == native.BASE + "/admin/workspaces/" + WORKSPACE + "/users"
        if denied:
            raise PermissionError("workspace member role required")
        return {"accessDetails": [{"workspaceAccessDetails": {"type": "Workspace", "workspaceRole": "Viewer"}, "principal": {
            "id": TENANT if principal_type == "EntireTenant" else GUEST, "type": principal_type, "displayName": "PRIVATE_GUEST",
            "userDetails": {"userPrincipalName": "private@example.com"}}}]}

    reader = Reader()
    native.collect(reader, request, {native.KIND}, "/tenants/" + TENANT)
    assert len(calls) == 2
    assert "PRIVATE" not in str(reader.collections)
    collections = reader.collections + [{"type": "directory_user", "scope": "/tenants/" + TENANT,
                                        "status": "collected", "items": [{"id": GUEST, "userType": "Guest"}]}]
    snap = make_snapshot("azure", ["/subscriptions/" + TENANT], collections,
                         metadata={"tenant_id": TENANT, "tenant_verified": True})
    return next(a for a in assess(snap, resources(snap)) if a.resource["type"] == native.KIND)


def test_guest_workspace_viewer_is_exposure():
    result = _scan()
    assert result.verdict() == "FAIL"
    assert result.external_ids == [GUEST]
    assert result.data_exposure is True


def test_entire_tenant_workspace_role_keeps_guest_eligibility_unknown():
    result = _scan(principal_type="EntireTenant")
    assert result.verdict() == "UNKNOWN"
    assert result.external_ids == []


def test_inaccessible_roles_remain_unknown():
    assert _scan(denied=True).verdict() == "UNKNOWN"


def test_selected_workspace_includes_directory_identity_and_membership():
    selected = azure._selected({"inventories": [native.KIND]}, None)
    assert {"directory_user", "directory_group", "directory_service_principal", "directory_membership"} <= selected


def test_report_item_guest_read_grant_uses_admin_access_details():
    item_id = "00000000-0000-0000-0000-000000000004"

    class Reader:
        collections = []
        budget = SimpleNamespace(max_pages=None)

        def check_cancelled(self):
            pass

        def call(self, request, url, *, audience):
            assert audience == native.AUDIENCE
            return request(url)

        def run(self, jobs):
            for kind, scope, service, fetch in jobs:
                self.collections.append({"type": kind, "scope": scope, "service": service,
                                         "status": "collected", "items": [item for page in fetch() for item in page]})

    def request(url):
        if url == native.BASE + "/admin/items":
            return {"itemEntities": [{"id": item_id, "workspaceId": WORKSPACE,
                                      "type": "Report", "name": "PRIVATE_REPORT"}]}
        assert url == native.BASE + "/admin/workspaces/" + WORKSPACE + "/items/" + item_id + "/users?type=Report"
        return {"accessDetails": [{"principal": {"id": GUEST, "type": "User",
                                              "displayName": "PRIVATE_GUEST"},
                                  "itemAccessDetails": {"type": "Report", "permissions": ["Read"],
                                                        "additionalPermissions": []}}]}

    reader = Reader()
    native.collect_items(reader, request, {native.ITEM_KIND}, "/tenants/" + TENANT)
    assert "PRIVATE" not in str(reader.collections)
    snap = make_snapshot("azure", ["/subscriptions/" + TENANT], reader.collections + [
        {"type": "directory_user", "scope": "/tenants/" + TENANT,
         "status": "collected", "items": [{"id": GUEST, "userType": "Guest"}]}],
        metadata={"tenant_id": TENANT, "tenant_verified": True})
    result = next(a for a in assess(snap, resources(snap)) if a.resource["type"] == native.ITEM_KIND)
    assert result.verdict() == "FAIL"
    assert result.data_exposure is True


def test_active_external_data_share_detects_foreign_recipient_tenant():
    share_id = "00000000-0000-0000-0000-000000000005"
    item_id = "00000000-0000-0000-0000-000000000004"
    foreign = "00000000-0000-0000-0000-000000000006"

    class Reader:
        collections = []
        budget = SimpleNamespace(max_pages=None)

        def check_cancelled(self):
            pass

        def call(self, request, url, *, audience):
            assert audience == native.AUDIENCE
            return request(url)

        def run(self, jobs):
            for kind, scope, service, fetch in jobs:
                self.collections.append({"type": kind, "scope": scope, "service": service,
                                         "status": "collected", "items": [item for page in fetch() for item in page]})

    def request(url):
        assert url == native.BASE + "/admin/items/externalDataShares"
        return {"value": [{"id": share_id, "workspaceId": WORKSPACE, "itemId": item_id,
                           "status": "Active", "acceptedByTenantId": foreign,
                           "paths": ["PRIVATE/path"], "invitationUrl": "https://example.com/PRIVATE",
                           "recipient": {"type": "ServicePrincipal", "tenantId": foreign,
                                         "principalId": GUEST}}]}

    reader = Reader()
    native.collect_external_shares(reader, request, {native.SHARE_KIND}, "/tenants/" + TENANT)
    assert "PRIVATE" not in str(reader.collections)
    snap = make_snapshot("azure", ["/subscriptions/" + TENANT], reader.collections,
                         metadata={"tenant_id": TENANT, "tenant_verified": True})
    result = next(a for a in assess(snap, resources(snap)) if a.resource["type"] == native.SHARE_KIND)
    assert result.verdict() == "FAIL"
    assert result.external_ids == [foreign]
    assert result.data_exposure is True
