"""Power BI admin-wide sharing evidence retains effective-status uncertainty."""

from types import SimpleNamespace

from peaso.analysis.internet_exposure import assess
from peaso.collectors import azure, azure_powerbi_public_share_native as native
from peaso.snapshot import make_snapshot, resources

TENANT = "00000000-0000-0000-0000-000000000001"
REPORT = "00000000-0000-0000-0000-000000000002"
GUEST = "00000000-0000-0000-0000-000000000003"


def _scan(kind):
    class Reader:
        collections = []
        budget = SimpleNamespace(max_pages=None)

        def check_cancelled(self):
            pass

        def call(self, request, url, *, audience):
            assert audience == native.AUDIENCE and native.allowed_route(url)
            return request(url)

        def run(self, jobs):
            for row_kind, scope, service, fetch in jobs:
                self.collections.append({"type": row_kind, "scope": scope, "service": service,
                                         "status": "collected", "items": [item for page in fetch() for item in page]})

    def request(url):
        assert url == native.BASE + ("/publishedToWeb" if kind == native.PUBLISHED else "/linksSharedToWholeOrganization")
        return {"artifactAccessEntities": [{"artifactId": REPORT, "artifactType": "Report",
                                            "shareType": "PublishToWeb" if kind == native.PUBLISHED else "Link",
                                            "displayName": "PRIVATE_REPORT", "sharer": {
                                                "emailAddress": "private@example.com"}}]}

    reader = Reader()
    native.collect(reader, request, {kind}, "/tenants/" + TENANT)
    assert "PRIVATE" not in str(reader.collections)
    snap = make_snapshot("azure", ["/subscriptions/" + TENANT], reader.collections + [
        {"type": "directory_user", "scope": "/tenants/" + TENANT,
         "status": "collected", "items": [{"id": GUEST, "userType": "Guest"}]}],
        metadata={"tenant_id": TENANT, "tenant_verified": True})
    return next(a for a in assess(snap, resources(snap)) if a.resource["type"] == kind)


def test_published_to_web_is_configured_but_effective_status_unknown():
    result = _scan(native.PUBLISHED)
    assert result.verdict() == "UNKNOWN"
    assert result.data_exposure is True
    assert any(step["layer"] == "publish_to_web" for step in result.path)


def test_organization_link_excludes_observed_guest():
    result = _scan(native.ORGANIZATION)
    assert result.verdict() == "PASS"
    assert result.external_ids == []


def test_only_exact_admin_routes_are_allowed():
    assert native.allowed_route(native.BASE + "/publishedToWeb")
    assert not native.allowed_route("https://example.com/v1.0/myorg/admin/widelySharedArtifacts/publishedToWeb")
    assert not native.allowed_route(native.BASE + "/publishedToWeb?token=secret")
    selected = azure._selected({"inventories": [native.PUBLISHED]}, None)
    assert "directory_user" not in selected
