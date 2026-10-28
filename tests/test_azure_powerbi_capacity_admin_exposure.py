"""Power BI capacity admins are projected safely and compared with tenant domains."""

from peaso.analysis.internet_exposure import assess
from peaso.collectors import azure, azure_swc
from peaso.snapshot import make_snapshot, resources


SCOPE = "/subscriptions/00000000-0000-0000-0000-000000000001"
RID = SCOPE + "/resourceGroups/rg/providers/Microsoft.PowerBIDedicated/capacities/cap"


def _result(members, domains=True):
    raw = {"id": RID, "type": "Microsoft.PowerBIDedicated/capacities", "name": "cap",
           "properties": {"administration": {"members": members}, "state": "Active",
                          "configuration": {"secret": "must-not-persist"}}}
    item = azure_swc.list_detail(raw, "powerbi_capacity")
    snap = make_snapshot("azure", [SCOPE], [
        {"type": "powerbi_capacity", "scope": SCOPE, "service": "Microsoft.PowerBIDedicated",
         "status": "collected", "items": [item]},
        {"type": "directory_domain", "scope": "/tenants/tenant", "service": "Microsoft.Graph",
         "status": "collected" if domains else "partial", "items": [{"id": "contoso.com", "isVerified": True}]},
    ])
    return next(a for a in assess(snap, resources(snap)) if a.resource["type"] == "powerbi_capacity"), item


def test_foreign_capacity_admin_and_safe_projection():
    row, item = _result(["outside@example.org"])
    assert row.verdict() == "FAIL" and row.external_ids == ["outside@example.org"]
    assert "must-not-persist" not in str(item)
    assert azure.ENDPOINTS["powerbi_capacity"] == ("Microsoft.PowerBIDedicated/capacities", "2021-01-01")


def test_capacity_admin_absence_and_identity_uncertainty():
    assert _result([])[0].verdict() == "PASS"
    assert _result(["member@contoso.com"])[0].verdict() == "UNKNOWN"
    assert _result(["outside@example.org"], domains=False)[0].verdict() == "UNKNOWN"


def test_selected_capacity_requires_tenant_domains():
    assert "directory_domain" in azure._selected({}, ["powerbi_capacity"])
