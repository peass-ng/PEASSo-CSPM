"""External ID authentication callbacks require an observed event listener."""

from types import SimpleNamespace

from peaso.analysis.internet_exposure import assess
from peaso.collectors import azure
from peaso.collectors import azure_external_id_extensions_native as external_id
from peaso.snapshot import make_snapshot, resources


TENANT = "00000000-0000-0000-0000-000000000001"
SCOPE = "/tenants/" + TENANT
EXT = "00000000-0000-0000-0000-000000000002"
LISTENER = "00000000-0000-0000-0000-000000000003"
APP = "00000000-0000-0000-0000-000000000004"


def _extension(host="partner.example"):
    return {"id": EXT, "@odata.type": "#microsoft.graph.onTokenIssuanceStartCustomExtension",
            "endpointConfiguration": {"targetUrl": "https://" + host + "/secret?sig=must-not-persist"},
            "authenticationConfiguration": {"resourceId": "api://must-not-persist"},
            "description": "must-not-persist"}


def _listener():
    return {"id": LISTENER, "@odata.type": "#microsoft.graph.onTokenIssuanceStartListener",
            "handler": {"customExtension": {"id": EXT, "description": "must-not-persist"}},
            "conditions": {"applications": {"includeApplications": [{"appId": APP}]}},
            "secret": "must-not-persist"}


def _assessment(extension, *, listeners=True, complete=True, domains=True):
    collections = [{"type": external_id.EXTENSION, "scope": SCOPE, "service": "Microsoft.Graph",
                    "status": "collected", "items": [extension]},
                   {"type": external_id.LISTENER, "scope": SCOPE, "service": "Microsoft.Graph",
                    "status": "collected" if complete else "denied",
                    "items": [external_id.project(external_id.LISTENER, _listener())]
                    if listeners and complete else []},
                   {"type": "directory_domain", "scope": SCOPE, "service": "Microsoft.Graph",
                    "status": "collected" if domains else "denied",
                    "items": [{"id": "owner.example", "isVerified": True}] if domains else []}]
    snap = make_snapshot("azure", [SCOPE], collections)
    return next(a for a in assess(snap, resources(snap)) if a.resource["type"] == external_id.EXTENSION)


def test_active_foreign_callback_and_secret_free_projection():
    extension = external_id.project(external_id.EXTENSION, _extension())
    assert "must-not-persist" not in str(extension)
    assert _assessment(extension).verdict() == "FAIL"
    assert _assessment(extension).external_ids == ["partner.example"]


def test_dormant_and_incomplete_listener_state():
    extension = external_id.project(external_id.EXTENSION, _extension())
    assert _assessment(extension, listeners=False).verdict() == "PASS"
    assert _assessment(extension, complete=False).verdict() == "UNKNOWN"
    assert _assessment(extension, domains=False).verdict() == "UNKNOWN"
    assert _assessment(external_id.project(external_id.EXTENSION,
           _extension("api.owner.example"))).verdict() == "UNKNOWN"
    ambiguous = external_id.project(external_id.LISTENER,
                  {**_listener(), "handler": {"customExtension": {}}})
    snap = make_snapshot("azure", [SCOPE], [
        {"type": external_id.EXTENSION, "scope": SCOPE, "status": "collected", "items": [extension]},
        {"type": external_id.LISTENER, "scope": SCOPE, "status": "collected", "items": [ambiguous]}])
    assert next(a for a in assess(snap, resources(snap))
                if a.resource["type"] == external_id.EXTENSION).verdict() == "UNKNOWN"


def test_two_paged_graph_lists_per_tenant():
    reader = azure._Reader({})
    calls = []

    def request(url, **kwargs):
        calls.append(url)
        return {"value": [_extension()] if url.endswith("customAuthenticationExtensions") else [_listener()]}

    external_id.collect(reader, request, set(external_id.KINDS), SimpleNamespace(tenant=TENANT))
    assert len(calls) == 2
    assert {row["type"] for row in reader.collections} == external_id.KINDS
    assert all(row["status"] == "collected" for row in reader.collections)
    assert "must-not-persist" not in str(reader.collections)
