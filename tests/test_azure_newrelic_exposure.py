"""New Relic observed telemetry routing with safe ARM projection."""

from types import SimpleNamespace

import pytest

from peaso.analysis.internet_exposure import assess
from peaso.collectors import azure, azure_newrelic_native as native
from peaso.snapshot import make_snapshot, resources


ARM = "https://management.azure.com"
SCOPE = "/subscriptions/00000000-0000-0000-0000-000000000001"
MONITOR = SCOPE + "/resourceGroups/rg/providers/NewRelic.Observability/monitors/rel"
SOURCE = SCOPE + "/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm"


def test_monitored_resource_read_and_partner_telemetry_finding():
    class Reader:
        def __init__(self):
            self.collections = []
            self.budget = SimpleNamespace(max_pages=3)
            self.calls = []

        def pages(self, request, url):
            assert url == ARM + SCOPE + "/providers/NewRelic.Observability/monitors?api-version=2026-06-01"
            yield [{"id": MONITOR, "name": "rel", "type": "NewRelic.Observability/monitors",
                    "properties": {"provisioningState": "Succeeded", "monitoringStatus": "Enabled",
                                   "marketplaceSubscriptionStatus": "Active",
                                   "newRelicAccountProperties": {"accountInfo": {"accountId": "partner-1",
                                                                          "ingestionKey": "must-not-persist"},
                                                                 "organizationInfo": {"organizationId": "org-1"}}}}]

        def call(self, request, url, *, body):
            self.calls.append((url, body))
            return {"value": [{"id": SOURCE, "sendingLogs": "Enabled", "sendingMetrics": "Disabled",
                               "reasonForLogsStatus": "must-not-persist"}], "nextLink": None}

        def run(self, jobs):
            for kind, scope, service, fetch in jobs:
                items = [item for page in fetch() for item in page]
                self.collections.append({"type": kind, "scope": scope, "service": service,
                                         "status": "collected" if items else "empty", "items": items})

    reader = Reader()
    native.collect(reader, lambda _: None, [SCOPE], set(native.TYPES), ARM)
    assert len(reader.calls) == 1 and reader.calls[0][1] == {}
    assert native.monitored_route(reader.calls[0][0], {}, ARM)
    assert "must-not-persist" not in str(reader.collections)
    snap = make_snapshot("azure", [SCOPE], reader.collections)
    finding = next(a for a in assess(snap, resources(snap)) if a.resource["type"] == native.RESOURCE)
    assert finding.verdict() == "FAIL" and finding.data_exposure is True
    assert finding.resource["data"]["resource_id"] == SOURCE
    assert azure._selected({}, [native.RESOURCE]) >= set(native.TYPES)


def test_monitored_route_is_exact_readonly_post():
    url = ARM + MONITOR + "/monitoredResources?api-version=2026-06-01"
    assert native.monitored_route(url, {}, ARM)
    assert not native.monitored_route(url, {"refresh": True}, ARM)
    assert not native.monitored_route(url.replace("monitoredResources", "refreshIngestionKey"), {}, ARM)
    assert not native.monitored_route(url.replace(ARM, "https://example.com"), {}, ARM)
    assert not native.monitored_route(url + "&api-version=2026-06-01", {}, ARM)
    with pytest.raises(azure.AzureReadError):
        azure._validate_readonly_post(url.replace("monitoredResources", "refreshIngestionKey"), ARM, {})


def test_disabled_send_state_is_not_partner_transfer():
    parent = {"id": MONITOR, "properties": {"provisioningState": "Succeeded",
                                            "monitoringStatus": "Enabled", "marketplaceSubscriptionStatus": "Active"}}
    child = {"id": MONITOR + "/monitoredResources/one", "monitor_id": MONITOR,
             "resource_id": SOURCE, "sendingLogs": "Disabled", "sendingMetrics": "Disabled"}
    snap = make_snapshot("azure", [SCOPE], [
        {"type": native.MONITOR, "scope": SCOPE, "service": "NewRelic.Observability",
         "status": "collected", "items": [parent]},
        {"type": native.RESOURCE, "scope": MONITOR, "service": "NewRelic.Observability",
         "status": "collected", "items": [child]},
    ])
    finding = next(a for a in assess(snap, resources(snap)) if a.resource["type"] == native.RESOURCE)
    assert finding.verdict() == "PASS" and finding.data_exposure is not True
