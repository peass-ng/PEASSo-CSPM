"""Definition webhooks retain no credential URI and require an observed instance."""

import pytest

from peaso.analysis.internet_exposure import assess
from peaso.collectors import azure, azure_swc
from peaso.collectors import azure_managed_application_definitions_native as definitions
from peaso.snapshot import make_snapshot, resources


SUB = "/subscriptions/00000000-0000-0000-0000-000000000001"
GROUP = SUB + "/resourceGroups/rg"
RID = GROUP + "/providers/Microsoft.Solutions/applicationDefinitions/definition"
APP = GROUP + "/providers/Microsoft.Solutions/applications/instance"


def _definition(host="partner.example", enabled=True):
    return {"id": RID, "name": "definition", "type": "Microsoft.Solutions/applicationDefinitions",
            "properties": {"isEnabled": enabled, "managementPolicy": {"mode": "Managed"},
                "notificationPolicy": {"notificationEndpoints": [{"uri":
                    "https://" + host + "/token-in-path?sig=must-not-persist"}]},
                "authorizations": [{"principalId": "publisher", "roleDefinitionId": "role"}],
                "packageFileUri": "https://secret.example/?sig=must-not-persist",
                "mainTemplate": {"password": "must-not-persist"}}}


def _assessment(definition, *, instance=True, domains=True):
    collections = [{"type": definitions.KIND, "scope": GROUP, "service": "Microsoft.Solutions",
                    "status": "collected", "items": [definition]},
                   {"type": "managed_application", "scope": SUB, "service": "Microsoft.Solutions",
                    "status": "collected", "items": ([azure_swc.list_detail({
                        "id": APP, "type": "Microsoft.Solutions/applications", "name": "instance",
                        "properties": {"provisioningState": "Succeeded", "applicationDefinitionId": RID}},
                        "managed_application")] if instance else [])},
                   {"type": "directory_domain", "scope": SUB, "service": "Microsoft.Graph",
                    "status": "collected" if domains else "denied", "items":
                    [{"id": "owner.example", "isVerified": True}] if domains else []}]
    snap = make_snapshot("azure", [SUB], collections)
    return next(row for row in assess(snap, resources(snap)) if row.resource["type"] == definitions.KIND)


def test_project_discards_secret_uris_and_templates_and_detects_foreign_webhook():
    row = definitions.project(_definition(), GROUP)
    assert "must-not-persist" not in str(row)
    assert row["properties"]["notificationHosts"] == ["partner.example"]
    assert _assessment(row).verdict() == "FAIL"
    assert _assessment(row).external_ids == ["partner.example"]


def test_missing_instance_or_domain_stays_unresolved_and_owned_domain_is_safe():
    row = definitions.project(_definition(), GROUP)
    assert _assessment(row, instance=False).verdict() == "UNKNOWN"
    assert _assessment(row, domains=False).verdict() == "UNKNOWN"
    assert _assessment(definitions.project(_definition("notify.owner.example"), GROUP)).verdict() == "PASS"
    assert _assessment(definitions.project(_definition(enabled=False), GROUP)).verdict() == "UNKNOWN"


def test_foreign_child_and_malformed_endpoints_rejected():
    with pytest.raises(ValueError):
        definitions.project({**_definition(), "id": "/subscriptions/other" + RID}, GROUP)
    with pytest.raises(ValueError):
        definitions.project(_definition("partner.example\\bad"), GROUP)


def test_collect_lists_each_observed_group_once():
    reader = azure._Reader({})
    reader.collections.append({"type": "resource_group", "scope": SUB, "status": "collected",
                               "items": [{"id": GROUP}, {"id": GROUP}]})
    calls = []

    def request(url, **kwargs):
        calls.append(url)
        return {"value": [_definition()]}

    definitions.collect(reader, request, {definitions.KIND})
    assert len(calls) == 1 and calls[0].endswith("applicationDefinitions?api-version=2019-07-01")
    assert reader.collections[-1]["items"][0]["properties"]["notificationHosts"] == ["partner.example"]
