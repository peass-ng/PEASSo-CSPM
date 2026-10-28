"""Read-only Service Bus namespace SAS rule inventory and exposure evidence."""

from urllib.parse import urlsplit

import pytest

from peaso.collectors import azure
from peaso.analysis.internet_exposure import assess
from peaso.snapshot import resources

SUB = "11111111-1111-1111-1111-111111111111"
SCOPE = "/subscriptions/" + SUB
RID = SCOPE + "/resourceGroups/rg/providers/Microsoft.ServiceBus/namespaces/bus"
RULE_ID = RID + "/authorizationRules/send"


class Transport:
    tenant = verified_tenant = "22222222-2222-2222-2222-222222222222"

    def __init__(self, rule=None, denied=False):
        self.calls = []
        self.rule = rule
        self.denied = denied

    def request(self, url, *, body=None, audience=azure.ARM):
        self.calls.append((url, body, audience))
        path = urlsplit(url).path
        if path == SCOPE + "/providers/Microsoft.ServiceBus/namespaces":
            return {"value": [{"id": RID, "name": "bus", "type": "Microsoft.ServiceBus/namespaces",
                               "properties": {"publicNetworkAccess": "Enabled", "disableLocalAuth": False,
                                              "serviceBusEndpoint": "https://bus.servicebus.windows.net"}}]}
        if path == RID + "/AuthorizationRules":
            if self.denied:
                raise azure.AzureReadError("rule list denied", status_code=403)
            return {"value": [self.rule] if self.rule else []}
        if path == RID + "/networkRuleSets/default":
            return {"id": path, "properties": {"publicNetworkAccess": "Enabled", "defaultAction": "Allow"}}
        return {"value": []}


def _collect(transport):
    snapshot = azure.collect({"scopes": [SUB], "options": {"retries": 0}},
                             ["servicebus_namespace"], transport=transport)
    item = next(row for row in snapshot["collections"] if row["type"] == "servicebus_namespace")["items"][0]
    return snapshot, item


def test_namespace_sas_rights_are_collected_without_key_material():
    rule = {"id": RULE_ID, "name": "send", "type": "Microsoft.ServiceBus/namespaces/authorizationRules",
            "properties": {"rights": ["Send"], "primaryKey": "PRIVATE_KEY_SENTINEL_A",
                           "secondaryKey": "PRIVATE_KEY_SENTINEL_B"}}
    transport = Transport(rule)
    snapshot, item = _collect(transport)
    assert item["_coverage"]["authorizationRules"]["status"] == "collected"
    assert item["authorizationRules"] == [{"id": RULE_ID, "name": "send", "type": rule["type"],
                                           "parent_id": RID, "properties": {"rights": ["Send"]}}]
    assert "PRIVATE_KEY_SENTINEL" not in repr(snapshot)
    rule_calls = [(url, body, audience) for url, body, audience in transport.calls
                  if urlsplit(url).path == RID + "/AuthorizationRules"]
    assert len(rule_calls) == 1 and rule_calls[0][1] is None and rule_calls[0][2] == azure.ARM
    assert "api-version=2024-01-01" in rule_calls[0][0]
    assessment = next(a for a in assess(snapshot, resources(snapshot)) if a.resource["type"] == "servicebus_namespace")
    assert assessment.verdict() == "FAIL"
    assert next(step for step in assessment.path if step["layer"] == "sas_authorization")["namespace_rules"] == [
        {"name": "send", "rights": ["Send"]}]


def test_namespace_rule_denial_preserves_unknown_sas_inventory():
    snapshot, item = _collect(Transport(denied=True))
    assert item["_coverage"]["authorizationRules"]["status"] not in ("collected", "empty")
    assert "authorizationRules" not in item
    assessment = next(a for a in assess(snapshot, resources(snapshot)) if a.resource["type"] == "servicebus_namespace")
    assert any("SAS authentication" in note for note in assessment.notes)


def test_disabled_local_auth_does_not_claim_sas_recipient():
    rule = {"id": RULE_ID, "name": "send", "type": "Microsoft.ServiceBus/namespaces/authorizationRules",
            "properties": {"rights": ["Send"]}}
    snapshot, item = _collect(Transport(rule))
    item["properties"]["disableLocalAuth"] = True
    assessment = next(a for a in assess(snapshot, resources(snapshot)) if a.resource["type"] == "servicebus_namespace")
    sas = next(step for step in assessment.path if step["layer"] == "sas_authorization")
    assert sas == {"layer": "sas_authorization", "decision": "disabled", "disable_local_auth": True}
    assert assessment.verdict() == "FAIL"  # The network listener remains public.


@pytest.mark.parametrize("rights", [["Owner"], "Send", ["Send", "Owner"]])
def test_invalid_rule_rights_do_not_become_collected_evidence(rights):
    rule = {"id": RULE_ID, "name": "send", "type": "Microsoft.ServiceBus/namespaces/authorizationRules",
            "properties": {"rights": rights}}
    _, item = _collect(Transport(rule))
    assert item["_coverage"]["authorizationRules"]["status"] == "malformed"
    assert "authorizationRules" not in item
