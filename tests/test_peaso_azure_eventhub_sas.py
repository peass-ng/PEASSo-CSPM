"""Event Hub namespace and entity SAS rule evidence from read-only ARM LISTs."""

from urllib.parse import urlsplit

from peaso.analysis.internet_exposure import assess
from peaso.collectors import azure
from peaso.snapshot import resources

SUB = "11111111-1111-1111-1111-111111111111"
SCOPE = "/subscriptions/" + SUB
RID = SCOPE + "/resourceGroups/rg/providers/Microsoft.EventHub/namespaces/events"
ENTITY = RID + "/eventhubs/orders"


class Transport:
    tenant = verified_tenant = "22222222-2222-2222-2222-222222222222"

    def __init__(self, *, deny_entity_rules=False, local_auth=False):
        self.calls = []
        self.deny_entity_rules = deny_entity_rules
        self.local_auth = local_auth

    def request(self, url, *, body=None, audience=azure.ARM):
        self.calls.append((url, body, audience))
        path = urlsplit(url).path
        if path == SCOPE + "/providers/Microsoft.EventHub/namespaces":
            return {"value": [{"id": RID, "name": "events", "type": "Microsoft.EventHub/namespaces",
                               "properties": {"publicNetworkAccess": "Enabled", "disableLocalAuth": self.local_auth,
                                              "serviceBusEndpoint": "https://events.servicebus.windows.net"}}]}
        if path == RID + "/eventhubs":
            return {"value": [{"id": ENTITY, "name": "orders",
                               "type": "Microsoft.EventHub/namespaces/eventhubs", "properties": {"status": "Active"}}]}
        if path == RID + "/authorizationRules":
            return {"value": [{"id": RID + "/authorizationRules/ns-reader", "name": "ns-reader",
                               "type": "Microsoft.EventHub/namespaces/authorizationRules",
                               "properties": {"rights": ["Listen"], "primaryKey": "PRIVATE_NAMESPACE_SENTINEL"}}]}
        if path == ENTITY + "/authorizationRules":
            if self.deny_entity_rules:
                raise azure.AzureReadError("entity rules denied", status_code=403)
            return {"value": [{"id": ENTITY + "/authorizationRules/sender", "name": "sender",
                               "type": "Microsoft.EventHub/namespaces/eventhubs/authorizationRules",
                               "properties": {"rights": ["Send"], "primaryKey": "PRIVATE_ENTITY_SENTINEL"}}]}
        if path == RID + "/networkRuleSets/default":
            return {"id": path, "properties": {"publicNetworkAccess": "Enabled", "defaultAction": "Allow"}}
        return {"value": []}


def _collect(transport):
    snapshot = azure.collect({"scopes": [SUB], "options": {"retries": 0}},
                             ["eventhub_namespace"], transport=transport)
    item = next(row for row in snapshot["collections"] if row["type"] == "eventhub_namespace")["items"][0]
    assessment = next(a for a in assess(snapshot, resources(snapshot)) if a.resource["type"] == "eventhub_namespace")
    return snapshot, item, assessment


def test_eventhub_sas_rule_rights_are_bound_and_keys_are_redacted():
    transport = Transport()
    snapshot, item, assessment = _collect(transport)
    assert item["_coverage"]["authorizationRules"]["status"] == "collected"
    assert item["_coverage"]["eventHubs"]["status"] == "collected"
    assert item["eventHubs"][0]["_coverage"]["authorizationRules"]["status"] == "collected"
    assert item["authorizationRules"][0]["properties"] == {"rights": ["Listen"]}
    assert item["eventHubs"][0]["authorizationRules"][0]["properties"] == {"rights": ["Send"]}
    assert "PRIVATE_NAMESPACE_SENTINEL" not in repr(snapshot)
    assert "PRIVATE_ENTITY_SENTINEL" not in repr(snapshot)
    assert any(urlsplit(url).path == ENTITY + "/authorizationRules" and body is None
               and audience == azure.ARM and "api-version=2026-01-01" in url
               for url, body, audience in transport.calls)
    assert assessment.verdict() == "FAIL"
    assert next(step for step in assessment.path if step["layer"] == "sas_authorization")["namespace_rules"] == [
        {"name": "ns-reader", "rights": ["Listen"]}]
    assert next(step for step in assessment.path if step["layer"] == "sas_entity_authorization")["rules"] == [
        {"entity": ENTITY, "name": "sender", "rights": ["Send"]}]


def test_eventhub_entity_rule_denial_preserves_incomplete_coverage():
    _, item, assessment = _collect(Transport(deny_entity_rules=True))
    entity = item["eventHubs"][0]
    assert entity["_coverage"]["authorizationRules"]["status"] not in ("collected", "empty")
    assert "authorizationRules" not in entity
    assert any("Event Hub entity SAS rule inventory is incomplete" in note for note in assessment.notes)


def test_disabled_eventhub_local_auth_does_not_apply_sas_rights():
    _, _, assessment = _collect(Transport(local_auth=True))
    assert next(step for step in assessment.path if step["layer"] == "sas_authorization")["decision"] == "disabled"
    assert all(step["layer"] != "sas_entity_authorization" for step in assessment.path)
