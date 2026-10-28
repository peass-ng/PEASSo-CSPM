"""ML online endpoints are collected through the existing cached child reader."""

import pytest

from peaso.collectors import azure
from test_peaso_collectors_azure_perf import FakeAzure, rows


RID = ("/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/rg/"
       "providers/Microsoft.MachineLearningServices/workspaces/ml")


def test_ml_workspace_uses_one_current_acl_capable_list_read():
    from urllib.parse import urlsplit, parse_qs

    calls = []
    def handler(url, body, audience):
        calls.append(url)
        if urlsplit(url).path.endswith("/providers/Microsoft.MachineLearningServices/workspaces"):
            assert parse_qs(urlsplit(url).query)["api-version"] == ["2026-03-01"]
            return {"value": [{"id": RID, "name": "ml", "properties": {
                "publicNetworkAccess": "Enabled", "networkAcls": {"defaultAction": "Deny",
                    "ipRules": [{"value": "8.8.8.8/32"}]}}}]}
        return {"value": []}

    snapshot = azure.collect({"scopes": ["00000000-0000-0000-0000-000000000001"]},
                             ["ml_workspace"], transport=FakeAzure(handler))
    workspace = rows(snapshot, "ml_workspace")[0]["items"][0]
    assert workspace["properties"]["networkAcls"]["ipRules"] == [{"value": "8.8.8.8/32"}]
    assert sum(urlsplit(url).path.endswith("/providers/Microsoft.MachineLearningServices/workspaces")
               for url in calls) == 1


def test_ml_online_endpoints_paged_once_and_bound_to_workspace():
    child = {"id": RID + "/onlineEndpoints/score", "name": "score",
             "type": "Microsoft.MachineLearningServices/workspaces/onlineEndpoints",
             "properties": {"publicNetworkAccess": "Enabled", "scoringUri": "https://score.example.test"}}
    url = "https://management.azure.com" + RID + "/onlineEndpoints?api-version=2024-04-01"
    urls = []

    def request(current, **kwargs):
        urls.append(current)
        return {"value": [child] if current == url else []}

    item = {"id": RID, "type": "Microsoft.MachineLearningServices/workspaces", "properties": {}}
    azure._embed(azure._Reader({}), request, [("ml_workspace", item)], skip=("diagnosticSettings",))
    assert urls.count(url) == 1
    assert item["_coverage"]["onlineEndpoints"]["status"] == "collected"
    assert item["onlineEndpoints"][0]["properties"] == child["properties"]


def test_ml_online_endpoint_rejects_foreign_child_identity():
    foreign = {"id": RID.replace("/ml", "/other") + "/onlineEndpoints/score", "name": "score",
               "type": "Microsoft.MachineLearningServices/workspaces/onlineEndpoints", "properties": {}}
    with pytest.raises(ValueError, match="malformed or foreign embedded child identity"):
        azure._child_rows([foreign], RID, "onlineEndpoints")
