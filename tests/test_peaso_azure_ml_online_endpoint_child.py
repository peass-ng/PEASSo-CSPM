"""ML online endpoints are collected through the existing cached child reader."""

import pytest

from peaso.collectors import azure


RID = ("/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/rg/"
       "providers/Microsoft.MachineLearningServices/workspaces/ml")


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
