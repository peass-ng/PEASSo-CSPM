"""ML scoring auth requirements accompany the observed public endpoint path."""

import pytest

from peaso.analysis.internet_exposure import assess
from peaso.snapshot import make_snapshot, resources

SCOPE = "/subscriptions/11111111-1111-1111-1111-111111111111"
RID = SCOPE + "/resourceGroups/rg/providers/Microsoft.MachineLearningServices/workspaces/ml"
ENDPOINT = RID + "/onlineEndpoints/score"


def _assessment(mode, *, workspace_public="Enabled", endpoint_public="Enabled", public_ip=True):
    item = {"id": RID, "properties": {"publicNetworkAccess": workspace_public,
        "networkAcls": {"defaultAction": "Deny", "ipRules": [
            {"value": "8.8.8.8/32"}] if public_ip else []}},
        "onlineEndpoints": [{"id": ENDPOINT, "properties": {"publicNetworkAccess": endpoint_public,
            "scoringUri": "https://score.example.test", "authMode": mode}}],
        "_coverage": {"onlineEndpoints": {"status": "collected"}}}
    snapshot = make_snapshot("azure", [SCOPE], [{"type": "ml_workspace", "scope": SCOPE,
        "service": "Microsoft.MachineLearningServices", "status": "collected", "items": [item]}])
    return next(a for a in assess(snapshot, resources(snapshot)) if a.resource["type"] == "ml_workspace")


@pytest.mark.parametrize("mode,requirement", [
    ("Key", "endpoint key"), ("AMLToken", "Azure ML token"),
    ("AADToken", "Entra identity with score/action RBAC")])
def test_public_scoring_path_records_native_auth_mode(mode, requirement):
    assessment = _assessment(mode)
    assert assessment.verdict() == "FAIL"
    assert {step["access_requirement"] for step in assessment.path
            if step["layer"] == "scoring_authentication"} == {requirement}
    assert any(step["layer"] == "listener" for step in assessment.path)


def test_lingering_selected_ip_endpoint_keeps_auth_mode():
    assessment = _assessment("Key", workspace_public="Disabled")
    assert assessment.verdict() == "FAIL"
    assert any(step["layer"] == "scoring_authentication" and step["auth_mode"] == "Key"
               for step in assessment.path)


def test_unknown_auth_mode_does_not_change_network_verdict():
    assessment = _assessment(None)
    assert assessment.verdict() == "FAIL"
    assert all(step["layer"] != "scoring_authentication" for step in assessment.path)
    assert any("authentication mode is unavailable" in note for note in assessment.notes)


def test_disabled_endpoint_does_not_claim_public_scoring_auth_path():
    assessment = _assessment("Key", endpoint_public="Disabled", public_ip=False)
    assert all(step["layer"] != "scoring_authentication" for step in assessment.path)
