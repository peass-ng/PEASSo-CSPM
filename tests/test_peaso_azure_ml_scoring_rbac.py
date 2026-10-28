"""Observed external RBAC grants are joined to the online endpoint auth mode."""

import pytest

from peaso.analysis.iam import review_findings
from peaso.snapshot import make_snapshot, resources

SUB = "/subscriptions/11111111-1111-1111-1111-111111111111"
TENANT = "/tenants/home"
WORKSPACE = SUB + "/resourceGroups/rg/providers/Microsoft.MachineLearningServices/workspaces/ml"
ENDPOINT = WORKSPACE + "/onlineEndpoints/score"
ROLE = SUB + "/providers/Microsoft.Authorization/roleDefinitions/reader"
PREFIX = "Microsoft.MachineLearningServices/workspaces/onlineEndpoints/"


def _find(mode, *, actions=(), data_actions=(), not_actions=(), not_data_actions=(),
          scope=WORKSPACE, principal="guest", principal_type="User", condition=None,
          endpoint_id=ENDPOINT):
    assignment = {"id": SUB + "/providers/Microsoft.Authorization/roleAssignments/a",
                  "properties": {"scope": scope, "principalId": principal,
                                 "principalType": principal_type, "roleDefinitionId": ROLE,
                                 "condition": condition}}
    definition = {"id": ROLE, "name": "reader", "properties": {"permissions": [{
        "actions": list(actions), "dataActions": list(data_actions),
        "notActions": list(not_actions), "notDataActions": list(not_data_actions)}]}}
    collections = [
        {"type": "ml_workspace", "scope": SUB, "service": "Microsoft.MachineLearningServices",
         "status": "collected", "items": [{"id": WORKSPACE, "onlineEndpoints": [{"id": endpoint_id,
            "properties": {"authMode": mode, "publicNetworkAccess": "Enabled"}}]}]},
        {"type": "role_assignment", "scope": SUB, "service": "Microsoft.Authorization",
         "status": "collected", "items": [assignment]},
        {"type": "role_definition", "scope": "/", "service": "Microsoft.Authorization",
         "status": "collected", "items": [definition]},
        {"type": "directory_user", "scope": TENANT, "service": "Microsoft.Graph",
         "status": "collected", "items": [{"id": "guest", "userType": "Guest"}]},
    ]
    if principal_type == "Group":
        collections.extend([
            {"type": "directory_group", "scope": TENANT, "service": "Microsoft.Graph",
             "status": "collected", "items": [{"id": principal}]},
            {"type": "directory_membership", "scope": TENANT + "/groups/" + principal,
             "service": "Microsoft.Graph", "status": "collected", "items": [{"id": "guest"}]},
        ])
    snapshot = make_snapshot("azure", [SUB], collections, metadata={"tenant_id": "home"})
    return [row for row in review_findings(snapshot, resources(snapshot))
            if row["check_id"] == "analysis.azure_ml_scoring_rbac_share"]


@pytest.mark.parametrize("mode,grant,field", [
    ("AADToken", "score/action", "data_actions"),
    ("AMLToken", "token/action", "actions"),
    ("Key", "listKeys/action", "actions"),
])
def test_external_guest_has_declared_mode_specific_scoring_grant(mode, grant, field):
    found = _find(mode, **{field: [PREFIX + grant]})
    assert len(found) == 1 and found[0]["status"] == "FAIL"
    evidence = found[0]["evidence"]
    assert evidence["online_endpoint_id"] == ENDPOINT.casefold()
    assert evidence["required_action"] == (PREFIX + grant).casefold()
    assert evidence["principal_id"] == "guest"
    assert evidence["auth_mode"] == mode


def test_mode_scope_and_exclusions_prevent_false_scoring_grant():
    score = PREFIX + "score/action"
    assert not _find("Key", data_actions=[score])
    assert not _find("AADToken", data_actions=[score], not_data_actions=[score])
    assert not _find("AADToken", data_actions=[score], scope=SUB + "/resourceGroups/other")
    assert not _find("AADToken", data_actions=[score], endpoint_id=ENDPOINT + "/extra")
    assert not _find("AADToken", data_actions=[score], scope="")


def test_nested_group_guest_and_assignment_condition_are_preserved():
    found = _find("AADToken", data_actions=[PREFIX + "score/action"],
                  principal="group", principal_type="Group", condition="@Resource[x] StringEquals 'y'")
    assert len(found) == 1 and found[0]["status"] == "MANUAL"
    evidence = found[0]["evidence"]
    assert evidence["via_group"] == "group"
    assert evidence["group_path"] == ["group"]
    assert evidence["membership_source"]
