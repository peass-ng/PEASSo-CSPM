"""ACR repository-token capabilities use collected metadata only."""

from peaso.analysis.internet_exposure import assess
from peaso.collectors.azure import _child_rows
from peaso.snapshot import make_snapshot, resources

SCOPE = "/subscriptions/11111111-1111-1111-1111-111111111111"
RID = SCOPE + "/resourceGroups/rg/providers/Microsoft.ContainerRegistry/registries/images"
MAP = RID + "/scopeMaps/pull"
TOKEN = RID + "/tokens/build"


def _assessment(*, status="enabled", map_actions=None, map_status="collected", admin=False,
                public="Enabled"):
    token = {"id": TOKEN, "name": "build", "properties": {"status": status, "scopeMapId": MAP}}
    scope_map = {"id": MAP, "name": "pull", "properties": {
        "actions": ["repositories/team/app/content/read"] if map_actions is None else map_actions}}
    registry = {"id": RID, "properties": {"publicNetworkAccess": public,
                "loginServer": "images.azurecr.io", "adminUserEnabled": admin,
                "networkRuleSet": {"defaultAction": "Allow"}},
                "tokens": [token], "scopeMaps": [scope_map] if map_status == "collected" else [],
                "_coverage": {"tokens": {"status": "collected"},
                              "scopeMaps": {"status": map_status}}}
    snapshot = make_snapshot("azure", [SCOPE], [{"type": "container_registry", "scope": SCOPE,
        "service": "Microsoft.ContainerRegistry", "status": "collected", "items": [registry]}])
    return next(a for a in assess(snapshot, resources(snapshot)) if a.resource["type"] == "container_registry")


def test_enabled_acr_token_reports_bounded_repository_rights():
    assessment = _assessment()
    assert assessment.verdict() == "FAIL"
    token = next(step for step in assessment.path if step["layer"] == "registry_tokens")
    assert token["decision"] == "conditional"
    assert token["enabled_tokens"] == [{"name": "build", "scope_map": MAP,
                                         "actions": ["repositories/team/app/content/read"]}]
    assert assessment.authenticated is True
    assert any("holders and password state are not inventoried" in note for note in assessment.notes)


def test_disabled_token_and_incomplete_scope_map_do_not_imply_rights():
    disabled = _assessment(status="disabled")
    assert all(step["layer"] != "registry_tokens" for step in disabled.path)
    incomplete = _assessment(map_status="denied")
    assert all(step["layer"] != "registry_tokens" for step in incomplete.path)
    assert any("scope-map inventory is incomplete" in note for note in incomplete.notes)


def test_admin_credentials_capability_does_not_override_network_block():
    assessment = _assessment(admin=True, public="Disabled")
    assert assessment.verdict() == "PASS"
    assert any(step["layer"] == "registry_admin_credentials" and step["decision"] == "conditional"
               for step in assessment.path)


def test_acr_native_projection_keeps_token_rights_metadata_without_passwords():
    token = _child_rows([{"id": TOKEN, "name": "build", "type": "Microsoft.ContainerRegistry/registries/tokens",
                          "properties": {"status": "enabled", "scopeMapId": MAP,
                                         "credentials": {"password": "PRIVATE_TOKEN_SENTINEL"}}}], RID, "tokens")
    scope_map = _child_rows([{"id": MAP, "name": "pull", "type": "Microsoft.ContainerRegistry/registries/scopeMaps",
                              "properties": {"actions": ["repositories/team/app/content/read"]}}], RID, "scopeMaps")
    assert token[0]["properties"] == {"status": "enabled", "scopeMapId": MAP}
    assert scope_map[0]["properties"] == {"actions": ["repositories/team/app/content/read"]}
    assert "PRIVATE_TOKEN_SENTINEL" not in repr((token, scope_map))
