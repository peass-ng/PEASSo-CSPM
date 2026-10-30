"""The historical Entra-named App Service source measures an outbound managed identity."""

from peaso.checks import CHECKS
from peaso.checks.claude2_azure_common import cid


def test_existing_web_app_identity_check_title_matches_its_unchanged_predicate():
    check_id = cid("web_app_register_with_entra")
    matches = [check for check in CHECKS if check.id == check_id]
    assert len(matches) == 1
    check = matches[0]
    assert check.dependencies == ["app_service"]

    def observed(identity=None, *, auth=None, kind="app"):
        row = {"kind": kind, "properties": {}}
        if identity is not None:
            row["identity"] = identity
        if auth is not None:
            row["authSettingsV2"] = {"properties": auth}
        return check.evaluate(row, {})[0]

    assert observed({"type": "SystemAssigned"}) == "PASS"
    assert observed({"type": "UserAssigned"}) == "PASS"
    assert observed({"type": "None"}, auth={"identityProviders": {"azureActiveDirectory": {}}}) == "FAIL"
    assert observed() == "FAIL"  # A complete site object without identity is source-defined None.
    assert observed({"type": "SystemAssigned"}, kind="functionapp") == "NOT_APPLICABLE"
    assert check.evaluate({"kind": "app"}, {})[0] == "UNKNOWN"
    assert check.evaluate({"collection_status": "denied"}, {})[0] == "UNKNOWN"
