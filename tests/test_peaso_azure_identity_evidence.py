"""Provider evidence boundaries for the two Azure identity source corrections."""

import copy
from types import SimpleNamespace

import pytest

from peaso.checks import CHECKS
from peaso.checks import claude_azure_identity as identity
from peaso.collectors.azure import DIRECTORY


CHECKS_BY_ID = {check.id: check for check in CHECKS}
ROOT = CHECKS_BY_ID["azure.claude.iam_root_custom_role_no_wildcard"]
WILDCARD = CHECKS_BY_ID["azure.claude.iam_custom_role_no_wildcard_actions"]
# The registered sign-in control is now the native-bound successor
# (tests/test_unused_iam_azure_user_completion.py). These boundaries remain
# the predecessor field semantics that successor builds on.
RECENT = SimpleNamespace(evaluate=identity.recent_sign_in)
SNAPSHOT = {"context": {"created_at": "2026-01-01T00:00:00Z"}}


def evaluate(check, item, index=None):
    before = copy.deepcopy((item, index))
    outcome = check.evaluate(item, {} if index is None else index)
    assert (item, index) == before
    return outcome


def user(success="2025-12-15T00:00:00Z", attempt="2025-12-31T00:00:00Z", *, user_type="Member"):
    return {"id": "u", "accountEnabled": True, "userType": user_type,
            "signInActivity": {"lastSuccessfulSignInDateTime": success, "lastSignInDateTime": attempt}}


def test_root_custom_role_is_unsupported_not_a_proven_wildcard_violation():
    root = identity._definition(actions=("*",), scopes=("/",))
    status, detail = evaluate(ROOT, root)
    assert status == "UNKNOWN" and detail["wildcard_actions"] == ["*"]
    assert "does not support root" in detail["reason"]
    assert evaluate(ROOT, identity._definition(scopes=("/",)))[0] == "UNKNOWN"
    assert evaluate(ROOT, identity._definition("BuiltInRole", actions=("*",), scopes=("/",)))[0] == "NOT_APPLICABLE"


def test_supported_arm_custom_role_is_outside_root_only_predicate_but_generic_wildcard_still_fails():
    subscription = identity._definition(actions=("*",), scopes=("/subscriptions/s",))
    assert evaluate(ROOT, subscription)[0] == "NOT_APPLICABLE"
    assert evaluate(WILDCARD, subscription)[0] == "FAIL"
    management_group = identity._definition(actions=("*",), scopes=("/providers/Microsoft.Management/managementGroups/m",))
    assert evaluate(ROOT, management_group)[0] == "NOT_APPLICABLE"


@pytest.mark.parametrize("scopes", [(), ("nonsense",), ("/subscriptions/s", 3)])
def test_empty_or_invalid_custom_scopes_are_unknown(scopes):
    assert evaluate(ROOT, identity._definition(scopes=scopes))[0] == "UNKNOWN"


def test_graph_directory_role_shape_is_not_mistaken_for_arm_custom_role():
    assert evaluate(ROOT, {"id": "graph-role", "isBuiltIn": False,
                           "rolePermissions": [{"allowedResourceActions": ["*"]}]})[0] == "UNKNOWN"


def test_successful_sign_in_includes_noninteractive_access_and_ignores_attempt_order():
    status, detail = evaluate(RECENT, user(attempt="2025-01-01T00:00:00Z"), SNAPSHOT)
    assert status == "PASS"
    assert detail["days_since_successful_sign_in"] == 17
    assert "non-interactive" in detail["activity_scope"]
    assert evaluate(RECENT, user(attempt=None, user_type="Guest"), SNAPSHOT)[0] == "PASS"


def test_recent_failed_attempt_cannot_hide_stale_successful_access():
    stale = user(success="2025-06-01T00:00:00Z", attempt="2025-12-31T00:00:00Z")
    status, detail = evaluate(RECENT, stale, SNAPSHOT)
    assert status == "FAIL" and detail["days_since_successful_sign_in"] > 90
    assert evaluate(RECENT, user(success="2025-06-01T00:00:00Z", user_type="Guest"), SNAPSHOT)[0] == "FAIL"


@pytest.mark.parametrize("activity", [
    {"lastSignInDateTime": "2025-12-31T00:00:00Z"},
    {"lastSignInDateTime": "2025-12-31T00:00:00Z", "lastSuccessfulSignInDateTime": None},
    {"lastSuccessfulSignInDateTime": "not-a-time"},
    {"lastSuccessfulSignInDateTime": "2026-01-02T00:00:00Z"},
    {"lastSuccessfulSignInDateTime": "2023-11-30T00:00:00Z"},
    None,
])
def test_attempt_only_missing_nonbackfilled_or_malformed_success_is_unknown(activity):
    assert evaluate(RECENT, {"id": "u", "accountEnabled": True, "signInActivity": activity}, SNAPSHOT)[0] == "UNKNOWN"


def test_denied_missing_snapshot_and_disabled_user_boundaries():
    denied = {"id": "u", "accountEnabled": True,
              "_coverage": {"signInActivity": {"status": "denied"}}}
    assert evaluate(RECENT, denied, SNAPSHOT)[0] == "UNKNOWN"
    assert evaluate(RECENT, user(), {})[0] == "UNKNOWN"
    disabled = user()
    disabled["accountEnabled"] = False
    assert evaluate(RECENT, disabled, {})[0] == "NOT_APPLICABLE"
    assert evaluate(RECENT, user(), {"context": {"created_at": "2023-11-01T00:00:00Z"}})[0] == "UNKNOWN"


def test_existing_graph_user_projection_reads_full_sign_in_activity_object():
    assert "$select=" in DIRECTORY["directory_user"]
    assert "signInActivity" in DIRECTORY["directory_user"]
