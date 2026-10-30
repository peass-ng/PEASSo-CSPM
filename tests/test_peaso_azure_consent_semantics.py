"""Graph authorizationPolicy self-consent assignments have a case-variant prefix."""
import copy

import pytest

from peaso.checks import CHECKS
from peaso.checks import claude_azure_identity  # noqa: F401 - registers the native checks


DISABLED = "azure.claude.entra_user_consent_disabled"
NOT_LEGACY = "azure.claude.entra_user_consent_not_legacy"
CHECK_BY_ID = {check.id: check for check in CHECKS}


def assignment(values):
    return {"defaultUserRolePermissions": {"permissionGrantPoliciesAssigned": values}}


def evaluate(check_id, item):
    original = copy.deepcopy(item)
    status, evidence = CHECK_BY_ID[check_id].evaluate(item, {})
    assert item == original
    return status, evidence


@pytest.mark.parametrize("prefix", ["managePermissionGrantsForSelf", "ManagePermissionGrantsForSelf", "mAnAgEpErMiSsIoNgRaNtSfOrSeLf"])
def test_graph_lowercase_and_get_uppercase_self_grant_prefix_are_equivalent(prefix):
    low = assignment([prefix + ".microsoft-user-default-low"])
    legacy = assignment([prefix + ".microsoft-user-default-legacy"])
    assert evaluate(DISABLED, low)[0] == "FAIL"
    assert evaluate(NOT_LEGACY, low)[0] == "PASS"
    assert evaluate(DISABLED, legacy)[0] == "FAIL"
    assert evaluate(NOT_LEGACY, legacy)[0] == "FAIL"


def test_exact_legacy_identity_and_unknown_custom_policy_are_distinct():
    custom = assignment(["managePermissionGrantsForSelf.tenant-custom"])
    assert evaluate(DISABLED, custom)[0] == "FAIL"
    status, evidence = evaluate(NOT_LEGACY, custom)
    assert status == "UNKNOWN" and "custom" in evidence["reason"]
    lookalike = assignment(["managePermissionGrantsForSelf.microsoft-user-default-legacy-extra"])
    assert evaluate(NOT_LEGACY, lookalike)[0] == "UNKNOWN"
    legacy_and_custom = assignment(["managePermissionGrantsForSelf.tenant-custom",
                                    "ManagePermissionGrantsForSelf.microsoft-user-default-legacy"])
    assert evaluate(NOT_LEGACY, legacy_and_custom)[0] == "FAIL"


def test_unrelated_owned_resource_prefix_and_substring_do_not_enable_self_consent():
    unrelated = assignment(["ManagePermissionGrantsForOwnedResource.DeveloperConsent",
                            "prefixmanagePermissionGrantsForSelf.microsoft-user-default-legacy"])
    assert evaluate(DISABLED, unrelated)[0] == "PASS"
    assert evaluate(NOT_LEGACY, unrelated)[0] == "PASS"
    assert evaluate(DISABLED, assignment([]))[0] == "PASS"
    assert evaluate(NOT_LEGACY, assignment([]))[0] == "PASS"


@pytest.mark.parametrize("item", [
    {},
    {"collection_status": "denied"},
    {"defaultUserRolePermissions": {}},
    assignment(None),
    assignment([3]),
    assignment([""]),
    assignment(["managePermissionGrantsForSelf."]),
    assignment(["managePermissionGrantsForSelf"]),
    assignment([" managePermissionGrantsForSelf.microsoft-user-default-low"]),
])
def test_missing_denied_nonstring_or_malformed_assignment_is_unknown(item):
    assert evaluate(DISABLED, copy.deepcopy(item))[0] == "UNKNOWN"
    assert evaluate(NOT_LEGACY, copy.deepcopy(item))[0] == "UNKNOWN"


