"""Tenant provenance and pinned native directory-policy branch semantics."""
import copy
import json
from pathlib import Path

import pytest

from peaso.checks import CHECKS, azure_ports_directory as ports
from peaso.checks.fixtures import CASES

ROOT = Path(__file__).resolve().parent.parent
REVIEWS = json.loads((ROOT / "peaso/rulepacks/reviewed_azure_ports_directory.json").read_text())
REGISTRY = {check.id: check for check in CHECKS}
def _verified_merge(row):
    """A corrected merge is legitimate only with a recorded same-requirement verification."""
    v = row.get('native_equivalence_verification')
    return bool(row.get('disposition') == 'merged' and row.get('review_classification') == 'corrected_native_merge' and v
                and v.get('verdict') == 'same_control_requirement' and v.get('target_native_checks') == row['native_checks'] and row['native_checks']
                and all(v.get(k) for k in ('resource', 'property', 'pass_condition', 'upstream_defect_only'))
                and row.get('upstream_defect', {}).get('reason'))


def _not_fake(row):
    """Unverified rows stay rejected with no native; verified rows are corrected merges."""
    return _verified_merge(row) or (row['disposition'] == 'rejected' and row['native_checks'] == [] and 'native_equivalence_verification' not in row)


def _cls(row):
    return row.get('upstream_defect', {}).get('classification') if row.get('review_classification') == 'corrected_native_merge' else row.get('review_classification')


@pytest.mark.parametrize("cid", ports.CHECK_IDS, ids=str)
def test_native_directory_policy_pass_fail_and_unavailable_facts(cid):
    check = REGISTRY[cid]
    for label, expected in (("pass", "PASS"), ("fail", "FAIL")):
        item = copy.deepcopy(CASES[cid][label])
        before = copy.deepcopy(item)
        assert check.evaluate(item, {"context": {"scope": "/tenants/tenant", "metadata": {"tenant_id": "tenant"}}})[0] == expected
        assert item == before
        assert check.evaluate(item, {"context": {"metadata": {"tenant_id": "foreign"}}})[0] == "UNKNOWN"
        item.pop("_provenance")
        assert check.evaluate(item, {})[0] == "UNKNOWN"
    for item in ({}, None, [], {"collection_status": "denied"}):
        assert check.evaluate(item, {})[0] == "UNKNOWN"


def test_unknown_invite_enum_and_guest_template_are_unknown_without_policy_edits():
    provenance = {"_provenance": {"tenant_id": "tenant"}}
    assert REGISTRY[ports.SOURCE_QUERIES["ad_authorization_policy_guest_invite_restricted"]].evaluate({**provenance, "allowInvitesFrom": "FutureVariant"}, {})[0] == "UNKNOWN"
    assert REGISTRY[ports.SOURCE_QUERIES["ad_authorization_policy_guest_user_access_restricted"]].evaluate({**provenance, "guestUserRoleId": "unrecognized"}, {})[0] == "UNKNOWN"


def test_current_graph_lowercase_consent_identifiers_cannot_false_pass_and_source_is_rejected():
    duckdb = pytest.importorskip('duckdb')
    policy = 'managePermissionGrantsForSelf.microsoft-user-default-low'
    with duckdb.connect(':memory:') as db:
        disallowed, restricted = db.execute("SELECT CASE WHEN ? LIKE 'ManagePermissionGrantsForSelf.%' THEN 'alarm' ELSE 'ok' END, CASE WHEN json_contains(?::JSON, '[\"ManagePermissionGrantsForSelf.microsoft-user-default-low\"]'::JSON) THEN 'ok' ELSE 'alarm' END", [policy, json.dumps([policy])]).fetchone()
    assert (disallowed, restricted) == ('ok', 'alarm')
    item = {'_provenance': {'tenant_id': 'tenant'}, 'defaultUserRolePermissions': {'permissionGrantPoliciesAssigned': [policy]}}
    denied = REGISTRY[ports.SOURCE_QUERIES['ad_authorization_policy_user_consent_disallowed']]
    low = REGISTRY[ports.SOURCE_QUERIES['ad_authorization_policy_user_consent_verified_publishers_selected_permissions']]
    assert denied.evaluate(item, {})[0] == 'FAIL'
    assert low.evaluate(item, {})[0] == 'PASS'
    item['defaultUserRolePermissions']['permissionGrantPoliciesAssigned'].append('managePermissionGrantsForSelf.microsoft-user-default-legacy')
    assert low.evaluate(item, {})[0] == 'FAIL'
    invalid = [row for row in REVIEWS.values() if _cls(row) == 'invalid_predicate' and row['source_review']['query_id'] in ('ad_authorization_policy_user_consent_disallowed', 'ad_authorization_policy_user_consent_verified_publishers_selected_permissions')]
    assert len(invalid) == 4
    assert all(_verified_merge(row) and row['source_review']['counterexample'] for row in invalid)
    assert all(_not_fake(row) for row in REVIEWS.values())
