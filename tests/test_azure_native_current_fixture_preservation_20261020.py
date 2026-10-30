"""Keep native successors distinct from unsupported historical toy identities."""
from copy import deepcopy

import pytest

from peaso.checks import evaluate_check
from peaso.checks.facts import MemoIndex
from peaso.checks.fixtures import CASES
from tests.azure_native_successor_inputs_20261020 import _native_rows, current_cases




def test_original_windows_sql_image_is_preserved_and_cannot_hide_disabled_secure_boot():
    cid = 'azure.claude.vm_windows_secure_boot'
    old = deepcopy(CASES[cid])
    assert old['not_applicable']['properties']['storageProfile']['osDisk']['osType'] == 'Windows'
    assert evaluate_check(cid, deepcopy(old['not_applicable']), {})[0] == 'FAIL'
    current = current_cases(cid, old)
    assert current['not_applicable']['properties']['storageProfile']['osDisk']['osType'] == 'Linux'
    assert evaluate_check(cid, deepcopy(current['not_applicable']), {})[0] == 'NOT_APPLICABLE'
    assert CASES[cid] == old


def test_old_unbound_vhd_account_fixture_is_not_rewritten_into_native_proof():
    cid = 'azure.claude.storage_vhd_accounts_cmk'
    before = deepcopy(CASES[cid])
    assert evaluate_check(cid, deepcopy(before['pass']), deepcopy(before['pass_index']))[0] == 'UNKNOWN'
    current = current_cases(cid, before)
    assert evaluate_check(cid, current['pass'], current['pass_index'])[0] == 'PASS'
    assert CASES[cid] == before
