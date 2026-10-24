"""Current native fixtures preserve positive, clean and unbound distinctions."""
from copy import deepcopy

import pytest

from peaso.checks import CHECKS
from tests.azure_native_successor_inputs_20261020 import current_cases

STORAGE = 'azure_storage_account_10_3_4_7_02943e9'
ACR = 'azure.review.acr.selected_image_secret_indicators'


@pytest.mark.parametrize('check_id', [STORAGE, ACR])
@pytest.mark.parametrize('branch,expected', [('pass', 'PASS'), ('fail', 'FAIL')])
def test_normal_collector_captures_have_expected_current_verdict(check_id, branch, expected):
    check = next(c for c in CHECKS if c.id == check_id)
    cases = current_cases(check_id, {})
    item, index = cases[branch], cases[branch + '_index']
    before = deepcopy((item, index))
    assert check.evaluate(item, index)[0] == expected
    assert (item, index) == before


@pytest.mark.parametrize('branch', ['pass', 'fail'])
def test_missing_storage_operation_does_not_create_retention_verdict(branch):
    check = next(c for c in CHECKS if c.id == STORAGE)
    cases = current_cases(STORAGE, {})
    index = cases[branch + '_index']
    for collection in index['collections']['storage_immutability_evidence']:
        for row in collection['items']:
            del row['_provenance']['source_operation']
    assert check.evaluate(cases[branch], index)[0] == 'UNKNOWN'


@pytest.mark.parametrize('branch', ['pass', 'fail'])
def test_foreign_acr_context_does_not_create_secret_verdict(branch):
    check = next(c for c in CHECKS if c.id == ACR)
    cases = current_cases(ACR, {})
    index = cases[branch + '_index']
    index['context']['scope'] = '/subscriptions/33333333-3333-3333-3333-333333333333'
    assert check.evaluate(cases[branch], index)[0] == 'UNKNOWN'


def test_unregistered_catalog_reference_still_fails_validation():
    from peaso.checks.catalog import manifest
    from scripts.peaso_review_catalog import validate_manifest
    data = manifest()
    row = next(r for r in data['checks'] if r['disposition'] in ('ported', 'merged'))
    row['native_checks'] = ['aws.unregistered.current_native_witness_test']
    with pytest.raises(ValueError, match='requires real native evaluator'):
        validate_manifest(data)
