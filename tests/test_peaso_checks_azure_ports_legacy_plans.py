"""Legacy pricing applicability and exact source selector proofs, native-only."""
import copy

import pytest

from peaso.checks import CHECKS, azure_ports_legacy_plans as ports
from peaso.checks.fixtures import CASES
from peaso.checks.azure_ports_defender import _fixture

REGISTRY = {check.id: check for check in CHECKS}


@pytest.mark.parametrize('cid', ports.CHECK_IDS, ids=str)
def test_legacy_plan_observed_standard_free_and_uncertain_absence(cid):
    check = REGISTRY[cid]
    for label, desired in (('pass', 'PASS'), ('fail', 'FAIL')):
        fixture = CASES[cid]
        item, index = copy.deepcopy(fixture[label]), copy.deepcopy(fixture[label + '_index'])
        before = copy.deepcopy((item, index))
        assert check.evaluate(item, index)[0] == desired
        assert (item, index) == before
    for status in ('empty', 'denied', 'partial', 'malformed'):
        assert check.evaluate({'scope': '/subscriptions/sub'}, _fixture('security_pricing', [], status))[0] == 'UNKNOWN'
    assert check.evaluate({'scope': '/tenants/tenant'}, {})[0] == 'NOT_APPLICABLE'
    index = copy.deepcopy(CASES[cid]['pass_index'])
    index['security_pricing'].append(copy.deepcopy(index['security_pricing'][0]))
    assert check.evaluate({'scope': '/subscriptions/sub'}, index)[0] == 'UNKNOWN'
    index['security_pricing'].pop()
    row = index['security_pricing'][0]['data']
    row['id'] = row['id'].replace('/sub/', '/foreign/')
    assert check.evaluate({'scope': '/subscriptions/sub'}, index)[0] == 'UNKNOWN'
    row['id'] = row['id'].replace('/foreign/', '/sub/')
    row['properties']['pricingTier'] = 'FutureTier'
    assert check.evaluate({'scope': '/subscriptions/sub'}, index)[0] == 'UNKNOWN'
