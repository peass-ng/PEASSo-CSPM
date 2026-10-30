"""Audit accounting and incomplete-data contracts; no cloud credentials used."""
from copy import deepcopy

import pytest

from scripts.audit_aws_native_contracts import registry
from tests.test_peaso_checks import CASES
from tests.aws_late_native_contracts_20261020 import workload_witness_case
from scripts.audit_aws_native_contracts import active_ids, producer_contracts, registry, source_ref
from tests.aws_late_native_contracts_20261020 import assert_workload_producer, workload_witness_case

CHECKS = registry()

@pytest.mark.parametrize('check', CHECKS, ids=lambda c: c.id)
def test_explicit_partial_resource_never_passes(check):
    if check.id == 'aws.review.workload.selected_command_literal_secret_indicators':
        item, index = workload_witness_case()
        assert check.evaluate(deepcopy(item), deepcopy(index))[0] == 'FAIL'
    else:
        cases = CASES[check.id]
        item = deepcopy(cases.get('pass', {}))
        index = deepcopy(cases.get('pass_index', cases.get('case_indices', {}).get('pass', cases.get('index', {}))))
    item['collection_status'] = 'partial'
    assert check.evaluate(item, index)[0] == 'UNKNOWN'


@pytest.mark.parametrize('check', [check for check in CHECKS if check.target == 'scope'], ids=lambda c: c.id)
def test_scope_partial_dependencies_cannot_prove_pass(check):
    cases = CASES[check.id]
    if 'pass' not in cases:
        pytest.skip('no positive shared scope fixture; absence is explicit')
    item = deepcopy(cases['pass'])
    index = deepcopy(cases.get('pass_index', cases.get('case_indices', {}).get('pass', cases.get('index', {}))))
    changed = 0
    for kind in check.dependencies:
        for envelope in index.get('collections', {}).get(kind, []):
            envelope['status'] = 'partial'
            changed += 1
    if not changed:
        # Legacy examples can predate a native dependency (for example the
        # account-global Config proof). They must remain unresolved, rather
        # than silently skipping this incomplete-evidence contract.
        assert check.evaluate(item, index)[0] != 'PASS', check.id
        return
    assert check.evaluate(item, index)[0] != 'PASS', check.id
