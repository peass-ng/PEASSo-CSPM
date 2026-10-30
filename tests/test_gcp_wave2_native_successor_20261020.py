"""Real native current/archived Functions witnesses for the bounded successor."""
from copy import deepcopy
import inspect
import json

import pytest

from peaso.checks import CHECKS
from peaso.checks import gcp_function_secret_partial_page_20261020 as current
from peaso.checks import gcp_function_secret_partial_positive_candidate_20261020 as candidate
from peaso.checks import gcp_function_secret_review_20261019 as predecessor
from peaso.collectors import gcp_function_secret_indicators as legacy
from peaso.collectors import gcp_function_secret_pairs_20261020 as paired

# Reviewed successor bodies outside proposal_boundary, and the whole reviewed outside text.
from tests.gcp_function_partial_positive_native_20261020 import TOKEN, collect_native, index_for, raw
from tests.gcp_wave2_historical_native_20261020 import collect_historical_native


@pytest.mark.parametrize('positive', [True, False])
@pytest.mark.parametrize('partial', [True, False])
def test_same_native_source_preserves_current_positive_and_absence_guards(monkeypatch, positive, partial):
    source = raw({'SETTING': TOKEN if positive else 'production'}, {'BUILD': 'release'})
    old_env, old_receipt, _ = collect_historical_native(monkeypatch, source, unavailable_second=partial)
    new_env, new_receipt, _ = collect_native(monkeypatch, source, unavailable_second=partial)
    old, = old_env['items']
    new, = new_env['items']
    assert old[legacy.MARKER]['schema'] == legacy.SCHEMA
    assert new[paired.MARKER]['schema'] == paired.SCHEMA
    registered, = [c for c in CHECKS if c.id == predecessor.CHECK_ID]
    assert inspect.unwrap(registered.evaluate) is current.evaluate
    expected = 'FAIL' if positive else 'UNKNOWN' if partial else 'PASS'
    assert candidate.evaluate(old, index_for(old, old_env))[0] == expected
    before = deepcopy(new)
    status, evidence = registered.evaluate(new, index_for(new, new_env))
    assert status == expected and new == before
    if partial:
        assert predecessor.evaluate(old, index_for(old, old_env))[0] == 'UNKNOWN'
    else:
        assert predecessor.evaluate(old, index_for(old, old_env))[0] == status
    if positive:
        assert evidence['complete'] is (not partial)
        assert {d['engine'] for leak in evidence['secret_leaks'] for d in leak['detectors']} == (
            {'kingfisher'} if partial else {'kingfisher', 'trufflehog'})
    # 75087001 made the current collector's ``function`` inventory depend on
    # ``cloudfunctions_location`` (the privilege model needs the project's
    # Functions regions): one location listing joins the current capture's
    # list and getIamPolicy reads; the historical capture keeps its two.
    locations = ['GET', 'https://cloudfunctions.googleapis.com/v2/projects/review/locations']
    for receipt, listings in ((old_receipt, 0), (new_receipt, 1)):
        assert receipt['raw_source_unchanged'] and receipt['secret_absent_from_retained_output']
        calls = receipt['http_calls']
        assert receipt['ordinary_inventory_status'] == 'collected' and calls.count(locations) == listings
        assert len([call for call in calls if call != locations]) == 2
    assert TOKEN not in json.dumps([old, new, evidence, old_receipt, new_receipt])


@pytest.mark.parametrize('profiles', [('batch', 'workbench', 'batch', 'workbench'),
                                     ('workbench', 'batch', 'workbench', 'batch')])
def test_mixed_order_proposal_imports_preserve_all_mutable_state_and_runtime_grants(monkeypatch, profiles):
    from peaso import checks, engine
    from peaso.checks import fixtures
    from peaso.collectors import gcp_workbench_source_runtime_20261020 as workbench
    from peaso.collectors import gcp_dataflow_batch_source_runtime_20261020 as jobs
    from tests.gcp_referenced_source_historical_compatibility_20261020 import proposal_boundary
    registry, cases, aliases = checks.CHECKS, fixtures.CASES, checks.CHECK_ALIASES
    monkeypatch.setitem(cases, '__wave2_mutable_probe__', {'nested': ['retained']})
    before_registry = tuple(registry)
    from tests.gcp_clarity_combined_successor_20261020 import cases_fingerprint
    before_cases, before_aliases = cases_fingerprint(cases), deepcopy(aliases)
    grants = (workbench._Grant, workbench._SEAL, jobs._Grant, jobs._SEAL)
    def forbidden_reinstallation():
        pytest.fail('Proposal import must not reinstall the global registry')
    monkeypatch.setattr(engine, '_registry', forbidden_reinstallation)
    for profile in profiles:
        assert proposal_boundary(profile)['proposal_registration_delta'] == 0
        assert checks.CHECKS is registry and fixtures.CASES is cases and checks.CHECK_ALIASES is aliases
        assert tuple(registry) == before_registry and all(a is b for a, b in zip(registry, before_registry))
        assert cases_fingerprint(cases) == before_cases and aliases == before_aliases
        assert (workbench._Grant, workbench._SEAL, jobs._Grant, jobs._SEAL) == grants
        assert all(a is b for a, b in zip((workbench._Grant, workbench._SEAL, jobs._Grant, jobs._SEAL), grants))


@pytest.mark.parametrize('mutation', ['snapshot', 'expected', 'scope', 'identity'])
def test_proposal_boundary_rejects_mutated_capability_fields_and_replacements(monkeypatch, mutation):
    from peaso.azure_function_package_index_20261020 import _Admitted
    from peaso.checks import fixtures
    from tests import gcp_referenced_source_historical_compatibility_20261020 as bridge
    probe = _Admitted({'mutable': ['before']}, {'nested': ['before']}, 'native-scope')
    monkeypatch.setitem(fixtures.CASES, '__wave2_capability_probe__', {'grant': probe})
    real_reload = bridge.importlib.reload
    def reload(module):
        module = real_reload(module)
        if module.__name__ == 'peaso.checks.gcp_batch_referenced_source_20261020_proposal':
            validate = module.validate_proposal
            def mutate_after_validation():
                receipt = validate()
                if mutation == 'snapshot': monkeypatch.setitem(probe.snapshot, 'mutable', ['changed'])
                elif mutation == 'expected': monkeypatch.setitem(probe.expected, 'nested', ['changed'])
                elif mutation == 'scope': monkeypatch.setattr(probe, 'scope', 'foreign-scope')
                else: monkeypatch.setitem(fixtures.CASES['__wave2_capability_probe__'], 'grant',
                                          _Admitted(deepcopy(probe.snapshot), deepcopy(probe.expected), probe.scope))
                return receipt
            monkeypatch.setattr(module, 'validate_proposal', mutate_after_validation)
        return module
    monkeypatch.setattr(bridge.importlib, 'reload', reload)
    with pytest.raises(AssertionError):
        bridge.proposal_boundary('batch')


