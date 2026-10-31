"""Selected Function settings checks register once and evaluate their native cases."""
from copy import deepcopy
import inspect
import pytest
from peaso import checks
from peaso.checks import fixtures, selected_admission
from peaso.checks import azure_function_settings_runtime_admission_20261020 as admission
from peaso.checks import azure_function_settings_review_20261020 as candidate
from peaso.checks import azure_function_settings_runtime_consumer_20261020 as current_candidate


def install():
    return admission.install()


@pytest.mark.parametrize('check',range(2))
@pytest.mark.parametrize('branch',['pass','fail','unknown'])
def test_exact_native_capture_projection_has_decisive_and_unresolved_branches(check,branch):
    install()
    cases=selected_admission.load_cases('azure_function_settings_runtime_cases_20261020.json')
    d=current_candidate.PROPOSALS[check];case=cases[d['id']]
    registered,=[c for c in checks.CHECKS if c.id==d['id']]
    assert inspect.unwrap(registered.evaluate) is d['evaluate']
    assert d['evaluate'](deepcopy(case[branch]),deepcopy(case[branch+'_index']))[0]==branch.upper()
    assert registered.evaluate(deepcopy(case[branch]),deepcopy(case[branch+'_index']))[0]==branch.upper()


@pytest.fixture
def isolated_registry():
    # Isolate in place: attested modules keep their CHECKS/CASES bindings.
    ids={d['id']for d in candidate.PROPOSALS}
    saved_checks=list(checks.CHECKS);saved_cases=dict(fixtures.CASES)
    checks.CHECKS[:]=[c for c in saved_checks if c.id not in ids]
    for k in ids:fixtures.CASES.pop(k,None)
    try:yield ids
    finally:
        checks.CHECKS[:]=saved_checks;fixtures.CASES.clear();fixtures.CASES.update(saved_cases)


def test_install_is_idempotent_without_overwriting_existing_registry(monkeypatch,isolated_registry):
    ids=isolated_registry;before=tuple(checks.CHECKS)
    install();install()
    assert tuple(checks.CHECKS[:len(before)])==before
    assert len([c for c in checks.CHECKS if c.id in ids])==2
    assert ids<=fixtures.CASES.keys()
