"""Admission preserves native semantics and fails closed on conflicts or tampering."""
from copy import deepcopy
import inspect
import json
from pathlib import Path
from dataclasses import replace
import pytest
from peaso import checks
from peaso.checks import fixtures
from peaso.checks import azure_function_settings_runtime_admission_20261020 as admission
from peaso.checks import azure_function_settings_review_20261020 as candidate
from peaso.checks import azure_function_settings_runtime_consumer_20261020 as current_candidate
from peaso.rawv2_private_source_successor_20261021 import install_admission
from tests.case_state_contract_20261020 import case_state

# Production admits this historical installer only through the RawV2 successor,
# which binds the drifted Function proposal sources to their exact reviewed epoch.
NAME = 'azure_function_settings_runtime_admission_20261020'


def install():
    return install_admission(NAME)


@pytest.mark.parametrize('check',range(2))
@pytest.mark.parametrize('branch',['pass','fail','unknown'])
def test_exact_native_capture_projection_has_decisive_and_unresolved_branches(check,branch):
    install()
    receipt=json.loads((Path(admission.__file__).parent/admission.RECEIPT).read_text())
    cases=json.loads(Path(receipt['fixture']['path']).read_text())
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


def test_second_registration_error_rolls_back_both_controls_and_cases(monkeypatch,isolated_registry):
    ids=isolated_registry;before=tuple(checks.CHECKS);cases=case_state(fixtures.CASES)
    original=checks.register;calls=[]
    def fail_second(*args,**kwargs):
        calls.append(args[0])
        if len(calls)==2:raise RuntimeError('injected second registration failure')
        return original(*args,**kwargs)
    monkeypatch.setattr(checks,'register',fail_second)
    with pytest.raises(RuntimeError,match='second registration'):install()
    assert len(calls)==2 and set(calls)==ids
    assert tuple(checks.CHECKS)==before and case_state(fixtures.CASES)==cases


def test_existing_conflicting_check_is_never_replaced(monkeypatch,isolated_registry):
    install()
    pos=next(i for i,c in enumerate(checks.CHECKS)if c.id==candidate.PROPOSALS[0]['id'])
    checks.CHECKS[pos]=replace(checks.CHECKS[pos],title='Conflicting reviewed contract')
    before=tuple(checks.CHECKS);cases=case_state(fixtures.CASES)
    with pytest.raises(RuntimeError,match='conflict'):install()
    assert tuple(checks.CHECKS)==before and case_state(fixtures.CASES)==cases


def test_conflicting_native_cases_are_not_silently_refreshed(monkeypatch,isolated_registry):
    cid=candidate.PROPOSALS[0]['id'];fixtures.CASES[cid]={'historical':'preserve'}
    before=tuple(checks.CHECKS)
    with pytest.raises(RuntimeError,match='CASES conflict'):install()
    assert tuple(checks.CHECKS)==before and fixtures.CASES[cid]=={'historical':'preserve'}


def test_runtime_helper_replacement_cannot_reuse_native_acceptance(monkeypatch,isolated_registry):
    before=tuple(checks.CHECKS)
    monkeypatch.setattr(current_candidate,'_evaluate',lambda *a:('PASS',{}))
    with pytest.raises((ValueError,RuntimeError)):install()
    assert tuple(checks.CHECKS)==before
