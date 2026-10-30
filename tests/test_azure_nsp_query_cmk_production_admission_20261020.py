"""Production source/callable/collision/rollback gates; no live authentication."""
import types

import pytest
from peaso import checks
from peaso.checks import fixtures
from peaso.checks import azure_nsp_query_cmk_production_tde_successor_20261020 as admission
from peaso.collectors import azure


def isolate(monkeypatch):
    monkeypatch.setattr(checks, 'CHECKS', [c for c in checks.CHECKS if c.id not in admission.IDS])
    monkeypatch.setattr(fixtures, 'CASES', {key: value for key, value in fixtures.CASES.items() if key not in admission.IDS})
    monkeypatch.setattr(admission, '_INSTALLED', {})


def test_installed_exactly_once_and_idempotent():
    before = tuple(checks.CHECKS)
    receipt, cases, declarations = admission.reviewed_inputs()
    admission.install();admission.install()
    assert tuple(checks.CHECKS) == before
    for spec, function in declarations:
        rows = [c for c in checks.CHECKS if c.id == spec['id']]
        assert len(rows) == 1 and rows[0].evaluate.__wrapped__ is function
        assert rows[0].dependencies == [spec['kind'], 'subscription']
        assert fixtures.CASES[spec['id']] == cases[spec['id']]
        assert admission.proof._metadata(rows[0]) == receipt['metadata'][spec['id']]


@pytest.mark.parametrize('stage', ['second_registration', 'second_fixture'])
def test_second_failure_rolls_back_checks_cases_and_admission(monkeypatch, stage):
    isolate(monkeypatch)
    before = tuple(checks.CHECKS);before_cases = dict(fixtures.CASES)
    if stage == 'second_registration':
        class FailingList(list):
            def append(self, value):
                if value.id == admission.IDS[1]: raise RuntimeError('injected second registration')
                super().append(value)
        monkeypatch.setattr(checks, 'CHECKS', FailingList(checks.CHECKS))
    else:
        class FailingCases(dict):
            def __setitem__(self, key, value):
                if key == admission.IDS[1]: raise RuntimeError('injected second fixture')
                super().__setitem__(key, value)
        monkeypatch.setattr(fixtures, 'CASES', FailingCases(fixtures.CASES))
    with pytest.raises(RuntimeError, match='injected second'): admission.install()
    assert tuple(checks.CHECKS) == before and fixtures.CASES == before_cases and admission._INSTALLED == {}


@pytest.mark.parametrize('which', ['partial_check', 'duplicate_check', 'cases', 'alias', 'kind', 'endpoint'])
def test_namespace_collision_is_not_replaced(monkeypatch, which):
    installed = next(c for c in checks.CHECKS if c.id == admission.IDS[0])
    isolate(monkeypatch)
    if which == 'partial_check': checks.CHECKS.append(installed)
    if which == 'duplicate_check': checks.CHECKS.extend([installed, installed])
    if which == 'cases': fixtures.CASES[admission.IDS[0]] = {'original': 'preserve'}
    if which == 'alias': monkeypatch.setattr(checks, 'CHECK_ALIASES', {**checks.CHECK_ALIASES, 'unrelated': admission.IDS[0]})
    if which == 'kind': monkeypatch.setattr(azure, 'TYPES', azure.TYPES + (admission.producer.KINDS[0],))
    if which == 'endpoint': monkeypatch.setitem(azure.ENDPOINTS, admission.producer.KINDS[0], ('Microsoft.Network', 'unreviewed'))
    before = tuple(checks.CHECKS);old_cases = dict(fixtures.CASES)
    with pytest.raises(RuntimeError): admission.install()
    assert tuple(checks.CHECKS) == before and fixtures.CASES == old_cases




