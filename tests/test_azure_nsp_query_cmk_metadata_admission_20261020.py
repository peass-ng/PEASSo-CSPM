"""Uninstalled two-control admission: native branches, tamper and rollback."""
from copy import deepcopy
from tests.shared_admission_epoch_compatibility_20261020 import snapshot_cases
import socket

import pytest
from peaso import checks
from peaso.checks import fixtures
from peaso.checks import azure_nsp_query_cmk_metadata_admission_20261020 as admission
from peaso.checks import azure_nsp_query_cmk_metadata_proposal_20261020 as candidate
from peaso.collectors import azure
from peaso.collectors import azure_nsp_query_cmk_metadata_proposal_20261020 as producer
from tests.test_azure_nsp_query_cmk_metadata_proposal_20261020 import NativeHTTP, capture, nsp_mode, query_mode
from tests.shared_admission_epoch_compatibility_20261020 import snapshot_cases, active_shared, source_at_epoch, sealed_ast
from dataclasses import replace


@pytest.fixture(autouse=True)
def offline_isolated_registry(monkeypatch):
    def blocked(*args, **kwargs):
        raise AssertionError('network, DNS and authentication forbidden')
    for owner, names in ((socket, ('create_connection', 'getaddrinfo', 'gethostbyname', 'gethostbyname_ex')),
                         (socket.socket, ('connect', 'connect_ex', 'sendto')), (azure, ('credential_for',))):
        for name in names:
            monkeypatch.setattr(owner, name, blocked)
    registry, case_store = checks.CHECKS, fixtures.CASES
    before = list(registry)
    old_cases = {cid: deepcopy(case_store[cid]) for cid in admission.IDS if cid in case_store}
    old_installed = dict(admission._INSTALLED)
    registry[:] = [c for c in registry if c.id not in admission.IDS]
    for cid in admission.IDS: case_store.pop(cid, None)
    admission._INSTALLED.clear()
    yield
    registry[:] = before
    checks.CHECKS = registry
    fixtures.CASES = case_store
    admission._INSTALLED.clear();admission._INSTALLED.update(old_installed)
    for cid in admission.IDS:
        if cid in old_cases: case_store[cid] = old_cases[cid]
        else: case_store.pop(cid, None)


@pytest.mark.parametrize('kind,mode,want', [
    (producer.NSP_KIND, 'enforced', 'PASS'), (producer.NSP_KIND, 'learning', 'FAIL'),
    (producer.NSP_KIND, 'transition', 'UNKNOWN'), (producer.NSP_KIND, 'profile_denied', 'DENIED'),
    (producer.NSP_KIND, 'association_partial', 'UNKNOWN'),
    (producer.QUERY_KIND, 'cmk', 'PASS'), (producer.QUERY_KIND, 'provider', 'FAIL'),
    (producer.QUERY_KIND, 'table_key_missing', 'UNKNOWN'), (producer.QUERY_KIND, 'no_links', 'NOT_APPLICABLE'),
    (producer.QUERY_KIND, 'denied_storage', 'DENIED'), (producer.QUERY_KIND, 'partial_links', 'UNKNOWN'),
    (producer.QUERY_KIND, 'table_service_key', 'FAIL'),
])
def test_explicit_atomic_install_actual_http_to_public_engine(monkeypatch, kind, mode, want):
    admission.install()
    http = NativeHTTP();(nsp_mode if kind == producer.NSP_KIND else query_mode)(http, mode)
    actual, _, findings = capture(monkeypatch, http, kind)
    assert actual == {want}, findings


def test_install_twice_is_atomic_and_idempotent():
    before = tuple(checks.CHECKS)
    admission.install();installed = tuple(checks.CHECKS)
    admission.install()
    assert tuple(checks.CHECKS) == installed and installed[:len(before)] == before
    assert [c.id for c in installed[len(before):]] == list(admission.IDS)
    assert set(admission._INSTALLED) == set(admission.IDS)


@pytest.mark.parametrize('target', ['predicate', 'strict_request', 'reader'])
def test_same_function_in_memory_code_replacement_rejected(monkeypatch, target):
    function = {'predicate': candidate.nsp, 'strict_request': producer.metadata_get, 'reader': azure._Reader.call}[target]
    changed = function.__code__.replace(co_consts=tuple('tampered_constant' if value is None else value for value in function.__code__.co_consts))
    monkeypatch.setattr(function, '__code__', changed)
    with pytest.raises(RuntimeError, match='executing code'): admission.reviewed_inputs()


@pytest.mark.parametrize('which', ['alias', 'partial_check', 'duplicate_check', 'cases', 'kind_endpoint'])
def test_registration_namespace_collision_rejected_without_changes(monkeypatch, which):
    if which == 'alias': monkeypatch.setitem(checks.CHECK_ALIASES, admission.IDS[0], 'existing.survivor')
    if which in ('partial_check', 'duplicate_check'):
        admission.install()
        if which == 'partial_check': checks.CHECKS[:] = [c for c in checks.CHECKS if c.id != admission.IDS[1]]
        else: checks.CHECKS.append(next(c for c in checks.CHECKS if c.id == admission.IDS[0]))
    if which == 'cases': fixtures.CASES[admission.IDS[0]] = {'unreviewed': True}
    if which == 'kind_endpoint': monkeypatch.setitem(azure.ENDPOINTS, producer.NSP_KIND, ('Microsoft.Example/items', '2026-01-01'))
    before = tuple(checks.CHECKS);old = deepcopy({cid: fixtures.CASES[cid] for cid in admission.IDS if cid in fixtures.CASES})
    with pytest.raises(RuntimeError, match='collision'): admission.install()
    assert tuple(checks.CHECKS) == before
    assert {cid: fixtures.CASES[cid] for cid in admission.IDS if cid in fixtures.CASES} == old


@pytest.mark.parametrize('stage', ['second_registration', 'second_fixture_write'])
def test_second_control_failure_rolls_back_both_checks_and_cases(monkeypatch, stage):
    before = tuple(checks.CHECKS);old = snapshot_cases(fixtures.CASES)
    if stage == 'second_registration':
        class FailSecondAppend(list):
            def append(self, item):
                if item.id == admission.IDS[1]: raise RuntimeError('injected second registration failure')
                return super().append(item)
        monkeypatch.setattr(checks, 'CHECKS', FailSecondAppend(checks.CHECKS))
    else:
        class FailSecondWrite(dict):
            def __setitem__(self, key, value):
                if key == admission.IDS[1]: raise RuntimeError('injected second fixture failure')
                return super().__setitem__(key, value)
        monkeypatch.setattr(fixtures, 'CASES', FailSecondWrite(fixtures.CASES))
    with pytest.raises(RuntimeError, match='injected second'): admission.install()
    assert tuple(checks.CHECKS) == before and fixtures.CASES == old
    assert admission._INSTALLED == {}


def test_later_dedicated_kind_additions_are_compatible(monkeypatch):
    monkeypatch.setattr(azure, 'TYPES', tuple(kind for kind in azure.TYPES if kind not in producer.KINDS) + producer.KINDS)
    admission.install();admission.install()
    assert all(sum(c.id == cid for c in checks.CHECKS) == 1 for cid in admission.IDS)


def test_duplicate_dedicated_kind_rejected(monkeypatch):
    monkeypatch.setattr(azure, 'TYPES', tuple(azure.TYPES) + (producer.NSP_KIND,) * 2)
    with pytest.raises(RuntimeError, match='kind collision'): admission.install()


