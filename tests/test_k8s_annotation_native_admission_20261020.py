"""Five actual registered successors: native HTTP, wrapper/source/admission guards."""
from copy import deepcopy
from dataclasses import replace
import hashlib
import importlib.util
import json
import sys
from pathlib import Path
import socket

import pytest
from kubernetes import config

from peaso import engine
import peaso.checks as registry
from tests.aws_k8s_current_native_inputs_20261020 import replace_registry_checks
from peaso.checks.fixtures import CASES
from peaso.checks import k8s_annotation_native_source_successor_20261021 as current_successor
admission = sys.modules[current_successor._PRIVATE_NAME]
assert admission.__file__ == str(current_successor.GUARD)
from peaso.checks import k8s_annotation_indicators_review_20261020 as candidate
from peaso.collectors import k8s
from peaso.collectors import k8s_annotation_indicators_20261020 as producer

_path = Path(__file__).with_name('test_k8s_annotation_psp_closure_20261020.py')
_spec = importlib.util.spec_from_file_location('prior_native_annotation_wire_fixtures', _path)
witness = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(witness)
CAPTURES = []
BASE_CASES = deepcopy({cid: CASES[cid] for cid in admission.IDS})


@pytest.fixture(autouse=True)
def offline(monkeypatch):
    def blocked(*args, **kwargs):
        pytest.fail('socket/DNS/live authentication forbidden')
    for name in ('connect', 'connect_ex'):
        monkeypatch.setattr(socket.socket, name, blocked)
    for name in ('getaddrinfo', 'gethostbyname', 'gethostbyname_ex', 'create_connection'):
        monkeypatch.setattr(socket, name, blocked)
    for name in ('load_kube_config', 'load_incluster_config', 'new_client_from_config'):
        monkeypatch.setattr(config, name, blocked)
    yield
    assert {cid: CASES[cid] for cid in admission.IDS} == BASE_CASES


@pytest.fixture(scope='session', autouse=True)
def receipts():
    yield
    import os
    if os.getenv('K8S_ANNOTATION_ADMISSION_RECEIPTS'):
        folder = Path(os.environ['K8S_ANNOTATION_ADMISSION_RECEIPTS']); folder.mkdir(parents=True, exist_ok=True)
        (folder / 'native-current-captures.json').write_text(json.dumps(CAPTURES, indent=2, sort_keys=True) + '\n')


def current(cid):
    return next(c for c in registry.CHECKS if c.id == cid)


def run_native(monkeypatch, cid, request, **kwargs):
    result = witness.execute(monkeypatch, cid, install=False, **kwargs)
    statuses, snapshot, pool, _ = result
    CAPTURES.append({'id': cid, 'node': request.node.nodeid, 'statuses': statuses,
        'http': deepcopy(pool.calls), 'snapshot': deepcopy(snapshot)})
    assert getattr(current(cid).evaluate, admission.MARK) == cid
    return result


@pytest.mark.parametrize('cid', admission.IDS)
@pytest.mark.parametrize('positive', [True, False])
def test_registered_native_pass_fail(monkeypatch, cid, positive, request):
    statuses, snapshot, _, _ = run_native(monkeypatch, cid, request, positive=positive)
    assert statuses == ['PASS' if positive else 'FAIL']
    report = engine.evaluate_snapshot(snapshot, checks=[cid])
    assert len(report['findings']) == 1
    evidence = report['findings'][0]['evidence']
    assert evidence['annotation_content_retained'] is False
    assert witness.CANARY not in json.dumps(report)


@pytest.mark.parametrize('cid', admission.IDS)
@pytest.mark.parametrize('mode', ['denied', 'partial', 'duplicate', 'http_partial', 'partial_representation'])
def test_registered_incomplete_native_unknown(monkeypatch, cid, mode, request):
    statuses, _, _, _ = run_native(monkeypatch, cid, request, mode=mode)
    assert statuses == ['DENIED' if mode == 'denied' else 'UNKNOWN']


@pytest.mark.parametrize('cid', admission.IDS)
@pytest.mark.parametrize('field', ['schema', 'flags', 'source', 'uid', 'context', 'scope'])
def test_registered_bound_projection_tamper_unknown(monkeypatch, cid, field, request):
    def change(snapshot):
        kind = current(cid).kind
        collection = next(c for c in snapshot['collections'] if c['type'] == kind)
        item = collection['items'][0]
        if field == 'schema': item[producer.MARKER]['schema'] = 'unreviewed'
        if field == 'flags': item[producer.MARKER]['flags']['snippet'] = 'false'
        if field == 'source': item[producer.MARKER]['source']['path'] += '/foreign'
        if field == 'uid': item['metadata']['uid'] = 'foreign-native-identity'
        if field == 'context': snapshot['metadata'][producer.CONTEXT]['session'] = '0' * 32
        if field == 'scope': item[producer.MARKER]['source']['scope'] = 'foreign-scope'
    statuses, _, _, _ = run_native(monkeypatch, cid, request, change_snapshot=change)
    assert statuses == ['UNKNOWN']


@pytest.mark.parametrize('cid', candidate.PSP_IDS)
def test_registered_modern_psp_not_applicable_no_legacy_reads(monkeypatch, cid, request):
    statuses, _, pool, _ = run_native(monkeypatch, cid, request, modern=True)
    assert statuses == ['NOT_APPLICABLE']
    assert len(pool.calls) == 2
    assert all('podsecuritypolicies' not in json.dumps(c) for c in pool.calls)


@pytest.mark.parametrize('cid', admission.IDS)
def test_managed_applicability_wrapper_preserved(monkeypatch, cid, request):
    def managed(doc):
        doc['metadata']['labels'] = {'addonmanager.kubernetes.io/mode': 'Reconcile'}
    statuses, snapshot, _, _ = run_native(monkeypatch, cid, request, positive=False, mutate=managed)
    assert statuses == ['NOT_APPLICABLE']
    finding, = engine.evaluate_snapshot(snapshot, checks=[cid])['findings']
    assert finding['evidence']['provider_managed'] is True


@pytest.mark.parametrize('cid', admission.IDS)
def test_old_annotations_complete_fixture_not_native_proof(cid):
    old = deepcopy(CASES[cid]['pass'])
    assert current(cid).evaluate(old, deepcopy(CASES[cid].get('pass_index', {})))[0] == 'UNKNOWN'
    assert current(cid).evaluate({}, {})[0] == 'UNKNOWN'


@pytest.mark.parametrize('cid', admission.IDS)
@pytest.mark.parametrize('tag,expected', [('pass', 'PASS'), ('fail', 'FAIL'), ('unknown', 'UNKNOWN')])
def test_current_test_only_native_overlay(cid, tag, expected):
    _, cases = admission._reviewed_inputs()
    assert current(cid).evaluate(deepcopy(cases[cid][tag]), deepcopy(cases[cid][tag + '_index']))[0] == expected


def test_same_ids_exact_metadata_wrappers_and_historical_cases():
    receipt, _ = admission._reviewed_inputs()
    assert set(admission._PREDECESSORS) == set(admission.IDS)
    for cid in admission.IDS:
        old = admission._PREDECESSORS[cid]; new = current(cid)
        assert admission._metadata(old) == admission._metadata(new)
        original_layers = admission._layers(old); new_layers = admission._layers(new)
        assert all(a.__code__ is b.__code__ for a, b in zip(original_layers[:3], new_layers[:3]))
        assert new_layers[0].__wrapped__ is new_layers[2]
        assert admission._bindings(new_layers[-1]) == {'check_id': cid}
        assert admission._hash(json.dumps(CASES[cid], sort_keys=True)) == receipt['historical_case_sha256'][cid]


def test_idempotence_accepts_fresh_factory_closures_without_replacing_checks():
    first, second = candidate.evaluate_for(admission.IDS[0]), candidate.evaluate_for(admission.IDS[0])
    assert first is not second and admission._function(first) == admission._function(second)
    before = tuple(registry.CHECKS)
    admission.install(); admission.install()
    assert all(a is b for a, b in zip(before, registry.CHECKS))


def predecessors(monkeypatch):
    replace_registry_checks(monkeypatch, [admission._PREDECESSORS.get(c.id, c) for c in registry.CHECKS])
    return tuple(registry.CHECKS)


@pytest.mark.parametrize('cid', admission.IDS)
def test_wrong_successor_check_id_closure_rejected_without_mutation(monkeypatch, cid):
    old = current(cid); wrong_id = next(i for i in admission.IDS if i != cid)
    leaf = admission._layers(old)[-1]
    replacement = admission._clone(old.evaluate, leaf, candidate.evaluate_for(wrong_id), {})
    setattr(replacement, admission.MARK, cid)
    bad = replace(old, evaluate=replacement)
    replace_registry_checks(monkeypatch, [bad if c.id == cid else c for c in registry.CHECKS])
    before = tuple(registry.CHECKS)
    with pytest.raises(RuntimeError, match='closure|wrappers'):
        admission.install()
    assert tuple(registry.CHECKS) == before


@pytest.mark.parametrize('cid', admission.IDS)
def test_predecessor_wrapper_drift_rejected_without_mutation(monkeypatch, cid):
    predecessors(monkeypatch)
    def forged(item, index): return 'PASS', {}
    replace_registry_checks(monkeypatch, [replace(c, evaluate=forged) if c.id == cid else c for c in registry.CHECKS])
    before = tuple(registry.CHECKS)
    with pytest.raises(RuntimeError, match='predecessor changed'):
        admission.install()
    assert tuple(registry.CHECKS) == before


def test_stage_failure_rolls_back_all_five_and_originals(monkeypatch):
    before = predecessors(monkeypatch); originals = dict(admission._PREDECESSORS); actual = admission._successor; calls = []
    def fail_third(check, module):
        calls.append(check.id)
        if len(calls) == 3: raise RuntimeError('injected staged failure')
        return actual(check, module)
    monkeypatch.setattr(admission, '_successor', fail_third)
    with pytest.raises(RuntimeError, match='injected staged failure'):
        admission.install()
    assert len(calls) == 3 and all(a is b for a, b in zip(before, registry.CHECKS))
    assert admission._PREDECESSORS == originals


def test_commit_failure_rolls_back_registry_and_originals(monkeypatch):
    before = predecessors(monkeypatch); originals = dict(admission._PREDECESSORS)
    class ThrowOnce(list):
        fired = False
        def __setitem__(self, key, value):
            if isinstance(key, slice) and not self.fired:
                self.fired = True; super().__setitem__(key, value)
                raise RuntimeError('injected commit failure')
            return super().__setitem__(key, value)
    replace_registry_checks(monkeypatch, ThrowOnce(before))
    with pytest.raises(RuntimeError, match='injected commit failure'):
        admission.install()
    assert all(a is b for a, b in zip(before, registry.CHECKS)) and admission._PREDECESSORS == originals


@pytest.mark.parametrize('path', admission.SOURCE_PATHS)
def test_exact_reviewed_source_drift_rejected(monkeypatch, path):
    actual = Path.read_bytes
    def drift(p):
        raw = actual(p)
        if str(p).endswith(path):
            if path == 'peaso/collectors/k8s.py':
                return raw.replace(b'def _sanitize(value):', b'def _sanitize(value):\n    # unreviewed owned source', 1)
            return raw + b'\n# unreviewed source'
        return raw
    monkeypatch.setattr(Path, 'read_bytes', drift)
    before = tuple(registry.CHECKS)
    with pytest.raises(RuntimeError, match='source changed'):
        admission.install()
    assert tuple(registry.CHECKS) == before


def test_new_evaluator_in_memory_drift_rejected(monkeypatch):
    monkeypatch.setattr(candidate, 'evaluate', lambda *args: ('PASS', {}))
    with pytest.raises(RuntimeError, match='callable changed'):
        admission.install()


def test_schema_drift_rejected(monkeypatch):
    monkeypatch.setattr(producer, 'SCHEMA', 'unreviewed-schema')
    with pytest.raises(RuntimeError, match='schema changed'):
        admission.install()


def test_fixture_byte_drift_rejected(monkeypatch):
    actual = Path.read_bytes
    def drift(p):
        raw = actual(p)
        return raw + b' ' if p.name == 'k8s_annotation_native_current_fixtures_20261020.json' else raw
    monkeypatch.setattr(Path, 'read_bytes', drift)
    with pytest.raises(RuntimeError, match='fixtures changed'):
        admission.install()


@pytest.mark.parametrize('field', ['schema_version', 'ids', 'sources', 'callables', 'schema', 'predecessors', 'python_bytecode'])
def test_malformed_receipt_rejected(monkeypatch, field):
    receipt, _ = admission._reviewed_inputs(); receipt.pop(field)
    actual = Path.read_text
    def malformed(p, *args, **kwargs):
        return json.dumps(receipt) if p.name == 'k8s_annotation_native_admission_20261020.json' else actual(p, *args, **kwargs)
    monkeypatch.setattr(Path, 'read_text', malformed)
    with pytest.raises(RuntimeError, match='admission receipt'):
        admission.install()


def test_native_preflight_failure_leaves_registry_untouched(monkeypatch):
    before = predecessors(monkeypatch); receipt, cases = admission._reviewed_inputs()
    cases[admission.IDS[2]]['pass']['metadata']['uid'] = 'foreign'
    monkeypatch.setattr(admission, '_reviewed_inputs', lambda: (receipt, cases))
    with pytest.raises(RuntimeError, match='witness failed'):
        admission.install()
    assert all(a is b for a, b in zip(before, registry.CHECKS))
