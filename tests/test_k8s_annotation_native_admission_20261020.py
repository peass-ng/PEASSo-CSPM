"""Five registered annotation successors evaluated against native HTTP captures."""
from copy import deepcopy
import importlib.util
import json
from pathlib import Path
import socket

import pytest
from kubernetes import config

from peaso import engine
import peaso.checks as registry
from tests.generic_k8s_behavior_successors_20261020 import annotation_native_cases
from peaso.checks.fixtures import CASES
from peaso.checks import k8s_annotation_native_admission_20261020 as admission
from peaso.checks import k8s_annotation_indicators_review_20261020 as candidate
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
    cases = annotation_native_cases()
    assert current(cid).evaluate(deepcopy(cases[cid][tag]), deepcopy(cases[cid][tag + '_index']))[0] == expected
