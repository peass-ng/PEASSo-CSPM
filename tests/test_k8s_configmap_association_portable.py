"""Focused native association tests; no live Kubernetes access."""
from copy import deepcopy
from pathlib import Path
import json
import os
import socket
import subprocess
import sys
import time

import pytest
from kubernetes.client import ApiClient, Configuration
from peaso import collectors, secret_scanning, checks
from peaso.collectors import k8s
from peaso.checks import k8s_literal_secret_review_20261020 as predicate
from tests import test_k8s_literal_secret_review_20261020 as native_test

from peaso.collectors import k8s_literal_configmap_association as source
from peaso.checks import k8s_literal_configmap_association_evaluator as evaluator
TOKEN = native_test.TOKEN


@pytest.fixture(autouse=True)
def offline(monkeypatch):
    def blocked(*args, **kwargs):
        pytest.fail('live network and cloud auth forbidden')
    for owner, names in ((socket, ('create_connection', 'getaddrinfo')),
                         (socket.socket, ('connect', 'connect_ex', 'sendto'))):
        for name in names:
            monkeypatch.setattr(owner, name, blocked)
    secret_scanning._RESULTS.clear()
    yield
    secret_scanning._RESULTS.clear()


def target(kind='Pod'):
    return {'cluster_id': native_test.CLUSTER, 'namespace': native_test.NS,
            'kind': kind, 'name': 'review-pod'}


def workload(kind='Pod'):
    t = target(kind)
    doc = {'apiVersion': source.NATIVE_KINDS[kind][0], 'kind': kind,
        'metadata': {'name': t['name'], 'namespace': t['namespace'],
            'uid': 'workload-uid', 'resourceVersion': '12'}}
    template = {'metadata': {'labels': {'app': 'review'}},
        'spec': {'containers': [{'name': 'main', 'image': 'example.invalid/fixture:1'}]}}
    if kind == 'Pod':
        doc['spec'] = template['spec']
    elif kind == 'PodTemplate':
        doc['template'] = template
    elif kind == 'CronJob':
        doc['spec'] = {'jobTemplate': {'spec': {'template': template}}}
    else:
        doc['spec'] = {'template': template}
    return t, doc


def podspec(doc, kind):
    value = doc
    for field in source.NATIVE_KINDS[kind][2]:
        value = value[field]
    return value


def configmap(name='settings', *, value=TOKEN, namespace=native_test.NS, version='4'):
    return {'apiVersion': 'v1', 'kind': 'ConfigMap',
        'metadata': {'name': name, 'namespace': namespace, 'uid': 'cm-uid', 'resourceVersion': version},
        'data': {'ACCESS_TOKEN': value, 'OTHER': 'ordinary'}}


def reference(doc, kind='Pod', mode='envFrom', *, optional=False):
    spec = podspec(doc, kind)
    container = spec['containers'][0]
    ref = {'name': 'settings', 'optional': optional}
    if mode == 'envFrom':
        container['envFrom'] = [{'configMapRef': ref}]
    elif mode == 'keyRef':
        container['env'] = [{'name': 'TOKEN', 'valueFrom': {'configMapKeyRef': {**ref, 'key': 'ACCESS_TOKEN'}}}]
    elif mode == 'volume':
        spec['volumes'] = [{'name': 'mounted', 'configMap': {**ref, 'items': [{'key': 'ACCESS_TOKEN', 'path': 'token'}]}}]
    elif mode == 'projected':
        spec['volumes'] = [{'name': 'mounted', 'projected': {'sources': [
            {'configMap': {**ref, 'items': [{'key': 'ACCESS_TOKEN', 'path': 'token'}]}}]}}]


@pytest.mark.parametrize('kind', [k for k in source.NATIVE_KINDS if k != 'ConfigMap'])
@pytest.mark.parametrize('mode', ('envFrom', 'keyRef', 'volume', 'projected'))
def test_exact_workload_reference_paths(kind, mode):
    t, doc = workload(kind)
    reference(doc, kind, mode)
    plan = source._plan(doc, t)
    assert len(plan) == 1 and plan[0][0] == 'settings'
    assert plan[0][3] == ('env' if mode in ('envFrom', 'keyRef') else 'volume')
    assert plan[0][1] == (None if mode == 'envFrom' else ('ACCESS_TOKEN',))


def test_optional_missing_key_and_required_missing_key():
    t, doc = workload()
    reference(doc, optional=True, mode='keyRef')
    plan = source._plan(doc, t)
    cm = configmap(value='ordinary')
    cm['data'].pop('ACCESS_TOKEN')
    values, count = source._project(cm, source._cm_target(t, 'settings'), plan)
    assert count == 0 and values == ['settings', 'cm-uid', '4']
    reference(doc, optional=False, mode='keyRef')
    with pytest.raises(source.Incomplete, match='required_configmap_key_missing'):
        source._project(cm, source._cm_target(t, 'settings'), source._plan(doc, t))


@pytest.mark.parametrize('fault', ('foreign', 'deleted', 'duplicate', 'too_many', 'oversize'))
def test_rejects_foreign_duplicate_and_bounded_inputs(fault):
    t, doc = workload()
    reference(doc, mode='volume')
    cm = configmap()
    if fault == 'foreign':
        cm['metadata']['namespace'] = 'other-team'
    elif fault == 'deleted':
        cm['metadata']['deletionTimestamp'] = '2026-10-21T00:00:00Z'
    elif fault == 'duplicate':
        doc['spec']['volumes'].append(deepcopy(doc['spec']['volumes'][0]))
    elif fault == 'too_many':
        doc['spec']['volumes'] = [{'name': f'v{i}', 'configMap': {'name': f'cm{i}'}}
                                   for i in range(source.MAX_CONFIGMAPS + 1)]
    else:
        cm['data']['ACCESS_TOKEN'] = 'x' * (source.base.MAX_VALUE + 1)
    with pytest.raises(source.Incomplete):
        if fault in ('duplicate', 'too_many'):
            source._plan(doc, t)
        else:
            source._project(cm, source._cm_target(t, 'settings'), source._plan(doc, t))


def test_configmap_version_drift_changes_bound_extraction():
    t, doc = workload()
    reference(doc, mode='keyRef')
    plan = source._plan(doc, t)
    first = source.AssociatedDoc(doc)
    first.associations = (plan, (('settings', configmap(version='4'), 200),))
    second = source.AssociatedDoc(doc)
    second.associations = (plan, (('settings', configmap(version='5'), 200),))
    assert source._extract(first, t) != source._extract(second, t)


def test_duplicate_association_identity_and_foreign_reference_rejected():
    t, doc = workload()
    reference(doc, mode='keyRef')
    plan = source._plan(doc, t)
    bound = source.AssociatedDoc(doc)
    bound.associations = (plan, (('settings', configmap(), 200), ('settings', configmap(), 200)))
    with pytest.raises(source.Incomplete, match='association_identity_unresolved'):
        source._extract(bound, t)
    doc['spec']['containers'][0]['env'][0]['valueFrom']['configMapKeyRef']['namespace'] = 'foreign'
    with pytest.raises(source.Incomplete, match='malformed_configmap_reference'):
        source._plan(doc, t)


@pytest.mark.parametrize('mode', ('envFrom', 'keyRef', 'volume', 'projected'))
def test_exact_native_get_pipeline_positive_and_clean_decisive(monkeypatch, mode):
    t = native_test.target()
    doc = native_test.native(t, value='ready = true')
    reference(doc, mode=mode)
    cm_target = source._cm_target(t, 'settings')
    path = source._path(cm_target)
    for value, expected in ((TOKEN, 'FAIL'), ('ordinary', 'PASS')):
        cm = configmap(value=value)
        snapshot, trace = native_test.capture(monkeypatch, targets=[t],
            documents={native_test.route(t): doc}, extra_documents={path: cm})
        finding = native_test.findings(snapshot)[0]
        assert finding['status'] == expected
        assert evaluator.evaluate(*native_test.item_index(snapshot))[0] == expected
        assert len(trace.calls) == 4 and [call[2] for call in trace.calls] == [native_test.route(t), path] * 2
        assert all(r.closed and r.released for r in trace.responses)
        assert TOKEN not in json.dumps(snapshot)
        assert trace.api.api_client.rest_client.pool_manager.literal_paths == frozenset()


@pytest.mark.parametrize('field', (
    'plan_binding', 'selection_binding', 'version_binding', 'request', 'identity',
    'scope_binding', 'cluster_binding', 'map_binding', 'path_binding', 'optional',
    'workload_uid_binding', 'workload_version_binding', 'status', 'bytes', 'ordinal',
    'reference_count', 'literal_count', 'source_requests', 'seal'))
def test_public_association_tamper_is_unknown(monkeypatch, field):
    t = native_test.target()
    doc = native_test.native(t, value='ready = true')
    reference(doc, mode='keyRef')
    cm_path = source._path(source._cm_target(t, 'settings'))
    snapshot, _ = native_test.capture(monkeypatch, targets=[t],
        documents={native_test.route(t): doc}, extra_documents={cm_path: configmap(value='ordinary')})
    item, index = native_test.item_index(snapshot)
    assert evaluator.evaluate(item, index)[0] == 'PASS'
    item, index = deepcopy(item), deepcopy(index)
    own = index['collections'][source.KIND][0]
    own['items'][0] = item
    association = item[source.MARKER]['association']
    receipts = index['context']['metadata'][source.KIND + '_configmap_receipts']
    receipt = receipts[0]
    if field == 'request':
        association['maps'][0]['requests'][0] = 'k8s-configmap-read-999'
    elif field == 'plan_binding':
        association['plan_binding'] = '0' * 64
    elif field == 'selection_binding':
        association['maps'][0]['selection_binding'] = '0' * 64
    elif field in ('identity', 'scope_binding', 'cluster_binding', 'map_binding',
                   'path_binding', 'optional', 'workload_uid_binding',
                   'workload_version_binding', 'status', 'bytes', 'ordinal'):
        receipt[field] = (True if field == 'optional' else 403 if field == 'status'
                          else 0 if field in ('bytes', 'ordinal') else '0' * 64)
        receipt['seal'] = evaluator._seal({k: v for k, v in receipt.items() if k != 'seal'})
    elif field == 'version_binding':
        receipt['version_binding'] = '0' * 64
        receipt['seal'] = evaluator._seal({k: v for k, v in receipt.items() if k != 'seal'})
    elif field in ('reference_count', 'literal_count'):
        item[source.MARKER][field] += 1
    elif field == 'source_requests':
        item[source.MARKER][field][0] = 'k8s-literal-read-999'
    else:
        receipt['seal'] = '0' * 64
    assert evaluator.evaluate(item, index)[0] == 'UNKNOWN'


def test_no_reference_configmap_branch_preserved(monkeypatch):
    t = native_test.target('ConfigMap', 'review-map')
    doc = native_test.native(t, value='ordinary')
    snapshot, _ = native_test.capture(monkeypatch, targets=[t],
        documents={native_test.route(t): doc})
    item, index = native_test.item_index(snapshot)
    assert 'association' not in item[source.MARKER]
    assert evaluator.evaluate(item, index)[0] == predicate.evaluate(item, index)[0] == 'PASS'


def test_stripped_association_cannot_fall_back_to_legacy_pass(monkeypatch):
    t = native_test.target()
    doc = native_test.native(t, value='ready = true')
    reference(doc, mode='keyRef')
    cm_path = source._path(source._cm_target(t, 'settings'))
    snapshot, _ = native_test.capture(monkeypatch, targets=[t],
        documents={native_test.route(t): doc}, extra_documents={cm_path: configmap(value='ordinary')})
    item, index = native_test.item_index(snapshot)
    item, index = deepcopy(item), deepcopy(index)
    index['collections'][source.KIND][0]['items'][0] = item
    del item[source.MARKER]['association']
    assert evaluator.evaluate(item, index)[0] == 'UNKNOWN'


@pytest.mark.parametrize('second_present', (False, True))
def test_optional_404_is_decisive_only_when_consistent(monkeypatch, second_present):
    t = native_test.target()
    doc = native_test.native(t, value='ready = true')
    reference(doc, mode='keyRef', optional=True)
    calls = []
    def optional_read(reader, api, target, state, *, optional):
        assert optional
        calls.append(1)
        return (configmap(value='ordinary'), 200) if second_present and len(calls) == 2 else (None, 0)
    monkeypatch.setattr(source, '_read_cm', optional_read)
    snapshot, trace = native_test.capture(monkeypatch, targets=[t],
        documents={native_test.route(t): doc})
    assert native_test.findings(snapshot)[0]['status'] == ('UNKNOWN' if second_present else 'PASS')
    assert len(calls) == 2 and len(trace.calls) == 2
    if second_present:
        assert not trace.scans


def test_json_snapshot_pass_and_fail_in_fresh_process_with_different_hmac_key(monkeypatch):
    t = native_test.target()
    doc = native_test.native(t, value='ready = true')
    reference(doc, mode='keyRef')
    path = source._path(source._cm_target(t, 'settings'))
    snapshots = []
    for value in (TOKEN, 'ordinary'):
        snapshot, _ = native_test.capture(monkeypatch, targets=[t],
            documents={native_test.route(t): doc}, extra_documents={path: configmap(value=value)})
        snapshots.append(snapshot)
    # The child imports secret_scanning afresh, so its HMAC key is unrelated
    # to the collector's key. Only public derived proof seals are recomputed.
    script = '''import json,socket,sys
from peaso import checks,engine,secret_scanning
from peaso.collectors import k8s_literal_secret_indicators as base
socket.create_connection=lambda *a,**k: (_ for _ in ()).throw(AssertionError("network forbidden"))
snapshots=json.load(sys.stdin)
statuses=[[f["status"] for f in engine.evaluate_snapshot(s,checks=[base.CHECK])["findings"]] for s in snapshots]
print(json.dumps({"statuses":statuses,"key_canary":secret_scanning._fingerprint("cross-process-canary")}))
'''
    repo = Path(__file__).resolve().parents[1]
    # The child measures the shipped evaluation path. The suite-wide
    # PEASO_SOURCE_ATTESTATION=always re-proves every source on a cold import
    # (minutes of CPU), which is not what this cross-process HMAC check tests.
    env = {k: v for k, v in os.environ.items() if k != 'PEASO_SOURCE_ATTESTATION'}
    child = subprocess.run([sys.executable, '-I', '-c', 'import sys;sys.path.insert(0,' + repr(str(repo)) + ');' + script],
        input=json.dumps(snapshots), text=True, capture_output=True, timeout=120,
        cwd=repo, env={**env, 'PYTHONDONTWRITEBYTECODE': '1'})
    assert child.returncode == 0, child.stderr
    result = json.loads(child.stdout)
    assert result['key_canary'] != secret_scanning._fingerprint('cross-process-canary')
    assert result['statuses'] == [['FAIL'], ['PASS']]


def test_missing_required_key_never_clean(monkeypatch):
    t = native_test.target()
    doc = native_test.native(t, value='ready = true')
    reference(doc, mode='keyRef')
    cm_target = source._cm_target(t, 'settings')
    cm = configmap()
    cm['data'].pop('ACCESS_TOKEN')
    snapshot, trace = native_test.capture(monkeypatch, targets=[t],
        documents={native_test.route(t): doc}, extra_documents={source._path(cm_target): cm})
    assert native_test.findings(snapshot)[0]['status'] == 'UNKNOWN'
    assert len(trace.calls) == 2 and not trace.scans


def test_real_offline_detectors_keep_workload_association(monkeypatch):
    t = native_test.target()
    doc = native_test.native(t, value='ready = true')
    reference(doc, mode='keyRef')
    path = source._path(source._cm_target(t, 'settings'))
    snapshot, trace = native_test.capture(monkeypatch, targets=[t],
        documents={native_test.route(t): doc}, extra_documents={path: configmap()}, real=True)
    assert native_test.findings(snapshot)[0]['status'] == 'FAIL'
    status, evidence = evaluator.evaluate(*native_test.item_index(snapshot))
    assert status == 'FAIL' and evidence['complete'] is True
    assert {d['engine'] for d in evidence['secret_leaks'][0]['detectors']} == {'kingfisher', 'trufflehog'}
    assert len(trace.calls) == 4 and TOKEN not in json.dumps(snapshot)


@pytest.mark.parametrize('change', ('version', 'content'))
def test_between_reads_configmap_drift_never_scans(monkeypatch, change):
    t = native_test.target()
    doc = native_test.native(t, value='ready = true')
    reference(doc, mode='keyRef')
    calls = []
    def changed_cm(reader, api, target, state, *, optional):
        calls.append(1)
        cm = configmap(value='ordinary')
        if len(calls) == 2:
            if change == 'version':
                cm['metadata']['resourceVersion'] = '5'
            else:
                cm['data']['ACCESS_TOKEN'] = 'changed'
        return cm, 200
    monkeypatch.setattr(source, '_read_cm', changed_cm)
    snapshot, trace = native_test.capture(monkeypatch, targets=[t],
        documents={native_test.route(t): doc})
    assert native_test.findings(snapshot)[0]['status'] == 'UNKNOWN'
    assert len(calls) == 2 and len(trace.calls) == 2 and not trace.scans


def test_optional_missing_object_uses_exact_404_and_stays_unknown(monkeypatch):
    t, doc = workload()
    reference(doc, mode='keyRef', optional=True)
    cm_target = source._cm_target(t, 'settings')
    path = source._path(cm_target)
    responses = []
    class Pool:
        def request(self, method, url, **kwargs):
            assert method == 'GET' and url == native_test.HOST + path
            assert kwargs['headers']['authorization'] == 'Bearer ' + native_test.AUTH
            response = native_test.Response({}, status=404)
            responses.append(response)
            return response
    configuration = Configuration()
    configuration.host = native_test.HOST
    configuration.api_key = {'authorization': native_test.AUTH}
    configuration.api_key_prefix = {'authorization': 'Bearer'}
    client = ApiClient(configuration)
    client.rest_client.pool_manager = Pool()
    api = k8s._wrap_client(client)
    api.api_client.rest_client.pool_manager.literal_paths = frozenset({path})
    reader = k8s.K8sReader({'retries': 0})
    state = {'calls': 0, 'bytes': 0, 'deadline': time.monotonic() + 30}
    first = source._read_cm(reader, api, cm_target, state, optional=True)
    second = source._read_cm(reader, api, cm_target, state, optional=True)
    assert first == second == (None, 0)
    assert state['calls'] == 2 and all(r.closed and r.released for r in responses)
    bound = source.AssociatedDoc(doc)
    bound.associations = (source._plan(doc, t), (('settings', None, 0),))
    with pytest.raises(source.Incomplete, match='no_nonempty_supported_literals'):
        source._extract(bound, t)
