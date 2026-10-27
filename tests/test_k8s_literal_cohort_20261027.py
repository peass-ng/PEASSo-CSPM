"""Automatic K8s literal cohorts keep the native path grant per worker."""
from concurrent.futures import ThreadPoolExecutor
from contextlib import nullcontext
from contextvars import copy_context
import threading
from types import SimpleNamespace
import pytest

from peaso.collectors.k8s import _BoundedPool, _LiteralReader, _automatic_literal_group
from peaso.collectors import k8s
from peaso import secret_scanning_batch as batch


def test_selected_paths_are_context_local_on_a_shared_transport():
    pool = _BoundedPool(object())
    barrier = threading.Barrier(2)

    def grant(path):
        pool.literal_paths = {path}
        barrier.wait(timeout=2)
        return pool.literal_paths

    with ThreadPoolExecutor(max_workers=2) as workers:
        left = workers.submit(copy_context().run, grant, '/api/v1/namespaces/a/pods/one')
        right = workers.submit(copy_context().run, grant, '/api/v1/namespaces/b/pods/two')
        assert left.result() == {'/api/v1/namespaces/a/pods/one'}
        assert right.result() == {'/api/v1/namespaces/b/pods/two'}
    assert pool.literal_paths == frozenset()


def test_literal_reader_keeps_collection_and_item_counts_private():
    class Parent:
        total = 9
        collections = [{'id': 'inventory'}]
        budget = object()

    parent = Parent()
    local = _LiteralReader(parent)
    local.total += 1
    local.collections.append({'id': 'literal'})
    local._configmap_association_phases['item'] = []
    assert parent.total == local.parent_total == 9
    assert parent.collections == [{'id': 'inventory'}]
    assert local.budget is parent.budget


def test_eight_workloads_share_one_preparation_and_commit_in_plan_order(monkeypatch):
    pool = _BoundedPool(object())
    targets = [{'namespace': 'team', 'name': str(index)} for index in range(8)]
    prepared = []

    def prepare(items, timeout):
        prepared.append(tuple(path for _, path in items))
        return {item: b'detected:' + item[0] for item in items}

    monkeypatch.setattr(batch, '_prepare_trufflehog_batch', prepare)

    def collect(reader, api, options, scopes, cluster):
        target = options['selected'][-1]
        name = target['name']
        path = '/team/pod/' + name
        pool.literal_paths = {path}
        assert pool.literal_paths == {path}
        source = ('value-' + name).encode()
        output = batch.prepared_output(source, name + '.literals')
        assert output == b'detected:' + source
        reader.collections.append({'type': 'literal', 'scope': scopes[0],
            'items': [{'id': name, 'detected': output.decode()}]})
        reader.total += 1
        return {'name': name}, set()

    literals = SimpleNamespace(OPTION='selected', base=SimpleNamespace(MAX_SECONDS=60, MAX_CONTENT=1024),
        identity=lambda target: target['name'], collect=collect)
    logs = SimpleNamespace(private_native_logs=nullcontext)
    parent = SimpleNamespace(total=0, collections=[], workers=8)
    results = _automatic_literal_group(parent, None, {}, ['team'], 'cluster', targets,
        literals, logs, True, True)
    assert len(prepared) == 1
    assert set(prepared[0]) == {str(i) + '.literals' for i in range(8)}
    assert [collection['items'][0]['id'] for _, collection, *_ in results] == [str(i) for i in range(8)]
    assert parent.collections == [] and parent.total == 0
    assert pool.literal_paths == frozenset()


@pytest.mark.parametrize('limits,workers,parallel,group_sizes', [({}, 8, True, [8]),
    ({}, 2, True, [2] * 4), ({'max_resources': 8}, 8, False, [8]),
    ({'max_calls': 127}, 8, False, [8])])
def test_automatic_collector_commits_eight_workloads_in_order(monkeypatch, limits, workers, parallel, group_sizes):
    from peaso.collectors import k8s_literal_configmap_association as literals
    from peaso.collectors import workload_environment_discovery as discovery
    from peaso.collectors import k8s_response_cache

    targets = tuple({'cluster_id': 'cluster', 'namespace': 'team', 'kind': 'Pod',
        'name': 'pod-' + str(index)} for index in range(8))
    monkeypatch.setattr(k8s, '_cluster_id', lambda api, auth: 'cluster')
    monkeypatch.setattr(k8s.annotation_indicators, 'collection_context', lambda api, cluster: None)
    monkeypatch.setattr(k8s_response_cache, 'install', lambda api: None)
    monkeypatch.setattr(k8s_response_cache, 'uninstall', lambda api: {})
    monkeypatch.setattr(discovery, 'k8s_workloads', lambda *args, **kwargs:
        discovery.Plan(targets, len(targets), True, 'complete'))
    monkeypatch.setattr(batch, '_volatile_shm_available', lambda total: True)

    def inventory(reader, jobs):
        for kind, scope, service, _ in jobs:
            reader.collections.append({'type': kind, 'scope': scope, 'service': service,
                'status': 'empty', 'items': []})

    monkeypatch.setattr(k8s.K8sReader, 'run', inventory)
    monkeypatch.setattr(k8s.K8sReader, 'unavailable', lambda self, kind, scope, service, exc: (_ for _ in ()).throw(exc))
    observed = []
    groups = []
    original_group = k8s._automatic_literal_group

    def grouped(*args):
        groups.append(len(args[5]))
        return original_group(*args)

    monkeypatch.setattr(k8s, '_automatic_literal_group', grouped)

    def collect(reader, api, options, scopes, cluster):
        target = options[literals.OPTION][0]
        ident = literals.identity(target)
        observed.append((target['name'], isinstance(reader, _LiteralReader)))
        marker = {'complete': True, 'leaks': [], 'parts': [{'part': 'literals'}]}
        reader.collections.append({'type': literals.KIND, 'scope': scopes[0],
            'service': 'kubernetes', 'status': 'collected',
            'items': [{'id': ident, literals.MARKER: marker}]})
        reader.total += 1
        return {literals.KIND + '_authorized': True,
            literals.KIND + '_selection': {scopes[0]: [ident]}}, set()

    monkeypatch.setattr(literals, 'collect', collect)
    snapshot = k8s.collect({'provider': 'k8s', 'scopes': ['team'],
        'auth': {'cluster_id': 'cluster'},
        'options': {'content_secret_scans': True,
            '_content_secret_scan_kinds': [literals.KIND], 'concurrency': workers, **limits}},
        requirements=[literals.KIND], api=SimpleNamespace(api_client=SimpleNamespace(last_response=None)))
    rows = [row for collection in snapshot['collections'] if collection['type'] == literals.KIND
        for row in collection['items']]
    assert [row['id'] for row in rows] == [literals.identity(target) for target in targets], (
        observed, [row for row in snapshot['collections'] if row['type'] == literals.KIND])
    assert len(snapshot['metadata']['automatic_workload_environment_batches'][literals.KIND]) == 8
    assert {name for name, _ in observed} == {target['name'] for target in targets}
    assert {local for _, local in observed} == {parallel}
    assert groups == group_sizes
