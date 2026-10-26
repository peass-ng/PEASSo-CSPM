"""Complete grouped API requests without unused per-observation sort cards.

python -m examples.benchmark_peaso_group_selection --rows 50000 --endpoint list
The reference restores the former eager selection at the three callers only.
"""
import argparse
import ast
from contextlib import contextmanager
import gc
import hashlib
import importlib
import inspect
import json
import statistics
import time
import tracemalloc

from examples.benchmark_peaso_finding_pages import api_fixture


def reference_factory():
    """Run identical application code with the former eager card construction."""
    module = importlib.import_module('peaso.server.app')
    source = ast.parse(inspect.getsource(module.create_app))
    changed = 0
    for node in ast.walk(source):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == 'finding_selection':
            if any(keyword.arg == 'sort_cards' for keyword in node.keywords):
                node.keywords = [keyword for keyword in node.keywords if keyword.arg != 'sort_cards']
                changed += 1
    assert changed == 3, 'review the benchmark reference when selection callers change'
    namespace = dict(vars(module))
    exec(compile(source, module.__file__, 'exec'), namespace)
    return namespace['create_app']


@contextmanager
def reference_client(client):
    from fastapi.testclient import TestClient
    state = client.app.state
    application = reference_factory()(state.settings, store=state.store, artifacts=state.artifacts,
        authenticator=state.authenticator)
    with TestClient(application, base_url='http://127.0.0.1:8000') as reference:
        reference.headers['Authorization'] = 'Bearer alice'
        yield reference


def compare(rows=50000, endpoint='list'):
    results = {name: {'seconds': [], 'cpu_seconds': [], 'digests': []} for name in ('baseline', 'optimized')}
    with api_fixture(rows) as (optimized, ident), reference_client(optimized) as baseline:
        path = f'/api/scans/{ident}/findings'
        params = {'aggregation': 'check', 'sort_by': 'title', 'limit': 100}
        if endpoint == 'summary':
            path, params = f'/api/scans/{ident}/summary', {'aggregation': 'check'}
        elif endpoint == 'detail':
            first = optimized.get(path, params=params)
            assert first.status_code == 200, first.text
            group = first.json()['items'][0]['id']
            path, params = f'/api/scans/{ident}/finding-groups/{group}', {'members_limit': 25}
        elif endpoint != 'list':
            raise ValueError('unsupported endpoint')
        for client in (baseline, optimized):
            warm = client.get(path, params=params)
            assert warm.status_code == 200, warm.text
        for iteration in range(3):
            variants = (('baseline', baseline), ('optimized', optimized))
            for name, client in variants if iteration % 2 == 0 else variants[::-1]:
                gc.collect()
                start, cpu = time.perf_counter(), time.process_time()
                response = client.get(path, params=params)
                results[name]['seconds'].append(time.perf_counter() - start)
                results[name]['cpu_seconds'].append(time.process_time() - cpu)
                assert response.status_code == 200, response.text
                results[name]['digests'].append(hashlib.sha256(response.content).hexdigest())
                del response
        for name, client in (('baseline', baseline), ('optimized', optimized)):
            gc.collect()
            tracemalloc.start()
            response = client.get(path, params=params)
            results[name]['peak_allocated_bytes'] = tracemalloc.get_traced_memory()[1]
            tracemalloc.stop()
            assert response.status_code == 200, response.text
            assert hashlib.sha256(response.content).hexdigest() == results[name]['digests'][0]
        for result in results.values():
            fingerprints = result.pop('digests')
            assert len(set(fingerprints)) == 1
            result['response_digest'] = fingerprints[0]
        assert results['baseline']['response_digest'] == results['optimized']['response_digest']
    return {**results, 'observations': rows, 'endpoint': endpoint, 'identical_response_bytes': True,
        'speedup': round(statistics.median(results['baseline']['seconds']) /
                         statistics.median(results['optimized']['seconds']), 2),
        'cpu_speedup': round(statistics.median(results['baseline']['cpu_seconds']) /
                             statistics.median(results['optimized']['cpu_seconds']), 2),
        'peak_allocation_ratio': round(results['baseline']['peak_allocated_bytes'] /
                                       results['optimized']['peak_allocated_bytes'], 2),
        'limitations': 'Synthetic complete HTTP request with a warm tenant-owned index. '
            'The reference restores eager card construction only; all grouping, filters, reviews and hydration run. '
            'Peak allocations are request-scoped and exclude fixture setup, native checks and process RSS.'}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--rows', type=int, default=50000)
    parser.add_argument('--endpoint', choices=('list', 'summary', 'detail'), default='list')
    args = parser.parse_args()
    print(json.dumps(compare(args.rows, args.endpoint), indent=2))
