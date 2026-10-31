"""Complete cached-index findings API requests, CPU time and allocation peak.

python -m tests.synthetic.benchmark_peaso_finding_pages --rows 50000 --sort title
Synthetic archived artifacts are prepared outside measurement; no checks run.
"""
import argparse
from contextlib import contextmanager, ExitStack
import gc
import hashlib
import importlib
import json
from pathlib import Path
import random
import statistics
import tempfile
import time
import tracemalloc
from unittest.mock import patch


def literal_summary(finding):
    fields = {'id', 'category', 'check_id', 'title', 'provider', 'service', 'resource_id', 'native_resource_id',
        'resource_name', 'scope', 'region', 'severity', 'status', 'frameworks', 'remediation', 'automated',
        'secret_fingerprint', 'linked_check_ids', 'scanner_status', 'ai_review'}
    if finding.get('secret_fingerprint'):
        fields.add('evidence_summary')
    value = {key: item for key, item in finding.items() if key in fields}
    if 'finding_type' in finding:
        value['finding_type'] = finding['finding_type']
    for key, item in list(value.items()):
        maximum = {'title': 400, 'resource_id': 1000, 'scope': 500, 'remediation': 1000,
            'service': 100, 'check_id': 200, 'category': 100, 'provider': 30}.get(key, 2000)
        if isinstance(item, str) and len(item) > maximum:
            value[key] = item[:maximum] + ' [Full value available in finding detail]'
            value['summary_truncated'] = True
    value['detail_available'] = True
    return value


def literal_page(rows, *, group_by='service', sort_by=None, sort_order='asc', offset=0, limit=500):
    if sort_by is None:
        rows.sort(key=lambda pair: (str(pair[1].get(group_by, '')), pair[1]['id']))
    else:
        severity = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4, 'informational': 4}
        def value(card):
            if sort_by == 'severity':
                name = str(card.get('severity') or '').casefold()
                return severity.get(name, 5), name
            if sort_by == 'resource_id':
                name = card.get('resource_name') or card.get('native_resource_id') or card.get('resource_id') or ''
            else:
                name = card.get(sort_by) or ''
            return str(name).casefold()
        rows.sort(key=lambda pair: pair[1]['id'])
        rows.sort(key=lambda pair: value(pair[1]), reverse=sort_order == 'desc')
    return rows[offset:offset + limit]


class LiteralStatusCounts:
    """The former two-set algorithm behind the same per-request interface."""
    def __init__(self):
        self.groups, self.all = {}, set()

    def add(self, status, identity):
        self.groups.setdefault(status, set()).add(identity)
        self.all.add(identity)

    def result(self):
        return {selection: len(set().union(*(self.groups.get(name, set()) for name in selection.split(','))))
            for selection in ('FAIL', 'PASS', 'UNKNOWN,MANUAL', 'DENIED', 'NOT_APPLICABLE,EMPTY')}

    @property
    def total(self):
        return len(self.all)


@contextmanager
def api_fixture(count):
    from fastapi import HTTPException
    from fastapi.testclient import TestClient
    from peaso.auth import Identity
    from peaso.server import create_app
    from peaso.server.config import Settings
    from peaso.storage import FileArtifacts, SQLiteStore
    if count < 1:
        raise ValueError('positive row count required')
    class Identities:
        def authenticate(self, authorization):
            if authorization == 'Bearer alice':
                return Identity('alice')
            if authorization == 'Bearer bob':
                return Identity('bob')
            raise HTTPException(401, 'Invalid authentication')
    with tempfile.TemporaryDirectory(prefix='peaso-api-page-') as directory:
        root = Path(directory)
        settings = Settings(state_dir=root / 'state', identity_dir=root / 'identity',
            local_token='local-benchmark-token-0123456789abcdef')
        store = SQLiteStore(settings.state_dir)
        artifacts = FileArtifacts(settings.state_dir / 'artifacts')
        connector = store.add_connector('alice', {'provider': 'aws'}, 'encrypted-fixture')
        job = store.enqueue('alice', {'connector_id': connector['id']})
        collector = store.claim('collector')
        store.finish(job['id'], collector['owner'], 'collected', artifacts.put('alice', job['id'], 'snapshot', {}))
        analyzer = store.claim('analyzer')
        randomizer = random.Random(28744)
        records = [{'id': f'finding-{randomizer.getrandbits(96):024x}', 'check_id': f'fixture.page-{i % 40}',
            'scope': f'{111122223333 + i % 5}/us-east-1',
            'severity': ('critical', 'high', 'medium', 'low', 'info')[i % 5],
            'status': ('FAIL', 'PASS', 'UNKNOWN', 'MANUAL')[i % 4],
            'resource_id': f'resource-{i}', 'native_resource_id': f'native-{i}',
            'finding_type': 'configuration', 'detail_available': True} for i in range(count)]
        records.sort(key=lambda item: item['id'])
        metadata = {f'fixture.page-{i}': {'provider': 'aws', 'category': 'hardening',
            'title': f'Native configuration {i}', 'service': f'service-{i % 12}',
            'remediation': 'Review the recorded setting.'} for i in range(40)}
        manifest = {'bundle_version': 1, 'summary': {'provider': 'aws', 'snapshot_id': 'synthetic', 'stats': {}},
            'finding_count': count, 'finding_chunks': [], 'check_meta': metadata,
            'check_frameworks': {key: ['Synthetic framework'] for key in metadata}}
        for offset in range(0, count, 250):
            group = records[offset:offset + 250]
            reference = artifacts.put('alice', job['id'], 'finding-index', {'items': group})
            manifest['finding_chunks'].append({'reference': reference, 'index_reference': reference,
                'first_id': group[0]['id'], 'last_id': group[-1]['id'], 'count': len(group)})
        reference = artifacts.put('alice', job['id'], 'manifest', manifest)
        store.finish(job['id'], analyzer['owner'], 'completed', reference)
        del records
        with TestClient(create_app(settings, store=store, artifacts=artifacts, authenticator=Identities()),
                base_url='http://127.0.0.1:8000') as client:
            client.headers['Authorization'] = 'Bearer alice'
            yield client, job['id']


@contextmanager
def implementation(baseline):
    from peaso import finding_page_order, finding_status_counts
    app_module = importlib.import_module('peaso.server.app')
    with ExitStack() as stack:
        if baseline:
            stack.enter_context(patch.object(finding_page_order, 'finding_page', literal_page))
            stack.enter_context(patch.object(app_module, 'finding_summary', literal_summary))
            stack.enter_context(patch.object(finding_status_counts, 'FindingStatusCounts', LiteralStatusCounts))
        yield


def compare(rows=50000, sort_by='title', order='asc', offset=0, limit=100):
    params = {'sort_order': order, 'offset': offset, 'limit': limit}
    if sort_by != 'default':
        params['sort_by'] = sort_by
    results = {name: {'seconds': [], 'cpu_seconds': [], 'digests': []} for name in ('baseline', 'optimized')}
    with api_fixture(rows) as (client, ident):
        path = f'/api/scans/{ident}/findings'
        warm = client.get(path, params=params)
        assert warm.status_code == 200, warm.text
        for iteration in range(3):
            for name in ('baseline', 'optimized') if iteration % 2 == 0 else ('optimized', 'baseline'):
                with implementation(name == 'baseline'):
                    gc.collect()
                    start, cpu = time.perf_counter(), time.process_time()
                    response = client.get(path, params=params)
                    results[name]['seconds'].append(time.perf_counter() - start)
                    results[name]['cpu_seconds'].append(time.process_time() - cpu)
                    assert response.status_code == 200, response.text
                    results[name]['digests'].append(hashlib.sha256(response.content).hexdigest())
                    total, returned = response.json()['total'], len(response.json()['items'])
                    del response
        for name in ('baseline', 'optimized'):
            with implementation(name == 'baseline'):
                gc.collect()
                tracemalloc.start()
                response = client.get(path, params=params)
                results[name]['peak_allocated_bytes'] = tracemalloc.get_traced_memory()[1]
                tracemalloc.stop()
                assert response.status_code == 200
                assert hashlib.sha256(response.content).hexdigest() == results[name]['digests'][0]
        for result in results.values():
            fingerprints = result.pop('digests')
            assert len(set(fingerprints)) == 1
            result['response_digest'] = fingerprints[0]
        assert results['baseline']['response_digest'] == results['optimized']['response_digest']
    return {**results, 'rows': rows, 'total': total, 'returned': returned, 'query': params,
        'identical_response_bytes': True,
        'speedup': round(statistics.median(results['baseline']['seconds']) /
                         statistics.median(results['optimized']['seconds']), 2),
        'cpu_speedup': round(statistics.median(results['baseline']['cpu_seconds']) /
                             statistics.median(results['optimized']['cpu_seconds']), 2),
        'peak_allocation_ratio': round(results['baseline']['peak_allocated_bytes'] /
                                       results['optimized']['peak_allocated_bytes'], 2),
        'limitations': 'Synthetic complete HTTP findings-list request with a cached tenant-owned index. '
            'Peak allocations cover one traced request, not total process RSS. Artifact setup and native scans are excluded.'}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--rows', type=int, default=50000)
    parser.add_argument('--sort', choices=('default', 'title', 'severity', 'service', 'account', 'status', 'resource_id'), default='title')
    parser.add_argument('--order', choices=('asc', 'desc'), default='asc')
    parser.add_argument('--offset', type=int, default=0)
    parser.add_argument('--limit', type=int, default=100)
    args = parser.parse_args()
    print(json.dumps(compare(args.rows, args.sort, args.order, args.offset, args.limit), indent=2))
