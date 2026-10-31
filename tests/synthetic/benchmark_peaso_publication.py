"""Lossless report artifact writes through the real hosted storage adapter.

python -m tests.synthetic.benchmark_peaso_publication --findings 10000 --latency-ms 20

S3 is simulated with a fixed per-PUT delay; no cloud requests are sent. Both
paths serialize, compress, encrypt by the same request policy, and write the
same report, Markdown, finding chunks/indexes, coverage and graphs. Grouping,
evaluation and cloud collection are outside this benchmark.
"""
import argparse
from contextlib import nullcontext
import gzip
import hashlib
import json
import threading
import time

from peaso.reports import render_markdown
from peaso.storage.artifacts import S3Artifacts
from peaso.storage.reports import chunks, finding_summary


class SimulatedS3:
    def __init__(self, latency):
        self.latency = latency
        self.lock = threading.Lock()
        self.active = self.peak = 0
        self.objects = {}

    def put_object(self, **request):
        with self.lock:
            self.active += 1
            self.peak = max(self.peak, self.active)
        try:
            time.sleep(self.latency)
            # Like S3, consume a streamed (file) body during the call: the
            # caller may close its spool as soon as put_object returns.
            if hasattr(request['Body'], 'read'):
                request = {**request, 'Body': request['Body'].read()}
            with self.lock:
                self.objects[request['Key']] = request
        finally:
            with self.lock:
                self.active -= 1


def synthetic_report(count):
    return {'schema_version': '1.0', 'provider': 'gcp', 'snapshot_id': 'synthetic',
            'created_at': '2026-01-01T00:00:00Z', 'scopes': ['projects/benchmark'], 'resources': [],
            'findings': [{'id': f'finding-{i:08d}', 'check_id': f'synthetic.check-{i % 10}',
                'category': 'hardening', 'title': 'Synthetic recorded configuration', 'severity': 'medium',
                'status': 'PASS' if i % 2 else 'UNKNOWN', 'provider': 'gcp', 'scope': 'projects/benchmark',
                'resource_id': f'resource-{i}', 'frameworks': [],
                'evidence': {'recorded_value': i, 'configuration': 'synthetic metadata · 数据 ' * 10}}
                for i in range(count)],
            'coverage': [{'level': 'check', 'check_id': f'synthetic.check-{i % 10}', 'scope': 'projects/benchmark',
                          'status': 'evaluated', 'resource_count': 1} for i in range(count)],
            'graphs': {'iam': {'nodes': [{'id': f'principal-{i}', 'label': f'principal-{i}',
                'type': 'service_account', 'provider': 'gcp', 'scope': 'projects/benchmark'}
                for i in range(count // 10)], 'edges': []}},
            'stats': {'finding_count': count}}


def publish_writes(store, report, markdown):
    """The same independent write types and final manifest barrier as publication."""
    tenant, scan = 'benchmark', 'a' * 32
    manifest = {'report_json': store.put(tenant, scan, 'report', report),
                'report_markdown': store.put_text(tenant, scan, 'markdown', markdown),
                'finding_chunks': [], 'coverage_chunks': [], 'graphs': {}}
    for group in chunks(report['findings']):
        reference = store.put(tenant, scan, 'findings', {'items': group})
        index = store.put(tenant, scan, 'finding-index', {'items': [finding_summary(f) for f in group]})
        manifest['finding_chunks'].append({'reference': reference, 'index_reference': index})
    for group in chunks(report['coverage']):
        manifest['coverage_chunks'].append(store.put(tenant, scan, 'coverage', {'items': group}))
    for kind in ('network', 'iam', 'privesc'):
        graph = report['graphs'].get(kind, {'nodes': [], 'edges': []})
        manifest['graphs'][kind] = store.put(tenant, scan, 'graph-' + kind, graph)
    return store.put(tenant, scan, 'manifest', manifest)


def content_digest(objects):
    """Normalize generated references by the contents they identify, recursively."""
    bodies = {}
    for key, request in objects.items():
        body = request['Body']
        if request.get('ContentEncoding') == 'gzip':
            body = gzip.decompress(body)
        reference = key.removeprefix('artifacts/')
        bodies[reference] = json.loads(body) if request['ContentType'] == 'application/json' else body.decode()
    memo = {}

    def normalize(value):
        if isinstance(value, dict):
            return {key: normalize(member) for key, member in value.items()}
        if isinstance(value, list):
            return [normalize(member) for member in value]
        if isinstance(value, str) and value in bodies:
            return {'artifact_content': fingerprint(value)}
        return value

    def fingerprint(reference):
        if reference not in memo:
            encoded = json.dumps(normalize(bodies[reference]), sort_keys=True, ensure_ascii=False).encode()
            memo[reference] = hashlib.sha256(encoded).hexdigest()
        return memo[reference]

    return hashlib.sha256(json.dumps(sorted(fingerprint(ref) for ref in bodies)).encode()).hexdigest()


def benchmark(findings=10000, latency_ms=20, workers=4):
    if findings < 1 or latency_ms < 0:
        raise ValueError('findings must be positive and latency must be nonnegative')
    report = synthetic_report(findings)
    before = json.dumps(report, sort_keys=True)
    markdown = render_markdown(report)
    output = {'findings': findings, 'simulated_put_latency_ms': latency_ms, 'workers': workers, 'cloud_calls': 0}
    for mode in ('serial', 'parallel'):
        times, fingerprints, peaks = [], [], []
        for _ in range(3):
            client = SimulatedS3(latency_ms / 1000)
            artifacts = S3Artifacts('private', client=client, kms_key='benchmark-key')
            started = time.perf_counter()
            context = artifacts.batch(workers=workers) if mode == 'parallel' else nullcontext(artifacts)
            with context as writer:
                reference = publish_writes(writer, report, markdown)
            times.append(round(time.perf_counter() - started, 6))
            assert list(client.objects)[-1] == 'artifacts/' + reference
            assert all(request['ServerSideEncryption'] == 'aws:kms' for request in client.objects.values())
            fingerprints.append(content_digest(client.objects))
            peaks.append(client.peak)
        assert len(set(fingerprints)) == 1
        output[mode] = {'seconds': times, 'artifact_count': len(client.objects), 'peak_uploads': peaks,
                        'content_digest': fingerprints[0]}
    assert output['serial']['content_digest'] == output['parallel']['content_digest']
    assert json.dumps(report, sort_keys=True) == before
    output['identical_artifact_contents'] = True
    output['limitations'] = ('Synthetic storage workload with simulated S3 latency. Timings include serialization, '
                             'compression and uploads, but exclude cloud collection, evaluation, grouping and Markdown generation.')
    return output


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--findings', type=int, default=10000)
    parser.add_argument('--latency-ms', type=float, default=20)
    parser.add_argument('--workers', type=int, default=4)
    args = parser.parse_args()
    print(json.dumps(benchmark(args.findings, args.latency_ms, args.workers), indent=2))
