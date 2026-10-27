"""Offline K8s Exposure replay input, pinned to this branch's native evaluator.

No credential, cluster, model, or network access is used. The output directory is
private because the staged AI document may contain native resource properties.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import resource
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from peaso.ai.collection_coverage import index
from peaso.ai.pipeline import compact_document, findings_document, inputs, review_context
from peaso.ai.review_groups import chunks, plan
from peaso.engine import evaluate_snapshot, hydrate_finding
from peaso.snapshot import canonical, make_snapshot, resources


HEAD = '79e4cf0bece73556721581d62553b165239206fa'
OUT = Path('/Users/carlospolop/peaso-work/replay/k8s-exposure-79e4cf0b')
SCOPE = 'k8s-cluster:paired-exposure-bench'
CREATED = '2026-10-27T00:00:00+00:00'
CATEGORIES = ['exposure']


def col(kind, items, service='k8s'):
    return {'type': kind, 'scope': SCOPE, 'service': service,
            'status': 'collected' if items else 'empty', 'items': items}


def fixture():
    """Small, varied declared-state fixture derived from checked-in K8s tests.

    Sources: test_peaso_analysis_internet_exposure.py K8s cases and
    test_peaso_k8s_principal_exposure.py. Addresses are documentation ranges
    where possible; 8.8.8.8 is used only as a public-address fixture.
    """
    public_node = {'metadata': {'name': 'worker'}, 'status': {'addresses': [
        {'type': 'ExternalIP', 'address': '8.8.8.8'}],
        'daemonEndpoints': {'kubeletEndpoint': {'Port': 10250}}}}
    service = {'metadata': {'name': 'public-lb', 'namespace': 'apps'},
               'spec': {'type': 'LoadBalancer', 'ports': [{'port': 443, 'protocol': 'TCP'}]},
               'status': {'loadBalancer': {'ingress': [{'hostname': 'lb.example.com'}]}}}
    pending_lb = {'metadata': {'name': 'pending-controller-lb', 'namespace': 'apps'},
                  'spec': {'type': 'LoadBalancer', 'ports': [{'port': 9443, 'protocol': 'TCP'}]},
                  'status': {'loadBalancer': {'ingress': []}}}
    nodeport = {'metadata': {'name': 'nodeport', 'namespace': 'apps'},
                'spec': {'type': 'NodePort', 'ports': [{'port': 80, 'nodePort': 30080}]}}
    external = {'metadata': {'name': 'external-ip', 'namespace': 'apps'},
                'spec': {'type': 'ClusterIP', 'externalIPs': ['8.8.4.4'],
                         'ports': [{'port': 8080}]}}
    ingress = {'metadata': {'name': 'public-ingress', 'namespace': 'apps'},
               'spec': {'rules': [{'host': 'web.example.com'}], 'tls': [{}]},
               'status': {'loadBalancer': {'ingress': [{'ip': '8.8.8.8'}]}}}
    pod = {'metadata': {'name': 'host-port', 'namespace': 'apps'},
           'spec': {'nodeName': 'worker', 'containers': [{'name': 'app',
                    'ports': [{'containerPort': 8080, 'hostPort': 8080}]}]},
           'status': {'phase': 'Running'}}
    gateway = {'metadata': {'name': 'edge', 'namespace': 'apps'},
               'spec': {'listeners': [{'name': 'web', 'port': 443, 'protocol': 'HTTPS'}]},
               'status': {'addresses': [{'type': 'IPAddress', 'value': '8.8.8.8'}]}}
    route = {'metadata': {'name': 'edge-route', 'namespace': 'apps'},
             'spec': {'parentRefs': [{'name': 'edge', 'sectionName': 'web'}],
                      'rules': [{'backendRefs': [{'name': 'public-lb'}]}]}}
    role = {'metadata': {'name': 'read-secrets'}, 'rules': [
        {'apiGroups': [''], 'resources': ['secrets'], 'verbs': ['get', 'list']} ]}
    binding = {'metadata': {'name': 'anonymous-secrets'},
               'roleRef': {'kind': 'ClusterRole', 'name': 'read-secrets',
                           'apiGroup': 'rbac.authorization.k8s.io'},
               'subjects': [{'kind': 'Group', 'name': 'system:unauthenticated',
                             'apiGroup': 'rbac.authorization.k8s.io'}]}
    kcc = {'metadata': {'name': 'public-bucket', 'generation': 1},
           'spec': {'resourceRef': {'kind': 'StorageBucket', 'name': 'public-bucket'},
                    'bindings': [{'role': 'roles/storage.objectViewer',
                                  'members': ['allUsers']}]}}
    webhook = {'metadata': {'name': 'external-hook'}, 'webhooks': [
        {'name': 'audit.example.com',
         'clientConfig': {'url': 'https://hooks.example.com/check'}}]}
    endpoint = {'metadata': {'name': 'vendor', 'namespace': 'apps'},
                'endpoints': [{'addresses': ['8.8.4.4']}],
                'ports': [{'port': 443, 'protocol': 'TCP'}]}
    return make_snapshot('k8s', [SCOPE], [
        col('service', [service, pending_lb, nodeport, external], 'core'),
        col('node', [public_node], 'core'), col('ingress', [ingress], 'networking'),
        col('pod', [pod], 'core'), col('gateway', [gateway], 'gateway'),
        col('httproute', [route], 'gateway'),
        col('clusterrole', [role], 'rbac'),
        col('clusterrolebinding', [binding], 'rbac'),
        col('kcc_iampolicy', [kcc], 'config_connector'),
        col('admission_configuration', [webhook], 'admission'),
        col('endpointslice', [endpoint], 'discovery'),
    ], created_at=CREATED, metadata={'synthetic': True, 'fixture': 'k8s-exposure-paired-79e4cf0b'})


def sha_bytes(data):
    return hashlib.sha256(data).hexdigest()


def put(path, value):
    data = (canonical(value) + '\n').encode()
    if path.exists():
        if path.read_bytes() != data:
            raise ValueError(f'pinned output drift: {path}')
        return sha_bytes(data)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(data)
    return sha_bytes(data)


def put_manifest(path, value):
    if path.exists():
        previous = json.loads(path.read_text())
        stable = lambda item: {key: val for key, val in item.items() if key != 'native_metrics'}
        if stable(previous) != stable(value):
            raise ValueError('pinned manifest drift')
        return sha_bytes(path.read_bytes())
    return put(path, value)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', type=Path, default=OUT)
    args = parser.parse_args()
    head = subprocess.check_output(['git', '-C', str(ROOT), 'rev-parse', 'HEAD'], text=True).strip()
    if subprocess.run(['git', '-C', str(ROOT), 'merge-base', '--is-ancestor', HEAD, head]).returncode:
        raise ValueError('K8s source commit drift')
    native_paths = ['peaso/analysis', 'peaso/checks', 'peaso/ai', 'peaso/engine.py', 'peaso/snapshot.py']
    if subprocess.run(['git', '-C', str(ROOT), 'diff', '--quiet', HEAD, head, '--', *native_paths]).returncode:
        raise ValueError('native or AI implementation changed since pinned commit')
    args.output.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(args.output, 0o700)
    snapshot = fixture()
    snapshot_sha = put(args.output / 'snapshot.json', snapshot)
    start_usage = resource.getrusage(resource.RUSAGE_SELF)
    started = time.monotonic()
    report = evaluate_snapshot(snapshot, categories=CATEGORIES, include_not_applicable=False)
    wall = time.monotonic() - started
    end_usage = resource.getrusage(resource.RUSAGE_SELF)
    report_sha = put(args.output / 'native-report.json', report)
    native_rows = [hydrate_finding(row, report.get('check_frameworks'), report.get('check_meta'),
                   report.get('check_meta_encoding'), report.get('remediation_templates'))
                   for row in report['findings']]
    native = [{'id': row['id'], 'check_id': row['check_id'], 'resource_id': row['resource_id'],
               'status': row['status'], 'category': row.get('category'), 'scope': row.get('scope')}
              for row in native_rows]
    hardening, exposure, duplicates = inputs(report)
    if hardening or duplicates or not exposure:
        raise ValueError('unexpected Exposure review selection')
    inventory = {row['id']: row for row in resources(snapshot)}
    resource_names = {row['id']: row['native_id'] for row in inventory.values()}
    checks_by_name = {(resource_names.get(row['resource_id']), row['check_id']): row
                      for row in native}
    if (checks_by_name[('apps/pending-controller-lb', 'analysis.internet_exposure')]['status'] != 'UNKNOWN'
            or checks_by_name[('apps/pending-controller-lb', 'k8s.service.review_public_type')]['status'] != 'FAIL'
            or checks_by_name[('apps/nodeport', 'analysis.internet_exposure')]['status'] != 'UNKNOWN'
            or checks_by_name[('apps/nodeport', 'k8s.service.review_public_type')]['status'] != 'FAIL'):
        raise ValueError('uncertain controller/firewall fixture contract drift')
    representatives, members = plan(exposure)
    batches = chunks(representatives)
    batch_receipts = []
    for number, batch in enumerate(batches):
        context = review_context(report, inventory, batch, _coverage=index(report.get('coverage')))
        document = compact_document(findings_document(context['scan'], batch, context['resources']))
        digest = put(args.output / f'findings-{number:03d}.json', document)
        batch_receipts.append({'number': number, 'finding_ids': [row['id'] for row in batch],
                               'sha256': digest, 'bytes': (args.output / f'findings-{number:03d}.json').stat().st_size})
    manifest = {'source_commit': HEAD, 'provider': 'k8s', 'fixture_sources': [
        'tests/test_peaso_analysis_internet_exposure.py',
        'tests/test_peaso_k8s_principal_exposure.py'],
        'snapshot_id': snapshot['snapshot_id'], 'snapshot_sha256': snapshot_sha,
        'native_report_sha256': report_sha, 'selected_categories': CATEGORIES,
        'native_findings': [dict(row, native_resource_id=resource_names.get(row['resource_id'])) for row in native],
        'review_finding_ids': [row['id'] for row in exposure],
        'representative_ids': [row['id'] for row in representatives],
        'group_members': {key: [row['id'] for row in value] for key, value in members.items()},
        'ai_batches': batch_receipts, 'resource_count': len(inventory),
        'collection_count': len(snapshot['collections']),
        'native_metrics': {'wall_seconds': wall,
                           'user_cpu_seconds': end_usage.ru_utime - start_usage.ru_utime,
                           'system_cpu_seconds': end_usage.ru_stime - start_usage.ru_stime,
                           'process_maxrss_bytes': end_usage.ru_maxrss * (1 if sys.platform == 'darwin' else 1024),
                           'model_calls': 0, 'input_tokens': 0, 'output_tokens': 0},
        'model_arm_status': 'queued_root_release_required'}
    put_manifest(args.output / 'manifest.json', manifest)
    print(json.dumps({'snapshot_id': manifest['snapshot_id'], 'snapshot_sha256': snapshot_sha,
                      'native_findings': len(native), 'review_ids': len(exposure),
                      'batches': len(batches), 'output': str(args.output)}, sort_keys=True))


if __name__ == '__main__':
    main()
