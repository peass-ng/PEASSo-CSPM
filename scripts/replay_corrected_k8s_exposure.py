"""Re-evaluate the pinned K8s snapshot against the one saved Exposure AI result.

This script makes no cloud or model calls. It preserves the original model
output and records every finding ID, including native UNKNOWN rows not sent to
the reviewer. The sole changed AI verdict is adjudicated against native facts.
"""
import hashlib
import json
import os
from pathlib import Path
import resource
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from peaso.ai.contracts import validate_reviews
from peaso.ai.pipeline import inputs
from peaso.ai.review_groups import expand
from peaso.engine import evaluate_snapshot
from peaso.snapshot import canonical

REPLAY = Path('/Users/carlospolop/peaso-work/replay/k8s-exposure-79e4cf0b')
EXTERNAL_IP_ID = 'analysis:b5e50d53b93373d06dd9dc11'


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_private(path, value):
    data = (canonical(value) + '\n').encode()
    if path.exists():
        if path.read_bytes() != data:
            raise ValueError('corrected replay output drift: ' + str(path))
        return
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(data)


def write_receipt(path, value):
    if path.exists():
        previous = json.loads(path.read_text())
        stable = lambda row: {key: item for key, item in row.items() if key != 'native_metrics'}
        if stable(previous) != json.loads(canonical(stable(value))):
            raise ValueError('corrected replay receipt drift')
        return
    write_private(path, value)


def main():
    manifest = json.loads((REPLAY / 'manifest.json').read_text())
    snapshot_path = REPLAY / 'snapshot.json'
    if digest(snapshot_path) != manifest['snapshot_sha256']:
        raise ValueError('snapshot drift')
    snapshot = json.loads(snapshot_path.read_text())
    if snapshot['snapshot_id'] != manifest['snapshot_id']:
        raise ValueError('snapshot identity drift')
    start_usage = resource.getrusage(resource.RUSAGE_SELF)
    started = time.monotonic()
    report = evaluate_snapshot(snapshot, categories=['exposure'], include_not_applicable=False)
    wall = time.monotonic() - started
    end_usage = resource.getrusage(resource.RUSAGE_SELF)
    if report['snapshot_id'] != manifest['snapshot_id']:
        raise ValueError('report snapshot drift')
    write_private(REPLAY / 'corrected-native-report.json', report)
    old_rows = {row['id']: row for row in manifest['native_findings']}
    new_rows = {row['id']: row for row in report['findings']}
    if set(new_rows) != set(old_rows):
        raise ValueError('finding ID drift')
    changed = {ident: (old_rows[ident]['status'], row['status']) for ident, row in new_rows.items()
               if row['status'] != old_rows[ident]['status']}
    if changed != {EXTERNAL_IP_ID: ('FAIL', 'UNKNOWN')}:
        raise ValueError('unexpected native verdict changes: ' + repr(changed))
    hardening, exposure, duplicates = inputs(report)
    if hardening or duplicates or len(exposure) != 8:
        raise ValueError('corrected reviewer selection drift')
    result = json.loads((REPLAY / 'model-run-000/result.json').read_text())
    reps = [{'id': ident} for ident in manifest['representative_ids']]
    initial = validate_reviews(result, reps)['items']
    members = {ident: [{'id': member} for member in values]
               for ident, values in manifest['group_members'].items()}
    expanded, recheck = expand(initial, members)
    if recheck:
        raise ValueError('representative needs separate review')
    ai = validate_reviews({'items': expanded}, [{'id': ident} for ident in manifest['review_finding_ids']])['items']
    by_id = {row['finding_id']: row for row in ai}
    external = new_rows[EXTERNAL_IP_ID]
    source = next(item for collection in snapshot['collections'] if collection['type'] == 'service'
                  for item in collection['items'] if item.get('metadata', {}).get('name') == 'external-ip')
    if (source['spec'].get('externalIPs') != ['8.8.4.4']
            or external['evidence']['public_addresses'] != ['8.8.4.4']
            or external['evidence']['exposed_ports'] != ['tcp/8080']
            or len(external['evidence_summary'].splitlines()) != 4
            or {gap['layer'] for gap in external['evidence']['unresolved']} != {'inventory', 'firewall'}
            or by_id[EXTERNAL_IP_ID]['verdict'] != 'UNKNOWN'):
        raise ValueError('externalIPs correction evidence drift')
    comparisons = []
    for ident, row in new_rows.items():
        ai_row = by_id.get(ident)
        verdict = ai_row['verdict'] if ai_row else 'NOT_REVIEWED'
        comparisons.append({'finding_id': ident, 'check_id': row['check_id'],
                            'native_resource_id': row.get('native_resource_id'),
                            'original_native_verdict': old_rows[ident]['status'],
                            'corrected_native_verdict': row['status'],
                            'saved_ai_verdict': verdict,
                            'transition': row['status'] + '->' + verdict,
                            'saved_ai_reason': ai_row['reason'] if ai_row else None})
    comparisons.sort(key=lambda row: row['finding_id'])
    if any(row['saved_ai_verdict'] not in ('NOT_REVIEWED', row['corrected_native_verdict'])
           for row in comparisons):
        raise ValueError('remaining AI/native verdict disagreement')
    metrics = json.loads((REPLAY / 'model-run-000/runtime-metrics.json').read_text())
    receipt = {'snapshot_id': manifest['snapshot_id'], 'snapshot_sha256': manifest['snapshot_sha256'],
               'original_native_report_sha256': manifest['native_report_sha256'],
               'corrected_native_report_sha256': digest(REPLAY / 'corrected-native-report.json'),
               'saved_ai_input_sha256': manifest['ai_batches'][0]['sha256'],
               'saved_ai_result_sha256': digest(REPLAY / 'model-run-000/result.json'),
               'selected_categories': ['exposure'], 'original_review_ids': manifest['review_finding_ids'],
               'corrected_review_ids': [row['id'] for row in exposure],
               'findings': comparisons, 'changed_native_verdicts': changed,
               'remaining_verdict_disagreements': 0,
               'external_ip_adjudication': {
                   'finding_id': EXTERNAL_IP_ID, 'saved_ai_unknown_supported': True,
                   'ai_claims_absent_snapshot_facts_as_known': False,
                   'recorded_declaration': 'Service externalIPs 8.8.4.4 and TCP/8080',
                   'missing_facts': ['address ownership', 'route to a cluster node', 'cloud firewall admission'],
                   'conclusion': 'AI identified missing evidence already available to the corrected native verdict; it added no post-correction fact or verdict.'},
               'native_metrics': {'wall_seconds': wall,
                                  'user_cpu_seconds': end_usage.ru_utime - start_usage.ru_utime,
                                  'system_cpu_seconds': end_usage.ru_stime - start_usage.ru_stime,
                                  'process_maxrss_bytes': end_usage.ru_maxrss * (1 if sys.platform == 'darwin' else 1024),
                                  'model_calls': 0, 'input_tokens': 0, 'output_tokens': 0},
               'saved_ai_metrics': {key: metrics[key] for key in ('model_calls', 'input_tokens', 'output_tokens',
                                    'wall_seconds', 'cpu_seconds', 'peak_rss_bytes')}}
    write_receipt(REPLAY / 'corrected-paired-summary.json', receipt)
    print(json.dumps({'snapshot_sha256': receipt['snapshot_sha256'], 'findings': len(comparisons),
                      'corrected_review_ids': len(exposure), 'remaining_verdict_disagreements': 0,
                      'receipt': str(REPLAY / 'corrected-paired-summary.json')}))


if __name__ == '__main__':
    main()
