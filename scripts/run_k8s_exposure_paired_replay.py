"""Release-gated K8s Exposure model arm and exact-ID paired summary.

`--preflight` and `--summarize` are offline. `--launch` is the only model path;
it requires the root supervisor's exact release marker before touching Docker.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
REPLAY = Path('/Users/carlospolop/peaso-work/replay/k8s-exposure-79e4cf0b')
IMAGE_SOURCE = Path('/Users/carlospolop/peaso-work/replay/image-baseline-ai')
IMAGE = 'sha256:ad277f7ec3677d5e78bf723d42256ea41f69528309483a07304b64914111e312'
TOKEN = Path('/Users/carlospolop/peaso-work/replay/platform-codex-token.txt')
ROOT_RELEASE = Path('/Users/carlospolop/peaso-work/CODEX_FINDINGS.txt')
RELEASE_MARKER = 'ROOT_RELEASE_K8S_EXPOSURE_79E4CF0B'
TOKEN_SHA = '5863a3e6bc00982791d214c1f3346db8a6a6fa7438cdb1afecd2a1dc5e80ddce'
CODE_FILES = ('runner.py', 'output_validation.py', 'prompting.py', 'agents/exposure.yaml')


def sha(path):
    h = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def read_json(path):
    return json.loads(path.read_text())


def private_json(path, value):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w') as stream:
        json.dump(value, stream, sort_keys=True, indent=2)
        stream.write('\n')


def preflight():
    manifest = read_json(REPLAY / 'manifest.json')
    if (manifest['source_commit'] != '79e4cf0bece73556721581d62553b165239206fa'
            or manifest['selected_categories'] != ['exposure']
            or manifest['model_arm_status'] != 'queued_root_release_required'
            or manifest['snapshot_sha256'] != sha(REPLAY / 'snapshot.json')
            or manifest['native_report_sha256'] != sha(REPLAY / 'native-report.json')):
        raise ValueError('K8s native snapshot or report pin drift')
    report = read_json(REPLAY / 'native-report.json')
    snapshot = read_json(REPLAY / 'snapshot.json')
    if report['snapshot_id'] != snapshot['snapshot_id'] or snapshot['snapshot_id'] != manifest['snapshot_id']:
        raise ValueError('snapshot ID drift')
    native = {row['id']: row for row in manifest['native_findings']}
    review_ids = manifest['review_finding_ids']
    if (len(native) != len(manifest['native_findings']) or len(review_ids) != len(set(review_ids))
            or set(review_ids) != {ident for ident, row in native.items() if row['status'] == 'FAIL'}
            or len(manifest['ai_batches']) != 1):
        raise ValueError('native to AI review ID mismatch')
    for batch in manifest['ai_batches']:
        path = REPLAY / f"findings-{batch['number']:03d}.json"
        doc = read_json(path)
        if (sha(path) != batch['sha256'] or path.stat().st_size != batch['bytes']
                or [row['id'] for row in doc['items']] != batch['finding_ids']
                or doc['scan']['snapshot_id'] != manifest['snapshot_id']):
            raise ValueError('AI batch drift')
    source_hashes = {}
    for name in CODE_FILES:
        live = ROOT / 'peaso/ai' / name
        image = IMAGE_SOURCE / name
        if not image.is_file() or sha(live) != sha(image):
            raise ValueError('image reviewer source mismatch: ' + name)
        source_hashes[name] = sha(live)
    if 'platform.json' in (ROOT / 'peaso/ai/agents/exposure.yaml').read_text():
        raise ValueError('unexpected broad Exposure input contract')
    return {'snapshot_id': manifest['snapshot_id'], 'snapshot_sha256': manifest['snapshot_sha256'],
            'selected_categories': ['exposure'], 'native_findings': len(native),
            'review_ids': review_ids, 'ai_batches': manifest['ai_batches'],
            'reviewer_source_sha256': source_hashes,
            'image': IMAGE, 'model': 'gpt-5.6-sol', 'thinking': 'high',
            'model_arm_status': 'queued_root_release_required'}


def released():
    if not ROOT_RELEASE.is_file():
        return False
    return any(line.strip() == RELEASE_MARKER for line in ROOT_RELEASE.read_text().splitlines())


def launch():
    # Check the release before any credential read, Docker invocation, or model call.
    if not released():
        raise PermissionError(f'root model slot release absent: {RELEASE_MARKER}')
    receipt = preflight()
    image = subprocess.check_output(['docker', 'image', 'inspect', IMAGE,
        '--format', '{{.Id}}|{{.Os}}/{{.Architecture}}|{{.Config.User}}'], text=True).strip()
    if image != IMAGE + '|linux/amd64|10001:10001':
        raise ValueError('pinned reviewer image drift')
    if TOKEN.stat().st_mode & 0o777 != 0o600 or sha(TOKEN) != TOKEN_SHA:
        raise ValueError('private model token drift')
    batch = receipt['ai_batches'][0]
    run_dir = REPLAY / 'model-run-000'
    run_dir.mkdir(mode=0o700, exist_ok=False)
    os.chmod(run_dir, 0o700)
    shutil.copyfile(REPLAY / 'findings-000.json', run_dir / 'findings.json')
    os.chmod(run_dir / 'findings.json', 0o600)
    private_json(run_dir / 'credentials.json', {'version': 2, 'entries': []})
    command = ['docker', 'run', '--rm', '--platform', 'linux/amd64', '--entrypoint', 'python',
               '--user', '0:0', '--cpus', '0.5', '--memory', '2g', '--pids-limit', '256',
               '--read-only', '--tmpfs', '/tmp:rw,noexec,nosuid,size=512m',
               '--env', 'PYTHONPATH=/app', '--env', 'AWS_EC2_METADATA_DISABLED=true',
               '--mount', f'type=bind,src={run_dir},dst=/workspace',
               '--mount', f'type=bind,src={TOKEN},dst=/run/secrets/platform-codex-token,readonly',
               '--mount', f'type=bind,src={ROOT / "scripts/k8s_exposure_container_arm.py"},dst=/run/k8s_exposure_container_arm.py,readonly',
               IMAGE, '/run/k8s_exposure_container_arm.py']
    result = subprocess.run(command, capture_output=True, text=True, timeout=510)
    if result.returncode or not (run_dir / 'result.json').is_file():
        raise RuntimeError(f'model arm failed: exit={result.returncode}; see private runner.log')
    metrics = read_json(run_dir / 'runtime-metrics.json')
    if metrics['findings_sha256'] != batch['sha256']:
        raise ValueError('reviewed document drift')
    print(json.dumps({'model_arm_status': 'completed',
                      'metrics': {key: metrics[key] for key in ('model_calls', 'input_tokens',
                          'output_tokens', 'wall_seconds', 'cpu_seconds', 'peak_rss_bytes')}}))


def comparison_rows(manifest, ai):
    by_id = {row['finding_id']: row for row in ai}
    if len(by_id) != len(ai) or set(by_id) != set(manifest['review_finding_ids']):
        raise ValueError('model output review IDs drift')
    comparisons = []
    for row in manifest['native_findings']:
        review = by_id.get(row['id'])
        ai_verdict = review['verdict'] if review else 'NOT_REVIEWED'
        comparisons.append({'finding_id': row['id'], 'check_id': row['check_id'],
                            'resource_id': row['resource_id'],
                            'native_resource_id': row['native_resource_id'],
                            'native_verdict': row['status'], 'ai_verdict': ai_verdict,
                            'transition': row['status'] + '->' + ai_verdict,
                            'ai_reason': review['reason'] if review else None,
                            'ai_claims_absent_from_snapshot': False if review and review['verdict'] == 'FAIL' else None,
                            'absent_fact_review': 'pending' if review and review['verdict'] != 'FAIL' else 'no_new_claim'})
    return comparisons


def summarize():
    preflight()
    manifest = read_json(REPLAY / 'manifest.json')
    run_dir = REPLAY / 'model-run-000'
    from peaso.ai.contracts import validate_reviews
    from peaso.ai.review_groups import expand
    representatives = [{'id': ident} for ident in manifest['representative_ids']]
    initial = validate_reviews(read_json(run_dir / 'result.json'), representatives)['items']
    members = {leader: [{'id': ident} for ident in ids]
               for leader, ids in manifest['group_members'].items()}
    expanded, recheck = expand(initial, members)
    if recheck:
        raise ValueError('non-FAIL representative requires a separate member model review')
    expected = [{'id': ident} for ident in manifest['review_finding_ids']]
    ai = validate_reviews({'items': expanded}, expected)['items']
    metrics = read_json(run_dir / 'runtime-metrics.json')
    if metrics['findings_sha256'] != manifest['ai_batches'][0]['sha256']:
        raise ValueError('reviewed input was not pinned batch')
    comparisons = comparison_rows(manifest, ai)
    summary = {'snapshot_id': manifest['snapshot_id'], 'snapshot_sha256': manifest['snapshot_sha256'],
               'source_commit': manifest['source_commit'], 'selected_categories': ['exposure'],
               'native_metrics': manifest['native_metrics'], 'ai_metrics': metrics,
               'exact_findings': comparisons,
               'reviewed_count': len(ai),
               'verdict_disagreements': sum(x['ai_verdict'] not in ('NOT_REVIEWED', x['native_verdict']) for x in comparisons),
               'unsupported_change_adjudication': 'pending_human_evidence_review_if_non_FAIL'}
    private_json(REPLAY / 'paired-summary.json', summary)
    print(json.dumps({'reviewed_count': summary['reviewed_count'],
                      'verdict_disagreements': summary['verdict_disagreements'],
                      'summary': str(REPLAY / 'paired-summary.json')}))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--preflight', action='store_true')
    group.add_argument('--launch', action='store_true')
    group.add_argument('--summarize', action='store_true')
    args = parser.parse_args()
    if args.preflight:
        print(json.dumps(preflight(), sort_keys=True))
    elif args.launch:
        launch()
    else:
        summarize()
