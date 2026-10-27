"""Guarded paired Azure Hardening hosted replay for saved scan a79ff6f9.

--preflight never reads a token, starts Docker, or contacts a model. --launch
requires the exact root release line, a pinned preflight, model token, stage
credentials and the production image already present locally.
"""

import argparse
from collections import deque
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
import json
import os
from pathlib import Path
import shutil
import subprocess
import time

from peaso.ai.contracts import validate_reviews
from peaso.ai.review_groups import chunks, expand
from scripts.prepare_azure_native_final_hosted_a79 import (
    OUT, IMAGE, MODEL, EFFORT, document, digest, prepare, private_json)


RELEASE = 'ROOT_RELEASE_AZURE_NATIVE_FINAL_A79FF6F9'
FINDINGS = Path.home() / 'peaso-work/CODEX_FINDINGS.txt'
ARM = Path(__file__).with_name('azure_native_final_hosted_arm.py')


def released():
    return RELEASE in FINDINGS.read_text().splitlines()


def image_ready():
    result = subprocess.run(['docker', 'image', 'inspect', IMAGE,
        '--format', '{{.Os}}/{{.Architecture}}|{{json .RepoDigests}}'],
        capture_output=True, text=True)
    return result.returncode == 0 and result.stdout.startswith('linux/amd64|') and IMAGE in result.stdout


def checked_private(path, expected):
    path = Path(path)
    if not path.is_file() or path.stat().st_mode & 0o077 or digest(path) != expected:
        raise ValueError('private_input_unpinned_or_permissive:' + path.name)
    return path


def stage(common, ids, arm, number, credentials):
    directory = OUT / f'{arm}-run' / f'launch-{number:03d}'
    directory.mkdir(parents=True, exist_ok=False, mode=0o700)
    os.chmod(directory, 0o700)
    private_json(directory / 'findings.json', document(common, ids))
    shutil.copyfile(credentials, directory / 'credentials.json')
    os.chmod(directory / 'credentials.json', 0o600)
    return directory


def launch_one(directory, token):
    command = ['docker', 'run', '--rm', '--platform', 'linux/amd64',
               '--entrypoint', 'python', '--user', '0:0', '--cpus', '0.5',
               '--memory', '2g', '--pids-limit', '256', '--read-only',
               '--tmpfs', '/tmp:rw,noexec,nosuid,size=512m',
               '--env', 'PYTHONPATH=/app', '--env', 'AWS_EC2_METADATA_DISABLED=true',
               '--mount', f'type=bind,src={directory},dst=/workspace',
               '--mount', f'type=bind,src={token},dst=/run/secrets/platform-codex-token,readonly',
               '--mount', f'type=bind,src={ARM},dst=/run/azure_native_final_hosted_arm.py,readonly',
               IMAGE, '/run/azure_native_final_hosted_arm.py']
    result = subprocess.run(command, capture_output=True, text=True, timeout=510)
    if result.returncode or not (directory / 'result.json').is_file():
        raise RuntimeError(f'reviewer_launch_failed:{directory.name}:exit={result.returncode}')
    return (json.loads((directory / 'runtime-metrics.json').read_text()),
            json.loads((directory / 'result.json').read_text()))


def run_arm(common, plan, arm, token, credentials):
    rows = {row['id']: row for row in common['hardening']}
    queue = deque((ids, True) for ids in plan['initial_batches'])
    output, launches = {}, []
    root = OUT / f'{arm}-run'
    root.mkdir(mode=0o700, exist_ok=False)
    start = time.monotonic()
    with ThreadPoolExecutor(max_workers=6) as pool:
        pending = {}
        sequence = 0
        while queue or pending:
            if time.monotonic() - start > 1200:
                raise TimeoutError('paired_arm_budget_exceeded')
            while queue and len(pending) < 6:
                ids, grouped = queue.popleft()
                directory = stage(common, ids, arm, sequence, credentials)
                sequence += 1
                pending[pool.submit(launch_one, directory, token)] = (ids, grouped, directory)
            done, _ = wait(pending, timeout=20, return_when=FIRST_COMPLETED)
            for future in done:
                ids, grouped, directory = pending.pop(future)
                metric, data = future.result()
                checked = validate_reviews(data, [rows[ident] for ident in ids])['items']
                members = {ident: [rows[member] for member in plan['members'].get(ident, ())]
                           for ident in ids} if grouped else {}
                expanded, recheck = expand(checked, members)
                for review in expanded:
                    ident = review['finding_id']
                    if ident in output:
                        raise ValueError('duplicate_hosted_review')
                    output[ident] = review
                queue.extendleft((part, False) for part in reversed(chunks([row['id'] for row in recheck])))
                launches.append({'launch_id': directory.name, 'task_ids': ids, **metric})
    if set(output) != set(plan['selected_ids']):
        raise ValueError('hosted_review_coverage_mismatch')
    result = {'arm': arm, 'reviews': [output[ident] for ident in plan['selected_ids']],
              'launches': launches, 'wall_seconds': time.monotonic() - start,
              'model_calls': sum(row['model_calls'] for row in launches),
              'input_tokens': sum(row['input_tokens'] for row in launches),
              'output_tokens': sum(row['output_tokens'] for row in launches),
              'cpu_x_peak_rss_byte_seconds': sum(row['cpu_seconds'] * row['peak_rss_bytes']
                                                 for row in launches)}
    private_json(root / 'arm-result.json', result)
    return result


def summarize_pair(common, baseline, candidate):
    baseline_rows = {row['finding_id']: row for row in baseline['reviews']}
    candidate_rows = {row['finding_id']: row for row in candidate['reviews']}
    for ident in common['native_ids']:
        if ident in candidate_rows:
            raise ValueError('native_id_also_ai_reviewed')
        candidate_rows[ident] = {'finding_id': ident, 'verdict': 'FAIL', 'reason': ''}
    if set(baseline_rows) != set(candidate_rows):
        raise ValueError('pair_review_coverage_mismatch')
    verdict = sorted(ident for ident in baseline_rows
                     if baseline_rows[ident]['verdict'] != candidate_rows[ident]['verdict'])
    exact = sorted(ident for ident in baseline_rows
                   if baseline_rows[ident] != candidate_rows[ident])
    return {'version': 1, 'scan_id': common['report']['snapshot_id'],
            'baseline_ai_ids': len(baseline['reviews']),
            'candidate_ai_ids': len(candidate['reviews']),
            'synthetic_native_fail_ids': len(common['native_ids']),
            'combined_review_ids': len(candidate_rows),
            'verdict_difference_ids': verdict, 'exact_review_difference_ids': exact,
            'exact_review_parity': not exact,
            'baseline_model_calls': baseline['model_calls'],
            'candidate_model_calls': candidate['model_calls'],
            'baseline_input_tokens': baseline['input_tokens'],
            'candidate_input_tokens': candidate['input_tokens'],
            'baseline_wall_seconds': baseline['wall_seconds'],
            'candidate_wall_seconds': candidate['wall_seconds'],
            'action_parity_evaluated': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--preflight', action='store_true')
    mode.add_argument('--launch', action='store_true')
    parser.add_argument('--preflight-sha256')
    parser.add_argument('--token-file', type=Path)
    parser.add_argument('--token-sha256')
    parser.add_argument('--credentials-file', type=Path)
    parser.add_argument('--credentials-sha256')
    args = parser.parse_args()
    if args.launch and not released():
        raise PermissionError('root_model_slot_not_released')
    receipt = prepare(quiet=True)
    current = digest(OUT / 'preflight.json')
    if args.preflight:
        print(json.dumps({'preflight_sha256': current, 'image_local_ready': image_ready(),
                          'baseline': {key: receipt['baseline'][key] for key in
                                       ('ai_ids', 'representatives', 'initial_batches', 'initial_findings_json_bytes')},
                          'candidate': {key: receipt['candidate'][key] for key in
                                        ('ai_ids', 'representatives', 'initial_batches', 'initial_findings_json_bytes')},
                          'model': MODEL, 'effort': EFFORT, 'max_slots': 6,
                          'hosted_model_launched': False}, sort_keys=True))
        return
    if args.preflight_sha256 != current:
        raise ValueError('preflight_sha256_drift')
    if not image_ready():
        raise ValueError('pinned_production_image_not_local')
    if (not args.token_file or not args.token_sha256
            or not args.credentials_file or not args.credentials_sha256):
        raise ValueError('private_model_inputs_required')
    token = checked_private(args.token_file, args.token_sha256)
    credentials = checked_private(args.credentials_file, args.credentials_sha256)
    value = json.loads(credentials.read_text())
    if type(value) is not dict or value.get('version') != 2 or type(value.get('entries')) is not list:
        raise ValueError('invalid_stage_credentials')
    common = json.loads((OUT / 'common.json').read_text())
    plans = json.loads((OUT / 'plans.json').read_text())
    if digest(OUT / 'common.json') != receipt['common_sha256'] or digest(OUT / 'plans.json') != receipt['plans_sha256']:
        raise ValueError('private_plan_drift')
    results = {arm: run_arm(common, plans[arm], arm, token, credentials)
               for arm in ('baseline', 'candidate')}
    private_json(OUT / 'pair-result.json', summarize_pair(common, results['baseline'], results['candidate']))


if __name__ == '__main__':
    main()
