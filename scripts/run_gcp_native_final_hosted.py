#!/usr/bin/env python3
"""Pinned GCP paired reviewer harness; launch requires root's unique release line.

--preflight validates staged model inputs and runtime without model calls.
--launch runs paired arms only after ROOT_RELEASE_GCP_NATIVE_FINAL_0864235E is
present as an exact line in ~/peaso-work/CODEX_FINDINGS.txt.
"""
import argparse
from collections import deque
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time

from peaso.ai.collection_coverage import index
from peaso.ai.contracts import validate_reviews
from peaso.ai.pipeline import compact_document, findings_document, private_json, review_context
from peaso.ai.review_groups import chunks, expand

from scripts.prepare_gcp_native_final_hosted import IMAGE, MODEL, PRIVATE, ROOT, SCAN, SOURCE_FILES, sha


TOKEN = Path.home() / 'peaso-work/replay/platform-codex-token.txt'
ARM = Path.home() / 'peaso-work/replay/hardening_84_container_arm.py'
RELEASE = 'ROOT_RELEASE_GCP_NATIVE_FINAL_0864235E'
FINDINGS = Path.home() / 'peaso-work/CODEX_FINDINGS.txt'


def load_pins():
    receipt = json.loads((PRIVATE / 'gcp-hosted-preflight.json').read_text())
    common_path, plans_path = PRIVATE / 'gcp-hosted-common.json', PRIVATE / 'gcp-hosted-plans.json'
    if (receipt['mode'] != 'offline_preflight_only' or receipt['hosted_model_launched']
            or receipt['scan_id'] != SCAN or receipt['image_id'] != IMAGE
            or receipt['model'] != MODEL or receipt['max_model_slots'] != 6
            or sha(common_path) != receipt['common_sha256']
            or sha(plans_path) != receipt['plans_sha256']
            or sha(ROOT / 'peaso/ai/gcp_native_final_allowlist.json') !=
               json.loads(common_path.read_text())['manifest_sha256']):
        raise ValueError('GCP hosted preflight pin drift')
    head = subprocess.check_output(['git', '-C', str(ROOT), 'rev-parse', 'HEAD'], text=True).strip()
    dirty = subprocess.check_output(['git', '-C', str(ROOT), 'status', '--porcelain'], text=True).strip()
    if head != receipt['source_head'] or dirty:
        raise ValueError('source head or clean status changed')
    if {name: sha(ROOT / name) for name in SOURCE_FILES} != receipt['source_sha256']:
        raise ValueError('source bytes changed')
    return receipt, json.loads(common_path.read_text()), json.loads(plans_path.read_text())


def document(common, identifiers):
    by_id = {row['id']: row for row in common['hardening']}
    batch = [by_id[ident] for ident in identifiers]
    context = review_context(common['report'], common['resources'], batch,
                             _coverage=index(common['report']['coverage']))
    return compact_document(findings_document(context['scan'], batch, context['resources']))


def planned_documents(common, plans):
    result = {}
    for name in ('baseline', 'candidate'):
        plan = plans[name]
        all_ids = set(plan['selected_ids'])
        reps = [ident for batch in plan['initial_batches'] for ident in batch]
        members = {ident for rows in plan['members'].values() for ident in rows}
        if (len(reps) != len(set(reps)) or set(reps) != set(plan['representative_ids'])
                or set(reps) | members != all_ids):
            raise ValueError('group plan changed')
        hashes, sizes = [], []
        for identifiers in plan['initial_batches']:
            doc = document(common, identifiers)
            if {row['id'] for row in doc['items']} != set(identifiers):
                raise ValueError('model document IDs changed')
            encoded = json.dumps(doc, sort_keys=True, separators=(',', ':')).encode()
            hashes.append(hashlib.sha256(encoded).hexdigest())
            sizes.append(len(encoded))
        result[name] = {'selected_rows': len(all_ids), 'representatives': len(reps),
                        'initial_batches': len(hashes), 'document_sha256': hashes,
                        'initial_document_bytes': sum(sizes)}
    return result


def runtime_preflight():
    if subprocess.check_output(['docker', 'image', 'inspect', IMAGE, '--format',
                                '{{.Id}}|{{.Os}}/{{.Architecture}}|{{.Config.User}}'],
                               text=True).strip() != IMAGE + '|linux/amd64|10001:10001':
        raise ValueError('pinned image identity changed')
    if TOKEN.stat().st_mode & 0o777 != 0o600 or not TOKEN.is_file():
        raise ValueError('private model credential unavailable')
    # Reuse the previously pinned b09 runner/prompt/model-catalog preflight.
    sys.path.insert(0, str(Path.home() / 'peaso-work/replay'))
    from run_paired_hardening_84_992 import runtime_preflight as pinned_runtime_preflight
    runtime = pinned_runtime_preflight()
    if (runtime['image_id'] != IMAGE or not runtime['gpt_5_6_sol_offered']
            or runtime['per_reviewer_vcpu'] != 0.5
            or runtime['per_reviewer_memory_bytes'] != 2 * 1024**3):
        raise ValueError('pinned reviewer runtime changed')
    return {key: runtime[key] for key in
            ('image_id', 'architecture', 'per_reviewer_vcpu',
             'per_reviewer_memory_bytes', 'max_reviewer_slots',
             'credential_sha256', 'model_catalog_http_status')}


def stage(common, name, number, identifiers):
    directory = PRIVATE / f'gcp-hosted-{name}' / f'launch-{number:03d}'
    directory.mkdir(parents=True, mode=0o700, exist_ok=False)
    private_json(directory / 'findings.json', document(common, identifiers))
    private_json(directory / 'credentials.json', {'version': 2, 'entries': []})
    return directory


def launch_one(directory):
    command = ['docker', 'run', '--rm', '--platform', 'linux/amd64',
               '--entrypoint', 'python', '--user', '0:0', '--cpus', '0.5',
               '--memory', '2g', '--pids-limit', '256', '--read-only',
               '--tmpfs', '/tmp:rw,noexec,nosuid,size=512m',
               '--env', 'PYTHONPATH=/app', '--env', 'AWS_EC2_METADATA_DISABLED=true',
               '--mount', f'type=bind,src={directory},dst=/workspace',
               '--mount', f'type=bind,src={TOKEN},dst=/run/secrets/platform-codex-token,readonly',
               '--mount', f'type=bind,src={ARM},dst=/run/hardening_84_container_arm.py,readonly',
               IMAGE, '/run/hardening_84_container_arm.py']
    completed = subprocess.run(command, capture_output=True, text=True, timeout=510)
    if completed.returncode or not (directory / 'result.json').is_file():
        raise RuntimeError(f'GCP reviewer launch failed: {directory.name}: {completed.returncode}')
    return (json.loads((directory / 'runtime-metrics.json').read_text()),
            json.loads((directory / 'result.json').read_text()))


def run_arm(common, plan, name):
    by_id = {row['id']: row for row in common['hardening']}
    queue = deque((batch, True) for batch in plan['initial_batches'])
    output, launches = {}, []
    start = time.monotonic()
    directory = PRIVATE / f'gcp-hosted-{name}'
    directory.mkdir(mode=0o700, exist_ok=False)
    with ThreadPoolExecutor(max_workers=6) as pool:
        pending = {}
        while queue or pending:
            if time.monotonic() - start > 1200:
                raise TimeoutError('GCP arm exceeded 1200 seconds')
            while queue and len(pending) < 6:
                identifiers, grouped = queue.popleft()
                work = stage(common, name, len(launches) + len(pending), identifiers)
                pending[pool.submit(launch_one, work)] = (identifiers, grouped, work)
            done, _ = wait(pending, timeout=20, return_when=FIRST_COMPLETED)
            for future in done:
                identifiers, grouped, work = pending.pop(future)
                metric, data = future.result()
                checked = validate_reviews(data, [by_id[ident] for ident in identifiers])['items']
                expanded, recheck = expand(checked, {
                    ident: [by_id[member] for member in plan['members'].get(ident, ())]
                    for ident in identifiers} if grouped else {})
                for review in expanded:
                    ident = review['finding_id']
                    if ident in output:
                        raise ValueError('duplicate model result ID')
                    output[ident] = review
                queue.extendleft((part, False) for part in reversed(
                    chunks([row['id'] for row in recheck])))
                launches.append({'launch_id': work.name, 'task_ids': identifiers, **metric})
    if set(output) != set(plan['selected_ids']):
        raise ValueError('model result coverage differs')
    result = {'arm': name, 'reviews': [output[ident] for ident in plan['selected_ids']],
              'launches': launches, 'wall_seconds': time.monotonic() - start,
              'model_calls': sum(row['model_calls'] for row in launches),
              'input_tokens': sum(row['input_tokens'] for row in launches),
              'output_tokens': sum(row['output_tokens'] for row in launches),
              'cpu_x_peak_rss_byte_seconds': sum(row['cpu_seconds'] * row['peak_rss_bytes']
                                                 for row in launches)}
    private_json(directory / 'arm-result.json', result)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--preflight', action='store_true')
    mode.add_argument('--launch', action='store_true')
    args = parser.parse_args()
    receipt, common, plans = load_pins()
    documents = planned_documents(common, plans)
    runtime = runtime_preflight()
    if args.preflight:
        print(json.dumps({'projection': receipt['projection'],
                          'documents': {name: {key: row[key] for key in
                                        ('selected_rows', 'representatives', 'initial_batches',
                                         'initial_document_bytes')}
                                        for name, row in documents.items()},
                          'runtime': {key: runtime[key] for key in
                                      ('image_id', 'architecture', 'max_reviewer_slots')},
                          'hosted_model_launched': False}, sort_keys=True))
        return
    if RELEASE not in {line.strip() for line in FINDINGS.read_text().splitlines()}:
        raise PermissionError('exclusive GCP model slot not released by root')
    for name in ('baseline', 'candidate'):
        run_arm(common, plans[name], name)


if __name__ == '__main__':
    main()
