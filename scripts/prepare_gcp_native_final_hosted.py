#!/usr/bin/env python3
"""Prepare private same-snapshot GCP Hardening arms; never launch a model."""
import gzip
import hashlib
import json
import os
from pathlib import Path
import subprocess

from peaso.ai.gcp_native_final import MANIFEST, candidate_check_ids, partition
from peaso.ai.pipeline import inputs, referenced_strings
from peaso.ai.review_groups import chunks, expand, plan


ROOT = Path(__file__).resolve().parents[1]
PRIVATE = Path.home() / 'peaso-work/native-final-gcp-private'
SCAN = '0864235ed9db4305a594e55bf8bceb82'
IMAGE = 'sha256:ad277f7ec3677d5e78bf723d42256ea41f69528309483a07304b64914111e312'
MODEL = {'provider': 'codex', 'model': 'gpt-5.6-sol', 'thinking': 'high'}
SOURCE_FILES = ('peaso/ai/pipeline.py', 'peaso/ai/review_groups.py',
                'peaso/ai/contracts.py', 'peaso/ai/gcp_native_final.py',
                'peaso/ai/gcp_native_final_allowlist.json')


def sha(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(8 << 20), b''):
            h.update(block)
    return h.hexdigest()


def private_json(path, value):
    path = Path(path)
    if path.exists():
        path.unlink()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w') as stream:
        json.dump(value, stream, sort_keys=True, separators=(',', ':'), default=str)
        stream.write('\n')


def main():
    if subprocess.check_output(['git', '-C', str(ROOT), 'status', '--porcelain'], text=True).strip():
        raise ValueError('source worktree is dirty')
    head = subprocess.check_output(['git', '-C', str(ROOT), 'rev-parse', 'HEAD'], text=True).strip()
    pre = PRIVATE / f'{SCAN}-pre-ai.json.gz'
    final = PRIVATE / f'{SCAN}-final.json.gz'
    snapshot = PRIVATE / f'{SCAN}-snapshot.json.gz'
    offline = json.loads((ROOT / 'docs/ai-review/native-final-gcp-offline-replay-v1.json').read_text())
    pair = next(row for row in offline['scans'] if row['scan_id'] == SCAN)
    if (sha(pre) != pair['pre_ai_sha256'] or sha(final) != pair['final_sha256']
            or sha(MANIFEST) != offline['manifest_sha256']
            or sha(snapshot) != 'a96f9f8a513c11978b5f63901ae55244af7fb83ddc5c9308278a1b282902b8f0'
            or candidate_check_ids() != frozenset({
                'gcp.compute.secure_boot', 'gcp.gke.secrets_encryption',
                'gcp.network.custom_subnets', 'gcp.reviewed.compute.deletion_protection'})):
        raise ValueError('saved source or candidate pin changed')
    with gzip.open(pre, 'rt') as stream:
        before = json.load(stream)
    with gzip.open(final, 'rt') as stream:
        after = json.load(stream)
    with gzip.open(snapshot, 'rt') as stream:
        captured = json.load(stream)
    if (before['snapshot_id'] != after['snapshot_id']
            or before['snapshot_id'] != captured['snapshot_id']
            or {before['provider'], after['provider'], captured['provider']} != {'gcp'}):
        raise ValueError('snapshot binding changed')
    flat = [row for group in before['findings']
            for row in (group.get('observations') or [group])]
    report = dict(before, findings=flat)
    hardening, exposure, _ = inputs(report)
    selected, remaining = partition(hardening, candidate_check_ids())
    if (len(hardening) != 265 or len(selected) != 7 or len(remaining) != 258
            or set(after['ai']['stage_inputs']['hardening']) != {row['id'] for row in hardening}
            or set(after['ai']['stage_inputs']['exposure']) != {row['id'] for row in exposure}):
        raise ValueError('GCP baseline queue changed')
    referenced = set(referenced_strings(hardening))
    resources = {row['id']: row for row in before['resources'] if row['id'] in referenced}
    common = {'report': {key: before[key] for key in
                        ('provider', 'snapshot_id', 'created_at', 'coverage')},
              'hardening': hardening, 'resources': resources,
              'native_ids': sorted(row['id'] for row in selected),
              'scan_id': SCAN, 'source_head': head,
              'source_sha256': {name: sha(ROOT / name) for name in SOURCE_FILES},
              'pre_ai_sha256': sha(pre), 'final_sha256': sha(final),
              'snapshot_sha256': sha(snapshot), 'manifest_sha256': sha(MANIFEST)}
    plans, projection = {}, {}
    saved_reviews = {row['finding_id']: row for row in after['ai']['reviews']['hardening']}
    for name, rows in (('baseline', hardening), ('candidate', remaining)):
        reps, members = plan(rows)
        batches = chunks(reps)
        _, recheck = expand([saved_reviews[row['id']] for row in reps], members)
        plans[name] = {'selected_ids': sorted(row['id'] for row in rows),
                       'representative_ids': [row['id'] for row in reps],
                       'members': {ident: [row['id'] for row in values]
                                   for ident, values in members.items()},
                       'initial_batches': [[row['id'] for row in batch] for batch in batches]}
        projection[name] = {'model_rows': len(rows), 'initial_representatives': len(reps),
                            'initial_batches': len(batches),
                            'saved_verdict_recheck_rows': len(recheck),
                            'saved_verdict_recheck_batches': len(chunks(recheck)),
                            'saved_verdict_total_batches': len(batches) + len(chunks(recheck))}
    common_path, plans_path = PRIVATE / 'gcp-hosted-common.json', PRIVATE / 'gcp-hosted-plans.json'
    private_json(common_path, common)
    private_json(plans_path, plans)
    receipt = {'schema_version': 1, 'mode': 'offline_preflight_only',
               'scan_id': SCAN, 'source_head': head,
               'source_sha256': common['source_sha256'],
               'common_sha256': sha(common_path), 'plans_sha256': sha(plans_path),
               'image_id': IMAGE, 'model': MODEL, 'architecture': 'linux/amd64',
               'reviewer_vcpu': 0.5, 'reviewer_memory_bytes': 2 * 1024**3,
               'max_model_slots': 6, 'projection': projection,
               'saved_action_count': len(after['ai']['actions']),
               'hosted_model_launched': False, 'production_scan_started': False}
    private_json(PRIVATE / 'gcp-hosted-preflight.json', receipt)
    print(json.dumps({'scan_id': SCAN, 'projection': projection,
                      'hosted_model_launched': False}, sort_keys=True))


if __name__ == '__main__':
    main()
