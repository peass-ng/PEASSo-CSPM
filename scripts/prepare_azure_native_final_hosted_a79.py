"""Build private paired Azure Hardening reviewer plans; never call a model.

The saved scan reports are exact, but their ephemeral AI input bundle is not
retained. Both arms use the same reconstructed document builder and source.
"""

import gzip
import hashlib
import json
import os
from pathlib import Path
import subprocess

from peaso.ai.collection_coverage import index as coverage_index
from peaso.ai.native_final_azure import EXPECTED, partition
from peaso.ai.pipeline import compact_document, findings_document, referenced_strings, review_context
from peaso.ai.review_groups import chunks, plan
from peaso.engine import hydrate_finding


ROOT = Path.home() / 'peaso-work/native-final-azure-private'
SCAN = 'a79ff6f9331246bd9e4f4bf6ba6fa207'
SOURCE = ROOT / SCAN
OUT = ROOT / 'hosted-a79'
ARTIFACTS = {
    'snapshot-a777a7319eda467bacdfbe5ea512371b.json': '8117ca71b27fa60dc9f4d370fb7e60bcd7cdacce36d3f567079f20519861ac78',
    'report-99f46be9f0774097b980177bc3a366ee.json': '9ed2de0adc5adde4255108177745f76fe87796ad4ec3ca4d8d7febe6a44e84af',
    'report-69052a550aef4494abea18a0cdf75f58.json': '452f7d615cbfa23bed95b6943aefa1242e7016c62dd879dd0a62b2919f2dd1b9',
}
SOURCE_PINS = {
    'peaso/ai/native_final_azure.py': '7fb7a7726211aa5642e426bc26133c2f349d1b65efd6424581349ce73ae89d98',
    'peaso/ai/native_final_azure_allowlist.json': 'ebc4afe73f78dc82ec62ee5013a8e63b55dd3524ba69bfdbb04253f42d925d16',
    'peaso/ai/pipeline.py': 'adc422cd6261a8c7379263097799168589e42990d485ac5a78f8bea7c0c87c9d',
    'peaso/ai/agents/hardening.yaml': '0e1fe6a88266da5f88e06509f843f056ca5e22ddbc25094bd7583a5664327844',
    'peaso/ai/_vendor/chack/model_aliases.py': '9b1002a9d5e81127c45ea3300305d4c76bf68103bc1088ad4f4752340e0359c7',
    'docs/ai-review/native-final-azure-saved-replay-v1.json': '0fc6a237c18fb47d83b33774cd90c7747f2e10862f9493ac10c3ff4ee8f7af56',
}
IMAGE = '202533532952.dkr.ecr.us-east-1.amazonaws.com/hacktricks-cspm-worker@sha256:eca921607a21ead7acf1ad02c55a6d151cc2e252fc14db8300db8dcfc47b38d6'
MODEL = 'gpt-5.6-sol'
EFFORT = 'high'


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def private_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(path.parent, 0o700)
    temp = path.with_name(path.name + '.tmp')
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w') as stream:
        json.dump(value, stream, sort_keys=True, separators=(',', ':'), default=str)
        stream.write('\n')
    os.replace(temp, path)
    os.chmod(path, 0o600)


def read_saved(name):
    path = SOURCE / name
    if digest(path) != ARTIFACTS[name]:
        raise ValueError('saved_artifact_sha256_drift:' + name)
    raw = path.read_bytes()
    return json.loads(gzip.decompress(raw) if raw[:2] == b'\x1f\x8b' else raw)


def document(common, batch):
    by_id = {row['id']: row for row in common['hardening']}
    rows = [by_id[ident] for ident in batch]
    context = review_context(common['report'], common['resources'], rows,
                             _coverage=coverage_index(common['report']['coverage']))
    return compact_document(findings_document(context['scan'], rows, context['resources']))


def prepare(repo=None, *, quiet=False):
    repo = Path(__file__).resolve().parents[1] if repo is None else Path(repo)
    for name, expected in SOURCE_PINS.items():
        if digest(repo / name) != expected:
            raise ValueError('source_pin_drift:' + name)
    snapshot = read_saved('snapshot-a777a7319eda467bacdfbe5ea512371b.json')
    pre = read_saved('report-99f46be9f0774097b980177bc3a366ee.json')
    final = read_saved('report-69052a550aef4494abea18a0cdf75f58.json')
    if (pre.get('provider') != 'azure' or snapshot.get('provider') != 'azure'
            or pre.get('snapshot_id') != final.get('snapshot_id')
            or pre.get('snapshot_id') != snapshot.get('snapshot_id')):
        raise ValueError('same_scan_contract_drift')
    manifest = json.loads((repo / 'peaso/ai/native_final_azure_allowlist.json').read_text())
    if (manifest['replay_qualification']['status'] != 'pending'
            or {row['check_id'] for row in manifest['checks']} != set(EXPECTED)):
        raise ValueError('candidate_manifest_not_pending')
    raw_rows = [row for group in pre['findings']
                for row in group.get('observations') or [group]
                if row.get('category') == 'hardening' and row.get('status') == 'FAIL']
    all_rows = [hydrate_finding(row, pre.get('check_frameworks'), pre.get('check_meta'),
                pre.get('check_meta_encoding'), pre.get('remediation_templates')) for row in raw_rows]
    stage_ids = final['ai']['stage_inputs']['hardening']
    if len(all_rows) != 434 or len({row['id'] for row in all_rows}) != 434 or set(stage_ids) != {row['id'] for row in all_rows}:
        raise ValueError('hardening_stage_input_drift')
    native, remaining = partition(all_rows, set(EXPECTED), pre.get('coverage'))
    if len(native) != 21 or len(remaining) != 413:
        raise ValueError('candidate_partition_drift')
    referenced = set(referenced_strings(all_rows))
    inventory = {row['id']: row for row in pre.get('resources', []) if row.get('id') in referenced}
    common = {
        'report': {key: pre[key] for key in ('provider', 'snapshot_id', 'created_at', 'coverage')},
        'hardening': all_rows, 'resources': inventory,
        'native_ids': sorted(row['id'] for row in native),
        'source_artifacts_sha256': ARTIFACTS, 'source_files_sha256': SOURCE_PINS,
    }
    plans, summary = {}, {}
    for arm, rows in (('baseline', all_rows), ('candidate', remaining)):
        reps, members = plan(rows)
        batches = chunks(reps)
        plans[arm] = {
            'selected_ids': sorted(row['id'] for row in rows),
            'representative_ids': [row['id'] for row in reps],
            'members': {ident: [row['id'] for row in group] for ident, group in members.items()},
            'initial_batches': [[row['id'] for row in batch] for batch in batches],
        }
        sizes, hashes = [], []
        for batch in plans[arm]['initial_batches']:
            payload = json.dumps(document(common, batch), sort_keys=True, separators=(',', ':'), default=str).encode()
            sizes.append(len(payload))
            hashes.append(hashlib.sha256(payload).hexdigest())
        summary[arm] = {'ai_ids': len(rows), 'representatives': len(reps),
                        'initial_batches': len(batches),
                        'initial_findings_json_bytes': sum(sizes),
                        'batch_bytes': sizes, 'batch_sha256': hashes}
    private_json(OUT / 'common.json', common)
    private_json(OUT / 'plans.json', plans)
    receipt = {'version': 1, 'mode': 'offline_preflight_only', 'scan_id': SCAN,
               'source_artifacts_sha256': ARTIFACTS, 'source_files_sha256': SOURCE_PINS,
               'harness_source_sha256': {name: digest(repo / 'scripts' / name) for name in (
                   'prepare_azure_native_final_hosted_a79.py',
                   'run_azure_native_final_hosted_a79.py',
                   'azure_native_final_hosted_arm.py')},
               'repo_head': subprocess.check_output(['git', '-C', str(repo), 'rev-parse', 'HEAD'], text=True).strip(),
               'snapshot_id': snapshot['snapshot_id'],
               'image': IMAGE, 'task_definition': 'hacktricks-cspm-ai:52',
               'model': MODEL, 'thinking_effort': EFFORT,
               'architecture': 'linux/amd64', 'per_task_vcpu': 0.5,
               'per_task_memory_bytes': 2 * 1024**3, 'max_slots': 6,
               'baseline': summary['baseline'], 'candidate': summary['candidate'],
               'native_synthetic_fail_rows': len(native),
               'common_sha256': digest(OUT / 'common.json'),
               'plans_sha256': digest(OUT / 'plans.json'),
               'hosted_model_launched': False, 'cloud_write': False,
               'input_reconstruction': 'same saved snapshot and pre-AI report; original ephemeral stage files not retained'}
    private_json(OUT / 'preflight.json', receipt)
    if not quiet:
        print(json.dumps({'scan_id': SCAN, 'baseline_ai_ids': summary['baseline']['ai_ids'],
                          'candidate_ai_ids': summary['candidate']['ai_ids'],
                          'baseline_batches': summary['baseline']['initial_batches'],
                          'candidate_batches': summary['candidate']['initial_batches'],
                          'hosted_model_launched': False}, sort_keys=True))
    return receipt


if __name__ == '__main__':
    prepare()
