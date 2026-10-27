#!/usr/bin/env python3
"""Refresh exactly the 21 affected source pins in a private inactive 245-ID candidate."""
import argparse
import ast
import hashlib
import json
import os
from pathlib import Path
import subprocess


ROOT = Path(__file__).resolve().parents[1]
SOURCE_BASE_COMMIT = 'f36700a64738e951b1c3b14ae1c75196e31b9ef9'
SOURCE_CANDIDATE_SHA = 'ab7bd46933757283b859e6089f70a55afd6db6060a14cd673d085fa9aeef9d7a'
GUARD_PROOF = ROOT / 'docs/ai-review/native-final-detail-guards-992-proof.json'
PIN_RECEIPT = ROOT / 'docs/ai-review/native-final-245-source-pin-refresh-v1.json'
SOURCES = {
    'peaso/checks/batch_remaining_aws.py': (13, '_ecs'),
    'peaso/checks/claude_aws_a_s3.py': (8, 'prowler_acl_disabled'),
}
GUARDED_IDS = {'aws_g6_ecs_all_containers_logging', 'aws.claude_a.s3.prowler_acl_disabled'}


def sha(data):
    return hashlib.sha256(data).hexdigest()


def source_transition(path, changed_function):
    old = subprocess.check_output(['git', 'show', SOURCE_BASE_COMMIT + ':' + path], cwd=ROOT)
    new = (ROOT / path).read_bytes()
    before = ast.parse(old.decode())
    after = ast.parse(new.decode())
    def nodes(tree):
        return [(getattr(node, 'name', None), ast.dump(node, include_attributes=False))
                for node in tree.body]
    old_nodes, new_nodes = nodes(before), nodes(after)
    if len(old_nodes) != len(new_nodes):
        raise ValueError('unexpected source node change: ' + path)
    changes = [name for (name, a), (other, b) in zip(old_nodes, new_nodes)
               if name != other or a != b]
    if changes != [changed_function]:
        raise ValueError('unexpected source function changes: ' + path + ' ' + repr(changes))
    return {'old_source_sha256': sha(old), 'new_source_sha256': sha(new),
            'only_changed_function': changed_function,
            'all_other_top_level_source_ast_unchanged': True}


def write_private(path, value):
    data = (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, 'wb') as stream:
        os.fchmod(stream.fileno(), 0o600)
        stream.write(data)
    return sha(data)


def refresh(candidate_path, output_path):
    original = Path(candidate_path).read_bytes()
    if sha(original) != SOURCE_CANDIDATE_SHA:
        raise ValueError('original private hosted245 candidate changed')
    candidate = json.loads(original)
    if len(candidate['checks']) != 245 or candidate['replay_qualification']['status'] != 'pending':
        raise ValueError('candidate not the inactive hosted245 cohort')
    proof_raw = GUARD_PROOF.read_bytes()
    proof = json.loads(proof_raw)
    if (proof['hosted245_staged_common_sha256'] !=
            '00f7ea1881e72cd22cb7e57c6764a1e6cddb43fe6ce62ce667b84e0746468030'):
        raise ValueError('staged-input transfer proof missing')
    transitions = {path: source_transition(path, changed) for path, (_count, changed) in SOURCES.items()}
    entries = []
    for check in candidate['checks']:
        ident = check['check_id']
        code = check['deterministic_evidence']['code_path_audit_ref']
        path = code['path']
        if path not in SOURCES:
            continue
        transition = transitions[path]
        if code['source_sha256'] != transition['old_source_sha256']:
            raise ValueError('prior candidate source pin mismatch: ' + ident)
        entries.append({'check_id': ident, 'source_path': path,
                        'old_audit_receipt_sha256': check['audit_receipt_sha256'],
                        'old_audit_ref': code['audit_ref'],
                        'source_change': 'fail_closed_guard_with_exact_992_parity' if ident in GUARDED_IDS
                                         else 'evaluator_function_unchanged_whole_file_pin_refresh',
                        'new_source_sha256': transition['new_source_sha256']})
    for path, (expected, _changed) in SOURCES.items():
        if sum(row['source_path'] == path for row in entries) != expected:
            raise ValueError('affected candidate entry count changed: ' + path)
    if {row['check_id'] for row in entries if row['source_change'].startswith('fail_closed')} != GUARDED_IDS:
        raise ValueError('guarded check set changed')
    receipt = {'schema_version': 1, 'status': 'inactive_source_pin_refresh',
               'source_base_commit': SOURCE_BASE_COMMIT,
               'original_candidate_sha256': SOURCE_CANDIDATE_SHA,
               'exact_992_guard_proof_sha256': sha(proof_raw),
               'hosted245_staged_common_sha256': proof['hosted245_staged_common_sha256'],
               'source_transitions': transitions, 'affected_check_count': len(entries),
               'checks': sorted(entries, key=lambda row: row['check_id']),
               'scope': 'All other candidate entries and replay qualification stay unchanged.'}
    receipt_bytes = (json.dumps(receipt, sort_keys=True, indent=2) + '\n').encode()
    PIN_RECEIPT.write_bytes(receipt_bytes)
    receipt_sha = sha(receipt_bytes)
    for check in candidate['checks']:
        code = check['deterministic_evidence']['code_path_audit_ref']
        if code['path'] not in SOURCES:
            continue
        code['source_sha256'] = transitions[code['path']]['new_source_sha256']
        code['audit_ref'] = 'docs/ai-review/native-final-245-source-pin-refresh-v1.json#check_id=' + check['check_id']
        check['audit_receipt_sha256'] = receipt_sha
    candidate_sha = write_private(output_path, candidate)
    return {'affected_check_count': len(entries), 'source_pin_receipt_sha256': receipt_sha,
            'corrected_candidate_sha256': candidate_sha}


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('original_candidate')
    parser.add_argument('output_candidate')
    args = parser.parse_args()
    print(json.dumps(refresh(args.original_candidate, args.output_candidate), sort_keys=True))
