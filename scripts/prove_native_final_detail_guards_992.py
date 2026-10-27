#!/usr/bin/env python3
"""Offline exact-992 parity proof for the ECS and S3 detail-status guards."""
import collections
import gzip
import hashlib
import json
from pathlib import Path
import sys

import ijson

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from peaso.checks import evaluate_check


ROOT = Path(__file__).resolve().parents[1]
SNAPSHOT_SHA = '3d7828c701a9457eeeb7d5aa497e1efd07a7977ccddeed498a73a2ba9dc2592f'
PRE_AI_SHA = '4dcaa76a21c6b3bfff2b4859c1d4c763964c92c69041fe2d95702315fffde2ba'
STAGED_COMMON_SHA = '00f7ea1881e72cd22cb7e57c6764a1e6cddb43fe6ce62ce667b84e0746468030'
CHECKS = {
    'aws_g6_ecs_all_containers_logging': ('ecs_task_definition', 'Definition', 4684, 13),
    'aws.claude_a.s3.prowler_acl_disabled': ('bucket', 'OwnershipControls', 148, 3),
}


def prove(snapshot_path, pre_ai_path, staged_common_path):
    if hashlib.sha256(Path(snapshot_path).read_bytes()).hexdigest() != SNAPSHOT_SHA:
        raise ValueError('exact 992 snapshot changed')
    if hashlib.sha256(Path(pre_ai_path).read_bytes()).hexdigest() != PRE_AI_SHA:
        raise ValueError('exact 992 pre-AI report changed')
    if hashlib.sha256(Path(staged_common_path).read_bytes()).hexdigest() != STAGED_COMMON_SHA:
        raise ValueError('hosted245 staged Hardening input bytes changed')
    staged = json.loads(Path(staged_common_path).read_text())
    staged_cohorts = {}
    for check in CHECKS:
        cohort = [row for row in staged['hardening'] if row['check_id'] == check]
        encoded = json.dumps(cohort, sort_keys=True, separators=(',', ':')).encode()
        staged_cohorts[check] = {'staged_row_count': len(cohort),
                                 'canonical_staged_rows_sha256': hashlib.sha256(encoded).hexdigest()}
    by_kind = collections.defaultdict(dict)
    detail_status = collections.defaultdict(collections.Counter)
    with gzip.open(snapshot_path, 'rb') as stream:
        for collection in ijson.items(stream, 'collections.item'):
            kind = collection.get('type')
            if kind not in {'bucket', 'ecs_task_definition'}:
                continue
            if collection.get('status') != 'collected':
                raise ValueError('source collection incomplete: ' + kind)
            scope = collection['scope']
            for item in collection.get('items') or []:
                identity = item.get('id') if kind == 'ecs_task_definition' else item.get('Name')
                key = (scope, identity)
                if key in by_kind[kind]:
                    raise ValueError('duplicate exact resource')
                by_kind[kind][key] = item
                field = 'Definition' if kind == 'ecs_task_definition' else 'OwnershipControls'
                detail = item.get(field)
                detail_status[kind][detail.get('collection_status') if isinstance(detail, dict) else None] += 1
    if (detail_status['ecs_task_definition'] != {'collected': 4684}
            or detail_status['bucket'] != {'collected': 147, 'empty': 1}):
        raise ValueError('exact 992 nested status coverage changed')
    counts = collections.Counter()
    fail_counts = collections.Counter()
    exact_ids = collections.defaultdict(list)
    with gzip.open(pre_ai_path, 'rb') as stream:
        for group in ijson.items(stream, 'findings.item'):
            for row in group.get('observations') or [group]:
                check = row.get('check_id')
                if check not in CHECKS:
                    continue
                kind, field, _expected, _expected_fails = CHECKS[check]
                scope = row['scope']
                item = by_kind[kind].get((scope, row['native_resource_id']))
                if item is None or row.get('status') not in ('PASS', 'FAIL'):
                    raise ValueError('exact finding ID or resource missing: ' + check)
                detail = item[field]
                if detail.get('collection_status') not in ('collected', 'empty'):
                    raise ValueError('FAIL detail not complete: ' + check)
                index = {}
                if kind == 'ecs_task_definition':
                    wrapper = {'provider': 'aws', 'type': kind, 'scope': scope, 'data': item}
                    index = {'context': {'provider': 'aws', 'scope': scope},
                             'collections': {kind: [{'type': kind, 'scope': scope,
                                                      'status': 'collected', 'items': [item]}]},
                             kind: [wrapper]}
                status, evidence = evaluate_check(check, item, index)
                if (status, evidence) != (row['status'], row['evidence']):
                    raise ValueError('exact 992 verdict/evidence parity changed: ' + check)
                counts[check] += 1
                fail_counts[check] += row['status'] == 'FAIL'
                exact_ids[check].append(row['id'])
    for check, (_kind, _field, expected, expected_fails) in CHECKS.items():
        if (counts[check] != expected or len(set(exact_ids[check])) != expected
                or fail_counts[check] != expected_fails
                or staged_cohorts[check]['staged_row_count'] != expected_fails):
            raise ValueError('exact native FAIL coverage changed: ' + check)
    return {
        'snapshot_sha256': SNAPSHOT_SHA, 'pre_ai_report_sha256': PRE_AI_SHA,
        'check_proofs': [
            {'check_id': check, 'exact_native_finding_count': counts[check],
             'exact_native_fail_count': fail_counts[check],
             'exact_finding_ids_sha256': hashlib.sha256('\n'.join(sorted(exact_ids[check])).encode()).hexdigest(),
             'verdict_and_evidence_parity_count': counts[check],
             'detail_status_counts': dict(detail_status[kind]),
             **staged_cohorts[check],
             'evaluator_path': ('peaso/checks/batch_remaining_aws.py' if kind == 'ecs_task_definition'
                                else 'peaso/checks/claude_aws_a_s3.py'),
             'evaluator_source_sha256': hashlib.sha256((ROOT / ('peaso/checks/batch_remaining_aws.py'
                                      if kind == 'ecs_task_definition' else 'peaso/checks/claude_aws_a_s3.py')).read_bytes()).hexdigest()}
            for check, (kind, _field, _expected, _expected_fails) in CHECKS.items()],
        'model_calls': 0, 'manifest_activation': False,
        'hosted245_staged_common_sha256': STAGED_COMMON_SHA,
        'staged_input_transfer': 'The saved exact-992 Hardening common input is byte-identical to the pre-fix hosted245 audit pin. Neither evaluator edit changes this staged file or its two affected check-ID cohorts; the completed hosted245 model token/cost receipt applies to those unchanged staged bytes. A newly generated manifest still requires source-hash revalidation.',
    }


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('snapshot')
    parser.add_argument('pre_ai_report')
    parser.add_argument('--staged-common', required=True)
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    result = prove(args.snapshot, args.pre_ai_report, args.staged_common)
    Path(args.output).write_text(json.dumps(result, sort_keys=True, indent=2) + '\n')
    print(json.dumps({r['check_id']: r['exact_native_fail_count'] for r in result['check_proofs']}))
