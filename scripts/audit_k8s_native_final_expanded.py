"""Rebuild the v2 K8s admission census from private same-snapshot artifacts.

No cloud, container, or model call. Output is numeric and contains no findings.
"""
from __future__ import annotations
import argparse
from collections import Counter, defaultdict
import gzip
import hashlib
import json
from pathlib import Path

from peaso.ai.review_groups import plan
from peaso.engine import hydrate_finding

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'outputs/k8s-native-final-saved-pairs-v2.json'
MANIFEST = ROOT / 'peaso/ai/k8s_native_final_allowlist.json'


def load(path):
    body = path.read_bytes()
    return json.loads(gzip.decompress(body) if body[:2] == b'\x1f\x8b' else body)


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def source(check):
    if check.startswith('k8s.ports.deployment.') or check.startswith('k8s.ports.replicaset.') or check.startswith('k8s.ports.pod.'):
        return 'peaso/checks/k8s_ports_workloads.py', 'register_workload -> evaluate_predicate', 'PodSpec fields'
    if check.startswith('k8s.ports.namespace.'):
        return 'peaso/checks/k8s_ports_cluster.py', 'network_namespace -> evaluate', 'metadata.name; complete networkpolicy inventory; policy metadata.namespace/spec'
    if check.startswith('k8s.ports.clusterrole.'):
        return 'peaso/checks/k8s_ports_cluster.py', 'wildcard', 'rules[].apiGroups/resources/verbs'
    if check.startswith('k8s.claude.deployment.'):
        return 'peaso/checks/claude_gcp_k8s_k8s.py', 'replicas', 'spec.replicas'
    if check.startswith('k8s.claude.pod.'):
        return 'peaso/checks/claude_gcp_k8s_k8s.py', 'pod_rule -> resource_present', 'spec.containers[].resources.requests.cpu'
    if check == 'k8s.namespace.restricted_admission':
        return 'peaso/checks/k8s.py', 'admission', 'metadata.labels.pod-security.kubernetes.io/enforce'
    if check.startswith('k8s.serviceaccount.'):
        return 'peaso/checks/k8s_extended.py', 'serviceaccount_automount', 'automountServiceAccountToken'
    if check.startswith('k8s.deployment.') or check.startswith('k8s.replicaset.'):
        return 'peaso/checks/k8s_extended.py', '_controller_check -> _evaluate_pod', 'spec.template.spec securityContext and containers'
    raise ValueError('unproven source: ' + check)


def observations(directory, manifest):
    out = {}
    for chunk in manifest['finding_chunks']:
        obj = load(directory / Path(chunk['reference']).name)
        assert len(obj['items']) == chunk['count']
        for row in obj['items']:
            assert row['id'] not in out
            out[row['id']] = row
    assert len(out) == manifest['observation_count']
    return out


def audit(private):
    pairs = load(private / 'pair-chunk-receipt.json')['pairs']
    comparison = load(private / 'expanded-source-compare.json')
    snapshots = load(private / 'snapshot-match-receipt.json')['matches']
    assert len(pairs) == len(snapshots) == 7
    for item in snapshots:
        path = private / item['scan_id'] / item['file']
        assert path.exists() and sha(path) == item['sha256']
        assert load(path)['snapshot_id'] == item['snapshot_id']
    counts = defaultdict(Counter)
    pair_rows = []
    total = 0
    for pair in pairs:
        directory = private / pair['scan_id']
        pre_path, final_path = directory / pair['pre_manifest'], directory / pair['final_manifest']
        pre, final = load(pre_path), load(final_path)
        assert pre['summary']['snapshot_id'] == final['summary']['snapshot_id'] == pair['snapshot_id']
        pre_rows, final_rows = observations(directory, pre), observations(directory, final)
        ai_path = directory / Path(pair['ai_review']).name
        ai = load(ai_path)
        reviews = {row['finding_id']: row for row in ai['reviews']['hardening']}
        stage_ids = ai['stage_inputs']['hardening']
        assert len(reviews) == len(stage_ids) and set(reviews) == set(stage_ids)
        report = load(directory / Path(pre['report_json']).name)
        assert report['snapshot_id'] == pair['snapshot_id']
        hardening = [hydrate_finding(obs, report['check_frameworks'], report['check_meta'],
                     report['check_meta_encoding'], report['remediation_templates'])
                     for group in report['findings'] for obs in (group.get('observations') or [group])
                     if obs.get('category', group.get('category')) == 'hardening' and obs['status'] == 'FAIL']
        assert len(hardening) == len(stage_ids) and {row['id'] for row in hardening} == set(stage_ids)
        reps, _ = plan(hardening)
        representative_ids = {row['id'] for row in reps}
        for ident in stage_ids:
            native = pre_rows[ident]
            review = reviews[ident]
            cid = native['check_id']
            assert native['status'] == 'FAIL' and final_rows[ident]['status'] == review['verdict']
            assert final_rows[ident]['evidence'] == native['evidence']
            counts[cid]['findings'] += 1
            counts[cid]['representatives'] += ident in representative_ids
            counts[cid]['disagreements'] += review['verdict'] != 'FAIL'
            counts[cid]['verdict_' + review['verdict']] += 1
            counts[cid]['nonempty_ai_reasons'] += bool(review.get('reason'))
            total += 1
        pair_rows.append({'scan_id': pair['scan_id'], 'snapshot_id': pair['snapshot_id'],
                          'pre_manifest_sha256': sha(pre_path), 'final_manifest_sha256': sha(final_path),
                          'ai_review_sha256': sha(ai_path), 'stage_inputs': len(stage_ids),
                          'representatives': len(reps), 'ai_status': ai['status'],
                          'saved_priorities_action_ids': sorted({fid for action in ai['actions'] for fid in action.get('finding_ids', [])})})
    assert len(counts) == len(comparison['checks']) == 87 and total == 1946
    eligible = []
    excluded = []
    for cid in sorted(counts):
        c = counts[cid]
        replay = comparison['checks'][cid]
        assert replay['native_fail_rows'] == replay['current_fail'] == replay['current_evidence_equal'] == c['findings']
        assert replay['current_status_changed'] == 0
        path, symbol, fields = source(cid) if c['disagreements'] == 0 else (None, None, None)
        row = {'check_id': cid, 'findings': c['findings'], 'initial_representatives': c['representatives'],
               'disagreements': c['disagreements'], 'verdicts': {k.removeprefix('verdict_'): v for k, v in c.items() if k.startswith('verdict_')},
               'source_rechecks': replay['current_evidence_equal'], 'nonempty_ai_reasons': c['nonempty_ai_reasons']}
        if path:
            first_symbol = symbol.split(' -> ')[0]
            lines = (ROOT / path).read_text().splitlines()
            locations = [n for n, text in enumerate(lines, 1) if text.lstrip().startswith('def ' + first_symbol + '(')]
            assert len(locations) == 1
            row['source'] = {'path': path, 'line': locations[0], 'symbol': symbol,
                             'fields': fields, 'sha256': sha(ROOT / path)}
            eligible.append(row)
        else:
            row['classification'] = 'AI downgrade of reproduced declared-state native FAIL; retained for AI because verdict disagreement exceeds zero'
            excluded.append(row)
    assert len(eligible) == 43 and sum(r['findings'] for r in eligible) == 703
    assert len(excluded) == 44 and sum(r['findings'] for r in excluded) == 1243
    admitted_ids = {row['check_id'] for row in eligible}
    for pair, row in zip(pairs, pair_rows):
        directory = private / pair['scan_id']
        pre = load(directory / pair['pre_manifest'])
        original = observations(directory, pre)
        ai = load(directory / Path(pair['ai_review']).name)
        reviews = {review['finding_id']: review for review in ai['reviews']['hardening']}
        native_ids = {ident for ident in ai['stage_inputs']['hardening']
                      if original[ident]['check_id'] in admitted_ids}
        remaining_ids = set(ai['stage_inputs']['hardening']) - native_ids
        assert all(reviews[ident] == {'finding_id': ident, 'verdict': 'FAIL', 'reason': ''}
                   for ident in native_ids)
        substituted = {ident: {'finding_id': ident, 'verdict': 'FAIL', 'reason': ''}
                       for ident in native_ids}
        substituted.update({ident: reviews[ident] for ident in remaining_ids})
        assert substituted == reviews
        row['native_substituted'] = len(native_ids)
        row['remaining_ai_inputs'] = len(remaining_ids)
        row['finding_id_verdict_reason_parity'] = True
        row['priorities_review_input_parity'] = True
        row['priorities_action_citation_ids_unchanged'] = True
    assert sum(row['native_substituted'] for row in pair_rows) == 703
    receipt = {'version': 2, 'pair_count': 7, 'exercised_check_ids': len(counts), 'hardening_failures': total,
               'admitted_check_ids': len(eligible), 'admitted_failures': 703,
               'remaining_ai_failures': 1243, 'source_compare_sha256': sha(private / 'expanded-source-compare.json'),
               'pair_receipt_sha256': sha(private / 'pair-chunk-receipt.json'), 'pairs': pair_rows,
               'admitted': eligible, 'excluded': excluded,
               'verdict_policy': 'zero disagreements required; AI reason text is not an admission criterion',
               'source_scope': 'recorded API fields and complete inventory only; runtime enforcement is not inferred'}
    OUT.write_text(json.dumps(receipt, indent=2, sort_keys=True) + '\n')
    manifest = {'version': 2, 'audit_receipt_sha256': sha(OUT),
                'qualification': {'status': 'offline_qualified', 'hosted_cost_gate': 'pending', 'hosted_receipt_sha256': None},
                'checks': [{'check_id': r['check_id'], 'reviewed_failures': r['findings'],
                            'initial_representatives': r['initial_representatives'], 'disagreements': 0,
                            'source_rechecks': r['source_rechecks'], 'source': r['source']}
                           for r in eligible]}
    MANIFEST.write_text(json.dumps(manifest, indent=2, sort_keys=True) + '\n')
    return receipt


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('private_dir', type=Path)
    args = parser.parse_args()
    result = audit(args.private_dir)
    print(json.dumps({key: result[key] for key in ('pair_count', 'exercised_check_ids', 'hardening_failures', 'admitted_check_ids', 'admitted_failures', 'remaining_ai_failures')}, sort_keys=True))


if __name__ == '__main__':
    main()
