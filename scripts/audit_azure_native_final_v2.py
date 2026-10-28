"""Source inventory and exact saved-snapshot replay for Azure Hardening v2.

This only writes an offline proof and pending manifest. It never calls a model.
Every exercised check gets an active evaluator source location and a decision.
"""

from collections import Counter, defaultdict
import gzip
import hashlib
import inspect
import json
from pathlib import Path

from peaso.checks import CHECKS
from peaso.engine import evaluate_snapshot
from scripts.audit_azure_native_final import audit


SCAN = 'a79ff6f9331246bd9e4f4bf6ba6fa207'
ARTIFACTS = {
    'snapshot-a777a7319eda467bacdfbe5ea512371b.json': '8117ca71b27fa60dc9f4d370fb7e60bcd7cdacce36d3f567079f20519861ac78',
    'report-99f46be9f0774097b980177bc3a366ee.json': '9ed2de0adc5adde4255108177745f76fe87796ad4ec3ca4d8d7febe6a44e84af',
    'report-69052a550aef4494abea18a0cdf75f58.json': '452f7d615cbfa23bed95b6943aefa1242e7016c62dd879dd0a62b2919f2dd1b9',
}
EXCLUDED = {
    'azure.claude.entra_ca_mfa_admin_portals': 'conditional_access_policy_intent',
    'azure.claude.entra_ca_mfa_management_api': 'conditional_access_policy_intent',
    'azure.claude2.entra_ca_mfa_all_users_or_roles': 'conditional_access_policy_intent',
    'azure.claude.entra_trusted_named_location_exists': 'corporate_range_intent_not_recorded',
    'azure.claude.defender_security_contact_email_configured': 'free_text_email_destination',
    'azure.claude.vm_windows_exploit_guard': 'guest_effect_not_proven_by_assignment',
    'azure.claude.vm_windows_max_password_age': 'guest_effect_not_proven_by_assignment',
    'azure.claude.vm_windows_min_password_age': 'guest_effect_not_proven_by_assignment',
    'azure.claude.vm_windows_min_password_length': 'guest_effect_not_proven_by_assignment',
    'azure.claude.vm_windows_no_reversible_password_encryption': 'guest_effect_not_proven_by_assignment',
    'azure.claude.vm_windows_password_complexity': 'guest_effect_not_proven_by_assignment',
    'azure.claude.vm_windows_password_history': 'guest_effect_not_proven_by_assignment',
    'azure.claude.vm_windows_secure_protocol_tls13': 'guest_effect_not_proven_by_assignment',
    'azure.claude.vm_windows_security_baseline': 'guest_effect_not_proven_by_assignment',
    'azure.review.acr.selected_image_high_critical_vulnerabilities': 'selected_image_content_or_vulnerability_interpretation',
    'azure.review.acr.selected_image_secret_indicators': 'selected_image_content_or_secret_interpretation',
}


def digest(data):
    return hashlib.sha256(data).hexdigest()


def saved(source, name):
    raw = (source / name).read_bytes()
    if digest(raw) != ARTIFACTS[name]:
        raise ValueError('saved_artifact_drift:' + name)
    return json.loads(gzip.decompress(raw) if raw[:2] == b'\x1f\x8b' else raw)


def observations(report):
    return {row['id']: row for group in report['findings']
            for row in group.get('observations') or [group]}


def coverage_statuses(report):
    found = defaultdict(list)
    for row in report['coverage']:
        if row.get('level') == 'check':
            found[('check', row.get('check_id'), row.get('scope'))].append(row.get('status'))
        if row.get('level') == 'collection':
            found[('collection', row.get('type'), row.get('scope'))].append(row.get('status'))
    return found


def complete(row, check, coverage):
    scope = row['scope']
    return (coverage[('check', check.id, scope)] == ['evaluated'] and
            all(coverage[('collection', dep, scope)] in (['collected'], ['empty'])
                for dep in check.dependencies))


def basis(check):
    ident = check.id
    if any(word in ident for word in ('credential', 'secret_age', 'expiration')):
        return 'recorded_timestamp_at_scan_time'
    if any(word in ident for word in ('alert_', 'backup_', 'site_recovery', 'jit_', 'associated', 'flow_log',
                                       'bastion_', 'global_admin', 'subnet_has_consumer')) or check.target == 'scope':
        return 'complete_collection_membership_or_count'
    return 'recorded_api_boolean_enum_or_count'


def build(repo, source):
    snapshot, pre, final = (saved(source, name) for name in ARTIFACTS)
    if (snapshot.get('provider') != 'azure' or pre.get('provider') != 'azure'
            or snapshot.get('snapshot_id') != pre.get('snapshot_id')
            or pre.get('snapshot_id') != final.get('snapshot_id')):
        raise ValueError('same_scan_snapshot_required')
    numeric = audit(pre, final, pre_sha=ARTIFACTS[list(ARTIFACTS)[1]],
                    final_sha=ARTIFACTS[list(ARTIFACTS)[2]])
    registry = {check.id: check for check in CHECKS}
    original = observations(pre)
    exercised = {row['check_id'] for row in original.values()
                 if row.get('category') == 'hardening'}
    numeric_by_check = {row['check_id']: row for row in numeric['per_check']}
    replay = evaluate_snapshot(snapshot, categories=['hardening'],
                               checks=sorted(exercised), include_not_applicable=False)
    repeated = observations(replay)
    for ident, row in original.items():
        if row.get('check_id') in exercised:
            match = repeated.get(ident)
            if match is None or any(row.get(field) != match.get(field) for field in ('status', 'evidence')):
                raise ValueError('snapshot_replay_drift:' + ident)
    if {ident for ident, row in original.items() if row.get('check_id') in exercised} != {
            ident for ident, row in repeated.items() if row.get('check_id') in exercised}:
        raise ValueError('snapshot_replay_identity_drift')
    coverage = coverage_statuses(pre)
    fail_rows = defaultdict(list)
    for row in original.values():
        if row.get('category') == 'hardening' and row.get('status') == 'FAIL':
            fail_rows[row['check_id']].append(row)
    source_hashes, decisions, selected = {}, [], []
    for ident in sorted(exercised):
        numeric_row = numeric_by_check.get(ident)
        check = registry[ident]
        function = inspect.unwrap(check.evaluate)
        path = Path(inspect.getsourcefile(function)).resolve().relative_to(repo)
        source_text, line = inspect.getsourcelines(function)
        source_hashes[str(path)] = digest((repo / path).read_bytes())
        source_hashes['peaso/collectors/azure.py'] = digest((repo / 'peaso/collectors/azure.py').read_bytes())
        if numeric_row is None:
            reason = 'no_saved_native_fail'
        elif not numeric_row['zero_disagreement_candidate']:
            reason = 'saved_ai_disagreement_or_published_change'
        elif ident in EXCLUDED:
            reason = EXCLUDED[ident]
        elif not all(complete(row, check, coverage) for row in fail_rows[ident]):
            reason = 'incomplete_or_unmapped_collection_coverage'
        else:
            reason = 'admit_source_proven'
        entry = {'check_id': ident, 'saved_fail_count': numeric_row['native_fail_count'] if numeric_row else 0,
                 'saved_ai_disagreements': numeric_row['ai_disagreement_count'] if numeric_row else 0,
                 'source_kind': check.kind, 'dependencies': list(check.dependencies),
                 'source_file': str(path), 'source_line': line,
                 'function_sha256': digest(''.join(source_text).encode()),
                 'source_basis': basis(check), 'decision': reason}
        decisions.append(entry)
        if reason == 'admit_source_proven':
            selected.append({key: entry[key] for key in ('check_id', 'saved_fail_count',
                'saved_ai_disagreements', 'source_kind', 'dependencies', 'source_file',
                'source_line', 'function_sha256', 'source_basis')})
    if set(EXCLUDED) - exercised:
        raise ValueError('stale_manual_exclusion')
    proof = {'version': 2, 'scan_id': SCAN, 'snapshot_id': snapshot['snapshot_id'],
             'artifact_sha256': ARTIFACTS, 'source_hashes': dict(sorted(source_hashes.items())),
             'source_decisions': decisions, 'exercised_check_count': len(decisions),
             'selected_check_count': len(selected),
             'selected_native_fail_count': sum(row['saved_fail_count'] for row in selected),
             'exact_replayed_observation_count': sum(row.get('check_id') in exercised for row in original.values()),
             'exact_snapshot_status_evidence_parity': True,
             'qualification_state': 'offline_only_hosted_quality_and_cost_pending'}
    manifest = {'version': 2, 'source_scan_id': SCAN, 'snapshot_id': snapshot['snapshot_id'],
                'base_commit': 'f204f3a5b25991390cb6baf2572710c4da8342bd',
                'source_proof_sha256': None, 'source_hashes': proof['source_hashes'],
                'replay_qualification': {'status': 'pending', 'saved_receipt_sha256': None,
                                         'hosted_receipt_sha256': None},
                'checks': selected}
    return proof, manifest


def main():
    repo = Path(__file__).resolve().parents[1]
    source = Path.home() / 'peaso-work/native-final-azure-private' / SCAN
    proof, manifest = build(repo, source)
    proof_path = repo / 'docs/ai-review/native-final-azure-source-audit-v2.json'
    proof_path.write_text(json.dumps(proof, indent=2, sort_keys=True) + '\n')
    manifest['source_proof_sha256'] = digest(proof_path.read_bytes())
    (repo / 'peaso/ai/native_final_azure_allowlist.json').write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + '\n')
    print(json.dumps({'exercised_checks': proof['exercised_check_count'],
                      'selected_checks': proof['selected_check_count'],
                      'selected_fail_rows': proof['selected_native_fail_count']}, sort_keys=True))


if __name__ == '__main__':
    main()
