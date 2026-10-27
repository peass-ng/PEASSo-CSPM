"""Saved Azure review audit must fail closed on incomplete or changed rows."""

import copy

import pytest

from scripts.audit_azure_native_final import audit


def reports():
    pre = {
        'provider': 'azure', 'snapshot_id': 'snapshot-1',
        'findings': [{'observations': [
            {'id': 'a', 'provider': 'azure', 'category': 'hardening',
             'check_id': 'azure.storage.no_shared_key', 'status': 'FAIL', 'severity': 'high'},
            {'id': 'b', 'provider': 'azure', 'category': 'hardening',
             'check_id': 'azure.vault.rbac', 'status': 'FAIL', 'severity': 'medium'},
        ]}],
    }
    final = copy.deepcopy(pre)
    final['ai'] = {'reviews': {'hardening': [
        {'finding_id': 'a', 'verdict': 'FAIL', 'reason': ''},
        {'finding_id': 'b', 'verdict': 'UNKNOWN', 'reason': 'needs context'},
    ]}}
    return pre, final


def run(pre, final):
    return audit(pre, final, pre_sha='a' * 64, final_sha='b' * 64)


def test_exact_join_and_disagreement_by_check():
    pre, final = reports()
    receipt = run(pre, final)
    assert receipt['candidate_check_count'] == 1
    assert receipt['native_fail_ids'] == 2
    assert receipt['per_check'][0]['zero_disagreement_candidate'] is True
    assert receipt['per_check'][1]['ai_disagreement_count'] == 1
    assert receipt['per_check'][1]['zero_disagreement_candidate'] is False
    assert 'needs context' not in str(receipt)


def test_missing_review_final_row_and_severity_exclude_candidate():
    pre, final = reports()
    final['ai']['reviews']['hardening'].pop(0)
    assert run(pre, final)['per_check'][0]['zero_disagreement_candidate'] is False
    pre, final = reports()
    final['findings'][0]['observations'].pop(0)
    assert run(pre, final)['per_check'][0]['missing_final_count'] == 1
    pre, final = reports()
    final['findings'][0]['observations'][0]['severity'] = 'critical'
    assert run(pre, final)['per_check'][0]['published_severity_change_count'] == 1
    pre, final = reports()
    final['findings'][0]['observations'][0]['status'] = 'UNKNOWN'
    assert run(pre, final)['per_check'][0]['published_status_change_count'] == 1


@pytest.mark.parametrize('mutation', [
    lambda pre, final: final.update(provider='aws'),
    lambda pre, final: final.update(snapshot_id='other'),
    lambda pre, final: pre['findings'][0]['observations'].append(copy.deepcopy(pre['findings'][0]['observations'][0])),
    lambda pre, final: final['ai']['reviews']['hardening'].append(copy.deepcopy(final['ai']['reviews']['hardening'][0])),
])
def test_identity_mismatch_or_duplicate_fails(mutation):
    pre, final = reports()
    mutation(pre, final)
    with pytest.raises(ValueError):
        run(pre, final)
