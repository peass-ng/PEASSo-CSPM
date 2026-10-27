"""The GCP proposal must fail closed when source or saved review facts drift."""
import gzip
import json

from scripts.audit_gcp_native_final_scalar import SPECS, audit, saved_replay


def _write_gzip(path, value):
    with gzip.open(path, 'wt') as stream:
        json.dump(value, stream)


def test_source_audit_replays_all_scalar_boundaries():
    receipt = audit()
    assert receipt['candidate_count'] == len(SPECS) == 12
    assert receipt['status'] == 'source_proven_replay_pending'
    assert receipt['runtime_admitted'] is False
    assert receipt['saved_replay'] is None
    assert all(row['fixture_outcomes']['denied'] == 'UNKNOWN'
               for row in receipt['checks'])


def test_saved_replay_detects_review_and_published_drift(tmp_path):
    finding = {'id': 'f1', 'provider': 'gcp', 'category': 'hardening',
               'check_id': 'gcp.compute.secure_boot', 'status': 'FAIL',
               'scanner_status': 'FAIL', 'severity': 'medium',
               'base_severity': 'medium', 'evidence': {
                   'field': 'shieldedInstanceConfig.enableSecureBoot', 'configured': False},
               'evidence_summary': 'Secure Boot disabled'}
    before = {'provider': 'gcp', 'snapshot_id': 'snapshot-1',
              'findings': [{'observations': [finding]}]}
    after = {'provider': 'gcp', 'snapshot_id': 'snapshot-1',
             'findings': [{'observations': [finding]}],
             'ai': {'reviews': {'hardening': [
                 {'finding_id': 'f1', 'verdict': 'FAIL', 'reason': ''}]}}}
    pre, post = tmp_path / 'pre.json.gz', tmp_path / 'post.json.gz'
    _write_gzip(pre, before)
    _write_gzip(post, after)
    assert saved_replay(pre, post)['exact_saved_parity'] is True
    after['ai']['reviews']['hardening'][0]['verdict'] = 'UNKNOWN'
    _write_gzip(post, after)
    assert saved_replay(pre, post)['exact_saved_parity'] is False
    after['ai']['reviews']['hardening'][0]['verdict'] = 'FAIL'
    after['findings'][0]['observations'][0] = dict(finding, severity='low')
    _write_gzip(post, after)
    assert saved_replay(pre, post)['exact_saved_parity'] is False
    before['findings'][0]['observations'][0] = dict(
        finding, evidence={'field': 'shieldedInstanceConfig.enableSecureBoot',
                           'configured': True})
    after['findings'][0]['observations'][0] = before['findings'][0]['observations'][0]
    _write_gzip(pre, before)
    _write_gzip(post, after)
    replay = saved_replay(pre, post)
    assert replay['exact_saved_parity'] is False
    assert next(row for row in replay['per_check']
                if row['check_id'] == 'gcp.compute.secure_boot')['evidence_mismatches'] == 1
