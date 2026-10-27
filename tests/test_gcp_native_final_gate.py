"""GCP native-final admission stays separate and fail closed."""
import hashlib
import json

from peaso.ai import gcp_native_final


def test_pending_candidate_is_inactive_even_with_switch_and_pin(monkeypatch):
    path = gcp_native_final.MANIFEST
    assert gcp_native_final.candidate_check_ids(path) == frozenset(gcp_native_final.CHECKS)
    monkeypatch.setenv('PEASO_GCP_HARDENING_NATIVE_FINAL_ENABLED', '1')
    monkeypatch.setenv('PEASO_GCP_HARDENING_NATIVE_FINAL_SHA256',
                       hashlib.sha256(path.read_bytes()).hexdigest())
    assert not gcp_native_final.admitted_check_ids(path)
    monkeypatch.setenv('PEASO_GCP_HARDENING_NATIVE_FINAL_ENABLED', '0')
    assert not gcp_native_final.admitted_check_ids(path)


def test_qualified_schema_still_requires_exact_pin_and_source(tmp_path, monkeypatch):
    value = json.loads(gcp_native_final.MANIFEST.read_text())
    value['replay_qualification'] = {'status': 'qualified',
                                     'hosted_receipt_sha256': 'a' * 64}
    path = tmp_path / 'candidate.json'
    path.write_text(json.dumps(value, sort_keys=True) + '\n')
    monkeypatch.setenv('PEASO_GCP_HARDENING_NATIVE_FINAL_ENABLED', '1')
    monkeypatch.setenv('PEASO_GCP_HARDENING_NATIVE_FINAL_SHA256',
                       hashlib.sha256(path.read_bytes()).hexdigest())
    assert not gcp_native_final.admitted_check_ids(path)
    monkeypatch.setattr(gcp_native_final, 'HOSTED_RECEIPT_SHA256', 'a' * 64)
    assert gcp_native_final.admitted_check_ids(path) == frozenset(gcp_native_final.CHECKS)
    path.write_bytes(path.read_bytes() + b' ')
    assert not gcp_native_final.admitted_check_ids(path)
    value['checks'][0]['saved_native_failures'] += 1
    path.write_text(json.dumps(value, sort_keys=True) + '\n')
    monkeypatch.setenv('PEASO_GCP_HARDENING_NATIVE_FINAL_SHA256',
                       hashlib.sha256(path.read_bytes()).hexdigest())
    assert not gcp_native_final.admitted_check_ids(path)


def test_partition_requires_exact_native_fail_evidence():
    base = {'id': 'f1', 'check_id': 'gcp.compute.secure_boot', 'provider': 'gcp',
            'category': 'hardening', 'status': 'FAIL',
            'evidence': {'field': 'shieldedInstanceConfig.enableSecureBoot',
                         'configured': False}}
    variants = [base,
                dict(base, id='f2', provider='aws'),
                dict(base, id='f3', category='exposure'),
                dict(base, id='f4', status='UNKNOWN'),
                dict(base, id='f5', scanner_status='UNKNOWN'),
                dict(base, id='f6', evidence={'field': base['evidence']['field'],
                                             'configured': True}),
                dict(base, id='f7', evidence={'field': base['evidence']['field'],
                                             'configured': 0}),
                dict(base, id='f8', evidence={**base['evidence'],
                                             'incomplete_dependencies': []})]
    native, ai = gcp_native_final.partition(variants, frozenset(gcp_native_final.CHECKS))
    assert [row['id'] for row in native] == ['f1']
    assert [row['id'] for row in ai] == [f'f{number}' for number in range(2, 9)]
