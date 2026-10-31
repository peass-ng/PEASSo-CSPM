"""GCP native-final admission stays separate and fail closed."""
import json

from peaso.ai import gcp_native_final


def test_pending_candidate_is_inactive_even_with_switch(monkeypatch):
    path = gcp_native_final.MANIFEST
    assert gcp_native_final.candidate_check_ids(path)
    monkeypatch.setenv('PEASO_GCP_HARDENING_NATIVE_FINAL_ENABLED', '1')
    assert not gcp_native_final.admitted_check_ids(path)
    monkeypatch.setenv('PEASO_GCP_HARDENING_NATIVE_FINAL_ENABLED', '0')
    assert not gcp_native_final.admitted_check_ids(path)


def test_qualified_manifest_requires_switch_and_valid_schema(tmp_path, monkeypatch):
    value = json.loads(gcp_native_final.MANIFEST.read_text())
    value['replay_qualification'] = {'status': 'qualified'}
    path = tmp_path / 'candidate.json'
    path.write_text(json.dumps(value, sort_keys=True) + '\n')
    assert not gcp_native_final.admitted_check_ids(path)
    monkeypatch.setenv('PEASO_GCP_HARDENING_NATIVE_FINAL_ENABLED', '1')
    assert gcp_native_final.admitted_check_ids(path) == gcp_native_final.candidate_check_ids()
    value['checks'][0]['unexpected'] = True
    path.write_text(json.dumps(value, sort_keys=True) + '\n')
    assert not gcp_native_final.admitted_check_ids(path)


def test_partition_requires_exact_native_fail_evidence():
    base = {'id': 'f1', 'check_id': 'gcp.compute.secure_boot', 'provider': 'gcp',
            'category': 'hardening', 'status': 'FAIL', 'scope': 'projects/p',
            'evidence': {'field': 'shieldedInstanceConfig.enableSecureBoot',
                         'configured': False}}
    coverage = [{'level': 'check', 'check_id': base['check_id'],
                 'scope': base['scope'], 'status': 'evaluated'},
                {'level': 'collection', 'type': 'instance',
                 'scope': base['scope'], 'status': 'collected'}]
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
    native, ai = gcp_native_final.partition(variants, gcp_native_final.candidate_check_ids(), coverage)
    assert [row['id'] for row in native] == ['f1']
    assert [row['id'] for row in ai] == [f'f{number}' for number in range(2, 9)]


def test_partial_disk_and_missing_check_scope_never_become_native_final():
    from peaso.checks.gcp_ports_relationships import csek

    status, evidence = csek({'name': 'disk'}, {})
    assert status == 'FAIL'  # The omitted field may be a partial projection.
    check_id = 'gcp.ports.compute_disk_encrypted_with_csk'
    row = {'id': 'disk', 'check_id': check_id, 'provider': 'gcp',
           'category': 'hardening', 'status': status, 'scope': 'projects/p',
           'evidence': evidence}
    coverage = [{'level': 'check', 'check_id': check_id,
                 'scope': 'projects/p', 'status': 'evaluated'},
                {'level': 'collection', 'type': 'disk',
                 'scope': 'projects/p', 'status': 'partial'}]
    admitted = gcp_native_final.candidate_check_ids()
    assert gcp_native_final.partition([row], admitted, coverage)[0] == []
    coverage[1]['status'] = 'collected'
    assert gcp_native_final.partition([row], admitted, coverage)[0] == [row]
    assert gcp_native_final.partition([row], admitted, coverage[:1])[0] == []
    assert gcp_native_final.partition([row], admitted, coverage + [coverage[0]])[0] == []
    assert gcp_native_final.partition([dict(row, scope='projects/q')], admitted, coverage)[0] == []
    assert gcp_native_final.partition([row], admitted)[0] == []
