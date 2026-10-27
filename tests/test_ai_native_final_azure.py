"""Azure admission stays isolated from the qualified AWS manifest."""

import copy
import hashlib
import json

from peaso.ai import native_final_azure


def _manifest():
    return json.loads(native_final_azure.MANIFEST.read_text())


def _write(tmp_path, monkeypatch, manifest):
    path = tmp_path / 'azure-manifest.json'
    raw = (json.dumps(manifest, sort_keys=True) + '\n').encode()
    path.write_bytes(raw)
    monkeypatch.setenv('PEASO_AZURE_HARDENING_NATIVE_FINAL_ENABLED', '1')
    monkeypatch.setenv('PEASO_AZURE_HARDENING_NATIVE_FINAL_SHA256', hashlib.sha256(raw).hexdigest())
    return path


def test_committed_manifest_pending_even_with_switch_and_pin(monkeypatch):
    monkeypatch.setenv('PEASO_AZURE_HARDENING_NATIVE_FINAL_ENABLED', '1')
    monkeypatch.setenv('PEASO_AZURE_HARDENING_NATIVE_FINAL_SHA256',
                       hashlib.sha256(native_final_azure.MANIFEST.read_bytes()).hexdigest())
    assert not native_final_azure.admitted_check_ids()


def test_exact_qualified_gate_and_source_pin(tmp_path, monkeypatch):
    value = _manifest()
    value['replay_qualification'] = {
        'status': 'qualified', 'saved_receipt_sha256': 'a' * 64,
        'hosted_receipt_sha256': 'b' * 64}
    path = _write(tmp_path, monkeypatch, value)
    assert native_final_azure.admitted_check_ids(path) == set(native_final_azure.EXPECTED)
    path.write_bytes(path.read_bytes() + b' ')
    assert not native_final_azure.admitted_check_ids(path)
    path = _write(tmp_path, monkeypatch, value)
    monkeypatch.delenv('PEASO_AZURE_HARDENING_NATIVE_FINAL_ENABLED')
    assert not native_final_azure.admitted_check_ids(path)


def test_manifest_widening_and_missing_receipt_rejected(tmp_path, monkeypatch):
    base = _manifest()
    base['replay_qualification'] = {
        'status': 'qualified', 'saved_receipt_sha256': 'a' * 64,
        'hosted_receipt_sha256': 'b' * 64}
    for mutation in (
        lambda m: m['checks'].append(dict(m['checks'][0], check_id='azure.other.setting')),
        lambda m: m['checks'][0].update(saved_ai_disagreements=1),
        lambda m: m['checks'][0].update(source_fields=['properties.unrelated']),
        lambda m: m['replay_qualification'].update(hosted_receipt_sha256=None),
        lambda m: m.update(source_proof_sha256='c' * 64),
    ):
        value = copy.deepcopy(base)
        mutation(value)
        assert not native_final_azure.admitted_check_ids(_write(tmp_path, monkeypatch, value))


def test_partition_keeps_incomplete_and_other_provider_with_ai():
    cid = 'azure.vault.rbac'
    rows = [
        {'id': 'a', 'provider': 'azure', 'category': 'hardening', 'status': 'FAIL', 'check_id': cid, 'scope': 's'},
        {'id': 'b', 'provider': 'azure', 'category': 'hardening', 'status': 'UNKNOWN', 'check_id': cid, 'scope': 's'},
        {'id': 'c', 'provider': 'aws', 'category': 'hardening', 'status': 'FAIL', 'check_id': cid, 'scope': 's'},
        {'id': 'd', 'provider': 'azure', 'category': 'hardening', 'status': 'FAIL',
         'scanner_status': 'UNKNOWN', 'check_id': cid, 'scope': 's'},
        {'id': 'e', 'provider': 'azure', 'category': 'hardening', 'status': 'FAIL',
         'check_id': cid, 'scope': 's', 'evidence': {'incomplete_dependencies': []}},
    ]
    coverage = [
        {'level': 'check', 'check_id': cid, 'scope': 's', 'status': 'evaluated'},
        {'level': 'collection', 'type': 'vault', 'scope': 's', 'status': 'collected'},
    ]
    native, ai = native_final_azure.partition(rows, {cid}, coverage)
    assert [row['id'] for row in native] == ['a']
    assert [row['id'] for row in ai] == ['b', 'c', 'd', 'e']
    for changed in ('partial', 'denied'):
        coverage[1]['status'] = changed
        assert native_final_azure.partition(rows, {cid}, coverage)[0] == []
    coverage[1]['status'] = 'collected'
    coverage[0]['status'] = 'partial'
    assert native_final_azure.partition(rows, {cid}, coverage)[0] == []
    coverage[0]['status'] = 'evaluated'
    assert native_final_azure.partition(rows, {cid}, coverage + [coverage[0]])[0] == []
    assert native_final_azure.partition(rows, {cid})[0] == []
