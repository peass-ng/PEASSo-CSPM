"""The inactive fragment requires a pinned source decision and exact refs."""
import json

import pytest

from scripts import build_native_final_low_rep_fragment_v2 as builder


def test_missing_recorded_field_cannot_be_invented():
    rows = [{'Configuration': {'projects': [{'name': 'one'}]}}]
    assert builder._recorded_path(rows, 'Configuration.projects[].artifacts.encryptionDisabled') == 'Configuration.projects[]'
    assert builder._recorded_path(rows, 'Risk.RiskConfiguration.Actions') == ''


def test_explicit_thresholds_and_inactive_fragment_boundary():
    age = builder._operation('aws.a.iam.password_policy_expiry_at_most_90',
                             [{'field_type': 'number'}], [])
    assert age == {'kind': 'number_comparison', 'comparison': 'gt',
                   'threshold': 90, 'threshold_unit': 'days'}
    fragment = json.loads((builder.ROOT /
        'docs/ai-review/native-final-low-rep-code-190-fragment-v2.json').read_text())
    receipt = json.loads(builder.RECEIPT.read_text())
    source_proven = {row['check_id'] for row in receipt['checks']
                     if row['decision'] == 'native_final_source_proven'}
    provisional = {row['check_id'] for row in receipt['checks']
                   if row['decision'] == 'provisional_source_candidate'}
    assert len(source_proven) == 141
    assert 'aws.cb.trustedadvisor.premium_support' not in source_proven
    assert len(provisional) == 24 and all(ident.startswith('aws.c2b.') for ident in provisional)
    assert {row['check_id'] for row in fragment['checks']} == source_proven
    reservation = next(row for row in fragment['checks']
                       if row['check_id'] == 'aws.b.lambda.reserved_concurrency')
    assert any('GetFunctionConcurrency' in field['api']
               for field in reservation['deterministic_evidence']['source_fields'])
    assert fragment['replay_qualification'] == {'status': 'pending', 'receipt_sha256': None}
    assert all(row['audit_receipt_sha256'] == builder.RECEIPT_SHA256
               for row in fragment['checks'])


def test_changed_source_receipt_rejects_builder(tmp_path, monkeypatch):
    receipt = tmp_path / 'receipt.json'
    receipt.write_text('{}')
    monkeypatch.setattr(builder, 'RECEIPT', receipt)
    with pytest.raises(ValueError, match='source review receipt changed'):
        builder.build(receipt, tmp_path / 'inventory.json', tmp_path / 'snapshot.bin')
