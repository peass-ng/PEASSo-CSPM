"""The inactive fragment requires a pinned source decision and exact refs."""

import pytest

from scripts import build_native_final_low_rep_fragment_v2 as builder
import json


def test_missing_recorded_field_cannot_be_invented():
    rows = [{'Configuration': {'projects': [{'name': 'one'}]}}]
    assert builder._recorded_path(rows, 'Configuration.projects[].artifacts.encryptionDisabled') == 'Configuration.projects[]'
    assert builder._recorded_path(rows, 'Risk.RiskConfiguration.Actions') == ''


def test_changed_source_receipt_rejects_builder(tmp_path, monkeypatch):
    receipt = tmp_path / 'receipt.json'
    receipt.write_text('{}')
    monkeypatch.setattr(builder, 'RECEIPT', receipt)
    with pytest.raises(ValueError, match='source review receipt changed'):
        builder.build(receipt, tmp_path / 'inventory.json', tmp_path / 'snapshot.bin')
