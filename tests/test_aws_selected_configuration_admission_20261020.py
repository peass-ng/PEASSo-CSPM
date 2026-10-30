"""The optional AWS reader must stay source-bound and outside default grants."""
from copy import deepcopy
import inspect
from pathlib import Path
import pytest
from peaso.checks import CHECKS,aws_selected_configuration_admission_20261020 as admission
from peaso.checks import aws_selected_configuration_secret_review_20261020 as reviewed
from peaso import rawv2_private_source_successor_20261021 as successor
from peaso.server.validation import OPTIONS,validate_connector
from fastapi import HTTPException


def test_registry_and_native_three_branch_inputs_are_the_reviewed_reader():
    check,=[c for c in CHECKS if c.id==reviewed.CHECK]
    assert inspect.unwrap(check.evaluate)is reviewed.evaluate
    assert check.kind=='configuration_selected_content' and check.allow_incomplete_failure
    assert 'selected_aws_configuration_content'in OPTIONS
    # Runtime admission reads through the RawV2 successor ledger, not the frozen receipt hashes.
    inputs=successor._with_artifacts(successor._aws_reviewed_inputs)[reviewed.CHECK]
    assert {reviewed.evaluate(inputs[b],inputs[b+'_index'])[0]for b in ('pass','fail','unknown')}=={'PASS','FAIL','UNKNOWN'}


def test_source_drift_is_rejected_without_registry_mutation(monkeypatch):
    original=Path.read_bytes;before=tuple(CHECKS)
    def read(path):
        raw=original(path)
        return raw+b'\n'if path.name=='aws_selected_configuration_secret_review_20261020.py'else raw
    monkeypatch.setattr(Path,'read_bytes',read)
    with pytest.raises(RuntimeError,match='source changed'):admission.install()
    assert tuple(CHECKS)==before


def test_fixture_drift_is_rejected(monkeypatch):
    original=Path.read_bytes
    monkeypatch.setattr(Path,'read_bytes',lambda p:original(p)+b'\n'if p.name.endswith('_20261020_fixtures.json')else original(p))
    with pytest.raises(RuntimeError,match='fixtures changed'):successor._with_artifacts(successor._aws_reviewed_inputs)


def test_optional_selector_rejects_wrong_provider_before_auth():
    with pytest.raises(HTTPException)as error:
        validate_connector('gcp',{}, {'selected_aws_configuration_content':[]}, {},scopes=['project'])
    assert error.value.status_code==422
