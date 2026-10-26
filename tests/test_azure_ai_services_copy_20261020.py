"""New AI configuration observations preserve typed native evidence and status."""
from copy import deepcopy
import json
from pathlib import Path

import pytest

from peaso.checks.azure_ai_services_observed import observation
from peaso.checks.azure_evidence_explanations import evidence_summary

FIXTURES = json.loads((Path(__file__).parent / 'fixtures/azure-ai-evidence-review-20261020.json').read_text())


@pytest.mark.parametrize('cid,row', [(cid, row) for cid, rows in FIXTURES.items() for row in rows])
def test_native_branches_have_brief_immutable_observations(cid, row):
    finding = {'provider': 'azure', 'check_id': cid, **deepcopy(row)}
    original = deepcopy(finding)
    text = evidence_summary(finding)
    missing_id = row['status'] == 'UNKNOWN' and row['evidence'].get('reason') == 'missing fact: id'
    assert bool(text) == (row['status'] in ('PASS', 'FAIL') or missing_id)
    if missing_id:
        assert observation(finding) is None
        assert text.startswith('The record is missing the resource ID.\n')
    if text:
        assert text.count('.') <= 3
        assert len(text.split()) <= 45
        assert '{' not in text and 'observed' not in text
        other = {**finding, 'status': 'FAIL' if finding['status'] == 'PASS' else 'PASS'}
        assert observation(other) is None
    assert finding == original


@pytest.mark.parametrize('cid', FIXTURES)
@pytest.mark.parametrize('status', ['PASS', 'FAIL', 'UNKNOWN', 'DENIED'])
def test_status_or_arbitrary_observed_text_cannot_supply_a_native_fact(cid, status):
    assert evidence_summary({'provider': 'azure', 'check_id': cid, 'status': status,
                             'evidence': {'observed': 'untrusted raw input'}}) is None
