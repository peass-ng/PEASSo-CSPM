"""New AI configuration observations preserve typed native evidence and status."""
import json
from pathlib import Path

import pytest

from peaso.checks.azure_evidence_explanations import evidence_summary

FIXTURES = json.loads((Path(__file__).parent / 'fixtures/azure-ai-evidence-review-20261020.json').read_text())


@pytest.mark.parametrize('cid', FIXTURES)
@pytest.mark.parametrize('status', ['PASS', 'FAIL', 'UNKNOWN', 'DENIED'])
def test_status_or_arbitrary_observed_text_cannot_supply_a_native_fact(cid, status):
    assert evidence_summary({'provider': 'azure', 'check_id': cid, 'status': status,
                             'evidence': {'observed': 'untrusted raw input'}}) is None
