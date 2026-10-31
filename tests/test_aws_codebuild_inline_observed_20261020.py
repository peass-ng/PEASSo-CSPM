"""Exercise the actual native/public DTOs, including preserved partial hits."""
from copy import deepcopy
import json
from pathlib import Path
import re

import pytest

from peaso.checks.aws_evidence_explanations import evidence_summary
from peaso.checks.selected_configuration_content_observed_20261020 import observation

PROOF = Path('tests/fixtures/public_secret_captures/aws-codebuild-buildspec-runtime-public-native-20261020.json')


@pytest.mark.parametrize('branch', ['pass', 'fail', 'partial', 'unknown', 'malformed'])
def test_actual_public_findings_are_brief_and_preserve_uncertainty(branch):
    proof = json.loads(PROOF.read_text())
    findings = proof['cases'][branch]['findings']
    selected = [f for f in findings if f['check_id'] == proof['check_id']]
    assert selected
    for finding in selected:
        before = deepcopy(finding)
        text = evidence_summary(finding)
        assert text and len(re.split(r'[.!?] +', text)) <= 3
        if finding['status'] not in ('PASS', 'FAIL'):
            assert observation(finding) is None
        assert finding == before


@pytest.mark.parametrize('fault', ['provider', 'status', 'fingerprint', 'path', 'scope', 'linked_check', 'raw_secret'])
def test_consolidated_copy_needs_actual_bound_leak_shape(fault):
    proof = json.loads(PROOF.read_text())
    finding = next(f for f in proof['cases']['partial']['findings'] if f['status'] == 'FAIL')
    assert observation(finding) and 'incomplete' in observation(finding)
    if fault == 'provider': finding['provider'] = 'azure'
    elif fault == 'status': finding['status'] = 'PASS'
    elif fault == 'fingerprint': finding['secret_fingerprint'] = '0' * 64
    elif fault == 'linked_check': finding['linked_check_ids'].append('unrelated.check')
    elif fault == 'raw_secret': finding['evidence']['secret_leaks'][0]['value'] = 'never-render'
    else: finding['evidence']['secret_leaks'][0]['locations'][0][fault] = 'unbound'
    assert observation(finding) is None
