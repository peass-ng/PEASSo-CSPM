"""Exact current explanations replay the native evaluator rather than titles."""
from copy import deepcopy
import re

import pytest

from peaso.checks import CHECKS
from peaso.checks.fixtures import CASES
from peaso.checks.k8s_evidence_explanations import (
    current_review_rows, evidence_summary,
)

CURRENT = current_review_rows()
CHECKS_BY_ID = {check.id: check for check in CHECKS if check.provider == 'k8s'}


@pytest.mark.parametrize('cid', sorted(CURRENT))
def test_current_native_witnesses_have_bounded_source_explanations(cid):
    row = CURRENT[cid]
    cases = CASES[cid]
    for state in ('pass', 'fail'):
        assert state in cases, (cid, state)
        index = cases.get(state + '_index', cases.get('index', {}))
        status, evidence = CHECKS_BY_ID[cid].evaluate(deepcopy(cases[state]), deepcopy(index))
        assert status == state.upper(), (cid, state, evidence)
        assert set(row['evidence_fields']) <= set(evidence), (cid, state, evidence)
        finding = {'provider': 'k8s', 'check_id': cid, 'status': status, 'evidence': evidence}
        before = deepcopy(finding)
        summary = evidence_summary(finding)
        assert isinstance(summary, str) and row['purpose'] in summary, (cid, state, evidence, summary)
        assert 1 <= len(summary.splitlines()) <= 3 and len(summary) <= 480
        assert not re.search(r'(?<![0-9a-f])[0-9a-f]{64}(?![0-9a-f])|sha256:', summary, re.I)
        assert finding == before


@pytest.mark.parametrize('cid', sorted(CURRENT))
def test_missing_or_malformed_current_evidence_never_invents_a_decision(cid):
    for status in ('PASS', 'FAIL'):
        for evidence in ({}, None, [], {'reason': 'missing fact'}, {'summary': 7, 'observed': 7}):
            assert evidence_summary({'provider': 'k8s', 'check_id': cid,
                                     'status': status, 'evidence': evidence}) is None
    cases = CASES[cid]
    if 'missing' in cases:
        index = cases.get('missing_index', cases.get('index', {}))
        status, evidence = CHECKS_BY_ID[cid].evaluate(deepcopy(cases['missing']), deepcopy(index))
        assert status in ('UNKNOWN', 'NOT_APPLICABLE')
        explanation = evidence_summary({'provider': 'k8s', 'check_id': cid,
                                        'status': status, 'evidence': evidence})
        assert explanation is None or 'uncertain' in explanation or 'not a tracked' in explanation
