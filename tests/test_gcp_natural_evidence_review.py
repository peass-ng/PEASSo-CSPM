"""Natural GCP prose is checked against source-bound, reviewed observations."""
from copy import deepcopy
import json
from pathlib import Path

import pytest

from peaso.checks import evaluate_check
from peaso.checks.facts import MemoIndex
from peaso.checks.fixtures import CASES
from peaso.checks.gcp_evidence_explanations import evidence_summary, CATALOG
from tests.gcp_clarity_combined_successor_20261020 import current_golden_rows
from peaso.checks import CHECKS, evaluate_check

HISTORICAL_GOLDEN=json.loads((Path(__file__).parent/'fixtures/gcp-natural-evidence-golden.json').read_text())
GOLDEN=current_golden_rows(HISTORICAL_GOLDEN)
NATIVE=json.loads((Path(__file__).parent/'fixtures/gcp-native-review-behavior.json').read_text())
NATIVE_BY_ID={row['id']:row for row in NATIVE['cases']}
CURRENT_EXAMPLES=[row for row in GOLDEN if 'reviewed_fields' in row]


@pytest.mark.parametrize('row',CURRENT_EXAMPLES,ids=lambda x:x['finding']['check_id']+'-'+x['case'])
def test_current_source_examples_preserve_reviewed_status_and_deciding_fields(row):
    finding=row['finding'];cid=finding['check_id']
    if row['fixture_source']=='peaso.checks.fixtures.CASES':
        spec=CASES[cid];label=row['case']
        item=spec[label];index=spec.get(label+'_index',spec.get('index',{}))
    else:
        spec=NATIVE_BY_ID[row['native_case_id']]
        item=spec['item'];index=spec['index']
    status,evidence=evaluate_check(cid,deepcopy(item),MemoIndex(deepcopy(index)))
    evidence=json.loads(json.dumps(evidence))
    assert status==finding['status']
    assert row['reviewed_fields']
    for field in row['reviewed_fields']:
        assert field in evidence
        assert evidence[field]==finding['evidence'][field],(cid,field)


@pytest.mark.parametrize('configured,expected',[(True,'Notebook file downloads are blocked.'),(False,'Notebook file downloads are allowed.')])
def test_notebook_boolean_is_a_sentence_with_the_correct_direction(configured,expected):
    text=evidence_summary(dict(provider='gcp',check_id='gcp_workbench_download_disabled',status='FAIL',evidence={'configured':configured}))
    assert text.startswith(expected)
    assert 'blocking:' not in text


@pytest.mark.parametrize('invalid',[0,1,'false',[],None])
def test_a_numeric_or_string_boolean_does_not_become_a_control_state(invalid):
    cid='gcp_workbench_download_disabled'
    text=evidence_summary(dict(provider='gcp',check_id=cid,status='FAIL',evidence={'configured':invalid}))
    assert text.startswith(CATALOG[cid]['missing_observation'])


def test_owner_required_gate_is_not_presented_as_observed_enforcement():
    text=evidence_summary(dict(provider='gcp',check_id='gcp_c5_cloudbuild_gate',status='FAIL',evidence={'approval_required':True,'security_test_step':'security-test'}))
    assert text.startswith('The policy requires build approval')
    assert 'observed trigger gate settings were not stored' in text
    assert not text.startswith('Production builds require approval.')


def test_rotation_period_preserves_the_extra_second_without_scientific_notation():
    text=evidence_summary(dict(provider='gcp',check_id='gcp.ports.kms_key_rotated_within_90_day',status='FAIL',evidence={'rotation_seconds':7776001}))
    assert text.startswith('The key is scheduled to rotate every 90 days and 1 second.')
    assert 'e+06' not in text
