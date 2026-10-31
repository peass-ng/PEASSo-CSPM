"""Actual normal-engine public DTOs keep their one-leak source meaning."""
from copy import deepcopy
import json
from pathlib import Path
import pytest
import re
from peaso.checks.public_source_secret_observed_20261020 import observation


def captures():
    rows=json.loads(Path('tests/fixtures/public_secret_captures/function_source_findings.json').read_text())
    return [pytest.param(finding,id=name) for name,finding in rows]


@pytest.mark.parametrize('finding',captures())
def test_actual_grouped_public_facts_stay_brief_and_unchanged(finding):
    before=deepcopy(finding);text=observation(finding)
    if finding['status']=='FAIL':
        assert text and len(text.split())<=35 and 'not validated' in text
        if finding['evidence'].get('complete') is False:assert 'incomplete' in text
    else:assert text is None
    assert finding==before


@pytest.mark.parametrize('finding',captures())
def test_actual_provider_report_keeps_complete_observation_brief(finding):
    if finding['status'] not in ('PASS','FAIL'):
        return
    if finding['provider']=='azure':
        from peaso.checks.azure_evidence_explanations import evidence_summary
    else:
        from peaso.checks.gcp_evidence_explanations import evidence_summary
    text=evidence_summary(finding)
    assert text and len(re.split(r'[.!?] +',text))<=3
    if finding['status']=='FAIL':assert text==observation(finding)


@pytest.mark.parametrize('provider',['azure','gcp'])
@pytest.mark.parametrize('fault',['provider','status','fingerprint','link','scope','engine','raw','unrelated_leak'])
def test_source_pair_copy_rejects_unbound_or_foreign_facts(provider,fault):
    f=next(deepcopy(p.values[0]) for p in captures() if p.values[0]['provider']==provider and p.values[0]['status']=='FAIL')
    assert observation(f)
    e=f['evidence'];field='package_source_assertions' if provider=='azure'else 'function_secret_pairs'
    record=e[field][0];section=record['parts'][0]if provider=='azure'else record
    if fault=='provider':f['provider']='k8s'
    elif fault=='status':f['status']='PASS'
    elif fault=='fingerprint':f['secret_fingerprint']='0'*64
    elif fault=='link':f['linked_check_ids'].append('foreign')
    elif fault=='scope':record['scope']='unbound'
    elif fault=='engine':section['engines'][0]['status']='unavailable'
    elif fault=='raw':section['leaks'if provider=='azure'else'secret_leaks'][0]['value']='never-render'
    else:section['leaks'if provider=='azure'else'secret_leaks'][0]['fingerprint']='0'*64
    assert observation(f)is None
