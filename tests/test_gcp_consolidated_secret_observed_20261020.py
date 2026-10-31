"""Actual public leak findings remain positive after cross-reader deduplication."""
from copy import deepcopy
import inspect
import json
from pathlib import Path
import pytest
from peaso.checks.gcp_consolidated_secret_observed_20261020 import observation
from peaso.checks.selected_configuration_content_observed_20261020 import observation as shared


def findings(value):
    if isinstance(value,dict):
        if 'check_id'in value and'status'in value:
            yield value
        else:
            for child in value.values():yield from findings(child)
    elif isinstance(value,list):
        for child in value:yield from findings(child)


PUBLIC=[]
for name in ['workbench-source-runtime-public-findings-20261020.json','dataflow-batch-source-runtime-public-findings-20261020.json']:
    PUBLIC.extend(findings(json.loads((Path('tests/fixtures/public_secret_captures')/name).read_text())))


@pytest.mark.parametrize('finding',PUBLIC)
def test_real_current_engine_public_findings_keep_their_observation(finding):
    before=deepcopy(finding);text=observation(finding)
    if finding['status']=='FAIL':
        assert text and 'likely secret'in text and'not validated'in text and len(text.split())<=35
        assert bool('inspection is incomplete'in text)==(finding['evidence'].get('complete')is False)
        assert shared(finding)==text
        if len(finding['linked_check_ids'])>1:assert 'Batch and Dataflow'in text
    else:assert text is None
    assert finding==before


@pytest.mark.parametrize('fault',['provider','status','id','linked_unknown','linked_duplicate','fingerprint','raw_value','empty_locations','empty_detectors','unknown_detector','duplicate_location','location_scope','location_path','location_resource','complete','observed'])
def test_malformed_consolidated_facts_cannot_supply_positive_copy(fault):
    f=deepcopy(next(f for f in PUBLIC if f['status']=='FAIL'and len(f.get('linked_check_ids',[]))>1));e=f['evidence'];leak=e['secret_leaks'][0]
    if fault=='provider':f['provider']='aws'
    elif fault=='status':f['status']='PASS'
    elif fault=='id':f['check_id']='gcp.review.unreviewed.secret_indicators'
    elif fault=='linked_unknown':f['linked_check_ids'].append('gcp.review.unreviewed.secret_indicators')
    elif fault=='linked_duplicate':f['linked_check_ids'].append(f['linked_check_ids'][0])
    elif fault=='fingerprint':f['secret_fingerprint']='0'*64
    elif fault=='raw_value':leak['value']='must-not-be-rendered'
    elif fault=='empty_locations':leak['locations']=[]
    elif fault=='empty_detectors':leak['detectors']=[]
    elif fault=='unknown_detector':leak['detectors'][0]['engine']='unreviewed'
    elif fault=='duplicate_location':leak['locations'].append(deepcopy(leak['locations'][0]))
    elif fault.startswith('location_'):leak['locations'][0][{'location_scope':'scope','location_path':'path','location_resource':'resource_id'}[fault]]='unbound'
    elif fault=='complete':e.update(complete=True,coverage='incomplete')
    elif fault=='observed':e['observed']='No secrets were found.'
    assert observation(f)is None


def test_actual_existing_dataproc_consumer_also_survives_public_deduplication():
    from peaso.checks import CHECKS
    from peaso.checks.fixtures import CASES
    from peaso.secret_findings import deduplicate_secret_findings
    cid='gcp.review.dataproc.selected_job_referenced_source_secret_indicators';check=next(c for c in CHECKS if c.id==cid);case=CASES[cid]
    item,index=deepcopy(case['fail']),deepcopy(case['fail_index']);status,evidence=inspect.unwrap(check.evaluate)(item,index)
    assert status=='FAIL'
    row={'id':'real-native-case','provider':'gcp','check_id':cid,'status':status,'resource_id':item['name'],'scope':index['context']['scope'],'evidence':evidence,'frameworks':[]}
    finding,=deduplicate_secret_findings([row]);text=observation(finding)
    assert text and'likely secret'in text and'selected source location'in text
    assert shared(finding)==text
