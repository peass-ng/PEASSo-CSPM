"""Archived report copy refresh must never re-evaluate historical evidence."""
from copy import deepcopy
import json
from pathlib import Path
import pytest
from peaso.checks.catalog import _base_description_for
from peaso.checks.aws_remaining_clarity_reviewed import ROWS as AWS_ROWS,description as aws_description,remediation as aws_remediation,_digest
from peaso.engine import hydrate_finding,CHECK_META_ENCODING
from peaso.finding_presentation import (CORRECTED_CHECK_IDS,criteria_contract,evaluator_contract_fingerprint,
                                       refresh_finding_presentation)

ROOT=Path(__file__).resolve().parents[1]


def _archived_kinesis_report_row():
    cid='aws.cb.kinesis.retention_exactly_168h'
    old_template=None
    for path in (ROOT/'peaso/rulepacks').glob('remediation*.json'):
        packed=json.loads(path.read_text())
        if isinstance(packed,dict) and cid in packed and _digest(packed[cid])==AWS_ROWS[cid]['remediation_base_sha256']:
            old_template=packed[cid];break
    assert old_template is not None
    # The same per-check encoding used by immutable schema-1.1 report bundles.
    meta=dict(_base_description_for(cid),title='Kinesis retention exactly 168 hours',severity='high',_derived='rm')
    meta.pop('rationale',None);meta.pop('remediation',None)
    if meta.get('not_applicable_when') is None:meta.pop('not_applicable_when',None)
    finding={'id':'old-result','provider':'aws','check_id':cid,'status':'FAIL','severity':'high',
             'resource_id':'arn:aws:kinesis:us-east-1:111111111111:stream/example','scope':'111111111111/us-east-1',
             'evidence':{'retention_hours':8760},'evaluator_version':'1.0.0','evaluation_version':'archived-release',
             'source_version':'archived-source','created_at':'2026-10-01T00:00:00Z'}
    hydrated=hydrate_finding(finding,None,{cid:meta},CHECK_META_ENCODING,{cid:old_template})
    current=aws_description(cid,_base_description_for(cid));current_template=aws_remediation(cid,old_template)
    return hydrated,current,current_template,old_template


def test_actual_old_report_gets_brief_guidance_without_rewriting_its_assessment():
    old,current,current_template,archived_template=_archived_kinesis_report_row();before=deepcopy(old)
    result,allow=refresh_finding_presentation(old,current,current_template,archived_template=archived_template)
    assert allow and result['guidance_refresh']['basis']=='matching_archived_criteria'
    assert result['description']==current['description']
    assert result['rationale']==current['description']
    assert result['remediation_details']['steps']==current_template['steps']
    assert result['remediation_details']['caveats']==current_template['caveats']
    for key in ['evidence','status','severity','resource_id','id','scope','evaluator_version','evaluation_version','source_version','created_at','evaluated','pass_when','fail_when']:
        assert result[key]==old[key]
    assert old==before
    assert result['severity']=='high'  # Current preference is informational.
    assert result['evidence']=={'retention_hours':8760}  # Longer retention stays longer.


def test_historical_how_and_actions_are_retained_if_criteria_changed():
    old,current,current_template,archived_template=_archived_kinesis_report_row();before=deepcopy(old)
    current['pass_when']='Retention meets an entirely different policy.'
    result,allow=refresh_finding_presentation(old,current,current_template,archived_template=archived_template)
    assert not allow
    assert result['guidance_refresh']['status']=='historical_definition'
    assert result['guidance_refresh']['basis']=='criteria_changed'
    assert 'archived result' in result['guidance_refresh']['message']
    assert {k:v for k,v in result.items() if k!='guidance_refresh'}==old
    assert old==before


def test_legacy_report_without_criteria_does_not_inherit_todays_definition():
    old,current,current_template,_=_archived_kinesis_report_row()
    for key in ['evaluated','pass_when','fail_when','not_applicable_when']:old.pop(key,None)
    result,allow=refresh_finding_presentation(old,current,current_template)
    assert not allow and result['guidance_refresh']['basis']=='criteria_unavailable'
    assert result['description']==old['description']
    assert result['remediation']==old['remediation']


@pytest.mark.parametrize('cid',sorted(CORRECTED_CHECK_IDS))
def test_corrected_callbacks_need_source_bound_proof_even_if_archived_criteria_match(cid):
    # Older reports only carry a shared version label. Equal generic prose is
    # not proof that the corrected GCP enum/default, component or port helper ran.
    contract={'evaluated':['native setting'],'pass_when':'The setting meets the criterion.',
              'fail_when':'The setting violates the criterion.','description':'Historical implementation description.'}
    old=dict(contract,check_id=cid,provider='gcp' if cid.startswith('gcp') else 'k8s' if cid.startswith('k8s') else 'aws',
             status='PASS',severity='medium',evidence={'configured':'historical-value'},evaluator_version='1.0.0')
    current=dict(contract,description='Current corrected implementation description.')
    result,allow=refresh_finding_presentation(old,current,None,current_evaluator_contract='a'*64)
    assert not allow and result['guidance_refresh']['basis']=='corrected_evaluator_unbound'
    assert result['description']=='Historical implementation description.' and result['status']=='PASS'
    assert result['evidence']==old['evidence']
    old['clarity_evaluation_contract']='a'*64
    result,allow=refresh_finding_presentation(old,current,None,current_evaluator_contract='a'*64)
    assert allow and result['description']==current['description']
    result,allow=refresh_finding_presentation(old,current,None,current_evaluator_contract='b'*64)
    assert not allow and result['description']==old['description']


def test_gcp_unknown_enum_historical_pass_is_not_presented_as_current_corrected_result():
    cid='gcp.claude.gke.release_channel'
    current=_base_description_for(cid)
    old=dict(current,check_id=cid,provider='gcp',status='PASS',severity='medium',
             description='The release channel is configured.',evidence={'release_channel':'UNRECOGNIZED_NEW_MODE'},evaluator_version='1.0.0')
    result,allow=refresh_finding_presentation(old,current,None,current_evaluator_contract='a'*64)
    assert not allow and result['status']=='PASS' and result['description']==old['description']
    assert result['evidence']['release_channel']=='UNRECOGNIZED_NEW_MODE'


def test_no_live_catalog_commands_are_added_to_an_archived_report():
    old,current,current_template,_=_archived_kinesis_report_row()
    current_template['cli']=[{'code':'new cloud mutation example'}]
    current_template['iac']=[{'code':'new infrastructure change'}]
    result,allow=refresh_finding_presentation(old,current,current_template)
    assert allow and result['remediation_details']['cli']==[]
    assert not result['remediation_details'].get('iac')
    old['remediation_details']={'cli':[{'code':'archived approved example'}],'field_binding':{'fields':['archived.field']}}
    result,allow=refresh_finding_presentation(old,current,current_template)
    assert result['remediation_details']['cli']==old['remediation_details']['cli']
    assert result['remediation_details']['field_binding']==old['remediation_details']['field_binding']


def test_draft_or_malformed_current_guidance_does_not_replace_approved_archived_guidance():
    old,current,current_template,_=_archived_kinesis_report_row()
    for invalid in [None,{},dict(current_template,review_status='draft'),dict(current_template,steps=['']),dict(current_template,caveats='malformed'),dict(current_template,references=['not-a-reference'])]:
        result,allow=refresh_finding_presentation(old,current,invalid)
        assert allow and result['remediation']==old['remediation']
        assert 'remediation_details' not in result


def test_only_known_none_applicability_omission_is_normalized():
    old,current,_,_=_archived_kinesis_report_row()
    assert 'not_applicable_when' not in old
    assert criteria_contract(old)==criteria_contract(dict(current,not_applicable_when=None))
    assert criteria_contract(old)!=criteria_contract(dict(current,not_applicable_when='Only Linux assets.'))
    assert criteria_contract(old)!=criteria_contract(dict(current,pass_when=current['pass_when']+' '))
    assert criteria_contract({'evaluated':[],'pass_when':'pass','fail_when':'fail'}) is None


def test_source_fingerprint_detects_shared_helper_changes_and_ignores_artifact_cache(tmp_path,monkeypatch):
    import peaso.finding_presentation as presentation
    root=tmp_path/'checks';root.mkdir()
    (root/'registry.py').write_text('def evaluate(): return _open_ports()\n')
    (root/'ports.py').write_text('def _open_ports(): return "old endpoint comparison"\n')
    monkeypatch.setattr(presentation,'_CHECKS_ROOT',root)
    evaluator_contract_fingerprint.cache_clear()
    try:
        before=evaluator_contract_fingerprint()
        (tmp_path/'.cache').mkdir();(tmp_path/'.cache'/'large-artifact').write_text('irrelevant')
        evaluator_contract_fingerprint.cache_clear()
        assert evaluator_contract_fingerprint()==before
        (root/'ports.py').write_text('def _open_ports(): return "inclusive interval comparison"\n')
        assert evaluator_contract_fingerprint()==before  # Immutable production process cache.
        evaluator_contract_fingerprint.cache_clear()
        after=evaluator_contract_fingerprint()
        assert after!=before
        (root/'ports.py').rename(root/'renamed_ports.py')
        evaluator_contract_fingerprint.cache_clear()
        assert evaluator_contract_fingerprint()!=after
    finally:evaluator_contract_fingerprint.cache_clear()


def test_missing_native_source_does_not_produce_an_empty_source_proof(tmp_path,monkeypatch):
    import peaso.finding_presentation as presentation
    monkeypatch.setattr(presentation,'_CHECKS_ROOT',tmp_path/'missing')
    evaluator_contract_fingerprint.cache_clear()
    try:
        with pytest.raises(ValueError,match='Native check source is unavailable'):
            evaluator_contract_fingerprint()
    finally:evaluator_contract_fingerprint.cache_clear()
