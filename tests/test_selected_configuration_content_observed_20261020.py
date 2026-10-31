"""Current native detector facts produce brief evidence; free text is no proof."""
from copy import deepcopy
import json
from pathlib import Path
import pytest
from peaso.checks.selected_configuration_content_observed_20261020 import observation,RULES
from peaso.checks import aws_selected_configuration_secret_review_20261020 as aws
from peaso.checks import azure_selected_configuration_secret_review_20261020 as arm
from peaso.checks import azure_selected_storage_secret_review_20261020 as storage
from peaso.checks import azure_devops_selected_content_secret_review_20261020 as devops
MODULES=[(aws,'aws_selected_configuration_secret_review_20261020_fixtures.json'),(arm,'azure_selected_secrets_admission_20261020_fixtures.json'),(storage,'azure_selected_storage_secret_review_20261020_fixtures.json'),(devops,'azure_devops_selected_content_secret_review_20261020_fixtures.json')]

from types import SimpleNamespace
from peaso.checks import azure_selected_declaration_secret_review_20261020 as declarations
MODULES += [pytest.param(SimpleNamespace(CHECK=d['id'],evaluate=declarations.EVALUATORS[profile]),'azure_declaration_secrets_admission_20261020_fixtures.json',id='azure_declaration_'+profile)for profile,d in zip(('app_configuration','data_factory','synapse'),declarations.DECLARATIONS)]

from types import SimpleNamespace
from peaso.checks import azure_selected_log_sample_secret_review_20261020 as declarations
MODULES += [pytest.param(SimpleNamespace(CHECK=d['id'],evaluate=declarations.EVALUATORS[profile]),'azure_log_samples_admission_20261020_fixtures.json',id='azure_log_'+profile)for profile,d in zip(('workspace','application'),declarations.DECLARATIONS)]

from peaso.checks import aws_s3_selected_source_secret_review_20261020 as s3
MODULES += [pytest.param(s3,'aws_s3_selected_source_native_cases_20261020.json',id='aws_s3')]

from peaso.checks import azure_ml_selected_job_secret_review_20261020 as ml
MODULES += [pytest.param(SimpleNamespace(CHECK=ml.DECLARATION['id'],evaluate=ml.evaluate),'azure_ml_job_variants_native_cases_20261021.json',id='azure_ml')]

from peaso.checks import k8s_selected_log_sample_secret_review_20261020 as k8s_logs
MODULES += [pytest.param(k8s_logs,'k8s_selected_log_sample_admitted_cases_20261020.json',id='k8s_logs')]

from peaso.checks import azure_databricks_notebook_secret_review_20261020 as notebook
MODULES += [pytest.param(SimpleNamespace(CHECK=notebook.DECLARATION['id'],evaluate=notebook.evaluate),'azure_databricks_current_native_cases_20261021.json',id='azure_databricks')]

from peaso.checks import azure_ml_selected_asset_secret_review_20261020 as ml_assets
MODULES += [pytest.param(SimpleNamespace(CHECK=d['id'],evaluate=ml_assets.environment if 'environment_conda' in d['id'] else ml_assets.code),'azure_ml_asset_secrets_admission_20261020_fixtures.json',id='azure_ml_asset_'+d['kind'])for d in ml_assets.DECLARATIONS]

from peaso.checks.gcp_dataproc_source_runtime_admission_20261020 import CHECK_IDS as dataproc_ids
from peaso.checks import CHECKS, fixtures

def current_registered_inputs(identities):
    # Startup already verifies the sealed current producers. Exercise current
    # registered facts here, leaving the immutable older loaders to history tests.
    registered = {check.id: check for check in CHECKS}
    assert len(identities) == len(set(identities))
    assert set(identities) <= set(registered)
    return [(dict(id=ident, kind=registered[ident].kind), registered[ident].evaluate) for ident in identities]

MODULES += [pytest.param(SimpleNamespace(CHECK=d['id'],evaluate=fn,current_native=True),'gcp_dataproc_source_runtime_cases_20261020.json',id='gcp_dataproc_'+d['kind'])for d,fn in current_registered_inputs(dataproc_ids)]

from peaso.checks import k8s_selected_metadata_secret_review_20261020 as k8s_metadata
MODULES += [pytest.param(k8s_metadata,'k8s_selected_metadata_secret_cases_20261020.json',id='k8s_metadata')]

from peaso.checks.gcp_workbench_source_runtime_admission_20261020 import CHECK_IDS as workbench_ids
MODULES += [pytest.param(SimpleNamespace(CHECK=d['id'],evaluate=fn,current_native=True),'gcp_workbench_source_runtime_cases_20261020.json',id='gcp_workbench_'+d['kind'])for d,fn in current_registered_inputs(workbench_ids)]

from peaso.checks.gcp_dataflow_batch_source_runtime_consumer_20261020 import DECLARATIONS as JOB_DECLARATIONS
jobs_ids = tuple(row["id"] for row in JOB_DECLARATIONS)
MODULES += [pytest.param(SimpleNamespace(CHECK=d['id'],evaluate=fn,current_native=True),'gcp_dataflow_batch_source_runtime_cases_20261020.json',id='gcp_job_source_'+d['kind'])for d,fn in current_registered_inputs(jobs_ids)]

from peaso.checks import aws_codebuild_buildspec_runtime_consumer_20261020 as codebuild
MODULES += [pytest.param(SimpleNamespace(CHECK=codebuild.DECLARATION['id'], evaluate=codebuild.evaluate), 'aws_codebuild_buildspec_runtime_cases_20261020.json', id='aws_codebuild_inline')]

def native(module,file,branch):
    cid=module.CHECK
    if getattr(module, 'current_native', False):
        from tests.shared_admission_epoch_compatibility_20261020 import snapshot_cases
        data = {cid: snapshot_cases(fixtures.CASES[cid])}
    else:
        data=json.loads((Path('peaso/checks')/file).read_text())
    if 'captures' in data:
        row=next(r for r in data['captures'] if r['expected_status']==branch.upper())
        return deepcopy(next(f for f in row['findings'] if f['check_id']==cid and f['status']==branch.upper()))
    if cid in data:
        row=data[cid];item,index=row[branch],row[branch+'_index']
    else:
        row=next(r for r in data['cases']if r['status']==branch.upper());item,index=row['input']['item'],row['input']['index']
    status,evidence=module.evaluate(item,index)
    return {'provider':RULES[cid][0],'check_id':cid,'status':status,'evidence':evidence}

@pytest.mark.parametrize('module,file',MODULES)
@pytest.mark.parametrize('branch',['pass','fail','unknown'])
def test_native_current_shapes(module,file,branch):
    f=native(module,file,branch);assert f['status']==branch.upper();text=observation(f)
    if branch=='unknown':assert text is None
    else:assert text and len(text.split())<=35

@pytest.mark.parametrize('module,file',MODULES)
@pytest.mark.parametrize('fault',['provider','status','complete','coverage','credential_validation','engines','leaks'])
def test_missing_or_flipped_facts_cannot_inherit_decisive_copy(module,file,fault):
    f=native(module,file,'pass')
    if fault=='provider':f['provider']='gcp' if f['provider']=='k8s' else 'k8s'
    elif fault=='status':f['status']='FAIL'
    elif fault=='complete':f['evidence']['complete']=False
    elif fault=='coverage':f['evidence']['coverage']='all_content'
    elif fault=='credential_validation':f['evidence']['credential_validation']='verified'
    elif fault=='leaks':f['evidence']['secret_leaks']=[{}]
    elif 'engines'in f['evidence']:f['evidence']['engines'][0]['status']='unavailable'
    else:f['evidence']['parts'][0]['engines'][0]['status']='unavailable'
    assert observation(f)is None


@pytest.mark.parametrize('branch',['pass','fail','unknown'])
def test_selected_s3_actual_server_summary_is_brief(branch):
    import re
    from peaso.checks.aws_evidence_explanations import evidence_summary
    f=native(s3,'aws_s3_selected_source_native_cases_20261020.json',branch)
    text=evidence_summary(f)
    assert text and len(re.split(r'[.!?] +',text))<=3
    if branch=='unknown':
        assert 'undetermined' in text and 'no clean result' in text


def test_actual_incomplete_metadata_hit_has_safe_brief_backend_summary():
    from peaso.checks.k8s_evidence_explanations import evidence_summary
    f=json.loads(Path('tests/fixtures/k8s-selected-metadata-partial-evidence-review-20261020.json').read_text())
    before=deepcopy(f)
    assert f['status']=='FAIL'and f['evidence']['complete']is False
    text=evidence_summary(f)
    assert text and 'inspection is incomplete' in text and text.count('.')==2
    assert 'not validated' in text and f==before
    f['status']='PASS'
    assert observation(f)is None and evidence_summary(f)is None
    f['status']='FAIL';f['evidence']['secret_leaks']=[]
    assert observation(f)is None and evidence_summary(f)is None


@pytest.mark.parametrize('fault',['no_completed_engine','wrong_version','bad_part_completion','bad_coverage','raw_value','missing_detector'])
def test_incomplete_metadata_hit_needs_coherent_native_detector_facts(fault):
    from peaso.checks.k8s_evidence_explanations import evidence_summary
    f=json.loads(Path('tests/fixtures/k8s-selected-metadata-partial-predicate-evidence-review-20261020.json').read_text())
    e=f['evidence'];part=e['parts'][0]
    if fault=='no_completed_engine':
        for engine in part['engines']:engine['status']='unavailable'
        part['complete']=False
    elif fault=='wrong_version':part['engines'][0]['version']='unreviewed'
    elif fault=='bad_part_completion':part['complete']=False
    elif fault=='bad_coverage':e['coverage']='all_cluster_metadata'
    elif fault=='raw_value':e['secret_leaks'][0]['value']='never-display-this'
    else:e['secret_leaks'][0]['detectors']=[]
    assert observation(f)is None and evidence_summary(f)is None


def test_actual_consolidated_metadata_hit_has_scope_bound_brief_summary():
    from peaso.checks.k8s_evidence_explanations import evidence_summary
    f=json.loads(Path('tests/fixtures/k8s-selected-metadata-consolidated-evidence-review-20261020.json').read_text())
    before=deepcopy(f);text=evidence_summary(f)
    assert text and 'selected object labels or annotations' in text and 'not validated' in text and text.count('.')==2
    assert 'complete'not in text and f==before
    for field in ('linked_check_ids','secret_fingerprint'):
        invalid=deepcopy(f);invalid.pop(field)
        assert observation(invalid)is None and evidence_summary(invalid)is None


@pytest.mark.parametrize('scenario',['pass','fail','unknown','partial_trusted_fail'])
def test_workbench_actual_public_engine_evidence_remains_brief(scenario):
    proof=json.loads(Path('tests/fixtures/public_secret_captures/workbench-source-runtime-public-findings-20261020.json').read_text())
    record=next(r for r in proof['records']if r['scenario']==scenario)
    from peaso.finding_observation import evidence_summary
    for finding in record['public_findings']:
        before=deepcopy(finding);summary=observation(finding)
        if finding['status']=='UNKNOWN':assert summary is None
        else:
            assert summary and len(summary.split())<=35
            assert bool('inspection is incomplete' in summary)==(scenario=='partial_trusted_fail')
            assert 'Workbench referenced source' in evidence_summary(finding)
        assert finding==before


@pytest.mark.parametrize('fault',['provider','status','fingerprint','linked','scope','resource','path','leak','flags'])
def test_workbench_consolidated_hit_rejects_unbound_public_facts(fault):
    rows=json.loads(Path('tests/fixtures/gcp-workbench-source-evidence-review-20261020.json').read_text())
    finding=deepcopy(next(f for fs in rows.values()for f in fs if f['status']=='FAIL'))
    if fault=='provider':finding['provider']='aws'
    elif fault=='status':finding['status']='PASS'
    elif fault=='fingerprint':finding['secret_fingerprint']='0'*64
    elif fault=='linked':finding['linked_check_ids'].append('unrelated')
    elif fault=='leak':finding['evidence']['secret_leaks'][0]['value']='not-retained'
    elif fault=='flags':finding['evidence'].update(complete=True,coverage='incomplete')
    else:finding['evidence']['secret_leaks'][0]['locations'][0][{'scope':'scope','resource':'resource_id','path':'path'}[fault]]='unbound'
    assert observation(finding)is None
