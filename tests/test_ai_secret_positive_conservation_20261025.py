"""Observed incomplete-content AI downgrade must retain typed detector positives."""
import copy,json
from pathlib import Path
import pytest
from peaso.ai.finding_reviews import apply_review,apply_report_reviews,review_index


def cases():
 p=Path(__file__).parent/'ai-secret-positive-redacted.json'
 if not p.exists():p=Path(__file__).parent/'fixtures/ai-secret-positive-redacted.json'
 return json.loads(p.read_text())['cases']

@pytest.mark.parametrize('provider',['aws','gcp','azure','k8s'])
@pytest.mark.parametrize('verdict',['PASS','UNKNOWN','DENIED','MANUAL','NOT_APPLICABLE','EMPTY'])
def test_typed_source_bound_secret_remains_fail_across_providers(provider,verdict):
 case=copy.deepcopy(cases()[0]);f=case['finding'];f['provider']=provider;f['scope']={'aws':'123456789012/us-east-1','gcp':'projects/owned-qa','azure':'/subscriptions/00000000-0000-0000-0000-000000000001','k8s':'qa-owned'}[provider]
 for location in f['evidence']['secret_leaks'][0]['locations']:location['scope']=f['scope']
 f['status']='FAIL';f.pop('scanner_status',None);before=copy.deepcopy(f);review={**case['review'],'verdict':verdict}
 actual=apply_review(f,review_index({'reviews':{'hardening':[review]}}))
 assert actual['status']==actual['scanner_status']=='FAIL' and actual['ai_review']=={'verdict':'FAIL','reason':''}
 assert actual['evidence']==before['evidence'] and f==before
 assert actual['evidence_summary']==f['evidence']['observed']
 assert apply_review(actual,review_index({'reviews':{'hardening':[review]}}))==actual

@pytest.mark.parametrize('which',[0,1])
def test_actual_shape_including_saved_incorrect_overlay_is_repaired(which):
 case=copy.deepcopy(cases()[which]);f=case['finding'];before=copy.deepcopy(f)
 actual=apply_review(f,review_index({'reviews':{'hardening':[case['review']]}}))
 assert f==before and before['status']=='UNKNOWN' and before['scanner_status']=='FAIL'
 assert actual['status']=='FAIL' and actual['evidence']==before['evidence']

@pytest.mark.parametrize('mutation',['no-proof','hash-only','fingerprint','id','resource','secret-field','provider','no-location','empty-path','unbound-location','foreign-scope','bad-engine','bad-rule','extra-secret-value','invalid-validation'])
def test_incomplete_or_fabricated_detector_proof_does_not_block_ai_correction(mutation):
 case=copy.deepcopy(cases()[0]);f=case['finding'];f['status']='FAIL';e=f['evidence'];leak=e['secret_leaks'][0]
 if mutation=='no-proof':e.pop('secret_leaks')
 elif mutation=='hash-only':e['secret_leaks']=[{'fingerprint':leak['fingerprint']}]
 elif mutation=='fingerprint':leak['fingerprint']='not-a-fingerprint'
 elif mutation=='id':f['id']='unbound'
 elif mutation=='resource':f['resource_id']='unbound'
 elif mutation=='secret-field':f['secret_fingerprint']='e'*64
 elif mutation=='provider':f['provider']='unknown'
 elif mutation=='no-location':leak['locations']=[]
 elif mutation=='empty-path':leak['locations'][0]['path']=''
 elif mutation=='unbound-location':leak['locations'][0].pop('resource_id')
 elif mutation=='foreign-scope':
  for loc in leak['locations']:loc['scope']='projects/foreign'
 elif mutation=='bad-engine':leak['detectors'][0]['engine']='arbitrary-pattern-check'
 elif mutation=='bad-rule':leak['detectors'][0]['rule']={}
 elif mutation=='extra-secret-value':leak['value']='must-never-be-used-as-proof'
 else:e['credential_validation']='verified'
 review={'finding_id':f['id'],'verdict':'PASS','reason':'Affirmative corrected native setting'}
 assert apply_review(f,review_index({'reviews':{'hardening':[review]}}))['status']=='PASS'


def test_ordinary_failure_legitimate_correction_and_other_categories_are_unchanged():
 f={'id':'ordinary','category':'hardening','provider':'gcp','status':'FAIL','evidence':{'setting':True}};review={'finding_id':'ordinary','verdict':'PASS','reason':'Affirmative corrected native setting'}
 assert apply_review(f,review_index({'reviews':{'hardening':[review]}}))['status']=='PASS'
 case=cases()[0];assert apply_review(case['finding'],review_index({'reviews':{'exposure':[case['review']]}}))==case['finding']


def test_report_counts_preserve_positive_and_original_model_output_is_not_rewritten():
 case=copy.deepcopy(cases()[0]);report={'findings':[case['finding']],'stats':{'by_status':{'FAIL':1}},'ai':{'reviews':{'hardening':[case['review']]}}};before=copy.deepcopy(report);actual=apply_report_reviews(report)
 assert report==before and actual['stats']['by_status']=={'FAIL':1} and actual['findings'][0]['status']=='FAIL'
 assert actual['ai']==before['ai'], 'Retain original model output for provenance; guard changes effective finding only'


def test_prompt_explicitly_separates_positive_matches_and_required_absent_configuration():
 root=Path(__file__).parent/'sources'
 if not root.exists():root=Path(__import__('peaso.ai.finding_reviews',fromlist=['x']).__file__).parents[2]
 for name in ['hardening','exposure']:
  text=(root/'peaso/ai/agents'/f'{name}.yaml').read_text();assert 'incomplete coverage does not remove the recorded match' in text and 'Do not test or verify the matched credential' in text
 text=(root/'peaso/ai/agents/hardening.yaml').read_text();assert 'no attached Cloud DNS logging policy is not PASS' in text
