"""Observed source applicability shapes stay factual, brief and status-preserving."""
from copy import deepcopy
import pytest
from peaso.checks.aws_scope_observed_evidence import REVIEWED_SCOPES,evidence_summary
from tests.test_peaso_aws_typed_finding_summary import actual

@pytest.mark.parametrize('row',REVIEWED_SCOPES,ids=lambda r:r['id']+'-'+r['status'])
def test_each_scope_sentence_uses_the_actual_registered_evaluator_witness(row):
 retired_sns=row['id']=='aws.cb.sns.policy_prohibit_public_access_perimeter' and row['case']=='not_applicable'
 # The retired id (fe6f7901) resolves to its surviving native, whose fixture
 # names the same policy-less topic witness 'no_policy'.
 finding=actual(row['id'],'no_policy' if retired_sns else row['case']);before=deepcopy(finding)
 if retired_sns:
  # GetTopicAttributes may omit Policy due to caller authorization. The old
  # applicability witness is historical, not proof of an absent policy now.
  assert finding['status']=='UNKNOWN'
  assert finding['evidence']=={'reason':'missing fact: Policy'}
  assert evidence_summary(finding)is None
  assert finding==before
  return
 assert finding['status']==row['status']
 assert finding['evidence']==row['witness']
 text=evidence_summary(finding)
 assert text==row['summary']
 assert len(text.split())<=40
 assert not text.startswith(('Observed evidence:','No observed evidence','Observed value:'))
 assert finding==before

@pytest.mark.parametrize('row',REVIEWED_SCOPES,ids=lambda r:r['id']+'-'+r['status'])
def test_status_and_witness_are_both_required(row):
 finding={'provider':'aws','check_id':row['id'],'status':row['status'],'evidence':deepcopy(row['witness'])}
 for status in ('PASS','FAIL','UNKNOWN','DENIED','EMPTY'):
  assert evidence_summary(dict(finding,status=status))is None
 assert evidence_summary(dict(finding,provider='gcp'))is None
 assert evidence_summary(dict(finding,check_id='new.unreviewed.check'))is None
 for empty in ({},None,[],False):
  assert evidence_summary(dict(finding,evidence=empty))is None

@pytest.mark.parametrize('row',REVIEWED_SCOPES,ids=lambda r:r['id']+'-'+r['status'])
def test_missing_or_wrong_typed_deciding_values_do_not_become_facts(row):
 for field,original in row['witness'].items():
  omitted=deepcopy(row['witness']);omitted.pop(field)
  f={'provider':'aws','check_id':row['id'],'status':row['status'],'evidence':omitted}
  assert evidence_summary(f)is None
  for malformed in (0,False,None,'unexpected-value',{'unexpected':True}):
   if type(malformed)is type(original)and malformed==original:continue
   bad=deepcopy(row['witness']);bad[field]=malformed
   assert evidence_summary(dict(f,evidence=bad))is None


def test_manual_ses_review_does_not_claim_effective_public_access():
 row=next(r for r in REVIEWED_SCOPES if r['status']=='MANUAL')
 text=evidence_summary({'provider':'aws','check_id':row['id'],'status':'MANUAL','evidence':row['witness']})
 assert 'both a public Allow and an explicit Deny'in text
 assert 'review whether'in text
 assert 'is public'not in text
