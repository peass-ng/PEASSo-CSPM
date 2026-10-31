"""Review contracts and genuine registered predicate fixtures for AWS guidance."""
from copy import deepcopy
import pytest
from peaso.checks import CHECKS, CHECK_ALIASES
from peaso.checks.fixtures import CASES
from peaso.checks.aws_remaining_clarity_reviewed import ROWS, description
from peaso.checks.aws_remaining_finding_summary import evidence_summary

CHECK_BY_ID={c.id:c for c in CHECKS}
RETIRED_SNS='aws.cb.sns.policy_prohibit_public_access_perimeter'
ACTIVE_SNS='aws.cb.sns.policy_no_unrestricted_wildcard'


def _current_id(cid):
    if cid == RETIRED_SNS:
        assert CHECK_ALIASES[cid] == ACTIVE_SNS
        return ACTIVE_SNS
    return cid


# These native corrections were accepted after the copy-only review. Reconstruct
# only their exact inverse, then compare with the ORIGINAL immutable binding.
# The successor hash also rejects any additional, unreviewed function change.
# Acceptance: docs/aws-review/{network-sdk-closure-review,data-sdk-closure-review,
# services-closure-review,network-semantic-review}.{json,md}; integrated in
# 15842280dfb336f356497451d94ec46b2ba5d4ee. This does not execute old predicates.


def _cases(cid):
    # These two existing registry fixtures live in test_peaso_checks.py.
    if cid=='aws.iam.no_full_admin':
        return {'pass':{'PolicyDocument':{'Statement':[]}},'fail':{'PolicyDocument':{'Statement':[{'Effect':'Allow','Action':'*','Resource':'*'}]}}}
    if cid=='aws.ec2.restrict_internet_ingress':
        return {'pass':{'IpPermissions':[]},'fail':{'IpPermissions':[{'IpProtocol':'tcp','FromPort':22,'ToPort':22,'IpRanges':[{'CidrIp':'0.0.0.0/0'}]}]}}
    return CASES[_current_id(cid)]

@pytest.mark.parametrize('cid',sorted(ROWS))
def test_registered_positive_negative_or_explicit_review_branches(cid):
    cases=_cases(cid)
    branches=['pass','fail']
    if cid in {'aws.b.acm.pending_validation_review','aws.claude2_a.config.aggregation_authorization_trusted','aws.claude2_a.dlm.snapshot_sharing_trusted_accounts'}:
        branches=['pass','manual']
    for branch in branches:
        status,evidence=CHECK_BY_ID[_current_id(cid)].evaluate(deepcopy(cases[branch]),deepcopy(cases.get(branch+'_index',cases.get('index',{}))))
        expected='UNKNOWN' if cid=='aws.c2b.ecs.container_instance_in_vpc' and branch=='fail' else branch.upper()
        assert status==expected,(cid,branch,status,evidence)
        finding={'provider':'aws','status':status,'check_id':cid,'evidence':evidence};before=deepcopy(finding)
        summary=evidence_summary(finding)
        if status != 'FAIL':assert summary is None
        if summary:assert isinstance(summary,str) and len(summary)<300
        assert finding==before


def test_unknown_unowned_and_nonfailure_observations_are_not_fabricated():
    cid=next(iter(ROWS))
    for status in ['PASS','UNKNOWN','MANUAL','DENIED','NOT_APPLICABLE']:
        assert evidence_summary({'provider':'aws','status':status,'check_id':cid,'evidence':{}}) is None
    assert evidence_summary({'provider':'aws','status':'FAIL','check_id':cid,'evidence':None}) is None
    assert evidence_summary({'provider':'aws','status':'FAIL','check_id':'other','evidence':{}}) is None
    assert evidence_summary({'provider':'gcp','status':'FAIL','check_id':cid,'evidence':{}}) is None
    value={'nested':[]};result=description('unreviewed',value);result['nested'].append(1)
    assert value['nested']==[]

@pytest.mark.parametrize('port',[22,443,5432])
def test_broad_ingress_observation_names_protocol_port_without_claiming_reachability(port):
    finding={'provider':'aws','status':'FAIL','check_id':'aws.ec2.restrict_internet_ingress','evidence':{'internet_ingress':[{'protocol':'tcp','from_port':port,'to_port':port,'source':'0.0.0.0/0'}]}}
    assert evidence_summary(finding)==f'The security group allows Internet ingress to tcp/{port}.'


def test_longer_kinesis_retention_is_not_described_as_short_retention():
    finding={'provider':'aws','status':'FAIL','check_id':'aws.cb.kinesis.retention_exactly_168h','evidence':{'retention_hours':8760}}
    assert evidence_summary(finding)=='Kinesis retention is 8760 hours; this profile prefers exactly 168.'


def test_aws_managed_key_does_not_become_plaintext_claim():
    finding={'provider':'aws','status':'FAIL','check_id':'aws.cb.sqs.cmk_encryption','evidence':{'kms_master_key_id':'alias/aws/sqs'}}
    assert evidence_summary(finding)=='The queue declares the AWS-managed SQS KMS alias; this profile prefers a customer-managed key.'


def test_redshift_disabled_and_encrypted_missing_reference_are_distinct_observations():
    finding={'provider':'aws','status':'FAIL','check_id':'aws.b.redshift.kms_key_declared','evidence':{'encrypted':False}}
    assert evidence_summary(finding)=='The Redshift cluster declares storage encryption disabled.'
    finding['evidence']={'encrypted':True,'kms_key_id':None}
    assert evidence_summary(finding)=='The encrypted Redshift cluster has no KMS key reference in the complete native inventory.'


def test_expired_certificate_uses_past_tense():
    finding={'provider':'aws','status':'FAIL','check_id':'aws.b.acm.expiry_thirty_days','evidence':{'remaining_calendar_days':-4}}
    assert evidence_summary(finding)=='The certificate expired 4 calendar days before the snapshot date.'


@pytest.mark.parametrize('cid',sorted(ROWS))
@pytest.mark.parametrize('evidence',[{}, {'unrelated':True}, {'internet_ingress':[None]}, {'configured':True}, {'short_retention_rules':[{'delete_after_days':'7'}]}])
def test_incomplete_or_malformed_facts_do_not_get_static_failure_claims(cid,evidence):
    assert evidence_summary({'provider':'aws','status':'FAIL','check_id':cid,'evidence':evidence}) is None

@pytest.mark.parametrize('cid',sorted(ROWS))
def test_native_positive_evidence_relabelled_fail_does_not_invent_weakness(cid):
    fixture=_cases(cid)
    status,evidence=CHECK_BY_ID[_current_id(cid)].evaluate(deepcopy(fixture['pass']),deepcopy(fixture.get('pass_index',fixture.get('index',{}))))
    if status=='PASS':assert evidence_summary({'provider':'aws','status':'FAIL','check_id':cid,'evidence':evidence}) is None
