"""Native SCP protection of GuardDuty, Config, Security Hub and CloudTrail; no customer inputs."""
import copy

from peaso.checks import evaluate_check
from peaso.finding_observation import evidence_summary

CID = 'aws_organizations_security_service_tamper_scp'
SCOPE = '123456789012/us-east-1'
MANAGEMENT = '123456789012'
MEMBER = '222222222222'
ORG = {'id': 'o-abcdefghij', 'Organization': {'Id': 'o-abcdefghij', 'MasterAccountId': MANAGEMENT}}
ADMIN = 'arn:aws:iam::*:role/SecurityAdmin'

GUARDDUTY = ['guardduty:DeleteDetector', 'guardduty:UpdateDetector', 'guardduty:DisassociateFromMasterAccount',
             'guardduty:DisassociateFromAdministratorAccount']
CONFIG = ['config:StopConfigurationRecorder', 'config:DeleteConfigurationRecorder', 'config:DeleteDeliveryChannel']
SECURITYHUB = ['securityhub:DisableSecurityHub', 'securityhub:DisassociateFromMasterAccount',
               'securityhub:DisassociateFromAdministratorAccount']
CLOUDTRAIL = ['cloudtrail:StopLogging', 'cloudtrail:DeleteTrail', 'cloudtrail:UpdateTrail', 'cloudtrail:PutEventSelectors']


def deny(actions, **extra):
    return {'Effect': 'Deny', 'Action': actions, 'Resource': '*', **extra}


def member(*statements, account=MEMBER):
    return {'AccountId': MANAGEMENT, 'TargetAccountId': account, 'OrganizationId': 'o-abcdefghij',
            'ScpApplicable': True, 'Complete': True,
            'Policies': [{'Id': 'p-fullaccess', 'Content': {'Statement': [{'Effect': 'Allow', 'Action': '*', 'Resource': '*'}]}},
                         {'Id': 'p-guardrails', 'Content': {'Statement': list(statements)}}]}


def management():
    return {'AccountId': MANAGEMENT, 'TargetAccountId': MANAGEMENT, 'OrganizationId': 'o-abcdefghij',
            'ScpApplicable': False, 'Complete': True, 'Policies': []}


def index(rows, status='collected'):
    facts = {'context': {'provider': 'aws', 'scope': SCOPE, 'created_at': '2026-11-18T00:00:00Z'}, 'collections': {}}
    for kind, items, state in (('organization', [ORG], 'collected'), ('organization_effective_scp', rows, status)):
        facts['collections'][kind] = [{'type': kind, 'scope': MANAGEMENT + '/global', 'status': state, 'items': items}]
        facts[kind] = [{'type': kind, 'scope': MANAGEMENT + '/global', 'data': item} for item in items]
    return facts


def evaluate(rows, status='collected'):
    return evaluate_check(CID, copy.deepcopy(ORG), index(rows, status))


def test_specific_actions_with_admin_role_exemption_pass_and_record_the_exemption():
    exempt = {'ArnNotLike': {'aws:PrincipalArn': [ADMIN]}}
    status, evidence = evaluate([management(), member(deny(GUARDDUTY + CONFIG + SECURITYHUB, Condition=exempt),
                                                      deny(CLOUDTRAIL, Condition={'StringNotLike': {'aws:PrincipalArn': ADMIN}}))])
    assert status == 'PASS'
    assert evidence['assessed_accounts'] == [MEMBER] and evidence['scp_exempt_accounts'] == [MANAGEMENT]
    assert evidence['exempted_principals'] == {MEMBER: [ADMIN]}


def test_only_cloudtrail_protected_fails_listing_the_other_services():
    # The audited organization: root, trail, region and leave-org guardrails, nothing for the detectors.
    statements = [deny(CLOUDTRAIL, Condition={'ArnNotLike': {'aws:PrincipalArn': ADMIN}}),
                  deny(['organizations:LeaveOrganization']),
                  deny('*', Condition={'StringLike': {'aws:PrincipalArn': 'arn:aws:iam::*:root'}}),
                  {'Effect': 'Deny', 'NotAction': ['iam:*', 'sts:*'], 'Resource': '*',
                   'Condition': {'StringNotEquals': {'aws:RequestedRegion': ['eu-west-1']}}}]
    status, evidence = evaluate([management(), member(*statements)])
    assert status == 'FAIL'
    assert evidence['accounts_without_tamper_deny'] == [MEMBER]
    assert evidence['unprotected_services'] == {MEMBER: ['config', 'guardduty', 'securityhub']}
    assert set(evidence['missing_actions'][MEMBER]) == set(GUARDDUTY + CONFIG + SECURITYHUB)
    assert 'GuardDuty' in evidence_summary({'provider': 'aws', 'check_id': CID, 'status': status, 'evidence': evidence})


def test_service_and_global_wildcards_count_case_insensitively():
    assert evaluate([member(deny(['GuardDuty:*', 'config:Delete*', 'config:stop*', 'securityhub:*', 'cloudtrail:*']))])[0] == 'PASS'
    assert evaluate([member(deny('*', Condition={'ArnNotEquals': {'aws:PrincipalArn': ADMIN}}))])[0] == 'PASS'
    status, evidence = evaluate([member(deny(['guardduty:Delete*', 'config:*', 'securityhub:*', 'cloudtrail:*']))])
    assert status == 'FAIL' and evidence['missing_actions'][MEMBER] == [
        'guardduty:DisassociateFromAdministratorAccount', 'guardduty:DisassociateFromMasterAccount', 'guardduty:UpdateDetector']


def test_region_conditioned_deny_does_not_protect():
    region = {'StringEquals': {'aws:RequestedRegion': 'us-east-1'}}
    status, evidence = evaluate([member(deny(['guardduty:*', 'config:*', 'securityhub:*', 'cloudtrail:*'], Condition=region))])
    assert status == 'FAIL'
    assert evidence['unprotected_services'][MEMBER] == ['cloudtrail', 'config', 'guardduty', 'securityhub']
    assert 'guardduty:DeleteDetector' in evidence['conditionally_denied_actions'][MEMBER]


def test_exemptions_that_cover_every_principal_or_scoped_resources_do_not_protect():
    everyone = {'ArnNotLike': {'aws:PrincipalArn': 'arn:aws:iam::*:role/*'}}
    assert evaluate([member(deny('*', Condition=everyone))])[0] == 'FAIL'
    scoped = {'Effect': 'Deny', 'Action': '*', 'Resource': 'arn:aws:cloudtrail:*:*:trail/org-trail'}
    assert evaluate([member(scoped)])[0] == 'FAIL'


def test_management_account_alone_is_not_applicable():
    assert evaluate([management()])[0] == 'NOT_APPLICABLE'


def test_unavailable_or_forged_scp_data_is_unknown():
    assert evaluate([], status='denied')[0] == 'UNKNOWN'
    assert evaluate([member(deny('*'))], status='partial')[0] == 'UNKNOWN'
    assert evaluate([])[0] == 'UNKNOWN'
    # A member account cannot exempt itself by clearing the applicability flag.
    forged = member(); forged['ScpApplicable'] = False
    assert evaluate([forged])[0] == 'UNKNOWN'
