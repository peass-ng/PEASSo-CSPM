"""Isolated tests for the signed sw44 AWS draft module."""
from __future__ import annotations

import copy

import pytest

from peaso.checks import CHECKS
from peaso.checks import compliance_new_sw44 as sw

ACCOUNT = '123456789012'
REGION = 'us-east-1'
SCOPE = ACCOUNT + '/' + REGION
GLOBAL = ACCOUNT + '/global'


@pytest.fixture(scope='module', autouse=True)
def remove_draft_registrations_after_tests():
    yield
    CHECKS[:] = [check for check in CHECKS if check.id not in sw.SPECS]


def row(**fields):
    return {'id': 'test-id', 'AccountId': ACCOUNT, 'Region': REGION, **fields}


def snapshot(kind, item, *, extras=None, settings=None, created_at='2026-10-12T00:00:00Z'):
    index = {'context': {'provider': 'aws', 'scope': SCOPE, 'settings': settings or {},
                         'created_at': created_at}, 'collections': {}}
    records = {kind: (GLOBAL if kind == 'iam_identity' else SCOPE, [item])}
    records.update(extras or {})
    for resource_kind, (scope, items) in records.items():
        status = 'collected' if items else 'empty'
        index['collections'][resource_kind] = [{'type': resource_kind, 'scope': scope,
                                                  'status': status, 'items': copy.deepcopy(items)}]
        index[resource_kind] = [{'type': resource_kind, 'scope': scope, 'data': copy.deepcopy(x)}
                                for x in items]
    return index


def case(cid):
    kind = sw.SPECS[cid][0]
    settings, extras = {}, {}
    if cid == 'aws_g6_cloudtrail_region_logging_trail_present':
        item = row(RegionName=REGION, Enabled=True)
        extras['cloudtrail_account_inventory'] = (GLOBAL, [
            {'TrailARN': 'arn:aws:cloudtrail:us-east-1:123456789012:trail/main',
             'AccountId': ACCOUNT, 'HomeRegion': REGION, 'IsMultiRegionTrail': False,
             'Status': {'IsLogging': True}}])
    elif cid == 'aws_bedrock_automated_reasoning_policy_attached':
        item = row(ApplicationId='app-1', GuardrailIdentifier='guardrail-1',
                   GuardrailVersion='1', AutomatedReasoningPolicyArn='arn:aws:bedrock:us-east-1:123456789012:automated-reasoning-policy/p1',
                   PolicyStatus='ACTIVE')
    elif cid == 'aws_controltower_landing_zone_active':
        item = row(OrganizationId='o-example', InScopeAiAccountIds=[ACCOUNT],
                   LandingZones=[{'Arn': 'arn:aws:controltower:us-east-1:123456789012:landingzone/one', 'Status': 'ACTIVE'}])
    elif cid == 'aws_identity_center_sso_configured':
        item = row(AuditedAccountId=ACCOUNT, Instances=[{'InstanceArn': 'arn:aws:sso:::instance/ssoins-one',
            'IdentityStoreId': 'd-one', 'AccountAssignments': [{'AccountId': ACCOUNT,
            'PrincipalId': 'user-1', 'UserStatus': 'ENABLED'}]}])
    elif cid == 'aws_resolver_managed_domain_lists_block':
        item = row(VpcId='vpc-1', Designated=True, ApprovedManagedDomainListIds=['rslvr-fdl-1'],
                   Associations=[{'VpcId': 'vpc-1', 'Status': 'COMPLETE', 'Rules': [
                       {'FirewallDomainListId': 'rslvr-fdl-1', 'Action': 'BLOCK'}]}])
    elif cid == 'aws_inspector_cvss_version':
        settings['approved_cvss_version'] = '3.1'
        item = row(findingArn='arn:aws:inspector2:us-east-1:123456789012:finding/one',
                   status='ACTIVE', type='PACKAGE_VULNERABILITY',
                   packageVulnerabilityDetails={'cvss': [{'version': '3.1', 'baseScore': 8.1}]})
    elif cid == 'aws_incident_workflow_sla':
        settings['approved_response_hours'] = 4
        item = row(Id='finding-1', CreatedAt='2026-10-10T00:00:00Z',
                   UpdatedAt='2026-10-10T02:00:00Z', Workflow={'Status': 'NOTIFIED'},
                   Severity={'Label': 'HIGH'})
    elif cid == 'aws.pci.vpc.antispoofing_ingress':
        item = row(InternetFacing=True, ProtectedInternalCidrs=['10.0.0.0/8'],
                   CdeCidrs=['192.168.0.0/16'], OrderedIngressRules=[
                       {'Priority': 1, 'Action': 'DROP', 'SourceCidr': '10.0.0.0/8',
                        'DestinationCidr': '192.168.0.0/16', 'FromInternet': True},
                       {'Priority': 2, 'Action': 'PASS', 'SourceCidr': '0.0.0.0/0',
                        'DestinationCidr': '192.168.0.0/16', 'FromInternet': True}])
    elif cid == 'aws.pci.kms.enclave_attestation_events':
        settings['approved_golden_pcrs'] = {'PCR0': ['abc123']}
        item = row(EventId='event-1', EventSource='kms.amazonaws.com',
                   IsEnclaveAttestation=True, AttestationPcrs={'PCR0': 'abc123'})
    elif cid == 'aws.pci.iam.policy_arn_attachment':
        settings['required_policy_arn'] = 'arn:aws:iam::123456789012:policy/Required'
        item = row(IdentityType='ROLE', Arn='arn:aws:iam::123456789012:role/Sample',
                   AttachedManagedPolicies=[{'PolicyArn': settings['required_policy_arn']}])
    elif cid == 'aws_cis_backup_recovery_point_isolation':
        settings['backup_policy_requires_locked_copies'] = True
        item = row(RecoveryPointArn='arn:aws:backup:us-east-1:123456789012:recovery-point:abc',
                   BackupVaultName='vault', IsEncrypted=True,
                   Vault={'BackupVaultName': 'vault', 'Locked': True},
                   IndependentOfflineCopyEvidence=True)
    elif cid == 'aws_cis_lightsail_ssm_patch_compliance':
        arn = 'arn:aws:lightsail:us-east-1:123456789012:Instance/abc'
        item = row(arn=arn, SsmMatch={'Verified': True, 'LightsailArn': arn,
                   'InstanceId': 'mi-abc'}, PatchState={'InstanceId': 'mi-abc',
                   'MissingCount': 0, 'FailedCount': 0, 'InstalledRejectedCount': 0})
    else:
        raise AssertionError(cid)
    return kind, item, snapshot(kind, item, settings=settings, extras=extras)


def evaluate(cid, item, index):
    matches = [check for check in CHECKS if check.id == cid]
    assert len(matches) == 1
    return matches[0].evaluate(item, index)[0]


@pytest.mark.parametrize('cid', [cid for cid in sw.SPECS if cid != 'aws_incident_workflow_sla'])
def test_pass_and_fail(cid):
    kind, item, index = case(cid)
    assert evaluate(cid, item, index) == 'PASS'
    bad = copy.deepcopy(item)
    if cid == 'aws_g6_cloudtrail_region_logging_trail_present':
        index['collections']['cloudtrail_account_inventory'][0]['items'][0]['Status']['IsLogging'] = False
        index['cloudtrail_account_inventory'][0]['data']['Status']['IsLogging'] = False
        assert evaluate(cid, item, index) == 'FAIL'
        return
    elif cid == 'aws_bedrock_automated_reasoning_policy_attached':
        bad['AutomatedReasoningPolicyArn'] = ''
    elif cid == 'aws_controltower_landing_zone_active':
        bad['LandingZones'][0]['Status'] = 'FAILED'
    elif cid == 'aws_identity_center_sso_configured':
        bad['Instances'][0]['AccountAssignments'] = []
    elif cid == 'aws_resolver_managed_domain_lists_block':
        bad['Associations'][0]['Rules'][0]['Action'] = 'ALLOW'
    elif cid == 'aws_inspector_cvss_version':
        bad['packageVulnerabilityDetails']['cvss'][0]['version'] = '2.0'
    elif cid == 'aws.pci.vpc.antispoofing_ingress':
        bad['OrderedIngressRules'][0]['Priority'] = 3
    elif cid == 'aws.pci.kms.enclave_attestation_events':
        bad['AttestationPcrs']['PCR0'] = '000000'
    elif cid == 'aws.pci.iam.policy_arn_attachment':
        bad['AttachedManagedPolicies'] = []
    elif cid == 'aws_cis_backup_recovery_point_isolation':
        bad['IsEncrypted'] = False
    elif cid == 'aws_cis_lightsail_ssm_patch_compliance':
        bad['PatchState']['MissingCount'] = 1
    index['collections'][kind][0]['items'] = [copy.deepcopy(bad)]
    index[kind][0]['data'] = copy.deepcopy(bad)
    assert evaluate(cid, bad, index) == 'FAIL'


@pytest.mark.parametrize('workflow', ['NEW', 'NOTIFIED', 'RESOLVED', 'SUPPRESSED'])
@pytest.mark.parametrize('severity', ['HIGH', 'CRITICAL'])
@pytest.mark.parametrize('provider_updated_at', [
    '2026-10-10T02:00:00Z',  # Previously produced a false PASS for NOTIFIED/RESOLVED.
    '2026-10-11T12:00:00Z',  # Previously produced a false FAIL despite an early response.
])
def test_securityhub_provider_timestamp_cannot_prove_workflow_response_sla(
        workflow, severity, provider_updated_at):
    # AWS BatchUpdateFindings does not change UpdatedAt when changing Workflow.
    # NEW can also be reset after investigation, so none of these current-state
    # records proves the first response time without workflow transition history.
    # https://docs.aws.amazon.com/cli/latest/reference/securityhub/batch-update-findings.html
    cid = 'aws_incident_workflow_sla'
    kind, item, index = case(cid)
    item.update(UpdatedAt=provider_updated_at, Workflow={'Status': workflow},
                Severity={'Label': severity})
    index['collections'][kind][0]['items'] = [copy.deepcopy(item)]
    index[kind][0]['data'] = copy.deepcopy(item)
    check = next(check for check in CHECKS if check.id == cid)
    status, evidence = check.evaluate(item, index)
    assert status == 'UNKNOWN'
    assert 'workflow transition history' in evidence['reason']
    assert 'UpdatedAt is not a workflow timestamp' in evidence['reason']


def test_securityhub_response_window_not_elapsed_is_not_applicable():
    cid = 'aws_incident_workflow_sla'
    _, item, index = case(cid)
    index['context']['created_at'] = '2026-10-10T03:00:00Z'
    assert evaluate(cid, item, index) == 'NOT_APPLICABLE'


@pytest.mark.parametrize('cid', list(sw.SPECS))
def test_unknown_for_incomplete_malformed_and_missing_fact(cid):
    kind, item, index = case(cid)
    incomplete = copy.deepcopy(index)
    incomplete['collections'][kind][0]['status'] = 'partial'
    assert evaluate(cid, item, incomplete) == 'UNKNOWN'
    malformed = copy.deepcopy(index)
    bad = copy.deepcopy(item)
    bad['AccountId'] = None
    malformed['collections'][kind][0]['items'] = [copy.deepcopy(bad)]
    malformed[kind][0]['data'] = copy.deepcopy(bad)
    assert evaluate(cid, bad, malformed) == 'UNKNOWN'
    absent = copy.deepcopy(index)
    del absent['collections'][kind]
    assert evaluate(cid, item, absent) == 'UNKNOWN'
    foreign = copy.deepcopy(index)
    foreign['context']['scope'] = '999999999999/us-east-1'
    assert evaluate(cid, item, foreign) == 'UNKNOWN'


@pytest.mark.parametrize('cid', [
    'aws_g6_cloudtrail_region_logging_trail_present',
    'aws_controltower_landing_zone_active',
    'aws_resolver_managed_domain_lists_block',
    'aws_inspector_cvss_version',
    'aws_incident_workflow_sla',
    'aws.pci.vpc.antispoofing_ingress',
    'aws.pci.kms.enclave_attestation_events',
])
def test_not_applicable(cid):
    kind, item, index = case(cid)
    changed = copy.deepcopy(item)
    if cid == 'aws_g6_cloudtrail_region_logging_trail_present':
        changed['Enabled'] = False
    elif cid == 'aws_controltower_landing_zone_active':
        changed['InScopeAiAccountIds'] = ['999999999999']
    elif cid == 'aws_resolver_managed_domain_lists_block':
        changed['Designated'] = False
    elif cid == 'aws_inspector_cvss_version':
        changed['status'] = 'CLOSED'
    elif cid == 'aws_incident_workflow_sla':
        changed['Severity']['Label'] = 'LOW'
    elif cid == 'aws.pci.vpc.antispoofing_ingress':
        changed['InternetFacing'] = False
    elif cid == 'aws.pci.kms.enclave_attestation_events':
        changed['IsEnclaveAttestation'] = False
    index['collections'][kind][0]['items'] = [copy.deepcopy(changed)]
    index[kind][0]['data'] = copy.deepcopy(changed)
    assert evaluate(cid, changed, index) == 'NOT_APPLICABLE'


@pytest.mark.parametrize('cid,setting', [
    ('aws_inspector_cvss_version', 'approved_cvss_version'),
    ('aws_incident_workflow_sla', 'approved_response_hours'),
    ('aws.pci.kms.enclave_attestation_events', 'approved_golden_pcrs'),
    ('aws.pci.iam.policy_arn_attachment', 'required_policy_arn'),
    ('aws_cis_backup_recovery_point_isolation', 'backup_policy_requires_locked_copies'),
])
def test_missing_customer_parameter_is_unknown(cid, setting):
    _, item, index = case(cid)
    del index['context']['settings'][setting]
    assert evaluate(cid, item, index) == 'UNKNOWN'


def test_dependency_and_matching_limits_are_unknown():
    cid = 'aws_g6_cloudtrail_region_logging_trail_present'
    _, item, index = case(cid)
    index['collections']['cloudtrail_account_inventory'][0]['status'] = 'partial'
    assert evaluate(cid, item, index) == 'UNKNOWN'

    cid = 'aws_cis_backup_recovery_point_isolation'
    kind, item, index = case(cid)
    item['IndependentOfflineCopyEvidence'] = False
    index['collections'][kind][0]['items'] = [copy.deepcopy(item)]
    index[kind][0]['data'] = copy.deepcopy(item)
    assert evaluate(cid, item, index) == 'UNKNOWN'

    cid = 'aws_cis_lightsail_ssm_patch_compliance'
    kind, item, index = case(cid)
    item['SsmMatch']['Verified'] = False
    index['collections'][kind][0]['items'] = [copy.deepcopy(item)]
    index[kind][0]['data'] = copy.deepcopy(item)
    assert evaluate(cid, item, index) == 'UNKNOWN'

    cid = 'aws.pci.vpc.antispoofing_ingress'
    kind, item, index = case(cid)
    item['OrderedIngressRules'][0]['SourceCidr'] = '10.0.0.0/9'
    index['collections'][kind][0]['items'] = [copy.deepcopy(item)]
    index[kind][0]['data'] = copy.deepcopy(item)
    assert evaluate(cid, item, index) == 'UNKNOWN'


def test_repeated_evaluation_does_not_change_facts():
    for cid in sw.SPECS:
        _, item, index = case(cid)
        original_item, original_index = copy.deepcopy(item), copy.deepcopy(index)
        assert evaluate(cid, item, index) == evaluate(cid, item, index)
        assert item == original_item and index == original_index


def test_enclave_missing_approved_pcr_is_unknown():
    cid = 'aws.pci.kms.enclave_attestation_events'
    _, item, index = case(cid)
    index['context']['settings']['approved_golden_pcrs']['PCR1'] = ['def456']
    assert evaluate(cid, item, index) == 'UNKNOWN'


@pytest.mark.parametrize('action', ['ALLOW', 'ALERT'])
@pytest.mark.parametrize('priority', [100, 300])
def test_dns_firewall_mixed_actions_cannot_certify_unconditional_blocking(action, priority):
    cid = 'aws_resolver_managed_domain_lists_block'
    kind, item, _ = case(cid)
    item['Associations'][0]['Priority'] = 101
    item['Associations'][0]['Rules'][0]['Priority'] = 200
    item['Associations'][0]['Rules'].append({'FirewallDomainListId': 'rslvr-fdl-1',
                                          'Action': action, 'Priority': priority})
    assert evaluate(cid, item, snapshot(kind, item)) == 'UNKNOWN'


@pytest.mark.parametrize('field,value', [('Qtype', 'A'), ('Qtype', 'ANY'),
    ('Qtype', ''), ('Qtype', None),
    ('FirewallDomainRedirectionAction', 'TRUST_REDIRECTION_DOMAIN'),
    ('FirewallDomainRedirectionAction', None),
    ('FirewallDomainRedirectionAction', 'invalid')])
def test_dns_firewall_restricted_or_malformed_filter_does_not_prove_all_queries_blocked(field, value):
    cid = 'aws_resolver_managed_domain_lists_block'
    kind, item, _ = case(cid)
    item['Associations'][0]['Rules'][0][field] = value
    assert evaluate(cid, item, snapshot(kind, item)) == 'UNKNOWN'


def test_dns_firewall_explicit_inspect_keeps_simple_block_proof():
    cid = 'aws_resolver_managed_domain_lists_block'
    kind, item, _ = case(cid)
    item['Associations'][0]['Rules'][0]['FirewallDomainRedirectionAction'] = 'INSPECT_REDIRECTION_DOMAIN'
    assert evaluate(cid, item, snapshot(kind, item)) == 'PASS'


@pytest.mark.parametrize('status,expected', [('CREATING', 'UNKNOWN'),
    ('CREATION_FAILED', 'UNKNOWN'), (None, 'UNKNOWN'), (True, 'UNKNOWN'),
    ('invalid', 'UNKNOWN'), ('COMPLETE', 'PASS')])
def test_dns_firewall_explicit_rule_status_must_be_complete(status, expected):
    cid = 'aws_resolver_managed_domain_lists_block'
    kind, item, _ = case(cid)
    item['Associations'][0]['Rules'][0]['Status'] = status
    assert evaluate(cid, item, snapshot(kind, item)) == expected
