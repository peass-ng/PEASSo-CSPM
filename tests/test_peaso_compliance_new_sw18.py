"""Offline signed Azure predicates, imported directly with registry isolation."""
from __future__ import annotations

import copy
import importlib
import json

import pytest

from peaso.checks import CHECKS

_before = list(CHECKS)
sw = importlib.import_module('peaso.checks.compliance_new_sw18')
OWN_CHECKS = {check.id: check for check in CHECKS if check.id in sw.IDS}
CHECKS[:] = _before

SCOPE = '/subscriptions/sub'
TENANT = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
PRINCIPAL = 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb'
ROLE = 'cccccccc-cccc-cccc-cccc-cccccccccccc'
ASSIGNMENT = 'dddddddd-dddd-dddd-dddd-dddddddddddd'
ROLE_ID = SCOPE + '/providers/Microsoft.Authorization/roleDefinitions/' + ROLE
VM = SCOPE + '/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm'
AT = '2026-10-12T00:00:00+00:00'


def proof():
    return {'tenant_verified': True, 'tenant_id': TENANT,
            'credential_context_id': 'capture1', 'customer_context_id': 'customer1'}


def path():
    return {'id': 'context-1', 'applicationId': 'azure-management', 'clientAppType': 'browser',
            'conditions': {'location': 'any', 'device': 'any', 'platform': 'any', 'risk': 'any'},
            'policyIds': ['ca1'], 'allowed': True, 'mfaRequired': True,
            'authenticationStrengthId': None, 'securityDefaultsProven': False}


def effective():
    return {'principalId': PRINCIPAL, 'roleDefinitionId': ROLE_ID, 'scope': SCOPE,
            'effective': True, 'principalType': 'User', 'accountEnabled': True,
            'effectiveSubscriptionScope': SCOPE, 'owner': True, 'writer': True,
            'paths': [path()]}


def obligations(names):
    return [{'name': name, 'applicable': True, 'satisfactory': True, 'observed_at': AT,
             'record_ids': ['record-' + name]} for name in names]


def scenario(check_id):
    kind = sw.META[check_id]['resource_kind']
    scope = '/tenants/' + TENANT if kind == 'directory_user' else SCOPE
    policy = {'scope': scope, 'status': 'collected', 'ancestorScopes': [],
              'approvedAuthenticationStrengthIds': ['strength1'],
              'nonPrivilegedMfaEquivalenceApproved': True,
              'confidentialVmIds': [VM], 'confidentialReviewMaxAgeSeconds': 86400,
              'patchReviewMaxAgeSeconds': 86400, 'softwareInventoryVmIds': [VM],
              'softwareInventoryMaxAgeSeconds': 86400,
              'softwareInventoryRequiredFields': ['softwareName', 'version', 'deviceId'],
              'requiredSoftwareNames': ['required-product'],
              'approvedTimeSourceIds': ['ntp-approved'],
              'approvedCredentialAdmins': [], 'approvedBackupPrincipalIds': [],
              'protectedScopes': [SCOPE], 'prohibitedRoleDefinitionIds': ['eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee'],
              'scopeAncestors': {SCOPE: []}, 'reviewMaxAgeDays': 30,
              'privilegedRoleDefinitionIds': [ROLE_ID],
              'requiredRoleAssignments': [{'roleDefinitionId': ROLE_ID, 'scope': SCOPE}],
              'authorizedRoleAssignments': [{'roleDefinitionId': ROLE_ID, 'scope': SCOPE,
                                            'principalIds': [PRINCIPAL]}]}
    for field in ('userRightsBaseline', 'timeSyncBaseline', 'sshBaseline'):
        policy[field] = {'name': field, 'version': '1.0.0', 'parameters': {'Required': 'value'},
                         'maxAgeSeconds': 86400, 'measurementResourceId': 'setting1',
                         'measurementReasonCode': 'ActualSetting'}
    metadata = {**proof(), 'subscription_tenants': {SCOPE: TENANT}, 'compliance_policy': policy}
    if kind == 'vm':
        row = {'id': VM, 'properties': {'storageProfile': {'osDisk': {'osType': 'Linux'}},
                  'securityProfile': {'securityType': 'ConfidentialVM', 'uefiSettings': {'vTpmEnabled': True}},
                  'osProfile': {'windowsConfiguration': {'patchSettings': {'patchMode': 'AutomaticByPlatform'}},
                                'linuxConfiguration': {'disablePasswordAuthentication': True,
                                                       'ssh': {'publicKeys': [{'path': '/home/user/.ssh/authorized_keys',
                                                                             'keyData': 'ssh-ed25519 public'}]}}}},
               'instanceView': {'statuses': [{'code': 'PowerState/running'}]}}
        if check_id in (sw.RDP_ID, sw.PATCH_ID):
            row['properties']['storageProfile']['osDisk']['osType'] = 'Windows'
    elif kind == 'role_assignment':
        row = {'id': SCOPE + '/providers/Microsoft.Authorization/roleAssignments/' + ASSIGNMENT,
               'properties': {'scope': SCOPE, 'principalId': PRINCIPAL, 'principalType': 'User',
                              'roleDefinitionId': ROLE_ID, 'condition': None}}
    else:
        row = {'id': PRINCIPAL, 'accountEnabled': True, '_provenance': proof()}
    dimensions = set(sw._ACCESS_DIMENSIONS) | set(sw._MFA_DIMENSIONS) | {
        'assignments', 'reports', 'parameters', 'exposure', 'process_records', 'software_pages',
        'installed_asset_universe', 'required_assets', 'protected_scopes', 'principal_lookup',
        'group_expansion', 'reviews', 'instances', 'decisions', 'scope_queries', 'decision_application',
        'directory_roles', 'registration', 'per_user_requirements', 'database_inventory', 'resource_inventory'}
    evidence = {'id': row['id'] + '#sw18:' + check_id, 'scope': scope,
                'check_id': check_id, 'subject_id': row['id'],
                '_provenance': {**proof(), 'read_only': True, 'adapter': 'sw18-resolved-v1',
                                'source_ids': [row['id']]},
                'coverage': {key: True for key in dimensions}}
    if check_id in (sw.RDP_ID, sw.CLOCK_ID, sw.SSH_ID):
        field = {sw.RDP_ID: 'userRightsBaseline', sw.CLOCK_ID: 'timeSyncBaseline', sw.SSH_ID: 'sshBaseline'}[check_id]
        baseline = policy[field]
        aid = VM + '/providers/Microsoft.GuestConfiguration/guestConfigurationAssignments/baseline'
        row['guestConfigurationAssignments'] = [{'id': aid, 'parent_id': VM,
                    'properties': {'latestReportId': 'report1', 'complianceStatus': 'Compliant',
                                   'guestConfiguration': {'name': baseline['name'], 'version': baseline['version'],
                                        'configurationParameter': [{'name': 'Required', 'value': 'value'}]}}}]
        row['_coverage'] = {'guestConfigurationAssignments': {'status': 'collected'}}
        measurement = {'sourceId': 'ntp-approved', 'synchronized': True, 'driftExceeded': False,
                       'protocolVersions': [2]}
        evidence.update(assignment_id=aid, effective_parameters={'Required': 'value'}, exposed=True,
                        report={'id': aid + '/reports/report1', '_provenance': {'representation': 'full'},
                                'properties': {'endTime': AT, 'complianceStatus': 'Compliant',
                                               'details': {'resources': [{'resourceId': 'setting1', 'reasons': [
                                                   {'code': 'ActualSetting', 'phrase': json.dumps(measurement)}]}]}}})
    elif check_id == sw.SOFTWARE_ID:
        evidence.update(observed_at=AT, softwareInventories=[{
            'id': VM + '/providers/Microsoft.Security/softwareInventories/product1',
            '_provenance': {'representation': 'full'},
            'properties': {'softwareName': 'required-product', 'version': '1.2', 'deviceId': 'host1'}}])
    elif check_id in (sw.CONFIDENTIAL_ID, sw.PATCH_ID):
        names = ('interfaces', 'tee_key_management', 'attestation', 'monitoring', 'annual_security_review',
                 'event_driven_security_review') if check_id == sw.CONFIDENTIAL_ID else (
                 'third_party_identification', 'third_party_testing', 'third_party_deployment',
                 'customer_approval', 'provider_rollout')
        evidence.update(reviewed_at=AT, obligations=obligations(names))
    elif check_id in (sw.CREDENTIAL_ID, sw.BACKUP_ID):
        action = 'Microsoft.Service/credentials/create' if check_id == sw.CREDENTIAL_ID else 'Microsoft.Sql/backup/restore'
        resource = SCOPE + '/resourceGroups/rg/providers/Microsoft.Sql/servers/sql/databases/db'
        evidence.update(actionInventory=[action], resourceIds=[resource], databaseIds=[resource],
                        principals=[{'id': PRINCIPAL, 'actions': [{'action': action, 'resourceId': resource,
                          'effectiveAccess': 'Denied', 'authorizedAttempt': {
                              'authorized': True, 'principalId': PRINCIPAL, 'action': action, 'resourceId': resource,
                              'record_id': 'attempt1', 'observed_at': AT, 'outcome': 'Denied'}}]}])
    elif check_id in (sw.PROHIBITED_ID, sw.SELECTED_ID):
        evidence.update(scopes=[{'scope': SCOPE, 'ancestorScopes': [], 'assignments': [copy.deepcopy(row)]}],
                        principals=[{'id': PRINCIPAL, 'type': 'User', 'resolved': True,
                                     'deleted': False, 'conforming': True}])
    elif check_id == sw.REVIEW_ID:
        evidence.update(effectiveAssignments=[effective()], reviews=[{
            'principalId': PRINCIPAL, 'roleDefinitionId': ROLE_ID, 'scope': SCOPE,
            'recurring': True, 'definition_id': 'review1', 'instances': [
                {'id': 'instance1', 'status': 'Completed', 'endDateTime': AT,
                 'decision': {'principalId': PRINCIPAL, 'applyResult': 'AppliedSuccessfully',
                              'decision': 'Approve', 'appliedDateTime': AT}}]}])
    elif check_id in (sw.OWNER_ID, sw.WRITER_ID):
        evidence['effectiveAssignments'] = [effective()]
    elif check_id == sw.USER_MFA_ID:
        evidence.update(privileged=False, requirements={'perUserMfaState': 'enabled'},
                        registration={'usableMfaRegistered': True}, paths=[path()])
    index = {'context': {'provider': 'azure', 'scope': scope, 'created_at': AT, 'metadata': metadata},
             'collections': {kind: [{'type': kind, 'scope': scope, 'status': 'collected',
                                    'service': 'Microsoft.Graph' if kind == 'directory_user' else 'Microsoft.Resources',
                                    '_provenance': proof(), 'items': [row]}],
                             sw.EVIDENCE_KIND: [{'type': sw.EVIDENCE_KIND, 'scope': scope,
                                                 'status': 'collected', 'items': [evidence]}]},
             kind: [{'type': kind, 'scope': scope, 'data': row}],
             sw.EVIDENCE_KIND: [{'type': sw.EVIDENCE_KIND, 'scope': scope, 'data': evidence}]}
    return row, index, evidence


def evaluate(check_id, row, index):
    return OWN_CHECKS[check_id].evaluate(row, index)


def set_measurement(evidence, **changes):
    reason = evidence['report']['properties']['details']['resources'][0]['reasons'][0]
    value = json.loads(reason['phrase'])
    value.update(changes)
    reason['phrase'] = json.dumps(value)


@pytest.mark.parametrize('check_id', sw.IDS)
def test_all_signed_predicates_safe_outcome(check_id):
    row, index, _ = scenario(check_id)
    expected = 'UNKNOWN' if check_id == sw.KEY_ID else 'PASS'
    assert evaluate(check_id, row, index)[0] == expected
    before_row, before_index = copy.deepcopy(row), copy.deepcopy(index)
    assert evaluate(check_id, row, index)[0] == expected
    assert row == before_row and index == before_index


@pytest.mark.parametrize('check_id', [value for value in sw.IDS if value != sw.KEY_ID])
def test_all_evaluable_signed_predicates_positive_failure(check_id):
    row, index, evidence = scenario(check_id)
    if check_id == sw.RDP_ID:
        evidence['report']['properties']['complianceStatus'] = 'NonCompliant'
    elif check_id == sw.CLOCK_ID:
        set_measurement(evidence, sourceId='unapproved-ntp')
    elif check_id == sw.SSH_ID:
        set_measurement(evidence, protocolVersions=[1, 2])
    elif check_id == sw.SOFTWARE_ID:
        evidence['softwareInventories'][0]['properties']['version'] = ''
    elif check_id == sw.CONFIDENTIAL_ID:
        row['properties']['securityProfile']['uefiSettings']['vTpmEnabled'] = False
    elif check_id == sw.PATCH_ID:
        evidence['obligations'][0]['satisfactory'] = False
    elif check_id in (sw.CREDENTIAL_ID, sw.BACKUP_ID):
        evidence['principals'][0]['actions'][0]['effectiveAccess'] = 'Allowed'
    elif check_id == sw.PROHIBITED_ID:
        index['context']['metadata']['compliance_policy']['prohibitedRoleDefinitionIds'] = [ROLE.upper()]
    elif check_id == sw.SELECTED_ID:
        evidence['principals'][0]['deleted'] = True
    elif check_id == sw.REVIEW_ID:
        evidence['reviews'] = []
    elif check_id in (sw.OWNER_ID, sw.WRITER_ID):
        evidence['effectiveAssignments'][0]['paths'][0].update(mfaRequired=False, policyIds=[])
    elif check_id == sw.USER_MFA_ID:
        evidence['registration']['usableMfaRegistered'] = False
    assert evaluate(check_id, row, index)[0] == 'FAIL'


@pytest.mark.parametrize('check_id', sw.IDS)
@pytest.mark.parametrize('boundary', ['partial', 'denied', 'malformed', 'missing', 'foreign', 'duplicate'])
def test_all_signed_predicates_unavailable_native_facts(check_id, boundary):
    row, index, _ = scenario(check_id)
    kind = sw.META[check_id]['resource_kind']
    if boundary in ('partial', 'denied'):
        index['collections'][kind][0]['status'] = boundary
    elif boundary == 'malformed':
        row['id'] = 7
    elif boundary == 'missing':
        row.pop('id')
    elif boundary == 'foreign':
        index['collections'][kind][0]['scope'] = '/subscriptions/foreign'
    else:
        index[kind].append(copy.deepcopy(index[kind][0]))
    assert evaluate(check_id, row, index)[0] == 'UNKNOWN'


@pytest.mark.parametrize('check_id', [value for value in sw.IDS if value != sw.KEY_ID])
@pytest.mark.parametrize('boundary', ['missing', 'partial', 'malformed', 'foreign', 'missing_policy'])
def test_supplemental_facts_cannot_invent_compliance(check_id, boundary):
    row, index, evidence = scenario(check_id)
    if boundary == 'missing':
        index.pop(sw.EVIDENCE_KIND)
        index['collections'].pop(sw.EVIDENCE_KIND)
    elif boundary == 'partial':
        index['collections'][sw.EVIDENCE_KIND][0]['status'] = 'partial'
    elif boundary == 'malformed':
        evidence['_provenance']['read_only'] = 'true'
    elif boundary == 'foreign':
        evidence['scope'] = '/subscriptions/foreign'
    else:
        if check_id == sw.USER_MFA_ID:
            evidence['requirements']['perUserMfaState'] = 'disabled'
        index['context']['metadata'].pop('compliance_policy')
    assert evaluate(check_id, row, index)[0] == 'UNKNOWN'


@pytest.mark.parametrize('check_id', [sw.RDP_ID, sw.CLOCK_ID, sw.SSH_ID])
@pytest.mark.parametrize('boundary', ['stale', 'wrong_baseline', 'wrong_version', 'wrong_parameters',
                                    'foreign_report', 'missing_report', 'assignment_partial', 'foreign_parent'])
def test_guest_reports_require_exact_current_baseline(check_id, boundary):
    row, index, evidence = scenario(check_id)
    guest = row['guestConfigurationAssignments'][0]['properties']['guestConfiguration']
    if boundary == 'stale':
        evidence['report']['properties']['endTime'] = '2020-01-01T00:00:00+00:00'
    elif boundary == 'wrong_baseline':
        guest['name'] = 'OtherAssignment'
    elif boundary == 'wrong_version':
        guest['version'] = '2.0'
    elif boundary == 'wrong_parameters':
        guest['configurationParameter'][0]['value'] = 'other'
    elif boundary == 'foreign_report':
        evidence['report']['id'] = VM + '/foreign'
    elif boundary == 'missing_report':
        evidence.pop('report')
    elif boundary == 'assignment_partial':
        row['_coverage']['guestConfigurationAssignments']['status'] = 'partial'
    else:
        row['guestConfigurationAssignments'][0]['parent_id'] = '/subscriptions/foreign'
    assert evaluate(check_id, row, index)[0] == 'UNKNOWN'


@pytest.mark.parametrize('check_id', [sw.CLOCK_ID, sw.SSH_ID])
def test_assignment_compliant_flag_without_specific_measurement_is_unknown(check_id):
    row, index, evidence = scenario(check_id)
    evidence['report']['properties'].pop('details')
    assert evaluate(check_id, row, index)[0] == 'UNKNOWN'
    evidence['report']['properties']['details'] = {'resources': []}
    assert evaluate(check_id, row, index)[0] == 'UNKNOWN'


@pytest.mark.parametrize('check_id', [sw.RDP_ID, sw.SSH_ID, sw.PATCH_ID, sw.KEY_ID])
def test_vm_not_applicable_os(check_id):
    row, index, _ = scenario(check_id)
    row['properties']['storageProfile']['osDisk']['osType'] = 'Linux' if check_id in (sw.RDP_ID, sw.PATCH_ID) else 'Windows'
    assert evaluate(check_id, row, index)[0] == 'NOT_APPLICABLE'


def test_other_not_applicable_conditions_are_measured():
    for check_id in (sw.CONFIDENTIAL_ID, sw.SOFTWARE_ID):
        row, index, _ = scenario(check_id)
        field = 'confidentialVmIds' if check_id == sw.CONFIDENTIAL_ID else 'softwareInventoryVmIds'
        index['context']['metadata']['compliance_policy'][field] = []
        assert evaluate(check_id, row, index)[0] == 'NOT_APPLICABLE'
    row, index, evidence = scenario(sw.SSH_ID)
    evidence['exposed'] = False
    assert evaluate(sw.SSH_ID, row, index)[0] == 'NOT_APPLICABLE'
    row, index, evidence = scenario(sw.BACKUP_ID)
    evidence['databaseIds'] = []
    assert evaluate(sw.BACKUP_ID, row, index)[0] == 'NOT_APPLICABLE'
    for check_id in (sw.REVIEW_ID, sw.OWNER_ID, sw.WRITER_ID):
        row, index, evidence = scenario(check_id)
        evidence['effectiveAssignments'] = []
        assert evaluate(check_id, row, index)[0] == 'NOT_APPLICABLE'
    row, index, evidence = scenario(sw.USER_MFA_ID)
    evidence['privileged'] = True
    assert evaluate(sw.USER_MFA_ID, row, index)[0] == 'NOT_APPLICABLE'
    evidence['privileged'] = False
    row['accountEnabled'] = False
    assert evaluate(sw.USER_MFA_ID, row, index)[0] == 'NOT_APPLICABLE'
    row, index, _ = scenario(sw.KEY_ID)
    row['instanceView']['statuses'][0]['code'] = 'PowerState/deallocated'
    assert evaluate(sw.KEY_ID, row, index)[0] == 'NOT_APPLICABLE'


def test_original_source_key_rule_grades_keys_independently_of_password():
    for keys in ([], [{'path': '/home/user/.ssh/authorized_keys', 'keyData': 'public-key'}]):
        for disabled in (True, False):
            row, index, _ = scenario(sw.KEY_ID)
            row['_provenance'] = {'representation': 'full', 'source_operation': 'get',
                                  'read_only': True, 'expand': 'instanceView'}
            config = row['properties']['osProfile']['linuxConfiguration']
            config['disablePasswordAuthentication'] = disabled
            config['ssh']['publicKeys'] = keys
            assert evaluate(sw.KEY_ID, row, index)[0] == ('FAIL' if keys else 'PASS')


def test_c5_technical_signals_do_not_replace_process_records():
    for check_id in (sw.CONFIDENTIAL_ID, sw.PATCH_ID):
        row, index, evidence = scenario(check_id)
        evidence.pop('obligations')
        status, detail = evaluate(check_id, row, index)
        assert status == 'UNKNOWN'
        if check_id == sw.CONFIDENTIAL_ID:
            assert detail['technical_signal'] == 'PRESENT'
    row, index, evidence = scenario(sw.PATCH_ID)
    row['properties']['osProfile']['windowsConfiguration']['patchSettings']['patchMode'] = 'Manual'
    assert evaluate(sw.PATCH_ID, row, index)[0] == 'FAIL'
    evidence.pop('obligations')
    assert evaluate(sw.PATCH_ID, row, index)[0] == 'UNKNOWN'


def test_software_inventory_full_read_missing_asset_and_field_vs_projection():
    row, index, evidence = scenario(sw.SOFTWARE_ID)
    evidence['softwareInventories'] = []
    assert evaluate(sw.SOFTWARE_ID, row, index)[0] == 'FAIL'
    row, index, evidence = scenario(sw.SOFTWARE_ID)
    asset = evidence['softwareInventories'][0]
    asset['properties'].pop('version')
    assert evaluate(sw.SOFTWARE_ID, row, index)[0] == 'FAIL'
    asset['_provenance']['representation'] = 'partial'
    assert evaluate(sw.SOFTWARE_ID, row, index)[0] == 'UNKNOWN'
    asset['_provenance']['representation'] = 'full'
    asset['properties']['version'] = 3
    assert evaluate(sw.SOFTWARE_ID, row, index)[0] == 'UNKNOWN'


def test_selected_roles_missing_required_grant_is_fail_not_vacuous_pass():
    row, index, evidence = scenario(sw.SELECTED_ID)
    evidence['scopes'][0]['assignments'] = []
    assert evaluate(sw.SELECTED_ID, row, index)[0] == 'FAIL'
    evidence['coverage']['principal_lookup'] = False
    assert evaluate(sw.SELECTED_ID, row, index)[0] == 'UNKNOWN'


@pytest.mark.parametrize('check_id', [sw.CREDENTIAL_ID, sw.BACKUP_ID])
def test_effective_permission_and_authorized_attempt_boundaries(check_id):
    row, index, evidence = scenario(check_id)
    action = evidence['principals'][0]['actions'][0]
    action['authorizedAttempt']['outcome'] = 'Succeeded'
    assert evaluate(check_id, row, index)[0] == 'FAIL'
    action['authorizedAttempt']['resourceId'] = '/subscriptions/foreign'
    assert evaluate(check_id, row, index)[0] == 'UNKNOWN'
    row, index, evidence = scenario(check_id)
    evidence['principals'][0]['actions'] = []
    assert evaluate(check_id, row, index)[0] == 'UNKNOWN'


@pytest.mark.parametrize('check_id', [sw.OWNER_ID, sw.WRITER_ID])
def test_mfa_paths_resolve_grants_strengths_and_graph_authority(check_id):
    row, index, evidence = scenario(check_id)
    p = evidence['effectiveAssignments'][0]['paths'][0]
    p.update(mfaRequired=False, authenticationStrengthId='strength1')
    assert evaluate(check_id, row, index)[0] == 'PASS'
    p['authenticationStrengthId'] = 'unapproved'
    assert evaluate(check_id, row, index)[0] == 'FAIL'
    p.update(authenticationStrengthId=None, policyIds=[], securityDefaultsProven=True,
             securityDefaultsEvidenceIds=['defaults-behavior-record'])
    assert evaluate(check_id, row, index)[0] == ('PASS' if check_id == sw.WRITER_ID else 'FAIL')
    evidence['_provenance']['customer_context_id'] = 'foreign-customer'
    assert evaluate(check_id, row, index)[0] == 'UNKNOWN'


def test_non_privileged_status_registration_equivalence_boundaries():
    row, index, evidence = scenario(sw.USER_MFA_ID)
    evidence['requirements']['perUserMfaState'] = 'disabled'
    assert evaluate(sw.USER_MFA_ID, row, index)[0] == 'PASS'
    index['context']['metadata']['compliance_policy']['nonPrivilegedMfaEquivalenceApproved'] = False
    assert evaluate(sw.USER_MFA_ID, row, index)[0] == 'UNKNOWN'
    evidence['paths'][0].update(mfaRequired=False, policyIds=[])
    assert evaluate(sw.USER_MFA_ID, row, index)[0] == 'FAIL'
    evidence['coverage']['sign_in_paths'] = False
    assert evaluate(sw.USER_MFA_ID, row, index)[0] == 'UNKNOWN'


def test_clock_unsynchronized_without_measured_drift_is_unknown():
    row, index, evidence = scenario(sw.CLOCK_ID)
    set_measurement(evidence, synchronized=False, driftExceeded=False)
    assert evaluate(sw.CLOCK_ID, row, index)[0] == 'UNKNOWN'
    set_measurement(evidence, driftExceeded=True)
    assert evaluate(sw.CLOCK_ID, row, index)[0] == 'FAIL'


def test_allowed_credential_or_backup_permission_needs_no_attempt_to_fail():
    for check_id in (sw.CREDENTIAL_ID, sw.BACKUP_ID):
        row, index, evidence = scenario(check_id)
        action = evidence['principals'][0]['actions'][0]
        action['effectiveAccess'] = 'Allowed'
        action.pop('authorizedAttempt')
        assert evaluate(check_id, row, index)[0] == 'FAIL'
        action['effectiveAccess'] = 'Denied'
        assert evaluate(check_id, row, index)[0] == 'UNKNOWN'


def test_backup_denial_coverage_requires_all_databases_not_one_attempt():
    row, index, evidence = scenario(sw.BACKUP_ID)
    evidence['databaseIds'].append(SCOPE + '/resourceGroups/rg/providers/Microsoft.Sql/servers/sql/databases/db2')
    assert evaluate(sw.BACKUP_ID, row, index)[0] == 'UNKNOWN'


@pytest.mark.parametrize('check_id', [sw.CONFIDENTIAL_ID, sw.PATCH_ID])
def test_c5_future_process_records_are_unknown(check_id):
    row, index, evidence = scenario(check_id)
    evidence['obligations'][0]['observed_at'] = '2030-01-01T00:00:00+00:00'
    assert evaluate(check_id, row, index)[0] == 'UNKNOWN'


@pytest.mark.parametrize('check_id', [sw.RDP_ID, sw.CLOCK_ID, sw.SSH_ID])
def test_guest_future_report_and_ambiguous_measurement_are_unknown(check_id):
    row, index, evidence = scenario(check_id)
    evidence['report']['properties']['endTime'] = '2030-01-01T00:00:00+00:00'
    assert evaluate(check_id, row, index)[0] == 'UNKNOWN'
    if check_id != sw.RDP_ID:
        evidence['report']['properties']['endTime'] = AT
        resources = evidence['report']['properties']['details']['resources']
        resources.append(copy.deepcopy(resources[0]))
        assert evaluate(check_id, row, index)[0] == 'UNKNOWN'


def test_prohibited_role_guid_and_inherited_native_properties():
    row, index, evidence = scenario(sw.PROHIBITED_ID)
    parent = '/providers/Microsoft.Management/managementGroups/parent'
    policy = index['context']['metadata']['compliance_policy']
    policy['scopeAncestors'][SCOPE] = [parent]
    evidence['scopes'][0]['ancestorScopes'] = [parent]
    inherited = evidence['scopes'][0]['assignments'][0]
    inherited['properties']['scope'] = parent
    inherited['properties']['principalType'] = 'ServicePrincipal'
    inherited['id'] = parent + '/providers/Microsoft.Authorization/roleAssignments/' + ASSIGNMENT
    policy['prohibitedRoleDefinitionIds'] = [ROLE]
    assert evaluate(sw.PROHIBITED_ID, row, index)[0] == 'FAIL'
    policy['prohibitedRoleDefinitionIds'] = [parent + '/providers/Microsoft.Authorization/roleDefinitions/' + ROLE.upper()]
    assert evaluate(sw.PROHIBITED_ID, row, index)[0] == 'FAIL'
    inherited['properties']['scope'] = '/subscriptions/foreign'
    assert evaluate(sw.PROHIBITED_ID, row, index)[0] == 'UNKNOWN'


def test_selected_role_inherited_grant_requires_exact_actual_scope_approval():
    row, index, evidence = scenario(sw.SELECTED_ID)
    parent = '/providers/Microsoft.Management/managementGroups/parent'
    policy = index['context']['metadata']['compliance_policy']
    policy['scopeAncestors'][SCOPE] = [parent]
    evidence['scopes'][0]['ancestorScopes'] = [parent]
    assignment = evidence['scopes'][0]['assignments'][0]
    assignment['properties']['scope'] = parent
    assignment['id'] = parent + '/providers/Microsoft.Authorization/roleAssignments/' + ASSIGNMENT
    assert evaluate(sw.SELECTED_ID, row, index)[0] == 'UNKNOWN'
    policy['authorizedRoleAssignments'].append({'scope': parent, 'roleDefinitionId': ROLE_ID,
                                              'principalIds': [PRINCIPAL]})
    assert evaluate(sw.SELECTED_ID, row, index)[0] == 'PASS'
    policy['authorizedRoleAssignments'][-1]['principalIds'] = []
    assert evaluate(sw.SELECTED_ID, row, index)[0] == 'FAIL'


def test_review_tuple_recency_application_and_no_summary_pass():
    row, index, evidence = scenario(sw.REVIEW_ID)
    instance = evidence['reviews'][0]['instances'][0]
    instance['decision']['applyResult'] = 'NotApplied'
    assert evaluate(sw.REVIEW_ID, row, index)[0] == 'FAIL'
    instance['decision']['applyResult'] = 'AppliedSuccessfully'
    instance['endDateTime'] = '2020-01-01T00:00:00+00:00'
    assert evaluate(sw.REVIEW_ID, row, index)[0] == 'FAIL'
    instance['endDateTime'] = AT
    instance['decision']['principalId'] = 'eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee'
    assert evaluate(sw.REVIEW_ID, row, index)[0] == 'UNKNOWN'


@pytest.mark.parametrize('check_id', [sw.OWNER_ID, sw.WRITER_ID])
def test_mfa_incomplete_membership_and_excluded_path_are_unknown_or_fail(check_id):
    row, index, evidence = scenario(check_id)
    evidence['coverage']['groups'] = False
    assert evaluate(check_id, row, index)[0] == 'UNKNOWN'
    evidence['coverage']['groups'] = True
    bypass = path()
    bypass.update(id='excluded-location', mfaRequired=False, policyIds=[])
    evidence['effectiveAssignments'][0]['paths'].append(bypass)
    assert evaluate(check_id, row, index)[0] == 'FAIL'
    bypass['allowed'] = False
    assert evaluate(check_id, row, index)[0] == 'PASS'


@pytest.mark.parametrize('check_id,dimension', [
    (sw.RDP_ID, 'parameters'), (sw.CLOCK_ID, 'reports'), (sw.SSH_ID, 'exposure'),
    (sw.SOFTWARE_ID, 'installed_asset_universe'), (sw.CONFIDENTIAL_ID, 'process_records'),
    (sw.PATCH_ID, 'process_records'), (sw.REVIEW_ID, 'decision_application'),
    (sw.CREDENTIAL_ID, 'resource_inventory'), (sw.BACKUP_ID, 'database_inventory'),
    (sw.PROHIBITED_ID, 'inheritance'), (sw.SELECTED_ID, 'group_expansion'),
    (sw.OWNER_ID, 'authentication_strengths'), (sw.WRITER_ID, 'grant_operators'),
    (sw.USER_MFA_ID, 'registration')])
@pytest.mark.parametrize('unavailable', [False, 'true', None])
def test_independent_resolution_coverage_is_strict(check_id, dimension, unavailable):
    row, index, evidence = scenario(check_id)
    evidence['coverage'][dimension] = unavailable
    assert evaluate(check_id, row, index)[0] == 'UNKNOWN'


def test_non_privileged_enabled_state_does_not_require_equivalence_policy():
    row, index, evidence = scenario(sw.USER_MFA_ID)
    index['context']['metadata'].pop('compliance_policy')
    assert evaluate(sw.USER_MFA_ID, row, index)[0] == 'PASS'
    evidence['requirements']['perUserMfaState'] = 'disabled'
    assert evaluate(sw.USER_MFA_ID, row, index)[0] == 'UNKNOWN'


@pytest.mark.parametrize('check_id', sw.IDS)
def test_engine_frozen_fact_views_keep_identical_outcomes(check_id):
    from peaso.checks.facts import MemoIndex
    from peaso.snapshot import freeze
    row, index, _ = scenario(check_id)
    expected = 'UNKNOWN' if check_id == sw.KEY_ID else 'PASS'
    assert evaluate(check_id, freeze(row), MemoIndex(freeze(index)))[0] == expected


@pytest.mark.parametrize('marker', [None, [], {'status': 'empty'}, {'status': 'partial'}])
def test_guest_software_selected_field_coverage_authority(marker):
    row, index, evidence = scenario(sw.SOFTWARE_ID)
    props = evidence['softwareInventories'][0]['properties']
    assert evaluate(sw.SOFTWARE_ID, row, index)[0] == 'PASS'
    props['_coverage'] = {'version': marker}
    assert evaluate(sw.SOFTWARE_ID, row, index)[0] == 'UNKNOWN'


def test_guest_software_complete_missing_field_remains_measured_failure():
    row, index, evidence = scenario(sw.SOFTWARE_ID)
    evidence['softwareInventories'][0]['properties'].pop('version')
    assert evaluate(sw.SOFTWARE_ID, row, index)[0] == 'FAIL'


@pytest.mark.parametrize('failure', ['missing_field', 'missing_required_item',
                                     'missing_field_on_second_asset', 'missing_field_after_unknown_name'])
def test_guest_software_independent_failure_survives_field_unavailability(failure):
    row, index, evidence = scenario(sw.SOFTWARE_ID)
    asset = evidence['softwareInventories'][0]
    if failure == 'missing_field_on_second_asset':
        second = copy.deepcopy(asset)
        second['id'] = VM + '/providers/Microsoft.Security/softwareInventories/product2'
        second['properties']['version'] = ''
        evidence['softwareInventories'].append(second)
    elif failure in ('missing_field', 'missing_field_after_unknown_name'):
        asset['properties']['version'] = ''
    else:
        asset['properties']['softwareName'] = 'other-product'
    marker_field = 'softwareName' if failure == 'missing_field_after_unknown_name' else 'deviceId'
    asset['properties']['_coverage'] = {marker_field: {'status': 'partial'}}
    assert evaluate(sw.SOFTWARE_ID, row, index)[0] == 'FAIL'


@pytest.mark.parametrize('global_gap', ['asset_identity', 'representation', 'universe'])
def test_guest_software_global_gap_precedes_independent_failure(global_gap):
    row, index, evidence = scenario(sw.SOFTWARE_ID)
    asset = evidence['softwareInventories'][0]
    asset['properties']['version'] = ''
    asset['properties']['_coverage'] = {'deviceId': {'status': 'partial'}}
    if global_gap == 'asset_identity':
        asset['id'] = '/subscriptions/foreign/providers/Microsoft.Security/softwareInventories/product1'
    elif global_gap == 'representation':
        asset['_provenance']['representation'] = 'partial'
    else:
        evidence['coverage']['installed_asset_universe'] = False
    assert evaluate(sw.SOFTWARE_ID, row, index)[0] == 'UNKNOWN'
