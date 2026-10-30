"""Direct sw17 evaluators with isolated registration and hostile fact boundaries."""
from __future__ import annotations

import copy
import json

import pytest

from peaso.checks import CHECKS

_before = {id(check) for check in CHECKS}
from peaso.checks import compliance_new_sw17 as sw
# Retain the actual registered safe evaluators while restoring the pre-import
# registry immediately. This cannot remove integrator-preexisting checks.
CHECKS[:] = [check for check in CHECKS if id(check) in _before]

SCOPE = '/subscriptions/11111111-1111-1111-1111-111111111111'
BASE = SCOPE + '/resourceGroups/rg/providers/'
VM = BASE + 'Microsoft.Compute/virtualMachines/vm'
NIC = BASE + 'Microsoft.Network/networkInterfaces/nic'
SUBNET = BASE + 'Microsoft.Network/virtualNetworks/vnet/subnets/default'
NSG = BASE + 'Microsoft.Network/networkSecurityGroups/nsg'
PIP = BASE + 'Microsoft.Network/publicIPAddresses/pip'
NOW = '2026-10-12T10:00:00Z'
OLD = '2020-01-01T00:00:00Z'
THUMB = 'a' * 40


def proof(operation='GET', at=NOW):
    return {'read_only': True, 'source_operation': operation, 'observed_at': at}


def row_id(kind):
    return VM + '/providers/Microsoft.ComplianceEvidence/' + kind + '/evidence'


def collection(index, kind, rows):
    index['collections'][kind] = [{'type': kind, 'scope': SCOPE, 'status': 'collected' if rows else 'empty', 'items': rows, '_provenance': proof()}]
    index[kind] = [{'type': kind, 'scope': SCOPE, 'data': row} for row in rows]


def vm(os='Windows'):
    return {'id': VM, 'properties': {'storageProfile': {'osDisk': {'osType': os}},
        'networkProfile': {'networkInterfaces': [{'id': NIC}]}},
        'guestConfigurationAssignments': [], '_coverage': {'guestConfigurationAssignments': {
            'status': 'collected', '_provenance': proof('assignment LIST')}}}


def policy_entry():
    return {'assignmentName': 'baseline', 'configurationName': 'approved-baseline',
        'configurationVersion': '1.0', 'maxReportAgeSeconds': 3600}


def index_for(check_id, machine, policy=None):
    index = {'context': {'provider': 'azure', 'scope': SCOPE, 'created_at': NOW,
        'metadata': {'compliance_policy': {'status': 'collected', 'scope': SCOPE,
            'checks': {check_id: policy or policy_entry()}}}}, 'collections': {}}
    collection(index, 'vm', [machine])
    return index


def run(suffix, machine, index):
    return sw.EVALUATORS[sw.PREFIX + suffix](machine, index)


def settings():
    return {category: {'category': category, 'expected': True} for category in
        ('firewallState', 'inboundConnections', 'outboundConnections', 'ruleManagement', 'notifications')}


def guest_case(suffix):
    check_id = sw.PREFIX + suffix
    machine = vm('Linux' if suffix == 'password_file_permissions_0644_linux' else 'Windows')
    pol = policy_entry()
    aid = VM + '/providers/Microsoft.GuestConfiguration/guestConfigurationAssignments/baseline'
    parameters = []
    props = {'group': 'Administrators', 'membershipComplete': True, 'observedMembers': ['alice']}
    if suffix == 'administrators_group_with_extra_accounts_windows':
        pol['approvedAdministrators'] = ['alice']
    elif suffix == 'administrators_group_with_no_specified_members_windows':
        pol['requiredAdministrators'] = ['alice']
    elif suffix == 'administrators_group_with_specified_members_windows':
        pol['prohibitedAdministrators'] = ['mallory']
    elif suffix == 'with_no_specified_certificates_in_trusted_root_windows':
        pol['requiredThumbprints'] = [THUMB]
        props = {'store': 'LocalMachine\\Root', 'certificateSetComplete': True, 'observedThumbprints': [THUMB]}
    elif suffix == 'password_file_permissions_0644_linux':
        parameters.extend([{'name': 'filePaths', 'value': '["/etc/passwd"]'}, {'name': 'requiredModes', 'value': '["0644"]'}])
        props = {'path': '/etc/passwd', 'mode': '0644'}
    elif suffix == 'meet_firewall_properties_windows':
        pol['requiredSettings'] = settings()
        parameters.append({'name': 'requiredSettings', 'value': json.dumps(settings())})
    elif suffix == 'rdp_service_disabled':
        props = {'serviceName': 'TermService', 'state': 'Disabled'}
    for key in ('approvedAdministrators', 'requiredAdministrators', 'prohibitedAdministrators', 'requiredThumbprints'):
        if key in pol:
            parameters.append({'name': key, 'value': json.dumps(pol[key])})
    assignment = {'id': aid, 'name': 'baseline', 'properties': {'latestReportId': 'latest',
        'complianceStatus': 'Compliant', 'guestConfiguration': {'name': 'approved-baseline',
            'version': '1.0', 'configurationParameter': parameters}}}
    machine['guestConfigurationAssignments'] = [assignment]
    resources = [{'resourceId': 'observed-setting', 'complianceStatus': 'Compliant', 'properties': props}]
    if suffix == 'meet_firewall_properties_windows':
        resources = [{'resourceId': name, 'complianceStatus': 'Compliant', 'properties': {
            'settingName': name, 'expected': True, 'observed': True}} for name in settings()]
    report = {'id': aid + '/reports/latest', '_provenance': proof('GuestConfigurationAssignmentReports_Get'), '_coverage': {'resources': {'status': 'collected'}},
        'properties': {'vm': {'id': VM}, 'assignment': {'name': 'baseline', 'configuration': {
            'name': 'approved-baseline', 'version': '1.0'}}, 'endTime': NOW,
            'operationStatus': 'Succeeded', 'details': {'complianceStatus': 'Compliant', 'resources': resources}}}
    index = index_for(check_id, machine, pol)
    collection(index, 'guest_configuration_report', [report])
    return machine, index


def network_case(suffix):
    machine = vm()
    config = {'id': NIC + '/ipConfigurations/primary', 'properties': {
        'privateIPAddress': '10.0.0.4', 'subnet': {'id': SUBNET}, 'publicIPAddress': {'id': PIP}}}
    nic = {'id': NIC, 'properties': {'virtualMachine': {'id': VM}, 'networkSecurityGroup': {'id': NSG}, 'ipConfigurations': [config]}}
    subnet = {'id': SUBNET, 'properties': {'networkSecurityGroup': None}}
    nsg = {'id': NSG, 'properties': {'securityRules': [], 'defaultSecurityRules': [rule(65500, 'Deny')]}}
    index = index_for(sw.PREFIX + suffix, machine)
    for kind, rows in [('nic', [nic]), ('subnet', [subnet]), ('nsg', [nsg]),
                       ('public_ip', [{'id': PIP, 'properties': {'ipAddress': '8.8.8.8'}}]), ('load_balancer', [])]:
        collection(index, kind, rows)
    return machine, index


def rule(priority, access, *, source='*', destination='*', source_port='*', port='*', protocol='*'):
    return {'name': 'rule' + str(priority), 'properties': {'direction': 'Inbound',
        'priority': priority, 'access': access, 'protocol': protocol, 'sourceAddressPrefix': source,
        'destinationAddressPrefix': destination, 'sourcePortRange': source_port, 'destinationPortRange': port}}


def native(index, kind):
    return index[kind][0]['data']


def normalized_fact(index, kind, **extra):
    record = {'id': row_id(kind), 'vm_id': VM, '_provenance': proof(), **extra}
    collection(index, kind, [record])
    return record


def allowlist_attestation(index, *, state='DeployedActive', alert='AlertObserved'):
    check_id = sw.PREFIX + 'adaptive_application_controls_enabled'
    group = SCOPE + '/providers/Microsoft.Security/locations/westeurope/applicationWhitelistings/group'
    policy_id = 'approved-policy'
    common = {'capture_id': 'capture-1', 'vm_id': VM, 'group_id': group,
              'policy_id': policy_id, 'policy_revision': 'revision-1'}
    origin = {**proof('ExternalAllowlistAttestation_Read'), 'issuer': 'audit-team',
              'evidence_uri': 'https://evidence.example/allowlist/capture-1'}
    row = {'id': row_id('application_allowlist_attestation'), 'check_id': check_id,
           'vm_id': VM, 'group_id': group, 'policy_id': policy_id,
           'policy_revision': 'revision-1', 'capture_id': 'capture-1',
           'captured_at': NOW, '_provenance': origin,
           'policy_observation': {**common, '_provenance': copy.deepcopy(origin),
                                  'result': state, 'enforcement_mode': 'Audit',
                                  'installed_rule_ids': ['installed-rule-1']},
           'alert_observation': {**common, '_provenance': copy.deepcopy(origin),
                                 'result': alert, 'execution_id': 'run-1',
                                 'unknown_application_id': 'unknown-app-1',
                                 'alert_id': 'alert-1'}}
    collection(index, 'application_allowlist_attestation', [row])
    return row


def defender_case(suffix):
    machine = vm()
    pol = policy_entry()
    pol['assessmentKeys'] = ['stable-key']
    index = index_for(sw.PREFIX + suffix, machine, pol)
    assessment = {'id': VM + '/providers/Microsoft.Security/assessments/stable-key', 'name': 'stable-key',
        '_provenance': proof('assessments LIST'), 'properties': {'resourceDetails': {'id': VM}, 'status': {'code': 'Healthy'}}}
    collection(index, 'security_assessment', [assessment])
    normalized_fact(index, 'vm_compliance_applicability', check_id=sw.PREFIX + suffix, applicable=True, basis='measured workload applicability')
    if suffix == 'adaptive_application_controls_enabled':
        pol['trustedAllowlistAttestationIssuers'] = ['audit-team']
        allowlist_attestation(index)
        group = {'id': SCOPE + '/providers/Microsoft.Security/locations/westeurope/applicationWhitelistings/group',
            '_provenance': proof(), 'properties': {'vmIds': [VM], 'policyApplicable': True,
                'policyActive': True, 'enforcementMode': 'Audit', 'pathRecommendations': [{'ruleId': 'r1'}],
                'unknownApplicationAlerts': {'_provenance': proof(), 'enabled': True, 'behaviorVerified': True}}}
        collection(index, 'application_whitelisting', [group])
    elif suffix == 'adaptive_network_hardening_recommendation_applied':
        _, network = network_case(suffix)
        for kind in ('nic', 'subnet', 'nsg'):
            collection(index, kind, [native(network, kind)])
        normalized_fact(index, 'adaptive_network_hardening', internetFacing=True, rulesComplete=True,
            requiredRules=[{'recommendationId': 'r1', 'nsgId': NSG, 'approved': True, 'applied': True,
                'effective': True, 'effectiveRuleEvidence': {'vm_id': VM, 'nsg_id': NSG,
                    'recommendationId': 'r1', 'matchesRecommendation': True, '_provenance': proof()}}])
    elif suffix == 'vulnerability_findings_resolved_for_sql_server':
        collection(index, 'sql_vm', [{'id': BASE + 'Microsoft.SqlVirtualMachine/sqlVirtualMachines/sql',
            'properties': {'virtualMachineResourceId': VM}}])
        pol.update(requiredFindingIds=['finding-1'], findingSetComplete=True)
        collection(index, 'security_subassessment', [{'id': assessment['id'] + '/subassessments/finding-1',
            'name': 'finding-1', 'assessment_key': 'stable-key', '_provenance': proof(),
            'properties': {'resourceDetails': {'id': VM}, 'status': {'code': 'Healthy'}}}])
    return machine, index


@pytest.mark.parametrize('suffix', sorted(sw.DEFENDER_SUFFIXES))
@pytest.mark.parametrize('state,expected', [('Healthy', 'PASS'), ('Unhealthy', 'FAIL')])
def test_defender_native_identity_matching_preserves_verdict(suffix, state, expected):
    machine, index = defender_case(suffix)
    native(index, 'security_assessment')['properties']['status']['code'] = state
    assert run(suffix, machine, index)[0] == expected


@pytest.mark.parametrize('suffix', sorted(sw.DEFENDER_SUFFIXES))
@pytest.mark.parametrize('state', ['Healthy', 'Unhealthy'])
@pytest.mark.parametrize('path', [
    VM + '-another/providers/Microsoft.Security/assessments/stable-key',
    VM + '/providers/Microsoft.Security/assessments/another-key',
    VM + '/providers/Microsoft.Other/assessments/stable-key',
])
def test_defender_native_identity_mismatch_is_unknown(suffix, state, path):
    machine, index = defender_case(suffix)
    assessment = native(index, 'security_assessment')
    assessment['id'] = path
    assessment['properties']['status']['code'] = state
    assert run(suffix, machine, index)[0] == 'UNKNOWN'


@pytest.mark.parametrize('suffix', sorted(sw.DEFENDER_SUFFIXES))
def test_defender_native_identity_case_insensitive(suffix):
    machine, index = defender_case(suffix)
    assessment = native(index, 'security_assessment')
    assessment['id'] = assessment['id'].upper()
    assessment['name'] = assessment['name'].upper()
    assessment['properties']['resourceDetails']['id'] = VM.upper()
    assert run(suffix, machine, index)[0] == 'PASS'


@pytest.mark.parametrize('path', [
    VM + '-another/providers/Microsoft.Security/assessments/stable-key/subassessments/finding-1',
    VM + '/providers/Microsoft.Security/assessments/another-key/subassessments/finding-1',
    VM + '/providers/Microsoft.Security/assessments/stable-key/subassessments/another-finding',
])
@pytest.mark.parametrize('state', ['Healthy', 'Unhealthy'])
def test_sql_finding_native_identity_mismatch_is_unknown(path, state):
    suffix = 'vulnerability_findings_resolved_for_sql_server'
    machine, index = defender_case(suffix)
    finding = native(index, 'security_subassessment')
    finding['id'] = path
    finding['properties']['status']['code'] = state
    assert run(suffix, machine, index)[0] == 'UNKNOWN'


def case(suffix):
    if suffix in sw.GUEST_SUFFIXES or suffix == 'rdp_service_disabled':
        return guest_case(suffix)
    if suffix in sw.DEFENDER_SUFFIXES:
        return defender_case(suffix)
    if suffix in ('remote_access_restricted_all_ports', 'tcp_udp_access_restricted_internet'):
        return network_case(suffix)
    machine = vm()
    index = index_for(sw.PREFIX + suffix, machine)
    if suffix == 'malware_agent_automatic_upgrade_enabled':
        normalized_fact(index, 'vm_antimalware_policy', agent='MicrosoftDefender', effectivePolicyComplete=True,
            agentPresent=True, serviceOperational=True, automaticSignatureUpdatesEnabled=True)
    elif suffix == 'system_updates_installed':
        machine['properties']['instanceView'] = {'patchStatus': {
            'availablePatchSummary': {'status': 'Succeeded', 'lastModifiedTime': NOW,
                                      'criticalAndSecurityPatchCount': 0},
            'lastPatchInstallationSummary': {'status': 'Succeeded',
                                             'installationActivityId': 'operation-1',
                                             'lastModifiedTime': '2026-10-12T09:00:00Z'}}}
        index['context']['metadata']['compliance_policy']['checks'][sw.PREFIX + suffix]['requirePciCompliance'] = False
    return machine, index


def unsafe(suffix, machine, index):
    if suffix in sw.DEFENDER_SUFFIXES:
        native(index, 'security_assessment')['properties']['status']['code'] = 'Unhealthy'
    elif suffix in sw.GUEST_SUFFIXES:
        resource = native(index, 'guest_configuration_report')['properties']['details']['resources'][0]
        resource['complianceStatus'] = 'NonCompliant'
        prop = resource['properties']
        if suffix == 'administrators_group_with_extra_accounts_windows':
            prop['observedMembers'].append('mallory')
        elif suffix == 'administrators_group_with_no_specified_members_windows':
            prop['observedMembers'] = []
        elif suffix == 'administrators_group_with_specified_members_windows':
            prop['observedMembers'].append('mallory')
        elif suffix == 'with_no_specified_certificates_in_trusted_root_windows':
            prop['observedThumbprints'] = []
        elif suffix == 'password_file_permissions_0644_linux':
            prop['mode'] = '0600'
        elif suffix == 'meet_firewall_properties_windows':
            prop['observed'] = False
    elif suffix == 'rdp_service_disabled':
        native(index, 'guest_configuration_report')['properties']['details']['resources'][0]['properties']['state'] = 'Enabled'
        collection(index, 'vm_rdp_exception', [])
    elif suffix == 'malware_agent_automatic_upgrade_enabled':
        native(index, 'vm_antimalware_policy')['automaticSignatureUpdatesEnabled'] = False
    elif suffix == 'system_updates_installed':
        machine['properties']['instanceView']['patchStatus']['availablePatchSummary']['criticalAndSecurityPatchCount'] = 1
    elif suffix == 'remote_access_restricted_all_ports':
        native(index, 'nsg')['properties']['securityRules'] = [rule(100, 'Allow')]
    elif suffix == 'tcp_udp_access_restricted_internet':
        native(index, 'nic')['properties']['networkSecurityGroup'] = None


SUFFIXES = sorted(cid.removeprefix(sw.PREFIX) for cid in sw.SPECS)


@pytest.mark.parametrize('suffix', SUFFIXES)
def test_pass(suffix):
    machine, index = case(suffix)
    assert run(suffix, machine, index)[0] == 'PASS'


@pytest.mark.parametrize('suffix', SUFFIXES)
def test_fail(suffix):
    machine, index = case(suffix)
    unsafe(suffix, machine, index)
    assert run(suffix, machine, index)[0] == 'FAIL'


@pytest.mark.parametrize('suffix', SUFFIXES)
@pytest.mark.parametrize('state', ['partial', 'denied', 'not_collected'])
def test_incomplete(suffix, state):
    machine, index = case(suffix)
    index['collections']['vm'][0]['status'] = state
    assert run(suffix, machine, index)[0] == 'UNKNOWN'


@pytest.mark.parametrize('suffix', SUFFIXES)
def test_missing_fact(suffix):
    machine, index = case(suffix)
    index.pop('context')
    assert run(suffix, machine, index)[0] == 'UNKNOWN'


@pytest.mark.parametrize('suffix', SUFFIXES)
def test_malformed_fact(suffix):
    machine, index = case(suffix)
    machine['_coverage'] = []
    assert run(suffix, machine, index)[0] == 'UNKNOWN'


@pytest.mark.parametrize('suffix', SUFFIXES)
def test_foreign_scope(suffix):
    machine, index = case(suffix)
    index['collections']['vm'][0]['scope'] = '/subscriptions/foreign'
    assert run(suffix, machine, index)[0] == 'UNKNOWN'
    machine, index = case(suffix)
    index['context']['provider'] = 'aws'
    assert run(suffix, machine, index)[0] == 'UNKNOWN'


@pytest.mark.parametrize('suffix', sorted(sw.GUEST_SUFFIXES | {'rdp_service_disabled', 'malware_agent_automatic_upgrade_enabled'}))
def test_not_applicable_os(suffix):
    machine, index = case(suffix)
    machine['properties']['storageProfile']['osDisk']['osType'] = 'Windows' if suffix == 'password_file_permissions_0644_linux' else 'Linux'
    assert run(suffix, machine, index)[0] == 'NOT_APPLICABLE'


@pytest.mark.parametrize('suffix', sorted(sw.DEFENDER_SUFFIXES - {'vulnerability_findings_resolved_for_sql_server'}))
def test_independent_inapplicability(suffix):
    machine, index = case(suffix)
    native(index, 'vm_compliance_applicability')['applicable'] = False
    assert run(suffix, machine, index)[0] == 'NOT_APPLICABLE'
    native(index, 'vm_compliance_applicability').pop('basis')
    assert run(suffix, machine, index)[0] == 'UNKNOWN'


@pytest.mark.parametrize('suffix', SUFFIXES)
def test_missing_required_fact(suffix):
    machine, index = case(suffix)
    if suffix in sw.GUEST_SUFFIXES or suffix == 'rdp_service_disabled':
        native(index, 'guest_configuration_report')['properties']['details'].pop('resources')
    elif suffix in sw.DEFENDER_SUFFIXES:
        native(index, 'security_assessment')['properties'].pop('status')
    elif suffix == 'malware_agent_automatic_upgrade_enabled':
        native(index, 'vm_antimalware_policy').pop('automaticSignatureUpdatesEnabled')
    elif suffix == 'system_updates_installed':
        machine['properties']['instanceView']['patchStatus']['availablePatchSummary'].pop('criticalAndSecurityPatchCount')
    else:
        native(index, 'nic')['properties'].pop('ipConfigurations')
    assert run(suffix, machine, index)[0] == 'UNKNOWN'


@pytest.mark.parametrize('suffix', SUFFIXES)
def test_malformed_required_fact(suffix):
    machine, index = case(suffix)
    if suffix in sw.GUEST_SUFFIXES or suffix == 'rdp_service_disabled':
        native(index, 'guest_configuration_report')['properties']['details']['resources'] = [None]
    elif suffix in sw.DEFENDER_SUFFIXES:
        native(index, 'security_assessment')['properties']['status']['code'] = 'FutureEnum'
    elif suffix == 'malware_agent_automatic_upgrade_enabled':
        native(index, 'vm_antimalware_policy')['automaticSignatureUpdatesEnabled'] = 'true'
    elif suffix == 'system_updates_installed':
        machine['properties']['instanceView']['patchStatus']['availablePatchSummary']['criticalAndSecurityPatchCount'] = True
    else:
        native(index, 'nic')['properties']['ipConfigurations'] = [None]
    assert run(suffix, machine, index)[0] == 'UNKNOWN'


@pytest.mark.parametrize('suffix', SUFFIXES)
def test_missing_collector_and_foreign_dependency(suffix):
    machine, index = case(suffix)
    kind = 'guest_configuration_report' if suffix in sw.GUEST_SUFFIXES or suffix == 'rdp_service_disabled' else 'security_assessment' if suffix in sw.DEFENDER_SUFFIXES else 'vm_antimalware_policy' if suffix == 'malware_agent_automatic_upgrade_enabled' else 'nic' if suffix in ('remote_access_restricted_all_ports', 'tcp_udp_access_restricted_internet') else 'vm'
    foreign = copy.deepcopy(index)
    foreign['collections'][kind][0]['scope'] = '/subscriptions/foreign'
    assert run(suffix, machine, foreign)[0] == 'UNKNOWN'
    index['collections'].pop(kind)
    assert run(suffix, machine, index)[0] == 'UNKNOWN'


@pytest.mark.parametrize('suffix', sorted(sw.GUEST_SUFFIXES | {'rdp_service_disabled'}))
def test_guest_exact_bindings_and_freshness(suffix):
    for mutation in ('old', 'future', 'no_age', 'wrong_vm', 'wrong_version', 'wrong_latest', 'summary_only', 'denied_detail', 'partial_report'):
        machine, index = case(suffix)
        report = native(index, 'guest_configuration_report')
        pol = index['context']['metadata']['compliance_policy']['checks'][sw.PREFIX + suffix]
        if mutation == 'old':
            report['properties']['endTime'] = OLD
        elif mutation == 'future':
            report['properties']['endTime'] = '2099-01-01T00:00:00Z'
        elif mutation == 'no_age':
            pol.pop('maxReportAgeSeconds')
        elif mutation == 'wrong_vm':
            report['properties']['vm']['id'] = VM + 'other'
        elif mutation == 'wrong_version':
            report['properties']['assignment']['configuration']['version'] = '2.0'
        elif mutation == 'wrong_latest':
            machine['guestConfigurationAssignments'][0]['properties']['latestReportId'] = 'other'
        elif mutation == 'summary_only':
            report['properties']['details']['resources'] = []
        elif mutation == 'denied_detail':
            report['_coverage']['resources']['status'] = 'denied'
        elif mutation == 'partial_report':
            index['collections']['guest_configuration_report'][0]['status'] = 'partial'
        assert run(suffix, machine, index)[0] == 'UNKNOWN', mutation


@pytest.mark.parametrize('suffix', sorted(sw.GUEST_SUFFIXES | {'rdp_service_disabled'}))
def test_assignment_absence_is_only_failure_when_signed(suffix):
    machine, index = case(suffix)
    machine['guestConfigurationAssignments'] = []
    expected = 'FAIL' if suffix in ('administrators_group_with_extra_accounts_windows', 'password_file_permissions_0644_linux') else 'UNKNOWN'
    assert run(suffix, machine, index)[0] == expected
    machine['_coverage']['guestConfigurationAssignments']['status'] = 'partial'
    assert run(suffix, machine, index)[0] == 'UNKNOWN'
    machine['_coverage']['guestConfigurationAssignments']['status'] = 'collected'
    machine['_coverage']['guestConfigurationAssignments']['_provenance']['observed_at'] = OLD
    assert run(suffix, machine, index)[0] == 'UNKNOWN'


@pytest.mark.parametrize('suffix', sorted(sw.GUEST_SUFFIXES - {'password_file_permissions_0644_linux'}))
def test_assignment_parameter_binding(suffix):
    machine, index = case(suffix)
    machine['guestConfigurationAssignments'][0]['properties']['guestConfiguration']['configurationParameter'][0]['value'] = '[]'
    assert run(suffix, machine, index)[0] == 'UNKNOWN'


def test_guest_adverse_before_uncertain_and_thumbprint_direction():
    for suffix in sw.GUEST_SUFFIXES:
        machine, index = case(suffix)
        unsafe(suffix, machine, index)
        resources = native(index, 'guest_configuration_report')['properties']['details']['resources']
        resources.append({'resourceId': 'unreadable', 'properties': {}})
        assert run(suffix, machine, index)[0] == 'FAIL'
    suffix = 'with_no_specified_certificates_in_trusted_root_windows'
    machine, index = case(suffix)
    pol = index['context']['metadata']['compliance_policy']['checks'][sw.PREFIX + suffix]
    pol['requiredThumbprints'] = []
    assert run(suffix, machine, index)[0] == 'UNKNOWN'
    suffix = 'meet_firewall_properties_windows'
    machine, index = case(suffix)
    index['context']['metadata']['compliance_policy']['checks'][sw.PREFIX + suffix]['requiredSettings'] = {'firewallState': settings()['firewallState']}
    assert run(suffix, machine, index)[0] == 'UNKNOWN'


@pytest.mark.parametrize('suffix', sorted(sw.DEFENDER_SUFFIXES))
def test_defender_healthy_alone_missing_stale_na_and_ambiguous(suffix):
    machine, index = case(suffix)
    assessment = native(index, 'security_assessment')
    assessment['_provenance']['observed_at'] = OLD
    assert run(suffix, machine, index)[0] == 'UNKNOWN'
    assessment['_provenance']['observed_at'] = NOW
    assessment['properties']['status']['code'] = 'NotApplicable'
    assert run(suffix, machine, index)[0] == 'UNKNOWN'
    assessment['properties']['status']['code'] = 'Healthy'
    duplicate = copy.deepcopy(assessment)
    duplicate['id'] += '-other'
    collection(index, 'security_assessment', [assessment, duplicate])
    assert run(suffix, machine, index)[0] == 'UNKNOWN'
    collection(index, 'security_assessment', [])
    assert run(suffix, machine, index)[0] == 'UNKNOWN'


def test_application_allowlist_and_alerts_required():
    suffix = 'adaptive_application_controls_enabled'
    machine, index = case(suffix)
    attestation = native(index, 'application_allowlist_attestation')
    attestation['alert_observation']['result'] = 'NoAlertObserved'
    assert run(suffix, machine, index)[0] == 'FAIL'
    attestation['alert_observation']['result'] = 'AlertObserved'
    attestation['policy_observation']['result'] = 'Inactive'
    assert run(suffix, machine, index)[0] == 'FAIL'
    collection(index, 'application_allowlist_attestation', [])
    assert run(suffix, machine, index)[0] == 'UNKNOWN'
    index['collections']['application_allowlist_attestation'][0]['status'] = 'partial'
    assert run(suffix, machine, index)[0] == 'UNKNOWN'


def test_network_recommendations_are_vm_bound_and_effective():
    suffix = 'adaptive_network_hardening_recommendation_applied'
    machine, index = case(suffix)
    recommendation = native(index, 'adaptive_network_hardening')['requiredRules'][0]
    recommendation['applied'] = False
    assert run(suffix, machine, index)[0] == 'FAIL'
    recommendation['applied'] = True
    recommendation['effective'] = False
    assert run(suffix, machine, index)[0] == 'FAIL'
    recommendation['effective'] = True
    recommendation['effectiveRuleEvidence']['vm_id'] = VM + 'other'
    assert run(suffix, machine, index)[0] == 'UNKNOWN'
    recommendation['effectiveRuleEvidence']['vm_id'] = VM
    recommendation['nsgId'] = NSG + 'other'
    assert run(suffix, machine, index)[0] == 'UNKNOWN'


def test_sql_all_findings_and_complete_join():
    suffix = 'vulnerability_findings_resolved_for_sql_server'
    machine, index = case(suffix)
    finding = native(index, 'security_subassessment')
    finding['properties']['status']['code'] = 'Unhealthy'
    assert run(suffix, machine, index)[0] == 'FAIL'
    finding['properties']['status']['code'] = 'NotApplicable'
    assert run(suffix, machine, index)[0] == 'UNKNOWN'
    collection(index, 'security_subassessment', [])
    assert run(suffix, machine, index)[0] == 'UNKNOWN'
    collection(index, 'sql_vm', [])
    assert run(suffix, machine, index)[0] == 'NOT_APPLICABLE'
    index['collections']['sql_vm'][0]['status'] = 'partial'
    assert run(suffix, machine, index)[0] == 'UNKNOWN'


def test_antimalware_config_not_signature_age():
    suffix = 'malware_agent_automatic_upgrade_enabled'
    machine, index = case(suffix)
    evidence = native(index, 'vm_antimalware_policy')
    evidence['signatureAgeSeconds'] = 10 ** 9
    assert run(suffix, machine, index)[0] == 'PASS'
    for field in ('agentPresent', 'serviceOperational'):
        evidence[field] = False
        assert run(suffix, machine, index)[0] == 'FAIL'
        evidence[field] = True
    evidence['agent'] = 'ThirdParty'
    assert run(suffix, machine, index)[0] == 'UNKNOWN'
    evidence.update(vendorEvidenceVerified=True, vendor='approved-vendor')
    assert run(suffix, machine, index)[0] == 'PASS'
    evidence['effectivePolicyComplete'] = False
    assert run(suffix, machine, index)[0] == 'UNKNOWN'


def test_rdp_exception_and_logging_complete():
    suffix = 'rdp_service_disabled'
    machine, index = case(suffix)
    native(index, 'guest_configuration_report')['properties']['details']['resources'][0]['properties']['state'] = 'Enabled'
    assert run(suffix, machine, index)[0] == 'UNKNOWN'
    normalized_fact(index, 'vm_rdp_exception', approved=True, officer='officer-1',
        valid_from='2026-10-12T09:00:00Z', valid_until='2026-10-12T11:00:00Z')
    assert run(suffix, machine, index)[0] == 'UNKNOWN'
    logs = normalized_fact(index, 'vm_remote_access_monitoring', routingEnabled=True, monitoredAlerts=True,
        eventCategories=['rdp-sign-in', 'rdp-session'])
    assert run(suffix, machine, index)[0] == 'PASS'
    for field in ('routingEnabled', 'monitoredAlerts'):
        logs[field] = False
        assert run(suffix, machine, index)[0] == 'FAIL'
        logs[field] = True
    native(index, 'vm_rdp_exception')['valid_until'] = OLD
    assert run(suffix, machine, index)[0] == 'UNKNOWN'


def test_updates_pci_post_installation_and_freshness():
    suffix = 'system_updates_installed'
    machine, index = case(suffix)
    pol = index['context']['metadata']['compliance_policy']['checks'][sw.PREFIX + suffix]
    pol['requirePciCompliance'] = True
    assert run(suffix, machine, index)[0] == 'UNKNOWN'
    evidence = normalized_fact(index, 'vm_patch_installation_compliance', operationId='operation-1',
        installedAt='2026-10-12T09:30:00Z', status='COMPLIANT')
    assert run(suffix, machine, index)[0] == 'PASS'
    evidence['status'] = 'NON_COMPLIANT'
    assert run(suffix, machine, index)[0] == 'FAIL'
    evidence['vm_id'] = VM + 'other'
    assert run(suffix, machine, index)[0] == 'UNKNOWN'
    summary = machine['properties']['instanceView']['patchStatus']['availablePatchSummary']
    summary['lastModifiedTime'] = OLD
    summary['criticalAndSecurityPatchCount'] = 2
    assert run(suffix, machine, index)[0] == 'UNKNOWN'


def test_nsg_priority_ranges_protocol_and_independent_associations():
    suffix = 'remote_access_restricted_all_ports'
    machine, index = case(suffix)
    props = native(index, 'nsg')['properties']
    props['securityRules'] = [rule(100, 'Deny'), rule(200, 'Allow')]
    assert run(suffix, machine, index)[0] == 'PASS'
    props['securityRules'] = [rule(100, 'Deny', port='0-1023'), rule(200, 'Deny', port='1024-65535'), rule(300, 'Allow')]
    assert run(suffix, machine, index)[0] == 'PASS'
    props['securityRules'][1]['properties']['destinationPortRange'] = '1024-65534'
    assert run(suffix, machine, index)[0] == 'FAIL'
    props['securityRules'] = [rule(100, 'Deny', protocol='Tcp'), rule(200, 'Allow', protocol='Udp')]
    assert run(suffix, machine, index)[0] == 'FAIL'
    props['securityRules'] = [rule(100, 'Allow', destination='10.0.0.5')]
    assert run(suffix, machine, index)[0] == 'PASS'
    props['securityRules'] = [rule(100, 'Allow', source='Internet')]
    assert run(suffix, machine, index)[0] == 'UNKNOWN'
    props['resolvedServiceTags'] = {'Internet': {'status': 'collected', 'prefixes': ['8.8.8.0/24']}}
    assert run(suffix, machine, index)[0] == 'FAIL'
    props['securityRules'] = [rule(100, 'Allow')]
    other = {'id': NSG + 'subnet', 'properties': {'securityRules': [], 'defaultSecurityRules': [rule(65500, 'Deny')]}}
    collection(index, 'nsg', [native(index, 'nsg'), other])
    native(index, 'subnet')['properties']['networkSecurityGroup'] = {'id': other['id']}
    assert run(suffix, machine, index)[0] == 'FAIL'
    native(index, 'nic')['properties']['networkSecurityGroup'] = None
    assert run(suffix, machine, index)[0] == 'PASS'
    native(index, 'subnet')['properties']['networkSecurityGroup'] = None
    status, evidence = run(suffix, machine, index)
    assert status == 'UNKNOWN' and evidence['unprotected_paths']


def test_nsg_source_and_source_port_partition_and_ipv6():
    suffix = 'remote_access_restricted_all_ports'
    machine, index = case(suffix)
    props = native(index, 'nsg')['properties']
    props['securityRules'] = [rule(100, 'Deny', source='0.0.0.0/1'),
        rule(200, 'Deny', source='128.0.0.0/1'), rule(300, 'Allow')]
    assert run(suffix, machine, index)[0] == 'PASS'
    props['securityRules'] = [rule(100, 'Deny', source_port='0-65534'), rule(200, 'Allow')]
    assert run(suffix, machine, index)[0] == 'FAIL'
    native(index, 'nic')['properties']['ipConfigurations'][0]['properties']['privateIPAddress'] = '2001:db8::4'
    props['securityRules'] = [rule(100, 'Allow', source='::/0')]
    assert run(suffix, machine, index)[0] == 'FAIL'
    props['securityRules'][0]['properties']['sourceAddressPrefix'] = '0.0.0.0/0'
    props['securityRules'][0]['properties']['sourceAddressPrefixes'] = ['2001:db8:1::/64']
    assert run(suffix, machine, index)[0] == 'UNKNOWN'


def test_nsg_attachment_no_stricter_port_test_and_no_false_nonexposure():
    suffix = 'tcp_udp_access_restricted_internet'
    machine, index = case(suffix)
    native(index, 'nsg')['properties']['securityRules'] = [rule(100, 'Allow')]
    assert run(suffix, machine, index)[0] == 'PASS'
    native(index, 'nic')['properties']['networkSecurityGroup'] = None
    native(index, 'subnet')['properties']['networkSecurityGroup'] = {'id': NSG}
    assert run(suffix, machine, index)[0] == 'PASS'
    native(index, 'subnet')['properties']['networkSecurityGroup'] = None
    assert run(suffix, machine, index)[0] == 'FAIL'
    native(index, 'nic')['properties']['ipConfigurations'][0]['properties']['publicIPAddress'] = None
    assert run(suffix, machine, index)[0] == 'NOT_APPLICABLE'
    index['collections']['load_balancer'][0]['status'] = 'partial'
    assert run(suffix, machine, index)[0] == 'UNKNOWN'


def test_load_balancer_public_backend_is_internet_facing():
    suffix = 'tcp_udp_access_restricted_internet'
    machine, index = case(suffix)
    config = native(index, 'nic')['properties']['ipConfigurations'][0]
    config['properties']['publicIPAddress'] = None
    lb_id = BASE + 'Microsoft.Network/loadBalancers/lb'
    frontend = lb_id + '/frontendIPConfigurations/front'
    pool = lb_id + '/backendAddressPools/pool'
    lb = {'id': lb_id, 'properties': {
        'frontendIPConfigurations': [{'id': frontend, 'properties': {'publicIPAddress': {'id': PIP}}}],
        'backendAddressPools': [{'id': pool, 'properties': {'loadBalancerBackendAddresses': [], 'backendIPConfigurations': [{'id': config['id']} ]}}],
        'loadBalancingRules': [{'properties': {'frontendIPConfiguration': {'id': frontend}, 'backendAddressPool': {'id': pool}}}],
        'inboundNatRules': [], 'inboundNatPools': []}}
    collection(index, 'load_balancer', [lb])
    assert run(suffix, machine, index)[0] == 'PASS'
    native(index, 'nic')['properties']['networkSecurityGroup'] = None
    assert run(suffix, machine, index)[0] == 'FAIL'
    lb['properties']['backendAddressPools'][0]['properties']['loadBalancerBackendAddresses'] = [{'properties': {'ipAddress': '10.0.0.4'}}]
    assert run(suffix, machine, index)[0] == 'UNKNOWN'


def test_firewall_values_preserve_types():
    suffix = 'meet_firewall_properties_windows'
    machine, index = case(suffix)
    prop = native(index, 'guest_configuration_report')['properties']['details']['resources'][0]['properties']
    prop['observed'] = 1
    assert run(suffix, machine, index)[0] == 'UNKNOWN'
    prop['observed'] = True
    prop['expected'] = 1
    assert run(suffix, machine, index)[0] == 'UNKNOWN'
    machine, index = case(suffix)
    parameter = machine['guestConfigurationAssignments'][0]['properties']['guestConfiguration']['configurationParameter'][0]
    bound = json.loads(parameter['value'])
    bound['firewallState']['expected'] = 1
    parameter['value'] = json.dumps(bound)
    assert run(suffix, machine, index)[0] == 'UNKNOWN'


@pytest.mark.parametrize('suffix', SUFFIXES)
def test_frozen_snapshots_and_collection_integrity(suffix):
    from peaso.snapshot import freeze
    machine, index = case(suffix)
    assert run(suffix, freeze(machine), freeze(index))[0] == 'PASS'
    index['collections']['vm'][0]['status'] = 'empty'
    assert run(suffix, machine, index)[0] == 'UNKNOWN'
    machine, index = case(suffix)
    index['collections']['vm'][0]['items'] = []
    assert run(suffix, machine, index)[0] == 'UNKNOWN'
    machine, index = case(suffix)
    index['vm'][0]['scope'] = '/subscriptions/foreign'
    assert run(suffix, machine, index)[0] == 'UNKNOWN'


def test_public_ip_based_lb_backend_requires_exact_vnet_and_address():
    suffix = 'tcp_udp_access_restricted_internet'
    machine, index = case(suffix)
    config = native(index, 'nic')['properties']['ipConfigurations'][0]
    config['properties']['publicIPAddress'] = None
    native(index, 'nic')['properties']['networkSecurityGroup'] = None
    lb_id = BASE + 'Microsoft.Network/loadBalancers/lb'
    front, pool = lb_id + '/frontendIPConfigurations/front', lb_id + '/backendAddressPools/pool'
    backend = {'properties': {'virtualNetwork': {'id': SUBNET.rsplit('/subnets/', 1)[0]}, 'ipAddress': '10.0.0.4'}}
    lb = {'id': lb_id, 'properties': {'frontendIPConfigurations': [{'id': front, 'properties': {'publicIPAddress': {'id': PIP}}}],
        'backendAddressPools': [{'id': pool, 'properties': {'backendIPConfigurations': [], 'loadBalancerBackendAddresses': [backend]}}],
        'loadBalancingRules': [{'properties': {'frontendIPConfiguration': {'id': front}, 'backendAddressPool': {'id': pool}}}], 'inboundNatRules': [], 'inboundNatPools': []}}
    collection(index, 'load_balancer', [lb])
    assert run(suffix, machine, index)[0] == 'FAIL'
    backend['properties']['virtualNetwork']['id'] += '-other'
    assert run(suffix, machine, index)[0] == 'NOT_APPLICABLE'
    backend['properties'].pop('virtualNetwork')
    assert run(suffix, machine, index)[0] == 'UNKNOWN'


def test_report_and_empty_exception_observation_authority():
    suffix = 'rdp_service_disabled'
    machine, index = case(suffix)
    report = native(index, 'guest_configuration_report')
    report['_provenance']['read_only'] = False
    assert run(suffix, machine, index)[0] == 'UNKNOWN'
    report['_provenance']['read_only'] = True
    report['properties']['details']['resources'][0]['properties']['state'] = 'Enabled'
    collection(index, 'vm_rdp_exception', [])
    assert run(suffix, machine, index)[0] == 'FAIL'
    index['collections']['vm_rdp_exception'][0]['_provenance']['observed_at'] = OLD
    assert run(suffix, machine, index)[0] == 'UNKNOWN'


def test_empty_certificate_requirement_needs_explicit_policy_decision():
    suffix = 'with_no_specified_certificates_in_trusted_root_windows'
    machine, index = case(suffix)
    pol = index['context']['metadata']['compliance_policy']['checks'][sw.PREFIX + suffix]
    pol.update(requiredThumbprints=[], emptyRequiredSetApproved=True)
    machine['guestConfigurationAssignments'][0]['properties']['guestConfiguration']['configurationParameter'][0]['value'] = '[]'
    assert run(suffix, machine, index)[0] == 'PASS'
    pol['emptyRequiredSetApproved'] = False
    assert run(suffix, machine, index)[0] == 'UNKNOWN'


def test_adaptive_native_normal_route_reaches_registered_check(monkeypatch):
    from datetime import datetime, timedelta, timezone
    from urllib.parse import urlsplit
    from peaso.collectors import azure, collect_live
    from peaso.collectors.azure_adaptive_network_native import KIND
    suffix = 'adaptive_network_hardening_recommendation_applied'
    cid = sw.PREFIX + suffix
    calculated = (datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat()
    class Transport:
        tenant = verified_tenant = '22222222-2222-2222-2222-222222222222'
        def __init__(self):
            self.calls = []
        def close(self):
            pass
        def request(self, url, *, body=None, audience=azure.ARM):
            self.calls.append(url)
            path = urlsplit(url).path
            if path == SCOPE + '/providers/Microsoft.Compute/virtualMachines':
                return {'value': [{'id': VM, 'name': 'vm', 'type': 'Microsoft.Compute/virtualMachines',
                                   'properties': {}}]}
            if path == VM:
                return {'id': VM, 'name': 'vm', 'type': 'Microsoft.Compute/virtualMachines',
                        'properties': {}, 'instanceView': {}}
            if path == VM + '/providers/Microsoft.Security/adaptiveNetworkHardenings':
                return {'value': [{'id': VM + '/providers/Microsoft.Security/adaptiveNetworkHardenings/default',
                    'name': 'default', 'type': 'Microsoft.Security/adaptiveNetworkHardenings',
                    'properties': {'rulesCalculationTime': calculated,
                        'rules': [{'name': 'rule1', 'direction': 'Inbound', 'ipAddresses': ['10.0.0.0/8'],
                                   'destinationPort': 443, 'protocols': ['TCP']}],
                        'effectiveNetworkSecurityGroups': [{'networkInterface': NIC,
                            'networkSecurityGroups': [NSG]}]}}]}
            return {'value': []}
    transport = Transport()
    monkeypatch.setattr(azure, 'AzureTransport', lambda auth: transport);monkeypatch.setattr(azure,'AzureTransportExposure',lambda auth: transport)
    assert KIND in sw.DEPENDENCIES[cid]
    snapshot = collect_live({'provider': 'azure', 'scopes': [SCOPE], 'options': {'retries': 0}},
                            sw.DEPENDENCIES[cid])
    from peaso.engine import _index
    from peaso.snapshot import resources
    index = _index(snapshot, resources(snapshot))
    index['context'] = {'provider': 'azure', 'scope': SCOPE, 'created_at': snapshot['created_at'],
        'metadata': {'compliance_policy': {'status': 'collected', 'scope': SCOPE,
            'checks': {cid: policy_entry()}}}}
    vm_row = index['vm'][0]['data']
    verdict, evidence = sw.REGISTERED_CHECKS[cid].evaluate(vm_row, index)
    assert verdict == 'UNKNOWN'
    assert evidence['native_recommendation_count'] == 1
    assert evidence['native_recommendation_ids'] == [VM.casefold() +
        '/providers/microsoft.security/adaptivenetworkhardenings/default']
    assert any('/adaptiveNetworkHardenings?' in call for call in transport.calls)
    assert 'applied' not in evidence and 'effective' not in evidence


def adaptive_native_row():
    return {'id': VM + '/providers/Microsoft.Security/adaptiveNetworkHardenings/default',
        'vm_id': VM, 'name': 'default', 'rules_calculation_time': NOW,
        'recommended_rules': [{'name': 'rule1', 'direction': 'Inbound',
            'ipAddresses': ['10.0.0.0/8'], 'destinationPort': 443, 'protocols': ['TCP']}],
        'effective_nsg_associations': [{'network_interface_id': NIC,
            'network_security_group_ids': [NSG]}],
        '_provenance': {**proof('AdaptiveNetworkHardenings_ListByExtendedResource'),
            'api_version': '2020-01-01', 'representation': 'native_recommendation_metadata',
            'endpoint': 'https://management.azure.com' + VM +
                '/providers/Microsoft.Security/adaptiveNetworkHardenings?api-version=2020-01-01'}}


@pytest.mark.parametrize('variant', [
    'valid', 'empty', 'partial', 'foreign_parent', 'wrong_child', 'wrong_operation',
    'wrong_endpoint', 'stale_calculation', 'duplicate_child', 'missing_applicability',
    'known_external_violation',
])
def test_adaptive_native_metadata_boundaries(variant):
    suffix = 'adaptive_network_hardening_recommendation_applied'
    machine, index = defender_case(suffix)
    row = adaptive_native_row()
    if variant == 'foreign_parent':
        row['vm_id'] = VM + 'other'
        row['id'] = row['vm_id'] + '/providers/Microsoft.Security/adaptiveNetworkHardenings/default'
    elif variant == 'wrong_child':
        row['id'] = VM + '/providers/Microsoft.Security/adaptiveNetworkHardenings/other'
    elif variant == 'wrong_operation':
        row['_provenance']['source_operation'] = 'unreviewed_operation'
    elif variant == 'wrong_endpoint':
        row['_provenance']['endpoint'] = 'https://management.azure.com' + VM + '/other'
    elif variant == 'stale_calculation':
        row['rules_calculation_time'] = OLD
    rows = [] if variant == 'empty' else [row, copy.deepcopy(row)] if variant == 'duplicate_child' else [row]
    collection(index, 'adaptive_network_hardening_native', rows)
    if variant == 'partial':
        index['collections']['adaptive_network_hardening_native'][0]['status'] = 'partial'
    if variant == 'missing_applicability':
        index['collections'].pop('vm_compliance_applicability')
        index.pop('vm_compliance_applicability')
    if variant == 'known_external_violation':
        native(index, 'security_assessment')['properties']['status']['code'] = 'Unhealthy'
    else:
        index['collections'].pop('adaptive_network_hardening')
        index.pop('adaptive_network_hardening')
    verdict, evidence = run(suffix, machine, index)
    if variant == 'known_external_violation':
        assert verdict == 'FAIL'
    else:
        assert verdict == 'UNKNOWN'
        if variant in ('valid', 'empty', 'missing_applicability'):
            assert evidence['native_recommendation_count'] == (0 if variant == 'empty' else 1)
            assert 'native_recommendation_status' not in evidence
        else:
            assert evidence['native_recommendation_status'] == 'unavailable'
        assert not ({'applied', 'approved', 'effective'} & evidence.keys())


@pytest.mark.parametrize('path,value', [
    (('vm_id',), VM + '-other'),
    (('group_id',), '/subscriptions/other/providers/Microsoft.Security/locations/westeurope/applicationWhitelistings/group'),
    (('policy_id',), 'unbound-policy'),
    (('captured_at',), OLD),
    (('_provenance', 'issuer'), 'untrusted'),
    (('policy_observation', 'capture_id'), 'other-capture'),
    (('alert_observation', '_provenance', 'observed_at'), OLD),
    (('alert_observation', 'alert_id'), ''),
    (('alert_observation', 'execution_id'), ''),
])
def test_allowlist_attestation_rejects_unbound_or_unmeasured_evidence(path, value):
    suffix = 'adaptive_application_controls_enabled'
    machine, index = defender_case(suffix)
    row = native(index, 'application_allowlist_attestation')
    target = row
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = value
    assert run(suffix, machine, index)[0] == 'UNKNOWN'


def test_allowlist_legacy_group_booleans_alone_cannot_pass():
    suffix = 'adaptive_application_controls_enabled'
    machine, index = defender_case(suffix)
    collection(index, 'application_allowlist_attestation', [])
    assert run(suffix, machine, index)[0] == 'UNKNOWN'


def test_allowlist_retired_group_absence_does_not_fail_valid_attestation():
    suffix = 'adaptive_application_controls_enabled'
    machine, index = defender_case(suffix)
    collection(index, 'application_whitelisting', [])
    assert run(suffix, machine, index)[0] == 'PASS'


def test_allowlist_unhealthy_native_assessment_remains_failure_without_attestation():
    suffix = 'adaptive_application_controls_enabled'
    machine, index = defender_case(suffix)
    native(index, 'security_assessment')['properties']['status']['code'] = 'Unhealthy'
    collection(index, 'application_allowlist_attestation', [])
    assert run(suffix, machine, index)[0] == 'FAIL'


# The fixed Docker built-in GET is a negative witness only. It does not
# provide a complete Docker host roster or an all-rules Healthy proof.
DOCKER_SUFFIX = 'container_security_configurations_vulnerabilities_remediated'
DOCKER_KEY = '0677209d-e675-2c6f-e91a-54cef2878663'
DOCKER_POLICY = '/providers/Microsoft.Authorization/policyDefinitions/e8cbc669-f12d-49eb-93e7-9273119e9933'


def docker_native_negative_case():
    machine, index = defender_case(DOCKER_SUFFIX)
    pol = index['context']['metadata']['compliance_policy']['checks'][sw.PREFIX + DOCKER_SUFFIX]
    pol['assessmentKeys'] = [DOCKER_KEY]
    assessment = native(index, 'security_assessment')
    assessment.update(type='Microsoft.Security/assessments', name=DOCKER_KEY,
                      id=VM + '/providers/Microsoft.Security/assessments/' + DOCKER_KEY)
    assessment['properties']['resourceDetails']['source'] = 'Azure'
    assessment['properties']['status']['code'] = 'Unhealthy'
    assessment['properties']['metadata'] = {'assessmentType': 'BuiltIn', 'policyDefinitionId': DOCKER_POLICY}
    assessment['_provenance'] = {**proof('Assessments_Get'), 'api_version': '2020-01-01',
        'representation': 'metadata', 'metadata_expanded': True, 'scope': SCOPE,
        'credential_context_id': 'capture-credential', 'customer_context_id': 'capture-customer'}
    index['context']['metadata'].update(context_binding='scan_local',
        credential_context_id='capture-credential', customer_context_id='capture-customer')
    del index['collections']['vm_compliance_applicability']
    del index['vm_compliance_applicability']
    return machine, index, assessment


def test_docker_native_required_unhealthy_without_applicability_is_fail():
    machine, index, _ = docker_native_negative_case()
    status, evidence = run(DOCKER_SUFFIX, machine, index)
    assert status == 'FAIL'
    assert evidence['unhealthy_assessment_keys'] == [DOCKER_KEY]
    assert evidence['source_operation'] == 'Assessments_Get'


@pytest.mark.parametrize('mutation', [
    'custom_assessment', 'wrong_policy', 'foreign_parent', 'stale_get',
    'duplicate', 'metadata_denied', 'healthy', 'not_applicable',
    'no_policy', 'unselected_key', 'wrong_customer', 'envelope_customer_mismatch',
])
def test_docker_native_negative_rejects_unproven_witness(mutation):
    machine, index, assessment = docker_native_negative_case()
    if mutation == 'custom_assessment':
        assessment['properties']['metadata']['assessmentType'] = 'CustomerManaged'
    elif mutation == 'wrong_policy':
        assessment['properties']['metadata']['policyDefinitionId'] = '/providers/Microsoft.Authorization/policyDefinitions/other'
    elif mutation == 'foreign_parent':
        assessment['properties']['resourceDetails']['id'] = VM + '-other'
    elif mutation == 'stale_get':
        assessment['_provenance']['observed_at'] = OLD
    elif mutation == 'duplicate':
        clone = copy.deepcopy(assessment)
        index['collections']['security_assessment'][0]['items'].append(clone)
        index['security_assessment'].append({'type': 'security_assessment', 'scope': SCOPE, 'data': clone})
    elif mutation == 'metadata_denied':
        assessment['properties']['_coverage'] = {'metadata': {'status': 'not_collected'}}
    elif mutation == 'healthy':
        assessment['properties']['status']['code'] = 'Healthy'
    elif mutation == 'not_applicable':
        assessment['properties']['status']['code'] = 'NotApplicable'
    elif mutation == 'no_policy':
        index['context']['metadata']['compliance_policy']['checks'].clear()
    elif mutation == 'unselected_key':
        index['context']['metadata']['compliance_policy']['checks'][sw.PREFIX + DOCKER_SUFFIX]['assessmentKeys'] = ['other-key']
    elif mutation == 'wrong_customer':
        assessment['_provenance']['customer_context_id'] = 'another-customer'
    elif mutation == 'envelope_customer_mismatch':
        index['collections']['security_assessment'][0]['_provenance']['customer_context_id'] = 'another-customer'
    assert run(DOCKER_SUFFIX, machine, index)[0] == 'UNKNOWN'


def test_docker_legacy_external_applicable_unhealthy_still_fails():
    machine, index = defender_case(DOCKER_SUFFIX)
    native(index, 'security_assessment')['properties']['status']['code'] = 'Unhealthy'
    assert run(DOCKER_SUFFIX, machine, index)[0] == 'FAIL'
