"""Isolated signed Azure sw13 evaluators and adversarial fact boundaries."""
from __future__ import annotations

import copy
import hashlib
import importlib
import json

import pytest
from peaso.checks import CHECKS

# Import the requested module directly; safe evaluator closures survive cleanup.
# When the integrator already imports it, preserve its existing registrations.
_before = {id(c) for c in CHECKS}
try:
    m = importlib.import_module('peaso.checks.compliance_new_sw13')
    REGISTERED = {c.id: c for c in CHECKS if c.id in m.IDS}
finally:
    CHECKS[:] = [c for c in CHECKS if id(c) in _before]

SUB = '/subscriptions/sub-13'
TENANT = '/tenants/tenant-13'
VAULT = SUB + '/resourceGroups/rg/providers/Microsoft.RecoveryServices/vaults/v'
APP = SUB + '/resourceGroups/rg/providers/Microsoft.Web/sites/app'
SUBNET = SUB + '/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/v/subnets/s'
POLICY = VAULT + '/backupPolicies/p'
ITEM = VAULT + '/backupFabrics/Azure/protectionContainers/c/protectedItems/i'
AT = '2026-10-12T12:00:00Z'
START = '2026-10-01T00:00:00Z'
END = '2026-11-01T00:00:00Z'


def dated():
    return {'document_id': 'approved-document', 'authorized_by': 'security-owner',
            'observed_at': START, 'expires_at': END}


def graph(rid, **fields):
    return {'id': rid, '_provenance': {'tenant_id': 'tenant-13', 'read_only': True}, **fields}


def obs(rid, owner=SUB, **fields):
    prov = {'read_only': True}
    if owner == TENANT:
        prov['tenant_id'] = 'tenant-13'
    return {'id': rid, 'scope': owner, '_provenance': prov, **fields}


def facts(cid, rows, p=None, owner=SUB):
    return {'context': {'provider': 'azure', 'scope': owner, 'created_at': AT,
        'metadata': {'compliance_policy': {'sw13': {'status': 'collected', 'scope': owner,
            **dated(), 'checks': {cid.replace('.', '|'): p or {}}}}}},
        'collections': {kind: [{'type': kind, 'scope': owner, 'status': 'collected' if values else 'empty',
                               'items': values}] for kind, values in rows.items()},
        **{kind: [{'type': kind, 'scope': owner, 'data': row} for row in values] for kind, values in rows.items()}}


def evaluate(cid, item, index):
    return m.EVALUATORS[cid](item, index)


def raw(index, kind, n=0):
    return index[kind][n]['data']


def set_rows(index, kind, rows):
    owner = index['context']['scope']
    index[kind] = [{'type': kind, 'scope': owner, 'data': r} for r in rows]
    index['collections'][kind] = [{'type': kind, 'scope': owner, 'status': 'collected' if rows else 'empty', 'items': rows}]


def ca_fixture(cid=m.USERS):
    r = graph('ca-1', state='enabled', conditions={
        'users': {'includeUsers': ['All'], 'excludeUsers': [], 'includeGroups': [], 'excludeGroups': [], 'includeRoles': [], 'excludeRoles': []},
        'applications': {'includeApplications': ['All'], 'excludeApplications': []},
        'clientAppTypes': ['all'], 'locations': None, 'platforms': None, 'devices': None,
        'signInRiskLevels': ['medium', 'high'] if cid == m.RISK else [], 'userRiskLevels': [],
        'authenticationFlows': {'transferMethods': 'deviceCodeFlow'} if cid == m.DEVICE else None},
        grantControls={'operator': 'AND', 'builtInControls': ['block'] if cid in (m.DEVICE, m.GEO) else ['mfa'],
                       'customAuthenticationFactors': [], 'termsOfUse': [], 'authenticationStrength': None})
    profile = obs('profile-1', TENANT, **dated(), userId='user-1', groupIds=['admin-group'],
                  roleTemplateIds=['admin-role'], membershipComplete=True, pimResolved=True)
    domains = {k: [{'value': v}] for k, v in {
        'application': 'app-1', 'clientAppType': 'browser', 'location': 'prohibited',
        'platform': 'windows', 'device': 'device-1', 'signInRisk': 'medium',
        'userRisk': 'none', 'authenticationFlow': 'deviceCodeFlow' if cid == m.DEVICE else 'ordinary'}.items()}
    domains['location'][0].update(country='XX', isTrusted=False)
    domains['device'][0].update(isCompliant=True, isHybridJoined=True)
    domains['application'][0].update(isApproved=True, isCompliant=True)
    if cid == m.RISK:
        domains['signInRisk'].append({'value': 'high'})
    partition = obs('partition-1', TENANT, **dated(), checkId=cid, exhaustive=True, userIds=['user-1'],
        domains=domains, partitionProof={k: 'approved partition proof' for k in domains})
    review = obs('review-1', TENANT, **dated(), checkId=cid, decision='block', userIds=['user-1'],
        userScope='all', scopeComplete=True, policyIds=['ca-1'], applicationIds=['app-1'], exceptionUserIds=[],
        exceptionsDocumentId='exceptions-doc', rationale='reviewed geographic risk', prohibitedCountries=['XX'])
    p = {'userScope': 'administrative' if cid == m.ADMIN else 'all', 'designatedGroups': ['admin-group'],
        'designatedRoles': [], 'requiredApplications': ['app-1'], 'requiredClientAppTypes': ['browser'],
        'riskLicensingConfirmed': True}
    rows = {'conditional_access_policy': [r], 'directory_user': [graph('user-1', accountEnabled=True)],
        'conditional_access_principal': [profile], 'conditional_access_partition': [partition],
        'named_location': [], 'authentication_strength': [], 'directory_security_defaults': [graph('defaults', isEnabled=False)],
        'azure_compliance_review': [review]}
    return r, facts(cid, rows, p, TENANT)


def backup_policy(count=30):
    return {'id': POLICY, 'parent_id': VAULT, '_provenance': {'representation': 'full'}, 'properties': {
        'backupManagementType': 'AzureIaasVM', 'timeZone': 'UTC',
        'schedulePolicy': {'schedulePolicyType': 'SimpleSchedulePolicy', 'scheduleRunFrequency': 'Daily',
                           'scheduleRunTimes': ['2020-01-01T02:00:00Z']},
        'retentionPolicy': {'retentionPolicyType': 'LongTermRetentionPolicy', 'dailySchedule': {
            'retentionTimes': ['2020-01-01T02:00:00Z'], 'retentionDuration': {'count': count, 'durationType': 'Days'}}}}}


def vault_fixture(cid):
    v = {'id': VAULT, '_provenance': {'representation': 'full'}, 'properties': {
        'encryption': {'keyVaultProperties': {'keyUri': 'https://vault.vault.azure.net/keys/key/version'},
            'kekIdentity': {'useSystemAssignedIdentity': True}},
        'securitySettings': {'immutabilitySettings': {'state': 'Locked'}}},
        'identity': {'type': 'SystemAssigned', 'principalId': 'principal-1'}}
    protected = {'id': ITEM, 'parent_id': VAULT, 'properties': {'policyId': POLICY, 'protectionState': 'Protected'}}
    point = {'id': ITEM + '/recoveryPoints/p', 'parent_id': ITEM,
        '_provenance': {'detail_get_complete': True, 'retention_schema_supported': True},
        'properties': {'isSoftDeleted': False, 'recoveryPointTime': '2026-10-01T00:00:00Z',
            'recoveryPointProperties': {'expiryTime': '2026-11-01T00:00:00Z'}}}
    job = {'id': VAULT + '/backupJobs/job-1', 'parent_id': VAULT, 'properties': {'operation': 'Restore',
           'status': 'Completed', 'startTime': '2026-10-10T01:00:00Z', 'endTime': '2026-10-10T02:00:00Z'}}
    test = obs(VAULT + '/restoreTests/test-1', protectedItemId=ITEM, jobId=job['id'], independentVerification=True,
        verifiedAt='2026-10-10T03:00:00Z', verificationDocumentId='verification-doc', result='Passed',
        required=True, restoredDataVerified=True)
    key = v['properties']['encryption']['keyVaultProperties']['keyUri']
    rows = {'recovery_vault': [v], 'backup_protected_item': [protected], 'backup_policy': [backup_policy()],
        'backup_recovery_point': [point], 'backup_job': [job], 'backup_restore_test': [test],
        'backup_restore_window': [obs(VAULT + '/restoreWindows/window', vaultId=VAULT,
            windowStart='2026-09-01T00:00:00Z', windowEnd=AT, jobsComplete=True, testsComplete=True)],
        'recovery_vault_capability': [obs(VAULT + '/capabilities/cmk', **dated(), vaultId=VAULT, cmkSupported=True)],
        'key_authorization_evidence': [obs(VAULT + '/keyAccess/access', **dated(), vaultId=VAULT, keyUri=key,
            principalId='principal-1', authorizationComplete=True, keyEnabled=True, networkAccessible=True,
            effectiveKeyOperations=['get', 'wrapKey', 'unwrapKey'])]}
    p = {'approvedKeyUris': [key], 'requiredMinimumFrequency': 'Daily', 'minimumRetentionDays': 30,
         'minRetentionDays': 30, 'criticalProtectedItemIds': [ITEM], 'restoreTestMaxAgeDays': 30}
    index = facts(cid, rows, p)
    if cid == m.RESTORE:
        # Explicit synthetic independent usable-data result, not a native job assertion.
        capture = {'tenant_id': 'fixture-tenant', 'credential_context_id': 'restore-fixture-capture',
                   'customer_context_id': 'restore-fixture-customer'}
        index['context']['metadata'].update(capture, tenant_verified=True)
        for kind in ('recovery_vault', 'backup_protected_item', 'backup_job'):
            env = index['collections'][kind][0]
            env['service'] = 'Microsoft.RecoveryServices'
            env['_provenance'] = {key: capture[key] for key in ('credential_context_id', 'customer_context_id')}
            for wrapped in index[kind]:
                wrapped['data'].setdefault('_provenance', {}).update(env['_provenance'])
                proof = wrapped['data']['_provenance']
                proof.update(read_only=True, api_version='2024-04-01')
                if kind == 'recovery_vault':
                    proof.update(source_operation='get', representation='full')
                else:
                    field = 'backupJobs' if kind == 'backup_job' else 'backupProtectedItems'
                    proof.update(source_operation='BackupJobs_List' if kind == 'backup_job' else 'BackupProtectedItems_List',
                                 representation='metadata', endpoint=VAULT + '/' + field)
        protected['properties']['backupManagementType'] = 'AzureIaasVM'
        job['properties'].update(jobType='AzureIaaSVMJob', backupManagementType='AzureIaasVM')
        digest = lambda value: hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'),
                                                         ensure_ascii=True, allow_nan=False).encode()).hexdigest()
        test.update(sourceRecoveryPointId=point['id'], restoreTargetId=SUB + '/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/restored')
        test['validationEvidence'] = {'document_id': test['verificationDocumentId'],
            'authorized_by': 'independent-restore-auditor', 'observed_at': test['verifiedAt'], 'expires_at': END,
            '_provenance': {'read_only': True, 'source_operation': 'external:restore-validation', 'representation': 'full'},
            'vaultId': VAULT, 'protectedItemId': ITEM, 'jobId': job['id'],
            'sourceRecoveryPointId': point['id'], 'restoreTargetId': test['restoreTargetId'],
            'credential_context_id': capture['credential_context_id'], 'customer_context_id': capture['customer_context_id'],
            'nativeEvidenceSha256': digest({'job': job, 'protected_item': protected, 'capture': capture}),
            'usableDataValidation': {'testId': 'synthetic-independent-usability', 'method': 'database-consistency-check',
                'result': 'Passed', 'resultArtifactSha256': 'a' * 64}}
        window = rows['backup_restore_window'][0]
        window.update(document_id='independent-complete-registry', authorized_by='independent-restore-auditor',
            observed_at=AT, expires_at=END, credential_context_id=capture['credential_context_id'],
            customer_context_id=capture['customer_context_id'], jobsInventorySha256=digest({'jobs': rows['backup_job'], 'capture': capture}))
        window['_provenance'].update(source_operation='external:restore-test-registry', representation='full')
    return v, index


def app_fixture(cid):
    app = {'id': APP, 'kind': 'functionapp' if cid == m.FUNCTION else 'app', 'configuration': {
        'id': APP + '/config/web', 'properties': {'ipSecurityRestrictionsDefaultAction': 'Deny',
        'ipSecurityRestrictions': [{'priority': 100, 'action': 'Allow', 'vnetSubnetResourceId': SUBNET,
                                    'ipAddress': None, 'headers': {}, 'tag': 'Default'}]}}}
    endpoint = obs(APP + '/endpoints/https', exposed=True, certificateBased=True, hostname='app.example.com', port=443)
    root, leaf = 'a' * 64, 'b' * 64
    reading = obs(APP + '/tlsObservations/https', endpointId=endpoint['id'], hostname='app.example.com',
        sni='app.example.com', port=443, handshakeStatus='Completed', observedAt=AT,
        presentedChainSha256=[leaf, root], leafSha256=leaf, fullPresentedChain=True,
        validatedAgainstRootSha256=[root], validatedAt=AT, chainValidation='Trusted', trustRootSha256=root,
        leaf={'notBefore': '2026-01-01T00:00:00Z', 'notAfter': '2027-01-01T00:00:00Z', 'subjectAlternativeNames': ['*.example.com']})
    reading['_provenance']['validationEngine'] = 'OpenSSL verified chain'
    fc = obs(APP + '/functionConfiguration/current', **dated(), appId=APP, packageType='Code', runtimeType='Language',
        hostingModel='Consumption', runtimeResolved=True,
        settings={'runtime': 'python|3.12.7', 'role': 'worker-role', 'timeoutSeconds': 300, 'memoryMB': 1536},
        sources={field: {'status': 'collected', 'operation': 'metadata GET', 'nativePath': field}
                 for field in ('runtime', 'role', 'timeoutSeconds', 'memoryMB')})
    rows = {'app_service': [app], 'app_service_config': [], 'subnet': [{'id': SUBNET,
        'properties': {'serviceEndpoints': [{'service': 'Microsoft.Web'}], 'addressPrefixes': ['10.0.0.0/24']}}],
        'app_service_endpoint': [endpoint], 'tls_endpoint_observation': [reading],
        'app_service_endpoint_inventory': [obs(APP + '/endpointInventory/current', **dated(), appId=APP,
            exposedPortsComplete=True, certificateEndpointsComplete=True, endpointIds=[endpoint['id']])],
        'function_app_configuration': [fc]}
    p = {'approvedSubnetIds': [SUBNET], 'approvedTrustRootSha256': [root], 'maxObservationAgeSeconds': 60,
        'expectedFunctionSettings': {APP: {'hostingModel': 'Consumption', **fc['settings']}}}
    return app, facts(cid, rows, p)


def notify_fixture():
    cid = m.NOTIFY
    item = graph('ca-1', state='enabled')
    event = graph('event-1', signInRiskLevel='high', createdDateTime='2026-10-11T01:00:00Z', status={'errorCode': 0})
    p = {'windowStart': '2026-10-11T00:00:00Z', 'windowEnd': '2026-10-12T00:00:00Z',
         'notificationMaxDelaySeconds': 3600, 'suspiciousRiskLevels': ['medium', 'high'], 'authorizedRecipientIds': ['responder']}
    monitor = obs('window-1', TENANT, checkId=cid, windowStart=p['windowStart'], windowEnd=p['windowEnd'],
        detectionEnabled=True, ingestionConfirmed=True, observationComplete=True, deliveryRegistryComplete=True, observedThrough=AT)
    delivery = obs('delivery-1', TENANT, eventId=event['id'], recipientId='responder', deliveryStatus='Delivered',
                   observedAt='2026-10-11T01:05:00Z')
    return item, facts(cid, {'conditional_access_policy': [item], 'audit_sign_in': [event],
        'authentication_monitoring_window': [monitor], 'authentication_notification': [delivery]}, p, TENANT)


def correlation_fixture():
    cid = m.CORRELATION
    wid = SUB + '/resourceGroups/rg/providers/Microsoft.OperationalInsights/workspaces/w'
    aid = SUB + '/resourceGroups/rg/providers/Microsoft.Insights/actionGroups/a'
    query = 'SigninLogs | join AzureActivity on CorrelationId | join AzureNetworkAnalytics_CL on CorrelationId'
    criterion = {'query': query, 'operator': 'GreaterThan', 'threshold': 0, 'timeAggregation': 'Count'}
    item = {'id': SUB + '/resourceGroups/rg/providers/Microsoft.Insights/scheduledQueryRules/r',
        'properties': {'enabled': True, 'kind': 'LogAlert', 'scopes': [wid], 'windowSize': 'PT15M',
            'evaluationFrequency': 'PT5M', 'criteria': {'allOf': [criterion]}, 'actions': {'actionGroups': [aid]}}}
    tables = ['SigninLogs', 'AzureActivity', 'AzureNetworkAnalytics_CL']
    p = {'requiredWorkspaceIds': [wid], 'requiredEventTables': tables, 'requiredCorrelationFragments': ['join', 'CorrelationId'],
        'maxCorrelationWindowSeconds': 3600, 'approvedCriteria': [{k: v for k, v in criterion.items() if k != 'query'}]}
    review = obs(item['id'] + '/reviews/query', **dated(), ruleId=item['id'], querySha256=hashlib.sha256(query.encode()).hexdigest(),
        correlatedTables=tables, approved=True)
    ingestion = [obs(wid + '/ingestion/' + name, **dated(), workspaceId=wid, tableName=name, ingestionConfirmed=True) for name in tables]
    return item, facts(cid, {'scheduled_query_rule': [item], 'action_group': [{'id': aid, 'properties': {'enabled': True}}],
        'security_query_review': [review], 'security_table_ingestion': ingestion}, p)


def fixture(cid):
    if cid in (m.ADMIN, m.USERS, m.RISK, m.DEVICE, m.GEO):
        return ca_fixture(cid)
    if cid in (m.CMK, m.IMMUTABLE, m.RESTORE, m.SCHEDULE, m.POINTS):
        return vault_fixture(cid)
    if cid in (m.SERVICE_ENDPOINT, m.TLS, m.FUNCTION):
        return app_fixture(cid)
    return notify_fixture() if cid == m.NOTIFY else correlation_fixture()


def unsafe(cid, item, index):
    if cid in (m.ADMIN, m.USERS, m.RISK, m.DEVICE, m.GEO):
        item['conditions']['users']['excludeUsers'] = ['user-1']
    elif cid == m.CMK:
        item['properties']['encryption']['keyVaultProperties']['keyUri'] = None
    elif cid == m.IMMUTABLE:
        item['properties']['securitySettings']['immutabilitySettings']['state'] = 'Unlocked'
    elif cid == m.SCHEDULE:
        raw(index, 'backup_policy')['properties']['retentionPolicy']['dailySchedule']['retentionDuration']['count'] = 29
    elif cid == m.POINTS:
        raw(index, 'backup_recovery_point')['properties']['recoveryPointProperties']['expiryTime'] = '2026-10-20T00:00:00Z'
    elif cid == m.RESTORE:
        set_rows(index, 'backup_restore_test', [])
    elif cid == m.SERVICE_ENDPOINT:
        item['configuration']['properties']['ipSecurityRestrictions'][0]['action'] = 'Deny'
    elif cid == m.TLS:
        raw(index, 'tls_endpoint_observation')['leaf']['notAfter'] = '2026-10-11T00:00:00Z'
    elif cid == m.FUNCTION:
        raw(index, 'function_app_configuration')['settings']['memoryMB'] = 512
    elif cid == m.NOTIFY:
        set_rows(index, 'authentication_notification', [])
    elif cid == m.CORRELATION:
        item['properties']['enabled'] = False


@pytest.mark.parametrize('cid', m.IDS)
def test_signed_predicate_pass_fail(cid):
    item, index = fixture(cid)
    status, evidence = evaluate(cid, item, index)
    assert status == 'PASS', evidence
    unsafe(cid, item, index)
    status, evidence = evaluate(cid, item, index)
    assert status == 'FAIL', evidence


@pytest.mark.parametrize('cid', m.IDS)
@pytest.mark.parametrize('fault', ['incomplete', 'malformed', 'missing_fact', 'foreign_collection', 'foreign_policy', 'duplicate'])
def test_unknown_fact_boundaries(cid, fault):
    item, index = fixture(cid)
    kind = m.SPECS[cid]['resource_kind']
    if fault == 'incomplete':
        index['collections'][kind][0]['status'] = 'partial'
    elif fault == 'malformed':
        item['id'] = {'not': 'a string'}
    elif fault == 'missing_fact':
        item.pop('id')
    elif fault == 'foreign_collection':
        index['collections'][kind][0]['scope'] = '/tenants/other' if index['context']['scope'] == TENANT else '/subscriptions/other'
    elif fault == 'foreign_policy':
        index['context']['metadata']['compliance_policy']['sw13']['scope'] = '/subscriptions/other'
        # Immutability's signed 30-day bound is intrinsic, no external policy.
        if cid == m.IMMUTABLE:
            raw(index, 'backup_policy')['properties']['backupManagementType'] = 'unknown'
    else:
        set_rows(index, kind, [item, copy.deepcopy(item)])
    status, evidence = evaluate(cid, item, index)
    assert status == 'UNKNOWN', evidence


@pytest.mark.parametrize('cid,kind', [(m.ADMIN, 'conditional_access_principal'), (m.USERS, 'conditional_access_partition'),
    (m.RISK, 'authentication_strength'), (m.DEVICE, 'azure_compliance_review'), (m.GEO, 'azure_compliance_review'),
    (m.NOTIFY, 'authentication_notification'), (m.CORRELATION, 'security_table_ingestion'),
    (m.CMK, 'key_authorization_evidence'), (m.IMMUTABLE, 'backup_policy'), (m.RESTORE, 'backup_restore_test'),
    (m.SCHEDULE, 'backup_policy'), (m.POINTS, 'backup_recovery_point'),
    (m.SERVICE_ENDPOINT, 'subnet'), (m.TLS, 'tls_endpoint_observation'), (m.FUNCTION, 'function_app_configuration')])
def test_absent_required_dependency_unknown(cid, kind):
    item, index = fixture(cid)
    index.pop(kind)
    index['collections'].pop(kind)
    assert evaluate(cid, item, index)[0] == 'UNKNOWN'


@pytest.mark.parametrize('cid', [m.ADMIN, m.USERS, m.RISK])
def test_mfa_or_alternative_conditions_report_only_and_strength(cid):
    item, index = ca_fixture(cid)
    item['grantControls'].update(operator='OR', builtInControls=['mfa', 'compliantDevice'])
    assert evaluate(cid, item, index)[0] == 'FAIL'
    item['grantControls']['operator'] = 'AND'
    assert evaluate(cid, item, index)[0] == 'PASS'
    item['state'] = 'enabledForReportingButNotEnforced'
    assert evaluate(cid, item, index)[0] == 'UNKNOWN'
    item['state'] = 'enabled'
    item['conditions']['devices'] = {'deviceFilter': {'mode': 'exclude', 'rule': 'device.isCompliant -eq True'}}
    assert evaluate(cid, item, index)[0] == 'UNKNOWN'
    item['conditions']['devices'] = None
    item['grantControls'].update(builtInControls=[], authenticationStrength={'id': 'strength-1'})
    set_rows(index, 'authentication_strength', [graph('strength-1', requirementsSatisfied='mfa', allowedCombinations=['fido2', 'windowsHelloForBusiness'])])
    assert evaluate(cid, item, index)[0] == 'PASS'
    raw(index, 'authentication_strength')['allowedCombinations'].append('password')
    raw(index, 'authentication_strength')['requirementsSatisfied'] = 'none'
    assert evaluate(cid, item, index)[0] == 'FAIL'
    raw(index, 'authentication_strength')['allowedCombinations'] = ['unknownNewMethod']
    assert evaluate(cid, item, index)[0] == 'UNKNOWN'


def test_administrative_scope_empty_and_unresolved_membership():
    item, index = ca_fixture(m.ADMIN)
    raw(index, 'conditional_access_principal')['groupIds'] = []
    raw(index, 'conditional_access_partition')['userIds'] = []
    assert evaluate(m.ADMIN, item, index)[0] == 'NOT_APPLICABLE'
    raw(index, 'conditional_access_principal')['membershipComplete'] = False
    assert evaluate(m.ADMIN, item, index)[0] == 'UNKNOWN'


def test_all_user_scope_does_not_silently_ignore_unmodeled_member():
    item, index = ca_fixture(m.USERS)
    set_rows(index, 'directory_user', [raw(index, 'directory_user'), graph('user-2', accountEnabled=True)])
    assert evaluate(m.USERS, item, index)[0] == 'UNKNOWN'


def test_security_defaults_enabled_requires_context_proof():
    item, index = ca_fixture(m.ADMIN)
    raw(index, 'directory_security_defaults')['isEnabled'] = True
    assert evaluate(m.ADMIN, item, index)[0] == 'UNKNOWN'
    partition = raw(index, 'conditional_access_partition')
    state = {k: v[0]['value'] for k, v in partition['domains'].items()}
    set_rows(index, 'security_defaults_context_proof', [obs('defaults-proof', TENANT, **dated(),
        checkId=m.ADMIN, contexts=[{'userId': 'user-1', 'state': state, 'mfaRequired': True}])])
    item['state'] = 'disabled'
    assert evaluate(m.ADMIN, item, index)[0] == 'PASS'
    raw(index, 'security_defaults_context_proof')['contexts'][0]['mfaRequired'] = False
    assert evaluate(m.ADMIN, item, index)[0] == 'FAIL'


@pytest.mark.parametrize('cid', [m.DEVICE, m.GEO])
def test_consideration_missing_expired_future_and_inaccessible_review(cid):
    item, index = ca_fixture(cid)
    set_rows(index, 'azure_compliance_review', [])
    assert evaluate(cid, item, index)[0] == 'FAIL'
    item, index = ca_fixture(cid)
    raw(index, 'azure_compliance_review')['expires_at'] = '2026-10-11T00:00:00Z'
    assert evaluate(cid, item, index)[0] == 'FAIL'
    raw(index, 'azure_compliance_review').update(observed_at='2026-10-13T00:00:00Z', expires_at=END)
    assert evaluate(cid, item, index)[0] == 'UNKNOWN'
    index['collections']['azure_compliance_review'][0]['status'] = 'denied'
    assert evaluate(cid, item, index)[0] == 'UNKNOWN'


def test_geographic_authorized_no_block_decision_and_country_membership():
    item, index = ca_fixture(m.GEO)
    review = raw(index, 'azure_compliance_review')
    review['decision'] = 'noBlockRequired'
    index['collections'].pop('conditional_access_partition')
    index.pop('conditional_access_partition')
    assert evaluate(m.GEO, item, index)[0] == 'PASS'
    item, index = ca_fixture(m.GEO)
    item['conditions']['locations'] = {'includeLocations': ['location-1'], 'excludeLocations': []}
    set_rows(index, 'named_location', [graph('location-1', **{'@odata.type': '#microsoft.graph.countryNamedLocation'},
        countriesAndRegions=['XX'], countryLookupMethod='clientIpAddress', includeUnknownCountriesAndRegions=False)])
    assert evaluate(m.GEO, item, index)[0] == 'PASS'
    raw(index, 'named_location')['countriesAndRegions'] = ['YY']
    assert evaluate(m.GEO, item, index)[0] == 'FAIL'
    raw(index, 'named_location')['@odata.type'] = '#microsoft.graph.ipNamedLocation'
    assert evaluate(m.GEO, item, index)[0] == 'UNKNOWN'


def test_device_code_documented_exception_is_scope_bound():
    item, index = ca_fixture(m.DEVICE)
    raw(index, 'azure_compliance_review')['exceptionUserIds'] = ['user-1']
    item['conditions']['users']['excludeUsers'] = ['user-1']
    assert evaluate(m.DEVICE, item, index)[0] == 'PASS'
    raw(index, 'azure_compliance_review').pop('exceptionsDocumentId')
    assert evaluate(m.DEVICE, item, index)[0] == 'UNKNOWN'


@pytest.mark.parametrize('cid', [m.IMMUTABLE, m.SCHEDULE])
def test_retention_no_calendar_rounding_unsupported_workload_and_all_branches(cid):
    item, index = vault_fixture(cid)
    duration = raw(index, 'backup_policy')['properties']['retentionPolicy']['dailySchedule']['retentionDuration']
    duration.update(count=1, durationType='Months')
    assert evaluate(cid, item, index)[0] == 'UNKNOWN'
    duration.update(count=5, durationType='Weeks')
    assert evaluate(cid, item, index)[0] == 'PASS'
    retention = raw(index, 'backup_policy')['properties']['retentionPolicy']
    retention['weeklySchedule'] = {'daysOfTheWeek': ['Sunday'], 'retentionTimes': ['2020-01-01T02:00:00Z'],
        'retentionDuration': {'count': 3, 'durationType': 'Weeks'}}
    assert evaluate(cid, item, index)[0] == ('PASS' if cid == m.IMMUTABLE else 'FAIL')
    raw(index, 'backup_policy')['properties']['backupManagementType'] = 'AzureWorkload'
    assert evaluate(cid, item, index)[0] == 'UNKNOWN'


def test_empty_vault_policy_and_active_item_not_applicable():
    for cid, kind in [(m.IMMUTABLE, 'backup_protected_item'), (m.SCHEDULE, 'backup_policy'), (m.POINTS, 'backup_protected_item')]:
        item, index = vault_fixture(cid)
        set_rows(index, kind, [])
        assert evaluate(cid, item, index)[0] == 'NOT_APPLICABLE'
    item, index = vault_fixture(m.RESTORE)
    index['context']['metadata']['compliance_policy']['sw13']['checks'][m.RESTORE.replace('.', '|')]['criticalProtectedItemIds'] = []
    assert evaluate(m.RESTORE, item, index)[0] == 'NOT_APPLICABLE'


def test_cmk_matching_identity_effective_access_and_unsupported_capability():
    item, index = vault_fixture(m.CMK)
    item['identity']['type'] = 'None'
    assert evaluate(m.CMK, item, index)[0] == 'FAIL'
    item, index = vault_fixture(m.CMK)
    raw(index, 'key_authorization_evidence')['effectiveKeyOperations'] = ['get']
    # Complete authoritative access evidence proves the required wrap/unwrap operations are absent.
    assert evaluate(m.CMK, item, index)[0] == 'FAIL'
    item, index = vault_fixture(m.CMK)
    raw(index, 'recovery_vault_capability')['cmkSupported'] = False
    assert evaluate(m.CMK, item, index)[0] == 'NOT_APPLICABLE'
    item, index = vault_fixture(m.CMK)
    item['properties']['encryption']['keyVaultProperties']['keyUri'] = 'https://evil.example.com/keys/k/v'
    assert evaluate(m.CMK, item, index)[0] == 'UNKNOWN'
    item['properties']['encryption']['keyVaultProperties']['keyUri'] = 'https://vault.vault.azure.net/keys/unapproved/version'
    assert evaluate(m.CMK, item, index)[0] == 'UNKNOWN'


def test_recovery_points_detail_empty_soft_deleted_and_exact_day_boundary():
    item, index = vault_fixture(m.POINTS)
    point = raw(index, 'backup_recovery_point')
    point['properties']['recoveryPointProperties']['expiryTime'] = '2026-10-31T00:00:00Z'
    assert evaluate(m.POINTS, item, index)[0] == 'PASS'
    point['properties']['recoveryPointProperties'].pop('expiryTime')
    assert evaluate(m.POINTS, item, index)[0] == 'UNKNOWN'
    item, index = vault_fixture(m.POINTS)
    raw(index, 'backup_recovery_point')['properties']['isSoftDeleted'] = True
    assert evaluate(m.POINTS, item, index)[0] == 'UNKNOWN'
    set_rows(index, 'backup_recovery_point', [])
    assert evaluate(m.POINTS, item, index)[0] == 'UNKNOWN'


def test_restore_exact_job_join_required_failure_and_no_friendly_name_fallback():
    item, index = vault_fixture(m.RESTORE)
    raw(index, 'backup_restore_test')['jobId'] = VAULT + '/backupJobs/other'
    assert evaluate(m.RESTORE, item, index)[0] == 'UNKNOWN'
    item, index = vault_fixture(m.RESTORE)
    raw(index, 'backup_restore_test')['restoredDataVerified'] = False
    raw(index, 'backup_restore_test')['result'] = 'Failed'
    raw(index, 'backup_restore_test')['validationEvidence']['usableDataValidation']['result'] = 'Failed'
    assert evaluate(m.RESTORE, item, index)[0] == 'FAIL'
    item, index = vault_fixture(m.RESTORE)
    raw(index, 'backup_restore_test')['result'] = 'Failed'
    raw(index, 'backup_restore_test')['validationEvidence']['usableDataValidation']['result'] = 'Failed'
    assert evaluate(m.RESTORE, item, index)[0] == 'FAIL'
    item, index = vault_fixture(m.RESTORE)
    raw(index, 'backup_job')['properties']['status'] = 'InProgress'
    assert evaluate(m.RESTORE, item, index)[0] == 'UNKNOWN'
    item, index = vault_fixture(m.RESTORE)
    raw(index, 'backup_restore_window')['windowStart'] = '2026-10-11T00:00:00Z'
    assert evaluate(m.RESTORE, item, index)[0] == 'UNKNOWN'


def test_notification_empty_window_ingestion_and_authorized_timely_delivery():
    item, index = notify_fixture()
    set_rows(index, 'audit_sign_in', [])
    set_rows(index, 'authentication_notification', [])
    assert evaluate(m.NOTIFY, item, index)[0] == 'PASS'
    raw(index, 'authentication_monitoring_window')['ingestionConfirmed'] = False
    assert evaluate(m.NOTIFY, item, index)[0] == 'UNKNOWN'
    item, index = notify_fixture()
    raw(index, 'authentication_notification')['recipientId'] = 'unauthorized'
    assert evaluate(m.NOTIFY, item, index)[0] == 'FAIL'
    item, index = notify_fixture()
    raw(index, 'authentication_notification')['observedAt'] = '2026-10-11T02:01:00Z'
    assert evaluate(m.NOTIFY, item, index)[0] == 'FAIL'


def test_correlation_exact_query_review_table_ingestion_window_and_action_group():
    item, index = correlation_fixture()
    item['properties']['criteria']['allOf'][0]['query'] += ' // forged fragment'
    assert evaluate(m.CORRELATION, item, index)[0] == 'UNKNOWN'
    item, index = correlation_fixture()
    raw(index, 'security_query_review')['approved'] = False
    assert evaluate(m.CORRELATION, item, index)[0] == 'FAIL'
    item, index = correlation_fixture()
    raw(index, 'security_table_ingestion')['ingestionConfirmed'] = False
    assert evaluate(m.CORRELATION, item, index)[0] == 'UNKNOWN'
    item, index = correlation_fixture()
    item['properties']['windowSize'] = 'PT2H'
    assert evaluate(m.CORRELATION, item, index)[0] == 'FAIL'
    item, index = correlation_fixture()
    raw(index, 'action_group')['properties']['enabled'] = False
    assert evaluate(m.CORRELATION, item, index)[0] == 'FAIL'


def test_service_endpoint_shadow_priority_headers_and_multi_prefix_coverage():
    item, index = app_fixture(m.SERVICE_ENDPOINT)
    rules = item['configuration']['properties']['ipSecurityRestrictions']
    rules.insert(0, {'priority': 50, 'action': 'Deny', 'vnetSubnetResourceId': None,
                     'ipAddress': '10.0.0.0/25', 'headers': {}, 'tag': 'Default'})
    assert evaluate(m.SERVICE_ENDPOINT, item, index)[0] == 'FAIL'
    rules[0]['action'] = 'Allow'
    # IP-based allow shadowing is not a named service endpoint path.
    assert evaluate(m.SERVICE_ENDPOINT, item, index)[0] == 'FAIL'
    rules.pop(0)
    rules[0]['headers'] = {'x-azure-fdid': ['front-door-id']}
    assert evaluate(m.SERVICE_ENDPOINT, item, index)[0] == 'UNKNOWN'
    item, index = app_fixture(m.SERVICE_ENDPOINT)
    raw(index, 'subnet')['properties']['addressPrefixes'].append('10.0.1.0/24')
    item['configuration']['properties']['ipSecurityRestrictions'].insert(0,
        {'priority': 50, 'action': 'Deny', 'vnetSubnetResourceId': None, 'ipAddress': '10.0.1.0/24', 'headers': {}, 'tag': 'Default'})
    assert evaluate(m.SERVICE_ENDPOINT, item, index)[0] == 'FAIL'


def test_tls_name_trust_chain_reachability_and_metadata_alone():
    item, index = app_fixture(m.TLS)
    reading = raw(index, 'tls_endpoint_observation')
    reading['leaf']['subjectAlternativeNames'] = ['other.example.com']
    assert evaluate(m.TLS, item, index)[0] == 'FAIL'
    reading['leaf']['subjectAlternativeNames'] = ['app.example.com']
    reading['chainValidation'] = 'Untrusted'
    assert evaluate(m.TLS, item, index)[0] == 'FAIL'
    reading['handshakeStatus'] = 'Unreachable'
    assert evaluate(m.TLS, item, index)[0] == 'UNKNOWN'
    item, index = app_fixture(m.TLS)
    raw(index, 'tls_endpoint_observation')['presentedChainSha256'] = []
    assert evaluate(m.TLS, item, index)[0] == 'UNKNOWN'
    item, index = app_fixture(m.TLS)
    raw(index, 'tls_endpoint_observation')['observedAt'] = START
    assert evaluate(m.TLS, item, index)[0] == 'UNKNOWN'
    item, index = app_fixture(m.TLS)
    set_rows(index, 'app_service_endpoint', [])
    raw(index, 'app_service_endpoint_inventory')['endpointIds'] = []
    assert evaluate(m.TLS, item, index)[0] == 'NOT_APPLICABLE'


def test_function_exceptions_floating_runtime_and_each_expected_field():
    item, index = app_fixture(m.FUNCTION)
    cfg = raw(index, 'function_app_configuration')
    cfg['packageType'] = 'Container'
    cfg['_provenance']['classificationSource'] = 'site.functionAppConfig.deployment'
    assert evaluate(m.FUNCTION, item, index)[0] == 'NOT_APPLICABLE'
    cfg['packageType'] = 'Code'
    cfg['runtimeType'] = 'OSOnly'
    assert evaluate(m.FUNCTION, item, index)[0] == 'NOT_APPLICABLE'
    cfg['runtimeType'] = 'Language'
    cfg['settings']['runtime'] = '~4'
    assert evaluate(m.FUNCTION, item, index)[0] == 'UNKNOWN'
    for field in ('runtime', 'role', 'timeoutSeconds', 'memoryMB'):
        item, index = app_fixture(m.FUNCTION)
        cfg = raw(index, 'function_app_configuration')
        cfg['settings'][field] = 'other' if field in ('runtime', 'role') else 123
        assert evaluate(m.FUNCTION, item, index)[0] == 'FAIL'
        cfg['sources'][field]['status'] = 'denied'
        assert evaluate(m.FUNCTION, item, index)[0] == 'UNKNOWN'


@pytest.mark.parametrize('cid', m.IDS)
def test_evaluation_is_offline_immutable_and_repeatable(cid):
    item, index = fixture(cid)
    original = copy.deepcopy((item, index))
    assert evaluate(cid, item, index) == evaluate(cid, item, index)
    assert (item, index) == original


def test_device_review_must_name_an_enabled_block_policy():
    item, index = ca_fixture(m.DEVICE)
    raw(index, 'azure_compliance_review')['exceptionUserIds'] = ['user-1']
    item['state'] = 'disabled'
    assert evaluate(m.DEVICE, item, index)[0] == 'FAIL'
    item['state'] = 'enabled'
    raw(index, 'azure_compliance_review')['policyIds'] = ['other-policy']
    assert evaluate(m.DEVICE, item, index)[0] == 'FAIL'


@pytest.mark.parametrize('cid,field,mutate', [
    (m.USERS, 'conditional_access_partition', lambda r: r.update(exhaustive=False)),
    (m.ADMIN, 'conditional_access_principal', lambda r: r.update(pimResolved=False)),
    (m.FUNCTION, 'function_app_configuration', lambda r: r.update(expires_at='2026-10-11T00:00:00Z')),
    (m.CMK, 'recovery_vault_capability', lambda r: r.update(cmkSupported='true')),
    (m.RESTORE, 'backup_restore_test', lambda r: r.pop('restoredDataVerified')),
    (m.TLS, 'tls_endpoint_observation', lambda r: r.update(fullPresentedChain=False)),
    (m.CORRELATION, 'security_query_review', lambda r: r.pop('correlatedTables')),
    (m.NOTIFY, 'authentication_monitoring_window', lambda r: r.update(deliveryRegistryComplete=False)),
])
def test_semantically_incomplete_or_malformed_detail_unknown(cid, field, mutate):
    item, index = fixture(cid)
    mutate(raw(index, field))
    assert evaluate(cid, item, index)[0] == 'UNKNOWN'


def test_immutability_uses_longest_applicable_retention_per_scheduled_day():
    item, index = vault_fixture(m.IMMUTABLE)
    retention = raw(index, 'backup_policy')['properties']['retentionPolicy']
    retention['dailySchedule']['retentionDuration']['count'] = 7
    days = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday']
    retention['weeklySchedule'] = {'daysOfTheWeek': days, 'retentionTimes': ['2020-01-01T02:00:00Z'],
                                  'retentionDuration': {'count': 6, 'durationType': 'Weeks'}}
    assert evaluate(m.IMMUTABLE, item, index)[0] == 'PASS'
    retention['weeklySchedule']['daysOfTheWeek'] = ['Sunday']
    assert evaluate(m.IMMUTABLE, item, index)[0] == 'FAIL'


@pytest.mark.parametrize('cid', [m.ADMIN, m.USERS, m.RISK])
def test_block_only_policy_does_not_prove_mfa_policy(cid):
    item, index = ca_fixture(cid)
    item['grantControls']['builtInControls'] = ['block']
    assert evaluate(cid, item, index)[0] == 'UNKNOWN'
