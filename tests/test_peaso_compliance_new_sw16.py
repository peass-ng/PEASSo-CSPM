"""Signed Azure sw16 predicates, with isolated direct module registration."""
from __future__ import annotations

import copy
import importlib

import pytest
from peaso.checks import CHECKS

_before_import = tuple(CHECKS)
api = importlib.import_module('peaso.checks.compliance_new_sw16')
OWN_CHECKS = {check.id: check for check in CHECKS if check.id in api.IDS}
CHECKS[:] = _before_import

SCOPE = '/subscriptions/11111111-1111-1111-1111-111111111111'
TENANT = '/tenants/22222222-2222-2222-2222-222222222222'
BASE = SCOPE + '/resourceGroups/rg/providers/'
DISK = BASE + 'Microsoft.Compute/disks/disk'
STORE = BASE + 'Microsoft.Storage/storageAccounts/store'
VAULT = BASE + 'Microsoft.DataProtection/backupVaults/backup'
INSTANCE = VAULT + '/backupInstances/instance'
BACKUP_POLICY = VAULT + '/backupPolicies/policy'
SEARCH = BASE + 'Microsoft.Search/searchServices/search'
KV = BASE + 'Microsoft.KeyVault/vaults/vault'
KEY = 'https://vault.vault.azure.net/keys/key'
VERSION = KEY + '/version1'
DEFINITION = '/providers/Microsoft.Authorization/policyDefinitions/cmk'
ASSIGNMENT = SCOPE + '/providers/Microsoft.Authorization/policyAssignments/assignment'
ROLE = SCOPE + '/providers/Microsoft.Authorization/roleDefinitions/role'
WORKSPACE = BASE + 'Microsoft.OperationalInsights/workspaces/logs'
DPS = BASE + 'Microsoft.Devices/provisioningServices/dps'
NOW = '2026-10-12T12:00:00Z'
PROOF = {'representation': 'full', 'read_only': True, 'source_operation': 'test-read'}


def full(**row):
    return {'_provenance': copy.deepcopy(PROOF), **row}


def cover(row, field, values):
    row[field] = values
    row.setdefault('_coverage', {})[field] = {'status': 'collected' if values else 'empty'}
    return row


def scoped(kinds, *, identifier=None, policy=None, scope=SCOPE):
    index = {'context': {'provider': 'azure', 'scope': scope, 'created_at': NOW,
                        'metadata': {'compliance_policy': {'sw16': {}}}}, 'collections': {}}
    for kind, rows in kinds.items():
        index['collections'][kind] = [{'type': kind, 'scope': scope,
                                      'status': 'collected' if rows else 'empty', 'items': rows}]
        index[kind] = [{'provider': 'azure', 'type': kind, 'scope': scope, 'data': row} for row in rows]
    if policy is not None:
        index['context']['metadata']['compliance_policy']['sw16'][identifier] = {
            'status': 'collected', 'scope': scope, **policy}
    return index


def row(index, kind, position=0):
    return index[kind][position]['data']


def evaluate(identifier, index):
    return OWN_CHECKS[identifier].evaluate({}, index)


def backup_instance(source=DISK):
    return full(id=INSTANCE, parent_id=VAULT, properties={
        'dataSourceInfo': {'resourceID': source}, 'policyInfo': {'policyId': BACKUP_POLICY},
        'currentProtectionState': 'ProtectionConfigured'})


def backup_index(identifier):
    source = DISK if identifier == api.IDS[0] else STORE
    instance = backup_instance(source)
    kinds = {'backup_vault': [{'id': VAULT}], 'backup_instance': [instance]}
    if identifier == api.IDS[0]:
        kinds['disk'] = [{'id': DISK}]
    else:
        account = cover({'id': STORE}, 'blobContainers', [
            {'id': STORE + '/blobServices/default/containers/container', 'name': 'container'}])
        kinds['storage_account'] = [account]
        instance['properties']['policyInfo']['policyParameters'] = {'backupDatasourceParametersList': [
            {'objectType': 'BlobBackupDatasourceParameters', 'containersList': ['container']}]}
        cover(instance, 'containerSelectionEvidence', [{'backupInstanceId': INSTANCE, 'mode': 'Explicit'}])
    index = scoped(kinds)
    index['collections']['backup_instance'][0]['covered_parent_ids'] = [VAULT]
    return index


def search_index():
    service = {'id': SEARCH, 'properties': {'disableLocalAuth': True}}
    cover(service, 'indexes', [full(serviceId=SEARCH, name='index', permissionFilterOption='enabled',
                                  fields=[{'name': 'acl', 'permissionFilter': 'userIds', 'filterable': True}])])
    cover(service, 'effectiveGrants', [full(serviceId=SEARCH, scope=SEARCH + '/indexes/index',
        principalId='principal', roleDefinitionId=ROLE, assignmentId=SEARCH + '/indexes/index/providers/Microsoft.Authorization/roleAssignments/assignment', condition=None,
        dataActions=['Microsoft.Search/searchServices/indexes/documents/read'], notDataActions=[])])
    cover(service, 'queryPaths', [full(serviceId=SEARCH, indexName='index', id='query-path',
        authentication='Entra', principalId='principal', authorized=True, permissionFiltering=True)])
    return scoped({'search_service': [service]}, identifier=api.IDS[2], policy={'services': [{
        'resourceId': SEARCH, 'requiredIndexes': ['index'], 'granularity': 'Document',
        'approvedPrincipalIds': ['principal'], 'requiredPermissionFilterFields': {'acl': 'userIds'}}]})


def rotation_index():
    evidence = full(id='rotation-evidence', scope_id=SCOPE, keyId=KEY, vaultId=KV,
                    armKeyId=KV + '/keys/key', vaultUri='https://vault.vault.azure.net',
                    rotationPolicy=full(keyId=KEY, lifetimeActions=[{
                        'action': {'type': 'Rotate'}, 'trigger': {'timeAfterCreate': 'P90D'}}]))
    cover(evidence, 'enforcementAssignments', [full(keyId=KEY, assignmentId=ASSIGNMENT,
        definitionId=DEFINITION, scope=SCOPE, effect='Deny', enforcementMode='Default', exempt=False,
        conditionsMatch=True, enforcesAutomaticRotation=True, parameters={'rotationInterval': 'P90D'})])
    cover(evidence, 'rotationIdentities', [full(keyId=KEY, principalId='principal', effectivePermissions=[
        'keys/rotate', 'keys/getrotationpolicy', 'keys/setrotationpolicy'])])
    return scoped({'key_rotation_evidence': [evidence]}, identifier=api.IDS[3], policy={
        'requiredKeyIds': [KEY], 'maxRotationInterval': 'P90D', 'rotationPolicyDefinitionId': DEFINITION})


def deviation_index():
    evidence = full(id='event-export', scope_id=SCOPE, windowStart='2026-10-12T00:00:00Z',
                    windowEnd=NOW, capturedAt=NOW, specificationSourceId='approved-spec-source',
                    detectedSpecificationIds=['specification'])
    evidence['_provenance']['observed_at'] = NOW
    cover(evidence, 'events', [full(id='deviation', scope_id=SCOPE, exportId='event-export',
        specificationSourceId='approved-spec-source', specificationId='specification',
        detectedAt='2026-10-12T01:00:00Z', automaticNotification=True, delivered=True,
        recipientExpertIds=['expert'], assessed=True, disposition='resolved',
        deliveredAt='2026-10-12T01:00:15Z', assessedAt='2026-10-12T01:00:30Z',
        _provenance=copy.deepcopy(evidence['_provenance']))])
    return scoped({'operational_deviation_evidence': [evidence]}, identifier=api.IDS[4], policy={
        'requiredSpecificationIds': ['specification'], 'specificationSourceId': 'approved-spec-source',
        'authorizedExpertIds': ['expert'],
        'immediateResponseSeconds': 60, 'windowStart': '2026-10-12T00:00:00Z', 'windowEnd': NOW})


def lifetime_index():
    key = full(id=KV + '/keys/key', data_plane_id=KEY, parent_id=KV, vaultUri='https://vault.vault.azure.net')
    cover(key, 'versions', [full(kid=VERSION, attributes={'enabled': True, 'nbf': 1, 'exp': 2000000000},
        provisioningRecord=full(keyVersionId=VERSION, secureProvisioning=True, identityVerified=True,
            authorized=True, identityVerifiedAt='2020-01-01T00:00:00Z', authorizedAt='2020-01-01T00:00:00Z',
            provisionedAt='2020-01-01T00:00:10Z', activatedAt='2020-01-01T00:00:20Z'))])
    return scoped({'key_vault_key': [key]}, identifier=api.IDS[5], policy={'requiredKeyIds': [KEY]})


def log_resource(parent, *, intune=False):
    cat_parent = '/providers/Microsoft.Intune' if intune else parent + '/providers/Microsoft.Insights'
    category = full(id=cat_parent + '/diagnosticSettingsCategories/AuditLogs', parent_id=parent,
                    name='AuditLogs', properties={'categoryType': 'Logs', 'categoryGroups': ['allLogs']})
    setting = full(id=cat_parent + '/diagnosticSettings/setting', parent_id=parent,
                   properties={'workspaceId': WORKSPACE, 'logs': [{'category': 'AuditLogs', 'enabled': True}]})
    cover(setting, 'retentionEvidence', [full(settingId=setting['id'], sinkId=WORKSPACE,
        category='AuditLogs', sourceId=WORKSPACE + '/tables/AuditLogs', retentionDays=90)])
    return cover(cover({'id': parent}, 'categories', [category]), 'diagnosticSettings', [setting])


def logging_index():
    resource = log_resource(DISK)
    return scoped({'azure_diagnostic_eligible_resource': [resource]}, identifier=api.IDS[6], policy={
        'resources': [{'resourceId': DISK, 'requiredCategories': ['AuditLogs'], 'requiredCategoryGroups': [],
                       'approvedSinkIds': [WORKSPACE], 'minRetentionDays': 90}]})


def intune_index():
    resource = log_resource('/providers/Microsoft.Intune', intune=True)
    resource['scope_id'] = TENANT
    return scoped({'intune_diagnostic_setting': [resource]}, scope=TENANT, identifier=api.IDS[7], policy={
        'requiredIntuneCategories': ['AuditLogs'], 'approvedWorkspaceIds': [WORKSPACE]})


def dps_index():
    assignment = full(id=ASSIGNMENT, properties={'policyDefinitionId': DEFINITION, 'scope': SCOPE,
        'parameters': {'effect': {'value': 'Audit'}}, 'enforcementMode': 'Default'}, active=True,
        definition=full(id=DEFINITION, properties={'policyRule': {'then': {'effect': "[parameters('effect')]"}}}),
        effectiveEffect='Audit', effectiveParameters={'effect': {'value': 'Audit'}}, parametersVerified=True)
    cover(assignment, 'exemptions', [])
    state = full(id='policy-state', scope_id=SCOPE, resourceId=DPS, policyDefinitionId=DEFINITION,
                 policyAssignmentId=ASSIGNMENT, complianceState='Compliant', timestamp='2026-10-12T11:59:00Z')
    state['_provenance']['source_operation'] = 'policyStates/latest/queryResults'
    return scoped({'iot_dps': [{'id': DPS}], 'azure_policy_state': [state],
                   'azure_policy_assignment_evidence': [assignment]}, identifier=api.IDS[8], policy={
                       'assignedDefinitionId': DEFINITION, 'maxPolicyStateAge': 3600})


BUILDERS = {api.IDS[0]: lambda: backup_index(api.IDS[0]), api.IDS[1]: lambda: backup_index(api.IDS[1]),
    api.IDS[2]: search_index, api.IDS[3]: rotation_index, api.IDS[4]: deviation_index,
    api.IDS[5]: lifetime_index, api.IDS[6]: logging_index, api.IDS[7]: intune_index, api.IDS[8]: dps_index}


@pytest.mark.parametrize('identifier', api.IDS)
def test_pass_complete_signed_evidence(identifier):
    assert evaluate(identifier, BUILDERS[identifier]())[0] == 'PASS'


@pytest.mark.parametrize('identifier', api.IDS)
def test_unknown_incomplete_missing_malformed_foreign_inventory(identifier):
    for kind in OWN_CHECKS[identifier].dependencies:
        index = BUILDERS[identifier]()
        index['collections'][kind][0]['status'] = 'partial'
        assert evaluate(identifier, index)[0] == 'UNKNOWN'
        index = BUILDERS[identifier]()
        index['collections'].pop(kind)
        assert evaluate(identifier, index)[0] == 'UNKNOWN'
        index = BUILDERS[identifier]()
        index['collections'][kind][0]['scope'] = '/subscriptions/foreign'
        assert evaluate(identifier, index)[0] == 'UNKNOWN'
        index = BUILDERS[identifier]()
        row(index, kind)['id'] = {'malformed': True}
        assert evaluate(identifier, index)[0] == 'UNKNOWN'
    index = BUILDERS[identifier]()
    index['context']['provider'] = 'aws'
    assert evaluate(identifier, index)[0] == 'UNKNOWN'


@pytest.mark.parametrize('identifier', api.IDS)
def test_unknown_missing_required_detail(identifier):
    index = BUILDERS[identifier]()
    kind = OWN_CHECKS[identifier].dependencies[0]
    detail = row(index, kind)
    if identifier in api.IDS[:2]:
        row(index, 'backup_instance')['properties'].pop('currentProtectionState')
    elif identifier == api.IDS[2]:
        detail.pop('queryPaths')
    elif identifier == api.IDS[3]:
        detail.pop('rotationPolicy')
    elif identifier == api.IDS[4]:
        detail['events'][0].pop('delivered')
    elif identifier == api.IDS[5]:
        detail['versions'][0].pop('provisioningRecord')
    elif identifier in api.IDS[6:8]:
        detail.pop('categories')
    else:
        row(index, 'azure_policy_state').pop('timestamp')
    assert evaluate(identifier, index)[0] == 'UNKNOWN'


def test_disk_backup_fail_empty_and_ambiguous_states():
    for state in ('NotProtected', 'ProtectionStopped', 'ProtectionError'):
        index = backup_index(api.IDS[0])
        row(index, 'backup_instance')['properties']['currentProtectionState'] = state
        assert evaluate(api.IDS[0], index)[0] == 'FAIL'
    index = backup_index(api.IDS[0])
    index['backup_instance'].clear()
    index['collections']['backup_instance'][0].update(items=[], status='empty')
    assert evaluate(api.IDS[0], index)[0] == 'FAIL'
    index = backup_index(api.IDS[0])
    row(index, 'backup_instance')['properties']['currentProtectionState'] = 'ProtectionConfiguring'
    assert evaluate(api.IDS[0], index)[0] == 'UNKNOWN'
    index = backup_index(api.IDS[0])
    second = copy.deepcopy(row(index, 'backup_instance'))
    second['id'] = VAULT + '/backupInstances/second'
    index['collections']['backup_instance'][0]['items'].append(second)
    index['backup_instance'].append({'type': 'backup_instance', 'scope': SCOPE, 'data': second})
    assert evaluate(api.IDS[0], index)[0] == 'UNKNOWN'
    index = backup_index(api.IDS[0])
    index['collections']['backup_instance'][0]['covered_parent_ids'] = []
    assert evaluate(api.IDS[0], index)[0] == 'UNKNOWN'


def test_blob_explicit_selection_fail_and_missing_selection_unknown():
    index = backup_index(api.IDS[1])
    instance = row(index, 'backup_instance')
    instance['properties']['policyInfo']['policyParameters']['backupDatasourceParametersList'][0]['containersList'] = []
    assert evaluate(api.IDS[1], index)[0] == 'FAIL'
    instance.pop('containerSelectionEvidence')
    assert evaluate(api.IDS[1], index)[0] == 'UNKNOWN'
    index = backup_index(api.IDS[1])
    row(index, 'storage_account')['blobContainers'][0]['id'] = STORE + '/blobServices/default/containers/foreign'
    assert evaluate(api.IDS[1], index)[0] == 'UNKNOWN'


def test_blob_automatic_selection_exact_decisions():
    index = backup_index(api.IDS[1])
    instance = row(index, 'backup_instance')
    selection = full(backupInstanceId=INSTANCE, mode='Automatic', documentedApi='provider-selection-export', policyId=BACKUP_POLICY)
    cover(selection, 'containerDecisions', [{'containerName': 'container', 'included': True}])
    instance['containerSelectionEvidence'][:] = [selection]
    assert evaluate(api.IDS[1], index)[0] == 'PASS'
    selection['containerDecisions'][0]['included'] = False
    assert evaluate(api.IDS[1], index)[0] == 'FAIL'
    cover(selection, 'containerDecisions', [])
    assert evaluate(api.IDS[1], index)[0] == 'UNKNOWN'


def test_search_index_document_and_bypass_boundaries():
    for change in ('broad_role', 'wrong_principal', 'filter_disabled', 'query_filter_disabled', 'api_key'):
        index = search_index()
        service = row(index, 'search_service')
        if change == 'broad_role':
            service['effectiveGrants'][0]['scope'] = SEARCH
            service['effectiveGrants'][0]['assignmentId'] = SEARCH + '/providers/Microsoft.Authorization/roleAssignments/assignment'
        if change == 'wrong_principal': service['effectiveGrants'][0]['principalId'] = 'other'
        if change == 'filter_disabled': service['indexes'][0]['permissionFilterOption'] = 'disabled'
        if change == 'query_filter_disabled': service['queryPaths'][0]['permissionFiltering'] = False
        if change == 'api_key':
            service['properties']['disableLocalAuth'] = False
            service['queryPaths'][0]['authentication'] = 'ApiKey'
        assert evaluate(api.IDS[2], index)[0] == 'FAIL', change
    index = search_index()
    row(index, 'search_service')['effectiveGrants'][0]['condition'] = 'unknown condition'
    assert evaluate(api.IDS[2], index)[0] == 'UNKNOWN'
    index = search_index()
    row(index, 'search_service')['properties']['disableLocalAuth'] = False
    assert evaluate(api.IDS[2], index)[0] == 'UNKNOWN'
    index = search_index()
    policy = index['context']['metadata']['compliance_policy']['sw16'][api.IDS[2]]['services'][0]
    policy['granularity'] = 'Index'
    row(index, 'search_service')['indexes'][0].pop('permissionFilterOption')
    row(index, 'search_service')['queryPaths'][0].pop('permissionFiltering')
    assert evaluate(api.IDS[2], index)[0] == 'PASS'


def test_rotation_all_three_obligations_and_missing_enforcement_details():
    for gap in ('action', 'interval', 'assignment', 'identity'):
        index = rotation_index()
        evidence = row(index, 'key_rotation_evidence')
        if gap == 'action': evidence['rotationPolicy']['lifetimeActions'] = []
        if gap == 'interval': evidence['rotationPolicy']['lifetimeActions'][0]['trigger']['timeAfterCreate'] = 'P91D'
        if gap == 'assignment': cover(evidence, 'enforcementAssignments', [])
        if gap == 'identity': evidence['rotationIdentities'][0]['effectivePermissions'] = ['keys/rotate']
        assert evaluate(api.IDS[3], index)[0] == 'FAIL', gap
    index = rotation_index()
    evidence = row(index, 'key_rotation_evidence')
    evidence['enforcementAssignments'][0]['effect'] = 'Disabled'
    evidence['enforcementAssignments'][0].pop('conditionsMatch')
    assert evaluate(api.IDS[3], index)[0] == 'UNKNOWN'
    index = rotation_index()
    row(index, 'key_rotation_evidence')['rotationPolicy']['lifetimeActions'][0]['trigger']['timeAfterCreate'] = 'P3M'
    assert evaluate(api.IDS[3], index)[0] == 'UNKNOWN'


def test_deviation_response_fail_timeliness_delivery_and_coverage_unknown():
    for field, value in [('automaticNotification', False), ('delivered', False), ('assessed', False),
                         ('recipientExpertIds', []), ('assessedAt', '2026-10-12T01:02:00Z')]:
        index = deviation_index()
        row(index, 'operational_deviation_evidence')['events'][0][field] = value
        assert evaluate(api.IDS[4], index)[0] == 'FAIL', field
    index = deviation_index()
    row(index, 'operational_deviation_evidence')['detectedSpecificationIds'] = ['other']
    assert evaluate(api.IDS[4], index)[0] == 'UNKNOWN'
    index = deviation_index()
    cover(row(index, 'operational_deviation_evidence'), 'events', [])
    assert evaluate(api.IDS[4], index)[0] == 'UNKNOWN'


def test_lifetime_dates_and_provisioning_both_required():
    for gap in ('nbf', 'exp', 'expired', 'future', 'identity', 'authorization', 'chronology'):
        index = lifetime_index()
        version = row(index, 'key_vault_key')['versions'][0]
        if gap in ('nbf', 'exp'): version['attributes'].pop(gap)
        if gap == 'expired': version['attributes']['exp'] = 2
        if gap == 'future': version['attributes']['nbf'] = 2000000000
        if gap == 'identity': version['provisioningRecord']['identityVerified'] = False
        if gap == 'authorization': version['provisioningRecord']['authorized'] = False
        if gap == 'chronology': version['provisioningRecord']['authorizedAt'] = '2020-01-01T00:01:00Z'
        assert evaluate(api.IDS[5], index)[0] == 'FAIL', gap
    index = lifetime_index()
    row(index, 'key_vault_key')['versions'][0]['attributes'] = []
    assert evaluate(api.IDS[5], index)[0] == 'UNKNOWN'
    index = lifetime_index()
    version = row(index, 'key_vault_key')['versions'][0]
    version['attributes']['_coverage'] = {'nbf': {'status': 'denied'}}
    assert evaluate(api.IDS[5], index)[0] == 'UNKNOWN'


@pytest.mark.parametrize('identifier', api.IDS[6:8])
def test_logging_categories_groups_and_authorized_destinations(identifier):
    builder = BUILDERS[identifier]
    kind = OWN_CHECKS[identifier].dependencies[0]
    for gap in ('disabled', 'sink', 'setting_absent'):
        index = builder()
        resource = row(index, kind)
        if gap == 'disabled': resource['diagnosticSettings'][0]['properties']['logs'][0]['enabled'] = False
        if gap == 'sink': resource['diagnosticSettings'][0]['properties']['workspaceId'] = WORKSPACE + 'other'
        if gap == 'setting_absent': cover(resource, 'diagnosticSettings', [])
        assert evaluate(identifier, index)[0] == 'FAIL', gap
    index = builder()
    resource = row(index, kind)
    resource['diagnosticSettings'][0]['properties']['logs'] = [{'categoryGroup': 'allLogs', 'enabled': True}]
    assert evaluate(identifier, index)[0] == 'PASS'
    resource['categories'][0]['properties'].pop('categoryGroups')
    assert evaluate(identifier, index)[0] == 'UNKNOWN'
    index = builder()
    row(index, kind)['diagnosticSettings'][0]['parent_id'] = 'foreign'
    assert evaluate(identifier, index)[0] == 'UNKNOWN'


def test_resource_logging_retention_pass_fail_unknown():
    index = logging_index()
    retention = row(index, 'azure_diagnostic_eligible_resource')['diagnosticSettings'][0]['retentionEvidence'][0]
    retention['retentionDays'] = 89
    assert evaluate(api.IDS[6], index)[0] == 'FAIL'
    retention['retentionDays'] = 0
    assert evaluate(api.IDS[6], index)[0] == 'PASS'
    retention.pop('retentionDays')
    assert evaluate(api.IDS[6], index)[0] == 'UNKNOWN'


def test_dps_fresh_exact_policy_state_only():
    index = dps_index()
    row(index, 'azure_policy_state')['complianceState'] = 'NonCompliant'
    assert evaluate(api.IDS[8], index)[0] == 'FAIL'
    for field, value in [('timestamp', '2026-10-01T00:00:00Z'), ('resourceId', DPS + 'other'),
                         ('complianceState', 'Exempt'), ('policyDefinitionId', DEFINITION + 'other')]:
        index = dps_index()
        row(index, 'azure_policy_state')[field] = value
        assert evaluate(api.IDS[8], index)[0] == 'UNKNOWN', field
    for field, value in [('active', False), ('effectiveEffect', 'Disabled'), ('parametersVerified', False)]:
        index = dps_index()
        row(index, 'azure_policy_assignment_evidence')[field] = value
        assert evaluate(api.IDS[8], index)[0] == 'UNKNOWN', field
    index = dps_index()
    cover(row(index, 'azure_policy_assignment_evidence'), 'exemptions', [full(
        resourceId=DPS, policyAssignmentId=ASSIGNMENT, active=True)])
    assert evaluate(api.IDS[8], index)[0] == 'UNKNOWN'
    index = dps_index()
    second = copy.deepcopy(row(index, 'azure_policy_state'))
    second['id'] = 'second-state'
    index['azure_policy_state'].append({'type': 'azure_policy_state', 'scope': SCOPE, 'data': second})
    index['collections']['azure_policy_state'][0]['items'].append(second)
    assert evaluate(api.IDS[8], index)[0] == 'UNKNOWN'


@pytest.mark.parametrize('identifier,kind', [(api.IDS[0], 'disk'), (api.IDS[1], 'storage_account'),
    (api.IDS[6], 'azure_diagnostic_eligible_resource'), (api.IDS[8], 'iot_dps')])
def test_not_applicable_complete_empty_inventory(identifier, kind):
    index = BUILDERS[identifier]()
    index[kind] = []
    index['collections'][kind][0].update(status='empty', items=[])
    assert evaluate(identifier, index)[0] == 'NOT_APPLICABLE'
    index['collections'][kind][0]['status'] = 'partial'
    assert evaluate(identifier, index)[0] == 'UNKNOWN'


@pytest.mark.parametrize('identifier', api.IDS)
def test_unknown_malformed_evidence_even_alongside_positive_gap(identifier):
    index = BUILDERS[identifier]()
    expected = 'UNKNOWN'
    if identifier in api.IDS[:2]:
        instance = row(index, 'backup_instance')
        instance['properties']['currentProtectionState'] = 'ProtectionError'
        instance['properties']['policyInfo'] = []
    elif identifier == api.IDS[2]:
        service = row(index, 'search_service')
        service['effectiveGrants'][0]['scope'] = SEARCH
        service['effectiveGrants'][0]['assignmentId'] = SEARCH + '/providers/Microsoft.Authorization/roleAssignments/assignment'
        service['queryPaths'][0]['authorized'] = 'true'
    elif identifier == api.IDS[3]:
        evidence = row(index, 'key_rotation_evidence')
        evidence['rotationPolicy']['lifetimeActions'] = []
        evidence['rotationIdentities'][0]['effectivePermissions'] = 'keys/rotate'
        # Missing Rotate is independently conclusive from the exact complete
        # native policy; unreadable rights cannot make this key compliant.
        expected = 'FAIL'
    elif identifier == api.IDS[4]:
        event = row(index, 'operational_deviation_evidence')['events'][0]
        event['automaticNotification'] = False
        event['assessed'] = 'yes'
    elif identifier == api.IDS[5]:
        version = row(index, 'key_vault_key')['versions'][0]
        version['attributes']['exp'] = 2
        version['provisioningRecord']['identityVerified'] = 'yes'
    elif identifier in api.IDS[6:8]:
        resource = row(index, OWN_CHECKS[identifier].dependencies[0])
        resource['diagnosticSettings'][0]['properties']['workspaceId'] = {'bad': True}
        resource['diagnosticSettings'][0]['properties']['logs'][0]['enabled'] = False
    else:
        state = row(index, 'azure_policy_state')
        state['complianceState'] = 'NonCompliant'
        state['timestamp'] = []
    assert evaluate(identifier, index)[0] == expected


@pytest.mark.parametrize('identifier', api.IDS[2:])
def test_unknown_missing_malformed_and_foreign_owner_policy(identifier):
    for change in ('missing', 'malformed', 'foreign'):
        index = BUILDERS[identifier]()
        policies = index['context']['metadata']['compliance_policy']['sw16']
        if change == 'missing': policies.pop(identifier)
        if change == 'malformed': policies[identifier] = []
        if change == 'foreign': policies[identifier]['scope'] = '/subscriptions/foreign'
        assert evaluate(identifier, index)[0] == 'UNKNOWN', change


def test_foreign_key_authority_experts_effect_and_category_scope_unknown():
    index = lifetime_index()
    row(index, 'key_vault_key')['vaultUri'] = 'https://foreign.vault.azure.net'
    assert evaluate(api.IDS[5], index)[0] == 'UNKNOWN'
    index = deviation_index()
    row(index, 'operational_deviation_evidence')['events'][0]['recipientExpertIds'].append('unauthorized')
    assert evaluate(api.IDS[4], index)[0] == 'FAIL'
    index = dps_index()
    row(index, 'azure_policy_assignment_evidence')['effectiveEffect'] = 'Deny'
    assert evaluate(api.IDS[8], index)[0] == 'UNKNOWN'
    index = intune_index()
    row(index, 'intune_diagnostic_setting')['categories'][0]['parent_id'] = '/providers/foreign'
    assert evaluate(api.IDS[7], index)[0] == 'UNKNOWN'


def test_no_supported_logs_and_empty_search_are_not_applicable():
    index = logging_index()
    resource = row(index, 'azure_diagnostic_eligible_resource')
    resource['categories'][0]['properties']['categoryType'] = 'Metrics'
    resource.pop('diagnosticSettings')
    assert evaluate(api.IDS[6], index)[0] == 'NOT_APPLICABLE'
    index = scoped({'search_service': []}, identifier=api.IDS[2], policy={'services': []})
    assert evaluate(api.IDS[2], index)[0] == 'NOT_APPLICABLE'


def test_search_elevated_permissions_and_exact_query_principal_grants():
    index = search_index()
    service = row(index, 'search_service')
    service['effectiveGrants'][0]['dataActions'].append(
        'Microsoft.Search/searchServices/indexes/contentSecurity/elevatedOperations/read')
    assert evaluate(api.IDS[2], index)[0] == 'FAIL'
    index = search_index()
    service = row(index, 'search_service')
    service['effectiveGrants'][0]['dataActions'] = ['*']
    assert evaluate(api.IDS[2], index)[0] == 'FAIL'
    service['effectiveGrants'][0]['notDataActions'] = [
        'Microsoft.Search/searchServices/indexes/contentSecurity/elevatedOperations/read']
    assert evaluate(api.IDS[2], index)[0] == 'PASS'
    index = search_index()
    service = row(index, 'search_service')
    service['queryPaths'][0]['principalId'] = 'other-approved'
    index['context']['metadata']['compliance_policy']['sw16'][api.IDS[2]]['services'][0][
        'approvedPrincipalIds'].append('other-approved')
    assert evaluate(api.IDS[2], index)[0] == 'FAIL'
    index = search_index()
    row(index, 'search_service')['effectiveGrants'][0]['scope'] = ''
    assert evaluate(api.IDS[2], index)[0] == 'UNKNOWN'


def test_deviation_foreign_event_scope_not_accepted():
    index = deviation_index()
    row(index, 'operational_deviation_evidence')['events'][0]['scope_id'] =        '/subscriptions/33333333-3333-3333-3333-333333333333'
    assert evaluate(api.IDS[4], index)[0] == 'UNKNOWN'


def test_deviation_foreign_event_source_not_accepted():
    index = deviation_index()
    row(index, 'operational_deviation_evidence')['events'][0]['_provenance']['source_operation'] = 'other-export'
    assert evaluate(api.IDS[4], index)[0] == 'UNKNOWN'


def test_deviation_empty_window_without_independent_coverage_unknown():
    index = deviation_index()
    cover(row(index, 'operational_deviation_evidence'), 'events', [])
    assert evaluate(api.IDS[4], index)[0] == 'UNKNOWN'


@pytest.mark.parametrize('variant', [
    'wrong_export_id', 'wrong_event_spec_source', 'wrong_policy_spec_source',
    'wrong_event_observation', 'wrong_capture_observation', 'capture_before_window_end',
    'delivery_after_capture', 'assessment_after_capture', 'event_at_window_end',
])
def test_deviation_export_event_and_capture_binding_boundaries(variant):
    index = deviation_index()
    export = row(index, 'operational_deviation_evidence')
    event = export['events'][0]
    policy = index['context']['metadata']['compliance_policy']['sw16'][api.IDS[4]]
    if variant == 'wrong_export_id':
        event['exportId'] = 'other-export'
    elif variant == 'wrong_event_spec_source':
        event['specificationSourceId'] = 'other-source'
    elif variant == 'wrong_policy_spec_source':
        policy['specificationSourceId'] = 'other-source'
    elif variant == 'wrong_event_observation':
        event['_provenance']['observed_at'] = '2026-10-12T11:59:00Z'
    elif variant == 'wrong_capture_observation':
        export['_provenance']['observed_at'] = '2026-10-12T11:59:00Z'
    elif variant == 'capture_before_window_end':
        export['capturedAt'] = '2026-10-12T01:00:40Z'
        export['_provenance']['observed_at'] = export['capturedAt']
        event['_provenance']['observed_at'] = export['capturedAt']
    elif variant in ('delivery_after_capture', 'assessment_after_capture'):
        policy['windowEnd'] = export['windowEnd'] = '2026-10-12T01:00:10Z'
        export['capturedAt'] = ('2026-10-12T01:00:10Z' if variant == 'delivery_after_capture'
                                else '2026-10-12T01:00:20Z')
        export['_provenance']['observed_at'] = export['capturedAt']
        event['_provenance']['observed_at'] = export['capturedAt']
    elif variant == 'event_at_window_end':
        event['detectedAt'] = NOW
    assert evaluate(api.IDS[4], index)[0] == 'UNKNOWN'
