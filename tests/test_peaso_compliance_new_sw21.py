"""Isolated sw21 signed predicate and evidence-boundary tests."""
from __future__ import annotations

import copy

import pytest
from peaso.checks import CHECKS

# Keep safe registered evaluator objects, then immediately restore the registry.
# This draft is run alone with --noconftest and never leaks registrations.
_before = list(CHECKS)
try:
    from peaso.checks import compliance_new_sw21 as sw
    DEFINITIONS = {c.id: c for c in CHECKS if c.id in sw.IDS}
finally:
    CHECKS[:] = _before

SUB = '/subscriptions/11111111-1111-1111-1111-111111111111'
TENANT = '/tenants/22222222-2222-2222-2222-222222222222'
ACTOR = '33333333-3333-3333-3333-333333333333'
CUSTOMER = '44444444-4444-4444-4444-444444444444'
PREFIX = SUB + '/resourceGroups/rg/providers/'
WORKSPACE = PREFIX + 'Microsoft.OperationalInsights/workspaces/logs'
VAULT = PREFIX + 'Microsoft.KeyVault/vaults/keys'
KEY = 'https://keys.vault.azure.net/keys/wrapping/v1'
NOW = '2026-10-12T00:00:00+00:00'
START = '2026-10-11T00:00:00+00:00'
CHANGE_TIME = '2026-10-11T12:00:00+00:00'
FULL = {'source_operation': 'get', 'representation': 'full', 'read_only': True}
TENANT_PROOF = {'tenant_id': TENANT.rsplit('/', 1)[1], 'tenant_verified': True, 'read_only': True}
PURVIEW, ENTRA, GRAPH, DOUBLE, CMK, LB, DEFAULT, PASSWORD, AUDIT, FRONT, SQL, ACI, FIREWALL, FILES, RESOURCE = sw.IDS


def coverage(row, field, values):
    row[field] = values
    row.setdefault('_coverage', {})[field] = {'status': 'collected' if values else 'empty'}
    return row


def facts(kinds, policy=None, evidence=None, tenant=False):
    scope = TENANT if tenant else SUB
    context = {'provider': 'azure', 'scope': scope, 'created_at': NOW,
               'metadata': {'compliance_policy': {'sw21': {'status': 'collected', 'scope': scope, **(policy or {})}},
                            'sw21Evidence': evidence or {}}}
    index = {'context': context, 'collections': {}}
    for kind, rows in kinds.items():
        index['collections'][kind] = [{'type': kind, 'scope': scope,
                                      'status': 'collected' if rows else 'empty', 'items': rows}]
        index[kind] = [{'provider': 'azure', 'type': kind, 'scope': scope, 'data': row} for row in rows]
    return index


def supported():
    return [{'name': 'AuditLogs', 'properties': {'categoryType': 'Logs', 'categoryGroups': ['allLogs']}},
            {'name': 'SignInLogs', 'properties': {'categoryType': 'Logs', 'categoryGroups': ['allLogs']}}]


def setting(parent=None, categories=None):
    categories = ['AuditLogs', 'SignInLogs', 'MicrosoftGraphActivityLogs'] if categories is None else categories
    rid = ('/providers/Microsoft.aadiam/diagnosticSettings/export' if parent is None else
           parent + '/providers/Microsoft.Insights/diagnosticSettings/export')
    row = {'id': rid, 'properties': {'logs': [{'category': c, 'enabled': True} for c in categories],
                                    'workspaceId': WORKSPACE}}
    if parent:
        row['parent_id'] = parent
    else:
        row['_provenance'] = TENANT_PROOF.copy()
    return coverage(row, 'destinationEvidence', [{'id': WORKSPACE, 'exists': True, 'reachable': True,
                                                  'effectiveRetentionDaysByCategory': {'AuditLogs': 365, 'SignInLogs': 365}}])


def diagnostic_policy():
    return {'entraDiagnostics': {'activityCategories': ['AuditLogs', 'SignInLogs'],
            'requiredActivityCategories': ['AuditLogs', 'SignInLogs'], 'approvedSinkIds': [WORKSPACE],
            'minimumRetentionDays': 90, 'requiredEventClasses': ['identity-change', 'privileged-action'],
            'windowStart': START, 'windowEnd': NOW}}


def databox():
    return {'id': PREFIX + 'Microsoft.DataBox/jobs/order', '_provenance': {**FULL, 'expand': 'details'},
            'sku': {'name': 'DataBox'}, 'identity': {'type': 'SystemAssigned', 'principalId': ACTOR}, 'properties': {'details': {
                'preferences': {'encryptionPreferences': {'doubleEncryption': 'Enabled'}},
                'keyEncryptionKey': {'kekType': 'CustomerManaged', 'kekUrl': KEY, 'kekVaultResourceID': VAULT,
                                     'identityProperties': {'type': 'SystemAssigned'}}}},
            'keyAccessEvidence': {'status': 'collected', 'source': 'effective-key-authorization', 'principalId': ACTOR,
                                 'keyUrl': KEY, 'vaultId': VAULT, 'permittedActions': ['get', 'wrapKey', 'unwrapKey']}}


def frontdoor_facts():
    profile = PREFIX + 'Microsoft.Cdn/profiles/front'
    endpoint = profile + '/afdEndpoints/ep'
    waf = PREFIX + 'Microsoft.Network/frontDoorWebApplicationFirewallPolicies/waf'
    return {'afd_profile': [{'id': profile, 'sku': {'name': 'Premium_AzureFrontDoor'}}],
            'afd_domain': [{'id': endpoint, 'properties': {'hostName': 'ep.azurefd.net'}}],
            'afd_route': [{'id': endpoint + '/routes/main', 'properties': {'enabledState': 'Enabled',
                          'supportedProtocols': ['Https'], 'customDomains': [], 'linkToDefaultDomain': 'Enabled',
                          'patternsToMatch': ['/*']}}],
            'afd_security_policy': [{'id': profile + '/securityPolicies/security', 'properties': {'parameters': {
                'type': 'WebApplicationFirewall', 'wafPolicy': {'id': waf},
                'associations': [{'domains': [{'id': endpoint}], 'patternsToMatch': ['/*']}]}}}],
            'frontdoor_waf_policy': [{'id': waf, '_provenance': FULL.copy(),
                                     'properties': {'policySettings': {'enabledState': 'Enabled'}}}]}


def make_case(cid, fail=False):
    if cid == PURVIEW:
        row = {'id': PREFIX + 'Microsoft.Purview/accounts/pv', 'location': 'westeurope',
               'properties': {'provisioningState': 'Succeeded', 'accountStatus': {'accountProvisioningState': 'Ready'}}}
        if fail:
            row['properties']['accountStatus']['accountProvisioningState'] = 'Disabled'
        index = facts({'purview_account': [row]}, {'purview': {'requiredRegions': ['westeurope'],
                      'serviceStatusMapping': {'Ready': 'ENABLED', 'Disabled': 'DISABLED'},
                      'serviceStatusMappingAuthority': 'approved-service-status-contract'}})
    elif cid in {ENTRA, GRAPH, AUDIT}:
        row = setting()
        if fail:
            for log in row['properties']['logs']:
                log['enabled'] = False
        evidence = {'identityAuditCoverage': {'status': 'collected', 'scope': TENANT, 'windowStart': START,
                    'windowEnd': NOW, 'verifiedEventClasses': ['identity-change', 'privileged-action'],
                    'privilegedActionsComplete': True, 'source': 'independent-audit-coverage'}}
        index = facts({'entra_diagnostic_setting': [row]}, diagnostic_policy(), evidence, tenant=True)
    elif cid in {DOUBLE, CMK}:
        row = databox()
        if fail:
            if cid == DOUBLE:
                row['properties']['details']['preferences']['encryptionPreferences']['doubleEncryption'] = 'Disabled'
            else:
                row['properties']['details']['keyEncryptionKey']['kekType'] = 'MicrosoftManaged'
        index = facts({'databox_job': [row]}, {'databox': {'skuDoubleEncryptionSupport': {'DataBox': True},
                                                       'approvedKeyUrls': [KEY], 'approvedVaultIds': [VAULT]}})
    elif cid == LB:
        row = {'id': PREFIX + 'Microsoft.Network/loadBalancers/lb',
               'routingChangeWindow': {'source': 'independent-routing-change-inventory', 'start': START, 'end': NOW}}
        change = {'id': 'change1', 'resourceId': row['id'], 'eventTimestamp': CHANGE_TIME, 'actorId': ACTOR,
                  'operationName': {'value': 'Microsoft.Network/loadBalancers/write'}, 'correlationId': 'event1'}
        coverage(row, 'routingChanges', [change])
        coverage(row, 'routingAuditEvents', [{'resourceId': row['id'], 'eventTimestamp': CHANGE_TIME,
                  'resolvedActorId': ACTOR, 'operationName': change['operationName'], 'status': {'value': 'Succeeded'},
                  'correlationId': 'event1', '_coverage': {'actorResolution': {'status': 'collected'}}}])
        coverage(row, 'auditDeliveryEvidence', [{'resourceId': row['id'], 'destinationId': WORKSPACE,
                  'durable': True, 'deliveredAt': CHANGE_TIME, 'correlationId': 'event1'}])
        index = facts({'load_balancer': [row]}, {'loadBalancerChanges': {'routingOperations': [change['operationName']['value']],
                      'trustedActorIds': [] if fail else [ACTOR], 'approvedDurableSinkIds': [WORKSPACE],
                      'windowStart': START, 'windowEnd': NOW}})
    elif cid == DEFAULT:
        row = {'id': PREFIX + 'Microsoft.Sql/servers/sql'}
        row['defaultCredentialAssessment'] = {'status': 'collected', 'authorization': {'approved': True, 'serverId': row['id']},
            'baseline': {'version': 'v1', 'credentialIds': ['default1']}, 'sqlCatalog': {'status': 'collected', 'loginNames': ['admin']},
            'endpointInventoryStatus': 'collected', 'endpoints': [{'id': 'sql.database.windows.net', 'serverId': row['id'],
                       'authenticationPaths': ['sql-password']}], 'testResultsStatus': 'collected',
            'tests': [{'endpointId': 'sql.database.windows.net', 'authenticationPath': 'sql-password',
                       'credentialId': 'default1', 'baselineVersion': 'v1', 'outcome': 'Authenticated' if fail else 'AccessDenied'}]}
        index = facts({'database_server': [row]})
    elif cid == PASSWORD:
        row = {'id': 'example.com', '_provenance': TENANT_PROOF.copy()}
        coverage(row, 'newlyProvisionedIdentities', [{'id': ACTOR, 'domainId': row['id'], 'policyId': 'policy1'}])
        coverage(row, 'effectivePasswordPolicies', [{'id': 'policy1', 'domainId': row['id'], 'authenticationType': 'Managed',
                    'sourcePolicyAuthority': 'effective-entra-policy', 'directlyVerifiedFields': ['complexity', 'lockoutThreshold', 'minimumLength'],
                    'settings': {'complexity': True, 'lockoutThreshold': 10, 'minimumLength': 7 if fail else 14}}])
        index = facts({'entra_domain': [row]}, {'passwords': {'approvedPasswordBaseline': {
                      'complexity': {'equals': True}, 'lockoutThreshold': {'maximum': 10}, 'minimumLength': {'minimum': 12}}}}, tenant=True)
    elif cid == FRONT:
        kinds = frontdoor_facts()
        if fail:
            kinds['frontdoor_waf_policy'][0]['properties']['policySettings']['enabledState'] = 'Disabled'
        index = facts(kinds)
        row = None
    elif cid == SQL:
        row = {'id': PREFIX + 'Microsoft.Sql/servers/sql', 'properties': {'publicNetworkAccess': 'Enabled'}}
        coverage(row, 'firewallRules', [{'id': row['id'] + '/firewallRules/range', 'parent_id': row['id'],
            'properties': {'startIpAddress': '0.0.0.0' if fail else '10.0.0.0',
                           'endIpAddress': '255.255.255.255' if fail else '10.0.0.255'}}])
        row['publicBypassEvidence'] = {'status': 'collected', 'serverId': row['id'],
                                     'admitsExternalPublicClient': False, 'source': 'effective-public-bypass-config'}
        index = facts({'mysql_postgresql_sql_server': [row]})
    elif cid == ACI:
        row = {'id': PREFIX + 'Microsoft.ContainerInstance/containerGroups/aci', '_provenance': FULL.copy(),
               'properties': {'instanceView': {'state': 'Running'}, 'containers': [{'name': 'worker'}],
                              'diagnostics': {'logAnalytics': {'workspaceId': CUSTOMER, 'logType': 'ContainerInsights'}}},
               'workspaceEvidence': {'customerId': CUSTOMER, 'id': WORKSPACE, 'exists': True}}
        coverage(row, 'containerLoggingEvidence', [{'containerName': 'worker', 'groupId': row['id'],
                 'loggingEnabled': not fail, 'workspaceCustomerId': CUSTOMER, 'collectedRecordCount': 3,
                 'lastCollectedAt': CHANGE_TIME, 'maxAgeSeconds': 86400}])
        index = facts({'container_group': [row]})
    elif cid in {FIREWALL, RESOURCE}:
        row = {'id': PREFIX + ('Microsoft.Network/azureFirewalls/fw' if cid == FIREWALL else 'Microsoft.Compute/virtualMachines/vm')}
        coverage(row, 'supportedCategories', supported())
        coverage(row, 'diagnosticSettings', [setting(row['id'], ['AuditLogs', 'SignInLogs'])])
        if fail:
            for log in row['diagnosticSettings'][0]['properties']['logs']:
                log['enabled'] = False
        kind = 'azure_firewall' if cid == FIREWALL else 'resource_diagnostic_setting'
        index = facts({kind: [row]}, {'firewallDiagnostics': {'requiredCategories': ['AuditLogs', 'SignInLogs'], 'approvedSinkIds': [WORKSPACE]}})
    elif cid == FILES:
        account = PREFIX + 'Microsoft.Storage/storageAccounts/account'
        row = {'id': account + '/fileServices/default/shares/share', 'name': 'share'}
        backup = {'id': PREFIX + 'Microsoft.RecoveryServices/vaults/vault/backupFabrics/Azure/protectionContainers/container/protectedItems/share',
                  'properties': {'protectedItemType': 'AzureFileShareProtectedItem', 'sourceResourceId': account,
                                 'friendlyName': 'share', 'policyId': PREFIX + 'Microsoft.RecoveryServices/vaults/vault/backupPolicies/daily',
                                 'protectionState': 'ProtectionStopped' if fail else 'Protected'}}
        index = facts({'storage_file_share_and_backup_item': [row], 'backup_protected_item': [backup]}, evidence={
                      'backupVaultInventory': {'status': 'collected', 'scope': SUB, 'allScopedVaultsAccessible': True}})
    else:
        raise AssertionError(cid)
    definition = DEFINITIONS[cid]
    return (index['context'] if definition.target == 'scope' else row), index


def evaluate(cid, item, index):
    return DEFINITIONS[cid].evaluate(item, index)[0]


@pytest.mark.parametrize('cid', sw.IDS)
def test_signed_pass_fail(cid):
    item, index = make_case(cid)
    original = copy.deepcopy((item, index))
    assert evaluate(cid, item, index) == 'PASS'
    assert (item, index) == original
    item, index = make_case(cid, fail=True)
    assert evaluate(cid, item, index) == 'FAIL'


@pytest.mark.parametrize('cid', sw.IDS)
@pytest.mark.parametrize('damage', ['incomplete', 'missing_collection', 'malformed_collection', 'foreign_collection',
                                  'foreign_wrapper', 'foreign_provider', 'inconsistent_projection', 'duplicate_identity'])
def test_inventory_boundaries_unknown(cid, damage):
    item, index = make_case(cid)
    kind = next(iter(index['collections']))
    envelope = index['collections'][kind][0]
    if damage == 'incomplete':
        envelope['status'] = 'partial'
    elif damage == 'missing_collection':
        del index['collections'][kind]
    elif damage == 'malformed_collection':
        index['collections'][kind] = 'bad'
    elif damage == 'foreign_collection':
        envelope['scope'] = '/subscriptions/99999999-9999-9999-9999-999999999999'
    elif damage == 'foreign_wrapper':
        index[kind][0]['scope'] = '/subscriptions/99999999-9999-9999-9999-999999999999'
    elif damage == 'foreign_provider':
        index['context']['provider'] = 'aws'
    elif damage == 'inconsistent_projection':
        envelope['items'] = []
    elif damage == 'duplicate_identity':
        index[kind].append(copy.deepcopy(index[kind][0]))
        envelope['items'].append(copy.deepcopy(envelope['items'][0]))
    assert evaluate(cid, item, index) == 'UNKNOWN'


def measured_fact(cid, index):
    kind = next(iter(index['collections']))
    row = index[kind][0]['data']
    return {
        PURVIEW: (row, 'location'), ENTRA: (row, 'properties'), GRAPH: (row, 'properties'),
        DOUBLE: (row, '_provenance'), CMK: (row, '_provenance'), LB: (row, 'routingChangeWindow'),
        DEFAULT: (row, 'defaultCredentialAssessment'), PASSWORD: (row, 'newlyProvisionedIdentities'),
        AUDIT: (row, 'properties'), FRONT: (row, 'sku'), SQL: (row, 'properties'),
        ACI: (row, 'properties'), FIREWALL: (row, 'supportedCategories'),
        FILES: (row, 'name'), RESOURCE: (row, 'supportedCategories'),
    }[cid]


@pytest.mark.parametrize('cid', sw.IDS)
@pytest.mark.parametrize('damage', ['missing', 'malformed', 'denied'])
def test_required_fact_boundaries_unknown(cid, damage):
    item, index = make_case(cid)
    row, field = measured_fact(cid, index)
    if damage == 'missing':
        del row[field]
    elif damage == 'malformed':
        row[field] = ['malformed']
    else:
        row.setdefault('_coverage', {})[field] = {'status': 'denied'}
    assert evaluate(cid, item, index) == 'UNKNOWN'


def first_row(index, kind=None):
    kind = next(iter(index['collections'])) if kind is None else kind
    return index[kind][0]['data']


def test_purview_missing_regions_status_mapping_and_normalization():
    item, index = make_case(PURVIEW)
    policy = index['context']['metadata']['compliance_policy']['sw21']['purview']
    policy['requiredRegions'].append('eastus')
    assert evaluate(PURVIEW, item, index) == 'FAIL'
    policy['requiredRegions'] = ['westeurope']
    row = first_row(index)
    row['properties']['accountStatus'].clear()
    assert evaluate(PURVIEW, item, index) == 'UNKNOWN'
    row['properties']['accountStatus']['accountProvisioningState'] = 'Ready'
    row['location'] = 'West Europe'
    assert evaluate(PURVIEW, item, index) == 'UNKNOWN'


@pytest.mark.parametrize('cid', [DOUBLE, CMK])
def test_databox_empty_jobs_and_full_expansion_defaults(cid):
    item, index = make_case(cid)
    row = first_row(index)
    if cid == DOUBLE:
        row['properties']['details'].pop('preferences')
    else:
        row['properties']['details']['keyEncryptionKey'].pop('kekType')
    assert evaluate(cid, item, index) == 'FAIL'
    row['_provenance'].pop('expand')
    assert evaluate(cid, item, index) == 'UNKNOWN'
    empty = facts({'databox_job': []})
    assert evaluate(cid, empty['context'], empty) == 'NOT_APPLICABLE'


def test_databox_double_sku_support_and_enum():
    item, index = make_case(DOUBLE)
    matrix = index['context']['metadata']['compliance_policy']['sw21']['databox']['skuDoubleEncryptionSupport']
    matrix['DataBox'] = False
    assert evaluate(DOUBLE, item, index) == 'NOT_APPLICABLE'
    matrix.clear()
    assert evaluate(DOUBLE, item, index) == 'UNKNOWN'
    matrix['DataBox'] = True
    first_row(index)['properties']['details']['preferences']['encryptionPreferences']['doubleEncryption'] = True
    assert evaluate(DOUBLE, item, index) == 'UNKNOWN'


@pytest.mark.parametrize('damage,expected', [
    ('invalid_url', 'FAIL'), ('wrong_vault', 'FAIL'), ('unapproved_key', 'FAIL'), ('denied_actions', 'FAIL'),
    ('foreign_principal', 'UNKNOWN'), ('missing_access', 'UNKNOWN'), ('incomplete_access', 'UNKNOWN'), ('unknown_type', 'UNKNOWN')])
def test_databox_cmk_key_identity_and_authorization(damage, expected):
    item, index = make_case(CMK)
    row = first_row(index)
    config = row['properties']['details']['keyEncryptionKey']
    if damage == 'invalid_url':
        config['kekUrl'] = 'http://keys.vault.azure.net/keys/wrapping/v1'
    elif damage == 'wrong_vault':
        config['kekVaultResourceID'] = VAULT + 'different'
    elif damage == 'unapproved_key':
        index['context']['metadata']['compliance_policy']['sw21']['databox']['approvedKeyUrls'] = []
    elif damage == 'denied_actions':
        row['keyAccessEvidence']['permittedActions'] = ['wrapKey']
    elif damage == 'foreign_principal':
        row['keyAccessEvidence']['principalId'] = CUSTOMER
    elif damage == 'missing_access':
        del row['keyAccessEvidence']
    elif damage == 'incomplete_access':
        row['keyAccessEvidence']['status'] = 'partial'
    else:
        config['kekType'] = 'Other'
    assert evaluate(CMK, item, index) == expected


@pytest.mark.parametrize('cid', [ENTRA, GRAPH])
@pytest.mark.parametrize('damage,expected', [('unapproved', 'FAIL'), ('no_destination', 'FAIL'), ('unresolved', 'UNKNOWN'),
                                         ('foreign_tenant', 'UNKNOWN'), ('null_destination', 'UNKNOWN')])
def test_tenant_exports_require_resolved_approved_sinks(cid, damage, expected):
    item, index = make_case(cid)
    row = first_row(index)
    if damage == 'unapproved':
        index['context']['metadata']['compliance_policy']['sw21']['entraDiagnostics']['approvedSinkIds'] = []
    elif damage == 'no_destination':
        del row['properties']['workspaceId']
    elif damage == 'unresolved':
        del row['destinationEvidence']
    elif damage == 'foreign_tenant':
        row['_provenance']['tenant_id'] = CUSTOMER
    else:
        row['properties']['workspaceId'] = None
    assert evaluate(cid, item, index) == expected


def test_entra_activity_any_and_explicit_both_requirements():
    item, index = make_case(ENTRA)
    first_row(index)['properties']['logs'][1]['enabled'] = False
    assert evaluate(ENTRA, item, index) == 'FAIL'
    index['context']['metadata']['compliance_policy']['sw21']['entraDiagnostics']['requiredActivityCategories'] = []
    assert evaluate(ENTRA, item, index) == 'PASS'


@pytest.mark.parametrize('damage,expected', [('retention', 'FAIL'), ('unreachable', 'FAIL'), ('unapproved', 'FAIL'),
    ('broad_missing', 'UNKNOWN'), ('event_class', 'UNKNOWN'), ('privileged', 'UNKNOWN'), ('window', 'UNKNOWN'), ('retention_unknown', 'UNKNOWN')])
def test_identity_audit_narrow_export_and_broad_requirements(damage, expected):
    item, index = make_case(AUDIT)
    destination = first_row(index)['destinationEvidence'][0]
    broad = index['context']['metadata']['sw21Evidence']['identityAuditCoverage']
    if damage == 'retention':
        destination['effectiveRetentionDaysByCategory']['SignInLogs'] = 30
    elif damage == 'unreachable':
        destination['reachable'] = False
    elif damage == 'unapproved':
        index['context']['metadata']['compliance_policy']['sw21']['entraDiagnostics']['approvedSinkIds'] = []
    elif damage == 'broad_missing':
        index['context']['metadata']['sw21Evidence'].clear()
    elif damage == 'event_class':
        broad['verifiedEventClasses'] = ['identity-change']
    elif damage == 'privileged':
        broad['privilegedActionsComplete'] = False
    elif damage == 'window':
        broad['windowStart'] = CHANGE_TIME
    else:
        del destination['effectiveRetentionDaysByCategory']
    assert evaluate(AUDIT, item, index) == expected


@pytest.mark.parametrize('cid', [FIREWALL, RESOURCE])
def test_resource_category_group_same_setting_and_foreign_parent(cid):
    item, index = make_case(cid)
    row = first_row(index)
    diagnostic = row['diagnosticSettings'][0]
    diagnostic['properties']['logs'] = [{'categoryGroup': 'allLogs', 'enabled': True}]
    assert evaluate(cid, item, index) == 'PASS'
    diagnostic['properties']['logs'] = [{'categoryGroup': 'futureGroup', 'enabled': True}]
    assert evaluate(cid, item, index) == 'UNKNOWN'
    diagnostic['properties']['logs'] = [{'categoryGroup': 'allLogs', 'enabled': True}]
    del diagnostic['properties']['workspaceId']
    row['diagnosticSettings'].append(setting(row['id'], []))
    assert evaluate(cid, item, index) == 'FAIL'
    diagnostic['parent_id'] = PREFIX + 'Microsoft.Compute/virtualMachines/foreign'
    assert evaluate(cid, item, index) == 'UNKNOWN'


@pytest.mark.parametrize('damage,expected', [('no_log', 'FAIL'), ('no_delivery', 'UNKNOWN'), ('incomplete_changes', 'UNKNOWN'),
                                          ('unmapped_operation', 'UNKNOWN'), ('unresolved_actor', 'UNKNOWN')])
def test_load_balancer_change_audit_boundaries(damage, expected):
    item, index = make_case(LB)
    row = first_row(index)
    if damage == 'no_log':
        coverage(row, 'routingAuditEvents', [])
        coverage(row, 'auditDeliveryEvidence', [])
    elif damage == 'no_delivery':
        coverage(row, 'auditDeliveryEvidence', [])
    elif damage == 'incomplete_changes':
        row['_coverage']['routingChanges']['status'] = 'partial'
    elif damage == 'unmapped_operation':
        row['routingChanges'][0]['operationName']['value'] = 'unknown-operation'
    else:
        row['routingAuditEvents'][0]['_coverage']['actorResolution']['status'] = 'partial'
    assert evaluate(LB, item, index) == expected


def test_load_balancer_complete_zero_change_window():
    item, index = make_case(LB)
    row = first_row(index)
    for field in ('routingChanges', 'routingAuditEvents', 'auditDeliveryEvidence'):
        coverage(row, field, [])
    assert evaluate(LB, item, index) == 'PASS'
    del row['routingChangeWindow']
    assert evaluate(LB, item, index) == 'UNKNOWN'


@pytest.mark.parametrize('damage', ['timeout', 'missing_test', 'unauthorized', 'partial_catalog', 'untested_path', 'foreign_baseline'])
def test_default_credentials_require_denied_tests_for_all_paths(damage):
    item, index = make_case(DEFAULT)
    assessment = first_row(index)['defaultCredentialAssessment']
    if damage == 'timeout':
        assessment['tests'][0]['outcome'] = 'Timeout'
    elif damage == 'missing_test':
        assessment['tests'] = []
    elif damage == 'unauthorized':
        assessment['authorization']['approved'] = False
    elif damage == 'partial_catalog':
        assessment['sqlCatalog']['status'] = 'partial'
    elif damage == 'untested_path':
        assessment['endpoints'][0]['authenticationPaths'].append('another-path')
    else:
        assessment['tests'][0]['baselineVersion'] = 'other-version'
    assert evaluate(DEFAULT, item, index) == 'UNKNOWN'


def test_password_only_graph_expiry_fields_unverified_and_federated():
    item, index = make_case(PASSWORD)
    row = first_row(index)
    measured = row['effectivePasswordPolicies'][0]
    measured['authenticationType'] = 'Federated'
    assert evaluate(PASSWORD, item, index) == 'PASS'
    measured['directlyVerifiedFields'] = ['passwordValidityPeriodInDays']
    measured['settings'] = {'passwordValidityPeriodInDays': 90}
    assert evaluate(PASSWORD, item, index) == 'UNKNOWN'
    del row['effectivePasswordPolicies']
    assert evaluate(PASSWORD, item, index) == 'UNKNOWN'


@pytest.mark.parametrize('damage', ['boolean_numeric_bound', 'nonfinite_value', 'missing_policy', 'foreign_domain'])
def test_password_baseline_malformed_bound_and_identity_joins(damage):
    item, index = make_case(PASSWORD)
    row = first_row(index)
    if damage == 'boolean_numeric_bound':
        row['effectivePasswordPolicies'][0]['settings']['minimumLength'] = True
    elif damage == 'nonfinite_value':
        row['effectivePasswordPolicies'][0]['settings']['minimumLength'] = float('nan')
    elif damage == 'missing_policy':
        row['newlyProvisionedIdentities'][0]['policyId'] = 'unknown'
    else:
        row['newlyProvisionedIdentities'][0]['domainId'] = 'foreign.com'
    assert evaluate(PASSWORD, item, index) == 'UNKNOWN'


@pytest.mark.parametrize('damage,expected', [('uncovered', 'FAIL'), ('ambiguous_pattern', 'UNKNOWN'), ('missing_waf', 'UNKNOWN'),
    ('disabled_route', 'NOT_APPLICABLE'), ('omitted_waf_state', 'PASS'), ('unresolved_default_domain', 'UNKNOWN')])
def test_frontdoor_route_association_and_default_semantics(damage, expected):
    item, index = make_case(FRONT)
    policy = first_row(index, 'afd_security_policy')['properties']['parameters']
    route = first_row(index, 'afd_route')['properties']
    waf = first_row(index, 'frontdoor_waf_policy')
    if damage == 'uncovered':
        policy['associations'] = []
    elif damage == 'ambiguous_pattern':
        policy['associations'][0]['patternsToMatch'] = ['/api/*']
    elif damage == 'missing_waf':
        index['frontdoor_waf_policy'] = []
        index['collections']['frontdoor_waf_policy'][0]['items'] = []
    elif damage == 'disabled_route':
        route['enabledState'] = 'Disabled'
    elif damage == 'omitted_waf_state':
        del waf['properties']['policySettings']['enabledState']
    else:
        del route['linkToDefaultDomain']
    assert evaluate(FRONT, item, index) == expected


@pytest.mark.parametrize('damage,expected', [('disabled', 'PASS'), ('public_single_ip', 'FAIL'), ('azure_bypass', 'FAIL'),
    ('unresolved_bypass', 'UNKNOWN'), ('reversed_range', 'UNKNOWN'), ('malformed_ip', 'UNKNOWN'), ('empty_rules', 'PASS')])
def test_database_public_network_effective_ingress(damage, expected):
    item, index = make_case(SQL)
    row = first_row(index)
    rule = row['firewallRules'][0]['properties']
    if damage == 'disabled':
        row['properties']['publicNetworkAccess'] = 'Disabled'
        del row['firewallRules']
        del row['publicBypassEvidence']
    elif damage == 'public_single_ip':
        rule['startIpAddress'] = rule['endIpAddress'] = '8.8.8.8'
    elif damage == 'azure_bypass':
        rule['startIpAddress'] = rule['endIpAddress'] = '0.0.0.0'
    elif damage == 'unresolved_bypass':
        row['publicBypassEvidence']['status'] = 'partial'
    elif damage == 'reversed_range':
        rule['startIpAddress'], rule['endIpAddress'] = rule['endIpAddress'], rule['startIpAddress']
    elif damage == 'malformed_ip':
        rule['startIpAddress'] = 'bogus'
    else:
        coverage(row, 'firewallRules', [])
    assert evaluate(SQL, item, index) == expected


@pytest.mark.parametrize('provider', ['Microsoft.DBforMySQL', 'Microsoft.DBforPostgreSQL'])
def test_database_flexible_servers_use_nested_public_access(provider):
    item, index = make_case(SQL)
    row = first_row(index)
    original = row['id']
    row['id'] = PREFIX + provider + '/flexibleServers/db'
    row['properties'] = {'network': {'publicNetworkAccess': 'Enabled'}}
    row['publicBypassEvidence']['serverId'] = row['id']
    for rule in row['firewallRules']:
        rule['id'] = rule['id'].replace(original, row['id'])
        rule['parent_id'] = row['id']
    assert evaluate(SQL, item, index) == 'PASS'
    row['firewallRules'][0]['properties']['startIpAddress'] = '8.8.8.8'
    row['firewallRules'][0]['properties']['endIpAddress'] = '8.8.8.9'
    assert evaluate(SQL, item, index) == 'FAIL'


@pytest.mark.parametrize('damage,expected', [('no_workspace', 'FAIL'), ('omitted_workspace', 'FAIL'), ('inactive', 'NOT_APPLICABLE'),
    ('logtype_only', 'UNKNOWN'), ('stale_collection', 'UNKNOWN'), ('wrong_workspace', 'UNKNOWN'), ('malformed_customer', 'UNKNOWN')])
def test_aci_workspace_container_logging_and_collection(damage, expected):
    item, index = make_case(ACI)
    row = first_row(index)
    if damage == 'no_workspace':
        row['properties']['diagnostics']['logAnalytics']['workspaceId'] = ''
    elif damage == 'omitted_workspace':
        del row['properties']['diagnostics']
    elif damage == 'inactive':
        row['properties']['instanceView']['state'] = 'Stopped'
    elif damage == 'logtype_only':
        del row['containerLoggingEvidence']
    elif damage == 'stale_collection':
        row['containerLoggingEvidence'][0]['maxAgeSeconds'] = 60
    elif damage == 'wrong_workspace':
        row['containerLoggingEvidence'][0]['workspaceCustomerId'] = ACTOR
    else:
        row['properties']['diagnostics']['logAnalytics']['workspaceId'] = WORKSPACE
    assert evaluate(ACI, item, index) == expected


@pytest.mark.parametrize('damage,expected', [('missing_backup', 'FAIL'), ('missing_policy', 'FAIL'), ('duplicate', 'UNKNOWN'),
    ('pending', 'UNKNOWN'), ('inaccessible_vault', 'UNKNOWN'), ('source_is_share', 'UNKNOWN'), ('normalized_case', 'PASS')])
def test_file_share_backup_join_and_protection_states(damage, expected):
    item, index = make_case(FILES)
    share = first_row(index, 'storage_file_share_and_backup_item')
    backup = first_row(index, 'backup_protected_item')
    if damage == 'missing_backup':
        index['backup_protected_item'] = []
        index['collections']['backup_protected_item'][0]['items'] = []
    elif damage == 'missing_policy':
        del backup['properties']['policyId']
    elif damage == 'duplicate':
        other = copy.deepcopy(backup)
        other['id'] += 'other'
        index['backup_protected_item'].append({'type': 'backup_protected_item', 'scope': SUB, 'data': other})
        index['collections']['backup_protected_item'][0]['items'].append(other)
    elif damage == 'pending':
        backup['properties']['protectionState'] = 'IRPending'
    elif damage == 'inaccessible_vault':
        index['context']['metadata']['sw21Evidence']['backupVaultInventory']['allScopedVaultsAccessible'] = False
    elif damage == 'source_is_share':
        backup['properties']['sourceResourceId'] = share['id']
    else:
        backup['properties']['sourceResourceId'] = backup['properties']['sourceResourceId'].upper()
        backup['properties']['friendlyName'] = 'SHARE'
        share['id'] = share['id'].upper()
    assert evaluate(FILES, item, index) == expected


@pytest.mark.parametrize('cid,kind', [(FILES, 'storage_file_share_and_backup_item'),
                                     (SQL, 'mysql_postgresql_sql_server'), (RESOURCE, 'resource_diagnostic_setting')])
def test_empty_scope_not_applicable(cid, kind):
    index = facts({kind: []})
    assert evaluate(cid, index['context'], index) == 'NOT_APPLICABLE'


@pytest.mark.parametrize('cid', sw.IDS)
def test_foreign_envelope_provider_and_masked_envelope_status_unknown(cid):
    item, index = make_case(cid)
    envelope = index['collections'][next(iter(index['collections']))][0]
    envelope['provider'] = 'aws'
    assert evaluate(cid, item, index) == 'UNKNOWN'
    envelope['provider'] = 'azure'
    envelope['_coverage'] = {'status': {'status': 'denied'}}
    assert evaluate(cid, item, index) == 'UNKNOWN'


def test_identity_audit_each_category_retention_and_missing_measurement():
    item, index = make_case(AUDIT)
    destination = first_row(index)['destinationEvidence'][0]
    destination['effectiveRetentionDaysByCategory']['AuditLogs'] = 30
    assert evaluate(AUDIT, item, index) == 'FAIL'
    destination['effectiveRetentionDaysByCategory']['AuditLogs'] = 365
    destination['effectiveRetentionDaysByCategory'].pop('SignInLogs')
    assert evaluate(AUDIT, item, index) == 'UNKNOWN'


@pytest.mark.parametrize('cid', [ENTRA, GRAPH, FIREWALL, RESOURCE])
def test_diagnostic_duplicates_and_invalid_approval_unknown(cid):
    item, index = make_case(cid)
    row = first_row(index)
    diagnostic = row if cid in {ENTRA, GRAPH} else row['diagnosticSettings'][0]
    diagnostic['properties']['logs'].append(copy.deepcopy(diagnostic['properties']['logs'][0]))
    assert evaluate(cid, item, index) == 'UNKNOWN'
    diagnostic['properties']['logs'].pop()
    if cid != RESOURCE:
        policy_name = 'firewallDiagnostics' if cid == FIREWALL else 'entraDiagnostics'
        index['context']['metadata']['compliance_policy']['sw21'][policy_name]['approvedSinkIds'] = ['not-a-resource']
        assert evaluate(cid, item, index) == 'UNKNOWN'


def test_cmk_full_missing_required_key_is_invalid_and_dns_case_normalizes():
    item, index = make_case(CMK)
    row = first_row(index)
    config = row['properties']['details']['keyEncryptionKey']
    del config['kekUrl']
    assert evaluate(CMK, item, index) == 'FAIL'
    config['kekUrl'] = KEY.replace('keys.vault.azure.net', 'KEYS.VAULT.AZURE.NET')
    row['keyAccessEvidence']['keyUrl'] = config['kekUrl']
    assert evaluate(CMK, item, index) == 'PASS'
    row['identity']['principalId'] = 'not-an-immutable-id'
    row['keyAccessEvidence']['principalId'] = row['identity']['principalId']
    assert evaluate(CMK, item, index) == 'UNKNOWN'


def test_password_missing_required_measurement_masks_incomplete_grade():
    item, index = make_case(PASSWORD, fail=True)
    row = first_row(index)
    row['effectivePasswordPolicies'][0]['directlyVerifiedFields'].remove('complexity')
    assert evaluate(PASSWORD, item, index) == 'UNKNOWN'


def test_default_credential_positive_authentication_is_decisive():
    item, index = make_case(DEFAULT, fail=True)
    first_row(index)['defaultCredentialAssessment']['endpoints'][0]['authenticationPaths'].append('second-path')
    assert evaluate(DEFAULT, item, index) == 'FAIL'


def test_frontdoor_complete_empty_route_inventory():
    kinds = frontdoor_facts()
    kinds['afd_route'] = []
    index = facts(kinds)
    assert evaluate(FRONT, index['context'], index) == 'NOT_APPLICABLE'


def test_load_balancer_delivery_before_change_is_unknown():
    item, index = make_case(LB)
    first_row(index)['auditDeliveryEvidence'][0]['deliveredAt'] = START
    assert evaluate(LB, item, index) == 'UNKNOWN'


def test_databox_selected_user_assigned_key_identity_and_metadata_resolution():
    item, index = make_case(CMK)
    row = first_row(index)
    identity_id = PREFIX + 'Microsoft.ManagedIdentity/userAssignedIdentities/key-identity'
    row['properties']['details']['keyEncryptionKey']['identityProperties'] = {
        'type': 'UserAssigned', 'userAssigned': {'resourceId': identity_id}}
    row['identity'] = {'type': 'UserAssigned', 'userAssignedIdentities': {
        identity_id: {'principalId': ACTOR, 'clientId': CUSTOMER}}}
    assert evaluate(CMK, item, index) == 'PASS'
    row['identity']['userAssignedIdentities'][identity_id] = {}
    assert evaluate(CMK, item, index) == 'UNKNOWN'
    row['keyIdentity'] = {'id': identity_id, '_provenance': FULL.copy(), 'properties': {'principalId': ACTOR}}
    assert evaluate(CMK, item, index) == 'PASS'
    row['keyIdentity']['id'] = identity_id + 'other'
    assert evaluate(CMK, item, index) == 'UNKNOWN'


def test_databox_selected_key_identity_and_get_permission_are_required():
    item, index = make_case(CMK)
    row = first_row(index)
    row['keyAccessEvidence']['permittedActions'] = ['wrapKey', 'unwrapKey']
    assert evaluate(CMK, item, index) == 'FAIL'
    row['keyAccessEvidence']['permittedActions'].append('get')
    row['properties']['details']['keyEncryptionKey'].pop('identityProperties')
    assert evaluate(CMK, item, index) == 'UNKNOWN'


@pytest.mark.parametrize('marker', [None, [], {'status': 'empty'}, {'status': 'partial'}])
def test_databox_literal_attached_identity_coverage_authority(marker):
    item, index = make_case(CMK)
    row = first_row(index)
    identity_id = PREFIX + 'Microsoft.ManagedIdentity/userAssignedIdentities/key-identity'
    row['properties']['details']['keyEncryptionKey']['identityProperties'] = {
        'type': 'UserAssigned', 'userAssigned': {'resourceId': identity_id}}
    attached = {identity_id: {'principalId': ACTOR, 'clientId': CUSTOMER}}
    row['identity'] = {'type': 'UserAssigned', 'userAssignedIdentities': attached}
    assert evaluate(CMK, item, index) == 'PASS'
    attached['_coverage'] = {identity_id: marker}
    assert evaluate(CMK, item, index) == 'UNKNOWN'


def test_databox_empty_attached_identity_uses_full_resolved_fallback():
    item, index = make_case(CMK)
    row = first_row(index)
    identity_id = PREFIX + 'Microsoft.ManagedIdentity/userAssignedIdentities/key-identity'
    row['properties']['details']['keyEncryptionKey']['identityProperties'] = {
        'type': 'UserAssigned', 'userAssigned': {'resourceId': identity_id}}
    row['identity'] = {'type': 'UserAssigned', 'userAssignedIdentities': {
        identity_id: {}, '_coverage': {identity_id: {'status': 'empty'}}}}
    row['keyIdentity'] = {'id': identity_id, '_provenance': FULL.copy(),
                          'properties': {'principalId': ACTOR}}
    assert evaluate(CMK, item, index) == 'PASS'
