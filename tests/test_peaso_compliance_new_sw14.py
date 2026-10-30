"""Signed sw14 predicates, imported directly with registration isolation."""
import copy
import importlib

import pytest
import peaso.checks as registry

# This staged module overlaps admitted checks. Capture its evaluator closures
# in a separate registry without replacing or deleting any runtime check.
_runtime_checks = registry.CHECKS
try:
    registry.CHECKS = []
    mod = importlib.import_module('peaso.checks.compliance_new_sw14')
finally:
    registry.CHECKS = _runtime_checks

SUB = '/subscriptions/11111111-1111-1111-1111-111111111111'
TENANT = '/tenants/22222222-2222-2222-2222-222222222222'
APP = '33333333-3333-3333-3333-333333333333'
NOW = '2026-10-12T12:00:00Z'


def arm(rtype, name='r'):
    return SUB + '/resourceGroups/rg/providers/' + rtype + '/' + name


def evidence(row, scope, **fields):
    return {'status': 'collected', '_provenance': {'resource_id': row['id'], 'scope': scope,
        'snapshot_id': 'snapshot-14', 'authority': 'approved-evidence', 'read_only': True}, **fields}


def make_index(row, kind, scope=SUB, policy=None):
    ctx = {'provider': 'azure', 'scope': scope, 'created_at': NOW, 'snapshot_id': 'snapshot-14', 'metadata': {'sw14Policy': {'scope': scope, 'status': 'collected', **(policy or {})}}}
    return {'context': ctx, 'collections': {kind: [{'type': kind, 'scope': scope,
        'status': 'collected', 'items': [row]}]}, kind: [{'type': kind, 'scope': scope, 'data': row}]}


def add(index, row, kind, scope):
    index['collections'][kind] = [{'type': kind, 'scope': scope, 'status': 'collected', 'items': [row]}]
    index[kind] = [{'type': kind, 'scope': scope, 'data': row}]


def child(row, field, **properties):
    prefix = '/providers/Microsoft.Insights/diagnosticSettings/' if field == 'diagnosticSettings' else '/' + field + '/'
    item = {'id': row['id'] + prefix + 'child', 'properties': properties,
        '_provenance': {'representation': 'full', 'read_only': True}}
    row.setdefault('_coverage', {})[field] = {'status': 'collected'}
    row[field] = [item]
    return item


def waf():
    row = {'id': arm(mod._TYPES['web_application_firewall_policy']),
        '_provenance': {'representation': 'full', 'read_only': True},
        'properties': {'policySettings': {'state': 'Enabled', 'mode': 'Prevention'}, 'customRules': [],
            'managedRules': {'managedRuleSets': [{'ruleSetType': 'OWASP', 'ruleSetVersion': '3.2', 'ruleGroupOverrides': []}]}}}
    gateway = arm('Microsoft.Network/applicationGateways')
    row['gatewayAssociations'] = evidence(row, SUB, gatewayInventory='complete', routeInventory='complete', paths=[{
        'gatewayId': gateway, 'listenerId': gateway + '/httpListeners/api', 'routeId': gateway + '/requestRoutingRules/api',
        'effectivePolicyId': row['id'], 'sku': 'WAF_v2', 'associationResolved': True, 'apiInScope': True}])
    return row


def remote_rule(action='Block', priority=10, ranges=None, negated=True):
    return {'priority': priority, 'state': 'Enabled', 'ruleType': 'MatchRule', 'action': action,
        'matchConditions': [{'matchVariables': [{'variableName': 'RemoteAddr'}], 'operator': 'IPMatch',
            'matchValues': ranges or ['10.0.0.0/8'], 'negationCondition': negated, 'transforms': []}]}


def application():
    return {'id': APP, '_provenance': {'tenant_id': TENANT.split('/')[-1], 'tenant_verified': True},
        'passwordCredentials': [{'keyId': 'key', 'startDateTime': '2026-10-01T12:00:00Z', 'endDateTime': '2027-10-01T12:00:00Z'}], 'keyCredentials': []}


def trust(row):
    row['trustInventory'] = evidence(row, TENANT, ownerIds=[APP],
        inventoriedPolicyTypes=['federation', 'roles', 'impersonation'],
        coverage={k: 'complete' for k in ['applications', 'managedIdentities', 'federatedCredentials', 'roleAssignments', 'roleDefinitions', 'impersonationPolicies']},
        federatedCredentials=[{'id': 'fic', 'ownerId': APP, 'issuer': 'https://issuer.example', 'subject': 'repo:approved', 'audiences': ['api://exchange']}],
        roleAssumptionPolicies=[{'id': 'role', 'principal': APP}])
    row['negativeAuthorizationEvidence'] = evidence(row, TENANT, tests=[{'scenario': scenario, 'authorized': True,
        'testedAt': '2026-10-11T12:00:00Z', 'outcome': 'Denied'} for scenario in ['unapprovedExternal', 'unauthenticated']])
    return {'federatedTrustPolicy': {'approvedTuples': [{'issuer': 'https://issuer.example', 'subject': 'repo:approved', 'audiences': ['api://exchange']}],
        'approvedPrincipals': [APP], 'requiredPolicyTypes': ['federation', 'roles', 'impersonation'], 'negativeEvidenceMaxAgeDays': 30}}


def pipeline():
    return {'id': 'pipeline-1', 'organization': 'org', 'projectId': 'project-1', 'revision': 'git-sha'}


def case(cid):
    kind = mod.SPECS[cid]['resource_kind']
    scope, policy = SUB, {}
    if kind == 'web_application_firewall_policy':
        row = waf()
        if cid == 'azure.other.gateway_api_cidr_allowlist':
            row['properties']['customRules'] = [remote_rule()]
            policy = {'approvedCidrs': ['10.0.0.0/8']}
        elif cid == 'azure_firewall_policy_6_4_1_6_2ad9039':
            row['firewallManagerOrder'] = evidence(row, SUB, ruleGroups=[{'groupId': 'g1', 'rank': 0}, {'groupId': 'g2', 'rank': 1}],
                deployedGroups=[{'groupId': 'g1', 'rank': 0}, {'groupId': 'g2', 'rank': 1}])
            row['firewallManagerOrder']['_provenance']['authority'] = 'FirewallManager'
        else:
            row['managedRuleCatalogue'] = evidence(row, SUB, ruleSets=[{'ruleSetType': 'OWASP', 'ruleSetVersion': '3.2',
                'ruleGroups': [{'ruleGroupName': 'SQLI', 'rules': [{'ruleId': '1', 'state': 'Enabled'}, {'ruleId': '2', 'state': 'Enabled'}]}]}])
    elif kind == 'application':
        scope, kind, row = TENANT, 'directory_application', application()
        if cid != 'azure.other.entra_app_secret_age_90':
            policy = trust(row)
    elif kind == 'devops_pipeline':
        scope, row = '/devops/org', pipeline()
        if cid == 'azure_devops_project_3_5_1_7_dc58423':
            policy = {'devopsCredentialPolicy': {'credentialVariableNames': ['AZURE_CLIENT_SECRET', 'PASSWORD'], 'requiredVariableNames': ['AZURE_CLIENT_SECRET']}}
            row['expandedVariables'] = evidence(row, scope, revision='git-sha', variableGroupIds=['group-1'], variables=[{
                'name': 'AZURE_CLIENT_SECRET', 'source': 'variableGroup', 'scopeId': 'group-1', 'isSecret': True}],
                coverage={k: 'complete' for k in ['projects', 'pipelines', 'variableGroups', 'templates', 'variables']})
        else:
            policy = {'devopsSecurityTestingPolicy': {'requiredTestCategories': ['SAST'], 'productionApplicationIds': ['prod'],
                'criticalApplicationIds': ['prod'], 'reviewWindowStart': '2026-10-01T00:00:00Z', 'reviewWindowEnd': '2026-10-12T00:00:00Z'}}
            row['securityTestingEvidence'] = evidence(row, scope,
                coverage={k: 'complete' for k in ['policy', 'activities', 'changes', 'builds', 'tests', 'reviews', 'deployments']},
                process={'documented': True, 'implemented': True, 'documentId': 'process'},
                activities=[{'id': 'activity', 'applicationId': 'prod', 'phase': 'development', 'occurredAt': '2026-10-09T00:00:00Z', 'buildId': 'build'}],
                platformChanges=[{'id': 'change', 'changedAt': '2026-10-08T00:00:00Z', 'affectedApplicationIds': ['prod']}],
                tests=[{'id': 'test', 'activityId': 'activity', 'changeId': 'change', 'buildId': 'build', 'applicationId': 'prod',
                    'category': 'SAST', 'state': 'Completed', 'outcome': 'Passed', 'completedAt': '2026-10-10T00:00:00Z'}],
                reviews=[{'id': 'review', 'applicationId': 'prod', 'changeId': 'change', 'reviewedAt': '2026-10-10T00:00:00Z',
                    'noAdverseActivityEffect': True, 'noAdverseSecurityEffect': True}])
    elif kind == 'vnet_gateway':
        kind = 'virtual_network_gateway'
        row = {'id': arm(mod._TYPES[kind]), 'properties': {'gatewayType': 'Vpn',
            'vpnClientConfiguration': {'vpnClientAddressPool': {'addressPrefixes': ['172.16.0.0/24']}},
            'ipConfigurations': [{'properties': {'subnet': {'id': arm('Microsoft.Network/virtualNetworks') + '/subnets/GatewaySubnet'}}}]}}
        if cid == 'azure_vnet_gateway_network_ssh_internet_access_restricted_e19b1dc':
            policy = {'approvedVnetIds': [arm('Microsoft.Network/virtualNetworks')]}
        else:
            sink = arm('Microsoft.OperationalInsights/workspaces')
            policy = {'approvedDiagnosticDestinationIds': [sink]}
            child(row, 'diagnosticSettings', logs=[{'category': 'P2SDiagnosticLog', 'enabled': True}], workspaceId=sink)
    elif kind == 'app_service':
        row = {'id': arm(mod._TYPES[kind]), 'kind': 'functionapp,linux', 'properties': {'publicNetworkAccess': 'Enabled'}}
        policy = {'approvedCidrs': ['10.0.0.0/8']}
    elif cid == 'azure.gap.postgresql_server_infrastructure_encryption_enabled':
        kind = 'postgresql_single_server'
        row = {'id': arm(mod._TYPES[kind]), 'properties': {'infrastructureEncryption': 'Enabled'}}
    else:
        row = {'id': arm(mod._TYPES[kind]), '_provenance': {'representation': 'full', 'read_only': True},
            'properties': {'network': {'publicNetworkAccess': 'Disabled'}}}
        if cid == 'azure.gap.postgres_sql_server_encrypted_at_rest_using_cmk':
            identity = arm('Microsoft.ManagedIdentity/userAssignedIdentities')
            uri = 'https://approved.vault.azure.net/keys/db/version'
            policy = {'approvedKeyVaultKeyIds': [uri]}
            row['identity'] = {'userAssignedIdentities': {identity: {}}}
            row['properties']['dataEncryption'] = {'type': 'AzureKeyVault', 'primaryKeyURI': uri, 'primaryUserAssignedIdentityId': identity}
        else:
            child(row, 'privateEndpointConnections', privateLinkServiceConnectionState={'status': 'Approved'}, privateEndpoint={'id': arm('Microsoft.Network/privateEndpoints')})
            if kind == 'postgresql_flexible_server':
                row['privateLinkSupport'] = evidence(row, scope, supported=True, networkMode='Public')
    idx = make_index(row, kind, scope, policy)
    if cid == 'azure_pci_1_2_8_19':
        config = {'id': row['id'] + '/config/web', 'parent_id': row['id'], 'properties': {
            'ipSecurityRestrictionsDefaultAction': 'Deny', 'ipSecurityRestrictions': [
                {'priority': 100, 'action': 'Allow', 'tag': 'Default', 'headers': {}, 'ipAddress': '10.0.0.0/8'}]}}
        add(idx, config, 'app_service_config', row['id'])
    return row, idx


def failure(cid, row, idx):
    if cid == 'azure_pci_1_2_8_19':
        idx['app_service_config'][0]['data']['properties']['ipSecurityRestrictionsDefaultAction'] = 'Allow'
    elif cid == 'azure.other.gateway_api_cidr_allowlist':
        row['properties']['customRules'].insert(0, remote_rule('Allow', 1, ['0.0.0.0/0'], False))
    elif cid == 'azure_firewall_policy_6_4_1_6_2ad9039':
        row['firewallManagerOrder']['deployedGroups'].reverse()
        for i, group in enumerate(row['firewallManagerOrder']['deployedGroups']):
            group['rank'] = i
    elif cid == 'azure_firewall_policy_6_4_1_7_a7975fc':
        row['properties']['managedRules']['managedRuleSets'][0]['ruleGroupOverrides'] = [{'ruleGroupName': 'SQLI', 'rules': []}]
    elif cid == 'azure.other.entra_app_secret_age_90':
        row['passwordCredentials'][0]['startDateTime'] = '2026-01-01T00:00:00Z'
    elif cid in {'azure.other.external_impersonation_denied', 'azure.other.federated_subject_restricted'}:
        row['trustInventory']['federatedCredentials'][0]['subject'] = '*'
    elif cid in {'azure.gap.mysql_server_private_link_used', 'azure.gap.postgres_server_private_link_used'}:
        row['privateEndpointConnections'] = []
        row['_coverage']['privateEndpointConnections']['status'] = 'empty'
    elif cid == 'azure.gap.postgres_sql_server_encrypted_at_rest_using_cmk':
        row['properties']['dataEncryption']['type'] = 'SystemManaged'
    elif cid == 'azure.gap.postgresql_server_infrastructure_encryption_enabled':
        row['properties']['infrastructureEncryption'] = 'Disabled'
    elif cid == 'azure.other.devops_security_test_evidence':
        row['securityTestingEvidence']['tests'] = []
    elif cid == 'azure_devops_project_3_5_1_7_dc58423':
        row['expandedVariables']['variables'][0]['isSecret'] = False
    elif cid == 'azure_vnet_gateway_10_2_1_1_14_4189d89':
        row['diagnosticSettings'][0]['properties']['logs'][0]['category'] = 'TunnelDiagnosticLog'
    else:
        idx['context']['metadata']['sw14Policy']['approvedVnetIds'] = []


@pytest.mark.parametrize('cid', mod.IDS)
def test_signed_pass_fail(cid):
    row, idx = case(cid)
    assert mod.EVALUATORS[cid](row, idx)[0] == 'PASS'
    failure(cid, row, idx)
    assert mod.EVALUATORS[cid](row, idx)[0] == 'FAIL'


@pytest.mark.parametrize('cid', mod.IDS)
@pytest.mark.parametrize('state', ['partial', 'denied', 'not_collected'])
def test_incomplete_inventory_unknown(cid, state):
    row, idx = case(cid)
    kind = next(iter(idx['collections']))
    idx['collections'][kind][0]['status'] = state
    assert mod.EVALUATORS[cid](row, idx)[0] == 'UNKNOWN'


@pytest.mark.parametrize('cid', mod.IDS)
def test_missing_malformed_foreign_facts_unknown(cid):
    row, idx = case(cid)
    assert mod.EVALUATORS[cid](row, {})[0] == 'UNKNOWN'
    row['_coverage'] = []
    assert mod.EVALUATORS[cid](row, idx)[0] == 'UNKNOWN'
    row.pop('_coverage')
    idx['context']['provider'] = 'aws'
    assert mod.EVALUATORS[cid](row, idx)[0] == 'UNKNOWN'
    idx['context']['provider'] = 'azure'
    kind = next(iter(idx['collections']))
    idx['collections'][kind][0]['scope'] = '/subscriptions/foreign'
    assert mod.EVALUATORS[cid](row, idx)[0] == 'UNKNOWN'


@pytest.mark.parametrize('cid', mod.IDS)
def test_missing_required_fact_unknown(cid):
    row, idx = case(cid)
    field = {
        'azure_pci_1_2_8_19': 'properties',
        'azure.other.gateway_api_cidr_allowlist': 'gatewayAssociations',
        'azure_firewall_policy_6_4_1_6_2ad9039': 'firewallManagerOrder',
        'azure_firewall_policy_6_4_1_7_a7975fc': 'managedRuleCatalogue',
        'azure.other.entra_app_secret_age_90': 'passwordCredentials',
        'azure.other.external_impersonation_denied': 'negativeAuthorizationEvidence',
        'azure.other.federated_subject_restricted': 'trustInventory',
        'azure.gap.postgres_server_private_link_used': 'privateLinkSupport',
        'azure.gap.postgres_sql_server_encrypted_at_rest_using_cmk': 'identity',
        'azure.gap.postgresql_server_infrastructure_encryption_enabled': 'properties',
        'azure.other.devops_security_test_evidence': 'securityTestingEvidence',
        'azure_devops_project_3_5_1_7_dc58423': 'expandedVariables',
        'azure_vnet_gateway_10_2_1_1_14_4189d89': 'diagnosticSettings',
        'azure_vnet_gateway_network_ssh_internet_access_restricted_e19b1dc': 'properties',
        'azure.gap.mysql_server_private_link_used': 'privateEndpointConnections',
    }[cid]
    row.pop(field)
    assert mod.EVALUATORS[cid](row, idx)[0] == 'UNKNOWN'


@pytest.mark.parametrize('cid', [
    'azure.other.gateway_api_cidr_allowlist', 'azure_firewall_policy_6_4_1_7_a7975fc',
    'azure.gap.postgres_sql_server_encrypted_at_rest_using_cmk',
    'azure.gap.postgresql_server_infrastructure_encryption_enabled',
    'azure_vnet_gateway_network_ssh_internet_access_restricted_e19b1dc'])
def test_empty_applicability(cid):
    row, idx = case(cid)
    if cid.startswith('azure_firewall') or cid == 'azure.other.gateway_api_cidr_allowlist':
        row['gatewayAssociations']['paths'] = []
        assert mod.EVALUATORS[cid](row, idx)[0] == 'NOT_APPLICABLE'
    else:
        kind = next(iter(idx['collections']))
        idx[kind] = []
        idx['collections'][kind][0].update(status='empty', items=[])
        assert mod.EVALUATORS[cid]({}, idx)[0] == 'NOT_APPLICABLE'


def test_function_applicability_and_private_ingress():
    cid = 'azure_pci_1_2_8_19'
    row, idx = case(cid)
    row['kind'] = 'app,linux'
    assert mod.EVALUATORS[cid](row, idx)[0] == 'NOT_APPLICABLE'
    row['kind'] = 'functionapp'
    row['properties']['publicNetworkAccess'] = 'Disabled'
    endpoint = arm('Microsoft.Network/privateEndpoints')
    child(row, 'privateEndpointConnections', privateLinkServiceConnectionState={'status': 'Approved'}, privateEndpoint={'id': endpoint})
    idx['context']['metadata']['sw14Policy'] = {'scope': SUB, 'status': 'collected', 'approvedPrivateEndpointIds': [endpoint]}
    assert mod.EVALUATORS[cid](row, idx)[0] == 'PASS'
    row['privateEndpointConnections'][0]['properties']['privateLinkServiceConnectionState']['status'] = 'Pending'
    assert mod.EVALUATORS[cid](row, idx)[0] == 'FAIL'
    row['_coverage']['privateEndpointConnections']['status'] = 'partial'
    assert mod.EVALUATORS[cid](row, idx)[0] == 'UNKNOWN'


def test_function_rule_priority_and_unresolved_tags():
    cid = 'azure_pci_1_2_8_19'
    row, idx = case(cid)
    props = idx['app_service_config'][0]['data']['properties']
    props['ipSecurityRestrictions'] = [
        {'priority': 1, 'action': 'Deny', 'ipAddress': '0.0.0.0/0', 'tag': 'Default', 'headers': {}},
        {'priority': 2, 'action': 'Allow', 'ipAddress': '0.0.0.0/0', 'tag': 'Default', 'headers': {}}]
    assert mod.EVALUATORS[cid](row, idx)[0] == 'PASS'
    props['ipSecurityRestrictions'].reverse()
    props['ipSecurityRestrictions'][0]['priority'] = 0
    assert mod.EVALUATORS[cid](row, idx)[0] == 'FAIL'
    props['ipSecurityRestrictions'][0]['tag'] = 'ServiceTag'
    assert mod.EVALUATORS[cid](row, idx)[0] == 'UNKNOWN'


def test_waf_order_defaults_unknown_matching_and_bypass():
    cid = 'azure.other.gateway_api_cidr_allowlist'
    row, idx = case(cid)
    row['properties']['customRules'][0].pop('state')
    row['properties']['policySettings'].pop('state')
    assert mod.EVALUATORS[cid](row, idx)[0] == 'PASS'
    row['properties']['customRules'][0]['matchConditions'][0]['transforms'] = ['Lowercase']
    assert mod.EVALUATORS[cid](row, idx)[0] == 'UNKNOWN'
    row['properties']['customRules'] = []
    assert mod.EVALUATORS[cid](row, idx)[0] == 'UNKNOWN'
    row['gatewayAssociations']['paths'][0]['effectivePolicyId'] = None
    assert mod.EVALUATORS[cid](row, idx)[0] == 'FAIL'
    row, idx = case(cid)
    row['properties']['customRules'].append(remote_rule('Allow', 20, ['0.0.0.0/0'], False))
    assert mod.EVALUATORS[cid](row, idx)[0] == 'PASS'
    row['properties']['customRules'][0]['state'] = 'Disabled'
    assert mod.EVALUATORS[cid](row, idx)[0] == 'FAIL'
    row, idx = case(cid)
    row['_provenance']['representation'] = 'partial'
    row['properties']['customRules'][0].pop('state')
    assert mod.EVALUATORS[cid](row, idx)[0] == 'UNKNOWN'


def test_managed_catalogue_rules_and_override_defaults():
    cid = 'azure_firewall_policy_6_4_1_7_a7975fc'
    row, idx = case(cid)
    ruleset = row['properties']['managedRules']['managedRuleSets'][0]
    ruleset['ruleGroupOverrides'] = [{'ruleGroupName': 'SQLI', 'rules': [{'ruleId': '1'}, {'ruleId': '2'}]}]
    assert mod.EVALUATORS[cid](row, idx)[0] == 'FAIL'
    ruleset['ruleGroupOverrides'][0]['rules'][1]['state'] = 'Enabled'
    assert mod.EVALUATORS[cid](row, idx)[0] == 'PASS'
    ruleset['ruleSetVersion'] = 'future'
    assert mod.EVALUATORS[cid](row, idx)[0] == 'UNKNOWN'
    row, idx = case(cid)
    row['properties']['policySettings']['state'] = 'Disabled'
    row.pop('managedRuleCatalogue')
    assert mod.EVALUATORS[cid](row, idx)[0] == 'FAIL'


def test_firewall_manager_priority_is_not_rank():
    cid = 'azure_firewall_policy_6_4_1_6_2ad9039'
    row, idx = case(cid)
    row.pop('firewallManagerOrder')
    row['properties']['customRules'] = [{'priority': i} for i in range(3)]
    assert mod.EVALUATORS[cid](row, idx)[0] == 'UNKNOWN'
    row, idx = case(cid)
    row['firewallManagerOrder']['deployedGroups'][0]['rank'] = 1
    assert mod.EVALUATORS[cid](row, idx)[0] == 'UNKNOWN'


def test_credential_age_boundary_inactive_null_and_empty_scope():
    cid = 'azure.other.entra_app_secret_age_90'
    row, idx = case(cid)
    credential = row['passwordCredentials'][0]
    credential['startDateTime'] = '2026-07-14T12:00:00Z'
    assert mod.EVALUATORS[cid](row, idx)[0] == 'FAIL'
    credential['startDateTime'] = '2026-07-14T12:00:01Z'
    assert mod.EVALUATORS[cid](row, idx)[0] == 'PASS'
    credential['endDateTime'] = None
    assert mod.EVALUATORS[cid](row, idx)[0] == 'UNKNOWN'
    credential.update(startDateTime='2025-01-01T00:00:00Z', endDateTime=NOW)
    assert mod.EVALUATORS[cid](row, idx)[0] == 'PASS'
    idx['directory_application'] = []
    idx['collections']['directory_application'][0].update(status='empty', items=[])
    assert mod.EVALUATORS[cid](idx['context'], idx)[0] == 'PASS'


def test_trust_subset_unapproved_and_negative_authorization():
    for cid in ['azure.other.external_impersonation_denied', 'azure.other.federated_subject_restricted']:
        row, idx = case(cid)
        row['trustInventory']['coverage']['managedIdentities'] = 'unmeasured'
        assert mod.EVALUATORS[cid](row, idx)[0] == 'UNKNOWN'
        row['trustInventory']['federatedCredentials'][0]['subject'] = 'unapproved'
        assert mod.EVALUATORS[cid](row, idx)[0] == 'FAIL'
    cid = 'azure.other.external_impersonation_denied'
    row, idx = case(cid)
    row['negativeAuthorizationEvidence']['tests'][0]['outcome'] = 'Succeeded'
    row.pop('trustInventory')
    assert mod.EVALUATORS[cid](row, idx)[0] == 'FAIL'
    row['negativeAuthorizationEvidence']['tests'][0]['outcome'] = 'Denied'
    assert mod.EVALUATORS[cid](row, idx)[0] == 'UNKNOWN'
    row, idx = case(cid)
    row['negativeAuthorizationEvidence']['tests'][0]['testedAt'] = '2026-01-01T00:00:00Z'
    assert mod.EVALUATORS[cid](row, idx)[0] == 'UNKNOWN'


@pytest.mark.parametrize('cid', ['azure.gap.mysql_server_private_link_used', 'azure.gap.postgres_server_private_link_used'])
def test_private_link_foreign_child_and_unresolved_status(cid):
    row, idx = case(cid)
    row['privateEndpointConnections'][0]['id'] = arm('Microsoft.DBforPostgreSQL/flexibleServers', 'foreign') + '/privateEndpointConnections/c'
    assert mod.EVALUATORS[cid](row, idx)[0] == 'UNKNOWN'
    row, idx = case(cid)
    row['privateEndpointConnections'][0]['properties']['privateLinkServiceConnectionState']['status'] = 'FutureState'
    assert mod.EVALUATORS[cid](row, idx)[0] == 'UNKNOWN'
    row, idx = case(cid)
    row['properties']['network']['publicNetworkAccess'] = 'Enabled'
    if 'postgres' in cid:
        assert mod.EVALUATORS[cid](row, idx)[0] == 'FAIL'
    else:
        idx['context']['metadata']['sw14Policy']['approvedCidrs'] = ['10.0.0.0/8']
        child(row, 'firewallRules', startIpAddress='10.1.0.0', endIpAddress='10.1.0.255')
        assert mod.EVALUATORS[cid](row, idx)[0] == 'PASS'
        row['firewallRules'][0]['properties']['endIpAddress'] = '11.0.0.1'
        assert mod.EVALUATORS[cid](row, idx)[0] == 'FAIL'


def test_cmk_key_and_identity_mismatch_missing_and_partial():
    cid = 'azure.gap.postgres_sql_server_encrypted_at_rest_using_cmk'
    row, idx = case(cid)
    row['identity']['userAssignedIdentities'] = {}
    assert mod.EVALUATORS[cid](row, idx)[0] == 'FAIL'
    row, idx = case(cid)
    row['properties']['dataEncryption'].pop('primaryKeyURI')
    assert mod.EVALUATORS[cid](row, idx)[0] == 'FAIL'
    row['_provenance']['representation'] = 'partial'
    assert mod.EVALUATORS[cid](row, idx)[0] == 'UNKNOWN'


def test_legacy_only_and_foreign_scope():
    cid = 'azure.gap.postgresql_server_infrastructure_encryption_enabled'
    row, idx = case(cid)
    flex = {'id': arm(mod._TYPES['postgresql_flexible_server']), 'properties': {'infrastructureEncryption': 'Disabled'}}
    assert mod.EVALUATORS[cid](flex, idx)[0] == 'PASS'
    assert mod.EVALUATORS[cid](idx['context'], idx)[0] == 'PASS'
    flex['id'] = flex['id'].replace(SUB, '/subscriptions/foreign')
    assert mod.EVALUATORS[cid](flex, idx)[0] == 'UNKNOWN'
    row['properties']['infrastructureEncryption'] = 'FutureState'
    assert mod.EVALUATORS[cid](row, idx)[0] == 'UNKNOWN'


def test_devops_variable_expansion_and_plaintext_yaml():
    cid = 'azure_devops_project_3_5_1_7_dc58423'
    row, idx = case(cid)
    row['expandedVariables']['coverage']['templates'] = 'unresolved'
    assert mod.EVALUATORS[cid](row, idx)[0] == 'UNKNOWN'
    row['expandedVariables']['variables'][0]['source'] = 'yamlLiteral'
    assert mod.EVALUATORS[cid](row, idx)[0] == 'FAIL'
    row, idx = case(cid)
    row['expandedVariables']['variables'] = []
    assert mod.EVALUATORS[cid](row, idx)[0] == 'UNKNOWN'
    row, idx = case(cid)
    row['expandedVariables']['revision'] = 'unrelated'
    assert mod.EVALUATORS[cid](row, idx)[0] == 'UNKNOWN'


def test_devops_test_window_changes_review_and_coverage():
    cid = 'azure.other.devops_security_test_evidence'
    row, idx = case(cid)
    row['securityTestingEvidence']['reviews'] = []
    assert mod.EVALUATORS[cid](row, idx)[0] == 'FAIL'
    row, idx = case(cid)
    row['securityTestingEvidence']['coverage']['changes'] = 'unmeasured'
    assert mod.EVALUATORS[cid](row, idx)[0] == 'UNKNOWN'
    row, idx = case(cid)
    row['securityTestingEvidence']['reviews'][0]['applicationId'] = 'foreign'
    assert mod.EVALUATORS[cid](row, idx)[0] == 'UNKNOWN'


def test_vpn_point_to_site_applicability_and_exact_category_destination():
    cid = 'azure_vnet_gateway_10_2_1_1_14_4189d89'
    row, idx = case(cid)
    row['properties']['gatewayType'] = 'ExpressRoute'
    assert mod.EVALUATORS[cid](row, idx)[0] == 'NOT_APPLICABLE'
    row['properties']['gatewayType'] = 'Vpn'
    row['properties']['vpnClientConfiguration']['vpnClientAddressPool']['addressPrefixes'] = []
    assert mod.EVALUATORS[cid](row, idx)[0] == 'NOT_APPLICABLE'
    row, idx = case(cid)
    row['diagnosticSettings'][0]['properties']['workspaceId'] = arm('Microsoft.OperationalInsights/workspaces', 'unapproved')
    assert mod.EVALUATORS[cid](row, idx)[0] == 'FAIL'
    row['diagnosticSettings'][0]['properties']['logs'][0]['enabled'] = 'true'
    assert mod.EVALUATORS[cid](row, idx)[0] == 'UNKNOWN'


@pytest.mark.parametrize('cid', [
    'azure.other.gateway_api_cidr_allowlist', 'azure.other.external_impersonation_denied',
    'azure_devops_project_3_5_1_7_dc58423', 'azure.gap.postgres_server_private_link_used'])
def test_foreign_evidence_and_approval_policy_unknown(cid):
    row, idx = case(cid)
    field = {'azure.other.gateway_api_cidr_allowlist': 'gatewayAssociations',
        'azure.other.external_impersonation_denied': 'negativeAuthorizationEvidence',
        'azure_devops_project_3_5_1_7_dc58423': 'expandedVariables',
        'azure.gap.postgres_server_private_link_used': 'privateLinkSupport'}[cid]
    row[field]['_provenance']['snapshot_id'] = 'other-snapshot'
    assert mod.EVALUATORS[cid](row, idx)[0] == 'UNKNOWN'
    row, idx = case(cid)
    if cid != 'azure.gap.postgres_server_private_link_used':
        idx['context']['metadata']['sw14Policy']['scope'] = '/subscriptions/foreign'
        assert mod.EVALUATORS[cid](row, idx)[0] == 'UNKNOWN'


@pytest.mark.parametrize('cid', mod.IDS)
def test_duplicate_inventory_and_foreign_wrapper_unknown(cid):
    row, idx = case(cid)
    kind = next(iter(idx['collections']))
    idx[kind].append(copy.deepcopy(idx[kind][0]))
    idx['collections'][kind][0]['items'].append(copy.deepcopy(row))
    assert mod.EVALUATORS[cid](row, idx)[0] == 'UNKNOWN'
    row, idx = case(cid)
    kind = next(iter(idx['collections']))
    idx[kind][0]['scope'] = '/subscriptions/foreign'
    assert mod.EVALUATORS[cid](row, idx)[0] == 'UNKNOWN'


def test_firewall_manager_complete_rank_mismatch_is_positive_evidence():
    cid = 'azure_firewall_policy_6_4_1_6_2ad9039'
    row, idx = case(cid)
    row['firewallManagerOrder']['deployedGroups'][1]['rank'] = 2
    assert mod.EVALUATORS[cid](row, idx)[0] == 'FAIL'


def test_postgres_unsupported_private_link_not_applicable():
    cid = 'azure.gap.postgres_server_private_link_used'
    row, idx = case(cid)
    row['privateLinkSupport']['supported'] = False
    assert mod.EVALUATORS[cid](row, idx)[0] == 'NOT_APPLICABLE'


def test_denied_embedded_field_unknown_even_with_value():
    cid = 'azure.gap.postgres_sql_server_encrypted_at_rest_using_cmk'
    row, idx = case(cid)
    row['properties']['dataEncryption']['_coverage'] = {'primaryKeyURI': {'status': 'denied'}}
    assert mod.EVALUATORS[cid](row, idx)[0] == 'UNKNOWN'


def test_empty_application_inventory_still_requires_tenant_authority():
    cid = 'azure.other.entra_app_secret_age_90'
    row, idx = case(cid)
    idx['directory_application'] = []
    idx['collections']['directory_application'][0].update(status='empty', items=[], scope=SUB)
    idx['context']['scope'] = SUB
    assert mod.EVALUATORS[cid](idx['context'], idx)[0] == 'UNKNOWN'


def test_gateway_all_addresses_approved_still_requires_protected_path():
    cid = 'azure.other.gateway_api_cidr_allowlist'
    row, idx = case(cid)
    idx['context']['metadata']['sw14Policy']['approvedCidrs'] = ['0.0.0.0/0', '::/0']
    row['properties']['policySettings']['state'] = 'Disabled'
    assert mod.EVALUATORS[cid](row, idx)[0] == 'UNKNOWN'
    row['gatewayAssociations']['paths'][0]['effectivePolicyId'] = None
    assert mod.EVALUATORS[cid](row, idx)[0] == 'UNKNOWN'
