"""Signed Azure sw19 evidence and scope boundaries; no registry leakage."""
from __future__ import annotations

import copy
import importlib

import pytest

from peaso.checks import CHECKS

# Import directly, retain the wrapped evaluators locally, undo only registrations
# introduced by this import. Preexisting registrations belong to the integrator.
_before = {check.id for check in CHECKS}
mod = importlib.import_module('peaso.checks.compliance_new_sw19')
CHECKS[:] = [check for check in CHECKS if check.id not in set(mod.IDS) - _before]

SCOPE = '/subscriptions/sub'
TENANT = '/tenants/tenant'
BASE = SCOPE + '/resourceGroups/rg/providers/'
NOW = '2026-10-12T00:00:00Z'
PROOF = {'tenant_id': 'tenant', 'tenant_verified': True, 'read_only': True,
         'credential_context_id': 'capture', 'customer_context_id': 'customer'}


def inventory(row, kind, *, extras=None, policy=None, status='collected', scope=SCOPE):
    rows_by_kind = {kind: [row], **(extras or {})}
    collections, facts = {}, {}
    for current, rows in rows_by_kind.items():
        directory = current in ('directory_user', 'conditional_access_policy')
        actual = TENANT if directory else scope
        collections[current] = [{'type': current, 'scope': actual,
            'service': 'Microsoft.Graph' if directory else 'ARM',
            '_provenance': copy.deepcopy(PROOF), 'status': status if current == kind else ('collected' if rows else 'empty'), 'items': rows}]
        facts[current] = [{'type': current, 'scope': actual, 'data': value} for value in rows]
    metadata = {**PROOF, 'subscription_tenants': {SCOPE: 'tenant'}}
    if policy is not None:
        metadata['compliance_policy'] = {'sw19': {'scope': scope, 'status': 'collected', **policy}}
    return {'context': {'provider': 'azure', 'scope': scope, 'created_at': NOW, 'metadata': metadata}, 'collections': collections, **facts}


def embed(item, field, value):
    item.setdefault('_coverage', {})[field] = {'status': 'collected'}
    item[field] = {'parent_id': item['id'], **value}
    return item


def children(item, field, rows):
    item.setdefault('_coverage', {})[field] = {'status': 'collected' if rows else 'empty'}
    item[field] = [{'parent_id': item['id'], **row} for row in rows]
    return item


def resolved(*fields):
    return {'resolved': {field: True for field in fields}}


def user():
    return {'id': 'user', 'accountEnabled': True, '_provenance': copy.deepcopy(PROOF),
            'signInActivity': {'lastSuccessfulSignInDateTime': '2026-10-11T00:00:00Z'}}


def roles(row, admin=False):
    return embed(row, 'effectiveRoles', {**resolved('directory', 'rbacHierarchy', 'pimActive', 'pimEligible', 'transitiveGroups', 'definitions'),
        'directoryRoleTemplateIds': [mod._GLOBAL_ADMIN] if admin else [], 'azureResourceWriter': admin, 'privilegedDirectoryUser': admin})


def ca():
    return {'id': 'policy', '_provenance': copy.deepcopy(PROOF), 'state': 'enabled',
        'grantControls': {'operator': 'AND', 'builtInControls': ['mfa'],
                          'customAuthenticationFactors': [], 'termsOfUse': [], 'authenticationStrength': None}}


def mfa(check_id, bad=False):
    row = roles(user(), admin=check_id in (mod.CIS_MFA, mod.ADMIN_MFA))
    if check_id == mod.CIS_MFA:
        embed(row, 'authenticationRequirements', {'api_version': 'beta', 'perUserMfaState': 'enforced'})
    decision = {'policyId': 'policy', 'matches': not bad, 'excluded': False,
                'authenticationStrengthRequiresMfa': False, **resolved(*mod._RESOLVED)}
    embed(row, 'mfaContexts', {**resolved(*mod._RESOLVED, 'inventory', 'registration', 'contextCoverage'),
        'registration': {'isMfaRegistered': True, 'isMfaCapable': True}, 'contexts': [
            {'id': 'browser-outside', 'purpose': 'azureConsole' if check_id == mod.ADMIN_MFA else 'requiredSignIn',
             'policyDecisions': [decision], 'securityDefaults': {
                 'applicabilityResolved': True, 'isEnabled': False, 'requiresMfa': False}}]})
    return row, {'conditional_access_policy': [ca()]}, None


def workspace():
    return {'id': BASE + 'Microsoft.OperationalInsights/workspaces/ws',
            'type': 'Microsoft.OperationalInsights/workspaces',
            'properties': {'features': {'clusterResourceId': None}}}


def front(family='classicFrontDoor'):
    if family == 'classicFrontDoor':
        return {'id': BASE + 'Microsoft.Network/frontDoors/fd', 'type': 'Microsoft.Network/frontDoors'}
    return {'id': BASE + 'Microsoft.Cdn/profiles/fd', 'type': 'Microsoft.Cdn/profiles',
            'sku': {'name': 'Standard_AzureFrontDoor' if family == 'afd' else 'Standard_Microsoft'}}


def domain(row, family='classicFrontDoor', bad=False):
    tail = {'classicFrontDoor': '/frontendEndpoints/custom', 'classicCdn': '/endpoints/ep/customDomains/custom', 'afd': '/customDomains/custom'}[family]
    types = {'classicFrontDoor': 'Microsoft.Network/frontDoors/frontendEndpoints', 'classicCdn': 'Microsoft.Cdn/profiles/endpoints/customDomains', 'afd': 'Microsoft.Cdn/profiles/customDomains'}
    config = {'certificateSource': 'AzureKeyVault', 'protocolType': 'ServerNameIndication',
              'minimumTlsVersion': ('1.0' if bad else '1.2') if family == 'classicFrontDoor' else ('TLS10' if bad else 'TLS12')}
    if family == 'afd':
        config['cipherSuiteSetType'] = 'TLS10_2019' if bad else 'TLS12_2023'
    field = {'classicFrontDoor': 'customHttpsConfiguration', 'classicCdn': 'customHttpsParameters', 'afd': 'tlsSettings'}[family]
    return {'id': row['id'] + tail, 'type': types[family], 'httpsState': 'Enabled',
            'properties': {'customHttpsProvisioningState': 'Enabled', 'provisioningState': 'Succeeded',
                           'deploymentStatus': 'Succeeded', field: config}}


def route(row, *, family='classicFrontDoor', bad=False, origin=False):
    tail = {'classicFrontDoor': '/routingRules/route', 'afd': '/afdEndpoints/ep/routes/route', 'classicCdn': '/endpoints/ep'}[family]
    types = {'classicFrontDoor': 'Microsoft.Network/frontDoors/routingRules', 'afd': 'Microsoft.Cdn/profiles/afdEndpoints/routes', 'classicCdn': 'Microsoft.Cdn/profiles/endpoints'}
    path = {'acceptedProtocols': ['Http', 'Https'], 'action': 'Forward' if origin or bad else 'Redirect',
            'redirectProtocol': 'HttpsOnly', 'forwardingProtocol': 'HttpOnly' if bad else 'HttpsOnly',
            'originProtocolEvidence': {'source': 'providerConfiguration', 'allPathsMeasured': True, 'protocol': 'HttpOnly' if bad else 'HttpsOnly'}}
    return {'id': row['id'] + tail, 'type': types[family], 'enabledState': 'Enabled', 'customOrigin': True,
            **resolved('routeAssociation', 'protocols', 'ruleSets', 'pathCoverage', 'originPolicy'), 'paths': [path]}


def access_proof(row, key, active=False):
    row['identity'] = {'principalId': 'identity'}
    embed(row, 'cmkAccess', {**resolved('keyMetadata', 'identity', 'access', 'network', 'provisioning'),
        'key_id': key, 'principal_id': 'identity', 'keyEnabled': True, 'keyUsable': True,
        'wrapKeyAllowed': True, 'unwrapKeyAllowed': True, 'encryptionActive': active})
    return row


def fixture(cid, bad=False):
    if cid in (mod.CIS_MFA, mod.ALL_MFA, mod.ADMIN_MFA):
        return mfa(cid, bad)
    if cid == mod.DIRECT:
        row = user()
        assignment = {'id': 'assignment', 'principalId': 'user', 'principalType': 'User',
                      'source': 'pimEligible', 'scope': TENANT, 'tenant_id': 'tenant', 'roleDefinitionId': 'role'}
        embed(row, 'directAssignments', {**resolved('users', 'directory', 'pimActive', 'pimEligible', 'rbacHierarchy', 'principalTypes'), 'hierarchyScopeIds': [TENANT, SCOPE], 'assignments': [assignment] if bad else []})
        return row, {}, None
    if cid == mod.STALE:
        row = user()
        embed(row, 'credentialActivity', {**resolved('credentialInventory', 'successfulUse', 'issuance'), 'credentials': [
            {'id': 'password', 'kind': 'password', 'active': True, 'issuedAt': '2025-01-01T00:00:00Z',
             'lastSuccessfulUse': '2025-01-02T00:00:00Z' if bad else '2026-10-11T00:00:00Z'}]})
        return row, {}, {cid: {'resource_id': row['id'], 'inactiveDays': 90}}
    if cid == mod.COMPROMISED:
        row = user()
        row['accountEnabled'] = bad
        embed(row, 'compromiseCases', {**resolved('allIdentities', 'monitoring', 'cases', 'review', 'disableHistory'), 'monitoringCovered': True, 'cases': [
            {'id': 'case', 'userId': 'user', 'confirmedCompromise': True, 'confirmedAt': '2026-10-01T00:00:00Z',
             'authorizedReview': True, 'disabledAt': None if bad else '2026-10-01T01:00:00Z', 'reviewedAt': '2026-10-01T02:00:00Z'}]})
        return row, {}, {cid: {'resource_id': row['id'], 'responseDeadlineHours': 24}}
    if cid in (mod.SNI, mod.TLS):
        row = front()
        child = domain(row, bad=bad)
        if cid == mod.SNI and bad:
            child['properties']['customHttpsConfiguration']['certificateSource'] = 'FrontDoor'
        children(row, 'domains', [child])
        return row, {}, None
    if cid in (mod.REDIRECT, mod.ORIGIN):
        row = front()
        children(row, 'effectiveRoutes', [route(row, bad=bad, origin=cid == mod.ORIGIN)])
        return row, {}, None
    if cid == mod.ACCESS_LOG:
        row = front()
        children(row, 'diagnosticCategories', [{'id': row['id'] + '/providers/Microsoft.Insights/diagnosticSettingsCategories/FrontdoorAccessLog',
            'type': 'Microsoft.Insights/diagnosticSettingsCategories', 'name': 'FrontdoorAccessLog',
            'properties': {'categoryType': 'Logs', 'categoryGroups': ['allLogs']}}])
        children(row, 'diagnosticSettings', [] if bad else [{
            'id': row['id'] + '/providers/Microsoft.Insights/diagnosticSettings/export',
            'type': 'Microsoft.Insights/diagnosticSettings', 'properties': {
                'logs': [{'categoryGroup': 'allLogs', 'enabled': True}],
                'workspaceId': workspace()['id'], 'storageAccountId': None}}])
        return row, {}, None
    if cid == mod.QUERY_CMK:
        row = workspace()
        account = {'id': BASE + 'Microsoft.Storage/storageAccounts/storage', 'type': 'Microsoft.Storage/storageAccounts',
            'properties': {'encryption': {'keySource': 'Microsoft.Storage' if bad else 'Microsoft.Keyvault',
                'keyVaultProperties': {'keyvaulturi': 'https://vault.vault.azure.net', 'keyname': 'key', 'keyversion': 'version'}}}}
        access_proof(account, 'https://vault.vault.azure.net/keys/key/version')
        embed(row, 'queryLinkedStorage', {'id': row['id'] + '/linkedStorageAccounts/Query', 'properties': {'storageAccountIds': [account['id']]}})
        return row, {'storage_account': [account]}, {cid: {'resource_id': row['id'], 'required': True}}
    if cid == mod.CLUSTER_CMK:
        row = workspace()
        cluster = {'id': BASE + 'Microsoft.OperationalInsights/clusters/cluster', 'type': 'Microsoft.OperationalInsights/clusters',
                   'properties': {'provisioningState': 'Succeeded', 'keyVaultProperties': {
                       'keyVaultUri': 'https://vault.vault.azure.net', 'keyName': 'key', 'keyVersion': 'bad' if bad else 'version'}}}
        key = 'https://vault.vault.azure.net/keys/key/version'
        access_proof(cluster, key, True)
        row['properties']['features']['clusterResourceId'] = cluster['id']
        return row, {'log_analytics_cluster': [cluster]}, {cid: {'resource_id': row['id'], 'approvedKeyVaultKeyIds': [key]}}
    if cid == mod.EXPIRY:
        row = workspace()
        embed(row, 'expiryQueries', {'queries': [{'table': 'Audit', 'workspace_id': row['id'], 'cutoff': '2026-09-12T00:00:00Z',
            'expiredEventCount': 1 if bad else 0, 'expiredEventTimes': ['2026-01-01T00:00:00Z'] if bad else [],
            'allRetainedTiers': True, 'entireAccessibleRange': True, 'queryComplete': True,
            'notTruncated': True, 'permissionsComplete': True}]})
        return row, {}, {cid: {'resource_id': row['id'], 'retentionDays': 30, 'tables': ['Audit']}}
    assert cid == mod.C5_LOGS
    row = workspace()
    controls = ('confidentiality', 'integrity', 'availability', 'access', 'recovery')
    embed(row, 'logProtectionMeasures', {**resolved('logs', 'infrastructure', 'policyCoverage'), 'measures': [
        {'control': c, 'measureId': c, 'evidenceRef': 'case/' + c, 'documented': True,
         'observation': 'violated' if bad and c == 'recovery' else 'implemented'} for c in controls]})
    return row, {}, {cid: {'resource_id': row['id'], 'requiredMeasures': {c: [c] for c in controls}}}


def run(cid, row, extras=None, policy=None, **kwargs):
    facts = inventory(row, mod.SPECS[cid]['resource_kind'], extras=extras, policy=policy, **kwargs)
    return invoke(cid, row, facts)


def invoke(cid, row, facts):
    return mod.EVALUATORS[cid](facts['context'] if cid == mod.CLUSTER_CMK else row, facts)


@pytest.mark.parametrize('cid', mod.IDS)
def test_pass_fail(cid):
    assert run(cid, *fixture(cid))[0] == 'PASS'
    assert run(cid, *fixture(cid, True))[0] == 'FAIL'


@pytest.mark.parametrize('cid', mod.IDS)
def test_missing_malformed_incomplete_and_foreign(cid):
    row, extras, policy = fixture(cid)
    assert run(cid, row, extras, policy, status='partial')[0] == 'UNKNOWN'
    assert run(cid, row, extras, policy, status='denied')[0] == 'UNKNOWN'
    malformed = copy.deepcopy(row)
    malformed['_coverage'] = 'bad'
    assert run(cid, malformed, extras, policy)[0] == 'UNKNOWN'
    missing = {key: value for key, value in row.items() if key in ('id', 'type', '_provenance')}
    assert run(cid, missing, extras, policy)[0] == 'UNKNOWN'
    assert run(cid, row, extras, policy, scope='/subscriptions/other')[0] == 'UNKNOWN'
    facts = inventory(row, mod.SPECS[cid]['resource_kind'], extras=extras, policy=policy)
    before = copy.deepcopy(facts)
    assert invoke(cid, row, facts)[0] == 'PASS'
    assert facts == before
    kind = mod.SPECS[cid]['resource_kind']
    facts['collections'][kind][0]['items'].append(copy.deepcopy(row))
    facts[kind].append(copy.deepcopy(facts[kind][0]))
    assert invoke(cid, row, facts)[0] == 'UNKNOWN'


@pytest.mark.parametrize('cid', [mod.CIS_MFA, mod.ALL_MFA, mod.ADMIN_MFA, mod.STALE])
def test_disabled_users_not_applicable(cid):
    row, extras, policy = fixture(cid)
    row['accountEnabled'] = False
    assert run(cid, row, extras, policy)[0] == 'NOT_APPLICABLE'


@pytest.mark.parametrize('cid', [mod.SNI, mod.TLS, mod.REDIRECT, mod.ORIGIN])
def test_empty_frontdoor_scope_not_applicable(cid):
    row = front()
    children(row, 'domains' if cid in (mod.SNI, mod.TLS) else 'effectiveRoutes', [])
    assert run(cid, row)[0] == 'NOT_APPLICABLE'


def test_mfa_context_exclusions_or_grants_legacy_and_defaults():
    for cid in (mod.ALL_MFA, mod.CIS_MFA, mod.ADMIN_MFA):
        row, extras, policy = fixture(cid)
        decision = row['mfaContexts']['contexts'][0]['policyDecisions'][0]
        decision['excluded'] = True
        assert run(cid, row, extras)[0] == 'FAIL'
        decision['excluded'] = False
        extras['conditional_access_policy'][0]['grantControls'].update(operator='OR', builtInControls=['mfa', 'compliantDevice'])
        assert run(cid, row, extras)[0] == 'FAIL'
        decision['resolved']['locations'] = False
        assert run(cid, row, extras)[0] == 'UNKNOWN'
    row, extras, _ = fixture(mod.CIS_MFA)
    row['authenticationRequirements']['perUserMfaState'] = 'disabled'
    assert run(mod.CIS_MFA, row, extras)[0] == 'FAIL'
    row.pop('authenticationRequirements')
    assert run(mod.CIS_MFA, row, extras)[0] == 'UNKNOWN'
    row, extras, _ = fixture(mod.ADMIN_MFA, True)
    row['mfaContexts']['contexts'][0]['securityDefaults'].update(isEnabled=True, requiresMfa=True)
    assert run(mod.ADMIN_MFA, row, extras)[0] == 'PASS'
    row['effectiveRoles']['directoryRoleTemplateIds'] = []
    assert run(mod.ADMIN_MFA, row, extras)[0] == 'NOT_APPLICABLE'


def test_direct_group_grants_and_pim_coverage():
    row, extras, _ = fixture(mod.DIRECT, True)
    row['directAssignments']['assignments'][0].update(principalId='group', principalType='Group')
    assert run(mod.DIRECT, row)[0] == 'PASS'
    row['directAssignments']['resolved']['pimEligible'] = False
    assert run(mod.DIRECT, row)[0] == 'UNKNOWN'


def test_stale_credential_missing_null_future_and_boundary():
    row, extras, policy = fixture(mod.STALE)
    credential = row['credentialActivity']['credentials'][0]
    credential['lastSuccessfulUse'] = None
    assert run(mod.STALE, row, extras, policy)[0] == 'UNKNOWN'
    credential['lastSuccessfulUse'] = '2026-07-14T00:00:00Z'
    assert run(mod.STALE, row, extras, policy)[0] == 'PASS'
    credential['lastSuccessfulUse'] = '2027-01-01T00:00:00Z'
    assert run(mod.STALE, row, extras, policy)[0] == 'UNKNOWN'
    row['signInActivity']['lastSuccessfulSignInDateTime'] = None
    assert run(mod.STALE, row, extras, policy)[0] == 'UNKNOWN'


def test_compromise_review_deadline_and_reenabled_evidence():
    row, extras, policy = fixture(mod.COMPROMISED)
    row['accountEnabled'] = True
    case = row['compromiseCases']['cases'][0]
    case['reenabledAt'] = '2026-10-02T00:00:00Z'
    assert run(mod.COMPROMISED, row, extras, policy)[0] == 'PASS'
    case['authorizedReview'] = False
    assert run(mod.COMPROMISED, row, extras, policy)[0] == 'FAIL'
    case['authorizedReview'] = True
    case.update(disabledAt=None, confirmedAt='2026-10-11T23:00:00Z', reviewedAt=None)
    assert run(mod.COMPROMISED, row, extras, policy)[0] == 'UNKNOWN'


@pytest.mark.parametrize('family', ['classicFrontDoor', 'classicCdn', 'afd'])
def test_tls_resource_specific_fields_presets_and_deployment(family):
    row = front(family)
    children(row, 'domains', [domain(row, family)])
    assert run(mod.TLS, row)[0] == 'PASS'
    children(row, 'domains', [domain(row, family, True)])
    assert run(mod.TLS, row)[0] == 'FAIL'
    child = row['domains'][0]
    if family == 'afd':
        child['properties']['tlsSettings'].update(cipherSuiteSetType='TLS10_2019', minimumTlsVersion='TLS13')
        assert run(mod.TLS, row)[0] == 'FAIL'
        child['properties']['tlsSettings']['cipherSuiteSetType'] = 'Customized'
        assert run(mod.TLS, row)[0] == 'PASS'
        child['properties']['deploymentStatus'] = 'InProgress'
        assert run(mod.TLS, row)[0] == 'UNKNOWN'
        assert run(mod.SNI, row)[0] == 'UNKNOWN'
    else:
        child['properties']['customHttpsProvisioningState'] = 'Disabled'
        assert run(mod.TLS, row)[0] == 'NOT_APPLICABLE'
        child['properties']['customHttpsProvisioningState'] = 'Enabling'
        assert run(mod.TLS, row)[0] == 'UNKNOWN'


def test_cdn_sni_explicit_ipbased_and_managed_certificate():
    row = front('classicCdn')
    child = domain(row, 'classicCdn')
    children(row, 'domains', [child])
    assert run(mod.SNI, row)[0] == 'PASS'
    row['domains'][0]['properties']['customHttpsParameters']['protocolType'] = 'IPBased'
    assert run(mod.SNI, row)[0] == 'FAIL'


@pytest.mark.parametrize('family', ['classicFrontDoor', 'classicCdn', 'afd'])
def test_origin_match_request_client_redirect_and_disabled(family):
    row = front(family)
    children(row, 'effectiveRoutes', [route(row, family=family, origin=True)])
    assert run(mod.ORIGIN, row)[0] == 'PASS'
    assert run(mod.REDIRECT, row)[0] == 'FAIL'
    path = row['effectiveRoutes'][0]['paths'][0]
    path['forwardingProtocol'] = 'MatchRequest'
    path['originProtocolEvidence']['protocol'] = 'MatchRequest'
    assert run(mod.ORIGIN, row)[0] == 'FAIL'
    path['acceptedProtocols'] = ['Https']
    assert run(mod.ORIGIN, row)[0] == 'PASS'
    assert run(mod.REDIRECT, row)[0] == 'PASS'
    if family == 'classicCdn':
        path.pop('originProtocolEvidence')
        assert run(mod.ORIGIN, row)[0] == 'UNKNOWN'
    row['effectiveRoutes'][0]['enabledState'] = 'Disabled'
    assert run(mod.ORIGIN, row)[0] == 'NOT_APPLICABLE'


def test_access_logs_category_discovery_group_destination_and_coverage():
    row, extras, _ = fixture(mod.ACCESS_LOG)
    setting = row['diagnosticSettings'][0]
    setting['properties']['logs'][0]['categoryGroup'] = 'unknownGroup'
    assert run(mod.ACCESS_LOG, row)[0] == 'UNKNOWN'
    setting['properties']['logs'] = [{'category': 'FrontdoorAccessLog', 'enabled': True}]
    assert run(mod.ACCESS_LOG, row)[0] == 'PASS'
    setting['properties']['workspaceId'] = None
    assert run(mod.ACCESS_LOG, row)[0] == 'FAIL'
    row['_coverage']['diagnosticCategories']['status'] = 'partial'
    assert run(mod.ACCESS_LOG, row)[0] == 'UNKNOWN'


def test_query_storage_cmk_link_and_usable_access():
    row, extras, policy = fixture(mod.QUERY_CMK)
    account = extras['storage_account'][0]
    account['cmkAccess']['keyUsable'] = False
    assert run(mod.QUERY_CMK, row, extras, policy)[0] == 'UNKNOWN'
    row['queryLinkedStorage']['properties']['storageAccountIds'] = []
    assert run(mod.QUERY_CMK, row, extras, policy)[0] == 'FAIL'
    policy[mod.QUERY_CMK]['required'] = False
    assert run(mod.QUERY_CMK, row, extras, policy)[0] == 'NOT_APPLICABLE'


def test_cluster_cmk_no_link_access_approval_and_state():
    row, extras, policy = fixture(mod.CLUSTER_CMK)
    cluster = extras['log_analytics_cluster'][0]
    cluster['cmkAccess']['principal_id'] = 'other'
    assert run(mod.CLUSTER_CMK, row, extras, policy)[0] == 'UNKNOWN'
    cluster['cmkAccess']['principal_id'] = 'identity'
    cluster['properties']['provisioningState'] = 'Updating'
    assert run(mod.CLUSTER_CMK, row, extras, policy)[0] == 'UNKNOWN'
    row['properties']['features']['clusterResourceId'] = None
    assert run(mod.CLUSTER_CMK, row, extras, policy)[0] == 'FAIL'
    assert run(mod.CLUSTER_CMK, row, extras)[0] == 'UNKNOWN'


def test_expiry_partial_zero_and_expired_event_positive_evidence():
    row, extras, policy = fixture(mod.EXPIRY)
    query = row['expiryQueries']['queries'][0]
    query['allRetainedTiers'] = False
    assert run(mod.EXPIRY, row, extras, policy)[0] == 'UNKNOWN'
    query.update(expiredEventCount=1, expiredEventTimes=['2026-01-01T00:00:00Z'])
    assert run(mod.EXPIRY, row, extras, policy)[0] == 'FAIL'
    query['cutoff'] = NOW
    assert run(mod.EXPIRY, row, extras, policy)[0] == 'UNKNOWN'


def test_c5_configuration_signals_do_not_replace_required_controls():
    row, extras, policy = fixture(mod.C5_LOGS)
    row['properties'].update(publicNetworkAccessForIngestion='Enabled', publicNetworkAccessForQuery='Enabled', retentionInDays=7)
    assert run(mod.C5_LOGS, row, extras, policy)[0] == 'PASS'
    row.pop('logProtectionMeasures')
    assert run(mod.C5_LOGS, row, extras, policy)[0] == 'UNKNOWN'
    row, extras, policy = fixture(mod.C5_LOGS)
    row['logProtectionMeasures']['measures'].pop()
    assert run(mod.C5_LOGS, row, extras, policy)[0] == 'UNKNOWN'


def test_complete_empty_workspace_cluster_scope_not_applicable():
    row = workspace()
    facts = inventory(row, 'log_analytics_workspace')
    facts['collections']['log_analytics_workspace'][0].update(status='empty', items=[])
    facts['log_analytics_workspace'] = []
    assert mod.EVALUATORS[mod.CLUSTER_CMK](facts['context'], facts)[0] == 'NOT_APPLICABLE'
    facts['collections']['log_analytics_workspace'][0]['status'] = 'partial'
    assert mod.EVALUATORS[mod.CLUSTER_CMK](facts['context'], facts)[0] == 'UNKNOWN'


def test_foreign_child_type_and_blocked_mfa_context_unknown():
    row, extras, _ = fixture(mod.ALL_MFA)
    extras['conditional_access_policy'][0]['grantControls']['builtInControls'] = ['block']
    assert run(mod.ALL_MFA, row, extras)[0] == 'UNKNOWN'
    row, _, _ = fixture(mod.REDIRECT)
    row['effectiveRoutes'][0]['type'] = 'Foreign/routingRules'
    assert run(mod.REDIRECT, row)[0] == 'UNKNOWN'


def test_cluster_all_workspaces_policy_map_and_unknown_precedence():
    row, extras, policy = fixture(mod.CLUSTER_CMK)
    second = copy.deepcopy(row)
    second['id'] = row['id'].replace('/ws', '/second')
    entry = policy[mod.CLUSTER_CMK]
    policy[mod.CLUSTER_CMK] = {'resources': {row['id']: entry, second['id']: {**entry, 'resource_id': second['id']}}}
    facts = inventory(row, 'log_analytics_workspace', extras=extras, policy=policy)
    facts['collections']['log_analytics_workspace'][0]['items'].append(second)
    facts['log_analytics_workspace'].append({'type': 'log_analytics_workspace', 'scope': SCOPE, 'data': second})
    assert mod.EVALUATORS[mod.CLUSTER_CMK](facts['context'], facts)[0] == 'PASS'
    second['properties']['features']['clusterResourceId'] = None
    assert mod.EVALUATORS[mod.CLUSTER_CMK](facts['context'], facts)[0] == 'FAIL'
    second['properties']['features'].pop('clusterResourceId')
    assert mod.EVALUATORS[mod.CLUSTER_CMK](facts['context'], facts)[0] == 'UNKNOWN'


def test_direct_foreign_tenant_and_unbound_arm_subscription():
    row, _, _ = fixture(mod.DIRECT, True)
    assignment = row['directAssignments']['assignments'][0]
    assignment['scope'] = '/tenants/foreign'
    row['directAssignments']['hierarchyScopeIds'].append('/tenants/foreign')
    assert run(mod.DIRECT, row)[0] == 'UNKNOWN'
    assignment.update(source='azureRbac', scope='/subscriptions/other')
    row['directAssignments']['hierarchyScopeIds'].append('/subscriptions/other')
    assert run(mod.DIRECT, row)[0] == 'UNKNOWN'


def test_c5_unsupported_configuration_enum_unknown_and_measure_violation():
    row, extras, policy = fixture(mod.C5_LOGS)
    row['properties']['publicNetworkAccessForQuery'] = 'futureEnum'
    assert run(mod.C5_LOGS, row, extras, policy)[0] == 'UNKNOWN'
