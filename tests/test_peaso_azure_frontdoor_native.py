"""Native ARM edge inventories and conservative effective-route boundaries."""
import copy
import pytest
from test_peaso_collector_swc2_azure_native import Fixture, ReadError
from peaso.collectors import azure
from peaso.collectors import azure_frontdoor_native as native
from peaso.snapshot import validate
from peaso.engine import evaluate_snapshot

SCOPE = '/subscriptions/11111111-1111-1111-1111-111111111111'
ROOT = SCOPE + '/resourceGroups/rg/providers/'

PROFILE = ROOT + 'Microsoft.Cdn/profiles/edge'
CLASSIC = ROOT + 'Microsoft.Network/frontDoors/classic'


def arm(rid, properties=None, **extra):
    parts = rid.rsplit('/providers/', 1)[-1].split('/')
    return {'id': rid, 'name': parts[-1], 'type': '/'.join([parts[0], *parts[1::2]]),
            'properties': {} if properties is None else properties, **extra}


def base_routes(family='afd', redirect='Enabled', forwarding='HttpsOnly'):
    paths = {}
    classic_list = SCOPE + '/providers/Microsoft.Network/frontDoors'
    profile_list = SCOPE + '/providers/Microsoft.Cdn/profiles'
    paths[classic_list] = {'value': []}
    paths[profile_list] = {'value': []}
    if family == 'classic':
        domain = arm(CLASSIC + '/frontendEndpoints/site', {'hostName': 'example.test',
            'customHttpsProvisioningState': 'Enabled', 'customHttpsConfiguration': {
                'certificateSource': 'AzureKeyVault', 'protocolType': 'ServerNameIndication', 'minimumTlsVersion': '1.2'}})
        pool = arm(CLASSIC + '/backendPools/pool', {'backends': [{'address': 'example.test'}]})
        rule = arm(CLASSIC + '/routingRules/default', {'acceptedProtocols': ['Http', 'Https'],
            'enabledState': 'Enabled', 'patternsToMatch': ['/*'], 'frontendEndpoints': [{'id': domain['id']}],
            'routeConfiguration': {'@odata.type': '#Microsoft.Azure.FrontDoor.Models.FrontdoorRedirectConfiguration',
                                   'redirectProtocol': 'HttpsOnly'}})
        parent = arm(CLASSIC, {'enabledState': 'Enabled', 'frontendEndpoints': [domain],
                               'routingRules': [rule], 'backendPools': [pool]})
        paths[classic_list] = {'value': [parent]};paths[CLASSIC] = parent
        return paths, parent
    parent = arm(PROFILE, sku={'name': 'Standard_AzureFrontDoor' if family == 'afd' else 'Standard_Microsoft'})
    paths[profile_list] = {'value': [parent]};paths[PROFILE] = parent
    endpoint = arm(PROFILE + ('/afdEndpoints/default' if family == 'afd' else '/endpoints/default'),
                   {'hostName': 'owned.azurefd.net', 'enabledState': 'Enabled', 'resourceState': 'Running', 'isHttpAllowed': True, 'isHttpsAllowed': True})
    child_path = '/afdEndpoints' if family == 'afd' else '/endpoints'
    paths[PROFILE + child_path] = {'value': [endpoint]};paths[endpoint['id']] = endpoint
    if family == 'afd':
        group = arm(PROFILE + '/originGroups/default', {'healthProbeSettings': {'probeProtocol': 'Https'}})
        origin = arm(group['id'] + '/origins/default', {'hostName': 'example.test', 'enabledState': 'Enabled'})
        route = arm(endpoint['id'] + '/routes/default', {'supportedProtocols': ['Http', 'Https'], 'enabledState': 'Enabled',
            'forwardingProtocol': forwarding, 'httpsRedirect': redirect, 'patternsToMatch': ['/*'],
            'customDomains': [], 'linkToDefaultDomain': 'Enabled', 'ruleSets': [], 'originGroup': {'id': group['id']}})
        for path, values in [(PROFILE + '/customDomains', []), (PROFILE + '/securityPolicies', []),
                             (PROFILE + '/originGroups', [group]), (endpoint['id'] + '/routes', [route]),
                             (group['id'] + '/origins', [origin])]:
            paths[path] = {'value': values}
            paths.update({r['id']: r for r in values})
    else:
        domain = arm(endpoint['id'] + '/customDomains/site', {'hostName': 'example.test',
            'customHttpsProvisioningState': 'Enabled', 'customHttpsParameters': {
                'certificateSource': 'AzureKeyVault', 'protocolType': 'ServerNameIndication', 'minimumTlsVersion': 'TLS12'}})
        paths[endpoint['id'] + '/customDomains'] = {'value': [domain]};paths[domain['id']] = domain
    return paths, parent


def collect(paths, kinds=None, **options):
    fixture = Fixture(paths)
    result = azure.collect({'scopes': [SCOPE.rsplit('/', 1)[-1]], 'options': {'retries': 0, **options}},
        ['frontdoor_and_cdn_endpoint'] if kinds is None else kinds, transport=fixture)
    assert validate(result) == result
    return result, fixture


def collection(result, kind):
    return next(c for c in result['collections'] if c['scope'] == SCOPE and c['type'] == kind)


@pytest.mark.parametrize('family', ['classic', 'afd', 'cdn'])
def test_native_three_edge_generations_keep_real_domains_and_children(family):
    paths, parent = base_routes(family)
    result, fixture = collect(paths)
    rows = collection(result, 'frontdoor_and_cdn_endpoint')
    assert rows['status'] == 'collected' and len(rows['items']) == 1
    item = rows['items'][0]
    assert item['id'] == parent['id'] and item['_coverage']['domains']['status'] in ('collected', 'empty')
    assert all(row['parent_id'] == parent['id'] for row in item['domains'])
    assert all(call[2] == azure.ARM for call in fixture.calls)
    assert item['_coverage']['effectiveRoutes']['status'] == 'collected'
    if family == 'cdn': assert item['effectiveRoutes'][0]['resolved']['originPolicy'] is False


@pytest.mark.parametrize('redirect,forwarding,expected', [('Enabled', 'HttpsOnly', 'PASS'),
    ('Disabled', 'HttpsOnly', 'FAIL'), ('Enabled', 'HttpOnly', 'PASS')])
def test_afd_native_https_redirect_reaches_real_check(redirect, forwarding, expected):
    paths, _ = base_routes('afd', redirect, forwarding)
    result, _ = collect(paths)
    finding = evaluate_snapshot(result, checks=['azure_frontdoor_app_ensure_http_is_redirected_to_https_517a3c9'])['findings'][0]
    assert finding['status'] == expected


@pytest.mark.parametrize('forwarding,expected', [('HttpsOnly', 'PASS'), ('HttpOnly', 'FAIL'), ('MatchRequest', 'PASS')])
def test_afd_native_origin_forwarding_reaches_real_check(forwarding, expected):
    paths, _ = base_routes('afd', 'Enabled', forwarding)
    result, _ = collect(paths)
    finding = evaluate_snapshot(result, checks=['azure_frontdoor_network_http_internet_access_restricted_7004685'])['findings'][0]
    assert finding['status'] == expected


@pytest.mark.parametrize('mode', ['rules', 'partial_paths', 'multiple_routes', 'missing_origin_group', 'unassociated', 'foreign_domain'])
def test_ambiguous_effective_paths_never_manufacture_pass_or_fail(mode):
    paths, _ = base_routes()
    rid = PROFILE + '/afdEndpoints/default/routes/default'
    row = paths[rid];props = row['properties']
    if mode == 'rules':props['ruleSets'] = [{'id': PROFILE + '/ruleSets/conditional'}]
    if mode == 'partial_paths':props['patternsToMatch'] = ['/private/*']
    if mode == 'missing_origin_group':props['originGroup']['id'] = PROFILE + '/originGroups/foreign'
    if mode == 'unassociated':props['linkToDefaultDomain'] = 'Disabled'
    if mode == 'foreign_domain':props['customDomains'] = [{'id': PROFILE.replace('11111111-1111-1111-1111-111111111111', '22222222-2222-2222-2222-222222222222') + '/customDomains/site'}]
    if mode == 'multiple_routes':
        other = copy.deepcopy(row);other['id'] += '-other';paths[other['id']] = other
        paths[PROFILE + '/afdEndpoints/default/routes']['value'].append(other)
    result, _ = collect(paths)
    assert collection(result, 'frontdoor_and_cdn_endpoint')['items'][0]['_coverage']['effectiveRoutes']['status'] == 'not_collected'
    for cid in ['azure_frontdoor_app_ensure_http_is_redirected_to_https_517a3c9', 'azure_frontdoor_network_http_internet_access_restricted_7004685']:
        assert evaluate_snapshot(result, checks=[cid])['findings'][0]['status'] == 'UNKNOWN'


@pytest.mark.parametrize('mode', ['parent_denied', 'child_denied', 'foreign_parent', 'foreign_child', 'duplicate_child', 'missing_child_properties'])
def test_native_edge_scope_failures_are_not_empty_or_complete(mode):
    paths, _ = base_routes()
    endpoint = PROFILE + '/afdEndpoints/default'
    if mode == 'parent_denied':paths[SCOPE + '/providers/Microsoft.Cdn/profiles'] = ReadError(403)
    elif mode == 'child_denied':paths[PROFILE + '/afdEndpoints'] = ReadError(403)
    elif mode == 'foreign_parent':paths[SCOPE + '/providers/Microsoft.Cdn/profiles']['value'][0]['id'] = PROFILE.replace('11111111-1111-1111-1111-111111111111', '22222222-2222-2222-2222-222222222222')
    elif mode == 'foreign_child':paths[PROFILE + '/afdEndpoints']['value'][0]['id'] = endpoint.replace('11111111-1111-1111-1111-111111111111', '22222222-2222-2222-2222-222222222222')
    elif mode == 'duplicate_child':paths[PROFILE + '/afdEndpoints']['value'] *= 2
    elif mode == 'missing_child_properties':paths[endpoint].pop('properties')
    result, _ = collect(paths)
    assert collection(result, 'frontdoor_and_cdn_endpoint')['status'] not in ('collected', 'empty')


def test_native_empty_universe_requires_both_product_family_lists():
    result, fixture = collect({})
    assert collection(result, 'frontdoor_and_cdn_endpoint')['status'] == 'empty'
    paths = [call[0] for call in fixture.calls]
    assert any('/Microsoft.Network/frontDoors?' in path for path in paths)
    assert any('/Microsoft.Cdn/profiles?' in path for path in paths)


@pytest.mark.parametrize('family,version,expected', [('classic', '1.2', 'PASS'), ('classic', '1.0', 'FAIL'),
    ('cdn', 'TLS12', 'PASS'), ('cdn', 'TLS10', 'FAIL')])
def test_native_custom_domain_tls_and_sni_are_not_api_generation_aliases(family, version, expected):
    paths, parent = base_routes(family)
    if family == 'classic':
        domain = parent['properties']['frontendEndpoints'][0]
        domain['properties']['customHttpsConfiguration']['minimumTlsVersion'] = version
    else:
        domain = paths[PROFILE + '/endpoints/default/customDomains/site']
        domain['properties']['customHttpsParameters']['minimumTlsVersion'] = version
    result, _ = collect(paths)
    assert evaluate_snapshot(result, checks=['azure_frontdoor_app_minimum_tls_version_12_0512053'])['findings'][0]['status'] == expected
    assert evaluate_snapshot(result, checks=['azure_frontdoor_1_2_5_4_ccc7b8f'])['findings'][0]['status'] == 'PASS'


@pytest.mark.parametrize('family', ['classic', 'afd', 'cdn'])
@pytest.mark.parametrize('enabled,expected', [(True, 'PASS'), (False, 'FAIL')])
def test_native_access_log_category_and_destination_configuration(family, enabled, expected):
    paths, parent = base_routes(family)
    category = arm(parent['id'] + '/providers/Microsoft.Insights/diagnosticSettingsCategories/' +
        ('FrontdoorAccessLog' if family == 'classic' else 'FrontDoorAccessLog' if family == 'afd' else 'AzureCdnAccessLog'),
        {'categoryType': 'Logs'})
    setting = arm(parent['id'] + '/providers/Microsoft.Insights/diagnosticSettings/export',
        {'logs': [{'category': category['name'], 'enabled': enabled}],
         'workspaceId': ROOT + 'Microsoft.OperationalInsights/workspaces/owned'})
    for path, row in [('diagnosticSettingsCategories', category), ('diagnosticSettings', setting)]:
        paths[parent['id'] + '/providers/Microsoft.Insights/' + path] = {'value': [row]}
        paths[row['id']] = row
    result, _ = collect(paths)
    assert evaluate_snapshot(result, checks=['azure_frontdoor_monitor_storage_account_with_activity_logs_is_private_d42518a'])['findings'][0]['status'] == expected


def test_native_classic_headers_and_free_text_are_never_retained():
    paths, parent = base_routes('classic')
    parent['properties']['routingRules'][0]['properties']['routeConfiguration']['headers'] = [{'headerName': 'Authorization', 'value': 'PRIVATE_CREDENTIAL_MARKER'}]
    parent['properties']['rulesEngines'] = [{'rules': [{'actions': [{'headerName': 'Authorization', 'value': 'PRIVATE_CREDENTIAL_MARKER'}]}]}]
    parent['properties']['description'] = 'PRIVATE_CREDENTIAL_MARKER'
    result, _ = collect(paths)
    assert 'PRIVATE_CREDENTIAL_MARKER' not in str(result)


@pytest.mark.parametrize('bad_name', ['..', '%2e%2e', 'a%2fb', 'a\\b'])
def test_provider_child_paths_cannot_escape_the_bound_parent(bad_name):
    paths, _ = base_routes()
    paths[PROFILE + '/afdEndpoints']['value'][0]['id'] = PROFILE + '/afdEndpoints/' + bad_name
    result, fixture = collect(paths)
    assert collection(result, 'frontdoor_and_cdn_endpoint')['status'] not in ('collected', 'empty')
    assert not any('/afdEndpoints/' + bad_name + '?' in row[0] for row in fixture.calls)


def test_afd_routes_security_policy_and_waf_are_shared_native_inventories():
    paths, _ = base_routes()
    endpoint = PROFILE + '/afdEndpoints/default'
    waf_id = ROOT + 'Microsoft.Network/frontDoorWebApplicationFirewallPolicies/owned'
    waf = arm(waf_id, {'policySettings': {'enabledState': 'Enabled', 'mode': 'Prevention'}})
    paths[SCOPE + '/providers/Microsoft.Network/frontDoorWebApplicationFirewallPolicies'] = {'value': [waf]}
    paths[waf_id] = waf
    policy = arm(PROFILE + '/securityPolicies/owned', {'parameters': {'type': 'WebApplicationFirewall',
        'wafPolicy': {'id': waf_id}, 'associations': [{'domains': [{'id': endpoint}], 'patternsToMatch': ['/*']}]}})
    paths[PROFILE + '/securityPolicies'] = {'value': [policy]};paths[policy['id']] = policy
    kinds = ['afd_profile', 'afd_domain', 'afd_route', 'afd_security_policy', 'frontdoor_waf_policy']
    result, _ = collect(paths, kinds)
    assert evaluate_snapshot(result, checks=['azure_frontdoor_1_2_8_4_90159db'])['findings'][0]['status'] == 'PASS'
    paths[policy['id']]['properties']['parameters']['associations'][0]['patternsToMatch'] = ['/other']
    result, _ = collect(paths, kinds)
    assert evaluate_snapshot(result, checks=['azure_frontdoor_1_2_8_4_90159db'])['findings'][0]['status'] == 'UNKNOWN'
    paths[policy['id']]['properties']['parameters']['associations'][0]['patternsToMatch'] = []
    result, _ = collect(paths, kinds)
    assert evaluate_snapshot(result, checks=['azure_frontdoor_1_2_8_4_90159db'])['findings'][0]['status'] == 'UNKNOWN'


def test_afd_public_route_without_waf_is_a_native_fail():
    paths, _ = base_routes()
    result, _ = collect(paths, ['afd_profile', 'afd_domain', 'afd_route', 'afd_security_policy', 'frontdoor_waf_policy'])
    assert evaluate_snapshot(result, checks=['azure_frontdoor_1_2_8_4_90159db'])['findings'][0]['status'] == 'FAIL'


@pytest.mark.parametrize('http,expected', [(True, 'FAIL'), (False, 'PASS')])
def test_classic_cdn_http_listener_has_independent_native_proof(http, expected):
    paths, _ = base_routes('cdn')
    endpoint = paths[PROFILE + '/endpoints/default']
    endpoint['properties']['isHttpAllowed'] = http
    result, _ = collect(paths)
    assert evaluate_snapshot(result, checks=['azure_frontdoor_app_ensure_http_is_redirected_to_https_517a3c9'])['findings'][0]['status'] == expected
    assert evaluate_snapshot(result, checks=['azure_frontdoor_network_http_internet_access_restricted_7004685'])['findings'][0]['status'] == 'UNKNOWN'


def test_classic_cdn_conditional_delivery_rule_cannot_certify_unresolved_paths():
    paths, _ = base_routes('cdn')
    endpoint = paths[PROFILE + '/endpoints/default']
    endpoint['properties']['deliveryPolicy'] = {'rules': [{'order': 1, 'actions': [{'name': 'ModifyRequestHeader', 'parameters': {'headerName': 'Authorization', 'value': 'PRIVATE_CREDENTIAL_MARKER'}}]}]}
    result, _ = collect(paths)
    assert evaluate_snapshot(result, checks=['azure_frontdoor_app_ensure_http_is_redirected_to_https_517a3c9'])['findings'][0]['status'] == 'UNKNOWN'
    assert 'PRIVATE_CREDENTIAL_MARKER' not in str(result)


@pytest.mark.parametrize('certificate_type,active,expected', [('CustomerCertificate', True, 'PASS'),
    ('ManagedCertificate', True, 'FAIL'), ('CustomerCertificate', False, 'UNKNOWN')])
def test_real_afd_certificate_model_uses_customer_certificate_type(certificate_type, active, expected):
    paths, _ = base_routes()
    domain = arm(PROFILE + '/customDomains/site', {'hostName': 'example.test', 'provisioningState': 'Succeeded',
        'deploymentStatus': 'Succeeded' if active else 'InProgress', 'domainValidationState': 'Approved',
        'tlsSettings': {'certificateType': certificate_type, 'cipherSuiteSetType': 'Customized', 'minimumTlsVersion': 'TLS12'}})
    paths[PROFILE + '/customDomains'] = {'value': [domain]};paths[domain['id']] = domain
    result, _ = collect(paths, ['cdn_profile'])
    assert evaluate_snapshot(result, checks=['azure_cdn_profile_1_2_8_5_ed953a0'])['findings'][0]['status'] == expected


def test_blob_origin_identity_check_does_not_treat_classic_cdn_as_unknown_afd():
    paths, _ = base_routes('cdn')
    result, _ = collect(paths, ['cdn_profile'])
    assert evaluate_snapshot(result, checks=['azure_cdn_profile_10_3_4_1_4e40487'])['findings'][0]['status'] == 'NOT_APPLICABLE'


@pytest.mark.parametrize('family', ['classic', 'cdn'])
def test_explicit_disabled_custom_https_is_failure_without_invented_certificate_fields(family):
    paths, parent = base_routes(family)
    domain = parent['properties']['frontendEndpoints'][0] if family == 'classic' else paths[PROFILE + '/endpoints/default/customDomains/site']
    domain['properties'] = {'hostName': 'example.test', 'customHttpsProvisioningState': 'Disabled'}
    result, _ = collect(paths)
    assert evaluate_snapshot(result, checks=['azure_frontdoor_1_2_5_4_ccc7b8f'])['findings'][0]['status'] == 'FAIL'
    assert evaluate_snapshot(result, checks=['azure_frontdoor_app_minimum_tls_version_12_0512053'])['findings'][0]['status'] == 'NOT_APPLICABLE'


@pytest.mark.parametrize('mode,expected', [('allow', 'PASS'), ('no_auth', 'FAIL'), ('no_read', 'FAIL'),
    ('condition', 'UNKNOWN'), ('deny', 'UNKNOWN'), ('foreign_account', 'UNKNOWN'), ('foreign_container', 'UNKNOWN'),
    ('foreign_role', 'UNKNOWN'), ('foreign_subject', 'UNKNOWN'), ('group', 'PASS'), ('private_link', 'FAIL'),
    ('http_origin', 'FAIL'), ('http_probe', 'FAIL'), ('not_data_action', 'FAIL'), ('wrong_header', 'FAIL')])
def test_blob_origin_identity_uses_real_arm_container_and_target_rbac(mode, expected):
    from urllib.parse import parse_qs, urlsplit
    paths, parent = base_routes()
    principal = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
    role = 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb'
    parent['identity'] = {'type': 'SystemAssigned', 'principalId': principal}
    group_id = PROFILE + '/originGroups/default'
    origin = paths[group_id + '/origins/default']
    origin['properties']['hostName'] = 'ownedacct.blob.core.windows.net'
    if mode == 'private_link':origin['properties']['sharedPrivateLinkResource'] = {'privateLink': {'id': ROOT + 'Microsoft.Storage/storageAccounts/ownedacct'}}
    group = paths[group_id]
    if mode != 'no_auth':group['properties']['authentication'] = {'type': 'SystemAssignedIdentity', 'scope': 'https://storage.azure.com/.default'}
    if mode == 'wrong_header':group['properties']['authentication']['tokenDestinationHeader'] = 'X-Azure-Authorization'
    if mode == 'http_probe':group['properties']['healthProbeSettings']['probeProtocol'] = 'Http'
    route = paths[PROFILE + '/afdEndpoints/default/routes/default'];route['properties']['originPath'] = '/container'
    if mode == 'http_origin':route['properties']['forwardingProtocol'] = 'HttpOnly'
    account = arm(ROOT + 'Microsoft.Storage/storageAccounts/ownedacct', {'primaryEndpoints': {'blob': 'https://ownedacct.blob.core.windows.net/'}})
    if mode == 'foreign_account':account['id'] = account['id'].replace('11111111-1111-1111-1111-111111111111','22222222-2222-2222-2222-222222222222')
    container_id = account['id'] + '/blobServices/default/containers/container'
    paths[SCOPE + '/providers/Microsoft.Storage/storageAccounts'] = {'value': [account]}
    container = arm(container_id)
    if mode == 'foreign_container':container['id'] += 'foreign'
    paths[container_id] = container
    role_id = SCOPE + '/providers/Microsoft.Authorization/roleDefinitions/' + role
    assignment = arm(container_id + '/providers/Microsoft.Authorization/roleAssignments/' + role,
        {'scope': container_id, 'principalId': principal, 'principalType': 'ServicePrincipal', 'roleDefinitionId': role_id})
    if mode == 'condition':assignment['properties']['condition'] = 'opaque ABAC condition'
    if mode == 'foreign_subject':assignment['properties']['principalId'] = role
    if mode == 'group':assignment['properties'].update(principalId=role, principalType='Group')
    paths[container_id + '/providers/Microsoft.Authorization/roleAssignments'] = {'value': [assignment]}
    paths[container_id + '/providers/Microsoft.Authorization/denyAssignments'] = {'value': [{'id': 'any'}] if mode == 'deny' else []}
    permission = {'dataActions': ['Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read'] if mode != 'no_read' else [], 'notDataActions': ['*'] if mode == 'not_data_action' else []}
    definition = {'id': role_id, 'properties': {'permissions': [permission]}}
    if mode == 'foreign_role':definition['id'] += 'foreign'
    paths[role_id] = definition
    result, fixture = collect(paths, ['cdn_profile'])
    finding = evaluate_snapshot(result, checks=['azure_cdn_profile_10_3_4_1_4e40487'])['findings'][0]
    assert finding['status'] == expected, finding['evidence']
    filtered = [call for call in fixture.calls if '/roleAssignments?' in call[0] and container_id in call[0]]
    if filtered:
        assert parse_qs(urlsplit(filtered[0][0]).query)['$filter'] == ["atScope() and assignedTo('" + principal + "')"]
    assert not any('blob.core.windows.net/' in call[0] for call in fixture.calls)
    assert all('api-version=2026-07-01' in call[0] for call in fixture.calls if '/originGroups?' in call[0] or '/originGroups/default?' in call[0])


@pytest.mark.parametrize('reverse', [False, True])
def test_shared_origin_group_different_container_paths_cannot_reuse_last_route_grant(reverse):
    paths, parent = base_routes()
    group = PROFILE + '/originGroups/default'
    paths[group + '/origins/default']['properties']['hostName'] = 'ownedacct.blob.core.windows.net'
    route = paths[PROFILE + '/afdEndpoints/default/routes/default']
    route['properties']['originPath'] = '/first-container'
    other = copy.deepcopy(route)
    other['id'] = other['id'].replace('/routes/default', '/routes/other')
    other['properties']['originPath'] = '/second-container'
    paths[other['id']] = other
    routes = [route, other]
    paths[PROFILE + '/afdEndpoints/default/routes'] = {'value': list(reversed(routes)) if reverse else routes}
    result, fixture = collect(paths, ['cdn_profile'])
    item = collection(result, 'cdn_profile')['items'][0]
    assert all(r['originAuthenticationPrerequisites']['status'] == 'not_collected' for r in item['routes'])
    assert all(o['blobContainerEvidence']['status'] == 'not_collected' for g in item['originGroups'] for o in g['origins'])
    finding = evaluate_snapshot(result, checks=['azure_cdn_profile_10_3_4_1_4e40487'])['findings'][0]
    assert finding['status'] == 'UNKNOWN', finding['evidence']
    assert not any('/roleAssignments?' in call[0] for call in fixture.calls)
