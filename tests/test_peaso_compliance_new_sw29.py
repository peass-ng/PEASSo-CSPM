"""Isolated signed Azure wave-2 evaluator cases."""
import pytest
from peaso.checks import CHECKS, evaluate_check
from peaso.checks import compliance_new_sw29 as sw

SCOPE = '/subscriptions/sub'
ML = SCOPE + '/resourceGroups/rg/providers/Microsoft.MachineLearningServices/workspaces/ws/computes/c1'
GW = SCOPE + '/resourceGroups/rg/providers/Microsoft.Network/applicationGateways/g1'
PG = SCOPE + '/resourceGroups/rg/providers/Microsoft.DBforPostgreSQL/servers/p1'
SUBNET = SCOPE + '/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/v1/subnets/s1'
NOW = '2026-10-12T12:00:00+00:00'

@pytest.fixture(scope='module', autouse=True)
def cleanup_registry():
    yield
    CHECKS[:] = [c for c in CHECKS if c.id not in sw.SPECS]


def proof(rid, **fields):
    return {'status': 'collected', 'read_only': True, 'resource_id': rid, **fields}


def base(kind):
    if kind == 'ml_compute':
        return {'id': ML, '_provenance': {'source_operation': 'LIST', 'read_only': True},
                'properties': {'computeType': 'ComputeInstance', 'properties': {
                    'enableNodePublicIp': True, 'subnet': {'id': SUBNET}}}}
    if kind == 'application_gateway':
        return {'id': GW, '_provenance': {'source_operation': 'GET', 'read_only': True},
                'properties': {'httpListeners': [], 'sslProfiles': [], 'sslCertificates': []}}
    return {'id': PG, '_provenance': {'source_operation': 'GET', 'read_only': True},
            'properties': {'sslEnforcement': 'Enabled', 'infrastructureEncryption': 'Enabled'},
            '_coverage': {'configurations': {'status': 'collected'}},
            'configurations': [{'id': PG + '/configurations/log_retention_days',
                                'name': 'log_retention_days', 'properties': {'value': '4'}}]}


def index(kind, item):
    policy = lambda **values: {'status': 'collected', 'read_only': True, 'scope': SCOPE, **values}
    context = {'provider': 'azure', 'scope': SCOPE, 'created_at': NOW,
               'metadata': {'sw29': {
                   'classification': policy(assignments=[{'resource_id': ML, 'classification': 'non_sensitive'}]),
                   'approvedNetworkBaseline': policy(approved_sensitive_subnet_ids=[SUBNET],
                                                     required_control_names=['nsg_rules', 'routes', 'private_access']),
                   'approvedSslPolicy': policy(minimum_protocol='TLSv1_2', approved_cipher_suites=['TLS_AES_128_GCM_SHA256'])}}}
    return {'context': context,
            'collections': {kind: [{'type': kind, 'scope': SCOPE, 'status': 'collected', 'items': [item]}]},
            kind: [{'type': kind, 'scope': SCOPE, 'data': item}]}


def listener(name, protocol='Https', **properties):
    return {'id': GW + '/httpListeners/' + name, 'properties': {'protocol': protocol, **properties}}


def case(check_id):
    kind = sw.SPECS[check_id]['resource_kind']
    item = base(kind)
    idx = index(kind, item)
    evidence = item.setdefault('sw29Evidence', {})
    if check_id.endswith('double_encryption_postgresql_single_server'):
        fail = lambda: item['properties'].update(infrastructureEncryption='Disabled')
        malformed = lambda: item['properties'].update(infrastructureEncryption='Else')
    elif check_id.endswith('postgresql_single_log_retention_days'):
        fail = lambda: item['configurations'][0]['properties'].update(value='3')
        malformed = lambda: item['configurations'][0]['properties'].update(value='three')
    elif check_id.endswith('postgresql_single_ssl_enforcement'):
        fail = lambda: item['properties'].update(sslEnforcement='Disabled')
        malformed = lambda: item['properties'].update(sslEnforcement='Else')
    elif check_id.endswith('ml_public_access_exception'):
        evidence['publicAccess'] = proof(ML, exception_registry_complete=True,
            exceptions=[{'resource_id': ML, 'approved': True, 'expires_at': '2026-10-13T00:00:00+00:00'}],
            network_policy_complete=True, effective_paths_complete=True,
            effective_ingress_paths=[{'complies_with_approved_controls': True}])
        fail = lambda: evidence['publicAccess'].update(exceptions=[])
        malformed = lambda: evidence['publicAccess'].update(effective_ingress_paths='bad')
    elif check_id.endswith('ml_root_exception'):
        evidence['rootAccess'] = proof(ML, root_enabled=False, managed_nodes_complete=True)
        fail = lambda: evidence['rootAccess'].update(root_enabled=True, exception_registry_complete=True, exceptions=[])
        malformed = lambda: evidence['rootAccess'].update(root_enabled='no')
    elif check_id.endswith('ml_terminal_exception'):
        evidence['terminalAccess'] = proof(ML, effective_access_complete=True, terminal_enabled=False)
        fail = lambda: evidence['terminalAccess'].update(terminal_enabled=True, sessions_complete=True,
                                                       exception_registry_complete=True, sessions=[], exceptions=[])
        malformed = lambda: evidence['terminalAccess'].update(terminal_enabled='no')
    elif check_id.endswith('ml_sensitive_subnet_allowlist') or check_id.endswith('ml_subnet_baseline'):
        if check_id.endswith('ml_sensitive_subnet_allowlist'):
            idx['context']['metadata']['sw29']['classification']['assignments'][0]['classification'] = 'sensitive'
        evidence['networkBaseline'] = proof(ML, subnet_id=SUBNET, subnet_get_complete=True,
            network_security_group_id=SCOPE + '/resourceGroups/rg/providers/Microsoft.Network/networkSecurityGroups/n1', baseline_complete=True,
            effective_controls=[{'name': n, 'complies': True} for n in ('nsg_rules', 'routes', 'private_access')])
        fail = lambda: evidence['networkBaseline'].update(network_security_group_id=None)
        malformed = lambda: evidence['networkBaseline'].update(subnet_id='bad')
    elif check_id.endswith('gateway_affinity_cookie_timeout'):
        evidence['affinityProbes'] = proof(GW, route_inventory_complete=True, routes=[{
            'route_id': 'r1', 'affinity_enabled': True, 'session_continuity_proven': True,
            'idle_probe_complete': True, 'idle_seconds': 1801, 'same_session_accepted': False}])
        fail = lambda: evidence['affinityProbes']['routes'][0].update(same_session_accepted=True)
        malformed = lambda: evidence['affinityProbes']['routes'][0].update(idle_seconds='late')
    elif check_id.endswith('gateway_client_rate_limit'):
        evidence['rateLimit'] = proof(GW, public_exposure_measured=True, public=True,
            effective_policy_complete=True, rules_and_priority_complete=True,
            effective_rules=[{'policy_mode': 'Prevention', 'rule_type': 'RateLimitRule',
                              'action': 'Block', 'duration': 'FiveMins', 'threshold': 2000,
                              'group_by': 'ClientAddr', 'effective_conditions_verified': True,
                              'not_shadowed': True}], runtime_window_complete=True,
            sliding_five_minute_limit_enforced=True, measured_block_seconds=60)
        fail = lambda: evidence['rateLimit'].update(measured_block_seconds=30)
        malformed = lambda: evidence['rateLimit'].update(measured_block_seconds='thirty')
    elif check_id.endswith('gateway_server_header_rewrite'):
        evidence['serverHeader'] = proof(GW, path_inventory_complete=True, paths=[{
            'path_id': 'route1', 'association_and_precedence_complete': True,
            'unconditional_rewrite_to_lb': True, 'runtime_sample_complete': True,
            'sampled_server_header': 'lb'}])
        fail = lambda: evidence['serverHeader']['paths'][0].update(sampled_server_header='backend')
        malformed = lambda: evidence['serverHeader']['paths'][0].update(runtime_sample_complete='yes')
    elif check_id.endswith('gateway_throttle_log_alert'):
        evidence['throttleLogs'] = proof(GW, logging_enabled=True, diagnostic_settings_complete=True,
            invocation_timeline_complete=True, log_query_complete=True,
            invocations=[{'invoked_at': '2026-10-12T11:00:00+00:00',
                          'correlated_log_at': '2026-10-12T11:04:00+00:00'}])
        fail = lambda: evidence['throttleLogs']['invocations'][0].update(correlated_log_at=None)
        malformed = lambda: evidence['throttleLogs']['invocations'][0].update(correlated_log_at='bad')
    elif check_id.endswith('lb_certificate_auto_renew'):
        evidence['certificateRenewal'] = proof(GW, bindings_and_versions_complete=True, history_complete=True,
            renewals=[{'trigger_at': '2026-10-10T00:00:00+00:00', 'expires_at': '2026-10-20T00:00:00+00:00',
                       'version_fingerprint_join_complete': True, 'listener_observations_complete': True,
                       'new_valid_version_issued_at': '2026-10-10T01:00:00+00:00',
                       'new_version_served_at': '2026-10-10T02:00:00+00:00'}])
        fail = lambda: evidence['certificateRenewal']['renewals'][0].update(new_version_served_at=None)
        malformed = lambda: evidence['certificateRenewal']['renewals'][0].update(expires_at='bad')
    elif check_id == 'azure_application_gateway_1_2_5_8_33a9d21':
        item['properties']['httpListeners'] = [listener('secure')]
        item['properties']['sslPolicy'] = {'policyType': 'Custom', 'minProtocolVersion': 'TLSv1_2',
                                          'cipherSuites': ['TLS_AES_128_GCM_SHA256']}
        evidence['frontDoorTls'] = proof(GW, family_inventory_complete=True, domains=[])
        fail = lambda: item['properties']['sslPolicy'].update(minProtocolVersion='TLSv1_0')
        malformed = lambda: item['properties']['sslPolicy'].update(minProtocolVersion='bad')
    else:
        assert check_id == 'azure_application_gateway_app_client_certificates_on_fcca0b8'
        cid = GW + '/sslCertificates/cert'
        item['properties']['httpListeners'] = [listener('secure', sslCertificate={'id': cid})]
        item['properties']['sslCertificates'] = [{'id': cid, 'properties': {
            'keyVaultSecretId': 'https://vault.vault.azure.net/secrets/cert'}}]
        evidence['certificateValidation'] = proof(GW, listeners=[{'listener_id': GW + '/httpListeners/secure',
            'key_vault_accessible': True, 'certificate_valid': True, 'chain_trusted': True}])
        fail = lambda: item['properties']['sslCertificates'][0]['properties'].update(keyVaultSecretId='')
        malformed = lambda: item['properties']['sslCertificates'][0]['properties'].update(keyVaultSecretId='bad')
    # The native envelope and data wrapper share the same object; mutations stay source-bound.
    return item, idx, fail, malformed


@pytest.mark.parametrize('check_id', sorted(sw.SPECS))
def test_pass_fail_unknown_per_signed_id(check_id):
    item, idx, fail, malformed = case(check_id)
    assert evaluate_check(check_id, item, idx)[0] == 'PASS'
    bad_item, bad_idx, bad, _ = case(check_id)
    bad()
    assert evaluate_check(check_id, bad_item, bad_idx)[0] == 'FAIL'
    malformed_item, malformed_idx, _, corrupt = case(check_id)
    corrupt()
    assert evaluate_check(check_id, malformed_item, malformed_idx)[0] == 'UNKNOWN'
    missing_item, missing_idx, _, _ = case(check_id)
    if sw.SPECS[check_id]['resource_kind'] == 'postgresql_single_server':
        missing_idx['collections'].clear()
    elif sw.SPECS[check_id]['resource_kind'] == 'ml_compute':
        missing_idx['context']['metadata']['sw29'].pop('classification')
    else:
        missing_idx['collections'].clear()
    assert evaluate_check(check_id, missing_item, missing_idx)[0] == 'UNKNOWN'
    incomplete_item, incomplete_idx, _, _ = case(check_id)
    incomplete_idx['collections'][sw.SPECS[check_id]['resource_kind']][0]['status'] = 'partial'
    assert evaluate_check(check_id, incomplete_item, incomplete_idx)[0] == 'UNKNOWN'


def test_not_applicable_scopes():
    for check_id in ('azure.other.ml_public_access_exception', 'azure.other.ml_root_exception',
                     'azure.other.ml_terminal_exception', 'azure.other.ml_sensitive_subnet_allowlist',
                     'azure.other.ml_subnet_baseline', 'azure.other.gateway_affinity_cookie_timeout',
                     'azure.other.gateway_client_rate_limit', 'azure.other.lb_certificate_auto_renew',
                     'azure_application_gateway_1_2_5_8_33a9d21',
                     'azure_application_gateway_app_client_certificates_on_fcca0b8'):
        item, idx, _, _ = case(check_id)
        if check_id == 'azure.other.ml_sensitive_subnet_allowlist':
            idx['context']['metadata']['sw29']['classification']['assignments'][0]['classification'] = 'non_sensitive'
        elif check_id.endswith('ml_subnet_baseline') or check_id.endswith('ml_root_exception') or check_id.endswith('ml_terminal_exception') or check_id.endswith('ml_public_access_exception'):
            idx['context']['metadata']['sw29']['classification']['assignments'][0]['classification'] = 'sensitive'
        elif check_id.endswith('gateway_affinity_cookie_timeout'):
            item['sw29Evidence']['affinityProbes']['routes'] = []
        elif check_id.endswith('gateway_client_rate_limit'):
            item['sw29Evidence']['rateLimit']['public'] = False
        elif check_id.endswith('lb_certificate_auto_renew'):
            item['sw29Evidence']['certificateRenewal']['renewals'] = []
        else:
            item['properties']['httpListeners'] = []
        assert evaluate_check(check_id, item, idx)[0] == 'NOT_APPLICABLE'


@pytest.mark.parametrize('check_id', sorted(sw.SPECS))
def test_missing_required_fact_and_foreign_scope_are_unknown(check_id):
    item, idx, _, _ = case(check_id)
    kind = sw.SPECS[check_id]['resource_kind']
    if kind == 'postgresql_single_server':
        if check_id.endswith('log_retention_days'):
            del item['configurations']
        elif check_id.endswith('ssl_enforcement'):
            del item['properties']['sslEnforcement']
        else:
            del item['properties']['infrastructureEncryption']
    elif kind == 'ml_compute':
        item.pop('sw29Evidence')
    elif check_id == 'azure_application_gateway_app_client_certificates_on_fcca0b8':
        item.pop('sw29Evidence')
    elif check_id == 'azure_application_gateway_1_2_5_8_33a9d21':
        item.pop('sw29Evidence')
    else:
        item.pop('sw29Evidence')
    assert evaluate_check(check_id, item, idx)[0] == 'UNKNOWN'
    item, idx, _, _ = case(check_id)
    idx['collections'][kind][0]['scope'] = '/subscriptions/foreign'
    assert evaluate_check(check_id, item, idx)[0] == 'UNKNOWN'


def test_gateway_tls_profile_overrides_default_and_frontdoor_gap_unknown():
    cid = 'azure_application_gateway_1_2_5_8_33a9d21'
    item, idx, _, _ = case(cid)
    profile_id = GW + '/sslProfiles/weak'
    item['properties']['httpListeners'][0]['properties']['sslProfile'] = {'id': profile_id}
    item['properties']['sslProfiles'] = [{'id': profile_id, 'properties': {'sslPolicy': {
        'policyType': 'Custom', 'minProtocolVersion': 'TLSv1_0',
        'cipherSuites': ['TLS_AES_128_GCM_SHA256']}}}]
    assert evaluate_check(cid, item, idx)[0] == 'FAIL'
    item['properties']['sslProfiles'][0]['properties']['sslPolicy']['minProtocolVersion'] = 'TLSv1_2'
    item['sw29Evidence']['frontDoorTls']['family_inventory_complete'] = False
    assert evaluate_check(cid, item, idx)[0] == 'UNKNOWN'


def test_rate_limit_shadowed_rule_and_unmeasured_runtime():
    cid = 'azure.other.gateway_client_rate_limit'
    item, idx, _, _ = case(cid)
    item['sw29Evidence']['rateLimit']['effective_rules'][0]['not_shadowed'] = False
    assert evaluate_check(cid, item, idx)[0] == 'FAIL'
    item['sw29Evidence']['rateLimit']['effective_rules'][0]['not_shadowed'] = True
    item['sw29Evidence']['rateLimit']['runtime_window_complete'] = False
    assert evaluate_check(cid, item, idx)[0] == 'UNKNOWN'


def test_ssh_disabled_is_not_terminal_authorization():
    cid = 'azure.other.ml_terminal_exception'
    item, idx, _, _ = case(cid)
    item['properties']['properties']['sshSettings'] = {'sshPublicAccess': 'Disabled'}
    del item['sw29Evidence']['terminalAccess']
    assert evaluate_check(cid, item, idx)[0] == 'UNKNOWN'


def test_key_vault_uri_without_validation_is_unknown():
    cid = 'azure_application_gateway_app_client_certificates_on_fcca0b8'
    item, idx, _, _ = case(cid)
    del item['sw29Evidence']['certificateValidation']
    assert evaluate_check(cid, item, idx)[0] == 'UNKNOWN'


def test_postgresql_configuration_coverage_conflict_unknown():
    cid = 'azure.cis.postgresql_single_log_retention_days'
    item, idx, _, _ = case(cid)
    item['_coverage']['configurations']['status'] = 'empty'
    assert evaluate_check(cid, item, idx)[0] == 'UNKNOWN'


