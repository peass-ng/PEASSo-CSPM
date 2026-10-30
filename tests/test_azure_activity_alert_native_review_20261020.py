"""Independent finite ARM alert declarations, not event delivery or probes."""
from copy import deepcopy
import socket
from urllib.parse import urlsplit

import pytest
from peaso.collectors import azure
from peaso.engine import evaluate_snapshot
from tests.test_peaso_azure_bulk_native import SUB, SCOPE, BASE, Transport, parent

ALERT_TYPE = 'Microsoft.Insights/activityLogAlerts'
RID = BASE + ALERT_TYPE + '/review-alert'
# Security operations are independently explicit, not copied from CASES or
# derived from evaluator closures. Scope and category variants remain separate.
OPERATIONS = [
 ('policy_assignment_write', 'Microsoft.Authorization/policyAssignments/write', None, 'create_policy_assignment'),
 ('policy_assignment_delete', 'Microsoft.Authorization/policyAssignments/delete', None, 'delete_policy_assignment'),
 ('nsg_write', 'Microsoft.Network/networkSecurityGroups/write', 'microsoft.network/networksecuritygroups', 'create_update_nsg'),
 ('nsg_delete', 'Microsoft.Network/networkSecurityGroups/delete', 'microsoft.network/networksecuritygroups', 'delete_nsg'),
 ('public_ip_write', 'Microsoft.Network/publicIPAddresses/write', 'microsoft.network/publicipaddresses', 'create_update_public_ip_address'),
 ('public_ip_delete', 'Microsoft.Network/publicIPAddresses/delete', 'microsoft.network/publicipaddresses', 'delete_public_ip_address'),
 ('security_solution_write', 'Microsoft.Security/securitySolutions/write', 'microsoft.security/securitysolutions', 'create_update_security_solution'),
 ('security_solution_delete', 'Microsoft.Security/securitySolutions/delete', 'microsoft.security/securitysolutions', 'delete_security_solution'),
 ('sql_firewall_rule_write', 'Microsoft.Sql/servers/firewallRules/write', 'microsoft.sql/servers/firewallrules', 'create_update_sql_servers_firewall_rule'),
 ('sql_firewall_rule_delete', 'Microsoft.Sql/servers/firewallRules/delete', 'microsoft.sql/servers/firewallrules', 'delete_sql_servers_firewall_rule'),
]
SPECS = []
for stem, operation, resource_type, port in OPERATIONS:
    category = 'Security' if stem.startswith('security_solution') else 'Administrative'
    for cid, family in [('azure.port.monitor_log_alert_' + port, 'strict'),
                        ('azure.claude.activity_log_alert_subscription_' + stem, 'strict'),
                        ('azure.claude.activity_log_alert_' + stem, 'loose')]:
        native_category = 'Administrative' if cid.startswith('azure.claude.') and stem.startswith('security_solution') else category
        SPECS.append(dict(id=cid, operation=operation, resource_type=resource_type, category=native_category, family=family))
for suffix, operation in [('write','Microsoft.Network/networksecuritygroups/securityrules/write'),
                           ('delete','Microsoft.Network/networksecuritygroups/securityrules/delete')]:
    SPECS.append(dict(id='azure.claude.activity_log_alert_subscription_nsg_rule_' + suffix, operation=operation,
                      resource_type='microsoft.network/networksecuritygroups/securityrules', category='Administrative', family='strict'))
SPECS += [dict(id='azure.claude.activity_log_alert_subscription_administrative_operations',
               operation='Microsoft.Sql/servers/firewallRules/write', resource_type=None, category='Administrative', family='strict'),
          dict(id='azure.claude.activity_log_alert_subscription_sql_server', operation=None,
               resource_type='microsoft.sql/servers', category='Administrative', family='strict'),
          dict(id='azure.claude.activity_log_alert_service_health', operation=None,
               resource_type=None, category='ServiceHealth', family='health-incident'),
          dict(id='azure.claude2.activity_log_alert_service_health', operation=None,
               resource_type=None, category='ServiceHealth', family='health')]


@pytest.fixture(autouse=True)
def offline(monkeypatch):
    def blocked(*a, **k):
        pytest.fail('native review forbids network and credential construction')
    for obj, name in [(socket, 'create_connection'), (socket, 'getaddrinfo'),
                      (socket.socket, 'connect'), (socket.socket, 'connect_ex'),
                      (azure, 'AzureTransport')]:
        monkeypatch.setattr(obj, name, blocked)


def native(spec):
    conditions = [{'field': 'category', 'equals': spec['category']}]
    if spec['operation']:
        conditions.append({'field': 'operationName', 'equals': spec['operation']})
    elif spec['resource_type']:
        conditions.append({'field': 'resourceType', 'equals': spec['resource_type']})
    if spec['family'] == 'health-incident':
        conditions.append({'field': 'properties.incidentType', 'equals': 'Incident'})
    row = parent(RID, ALERT_TYPE, {'enabled': True, 'scopes': [SCOPE],
                                 'condition': {'allOf': conditions}, 'actions': {'actionGroups': []}})
    row['location'] = 'Global'
    return row


def capture(spec, mode):
    value = native(spec)
    if mode == 'disabled': value['properties']['enabled'] = False
    if mode == 'wrong-operation':
        for entry in value['properties']['condition']['allOf']:
            if entry['field'] != 'category': entry['equals'] = 'Unrelated'
        if len(value['properties']['condition']['allOf']) == 1:
            value['properties']['condition']['allOf'][0]['equals'] = 'Unrelated'
    if mode == 'lowercase-values':
        for entry in value['properties']['condition']['allOf']: entry['equals'] = entry['equals'].lower()
    if mode == 'uppercase-fields':
        for entry in value['properties']['condition']['allOf']: entry['field'] = entry['field'].upper()
    if mode == 'scope-case-alias':
        value['properties']['scopes'] = [SCOPE.upper() + '/']
    if mode == 'foreign-list': value['id'] = RID.replace(SUB, '99999999-9999-9999-9999-999999999999')
    endpoint = SCOPE + '/providers/' + ALERT_TYPE
    routes = {endpoint: {'value': [deepcopy(value)]}, RID: value,
              SCOPE + '/resourcegroups': {'value': [parent(SCOPE + '/resourceGroups/rg', 'Microsoft.Resources/resourceGroups', {})]}}
    if mode == 'empty': routes[endpoint] = {'value': []}
    if mode == 'denied': routes[endpoint] = azure.AzureReadError('Forbidden', 403)
    if mode == 'partial':
        def pages(query):
            if '$skiptoken' in query: raise azure.AzureReadError('Forbidden', 403)
            return {'value': [deepcopy(value)], 'nextLink': azure.ARM + endpoint + '?api-version=2020-10-01&$skiptoken=next'}
        routes[endpoint] = pages
    api = Transport(routes)
    wanted = ['activity_log_alert'] + (['resource_group'] if spec['family'] == 'health' else [])
    snap = azure.collect({'provider': 'azure', 'scopes': [SUB], 'options': {'retries': 0}}, wanted, transport=api)
    findings = evaluate_snapshot(snap, checks=[spec['id']], include_not_applicable=True)['findings']
    return snap, api, findings


@pytest.mark.parametrize('spec', SPECS, ids=lambda s: s['id'])
@pytest.mark.parametrize('mode,expected', [('good','PASS'),('disabled','FAIL'),('wrong-operation','FAIL'),
                                         ('empty','FAIL'),('denied','DENIED'),
                                         ('foreign-list','UNKNOWN'),('lowercase-values','PASS'),
                                         ('uppercase-fields','PASS'),('scope-case-alias','PASS')])
def test_native_deciding_declarations(spec, mode, expected):
    snapshot, api, findings = capture(spec, mode)
    assert findings and {f['status'] for f in findings} == {expected}, findings
    assert not any('delivery' in f.get('evidence', {}) for f in findings)
    assert any(urlsplit(url).path == SCOPE + '/providers/' + ALERT_TYPE for url in api.calls)
    assert snapshot['metadata']['tenant_verified'] is True


@pytest.mark.parametrize('spec', SPECS, ids=lambda s: s['id'])
def test_partial_native_inventory_never_certifies_unobserved_subscription_coverage(spec):
    _, _, findings = capture(spec, 'partial')
    assert any(f['status'] == 'UNKNOWN' for f in findings), findings
