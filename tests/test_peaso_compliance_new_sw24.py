"""Direct, registry-isolated signed Azure sw24 contract and boundary tests."""
from __future__ import annotations

import copy

import pytest

from peaso.checks import CHECKS

_before = list(CHECKS)
from peaso.checks import compliance_new_sw24 as sw24
CHECKS[:] = _before

SCOPE = '/subscriptions/11111111-1111-1111-1111-111111111111'
BASE = SCOPE + '/resourceGroups/rg/providers/'
APIM = BASE + 'Microsoft.ApiManagement/service/gateway'
ML = BASE + 'Microsoft.MachineLearningServices/workspaces/ml'
COMPUTE = ML + '/computes/instance'
SUBNET = BASE + 'Microsoft.Network/virtualNetworks/network/subnets/private'
GROUP = BASE + 'Microsoft.Insights/actionGroups/responders'
ALERT = BASE + 'Microsoft.Insights/activityLogAlerts/change'
WORKSPACE = BASE + 'Microsoft.OperationalInsights/workspaces/audit'
COMPONENT = BASE + 'Microsoft.Insights/components/app'
REDIS = BASE + 'Microsoft.Cache/redis/cache'
START = '2026-10-12T10:00:00Z'
EVENT = '2026-10-12T10:01:00Z'
PUBLISHED = '2026-10-12T10:01:10Z'
UNTIL = '2026-10-12T10:05:00Z'
END = '2026-10-12T11:00:00Z'


def child(parent, segment, name, **data):
    return {'id': parent + '/' + segment + '/' + name, 'parent_id': parent, **data}


def children(parent, key, rows):
    parent[key] = rows
    parent.setdefault('_coverage', {})[key] = {'status': 'collected' if rows else 'empty'}


def compute():
    return {'id': COMPUTE, 'parent_id': ML,
            'properties': {'computeType': 'ComputeInstance', 'properties': {
                'enableNodePublicIp': False, 'subnet': {'id': SUBNET}}},
            '_provenance': {'source_operation': 'LIST', 'api_version': '2024-04-01', 'read_only': True, 'representation': 'full'},
            'imageIds': {'vm': ['approved-vm'], 'container': ['approved-container']},
            '_coverage': {'imageIds': {'status': 'collected'}}}


def sources(kinds):
    return [{'kind': k, 'status': 'collected', 'references': ['source:' + k],
             'documents': [{'id': 'source:' + k, 'data': {'source_kind': k, 'full_inventory': []},
                'sha256': sw24.digest({'source_kind': k, 'full_inventory': []}), 'observed_at': EVENT,
                '_provenance': {'read_only': True}}]} for k in kinds]


def reviewed(kinds, **details):
    return {'unresolved': [], 'sources': sources(kinds), **details}


def policy(cid, rid, **extra):
    return {'check_id': cid, 'resource_id': rid, 'status': 'collected',
            'window': {'start': START, 'end': END}, **extra}


def index(groups, pol):
    return {'context': {'provider': 'azure', 'scope': SCOPE, 'created_at': END,
            'metadata': {'compliance_policy': {'sw24': {'status': 'collected', 'scope': SCOPE, 'checks': [pol]}}}},
            'collections': {k: [{'type': k, 'scope': SCOPE, 'status': 'collected' if rows else 'empty', 'items': rows}] for k, rows in groups.items()},
            **{k: [{'type': k, 'scope': SCOPE, 'data': row} for row in rows] for k, rows in groups.items()}}


def add_evidence(groups, cid, rid, pol, config, payload):
    if 'resolution' in payload:
        pol['reviewedResolutionSha256'] = sw24.digest(payload['resolution'])
    groups[sw24.EVIDENCE_KIND] = [{'id': 'evidence-' + cid, 'check_id': cid,
        'resource_id': rid, 'schema_version': 1, 'status': 'collected', 'observed_at': UNTIL,
        'configuration_sha256': sw24.digest(config),
        'policy_sha256': sw24.digest({k: v for k, v in pol.items() if k != 'reviewedResolutionSha256'}),
        '_provenance': {'read_only': True, 'source': 'authorized observation import'}, 'payload': payload}]


def native_apim():
    service = {'id': APIM}
    api = child(APIM, 'apis', 'api;rev=1', _provenance={'deployed': True}, _coverage={'revisions': {'status': 'collected'}})
    op = child(api['id'], 'operations', 'get')
    children(api, 'operations', [op])
    children(api, 'diagnostics', [])
    children(service, 'apis', [api])
    logger = child(APIM, 'loggers', 'ai', properties={'loggerType': 'applicationInsights', 'resourceId': COMPONENT})
    children(service, 'loggers', [logger])
    capture = {'request': {'headers': [], 'body': {'bytes': 0}}, 'response': {'headers': [], 'body': {'bytes': 0}}}
    diagnostic = child(APIM, 'diagnostics', 'applicationinsights', properties={
        'loggerId': logger['id'], 'verbosity': 'error',
        'sampling': {'samplingType': 'fixed', 'percentage': 100}, 'alwaysLog': 'allErrors',
        'frontend': copy.deepcopy(capture), 'backend': copy.deepcopy(capture)})
    children(service, 'diagnostics', [diagnostic])
    return service, api, op, logger


def fixture(cid):
    spec = sw24.SPECS[cid]
    if spec['resource_kind'] == 'api_management':
        item, api, op, logger = native_apim()
        pol = policy(cid, APIM.lower(), requiredApiIds=[api['id']], minimumSamplingPercentage=100)
        groups = {'api_management': [item], 'application_insights': [{'id': COMPONENT}], 'redis_cache': []}
        payload = {'loggers': [{'logger_id': logger['id'], 'configuration_sha256': sw24.digest(logger['properties']),
            'destination_id': COMPONENT, 'destination_exists': True, 'credentials_usable': True,
            'observed_at': EVENT, 'observation_id': 'logger-observation'}],
            'receipts': [{'api_id': api['id'], 'logger_id': logger['id'], 'destination_id': COMPONENT,
                          'request_id': 'received-http-request', 'received_at': PUBLISHED}]}
        if cid == sw24.CACHE_ID:
            cache = child(APIM, 'caches', 'external', properties={'resourceId': REDIS}, connectionEndpoint={'host': 'cache.redis.cache.windows.net', 'tls': True})
            children(item, 'caches', [cache])
            groups['redis_cache'] = [{'id': REDIS, 'properties': {'hostName': 'cache.redis.cache.windows.net', 'enableNonSslPort': False, 'minimumTlsVersion': '1.2'}}]
            pol.update(requiredOperationIds=[op['id']], approvedEncryptedCacheIds=[cache['id']])
            at_rest = {'encrypted': True, 'approved': True, 'evidence_id': 'at-rest-evidence'}
            payload = {'resolution': reviewed(('global_policies', 'product_policies', 'api_policies', 'operation_policies', 'product_bindings', 'cache_bindings'), paths=[{
                'operation_id': op['id'], 'path_id': 'unconditional',
                'inbound': [{'kind': 'cache-lookup', 'cache_id': cache['id'], 'at_rest': at_rest}],
                'outbound': [{'kind': 'cache-store', 'cache_id': cache['id'], 'at_rest': at_rest}]}])}
        add_evidence(groups, cid, APIM.lower(), pol, item, payload)
    elif spec['resource_kind'] == 'ml_workspace':
        item = {'id': ML, 'properties': {'publicNetworkAccess': 'Disabled'}}
        comp = compute()
        groups = {'ml_workspace': [item], 'ml_compute': [comp]}
        pol = policy(cid, ML.lower(), sensitiveComputeIds=[COMPUTE], nonsensitiveComputeIds=[COMPUTE],
                     approvedSubnetIds=[SUBNET], approvedImageIds=['approved-vm', 'approved-container'],
                     approvedPrincipalIds=['22222222-2222-2222-2222-222222222222'], approvedDestinationIds=[WORKSPACE],
                     ingestionDelaySeconds=60, correlationToleranceSeconds=5)
        payload = {}
        if cid == sw24.PUBLIC_ID:
            payload = {'resolution': reviewed(('workspace_network', 'endpoint_inventory', 'proxy_inventory', 'effective_network_paths'), paths=[
                {'compute_id': COMPUTE, 'path_type': k, 'path_ids': [], 'public_ip_access': False}
                for k in ('workspace', 'endpoint', 'proxy', 'network')])}
        elif cid == sw24.EGRESS_ID:
            payload = {'resolution': reviewed(('network_mode', 'subnets', 'nsgs', 'routes', 'firewalls', 'nat', 'outbound_observations'), egress=[{
                'compute_id': COMPUTE, 'route_ids': [SUBNET], 'firewall_ids': [], 'direct_internet': False,
                'observations': [{'destination': 'https://test.example', 'observation_id': 'outbound', 'observed_at': EVENT, 'outcome': 'blocked'}]}])}
        elif cid == sw24.IMAGES_ID:
            payload = {'resolution': reviewed(('policy_assignments', 'policy_definitions', 'policy_initiatives', 'policy_exemptions', 'policy_insights', 'inherited_scopes'), deny_domains=[
                {'image_type': k, 'scope': ML, 'allowed_image_ids': pol['approvedImageIds'], 'effect': 'Deny', 'enforcementMode': 'Default', 'excluded_compute_ids': []}
                for k in ('vm', 'container')]), 'creation_probes': [
                {'image_type': k, 'scope': ML, 'image_id': 'unapproved-' + k, 'probe_id': 'probe-' + k, 'authorized': True,
                 'observed_at': EVENT, 'outcome': 'denied_by_policy'} for k in ('vm', 'container')]}
        elif cid == sw24.ACCESS_ID:
            payload = {'resolution': reviewed(('role_assignments', 'role_definitions', 'deny_assignments', 'conditions', 'transitive_groups', 'inherited_scopes'), effective_access=[{
                'compute_id': COMPUTE, 'permissions': [{'principal_id': '22222222-2222-2222-2222-222222222222', 'permission': 'read', 'source_ids': ['assignment-expanded']}]}])}
        elif cid == sw24.DOWNLOAD_ID:
            backend = BASE + 'Microsoft.Storage/storageAccounts/files/blobServices/default'
            payload = {'resolution': reviewed(('instance_classification', 'download_paths', 'backing_resources', 'supported_categories', 'diagnostic_settings'), instances=[{'compute_id': COMPUTE, 'download_path_ids': ['blob']}]),
                'paths': [{'path_id': 'blob', 'resource_id': backend, 'supported_categories': ['StorageRead'],
                'diagnostic_settings': [{'parent_id': backend, 'properties': {'workspaceId': WORKSPACE, 'logs': [{'category': 'StorageRead', 'enabled': True}]}}],
                'downloads': [{'probe_or_event_id': 'download-probe', 'identity': 'principal', 'object_id': 'file.csv', 'occurred_at': EVENT,
                    'observed_until': UNTIL, 'record_inventory_complete': True,
                    'records': [{'record_id': 'record', 'identity': 'principal', 'object_id': 'file.csv', 'event_time': EVENT, 'destination_id': WORKSPACE}]}]}]}
        if cid == sw24.DOWNLOAD_ID:
            payload['resolution']['path_facts'] = [{k: row[k] for k in ('path_id', 'resource_id', 'supported_categories', 'diagnostic_settings')} for row in payload['paths']]
        add_evidence(groups, cid, ML.lower(), pol, sw24._configuration(item, groups['ml_compute']), payload)
    else:
        item = {'provider': 'azure', 'scope': SCOPE}
        pol = policy(cid, SCOPE.lower(), monitoredChannelIds=['monitored'], deliveryDeadlineSeconds=60)
        action_group = {'id': GROUP, 'properties': {'enabled': True}}
        operation = 'Microsoft.Insights/diagnosticSettings/write'
        cases = [{'case_id': 'change', 'scope': ML, 'operation': operation, 'statuses': ['Started', 'Failed'] if cid == sw24.RETENTION_ID else ['Succeeded']}]
        pol['requiredCases'] = cases
        alert = {'id': ALERT, 'properties': {'enabled': True, 'scopes': [SCOPE],
            'condition': {'allOf': [{'field': 'category', 'equals': 'Administrative'}]},
            'actions': {'actionGroups': [{'actionGroupId': GROUP}]}}}
        groups = {'activity_log_alert': [alert], 'action_group': [action_group]}
        if cid == sw24.DESTINATION_ID:
            resources = [ML, COMPUTE]
            cases = [{'case_id': str(i) + operation, 'scope': resource, 'operation': 'Microsoft.Insights/diagnosticSettings/' + operation, 'statuses': ['Succeeded']}
                     for i, resource in enumerate(resources) for operation in ('write', 'delete')]
            pol.update(requiredCases=cases, resourceIds=resources)
        payload = {'event_inventory_complete': True, 'case_ids': [r['case_id'] for r in cases], 'events': [{
            'case_id': r['case_id'], 'event_id': r['case_id'], 'scope': r['scope'], 'operation': r['operation'], 'status': r['statuses'][-1],
            'occurred_at': EVENT, 'observed_until': UNTIL, 'delivery_inventory_complete': True,
            'deliveries': [{'alert_id': ALERT, 'action_group_id': GROUP, 'channel_id': 'monitored', 'delivery_id': 'delivered-' + r['case_id'], 'published_at': PUBLISHED}]}
            for r in cases]}
        config = {'alerts': groups['activity_log_alert'], 'action_groups': groups['action_group']}
        if cid == sw24.DESTINATION_ID:
            payload['resolution'] = reviewed(('service_inventory', 'child_resource_inventory', 'redirection_controls', 'operational_state'), resource_ids=pol['resourceIds'])
            payload['control_tests'] = [{'resource_id': r['scope'], 'operation': r['operation'], 'test_id': r['case_id'],
                'observed_at': EVENT, 'before_state': 'Running', 'after_state': 'Running', 'redirection_applied': False} for r in cases]
        elif cid == sw24.ANOMALY_ID:
            detectors = [{'kind': k, 'criteria': [{'query': 'approved query ' + k, 'operator': 'GreaterThan', 'threshold': 10, 'timeAggregation': 'Count'}],
                'scopes': [WORKSPACE], 'tableIds': ['AzureActivity' if k == 'suspicious_api_requests' else 'LAQueryLogs'],
                'maxEvaluationSeconds': 60, 'maxWindowSeconds': 300, 'maxLatencySeconds': 60, 'principalColumn': 'AADObjectId'}
                for k in ('suspicious_api_requests', 'per_principal_log_query_volume')]
            pol['detectors'] = detectors
            rules = [{'id': BASE + 'Microsoft.Insights/scheduledQueryRules/' + d['kind'], 'properties': {
                'enabled': True, 'criteria': {'allOf': d['criteria']}, 'scopes': d['scopes'], 'evaluationFrequency': 'PT1M',
                'windowSize': 'PT5M', 'actions': {'actionGroups': [GROUP]}}} for d in detectors]
            groups['scheduled_query_rule'] = rules
            config = {'rules': rules, 'action_groups': groups['action_group']}
            payload = {'resolution': reviewed(('query_semantics', 'thresholds', 'per_principal_aggregation', 'scope_inventory', 'source_tables', 'delivery'), detector_kinds=[d['kind'] for d in detectors]),
                'tables': [{'table_id': d['tableIds'][0], 'available': True, 'observed_at': EVENT} for d in detectors],
                'detections': [{'kind': d['kind'], 'rule_id': r['id'], 'event_id': d['kind'], 'principal_id': 'principal',
                    'event_time': EVENT, 'observed_until': UNTIL, 'delivery_inventory_complete': True,
                    'deliveries': [{'action_group_id': GROUP, 'delivery_id': d['kind'], 'published_at': PUBLISHED}]}
                    for d, r in zip(detectors, rules)]}
        add_evidence(groups, cid, SCOPE.lower(), pol, config, payload)
    return item, groups, pol


def evaluate(cid, item, groups, pol):
    return sw24.CHECK_OBJECTS[cid].evaluate(item, index(groups, pol))


def rebind(cid, item, groups, pol):
    old = groups[sw24.EVIDENCE_KIND][0]
    rid = old['resource_id']
    if sw24.SPECS[cid]['resource_kind'] == 'api_management':
        config = item
    elif sw24.SPECS[cid]['resource_kind'] == 'ml_workspace':
        config = sw24._configuration(item, groups['ml_compute'])
    elif cid == sw24.ANOMALY_ID:
        config = {'rules': groups['scheduled_query_rule'], 'action_groups': groups['action_group']}
    else:
        config = {'alerts': groups['activity_log_alert'], 'action_groups': groups['action_group']}
    add_evidence(groups, cid, rid, pol, config, old['payload'])


@pytest.mark.parametrize('cid', sw24.IDS)
def test_pass_complete_native_and_measured_facts(cid):
    item, groups, pol = fixture(cid)
    status, evidence = evaluate(cid, item, groups, pol)
    assert status == 'PASS', evidence


@pytest.mark.parametrize('cid', sw24.IDS)
def test_fail_positive_evidence(cid):
    item, groups, pol = fixture(cid)
    payload = groups[sw24.EVIDENCE_KIND][0]['payload']
    if cid == sw24.CACHE_ID:
        payload['resolution']['paths'][0]['outbound'] = []
    elif cid in (sw24.HTTP_ID, sw24.VERBOSE_ID, sw24.METHODS_ID, sw24.INSIGHTS_ID):
        children(item, 'diagnostics', [])
    elif cid == sw24.SUBNET_ID:
        groups['ml_compute'][0]['properties']['properties']['subnet']['id'] = SUBNET + '-other'
    elif cid in (sw24.PUBLIC_ID, sw24.EGRESS_ID):
        groups['ml_compute'][0]['properties']['properties']['enableNodePublicIp'] = True
    elif cid == sw24.IMAGES_ID:
        groups['ml_compute'][0]['imageIds']['vm'] = ['unapproved-image']
    elif cid == sw24.ACCESS_ID:
        payload['resolution']['effective_access'][0]['permissions'][0]['principal_id'] = '33333333-3333-3333-3333-333333333333'
    elif cid == sw24.DOWNLOAD_ID:
        payload['paths'][0]['downloads'][0]['records'] = []
    elif cid == sw24.DESTINATION_ID:
        payload['control_tests'][0]['redirection_applied'] = True
    elif cid == sw24.ANOMALY_ID:
        payload['detections'][0]['deliveries'] = []
    else:
        payload['events'][0]['deliveries'] = []
    rebind(cid, item, groups, pol)
    status, evidence = evaluate(cid, item, groups, pol)
    assert status == 'FAIL', evidence


@pytest.mark.parametrize('cid', sw24.IDS)
@pytest.mark.parametrize('damage', ['missing', 'partial', 'denied', 'malformed', 'foreign', 'duplicate', 'index_mismatch'])
def test_unknown_inventory_authority(cid, damage):
    item, groups, pol = fixture(cid)
    kind = 'scheduled_query_rule' if cid == sw24.ANOMALY_ID else sw24.SPECS[cid]['resource_kind']
    scoped = index(groups, pol)
    if damage == 'missing':
        del scoped['collections'][kind]
    elif damage in ('partial', 'denied'):
        scoped['collections'][kind][0]['status'] = damage
    elif damage == 'malformed':
        scoped[kind][0]['data'] = []
    elif damage == 'foreign':
        scoped['collections'][kind][0]['scope'] = '/subscriptions/other'
    elif damage == 'duplicate':
        scoped[kind].append(copy.deepcopy(scoped[kind][0]))
        scoped['collections'][kind][0]['items'].append(copy.deepcopy(scoped['collections'][kind][0]['items'][0]))
    else:
        scoped['collections'][kind][0]['items'] = []
    assert sw24.CHECK_OBJECTS[cid].evaluate(item, scoped)[0] == 'UNKNOWN'


@pytest.mark.parametrize('cid', sw24.IDS)
def test_unknown_missing_required_fact(cid):
    item, groups, pol = fixture(cid)
    if cid == sw24.SUBNET_ID:
        del groups['ml_compute'][0]['properties']['properties']['subnet']
    else:
        del groups[sw24.EVIDENCE_KIND]
    assert evaluate(cid, item, groups, pol)[0] == 'UNKNOWN'


@pytest.mark.parametrize('cid', sw24.IDS)
def test_unknown_malformed_required_fact(cid):
    item, groups, pol = fixture(cid)
    if cid == sw24.SUBNET_ID:
        groups['ml_compute'][0]['properties']['properties']['subnet'] = {'id': 42}
    else:
        groups[sw24.EVIDENCE_KIND][0]['payload'] = []
    assert evaluate(cid, item, groups, pol)[0] == 'UNKNOWN'


@pytest.mark.parametrize('cid', [cid for cid in sw24.IDS if cid != sw24.SUBNET_ID])
@pytest.mark.parametrize('damage', ['stale_config', 'stale_policy', 'foreign', 'unreviewed', 'future_time'])
def test_unknown_evidence_binding(cid, damage):
    item, groups, pol = fixture(cid)
    evidence = groups[sw24.EVIDENCE_KIND][0]
    if damage == 'stale_config':
        evidence['configuration_sha256'] = '0' * 64
    elif damage == 'stale_policy':
        evidence['policy_sha256'] = '0' * 64
    elif damage == 'foreign':
        evidence['resource_id'] = ML.replace(SCOPE, '/subscriptions/other')
    elif damage == 'future_time':
        evidence['observed_at'] = '2027-01-01T00:00:00Z'
    elif 'resolution' in evidence['payload']:
        pol['reviewedResolutionSha256'] = '0' * 64
    else:
        evidence['_provenance']['read_only'] = False
    assert evaluate(cid, item, groups, pol)[0] == 'UNKNOWN'


@pytest.mark.parametrize('cid', [sw24.METHODS_ID, sw24.INSIGHTS_ID, sw24.SUBNET_ID, sw24.EGRESS_ID, sw24.PUBLIC_ID, sw24.ACCESS_ID, sw24.DOWNLOAD_ID])
def test_not_applicable_complete_empty_scope(cid):
    item, groups, pol = fixture(cid)
    if cid == sw24.METHODS_ID:
        children(item['apis'][0], 'operations', [])
    elif cid == sw24.INSIGHTS_ID:
        children(item, 'apis', [])
    elif cid in (sw24.SUBNET_ID, sw24.EGRESS_ID):
        groups['ml_compute'] = []
    elif cid == sw24.DOWNLOAD_ID:
        pol['nonsensitiveComputeIds'] = []
    else:
        pol['sensitiveComputeIds'] = []
    assert evaluate(cid, item, groups, pol)[0] == 'NOT_APPLICABLE'


@pytest.mark.parametrize('cid,verbosity,expected', [
    (sw24.VERBOSE_ID, 'verbose', 'PASS'), (sw24.VERBOSE_ID, 'information', 'FAIL'),
    (sw24.METHODS_ID, 'information', 'PASS'), (sw24.METHODS_ID, 'verbose', 'FAIL'),
    (sw24.HTTP_ID, 'verbose', 'PASS'), (sw24.HTTP_ID, 'future', 'UNKNOWN')])
def test_apim_frozen_verbosity_and_metadata_capture(cid, verbosity, expected):
    item, groups, pol = fixture(cid)
    item['diagnostics'][0]['properties']['verbosity'] = verbosity
    rebind(cid, item, groups, pol)
    assert evaluate(cid, item, groups, pol)[0] == expected


@pytest.mark.parametrize('cid,percentage,always_errors,expected', [
    (sw24.VERBOSE_ID, 0, True, 'PASS'), (sw24.VERBOSE_ID, 0, False, 'FAIL'),
    (sw24.METHODS_ID, 0, True, 'FAIL'), (sw24.INSIGHTS_ID, 0, True, 'FAIL'),
    (sw24.HTTP_ID, 50, True, 'UNKNOWN'), (sw24.HTTP_ID, 0, True, 'UNKNOWN'),
    (sw24.HTTP_ID, 0, False, 'FAIL')])
def test_apim_sampling_and_error_only_semantics(cid, percentage, always_errors, expected):
    item, groups, pol = fixture(cid)
    props = item['diagnostics'][0]['properties']
    props['sampling']['percentage'] = percentage
    if not always_errors:
        del props['alwaysLog']
    rebind(cid, item, groups, pol)
    assert evaluate(cid, item, groups, pol)[0] == expected


@pytest.mark.parametrize('damage', ['missing_sampling', 'bool_percentage', 'missing_logger_destination', 'missing_capture', 'incomplete_revision', 'foreign_logger', 'future_logger_type'])
def test_apim_unresolved_native_semantics_unknown(damage):
    cid = sw24.HTTP_ID
    item, groups, pol = fixture(cid)
    props = item['diagnostics'][0]['properties']
    if damage == 'missing_sampling':
        del props['sampling']
    elif damage == 'bool_percentage':
        props['sampling']['percentage'] = True
    elif damage == 'missing_logger_destination':
        del item['loggers'][0]['properties']['resourceId']
    elif damage == 'missing_capture':
        del props['backend']
    elif damage == 'incomplete_revision':
        item['apis'][0]['_coverage']['revisions']['status'] = 'partial'
    elif damage == 'foreign_logger':
        props['loggerId'] = APIM.replace('gateway', 'other') + '/loggers/ai'
    else:
        item['loggers'][0]['properties']['loggerType'] = 'future'
    rebind(cid, item, groups, pol)
    assert evaluate(cid, item, groups, pol)[0] == 'UNKNOWN'


def test_apim_api_override_supersedes_same_named_service_diagnostic():
    cid = sw24.METHODS_ID
    item, groups, pol = fixture(cid)
    api = item['apis'][0]
    override = copy.deepcopy(item['diagnostics'][0])
    override.update(id=api['id'] + '/diagnostics/applicationinsights', parent_id=api['id'])
    override['properties']['sampling']['percentage'] = 0
    children(api, 'diagnostics', [override])
    rebind(cid, item, groups, pol)
    assert evaluate(cid, item, groups, pol)[0] == 'FAIL'


def test_all_methods_empty_api_has_no_phantom_operation_requirement():
    cid = sw24.METHODS_ID
    item, groups, pol = fixture(cid)
    empty_api = child(APIM, 'apis', 'empty;rev=1', _provenance={'deployed': True}, _coverage={'revisions': {'status': 'collected'}})
    children(empty_api, 'operations', [])
    children(empty_api, 'diagnostics', [])
    item['apis'].append(empty_api)
    rebind(cid, item, groups, pol)
    assert evaluate(cid, item, groups, pol)[0] == 'PASS'


@pytest.mark.parametrize('field', ['receipts', 'loggers'])
def test_apim_sink_or_logger_observation_outside_window_unknown(field):
    cid = sw24.HTTP_ID
    item, groups, pol = fixture(cid)
    row = groups[sw24.EVIDENCE_KIND][0]['payload'][field][0]
    row['received_at' if field == 'receipts' else 'observed_at'] = '2026-10-11T10:00:00Z'
    assert evaluate(cid, item, groups, pol)[0] == 'UNKNOWN'


def test_cache_native_external_resource_uri_supported():
    cid = sw24.CACHE_ID
    item, groups, pol = fixture(cid)
    item['caches'][0]['properties']['resourceId'] = 'https://management.azure.com' + REDIS
    rebind(cid, item, groups, pol)
    assert evaluate(cid, item, groups, pol)[0] == 'PASS'


@pytest.mark.parametrize('damage', ['missing_endpoint', 'foreign_uri', 'unresolved_clause', 'missing_path'])
def test_cache_unresolved_external_or_effective_paths_unknown(damage):
    cid = sw24.CACHE_ID
    item, groups, pol = fixture(cid)
    resolution = groups[sw24.EVIDENCE_KIND][0]['payload']['resolution']
    if damage == 'missing_endpoint':
        del item['caches'][0]['connectionEndpoint']
    elif damage == 'foreign_uri':
        item['caches'][0]['properties']['resourceId'] = 'https://untrusted.example' + REDIS
    elif damage == 'unresolved_clause':
        resolution['unresolved'] = ['choose branch']
    else:
        resolution['paths'] = []
    rebind(cid, item, groups, pol)
    assert evaluate(cid, item, groups, pol)[0] == 'UNKNOWN'


@pytest.mark.parametrize('cid', [sw24.PUBLIC_ID, sw24.EGRESS_ID])
def test_false_node_flag_requires_complete_effective_network_proof(cid):
    item, groups, pol = fixture(cid)
    resolution = groups[sw24.EVIDENCE_KIND][0]['payload']['resolution']
    resolution['paths' if cid == sw24.PUBLIC_ID else 'egress'] = []
    rebind(cid, item, groups, pol)
    assert evaluate(cid, item, groups, pol)[0] == 'UNKNOWN'


@pytest.mark.parametrize('cid', [sw24.PUBLIC_ID, sw24.EGRESS_ID])
def test_reviewed_effective_network_public_or_egress_path_fails(cid):
    item, groups, pol = fixture(cid)
    resolution = groups[sw24.EVIDENCE_KIND][0]['payload']['resolution']
    if cid == sw24.PUBLIC_ID:
        resolution['paths'][0]['public_ip_access'] = True
    else:
        resolution['egress'][0]['direct_internet'] = True
        resolution['egress'][0]['observations'][0]['outcome'] = 'allowed'
    rebind(cid, item, groups, pol)
    assert evaluate(cid, item, groups, pol)[0] == 'FAIL'


@pytest.mark.parametrize('cid', [sw24.PUBLIC_ID, sw24.EGRESS_ID])
@pytest.mark.parametrize('flag', [None, 1, 'false'])
def test_missing_or_malformed_public_ip_flag_unknown(cid, flag):
    item, groups, pol = fixture(cid)
    groups['ml_compute'][0]['properties']['properties']['enableNodePublicIp'] = flag
    assert evaluate(cid, item, groups, pol)[0] == 'UNKNOWN'


@pytest.mark.parametrize('full,expected', [(True, 'FAIL'), (False, 'UNKNOWN')])
def test_subnet_explicit_no_placement_requires_full_native_response(full, expected):
    cid = sw24.SUBNET_ID
    item, groups, pol = fixture(cid)
    comp = groups['ml_compute'][0]
    comp['properties']['properties']['subnet'] = None
    comp['_provenance']['representation'] = 'full' if full else 'partial'
    assert evaluate(cid, item, groups, pol)[0] == expected


@pytest.mark.parametrize('damage', ['foreign_scope', 'missing_image', 'unenforced_domain', 'missing_container_probe'])
def test_image_coverage_and_probe_binding_unknown(damage):
    cid = sw24.IMAGES_ID
    item, groups, pol = fixture(cid)
    payload = groups[sw24.EVIDENCE_KIND][0]['payload']
    if damage == 'foreign_scope':
        payload['creation_probes'][0]['scope'] = ML + '-other'
        payload['creation_probes'][0]['outcome'] = 'created'
    elif damage == 'missing_image':
        del groups['ml_compute'][0]['imageIds']
    elif damage == 'unenforced_domain':
        payload['resolution']['deny_domains'][0]['enforcementMode'] = 'DoNotEnforce'
    else:
        payload['creation_probes'].pop()
    rebind(cid, item, groups, pol)
    assert evaluate(cid, item, groups, pol)[0] == 'UNKNOWN'


def test_successful_prohibited_image_creation_is_positive_failure():
    cid = sw24.IMAGES_ID
    item, groups, pol = fixture(cid)
    groups[sw24.EVIDENCE_KIND][0]['payload']['creation_probes'][0]['outcome'] = 'created'
    pol['reviewedResolutionSha256'] = '0' * 64
    assert evaluate(cid, item, groups, pol)[0] == 'FAIL'


@pytest.mark.parametrize('damage', ['missing_compute_expansion', 'unresolved_condition', 'malformed_principal'])
def test_effective_rbac_expansion_uncertainty_unknown(damage):
    cid = sw24.ACCESS_ID
    item, groups, pol = fixture(cid)
    resolution = groups[sw24.EVIDENCE_KIND][0]['payload']['resolution']
    if damage == 'missing_compute_expansion':
        resolution['effective_access'] = []
    elif damage == 'unresolved_condition':
        resolution['unresolved'] = ['role condition']
    else:
        resolution['effective_access'][0]['permissions'][0]['principal_id'] = 'malformed'
    rebind(cid, item, groups, pol)
    assert evaluate(cid, item, groups, pol)[0] == 'UNKNOWN'


@pytest.mark.parametrize('damage', ['unreviewed_backend', 'short_window', 'missing_download', 'partial_records'])
def test_download_path_attribution_or_observation_unresolved_unknown(damage):
    cid = sw24.DOWNLOAD_ID
    item, groups, pol = fixture(cid)
    path = groups[sw24.EVIDENCE_KIND][0]['payload']['paths'][0]
    if damage == 'unreviewed_backend':
        path['resource_id'] += '-other'
    elif damage == 'short_window':
        path['downloads'][0]['observed_until'] = PUBLISHED
    elif damage == 'missing_download':
        path['downloads'] = []
    else:
        path['downloads'][0]['record_inventory_complete'] = False
    assert evaluate(cid, item, groups, pol)[0] == 'UNKNOWN'


def test_status_specific_alerts_collectively_cover_attempted_retention_case():
    cid = sw24.RETENTION_ID
    item, groups, pol = fixture(cid)
    first = groups['activity_log_alert'][0]
    first['properties']['condition']['allOf'].append({'field': 'status', 'equals': 'Started'})
    second = copy.deepcopy(first)
    second['id'] = ALERT + '-failed'
    second['properties']['condition']['allOf'][-1]['equals'] = 'Failed'
    groups['activity_log_alert'].append(second)
    groups[sw24.EVIDENCE_KIND][0]['payload']['events'][0]['deliveries'][0]['alert_id'] = second['id']
    rebind(cid, item, groups, pol)
    assert evaluate(cid, item, groups, pol)[0] == 'PASS'


def test_success_only_retention_alert_is_proven_coverage_gap():
    cid = sw24.RETENTION_ID
    item, groups, pol = fixture(cid)
    groups['activity_log_alert'][0]['properties']['condition']['allOf'].append({'field': 'status', 'equals': 'Succeeded'})
    rebind(cid, item, groups, pol)
    assert evaluate(cid, item, groups, pol)[0] == 'FAIL'


@pytest.mark.parametrize('cid', [sw24.ACTIVITY_ID, sw24.RETENTION_ID])
@pytest.mark.parametrize('damage', ['unknown_filter', 'partial_delivery', 'short_delivery', 'missing_case'])
def test_required_alert_coverage_unknown_when_semantics_or_delivery_unresolved(cid, damage):
    item, groups, pol = fixture(cid)
    payload = groups[sw24.EVIDENCE_KIND][0]['payload']
    if damage == 'unknown_filter':
        groups['activity_log_alert'][0]['properties']['condition']['allOf'].append({'field': 'unknown', 'equals': 'x'})
    elif damage == 'partial_delivery':
        payload['events'][0]['delivery_inventory_complete'] = False
    elif damage == 'short_delivery':
        payload['events'][0]['observed_until'] = PUBLISHED
    else:
        payload['events'] = []
    rebind(cid, item, groups, pol)
    assert evaluate(cid, item, groups, pol)[0] == 'UNKNOWN'


@pytest.mark.parametrize('damage,expected', [('halts', 'PASS'), ('missing_child', 'UNKNOWN'), ('missing_publication', 'FAIL')])
def test_diagnostic_destination_enforcement_and_child_publication(damage, expected):
    cid = sw24.DESTINATION_ID
    item, groups, pol = fixture(cid)
    payload = groups[sw24.EVIDENCE_KIND][0]['payload']
    if damage == 'halts':
        payload['control_tests'][0].update(after_state='Stopped', redirection_applied=True)
    elif damage == 'missing_child':
        payload['control_tests'].pop()
    else:
        payload['events'][-1]['deliveries'] = []
    assert evaluate(cid, item, groups, pol)[0] == expected


@pytest.mark.parametrize('damage,expected', [('late_delivery', 'FAIL'), ('unmeasured_table', 'UNKNOWN'), ('partial_observation', 'UNKNOWN'), ('missing_second_detector', 'UNKNOWN')])
def test_anomaly_requires_both_reviewed_detectors_tables_and_latency(damage, expected):
    cid = sw24.ANOMALY_ID
    item, groups, pol = fixture(cid)
    payload = groups[sw24.EVIDENCE_KIND][0]['payload']
    if damage == 'late_delivery':
        payload['detections'][0]['deliveries'][0]['published_at'] = '2026-10-12T10:03:00Z'
    elif damage == 'unmeasured_table':
        payload['tables'].pop()
    elif damage == 'partial_observation':
        payload['detections'][0]['delivery_inventory_complete'] = False
    else:
        payload['detections'].pop()
    assert evaluate(cid, item, groups, pol)[0] == expected


def test_disabled_reviewed_detector_with_unknown_alternative_cannot_fail():
    cid = sw24.ANOMALY_ID
    item, groups, pol = fixture(cid)
    groups['scheduled_query_rule'][0]['properties']['enabled'] = False
    alternative = copy.deepcopy(groups['scheduled_query_rule'][0])
    alternative['id'] += '-alternative'
    alternative['properties']['enabled'] = True
    alternative['properties']['criteria']['allOf'][0]['query'] = 'unreviewed alternative KQL'
    groups['scheduled_query_rule'].append(alternative)
    rebind(cid, item, groups, pol)
    assert evaluate(cid, item, groups, pol)[0] == 'UNKNOWN'


@pytest.mark.parametrize('cid', [sw24.CACHE_ID, sw24.PUBLIC_ID, sw24.EGRESS_ID, sw24.IMAGES_ID, sw24.ACCESS_ID, sw24.DOWNLOAD_ID, sw24.DESTINATION_ID, sw24.ANOMALY_ID])
def test_reviewed_source_documents_must_be_complete_current_and_unaltered(cid):
    item, groups, pol = fixture(cid)
    resolution = groups[sw24.EVIDENCE_KIND][0]['payload']['resolution']
    resolution['sources'][0]['documents'][0]['data']['altered'] = True
    rebind(cid, item, groups, pol)
    assert evaluate(cid, item, groups, pol)[0] == 'UNKNOWN'
