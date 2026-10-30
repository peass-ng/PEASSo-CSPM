"""Adversarial tests of all 15 signed sw12 Azure snapshot predicates."""
from __future__ import annotations

import copy
import hashlib
import importlib
import json
import sys

import pytest

from peaso.checks import CHECKS

IDS = tuple('azure.other.' + value for value in (
    'attack_t1525', 'attack_t1526', 'attack_t1537', 'attack_t1546', 'attack_t1552',
    'attack_t1562', 'attack_t1578', 'attack_t1580', 'attack_t1606', 'attack_t1614',
    'attack_t1619', 'attack_t1621', 'attack_t1648', 'attack_t1651', 'enumeration_alert'))
DETECTIONS = IDS[:-1]
SCOPE = '/subscriptions/00000000-0000-0000-0000-000000000001'
OTHER = '/subscriptions/00000000-0000-0000-0000-000000000002'
PREFIX = SCOPE + '/resourceGroups/rg/providers/'
WORKSPACE = PREFIX + 'Microsoft.OperationalInsights/workspaces/logs'
GROUP = PREFIX + 'Microsoft.Insights/actionGroups/responders'
RULE = PREFIX + 'Microsoft.Insights/scheduledQueryRules/detection'
REGISTRY = PREFIX + 'Microsoft.ContainerRegistry/registries/images'
FUNCTION = PREFIX + 'Microsoft.Web/sites/function'
VAULT = PREFIX + 'Microsoft.KeyVault/vaults/secrets'
VM = PREFIX + 'Microsoft.Compute/virtualMachines/host'
CAPTURE = '2026-10-12T12:00:00+00:00'
OBSERVED = '2026-10-12T11:59:00+00:00'
START = '2026-10-12T11:00:00+00:00'
END = '2026-10-12T11:50:00+00:00'


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'),
                                    ensure_ascii=False, allow_nan=False).encode()).hexdigest()


def qhash(value):
    return hashlib.sha256(value.strip().encode()).hexdigest()


def provenance(operation):
    return {'source_operation': operation, 'read_only': True, 'native_response_complete': True}


@pytest.fixture(scope='module')
def sw12():
    name = 'peaso.checks.compliance_new_sw12'
    already_loaded = name in sys.modules
    before = {id(check) for check in CHECKS}
    module = importlib.import_module(name)
    # Retain the module's own safe Check objects, without leaking registration.
    added = {id(check) for check in CHECKS if id(check) not in before}
    CHECKS[:] = [check for check in CHECKS if id(check) not in added]
    yield module
    CHECKS[:] = [check for check in CHECKS if id(check) not in added]
    if not already_loaded:
        sys.modules.pop(name, None)
        import peaso.checks as checks
        if getattr(checks, 'compliance_new_sw12', None) is module:
            delattr(checks, 'compliance_new_sw12')


def set_rows(index, kind, rows, *, status=None, **extra):
    index['collections'][kind] = [{'type': kind, 'scope': SCOPE,
        'status': status or ('collected' if rows else 'empty'), 'items': rows, **extra}]
    index[kind] = [{'type': kind, 'scope': SCOPE, 'data': row} for row in rows]


def policy(index, cid):
    return index['context']['metadata']['compliance_policy']['sw12']['checks'][cid]


def detection_case(cid):
    tables = {'attack_t1525': 'ContainerRegistryRepositoryEvents', 'attack_t1526': 'CloudServiceDiscovery_CL',
        'attack_t1537': 'StorageBlobLogs', 'attack_t1546': 'AzureActivity', 'attack_t1552': 'KeyVaultAuditEvents',
        'attack_t1562': 'AzureActivity', 'attack_t1578': 'AzureActivity', 'attack_t1580': 'ResourceReadAudit_CL',
        'attack_t1606': 'SigninLogs', 'attack_t1614': 'SysmonEvent', 'attack_t1619': 'StorageBlobLogs',
        'attack_t1621': 'SigninLogs', 'attack_t1648': 'FunctionAppLogs', 'attack_t1651': 'AzureDiagnostics'}
    technique = cid.rsplit('.', 1)[-1]
    table = tables[technique]
    source = REGISTRY if technique == 'attack_t1525' else FUNCTION if technique == 'attack_t1648' else VAULT if technique == 'attack_t1552' else VM
    query = table + ' | where OperationName == "approved-event"'
    condition = {'query': query, 'operator': 'GreaterThan', 'threshold': 0,
        'timeAggregation': 'Count', 'dimensions': [],
        'failingPeriods': {'numberOfEvaluationPeriods': 1, 'minFailingPeriodsToAlert': 1}}
    signature = {**condition, 'query_sha256': qhash(query), 'metricMeasureColumn': None, 'resourceIdColumn': None}
    signature.pop('query')
    requirement = {'workspace_id': WORKSPACE, 'source_id': source, 'pattern_id': technique, 'table': table,
        'semantics_reviewed': True, 'trigger_semantics_reviewed': True,
        'requiredQueryFragments': [table, 'OperationName == "approved-event"'], 'approvedCriteria': [[signature]],
        'min_window_seconds': 600, 'max_window_seconds': 1800, 'max_frequency_seconds': 300,
        'max_notification_delay_seconds': 600, 'max_ingestion_age_seconds': 600,
        'required_operations': ['read', 'list'] if technique == 'attack_t1580' else ['approved-event'],
        'read_list_applicable': True}
    check_policy = {'queryNormalization': 'kql-lf-trim-v1', 'requiredWorkspaceIds': [WORKSPACE],
        'requiredActionGroupIds': [GROUP], 'requirements': [requirement],
        'max_action_delivery_age_seconds': 600, 'max_test_age_seconds': 600,
        'serverless_service_ids': [FUNCTION], 'empty_registry_scope_not_applicable': True}
    if technique == 'attack_t1552':
        check_policy['credential_source_inventory'] = [{'source_class': 'key_vault', 'reviewed': True,
            'in_scope': True, 'source_id': VAULT}, *[{'source_class': klass, 'reviewed': True,
            'in_scope': False, 'exclusion_reason': 'Owner reviewed absence from this scoped environment'}
            for klass in ('host_files', 'application_repository', 'os_repository')]]
    rule = {'id': RULE, 'type': 'Microsoft.Insights/scheduledQueryRules', 'kind': 'LogAlert',
        '_provenance': provenance('scheduled_query_rules_list_by_subscription'),
        'properties': {'enabled': True, 'scopes': [WORKSPACE], 'criteria': {'allOf': [condition]},
            'windowSize': 'PT10M', 'evaluationFrequency': 'PT5M', 'muteActionsDuration': 'PT0S',
            'actions': {'actionGroups': [GROUP]}}}
    group = {'id': GROUP, 'type': 'Microsoft.Insights/actionGroups',
        '_provenance': provenance('action_groups_list_by_subscription'),
        'properties': {'enabled': True, 'webhookReceivers': [{'name': 'receiver', 'useCommonAlertSchema': True}]}}
    group['_delivery'] = {'status': 'reachable', 'observed_at': OBSERVED, 'evidence_id': 'receiver-ack',
        'read_only': True, 'configuration_sha256': digest(group['properties'])}
    telemetry = {'id': 'telemetry-1', 'check_id': cid, 'workspace_id': WORKSPACE, 'source_id': source,
        'pattern_id': technique, 'table': table, 'routing_enabled': True,
        'routing_evidence_ids': [source + '/providers/Microsoft.Insights/diagnosticSettings/logs'],
        'event_feed_status': 'available', 'query_window': {'start': START, 'end': OBSERVED},
        'event_count': 1, 'latest_event_at': OBSERVED, 'supported_operations': requirement['required_operations'],
        '_provenance': provenance('azure_detection_telemetry')}
    test_config = {'criteria': [signature], 'frequency': 300, 'window': 600, 'effective_window': 600,
        'mute': 0, 'scopes': [WORKSPACE.casefold()], 'groups': [GROUP.casefold()]}
    test = {'id': 'test-1', 'check_id': 'azure.other.attack_t1648', 'rule_id': RULE,
        'workspace_id': WORKSPACE, 'source_id': source, 'pattern_id': technique,
        'configuration_sha256': digest(test_config), 'trigger_event_id': 'known-event',
        'correlation_id': 'test-correlation', 'status': 'delivered', 'action_group_id': GROUP,
        'event_at': '2026-10-12T11:55:00+00:00', 'fired_at': '2026-10-12T11:56:00+00:00',
        'delivered_at': '2026-10-12T11:57:00+00:00', 'observed_at': OBSERVED,
        '_provenance': provenance('azure_detection_test')}
    index = {'context': {'provider': 'azure', 'scope': SCOPE, 'created_at': CAPTURE,
        'metadata': {'compliance_policy': {'sw12': {'scope': SCOPE, 'status': 'collected',
            'observed_at': OBSERVED, 'max_age_seconds': 3600, 'checks': {cid: check_policy}}}}}, 'collections': {}}
    for kind, rows in {'scheduled_query_rule': [rule], 'action_group': [group],
            'log_analytics_workspace': [{'id': WORKSPACE, 'properties': {'customerId': 'workspace-guid'}}],
            'azure_detection_telemetry': [telemetry], 'container_registry': [{'id': REGISTRY, 'properties': {}}],
            'azure_detection_test': [test]}.items():
        set_rows(index, kind, rows)
    return index['context'], index


def enumeration_case():
    cid = IDS[-1]
    query = 'AzureActivity | where OperationName == "enumeration"'
    query_hash = qhash(query)
    check_policy = {'semantics_reviewed': True, 'queryNormalization': 'kql-lf-trim-v1',
        'enumeration_query': query, 'enumeration_query_sha256': query_hash,
        'enumerationEventQueryFragments': ['AzureActivity', '"enumeration"'],
        'monitoredChannelIds': ['security-channel'], 'window_start': START, 'window_end': END,
        'max_window_age_seconds': 1800, 'max_delivery_delay_seconds': 300}
    index = {'context': {'provider': 'azure', 'scope': SCOPE, 'created_at': CAPTURE,
        'metadata': {'compliance_policy': {'sw12': {'scope': SCOPE, 'status': 'collected',
            'observed_at': OBSERVED, 'max_age_seconds': 3600, 'checks': {cid: check_policy}}}}}, 'collections': {}}
    event = {'id': 'event-1', 'client_identity': 'client-1', 'timestamp': '2026-10-12T11:20:00+00:00',
        'activity_nature': 'enumeration', 'correlation_id': 'correlation-1', 'query_sha256': query_hash,
        '_provenance': provenance('azure_enumeration_independent_query')}
    delivery = {'id': 'delivery-1', 'event_id': event['id'], 'correlation_id': event['correlation_id'],
        'channel_id': 'security-channel', 'publication_status': 'published',
        'published_at': '2026-10-12T11:21:00+00:00', 'payload_complete': True,
        'payload': {k: event[k] for k in ('client_identity', 'timestamp', 'activity_nature')},
        '_provenance': provenance('azure_enumeration_destination_read')}
    set_rows(index, 'azure_enumeration_event', [event], query_window={
        'start': START, 'end': END, 'complete': True, 'independent': True, 'query_sha256': query_hash})
    set_rows(index, 'azure_enumeration_delivery', [delivery], query_window={
        'start': START, 'end': END, 'complete': True, 'settled_through': OBSERVED})
    coverage = {'id': 'coverage-1', 'query_sha256': query_hash, 'window_start': START, 'window_end': END,
        'monitoredChannelIds': ['security-channel'], 'detection_continuous': True, 'delivery_continuous': True,
        '_provenance': provenance('azure_enumeration_continuous_coverage')}
    set_rows(index, 'azure_enumeration_coverage', [coverage])
    return index['context'], index


def case(cid):
    return enumeration_case() if cid == IDS[-1] else detection_case(cid)


def grade(sw12, cid, item, index):
    return sw12.CHECK_OBJECTS[cid].evaluate(item, index)[0]


@pytest.mark.parametrize('cid', IDS)
def test_signed_predicates_pass(sw12, cid):
    item, index = case(cid)
    assert grade(sw12, cid, item, index) == 'PASS'


@pytest.mark.parametrize('cid', IDS)
def test_signed_predicates_fail_on_complete_positive_gap(sw12, cid):
    item, index = case(cid)
    kind = 'azure_enumeration_delivery' if cid == IDS[-1] else 'scheduled_query_rule'
    extra = {'query_window': index['collections'][kind][0]['query_window']} if cid == IDS[-1] else {}
    set_rows(index, kind, [], **extra)
    assert grade(sw12, cid, item, index) == 'FAIL'


@pytest.mark.parametrize('cid', IDS)
@pytest.mark.parametrize('state', ['partial', 'denied', 'not_collected', 'error'])
def test_incomplete_inventory_unknown(sw12, cid, state):
    item, index = case(cid)
    kind = 'azure_enumeration_delivery' if cid == IDS[-1] else 'scheduled_query_rule'
    index['collections'][kind][0]['status'] = state
    assert grade(sw12, cid, item, index) == 'UNKNOWN'


@pytest.mark.parametrize('cid', IDS)
def test_missing_fact_unknown(sw12, cid):
    item, index = case(cid)
    if cid == IDS[-1]:
        index['azure_enumeration_event'][0]['data'].pop('timestamp')
    else:
        index['scheduled_query_rule'][0]['data']['properties'].pop('criteria')
    assert grade(sw12, cid, item, index) == 'UNKNOWN'


@pytest.mark.parametrize('cid', IDS)
def test_malformed_fact_unknown(sw12, cid):
    item, index = case(cid)
    if cid == IDS[-1]:
        index['azure_enumeration_delivery'][0]['data']['payload']['timestamp'] = []
    else:
        index['scheduled_query_rule'][0]['data']['properties']['enabled'] = 'true'
    assert grade(sw12, cid, item, index) == 'UNKNOWN'


@pytest.mark.parametrize('cid', IDS)
def test_missing_collector_unknown(sw12, cid):
    item, index = case(cid)
    kind = 'azure_enumeration_delivery' if cid == IDS[-1] else 'azure_detection_telemetry'
    index['collections'].pop(kind)
    index.pop(kind)
    assert grade(sw12, cid, item, index) == 'UNKNOWN'


@pytest.mark.parametrize('cid', IDS)
@pytest.mark.parametrize('location', ['context', 'subject', 'collection', 'wrapper', 'policy'])
def test_foreign_scope_unknown(sw12, cid, location):
    item, index = case(cid)
    if location == 'context':
        item = copy.deepcopy(item)
        index['context']['scope'] = OTHER
    elif location == 'subject':
        item = {**item, 'scope': OTHER}
    elif location == 'policy':
        index['context']['metadata']['compliance_policy']['sw12']['scope'] = OTHER
    else:
        kind = 'azure_enumeration_event' if cid == IDS[-1] else 'scheduled_query_rule'
        index['collections'][kind][0]['scope'] = OTHER if location == 'collection' else SCOPE
        if location == 'wrapper':
            index[kind][0]['scope'] = OTHER
    assert grade(sw12, cid, item, index) == 'UNKNOWN'


@pytest.mark.parametrize('cid', IDS)
def test_duplicate_and_projection_mismatch_unknown(sw12, cid):
    item, index = case(cid)
    kind = 'azure_enumeration_event' if cid == IDS[-1] else 'scheduled_query_rule'
    row = index[kind][0]['data']
    extra = {'query_window': index['collections'][kind][0]['query_window']} if cid == IDS[-1] else {}
    set_rows(index, kind, [row, copy.deepcopy(row)], **extra)
    assert grade(sw12, cid, item, index) == 'UNKNOWN'
    item, index = case(cid)
    index[kind][0]['data'] = {**index[kind][0]['data'], 'id': 'different-id'}
    assert grade(sw12, cid, item, index) == 'UNKNOWN'


@pytest.mark.parametrize('cid', IDS)
def test_missing_unreviewed_stale_policy_unknown(sw12, cid):
    for change in ('missing', 'stale', 'future'):
        item, index = case(cid)
        root = index['context']['metadata']['compliance_policy']['sw12']
        if change == 'missing':
            root['checks'].pop(cid)
        else:
            root['observed_at'] = '2026-10-01T00:00:00+00:00' if change == 'stale' else '2026-10-13T00:00:00+00:00'
        assert grade(sw12, cid, item, index) == 'UNKNOWN'


@pytest.mark.parametrize('cid', DETECTIONS)
def test_unreviewed_query_and_empty_required_scope_unknown(sw12, cid):
    item, index = case(cid)
    query = index['scheduled_query_rule'][0]['data']['properties']['criteria']['allOf'][0]
    query['query'] += ' | where true'
    assert grade(sw12, cid, item, index) == 'UNKNOWN'
    item, index = case(cid)
    policy(index, cid)['requiredWorkspaceIds'] = []
    assert grade(sw12, cid, item, index) == 'UNKNOWN'
    item, index = case(cid)
    policy(index, cid)['requirements'][0]['semantics_reviewed'] = False
    assert grade(sw12, cid, item, index) == 'UNKNOWN'


@pytest.mark.parametrize('cid', DETECTIONS)
def test_trigger_and_timing_gaps_fail(sw12, cid):
    for field, value in [('windowSize', 'PT1M'), ('evaluationFrequency', 'PT1H'),
                         ('overrideQueryTimeRange', 'P2D'), ('muteActionsDuration', 'P1D')]:
        item, index = case(cid)
        index['scheduled_query_rule'][0]['data']['properties'][field] = value
        assert grade(sw12, cid, item, index) == 'FAIL'
    item, index = case(cid)
    index['scheduled_query_rule'][0]['data']['properties']['criteria']['allOf'][0]['threshold'] = 999999
    assert grade(sw12, cid, item, index) == 'UNKNOWN'
    req = policy(index, cid)['requirements'][0]
    rejected = copy.deepcopy(req['approvedCriteria'][0])
    rejected[0]['threshold'] = 999999
    req.update(non_triggeringCriteria=[rejected], non_triggering_semantics_reviewed=True)
    assert grade(sw12, cid, item, index) == 'FAIL'


@pytest.mark.parametrize('cid', DETECTIONS)
def test_disabled_rule_and_action_group_boundary(sw12, cid):
    item, index = case(cid)
    index['scheduled_query_rule'][0]['data']['properties']['enabled'] = False
    assert grade(sw12, cid, item, index) == 'FAIL'
    item, index = case(cid)
    group = index['action_group'][0]['data']
    group['properties']['enabled'] = False
    group['_delivery']['configuration_sha256'] = digest(group['properties'])
    expected = 'UNKNOWN' if cid.endswith(('attack_t1546', 'attack_t1621')) else 'FAIL'
    assert grade(sw12, cid, item, index) == expected


@pytest.mark.parametrize('cid', DETECTIONS)
def test_missing_action_group_and_feed_unknown(sw12, cid):
    item, index = case(cid)
    set_rows(index, 'action_group', [])
    assert grade(sw12, cid, item, index) == 'UNKNOWN'
    item, index = case(cid)
    index['azure_detection_telemetry'][0]['data']['event_feed_status'] = 'unresolved'
    assert grade(sw12, cid, item, index) == 'UNKNOWN'


@pytest.mark.parametrize('cid', DETECTIONS)
def test_every_required_workspace_and_pattern_is_covered(sw12, cid):
    item, index = case(cid)
    second = copy.deepcopy(policy(index, cid)['requirements'][0])
    second['pattern_id'] = 'second-pattern'
    second['approvedCriteria'][0][0]['query_sha256'] = qhash('second reviewed query')
    second['requiredQueryFragments'] = ['second reviewed query']
    policy(index, cid)['requirements'].append(second)
    telemetry = copy.deepcopy(index['azure_detection_telemetry'][0]['data'])
    telemetry['id'], telemetry['pattern_id'] = 'telemetry-2', 'second-pattern'
    set_rows(index, 'azure_detection_telemetry', [index['azure_detection_telemetry'][0]['data'], telemetry])
    # The other enabled query is unreviewed for the second pattern: UNKNOWN.
    assert grade(sw12, cid, item, index) == 'UNKNOWN'
    set_rows(index, 'scheduled_query_rule', [])
    assert grade(sw12, cid, item, index) == 'FAIL'


def test_registry_empty_explicit_scope_not_applicable(sw12):
    cid = IDS[0]
    item, index = case(cid)
    set_rows(index, 'container_registry', [])
    assert grade(sw12, cid, item, index) == 'NOT_APPLICABLE'
    policy(index, cid)['empty_registry_scope_not_applicable'] = False
    assert grade(sw12, cid, item, index) == 'UNKNOWN'
    index['collections']['container_registry'][0]['status'] = 'partial'
    assert grade(sw12, cid, item, index) == 'UNKNOWN'


def test_credential_full_source_coverage_cannot_be_keyvault_only(sw12):
    cid = 'azure.other.attack_t1552'
    item, index = case(cid)
    policy(index, cid).pop('credential_source_inventory')
    assert grade(sw12, cid, item, index) == 'UNKNOWN'
    item, index = case(cid)
    source = policy(index, cid)['credential_source_inventory'][1]
    source.update(in_scope=True, source_id='host-files-source')
    assert grade(sw12, cid, item, index) == 'UNKNOWN'


def test_resource_discovery_requires_read_and_list_sources(sw12):
    cid = 'azure.other.attack_t1580'
    item, index = case(cid)
    policy(index, cid)['requirements'][0]['table'] = 'AzureActivity'
    assert grade(sw12, cid, item, index) == 'UNKNOWN'
    item, index = case(cid)
    index['azure_detection_telemetry'][0]['data']['supported_operations'] = ['write']
    assert grade(sw12, cid, item, index) == 'UNKNOWN'


@pytest.mark.parametrize('cid', ['azure.other.attack_t1537', 'azure.other.attack_t1619'])
def test_blob_ingestion_must_be_current(sw12, cid):
    item, index = case(cid)
    row = index['azure_detection_telemetry'][0]['data']
    row['latest_event_at'] = '2026-10-12T11:01:00+00:00'
    assert grade(sw12, cid, item, index) == 'UNKNOWN'
    row['latest_event_at'], row['event_count'] = None, 0
    assert grade(sw12, cid, item, index) == 'UNKNOWN'


def test_serverless_test_binds_configuration_and_live_delivery(sw12):
    cid = 'azure.other.attack_t1648'
    for change in ('missing', 'stale', 'other_config', 'not_fired', 'bad_correlation'):
        item, index = case(cid)
        row = index['azure_detection_test'][0]['data']
        if change == 'missing':
            set_rows(index, 'azure_detection_test', [])
        elif change == 'stale':
            row.update(event_at='2026-10-01T00:00:00+00:00', fired_at='2026-10-01T00:01:00+00:00',
                delivered_at='2026-10-01T00:02:00+00:00', observed_at='2026-10-01T00:03:00+00:00')
        elif change == 'other_config':
            row['configuration_sha256'] = '0' * 64
        elif change == 'not_fired':
            row.update(status='not_fired', fired_at=None, delivered_at=None)
        else:
            row['correlation_id'] = ''
        assert grade(sw12, cid, item, index) == 'UNKNOWN'


def test_impair_defenses_all_conditions_dimensions_and_override(sw12):
    cid = 'azure.other.attack_t1562'
    for change in ('second_condition', 'dimension', 'failing_periods'):
        item, index = case(cid)
        conditions = index['scheduled_query_rule'][0]['data']['properties']['criteria']['allOf']
        if change == 'second_condition':
            conditions.append({**copy.deepcopy(conditions[0]), 'threshold': 99999})
        elif change == 'dimension':
            conditions[0]['dimensions'] = [{'name': 'ResourceId', 'operator': 'Exclude', 'values': ['*']}]
        else:
            conditions[0]['failingPeriods'] = {'numberOfEvaluationPeriods': 10, 'minFailingPeriodsToAlert': 10}
        assert grade(sw12, cid, item, index) == 'UNKNOWN'
        req = policy(index, cid)['requirements'][0]
        rejected = []
        for condition in conditions:
            signature = {**copy.deepcopy(condition), 'query_sha256': qhash(condition['query']),
                'metricMeasureColumn': None, 'resourceIdColumn': None}
            signature.pop('query')
            rejected.append(signature)
        req.update(non_triggeringCriteria=[rejected], non_triggering_semantics_reviewed=True)
        assert grade(sw12, cid, item, index) == 'FAIL'
    item, index = case(cid)
    index['scheduled_query_rule'][0]['data']['properties']['overrideQueryTimeRange'] = 'PT30M'
    assert grade(sw12, cid, item, index) == 'PASS'


def test_enumeration_requires_identity_time_nature_and_approved_publication(sw12):
    cid = IDS[-1]
    for field in ('client_identity', 'timestamp', 'activity_nature'):
        item, index = case(cid)
        index['azure_enumeration_delivery'][0]['data']['payload'].pop(field)
        assert grade(sw12, cid, item, index) == 'FAIL'
    item, index = case(cid)
    index['azure_enumeration_delivery'][0]['data']['channel_id'] = 'unmonitored-channel'
    assert grade(sw12, cid, item, index) == 'FAIL'
    item, index = case(cid)
    index['azure_enumeration_delivery'][0]['data']['payload_complete'] = False
    assert grade(sw12, cid, item, index) == 'UNKNOWN'


def test_enumeration_empty_window_requires_continuous_coverage(sw12):
    cid = IDS[-1]
    item, index = case(cid)
    for kind in ('azure_enumeration_event', 'azure_enumeration_delivery'):
        set_rows(index, kind, [], query_window=index['collections'][kind][0]['query_window'])
    assert grade(sw12, cid, item, index) == 'PASS'
    index['azure_enumeration_coverage'][0]['data']['delivery_continuous'] = False
    assert grade(sw12, cid, item, index) == 'UNKNOWN'
    index['collections'].pop('azure_enumeration_coverage')
    index.pop('azure_enumeration_coverage')
    assert grade(sw12, cid, item, index) == 'UNKNOWN'


def test_enumeration_independence_settlement_and_correlation_unknown(sw12):
    cid = IDS[-1]
    for change in ('independent', 'settled', 'correlation', 'out_of_window'):
        item, index = case(cid)
        if change == 'independent':
            index['collections']['azure_enumeration_event'][0]['query_window']['independent'] = False
        elif change == 'settled':
            index['collections']['azure_enumeration_delivery'][0]['query_window']['settled_through'] = END
        elif change == 'correlation':
            index['azure_enumeration_delivery'][0]['data']['correlation_id'] = 'other'
        else:
            index['azure_enumeration_event'][0]['data']['timestamp'] = CAPTURE
        assert grade(sw12, cid, item, index) == 'UNKNOWN'


@pytest.mark.parametrize('cid', IDS)
def test_repeat_evaluation_immutable(sw12, cid):
    item, index = case(cid)
    original = copy.deepcopy(index)
    for _ in range(3):
        assert grade(sw12, cid, item, index) == 'PASS'
    assert index == original


@pytest.mark.parametrize('cid', IDS)
def test_frozen_engine_views_and_memo_indexes(sw12, cid):
    from peaso.checks.facts import MemoIndex
    from peaso.snapshot import freeze
    item, index = case(cid)
    frozen = freeze(index)
    memo = MemoIndex(frozen)
    for _ in range(2):
        assert grade(sw12, cid, freeze(item), memo) == 'PASS'


@pytest.mark.parametrize('cid', DETECTIONS)
def test_multiple_workspaces_respect_signed_all_vs_exists(sw12, cid):
    item, index = case(cid)
    workspace2 = WORKSPACE + '2'
    pol = policy(index, cid)
    pol['requiredWorkspaceIds'].append(workspace2)
    req = copy.deepcopy(pol['requirements'][0])
    req['workspace_id'] = workspace2
    pol['requirements'].append(req)
    set_rows(index, 'log_analytics_workspace', [index['log_analytics_workspace'][0]['data'],
        {'id': workspace2, 'properties': {'customerId': 'workspace2-guid'}}])
    telemetry = copy.deepcopy(index['azure_detection_telemetry'][0]['data'])
    telemetry['id'], telemetry['workspace_id'] = 'telemetry-2', workspace2
    set_rows(index, 'azure_detection_telemetry', [index['azure_detection_telemetry'][0]['data'], telemetry])
    expected = 'PASS' if cid.endswith(('attack_t1614', 'attack_t1651')) else 'FAIL'
    assert grade(sw12, cid, item, index) == expected
    rule2 = copy.deepcopy(index['scheduled_query_rule'][0]['data'])
    rule2['id'], rule2['properties']['scopes'] = RULE + '2', [workspace2]
    set_rows(index, 'scheduled_query_rule', [index['scheduled_query_rule'][0]['data'], rule2])
    if cid.endswith('attack_t1648'):
        test2 = copy.deepcopy(index['azure_detection_test'][0]['data'])
        test2.update(id='test-2', rule_id=rule2['id'], workspace_id=workspace2,
            configuration_sha256=digest({'criteria': req['approvedCriteria'][0], 'frequency': 300,
                'window': 600, 'effective_window': 600, 'mute': 0,
                'scopes': [workspace2.casefold()], 'groups': [GROUP.casefold()]}))
        set_rows(index, 'azure_detection_test', [index['azure_detection_test'][0]['data'], test2])
    assert grade(sw12, cid, item, index) == 'PASS'


def test_credential_host_file_source_requires_measured_detector(sw12):
    cid = 'azure.other.attack_t1552'
    item, index = case(cid)
    pol = policy(index, cid)
    pol['credential_source_inventory'][1].update(in_scope=True, source_id='host-files-source')
    req = copy.deepcopy(pol['requirements'][0])
    req.update(source_id='host-files-source', table='SysmonEvent', pattern_id='host-file-discovery')
    query = 'SysmonEvent | where OperationName == "credential-file-read"'
    req['requiredQueryFragments'] = ['SysmonEvent', '"credential-file-read"']
    req['approvedCriteria'][0][0]['query_sha256'] = qhash(query)
    pol['requirements'].append(req)
    rule = copy.deepcopy(index['scheduled_query_rule'][0]['data'])
    rule['id'] = RULE + '2'
    rule['properties']['criteria']['allOf'][0]['query'] = query
    set_rows(index, 'scheduled_query_rule', [index['scheduled_query_rule'][0]['data'], rule])
    assert grade(sw12, cid, item, index) == 'UNKNOWN'
    telemetry = copy.deepcopy(index['azure_detection_telemetry'][0]['data'])
    telemetry.update(id='host-telemetry', source_id='host-files-source', table='SysmonEvent',
        pattern_id='host-file-discovery', routing_evidence_ids=['dcr-config-evidence'])
    set_rows(index, 'azure_detection_telemetry', [index['azure_detection_telemetry'][0]['data'], telemetry])
    assert grade(sw12, cid, item, index) == 'PASS'


@pytest.mark.parametrize('cid', IDS)
@pytest.mark.parametrize('change', ['masked', 'provenance', 'provider', 'foreign_id'])
def test_masked_untrusted_and_foreign_evidence_unknown(sw12, cid, change):
    item, index = case(cid)
    kind = 'azure_enumeration_event' if cid == IDS[-1] else 'scheduled_query_rule'
    row = index[kind][0]['data']
    if change == 'masked':
        if cid == IDS[-1]:
            row['_coverage'] = {'timestamp': {'status': 'denied'}}
        else:
            row['properties']['_coverage'] = {'enabled': {'status': 'partial'}}
    elif change == 'provenance':
        row['_provenance']['native_response_complete'] = False
    elif change == 'provider':
        item = {**item, 'provider': 'aws'}
    else:
        row['id'] = OTHER + '/resourceGroups/rg/providers/Microsoft.Insights/scheduledQueryRules/rule'
    assert grade(sw12, cid, item, index) == 'UNKNOWN'


@pytest.mark.parametrize('cid', DETECTIONS)
def test_source_partial_bad_timing_and_unknown_group_evidence(sw12, cid):
    for change in ('partial', 'future', 'coverage', 'unmatched', 'route_absent'):
        item, index = case(cid)
        row = index['azure_detection_telemetry'][0]['data']
        if change == 'partial':
            index['collections']['azure_detection_telemetry'][0]['status'] = 'partial'
        elif change == 'future':
            row['query_window']['end'] = '2026-10-13T00:00:00+00:00'
        elif change == 'coverage':
            row['_coverage'] = {'routing_enabled': {'status': 'denied'}}
        elif change == 'unmatched':
            row['pattern_id'] = 'other-pattern'
        else:
            row['routing_enabled'], row['routing_evidence_ids'] = False, []
        expected = 'FAIL' if change == 'route_absent' else 'UNKNOWN'
        assert grade(sw12, cid, item, index) == expected


def test_enumeration_each_detected_event_needs_publication(sw12):
    cid = IDS[-1]
    item, index = case(cid)
    event = copy.deepcopy(index['azure_enumeration_event'][0]['data'])
    event.update(id='event-2', client_identity='client-2', correlation_id='correlation-2')
    set_rows(index, 'azure_enumeration_event', [index['azure_enumeration_event'][0]['data'], event],
        query_window=index['collections']['azure_enumeration_event'][0]['query_window'])
    assert grade(sw12, cid, item, index) == 'FAIL'
    delivery = copy.deepcopy(index['azure_enumeration_delivery'][0]['data'])
    delivery.update(id='delivery-2', event_id=event['id'], correlation_id=event['correlation_id'])
    delivery['payload']['client_identity'] = event['client_identity']
    set_rows(index, 'azure_enumeration_delivery', [index['azure_enumeration_delivery'][0]['data'], delivery],
        query_window=index['collections']['azure_enumeration_delivery'][0]['query_window'])
    assert grade(sw12, cid, item, index) == 'PASS'


def test_query_normalization_preserves_literals_comments_and_internal_space(sw12):
    query = 'AzureActivity | where OperationName == "A  B"\n// reviewed comment'
    assert sw12.query_digest('  ' + query.replace('\n', '\r\n') + '\r\n') == sw12.query_digest(query)
    assert sw12.query_digest(query.replace('A  B', 'A B')) != sw12.query_digest(query)
    assert sw12.query_digest(query.replace('A  B', 'a  b')) != sw12.query_digest(query)
    assert sw12.query_digest(query.split('\n')[0]) != sw12.query_digest(query)


def test_full_native_omission_defaults_and_nonalert_kind(sw12):
    cid = 'azure.other.attack_t1562'
    item, index = case(cid)
    rule = index['scheduled_query_rule'][0]['data']
    rule.pop('kind')
    rule['properties'].pop('muteActionsDuration')
    condition = rule['properties']['criteria']['allOf'][0]
    condition.pop('dimensions')
    condition.pop('failingPeriods')
    assert grade(sw12, cid, item, index) == 'PASS'
    rule['kind'] = 'LogToMetric'
    assert grade(sw12, cid, item, index) == 'FAIL'
    rule['kind'] = 'FutureUnknownKind'
    assert grade(sw12, cid, item, index) == 'UNKNOWN'


def test_enumeration_late_publication_is_violation(sw12):
    cid = IDS[-1]
    item, index = enumeration_case()
    index['azure_enumeration_delivery'][0]['data']['published_at'] = '2026-10-12T11:25:01+00:00'
    assert grade(sw12, cid, item, index) == 'FAIL'


@pytest.mark.parametrize("variant,expected", [
    ("exact_deadline", "PASS"),
    ("late_with_earlier_failed_attempt", "FAIL"),
    ("timely_second_channel", "PASS"),
    ("late_other_channel", "PASS"),
])
def test_enumeration_publication_deadline_boundaries(sw12, variant, expected):
    cid = IDS[-1]
    item, index = enumeration_case()
    row = index['azure_enumeration_delivery'][0]['data']
    if variant == "exact_deadline":
        row['published_at'] = '2026-10-12T11:25:00+00:00'
    elif variant == "late_with_earlier_failed_attempt":
        row['published_at'] = '2026-10-12T11:25:01+00:00'
        earlier = copy.deepcopy(row)
        earlier.update(id='delivery-2', publication_status='failed',
                       published_at='2026-10-12T11:21:00+00:00')
        set_rows(index, 'azure_enumeration_delivery', [row, earlier],
                 query_window=index['collections']['azure_enumeration_delivery'][0]['query_window'])
    else:
        late = copy.deepcopy(row)
        late.update(id='delivery-2', published_at='2026-10-12T11:25:01+00:00')
        if variant == "late_other_channel":
            late['channel_id'] = 'other-channel'
        set_rows(index, 'azure_enumeration_delivery', [row, late],
                 query_window=index['collections']['azure_enumeration_delivery'][0]['query_window'])
    assert grade(sw12, cid, item, index) == expected
