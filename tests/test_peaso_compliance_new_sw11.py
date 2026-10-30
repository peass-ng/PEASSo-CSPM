"""Signed Azure detection boundaries; import this swarm module in isolation."""
from __future__ import annotations

import copy
import importlib

import pytest

from peaso import checks as registry

# Direct imports register checks. Retain local safe evaluator references, then
# remove only additions made by this import, preserving every previous object.
_before = tuple(registry.CHECKS)
sw = importlib.import_module('peaso.checks.compliance_new_sw11')
_added = {id(check) for check in registry.CHECKS if check.id in sw.IDS and all(check is not old for old in _before)}
registry.CHECKS[:] = [check for check in registry.CHECKS if id(check) not in _added]

SCOPE = '/subscriptions/00000000-1111-2222-3333-444444444444'
PREFIX = SCOPE + '/resourceGroups/rg/providers/'
WORKSPACE = PREFIX + 'Microsoft.OperationalInsights/workspaces/security'
GROUP = PREFIX + 'Microsoft.Insights/actionGroups/response'
RULE = PREFIX + 'Microsoft.Insights/scheduledQueryRules/detection'
SOURCE = PREFIX + 'Microsoft.Storage/storageAccounts/sensitive'
CAPTURE = '2026-10-12T12:00:00Z'
RECENT = '2026-10-12T11:59:00Z'


def trigger():
    return {'timeAggregation': 'Count', 'operator': 'GreaterThan', 'threshold': 0,
            'failingPeriods': {'numberOfEvaluationPeriods': 1, 'minFailingPeriodsToAlert': 1},
            'dimensions': [], 'metricMeasureColumn': None, 'resourceIdColumn': None}


def put(index, kind, rows, status=None):
    status = status or ('collected' if rows else 'empty')
    index.setdefault('collections', {})[kind] = [{'type': kind, 'scope': SCOPE,
        'service': 'Microsoft.Insights', 'status': status, 'items': rows}]
    index[kind] = [{'provider': 'azure', 'type': kind, 'scope': SCOPE,
                   'native_id': row['id'], 'data': row} for row in rows]


def fixture(check_id):
    technique = check_id.rsplit('t', 1)[1]
    table = sw.TABLES.get(technique, 'SQLSecurityAuditEvents' if technique == '1213' else 'AzureActivity')
    query = table + ' | where OperationName == "approved event" | summarize count()'
    condition = {'query': query, **trigger()}
    review = {'sha256': sw.normalized_query_hash(query), 'normalization': sw.NORMALIZATION,
              'semantics_reviewed': True, 'fully_resolved': True,
              'effective_workspace_ids': [WORKSPACE], 'source_tables': [table],
              'evaluationFrequency': 'PT5M', 'windowSize': 'PT5M', 'max_lookback_seconds': 600,
              'trigger_semantics_reviewed': True, 'trigger': trigger(), 'max_trigger_delay_seconds': 300}
    requirement = {'pattern_id': 'primary', 'workspace_id': WORKSPACE,
                   'scope_ids': [WORKSPACE], 'queries': [review],
                   'required_fragments': ['where OperationName == "approved event"'],
                   'approved_action_group_ids': [GROUP], 'max_notification_delay_seconds': 600,
                   'sources': [{'resource_id': SOURCE, 'table': table, 'lookback_seconds': 600}]}
    row = {'id': RULE, 'kind': 'LogAlert', '_provenance': {'representation': 'full'},
           'properties': {'enabled': True, 'scopes': [WORKSPACE], 'criteria': {'allOf': [condition]},
                          'evaluationFrequency': 'PT5M', 'windowSize': 'PT5M',
                          'overrideQueryTimeRange': None, 'muteActionsDuration': 'PT0S',
                          'actions': {'actionGroups': [GROUP]}}}
    group = {'id': GROUP, 'properties': {'enabled': True},
             '_delivery_evidence': {'status': 'collected', 'reachable': True,
                 'action_group_id': GROUP, 'observed_at': RECENT, 'max_age_seconds': 600}}
    policy = {'status': 'collected', 'subscription_scope': SCOPE,
              'checks': {check_id: {'requirements': [requirement]}}}
    index = {'context': {'provider': 'azure', 'scope': SCOPE, 'created_at': CAPTURE,
              'metadata': {'compliance_policy': {'azure_attack_detection': policy}}}}
    put(index, 'scheduled_query_rule', [row])
    put(index, 'action_group', [group])
    put(index, 'log_analytics_workspace', [{'id': WORKSPACE}])
    telemetry = {'id': '|'.join((WORKSPACE.casefold(), SOURCE.casefold(), table)),
                 'workspace_id': WORKSPACE, 'source_resource_id': SOURCE, 'table': table,
                 'export_enabled': True, 'routing_verified': True, 'queried_at': CAPTURE,
                 'lookback_seconds': 600, 'last_ingested_at': RECENT, 'row_count': 1,
                 '_provenance': {'source_operation': 'logs.query', 'read_only': True,
                                 'source_filter_verified': True}}
    put(index, 'azure_detection_telemetry', [telemetry])
    return {'scope': SCOPE}, index


def evaluate(check_id, pair=None):
    item, index = pair or fixture(check_id)
    return sw.EVALUATORS[check_id](item, index)


def policy(index, check_id):
    return index['context']['metadata']['compliance_policy']['azure_attack_detection']['checks'][check_id]['requirements'][0]


def rule(index):
    return index['scheduled_query_rule'][0]['data']


@pytest.mark.parametrize('check_id', sw.IDS)
def test_pass_reviewed_complete_coverage(check_id):
    assert evaluate(check_id)[0] == 'PASS'


@pytest.mark.parametrize('check_id', sw.IDS)
def test_fail_proven_missing_rule(check_id):
    pair = fixture(check_id)
    put(pair[1], 'scheduled_query_rule', [])
    assert evaluate(check_id, pair)[0] == 'FAIL'


@pytest.mark.parametrize('check_id', sw.IDS)
def test_fail_disabled_rule(check_id):
    pair = fixture(check_id)
    rule(pair[1])['properties']['enabled'] = False
    assert evaluate(check_id, pair)[0] == 'FAIL'


@pytest.mark.parametrize('check_id', sw.IDS)
@pytest.mark.parametrize('kind', ['scheduled_query_rule', 'action_group', 'log_analytics_workspace'])
def test_unknown_incomplete_inventory(check_id, kind):
    pair = fixture(check_id)
    pair[1]['collections'][kind][0]['status'] = 'partial'
    assert evaluate(check_id, pair)[0] == 'UNKNOWN'


@pytest.mark.parametrize('check_id', sw.IDS)
@pytest.mark.parametrize('field', ['enabled', 'scopes', 'criteria', 'actions'])
def test_unknown_missing_native_fact(check_id, field):
    pair = fixture(check_id)
    rule(pair[1])['properties'].pop(field)
    assert evaluate(check_id, pair)[0] == 'UNKNOWN'


@pytest.mark.parametrize('check_id', sw.IDS)
@pytest.mark.parametrize('field,value', [('enabled', 'true'), ('scopes', WORKSPACE),
                                        ('criteria', {'allOf': [None]}), ('actions', [])])
def test_unknown_malformed_native_fact(check_id, field, value):
    pair = fixture(check_id)
    rule(pair[1])['properties'][field] = value
    assert evaluate(check_id, pair)[0] == 'UNKNOWN'


@pytest.mark.parametrize('check_id', sw.IDS)
def test_unknown_missing_policy_and_no_vacuous_pass(check_id):
    pair = fixture(check_id)
    pair[1]['context']['metadata'] = {}
    assert evaluate(check_id, pair)[0] == 'UNKNOWN'
    pair = fixture(check_id)
    pair[1]['context']['metadata']['compliance_policy']['azure_attack_detection']['checks'][check_id]['requirements'] = []
    assert evaluate(check_id, pair)[0] == 'UNKNOWN'


@pytest.mark.parametrize('check_id', sw.IDS)
@pytest.mark.parametrize('location', ['item', 'context', 'envelope', 'wrapper', 'native', 'policy'])
def test_unknown_foreign_scope(check_id, location):
    pair = fixture(check_id)
    foreign = SCOPE.replace('00000000', 'ffffffff')
    item, index = pair
    if location == 'item':
        item['scope'] = foreign
    elif location == 'context':
        index['context']['provider'] = 'aws'
    elif location == 'envelope':
        index['collections']['scheduled_query_rule'][0]['scope'] = foreign
    elif location == 'wrapper':
        index['scheduled_query_rule'][0]['scope'] = foreign
    elif location == 'native':
        rule(index)['id'] = RULE.replace(SCOPE, foreign)
    else:
        index['context']['metadata']['compliance_policy']['azure_attack_detection']['subscription_scope'] = foreign
    assert evaluate(check_id, pair)[0] == 'UNKNOWN'


@pytest.mark.parametrize('check_id', sw.IDS)
def test_unknown_duplicate_and_contradictory_inventory(check_id):
    pair = fixture(check_id)
    put(pair[1], 'scheduled_query_rule', [rule(pair[1]), copy.deepcopy(rule(pair[1]))])
    assert evaluate(check_id, pair)[0] == 'UNKNOWN'
    pair = fixture(check_id)
    pair[1]['collections']['scheduled_query_rule'][0]['status'] = 'empty'
    assert evaluate(check_id, pair)[0] == 'UNKNOWN'
    pair = fixture(check_id)
    pair[1]['collections']['scheduled_query_rule'][0]['items'] = []
    assert evaluate(check_id, pair)[0] == 'UNKNOWN'


@pytest.mark.parametrize('check_id', sw.IDS)
@pytest.mark.parametrize('field', ['fully_resolved', 'semantics_reviewed', 'normalization', 'sha256'])
def test_unknown_unreviewed_or_malformed_policy(check_id, field):
    pair = fixture(check_id)
    policy(pair[1], check_id)['queries'][0].pop(field)
    assert evaluate(check_id, pair)[0] == 'UNKNOWN'


@pytest.mark.parametrize('check_id', [x for x in sw.IDS if x.rsplit('t', 1)[1] not in sw.NO_TELEMETRY])
def test_unknown_missing_incomplete_and_empty_telemetry(check_id):
    pair = fixture(check_id)
    pair[1]['collections'].pop('azure_detection_telemetry')
    assert evaluate(check_id, pair)[0] == 'UNKNOWN'
    pair = fixture(check_id)
    pair[1]['collections']['azure_detection_telemetry'][0]['status'] = 'partial'
    assert evaluate(check_id, pair)[0] == 'UNKNOWN'
    pair = fixture(check_id)
    put(pair[1], 'azure_detection_telemetry', [])
    assert evaluate(check_id, pair)[0] == 'UNKNOWN'


@pytest.mark.parametrize('check_id', sw.IDS)
def test_action_group_state_matches_signed_predicate(check_id):
    pair = fixture(check_id)
    pair[1]['action_group'][0]['data']['properties']['enabled'] = False
    expected = 'PASS' if check_id.endswith('1496') else 'UNKNOWN' if check_id.endswith('1074') else 'FAIL'
    assert evaluate(check_id, pair)[0] == expected


@pytest.mark.parametrize('technique', sorted(sw.TRIGGERS))
@pytest.mark.parametrize('mutation', ['threshold', 'operator', 'aggregation', 'periods', 'dimensions'])
def test_fail_reviewed_query_with_nonapproved_trigger(technique, mutation):
    check_id = 'azure.other.attack_t' + technique
    pair = fixture(check_id)
    condition = rule(pair[1])['properties']['criteria']['allOf'][0]
    if mutation == 'threshold':
        condition['threshold'] = 1e12
    elif mutation == 'operator':
        condition['operator'] = 'LessThan'
    elif mutation == 'aggregation':
        condition['timeAggregation'] = 'Maximum'
    elif mutation == 'periods':
        condition['failingPeriods']['numberOfEvaluationPeriods'] = 2
    else:
        condition['dimensions'] = [{'name': 'OperationName', 'operator': 'Exclude', 'values': ['approved event']}]
    assert evaluate(check_id, pair)[0] == 'FAIL'


@pytest.mark.parametrize('technique', sorted(sw.DELAY))
def test_fail_unbounded_override_or_excessive_mute(technique):
    check_id = 'azure.other.attack_t' + technique
    pair = fixture(check_id)
    rule(pair[1])['properties']['overrideQueryTimeRange'] = 'P1D'
    assert evaluate(check_id, pair)[0] == 'FAIL'
    pair = fixture(check_id)
    rule(pair[1])['properties']['muteActionsDuration'] = 'PT20M'
    assert evaluate(check_id, pair)[0] == 'FAIL'
    pair = fixture(check_id)
    rule(pair[1])['properties'].pop('overrideQueryTimeRange')
    rule(pair[1])['_provenance'] = {'representation': 'partial'}
    assert evaluate(check_id, pair)[0] == 'UNKNOWN'


@pytest.mark.parametrize('check_id', [x for x in sw.IDS if not x.endswith('1496')])
def test_timing_policy_and_native_values_are_required(check_id):
    pair = fixture(check_id)
    policy(pair[1], check_id)['queries'][0].pop('max_lookback_seconds')
    assert evaluate(check_id, pair)[0] == 'UNKNOWN'
    pair = fixture(check_id)
    rule(pair[1])['properties']['evaluationFrequency'] = 'not-a-duration'
    assert evaluate(check_id, pair)[0] == 'UNKNOWN'
    pair = fixture(check_id)
    rule(pair[1])['properties']['evaluationFrequency'] = 'PT10M'
    assert evaluate(check_id, pair)[0] == 'FAIL'


@pytest.mark.parametrize('check_id', sw.IDS)
def test_additional_and_condition_stays_unknown(check_id):
    pair = fixture(check_id)
    rule(pair[1])['properties']['criteria']['allOf'].append({'query': 'AzureActivity | where false', **trigger()})
    assert evaluate(check_id, pair)[0] == 'UNKNOWN'


@pytest.mark.parametrize('check_id', sw.IDS)
def test_exact_digest_does_not_accept_comment_or_literal_keyword_tricks(check_id):
    pair = fixture(check_id)
    condition = rule(pair[1])['properties']['criteria']['allOf'][0]
    condition['query'] += '\n| where false // contains original detection tokens'
    expected = 'UNKNOWN' if check_id.rsplit('t', 1)[1] in sw.FRAGMENTS else 'FAIL'
    assert evaluate(check_id, pair)[0] == expected


@pytest.mark.parametrize('check_id', sw.IDS)
def test_immutable_repeat_evaluation(check_id):
    pair = fixture(check_id)
    before = copy.deepcopy(pair)
    assert evaluate(check_id, pair)[0] == 'PASS'
    assert evaluate(check_id, pair)[0] == 'PASS'
    assert pair == before


def test_query_normalization_preserves_string_literals():
    assert sw.normalized_query_hash('  AuditLogs\r\n| count\n') == sw.normalized_query_hash('AuditLogs\n| count')
    assert sw.normalized_query_hash('AuditLogs | where x == "a  b"') != sw.normalized_query_hash('AuditLogs | where x == "a b"')
    assert sw.normalized_query_hash('AuditLogs | where x == "A"') != sw.normalized_query_hash('AuditLogs | where x == "a"')


@pytest.mark.parametrize('technique', ['1049', '1069', '1213'])
def test_measured_ingestion_absence_differs_from_unreadable_telemetry(technique):
    check_id = 'azure.other.attack_t' + technique
    pair = fixture(check_id)
    row = pair[1]['azure_detection_telemetry'][0]['data']
    row['last_ingested_at'], row['row_count'] = None, 0
    assert evaluate(check_id, pair)[0] == ('FAIL' if technique == '1049' else 'UNKNOWN')
    row['row_count'] = -1
    assert evaluate(check_id, pair)[0] == 'UNKNOWN'


def test_t1213_disabled_data_plane_logging_and_control_plane_rejection():
    check_id = 'azure.other.attack_t1213'
    pair = fixture(check_id)
    pair[1]['azure_detection_telemetry'][0]['data']['export_enabled'] = False
    assert evaluate(check_id, pair)[0] == 'FAIL'
    pair = fixture(check_id)
    policy(pair[1], check_id)['queries'][0]['source_tables'] = ['AzureActivity']
    assert evaluate(check_id, pair)[0] == 'UNKNOWN'


def test_t1136_requires_fresh_reachable_delivery_evidence():
    check_id = 'azure.other.attack_t1136'
    pair = fixture(check_id)
    group = pair[1]['action_group'][0]['data']
    group['_delivery_evidence']['reachable'] = False
    assert evaluate(check_id, pair)[0] == 'FAIL'
    group.pop('_delivery_evidence')
    assert evaluate(check_id, pair)[0] == 'UNKNOWN'
    pair = fixture(check_id)
    pair[1]['action_group'][0]['data']['_delivery_evidence']['observed_at'] = '2020-01-01T00:00:00Z'
    assert evaluate(check_id, pair)[0] == 'UNKNOWN'


def test_t1199_documented_omitted_kind_default_requires_full_representation():
    check_id = 'azure.other.attack_t1199'
    pair = fixture(check_id)
    rule(pair[1]).pop('kind')
    assert evaluate(check_id, pair)[0] == 'PASS'
    rule(pair[1])['_provenance']['representation'] = 'partial'
    assert evaluate(check_id, pair)[0] == 'UNKNOWN'


@pytest.mark.parametrize('technique', ['1087', '1496', '1049', '1499'])
def test_existential_vs_every_required_workspace(technique):
    check_id = 'azure.other.attack_t' + technique
    pair = fixture(check_id)
    first = policy(pair[1], check_id)
    second = copy.deepcopy(first)
    other_ws = WORKSPACE + '-other'
    second['workspace_id'] = other_ws
    second['scope_ids'] = [other_ws]
    second['queries'][0]['effective_workspace_ids'] = [other_ws]
    pair[1]['context']['metadata']['compliance_policy']['azure_attack_detection']['checks'][check_id]['requirements'].append(second)
    put(pair[1], 'log_analytics_workspace', [{'id': WORKSPACE}, {'id': other_ws}])
    if technique not in sw.NO_TELEMETRY:
        old = pair[1]['azure_detection_telemetry'][0]['data']
        new = copy.deepcopy(old)
        new['workspace_id'] = other_ws
        new['id'] = '|'.join((other_ws.casefold(), SOURCE.casefold(), new['table']))
        put(pair[1], 'azure_detection_telemetry', [old, new])
    assert evaluate(check_id, pair)[0] == ('PASS' if technique in sw.EXISTENTIAL else 'FAIL')


@pytest.mark.parametrize('technique', ['1110', '1499', '1518'])
def test_all_required_patterns_are_covered(technique):
    check_id = 'azure.other.attack_t' + technique
    pair = fixture(check_id)
    second = copy.deepcopy(policy(pair[1], check_id))
    second['pattern_id'] = 'secondary'
    second['queries'][0]['sha256'] = sw.normalized_query_hash('DifferentReviewedPattern | count')
    pair[1]['context']['metadata']['compliance_policy']['azure_attack_detection']['checks'][check_id]['requirements'].append(second)
    assert evaluate(check_id, pair)[0] == 'FAIL'


def test_direct_import_does_not_leak_registry_changes():
    assert not _added.intersection(id(check) for check in registry.CHECKS)


def tenant_fixture(check_id='azure.other.attack_t1069'):
    pair = fixture(check_id)
    tenant = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'
    source = '/tenants/' + tenant
    metadata = pair[1]['context']['metadata']
    metadata.update(tenant_id=tenant, tenant_verified=True,
                    credential_context_id='capture-1', customer_context_id='customer-1',
                    subscription_tenants={SCOPE: tenant})
    policy(pair[1], check_id)['sources'][0]['resource_id'] = source
    row = pair[1]['azure_detection_telemetry'][0]['data']
    row['source_resource_id'] = source
    row['id'] = '|'.join((WORKSPACE.casefold(), source.casefold(), row['table']))
    row['_provenance'].update(tenant_id=tenant, tenant_verified=True,
                             credential_context_id='capture-1', customer_context_id='customer-1')
    pair[1]['azure_detection_telemetry'][0]['native_id'] = row['id']
    return pair


def test_pass_subscription_activity_and_verified_tenant_sources():
    assert evaluate('azure.other.attack_t1069', tenant_fixture())[0] == 'PASS'
    pair = fixture('azure.other.attack_t1082')
    policy(pair[1], 'azure.other.attack_t1082')['sources'][0]['resource_id'] = SCOPE
    row = pair[1]['azure_detection_telemetry'][0]['data']
    row['source_resource_id'] = SCOPE
    row['id'] = '|'.join((WORKSPACE.casefold(), SCOPE.casefold(), row['table']))
    pair[1]['azure_detection_telemetry'][0]['native_id'] = row['id']
    assert evaluate('azure.other.attack_t1082', pair)[0] == 'PASS'


@pytest.mark.parametrize('field,value', [('tenant_id', 'foreign'), ('tenant_verified', False),
                                        ('credential_context_id', 'foreign'), ('customer_context_id', 'foreign')])
def test_unknown_foreign_tenant_capture_and_customer_proof(field, value):
    pair = tenant_fixture()
    pair[1]['azure_detection_telemetry'][0]['data']['_provenance'][field] = value
    assert evaluate('azure.other.attack_t1069', pair)[0] == 'UNKNOWN'


def test_unknown_unverified_tenant_or_subscription_mapping():
    pair = tenant_fixture()
    pair[1]['context']['metadata']['tenant_verified'] = False
    assert evaluate('azure.other.attack_t1069', pair)[0] == 'UNKNOWN'
    pair = tenant_fixture()
    pair[1]['context']['metadata']['subscription_tenants'] = {SCOPE: 'foreign'}
    assert evaluate('azure.other.attack_t1069', pair)[0] == 'UNKNOWN'


@pytest.mark.parametrize('field,value', [('row_count', True), ('last_ingested_at', 'invalid'),
    ('lookback_seconds', -1), ('queried_at', '2030-01-01T00:00:00Z'),
    ('routing_verified', 'true'), ('export_enabled', None)])
def test_unknown_malformed_telemetry(field, value):
    check_id = 'azure.other.attack_t1049'
    pair = fixture(check_id)
    pair[1]['azure_detection_telemetry'][0]['data'][field] = value
    assert evaluate(check_id, pair)[0] == 'UNKNOWN'


@pytest.mark.parametrize('field', ['source_operation', 'source_filter_verified', 'read_only'])
def test_unknown_missing_telemetry_provenance(field):
    check_id = 'azure.other.attack_t1049'
    pair = fixture(check_id)
    pair[1]['azure_detection_telemetry'][0]['data']['_provenance'].pop(field)
    assert evaluate(check_id, pair)[0] == 'UNKNOWN'


@pytest.mark.parametrize('technique', sorted(sw.TRIGGERS))
def test_unknown_missing_trigger_review_or_malformed_trigger(technique):
    check_id = 'azure.other.attack_t' + technique
    pair = fixture(check_id)
    policy(pair[1], check_id)['queries'][0].pop('trigger_semantics_reviewed')
    assert evaluate(check_id, pair)[0] == 'UNKNOWN'
    pair = fixture(check_id)
    rule(pair[1])['properties']['criteria']['allOf'][0]['threshold'] = float('nan')
    assert evaluate(check_id, pair)[0] == 'UNKNOWN'
    pair = fixture(check_id)
    rule(pair[1])['properties']['criteria']['allOf'][0]['failingPeriods']['minFailingPeriodsToAlert'] = 0
    assert evaluate(check_id, pair)[0] == 'UNKNOWN'


@pytest.mark.parametrize('technique', ['1069', '1074'])
def test_fragment_policy_is_mandatory_and_absent_fragments_fail(technique):
    check_id = 'azure.other.attack_t' + technique
    pair = fixture(check_id)
    policy(pair[1], check_id).pop('required_fragments')
    assert evaluate(check_id, pair)[0] == 'UNKNOWN'
    pair = fixture(check_id)
    rule(pair[1])['properties']['criteria']['allOf'][0]['query'] = 'UnapprovedTable | count'
    assert evaluate(check_id, pair)[0] == 'FAIL'


def test_t1496_does_not_require_timing_or_ingestion():
    check_id = 'azure.other.attack_t1496'
    pair = fixture(check_id)
    for field in ('evaluationFrequency', 'windowSize', 'overrideQueryTimeRange', 'muteActionsDuration'):
        rule(pair[1])['properties'].pop(field)
    for field in ('evaluationFrequency', 'windowSize', 'max_lookback_seconds', 'trigger', 'trigger_semantics_reviewed'):
        policy(pair[1], check_id)['queries'][0].pop(field)
    pair[1]['collections'].pop('azure_detection_telemetry')
    pair[1]['action_group'][0]['data']['properties'].pop('enabled')
    assert evaluate(check_id, pair)[0] == 'PASS'


def test_policy_expiry_and_native_fact_coverage_remain_unknown():
    check_id = 'azure.other.attack_t1049'
    pair = fixture(check_id)
    owner_policy = pair[1]['context']['metadata']['compliance_policy']['azure_attack_detection']
    owner_policy.update(observed_at='2020-01-01T00:00:00Z', max_age_seconds=600)
    assert evaluate(check_id, pair)[0] == 'UNKNOWN'
    pair = fixture(check_id)
    rule(pair[1])['properties']['_coverage'] = {'enabled': {'status': 'denied'}}
    assert evaluate(check_id, pair)[0] == 'UNKNOWN'


@pytest.mark.parametrize('technique', sorted(sw.DELAY))
def test_notification_delay_includes_reviewed_trigger_delay(technique):
    check_id = 'azure.other.attack_t' + technique
    pair = fixture(check_id)
    rule(pair[1])['properties']['muteActionsDuration'] = 'PT6M'
    assert evaluate(check_id, pair)[0] == 'FAIL'
    pair = fixture(check_id)
    policy(pair[1], check_id)['queries'][0].pop('max_trigger_delay_seconds')
    assert evaluate(check_id, pair)[0] == 'UNKNOWN'


def test_t1213_complete_disabled_export_fails_without_log_query():
    check_id = 'azure.other.attack_t1213'
    pair = fixture(check_id)
    row = pair[1]['azure_detection_telemetry'][0]['data']
    row['export_enabled'] = False
    row['routing_verified'] = False
    for key in ('queried_at', 'row_count', 'last_ingested_at', 'lookback_seconds'):
        row.pop(key)
    row['_provenance'] = {'source_operation': 'diagnostic_settings.list', 'read_only': True,
                          'source_filter_verified': True, 'export_inventory_status': 'collected',
                          'export_observed_at': RECENT, 'export_max_age_seconds': 600}
    assert evaluate(check_id, pair)[0] == 'FAIL'
    row['_provenance']['export_inventory_status'] = 'partial'
    assert evaluate(check_id, pair)[0] == 'UNKNOWN'
