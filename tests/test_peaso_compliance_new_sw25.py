"""Isolated signed Azure evidence checks; no published-registry dependency."""
from __future__ import annotations

import copy
import hashlib
import json

import pytest

from peaso.checks import CHECKS
_before = tuple(CHECKS)
from peaso.checks import compliance_new_sw25 as sw
# Keep callable Check objects locally; restore the registry immediately, so this
# draft never affects other test files, even if this file is imported with them.
CHECKS[:] = _before

SCOPE = '/subscriptions/sub'
NOW = '2026-10-12T12:00:00+00:00'
START = '2026-10-12T10:00:00+00:00'
END = '2026-10-12T11:00:00+00:00'
RESOURCE = SCOPE + '/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm'
GATEWAY = SCOPE + '/resourceGroups/rg/providers/Microsoft.Network/applicationGateways/gw'
CLUSTER = SCOPE + '/resourceGroups/rg/providers/Microsoft.ContainerService/managedClusters/aks'
GROUP = SCOPE + '/resourceGroups/rg/providers/Microsoft.Insights/actionGroups/ag'
ALERT = SCOPE + '/resourceGroups/rg/providers/Microsoft.Insights/metricAlerts/metric'
PROOF = {'tenant_verified': True, 'tenant_id': 'tenant', 'credential_context_id': 'capture', 'customer_context_id': 'customer'}


def facts(cid, policy, inventories, graph=False):
    metadata = {'sw25_policy': {cid: {'scope': SCOPE, **policy}}, **PROOF,
                'subscription_tenants': {SCOPE: 'tenant'}}
    index = {'context': {'provider': 'azure', 'scope': SCOPE, 'created_at': NOW, 'metadata': metadata}, 'collections': {}}
    for kind, rows in inventories.items():
        collection_scope = '/tenants/tenant' if graph else SCOPE
        if graph:
            rows = [{**row, '_provenance': PROOF.copy()} for row in rows]
        index['collections'][kind] = [{'type': kind, 'scope': collection_scope,
            'status': 'collected' if rows else 'empty', 'items': rows,
            **({'service': 'Microsoft.Graph', '_provenance': PROOF.copy()} if graph else {})}]
        index[kind] = [{'type': kind, 'scope': collection_scope, 'data': row} for row in rows]
    return index


def evaluate(cid, index):
    return sw.EVALUATORS[cid]({'scope': SCOPE}, index)


def data(index, kind, number=0):
    return index[kind][number]['data']


def replace_rows(index, kind, rows):
    env = index['collections'][kind][0]
    env['items'] = rows
    env['status'] = 'collected' if rows else 'empty'
    index[kind] = [{'type': kind, 'scope': env['scope'], 'data': row} for row in rows]


def review(cid):
    guest_only = cid in (sw.MONTHLY_ID, sw.REGULAR_ID)
    role = 'none' if guest_only else 'nonPrivileged' if cid == sw.NONPRIV_ID else 'tenantCreator' if cid == sw.TENANT_ID else 'privileged'
    subject = {'id': 'subject', 'principalId': 'user', 'roleDefinitionId': 'role',
        'assignmentId': 'assignment', 'roleClass': role, 'userType': 'Guest', 'accountEnabled': True,
        'grantState': 'None' if guest_only else 'Active'}
    definition = {'id': 'definition', 'status': 'InProgress', 'settings': {'recurrence': {'pattern': {'type': 'weekly', 'interval': 1}}},
        '_coverage': {'instances': {'status': 'collected'}},
        '_resolvedScope': {'status': 'collected', 'subjectIds': ['subject'], 'excludedSubjectIds': []},
        '_resolvedSchedule': {'status': 'collected', 'coverageStart': '2026-01-01T00:00:00Z',
            'coverageEnd': NOW, 'activeStart': '2026-01-01T00:00:00Z', 'activeEnd': None,
            'dueWindows': [{'instanceId': 'instance', 'subjectIds': ['subject'], 'startDateTime': '2026-10-01T00:00:00Z', 'endDateTime': '2026-10-08T00:00:00Z'}]}}
    instance = {'id': 'instance', 'definitionId': 'definition', 'status': 'Completed',
        'completedDateTime': '2026-10-07T12:00:00Z', '_coverage': {'decisions': {'status': 'collected'}}}
    decision = {'id': 'decision', 'instanceId': 'instance', '_subjectId': 'subject', 'principal': {'id': 'user'},
        'decision': 'Approve', 'reviewedDateTime': '2026-10-07T10:00:00Z', 'reviewedBy': {'id': 'reviewer'}}
    return facts(cid, {'maxReviewAgeDays': 90, 'reviewMaxAgeDays': 90}, {
        'access_review_subject': [subject], 'access_review_definition': [definition],
        'access_review_instance': [instance], 'access_review_decision': [decision]}, graph=True)


def metric_props():
    return {'enabled': True, 'scopes': [RESOURCE], 'severity': 2, 'evaluationFrequency': 'PT1M', 'windowSize': 'PT5M',
        'criteria': {'odata.type': 'Microsoft.Azure.Monitor.SingleResourceMultipleMetricCriteria', 'allOf': [
            {'criterionType': 'StaticThresholdCriterion', 'metricName': 'Percentage CPU', 'metricNamespace': 'Microsoft.Compute/virtualMachines',
             'timeAggregation': 'Average', 'operator': 'GreaterThan', 'threshold': 80, 'dimensions': []}]},
        'actions': [{'actionGroupId': GROUP}]}


def alert_families():
    result = {}
    for kind, native in sw.ARM_TYPES.items():
        if kind not in sw.FAMILIES:
            continue
        props = {'enabled': True, 'scopes': [RESOURCE], '_applicableActionStates': ['Activated', 'Resolved'] if kind != 'activity_log_alert' else ['Activated'],
                 'actions': [{'actionGroupId': GROUP}] if kind == 'metric_alert' else {'actionGroups': [GROUP] if kind == 'scheduled_query_rule' else [{'actionGroupId': GROUP}]}}
        props['_actionStateBindings'] = [{'state': s, 'actionGroupIds': [GROUP]} for s in props['_applicableActionStates']]
        result[kind] = [{'id': SCOPE + '/resourceGroups/rg/providers/' + native + '/alert', 'properties': props}]
    return result


def monitoring(cid):
    props = metric_props()
    alerts = [{'id': ALERT, 'properties': props}]
    if cid == sw.ROUTING_ID:
        return facts(cid, {}, alert_families())
    if cid == sw.REQUIRED_ID:
        return facts(cid, {'requiredMetrics': [{'resourceId': RESOURCE, 'metricName': 'Percentage CPU', 'metricNamespace': 'Microsoft.Compute/virtualMachines'}]},
                     {'metric_alert': alerts, 'azure_resource': [{'id': RESOURCE}]})
    if cid == sw.SETTINGS_ID:
        expected = copy.deepcopy(props); expected['actionGroupIds'] = [GROUP]
        return facts(cid, {'expectedMetricSettings': [expected]}, {'metric_alert': alerts, 'action_group': [{'id': GROUP, 'properties': {'enabled': True}}]})
    if cid == sw.REPORT_ID:
        return facts(cid, {'windowStart': START, 'windowEnd': END, 'maxReportDelaySeconds': 300,
            'departmentRecipients': {'operations': ['receiver']},
            'criticalFailures': [{'operationName': 'critical/write', 'departmentIds': ['operations']}]}, {
            'failure_reporting_window': [{'id': 'window', 'windowStart': START, 'windowEnd': END, 'operationNames': ['critical/write'], 'continuousCoverage': []}],
            'failure_reporting_coverage': [],
            'critical_failure_event': [{'id': 'event', 'operationName': 'critical/write', 'status': 'Failed', 'eventTime': '2026-10-12T10:30:00Z'}],
            'failure_delivery_record': [{'id': 'delivery', 'eventId': 'event', 'departmentId': 'operations', 'automatic': True,
                '_coverage': {'receiver': {'status': 'collected'}},
                'receiverId': 'receiver', 'state': 'Delivered', 'attemptedAt': '2026-10-12T10:30:30Z', 'deliveredAt': '2026-10-12T10:31:00Z'}]})
    if cid == sw.CAPACITY_ID:
        return facts(cid, {'windowStart': START, 'windowEnd': END, 'components': [{'resourceId': RESOURCE,
            'failureScenarioIds': ['nodeFailure'], 'toleranceFraction': 0.8, 'sampleIntervalSeconds': 1800}]}, {
            'azure_resource': [{'id': RESOURCE}], 'capacity_change_record': [],
            'capacity_record': [{'resourceId': RESOURCE, 'windowStart': START, 'windowEnd': END,
                '_coverage': {'samples': {'status': 'collected'}},
                'samples': [{'time': START, 'usage': 20}, {'time': END, 'usage': 40}, {'time': '2026-10-12T10:30:00Z', 'usage': 30}],
                'baseline': {'average': 30, 'peak': 40, 'approvalRecordId': 'approved', 'approvedAt': END},
                'forecast': {'id': 'forecast', 'issuedAt': END, 'average': 30, 'peak': 50, 'capacity': 100,
                    'failureScenarios': [{'id': 'nodeFailure', 'average': 35, 'peak': 55, 'capacity': 80}]}}]})
    assert cid == sw.GATEWAY_ID
    begin, finish = '2026-10-12T10:00:00Z', '2026-10-12T10:05:00Z'
    props['scopes'] = [GATEWAY]
    props['criteria']['allOf'][0].update(metricName='HealthyToUnhealthyTargetFraction', metricNamespace='Peaso/GatewayTransitions', threshold=0.1)
    semantic = {'id': 'semantic', 'alertId': ALERT, 'parserVersion': 'gateway-transition-v1',
        'propertiesSha256': hashlib.sha256(json.dumps(props, sort_keys=True, separators=(',', ':')).encode()).hexdigest(),
        'criteria': {'numerator': 'healthyToUnhealthyTargets', 'denominator': 'totalTargetsAtWindowStart', 'windowSeconds': 300,
                     'operator': 'GreaterThan', 'thresholdFraction': 0.1}, 'evaluationFrequencySeconds': 60}
    return facts(cid, {'windowStart': begin, 'windowEnd': finish, 'maxAlertLatencySeconds': 120, 'evaluationIntervalSeconds': 60,
        'targetDenominator': 'totalTargetsAtWindowStart'}, {'application_gateway': [{'id': GATEWAY}],
        'metric_alert': alerts, 'activity_log_alert': [], 'scheduled_query_rule': [],
        'action_group': [{'id': GROUP, 'properties': {'enabled': True}}], 'gateway_alert_semantics': [semantic],
        'gateway_health_evidence': [{'id': 'evidence', 'gatewayId': GATEWAY, 'coverageStart': begin, 'coverageEnd': finish,
            '_coverage': {'windows': {'status': 'collected'}, 'alertEvaluations': {'status': 'collected'}},
            'windows': [{'start': begin, 'end': finish, 'startTargetIds': ['target'], 'endTargetIds': ['target'],
                'targets': [{'id': 'target', 'startHealth': 'Healthy', 'endHealth': 'Unhealthy', '_coverage': {'transitions': {'status': 'collected'}},
                             'transitions': [{'at': '2026-10-12T10:04:00Z', 'fromHealth': 'Healthy', 'toHealth': 'Unhealthy'}]}],
                'alertEvaluations': [{'alertId': ALERT, 'fired': True, 'firedAt': '2026-10-12T10:05:30Z',
                    'actionGroupId': GROUP, 'deliveredAt': '2026-10-12T10:05:40Z'}]}]}]})


def kubernetes(cid):
    containers = [{'name': 'main', 'image': 'approved.example/team/app:v1', 'resources': {'limits': {'cpu': '500m', 'memory': '128Mi'}},
                   'securityContext': {'appArmorProfile': {'type': 'RuntimeDefault'}}}]
    pod = {'metadata': {'uid': 'pod-uid', 'name': 'pod', 'namespace': 'ns'},
        '_provenance': {'cluster_id': CLUSTER, 'source_operation': 'list_pods', 'representation': 'full'},
        'spec': {'containers': containers, 'initContainers': [copy.deepcopy({**containers[0], 'name': 'init'})],
                 'ephemeralContainers': [copy.deepcopy({**containers[0], 'name': 'debug'})]}}
    inventories = {'pod': [pod], 'kubernetes_scope': [{'id': 'scope', 'clusters': [{'id': CLUSTER, 'kind': 'AKS', 'namespaces': ['ns'],
        '_coverage': {'namespaces': {'status': 'collected'}, 'pods': {'status': 'collected'}}}]}]}
    policy = {'containerKinds': ['containers', 'initContainers', 'ephemeralContainers']}
    if cid in (sw.LIMITS_ID, sw.APPARMOR_ID):
        inventories['pod_runtime'] = [{'id': 'runtime', 'clusterId': CLUSTER, 'podUid': 'pod-uid', 'nodeOs': 'linux',
            'kubernetesVersion': 'v1.31.0', 'appArmorEnabled': True, 'runtimeDefaultSupported': True, 'admissionEffectsResolved': True,
            '_coverage': {'limitRangeBindings': {'status': 'collected'}}, 'limitRangeBindings': []}]
    if cid == sw.LIMITS_ID:
        policy.update(maxCpu='1', maxMemory='256Mi'); inventories['limit_range'] = []
    elif cid == sw.APPARMOR_ID:
        policy.update(allowedProfiles=[{'type': 'RuntimeDefault'}], nonLinuxApplies=False)
        # Explicit synthetic external host observations; the native Pod capture
        # and the node capability flags above do not supply applied profiles.
        pod['spec']['nodeName'] = 'node-a'
        pod['status'] = {status: [{'name': name, 'containerID': 'containerd://' + name}]
                         for status, name in (('containerStatuses', 'main'),
                                              ('initContainerStatuses', 'init'),
                                              ('ephemeralContainerStatuses', 'debug'))}
        runtime = inventories['pod_runtime'][0]
        common = {'clusterId': CLUSTER, 'podUid': 'pod-uid', 'nodeName': 'node-a',
                  'nodeUid': 'node-uid', 'observer': 'independent-host-observer',
                  'sourceDocumentId': 'external-host-measurement', 'readOnly': True,
                  'observedAt': '2026-10-12T11:59:00Z',
                  'credential_context_id': PROOF['credential_context_id'],
                  'customer_context_id': PROOF['customer_context_id']}
        runtime['appArmorNodeEvidence'] = {**common, 'sourceOperation': 'external_node_runtime_read',
            'nodeOs': 'linux', 'appArmorEnabled': True, 'kubernetesVersion': 'v1.31.0',
            'runtimeDefaultSupported': True, 'runtimeDefaultProfileName': 'runtime-profile-a'}
        runtime['appArmorProfiles'] = [{**common, 'sourceOperation': 'external_container_kernel_profile_read',
            'containerKind': kind, 'containerName': name, 'containerId': 'containerd://' + name,
            'profileType': 'RuntimeDefault', 'appliedProfileName': 'runtime-profile-a',
            'enforcementMode': 'enforce'} for kind, name in
            (('containers', 'main'), ('initContainers', 'init'), ('ephemeralContainers', 'debug'))]
    else:
        policy.update(mode='images', allowed=['approved.example/team/app:v1'], immutableImages=False)
    return facts(cid, policy, inventories)


def fixture(cid):
    return review(cid) if cid in sw.REVIEW_IDS else kubernetes(cid) if cid in (sw.LIMITS_ID, sw.APPARMOR_ID, sw.IMAGES_ID) else monitoring(cid)


def unsafe(cid, index):
    if cid in sw.REVIEW_IDS:
        data(index, 'access_review_decision')['decision'] = 'NotReviewed'
    elif cid == sw.REPORT_ID:
        data(index, 'failure_delivery_record')['deliveredAt'] = '2026-10-12T10:45:00Z'
    elif cid == sw.ROUTING_ID:
        row = data(index, 'activity_log_alert')['properties']
        row['actions']['actionGroups'] = []
        for binding in row['_actionStateBindings']: binding['actionGroupIds'] = []
    elif cid == sw.CAPACITY_ID:
        data(index, 'capacity_record')['forecast']['failureScenarios'][0]['peak'] = 79
    elif cid == sw.GATEWAY_ID:
        data(index, 'gateway_health_evidence')['windows'][0]['alertEvaluations'][0] = {'alertId': ALERT, 'fired': False}
    elif cid in (sw.REQUIRED_ID, sw.SETTINGS_ID):
        data(index, 'metric_alert')['properties']['enabled'] = False
    elif cid == sw.LIMITS_ID:
        data(index, 'pod')['spec']['ephemeralContainers'][0]['resources']['limits']['cpu'] = '2'
    elif cid == sw.APPARMOR_ID:
        data(index, 'pod')['spec']['initContainers'][0]['securityContext']['appArmorProfile']['type'] = 'Unconfined'
    elif cid == sw.IMAGES_ID:
        data(index, 'pod')['spec']['ephemeralContainers'][0]['image'] = 'evil.example/team/app:v1'


@pytest.mark.parametrize('cid', sw.IDS)
def test_pass(cid):
    index = fixture(cid)
    baseline = copy.deepcopy(index)
    for _ in range(2): assert evaluate(cid, index)[0] == 'PASS'
    assert index == baseline


@pytest.mark.parametrize('cid', sw.IDS)
def test_positive_fail(cid):
    index = fixture(cid); unsafe(cid, index)
    assert evaluate(cid, index)[0] == 'FAIL'


@pytest.mark.parametrize('cid', sw.IDS)
@pytest.mark.parametrize('damage', ['missing_fact', 'incomplete', 'denied', 'malformed', 'foreign_scope', 'duplicate', 'missing_policy'])
def test_unknown_boundaries(cid, damage):
    index = fixture(cid)
    kind = sw.DEPENDENCIES[cid][0]
    if damage == 'missing_fact':
        del index['collections'][kind]; del index[kind]
    elif damage in ('incomplete', 'denied'):
        index['collections'][kind][0]['status'] = 'partial' if damage == 'incomplete' else 'denied'
    elif damage == 'malformed':
        index[kind][0]['data'] = 'malformed'
    elif damage == 'foreign_scope':
        index['collections'][kind][0]['scope'] = '/subscriptions/foreign'
    elif damage == 'duplicate':
        rows = [w['data'] for w in index[kind]]
        replace_rows(index, kind, [*rows, copy.deepcopy(rows[0])])
    elif damage == 'missing_policy':
        index['context']['metadata']['sw25_policy'].pop(cid)
    assert evaluate(cid, index)[0] == 'UNKNOWN'


@pytest.mark.parametrize('cid', sw.REVIEW_IDS)
def test_review_complete_absence_and_not_applicable(cid):
    index = fixture(cid)
    replace_rows(index, 'access_review_decision', [])
    assert evaluate(cid, index)[0] == 'FAIL'
    index = fixture(cid); replace_rows(index, 'access_review_definition', []); replace_rows(index, 'access_review_instance', []); replace_rows(index, 'access_review_decision', [])
    assert evaluate(cid, index)[0] == 'FAIL'
    index = fixture(cid); replace_rows(index, 'access_review_subject', [])
    assert evaluate(cid, index)[0] == ('PASS' if cid == sw.NONPRIV_ID else 'NOT_APPLICABLE')


@pytest.mark.parametrize('cid', [sw.REGULAR_ID, sw.NONPRIV_ID, sw.PRIV_ID, sw.TENANT_ID])
def test_review_latest_completed_and_newer_in_progress(cid):
    index = fixture(cid)
    latest = copy.deepcopy(data(index, 'access_review_instance'))
    latest.update(id='new', status='InProgress'); latest.pop('completedDateTime')
    replace_rows(index, 'access_review_instance', [data(index, 'access_review_instance'), latest])
    assert evaluate(cid, index)[0] == 'PASS'
    latest.update(status='Completed', completedDateTime='2026-10-11T00:00:00Z')
    assert evaluate(cid, index)[0] == 'FAIL'


@pytest.mark.parametrize('cid', sw.REVIEW_IDS)
def test_review_unresolved_scope_pages_and_foreign_principal(cid):
    index = fixture(cid)
    data(index, 'access_review_definition')['_resolvedScope']['status'] = 'partial'
    assert evaluate(cid, index)[0] == 'UNKNOWN'
    index = fixture(cid)
    data(index, 'access_review_definition')['_coverage']['instances']['status'] = 'denied'
    assert evaluate(cid, index)[0] == 'UNKNOWN'
    index = fixture(cid)
    data(index, 'access_review_decision')['principal']['id'] = 'other'
    assert evaluate(cid, index)[0] == 'FAIL'
    index = fixture(cid)
    index['context']['metadata']['customer_context_id'] = 'other'
    assert evaluate(cid, index)[0] == 'UNKNOWN'


def test_monthly_due_window_cadence_and_completion():
    index = fixture(sw.MONTHLY_ID)
    data(index, 'access_review_definition')['settings']['recurrence']['pattern'] = {'type': 'absoluteMonthly', 'interval': 1}
    assert evaluate(sw.MONTHLY_ID, index)[0] == 'PASS'
    data(index, 'access_review_instance')['completedDateTime'] = '2026-10-09T00:00:00Z'
    assert evaluate(sw.MONTHLY_ID, index)[0] == 'FAIL'
    index = fixture(sw.MONTHLY_ID)
    data(index, 'access_review_definition')['settings']['recurrence']['pattern']['interval'] = 5
    assert evaluate(sw.MONTHLY_ID, index)[0] == 'FAIL'
    index = fixture(sw.MONTHLY_ID)
    data(index, 'access_review_definition')['_resolvedSchedule']['dueWindows'] = []
    assert evaluate(sw.MONTHLY_ID, index)[0] == 'UNKNOWN'


def test_review_dontknow_reviewer_and_tenant_deny():
    index = fixture(sw.REGULAR_ID)
    data(index, 'access_review_decision')['decision'] = 'DontKnow'
    assert evaluate(sw.REGULAR_ID, index)[0] == 'PASS'
    data(index, 'access_review_decision').pop('reviewedBy')
    assert evaluate(sw.REGULAR_ID, index)[0] == 'UNKNOWN'
    index = fixture(sw.TENANT_ID)
    data(index, 'access_review_decision')['decision'] = 'Deny'
    assert evaluate(sw.TENANT_ID, index)[0] == 'FAIL'


def test_reporting_empty_events_need_independent_coverage_and_automatic_delivery():
    index = fixture(sw.REPORT_ID)
    data(index, 'failure_delivery_record')['automatic'] = False
    assert evaluate(sw.REPORT_ID, index)[0] == 'FAIL'
    replace_rows(index, 'critical_failure_event', []); replace_rows(index, 'failure_delivery_record', [])
    assert evaluate(sw.REPORT_ID, index)[0] == 'UNKNOWN'
    data(index, 'failure_reporting_window')['continuousCoverage'] = [{'start': START, 'end': END,
        'detectionEvidenceIds': ['probe'], 'reportingEvidenceIds': ['delivery-test']}]
    assert evaluate(sw.REPORT_ID, index)[0] == 'UNKNOWN'
    replace_rows(index, 'failure_reporting_coverage', [{'id': pid, 'purpose': purpose, 'independentMonitorId': 'separate-monitor',
        'operationNames': ['critical/write'], '_coverage': {'segments': {'status': 'collected'}},
        'segments': [{'start': START, 'end': END, 'available': True, 'sourceRecordIds': ['observation'],
            'receiverIds': ['receiver'], 'automaticNotificationCount': 10, 'maximumMeasuredDelaySeconds': 60}]}
        for pid, purpose in [('probe', 'detection'), ('delivery-test', 'reporting')]])
    assert evaluate(sw.REPORT_ID, index)[0] == 'PASS'


def test_capacity_breach_requires_initiated_change_and_samples():
    index = fixture(sw.CAPACITY_ID); unsafe(sw.CAPACITY_ID, index)
    replace_rows(index, 'capacity_change_record', [{'id': 'change', 'resourceId': RESOURCE, 'forecastId': 'forecast',
        'initiatedAt': '2026-10-12T11:30:00Z', 'changeManagementId': 'ticket'}])
    assert evaluate(sw.CAPACITY_ID, index)[0] == 'PASS'
    data(index, 'capacity_record')['samples'] = []
    assert evaluate(sw.CAPACITY_ID, index)[0] == 'UNKNOWN'


def test_alert_optional_approved_group_and_unresolved_state():
    index = fixture(sw.ROUTING_ID)
    index['context']['metadata']['sw25_policy'][sw.ROUTING_ID]['actionGroupId'] = GROUP.replace('/ag', '/other')
    assert evaluate(sw.ROUTING_ID, index)[0] == 'FAIL'
    index = fixture(sw.ROUTING_ID)
    data(index, 'metric_alert')['properties'].pop('_applicableActionStates')
    assert evaluate(sw.ROUTING_ID, index)[0] == 'UNKNOWN'


def test_metric_exact_match_dimensions_action_status_and_dynamic_criteria():
    index = fixture(sw.SETTINGS_ID)
    data(index, 'metric_alert')['properties']['criteria']['allOf'][0]['threshold'] = 81
    assert evaluate(sw.SETTINGS_ID, index)[0] == 'FAIL'
    index = fixture(sw.SETTINGS_ID)
    data(index, 'action_group')['properties']['enabled'] = False
    assert evaluate(sw.SETTINGS_ID, index)[0] == 'FAIL'
    index = fixture(sw.SETTINGS_ID)
    data(index, 'metric_alert')['properties']['criteria']['allOf'][0]['criterionType'] = 'DynamicThresholdCriterion'
    assert evaluate(sw.SETTINGS_ID, index)[0] == 'UNKNOWN'
    index = fixture(sw.REQUIRED_ID)
    index['context']['metadata']['sw25_policy'][sw.REQUIRED_ID]['requiredMetrics'] = []
    assert evaluate(sw.REQUIRED_ID, index)[0] == 'NOT_APPLICABLE'


def test_gateway_simple_health_threshold_fails_and_missing_delivery_unknown():
    index = fixture(sw.GATEWAY_ID)
    data(index, 'gateway_alert_semantics')['criteria']['numerator'] = 'UnhealthyHostCount'
    assert evaluate(sw.GATEWAY_ID, index)[0] == 'FAIL'
    index = fixture(sw.GATEWAY_ID)
    data(index, 'gateway_health_evidence')['windows'][0]['alertEvaluations'][0].pop('deliveredAt')
    assert evaluate(sw.GATEWAY_ID, index)[0] == 'UNKNOWN'
    index = fixture(sw.GATEWAY_ID)
    replace_rows(index, 'application_gateway', [])
    assert evaluate(sw.GATEWAY_ID, index)[0] == 'NOT_APPLICABLE'


def test_limits_missing_and_namespace_defaults_and_admission():
    index = fixture(sw.LIMITS_ID)
    main = data(index, 'pod')['spec']['containers'][0]
    main.pop('resources')
    assert evaluate(sw.LIMITS_ID, index)[0] == 'FAIL'
    replace_rows(index, 'limit_range', [{'metadata': {'uid': 'lr', 'namespace': 'ns', 'resourceVersion': '42'}, '_provenance': {'cluster_id': CLUSTER},
        'spec': {'limits': [{'type': 'Container', 'default': {'cpu': '500m', 'memory': '128Mi'}}]}}])
    assert evaluate(sw.LIMITS_ID, index)[0] == 'UNKNOWN'
    data(index, 'pod_runtime')['limitRangeBindings'] = [{'uid': 'lr', 'resourceVersion': '42'}]
    assert evaluate(sw.LIMITS_ID, index)[0] == 'PASS'
    data(index, 'pod_runtime')['admissionEffectsResolved'] = False
    assert evaluate(sw.LIMITS_ID, index)[0] == 'UNKNOWN'
    index = fixture(sw.LIMITS_ID)
    data(index, 'pod')['spec']['containers'][0]['resources']['limits']['cpu'] = 'garbage'
    assert evaluate(sw.LIMITS_ID, index)[0] == 'UNKNOWN'


def test_apparmor_override_default_legacy_and_nonlinux():
    index = fixture(sw.APPARMOR_ID)
    pod = data(index, 'pod')
    for key in ('containers', 'initContainers', 'ephemeralContainers'):
        pod['spec'][key][0].pop('securityContext')
    assert evaluate(sw.APPARMOR_ID, index)[0] == 'PASS'
    data(index, 'pod_runtime')['appArmorNodeEvidence']['runtimeDefaultSupported'] = False
    assert evaluate(sw.APPARMOR_ID, index)[0] == 'UNKNOWN'
    index = fixture(sw.APPARMOR_ID)
    data(index, 'pod_runtime')['appArmorNodeEvidence']['nodeOs'] = 'windows'
    assert evaluate(sw.APPARMOR_ID, index)[0] == 'NOT_APPLICABLE'
    index = fixture(sw.APPARMOR_ID)
    data(index, 'pod_runtime')['appArmorNodeEvidence']['kubernetesVersion'] = 'v1.29.0'
    pod = data(index, 'pod')
    pod['metadata']['annotations'] = {}
    for key in ('containers', 'initContainers', 'ephemeralContainers'):
        container = pod['spec'][key][0]; container.pop('securityContext')
        pod['metadata']['annotations']['container.apparmor.security.beta.kubernetes.io/' + container['name']] = 'runtime/default'
    assert evaluate(sw.APPARMOR_ID, index)[0] == 'PASS'


def test_images_tag_registry_boundaries_and_runtime_digest():
    index = fixture(sw.IMAGES_ID)
    policy = index['context']['metadata']['sw25_policy'][sw.IMAGES_ID]
    policy.update(mode='registries', allowed=['approved.example'])
    assert evaluate(sw.IMAGES_ID, index)[0] == 'PASS'
    data(index, 'pod')['spec']['containers'][0]['image'] = 'approved.example.evil/team/app:v1'
    assert evaluate(sw.IMAGES_ID, index)[0] == 'FAIL'
    index = fixture(sw.IMAGES_ID)
    policy = index['context']['metadata']['sw25_policy'][sw.IMAGES_ID]
    digest = 'sha256:' + 'a' * 64
    policy.update(mode='digests', allowed=[digest])
    assert evaluate(sw.IMAGES_ID, index)[0] == 'UNKNOWN'
    pod = data(index, 'pod'); pod['status'] = {}
    for kind, status in [('containers', 'containerStatuses'), ('initContainers', 'initContainerStatuses'), ('ephemeralContainers', 'ephemeralContainerStatuses')]:
        pod['status'][status] = [{'name': pod['spec'][kind][0]['name'], 'imageID': 'containerd://' + digest}]
    assert evaluate(sw.IMAGES_ID, index)[0] == 'PASS'
    pod['status']['ephemeralContainerStatuses'][0]['imageID'] = 'containerd://sha256:' + 'b' * 64
    assert evaluate(sw.IMAGES_ID, index)[0] == 'FAIL'


@pytest.mark.parametrize('cid', sw.IDS)
def test_missing_required_evaluator_field(cid):
    index = fixture(cid)
    if cid in sw.REVIEW_IDS:
        data(index, 'access_review_instance').pop('completedDateTime')
    elif cid == sw.REPORT_ID:
        data(index, 'failure_delivery_record').pop('receiverId')
    elif cid == sw.ROUTING_ID:
        data(index, 'metric_alert')['properties'].pop('enabled')
    elif cid == sw.CAPACITY_ID:
        data(index, 'capacity_record')['forecast'].pop('capacity')
    elif cid == sw.GATEWAY_ID:
        data(index, 'gateway_health_evidence')['windows'][0]['targets'][0].pop('transitions')
    elif cid in (sw.SETTINGS_ID, sw.REQUIRED_ID):
        data(index, 'metric_alert')['properties']['criteria']['allOf'][0].pop('metricName')
    elif cid == sw.LIMITS_ID:
        data(index, 'pod_runtime').pop('limitRangeBindings')
    elif cid == sw.APPARMOR_ID:
        data(index, 'pod_runtime').pop('nodeOs')
    elif cid == sw.IMAGES_ID:
        data(index, 'pod')['spec']['containers'][0].pop('image')
    assert evaluate(cid, index)[0] == 'UNKNOWN'


@pytest.mark.parametrize('cid', sw.IDS)
def test_masked_dependency_field_and_foreign_scope_subject(cid):
    index = fixture(cid)
    assert sw.EVALUATORS[cid]({'scope': '/subscriptions/foreign'}, index)[0] == 'UNKNOWN'
    kind = sw.DEPENDENCIES[cid][0]
    row = data(index, kind)
    identity = 'metadata' if kind == 'pod' else 'resourceId' if kind == 'capacity_record' else 'id'
    row['_coverage'] = {identity: {'status': 'denied'}}
    assert evaluate(cid, index)[0] == 'UNKNOWN'


def test_gateway_recovered_target_still_counts_unhealthy_transition():
    index = fixture(sw.GATEWAY_ID)
    window = data(index, 'gateway_health_evidence')['windows'][0]
    target = window['targets'][0]
    target['endHealth'] = 'Healthy'
    target['transitions'].append({'at': '2026-10-12T10:04:30Z', 'fromHealth': 'Unhealthy', 'toHealth': 'Healthy'})
    assert evaluate(sw.GATEWAY_ID, index)[0] == 'PASS'
    window['alertEvaluations'] = [{'alertId': ALERT, 'fired': False}]
    assert evaluate(sw.GATEWAY_ID, index)[0] == 'FAIL'
    target.pop('transitions')
    assert evaluate(sw.GATEWAY_ID, index)[0] == 'UNKNOWN'


def test_tenant_known_denial_precedes_unresolved_other_assignment():
    index = fixture(sw.TENANT_ID)
    unsafe(sw.TENANT_ID, index)
    data(index, 'access_review_decision')['decision'] = 'Deny'
    subject = copy.deepcopy(data(index, 'access_review_subject'))
    subject.update(id='unresolved-subject', roleClass='unresolved')
    replace_rows(index, 'access_review_subject', [data(index, 'access_review_subject'), subject])
    assert evaluate(sw.TENANT_ID, index)[0] == 'FAIL'


def test_equivalent_alert_durations_and_optional_metric_namespace_and_group():
    index = fixture(sw.SETTINGS_ID)
    data(index, 'metric_alert')['properties']['evaluationFrequency'] = 'PT60S'
    data(index, 'metric_alert')['properties']['windowSize'] = 'PT300S'
    index['context']['metadata']['sw25_policy'][sw.SETTINGS_ID]['expectedMetricSettings'][0].pop('actionGroupIds')
    assert evaluate(sw.SETTINGS_ID, index)[0] == 'PASS'
    index = fixture(sw.REQUIRED_ID)
    index['context']['metadata']['sw25_policy'][sw.REQUIRED_ID]['requiredMetrics'][0].pop('metricNamespace')
    assert evaluate(sw.REQUIRED_ID, index)[0] == 'PASS'


def test_reporting_pending_after_deadline_and_receiver_resolution():
    index = fixture(sw.REPORT_ID)
    data(index, 'failure_delivery_record')['state'] = 'Pending'
    assert evaluate(sw.REPORT_ID, index)[0] == 'FAIL'
    index = fixture(sw.REPORT_ID)
    data(index, 'failure_delivery_record')['_coverage']['receiver']['status'] = 'denied'
    assert evaluate(sw.REPORT_ID, index)[0] == 'UNKNOWN'
    index = fixture(sw.REPORT_ID)
    data(index, 'failure_delivery_record')['receiverId'] = 'another-department'
    assert evaluate(sw.REPORT_ID, index)[0] == 'FAIL'


def test_localhost_apparmor_profile_requires_exact_owner_match():
    index = fixture(sw.APPARMOR_ID)
    profile = data(index, 'pod')['spec']['containers'][0]['securityContext']['appArmorProfile']
    profile.update(type='Localhost', localhostProfile='approved-profile')
    assert evaluate(sw.APPARMOR_ID, index)[0] == 'FAIL'
    index['context']['metadata']['sw25_policy'][sw.APPARMOR_ID]['allowedProfiles'].append({'type': 'Localhost', 'localhostProfile': 'approved-profile'})
    measured = data(index, 'pod_runtime')['appArmorProfiles'][0]
    measured.update(profileType='Localhost', appliedProfileName='kernel-profile-a', resolvedLocalhostProfile='approved-profile')
    assert evaluate(sw.APPARMOR_ID, index)[0] == 'PASS'
    profile.pop('localhostProfile')
    assert evaluate(sw.APPARMOR_ID, index)[0] == 'UNKNOWN'


def test_approved_pinned_image_needs_runtime_byte_evidence():
    index = fixture(sw.IMAGES_ID)
    policy = index['context']['metadata']['sw25_policy'][sw.IMAGES_ID]
    digest = 'sha256:' + 'c' * 64
    pinned = 'approved.example/team/app@' + digest
    policy['allowed'] = [pinned]
    pod = data(index, 'pod'); pod['status'] = {}
    for kind, status in [('containers', 'containerStatuses'), ('initContainers', 'initContainerStatuses'), ('ephemeralContainers', 'ephemeralContainerStatuses')]:
        pod['spec'][kind][0]['image'] = pinned
    assert evaluate(sw.IMAGES_ID, index)[0] == 'UNKNOWN'
    for kind, status in [('containers', 'containerStatuses'), ('initContainers', 'initContainerStatuses'), ('ephemeralContainers', 'ephemeralContainerStatuses')]:
        pod['status'][status] = [{'name': pod['spec'][kind][0]['name'], 'imageID': 'docker-pullable://' + pinned}]
    assert evaluate(sw.IMAGES_ID, index)[0] == 'PASS'
    policy.update(immutableImages=True, allowedDigests=[digest])
    assert evaluate(sw.IMAGES_ID, index)[0] == 'PASS'
    policy['allowedDigests'] = ['sha256:' + 'd' * 64]
    assert evaluate(sw.IMAGES_ID, index)[0] == 'FAIL'


@pytest.mark.parametrize('cid', sw.REVIEW_IDS)
def test_review_stale_decision_cannot_hide_behind_recent_completion(cid):
    index = fixture(cid)
    data(index, 'access_review_decision')['reviewedDateTime'] = '2025-01-01T00:00:00Z'
    assert evaluate(cid, index)[0] == 'FAIL'


def test_signed_custom_metric_thresholds_are_compared_exactly():
    index = fixture(sw.SETTINGS_ID)
    index['context']['metadata']['sw25_policy'][sw.SETTINGS_ID]['expectedMetricSettings'][0]['criteria']['allOf'][0]['threshold'] = -1
    data(index, 'metric_alert')['properties']['criteria']['allOf'][0]['threshold'] = -1
    assert evaluate(sw.SETTINGS_ID, index)[0] == 'PASS'
    data(index, 'metric_alert')['properties']['criteria']['allOf'][0]['threshold'] = -2
    assert evaluate(sw.SETTINGS_ID, index)[0] == 'FAIL'


def _gateway_registered_status(index):
    """Exercise the staged check through the signed snapshot and actual engine."""
    from tests.compliance_draft_isolation import staged_registry
    from peaso.engine import evaluate_snapshot
    from peaso.snapshot import make_snapshot
    with staged_registry(['compliance_new_sw25']):
        collections = [c for envelopes in index['collections'].values() for c in envelopes]
        snapshot = make_snapshot('azure', [SCOPE], collections,
                                 metadata=index['context']['metadata'], created_at=NOW)
        findings = evaluate_snapshot(snapshot, checks=[sw.GATEWAY_ID])['findings']
        return next(f['status'] for f in findings if f['check_id'] == sw.GATEWAY_ID)


def _gateway_two_windows(first, second):
    index = fixture(sw.GATEWAY_ID)
    policy = index['context']['metadata']['sw25_policy'][sw.GATEWAY_ID]
    policy['windowEnd'] = '2026-10-12T10:06:00Z'
    evidence = data(index, 'gateway_health_evidence')
    evidence['coverageEnd'] = policy['windowEnd']
    original = evidence['windows'][0]
    earlier = copy.deepcopy(original)
    later = copy.deepcopy(original)
    earlier['targets'][0].update(first)
    later.update(start='2026-10-12T10:01:00Z', end='2026-10-12T10:06:00Z')
    later['targets'][0].update(second)
    for window in (earlier, later):
        window['alertEvaluations'] = [{'alertId': ALERT, 'fired': False}]
    evidence['windows'] = [earlier, later]
    return index


def test_gateway_overlapping_incompatible_constant_health_cannot_pass_registered_engine():
    index = _gateway_two_windows(
        {'startHealth': 'Healthy', 'endHealth': 'Healthy', 'transitions': []},
        {'startHealth': 'Unhealthy', 'endHealth': 'Unhealthy', 'transitions': []})
    assert _gateway_registered_status(index) == 'UNKNOWN'


def _gateway_mark_delivered(window, fired_at, delivered_at):
    window['alertEvaluations'] = [{'alertId': ALERT, 'fired': True,
        'firedAt': fired_at, 'actionGroupId': GROUP, 'deliveredAt': delivered_at}]


def test_gateway_overlapping_same_healthy_history_passes():
    index = _gateway_two_windows(
        {'startHealth': 'Healthy', 'endHealth': 'Healthy', 'transitions': []},
        {'startHealth': 'Healthy', 'endHealth': 'Healthy', 'transitions': []})
    assert _gateway_registered_status(index) == 'PASS'


def test_gateway_overlapping_shared_unhealthy_event_and_delivery_passes():
    event = {'at': '2026-10-12T10:04:00Z', 'fromHealth': 'Healthy', 'toHealth': 'Unhealthy'}
    index = _gateway_two_windows(
        {'startHealth': 'Healthy', 'endHealth': 'Unhealthy', 'transitions': [event]},
        {'startHealth': 'Healthy', 'endHealth': 'Unhealthy', 'transitions': [event]})
    windows = data(index, 'gateway_health_evidence')['windows']
    _gateway_mark_delivered(windows[0], '2026-10-12T10:05:30Z', '2026-10-12T10:05:40Z')
    _gateway_mark_delivered(windows[1], '2026-10-12T10:06:30Z', '2026-10-12T10:06:40Z')
    assert _gateway_registered_status(index) == 'PASS'


def test_gateway_overlapping_shared_recovery_after_breach_passes():
    events = [
        {'at': '2026-10-12T10:02:00Z', 'fromHealth': 'Healthy', 'toHealth': 'Unhealthy'},
        {'at': '2026-10-12T10:03:00Z', 'fromHealth': 'Unhealthy', 'toHealth': 'Healthy'}]
    index = _gateway_two_windows(
        {'startHealth': 'Healthy', 'endHealth': 'Healthy', 'transitions': events},
        {'startHealth': 'Healthy', 'endHealth': 'Healthy', 'transitions': events})
    windows = data(index, 'gateway_health_evidence')['windows']
    _gateway_mark_delivered(windows[0], '2026-10-12T10:05:30Z', '2026-10-12T10:05:40Z')
    _gateway_mark_delivered(windows[1], '2026-10-12T10:06:30Z', '2026-10-12T10:06:40Z')
    assert _gateway_registered_status(index) == 'PASS'


def test_gateway_transition_at_first_end_agrees_with_second_history():
    event = {'at': '2026-10-12T10:05:00Z', 'fromHealth': 'Healthy', 'toHealth': 'Unhealthy'}
    index = _gateway_two_windows(
        {'startHealth': 'Healthy', 'endHealth': 'Unhealthy', 'transitions': [event]},
        {'startHealth': 'Healthy', 'endHealth': 'Unhealthy', 'transitions': [event]})
    windows = data(index, 'gateway_health_evidence')['windows']
    _gateway_mark_delivered(windows[0], '2026-10-12T10:05:30Z', '2026-10-12T10:05:40Z')
    _gateway_mark_delivered(windows[1], '2026-10-12T10:06:30Z', '2026-10-12T10:06:40Z')
    assert _gateway_registered_status(index) == 'PASS'


def test_gateway_transition_at_first_end_disagrees_with_second_history():
    event = {'at': '2026-10-12T10:05:00Z', 'fromHealth': 'Healthy', 'toHealth': 'Unhealthy'}
    index = _gateway_two_windows(
        {'startHealth': 'Healthy', 'endHealth': 'Unhealthy', 'transitions': [event]},
        {'startHealth': 'Healthy', 'endHealth': 'Healthy', 'transitions': []})
    _gateway_mark_delivered(data(index, 'gateway_health_evidence')['windows'][0],
                            '2026-10-12T10:05:30Z', '2026-10-12T10:05:40Z')
    assert _gateway_registered_status(index) == 'UNKNOWN'


def test_gateway_nonoverlapping_target_windows_do_not_invent_gap_membership():
    index = _gateway_two_windows(
        {'startHealth': 'Healthy', 'endHealth': 'Healthy', 'transitions': []},
        {'startHealth': 'Unhealthy', 'endHealth': 'Unhealthy', 'transitions': []})
    policy = index['context']['metadata']['sw25_policy'][sw.GATEWAY_ID]
    policy['windowEnd'] = '2026-10-12T10:11:00Z'
    policy['evaluationIntervalSeconds'] = 360
    evidence = data(index, 'gateway_health_evidence')
    evidence['coverageEnd'] = policy['windowEnd']
    evidence['windows'][1].update(start='2026-10-12T10:06:00Z', end=policy['windowEnd'])
    assert _gateway_registered_status(index) == 'PASS'


def test_gateway_different_target_ids_in_overlapping_windows_do_not_cross_join():
    index = _gateway_two_windows(
        {'startHealth': 'Healthy', 'endHealth': 'Healthy', 'transitions': []},
        {'startHealth': 'Unhealthy', 'endHealth': 'Unhealthy', 'transitions': []})
    later = data(index, 'gateway_health_evidence')['windows'][1]
    later['targets'][0]['id'] = 'other-target'
    later['startTargetIds'] = ['other-target']
    later['endTargetIds'] = ['other-target']
    assert _gateway_registered_status(index) == 'PASS'


def test_gateway_contradiction_does_not_mask_measured_nonalerted_breach():
    event = {'at': '2026-10-12T10:04:00Z', 'fromHealth': 'Healthy', 'toHealth': 'Unhealthy'}
    index = _gateway_two_windows(
        {'startHealth': 'Healthy', 'endHealth': 'Unhealthy', 'transitions': [event]},
        {'startHealth': 'Unhealthy', 'endHealth': 'Unhealthy', 'transitions': []})
    assert _gateway_registered_status(index) == 'FAIL'


def test_gateway_overlapping_shifted_transition_times_are_unknown():
    earlier_event = {'at': '2026-10-12T10:04:00Z', 'fromHealth': 'Healthy', 'toHealth': 'Unhealthy'}
    later_event = {'at': '2026-10-12T10:03:00Z', 'fromHealth': 'Healthy', 'toHealth': 'Unhealthy'}
    index = _gateway_two_windows(
        {'startHealth': 'Healthy', 'endHealth': 'Unhealthy', 'transitions': [earlier_event]},
        {'startHealth': 'Healthy', 'endHealth': 'Unhealthy', 'transitions': [later_event]})
    windows = data(index, 'gateway_health_evidence')['windows']
    _gateway_mark_delivered(windows[0], '2026-10-12T10:05:30Z', '2026-10-12T10:05:40Z')
    _gateway_mark_delivered(windows[1], '2026-10-12T10:06:30Z', '2026-10-12T10:06:40Z')
    assert _gateway_registered_status(index) == 'UNKNOWN'


def test_critical_future_continuity_cannot_pass():
    index = fixture(sw.REPORT_ID)
    replace_rows(index, 'critical_failure_event', [])
    replace_rows(index, 'failure_delivery_record', [])
    future = '2026-10-12T13:00:00Z'
    data(index, 'failure_reporting_window')['continuousCoverage'] = [{
        'start': START, 'end': future, 'detectionEvidenceIds': ['probe'],
        'reportingEvidenceIds': ['delivery-test']}]
    replace_rows(index, 'failure_reporting_coverage', [{
        'id': pid, 'purpose': purpose, 'independentMonitorId': 'separate-monitor',
        'operationNames': ['critical/write'], '_coverage': {'segments': {'status': 'collected'}},
        'segments': [{'start': START, 'end': future, 'available': True,
            'sourceRecordIds': ['observation'], 'receiverIds': ['receiver'],
            'automaticNotificationCount': 10, 'maximumMeasuredDelaySeconds': 60}]}
        for pid, purpose in [('probe', 'detection'), ('delivery-test', 'reporting')]])
    assert evaluate(sw.REPORT_ID, index)[0] == 'UNKNOWN'


def critical_empty_coverage_case():
    index = fixture(sw.REPORT_ID)
    replace_rows(index, 'critical_failure_event', [])
    replace_rows(index, 'failure_delivery_record', [])
    data(index, 'failure_reporting_window')['continuousCoverage'] = [{
        'start': START, 'end': END, 'detectionEvidenceIds': ['probe'],
        'reportingEvidenceIds': ['delivery-test']}]
    replace_rows(index, 'failure_reporting_coverage', [{
        'id': pid, 'purpose': purpose, 'independentMonitorId': 'separate-monitor',
        'operationNames': ['critical/write'], '_coverage': {'segments': {'status': 'collected'}},
        'segments': [{'start': START, 'end': END, 'available': True,
            'sourceRecordIds': ['observation'], 'receiverIds': ['receiver'],
            'automaticNotificationCount': 10, 'maximumMeasuredDelaySeconds': 60}]}
        for pid, purpose in [('probe', 'detection'), ('delivery-test', 'reporting')]])
    return index


@pytest.mark.parametrize('variant,expected', [
    ('valid_closed_window', 'PASS'),
    ('future_interval_only', 'UNKNOWN'),
    ('future_detection_segment', 'UNKNOWN'),
    ('future_reporting_segment', 'UNKNOWN'),
    ('extra_future_detection_segment', 'UNKNOWN'),
    ('extra_future_reporting_segment', 'UNKNOWN'),
    ('interval_ends_at_capture', 'PASS'),
    ('segments_end_at_capture', 'PASS'),
    ('one_second_after_capture', 'UNKNOWN'),
])
def test_critical_continuity_snapshot_boundaries(variant, expected):
    index = critical_empty_coverage_case()
    interval = data(index, 'failure_reporting_window')['continuousCoverage'][0]
    detection = data(index, 'failure_reporting_coverage', 0)['segments']
    reporting = data(index, 'failure_reporting_coverage', 1)['segments']
    future = '2026-10-12T13:00:00Z'
    if variant == 'future_interval_only':
        interval['end'] = future
    elif variant == 'future_detection_segment':
        detection[0]['end'] = future
    elif variant == 'future_reporting_segment':
        reporting[0]['end'] = future
    elif variant == 'extra_future_detection_segment':
        detection.append({**detection[0], 'start': END, 'end': future})
    elif variant == 'extra_future_reporting_segment':
        reporting.append({**reporting[0], 'start': END, 'end': future})
    elif variant == 'interval_ends_at_capture':
        interval['end'] = NOW
        detection[0]['end'] = NOW
        reporting[0]['end'] = NOW
    elif variant == 'segments_end_at_capture':
        detection[0]['end'] = NOW
        reporting[0]['end'] = NOW
    elif variant == 'one_second_after_capture':
        detection[0]['end'] = '2026-10-12T12:00:01Z'
    assert evaluate(sw.REPORT_ID, index)[0] == expected
