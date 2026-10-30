"""Source-bound tests for the unpublished sw53 GCP checks."""
from __future__ import annotations

import copy
import pytest

from peaso.checks import evaluate_check
from peaso.checks import compliance_new_sw53 as sw
from peaso.checks import CHECKS, evaluate_check

SCOPE = 'projects/p'
NOW = '2026-10-12T00:00:00Z'
RECENT = '2026-10-11T00:00:00Z'
OLD = '2026-08-01T00:00:00Z'
VM = {'name': 'vm', 'status': 'RUNNING'}
SQL = {'name': 'db', 'instanceType': 'CLOUD_SQL_INSTANCE', 'region': 'us-central1',
       'settings': {'backupConfiguration': {'enabled': True}, 'ipConfiguration': {'ipv4Enabled': False}}}
TARGET = {'name': 'restore', 'instanceType': 'CLOUD_SQL_INSTANCE', 'region': 'us-east1',
          'settings': {'backupConfiguration': {'enabled': True}, 'ipConfiguration': {'ipv4Enabled': False}}}
PROJECT = {'name': SCOPE}
IAM = {'name': SCOPE, '_representation': 'full', 'bindings': [{'role': 'roles/owner', 'members': ['user:a@example.com']}]}
INVENTORY = {'name': 'inv', 'instanceName': 'vm', 'updateTime': RECENT,
             'items': {'installedPackages': [{'name': 'safe', 'version': '1', 'installTime': RECENT},
                                            {'name': 'agent', 'version': '1', 'installTime': RECENT}]}}
VULN = {'name': 'report', 'instanceName': 'vm', 'vulnerabilities': []}
DEPLOY = {'name': 'deployment', 'enabled': True, 'instanceFilter': {'instanceNames': ['vm']},
          'recurringSchedule': {'active': True}}
OP = {'name': 'op', 'sourceInstance': 'db', 'targetId': 'restore', 'operationType': 'CLONE',
      'status': 'DONE', 'error': {}, 'endTime': RECENT, 'validated': True}
POLICY = {'vm_scope': ['vm'], 'sql_scope': ['db'], 'approved_software_register': [
    {'name': 'safe', 'version': '1'}, {'name': 'agent', 'version': '1'}],
    'approved_packages': {'safe': ['1'], 'agent': ['1']},
    'approved_agent_package_by_vm': {'vm': 'agent'},
    'approved_patch_grace_hours': 48, 'approved_patch_sla_hours': 48,
    'approved_patch_age_hours': 72, 'approved_rpo_hours': 48,
    'approved_offsite_policy': True, 'approved_restore_test_targets': ['restore'],
    'approved_restoration_instances': ['restore'],
    'required_condition_attributes': [{'resource': SCOPE, 'role': 'roles/owner',
        'member': 'user:a@example.com', 'attributes': ['request.time']}],
    'expiring_privileged_grants': [{'resource': SCOPE, 'role': 'roles/owner',
        'member': 'user:a@example.com'}],
    'personnel_changes': [], 'personnel_change_feed_complete': True,
}


def facts(kind, item, extra=None, policy=None):
    items = {kind: [item]}
    items.update(extra or {})
    context = {'provider': 'gcp', 'scope': SCOPE, 'created_at': NOW,
               'inherited_iam_complete': True, 'policy': copy.deepcopy(POLICY if policy is None else policy)}
    index = {'context': context, 'collections': {}}
    for resource_kind, rows in items.items():
        index['collections'][resource_kind] = [{'type': resource_kind, 'scope': SCOPE,
                                                 'status': 'collected', 'items': copy.deepcopy(rows)}]
        index[resource_kind] = [{'type': resource_kind, 'scope': SCOPE, 'data': copy.deepcopy(row)} for row in rows]
    return index


def scenario(check_id):
    vm = copy.deepcopy(VM); sql = copy.deepcopy(SQL); project = copy.deepcopy(PROJECT)
    iam = copy.deepcopy(IAM); inventory = copy.deepcopy(INVENTORY)
    if check_id == 'gcp_c5_software_inventory':
        return 'instance', vm, {'os_inventory': [inventory]}, lambda f: f['context']['policy']['approved_software_register'].pop()
    if check_id == 'gcp_compute_approved_packages':
        return 'instance', vm, {'os_inventory': [inventory]}, lambda f: f['context']['policy']['approved_packages']['safe'].clear()
    if check_id == 'gcp_c5_malware_telemetry':
        return 'instance', vm, {'os_inventory': [inventory]}, lambda f: [p for p in f['os_inventory'][0]['data']['items']['installedPackages'] if p['name'] != 'agent']
    if check_id in ('gcp.compute.os_patch_compliance', 'gcp_compute_os_patch_compliance'):
        extra = {'os_inventory': [inventory], 'os_vulnerability_report': [copy.deepcopy(VULN)]}
        def fail(f):
            f['os_vulnerability_report'][0]['data']['vulnerabilities'] = [{'severity': 'CRITICAL',
                'items': [{'availableInventoryItem': {'name': 'openssl', 'publishedTime': OLD}}]}]
        return 'instance', vm, extra, fail
    if check_id == 'gcp_c5_patch_deployment':
        return 'instance', vm, {'os_inventory': [inventory], 'os_patch_deployment': [copy.deepcopy(DEPLOY)]}, lambda f: f['os_patch_deployment'][0]['data'].update(enabled=False)
    if check_id == 'gcp_c5_sql_backup_run':
        return 'sql_instance', sql, {'sql_backup_run': [{'name': 'run', 'instanceName': 'db', 'type': 'AUTOMATED', 'status': 'SUCCESSFUL', 'endTime': RECENT}]}, lambda f: f['sql_backup_run'][0]['data'].update(status='FAILED')
    if check_id == 'gcp_c5_backup_remote_location':
        return 'sql_instance', sql, {'backup_target': [{'name': 'target', 'sourceInstance': 'db', 'failureRegion': 'us-east1'}]}, lambda f: f['backup_target'][0]['data'].update(failureRegion='us-central1')
    if check_id == 'gcp_c5_restore_test':
        return 'sql_instance', sql, {'sql_operation': [copy.deepcopy(OP)]}, lambda f: f['sql_operation'][0]['data'].update(endTime='2025-01-01T00:00:00Z')
    if check_id == 'gcp_c5_restore_destination':
        extra = {'sql_instance': [sql, copy.deepcopy(TARGET)], 'sql_operation': [copy.deepcopy(OP)],
                 'iam_policy': [{'name': 'db', '_representation': 'full', 'bindings': []}, {'name': 'restore', '_representation': 'full', 'bindings': []}]}
        return 'sql_instance', sql, extra, lambda f: f['context']['policy']['approved_restoration_instances'].clear()
    if check_id in ('gcp_c5_iam_conditions', 'gcp_c5_iam_expiry'):
        iam['bindings'][0]['condition'] = {'expression': 'request.time < timestamp("2027-01-01T00:00:00Z")'}
        return 'iam_policy', iam, {}, lambda f: f['iam_policy'][0]['data']['bindings'][0].pop('condition')
    if check_id == 'gcp_c5_iam_change_timeliness':
        def fail(f):
            f['context']['policy']['personnel_changes'] = [{'resource': SCOPE, 'principal': 'user:a@example.com',
                'forbiddenRole': 'roles/owner', 'tier': 'privileged', 'effectiveTime': OLD}]
        return 'iam_policy', iam, {}, fail
    if check_id == 'gcp.logging.access_transparency_entries':
        extra = {'access_transparency_entry': [{'name': 'entry', 'project': SCOPE,
            'logName': SCOPE + '/logs/cloudaudit.googleapis.com%2Faccess_transparency', 'timestamp': RECENT}]}
        return 'project', project, extra, lambda f: f['access_transparency_entry'][0]['data'].update(timestamp=OLD)
    if check_id == 'gcp_cloudsql_backup_failure_alert':
        extra = {'logging_metric': [{'name': SCOPE + '/metrics/failed_backup',
            'filter': 'resource.type="cloudsql_database" AND backup status FAILED', 'disabled': False, 'metricId': 'failed_backup', 'filterMatchesFailedCloudSqlBackupRun': True}],
            'monitoring_alert_policy': [{'name': 'alert', 'enabled': True,
                'conditions': [{'conditionThreshold': {'filter': 'metric.type="logging.googleapis.com/user/failed_backup"'}}]}]}
        return 'project', project, extra, lambda f: f['monitoring_alert_policy'][0]['data'].update(enabled=False)
    raise AssertionError(check_id)


@pytest.mark.parametrize('check_id', list(sw.META))
def test_pass_fail_and_signed_metadata(check_id):
    kind, item, extra, fail = scenario(check_id)
    index = facts(kind, item, extra)
    assert evaluate_check(check_id, item, index)[0] == 'PASS'
    failed = copy.deepcopy(index)
    maybe = fail(failed)
    if check_id == 'gcp_c5_malware_telemetry':
        failed['os_inventory'][0]['data']['items']['installedPackages'] = maybe
    for resource_kind, rows in failed.items():
        if resource_kind in failed['collections'] and isinstance(rows, list):
            failed['collections'][resource_kind][0]['items'] = [copy.deepcopy(r['data']) for r in rows]
    expected = 'UNKNOWN' if check_id == 'gcp.logging.access_transparency_entries' else 'FAIL'
    assert evaluate_check(check_id, failed[kind][0]['data'] if check_id in ('gcp_c5_iam_conditions', 'gcp_c5_iam_expiry') else item, failed)[0] == expected


@pytest.mark.parametrize('check_id', list(sw.META))
def test_incomplete_malformed_and_missing_fact_are_unknown(check_id):
    kind, item, extra, _ = scenario(check_id)
    index = facts(kind, item, extra)
    partial = copy.deepcopy(index)
    partial['collections'][kind][0]['status'] = 'partial'
    assert evaluate_check(check_id, item, partial)[0] == 'UNKNOWN'
    foreign = copy.deepcopy(index)
    foreign['collections'][kind][0]['scope'] = 'projects/other'
    assert evaluate_check(check_id, item, foreign)[0] == 'UNKNOWN'
    malformed = copy.deepcopy(index)
    malformed[kind][0]['data']['name'] = 4
    assert evaluate_check(check_id, item, malformed)[0] == 'UNKNOWN'
    missing = copy.deepcopy(index)
    missing['context'].pop('policy') if check_id not in ('gcp.logging.access_transparency_entries', 'gcp_cloudsql_backup_failure_alert') else missing['collections'].pop(next(iter(extra)))
    assert evaluate_check(check_id, item, missing)[0] == 'UNKNOWN'


@pytest.mark.parametrize('check_id', [x for x in sw.META if sw.META[x]['kind'] in ('instance', 'sql_instance')])
def test_out_of_scope_not_applicable(check_id):
    kind, item, extra, _ = scenario(check_id)
    index = facts(kind, item, extra)
    index['context']['policy']['vm_scope' if kind == 'instance' else 'sql_scope'] = []
    if check_id == 'gcp_c5_malware_telemetry':
        index['context']['policy']['approved_agent_package_by_vm'] = {}
    assert evaluate_check(check_id, item, index)[0] == 'NOT_APPLICABLE'


@pytest.mark.parametrize('check_id', [x for x in sw.META if sw.EXTRA[x]])
def test_missing_dependency_inventory_is_unknown(check_id):
    kind, item, extra, _ = scenario(check_id)
    index = facts(kind, item, extra)
    dependency = sw.EXTRA[check_id][0]
    index['collections'].pop(dependency)
    index.pop(dependency)
    assert evaluate_check(check_id, item, index)[0] == 'UNKNOWN'


def test_iam_requires_full_representation_and_inherited_coverage():
    for check_id in ('gcp_c5_iam_conditions', 'gcp_c5_iam_expiry', 'gcp_c5_iam_change_timeliness'):
        kind, item, extra, _ = scenario(check_id)
        index = facts(kind, item, extra)
        item.pop('_representation')
        index[kind][0]['data'].pop('_representation')
        assert evaluate_check(check_id, item, index)[0] == 'UNKNOWN'
        item['_representation'] = 'full'
        index[kind][0]['data']['_representation'] = 'full'
        index['context']['inherited_iam_complete'] = False
        assert evaluate_check(check_id, item, index)[0] == 'UNKNOWN'


def test_approved_numeric_version_range_and_ambiguous_alert_filter():
    kind, item, extra, _ = scenario('gcp_compute_approved_packages')
    index = facts(kind, item, extra)
    index['context']['policy']['approved_packages']['safe'] = ['>=1,<2']
    assert evaluate_check('gcp_compute_approved_packages', item, index)[0] == 'PASS'
    index['context']['policy']['approved_packages']['safe'] = ['>=2']
    assert evaluate_check('gcp_compute_approved_packages', item, index)[0] == 'FAIL'
    kind, item, extra, _ = scenario('gcp_cloudsql_backup_failure_alert')
    index = facts(kind, item, extra)
    index['monitoring_alert_policy'][0]['data']['conditions'][0]['conditionThreshold']['filter'] = (
        'NOT metric.type="logging.googleapis.com/user/failed_backup"')
    index['collections']['monitoring_alert_policy'][0]['items'] = [copy.deepcopy(index['monitoring_alert_policy'][0]['data'])]
    assert evaluate_check('gcp_cloudsql_backup_failure_alert', item, index)[0] == 'UNKNOWN'
