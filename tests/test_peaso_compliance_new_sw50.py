"""Isolated draft tests for signed sw50 GCP checks."""
from __future__ import annotations

import copy
from datetime import datetime, timedelta, timezone

import pytest

from peaso.checks import evaluate_check
from peaso.checks import compliance_new_sw50 as sw
from peaso.checks import CHECKS, evaluate_check


SCOPE = 'projects/demo-project'
NOW = datetime(2026, 10, 12, tzinfo=timezone.utc)


def stamp(seconds=0):
    return (NOW + timedelta(seconds=seconds)).isoformat()


def index(kind, rows, *, metadata=None, status='collected', scope=SCOPE, coverage=None):
    env = {'type': kind, 'scope': scope, 'status': status, 'items': copy.deepcopy(rows)}
    if coverage is not None:
        env['audit_coverage'] = coverage
    return {'context': {'provider': 'gcp', 'scope': scope, 'created_at': stamp(),
                        'metadata': metadata or {}},
            'collections': {kind: [env]},
            kind: [{'type': kind, 'scope': scope, 'data': copy.deepcopy(row)} for row in rows]}


def event(method='other.method', principal='user@example.com', code=0, seconds=0, number=0, **extra):
    row = {'insertId': f'event-{number}', 'logName': SCOPE + '/logs/cloudaudit.googleapis.com%2Factivity',
           'resource': {'type': 'cloud_run_revision' if method == 'run.routes.invoke' else 'audited_resource',
                        'labels': {'project_id': 'demo-project'}}, 'timestamp': stamp(seconds),
           'authenticationEvent': False,
           'protoPayload': {'methodName': method, 'authenticationInfo': {'principalEmail': principal},
                            'status': {'code': code}, 'requestMetadata': {'callerIp': '192.0.2.4'}}}
    for key, value in extra.items():
        row['protoPayload'][key] = value
    return row


def audit_index(rows, metadata=None, *, complete=True, status='collected'):
    coverage = {'complete': complete, 'all_pages': True, 'start': stamp(-3600),
                'end': stamp(3600), 'authentication_events': True}
    return index('audit_log', rows, metadata=metadata, status=status, coverage=coverage)


def bucket(name='storage-bucket', **extra):
    return {'name': name, '_provenance': {'scope': SCOPE},
            'softDeletePolicy': {'retentionDurationSeconds': '0'},
            'versioning': {'enabled': False}, 'retentionPolicy': {'retentionPeriod': '0'},
            'location': 'EU', 'replicationHealth': {'status': 'HEALTHY'},
            'iamPolicy': {'bindings': []}, 'iamConfiguration': {'uniformBucketLevelAccess': {'enabled': True}},
            **extra}


def run(cid, row, facts):
    return evaluate_check(cid, row, facts)[0]


@pytest.mark.parametrize('cid', [key for key in sw.SPECS if key.startswith('gcp_logging_detect_')])
def test_audit_pass_fail_and_unavailable(cid):
    if cid == 'gcp_logging_detect_t1110':
        rows = [event('authentication.login', code=7, seconds=n * 20, number=n) for n in range(10)]
        for row in rows:
            row['authenticationEvent'] = True
        policy = {}
    elif cid in ('gcp_logging_detect_t1119', 'gcp_logging_detect_t1518',
                 'gcp_logging_detect_t1526', 'gcp_logging_detect_t1614', 'gcp_logging_detect_t1619'):
        method = {'gcp_logging_detect_t1119': 'service.Get',
                  'gcp_logging_detect_t1518': 'osconfig.inventories.get',
                  'gcp_logging_detect_t1526': 'serviceusage.services.list',
                  'gcp_logging_detect_t1614': 'compute.regions.list',
                  'gcp_logging_detect_t1619': 'storage.objects.list'}[cid]
        rows = [event(method, seconds=n * 20, number=n) for n in range(2)]
        policy = {'approved_read_rate' if cid.endswith('t1119') else 'approved_list_rate': 1}
    elif cid == 'gcp_logging_detect_t1490':
        rows = [event('cloudsql.backupRuns.delete')]
        policy = {'approved_backup_admins': []}
    else:
        method, key = {
            'gcp_logging_detect_t1136': ('google.iam.admin.v1.CreateServiceAccount', 'approved_identity_admins'),
            'gcp_logging_detect_t1546': ('google.devtools.cloudbuild.v1.CloudBuild.CreateBuildTrigger', 'approved_automation_admins'),
            'gcp_logging_detect_t1648': ('run.routes.invoke', 'approved_invokers'),
            'gcp_logging_detect_t1651': ('SetIamPolicy', 'approved_cloud_admins'),
        }[cid]
        rows, policy = [event(method)], {key: []}
    facts = audit_index(rows, policy)
    assert run(cid, rows[0], facts) == 'FAIL'
    safe = [event(number=99)]
    assert run(cid, safe[0], audit_index(safe, policy)) == 'PASS'
    assert run(cid, rows[0], audit_index(rows, policy, complete=False)) == 'UNKNOWN'
    assert run(cid, rows[0], audit_index(rows, policy, status='partial')) == 'UNKNOWN'
    if policy:
        assert run(cid, rows[0], audit_index(rows, {})) == 'UNKNOWN'
    malformed = copy.deepcopy(rows)
    malformed[0]['protoPayload']['status']['code'] = 'zero'
    assert run(cid, malformed[0], audit_index(malformed, policy)) == 'UNKNOWN'
    missing = index('audit_log', rows, metadata=policy)
    assert run(cid, rows[0], missing) == 'UNKNOWN'
    foreign = copy.deepcopy(rows)
    foreign[0]['resource']['labels']['project_id'] = 'other'
    assert run(cid, foreign[0], audit_index(foreign, policy)) == 'UNKNOWN'
    if cid == 'gcp_logging_detect_t1648':
        wrong_type = copy.deepcopy(rows)
        wrong_type[0]['resource']['type'] = 'gce_instance'
        assert run(cid, wrong_type[0], audit_index(wrong_type, policy)) == 'UNKNOWN'


def test_authentication_grouping_and_window():
    cid = 'gcp_logging_detect_t1110'
    rows = [event('authentication.login', code=7, seconds=n * 40, number=n) for n in range(10)]
    for row in rows:
        row['authenticationEvent'] = True
    assert run(cid, rows[0], audit_index(rows)) == 'PASS'
    for row in rows:
        row['timestamp'] = stamp()
    rows[-1]['protoPayload']['requestMetadata']['callerIp'] = '192.0.2.5'
    assert run(cid, rows[0], audit_index(rows)) == 'PASS'
    rows[-1]['protoPayload']['requestMetadata']['callerIp'] = '192.0.2.4'
    assert run(cid, rows[0], audit_index(rows)) == 'FAIL'


def test_cloud_sql_disable_requires_explicit_request_intent():
    cid = 'gcp_logging_detect_t1490'
    row = event('cloudsql.instances.update', request={'settings': {'backupConfiguration': {'enabled': False}}})
    assert run(cid, row, audit_index([row], {'approved_backup_admins': []})) == 'FAIL'
    row['protoPayload']['request'] = {'settings': {'backupConfiguration': {'enabled': True}}}
    assert run(cid, row, audit_index([row], {'approved_backup_admins': []})) == 'PASS'
    row['protoPayload']['request'] = {}
    assert run(cid, row, audit_index([row], {'approved_backup_admins': []})) == 'UNKNOWN'


def test_deletion_pass_fail_unknown_and_not_applicable():
    cid = 'gcp_c5_deletion_recoverability'
    row = bucket()
    policy = {'approved_bucket_deletions': {'storage-bucket': {'immediate_deletion': True, 'deadline': stamp(-30)}}}
    assert run(cid, row, index('bucket', [row], metadata=policy)) == 'PASS'
    bad = bucket(softDeletePolicy={'retentionDurationSeconds': '3600'})
    assert run(cid, bad, index('bucket', [bad], metadata=policy)) == 'FAIL'
    assert run(cid, row, index('bucket', [row], metadata={'approved_bucket_deletions': {}})) == 'NOT_APPLICABLE'
    assert run(cid, row, index('bucket', [row])) == 'UNKNOWN'
    assert run(cid, row, index('bucket', [row], metadata=policy, status='partial')) == 'UNKNOWN'
    malformed = bucket(versioning={'enabled': 'false'})
    assert run(cid, malformed, index('bucket', [malformed], metadata=policy)) == 'UNKNOWN'


def test_log_retention_pass_fail_unknown_and_external():
    cid = 'gcp_c5_log_retention'
    name = SCOPE + '/locations/global/buckets/audit'
    row = bucket(name, retentionDays=30, locked=True, destinationExternal=False)
    policy = {'approved_log_retention': {'minimum_days': 20, 'maximum_days': 90,
                                         'lock_required': True, 'deletion_deadline': stamp(-30)}}
    assert run(cid, row, index('bucket', [row], metadata=policy)) == 'PASS'
    bad = dict(row, retentionDays=10)
    assert run(cid, bad, index('bucket', [bad], metadata=policy)) == 'FAIL'
    external = dict(row, destinationExternal=True)
    assert run(cid, external, index('bucket', [external], metadata=policy)) == 'UNKNOWN'
    assert run(cid, row, index('bucket', [row])) == 'UNKNOWN'
    malformed = dict(row, retentionDays='30')
    assert run(cid, malformed, index('bucket', [malformed], metadata=policy)) == 'UNKNOWN'


def test_replication_pass_fail_unknown():
    cid = 'gcp_gcs_replication_status'
    row = bucket()
    policy = {'expected_replica_locations': {'storage-bucket': ['EU']}}
    assert run(cid, row, index('bucket', [row], metadata=policy)) == 'PASS'
    bad = bucket(location='US')
    assert run(cid, bad, index('bucket', [bad], metadata=policy)) == 'FAIL'
    assert run(cid, row, index('bucket', [row])) == 'UNKNOWN'
    missing = dict(row)
    missing.pop('replicationHealth')
    assert run(cid, missing, index('bucket', [missing], metadata=policy)) == 'UNKNOWN'
    malformed = bucket(customPlacementConfig={'dataLocations': 'EU'})
    assert run(cid, malformed, index('bucket', [malformed], metadata=policy)) == 'UNKNOWN'


def test_public_bucket_iam_and_acl_and_unknown():
    cid = 'gcp_pci_bucket_157fb0c69361'
    row = bucket()
    assert run(cid, row, index('bucket', [row])) == 'PASS'
    bad = bucket(iamPolicy={'bindings': [{'role': 'roles/storage.objectViewer', 'members': ['allUsers']}]})
    assert run(cid, bad, index('bucket', [bad])) == 'FAIL'
    acl = bucket(iamConfiguration={'uniformBucketLevelAccess': {'enabled': False}},
                 bucketAccessControls={'status': 'collected', 'all_pages': True,
                                       'items': [{'bucket': 'storage-bucket', 'entity': 'allUsers', 'role': 'READER'}]},
                 objectAccessControls={'status': 'collected', 'all_pages': True, 'all_objects': True, 'items': []})
    assert run(cid, acl, index('bucket', [acl])) == 'FAIL'
    acl['bucketAccessControls']['items'][0]['role'] = 'WRITER'
    assert run(cid, acl, index('bucket', [acl])) == 'FAIL'
    missing = bucket(iamConfiguration={'uniformBucketLevelAccess': {'enabled': False}})
    assert run(cid, missing, index('bucket', [missing])) == 'UNKNOWN'
    custom = bucket(iamPolicy={'bindings': [{'role': 'projects/demo-project/roles/custom', 'members': ['allUsers']}]})
    assert run(cid, custom, index('bucket', [custom])) == 'UNKNOWN'
    malformed = bucket(iamPolicy={'bindings': 'bad'})
    assert run(cid, malformed, index('bucket', [malformed])) == 'UNKNOWN'
    assert run(cid, row, index('bucket', [row], status='partial')) == 'UNKNOWN'
