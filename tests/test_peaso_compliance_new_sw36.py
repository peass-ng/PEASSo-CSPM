"""Isolated contract tests for the fifteen signed sw36 AWS predicates."""
from __future__ import annotations

import copy
import pytest

from peaso.checks import CHECKS, evaluate_check
import sys
sw = sys.modules['peaso.checks._bulk_pending_compliance_new_sw36']

SCOPE = '123456789012/us-east-1'
INSTANCE = 'i-12345678'
BUCKET = 'archive-bucket'
DOCUMENT = 'arn:aws:ssm:us-east-1:123456789012:document/Contain'
SIEM = 'arn:aws:lambda:us-east-1:123456789012:function:siem'
METRIC = 'arn:aws:lambda:us-east-1:123456789012:function:metrics'
TARGET = 'arn:aws:sns:us-east-1:123456789012:alert'


@pytest.fixture(scope='module', autouse=True)
def cleanup_registry():
    yield
    CHECKS[:] = [check for check in CHECKS if check.id not in sw.IDS]


def index(kind, rows, *, inputs=None, extras=None):
    collections = {}
    projected = {}
    for resource_kind, batch in {kind: rows, **(extras or {})}.items():
        collections[resource_kind] = [{'type': resource_kind, 'scope': SCOPE,
            'status': 'collected' if batch else 'empty', 'items': copy.deepcopy(batch)}]
        projected[resource_kind] = [{'type': resource_kind, 'scope': SCOPE, 'data': copy.deepcopy(row)} for row in batch]
    return {'context': {'provider': 'aws', 'scope': SCOPE,
        'created_at': '2026-10-12T12:00:00+00:00',
        'metadata': {'compliance_inputs': inputs or {}}},
        'collections': collections, **projected}


def archive_index(item):
    arn = 'arn:aws:cloudtrail:us-east-1:123456789012:trail/a'
    observed = {'TrailARN': arn, 'Name': 'a', 'HomeRegion': 'us-east-1',
        'SourceRegion': 'us-east-1', 'IsOrganizationTrail': False, 'IsMultiRegionTrail': True}
    trail = {**observed, 'AccountId': '123456789012', 'S3BucketName': BUCKET,
        '_provenance': {'operation': 'cloudtrail:DescribeTrails', 'native_response_complete': True},
        '_account_trail_observations': [observed], '_account_trail_binding': {
        'caller_account_id': '123456789012', 'trail_arn': arn,
        'identity_operation': 'sts:GetCallerIdentity',
        'describe_operation': 'cloudtrail:DescribeTrails', 'include_shadow_trails': True,
        'capture_observed_at': '2026-10-12T12:00:00+00:00'}}
    facts = index('s3_bucket', [item], extras={'cloudtrail_account_inventory': [trail]})
    facts['context']['scope'] = '123456789012/global'
    facts['context']['metadata']['region_discovery'] = [{'account_id': '123456789012',
        'caller_account_id': '123456789012', 'scope': '123456789012/global',
        'partition': 'aws', 'source_operation': 'ec2:DescribeRegions',
        'all_regions': True, 'read_only': True, 'status': 'collected',
        'observed_at': '2026-10-12T12:00:00+00:00', 'regions': ['us-east-1']}]
    for kind, envelopes in facts['collections'].items():
        for envelope in envelopes:
            envelope.update({'scope': '123456789012/global', 'global': True, 'account_id': '123456789012'})
        for wrapper in facts[kind]:
            wrapper['scope'] = '123456789012/global'
    return facts


def managed(**fields):
    return {'InstanceId': INSTANCE, 'PingStatus': 'Online',
        'AssociationCompliance': {'collection_status': 'collected',
            'source_operation': 'ssm:ListComplianceItems', 'items': [
                {'ComplianceType': 'Association', 'Id': 'assoc-1', 'Status': 'COMPLIANT'}]},
        'ApplicationInventory': {'collection_status': 'collected',
            'source_operation': 'ssm:ListInventoryEntries', 'TypeName': 'AWS:Application',
            'Entries': [{'Name': 'agent', 'Version': '1.0',
                'CaptureTime': '2026-10-12T11:00:00+00:00'}]}, **fields}


def bucket(**fields):
    return {'Name': BUCKET,
        'Versioning': {'collection_status': 'collected', 'Status': 'Enabled'},
        'ObjectLock': {'collection_status': 'collected',
            'ObjectLockConfiguration': {'ObjectLockEnabled': 'Enabled', 'Rule': {
                'DefaultRetention': {'Mode': 'COMPLIANCE', 'Days': 100}}}},
        'Lifecycle': {'collection_status': 'collected', 'Rules': [{
            'ID': 'expire-all', 'Status': 'Enabled', 'Filter': {},
            'Expiration': {'Days': 30}, 'NoncurrentVersionExpiration': {'NoncurrentDays': 30}}]},
        'PublicAccessBlock': {'collection_status': 'collected',
            'PublicAccessBlockConfiguration': {key: True for key in (
                'BlockPublicAcls', 'IgnorePublicAcls', 'BlockPublicPolicy', 'RestrictPublicBuckets')}},
        'Policy': {'collection_status': 'collected', 'Policy': {'Statement': []}}, **fields}


def rule(name, source, detail_type, *, detail=None, targets=(TARGET,)):
    pattern = {'source': [source], 'detail-type': [detail_type]}
    if detail is not None:
        pattern['detail'] = detail
    return {'Name': name, 'EventBusName': 'default', 'State': 'ENABLED', 'EventPattern': pattern,
        'Targets': {'collection_status': 'collected',
            'items': [{'Id': str(number), 'Arn': arn} for number, arn in enumerate(targets)]}}


def case(check_id):
    scope_item = {'scope': SCOPE}
    app = managed()
    b = bucket()
    cases = {
        'aws_ssm_application_inventory_fresh': (scope_item,
            index('ssm_managed_instance', [app], extras={'instance': [
                {'InstanceId': INSTANCE, 'State': {'Name': 'running'}}]}),
            lambda facts: _set_ssm(facts, 'ApplicationInventory', {
                **facts['ssm_managed_instance'][0]['data']['ApplicationInventory'],
                'Entries': [{'Name': 'agent', 'Version': '1.0',
                    'CaptureTime': '2026-10-10T11:00:00+00:00'}]}),
            None),
        'aws_ssm_endpoint_device_compliance': (app,
            index('ssm_managed_instance', [app], inputs={'endpoint_instance_ids': [INSTANCE],
                'approved_association_ids': ['assoc-1']}),
            lambda facts: _set_ssm(facts, 'PingStatus', 'ConnectionLost'),
            lambda facts: facts['context']['metadata']['compliance_inputs'].update(endpoint_instance_ids=['i-abcdef12'])),
        'aws_ssm_removable_storage_policy_compliance': (app,
            index('ssm_managed_instance', [app], inputs={'managed_instance_ids': [INSTANCE],
                'removable_media_association_id': 'assoc-1'}),
            lambda facts: _set_ssm(facts, 'PingStatus', 'ConnectionLost'),
            lambda facts: facts['context']['metadata']['compliance_inputs'].update(managed_instance_ids=['i-abcdef12'])),
        'aws_ssm_software_allowlist_compliance': (app,
            index('ssm_managed_instance', [app], inputs={'managed_instance_ids': [INSTANCE],
                'allowed_packages': [{'Name': 'agent', 'Version': '1.0'}]}),
            lambda facts: facts['context']['metadata']['compliance_inputs'].update(allowed_packages=[]),
            lambda facts: facts['context']['metadata']['compliance_inputs'].update(managed_instance_ids=['i-abcdef12'])),
        'aws_ssm_software_inventory_enumeration': (scope_item,
            index('ssm_managed_instance', [app], inputs={'approved_inventory_reader_arns': [SIEM]},
                extras={'ssm_inventory_read_event': [{'EventId': 'evt-1', 'EventName': 'GetInventory',
                    'EventSource': 'ssm.amazonaws.com', 'userIdentity': {'arn': SIEM}, 'success': True}]}),
            lambda facts: _set_event(facts, 'userIdentity', {'arn': TARGET}),
            None),
        'aws_incident_evidence_retention': (b,
            index('s3_bucket', [b], inputs={'incident_evidence_bucket_names': [BUCKET],
                'evidence_retention_days': 90}),
            lambda facts: _set_bucket(facts, 'Versioning', {'collection_status': 'collected', 'Status': 'Suspended'}),
            lambda facts: facts['context']['metadata']['compliance_inputs'].update(incident_evidence_bucket_names=['other'])),
        'aws_log_archive_immutable': (b,
            archive_index(b),
            lambda facts: _set_bucket(facts, 'ObjectLock', {'collection_status': 'empty'}),
            lambda facts: _set_cloudtrail(facts, 'S3BucketName', 'other')),
        'aws_s3_delete_lifecycle': (b,
            index('s3_bucket', [b], inputs={'customer_data_bucket_names': [BUCKET],
                'approved_deletion_days': 90}),
            lambda facts: _set_bucket(facts, 'Lifecycle', {'collection_status': 'empty'}),
            lambda facts: facts['context']['metadata']['compliance_inputs'].update(customer_data_bucket_names=['other'])),
        'aws_sensitive_data_rest_access_controls': (b,
            index('s3_bucket', [b], inputs={'sensitive_bucket_names': [BUCKET],
                'approved_sensitive_principal_arns': [SIEM]}),
            lambda facts: _set_bucket(facts, 'PublicAccessBlock', {'collection_status': 'empty'}),
            lambda facts: facts['context']['metadata']['compliance_inputs'].update(sensitive_bucket_names=['other'])),
        'aws_siem_log_immutable_archive': (b,
            index('s3_bucket', [b], inputs={'siem_archive_bucket_names': [BUCKET],
                'siem_archive_minimum_days': 90}),
            lambda facts: _set_bucket(facts, 'ObjectLock', {'collection_status': 'empty'}),
            lambda facts: facts['context']['metadata']['compliance_inputs'].update(siem_archive_bucket_names=['other'])),
        'aws_guardduty_high_finding_alert': (scope_item,
            index('eventbridge_rule', [rule('gd', 'aws.guardduty', 'GuardDuty Finding',
                detail={'severity': [{'numeric': ['>=', 7]}]})]),
            lambda facts: _set_rule(facts, 'Targets', {'collection_status': 'empty', 'items': []}),
            None),
        'aws_guardduty_siem_forwarding': (scope_item,
            index('eventbridge_rule', [rule('siem', 'aws.guardduty', 'GuardDuty Finding', targets=[SIEM])],
                inputs={'approved_siem_forwarder_arns': [SIEM]}),
            lambda facts: _set_rule(facts, 'Targets', {'collection_status': 'empty', 'items': []}),
            None),
        'aws_incident_automated_containment': (scope_item,
            index('eventbridge_rule', [rule('contain', 'aws.guardduty', 'GuardDuty Finding', targets=[DOCUMENT])],
                inputs={'approved_incident_event_classes': [{'source': 'aws.guardduty',
                    'detail_type': 'GuardDuty Finding', 'document_arn': DOCUMENT}]}),
            lambda facts: _set_rule(facts, 'Targets', {'collection_status': 'empty', 'items': []}),
            None),
        'aws_inspector_findings_metric_export': (scope_item,
            index('eventbridge_rule', [rule('inspector', 'aws.inspector2', 'Inspector2 Finding',
                detail={'resources': {'type': ['AWS_EC2_INSTANCE']}}, targets=[METRIC])],
                inputs={'approved_metric_pipeline_arn': METRIC}),
            lambda facts: _set_rule(facts, 'Targets', {'collection_status': 'empty', 'items': []}),
            None),
        'aws_securityhub_critical_findings_alert': (scope_item,
            index('eventbridge_rule', [rule('hub', 'aws.securityhub', 'Security Hub Findings - Imported',
                detail={'findings': {'Severity': {'Label': ['CRITICAL']}}})]),
            lambda facts: _set_rule(facts, 'Targets', {'collection_status': 'empty', 'items': []}),
            None),
    }
    return cases[check_id]


def _set_ssm(facts, field, value):
    facts['ssm_managed_instance'][0]['data'][field] = value
    facts['collections']['ssm_managed_instance'][0]['items'][0][field] = copy.deepcopy(value)


def _set_bucket(facts, field, value):
    facts['s3_bucket'][0]['data'][field] = value
    facts['collections']['s3_bucket'][0]['items'][0][field] = copy.deepcopy(value)


def _set_rule(facts, field, value):
    facts['eventbridge_rule'][0]['data'][field] = value
    facts['collections']['eventbridge_rule'][0]['items'][0][field] = copy.deepcopy(value)


def _set_event(facts, field, value):
    facts['ssm_inventory_read_event'][0]['data'][field] = value
    facts['collections']['ssm_inventory_read_event'][0]['items'][0][field] = copy.deepcopy(value)


def _set_cloudtrail(facts, field, value):
    facts['cloudtrail_account_inventory'][0]['data'][field] = value
    facts['collections']['cloudtrail_account_inventory'][0]['items'][0][field] = copy.deepcopy(value)


def evaluate(check_id, item, facts):
    if isinstance(item, dict) and 'scope' not in item:
        kind = next(check.kind for check in CHECKS if check.id == check_id)
        item = copy.deepcopy(facts[kind][0]['data'])
    return evaluate_check(check_id, item, facts)[0]


@pytest.mark.parametrize('check_id', sw.IDS)
def test_signed_pass_fail_unknown_and_incomplete(check_id):
    item, good, break_it, _ = case(check_id)
    assert evaluate(check_id, item, good) == 'PASS', check_id
    bad = copy.deepcopy(good)
    break_it(bad)
    assert evaluate(check_id, item, bad) == 'FAIL', check_id
    missing = copy.deepcopy(good)
    missing['collections'].pop(next(iter(missing['collections'])))
    assert evaluate(check_id, item, missing) == 'UNKNOWN', check_id
    partial = copy.deepcopy(good)
    for envelope in partial['collections'].values():
        envelope[0]['status'] = 'partial'
    assert evaluate(check_id, item, partial) == 'UNKNOWN', check_id
    foreign = copy.deepcopy(good)
    for envelope in foreign['collections'].values():
        envelope[0]['scope'] = '999999999999/eu-west-1'
    assert evaluate(check_id, item, foreign) == 'UNKNOWN', check_id
    malformed = copy.deepcopy(good)
    primary = next(iter(malformed['collections']))
    malformed[primary][0]['data'] = []
    assert evaluate(check_id, item, malformed) == 'UNKNOWN', check_id


@pytest.mark.parametrize('check_id', [check_id for check_id in sw.IDS if case(check_id)[3] is not None])
def test_out_of_scope_not_applicable(check_id):
    item, facts, _, make_out_of_scope = case(check_id)
    make_out_of_scope(facts)
    if 'scope' not in item:
        kind = next(check.kind for check in CHECKS if check.id == check_id)
        item = copy.deepcopy(facts[kind][0]['data'])
    assert evaluate_check(check_id, item, facts)[0] == 'NOT_APPLICABLE'


def test_policy_inputs_and_uncollected_new_facts_are_unknown():
    for check_id in sw.IDS:
        item, facts, _, _ = case(check_id)
        stripped = copy.deepcopy(facts)
        stripped['context']['metadata']['compliance_inputs'] = {}
        if check_id in {
            'aws_ssm_endpoint_device_compliance', 'aws_ssm_removable_storage_policy_compliance',
            'aws_ssm_software_allowlist_compliance', 'aws_ssm_software_inventory_enumeration',
            'aws_incident_evidence_retention', 'aws_s3_delete_lifecycle',
            'aws_sensitive_data_rest_access_controls', 'aws_siem_log_immutable_archive',
            'aws_guardduty_siem_forwarding', 'aws_incident_automated_containment',
            'aws_inspector_findings_metric_export'}:
            assert evaluate(check_id, item, stripped) == 'UNKNOWN'


def test_ssm_complete_absence_and_provenance_boundaries():
    check_id = 'aws_ssm_application_inventory_fresh'
    item, facts, _, _ = case(check_id)
    absent = copy.deepcopy(facts)
    absent['ssm_managed_instance'] = []
    absent['collections']['ssm_managed_instance'][0].update(status='empty', items=[])
    assert evaluate(check_id, item, absent) == 'FAIL'
    no_running = copy.deepcopy(facts)
    no_running['instance'][0]['data']['State']['Name'] = 'stopped'
    no_running['collections']['instance'][0]['items'][0]['State']['Name'] = 'stopped'
    assert evaluate(check_id, item, no_running) == 'NOT_APPLICABLE'
    future = copy.deepcopy(facts)
    _set_ssm(future, 'ApplicationInventory', {**future['ssm_managed_instance'][0]['data']['ApplicationInventory'],
        'Entries': [{'Name': 'agent', 'Version': '1.0', 'CaptureTime': '2026-10-13T00:00:00+00:00'}]})
    assert evaluate(check_id, item, future) == 'FAIL'
    for check_id in ('aws_ssm_endpoint_device_compliance', 'aws_ssm_removable_storage_policy_compliance'):
        item, facts, _, _ = case(check_id)
        missing = copy.deepcopy(facts)
        _set_ssm(missing, 'AssociationCompliance', {'collection_status': 'empty',
            'source_operation': 'ssm:ListComplianceItems', 'items': []})
        assert evaluate(check_id, item, missing) == 'FAIL'
        summary = copy.deepcopy(facts)
        _set_ssm(summary, 'AssociationCompliance', {'collection_status': 'collected',
            'source_operation': 'ssm:ListResourceComplianceSummaries', 'items': []})
        assert evaluate(check_id, item, summary) == 'UNKNOWN'


def test_s3_policy_and_lifecycle_need_whole_bucket_proof():
    item, facts, _, _ = case('aws_s3_delete_lifecycle')
    filtered = copy.deepcopy(facts)
    lifecycle = copy.deepcopy(filtered['s3_bucket'][0]['data']['Lifecycle'])
    lifecycle['Rules'][0]['Filter'] = {'Prefix': 'logs/'}
    _set_bucket(filtered, 'Lifecycle', lifecycle)
    assert evaluate('aws_s3_delete_lifecycle', item, filtered) == 'FAIL'
    item, facts, _, _ = case('aws_sensitive_data_rest_access_controls')
    unapproved = copy.deepcopy(facts)
    _set_bucket(unapproved, 'Policy', {'collection_status': 'collected', 'Policy': {'Statement': [{
        'Effect': 'Allow', 'Action': 's3:Get*', 'Principal': {'AWS': TARGET},
        'Resource': 'arn:aws:s3:::archive-bucket/*'}]}})
    assert evaluate('aws_sensitive_data_rest_access_controls', item, unapproved) == 'FAIL'
    conditional = copy.deepcopy(unapproved)
    _set_bucket(conditional, 'Policy', {'collection_status': 'collected', 'Policy': {'Statement': [{
        'Effect': 'Allow', 'Action': 's3:GetObject', 'Principal': {'AWS': TARGET},
        'Resource': 'arn:aws:s3:::archive-bucket/*',
        'Condition': {'StringEquals': {'aws:PrincipalOrgID': 'o-test'}}}]}})
    assert evaluate('aws_sensitive_data_rest_access_controls', item, conditional) == 'UNKNOWN'
    absent_flag = copy.deepcopy(facts)
    block = copy.deepcopy(absent_flag['s3_bucket'][0]['data']['PublicAccessBlock'])
    del block['PublicAccessBlockConfiguration']['BlockPublicAcls']
    _set_bucket(absent_flag, 'PublicAccessBlock', block)
    assert evaluate('aws_sensitive_data_rest_access_controls', item, absent_flag) == 'UNKNOWN'


def test_event_rule_coverage_and_target_completeness():
    for check_id in ('aws_guardduty_high_finding_alert', 'aws_guardduty_siem_forwarding',
            'aws_incident_automated_containment', 'aws_inspector_findings_metric_export',
            'aws_securityhub_critical_findings_alert'):
        item, facts, _, _ = case(check_id)
        no_rules = copy.deepcopy(facts)
        no_rules['eventbridge_rule'] = []
        no_rules['collections']['eventbridge_rule'][0].update(status='empty', items=[])
        assert evaluate(check_id, item, no_rules) == 'FAIL'
        partial_target = copy.deepcopy(facts)
        _set_rule(partial_target, 'Targets', {'collection_status': 'partial', 'items': []})
        assert evaluate(check_id, item, partial_target) == 'UNKNOWN'
        restrictive = copy.deepcopy(facts)
        pattern = copy.deepcopy(restrictive['eventbridge_rule'][0]['data']['EventPattern'])
        pattern['account'] = ['999999999999']
        _set_rule(restrictive, 'EventPattern', pattern)
        assert evaluate(check_id, item, restrictive) == 'UNKNOWN'


def test_schedule_only_rule_cannot_prove_event_alert():
    item, facts, _, _ = case('aws_guardduty_high_finding_alert')
    schedule = copy.deepcopy(facts['eventbridge_rule'][0]['data'])
    schedule.pop('EventPattern')
    schedule.update(Name='schedule', ScheduleExpression='rate(1 hour)')
    facts['eventbridge_rule'].append({'type': 'eventbridge_rule', 'scope': SCOPE, 'data': copy.deepcopy(schedule)})
    facts['collections']['eventbridge_rule'][0]['items'].append(copy.deepcopy(schedule))
    assert evaluate('aws_guardduty_high_finding_alert', item, facts) == 'PASS'
    _set_rule(facts, 'Targets', {'collection_status': 'empty', 'items': []})
    assert evaluate('aws_guardduty_high_finding_alert', item, facts) == 'FAIL'


def test_engine_evaluates_new_scope_and_resource_kinds():
    from tests.archived_check_contract import evaluate_snapshot
    from peaso.snapshot import make_snapshot

    event = rule('alert', 'aws.guardduty', 'GuardDuty Finding',
        detail={'severity': [{'numeric': ['>=', 7]}]})
    b = bucket()
    snapshot = make_snapshot('aws', [SCOPE], [
        {'type': 'eventbridge_rule', 'scope': SCOPE, 'service': 'events',
            'status': 'collected', 'items': [event]},
        {'type': 's3_bucket', 'scope': SCOPE, 'service': 's3',
            'status': 'collected', 'items': [b]},
    ], created_at='2026-10-12T12:00:00+00:00',
        metadata={'compliance_inputs': {'siem_archive_bucket_names': [BUCKET],
            'siem_archive_minimum_days': 90}})
    selected = ['aws_guardduty_high_finding_alert', 'aws_siem_log_immutable_archive']
    report = evaluate_snapshot(snapshot, categories=['hardening'], checks=selected)
    statuses = {row['check_id']: row['status'] for row in report['findings'] if row['check_id'] in selected}
    assert statuses == {check_id: 'PASS' for check_id in selected}
