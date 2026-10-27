"""Admission and downstream contract for reviewed native Hardening failures."""
import copy
import hashlib
import json
from pathlib import Path

from peaso.ai import native_final, pipeline
from peaso.ai.briefing import build
from peaso.ai.contracts import validate_actions
from peaso.ai.finding_reviews import apply_report_reviews, apply_review, presented_reviews, review_index


def qualified_manifest():
    return {
        'version': 2,
        'source_scan_id': native_final.SOURCE_SCAN,
        'base_commit': native_final.BASE_COMMIT,
        'replay_qualification': {'status': 'qualified', 'receipt_sha256': 'a' * 64},
        'checks': [{
            'check_id': 'aws.test.direct_setting',
            'prod992_disagreements': 0,
            'prod992_reviewed_failures': 7,
            'audit_receipt_sha256': 'b' * 64,
            'deterministic_evidence': {
                'source_fields': [{
                    'api': 'ec2:DescribeInstances',
                    'field_path': 'Instances[].MetadataOptions.HttpTokens',
                    'field_type': 'enum',
                    'source_semantics': 'recorded_api_field',
                    'recorded_evidence_ref': 'prod992/pre-ai-report#finding-h1',
                }],
                'operation': {'kind': 'literal_comparison', 'comparison': 'eq',
                              'threshold': 'optional', 'threshold_unit': None},
                'scan_time': None,
                'code_path_audit_ref': {
                    'path': 'peaso/checks/aws.py', 'symbol': 'versioning',
                    'source_sha256': hashlib.sha256((Path(native_final.__file__).resolve()
                        .parents[2] / 'peaso/checks/aws.py').read_bytes()).hexdigest(),
                    'audit_ref': 'native-final-audit-992#aws.test.direct_setting',
                },
            },
        }],
    }


def write_manifest(tmp_path, monkeypatch, value):
    path = tmp_path / 'native-final.json'
    raw = (json.dumps(value, sort_keys=True) + '\n').encode()
    path.write_bytes(raw)
    monkeypatch.setenv('PEASO_HARDENING_NATIVE_FINAL_ENABLED', '1')
    monkeypatch.setenv('PEASO_HARDENING_NATIVE_FINAL_SHA256', hashlib.sha256(raw).hexdigest())
    return path


def test_default_disabled_and_version_pin_fail_closed(tmp_path, monkeypatch):
    path = write_manifest(tmp_path, monkeypatch, qualified_manifest())
    monkeypatch.delenv('PEASO_HARDENING_NATIVE_FINAL_ENABLED')
    assert not native_final.admitted_check_ids(path)
    monkeypatch.setenv('PEASO_HARDENING_NATIVE_FINAL_ENABLED', '1')
    assert native_final.admitted_check_ids(path) == {'aws.test.direct_setting'}
    path.write_bytes(path.read_bytes() + b' ')
    assert not native_final.admitted_check_ids(path)
    value = qualified_manifest()
    value['version'] = 1
    path = write_manifest(tmp_path, monkeypatch, value)
    assert not native_final.admitted_check_ids(path)


def test_no_heuristic_or_unqualified_admission(tmp_path, monkeypatch):
    for change in (
        lambda m: m['replay_qualification'].update(status='pending'),
        lambda m: m['checks'][0].update(prod992_disagreements=1),
        lambda m: m['checks'][0].update(prod992_reviewed_failures=0),
        lambda m: m['checks'][0].update(deterministic_evidence='looks like API config'),
        lambda m: m['checks'][0].update(check_id='gcp.test.direct_setting'),
    ):
        value = qualified_manifest()
        change(value)
        assert not native_final.admitted_check_ids(write_manifest(tmp_path, monkeypatch, value))
    rows = [
        {'id': 'h1', 'check_id': 'aws.test.direct_setting', 'provider': 'aws',
         'category': 'hardening', 'status': 'FAIL'},
        {'id': 'h2', 'check_id': 'aws.test.similar_setting', 'provider': 'aws',
         'category': 'hardening', 'status': 'FAIL', 'title': 'Same API setting'},
        {'id': 'h3', 'check_id': 'aws.test.direct_setting', 'provider': 'aws',
         'category': 'hardening', 'status': 'UNKNOWN'},
        {'id': 'h4', 'check_id': 'aws.test.direct_setting', 'provider': 'azure',
         'category': 'hardening', 'status': 'FAIL'},
        {'id': 'h5', 'check_id': 'aws.test.direct_setting', 'provider': 'aws',
         'category': 'hardening', 'status': 'FAIL',
         'evidence': {'incomplete_dependencies': [{'status': 'partial'}]}},
        {'id': 'h6', 'check_id': 'aws.test.direct_setting', 'provider': 'aws',
         'category': 'hardening', 'status': 'FAIL', 'scanner_status': 'UNKNOWN'},
    ]
    native, ai = native_final.partition(rows, native_final.admitted_check_ids(
        write_manifest(tmp_path, monkeypatch, qualified_manifest())))
    assert [row['id'] for row in native] == ['h1']
    assert [row['id'] for row in ai] == ['h2', 'h3', 'h4', 'h5', 'h6']


def test_fixed_age_from_recorded_api_timestamp_and_scan_time(tmp_path, monkeypatch):
    value = qualified_manifest()
    evidence = value['checks'][0]['deterministic_evidence']
    evidence['source_fields'] = [{
        'api': 'iam:ListAccessKeys', 'field_path': 'AccessKeyMetadata[].CreateDate',
        'field_type': 'timestamp', 'recorded_evidence_ref': 'prod992/pre-ai-report#key-age',
        'source_semantics': 'recorded_api_timestamp',
    }]
    evidence['operation'] = {'kind': 'age_comparison', 'comparison': 'gt',
                             'threshold': 90, 'threshold_unit': 'days'}
    evidence['scan_time'] = {'source_field': 'snapshot.metadata.capture_time',
                             'recorded_evidence_ref': 'prod992/snapshot#capture-time'}
    assert native_final.admitted_check_ids(write_manifest(tmp_path, monkeypatch, value)) == {
        'aws.test.direct_setting'}
    evidence['scan_time'] = None
    assert not native_final.admitted_check_ids(write_manifest(tmp_path, monkeypatch, value))
    evidence['scan_time'] = {'source_field': 'snapshot.metadata.capture_time',
                             'recorded_evidence_ref': 'prod992/snapshot#capture-time'}
    evidence['operation']['threshold'] = '90 days'
    assert not native_final.admitted_check_ids(write_manifest(tmp_path, monkeypatch, value))


def test_content_policy_intent_and_unreviewed_code_path_rejected(tmp_path, monkeypatch):
    for mutate in (
        lambda e: e['source_fields'][0].update(field_type='content'),
        lambda e: e['source_fields'][0].update(field_type='policy_document'),
        lambda e: e['source_fields'][0].update(source_semantics='policy_intent'),
        lambda e: e['source_fields'][0].update(source_semantics='free_text'),
        lambda e: e['operation'].update(kind='semantic_judgment'),
        lambda e: e['operation'].update(kind='free_text_match'),
        lambda e: e.update(code_path_audit_ref='looks safe'),
        lambda e: e['code_path_audit_ref'].update(path='../policy.py'),
        lambda e: e['code_path_audit_ref'].update(symbol='not_a_real_evaluator'),
        lambda e: e['code_path_audit_ref'].update(source_sha256='0' * 64),
    ):
        value = qualified_manifest()
        mutate(value['checks'][0]['deterministic_evidence'])
        assert not native_final.admitted_check_ids(write_manifest(tmp_path, monkeypatch, value))


def test_exact_pinned_iam_activity_evaluator_path(tmp_path, monkeypatch):
    value = qualified_manifest()
    ref = value['checks'][0]['deterministic_evidence']['code_path_audit_ref']
    ref['path'] = 'peaso/unused_iam_aws_activity.py'
    ref['symbol'] = 'evaluate'
    ref['source_sha256'] = hashlib.sha256((Path(native_final.__file__).resolve()
        .parents[2] / ref['path']).read_bytes()).hexdigest()
    assert native_final.admitted_check_ids(write_manifest(tmp_path, monkeypatch, value)) == {
        'aws.test.direct_setting'}
    ref['path'] = 'peaso/unused_iam_aws_completion.py'
    ref['source_sha256'] = hashlib.sha256((Path(native_final.__file__).resolve()
        .parents[2] / ref['path']).read_bytes()).hexdigest()
    assert not native_final.admitted_check_ids(write_manifest(tmp_path, monkeypatch, value))


def test_native_fail_reaches_priorities_with_exact_id_and_report_unchanged(tmp_path):
    row = {'id': 'finding-h1', 'check_id': 'aws.test.direct_setting', 'provider': 'aws',
           'category': 'hardening', 'status': 'FAIL', 'resource_id': 'resource-1',
           'scope': '123456789012/us-east-1', 'title': 'Require setting',
           'severity': 'high', 'evidence': {'HttpTokens': 'optional'}}
    report = {'provider': 'aws', 'findings': [row], 'coverage': [
        {'type': 'ec2', 'status': 'evaluated'}], 'graphs': {}}
    original = copy.deepcopy(report)
    native, ai = native_final.partition(pipeline.inputs(report)[0], {'aws.test.direct_setting'})
    assert ai == []
    reviews = native_final.reviews(native)
    assert reviews == [{'finding_id': 'finding-h1', 'verdict': 'FAIL', 'reason': ''}]
    build(tmp_path, {'report': report, 'inventory': [], 'least_privilege': {'items': []}},
          native, reviews, pipeline.private_json)
    brief = json.loads((tmp_path / 'platform.json').read_text())
    assert brief['review_counts']['hardening:FAIL'] == 1
    assert brief['sections']['findings'][0]['example']['id'] == 'finding-h1'
    assert validate_actions({'actions': [{
        'rank': 1, 'title': 'Require setting', 'finding_ids': ['finding-h1'],
        'rationale': 'Recorded HttpTokens is optional.', 'steps': ['Require tokens'],
        'verification': 'Read HttpTokens', 'severity': 'high', 'effort': 'low',
    }], 'limitations': []}, report, reviews)['actions'][0]['finding_ids'] == ['finding-h1']
    assert report == original


def test_published_native_finding_and_coverage_are_untouched():
    native = {'id': 'h1', 'check_id': 'aws.test.direct_setting', 'category': 'hardening',
              'status': 'FAIL', 'evidence': {'HttpTokens': 'optional'}}
    other = {'id': 'h2', 'check_id': 'aws.test.other_setting', 'category': 'hardening',
             'status': 'FAIL'}
    report = {'findings': [native, other], 'coverage': [{'status': 'evaluated'}],
              'stats': {'by_status': {'FAIL': 2}}, 'ai': {
                  'native_final': {'hardening': ['h1']}, 'reviews': {'hardening': [
                      {'finding_id': 'h1', 'verdict': 'FAIL', 'reason': ''},
                      {'finding_id': 'h2', 'verdict': 'PASS', 'reason': 'The setting is enabled.'}],
                      'exposure': []}}}
    published = apply_report_reviews(report)
    assert published['findings'][0] == native
    assert published['findings'][1]['status'] == 'PASS'
    assert published['coverage'] == report['coverage']
    assert report['findings'] == [native, other]


def test_grouped_observation_and_api_provenance_keep_native_result():
    native = {'id': 'native-observation', 'check_id': 'aws.test.direct_setting',
              'category': 'hardening', 'status': 'FAIL', 'evidence': {'flag': False}}
    other = {'id': 'ai-observation', 'check_id': 'aws.test.other_setting',
             'category': 'hardening', 'status': 'FAIL'}
    ai = {'native_final': {'hardening': ['native-observation']}, 'reviews': {
        'hardening': [
            {'finding_id': 'native-observation', 'verdict': 'FAIL', 'reason': ''},
            {'finding_id': 'ai-observation', 'verdict': 'PASS', 'reason': 'Enabled.'}],
        'exposure': []}}
    grouped = {'finding_grouping': 'check-v1', 'findings': [
        {'id': 'check-group', 'category': 'hardening', 'status': 'FAIL',
         'observations': [native, other]}], 'coverage': [{'status': 'evaluated'}], 'ai': ai}
    published = apply_report_reviews(grouped)
    assert published['findings'][0]['observations'][0] == native
    assert 'ai_review' not in published['findings'][0]['observations'][0]
    assert published['coverage'] == grouped['coverage']
    assert ('hardening', 'native-observation') not in review_index(ai)
    assert ('hardening', 'ai-observation') in review_index(ai)
    assert apply_review(native, review_index(ai)) == native
    api_rows = presented_reviews(ai, 0, 10)['hardening']
    assert [(row['finding_id'], row['source']) for row in api_rows] == [
        ('native-observation', 'native_final'), ('ai-observation', 'ai')]
