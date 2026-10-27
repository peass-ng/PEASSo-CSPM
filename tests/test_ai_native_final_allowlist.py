"""Admission and downstream contract for reviewed native Hardening failures."""
import copy
import hashlib
import json

from peaso.ai import native_final, pipeline
from peaso.ai.briefing import build
from peaso.ai.contracts import validate_actions
from peaso.ai.finding_reviews import apply_report_reviews


def qualified_manifest():
    return {
        'version': 1,
        'source_scan_id': native_final.SOURCE_SCAN,
        'base_commit': native_final.BASE_COMMIT,
        'replay_qualification': {'status': 'qualified', 'receipt_sha256': 'a' * 64},
        'checks': [{
            'check_id': 'aws.test.direct_setting',
            'prod992_disagreements': 0,
            'prod992_reviewed_failures': 7,
            'audit_receipt_sha256': 'b' * 64,
            'direct_api_setting_evidence': {
                'api': 'ec2:DescribeInstances',
                'setting_path': 'Instances[].MetadataOptions.HttpTokens',
                'recorded_evidence_ref': 'prod992/pre-ai-report#finding-h1',
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
    value['version'] = 2
    path = write_manifest(tmp_path, monkeypatch, value)
    assert not native_final.admitted_check_ids(path)


def test_no_heuristic_or_unqualified_admission(tmp_path, monkeypatch):
    for change in (
        lambda m: m['replay_qualification'].update(status='pending'),
        lambda m: m['checks'][0].update(prod992_disagreements=1),
        lambda m: m['checks'][0].update(prod992_reviewed_failures=0),
        lambda m: m['checks'][0].update(direct_api_setting_evidence='looks like API config'),
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
    ]
    native, ai = native_final.partition(rows, native_final.admitted_check_ids(
        write_manifest(tmp_path, monkeypatch, qualified_manifest())))
    assert [row['id'] for row in native] == ['h1']
    assert [row['id'] for row in ai] == ['h2', 'h3', 'h4']


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
