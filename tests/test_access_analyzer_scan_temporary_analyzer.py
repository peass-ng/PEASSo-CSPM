"""A scan-created temporary Access Analyzer is never reported as a customer resource.

When a Region has no analyzer, collection creates ``peaso-scan-*-external``,
reads its findings and deletes it. Findings must point at the externally
accessible resources, and "analyzer exists/active" controls must still fail.
"""
from peaso.engine import evaluate_snapshot
from peaso.snapshot import make_snapshot

ACCOUNT = '614095388140'
SCOPE = ACCOUNT + '/us-west-2'
GAP = 'aws.gap.accessanalyzer.no_active_findings'
PRESENT = 'aws.a.accessanalyzer.region_present'
ACTIVE = 'aws.a.accessanalyzer.region_active'
HACKTRICKS = 'aws.claude_a.accessanalyzer.active_without_findings'
BUCKET = 'arn:aws:s3:::prod-exports'
ROLE = 'arn:aws:iam::%s:role/vendor-sync' % ACCOUNT


def external(resource, kind, principal, condition=None, finding_id='f1'):
    access = {'principal': principal, 'action': ['sts:AssumeRole'], 'isPublic': False}
    if condition:
        access['condition'] = condition
    return {'id': finding_id, 'status': 'ACTIVE', 'findingType': 'ExternalAccess', 'resource': resource,
            'resourceType': kind, 'resourceOwnerAccount': ACCOUNT,
            'FindingDetails': {'collection_status': 'collected', 'items': [{'externalAccessDetails': access}]}}


def temporary(findings):
    name = 'peaso-scan-17aff2696cfc4817ad800112dfb272f2-external'
    return {'arn': 'arn:aws:access-analyzer:us-west-2:%s:analyzer/%s' % (ACCOUNT, name), 'name': name,
            'type': 'ACCOUNT', 'status': 'ACTIVE', '_scan_temporary': True, 'Findings': findings,
            '_coverage': {'InitialAnalysis': {'status': 'partial', 'reason': 'initial_analysis_completion_unconfirmed'}}}


def customer(findings, status='ACTIVE'):
    return {'arn': 'arn:aws:access-analyzer:us-west-2:%s:analyzer/org-analyzer' % ACCOUNT, 'name': 'org-analyzer',
            'type': 'ACCOUNT', 'status': status, 'Findings': findings}


def run(analyzers, status='partial', error=None):
    collection = {'type': 'access_analyzer', 'scope': SCOPE, 'service': 'accessanalyzer', 'status': status, 'items': analyzers}
    if status == 'partial':
        collection['error'] = error or {'code': 'initial_analysis_completion_unconfirmed'}
    snapshot = make_snapshot('aws', [SCOPE], [collection], created_at='2026-11-17T00:00:00Z')
    report = evaluate_snapshot(snapshot, categories=['hardening', 'least_privilege'], checks=[GAP, PRESENT, ACTIVE, HACKTRICKS])
    return {f['check_id']: f for f in report['findings'] if f['scope'] == SCOPE}


def test_temporary_analyzer_findings_name_the_exposed_resources_not_the_analyzer():
    findings = run([temporary([external(BUCKET, 'AWS::S3::Bucket', {'AWS': '999988887777'}),
                               external(ROLE, 'AWS::IAM::Role', {'AWS': '111122223333'}, {'sts:ExternalId': 'x'}, 'f2')])])
    gap = findings[GAP]
    assert gap['status'] == 'FAIL'
    rendered = repr(gap)
    assert 'peaso-scan-' not in rendered and 'analyzer/' not in rendered
    assert not gap.get('native_resource_id') and not gap.get('resource_name')
    exposed = {row['resource']: row for row in gap['evidence']['externally_accessible_resources']}
    assert set(exposed) == {BUCKET, ROLE} == set(gap['evidence']['external_resources'])
    assert exposed[BUCKET]['resource_type'] == 'AWS::S3::Bucket'
    assert exposed[BUCKET]['external_access'][0]['principal'] == {'AWS': '999988887777'}
    assert exposed[ROLE]['external_access'][0]['condition'] == {'sts:ExternalId': 'x'}
    assert all('analyzer' not in row for row in exposed.values())
    assert gap['evidence']['customer_analyzers'] == []


def test_temporary_analyzer_never_satisfies_analyzer_presence_controls():
    for analyzer_findings in ([], [external(BUCKET, 'AWS::S3::Bucket', {'AWS': '*'})]):
        findings = run([temporary(analyzer_findings)])
        assert findings[PRESENT]['status'] == 'FAIL'
        assert findings[ACTIVE]['status'] == 'FAIL'
        assert findings[HACKTRICKS]['status'] == 'FAIL'
        assert 'peaso-scan-' not in repr(findings[HACKTRICKS]['evidence'])


def test_temporary_analyzer_without_findings_does_not_pass_the_findings_control():
    # Its initial analysis may be unfinished, so an empty result proves nothing.
    assert run([temporary([])])[GAP]['status'] == 'UNKNOWN'


def test_leftover_scan_analyzer_in_complete_inventory_is_not_a_customer_analyzer():
    leftover = dict(temporary([]))
    leftover.pop('_scan_temporary')
    leftover.pop('_coverage')
    findings = run([leftover], status='collected')
    assert findings[PRESENT]['status'] == 'FAIL'
    assert findings[ACTIVE]['status'] == 'FAIL'
    assert findings[HACKTRICKS]['status'] == 'FAIL'


def test_customer_analyzer_findings_keep_the_analyzer_and_name_the_resource():
    findings = run([customer([external(BUCKET, 'AWS::S3::Bucket', {'AWS': '999988887777'})])], status='collected')
    gap = findings[GAP]
    assert gap['status'] == 'FAIL'
    row = gap['evidence']['externally_accessible_resources'][0]
    assert row['resource'] == BUCKET and row['analyzer'].endswith('/org-analyzer')
    assert findings[PRESENT]['status'] == 'PASS' and findings[ACTIVE]['status'] == 'PASS'


def test_customer_analyzer_without_findings_passes():
    findings = run([customer([])], status='collected')
    assert findings[GAP]['status'] == 'PASS'
    assert findings[PRESENT]['status'] == 'PASS'


def test_incomplete_listing_without_scan_analyzer_does_not_prove_absence():
    findings = run([], status='partial', error={'code': 'page_limit'})
    assert findings[PRESENT]['status'] == 'UNKNOWN'
    assert findings[ACTIVE]['status'] == 'UNKNOWN'
    assert findings[GAP]['status'] == 'UNKNOWN'
