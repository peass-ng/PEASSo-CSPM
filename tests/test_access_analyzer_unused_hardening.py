"""SDK pagination and offline hardening/least-privilege conservation of unused access."""
from copy import deepcopy
from datetime import datetime, timezone

import boto3
import pytest
from botocore.stub import Stubber
from peaso.collectors import aws
from peaso.collectors.aws_facts_cb_ca import _analyzer_findings
from peaso.checks import CHECKS
from peaso.checks.claude_aws_a_common import idx
from peaso.least_privilege import project

ACCOUNT = '123456789012'
ARN = f'arn:aws:access-analyzer:us-east-1:{ACCOUNT}:analyzer/unused'
NOW = datetime(2026, 10, 21, tzinfo=timezone.utc)
CHECK = next(c for c in CHECKS if c.id == 'aws.claude_a.accessanalyzer.active_without_findings')
KINDS = {
    'UnusedIAMRole': {'unusedIamRoleDetails': {'lastAccessed': NOW}},
    'UnusedIAMUserAccessKey': {'unusedIamUserAccessKeyDetails': {'accessKeyId': 'AKIA'+'A'*16}},
    'UnusedIAMUserPassword': {'unusedIamUserPasswordDetails': {}},
    'UnusedPermission': {'unusedPermissionDetails': {'serviceNamespace': 's3', 'actions': [{'action': 'GetObject', 'lastAccessed': NOW}]}}
}


def summary(kind):
    return dict(analyzedAt=NOW, createdAt=NOW, updatedAt=NOW, id=kind, findingType=kind,
                status='ACTIVE', resourceType='AWS::IAM::Role' if kind == 'UnusedIAMRole' else 'AWS::IAM::User',
                resourceOwnerAccount=ACCOUNT, resource=f'arn:aws:iam::{ACCOUNT}:user/example')


def analyzer(findings):
    return dict(arn=ARN, name='unused', type='ACCOUNT_UNUSED_ACCESS', status='ACTIVE', Findings=findings,
                configuration={'unusedAccess': {'unusedAccessAge': 90}})


def test_live_access_analyzer_sdk_is_banned_before_any_request(monkeypatch):
    session = boto3.Session(aws_access_key_id='inert', aws_secret_access_key='inert')
    client = session.client('accessanalyzer', region_name='us-east-1')
    stub = Stubber(client)
    monkeypatch.setattr(aws.Requests, 'client', lambda *args, **kwargs: client)
    with stub:
        with pytest.raises(aws.ReadFailure) as failure:
            _analyzer_findings(aws.Requests({}), session, 'us-east-1', [analyzer([])])
        stub.assert_no_pending_responses()
    assert (failure.value.status, failure.value.code) == ('not_collected', 'access_analyzer_live_api_banned')


def test_recorded_finding_pages_keep_all_four_unused_types_and_metadata():
    kinds = list(KINDS)
    calls = []

    class Requests:
        def pages(self, session, service, region, operation, expression, **arguments):
            calls.append((operation, arguments))
            if operation == 'get_analyzer':
                return aws.ReadResult([{'arn': ARN, 'name': 'unused', 'type': 'ACCOUNT_UNUSED_ACCESS', 'status': 'ACTIVE',
                    'createdAt': NOW, 'configuration': {'unusedAccess': {'unusedAccessAge': 90}}}], 'collected')
            if operation == 'list_findings_v2':
                return aws.ReadResult([summary(kind) for kind in kinds], 'collected')
            kind = arguments['id']
            detail = dict(summary(kind), findingDetails=[KINDS[kind]])
            if kind == 'UnusedPermission':
                second = dict(detail, findingDetails=[{'unusedPermissionDetails': {'serviceNamespace': 'ec2'}}])
                return aws.ReadResult([dict(detail, nextToken='more'), second], 'collected')
            return aws.ReadResult([detail], 'collected')

    incomplete_summary = analyzer([])
    incomplete_summary.pop('configuration')
    result = _analyzer_findings(Requests(), object(), 'us-east-1', [incomplete_summary])[0]
    assert [operation for operation, _ in calls] == ['get_analyzer', 'list_findings_v2'] + ['get_finding_v2'] * 4
    assert len(result['Findings']) == 4
    assert all(row['analyzedAt'] for row in result['Findings'])
    assert all(row['FindingDetails']['collection_status'] == 'collected' for row in result['Findings'])
    assert all('nextToken' not in row for row in result['Findings'])
    assert len(result['Findings'][-1]['UnusedPermissionDetails']['items']) == 2
    status, evidence = CHECK.evaluate({}, idx(access_analyzer=[result]))
    assert status == 'FAIL' and CHECK.category == 'hardening'
    assert evidence['unused_access_findings'] == 4
    assert {row['findingType'] for row in evidence['access_analyzer_findings']} == set(KINDS)
    least = project('aws', [{'type': 'access_analyzer', 'scope': ACCOUNT+'/us-east-1', 'data': result}])
    suggestions = least['items'][0]['suggestions']
    assert {s['value'] for s in suggestions} == {'s3:GetObject', 'ec2'}
    assert suggestions[0]['last_accessed'] == NOW


@pytest.mark.parametrize('kind', list(KINDS))
def test_each_unused_type_is_hardening_without_least_privilege_dependency(kind):
    finding = dict(summary(kind), FindingDetails={'collection_status': 'collected', 'items': [KINDS[kind]]})
    before = deepcopy(finding)
    status, evidence = CHECK.evaluate({}, idx(access_analyzer=[analyzer([finding])]))
    assert status == 'FAIL' and evidence['unused_access_findings'] == 1
    assert evidence['access_analyzer_findings'][0]['unused_access_days'] == 90
    assert finding == before
    if kind != 'UnusedPermission':
        assert project('aws', [{'type': 'access_analyzer', 'data': analyzer([finding])}])['total'] == 0


def test_positive_findings_survive_partial_listing_and_details():
    class Requests:
        def pages(self, *args, **kwargs):
            if args[3] == 'list_findings_v2':
                return aws.ReadResult([summary('UnusedPermission')], 'partial', {'code': 'page_limit'})
            return aws.ReadResult([dict(summary('UnusedPermission'), findingDetails=[KINDS['UnusedPermission']])], 'partial', {'code': 'page_limit'})
    collected = _analyzer_findings(Requests(), object(), 'us-east-1', [analyzer([])])[0]
    assert collected['_coverage']['Findings']['status'] == 'partial'
    index = idx(access_analyzer=[collected])
    index['collections']['access_analyzer'][0]['status'] = 'partial'
    assert CHECK.allow_incomplete_failure
    assert CHECK.evaluate({}, index)[0] == 'FAIL'
    least = project('aws', [{'type': 'access_analyzer', 'data': collected}])
    assert least['items'][0]['suggestions'][0]['details_complete'] is False


@pytest.mark.parametrize('coverage', ['Findings', 'InitialAnalysis'])
def test_incomplete_empty_analyzer_never_passes(coverage):
    row = analyzer([])
    row['_coverage'] = {coverage: {'status': 'partial'}}
    assert CHECK.evaluate({}, idx(access_analyzer=[row]))[0] == 'UNKNOWN'


def test_archived_unused_finding_is_not_an_active_alarm():
    row = analyzer([dict(summary('UnusedIAMRole'), status='ARCHIVED')])
    assert CHECK.evaluate({}, idx(access_analyzer=[row]))[0] == 'PASS'


def test_denied_detail_does_not_erase_unused_finding_from_hardening():
    class Requests:
        def pages(self, *args, **kwargs):
            if args[3] == 'list_findings_v2':
                return aws.ReadResult([summary('UnusedIAMRole')], 'collected')
            return aws.ReadResult([], 'denied', {'code': 'AccessDenied'})
    collected = _analyzer_findings(Requests(), object(), 'us-east-1', [analyzer([])])[0]
    assert collected['Findings'][0]['FindingDetails']['collection_status'] == 'denied'
    status, evidence = CHECK.evaluate({}, idx(access_analyzer=[collected]))
    assert status == 'FAIL' and evidence['unused_access_findings'] == 1


def test_persistent_external_analyzer_keeps_details_and_current_resolved_status():
    class Requests:
        def pages(self, *args, **kwargs):
            if args[3] == 'list_findings_v2':
                return aws.ReadResult([summary('ExternalAccess')], 'collected')
            return aws.ReadResult([dict(summary('ExternalAccess'), status='RESOLVED', findingDetails=[{
                'externalAccessDetails': {'isPublic': True, 'condition': {}, 'action': ['s3:GetObject']}}])], 'collected')
    row = analyzer([])
    row['type'] = 'ACCOUNT'
    collected = _analyzer_findings(Requests(), object(), 'us-east-1', [row])[0]
    assert collected['Findings'][0]['FindingDetails']['items'][0]['externalAccessDetails']['isPublic'] is True
    assert CHECK.evaluate({}, idx(access_analyzer=[collected]))[0] == 'PASS'


def test_unused_configuration_is_read_when_list_omits_analysis_window():
    calls = []
    class Requests:
        def pages(self, *args, **kwargs):
            calls.append(args[3])
            if args[3] == 'get_analyzer':
                return aws.ReadResult([{'arn': ARN, 'configuration': {'unusedAccess': {'unusedAccessAge': 90}}}], 'collected')
            return aws.ReadResult([], 'empty')
    row = analyzer([])
    row.pop('configuration')
    collected = _analyzer_findings(Requests(), object(), 'us-east-1', [row])[0]
    assert collected['configuration']['unusedAccess']['unusedAccessAge'] == 90
    assert calls == ['get_analyzer', 'list_findings_v2']


def test_hardening_only_engine_keeps_all_unused_types_with_partial_inventory():
    import json
    from peaso.engine import evaluate_snapshot, hydrate_findings
    from peaso.snapshot import make_snapshot
    rows = [dict(summary(kind), FindingDetails={'collection_status': 'collected', 'items': [value]}) for kind, value in KINDS.items()]
    # Native collector serialization converts SDK timestamps before sealing.
    native = json.loads(json.dumps(analyzer(rows), default=lambda value: value.isoformat()))
    scope = ACCOUNT+'/us-east-1'
    snapshot = make_snapshot('aws', [scope], [{'type':'access_analyzer', 'scope':scope,
        'service':'accessanalyzer', 'status':'partial', 'items':[native], 'error':{'code':'page_limit'}}])
    report = hydrate_findings(evaluate_snapshot(snapshot, categories=['hardening'], checks=[CHECK.id]))
    finding = next(f for f in report['findings'] if f['check_id'] == CHECK.id)
    assert finding['status'] == 'FAIL' and finding['category'] == 'hardening', finding
    assert finding['evidence']['unused_access_findings'] == 4
    assert len(finding['evidence']['access_analyzer_findings']) == 4


def test_generated_customer_policy_grants_configuration_read_without_write():
    from pathlib import Path
    import json
    from scripts.peaso_deploy_customer_policy import build_policy, iam_action, policy_size
    assert iam_action('accessanalyzer', 'get_analyzer') == 'access-analyzer:GetAnalyzer'
    policy = build_policy({('accessanalyzer', 'get_analyzer')})
    actions = {action for row in policy['Statement'] for action in row.get('Action', [])}
    assert 'access-analyzer:GetAnalyzer' in actions
    assert not any(action.startswith('access-analyzer:') and not action.startswith('access-analyzer:Get') for action in actions)
    template = json.loads(Path('infra/aws/customer-role.json').read_text())
    documents = [row['Properties']['PolicyDocument'] for row in template['Resources'].values() if row['Type'] == 'AWS::IAM::ManagedPolicy']
    assert all(policy_size(document) <= 6144 for document in documents)
    assert any('access-analyzer:GetAnalyzer' in statement.get('Action', []) for document in documents for statement in document['Statement'])


def test_unused_hardening_observation_lists_types_without_raw_ids():
    from peaso.provider_followup_observations_20261021 import evidence_summary
    finding = {'check_id': CHECK.id, 'provider':'aws', 'status':'FAIL', 'evidence':{
        'access_analyzer_findings':[summary(kind) for kind in KINDS]}}
    summary_text = evidence_summary(finding)
    for phrase in ('1 role', '1 access key', '1 console password', '1 permission finding'):
        assert phrase in summary_text
    assert 'sha256:' not in summary_text
    from peaso.server.evidence_static import evidence_summary as hosted_summary
    assert hosted_summary(finding) == summary_text
