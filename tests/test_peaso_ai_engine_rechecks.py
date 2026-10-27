"""Native counterexamples to independently confirmed AI/engine disagreements."""
from copy import deepcopy
import json
from types import SimpleNamespace
import pytest
from peaso.checks import CHECKS
from peaso.checks.fixtures import CASES
from peaso.checks.aws_resource_policy_scope import review_document
from peaso.checks.aws_ip_policy_boundary import normalize
from peaso.collectors.aws_ai_recheck_facts_20261020 import FETCHERS, instances, queues, schedules
from peaso.collectors.aws import ReadResult

REGISTRY = {c.id: c for c in CHECKS}


def run(cid, item=None, index=None):
    case = CASES[cid]
    return REGISTRY[cid].evaluate(deepcopy(item if item is not None else case['fail']),
                                  deepcopy(index if index is not None else case.get('fail_index', case.get('index', {}))))


@pytest.mark.parametrize('cid', ['aws.b.docdb.deletion_protection', 'aws.b.neptune_cluster.deletion_protection',
                                'aws.b.neptune_cluster.iam_authentication', 'aws.b.neptune.audit_logging'])
def test_shared_database_api_cannot_apply_docdb_or_neptune_controls_to_aurora(cid):
    native = dict(CASES[cid]['fail'], Engine='aurora-postgresql')
    assert run(cid, native)[0] == 'NOT_APPLICABLE'
    assert run(cid)[0] == 'FAIL'


def test_aurora_postgresql_does_not_require_an_unsupported_upgrade_log_export():
    cid = 'aws.b.rds.engine_log_exports'
    assert run(cid, {'Engine': 'aurora-postgresql', 'EnabledCloudwatchLogsExports': ['postgresql']})[0] == 'PASS'
    assert run(cid, {'Engine': 'aurora-postgresql', 'EnabledCloudwatchLogsExports': []})[0] == 'FAIL'
    assert run(cid, {'Engine': 'postgres', 'EnabledCloudwatchLogsExports': ['postgresql']})[0] == 'FAIL'


def test_ebs_optimization_default_is_not_disabled_by_the_instance_flag():
    cid = 'aws.claude_a.ec2.instance_ebs_optimized'
    assert run(cid, dict(CASES[cid]['fail'], InstanceType='t3.micro'))[0] == 'PASS'
    assert run(cid, dict(CASES[cid]['fail'], InstanceType='m3.large'))[0] == 'FAIL'


@pytest.mark.parametrize('cid', ['aws.claude_a.iam.policy_in_use', 'aws.claude_a.iam.custom_policy_in_use'])
def test_permissions_boundary_usage_is_real_policy_usage(cid):
    native = dict(CASES[cid]['fail'], AttachmentCount=0, PermissionsBoundaryUsageCount=8)
    assert run(cid, native)[0] == 'PASS'
    assert run(cid, dict(native, PermissionsBoundaryUsageCount=0))[0] == 'FAIL'


def test_zero_subscription_topic_has_no_delivery_endpoint_to_log():
    cid = 'aws.cb.sns.failure_feedback_role';native = deepcopy(CASES[cid]['fail'])
    native['Attributes']['Attributes'].update(SubscriptionsConfirmed='0', SubscriptionsPending='0')
    assert run(cid, native)[0] == 'NOT_APPLICABLE'
    native['Attributes']['Attributes']['SubscriptionsConfirmed'] = '1'
    assert run(cid, native)[0] == 'FAIL'


def test_dlq_requires_an_exact_native_reference_and_not_a_name_suffix():
    cid = 'aws.cb.sqs.dead_letter_queue';native = deepcopy(CASES[cid]['fail'])
    arn = native['Attributes']['Attributes']['QueueArn']
    index = {'eventbridge_rule': [{'data': {'Targets': {'items': [{'DeadLetterConfig': {'Arn': arn}}]}}}]}
    assert run(cid, native, index)[0] == 'NOT_APPLICABLE'
    index['eventbridge_rule'][0]['data']['Targets']['items'][0]['DeadLetterConfig']['Arn'] += '-other'
    assert run(cid, native, index)[0] == 'FAIL'


@pytest.mark.parametrize('cid', ['aws.cb.secretsmanager.rotation_rules_present', 'aws.cb.secretsmanager.rotated_as_scheduled'])
def test_owning_service_is_required_to_exclude_customer_rotation_rules(cid):
    assert run(cid, dict(CASES[cid]['fail'], OwningService='events'))[0] == 'NOT_APPLICABLE'
    assert run(cid)[0] == 'FAIL'


def policy(resource='arn:aws:execute-api:us-east-1:111111111111:api/*'):
    return {'Statement': [dict(Effect='Allow', Principal='*', Action='execute-api:Invoke', Resource=resource),
        dict(Effect='Deny', Principal='*', Action='execute-api:Invoke', Resource=resource,
             Condition={'NotIpAddress': {'aws:SourceIp': ['203.0.113.10/32', '2a06:98c0::/29']}})]}


def test_explicit_ip_deny_covers_allow_and_preserves_case_sensitive_resources():
    doc = policy();old = deepcopy(doc);normalized, changed = normalize(doc)
    assert changed and review_document(normalized, minimum_ipv6_prefix=1) == ([], [])
    assert doc == old
    doc['Statement'][1]['Resource'] = doc['Statement'][1]['Resource'].replace(':api/', ':API/')
    assert not normalize(doc)[1]
    doc = policy();doc['Statement'][1]['Condition']['Bool'] = {'aws:SecureTransport': 'false'}
    assert not normalize(doc)[1]


def test_escaped_api_policy_and_caller_account_boundary():
    cid = 'aws.c2b.apigateway.rest_api_policy_not_public'
    native = dict(CASES[cid]['fail'], policy=json.dumps(policy()).replace('"', '\\"'))
    assert run(cid, native)[0] == 'PASS'
    assert run(cid)[0] == 'FAIL'
    kms = {'Statement': [dict(Effect='Allow', Principal='*', Action='kms:Decrypt', Resource='*',
                            Condition={'StringEquals': {'kms:CallerAccount': '111111111111'}})]}
    assert review_document(kms) == ([], [])
    kms['Statement'][0]['Condition']['StringEquals']['kms:CallerAccount'] = '*'
    assert review_document(kms)[0]


def test_database_fetcher_filters_shared_endpoint_and_does_not_hide_missing_engine():
    calls = []
    def pages(*args, **kwargs):
        calls.append(kwargs)
        return ReadResult([{'DBClusterArn': 'aurora', 'Engine': 'aurora-postgresql'}, {'DBClusterArn': 'neptune', 'Engine': 'neptune'}])
    r = FETCHERS['neptune_cluster'](SimpleNamespace(pages=pages), None, 'us-east-1', '111111111111')
    assert [v['Engine'] for v in r.items] == ['neptune']
    assert calls == [{'Filters': [{'Name': 'engine', 'Values': ['neptune']}]}]
    r = FETCHERS['neptune_cluster'](SimpleNamespace(pages=lambda *a, **k: ReadResult([{}])), None, 'us-east-1', '111111111111')
    assert r.status == 'partial'


def test_native_metadata_enrichers_do_not_collect_schedule_input_or_change_native_objects():
    original = [{'InstanceType': 't3.micro', 'EbsOptimized': False}]
    reader = SimpleNamespace(pages=lambda *a, **k: ReadResult([{'InstanceType': 't3.micro', 'EbsInfo': {'EbsOptimizedSupport': 'default'}}]))
    result = instances(reader, None, 'us-east-1', original)
    assert 'InstanceTypeInfo' not in original[0] and result[0]['InstanceTypeInfo']['EbsInfo']['EbsOptimizedSupport'] == 'default'
    reader = SimpleNamespace(pages=lambda *a, **k: ReadResult([{'Name': 's', 'GroupName': 'g'}]),
        detail=lambda *a, **k: {'Arn': 'schedule', 'Name': 's', 'GroupName': 'g', 'Target': {'Arn': 'target', 'Input': 'sensitive', 'DeadLetterConfig': {'Arn': 'queue'}}})
    r = schedules(reader, None, 'us-east-1', '111111111111')
    assert r.items[0]['Target'] == {'Arn': 'target', 'DeadLetterConfig': {'Arn': 'queue'}}
    assert 'sensitive' not in json.dumps(r.items)


@pytest.mark.parametrize('cid', ['aws.claude_a.iam.prowler_role_confused_deputy_prevented', 'aws.claude_a.iam.prowler_role_service_trust_bound_to_account'])
def test_firehose_requires_an_enforced_external_id_for_its_own_account(cid):
    native = deepcopy(CASES[cid]['fail'])
    account = native['Arn'].split(':')[4]
    native['AssumeRolePolicyDocument'] = {'Statement': [{'Effect': 'Allow', 'Principal': {'Service': 'firehose.amazonaws.com'},
        'Action': 'sts:AssumeRole', 'Condition': {'StringEquals': {'sts:ExternalId': account}}}]}
    assert run(cid, native)[0] == 'PASS'
    native['AssumeRolePolicyDocument']['Statement'][0]['Condition']['StringEquals']['sts:ExternalId'] = '*'
    assert run(cid, native)[0] == 'FAIL'
    native['AssumeRolePolicyDocument']['Statement'][0]['Condition'] = {'StringEqualsIfExists': {'sts:ExternalId': account}}
    expected = 'FAIL' if cid.endswith('confused_deputy_prevented') else 'NOT_APPLICABLE'
    assert run(cid, native)[0] == expected


def test_unconditioned_mixed_service_and_aws_trust_is_outside_conditioned_control():
    cid = 'aws.claude_a.iam.prowler_role_service_trust_bound_to_account'
    native = deepcopy(CASES[cid]['fail'])
    native['AssumeRolePolicyDocument'] = {'Statement': [{'Effect': 'Allow',
        'Principal': {'Service': 'lambda.amazonaws.com', 'AWS': 'arn:aws:iam::111111111111:root'},
        'Action': 'sts:AssumeRole'}]}
    assert run(cid, native)[0] == 'NOT_APPLICABLE'


def test_cognito_user_pool_audience_is_recognized_case_insensitively_but_requires_review():
    from peaso.analysis.trust import aws_federated_trust
    issuer = 'cognito-idp.us-east-1.amazonaws.com/us-east-1_Example'
    resource = {'data': {'AssumeRolePolicyDocument': {'Statement': [{'Effect': 'Allow',
        'Principal': {'Federated': 'arn:aws:iam::111111111111:oidc-provider/'+issuer}, 'Action': 'sts:AssumeRoleWithWebIdentity',
        'Condition': {'StringEquals': {issuer+':aud': 'client'}}}]}}}
    assert aws_federated_trust({}, resource)[0] == 'MANUAL'
    resource['data']['AssumeRolePolicyDocument']['Statement'][0]['Condition']['StringEquals'][issuer+':sub'] = 'user'
    assert aws_federated_trust({}, resource)[0] == 'PASS'


def test_empty_dead_letter_source_response_is_supported_and_denied_metadata_is_unknown():
    calls=[]
    def pages(*args, **kwargs):
        calls.append((args, kwargs));return ReadResult([], 'empty')
    cid='aws.cb.sqs.dead_letter_queue';native=deepcopy(CASES[cid]['fail'])
    reader=SimpleNamespace(pages=pages)
    output=queues(reader,None,'us-east-1',[native])
    assert calls[0][0][-1]=='queueUrls || `[]`' and calls[0][1]['MaxResults']==1000
    assert output[0]['DeadLetterSourceQueues']['collection_status']=='empty'
    assert run(cid,output[0])[0]=='FAIL'
    output[0]['DeadLetterSourceQueues']['collection_status']='denied'
    assert run(cid,output[0])[0]=='UNKNOWN'


def test_single_public_port_is_a_failure_with_a_short_decisive_explanation():
    from peaso.finding_observation import evidence_summary
    from peaso.ai.pipeline import findings_document
    cid = 'aws.claude_a.vpc.sg_no_world_any_port_on_customer_enis'
    native = deepcopy(CASES[cid]['fail'])
    native['IpPermissions'][0].update(IpProtocol='tcp', FromPort=443, ToPort=443)
    status, evidence = run(cid, native)
    assert status == 'FAIL'
    finding = dict(id='finding-sg', check_id=cid, provider='aws', category='exposure', status=status,
                   evidence=evidence, fail_when='Any internet-open port reaches a customer-managed interface.',
                   pass_when='No internet-open rule reaches a customer-managed interface.')
    before = deepcopy(finding)
    text = evidence_summary(finding)
    assert 'TCP 443' in text and '0.0.0.0/0' in text
    assert 'Any internet-open port' in text and 'all ports do not need' in text and len(text) < 360
    record = findings_document({'provider': 'aws'}, [finding])['items'][0]
    assert record['evidence_summary'] == text and record['fail_when'] == finding['fail_when']
    assert record['evidence'] == evidence and finding == before
    # Missing the witness must not invent a port, while retaining the exact control semantics.
    finding['evidence'] = {k: v for k, v in evidence.items() if k != 'internet_ingress'}
    assert 'TCP 443' not in evidence_summary(finding)


def test_rds_optional_engine_does_not_erase_unrelated_metadata_and_fact_reads_are_selected():
    reader = SimpleNamespace(pages=lambda *a, **k: ReadResult([{'DBInstanceIdentifier': 'database', 'MonitoringInterval': 60}]))
    read = FETCHERS['rds_instance'](reader, None, 'us-east-1', '111111111111')
    assert read.status == 'collected' and read.items[0]['MonitoringInterval'] == 60
    reader = SimpleNamespace(ebs_optimization_facts_requested=False, sqs_dead_letter_sources_requested=False,
                             pages=lambda *a, **k: pytest.fail('Unselected metadata must not consume API calls'))
    assert instances(reader, None, 'us-east-1', [{'EbsOptimized': False}]) == [{'EbsOptimized': False}]
    assert queues(reader, None, 'us-east-1', [{'QueueUrl': 'url'}]) == [{'QueueUrl': 'url'}]


def test_corrected_boundary_evidence_explains_real_usage_without_claiming_attachments():
    from peaso.finding_observation import evidence_summary
    cid = 'aws.claude_a.iam.policy_in_use'
    status, evidence = run(cid, dict(CASES[cid]['fail'], AttachmentCount=0, PermissionsBoundaryUsageCount=8))
    text = evidence_summary(dict(provider='aws', check_id=cid, status=status, evidence=evidence))
    assert '8 identities' in text and 'not unused' in text and len(text) < 300
    assert evidence_summary(dict(provider='aws', check_id=cid, status='PASS', evidence={})) != text


def test_global_shield_resource_is_assessed_once_without_hiding_regional_resources():
    import gzip
    from pathlib import Path
    cid = 'aws.pci.shield.protection_all_internet_resources'
    case = json.loads(gzip.decompress((Path(__file__).parent/'fixtures/aws_bulk_clarity_reviewed.json.gz').read_bytes()))[cid]['FAIL']
    base = deepcopy(case['index'])
    cloudfront = {'ARN': 'arn:aws:cloudfront::123456789012:distribution/D1'}
    base['cloudfront_distribution'] = [{'data': cloudfront, 'scope': '123456789012/global', 'type': 'cloudfront_distribution'}]
    base['collections']['cloudfront_distribution'][0].update(status='collected', items=[cloudfront])
    base['load_balancer'] = []
    base['collections']['load_balancer'][0].update(status='empty', items=[])
    base['context']['metadata'] = {'selected_scopes': ['123456789012/us-west-2', '123456789012/us-east-1']}
    def scoped(region):
        index = deepcopy(base);scope = '123456789012/'+region
        index['context']['scope'] = scope;index['context']['policy_inputs']['scope'] = scope
        for rows in index['collections'].values():
            for row in rows:
                if not row['scope'].endswith('/global'):
                    row['scope'] = scope
        return index
    status, evidence = REGISTRY[cid].evaluate({}, scoped('us-east-1'))
    assert status == 'FAIL' and evidence['unprotected_resource_arns'] == [cloudfront['ARN']]
    assert REGISTRY[cid].evaluate({}, scoped('us-west-2'))[0] == 'NOT_APPLICABLE'
    west = scoped('us-west-2')
    alb = {'LoadBalancerArn': 'arn:aws:elasticloadbalancing:us-west-2:123456789012:loadbalancer/app/a/b',
           'Type': 'application', 'Scheme': 'internet-facing'}
    west['load_balancer'] = [{'data': alb, 'scope': '123456789012/us-west-2', 'type': 'load_balancer'}]
    west['collections']['load_balancer'][0].update(status='collected', items=[alb])
    status, evidence = REGISTRY[cid].evaluate({}, west)
    assert status == 'FAIL' and evidence['unprotected_resource_arns'] == [alb['LoadBalancerArn']]


@pytest.mark.parametrize('cid,key,fragment', [
    ('aws.c2b.efs.policy_not_open_to_vpc_clients', 'policy', 'mount targets'),
    ('aws.c2b.efs.policy_enforces_ssl', 'policy', 'unencrypted NFS'),
    ('aws.c2b.efs.automatic_backups_enabled', 'backup_policy_status', 'enabled AWS Backup'),
    ('aws.cb.secretsmanager.rotated_as_scheduled', 'rotation_rules', 'rotation schedule'),
    ('aws.cb.ssmincidents.active_with_response_plans', 'replication_set', 'response plan'),
    ('aws.claude_a.ec2.account_imdsv2_default', 'http_tokens', 'IMDSv2'),
    ('aws.claude_a.iam.role_used_within_60_days', 'last_used', 'does not prove'),
])
def test_recorded_absence_is_explained_without_inventing_missing_facts(cid, key, fragment):
    from peaso.checks.aws_ai_recheck_evidence_20261020 import evidence_summary
    finding = dict(provider='aws', check_id=cid, status='FAIL', evidence={key: None})
    text = evidence_summary(finding)
    assert fragment in text and len(text) < 250
    finding['evidence'] = {}
    assert evidence_summary(finding) is None


def test_targeted_dlq_collection_includes_lambda_function_destinations():
    from peaso.engine import plan_collection
    cid = 'aws.cb.sqs.dead_letter_queue'
    assert 'lambda_function' in plan_collection({'provider': 'aws', 'checks': [cid]})
    native = deepcopy(CASES[cid]['fail'])
    arn = native['Attributes']['Attributes']['QueueArn']
    assert run(cid, native, {'lambda_function': [{'data': {'DeadLetterConfig': {'TargetArn': arn}}}]})[0] == 'NOT_APPLICABLE'
