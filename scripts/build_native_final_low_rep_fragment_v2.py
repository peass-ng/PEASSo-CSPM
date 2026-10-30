#!/usr/bin/env python3
"""Build an inactive v2 fragment only from the pinned 190-ID source receipt.

The builder describes reviewed source predicates. It never admits a check at
runtime, and the exact 992 snapshot is used only to resolve recorded refs.
"""
import argparse
import gzip
import hashlib
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts.audit_native_final_low_reps import SNAPSHOT_SHA256, json_items


ROOT = Path(__file__).resolve().parents[1]
RECEIPT = ROOT / 'docs/ai-review/native-final-low-rep-code-190-v3.json'
RECEIPT_SHA256 = '1ed2f23460b3ce98a4b3de993062bd2c7b9d24a9bf986aafbf4efe06b7128682'
SCAN_ID = '992d7b8cbd4340a79e41139ba1a44c1e'
BASE_COMMIT = 'd3e0e0ebfc8cf85196951460ed6db99f59e99c19'

# Exact source family for each recorded kind. Checks with multiple source APIs
# have each nested response named in their per-ID source receipt.
API_BY_KIND = {
    'aws_account_configuration': 'account:GetAlternateContact',
    'cloudtrail': 'cloudtrail:DescribeTrails/GetTrailStatus/GetInsightSelectors',
    'cloudwatch_alarm': 'cloudwatch:DescribeAlarms',
    'log_group': 'logs:DescribeLogGroups',
    'aws_account': 'iam:GetAccountPasswordPolicy',
    'iam_password_policy': 'iam:GetAccountPasswordPolicy',
    'bucket': 's3:GetBucketConfiguration',
    'load_balancer': 'elasticloadbalancing:DescribeLoadBalancers/DescribeLoadBalancerAttributes',
    'rest_api_stage': 'apigateway:GetStages',
    'cloudfront_distribution': 'cloudfront:GetDistributionConfig',
    'cognito_identity_pool': 'cognito-identity:DescribeIdentityPool',
    'dynamodb_table': 'dynamodb:DescribeTable/DescribeContinuousBackups',
    'ecr_repository': 'ecr:DescribeRepositories/GetLifecyclePolicy',
    'ecs_task_definition': 'ecs:DescribeTaskDefinition',
    'lambda_function': 'lambda:GetFunctionConfiguration/GetFunctionConcurrency',
    'rds_instance': 'rds:DescribeDBInstances',
    'ssm_parameter_metadata': 'ssm:DescribeParameters',
    'cloudformation_stack': 'cloudformation:DescribeStacks',
    'glue_data_catalog': 'glue:GetDataCatalogEncryptionSettings',
    'route53_domain': 'route53domains:GetDomainDetail',
    'route53_zone': 'route53:ListQueryLoggingConfigs',
    'sns_topic': 'sns:GetTopicAttributes',
    'sqs_queue': 'sqs:GetQueueAttributes',
    'ec2_regional_settings': 'ec2:GetEbsEncryptionByDefault',
    'instance': 'ec2:DescribeInstances',
    'ec2_launch_template': 'ec2:DescribeLaunchTemplateVersions',
    'guardduty_finding': 'guardduty:ListFindings/GetFindings',
    'iam_user': 'iam:GetUser/ListAccessKeys/ListMFADevices',
    'kms_key': 'kms:DescribeKey/GetKeyRotationStatus',
    'secret': 'secretsmanager:DescribeSecret',
    'iam_credential_report': 'iam:GenerateCredentialReport/GetCredentialReport',
    'acm_certificate': 'acm:DescribeCertificate',
    'http_api_stage': 'apigatewayv2:GetStages',
    'codebuild_project': 'codebuild:BatchGetProjects',
    'cognito_user_pool': 'cognito-idp:DescribeUserPool/DescribeRiskConfiguration',
    'sagemaker_training_job': 'sagemaker:DescribeTrainingJob',
    'ssmincidents_account': 'ssm-incidents:ListReplicationSets/ListResponsePlans',
    'ebs_volume': 'ec2:DescribeVolumes',
    'ec2_image': 'ec2:DescribeImages',
    'network_interface': 'ec2:DescribeNetworkInterfaces',
    'guardduty_detector': 'guardduty:GetDetector/ListFindings',
}

# These are operation classes reviewed against the exact FAIL expression in
# the pinned source receipt. The code path ref below carries that expression.
COUNT_ZERO = frozenset({
    'aws.a.cloudwatch.alarm_state_actions', 'aws.c2b.cloudformation.notifications',
    'aws.cb.route53.public_zone_query_logging', 'aws.claude_a.iam.user_in_group',
})
COUNT_GT_ONE = frozenset({'aws.claude_a.iam.user_one_active_key', 'aws.iam.access_key_count'})
LIST_MEMBERSHIP = {
    'aws.b.ecs.no_privileged_containers': ('any', True),
    'aws.claude_a.s3.lifecycle_rule_enabled': ('not_contains', 'Enabled'),
    'aws.claude_a.s3.prowler_acl_disabled': ('not_contains', 'BucketOwnerEnforced'),
    'aws.claude_a.s3.replication_rule_enabled': ('not_contains', 'Enabled'),
    'aws.cb.route53.domain_transfer_lock': ('not_contains', 'clientTransferProhibited'),
}
NUMBER_THRESHOLDS = {
    'aws.a.iam.password_policy_expiry_at_most_90': ('gt', 90, 'days'),
    'aws.a.iam.password_policy_minimum_length_14': ('lt', 14, 'characters'),
    'aws.a.iam.password_policy_reuse_at_least_24': ('lt', 24, 'uses'),
    'aws.b.cognito.password_minimum_fourteen': ('lt', 14, 'characters'),
}
LITERAL_OPS = {
    'aws.b.cloudfront.geo_restrictions': ('eq', 'none'),
    'aws.b.cloudfront.sni': ('ne', 'sni-only'),
    'aws.b.cognito.deletion_protection': ('ne', 'ACTIVE'),
    'aws.b.cognito.enforced_threat_protection': ('ne', 'ENFORCED'),
    'aws.b.cognito.no_guest_identities': ('eq', True),
    'aws.b.cognito.required_mfa': ('ne', 'ON'),
    'aws.b.codebuild.nonprivileged': ('eq', True),
    'aws.b.dynamodb.point_in_time_recovery': ('ne', 'ENABLED'),
    'aws.b.ecr.all_tags_immutable': ('ne', 'IMMUTABLE'),
    'aws.b.ecr.source_some_immutability': ('eq', 'MUTABLE'),
    'aws.b.ecs.no_host_pid': ('eq', 'host'),
    'aws.b.lambda.active_tracing': ('ne', 'Active'),
    'aws.b.ssm.parameter_secure_type': ('ne', 'SecureString'),
    'aws.c2b.cloudfront.default_behavior_https': ('eq', 'allow-all'),
    'aws.cb.glue.catalog_metadata_encryption': ('eq', 'DISABLED'),
    'aws.claude_a.ec2.instance_detailed_monitoring': ('ne', 'enabled'),
    'aws.ecr.immutable_tags': ('ne', 'IMMUTABLE'),
}
BOOLEAN_COMPARISONS = {
    'aws.b.rds_instance.nondefault_port_policy': 'or',
    'aws.b.apigateway.wildcard_cache_encryption': 'or',
    'aws.b.cloudfront.custom_acm_certificate': 'or',
    'aws.b.cloudfront.viewer_encryption': 'or',
    'aws.claude_a.ec2.instance_imdsv2_applied': 'or',
}


def _values(rows, path):
    values = rows
    for part in path.split('.'):
        many = part.endswith('[]')
        name = part[:-2] if many else part
        found = []
        for value in values:
            if isinstance(value, dict) and name in value:
                child = value[name]
                if many and isinstance(child, list):
                    found.extend(child)
                elif not many:
                    found.append(child)
        if not found:
            return []
        values = found
    return values


def _recorded_path(rows, path):
    """Use the longest observed ancestor when the reviewed field is absent."""
    pieces = path.split('.')
    for size in range(len(pieces), 0, -1):
        prefix = '.'.join(pieces[:size])
        if _values(rows, prefix):
            return prefix
    return ''


def _field_type(path, values):
    if path.endswith(('Date', 'Time', 'Timestamp', 'At')):
        return 'timestamp'
    if any(type(value) is bool for value in values):
        return 'boolean'
    if any(type(value) in (int, float) for value in values):
        return 'number'
    if any(isinstance(value, list) for value in values) or '[]' in path:
        return 'list'
    if any(isinstance(value, dict) for value in values):
        return 'boolean'  # existence of a structured response section
    return 'enum'


def _operation(ident, fields, predicates):
    if ident == 'aws.claude_a.s3.prowler_kms_encryption':
        return {'kind': 'list_membership', 'comparison': 'not_contains',
                'threshold': 'aws:kms|aws:kms:dsse', 'threshold_unit': None}
    if ident == 'aws.c2b.cloudfront.recommended_tls_policy':
        return {'kind': 'list_membership', 'comparison': 'not_contains',
                'threshold': 'CF_RECOMMENDED_TLS', 'threshold_unit': None}
    if ident in LITERAL_OPS:
        comparison, threshold = LITERAL_OPS[ident]
        return {'kind': 'literal_comparison', 'comparison': comparison,
                'threshold': threshold, 'threshold_unit': None}
    if ident in COUNT_ZERO:
        return {'kind': 'count_comparison', 'comparison': 'eq',
                'threshold': 0, 'threshold_unit': 'items'}
    if ident in COUNT_GT_ONE:
        return {'kind': 'count_comparison', 'comparison': 'gt',
                'threshold': 1, 'threshold_unit': 'items'}
    if ident in LIST_MEMBERSHIP:
        comparison, threshold = LIST_MEMBERSHIP[ident]
        return {'kind': 'list_membership', 'comparison': comparison,
                'threshold': threshold, 'threshold_unit': None}
    if ident in NUMBER_THRESHOLDS:
        comparison, threshold, unit = NUMBER_THRESHOLDS[ident]
        return {'kind': 'number_comparison', 'comparison': comparison,
                'threshold': threshold, 'threshold_unit': unit}
    if len(fields) >= 2:
        expression = ' '.join(p['expression'] for p in predicates)
        return {'kind': 'boolean_combination',
                'comparison': BOOLEAN_COMPARISONS.get(
                    ident, 'or' if ' or ' in expression else 'and'),
                'threshold': None, 'threshold_unit': None}
    return {'kind': 'literal_comparison', 'comparison': 'eq',
            'threshold': False if fields[0]['field_type'] == 'boolean' else '',
            'threshold_unit': None}


def build(source_receipt, source_inventory, snapshot):
    source_receipt = Path(source_receipt)
    if hashlib.sha256(source_receipt.read_bytes()).hexdigest() != RECEIPT_SHA256:
        raise ValueError('source review receipt changed')
    if hashlib.sha256(Path(snapshot).read_bytes()).hexdigest() != SNAPSHOT_SHA256:
        raise ValueError('exact 992 snapshot changed')
    receipt = json.loads(source_receipt.read_text())
    inventory_raw = Path(source_inventory).read_bytes()
    if hashlib.sha256(inventory_raw).hexdigest() != receipt['source_inventory_sha256']:
        raise ValueError('source inventory changed')
    inventory = json.loads(inventory_raw)
    if (receipt['scan_id'] != SCAN_ID or receipt['source_proven_count'] != 141
            or receipt['provisional_candidate_count'] != 24
            or receipt['retain_ai_count'] != 25
            or receipt['exact_fail_scope_binding']['source_proven_fail_ids_bound_to_collected_scopes'] != 6711
            or receipt['exact_fail_scope_binding']['source_proven_fail_ids_bound_to_exact_resources'] != 6702
            or receipt['exact_fail_scope_binding']['scope_target_fail_ids_with_complete_dependencies'] != 9):
        raise ValueError('reviewed source decision or exact FAIL binding changed')
    inventory_by_id = {row['check_id']: row for row in inventory['checks']}
    approved = [row for row in receipt['checks'] if row['decision'] == 'native_final_source_proven']
    kinds = {inventory_by_id[row['check_id']]['kind'] for row in approved}
    if 'aws_account' in kinds:
        kinds.add('iam_password_policy')
    rows = {kind: [] for kind in kinds}
    with gzip.open(snapshot, 'rb') as stream:
        for collection in json_items(stream, 'collections.item'):
            kind = collection.get('type')
            if kind in rows and collection.get('status') == 'collected':
                rows[kind].extend(collection.get('items') or [])
    checks = []
    for proof in sorted(approved, key=lambda value: value['check_id']):
        ident = proof['check_id']
        kind = inventory_by_id[ident]['kind']
        if inventory_by_id[ident]['native_fail_count'] != proof['native_fail_count']:
            raise ValueError('numeric source inventory changed: ' + ident)
        if proof['exact_fail_scope_binding']['matched_native_fail_ids'] != proof['native_fail_count']:
            raise ValueError('exact native FAIL binding lost: ' + ident)
        paths = list(dict.fromkeys(proof['bound_api_fields']))
        if not paths:
            raise ValueError('no recorded field paths: ' + ident)
        fields = []
        for raw_path in paths:
            source_kind, path = kind, raw_path
            if path.startswith('iam_password_policy.'):
                source_kind, path = 'iam_password_policy', path.removeprefix('iam_password_policy.')
            observed = _recorded_path(rows.get(source_kind, []), path)
            if not observed:
                continue  # derived local name, not an API field
            values = _values(rows[source_kind], observed)
            field_type = _field_type(path, _values(rows[source_kind], path) or values)
            if (source_kind == 'iam_password_policy' and path in {
                    'PasswordPolicy.MaxPasswordAge',
                    'PasswordPolicy.MinimumPasswordLength',
                    'PasswordPolicy.PasswordReusePrevention'}):
                field_type = 'number'  # typed source spec; 992 may record absent policy
            if field_type == 'timestamp':
                # This slice contains no age predicate; a timestamp used only
                # for presence stays an enum until a separate age schema audit.
                field_type = 'enum'
            fields.append({
                'api': API_BY_KIND[source_kind], 'field_path': path,
                'field_type': field_type, 'source_semantics': 'recorded_api_field',
                'recorded_evidence_ref': f'sha256:{SNAPSHOT_SHA256}#collections[type={source_kind}].items[].{observed}',
            })
        if not fields:
            raise ValueError('no exact recorded evidence ref: ' + ident)
        evaluator = proof['underlying_evaluator'] or proof['evaluator']
        path = evaluator['path']
        source_hash = hashlib.sha256((ROOT / path).read_bytes()).hexdigest()
        if source_hash != evaluator['source_file_sha256']:
            raise ValueError('evaluator source pin changed: ' + ident)
        code_ref = {
            'path': path, 'symbol': evaluator['symbol'],
            'source_sha256': source_hash,
            'audit_ref': (f'docs/ai-review/native-final-low-rep-code-190-v3.json#check_id={ident};'
                          f'{path}:{evaluator["first_line"]}-{evaluator["last_line"]}'),
        }
        checks.append({
            'check_id': ident, 'prod992_disagreements': 0,
            'prod992_reviewed_failures': proof['native_fail_count'],
            'audit_receipt_sha256': RECEIPT_SHA256,
            'deterministic_evidence': {
                'source_fields': fields,
                'operation': _operation(ident, fields, proof['fail_predicates']),
                'scan_time': None, 'code_path_audit_ref': code_ref,
            },
        })
    if len(checks) != 141:
        raise ValueError('source-proven check count changed')
    return {'version': 2, 'source_scan_id': SCAN_ID, 'base_commit': BASE_COMMIT,
            'replay_qualification': {'status': 'pending', 'receipt_sha256': None},
            'checks': checks}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-inventory', required=True)
    parser.add_argument('--snapshot', required=True)
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    candidate = build(RECEIPT, args.source_inventory, args.snapshot)
    Path(args.output).write_text(json.dumps(candidate, indent=2, sort_keys=True) + '\n')
    print(json.dumps({'checks': len(candidate['checks']), 'status': 'pending'}))


if __name__ == '__main__':
    main()
