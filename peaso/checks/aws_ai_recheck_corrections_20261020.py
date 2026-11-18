"""Evidence-reviewed corrections discovered by a real scan's AI rechecks.

Native facts decide each correction. No AI output is evaluated as policy input.
The original source predicates remain available through __wrapped__.
"""
from dataclasses import replace
from functools import wraps
import json
import re
from .facts import get, Unavailable

POLICY_USE = {'aws.claude_a.iam.policy_in_use', 'aws.claude_a.iam.custom_policy_in_use'}
BOUNDARY_APPLICABILITY = {'aws.claude_a.iam.custom_policy_attached_to_role', 'aws.pci.iam.policy_attached_to_active_principal'}
IDS = POLICY_USE | BOUNDARY_APPLICABILITY | {
    'aws_kms_key_expiry',
    'aws.b.rds.engine_log_exports', 'aws.claude_a.ec2.instance_ebs_optimized',
    'aws.cb.sns.failure_feedback_role', 'aws.cb.sqs.dead_letter_queue',
    'aws.cb.secretsmanager.rotation_rules_present', 'aws.cb.secretsmanager.rotated_as_scheduled', 'aws.claude_a.ebs.volume_in_backup_selection', 'aws.c2b.apigateway.rest_api_policy_not_public',
    'aws.claude_a.iam.prowler_role_confused_deputy_prevented',
    'aws.claude_a.iam.prowler_role_service_trust_bound_to_account',
    'aws.pci.shield.protection_all_internet_resources',
    'aws.claude_a.vpc.sg_no_world_any_port_on_customer_enis',
}


def _objects(value):
    if isinstance(value, dict):
        yield value
        for child in value.values():
            yield from _objects(child)
    elif isinstance(value, (list, tuple)):
        for child in value:
            yield from _objects(child)


def dead_letter_references(item, index):
    """Positive, exact native destination references; never infer from names."""
    arn = get(item, 'Attributes.Attributes.QueueArn', str)
    inverse = item.get('DeadLetterSourceQueues', {})
    sources = inverse.get('items')
    if inverse.get('collection_status') == 'collected' and isinstance(sources, (list, tuple)) and sources:
        from urllib.parse import urlsplit
        target = urlsplit(get(item, 'QueueUrl', str))
        account = arn.split(':')[4]
        prefix = '/'+account+'/'
        parsed = [urlsplit(value) for value in sources if isinstance(value, str)]
        if len(parsed) == len(sources) and all(value.scheme == 'https' and value.netloc == target.netloc
                and value.path.startswith(prefix) and len(value.path) > len(prefix) and not value.query and not value.fragment
                for value in parsed):
            return True
    for kind in ('sqs_queue', 'lambda_function', 'lambda_event_source_mapping', 'event_rule', 'eventbridge_rule', 'scheduler_schedule'):
        for wrapper in index.get(kind, []):
            data = wrapper.get('data', {})
            if kind == 'sqs_queue':
                policy = data.get('Attributes', {}).get('Attributes', {}).get('RedrivePolicy')
                try:
                    policy = json.loads(policy) if isinstance(policy, str) else policy
                except ValueError:
                    policy = None
                if isinstance(policy, dict) and policy.get('deadLetterTargetArn') == arn:
                    return True
            else:
                for obj in _objects(data):
                    dlq = obj.get('DeadLetterConfig')
                    if isinstance(dlq, dict) and (dlq.get('Arn') == arn or dlq.get('TargetArn') == arn):
                        return True
                    failed = obj.get('OnFailure')
                    if isinstance(failed, dict) and failed.get('Destination') == arn:
                        return True
    return False


def _override(check, original, item, index):
    from . import result
    if not isinstance(item, dict):
        return original(item, index)
    if check.id == 'aws_kms_key_expiry':
        envelope = item.get('Metadata')
        metadata = envelope.get('KeyMetadata') if isinstance(envelope, dict) else None
        if isinstance(metadata, dict) and metadata.get('KeyState') == 'PendingReplicaDeletion':
            # AWS reports this state while a multi-Region primary waits for
            # replicas to be deleted. The source predicate already handles
            # PendingDeletion; retain its identity, Enabled and tag guards.
            from inspect import unwrap
            unwrap(original).__globals__['_inventory'](item, index, 'kms_key')
            normalized = dict(item, Metadata=dict(envelope, KeyMetadata=dict(
                metadata, KeyState='PendingDeletion')))
            projected = dict(index)
            collections = dict(index['collections'])
            collections['kms_key'] = [dict(index['collections']['kms_key'][0], items=[
                normalized if row == item else row
                for row in index['collections']['kms_key'][0]['items']])]
            projected['collections'] = collections
            projected['kms_key'] = [dict(wrapper, data=normalized if wrapper['data'] == item else wrapper['data'])
                                    for wrapper in index['kms_key']]
            status, evidence = original(normalized, projected)
            if status in ('PASS', 'FAIL') and isinstance(evidence, dict):
                evidence = dict(evidence, key_state='PendingReplicaDeletion')
            return status, evidence
    engine = item.get('Engine')
    expected = {'docdb_cluster': 'docdb', 'docdb_instance': 'docdb', 'neptune_cluster': 'neptune'}.get(check.kind)
    if ((expected and isinstance(engine, str) and engine != expected) or
            (check.kind in {'rds_cluster', 'rds_instance'} and engine in {'docdb', 'neptune'})):
        return 'NOT_APPLICABLE', {'engine': engine, 'expected_engine': expected,
                                  'reason': 'The shared database API returned a different database engine.'}
    if check.id == 'aws.pci.shield.protection_all_internet_resources':
        return _shield_scope(item, index, original)
    status, evidence = original(item, index)
    if status != 'FAIL':
        return status, evidence
    cid = check.id
    if cid in {'aws.claude_a.iam.prowler_role_confused_deputy_prevented', 'aws.claude_a.iam.prowler_role_service_trust_bound_to_account'}:
        from copy import deepcopy
        from .claude_aws_a_lib_trust import _pins_every_value
        normalized = deepcopy(item)
        account = get(item, 'Arn', str).split(':')[4]
        document = get(normalized, 'AssumeRolePolicyDocument', dict)
        statements = document.get('Statement', [])
        statements = [statements] if isinstance(statements, dict) else statements
        changed = False
        for statement in statements:
            principal = statement.get('Principal')
            if principal not in ({'Service': 'firehose.amazonaws.com'}, {'Service': ['firehose.amazonaws.com']}):
                continue
            if _pins_every_value(statement, 'sts:externalid', lambda value: value == account):
                statement.setdefault('Condition', {}).setdefault('StringEquals', {})['aws:SourceAccount'] = account
                changed = True
        if changed and original(normalized, index)[0] == 'PASS':
            return result(False, service='firehose.amazonaws.com', enforced_external_id_account=account,
                          reason='Firehose supplies its account ID as ExternalId, as documented by AWS.')
    if cid == 'aws.claude_a.vpc.sg_no_world_any_port_on_customer_enis':
        from inspect import unwrap
        helpers = unwrap(original).__globals__
        witnesses = []
        for rule in helpers['sg_ingress'](item):
            if not helpers['prowler_sg_open'](rule, '-1', any_address=True, all_ports=True):
                continue
            for field, key, world in (('IpRanges', 'CidrIp', '0.0.0.0/0'), ('Ipv6Ranges', 'CidrIpv6', '::/0')):
                if any(row.get(key) == world for row in rule.get(field, []) if isinstance(row, dict)):
                    witnesses.append({'protocol': rule.get('IpProtocol'), 'from_port': rule.get('FromPort'),
                                      'to_port': rule.get('ToPort'), 'source': world})
        return status, dict(evidence, internet_ingress=witnesses)
    if cid == 'aws.claude_a.ebs.volume_in_backup_selection':
        from inspect import unwrap
        helpers = unwrap(original).__globals__
        arn = helpers['ec2_arn'](index, 'volume', get(item, 'VolumeId', str))
        keys = set(helpers['tags'](item))
        selections = helpers['items'](index, 'backup_selection')
        matched = any(arn in helpers['optional'](selection, 'Resources', [], list) or
                      any(get(condition, 'ConditionKey', str) in keys for condition in
                          helpers['list_of_objects'](helpers['optional'](selection, 'ListOfTags', [], list)))
                      for selection in selections)
        return status, dict(evidence, backup_selection_match=matched, backup_selections_evaluated=len(selections))
    if cid == 'aws.c2b.apigateway.rest_api_policy_not_public':
        from .aws_ip_policy_boundary import normalize
        from .aws_resource_policy_scope import review_document
        normalized, changed = normalize(get(item, 'policy'))
        if changed:
            violations, uncertain = review_document(normalized, minimum_ipv6_prefix=1)
            if not violations and not uncertain:
                return result(False, public_statements=0, source_boundary='covering_explicit_deny_outside_ip_allowlist')
    if cid == 'aws.b.rds.engine_log_exports' and engine == 'aurora-postgresql':
        logs = get(item, 'EnabledCloudwatchLogsExports', list)
        return result('postgresql' not in logs, engine=engine, exported_categories=logs,
                      required_categories=['postgresql'], reason='Aurora PostgreSQL does not export the RDS PostgreSQL upgrade log category.')
    if cid == 'aws.claude_a.ec2.instance_ebs_optimized':
        instance_type = item.get('InstanceType', '')
        info = item.get('InstanceTypeInfo', {})
        support = info.get('EbsInfo', {}).get('EbsOptimizedSupport') if info.get('InstanceType') == instance_type else None
        # AWS documents these current-generation families as optimized by default.
        # Unrecognized types keep the native result; names never infer optional support.
        if support == 'default' or re.fullmatch(r'(?:t3|t3a|t4g)\.(?:nano|micro|small|medium|large|xlarge|2xlarge)', instance_type):
            return result(False, ebs_optimized=True, instance_type=instance_type, optimization='enabled_by_instance_type_default')
        if item.get('_coverage', {}).get('InstanceTypeInfo'):
            from . import unknown
            return unknown('Native instance-type EBS optimization support was unavailable')
    if cid in POLICY_USE | BOUNDARY_APPLICABILITY:
        count = item.get('PermissionsBoundaryUsageCount')
        if isinstance(count, int) and not isinstance(count, bool) and count > 0:
            if cid in BOUNDARY_APPLICABILITY and item.get('AttachmentCount') == 0:
                return 'NOT_APPLICABLE', {'permissions_boundary_usage_count': count, 'permissions_policy_attachment_count': 0,
                    'reason': 'Policy is used as a permissions boundary, not as a permissions-policy attachment; it is not unused.'}
            if cid in POLICY_USE:
                return result(False, permissions_boundary_usage_count=count, policy_in_use=True)
    if cid == 'aws.cb.sns.failure_feedback_role':
        attrs = get(item, 'Attributes.Attributes', dict)
        if attrs.get('SubscriptionsConfirmed') == '0' and attrs.get('SubscriptionsPending') == '0':
            return 'NOT_APPLICABLE', {'subscriptions_confirmed': 0, 'subscriptions_pending': 0, 'reason': 'No confirmed or pending subscription exists for delivery-status logging.'}
    if cid == 'aws.cb.sqs.dead_letter_queue':
        if dead_letter_references(item, index):
            return 'NOT_APPLICABLE', {'dead_letter_destination': True, 'queue_arn': get(item, 'Attributes.Attributes.QueueArn', str), 'reason': 'The queue is an explicitly configured dead-letter destination; no chained DLQ is required.'}
        inverse = item.get('DeadLetterSourceQueues')
        if isinstance(inverse, dict) and inverse.get('collection_status') not in ('collected', 'empty'):
            from . import unknown
            return unknown('Dead-letter source metadata was unavailable')
    if cid in {'aws.cb.secretsmanager.rotation_rules_present', 'aws.cb.secretsmanager.rotated_as_scheduled'} and isinstance(item.get('OwningService'), str) and item['OwningService']:
        return 'NOT_APPLICABLE', {'owning_service': item['OwningService'], 'reason': 'The owning AWS service manages this secret; customer rotation rules are not required.'}
    return status, evidence



def _shield_native_arn(row, scope, kind):
    """DescribeAddresses/Classic DescribeLoadBalancers omit resource ARNs."""
    from .facts import Unavailable, get
    if "ShieldResourceArn" in row or "ShieldResourceArn" in row.get("_coverage", {}):
        return get(row, "ShieldResourceArn", str)
    account, region = scope.split("/")
    if kind == "elastic_ip":
        allocation = get(row, "AllocationId", str)
        if re.fullmatch(r"eipalloc-[0-9a-f]{8,17}", allocation) is None:
            raise Unavailable("Shield EIP allocation identity unavailable")
        return f"arn:aws:ec2:{region}:{account}:eip-allocation/{allocation}"
    name = get(row, "LoadBalancerName", str)
    if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9-]{0,31}", name) is None:
        raise Unavailable("Shield Classic ELB identity unavailable")
    return f"arn:aws:elasticloadbalancing:{region}:{account}:loadbalancer/{name}"


def _shield_scope(item, index, original):
    from . import result
    # The source is loaded into an admission namespace. Importing its module
    # here would register its checks again; reuse its already-bound pure helpers.
    from inspect import unwrap
    helpers = unwrap(original).__globals__
    _rows, _scope, _arn, _account_arn = (helpers[name] for name in ('_rows', '_scope', '_arn', '_account_arn'))
    scope = _scope(index)
    account = scope.split('/')[0]
    scopes = index.get('context', {}).get('metadata', {}).get('selected_scopes', [])
    eligible = sorted(s for s in scopes if isinstance(s, str) and s.startswith(account+'/') and not s.endswith('/global'))
    if not eligible:
        regions = index.get('context', {}).get('metadata', {}).get('regions', [])
        eligible = sorted(account+'/'+r for r in regions if isinstance(r, str) and re.fullmatch(r'[a-z]+-[a-z0-9-]+-\d+', r))
    canonical = eligible[0] if eligible else scope
    protected = {_arn(get(row, 'ResourceArn', str)) for row in _rows(index, 'shield_protection')}
    public = []
    for kind in ('load_balancer', 'classic_load_balancer', 'cloudfront_distribution', 'elastic_ip'):
        for row in _rows(index, kind):
            if kind == 'cloudfront_distribution':
                if scope == canonical:
                    public.append(_account_arn(get(row, 'ARN', str), index, 'cloudfront'))
            elif kind == 'load_balancer':
                if get(row, 'Type', str) == 'application' and get(row, 'Scheme', str) == 'internet-facing':
                    public.append(_account_arn(get(row, 'LoadBalancerArn', str), index, 'elasticloadbalancing'))
            elif kind == 'classic_load_balancer':
                if get(row, 'Scheme', str) == 'internet-facing':
                    public.append(_account_arn(_shield_native_arn(row, scope, kind), index, 'elasticloadbalancing'))
            else:
                public.append(_account_arn(_shield_native_arn(row, scope, kind), index, 'ec2'))
    if not public:
        return 'NOT_APPLICABLE', {'reason': 'No regional supported internet resource; global CloudFront is assessed once.', 'global_cloudfront_scope': canonical}
    return result(bool(set(public)-protected), unprotected_resource_arns=sorted(set(public)-protected),
                  assessed=len(set(public)), global_cloudfront_scope=canonical)


def install():
    from . import CHECKS, unknown
    for position, check in enumerate(CHECKS):
        if check.id not in IDS and check.kind not in {'docdb_cluster', 'docdb_instance', 'neptune_cluster'}:
            continue
        def wrap(check):
            original = check.evaluate
            @wraps(original)
            def evaluate(item, index):
                try:
                    return _override(check, original, item, index)
                except (Unavailable, KeyError, TypeError, ValueError) as error:
                    return unknown(str(error))
            return evaluate
        dependencies = check.dependencies
        if check.id == 'aws.cb.sqs.dead_letter_queue':
            dependencies = tuple(dict.fromkeys([*dependencies, 'eventbridge_rule', 'lambda_function', 'lambda_event_source_mapping', 'scheduler_schedule']))
        CHECKS[position] = replace(check, evaluate=wrap(check), declared_dependencies=dependencies)
