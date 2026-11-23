"""Direct subjects of failed evaluations, separate from linked evidence."""
import re
from collections import defaultdict
from functools import lru_cache

from .report_asset_ids import guardduty_detector_arn

_OPAQUE = re.compile(r'(?:[a-f0-9]{32}|(?:sha256:)?[a-f0-9]{64})', re.IGNORECASE)
_OPAQUE_LEAK_SOURCE = re.compile(r'[a-z0-9_-]+:leak:[a-f0-9]{64}', re.IGNORECASE)
_NON_RESOURCE = ('scope:', 'inventory:', 'selection:', 'secret:', 'analysis:')
DEPLOYMENT_ADMIN = 'deployment_role_administrator_access'
WRITABLE_TASK_ROOT = 'aws.b.ecs.all_readonly_roots'
UNENCRYPTED_VOLUME = 'unencrypted_storage_volume'
ISOLATED_PROBLEMS = {DEPLOYMENT_ADMIN, WRITABLE_TASK_ROOT, UNENCRYPTED_VOLUME}
_ADMIN_ATTACHMENT_CHECKS = {
    'aws.claude_a.iam.role_no_administrator_access',
    'aws.claude_a.iam.prowler_role_no_administratoraccess',
}
_DEPLOYMENT_ISSUERS = {'token.actions.githubusercontent.com', 'gitlab.com', 'api.bitbucket.org/2.0/workspaces'}
_TRAIL_BUCKET_CHECKS = {'aws.a.cloudtrail.bucket_access_logging', 'aws.a.cloudtrail.home_bucket_access_logging',
                        'aws.a.cloudtrail.bucket_mfa_delete', 'aws.a.cloudtrail.home_bucket_mfa_join',
                        'aws.nist.all_cloudtrail_destination_bucket_access_logging'}
_TRAIL_BUCKET_LISTS = {'aws_g6_all_cloudtrail_destination_bucket_access_logging': 'unlogged_buckets',
                       'aws_cloudtrail_bucket_lifecycle_retention_365': 'early_retention_buckets'}
_REVIEWED_JOIN_ANCHORS = {WRITABLE_TASK_ROOT, 'aws_cis_s3_macie_classification_coverage',
                          'aws.cb.rds.instance_multi_az_or_cluster',
                          'aws_nist_elb_application_gateway_network_lb_multiple_az_configured'}
_ENDPOINT_CHECKS = {'aws.claude_a.vpc.' + name for name in ('interface_endpoint_ssm_incidents',
                    'interface_endpoint_ecr_dkr', 'vpc_endpoint_ec2', 'interface_endpoint_ssm',
                    'interface_endpoint_ssm_contacts', 'interface_endpoint_ecr_api')}
_DIRECT_EXPOSURE_CHECKS = {'analysis.internet_exposure', 'analysis.principal_exposure',
                           'analysis.exposed_privileged_workload'}
_VOLUME_ENCRYPTION_CHECKS = {'aws.ebs.encryption', 'aws.claude_a.ebs.attached_volume_encrypted',
                             'aws.c2b.ecs.cluster_instance_volumes_encrypted'}
_AWS_CONFIGURATION_TYPES = {'aws_account', 'iam_account_summary', 'iam_password_policy',
                            's3_account_public_access_block', 'ec2_regional_settings'}


@lru_cache(maxsize=1)
def native_contracts():
    from .checks import CHECKS

    return {check.id: (check.kind, frozenset(check.dependencies) - {check.kind}) for check in CHECKS}


def special_kind(finding):
    from .finding_types import annotate

    evidence = finding.get('evidence') or {}
    check = finding.get('check_id', '')
    if evidence.get('secret_leaks') or annotate(finding)['finding_type'] == 'detected_leaks':
        return 'leaks'
    if ('selected_' in check and 'image' in check and 'vulnerabilit' in check
            or evidence.get('Image') and isinstance(evidence.get('Vulnerabilities'), list)
            or evidence.get('image_digest') and isinstance(evidence.get('severity_counts'), dict)):
        return 'image_cves'
    return None


def opaque_asset_id(native_id):
    return bool(isinstance(native_id, str) and
                (_OPAQUE.fullmatch(native_id) or _OPAQUE_LEAK_SOURCE.fullmatch(native_id)))


def subject(provider, scope, resource_type, native_id, kind='resource'):
    if not all(isinstance(value, str) and value.strip() for value in (provider, scope, resource_type, native_id)):
        return None
    if kind == 'resource' and (native_id.startswith(_NON_RESOURCE) or opaque_asset_id(native_id)):
        return None
    if scope in ('unknown', 'selected_scopes', 'requested_scopes'):
        return None
    if kind == 'resource' and provider == 'aws' and native_id.startswith('arn:'):
        parts = native_id.split(':', 5)
        if len(parts) == 6 and parts[4].isdigit():
            scope = f'{parts[4]}/{parts[3] or "global"}'
        elif len(parts) == 6 and parts[2] == 's3' and parts[3:5] == ['', '']:
            scope = scope.split('/')[0] + '/global'
    return {'provider': provider, 'scope': scope, 'type': resource_type, 'native_id': native_id, 'kind': kind}


def identity(item):
    provider, scope, kind, resource_type, native = (item[key] for key in ('provider', 'scope', 'kind', 'type', 'native_id'))
    if kind == 'resource' and provider == 'aws' and native.startswith('arn:'):
        # IAM/endpoint/exposure projections may use different inventory types
        # to describe the same ARN. The ARN is the cloud resource identity.
        resource_type = ''
    if kind == 'resource' and provider == 'azure' and native.lower().startswith(('/subscriptions/', '/providers/')):
        native, scope, resource_type = native.lower(), scope.lower(), ''
    return provider, scope, kind, resource_type, native


def unique(items):
    indexed = {}
    for item in items:
        if item is not None:
            key = identity(item)
            if key not in indexed or item['type'] < indexed[key]['type']:
                indexed[key] = item
    return [indexed[key] for key in sorted(indexed)]


def direct_exposure_subject(check, resource):
    if check in _DIRECT_EXPOSURE_CHECKS:
        return subject(resource['provider'], resource['scope'], resource['type'], resource.get('native_id'))
    return None


def labels(items):
    counts = defaultdict(set)
    for item in items:
        counts[item['native_id']].add(identity(item))
    return sorted(f"{item['native_id']} ({item['scope']}, {item['type']})"
                  if len(counts[item['native_id']]) > 1 else item['native_id'] for item in items)


class SubjectIndex:
    def __init__(self, inventory, provider):
        self.provider = provider
        self.by_id = {item['id']: item for item in inventory if item.get('id')}
        self.by_native = defaultdict(list)
        self.aws_buckets = defaultdict(list)
        for resource in self.by_id.values():
            if isinstance(resource.get('native_id'), str):
                self.by_native[resource.get('scope'), resource['native_id']].append(resource)
                if resource.get('type') == 'bucket' and isinstance(resource.get('scope'), str):
                    self.aws_buckets[resource['scope'].split('/')[0], resource['native_id']].append(resource)

    def resource(self, finding):
        rid = finding.get('resource_id') or ''
        if resource := self.by_id.get(rid):
            return resource
        matches = self.by_native.get((finding.get('scope'), finding.get('native_resource_id') or rid), ())
        return matches[0] if len(matches) == 1 else None

    def direct(self, finding):
        """Resolve the evaluated subject. Generic relationships have no attribution authority."""
        if finding.get('status') != 'FAIL':
            return []
        evidence = finding.get('evidence') or {}
        check = finding.get('check_id', '')
        if evidence.get('source') == 'ai_network_review' or check.startswith('ai.'):
            return []
        if 'affected_subjects' in finding:
            return finding['affected_subjects']
        provider = finding.get('provider') or self.provider
        scope = finding.get('scope')
        rid = finding.get('resource_id') or ''
        special = special_kind(finding)
        if special == 'image_cves':
            from .ai.special_report_details import image_details

            items = []
            for row in image_details([finding]):
                asset, digest = row['asset'], row['digest']
                if asset and digest and not asset.endswith('@' + digest):
                    asset += '@' + digest
                if any(row['counts'].values()):
                    items.append(subject(provider, row['scope'] or scope, 'container_image', asset))
            return unique(items)
        if special == 'leaks':
            return unique(subject(provider, loc.get('scope') or scope, 'content_source', loc.get('resource_id'))
                          for leak in evidence.get('secret_leaks', []) if isinstance(leak, dict)
                          for loc in leak.get('locations', []) if isinstance(loc, dict))
        if check == 'analysis.exposed_container_cves':
            workload = subject(provider, scope, 'container_workload', evidence.get('workload'))
            return [workload] if workload and evidence.get('exposure_routes') else []
        if check == 'aws_organizations_security_service_tamper_scp':
            return unique(subject(provider, f'{account}/global', check, f'{account}/global', 'scope')
                          for account in evidence.get('accounts_without_tamper_deny', [])
                          if isinstance(account, str) and re.fullmatch(r'[0-9]{12}', account))
        if check in ('aws.c2b.ecs.cluster_instance_volumes_encrypted', 'aws_g6_ecs_fargate_storage_encryption'):
            return self.joined_subjects(finding, evidence.get('unencrypted_volumes'),
                                        {'ebs_volume', 'efs_file_system'})
        if check in _TRAIL_BUCKET_CHECKS or check in _TRAIL_BUCKET_LISTS:
            if evidence.get('remote_mfa_delete') == 'unknown':
                return []
            trail = self.resource(finding) or {}
            names = (evidence.get(_TRAIL_BUCKET_LISTS[check]) if check in _TRAIL_BUCKET_LISTS else
                     [evidence.get('destination_bucket') or evidence.get('bucket') or
                      (trail.get('data') or {}).get('S3BucketName')])
            return self.joined_subjects(finding, names, {'bucket'}, bucket_join=True)
        if rid.startswith('scope:') or evidence.get('evaluation_target') == 'scope':
            setting = subject(provider, scope, check, scope, 'scope')
            return [setting] if setting else []
        resource = self.resource(finding)
        if resource is None:
            return []
        native = resource.get('native_id')
        resource_type = resource.get('type')
        if provider == 'aws' and resource_type in _AWS_CONFIGURATION_TYPES:
            where = resource.get('scope') or scope
            if isinstance(where, str) and resource_type != 'ec2_regional_settings':
                where = where.split('/')[0] + '/global'
            setting = subject(provider, where, check, where, 'scope')
            return [setting] if setting else []
        native = guardduty_detector_arn(native, finding, resource_type=resource_type) or native
        contract = native_contracts().get(check)
        if contract is None and check not in _DIRECT_EXPOSURE_CHECKS and check != 'admin-equivalent':
            return []
        if contract is not None:
            target, dependencies = contract
            reviewed_anchor = check in _REVIEWED_JOIN_ANCHORS or (
                check in _ENDPOINT_CHECKS and resource_type == 'vpc' and evidence.get('endpoint_present') is False)
            if target != resource_type or dependencies and not reviewed_anchor:
                return []
        if provider == 'aws' and resource_type == 'bucket' and native and not native.startswith('arn:'):
            native = 'arn:aws:s3:::' + native
        item = subject(resource.get('provider') or provider, resource.get('scope') or scope, resource_type, native)
        return [item] if item else []

    def joined_subjects(self, finding, native_ids, kinds, *, bucket_join=False):
        scope = finding.get('scope')
        if not isinstance(scope, str) or not isinstance(native_ids, list):
            return []
        items = []
        for native in native_ids:
            if not isinstance(native, str):
                continue
            matches = (self.aws_buckets[scope.split('/')[0], native] if bucket_join else
                       self.by_native[scope, native])
            matches = [r for r in matches if r.get('type') in kinds]
            if len(matches) == 1:
                resource = matches[0]
                items.append(subject('aws', resource['scope'], resource['type'],
                                     'arn:aws:s3:::' + native if bucket_join else native))
        return unique(items)

    def problem(self, finding):
        """Bind the deployment-specific claim to the same role's grant and trust."""
        check = finding.get('check_id', '')
        if check in _VOLUME_ENCRYPTION_CHECKS:
            return UNENCRYPTED_VOLUME
        if check not in _ADMIN_ATTACHMENT_CHECKS or finding.get('status') != 'FAIL':
            return check
        if finding.get('affected_problem') == DEPLOYMENT_ADMIN:
            return DEPLOYMENT_ADMIN
        resource = self.resource(finding) or {}
        data = resource.get('data') or {}
        policies = data.get('AttachedManagedPolicies') or []
        if resource.get('type') != 'iam_role' or not any(
                isinstance(policy, dict) and re.fullmatch(r'arn:aws(?:-[a-z0-9-]+)?:iam::aws:policy/AdministratorAccess',
                                                         str(policy.get('PolicyArn', ''))) for policy in policies):
            return check
        trust = data.get('AssumeRolePolicyDocument') or {}
        if not isinstance(trust, dict):
            return check
        statements = trust.get('Statement') or []
        statements = statements if isinstance(statements, list) else [statements]
        if any(isinstance(s, dict) and s.get('Effect') == 'Deny' for s in statements):
            return check
        account = resource.get('scope', '').split('/')[0]
        for statement in statements:
            if not isinstance(statement, dict) or statement.get('Effect') != 'Allow' or statement.get('NotAction'):
                continue
            actions = statement.get('Action') or []
            actions = actions if isinstance(actions, list) else [actions]
            if 'sts:assumerolewithwebidentity' not in {str(action).lower() for action in actions}:
                continue
            principal = statement.get('Principal')
            federated = principal.get('Federated', []) if isinstance(principal, dict) else []
            for arn in federated if isinstance(federated, list) else [federated]:
                if not isinstance(arn, str) or f':{account}:oidc-provider/' not in arn:
                    continue
                issuer = arn.split(':oidc-provider/', 1)[1]
                if issuer in _DEPLOYMENT_ISSUERS or issuer.startswith('api.bitbucket.org/2.0/workspaces/'):
                    return DEPLOYMENT_ADMIN
        return check

    @staticmethod
    def incomplete(finding, affected):
        if finding.get('affected_scope_incomplete') or not affected:
            return True
        evidence = finding.get('evidence') or {}
        if evidence.get('complete') is False:
            return True
        if evidence.get('secret_leaks'):
            return any(not loc.get('resource_id') or opaque_asset_id(loc['resource_id'])
                       for leak in evidence.get('secret_leaks', []) if isinstance(leak, dict)
                       for loc in leak.get('locations', []) if isinstance(loc, dict))
        check = finding.get('check_id')
        field = ('unencrypted_volumes' if check in _VOLUME_ENCRYPTION_CHECKS or
                 check == 'aws_g6_ecs_fargate_storage_encryption' else _TRAIL_BUCKET_LISTS.get(check))
        expected = evidence.get(field)
        return isinstance(expected, list) and len({item for item in expected if isinstance(item, str)}) > len(affected)


def set_issue_subjects(issue, items, *, incomplete=False):
    confirmed = unique(items)
    issue['affected_subjects'] = confirmed
    issue['affected_assets'] = labels([item for item in confirmed if item['kind'] == 'resource'])
    issue['affected_scopes'] = sorted({item['scope'] for item in confirmed if item['kind'] == 'scope'})
    issue['affected_scope_incomplete'] = incomplete


def present_verified_scope(issue):
    """Keep old prose and references without publishing inferred asset counts."""
    if 'affected_subjects' in issue:
        return issue
    value = {key: item for key, item in issue.items() if key not in ('affected_assets', 'manual_affected_assets')}
    return dict(value, affected_assets=[], affected_scopes=[], affected_scope_incomplete=True)


def grouped_subjects(findings):
    failures = [row for row in findings if row.get('status') == 'FAIL']
    subjects = unique(item for row in failures for item in row.get('affected_subjects', []))
    return (len([item for item in subjects if item['kind'] == 'resource']),
            sorted({item['scope'] for item in subjects if item['kind'] == 'scope'}),
            any(row.get('affected_scope_incomplete') or not row.get('affected_subjects') for row in failures))
