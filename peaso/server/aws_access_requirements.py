"""Read-only inspection of the actual AWS scanning identity's policy grants."""
import re

BASELINE_ACTIONS = ('iam:GetAccountAuthorizationDetails', 'ec2:DescribeInstances',
                    'ec2:DescribeRegions', 's3:ListAllMyBuckets')


def _pages(method, field, **kwargs):
    marker, seen, rows = None, set(), []
    for _ in range(20):
        page = method(**kwargs, MaxItems=100, **({'Marker': marker} if marker else {}))
        if not isinstance(page, dict) or not isinstance(page.get(field), list):
            raise ValueError('Incomplete IAM policy inventory')
        rows.extend(page[field])
        if page.get('IsTruncated', False) is False:
            return rows
        marker = page.get('Marker')
        if not isinstance(marker, str) or not marker or marker in seen:
            raise ValueError('Invalid IAM policy continuation')
        seen.add(marker)
    raise ValueError('IAM policy inventory exceeded its page limit')


def check_policy_requirements(iam, identity, scope, issues):
    """Check required baseline and recommended exact policy ARNs, per account.

    Attachments do not prove effective access. Existing live inventory probes
    still run, and custom policies may satisfy the bounded baseline through
    simulation without requiring broad AWS managed policies.
    """
    def issue(severity, message):
        issues.append(dict(severity=severity, scope=scope, message=message))

    arn = identity.get('Arn', '')
    match = re.fullmatch(r'arn:([^:]+):(iam|sts)::([0-9]{12}):(.+)', arn)
    if not match or match[3] != identity.get('Account'):
        issue('critical', 'Cannot identify the scanning IAM user or role to verify required policies.')
        return
    partition, service, account, resource = match.groups()
    policy_prefix = f'arn:{partition}:iam::aws:policy/'
    principal_arn = arn
    policies = set()
    complete = True
    try:
        if service == 'iam' and resource.startswith('user/'):
            name = resource.rsplit('/', 1)[-1]
            rows = _pages(iam.list_attached_user_policies, 'AttachedPolicies', UserName=name)
            policies.update(row['PolicyArn'] for row in rows)
            groups = _pages(iam.list_groups_for_user, 'Groups', UserName=name)
            if len(groups) > 100:
                raise ValueError('Too many IAM groups')
            for group in groups:
                rows = _pages(iam.list_attached_group_policies, 'AttachedPolicies', GroupName=group['GroupName'])
                policies.update(row['PolicyArn'] for row in rows)
        elif (resource.startswith('assumed-role/') and service == 'sts') or (resource.startswith('role/') and service == 'iam'):
            name = resource.split('/')[1] if service == 'sts' else resource.rsplit('/', 1)[-1]
            rows = _pages(iam.list_attached_role_policies, 'AttachedPolicies', RoleName=name)
            policies.update(row['PolicyArn'] for row in rows)
            if service == 'sts':
                # GetRole preserves the path, which the STS session ARN omits.
                principal_arn = iam.get_role(RoleName=name)['Role']['Arn']
        else:
            issue('critical', 'Use an IAM user or assumed scanning role so its required policy grants can be checked.')
            return
    except Exception:
        complete = False

    baseline = policy_prefix + 'ReadOnlyAccess'
    security = policy_prefix + 'SecurityAudit'
    if baseline not in policies and security not in policies:
        equivalent = False
        try:
            result = iam.simulate_principal_policy(PolicySourceArn=principal_arn,
                ActionNames=list(BASELINE_ACTIONS), ResourceArns=['*'])
            rows = result.get('EvaluationResults', [])
            equivalent = (result.get('IsTruncated', False) is False
                and len(rows) == len(BASELINE_ACTIONS)
                and {row.get('EvalActionName') for row in rows} == set(BASELINE_ACTIONS)
                and all(row.get('EvalDecision') == 'allowed' and not row.get('MissingContextValues') for row in rows))
        except Exception:
            pass
        if not equivalent:
            prefix = 'Missing required policy' if complete else 'Could not verify required policy'
            issue('critical', f'{prefix} {baseline} or {security}, or equivalent baseline inventory permissions. Without one of these, account, IAM and compute inventory cannot be relied on.')
    for name, consequence in (
        ('ReadOnlyAccess', 'Some service inventory and configuration data may be missing.'),
        ('SecurityAudit', 'Some security configuration and IAM audit data may be missing.'),
    ):
        policy = policy_prefix + name
        if policy not in policies:
            prefix = 'Missing recommended policy' if complete else 'Could not verify recommended policy'
            issue('advisory', f'{prefix} {policy}. {consequence}')
    if not complete:
        issue('advisory', 'IAM policy attachment inspection was incomplete. Allow the scanning identity to list its attached policies and, for IAM users, its groups and their policies. Some checks might fail.')
