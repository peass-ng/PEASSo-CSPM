"""Native SCP protection of AWS security services against member-account tampering.

The signed sw37 predicate needed a customer list of audited accounts and
break-glass principals, and accepted only ``service:*`` denies with no
condition. Real tamper SCPs deny the specific disable/delete actions and exempt
an administration role through ``aws:PrincipalArn``. This successor keeps the
check ID and decides from provider facts only: every ACTIVE member account in
the effective-SCP inventory must inherit a Deny of the key tamper actions of
each service, on all resources, either unconditionally or conditioned only on
an exempted principal ARN. The management account is never restricted by SCPs.
"""
from __future__ import annotations

import re
import sys

from .facts import Unavailable, get

CHECK_ID = 'aws_organizations_security_service_tamper_scp'
TITLE = 'SCPs deny disabling GuardDuty, Config, Security Hub and CloudTrail'
REMEDIATION = ('Attach an SCP to the organization root (or every member OU) that denies the listed '
               'GuardDuty, AWS Config, Security Hub and CloudTrail disable/delete actions on Resource "*", '
               'exempting only your security administration role with an ArnNotLike aws:PrincipalArn condition.')

# Key actions an account administrator would use to blind each service.
TAMPER_ACTIONS = {
    'guardduty': ('guardduty:DeleteDetector', 'guardduty:UpdateDetector',
                  'guardduty:DisassociateFromMasterAccount', 'guardduty:DisassociateFromAdministratorAccount'),
    'config': ('config:StopConfigurationRecorder', 'config:DeleteConfigurationRecorder',
               'config:DeleteDeliveryChannel'),
    'securityhub': ('securityhub:DisableSecurityHub', 'securityhub:DisassociateFromMasterAccount',
                    'securityhub:DisassociateFromAdministratorAccount'),
    'cloudtrail': ('cloudtrail:StopLogging', 'cloudtrail:DeleteTrail'),
}
# Reported, never decisive.
OPTIONAL_ACTIONS = ('access-analyzer:DeleteAnalyzer',)

_EXEMPT_OPERATORS = {'arnnotlike', 'arnnotequals', 'stringnotlike', 'stringnotequals'}
# A pattern that exempts every principal (or every role/user) protects nothing.
_BROAD = re.compile(r'\*|arn:\*|arn:aws[\w*-]*:(?:iam|sts|\*)::[^:]*:(?:\*|role/\*|user/\*|assumed-role/\*|\*/\*)',
                    re.IGNORECASE)


def _sw37():
    module = sys.modules.get('peaso.checks._bulk_pending_compliance_new_sw37')
    if module is None:
        raise Unavailable('Organizations SCP helpers unavailable')
    return module


def _values(value, what):
    values = [value] if isinstance(value, str) else value
    if not isinstance(values, list) or not values or any(not isinstance(v, str) or not v for v in values):
        raise Unavailable('malformed SCP ' + what)
    return values


def _matches(pattern, action):
    regex = ''.join('.*' if c == '*' else '.' if c == '?' else re.escape(c) for c in pattern)
    return re.fullmatch(regex, action, re.IGNORECASE) is not None


def _covered(statement, actions):
    """Actions the statement's Action/NotAction applies to."""
    if ('Action' in statement) == ('NotAction' in statement):
        raise Unavailable('SCP statement needs exactly one of Action or NotAction')
    if 'Action' in statement:
        patterns = _values(statement['Action'], 'Action')
        return {a for a in actions if any(_matches(p, a) for p in patterns)}
    patterns = _values(statement['NotAction'], 'NotAction')
    return {a for a in actions if not any(_matches(p, a) for p in patterns)}


def _all_resources(statement):
    if 'NotResource' in statement or 'Resource' not in statement:
        return False
    return '*' in _values(statement['Resource'], 'Resource')


def _false(value):
    values = value if isinstance(value, list) else [value]
    return bool(values) and all(v is False or (isinstance(v, str) and v.lower() == 'false') for v in values)


def _exemption(condition, organization_id):
    """Exempted principal patterns when the condition only exempts principals, else None."""
    if not isinstance(condition, dict):
        raise Unavailable('malformed SCP Condition')
    exempted = []
    for operator, clause in condition.items():
        if not isinstance(operator, str) or not isinstance(clause, dict) or not clause:
            raise Unavailable('malformed SCP Condition')
        base = operator.lower()
        base = base[:-len('ifexists')] if base.endswith('ifexists') else base
        for key, value in clause.items():
            if not isinstance(key, str):
                raise Unavailable('malformed SCP Condition key')
            key = key.lower()
            if base in _EXEMPT_OPERATORS and key == 'aws:principalarn':
                values = _values(value, 'Condition value')
                if any(_BROAD.fullmatch(v) for v in values):
                    return None
                exempted.extend(values)
            elif base in ('stringequals', 'stringlike') and key == 'aws:principalorgid':
                # Every principal an SCP restricts belongs to this organization.
                if not any(_matches(v, organization_id) for v in _values(value, 'Condition value')):
                    return None
            elif base == 'bool' and key == 'aws:principalisawsservice' and _false(value):
                continue  # SCPs never restrict service principals.
            else:
                return None
    return exempted


def _accounts(item, index):
    sw = _sw37()
    sw._member(item, index, 'organization', 'id')
    organization = get(item, 'Organization', dict)
    organization_id, management = get(organization, 'Id', str), get(organization, 'MasterAccountId', str)
    rows = sw._rows(index, 'organization_effective_scp')
    if not rows:
        raise Unavailable('effective SCP inventory is empty')
    assessed, exempt = {}, []
    for row in rows:
        account = get(row, 'TargetAccountId' if 'TargetAccountId' in row else 'AccountId', str)
        if not re.fullmatch(r'\d{12}', account) or account in assessed or account in exempt:
            raise Unavailable('effective SCP account identity invalid or duplicated')
        if 'OrganizationId' in row and get(row, 'OrganizationId', str) != organization_id:
            raise Unavailable('effective SCP row belongs to another organization')
        if row.get('ScpApplicable') is False:
            if account != management or get(row, 'Complete', bool) is not True:
                raise Unavailable('SCP exemption is not bound to management account')
            exempt.append(account)  # SCPs do not restrict the management account.
            continue
        if 'Complete' in row and get(row, 'Complete', bool) is not True:
            raise Unavailable('effective SCP path incomplete')
        assessed[account] = get(row, 'Policies', list)
    return organization_id, assessed, exempt


def _account_protection(policies, organization_id):
    required = {a for actions in TAMPER_ACTIONS.values() for a in actions} | set(OPTIONAL_ACTIONS)
    denied, conditional, exempted = set(), set(), set()
    for statement in _sw37()._deny_statements(policies):
        if not isinstance(statement, dict):
            raise Unavailable('malformed SCP statement')
        covered = _covered(statement, required)
        if not covered or not _all_resources(statement) or 'Principal' in statement or 'NotPrincipal' in statement:
            continue
        condition = statement.get('Condition') or {}
        principals = _exemption(condition, organization_id) if condition else []
        if principals is None:
            conditional |= covered
            continue
        denied |= covered
        exempted.update(principals)
    return denied, conditional - denied, exempted


def evaluate(item, index):
    organization_id, assessed, exempt = _accounts(item, index)
    if not assessed:
        return 'NOT_APPLICABLE', {'reason': 'SCPs do not restrict the organization management account',
                                  'scp_exempt_accounts': exempt}
    unprotected, missing, conditional, exempted, analyzer = {}, {}, {}, {}, []
    for account, policies in sorted(assessed.items()):
        denied, only_conditional, principals = _account_protection(policies, organization_id)
        gaps = {service: [a for a in actions if a not in denied] for service, actions in TAMPER_ACTIONS.items()}
        gaps = {service: actions for service, actions in gaps.items() if actions}
        if gaps:
            unprotected[account] = sorted(gaps)
            missing[account] = sorted(a for actions in gaps.values() for a in actions)
        if only_conditional - set(OPTIONAL_ACTIONS):
            conditional[account] = sorted(only_conditional - set(OPTIONAL_ACTIONS))
        if principals:
            exempted[account] = sorted(principals)
        if any(a not in denied for a in OPTIONAL_ACTIONS):
            analyzer.append(account)
    evidence = {'accounts_without_tamper_deny': sorted(unprotected), 'unprotected_services': unprotected,
                'missing_actions': missing, 'assessed_accounts': sorted(assessed), 'scp_exempt_accounts': exempt,
                'exempted_principals': exempted, 'conditionally_denied_actions': conditional,
                'access_analyzer_delete_not_denied_accounts': analyzer}
    return ('FAIL' if unprotected else 'PASS'), evidence


def description():
    return {
        'description': ('Checks that every member account inherits SCPs denying the actions an account administrator '
                        'would use to disable GuardDuty, AWS Config, Security Hub and CloudTrail. Without them, an '
                        'attacker with admin rights in a member account can blind monitoring before acting.'),
        'evaluated': ['organizations:ListAccounts, ListParents, ListPoliciesForTarget and DescribePolicy: SCPs '
                      'attached on each ACTIVE account-to-root path',
                      'Deny statements: Action/NotAction (IAM wildcards, case-insensitive), Resource and Condition',
                      'Complete inventories: organization, organization_effective_scp'],
        'pass_when': ('Every member account has Deny statements on all resources covering ' + ', '.join(
            a for actions in TAMPER_ACTIONS.values() for a in actions) + ', unconditionally or only exempting '
            'named principals through ArnNotLike/ArnNotEquals/StringNotLike/StringNotEquals on aws:PrincipalArn.'),
        'fail_when': ('A member account lacks such a Deny for any of those actions. A Deny limited by any other '
                      'condition (for example a Region) does not count. Evidence lists unprotected services and '
                      'missing actions per account.'),
        'not_applicable_when': 'Only the management account was assessed; SCPs never restrict it.',
        'remediation': REMEDIATION,
    }


def install():
    """Replace the signed customer-input callback in place, keeping ID and position."""
    from dataclasses import replace
    from . import CHECKS, register
    position = next(i for i, check in enumerate(CHECKS) if check.id == CHECK_ID)
    original = CHECKS.pop(position)
    register(CHECK_ID, original.provider, 'hardening', original.kind, TITLE, original.severity, original.control,
             REMEDIATION, dependencies=list(original.dependencies), target=original.target)(evaluate)
    CHECKS.insert(position, replace(CHECKS.pop(), category=original.category))
