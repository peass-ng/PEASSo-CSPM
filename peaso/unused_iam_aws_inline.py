"""Structural consumers of inline policies embedded in native IAM groups."""
from __future__ import annotations
import json
import re
from pathlib import Path

CHECK = 'aws.iam.group_inline_policies_have_members'
TITLE = 'Group inline policies have member identities'
NAME = r'[\w+=,.@-]+'


class EvidenceError(ValueError):
    def __init__(self, reason, status='UNKNOWN'):
        super().__init__(reason); self.status = status


def field(item, key, default=...):
    if not isinstance(item, dict): raise EvidenceError('native IAM object is unavailable')
    if item.get('collection_status', 'collected') not in ('collected', 'empty'):
        raise EvidenceError('native IAM object read is incomplete', 'DENIED' if item.get('collection_status') == 'denied' else 'UNKNOWN')
    coverage = item.get('_coverage', {})
    if not isinstance(coverage, dict): raise EvidenceError('IAM field coverage is malformed')
    state = coverage.get(key, {})
    if not isinstance(state, dict): raise EvidenceError('IAM field coverage is malformed')
    if state.get('status', 'collected') not in ('collected', 'empty'):
        raise EvidenceError(key + ' is unavailable', 'DENIED' if state.get('status') == 'denied' else 'UNKNOWN')
    if key in item: return item[key]
    if default is ...: raise EvidenceError(key + ' is unavailable')
    return default


def authority(index):
    context = index.get('context', {})
    scope = context.get('scope')
    if context.get('provider') != 'aws' or not isinstance(scope, str) or not re.fullmatch(r'[0-9]{12}/global', scope):
        raise EvidenceError('account-wide native IAM scope is unavailable')
    return scope, scope[:12]


def identity(item, account, kind):
    name = field(item, kind + 'Name')
    stable = field(item, kind + 'Id')
    arn = field(item, 'Arn')
    if (not isinstance(name, str) or not re.fullmatch(NAME, name, re.ASCII)
            or len(name) > (128 if kind == 'Group' else 64)
            or not isinstance(stable, str) or not re.fullmatch(('AGPA' if kind == 'Group' else 'AIDA') + r'[A-Z0-9]{12,124}', stable)):
        raise EvidenceError('native IAM identity is malformed')
    match = re.fullmatch(r'arn:(aws(?:-[a-z0-9]+)*):iam::([0-9]{12}):' + kind.lower() + r'/(.+)', arn) if isinstance(arn, str) else None
    if (not match or match[2] != account or match[3].rsplit('/', 1)[-1] != name
            or item.get('AccountId', account) != account or any(p in ('', '.', '..') for p in match[3].split('/'))):
        raise EvidenceError('native IAM ARN and assessed account disagree')
    proof = item.get('_provenance')
    if (not isinstance(proof, dict) or proof.get('operation') != 'iam:GetAccountAuthorizationDetails'
            or proof.get('native_response_complete') is not True):
        raise EvidenceError('complete native IAM authorization response is unavailable')
    return name, stable, arn


def records(index, kind, scope):
    collections = index.get('collections', {}).get(kind)
    rows = index.get(kind)
    if not isinstance(collections, list) or len(collections) != 1 or not isinstance(rows, list):
        raise EvidenceError('unique scoped ' + kind + ' inventory is unavailable')
    collection = collections[0]
    if (collection.get('type') != kind or collection.get('scope') != scope or collection.get('service') != 'iam'
            or collection.get('account_id', scope[:12]) != scope[:12]
            or not isinstance(collection.get('items'), list)
            or any(not isinstance(row, dict) or row.get('scope') != scope or row.get('type') != kind for row in rows)
            or [row.get('data') for row in rows] != collection['items']):
        raise EvidenceError('native IAM collection and resource projection disagree')
    return collection['items'], collection


def members(index, scope, account):
    from peaso.checks.facts import memoized
    def build():
        users, collection = records(index, 'iam_user', scope)
        by_group, unresolved, seen_ids, seen_names = {}, [], set(), set()
        for user in users:
            try:
                name, stable, arn = identity(user, account, 'User')
            except EvidenceError as exc:
                unresolved.append(exc)
                continue
            if stable in seen_ids or name.casefold() in seen_names:
                raise EvidenceError('native IAM user identity is duplicated')
            seen_ids.add(stable);seen_names.add(name.casefold())
            try:
                groups = field(user, 'GroupList', [])
                if (not isinstance(groups, list) or any(not isinstance(g, str) or not re.fullmatch(NAME, g, re.ASCII) or len(g) > 128 for g in groups)
                        or len({g.casefold() for g in groups}) != len(groups)):
                    raise EvidenceError('native user group memberships are malformed')
                for group in groups:
                    by_group.setdefault(group.casefold(), []).append({'user_arn': arn, 'user_id': stable, 'user_name': name})
            except EvidenceError as exc:
                unresolved.append(exc)
        return by_group, unresolved, collection
    return memoized(index, ('unused_aws_group_inline_members', scope), build)


def current_group(item, index, scope, stable, name):
    from peaso.checks.facts import memoized
    def build():
        groups, source = records(index, 'iam_group', scope)
        by_id, by_name = {}, {}
        for group in groups:
            if not isinstance(group, dict):
                continue
            by_id.setdefault(str(group.get('GroupId')), []).append(group)
            by_name.setdefault(str(group.get('GroupName')).casefold(), []).append(group)
        return by_id, by_name, source
    by_id, by_name, source = memoized(index, ('unused_aws_group_inline_current', scope), build)
    if by_id.get(stable) != [item] or by_name.get(name.casefold()) != [item]:
        raise EvidenceError('assessed group is missing or duplicated in current IAM inventory')
    return source


def evaluate(item, index):
    try:
        scope, account = authority(index)
        name, stable, arn = identity(item, account, 'Group')
        source = current_group(item, index, scope, stable, name)
        if source.get('status') not in ('collected', 'partial'):
            raise EvidenceError('group inventory is unavailable', 'DENIED' if source.get('status') == 'denied' else 'UNKNOWN')
        policies = field(item, 'GroupPolicyList', [])
        if not isinstance(policies, list): raise EvidenceError('inline policy inventory is malformed')
        seen = set()
        for policy in policies:
            if not isinstance(policy, dict): raise EvidenceError('inline policy metadata is malformed')
            pname, document = field(policy, 'PolicyName'), field(policy, 'PolicyDocument')
            if (not isinstance(pname, str) or not re.fullmatch(NAME, pname, re.ASCII) or len(pname) > 128 or pname.casefold() in seen
                    or not isinstance(document, dict)):
                raise EvidenceError('inline policy name or document is malformed')
            statements = document.get('Statement')
            statements = [statements] if isinstance(statements, dict) else statements
            if not isinstance(statements, list) or not statements or any(not isinstance(s, dict) or s.get('Effect') not in ('Allow', 'Deny') for s in statements):
                raise EvidenceError('inline policy statements are unavailable')
            for statement in statements:
                for positive, negative in (('Action', 'NotAction'), ('Resource', 'NotResource')):
                    if (positive in statement) == (negative in statement):
                        raise EvidenceError('inline policy action or resource clauses are malformed')
                    values = statement.get(positive, statement.get(negative))
                    values = [values] if isinstance(values, str) else values
                    if not isinstance(values, list) or not values or any(not isinstance(v, str) or not v for v in values):
                        raise EvidenceError('inline policy action or resource values are malformed')
                if 'Condition' in statement and not isinstance(statement['Condition'], dict):
                    raise EvidenceError('inline policy conditions are malformed')
            seen.add(pname.casefold())
        if not policies:
            return 'NOT_APPLICABLE', {'reason': 'group has no inline policy'}
        membership, unresolved, users = members(index, scope, account)
        found = membership.get(name.casefold(), [])
        evidence = {'group_arn': arn, 'group_id': stable, 'group_name': name, 'inline_policies': list(policies),
                    'member_identities': found, 'semantics': 'Declared group membership and embedded policies, not permission-use history or effective access.'}
        policy_count = f'{len(policies)} inline ' + ('policy' if len(policies) == 1 else 'policies')
        if found:
            member_count = f'{len(found)} captured member ' + ('identity' if len(found) == 1 else 'identities')
            return 'PASS', {**evidence, 'summary': f'Group {name} has {policy_count} and {member_count}.\nThe captured members are declared consumers of the group policies.\nMembership does not establish when any permission was used.'}
        if users.get('status') not in ('collected', 'empty'):
            cause = users.get('error', {}).get('cause_status', users.get('status'))
            raise EvidenceError('complete account-wide user membership inventory is unavailable', 'DENIED' if cause == 'denied' else 'UNKNOWN')
        if unresolved: raise unresolved[0]
        return 'FAIL', {**evidence, 'summary': f'Group {name} has {policy_count} and no IAM user members.\nNo current user inherits these embedded policies through the group.\nThe unused declarations could grant access again if users are added later.'}
    except (EvidenceError, ValueError, TypeError, KeyError, AttributeError) as exc:
        return getattr(exc, 'status', 'UNKNOWN'), {'reason': str(exc), 'summary': str(exc).rstrip('.') + '.\nThe group’s current inline-policy consumers are unresolved.\nAny embedded permissions could still be inherited when a user joins the group.'}


def install(registry):
    from peaso.checks.fixtures import CASES
    raw = Path(__file__).with_name('checks').joinpath('unused_iam_aws_inline_cases.json').read_bytes()
    cases = json.loads(raw)
    if set(cases) != {CHECK}: raise ValueError('AWS inline-policy native case IDs changed')
    CASES.update(cases)
    registry.register(CHECK, 'aws', 'hardening', 'iam_group', TITLE, 'low', 'AC-2',
        'Review group ownership and remove obsolete embedded policies after confirming the group has no intended consumers.',
        dependencies=('iam_group', 'iam_user'), allow_incomplete_failure=True)(evaluate)
