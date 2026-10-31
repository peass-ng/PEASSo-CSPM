"""Native empty-group and provider-observed unused-grant Hardening controls."""
from __future__ import annotations
from decimal import Decimal
from pathlib import Path
import json
import re
from datetime import timedelta

from peaso.gcp_iam_usage_contract import timestamp
from peaso.unused_iam_gcp import Unavailable, _tokens

GROUP = 'gcp.iam.static_group_has_members'
GRANT = 'gcp.iam.role_grant_has_observed_permission_use'
POLICY_TYPE = 'google.iam.policy.Insight'


def authority(item, index):
    proof = item.get('_provenance')
    context = index.get('context', {})
    scope = context.get('scope')
    if (context.get('provider') != 'gcp' or not isinstance(scope, str)
            or not re.fullmatch(r'(?:projects|folders|organizations)/[A-Za-z0-9_-]+', scope)
            or not isinstance(proof, dict) or proof.get('scope') != scope
            or timestamp(proof.get('collected_at')) != timestamp(context.get('metadata', {}).get('asset_read_time', context.get('created_at')))):
        raise Unavailable('native identity capture does not match the selected scope')
    clock = timestamp(context['created_at'])
    captured = timestamp(proof['collected_at'])
    if captured > clock or clock-captured > timedelta(days=1):
        raise Unavailable('native capture start is outside the completed scan interval')
    return scope, clock


def records(index, kind, scope):
    collections = index.get('collections', {}).get(kind)
    projected = index.get(kind)
    if not isinstance(collections, list) or len(collections) != 1 or not isinstance(projected, list):
        raise Unavailable('native inventory was not collected: ' + kind)
    collection = collections[0]
    rows = collection.get('items')
    if (collection.get('type') != kind or collection.get('scope') != scope
            or not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows)
            or [row.get('data') for row in projected if isinstance(row, dict)] != rows):
        raise Unavailable('native inventory projection differs from its capture: ' + kind)
    return rows, collection


def request_rows(index, refs, scope, *, method, urls, all_required=True):
    ledger = index.get('context', {}).get('metadata', {}).get('source_requests')
    if (not isinstance(ledger, list) or not isinstance(refs, list) or not refs
            or any(not isinstance(ref, str) or not ref for ref in refs) or len(set(refs)) != len(refs)):
        raise Unavailable('native request provenance is unavailable')
    matched = []
    for ref in refs:
        matches = [row for row in ledger if isinstance(row, dict) and row.get('id') == ref]
        if len(matches) != 1:
            raise Unavailable('native request identity is missing or duplicated')
        row = matches[0]
        valid = (row.get('scope') == scope and row.get('method') == method
                 and row.get('url') in urls and row.get('status') == 'collected')
        if valid:
            matched.append(row)
        elif all_required:
            raise Unavailable('native request differs from its read authority',
                              'DENIED' if row.get('status') == 'denied' else 'UNKNOWN')
    if not matched:
        raise Unavailable('no successful bound native read was recorded')
    return matched


def group_has_members(item, index):
    scope, now = authority(item, index)
    rows, collection = records(index, 'group', scope)
    if item not in rows:
        raise Unavailable('group differs from its current captured inventory')
    name = item.get('name')
    if not isinstance(name, str) or not re.fullmatch(r'groups/[A-Za-z0-9_-]+', name):
        raise Unavailable('Cloud Identity group resource name is unavailable')
    proof = item['_provenance']
    if proof.get('representation') != 'full' or not re.fullmatch(r'customers/C[A-Za-z0-9_-]+', item.get('parent', '')):
        raise Unavailable('complete Google directory group metadata is unavailable')
    request_rows(index, proof.get('source_requests'), scope, method='GET',
                 urls={'https://cloudidentity.googleapis.com/v1/groups', 'https://cloudidentity.googleapis.com/v1/'+name}, all_required=False)
    marker = item.get('_coverage', {}).get('directMemberships')
    if not isinstance(marker, dict) or marker.get('scope') != scope or marker.get('group') != name or timestamp(marker.get('collected_at')) != timestamp(proof.get('collected_at')):
        raise Unavailable('per-group direct membership observation is unavailable')
    names = item.get('_direct_membership_names')
    if (not isinstance(names, list) or len(set(names)) != len(names)
            or any(not isinstance(value, str) or not re.fullmatch(re.escape(name)+r'/memberships/[A-Za-z0-9_-]+', value) for value in names)):
        raise Unavailable('direct membership identities are inconsistent')
    endpoint = 'https://cloudidentity.googleapis.com/v1/'+name+'/memberships'
    evidence = {'group_name': name, 'group_email': item.get('groupKey', {}).get('id'),
                'direct_membership_names': names, 'membership_count': len(names), 'source_endpoint': endpoint}
    if names:
        request_rows(index, item.get('_direct_membership_requests'), scope, method='GET', urls={endpoint})
        return 'PASS', {**evidence, 'summary': f'{name} has {len(names)} recorded direct membership(s).\nThe membership list identifies a declared consumer of this group.\nMembership is separate from authentication activity.'}
    if marker.get('status') != 'collected':
        raise Unavailable('direct group membership listing did not complete',
                          'DENIED' if marker.get('status') == 'denied' else 'UNKNOWN')
    request_rows(index, marker.get('source_requests'), scope, method='GET', urls={endpoint})
    if 'dynamicGroupMetadata' in item:
        raise Unavailable('dynamic group membership may change with its query')
    return 'FAIL', {**evidence, 'summary': f'{name} has no direct members in its complete Cloud Identity membership list.\nThis static group currently has no member to receive its grants.\nObsolete group grants can make account access harder to review.'}


def _condition(value):
    if value is None:
        return ''
    if not isinstance(value, dict) or not isinstance(value.get('expression', ''), str):
        raise Unavailable('IAM condition expression is malformed')
    return value.get('expression', '')


def _permissions(value):
    if not isinstance(value, list):
        raise Unavailable('policy insight permission observations are unavailable')
    names = []
    for row in value:
        name = row.get('permission') if isinstance(row, dict) else None
        if not isinstance(name, str) or not re.fullmatch(r'[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z0-9_]+)+', name) or name in names:
            raise Unavailable('policy insight permission observation is malformed')
        names.append(name)
    return names


def grant_has_usage(item, index):
    scope, now = authority(item, index)
    rows, collection = records(index, 'insight', scope)
    if item not in rows:
        raise Unavailable('policy insight differs from its native capture')
    name = item.get('name')
    pattern = r'((?:projects|folders|organizations)/[^/]+)/locations/([a-z0-9-]+)/insightTypes/google\.iam\.policy\.Insight/insights/[^/?#]+'
    matched = re.fullmatch(pattern, name or '')
    aliases = {scope}
    if scope.startswith('projects/'):
        aliases.update('projects/'+token for token in _tokens(index, scope))
    if not matched or matched[1] not in aliases:
        raise Unavailable('policy insight belongs to a different scope or type')
    endpoint = f'https://recommender.googleapis.com/v1/{scope}/locations/{matched[2]}/insightTypes/{POLICY_TYPE}/insights'
    request_rows(index, item['_provenance'].get('source_requests'), scope, method='GET', urls={endpoint})
    state = item.get('stateInfo')
    if not isinstance(state, dict) or state.get('state') not in ('ACTIVE', 'ACCEPTED', 'DISMISSED'):
        raise Unavailable('policy insight state is unavailable')
    if state['state'] != 'ACTIVE':
        return 'NOT_APPLICABLE', {'reason': 'policy insight is not ACTIVE', 'insight_name': name}
    if item.get('insightSubtype') != 'PERMISSIONS_USAGE':
        return 'NOT_APPLICABLE', {'reason': 'insight is not a permissions-usage observation', 'insight_name': name}
    if item.get('category') != 'SECURITY':
        raise Unavailable('policy insight category is inconsistent')
    duration = item.get('observationPeriod')
    if not isinstance(duration, str) or not re.fullmatch(r'[0-9]{1,12}(?:\.[0-9]{1,9})?s', duration):
        raise Unavailable('policy insight observation duration is unavailable')
    seconds = Decimal(duration[:-1])
    refreshed = timestamp(item.get('lastRefreshTime'))
    if seconds < 90*86400 or refreshed > now or now-refreshed > timedelta(days=3):
        raise Unavailable('policy insight needs at least 90 days and a current provider refresh')
    targets = item.get('targetResources')
    if not isinstance(targets, list) or len(targets) != 1 or not isinstance(targets[0], str):
        raise Unavailable('policy insight resource target is unavailable or ambiguous')
    target = targets[0]
    content = item.get('content')
    if not isinstance(content, dict):
        raise Unavailable('policy insight content is unavailable')
    role, member = content.get('role'), content.get('member')
    if not isinstance(role, str) or not re.fullmatch(r'(?:roles/[\w.]+|(?:projects|organizations)/[\w.-]+/roles/[\w.]+)', role):
        raise Unavailable('policy insight role is malformed')
    if not isinstance(member, str) or not member or not (':' in member or member in ('allUsers', 'allAuthenticatedUsers')):
        raise Unavailable('policy insight principal is malformed')
    expression = _condition(content.get('condition'))
    policies, _ = records(index, 'iam_policy', scope)
    bound = []
    for policy in policies:
        resource = policy.get('name')
        if (resource != target and not (resource in aliases and target in {'//cloudresourcemanager.googleapis.com/'+alias for alias in aliases})):
            continue
        authority(policy, index)
        bindings = policy.get('bindings')
        if not isinstance(bindings, list):
            raise Unavailable('current resource IAM bindings are unavailable')
        for binding in bindings:
            if (isinstance(binding, dict) and binding.get('role') == role
                    and isinstance(binding.get('members'), list) and member in binding['members']
                    and _condition(binding.get('condition')) == expression):
                proof = policy['_provenance']
                root = resource in aliases and proof.get('representation') == 'full'
                request_rows(index, proof.get('source_requests'), scope,
                    method='POST' if root else 'GET',
                    urls={f'https://cloudresourcemanager.googleapis.com/v3/{scope}:getIamPolicy'} if root else
                         {f'https://cloudasset.googleapis.com/v1/{scope}:searchAllIamPolicies'}, all_required=False)
                bound.append(policy)
    if not bound:
        raise Unavailable('insight does not match a currently captured resource, role, principal and condition')
    used = _permissions(content.get('exercisedPermissions'))
    inferred = _permissions(content.get('inferredPermissions'))
    evidence = {'insight_name': name, 'resource_name': target, 'role': role, 'principal': member,
                'condition_expression': expression, 'exercised_permissions': used,
                'inferred_permissions': inferred, 'observation_start': (refreshed-timedelta(seconds=float(seconds))).isoformat(),
                'observation_end': refreshed.isoformat(), 'observation_days': int(seconds//86400),
                'source_endpoint': endpoint}
    if used:
        return 'PASS', {**evidence, 'summary': f'{member} has recorded permission use through {role} on {target}.\nThe provider insight lists {len(used)} exercised permission(s) in its observation window.\nOther permissions in the role may still need a separate least-privilege review.'}
    if inferred:
        raise Unavailable('no exercised permissions are listed, but Google infers permissions this principal may need')
    return 'FAIL', {**evidence, 'summary': f'{member} has no recorded permission use through {role} on {target}.\nThe ACTIVE Google insight covers {int(seconds//86400)} days ending {refreshed.date().isoformat()} and lists no exercised or inferred permissions.\nThis current grant could preserve access after its original purpose has ended.'}


def _observe(predicate, item, index, subject):
    try:
        return predicate(item, index)
    except (Unavailable, ValueError, TypeError, KeyError, AttributeError) as exc:
        return getattr(exc, 'status', 'UNKNOWN'), {'reason': str(exc),
            'summary': f'{str(exc).rstrip(".")}.\nThe required {subject} details are unavailable or inconsistent.\nIt is unclear whether this access object is obsolete.'}


def evaluate_group(item, index):
    return _observe(group_has_members, item, index, 'direct group membership')


def evaluate_grant(item, index):
    return _observe(grant_has_usage, item, index, 'current IAM grant and permission-use')


DECLARATIONS = (
    (GROUP, 'group', 'Static Cloud Identity group has direct members', evaluate_group, ('group', 'group_membership')),
    (GRANT, 'insight', 'Current IAM role grant has observed permission use', evaluate_grant, ('insight', 'iam_policy')),
)


def install(registry):
    from peaso.checks.fixtures import CASES
    raw = Path(__file__).with_name('checks').joinpath('unused_iam_gcp_authorization_cases.json').read_bytes()
    cases = json.loads(raw)
    if set(cases) != {GROUP, GRANT}:
        raise ValueError('GCP unused authorization native case IDs changed')
    CASES.update(cases)
    for cid, kind, title, evaluate, dependencies in DECLARATIONS:
        registry.register(cid, 'gcp', 'hardening', kind, title, 'low', 'AC-2',
            'Confirm the group or grant owner and its dependencies before removing obsolete access.',
            dependencies=dependencies, allow_incomplete_failure=True)(evaluate)


