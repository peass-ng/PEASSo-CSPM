"""Native Graph authentication-strength metadata; no simulated sign-in claims."""
from __future__ import annotations
import re
from threading import Lock

GRAPH = 'https://graph.microsoft.com'
NATIVE_TYPES = frozenset({'authentication_strength', 'conditional_access_group_membership', 'conditional_access_risk_entitlement'})
_GUID = re.compile(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}', re.I)


def collect(reader, request, wanted, transport):
    if 'conditional_access_risk_entitlement' in wanted:
        from . import azure_conditional_access_risk_native
        azure_conditional_access_risk_native.collect(reader, request, wanted, transport)
    if 'conditional_access_group_membership' in wanted:
        _collect_group_membership(reader, request, transport)
    if 'authentication_strength' not in wanted:
        return
    from .azure import AzureReadError
    tenant = getattr(transport, 'verified_tenant', None)
    if not isinstance(tenant, str) or not _GUID.fullmatch(tenant):
        reader.unavailable('authentication_strength', '/tenants/unverified', 'Microsoft.Graph',
            AzureReadError('native_strength_tenant_unverified'))
        return
    endpoint = '/v1.0/policies/authenticationStrengthPolicies'
    def fetch():
        seen = set()
        for rows in reader.pages(request, GRAPH + endpoint, audience=GRAPH, next_key='@odata.nextLink'):
            safe = []
            for raw in rows:
                rid = raw.get('id')
                if not isinstance(rid, str) or not _GUID.fullmatch(rid) or rid.casefold() in seen:
                    raise ValueError('native authentication strength identity malformed or duplicate')
                seen.add(rid.casefold())
                methods = raw.get('allowedCombinations')
                if (not isinstance(methods, list) or not methods or
                        any(not isinstance(m, str) or not m for m in methods) or len(methods) != len(set(methods))):
                    raise ValueError('native authentication strength combinations malformed')
                safe.append({'id': rid, 'requirementsSatisfied': raw.get('requirementsSatisfied'),
                    'allowedCombinations': methods, '_provenance': {'read_only': True,
                    'tenant_id': tenant, 'tenant_verified': True, 'endpoint': endpoint,
                    'source_operation': 'authenticationStrengthPolicies_List', 'representation': 'full'}})
            yield safe
    reader.run([('authentication_strength', '/tenants/' + tenant, 'Microsoft.Graph', fetch)])


GROUP_KIND = 'conditional_access_group_membership'
MAX_REFERENCED_GROUPS = 64
MAX_MEMBERS_PER_GROUP = 100000
MAX_TOTAL_GROUP_MEMBERS = 200000
_POLICY_ENDPOINT = '/v1.0/identity/conditionalAccess/policies'
_NON_USER_TYPES = frozenset({'#microsoft.graph.group', '#microsoft.graph.device',
    '#microsoft.graph.servicePrincipal', '#microsoft.graph.orgContact'})


def _requested_groups(reader, tenant):
    scope = '/tenants/' + tenant
    sources = [row for row in reader.collections if row.get('type') == 'conditional_access_policy']
    if len(sources) != 1:
        raise ValueError('one complete tenant-bound Conditional Access policy inventory required')
    source = sources[0]
    if source.get('status') not in ('collected', 'empty'):
        # A denied or unread parent leaves membership unknown, not malformed.
        from .azure import AzureReadError
        raise AzureReadError('native_parent_inventory_incomplete')
    if (source.get('scope', '').casefold() != scope.casefold() or
            source.get('status') not in ('collected', 'empty') or
            not isinstance(source.get('items'), list) or
            (source['status'] == 'empty') != (not source['items'])):
        raise ValueError('Conditional Access policy inventory incomplete or foreign')
    groups, policies = set(), set()
    for row in source['items']:
        if not isinstance(row, dict):
            raise ValueError('malformed Conditional Access policy row')
        rid = row.get('id')
        proof = row.get('_provenance')
        if (not isinstance(rid, str) or not _GUID.fullmatch(rid) or rid.casefold() in policies or
                not isinstance(proof, dict) or proof.get('tenant_verified') is not True or
                str(proof.get('tenant_id', '')).casefold() != tenant.casefold() or
                proof.get('read_only') is not True or proof.get('endpoint') != _POLICY_ENDPOINT):
            raise ValueError('Conditional Access policy identity or tenant authority invalid')
        policies.add(rid.casefold())
        state = row.get('state')
        if state not in ('enabled', 'disabled', 'enabledForReportingButNotEnforced'):
            raise ValueError('Conditional Access policy state unresolved')
        if state != 'enabled':
            continue
        conditions = row.get('conditions')
        users = conditions.get('users') if isinstance(conditions, dict) else None
        if not isinstance(users, dict):
            raise ValueError('enabled Conditional Access users condition unavailable')
        for key in ('includeGroups', 'excludeGroups'):
            values = users.get(key)
            if not isinstance(values, list):
                raise ValueError('enabled Conditional Access group references unavailable')
            for value in values:
                if not isinstance(value, str) or not _GUID.fullmatch(value):
                    raise ValueError('malformed Conditional Access group reference')
                groups.add(value.casefold())
                if len(groups) > MAX_REFERENCED_GROUPS:
                    raise ValueError('Conditional Access referenced-group hard limit exceeded')
    return sorted(groups)


def _group_metadata(reader, request, group_id):
    endpoint = '/v1.0/groups/' + group_id + '?$select=id,visibility,groupTypes,membershipRuleProcessingState'
    row = reader.call(request, GRAPH + endpoint, audience=GRAPH)
    if not isinstance(row, dict) or str(row.get('id', '')).casefold() != group_id:
        raise ValueError('requested group metadata identity mismatch')
    kinds = row.get('groupTypes')
    visibility = row.get('visibility', object())
    if (not isinstance(kinds, list) or any(kind not in ('Unified', 'DynamicMembership') for kind in kinds) or
            len(kinds) != len(set(kinds)) or visibility not in (None, 'Public', 'Private', 'HiddenMembership')):
        raise ValueError('requested group visibility or type unresolved')
    if 'DynamicMembership' in kinds or visibility == 'HiddenMembership':
        raise ValueError('dynamic or hidden group membership completeness unproven')
    if visibility is None and 'Unified' in kinds:
        raise ValueError('Unified group visibility unavailable')
    return endpoint


def _collect_group_membership(reader, request, transport):
    from .azure import AzureReadError
    tenant = getattr(transport, 'verified_tenant', None)
    if not isinstance(tenant, str) or not _GUID.fullmatch(tenant):
        reader.unavailable(GROUP_KIND, '/tenants/unverified', 'Microsoft.Graph',
            AzureReadError('native_group_tenant_unverified'))
        return
    tenant = tenant.casefold()
    scope = '/tenants/' + tenant
    selected_tenant = getattr(transport, 'tenant', None)
    if (selected_tenant is not None and
            (not isinstance(selected_tenant, str) or selected_tenant.casefold() != tenant)):
        reader.unavailable(GROUP_KIND, scope, 'Microsoft.Graph',
            AzureReadError('native_group_tenant_mismatch'))
        return
    try:
        groups = _requested_groups(reader, tenant)
    except (ValueError, AzureReadError) as exc:
        reader.unavailable(GROUP_KIND, scope, 'Microsoft.Graph', exc)
        return
    if not groups:
        reader.run([(GROUP_KIND, scope, 'Microsoft.Graph', lambda: iter([[]]))])
        return
    jobs = []
    total_members = [0]
    member_budget_lock = Lock()
    for group_id in groups:
        endpoint = '/v1.0/groups/' + group_id + '/transitiveMembers'
        def fetch(group_id=group_id, endpoint=endpoint):
            metadata_endpoint = _group_metadata(reader, request, group_id)
            users, seen = set(), set()
            group_members = 0
            # The untyped endpoint avoids an advanced-query header and retains
            # only type-qualified user IDs, including nested group members.
            for page in reader.pages(request, GRAPH + endpoint, audience=GRAPH, next_key='@odata.nextLink'):
                # Count every returned directory-object reference, including
                # nonusers and duplicates, before retaining any part of a page.
                count = len(page)
                if group_members + count > MAX_MEMBERS_PER_GROUP:
                    raise AzureReadError('group_member_limit')
                with member_budget_lock:
                    if total_members[0] + count > MAX_TOTAL_GROUP_MEMBERS:
                        raise AzureReadError('group_member_total_limit')
                    total_members[0] += count
                group_members += count
                for member in page:
                    if not isinstance(member, dict):
                        raise ValueError('malformed transitive group member')
                    rid = member.get('id')
                    kind = member.get('@odata.type')
                    if (not isinstance(rid, str) or not _GUID.fullmatch(rid) or
                            rid.casefold() in seen or
                            kind not in _NON_USER_TYPES | {'#microsoft.graph.user'}):
                        raise ValueError('transitive member identity, type or uniqueness unresolved')
                    seen.add(rid.casefold())
                    if kind == '#microsoft.graph.user':
                        users.add(rid.casefold())
            yield [{'id': group_id, 'group_id': group_id, 'user_ids': sorted(users),
                '_provenance': {'read_only': True, 'tenant_id': tenant, 'tenant_verified': True,
                    'requested_group_id': group_id, 'source_operation': 'Groups_TransitiveMembers_List',
                    'endpoint': endpoint, 'group_metadata_endpoint': metadata_endpoint,
                    'representation': 'complete_transitive_user_ids'}}]
        jobs.append((GROUP_KIND, scope + '/groups/' + group_id, 'Microsoft.Graph', fetch))
    reader.run(jobs)
