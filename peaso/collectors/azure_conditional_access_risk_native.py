"""Passive, tenant-bound Microsoft Graph entitlement facts for sign-in risk CA.

A P2 plan intersection is only a license capability fact, not a claim that
risk-based MFA is configured or effective for any user.
"""
from __future__ import annotations

import re

GRAPH = 'https://graph.microsoft.com'
KIND = 'conditional_access_risk_entitlement'
NATIVE_TYPES = frozenset({KIND})
_GUID = re.compile(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}', re.I)
_SKU_ID = re.compile(r'[A-Za-z0-9_-]{1,160}')
P2_SERVICE_PLAN_ID = 'eec0eb4f-6444-4f95-aba0-50c24d67f998'
POLICY_ENDPOINT = '/v1.0/identity/conditionalAccess/policies'
USERS_ENDPOINT = '/v1.0/users?$select=id,accountEnabled,assignedPlans'
SKUS_ENDPOINT = '/v1.0/subscribedSkus'
MAX_SKUS = 256
MAX_SKU_PLANS = 8192
MAX_PLANS_PER_SKU = 512
MAX_USERS = 100000
MAX_USER_PLANS = 256
MAX_TOTAL_USER_PLANS = 1000000
_SKU_STATES = frozenset({'Enabled', 'Warning', 'Suspended', 'Deleted', 'LockedOut'})
_PLAN_STATES = frozenset({'Success', 'Disabled', 'Error', 'PendingInput',
                          'PendingActivation', 'PendingProvisioning'})
_USER_PLAN_STATES = frozenset({'Enabled', 'Warning', 'Suspended', 'Deleted', 'LockedOut'})


def _risk_policy_present(reader, tenant):
    scope = '/tenants/' + tenant
    sources = [row for row in reader.collections if row.get('type') == 'conditional_access_policy']
    if len(sources) != 1:
        raise ValueError('one complete tenant-bound Conditional Access inventory required')
    source = sources[0]
    if source.get('status') not in ('collected', 'empty'):
        # A denied or unread parent leaves the entitlement unknown, not malformed.
        from .azure import AzureReadError
        raise AzureReadError('native_parent_inventory_incomplete')
    if (source.get('scope', '').casefold() != scope.casefold() or
            source.get('status') not in ('collected', 'empty') or
            not isinstance(source.get('items'), list) or
            (source['status'] == 'empty') != (not source['items'])):
        raise ValueError('Conditional Access inventory incomplete or foreign')
    seen, relevant = set(), False
    for row in source['items']:
        if not isinstance(row, dict):
            raise ValueError('Conditional Access policy malformed')
        rid, proof = row.get('id'), row.get('_provenance')
        if (not isinstance(rid, str) or not _GUID.fullmatch(rid) or rid.casefold() in seen or
                not isinstance(proof, dict) or proof.get('tenant_verified') is not True or
                str(proof.get('tenant_id', '')).casefold() != tenant or
                proof.get('read_only') is not True or proof.get('endpoint') != POLICY_ENDPOINT):
            raise ValueError('Conditional Access policy identity or tenant authority invalid')
        seen.add(rid.casefold())
        state = row.get('state')
        if state not in ('enabled', 'disabled', 'enabledForReportingButNotEnforced'):
            raise ValueError('Conditional Access policy state unresolved')
        if state != 'enabled':
            continue
        conditions = row.get('conditions')
        if not isinstance(conditions, dict):
            raise ValueError('enabled policy conditions unavailable')
        # An unset risk condition does not restrict the sibling rule. It must
        # not suppress licensing reads needed by another explicit risk rule.
        values = conditions.get('signInRiskLevels')
        values = [] if values is None else values
        if (not isinstance(values, list) or any(not isinstance(value, str) or not value for value in values)
                or len(values) != len(set(values))):
            raise ValueError('enabled policy sign-in risk condition unresolved')
        relevant |= bool(values)
    return relevant


def _eligible_p2_plans(reader, request):
    from .azure import AzureReadError
    plans, seen_skus, seen_sku_guids = set(), set(), set()
    sku_count = plan_count = 0
    for page in reader.pages(request, GRAPH + SKUS_ENDPOINT, audience=GRAPH, next_key='@odata.nextLink'):
        if sku_count + len(page) > MAX_SKUS:
            raise AzureReadError('risk_sku_limit')
        sku_count += len(page)
        for sku in page:
            if not isinstance(sku, dict):
                raise ValueError('subscribed SKU malformed')
            rid, guid = sku.get('id'), sku.get('skuId')
            if (not isinstance(rid, str) or not _SKU_ID.fullmatch(rid) or rid.casefold() in seen_skus or
                    not isinstance(guid, str) or not _GUID.fullmatch(guid) or guid.casefold() in seen_sku_guids):
                raise ValueError('subscribed SKU identity missing, foreign or duplicate')
            seen_skus.add(rid.casefold())
            seen_sku_guids.add(guid.casefold())
            state, applies = sku.get('capabilityStatus'), sku.get('appliesTo')
            if state not in _SKU_STATES or applies not in ('User', 'Company'):
                raise ValueError('subscribed SKU applicability or status unresolved')
            service_plans = sku.get('servicePlans')
            if not isinstance(service_plans, list):
                raise ValueError('subscribed SKU service plans absent')
            if len(service_plans) > MAX_PLANS_PER_SKU or plan_count + len(service_plans) > MAX_SKU_PLANS:
                raise AzureReadError('risk_sku_plan_limit')
            plan_count += len(service_plans)
            seen_plans = set()
            for plan in service_plans:
                if not isinstance(plan, dict):
                    raise ValueError('subscribed SKU service plan malformed')
                pid, name, provision = (plan.get('servicePlanId'), plan.get('servicePlanName'),
                                        plan.get('provisioningStatus'))
                if (not isinstance(pid, str) or not _GUID.fullmatch(pid) or pid.casefold() in seen_plans or
                        not isinstance(name, str) or not name or provision not in _PLAN_STATES or
                        (name == 'AAD_PREMIUM_P2') != (pid.casefold() == P2_SERVICE_PLAN_ID)):
                    raise ValueError('subscribed SKU service plan identity or mapping unresolved')
                seen_plans.add(pid.casefold())
                if (name == 'AAD_PREMIUM_P2' and state == 'Enabled' and applies == 'User'
                        and provision == 'Success'):
                    plans.add(pid.casefold())
    return plans


def _users(reader, request, tenant, p2_plans):
    from .azure import AzureReadError
    user_count = plan_count = 0
    seen_users = set()
    for page in reader.pages(request, GRAPH + USERS_ENDPOINT, audience=GRAPH, next_key='@odata.nextLink'):
        if user_count + len(page) > MAX_USERS:
            raise AzureReadError('risk_user_limit')
        user_count += len(page)
        safe = []
        for row in page:
            if not isinstance(row, dict):
                raise ValueError('licensed user malformed')
            rid, enabled, assigned = row.get('id'), row.get('accountEnabled'), row.get('assignedPlans')
            if (not isinstance(rid, str) or not _GUID.fullmatch(rid) or rid.casefold() in seen_users or
                    type(enabled) is not bool or not isinstance(assigned, list)):
                raise ValueError('licensed user identity, account state or plan inventory unresolved')
            seen_users.add(rid.casefold())
            if len(assigned) > MAX_USER_PLANS or plan_count + len(assigned) > MAX_TOTAL_USER_PLANS:
                raise AzureReadError('risk_user_plan_limit')
            plan_count += len(assigned)
            active, seen_plans = set(), set()
            for plan in assigned:
                if not isinstance(plan, dict):
                    raise ValueError('user assigned plan malformed')
                pid, state = plan.get('servicePlanId'), plan.get('capabilityStatus')
                if (not isinstance(pid, str) or not _GUID.fullmatch(pid) or pid.casefold() in seen_plans
                        or state not in _USER_PLAN_STATES):
                    raise ValueError('user assigned plan identity or status unresolved')
                seen_plans.add(pid.casefold())
                if state == 'Enabled':
                    active.add(pid.casefold())
            safe.append({'id': rid.casefold(), 'user_id': rid.casefold(), 'account_enabled': enabled,
                'active_service_plan_ids': sorted(active), 'risk_p2_service_plan_ids': sorted(active & p2_plans),
                '_provenance': {'tenant_id': tenant, 'tenant_verified': True, 'read_only': True,
                    'source_operation': 'Graph_UsersAssignedPlans+SubscribedSkus_List',
                    'users_endpoint': USERS_ENDPOINT, 'skus_endpoint': SKUS_ENDPOINT,
                    'representation': 'risk_entitlement_plan_ids'}})
        yield safe


def collect(reader, request, wanted, transport):
    if KIND not in wanted:
        return
    from .azure import AzureReadError
    tenant = getattr(transport, 'verified_tenant', None)
    if not isinstance(tenant, str) or not _GUID.fullmatch(tenant):
        reader.unavailable(KIND, '/tenants/unverified', 'Microsoft.Graph',
            AzureReadError('native_risk_tenant_unverified'))
        return
    tenant = tenant.casefold()
    scope = '/tenants/' + tenant
    selected_tenant = getattr(transport, 'tenant', None)
    if (selected_tenant is not None and
            (not isinstance(selected_tenant, str) or selected_tenant.casefold() != tenant)):
        reader.unavailable(KIND, scope, 'Microsoft.Graph', AzureReadError('native_risk_tenant_mismatch'))
        return
    try:
        relevant = _risk_policy_present(reader, tenant)
    except (ValueError, AzureReadError) as exc:
        reader.unavailable(KIND, scope, 'Microsoft.Graph', exc)
        return
    if not relevant:
        reader.run([(KIND, scope, 'Microsoft.Graph', lambda: iter([[]]))])
        reader.collections[-1]['metadata'] = {'reason': 'no-enabled-signin-risk-policy'}
        return
    def fetch():
        p2_plans = _eligible_p2_plans(reader, request)
        yield from _users(reader, request, tenant, p2_plans)
    reader.run([(KIND, scope, 'Microsoft.Graph', fetch)])
