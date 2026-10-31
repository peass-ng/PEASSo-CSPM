"""Bound Directory login history and structurally orphaned federation pools."""
from __future__ import annotations
from functools import partial
from pathlib import Path
from datetime import timedelta
from urllib.parse import quote
import json
import re

from peaso.gcp_iam_usage_contract import timestamp
from peaso.unused_iam_gcp import Unavailable, _tokens, _field
from peaso.unused_iam_gcp_authorization import authority, records, request_rows, _observe
from peaso.gcp_directory_usage_contract import KIND, FIELDS, USERS

USER = 'gcp.iam.directory_user_recent_recorded_login'
WORKLOAD = 'gcp.iam.workload_identity_pool_has_enabled_provider'
WORKFORCE = 'gcp.iam.workforce_pool_has_enabled_provider'


def _bool(row, field, *, default=None):
    coverage = row.get('_coverage', {})
    marker = coverage.get(field) if isinstance(coverage, dict) else None
    if marker is not None and (not isinstance(marker, dict) or marker.get('status') not in ('collected', 'empty')):
        raise Unavailable('native state is unavailable: '+field, 'DENIED' if isinstance(marker, dict) and marker.get('status') == 'denied' else 'UNKNOWN')
    value = row.get(field, default)
    if type(value) is not bool:
        raise Unavailable('native state is missing or malformed: '+field)
    return value


def _directory_customer(item, index, scope):
    binding = item.get('_directoryBinding')
    if not isinstance(binding, dict) or binding.get('status') != 'collected' or binding.get('scope') != scope:
        raise Unavailable('independent project and Directory customer binding is unavailable',
                          'DENIED' if isinstance(binding, dict) and binding.get('status') == 'denied' else 'UNKNOWN')
    customer = binding.get('customer')
    if (not isinstance(customer, str) or not re.fullmatch(r'C[A-Za-z0-9_-]+', customer)
            or item.get('customerId') != customer or item.get('directoryCustomer') != customer):
        raise Unavailable('Directory user belongs to a different customer')
    chain = binding.get('chain')
    if not isinstance(chain, list) or not chain or len(chain) > 32:
        raise Unavailable('Directory project hierarchy proof is unavailable')
    current, seen = scope, set()
    for position, row in enumerate(chain):
        if not isinstance(row, dict) or row.get('requested') != current or current in seen:
            raise Unavailable('Directory project hierarchy is inconsistent')
        seen.add(current)
        request_rows(index, [row.get('source_request')], scope, method='GET',
                     urls={'https://cloudresourcemanager.googleapis.com/v3/'+current})
        if position == 0:
            if (not re.fullmatch(r'projects/[1-9][0-9]*', str(row.get('name', '')))
                    or current not in (row['name'], 'projects/'+str(row.get('projectId', '')))):
                raise Unavailable('Directory project identity is inconsistent')
        elif row.get('name') != current:
            raise Unavailable('Directory ancestor identity is inconsistent')
        if position == len(chain)-1:
            if (not re.fullmatch(r'organizations/[1-9][0-9]*', current)
                    or row.get('directoryCustomerId') != customer or binding.get('organization') != current):
                raise Unavailable('Directory organization and customer binding is inconsistent')
        else:
            current = row.get('parent')
            if not isinstance(current, str) or not re.fullmatch(r'(?:folders|organizations)/[1-9][0-9]*', current):
                raise Unavailable('Directory hierarchy parent is unavailable')
    return customer


def user_login(item, index):
    scope, now = authority(item, index)
    users, _ = records(index, 'workspace_user', scope)
    if sum(row == item for row in users) != 1:
        raise Unavailable('user differs from its unique captured Directory identity')
    customer = _directory_customer(item, index, scope)
    uid, email = item.get('id'), item.get('primaryEmail')
    if (not isinstance(uid, str) or not uid or not isinstance(email, str)
            or not re.fullmatch(r'[^@/\s]+@[^@/\s]+', email)
            or item.get('name') != f'customers/{customer}/workspace_user/{uid}'):
        raise Unavailable('Directory user identity is inconsistent')
    request_rows(index, item['_provenance'].get('source_requests'), scope, method='GET', urls={USERS}, all_required=False)
    if _bool(item, 'suspended') or _bool(item, 'archived'):
        return 'NOT_APPLICABLE', {'user_id': uid, 'principal': email, 'reason': 'Directory user is suspended or archived'}
    observations, collection = records(index, KIND, scope)
    matching = [row for row in observations if row.get('user_id') == uid]
    if len(matching) != 1:
        raise Unavailable('unique individual-user login observation is unavailable',
                          'DENIED' if collection.get('status') == 'denied' else 'UNKNOWN')
    observation = matching[0]
    authority(observation, index)
    if (observation.get('directory_customer') != customer or observation.get('user_name') != item['name']
            or observation.get('name') != f'customers/{customer}/users/{uid}/loginActivity'):
        raise Unavailable('individual-user observation belongs to another identity')
    if observation.get('status') != 'collected':
        raise Unavailable('individual-user login metadata could not be read',
                          'DENIED' if observation.get('status') == 'denied' else 'UNKNOWN')
    endpoint = USERS+'/'+quote(uid, safe='')
    receipts = request_rows(index, observation['_provenance'].get('source_requests'), scope, method='GET', urls={endpoint})
    for receipt in receipts:
        query = receipt.get('query')
        if (not isinstance(query, dict) or query.get('projection') != 'full' or query.get('viewType') != 'admin_view'
                or query.get('fields') != FIELDS):
            raise Unavailable('individual-user metadata projection is not the requested native read')
    detail = observation.get('detail')
    if (not isinstance(detail, dict) or detail.get('id') != uid or detail.get('customerId') != customer
            or str(detail.get('primaryEmail', '')).casefold() != email.casefold()):
        raise Unavailable('individual-user detail identity is inconsistent')
    if _bool(detail, 'suspended') or _bool(detail, 'archived'):
        return 'NOT_APPLICABLE', {'user_id': uid, 'principal': email, 'reason': 'Individual Directory user is suspended or archived'}
    created = timestamp(detail.get('creationTime'))
    if created > now:
        raise Unavailable('Directory user creation time is in the future')
    evidence = {'user_id': uid, 'principal': email, 'directory_customer': customer,
                'created_at': created.isoformat(), 'threshold_days': 90, 'source_endpoint': endpoint}
    last = timestamp(detail['lastLoginTime']) if detail.get('lastLoginTime') else None
    if last is not None and (last < created or last > now):
        raise Unavailable('recorded login is outside the current user lifetime; a missing-date sentinel cannot prove inactivity')
    if created >= now-timedelta(days=90):
        return 'PASS', {**evidence, 'object_age_days': (now-created).days,
            'summary': f'{email} was created on {created.date().isoformat()}.\nThis enabled account has existed for fewer than 90 days.\nIts creation age is separate from login activity.'}
    if last is None:
        raise Unavailable('individual Directory user has no valid recorded login date')
    days = (now-last).days
    evidence.update(last_recorded_login=last.isoformat(), days_since_recorded_login=days)
    failed = last < now-timedelta(days=90)
    return ('FAIL' if failed else 'PASS'), {**evidence,
        'summary': f'{email} last logged in on {last.date().isoformat()}, {days} days before capture.\nThe individual Directory user record identifies this enabled account and its creation date.\n' + ('Old accounts can retain access after their owners stop using them.' if failed else 'The recorded login is within the 90-day review period.')}


def _full_list(index, refs, scope, endpoint, *, parent=None):
    receipts = request_rows(index, refs, scope, method='GET', urls={endpoint}, all_required=False)
    for receipt in receipts:
        query = receipt.get('query')
        if (not isinstance(query, dict) or any(field in query for field in ('fields', 'filter'))
                or parent is not None and query.get('parent') != parent):
            raise Unavailable('federation inventory read is filtered or belongs to another parent')
    return receipts


def pool_provider(item, index, *, workforce):
    scope, now = authority(item, index)
    kind, child = ('workforce_pool', 'workforce_provider') if workforce else ('workload_identity_pool', 'workload_identity_provider')
    pools, parent_collection = records(index, kind, scope)
    if sum(pool == item for pool in pools) != 1:
        raise Unavailable('federation pool differs from its unique captured identity')
    name = item.get('name')
    if workforce:
        if (not scope.startswith('organizations/') or item.get('parent') != scope
                or not isinstance(name, str) or not re.fullmatch(r'locations/global/workforcePools/[^/?#]+', name)):
            raise Unavailable('workforce pool is outside its selected organization')
        endpoint = 'https://iam.googleapis.com/v1/locations/global/workforcePools'
    else:
        if not scope.startswith('projects/'):
            raise Unavailable('workload identity pool has no project authority')
        match = re.fullmatch(r'projects/([^/]+)/locations/global/workloadIdentityPools/[^/?#]+', name or '')
        marker = item.get('_coverage', {}).get('_projectIdentity', {})
        if marker.get('status') == 'denied':
            raise Unavailable('workload identity pool project alias could not be read', 'DENIED')
        if not match or match[1] not in _tokens(index, scope):
            raise Unavailable('workload identity pool belongs to another project')
        endpoint = f'https://iam.googleapis.com/v1/{scope}/locations/global/workloadIdentityPools'
    _full_list(index, item['_provenance'].get('source_requests'), scope, endpoint, parent=scope if workforce else None)
    state = _field(item, 'state')
    if state == 'DELETED' or _bool(item, 'disabled', default=False):
        return 'NOT_APPLICABLE', {'pool_name': name, 'reason': 'federation pool is disabled or deleted'}
    if state != 'ACTIVE':
        raise Unavailable('federation pool state is unavailable')
    if not workforce:
        mode = _field(item, 'mode', 'MODE_UNSPECIFIED')
        if mode == 'TRUST_DOMAIN':
            return 'NOT_APPLICABLE', {'pool_name': name, 'reason': 'trust-domain pools use managed workload identities and cannot contain federation providers'}
        if mode not in ('MODE_UNSPECIFIED', 'FEDERATION_ONLY'):
            raise Unavailable('workload identity pool mode is unrecognized')
    providers, collection = records(index, child, scope)
    matches, unresolved, seen = [], [], set()
    for provider in providers:
        provider_name = provider.get('name')
        if not isinstance(provider_name, str) or not re.fullmatch(r'.+/providers/[^/?#]+', provider_name):
            unresolved.append('malformed provider name')
            continue
        if not provider_name.startswith(name+'/providers/'):
            continue
        if not re.fullmatch(re.escape(name)+r'/providers/[^/?#]+', provider_name):
            unresolved.append('provider parent path is malformed')
            continue
        if provider_name in seen:
            raise Unavailable('duplicate federation provider identity')
        seen.add(provider_name)
        authority(provider, index)
        _full_list(index, provider['_provenance'].get('source_requests'), scope, 'https://iam.googleapis.com/v1/'+name+'/providers')
        provider_state = _field(provider, 'state', None)
        if provider_state == 'DELETED':
            continue
        if provider_state != 'ACTIVE':
            unresolved.append('provider state unavailable')
            continue
        if not _bool(provider, 'disabled', default=False):
            matches.append(provider_name)
    evidence = {'pool_name': name, 'enabled_provider_names': matches, 'captured_provider_names': sorted(seen),
                'provider_list_endpoint': 'https://iam.googleapis.com/v1/'+name+'/providers',
                'semantics': 'Declared provider availability, separate from token-exchange or authentication history'}
    if matches:
        return 'PASS', {**evidence, 'summary': f'{name} has {len(matches)} enabled federation provider(s).\nThe current provider definitions contain a declared identity source for this pool.\nProvider availability is separate from successful authentication activity.'}
    if unresolved or collection.get('status') not in ('collected', 'empty') or parent_collection.get('status') not in ('collected', 'empty'):
        raise Unavailable('complete current federation provider inventory is unavailable',
                          'DENIED' if collection.get('status') == 'denied' else 'UNKNOWN')
    _full_list(index, collection.get('source_requests'), scope, evidence['provider_list_endpoint'])
    return 'FAIL', {**evidence, 'summary': f'{name} has no enabled federation providers in its complete provider list.\nThis active pool has no enabled external identity source for new token exchanges.\nAn obsolete pool can leave confusing identity references and grants to maintain.'}


def evaluate_user(item, index):
    return _observe(user_login, item, index, 'individual-user login')


def evaluate_workload(item, index):
    return _observe(partial(pool_provider, workforce=False), item, index, 'workload federation provider')


def evaluate_workforce(item, index):
    return _observe(partial(pool_provider, workforce=True), item, index, 'workforce federation provider')


DECLARATIONS = (
    (USER, 'workspace_user', 'Enabled directory user has a recent recorded login', evaluate_user, ('workspace_user', KIND)),
    (WORKLOAD, 'workload_identity_pool', 'Active workload identity pool has an enabled federation provider', evaluate_workload, ('workload_identity_pool', 'workload_identity_provider')),
    (WORKFORCE, 'workforce_pool', 'Active workforce pool has an enabled federation provider', evaluate_workforce, ('workforce_pool', 'workforce_provider')),
)


def install(registry):
    from peaso.checks.fixtures import CASES
    raw = Path(__file__).with_name('checks').joinpath('unused_iam_gcp_directory_cases.json').read_bytes()
    cases = json.loads(raw)
    if set(cases) != {USER, WORKLOAD, WORKFORCE}:
        raise ValueError('GCP Directory and federation case IDs changed')
    CASES.update(cases)
    for cid, kind, title, evaluate, dependencies in DECLARATIONS:
        registry.register(cid, 'gcp', 'hardening', kind, title, 'low', 'AC-2',
            'Review ownership and dependencies before disabling an inactive account or removing an obsolete federation pool.',
            dependencies=dependencies, allow_incomplete_failure=True)(evaluate)


