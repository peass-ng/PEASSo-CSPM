"""Read-only Azure activity receipts with metadata-only credential projection."""
from __future__ import annotations
from datetime import datetime, timezone
from peaso.azure_unused_iam_contract import (
    KIND, SCHEMA, GRAPH, BASE_KINDS, REPORTS, MAX_REPORT_ROWS, guid,
    required_types as activity_required_types, project_native, project_report,
)


def required_types(wanted):
    from peaso.azure_unused_role_contract import required_types as role_required_types
    from peaso.azure_unused_arm_role_contract import required_types as arm_required_types
    return activity_required_types(wanted) | role_required_types(wanted) | arm_required_types(wanted) | ({"directory_user"} if "azure_unused_iam_user_success_evidence" in wanted else set())


def collect(reader, request, scopes, wanted, transport, credential_context_id, customer_context_id):
    from .azure_unused_iam_user_completion import collect as collect_user_success
    collect_user_success(reader, request, scopes, wanted, transport, credential_context_id, customer_context_id)
    from .azure_unused_arm_roles_20261021 import collect as collect_arm_roles
    collect_arm_roles(reader, request, scopes, wanted, transport, credential_context_id, customer_context_id)
    from .azure_unused_roles_20261021 import collect as collect_roles
    collect_roles(reader, request, scopes, wanted, transport, credential_context_id, customer_context_id)
    if KIND not in wanted:
        return
    from .azure import _safe_error, ordered_parallel
    try:
        tenant = guid(getattr(transport, 'verified_tenant', None))
        if guid(getattr(transport, 'tenant', None)) != tenant:
            raise ValueError('selected tenant differs from authenticated tenant')
    except ValueError as exc:
        reader.unavailable(KIND, '/tenants/unverified', 'Microsoft.Graph', exc)
        return
    scope = '/tenants/' + tenant
    proof = {'schema': SCHEMA, 'read_only': True, 'tenant_verified': True, 'tenant_id': tenant,
             'credential_context_id': credential_context_id, 'customer_context_id': customer_context_id,
             'endpoint': 'native-unused-iam-projection', 'observed_at': datetime.now(timezone.utc).isoformat()}
    native = []
    for collection in reader.collections:
        kind = collection.get('type')
        if kind not in BASE_KINDS:
            continue
        actual = str(collection.get('scope', '')).casefold()
        if actual != scope and not (kind == 'directory_membership' and actual.startswith(scope + '/groups/')):
            continue
        result = {'type': kind, 'scope': collection['scope'], 'service': collection.get('service'),
                  'status': collection.get('status'), 'items': []}
        try:
            result['items'] = [project_native(kind, row) for row in collection.get('items', [])]
        except ValueError:
            result.update(status='unknown', items=[], error={'code': 'malformed_directory_metadata'})
        if 'error' in collection:
            # Shared reader errors are already sanitized; preserve denied versus unknown.
            result['error'] = collection['error']
        native.append(result)
    def read_report(spec):
        name, endpoint = spec
        source = {'name': name, 'endpoint': endpoint, 'audience': GRAPH, 'method': 'GET',
                  'body': None, 'items': [], 'status': 'not_collected', 'integrity_error': False}
        seen = set()
        try:
            for page in reader.pages(request, GRAPH + endpoint, audience=GRAPH, next_key='@odata.nextLink'):
                for raw in page:
                    row = project_report(name, raw)
                    if row['id'] in seen:
                        raise ValueError('duplicate activity report identity')
                    if len(source['items']) >= MAX_REPORT_ROWS:
                        raise ValueError('activity report row limit exceeded')
                    seen.add(row['id'])
                    source['items'].append(row)
            source['status'] = 'collected' if source['items'] else 'empty'
        except Exception as exc:
            status, error = _safe_error(exc)
            source.update(status='partial' if source['items'] else status, error=error, integrity_error=isinstance(exc, ValueError))
        return source
    # Independent activity reports run bounded in parallel, kept in REPORTS order.
    reports = []
    for ok, source in ordered_parallel(reader, read_report, list(REPORTS.items())):
        if not ok:
            raise source
        reports.append(source)
    # Graph v1.0 has a documented service-principal membership omission.
    # Reuse positive membership evidence, but verify candidate empty static
    # groups with beta before treating absence as an empty group.
    groups = {guid(row['id']): row for c in native if c['type'] == 'directory_group'
              and c['scope'].casefold() == scope for row in c['items']}
    candidates = []
    for source in native:
        if source['type'] != 'directory_membership' or source['status'] != 'empty':
            continue
        group_id = source['scope'].rsplit('/', 1)[-1]
        group = groups.get(group_id.casefold())
        if not group or 'DynamicMembership' in group.get('groupTypes', []) or group.get('visibility') == 'HiddenMembership':
            continue
        candidates.append((source, '/beta/groups/' + guid(group_id) + '/members?$select=id'))
    def verify_members(candidate):
        # Each candidate mutates only its own membership source.
        source, endpoint = candidate
        source.update(endpoint=endpoint, membership_api='beta', method='GET', items=[])
        seen = set()
        try:
            for page in reader.pages(request, GRAPH + endpoint, audience=GRAPH, next_key='@odata.nextLink'):
                for raw in page:
                    member_id = guid(raw.get('id'))
                    if member_id in seen:
                        raise ValueError('duplicate group member identity')
                    seen.add(member_id)
                    source['items'].append({'id': member_id})
            source['status'] = 'collected' if source['items'] else 'empty'
            source.pop('error', None)
        except Exception as exc:
            status, error = _safe_error(exc)
            source.update(status='partial' if source['items'] else status, error=error)
    for ok, value in ordered_parallel(reader, verify_members, candidates):
        if not ok:
            raise value
    record = {'id': scope + '/unusedIamEvidence', 'schema': SCHEMA, 'native_collections': native,
              'reports': reports, '_provenance': proof}
    # Source failures stay typed inside the projection; one denied activity API
    # must not hide an independently confirmed empty group or stale credential.
    reader.collections.append({'type': KIND, 'scope': scope, 'service': 'Microsoft.Graph',
                               'status': 'collected', 'items': [record], '_provenance': dict(proof)})
