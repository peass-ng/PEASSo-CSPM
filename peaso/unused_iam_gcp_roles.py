"""Custom-role consumers in the complete scoped root/Cloud Asset IAM inventory."""
from pathlib import Path
import json
import re

from peaso.unused_iam_gcp import Unavailable, _tokens, _field
from peaso.unused_iam_gcp_authorization import authority, records, request_rows, _observe

CHECK = 'gcp.iam.custom_role_has_declared_grants'


def _role(name, aliases):
    match = re.fullmatch(r'((?:projects|organizations)/[^/]+)/roles/([A-Za-z0-9_.]+)', name or '')
    if not match:
        return None
    return match[2] if match[1] in aliases else None


def role_consumers(item, index):
    scope, now = authority(item, index)
    name = _field(item, 'name')
    if isinstance(name, str) and re.fullmatch(r'roles/[A-Za-z0-9_.]+', name):
        return 'NOT_APPLICABLE', {'reason': 'Google predefined role, not a customer custom-role definition'}
    if not isinstance(name, str) or not re.fullmatch(r'(?:projects|organizations)/[^/]+/roles/[A-Za-z0-9_.]+', name):
        raise Unavailable('custom role resource name is malformed')
    roles, _ = records(index, 'iam_role', scope)
    if sum(row == item for row in roles) != 1:
        raise Unavailable('custom role differs from its unique current native definition')
    marker = item.get('_coverage', {}).get('_projectIdentity', {})
    if marker and marker.get('status') not in ('collected', 'empty'):
        raise Unavailable('custom role project identity read is unavailable', 'DENIED' if marker.get('status') == 'denied' else 'UNKNOWN')
    aliases = {scope}
    if scope.startswith('projects/'):
        aliases.update('projects/'+token for token in _tokens(index, scope))
    role_id = _role(name, aliases)
    if role_id is None:
        owner = name.split('/roles/')[0]
        if (scope.startswith('projects/') and owner.startswith('projects/')
                and any(token.split('/')[1].isdecimal() for token in (scope, owner))
                and not index['context']['metadata'].get('data_service_project_bindings', {}).get(scope)):
            raise Unavailable('custom role project number alias is unproven')
        return 'NOT_APPLICABLE', {'role_name': name, 'reason': 'referenced custom role is owned by another scope; assess its owning scope'}
    proof = item['_provenance']
    role_reads = request_rows(index, proof.get('source_requests'), scope, method='GET',
        urls={'https://iam.googleapis.com/v1/'+scope+'/roles', *('https://iam.googleapis.com/v1/'+alias+'/roles/'+role_id for alias in aliases)}, all_required=False)
    for receipt in role_reads:
        query = receipt.get('query')
        if (not isinstance(query, dict) or set(query)-{'view', 'showDeleted', 'pageSize', 'pageToken'}
                or receipt['url'].endswith('/roles') and query.get('view') != 'FULL'):
            raise Unavailable('custom role was not read as a complete native definition')
    deleted = _field(item, 'deleted', False)
    if type(deleted) is not bool:
        raise Unavailable('custom role deletion state is malformed')
    if deleted:
        return 'NOT_APPLICABLE', {'role_name': name, 'reason': 'custom role is soft-deleted'}
    permissions = _field(item, 'includedPermissions', [])
    if (not isinstance(permissions, list) or len(set(permissions)) != len(permissions)
            or any(not isinstance(p, str) or not re.fullmatch(r'[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z0-9_]+)+', p) for p in permissions)):
        raise Unavailable('custom role permission definition is malformed')
    by_role, unresolved, policies, collection, root_url, search_url = _policy_graph(index, scope, aliases)
    consumers = by_role.get(role_id, [])
    evidence = {'role_name': name, 'included_permissions': permissions, 'declared_grants': consumers,
                'inventory_scope': scope, 'source_endpoints': [root_url, search_url],
                'semantics': 'Declared grants in direct root IAM policy and Cloud Asset supported scoped IAM policies; not authentication history'}
    if consumers:
        return 'PASS', {**evidence, 'summary': f'{name} has {len(consumers)} recorded IAM grant(s) with declared principals.\nThe captured bindings identify consumers of this custom role.\nA declared grant is separate from successful permission use.'}
    if collection.get('status') not in ('collected', 'empty') or unresolved:
        ledger = index['context']['metadata'].get('source_requests', [])
        denied = (collection.get('status') == 'denied' or collection.get('error', {}).get('kind') == 'denied'
            or any(row.get('scope') == scope and row.get('status') == 'denied'
                   and (row.get('url'), row.get('method')) in ((root_url, 'POST'), (search_url, 'GET'))
                   for row in ledger if isinstance(row, dict)))
        raise Unavailable('complete scoped IAM policy inventory is unavailable', 'DENIED' if denied else 'UNKNOWN')
    refs = collection.get('source_requests')
    if not isinstance(refs, list) or not refs:
        raise Unavailable('complete IAM inventory source requests are unavailable')
    roots = request_rows(index, refs, scope, method='POST', urls={root_url}, all_required=False)
    if not any(p.get('name') in aliases and p['_provenance'].get('representation') == 'full' for p in policies):
        raise Unavailable('direct complete owning-scope IAM policy is unavailable')
    if any(row.get('request') != {'options': {'requestedPolicyVersion': 3}} for row in roots):
        raise Unavailable('owning-scope IAM read did not request conditional policy version 3')
    searches = request_rows(index, refs, scope, method='GET', urls={search_url}, all_required=False)
    for receipt in searches:
        query = receipt.get('query')
        if (not isinstance(query, dict) or set(query)-{'pageSize', 'pageToken', 'query', 'orderBy'}
                or query.get('query', '') != ''):
            raise Unavailable('IAM search is filtered or has an incomplete field projection')
    return 'FAIL', {**evidence, 'summary': f'{name} has no grant with a principal in the complete scoped IAM inventory.\nThe owning-scope policy and unfiltered Cloud Asset policy search contain no consumer for this role.\nAn obsolete permission definition can make access reviews and future role reuse harder to manage.'}



def _policy_graph(index, scope, aliases):
    from peaso.checks.facts import memoized
    def build():
        policies, collection = records(index, 'iam_policy', scope)
        root_url = 'https://cloudresourcemanager.googleapis.com/v3/'+scope+':getIamPolicy'
        search_url = 'https://cloudasset.googleapis.com/v1/'+scope+':searchAllIamPolicies'
        ledger = index['context']['metadata'].get('source_requests')
        if not isinstance(ledger, list):
            raise Unavailable('scoped IAM request ledger is unavailable')
        by_role, unresolved = {}, []
        receipt_index = {}
        for row in ledger:
            if isinstance(row, dict) and isinstance(row.get('id'), str):
                receipt_index.setdefault(row['id'], []).append(row)
        def policy_read(refs, root):
            if (not isinstance(refs, list) or not refs or any(not isinstance(ref, str) for ref in refs)
                    or len(set(refs)) != len(refs)):
                raise Unavailable('IAM policy read references are unavailable')
            valid = False
            for ref in refs:
                matches = receipt_index.get(ref, [])
                if len(matches) != 1:
                    raise Unavailable('IAM policy read reference is missing or duplicated')
                row = matches[0]
                valid = valid or (row.get('scope') == scope and row.get('method') == ('POST' if root else 'GET')
                    and row.get('url') == (root_url if root else search_url) and row.get('status') == 'collected')
            if not valid:
                raise Unavailable('IAM policy has no successful scoped native read')
        for policy in policies:
            try:
                authority(policy, index)
                resource = policy.get('name')
                if not isinstance(resource, str) or not resource:
                    raise Unavailable('IAM policy resource identity is unavailable')
                refs = policy['_provenance'].get('source_requests')
                native_root = resource in aliases and policy['_provenance'].get('representation') == 'full'
                policy_read(refs, native_root)
                bindings = _field(policy, 'bindings')
                if not isinstance(bindings, list):
                    raise Unavailable('scoped IAM bindings are malformed')
                for binding in bindings:
                    if not isinstance(binding, dict) or not isinstance(binding.get('role'), str) or not isinstance(binding.get('members'), list):
                        raise Unavailable('IAM role binding is malformed')
                    if not re.fullmatch(r'(?:roles/[A-Za-z0-9_.]+|(?:projects|organizations)/[^/]+/roles/[A-Za-z0-9_.]+)', binding['role']):
                        raise Unavailable('IAM binding role name is malformed')
                    candidate = _role(binding['role'], aliases)
                    if candidate is None:
                        continue
                    members = binding['members']
                    if any(not isinstance(member, str) or not member for member in members):
                        raise Unavailable('role binding members are malformed')
                    if members:
                        by_role.setdefault(candidate, []).append({'resource_name': resource, 'declared_role': binding['role'],
                                          'members': list(members), 'condition': binding.get('condition')})
            except (Unavailable, ValueError, TypeError, KeyError, AttributeError) as exc:
                unresolved.append(str(exc))
        return by_role, unresolved, policies, collection, root_url, search_url
    return memoized(index, ('unused_gcp_custom_role_grants', scope, tuple(sorted(aliases))), build)


def evaluate_role(item, index):
    return _observe(role_consumers, item, index, 'custom-role definition and scoped IAM grant')


def install(registry):
    from peaso.checks.fixtures import CASES
    raw = Path(__file__).with_name('checks').joinpath('unused_iam_gcp_roles_cases.json').read_bytes()
    cases = json.loads(raw)
    if set(cases) != {CHECK}:
        raise ValueError('GCP custom role native case IDs changed')
    CASES.update(cases)
    registry.register(CHECK, 'gcp', 'hardening', 'iam_role', 'Custom role has a declared grant in scoped IAM inventory',
        'low', 'AC-2', 'Confirm role ownership and any supported-resource coverage gaps before deleting an obsolete custom role.',
        dependencies=('iam_role', 'iam_policy'), allow_incomplete_failure=True)(evaluate_role)


