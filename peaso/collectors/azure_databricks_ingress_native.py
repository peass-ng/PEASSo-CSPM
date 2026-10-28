"""Read exact Databricks workspace context-ingress binding and account policy."""
import json
import re
from urllib.error import HTTPError
from urllib.request import Request, build_opener, ProxyHandler

from .azure_databricks_native import HOST, _NoRedirect, _unique_object, validate_auth, normalize

KIND = 'databricks_workspace_ingress_policy'
MAX_RESPONSE_BYTES = 2_000_000
UUID = r'[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}'
_BINDING = re.compile(r'/api/2\.0/accounts/(' + UUID + r')/workspaces/([1-9][0-9]{0,18})/network')
_POLICY = re.compile(r'/api/2\.0/accounts/(' + UUID + r')/network-policies/([A-Za-z0-9_.-]{1,32})')


def endpoint(path):
    policy = _POLICY.fullmatch(path) if isinstance(path, str) else None
    if (not isinstance(path, str) or not (_BINDING.fullmatch(path) or policy)
            or policy and policy[2] in ('.', '..')):
        raise ValueError('untrusted Databricks ingress endpoint')
    return HOST + path


def project(value, path):
    match = _BINDING.fullmatch(path)
    if match:
        policy_id = value.get('network_policy_id') if isinstance(value, dict) else None
        if (not isinstance(value, dict) or type(value.get('workspace_id')) is not int
                or value['workspace_id'] != int(match[2])
                or not isinstance(policy_id, str) or not re.fullmatch(r'[A-Za-z0-9_.-]{1,32}', policy_id)
                or policy_id in ('.', '..')):
            raise ValueError('foreign Databricks workspace ingress binding')
        return {'workspace_id': value['workspace_id'], 'network_policy_id': policy_id}
    match = _POLICY.fullmatch(path)
    if (not match or not isinstance(value, dict) or not isinstance(value.get('account_id'), str)
            or value['account_id'].casefold() != match[1].casefold()
            or value.get('network_policy_id') != match[2]):
        raise ValueError('foreign Databricks ingress policy')
    ingress = value.get('ingress')
    public = ingress.get('public_access') if isinstance(ingress, dict) else None
    if not isinstance(public, dict) or public.get('restriction_mode') not in ('FULL_ACCESS', 'RESTRICTED_ACCESS'):
        raise ValueError('Databricks ingress public mode unavailable')
    allows = public.get('allow_rules', [] if public['restriction_mode'] == 'FULL_ACCESS' else None)
    denies = public.get('deny_rules', [])
    if (not isinstance(allows, list) or not isinstance(denies, list)
            or len(allows) > 1000 or len(denies) > 1000
            or any(not isinstance(rule, dict) for rule in (*allows, *denies))):
        raise ValueError('Databricks ingress rules unavailable')
    return {'account_id': match[1], 'network_policy_id': match[2],
            'restriction_mode': public['restriction_mode'],
            'allow_rule_count': len(allows), 'deny_rule_count': len(denies)}


def request_policy(path, auth):
    """Only supplied account OAuth; no ambient AAD, proxy, redirect, or writes."""
    from .azure import AzureReadError
    url = endpoint(path)
    validate_auth(auth)
    token = auth.get('databricks_account_token')
    if not token:
        raise AzureReadError('databricks_account_credential_missing')
    req = Request(url, headers={'Authorization': 'Bearer ' + token, 'Accept': 'application/json'}, method='GET')
    try:
        with build_opener(ProxyHandler({}), _NoRedirect()).open(req, timeout=20) as response:
            body = response.read(MAX_RESPONSE_BYTES + 1)
        if len(body) > MAX_RESPONSE_BYTES:
            raise AzureReadError('databricks_ingress_response_limit')
        return project(json.loads(body, object_pairs_hook=_unique_object), path)
    except HTTPError as exc:
        status = exc.code
        exc.close()
        raise AzureReadError('databricks_ingress_http_error', status) from None


def collect(reader, transport, scopes, wanted, options, auth):
    if 'databricks_workspace' not in wanted:
        return
    from .azure import AzureReadError, _safe_error
    approval = normalize(options)
    if approval is None:
        return
    parents = {row['scope'].casefold(): row for row in reader.collections
               if row['type'] == 'databricks_account_workspace'}
    arm = {row['scope'].casefold(): row for row in reader.collections
           if row['type'] == 'databricks_workspace'}
    jobs = []
    for scope in scopes:
        if approval['scope'].casefold() != scope.casefold():
            continue
        def inventory(scope=scope):
            parent, arm_parent = parents.get(scope.casefold()), arm.get(scope.casefold())
            if (parent is None or parent['status'] not in ('collected', 'empty')
                    or arm_parent is None or arm_parent['status'] not in ('collected', 'empty')):
                raise AzureReadError('databricks_account_workspace_inventory_incomplete')
            arm_ids = {item['id'].casefold() for item in arm_parent['items']}
            account = approval['databricksAccount']['accountId']
            rows = []
            for item in parent['items']:
                rid, wid = item.get('id'), item.get('workspaceId')
                if (not isinstance(rid, str) or rid.casefold() not in arm_ids
                        or item.get('accountId') != account or type(wid) is not int
                        or not 1 <= wid <= 2**63-1):
                    raise ValueError('foreign Databricks account workspace')
                row = {'id': rid, 'policyStatus': 'unavailable'}
                try:
                    binding_path = f'/api/2.0/accounts/{account}/workspaces/{wid}/network'
                    binding = reader.call(transport.request_databricks_ingress, binding_path)
                    binding = project(binding, binding_path)
                    policy_path = f'/api/2.0/accounts/{account}/network-policies/{binding["network_policy_id"]}'
                    policy = reader.call(transport.request_databricks_ingress, policy_path)
                    policy = project(policy, policy_path)
                    row.update(policyStatus='collected', **{k: policy[k] for k in
                        ('network_policy_id', 'restriction_mode', 'allow_rule_count', 'deny_rule_count')},
                        _provenance={'source_operations': ['Account.WorkspaceNetworkOption.Get', 'Account.NetworkPolicy.Get'],
                                     'read_only': True, 'exact_resource_id': rid, 'account_id': account, 'workspace_id': wid})
                except Exception as exc:
                    row['policyStatus'], _ = _safe_error(exc)
                rows.append(row)
            yield rows
        jobs.append((KIND, scope, 'Databricks.Account', inventory))
    reader.run(jobs)
