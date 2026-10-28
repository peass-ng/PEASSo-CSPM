"""Read exact Databricks workspace context-ingress binding and account policy."""
import ipaddress
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


def _public_rule(rule, target, *, deny=False):
    """Project a public UI or SQL API rule with an exact broad identity type."""
    if not isinstance(rule, dict) or set(rule) - {'origin', 'destination', 'authentication', 'label'}:
        return None
    destination = rule.get('destination')
    if target == 'ui':
        if destination not in ({'all_destinations': True}, {'workspace_ui': {'all_destinations': True}}):
            return None
    elif target == 'api':
        if destination == {'all_destinations': True} or destination == {'workspace_api': {}}:
            scope = 'all'
        elif (not deny and isinstance(destination, dict) and set(destination) == {'workspace_api'}
              and isinstance(destination['workspace_api'], dict)
              and set(destination['workspace_api']) == {'scopes', 'scope_qualifier'}
              and isinstance(destination['workspace_api']['scopes'], list)
              and 1 <= len(destination['workspace_api']['scopes']) <= 100
              and 'sql' in destination['workspace_api']['scopes']
              and destination['workspace_api']['scope_qualifier'] in
                  ('API_SCOPE_QUALIFIER_READ', 'API_SCOPE_QUALIFIER_ALL')):
            scope = 'sql'
        else:
            return None
    else:
        raise ValueError('unsupported Databricks ingress target')
    authentication = rule.get('authentication')
    identities = {None: 'both',
                  'IDENTITY_TYPE_ALL_USERS': 'users',
                  'IDENTITY_TYPE_ALL_SERVICE_PRINCIPALS': 'service_principals'}
    identity_type = authentication.get('identity_type') if isinstance(authentication, dict) else None
    if authentication is not None and (not isinstance(authentication, dict)
                                       or set(authentication) != {'identity_type'}
                                       or identity_type is None
                                       or identity_type not in identities):
        return None
    identity = identities[identity_type]
    origin = rule.get('origin')
    if not isinstance(origin, dict):
        return None
    if origin == {'all_ip_ranges': True}:
        result = {'origin': 'all', 'ranges': [], 'identity': identity}
        return {**result, 'scope': scope} if target == 'api' else result
    if len(origin) != 1 or next(iter(origin)) not in ('included_ip_ranges', 'excluded_ip_ranges'):
        return None
    kind, spec = next(iter(origin.items()))
    if not isinstance(spec, dict) or set(spec) != {'ip_ranges'} or not isinstance(spec['ip_ranges'], list) or not 1 <= len(spec['ip_ranges']) <= 1000:
        return None
    ranges = []
    for raw in spec['ip_ranges']:
        if not isinstance(raw, str):
            return None
        try:
            network = ipaddress.ip_network(raw, strict=False)
        except ValueError:
            return None
        if network.version != 4:
            return None
        ranges.append(str(network))
    result = {'origin': 'include' if kind == 'included_ip_ranges' else 'exclude',
              'ranges': ranges, 'identity': identity}
    return {**result, 'scope': scope} if target == 'api' else result


def _other_destination(rule, target):
    """Count a recognized deny whose destination cannot affect this target."""
    if not isinstance(rule, dict) or set(rule) - {'origin', 'destination', 'authentication', 'label'}:
        return False
    destination = rule.get('destination')
    return (target == 'ui' and isinstance(destination, dict) and set(destination) == {'workspace_api'}
            or target == 'api' and destination == {'workspace_ui': {'all_destinations': True}})


def _valid_projected_rule(rule, *, api=False):
    if (not isinstance(rule, dict) or set(rule) != ({'origin', 'ranges', 'scope', 'identity'}
                                                  if api else {'origin', 'ranges', 'identity'})
            or rule['origin'] not in ('all', 'include', 'exclude')
            or rule['identity'] not in ('both', 'users', 'service_principals')
            or not isinstance(rule['ranges'], list) or len(rule['ranges']) > 1000
            or rule['origin'] == 'all' and rule['ranges']
            or rule['origin'] != 'all' and not rule['ranges']
            or api and rule['scope'] not in ('all', 'sql')):
        return False
    try:
        return all(isinstance(cidr, str) and isinstance(
            ipaddress.ip_network(cidr, strict=False), ipaddress.IPv4Network) for cidr in rule['ranges'])
    except ValueError:
        return False


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
    # The concrete transport projects before handing metadata to the reader;
    # injected transports are projected at the collector boundary as well.
    if 'ingress' not in value and set(value) == {
            'account_id', 'network_policy_id', 'restriction_mode',
            'allow_rule_count', 'deny_rule_count', 'public_ui_rules', 'public_ui_denies',
            'public_api_rules', 'public_api_denies', 'ui_ignored_deny_count', 'api_ignored_deny_count'}:
        if (value['restriction_mode'] not in ('FULL_ACCESS', 'RESTRICTED_ACCESS')
                or type(value['allow_rule_count']) is not int or not 0 <= value['allow_rule_count'] <= 1000
                or type(value['deny_rule_count']) is not int or not 0 <= value['deny_rule_count'] <= 1000
                or not isinstance(value['public_ui_rules'], list)
                or len(value['public_ui_rules']) > value['allow_rule_count']
                or not isinstance(value['public_ui_denies'], list)
                or len(value['public_ui_denies']) > value['deny_rule_count']
                or not isinstance(value['public_api_rules'], list)
                or len(value['public_api_rules']) > value['allow_rule_count']
                or not isinstance(value['public_api_denies'], list)
                or len(value['public_api_denies']) > value['deny_rule_count']
                or type(value['ui_ignored_deny_count']) is not int
                or type(value['api_ignored_deny_count']) is not int
                or not 0 <= value['ui_ignored_deny_count'] <= value['deny_rule_count']
                or not 0 <= value['api_ignored_deny_count'] <= value['deny_rule_count']
                or len(value['public_ui_denies']) + value['ui_ignored_deny_count'] > value['deny_rule_count']
                or len(value['public_api_denies']) + value['api_ignored_deny_count'] > value['deny_rule_count']
                or any(not _valid_projected_rule(rule) for rule in
                       (*value['public_ui_rules'], *value['public_ui_denies']))
                or any(not _valid_projected_rule(rule, api=True) for rule in
                       (*value['public_api_rules'], *value['public_api_denies']))
                or sum(len(rule['ranges']) for rule in (*value['public_ui_rules'], *value['public_ui_denies'],
                       *value['public_api_rules'], *value['public_api_denies'])) > 2000):
            raise ValueError('invalid projected Databricks ingress policy')
        return value
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
    ui_rules = [projected for rule in allows if (projected := _public_rule(rule, 'ui')) is not None]
    ui_denies = [projected for rule in denies if (projected := _public_rule(rule, 'ui', deny=True)) is not None]
    api_rules = [projected for rule in allows if (projected := _public_rule(rule, 'api')) is not None]
    api_denies = [projected for rule in denies if (projected := _public_rule(rule, 'api', deny=True)) is not None]
    if sum(len(rule['ranges']) for rule in (*ui_rules, *ui_denies, *api_rules, *api_denies)) > 2000:
        raise ValueError('oversized Databricks ingress ranges')
    return {'account_id': match[1], 'network_policy_id': match[2],
            'restriction_mode': public['restriction_mode'],
            'allow_rule_count': len(allows), 'deny_rule_count': len(denies),
            'public_ui_rules': ui_rules, 'public_ui_denies': ui_denies,
            'public_api_rules': api_rules, 'public_api_denies': api_denies,
            'ui_ignored_deny_count': sum(_other_destination(rule, 'ui') for rule in denies),
            'api_ignored_deny_count': sum(_other_destination(rule, 'api') for rule in denies)}


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
                        ('network_policy_id', 'restriction_mode', 'allow_rule_count', 'deny_rule_count',
                         'public_ui_rules', 'public_ui_denies', 'public_api_rules', 'public_api_denies',
                         'ui_ignored_deny_count', 'api_ignored_deny_count')},
                        _provenance={'source_operations': ['Account.WorkspaceNetworkOption.Get', 'Account.NetworkPolicy.Get'],
                                     'read_only': True, 'exact_resource_id': rid, 'account_id': account, 'workspace_id': wid})
                except Exception as exc:
                    row['policyStatus'], _ = _safe_error(exc)
                rows.append(row)
            yield rows
        jobs.append((KIND, scope, 'Databricks.Account', inventory))
    reader.run(jobs)
