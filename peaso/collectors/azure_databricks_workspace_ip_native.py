"""Bounded read-only workspace IP policy reads using pre-existing Databricks PATs."""
import ipaddress
import json
import re
from urllib.error import HTTPError
from urllib.parse import urlsplit
from urllib.request import Request, build_opener, ProxyHandler

from .azure_databricks_native import _NoRedirect, _unique_object

FIELD = 'databricks_workspace_token_secret'
MAX_WORKSPACES = 32
MAX_RESPONSE_BYTES = 2_000_000
_UUID = r'[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}'
_RID = re.compile(r'/subscriptions/' + _UUID + r'/resourceGroups/[A-Za-z0-9_.()-]+/providers/Microsoft\.Databricks/workspaces/[A-Za-z0-9_.()-]+', re.I)
_PAT = re.compile(r'(?:dapi)?[A-Za-z0-9]{32}')
_HOST = re.compile(r'adb-([1-9][0-9]{0,18})\.[0-9]+\.azuredatabricks\.net')


def validate_auth(auth):
    if FIELD not in auth:
        return
    values = auth[FIELD]
    if not isinstance(values, dict) or not 1 <= len(values) <= MAX_WORKSPACES:
        raise ValueError('invalid Databricks workspace PAT mapping')
    seen = set()
    for rid, token in values.items():
        if (not isinstance(rid, str) or len(rid) > 1024 or not _RID.fullmatch(rid)
                or any(part in ('.', '..') for part in rid.split('/')) or rid.casefold() in seen
                or not isinstance(token, str) or not _PAT.fullmatch(token)):
            raise ValueError('invalid Databricks workspace PAT mapping')
        seen.add(rid.casefold())


def endpoint(host, workspace_id, path):
    if (not isinstance(host, str) or not isinstance(workspace_id, str)
            or not re.fullmatch(r'[1-9][0-9]{0,18}', workspace_id)
            or not isinstance(path, str) or path not in
            ('/api/2.0/workspace-conf?keys=enableIpAccessLists', '/api/2.0/ip-access-lists')):
        raise ValueError('invalid Databricks workspace policy endpoint')
    parsed = urlsplit(host)
    hostname = host if '://' not in host else parsed.hostname
    if (not isinstance(hostname, str) or (host != hostname and host != 'https://' + hostname)
            or not (match := _HOST.fullmatch(hostname)) or match[1] != workspace_id):
        raise ValueError('foreign Databricks workspace host')
    return 'https://' + hostname + path


def project(value, path):
    if path == '/api/2.0/workspace-conf?keys=enableIpAccessLists':
        if not isinstance(value, dict) or value.get('enableIpAccessLists') not in ('true', 'false'):
            raise ValueError('invalid Databricks IP access setting')
        return {'enableIpAccessLists': value['enableIpAccessLists']}
    if (not isinstance(value, dict) or 'next_page_token' in value
            or not isinstance(value.get('ip_access_lists'), list) or len(value['ip_access_lists']) > 1000):
        raise ValueError('invalid Databricks IP access lists')
    rows = []
    seen = set()
    total_addresses = 0
    for item in value['ip_access_lists']:
        if not isinstance(item, dict) or type(item.get('enabled')) is not bool or item.get('list_type') not in ('ALLOW', 'BLOCK'):
            raise ValueError('invalid Databricks IP access list')
        list_id = item.get('list_id')
        addresses = item.get('ip_addresses')
        if (not isinstance(list_id, str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,128}', list_id)
                or list_id in seen or not isinstance(addresses, list) or len(addresses) > 1000
                or type(item.get('address_count')) is not int or item['address_count'] != len(addresses)):
            raise ValueError('invalid Databricks IP access list')
        seen.add(list_id)
        total_addresses += len(addresses)
        if total_addresses > 1000:
            raise ValueError('oversized Databricks IP access lists')
        normalized = []
        for address in addresses:
            if not isinstance(address, str):
                raise ValueError('invalid Databricks IP range')
            try:
                network = ipaddress.ip_network(address, strict=False)
            except ValueError:
                raise ValueError('invalid Databricks IP range') from None
            if network.version != 4:
                raise ValueError('invalid Databricks IP range')
            normalized.append(str(network))
        rows.append({'list_id': list_id, 'list_type': item['list_type'], 'enabled': item['enabled'], 'ip_addresses': normalized})
    return {'ip_access_lists': rows}


def request_policy(host, workspace_id, path, token):
    """Use only the caller-supplied PAT; no AAD exchange, redirects or proxy."""
    from .azure import AzureReadError
    url = endpoint(host, workspace_id, path)
    if not isinstance(token, str) or not _PAT.fullmatch(token):
        raise ValueError('invalid Databricks workspace PAT')
    req = Request(url, headers={'Authorization': 'Bearer ' + token, 'Accept': 'application/json'}, method='GET')
    try:
        with build_opener(ProxyHandler({}), _NoRedirect()).open(req, timeout=20) as response:
            body = response.read(MAX_RESPONSE_BYTES + 1)
        if len(body) > MAX_RESPONSE_BYTES:
            raise AzureReadError('databricks_workspace_policy_response_limit')
        return project(json.loads(body, object_pairs_hook=_unique_object), path)
    except HTTPError as exc:
        status = exc.code
        exc.close()
        raise AzureReadError('databricks_workspace_policy_http_error', status) from None


def collect(reader, transport, scopes, wanted, auth):
    if 'databricks_workspace' not in wanted:
        return
    from .azure import AzureReadError, _safe_error
    tokens = {rid.casefold(): token for rid, token in auth.get(FIELD, {}).items()}
    parents = {row['scope'].casefold(): row for row in reader.collections
               if row['type'] == 'databricks_workspace'}
    jobs = []
    for scope in scopes:
        def inventory(scope=scope):
            parent = parents.get(scope.casefold())
            if parent is None or parent['status'] not in ('collected', 'empty'):
                raise AzureReadError('databricks_arm_inventory_incomplete')
            rows = []
            for item in parent['items']:
                rid = item['id']
                fields = item.get('properties', {})
                wid = fields.get('workspaceId') if isinstance(fields, dict) else None
                host = fields.get('workspaceUrl') if isinstance(fields, dict) else None
                token = tokens.get(rid.casefold())
                row = {'id': rid, 'policyStatus': 'missing_credential' if token is None else 'unavailable'}
                if token is not None:
                    try:
                        # Validate the ARM host/ID binding before any request.
                        endpoint(host, wid, '/api/2.0/ip-access-lists')
                        setting = reader.call(transport.request_databricks_workspace_ip, host, wid,
                                              '/api/2.0/workspace-conf?keys=enableIpAccessLists', token)
                        setting = project(setting, '/api/2.0/workspace-conf?keys=enableIpAccessLists')
                        if setting['enableIpAccessLists'] == 'true':
                            lists = reader.call(transport.request_databricks_workspace_ip, host, wid,
                                                '/api/2.0/ip-access-lists', token)
                            lists = project(lists, '/api/2.0/ip-access-lists')
                        else:
                            lists = {'ip_access_lists': []}
                        row.update(policyStatus='collected', ipAccessListsEnabled=setting['enableIpAccessLists'] == 'true',
                                   ipAccessLists=lists['ip_access_lists'],
                                   _provenance={'source_operations': ['Workspace.WorkspaceConf.GetStatus'] +
                                       (['Workspace.IpAccessLists.List'] if setting['enableIpAccessLists'] == 'true' else []),
                                                'read_only': True, 'exact_resource_id': rid})
                    except Exception as exc:
                        status, _ = _safe_error(exc)
                        row['policyStatus'] = status
                rows.append(row)
            yield rows
        jobs.append(('databricks_workspace_ip_policy', scope, 'Databricks.Workspace', inventory))
    reader.run(jobs)
