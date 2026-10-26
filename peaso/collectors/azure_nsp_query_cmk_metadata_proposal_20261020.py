"""Uninstalled, bounded ARM metadata adapters; no content or key reads.

The caller supplies the existing authenticated AzureTransport and _Reader. These
functions do not discover credentials or install any shared collection hook.
"""
import json
import re
from urllib.parse import parse_qs, urlsplit

ARM = 'https://management.azure.com'
NSP_VERSION = '2026-01-01'
LINK_VERSION = '2025-07-01'
STORAGE_VERSION = '2023-05-01'
WORKSPACE_VERSION = '2023-09-01'
NSP_KIND = 'network_security_perimeter_association_declaration'
QUERY_KIND = 'workspace_query_storage_cmk_declaration'
KINDS = (NSP_KIND, QUERY_KIND)
NSP = 'Microsoft.Network/networkSecurityPerimeters'
WORKSPACE = 'Microsoft.OperationalInsights/workspaces'
STORAGE = 'Microsoft.Storage/storageAccounts'
LINK_TYPES = ('CustomLogs', 'AzureWatson', 'Query', 'Ingestion', 'Alerts')
GUID = r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}'
SEGMENT = r'[A-Za-z0-9][A-Za-z0-9_.()-]{0,89}'
SCHEMA = 'azure-nsp-query-cmk-metadata-v1'
MAX_BYTES = 262144
MAX_ROWS = 64
MAX_PAGES = 8


def _unique_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError('duplicate native JSON field')
        value[key] = item
    return value


def _reject_constant(value):
    raise ValueError('nonfinite native JSON')


def metadata_get(transport, url):
    """Strict metadata GET through the existing AzureTransport read path.

    The transport returns the exact 200 response bytes (no redirects) and
    shares them with identical reads in this scan. This adapter keeps its own
    response budget and rejects duplicate or nonfinite JSON fields.
    """
    from . import azure
    parsed = urlsplit(url)
    if (parsed.scheme != 'https' or parsed.netloc != 'management.azure.com'
            or parsed.username or parsed.password or parsed.fragment):
        raise ValueError('untrusted ARM metadata origin')
    try:
        raw = transport.raw_get(url, audience=azure.ARM)
    except azure.AzureReadError as exc:
        if exc.code == 'incomplete_native_response':
            raise ValueError('native metadata HTTP response incomplete') from None
        raise
    if len(raw) > MAX_BYTES:
        raise ValueError('native metadata response budget exceeded')
    return json.loads(raw, object_pairs_hook=_unique_object, parse_constant=_reject_constant)


def scope_id(value):
    if not isinstance(value, str) or not re.fullmatch('/subscriptions/' + GUID, value, re.I):
        raise ValueError('invalid selected subscription')
    return value


def resource_id(value, scope, typ):
    scope_id(scope)
    if (not isinstance(value, str) or len(value) > 1024 or not re.fullmatch(
            re.escape(scope) + '/resourceGroups/' + SEGMENT + '/providers/' +
            re.escape(typ) + '/' + SEGMENT, value, re.I)):
        raise ValueError('native resource identity mismatch')
    name = value.rsplit('/', 1)[-1]
    if typ == NSP and (len(name) > 80 or not re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9_.-]*[A-Za-z0-9_])?', name)):
        raise ValueError('native perimeter name mismatch')
    if typ == STORAGE and not re.fullmatch('[a-z0-9]{3,24}', name, re.I):
        raise ValueError('native storage name mismatch')
    if typ == WORKSPACE and not re.fullmatch('[A-Za-z0-9][A-Za-z0-9-]{2,61}[A-Za-z0-9]', name):
        raise ValueError('native workspace name mismatch')
    return value


def identity(raw, rid, typ):
    if (not isinstance(raw, dict) or not isinstance(raw.get('id'), str)
            or raw['id'].casefold() != rid.casefold()
            or not isinstance(raw.get('type'), str) or raw['type'].casefold() != typ.casefold()
            or not isinstance(raw.get('name'), str)
            or raw['name'].casefold() != rid.rsplit('/', 1)[-1].casefold()
            or not isinstance(raw.get('properties'), dict)):
        raise ValueError('native representation mismatch')
    return raw['properties']


def child_id(value, parent, collection):
    if (not isinstance(value, str) or not re.fullmatch(
            re.escape(parent) + '/' + re.escape(collection) + '/' + SEGMENT, value, re.I)):
        raise ValueError('native child belongs to another parent')
    if collection in ('profiles', 'resourceAssociations'):
        name = value.rsplit('/', 1)[-1]
        if len(name) > 80 or not re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9_.-]*[A-Za-z0-9_])?', name):
            raise ValueError('native perimeter child name mismatch')
    return value


class Capture:
    """Fixed ARM origin and explicit bounded source receipts from completed reads."""
    def __init__(self, reader, transport, scope):
        self.reader, self.transport, self.scope = reader, transport, scope_id(scope)
        context = getattr(transport, 'ai_context_id', None)
        if not isinstance(context, str) or not re.fullmatch('[0-9a-f]{32}', context):
            raise ValueError('authenticated transport capture identity unavailable')
        self.context = context
        self.cache = {}

    def request(self, path, version, operation, continuation=None):
        url = ARM + path + '?api-version=' + version if continuation is None else continuation
        parsed = urlsplit(url)
        query = parse_qs(parsed.query, keep_blank_values=True)
        if (parsed.scheme != 'https' or parsed.netloc != 'management.azure.com'
                or parsed.path != path or parsed.username or parsed.password or parsed.fragment
                or query.get('api-version') != [version]
                or any(k not in ('api-version', '$skipToken', '$skiptoken') for k in query)
                or any(len(v) != 1 or len(v[0]) > 4096 for v in query.values())):
            raise ValueError('untrusted metadata continuation')
        value = self.reader.call(metadata_get, self.transport, url)
        if not isinstance(value, dict) or 'error' in value:
            raise ValueError('native metadata response unavailable')
        proof = {'operation': operation, 'method': 'GET', 'path': path,
                 'api_version': version, 'credential_context_id': self.context,
                 'scope': self.scope}
        return value, proof

    def listing(self, path, version, operation):
        rows, seen, receipts, continuation = [], set(), [], None
        for _ in range(MAX_PAGES):
            try:
                raw, proof = self.request(path, version, operation, continuation)
            except Exception as exc:
                if receipts:
                    from .azure import AzureReadError
                    raise AzureReadError('native_list_incomplete') from exc
                raise
            page = raw.get('value')
            if not isinstance(page, list) or any(not isinstance(row, dict) for row in page):
                raise ValueError('native metadata list malformed')
            rows.extend(page)
            receipts.append(proof)
            if len(rows) > MAX_ROWS:
                raise ValueError('native metadata row budget exceeded')
            continuation = raw.get('nextLink')
            if continuation is None or continuation == '':
                return rows, receipts
            if not isinstance(continuation, str) or continuation in seen:
                raise ValueError('native metadata continuation malformed')
            seen.add(continuation)
        raise ValueError('native metadata page budget exceeded')

    def full(self, rid, typ, version, operation):
        key = (rid.casefold(), version)
        if key not in self.cache:
            raw, proof = self.request(rid, version, operation)
            props = identity(raw, rid, typ)
            self.cache[key] = (props, proof)
        return self.cache[key]

    def marker(self, receipts):
        return {'schema': SCHEMA, 'scope': self.scope, 'credential_context_id': self.context,
                'reads': receipts}


def _parents(capture, typ, version, operation):
    rows, receipts = capture.listing(capture.scope + '/providers/' + typ, version, operation)
    seen = set()
    for raw in rows:
        rid = resource_id(raw.get('id'), capture.scope, typ)
        identity(raw, rid, typ)
        if rid.casefold() in seen:
            raise ValueError('duplicate native parent identity')
        seen.add(rid.casefold())
    return rows, receipts


def nsp_items(capture):
    parents, inventory = _parents(capture, NSP, NSP_VERSION, 'NetworkSecurityPerimeters_ListBySubscription')
    seen, protected_seen = set(), set()
    for parent in parents:
        nsp = parent['id']
        # Parent provisioning is a deployment declaration, not applied routing.
        if parent['properties'].get('provisioningState') != 'Succeeded':
            raise ValueError('native perimeter provisioning unresolved')
        rows, listed = capture.listing(nsp + '/resourceAssociations', NSP_VERSION, 'NetworkSecurityPerimeterAssociations_List')
        for raw in rows:
            rid = child_id(raw.get('id'), nsp, 'resourceAssociations')
            identity(raw, rid, NSP + '/resourceAssociations')
            if rid.casefold() in seen:
                raise ValueError('duplicate native association identity')
            seen.add(rid.casefold())
            # Full GET prevents accepting a list/detail identity disagreement.
            props, full = capture.full(rid, NSP + '/resourceAssociations', NSP_VERSION, 'NetworkSecurityPerimeterAssociations_Get')
            if raw['properties'] != props:
                raise ValueError('native association changed during capture')
            profile = child_id(props.get('profile', {}).get('id') if isinstance(props.get('profile'), dict) else None, nsp, 'profiles')
            protected = props.get('privateLinkResource', {}).get('id') if isinstance(props.get('privateLinkResource'), dict) else None
            # Initial native capability boundary: Storage only. Other resource
            # families require separately reviewed full GET/capability adapters.
            protected = resource_id(protected, capture.scope, STORAGE)
            if protected.casefold() in protected_seen:
                raise ValueError('ambiguous protected resource associations')
            protected_seen.add(protected.casefold())
            _, profile_read = capture.full(profile, NSP + '/profiles', NSP_VERSION, 'NetworkSecurityPerimeterProfiles_Get')
            storage, protected_read = capture.full(protected, STORAGE, STORAGE_VERSION, 'StorageAccounts_GetProperties')
            mode = props.get('accessMode')
            yield {'id': rid, 'type': NSP + '/resourceAssociations', 'nsp_id': nsp,
                   'profile_id': profile, 'protected_resource_id': protected,
                   'access_mode': mode if mode in ('Learning', 'Audit', 'Enforced') else None,
                   'provisioned': props.get('provisioningState') == 'Succeeded',
                   'provisioning_issues_absent': props.get('hasProvisioningIssues') == 'no',
                   'protected_provisioned': storage.get('provisioningState') == 'Succeeded',
                   '_capture': capture.marker(inventory + listed + [full, profile_read, protected_read])}


def cmk_reference(encryption):
    """Validate declared key reference; never retain URI/name/version or read key."""
    props = encryption.get('keyvaultproperties')
    if not isinstance(props, dict):
        return False
    uri, name, version = (props.get(key) for key in ('keyvaulturi', 'keyname', 'keyversion'))
    if not isinstance(uri, str) or len(uri) > 256 or not isinstance(name, str) or not re.fullmatch('[A-Za-z0-9-]{1,127}', name):
        return False
    parsed = urlsplit(uri)
    if (parsed.scheme != 'https' or not re.fullmatch(r'[a-zA-Z0-9-]{3,24}\.(?:vault|managedhsm)\.azure\.net', parsed.netloc)
            or parsed.path not in ('', '/') or parsed.query or parsed.fragment):
        return False
    # Omitted/empty version is a native versionless (automatic update) reference.
    return 'keyversion' not in props or version == '' or isinstance(version, str) and bool(re.fullmatch('[0-9a-fA-F]{32}', version))


def query_items(capture):
    parents, inventory = _parents(capture, WORKSPACE, WORKSPACE_VERSION, 'Workspaces_ListBySubscription')
    for parent in parents:
        rid = parent['id']
        workspace, detail = capture.full(rid, WORKSPACE, WORKSPACE_VERSION, 'Workspaces_Get')
        if workspace.get('provisioningState') != 'Succeeded':
            raise ValueError('native workspace provisioning unresolved')
        rows, listed = capture.listing(rid + '/linkedStorageAccounts', LINK_VERSION, 'LinkedStorageAccounts_ListByWorkspace')
        queries, seen = [], set()
        for raw in rows:
            link = child_id(raw.get('id'), rid, 'linkedStorageAccounts')
            props = identity(raw, link, WORKSPACE + '/linkedStorageAccounts')
            source = props.get('dataSourceType')
            if source not in LINK_TYPES or link.rsplit('/', 1)[-1] != source or link.casefold() in seen:
                raise ValueError('native linked storage source or identity unresolved')
            seen.add(link.casefold())
            ids = props.get('storageAccountIds')
            if not isinstance(ids, list) or len(ids) > MAX_ROWS:
                raise ValueError('native linked account list malformed')
            owned = [resource_id(account, capture.scope, STORAGE) for account in ids]
            if len({account.casefold() for account in owned}) != len(owned):
                raise ValueError('duplicate linked storage account')
            if source == 'Query':
                queries.append((link, owned))
        accounts, reads = [], inventory + [detail] + listed
        if len(queries) > 1:
            raise ValueError('duplicate Query link')
        for _, ids in queries:
            for account in ids:
                props, receipt = capture.full(account, STORAGE, STORAGE_VERSION, 'StorageAccounts_GetProperties')
                reads.append(receipt)
                encryption = props.get('encryption')
                if not isinstance(encryption, dict):
                    key, valid, table_key = None, False, None
                else:
                    key = encryption.get('keySource')
                    key = key.casefold() if isinstance(key, str) else None
                    key = key if key in ('microsoft.storage', 'microsoft.keyvault') else None
                    valid = cmk_reference(encryption) if key == 'microsoft.keyvault' else False
                    services = encryption.get('services')
                    table = services.get('table') if isinstance(services, dict) else None
                    table_key = table.get('keyType') if isinstance(table, dict) else None
                    if (table_key not in ('Account', 'Service') or
                            isinstance(table, dict) and 'enabled' in table and table['enabled'] is not True):
                        table_key = None
                accounts.append({'id': account, 'key_source': key, 'cmk_reference_valid': valid,
                                 'table_key_type': table_key,
                                 'provisioned': props.get('provisioningState') == 'Succeeded'})
        yield {'id': rid, 'type': WORKSPACE, 'query_link_id': queries[0][0] if queries else None,
               'accounts': accounts, '_capture': capture.marker(reads)}


def collect(connector, requirements=None, *, transport=None):
    """Proposed local bridge only; no import-time or shared runtime installation."""
    from .azure import AzureTransport, _Reader
    from peaso.snapshot import make_snapshot
    wanted = tuple(requirements if requirements is not None else KINDS)
    if any(kind not in KINDS for kind in wanted) or len(set(wanted)) != len(wanted):
        raise ValueError('unsupported metadata proposal kind')
    if connector.get('provider') != 'azure':
        raise ValueError('Azure metadata connector required')
    scopes = connector.get('scopes')
    if not isinstance(scopes, list) or not 1 <= len(scopes) <= 8:
        raise ValueError('one to eight selected subscription scopes required')
    scopes = [scope_id('/subscriptions/' + value if isinstance(value, str) and not value.startswith('/') else value) for value in scopes]
    if len({scope.casefold() for scope in scopes}) != len(scopes):
        raise ValueError('duplicate selected subscription scope')
    options = connector.get('options', {})
    limits = {'max_calls': 128, 'max_pages': MAX_PAGES, 'max_resources': 128,
              'collection_deadline_seconds': 120, 'concurrency': 1, 'retries': 0}
    for key, maximum in tuple(limits.items()):
        if key in options:
            value = options[key]
            if type(value) is not int or not 1 <= value <= maximum:
                raise ValueError('metadata proposal budget invalid')
            limits[key] = value
    # Existing transport is reused; never obtain a second credential/context.
    if transport is None or not isinstance(transport, AzureTransport):
        raise ValueError('existing authenticated AzureTransport required')
    reader = _Reader(limits)
    jobs = []
    for scope in scopes:
        capture = Capture(reader, transport, scope)
        for kind in wanted:
            def fetch(kind=kind, capture=capture):
                for item in (nsp_items(capture) if kind == NSP_KIND else query_items(capture)):
                    yield [item]
            jobs.append((kind, scope, 'Microsoft.Network' if kind == NSP_KIND else 'Microsoft.OperationalInsights', fetch))
    reader.run(jobs)
    return make_snapshot('azure', scopes, reader.collections, metadata={
        **reader.metadata(), 'credential_context_id': transport.ai_context_id,
        'proposal_schema': SCHEMA, 'integration': 'unregistered-local-bridge'})
