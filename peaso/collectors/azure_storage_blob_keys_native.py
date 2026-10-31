"""Readonly Blob encryption metadata; no blob content or Key Vault secret/key reads."""
from datetime import datetime, timezone
import re
from urllib.parse import urlencode

KIND = 'storage_blob_key_evidence'
NATIVE_TYPES = {KIND}
CONTRACT = 'native-blob-key-binding-v1'
ARM = 'https://management.azure.com'
VERSION = '2023-05-01'
BLOB_VERSION = '2023-11-03'
ACCOUNT_KEY = '$account-encryption-key'
CID = 'azure_storage_account_defender_ensure_defender_for_keyvault_is_on_2cabbc3'
SUB = r'/subscriptions/[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}'
ACCOUNT = SUB + r'/resourceGroups/[^/?#%\\\s]+/providers/Microsoft.Storage/storageAccounts/[a-z0-9]{3,24}'
SCOPE_NAME = r'[A-Za-z0-9][A-Za-z0-9._-]{0,62}'
CONTAINER_NAME = r'(?:[a-z0-9](?:[a-z0-9-]{1,61}[a-z0-9])?|\$root|\$web|\$logs)'
KEY_URI = r'https://[A-Za-z0-9-]{3,24}\.vault\.azure\.net/keys/[A-Za-z0-9-]{1,127}/[A-Za-z0-9-]{1,127}'
MAX_BLOBS = 50000
MAX_PAGES = 1000


def required_types(wanted):
    return {'storage_account', 'storage_container', 'storage_encryption_scope'} if KIND in wanted else set()


def _object(value):
    if not isinstance(value, dict): raise ValueError('native storage object unavailable')
    return value


def _identity(row, parent, suffix, typ):
    row = _object(row)
    rid = row.get('id')
    if (not isinstance(rid, str) or re.fullmatch(re.escape(parent) + suffix, rid, re.I) is None
            or any(p in ('.', '..') for p in rid.split('/'))
            or str(row.get('type', '')).casefold() != typ.casefold()):
        raise ValueError('foreign native storage identity')
    return rid


def _inventory(reader, scope, kind):
    rows = [c for c in reader.collections if c.get('type') == kind and str(c.get('scope', '')).casefold() == scope.casefold()]
    if len(rows) != 1 or rows[0].get('status') not in ('collected', 'empty'):
        raise ValueError('complete native storage inventory unavailable')
    values = rows[0].get('items')
    if not isinstance(values, list) or (rows[0]['status'] == 'empty') != (not values):
        raise ValueError('native storage inventory inconsistent')
    seen = set()
    for row in values:
        rid = _object(row).get('id')
        if not isinstance(rid, str) or rid.casefold() in seen: raise ValueError('ambiguous storage inventory')
        seen.add(rid.casefold())
    return values


def _get(reader, request, rid, typ):
    raw = reader.call(request, ARM + rid + '?api-version=' + VERSION)
    if (str(_object(raw).get('id', '')).casefold() != rid.casefold()
            or str(raw.get('type', '')).casefold() != typ.casefold()):
        # ARM omits etag on storage account and encryption scope GETs.
        raise ValueError('native storage GET identity unavailable')
    return raw


def _key(source, props, *, account=False):
    if not isinstance(source, str): raise ValueError('native encryption key source unavailable')
    if source.casefold() == 'microsoft.storage': return {'source': 'Microsoft.Storage'}
    if source.casefold() != 'microsoft.keyvault': raise ValueError('native encryption key source unsupported')
    current = _object(props).get('currentVersionedKeyIdentifier')
    if not isinstance(current, str) or re.fullmatch(KEY_URI, current) is None:
        raise ValueError('currently used versioned Key Vault key unavailable')
    # A configured version is not evidence of the version currently in use.
    if account:
        uri, name = props.get('keyvaulturi'), props.get('keyname')
        if not isinstance(uri, str) or not isinstance(name, str) or current.rsplit('/', 1)[0] != uri.rstrip('/') + '/keys/' + name:
            raise ValueError('current account Key Vault key does not match configured identity')
        version = props.get('keyversion')
        if version not in (None, '') and (not isinstance(version, str) or current != uri.rstrip('/') + '/keys/' + name + '/' + version):
            raise ValueError('current account Key Vault version differs')
    else:
        configured = props.get('keyUri')
        if not isinstance(configured, str) or configured not in (current, current.rsplit('/', 1)[0]):
            raise ValueError('current scope Key Vault identity differs')
    return {'source': 'Microsoft.KeyVault', 'key_uri': current}


def _account_metadata(raw):
    props = _object(raw.get('properties'))
    encryption = _object(props.get('encryption'))
    blob = _object(_object(encryption.get('services')).get('blob'))
    if blob.get('enabled') is not True or blob.get('keyType') != 'Account':
        raise ValueError('native blob service account encryption binding unavailable')
    source = encryption.get('keySource')
    kv = encryption.get('keyvaultproperties')
    key = _key(source, kv, account=True)
    return key


def _scope_metadata(raw):
    props = _object(raw.get('properties'))
    if props.get('state') not in ('Enabled', 'Disabled'): raise ValueError('native scope state unavailable')
    return {'id': raw['id'], 'name': raw['id'].rsplit('/', 1)[1], 'state': props['state'],
            'key': _key(props.get('source'), props.get('keyVaultProperties'))}


def _blob_pages(reader, transport, endpoint, name, count):
    marker, seen_markers, seen, result = '', set(), set(), []
    cap = MAX_PAGES if reader.budget.max_pages is None else min(MAX_PAGES, reader.budget.max_pages)
    for _ in range(cap):
        reader.check_cancelled()
        query = {'restype': 'container', 'comp': 'list', 'maxresults': 500,
                 'include': 'snapshots,versions,deleted,deletedwithversions'}
        if marker: query['marker'] = marker
        page = reader.call(transport.request_blob_inventory, endpoint + name + '?' + urlencode(query))
        if (not isinstance(page, dict) or page.get('service_endpoint', '').rstrip('/') != endpoint.rstrip('/')
                or page.get('container_name') != name or page.get('api_version') != BLOB_VERSION
                or page.get('marker') != marker or not isinstance(page.get('next_marker'), str)
                or len(page['next_marker']) > 8192 or not isinstance(page.get('items'), list)):
            raise ValueError('native blob page binding unavailable')
        for blob in page['items']:
            blob = _object(blob)
            identity = blob.get('identity_sha256')
            if (not isinstance(identity, str) or re.fullmatch(r'[0-9a-f]{64}', identity) is None or identity in seen
                    or type(blob.get('server_encrypted')) is not bool or type(blob.get('customer_provided_key')) is not bool):
                raise ValueError('native blob identity/encryption metadata ambiguous')
            if blob['server_encrypted'] is not True or blob['customer_provided_key']:
                raise ValueError('native blob key is not resolvable from ARM')
            clean = {'identity_sha256': identity}
            if 'encryption_scope' in blob:
                name_ = blob['encryption_scope']
                if not isinstance(name_, str) or re.fullmatch(SCOPE_NAME, name_) is None:
                    raise ValueError('native blob encryption scope malformed')
                clean['encryption_scope'] = name_
            seen.add(identity); result.append(clean); count[0] += 1
            limit = MAX_BLOBS if reader.budget.max_items is None else min(MAX_BLOBS, max(0, reader.budget.max_items - reader.total))
            if count[0] > limit: raise ValueError('native blob resource budget exceeded')
        marker = page['next_marker']
        if not marker: return result
        if marker in seen_markers: raise ValueError('native blob continuation cycle')
        seen_markers.add(marker)
    raise ValueError('native blob page budget exceeded')


def _decision(payload):
    payload = _object(payload)
    account = _object(payload.get('account_key'))
    def key(value):
        value = _object(value)
        source = value.get('source')
        if source == 'Microsoft.Storage': return source
        if source != 'Microsoft.KeyVault' or not isinstance(value.get('key_uri'), str) or re.fullmatch(KEY_URI, value['key_uri']) is None:
            raise ValueError('unresolved effective key')
        return source
    key(account)
    scopes, names = {}, set()
    if not isinstance(payload.get('scopes'), list): raise ValueError('scope inventory unavailable')
    for scope in payload['scopes']:
        name = scope.get('name')
        if not isinstance(name, str) or re.fullmatch(SCOPE_NAME, name) is None or name.casefold() in names or scope.get('state') not in ('Enabled', 'Disabled'):
            raise ValueError('ambiguous encryption scope')
        names.add(name.casefold()); key(scope.get('key')); scopes[name.casefold()] = scope
    containers = payload.get('containers')
    if not isinstance(containers, list): raise ValueError('container inventory unavailable')
    bad, ids = [], set()
    for container in containers:
        cid = container.get('id')
        if not isinstance(cid, str) or cid.casefold() in ids: raise ValueError('duplicate container')
        ids.add(cid.casefold())
        default, mandatory = container.get('default_scope'), container.get('deny_override')
        if not isinstance(default, str) or type(mandatory) is not bool: raise ValueError('container defaults unresolved')
        def effective(name):
            if name == ACCOUNT_KEY: return account
            scope = scopes.get(name.casefold())
            if scope is None: raise ValueError('unknown blob/container scope')
            return scope['key']
        if default != ACCOUNT_KEY and (default.casefold() not in scopes or scopes[default.casefold()]['state'] != 'Enabled'):
            raise ValueError('default scope not enabled')
        default_source = key(effective(default))
        writes = [default_source] if mandatory else [key(account), *[key(s['key']) for s in scopes.values() if s['state'] == 'Enabled']]
        if not mandatory and default_source not in writes: raise ValueError('disabled default scope unresolved')
        blobs, seen = container.get('blobs'), set()
        if not isinstance(blobs, list): raise ValueError('historical blobs unavailable')
        measured = []
        for blob in blobs:
            identity = blob.get('identity_sha256')
            if not isinstance(identity, str) or re.fullmatch(r'[0-9a-f]{64}', identity) is None or identity in seen: raise ValueError('ambiguous historical blob')
            seen.add(identity)
            scope = blob.get('encryption_scope', ACCOUNT_KEY)
            if not isinstance(scope, str) or scope != ACCOUNT_KEY and re.fullmatch(SCOPE_NAME, scope) is None: raise ValueError('historical blob scope unresolved')
            measured.append(key(effective(scope)))
        if 'Microsoft.Storage' in measured or mandatory and default_source == 'Microsoft.Storage': bad.append(cid)
        elif 'Microsoft.Storage' in writes: raise ValueError('optional platform-managed writes remain possible')
    if not containers: return 'NOT_APPLICABLE', {'reason': 'complete native container inventory empty'}
    return ('FAIL' if bad else 'PASS'), {'containers_with_measured_platform_managed_encryption': bad,
            'semantics': 'Native complete Blob metadata and current ARM key bindings; no content or key material read'}


def collect(reader, request, transport, scopes, wanted, options):
    if KIND not in wanted: return
    count = [0]
    for scope in scopes:
        def rows(scope=scope):
            if not isinstance(scope, str) or re.fullmatch(SUB, scope, re.I) is None: raise ValueError('native storage scope invalid')
            accounts = _inventory(reader, scope, 'storage_account')
            containers = _inventory(reader, scope, 'storage_container')
            encryption_scopes = _inventory(reader, scope, 'storage_encryption_scope')
            bindings = {}
            for account in accounts:
                aid = _identity(account, scope, r'/resourceGroups/[^/?#%\\\s]+/providers/Microsoft.Storage/storageAccounts/[a-z0-9]{3,24}', 'Microsoft.Storage/storageAccounts')
                bindings[aid.casefold()] = {'account': account, 'containers': [], 'scopes': []}
            for kind, values, field, suffix, typ in (
                ('container', containers, 'containers', '/blobServices/default/containers/' + CONTAINER_NAME, 'Microsoft.Storage/storageAccounts/blobServices/containers'),
                ('scope', encryption_scopes, 'scopes', '/encryptionScopes/' + SCOPE_NAME, 'Microsoft.Storage/storageAccounts/encryptionScopes')):
                for row in values:
                    parent = row.get('parent_id')
                    if not isinstance(parent, str) or parent.casefold() not in bindings: raise ValueError('foreign encryption/container parent')
                    _identity(row, parent, suffix, typ)
                    bindings[parent.casefold()][field].append(row)
            for binding in bindings.values():
                aid = binding['account']['id']
                raw = _get(reader, request, aid, 'Microsoft.Storage/storageAccounts')
                endpoint = _object(raw.get('properties')).get('primaryEndpoints', {}).get('blob')
                name = aid.rsplit('/', 1)[1]
                if not isinstance(endpoint, str) or not re.fullmatch('https://' + re.escape(name) + r'\.blob\.core\.windows\.net/?', endpoint):
                    raise ValueError('native storage endpoint invalid')
                endpoint = endpoint.rstrip('/') + '/'
                transport.allow_storage(endpoint, name, 'blob')
                payload = {'account_key': _account_metadata(raw), 'scopes': [], 'containers': []}
                for source in binding['scopes']:
                    current = _get(reader, request, source['id'], 'Microsoft.Storage/storageAccounts/encryptionScopes')
                    payload['scopes'].append(_scope_metadata(current))
                for source in binding['containers']:
                    current = _get(reader, request, source['id'], 'Microsoft.Storage/storageAccounts/blobServices/containers')
                    props = _object(current.get('properties'))
                    payload['containers'].append({'id': current['id'], 'default_scope': props.get('defaultEncryptionScope'),
                        'deny_override': props.get('denyEncryptionScopeOverride'),
                        'blobs': _blob_pages(reader, transport, endpoint, current['id'].rsplit('/', 1)[1], count)})
                # Validate all joins now; unresolved optional writes may still
                # carry useful facts, with UNKNOWN decided by the evaluator.
                yield [{'id': aid + '/complianceEvidence/nativeBlobKeys', 'parent_id': aid, '_metadata_projection': CONTRACT,
                    'payload': payload, '_provenance': {'schema_version': 1, 'read_only': True, 'complete': True,
                        'source_operation': 'ARM_storage_encryption+Blob_List_metadata', 'api_version': VERSION,
                        'blob_api_version': BLOB_VERSION, 'captured_at': 'pending_native_snapshot_binding'}}]
        reader.run([(KIND, scope, 'Microsoft.Storage', rows)])


def snapshot_instant(collections, wanted, instant=None):
    if KIND not in wanted: return instant
    instant = instant or datetime.now(timezone.utc).isoformat()
    for env in collections:
        if env.get('type') == KIND:
            for row in env['items']: row['_provenance']['captured_at'] = instant
    return instant


def has_native(item, index):
    parent = str(item.get('id', '')).casefold()
    return any(isinstance(w.get('data'), dict) and str(w['data'].get('parent_id', '')).casefold() == parent
        and '_metadata_projection' in w['data'] for w in index.get(KIND, []) if isinstance(w, dict))


def assess(parent, context, evidence, parents):
    unknown = ('UNKNOWN', {'reason': 'native Blob inventory or effective encryption key binding unresolved'})
    try:
        matches = []
        for row in evidence.values():
            pid = row.get('parent_id')
            if not isinstance(pid, str) or pid.casefold() not in parents or row.get('id', '').casefold() != (pid + '/complianceEvidence/nativeBlobKeys').casefold(): return unknown
            if pid.casefold() == parent: matches.append(row)
        if len(matches) != 1: return unknown
        row = matches[0]; proof = _object(row.get('_provenance'))
        if (row.get('_metadata_projection') != CONTRACT or type(proof.get('schema_version')) is not int or proof['schema_version'] != 1
                or proof.get('read_only') is not True or proof.get('complete') is not True
                or proof.get('source_operation') != 'ARM_storage_encryption+Blob_List_metadata'
                or proof.get('api_version') != VERSION or proof.get('blob_api_version') != BLOB_VERSION
                or proof.get('captured_at') != context.get('created_at')): return unknown
        payload = _object(row.get('payload'))
        for encrypted_scope in payload.get('scopes', []):
            _identity({**encrypted_scope, 'type': 'Microsoft.Storage/storageAccounts/encryptionScopes'}, parents[parent]['id'],
                '/encryptionScopes/' + SCOPE_NAME, 'Microsoft.Storage/storageAccounts/encryptionScopes')
            if encrypted_scope['name'] != encrypted_scope['id'].rsplit('/', 1)[1]: return unknown
        for container in payload.get('containers', []):
            _identity({**container, 'type': 'Microsoft.Storage/storageAccounts/blobServices/containers'}, parents[parent]['id'],
                '/blobServices/default/containers/' + CONTAINER_NAME, 'Microsoft.Storage/storageAccounts/blobServices/containers')
        return _decision(payload)
    except (ValueError, TypeError, KeyError, AttributeError):
        return unknown
