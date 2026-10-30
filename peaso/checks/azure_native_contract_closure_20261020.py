"""Unregistered configuration-only successors; registration is an atomic root task.

These predicates never infer key access, encryption of actual data or universal
Defender analysis. No registration, CASES mutation or framework edge occurs here.
"""
from functools import wraps
import re
from urllib.parse import urlsplit
from uuid import UUID

from . import result, unknown
from .facts import Unavailable, complete_items, get, list_of_objects

CLUSTER = 'azure.encryption.log_analytics_cluster_cmk_declared'
STREAM = 'azure.encryption.stream_analytics_job_storage_cmk_declared'
NATIVE = {
    'log_analytics_cluster': ('Microsoft.OperationalInsights/clusters', '2023-09-01'),
    'stream_analytics_job': ('Microsoft.StreamAnalytics/streamingjobs', '2020-03-01'),
    'storage_account': ('Microsoft.Storage/storageAccounts', '2023-05-01'),
}
# The collector's storage-account full GET moved to 2026-06-01; both reviewed
# read-only GET versions return the same declared properties used here.
ACCEPTED_VERSIONS = {'storage_account': ('2023-05-01', '2026-06-01')}


def _safe(fn):
    @wraps(fn)
    def evaluate(item, index):
        try:
            return fn(item, index)
        except Unavailable as exc:
            return unknown(str(exc))
    return evaluate


def _guid(value):
    if not isinstance(value, str):
        raise Unavailable('native identity GUID is unavailable')
    try:
        identifier = UUID(value)
    except ValueError as exc:
        raise Unavailable('native identity GUID is malformed') from exc
    if not identifier.int or str(identifier) != value.casefold():
        raise Unavailable('native identity GUID is not canonical')
    return value.casefold()


def _arm_id(value, scope, resource_type):
    segment = r'[^/?#%\\\s]+'
    if (not isinstance(value, str) or re.fullmatch(re.escape(scope) + '/resourceGroups/' + segment
            + '/providers/' + re.escape(resource_type) + '/' + segment, value, re.I) is None
            or any(part in ('.', '..') for part in value.split('/'))):
        raise Unavailable('resource identity does not belong to the selected native scope and kind')
    return value.casefold()


def _context(index):
    ctx = get(index, 'context', dict)
    if get(ctx, 'provider', str) != 'azure':
        raise Unavailable('Azure context is unavailable')
    scope = get(ctx, 'scope', str)
    match = re.fullmatch(r'/subscriptions/([^/]+)', scope, re.I)
    if match is None:
        raise Unavailable('one selected subscription is required')
    _guid(match[1])
    meta = get(ctx, 'metadata', dict)
    tenant = _guid(get(meta, 'tenant_id', str))
    credential = get(meta, 'credential_context_id', str)
    if (get(meta, 'tenant_verified', bool) is not True
            or re.fullmatch(r'[0-9a-f]{32}', credential) is None
            or get(meta, 'customer_context_id', str) != 'scan-local:' + credential):
        raise Unavailable('authenticated native capture binding is unavailable')
    return scope, tenant, meta


def _inventory(index, kind):
    scope, tenant, meta = _context(index)
    native_type, version = NATIVE[kind]
    envelopes = get(index, 'collections', dict).get(kind)
    if not isinstance(envelopes, list) or len(envelopes) != 1:
        raise Unavailable('native inventory is missing or ambiguous: ' + kind)
    env = envelopes[0]
    if (get(env, 'type', str) != kind or get(env, 'service', str).casefold() != native_type.split('/')[0].casefold()
            or get(env, 'scope', str).casefold() != scope.casefold()
            or get(env, 'status', str) not in ('collected', 'empty')):
        raise Unavailable('native inventory is incomplete or foreign: ' + kind)
    def bound(row):
        proof = get(row, '_provenance', dict)
        if any(get(proof, field, str) != get(meta, field, str)
               for field in ('credential_context_id', 'customer_context_id')):
            raise Unavailable('native inventory capture differs from the selected context')
        return proof
    bound(env)
    native_rows = list_of_objects(get(env, 'items', list))
    rows = complete_items(index, kind)
    if ((env['status'] == 'empty') != (not native_rows)
            or sorted(rows, key=lambda r: r.get('id', '')) != sorted(native_rows, key=lambda r: r.get('id', ''))):
        raise Unavailable('native inventory and public projection disagree')
    seen = set()
    for row in rows:
        rid = _arm_id(get(row, 'id', str), scope, native_type)
        if (rid in seen or get(row, 'type', str).casefold() != native_type.casefold()
                or get(row, 'name', str).casefold() != rid.rsplit('/', 1)[-1]):
            raise Unavailable('native inventory has conflicting identity or type')
        seen.add(rid)
        proof = bound(row)
        if (get(proof, 'source_operation', str) != 'get' or get(proof, 'read_only', bool) is not True
                or get(proof, 'api_version', str) not in ACCEPTED_VERSIONS.get(kind, (version,))):
            raise Unavailable('authoritative native GET metadata is unavailable')
        representation = get(proof, 'representation', str)
        if kind in ('storage_account', 'log_analytics_cluster'):
            if representation != 'full':
                raise Unavailable('native metadata GET representation is incomplete')
        if kind == 'log_analytics_cluster' and get(proof, 'request_path', str).casefold() != rid:
            raise Unavailable('native cluster GET belongs to another resource')
        if kind == 'stream_analytics_job' and (representation != 'metadata' or get(proof, 'source_representation', str) != 'full'
                or get(proof, 'request_path', str).casefold() != rid):
            raise Unavailable('native service metadata projection is not bound to its full GET')
    return rows, tenant


def _owned(item, index, kind):
    rows, tenant = _inventory(index, kind)
    matches = [row for row in rows if get(row, 'id', str).casefold() == get(item, 'id', str).casefold()]
    if len(matches) != 1 or matches[0] != item:
        raise Unavailable('evaluated resource does not match the native capture')
    if get(item, 'properties.provisioningState', str) != 'Succeeded':
        raise Unavailable('resource configuration provisioning is not succeeded')
    return tenant


def _key_reference(key, *, storage=False):
    if not isinstance(key, dict):
        raise Unavailable('CMK reference is malformed')
    uri_field, name_field, version_field = ('keyvaulturi', 'keyname', 'keyversion') if storage else ('keyVaultUri', 'keyName', 'keyVersion')
    uri, name = get(key, uri_field, str), get(key, name_field, str)
    try:
        parsed = urlsplit(uri)
        valid = (parsed.scheme == 'https' and parsed.netloc.casefold() == (parsed.hostname or '').casefold() and not parsed.username
                 and not parsed.password and parsed.port is None and parsed.path in ('', '/')
                 and not parsed.query and not parsed.fragment and '--' not in (parsed.hostname or '')
                 and re.fullmatch(r'[a-z0-9][a-z0-9-]{1,22}[a-z0-9]\.(?:vault|managedhsm)\.azure\.net', parsed.hostname or '') is not None)
    except ValueError:
        valid = False
    if not valid or re.fullmatch(r'[A-Za-z0-9-]{1,127}', name) is None:
        raise Unavailable('CMK reference is not a supported native vault/key identifier')
    version = key.get(version_field, '')
    if not isinstance(version, str) or version and re.fullmatch(r'[A-Za-z0-9]{32}', version) is None:
        raise Unavailable('CMK key version is malformed')
    return 'https://' + parsed.hostname + '/keys/' + name + ('/' + version if version else ''), 'versioned' if version else 'latest'


def _assigned(identity, tenant):
    if not isinstance(identity, dict):
        raise Unavailable('managed identity declaration is malformed')
    raw = get(identity, 'type', str)
    parts = raw.split(',')
    modes = {part.strip() for part in parts}
    if (len(parts) != len(modes) or not modes <= {'None', 'SystemAssigned', 'UserAssigned'}
            or 'None' in modes and modes != {'None'}):
        raise Unavailable('managed identity type is unrecognized or contradictory')
    users = identity.get('userAssignedIdentities', {})
    if not isinstance(users, dict):
        raise Unavailable('assigned user identities are malformed')
    selected = {}
    for rid, row in users.items():
        match = re.fullmatch(r'/subscriptions/([^/]+)/resourceGroups/[^/?#%\\\s]+/providers/Microsoft\.ManagedIdentity/userAssignedIdentities/[^/?#%\\\s]+', rid, re.I) if isinstance(rid, str) else None
        if match is None or any(p in ('.', '..') for p in rid.split('/')):
            raise Unavailable('assigned user identity ARM reference is malformed')
        _guid(match[1])
        principal = _guid(get(row, 'principalId', str))
        if 'clientId' in row:
            _guid(get(row, 'clientId', str))
        if rid.casefold() in selected:
            raise Unavailable('assigned user identity reference is ambiguous')
        selected[rid.casefold()] = principal
    if 'UserAssigned' not in modes and selected or 'UserAssigned' in modes and not selected:
        raise Unavailable('assigned identity type and native references disagree')
    system = None
    if 'SystemAssigned' in modes:
        system = _guid(get(identity, 'principalId', str))
        if _guid(get(identity, 'tenantId', str)) != tenant:
            raise Unavailable('system identity belongs to another tenant')
    return modes, system, selected


@_safe
def log_cluster_cmk_declared(item, index):
    """Assess the cluster's declared CMK reference and unambiguous assigned identity."""
    tenant = _owned(item, index, 'log_analytics_cluster')
    props = get(item, 'properties', dict)
    key = props.get('keyVaultProperties')
    if key is None or key == {}:
        return result(True, reason='The native cluster GET declares no CMK reference.')
    reference, version_mode = _key_reference(key)
    identity = item.get('identity')
    if identity is None:
        return result(True, reason='The cluster declares no managed identity for its CMK configuration.')
    modes, system, users = _assigned(identity, tenant)
    if modes == {'None'}:
        return result(True, reason='The cluster managed identity is disabled.')
    if modes == {'SystemAssigned'}:
        principal, identity_ref = system, item['id']
    elif modes == {'UserAssigned'} and len(users) == 1:
        identity_ref, principal = next(iter(users.items()))
    else:
        raise Unavailable('the native cluster declaration does not select one encryption identity')
    return result(False, reason='The cluster declares a coherent CMK reference and assigned managed identity.',
        key_reference=reference, key_version_mode=version_mode, identity_reference=identity_ref, principal_id=principal,
        semantics='Configuration only; key access, availability and encryption of actual data are not assessed.')


@_safe
def stream_job_storage_cmk_declared(item, index):
    """Join actual external job-storage configuration to selected native storage encryption."""
    _owned(item, index, 'stream_analytics_job')
    props = get(item, 'properties', dict)
    policy = get(props, 'contentStoragePolicy', str)
    if policy == 'SystemAccount':
        return 'NOT_APPLICABLE', {'reason': 'The job selects built-in service storage; this check assesses external job storage only.'}
    if policy != 'JobStorageAccount':
        raise Unavailable('native content storage policy is unrecognized')
    if get(props, 'jobType', str) != 'Cloud':
        raise Unavailable('this native job-storage contract supports Cloud jobs only')
    storage = get(props, 'jobStorageAccount', dict)
    mode = storage.get('authenticationMode', 'ConnectionString')
    if mode not in ('ConnectionString', 'Msi', 'UserToken'):
        raise Unavailable('native job-storage authentication mode is unrecognized')
    name = get(storage, 'accountName', str)
    if re.fullmatch(r'[a-z0-9]{3,24}', name) is None:
        raise Unavailable('native job storage account name is malformed')
    accounts, tenant = _inventory(index, 'storage_account')
    matches = [row for row in accounts if get(row, 'name', str) == name]
    if len(matches) != 1:
        raise Unavailable('job storage is absent, outside the selected subscription or ambiguous')
    account = matches[0]
    if get(account, 'properties.provisioningState', str) != 'Succeeded':
        raise Unavailable('job storage account configuration is not provisioned')
    encryption = get(account, 'properties.encryption', dict)
    # The exact2023-05-01 REST schema declares this default and case-insensitive enum.
    source = encryption.get('keySource', 'Microsoft.Storage')
    if not isinstance(source, str):
        raise Unavailable('storage encryption key source is malformed')
    if source.casefold() == 'microsoft.storage':
        return result(True, reason='The selected external job storage account declares Microsoft-managed encryption.',
                      storage_account_id=account['id'])
    if source.casefold() != 'microsoft.keyvault':
        raise Unavailable('storage encryption key source is unrecognized')
    reference, version_mode = _key_reference(get(encryption, 'keyvaultproperties', dict), storage=True)
    modes, system, users = _assigned(get(account, 'identity', dict), tenant)
    selected = encryption.get('identity', {})
    if selected is None:
        selected = {}
    if not isinstance(selected, dict) or any(k != 'userAssignedIdentity' for k in selected):
        raise Unavailable('storage encryption identity selector is unsupported')
    user_ref = selected.get('userAssignedIdentity')
    if user_ref is not None:
        if not isinstance(user_ref, str) or user_ref.casefold() not in users:
            raise Unavailable('storage encryption selects an unassigned user identity')
        principal = users[user_ref.casefold()]
        identity_ref = user_ref
    elif 'SystemAssigned' in modes:
        principal, identity_ref = system, account['id']
    else:
        raise Unavailable('storage encryption identity selection is unresolved')
    return result(False, reason='The external job storage resolves uniquely to a native CMK declaration and assigned encryption identity.',
        storage_account_id=account['id'], key_reference=reference, key_version_mode=version_mode,
        identity_reference=identity_ref, principal_id=principal,
        semantics='Job-storage configuration only; built-in storage, effective key access and encryption of actual job data are not assessed.')


# Declarative proposals only. Root supplies canonical registration and thematic
# metadata after review; these records create no numbered framework mappings.
PROPOSALS = (
    {'id': CLUSTER, 'provider': 'azure', 'category': 'encryption', 'kind': 'log_analytics_cluster',
     'title': 'Log Analytics cluster declares a customer-managed key and managed identity',
     'severity': 'medium', 'dependencies': ('log_analytics_cluster',), 'evaluate': log_cluster_cmk_declared,
     'description': 'Checks the native cluster CMK reference and assigned managed identity. It does not verify key access, availability or encryption of stored data.',
     'remediation': ('Configure a supported Key Vault or Managed HSM key reference on the cluster.',
                     'Assign the intended system identity or one user identity; review its key permissions separately.')},
    {'id': STREAM, 'provider': 'azure', 'category': 'encryption', 'kind': 'stream_analytics_job',
     'title': 'External Stream Analytics job storage declares customer-managed encryption',
     'severity': 'medium', 'dependencies': ('stream_analytics_job', 'storage_account'), 'evaluate': stream_job_storage_cmk_declared,
     'description': 'For jobs selecting external job storage, resolves the account within the selected subscription and checks its CMK declaration and assigned encryption identity. Built-in storage and effective key use are outside this check.',
     'remediation': ('Confirm the job selects the intended external storage account.',
                     'Configure that account with a supported CMK reference and its assigned encryption identity.',
                     'Review key permissions, availability and job operation separately.')},
)
