"""Passive managementPolicies/default metadata; execution/history remain unresolved.

Owner windows describe requirements, never observations.  Neither a configured
lifecycle timer nor an owner declaration proves version/snapshot deletion or an
actual deletion deadline.  The frozen lifecycle evaluator therefore stays
UNKNOWN until its independent execution/applicability authorities exist.
"""
from __future__ import annotations

import copy
import json
import math
import re
from datetime import datetime, timezone

ARM = 'https://management.azure.com'
API_VERSION = '2023-05-01'
NAMESPACE = 'azure_storage_lifecycle'
KIND = 'storage_management_policy_evidence'
VERSION_KIND = 'storage_version_lifecycle_evidence'
NATIVE_TYPES = {KIND, VERSION_KIND}
_SUB = r'/subscriptions/[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}'
_ACCOUNT = _SUB + r'/resourceGroups/[^/?#%\\\x00-\x20]+/providers/Microsoft.Storage/storageAccounts/[a-z0-9]{3,24}'
_UNRESOLVED = ('version_snapshot_protection_unresolved', 'immutable_deletion_execution_unresolved', 'tag_and_rule_overlap_unresolved')


def _time(value):
    if not isinstance(value, str) or len(value) > 64:
        raise ValueError('invalid lifecycle review timestamp')
    parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
    if parsed.utcoffset() is None:
        raise ValueError('lifecycle review requires timezone')
    return parsed.astimezone(timezone.utc)


def _bounded(value, limit):
    def walk(item, depth=0):
        if depth > 14:
            raise ValueError('lifecycle metadata depth exceeded')
        if isinstance(item, dict):
            if len(item) > 256 or any(not isinstance(k, str) for k in item):
                raise ValueError('lifecycle metadata map invalid')
            for child in item.values():
                walk(child, depth + 1)
        elif isinstance(item, list):
            if len(item) > 1000:
                raise ValueError('lifecycle metadata list exceeded')
            for child in item:
                walk(child, depth + 1)
        elif item is not None and type(item) not in (str, bool, int, float):
            raise ValueError('lifecycle metadata scalar invalid')
        elif isinstance(item, float) and not math.isfinite(item):
            raise ValueError('nonfinite lifecycle metadata')
    walk(value)
    if len(json.dumps(value, ensure_ascii=False, allow_nan=False).encode()) > limit:
        raise ValueError('lifecycle metadata size exceeded')


def _text(value, maximum=512, empty=False):
    if not isinstance(value, str) or len(value) > maximum or (not value and not empty) or any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise ValueError('invalid lifecycle text')
    return value


def _account(value, scope):
    if not isinstance(value, str) or not re.fullmatch(_ACCOUNT, value, re.I) or not value.casefold().startswith(scope.casefold() + '/') or any(p in ('.', '..') for p in value.split('/')):
        raise ValueError('foreign or malformed lifecycle account')
    return value


def normalize(options):
    """Validate normative input only; accepted stale/future reviews stay ineligible."""
    params = options.get('compliance_parameters', {})
    if not isinstance(params, dict):
        raise ValueError('invalid compliance parameters')
    if NAMESPACE not in params:
        return None
    review = params[NAMESPACE]
    _bounded(review, 50000)
    fields = {'scope', 'status', 'authorized_by', 'document_id', 'observed_at', 'expires_at', 'accounts'}
    if not isinstance(review, dict) or set(review) != fields or review['status'] != 'collected' or not isinstance(review['scope'], str) or not re.fullmatch(_SUB, review['scope'], re.I):
        raise ValueError('invalid lifecycle owner review')
    for name in ('authorized_by', 'document_id'):
        if _text(review[name]).strip() != review[name]:
            raise ValueError('invalid lifecycle approval identity')
    if _time(review['observed_at']) >= _time(review['expires_at']):
        raise ValueError('invalid lifecycle approval window')
    accounts = review['accounts']
    if not isinstance(accounts, list) or not 1 <= len(accounts) <= 256:
        raise ValueError('invalid lifecycle approved accounts')
    seen = set()
    for account in accounts:
        if not isinstance(account, dict) or set(account) != {'account_id', 'protected_prefixes'}:
            raise ValueError('invalid lifecycle account criteria')
        aid = _account(account['account_id'], review['scope']).casefold()
        if aid in seen:
            raise ValueError('duplicate lifecycle account')
        seen.add(aid)
        prefixes = account['protected_prefixes']
        if not isinstance(prefixes, list) or len(prefixes) > 256:
            raise ValueError('invalid lifecycle protected prefixes')
        names = set()
        for target in prefixes:
            if not isinstance(target, dict) or set(target) != {'prefix', 'minimum_retention_days', 'maximum_deletion_days'}:
                raise ValueError('invalid lifecycle retention criterion')
            prefix = _text(target['prefix'], 1024, empty=True)
            if prefix in names:
                raise ValueError('duplicate lifecycle protected prefix')
            names.add(prefix)
            minimum, maximum = target['minimum_retention_days'], target['maximum_deletion_days']
            if type(minimum) is not int or type(maximum) is not int or not 0 <= minimum <= maximum <= 146000 or maximum == 0:
                raise ValueError('invalid lifecycle retention window')
    raw = options.get('compliance_policy', {})
    if not isinstance(raw, dict) or set(raw).intersection({'scope', 'status', 'authorized_by', 'document_id', 'observed_at', 'expires_at', 'max_age_seconds', 'parameters'}):
        raise ValueError('competing lifecycle flat approval')
    return copy.deepcopy(review)


def required_types(wanted):
    return {'storage_account'} if NATIVE_TYPES.intersection(wanted) else set()


def _native_policy(raw, account):
    """Exact singleton identity and bounded public rule metadata, without extras."""
    _bounded(raw, 1024 * 1024)
    expected = account + '/managementPolicies/default'
    if not isinstance(raw, dict) or str(raw.get('id', '')).casefold() != expected.casefold() or str(raw.get('type', '')).casefold() != 'microsoft.storage/storageaccounts/managementpolicies' or not isinstance(raw.get('properties'), dict):
        raise ValueError('foreign or malformed lifecycle GET')
    properties = raw['properties']
    policy = properties.get('policy')
    if not isinstance(policy, dict) or set(policy) != {'rules'} or not isinstance(policy['rules'], list) or len(policy['rules']) > 100:
        raise ValueError('incomplete lifecycle policy rules')
    seen = set()
    documented_defaults = []
    policy = copy.deepcopy(policy)
    for rule in policy['rules']:
        if not isinstance(rule, dict) or set(rule) - {'name', 'type', 'enabled', 'definition'} or not {'name', 'type', 'definition'} <= set(rule) or rule['type'] != 'Lifecycle' or ('enabled' in rule and type(rule['enabled']) is not bool):
            raise ValueError('unsupported lifecycle rule')
        name = _text(rule['name'], 256)
        if name in seen:
            raise ValueError('duplicate lifecycle rule')
        seen.add(name)
        if 'enabled' not in rule:
            rule['enabled'] = True
            documented_defaults.append({'rule': name, 'field': 'enabled', 'value': True})
        definition = rule['definition']
        if not isinstance(definition, dict) or set(definition) - {'filters', 'actions'} or 'actions' not in definition:
            raise ValueError('unsupported lifecycle definition')
        filters = definition.get('filters', {'blobTypes': ['blockBlob', 'appendBlob']})
        if not isinstance(filters, dict) or set(filters) - {'blobTypes', 'prefixMatch', 'blobIndexMatch'}:
            raise ValueError('unsupported lifecycle filters')
        types = filters.get('blobTypes')
        if not isinstance(types, list) or not types or any(t not in ('blockBlob', 'appendBlob') for t in types) or len(set(types)) != len(types):
            raise ValueError('invalid lifecycle blob types')
        prefixes = filters.get('prefixMatch', [])
        if not isinstance(prefixes, list) or len(prefixes) > 10 or any(not isinstance(p, str) or len(p) > 1024 for p in prefixes) or len(set(prefixes)) != len(prefixes):
            raise ValueError('invalid lifecycle prefix filters')
        tags = filters.get('blobIndexMatch', [])
        if not isinstance(tags, list) or len(tags) > 10:
            raise ValueError('invalid lifecycle tag filters')
        for tag in tags:
            if not isinstance(tag, dict) or set(tag) != {'name', 'op', 'value'} or tag['op'] != '==':
                raise ValueError('invalid lifecycle tag predicate')
            _text(tag['name'], 128); _text(tag['value'], 256, empty=True)
        actions = definition['actions']
        if not isinstance(actions, dict) or not actions or set(actions) - {'baseBlob', 'snapshot', 'version'}:
            raise ValueError('unsupported lifecycle actions')
        for kind, operations in actions.items():
            allowed = {'delete', 'tierToCool', 'tierToArchive', 'tierToCold', 'enableAutoTierToHotFromCool'} if kind == 'baseBlob' else {'delete', 'tierToCool', 'tierToArchive', 'tierToCold'}
            if not isinstance(operations, dict) or not operations or set(operations) - allowed:
                raise ValueError('unsupported lifecycle operation')
            for op, condition in operations.items():
                if op == 'enableAutoTierToHotFromCool':
                    if type(condition) is not bool:
                        raise ValueError('invalid lifecycle automatic tier flag')
                    continue
                fields = {'daysAfterModificationGreaterThan', 'daysAfterCreationGreaterThan', 'daysAfterLastAccessTimeGreaterThan', 'daysAfterLastTierChangeGreaterThan'} if kind == 'baseBlob' else {'daysAfterCreationGreaterThan', 'daysAfterLastTierChangeGreaterThan'}
                if not isinstance(condition, dict) or not condition or set(condition) - fields or any(type(n) not in (int, float) or (isinstance(n, float) and not math.isfinite(n)) or not 0 <= n <= 1000000000 for n in condition.values()):
                    raise ValueError('invalid lifecycle action threshold')
    result = {'id': expected, 'type': raw['type'], 'properties': {'policy': copy.deepcopy(policy)}, 'read_complete': True}
    if documented_defaults:
        result['documented_defaults'] = documented_defaults
        result['defaults_source'] = 'https://learn.microsoft.com/en-us/azure/storage/blobs/lifecycle-management-policy-structure'
    if 'lastModifiedTime' in properties:
        _time(properties['lastModifiedTime'])
        result['properties']['lastModifiedTime'] = properties['lastModifiedTime']
    return result


def _version_payload(reader, account, policy):
    """Reuse optional native inventories without claiming blob/version population."""
    payload = {'management_policy': copy.deepcopy(policy), 'versioning_read_complete': False,
               'containers': {'collection_status': 'unavailable', 'items': []},
               'unresolved_authorities': ['required_blob_version_population_unresolved',
                   'required_blob_tags_unresolved', 'required_blob_scope_unresolved']}
    service_id = account + '/blobServices/default'
    services = [c for c in reader.collections if c['type'] == 'storage_service'
                and c['scope'].casefold() == (account + '/blobServices').casefold()]
    if len(services) == 1 and services[0]['status'] == 'collected' and len(services[0]['items']) == 1:
        service = services[0]['items'][0]
        props = service.get('properties')
        if (str(service.get('id', '')).casefold() == service_id.casefold()
                and str(service.get('type', '')).casefold() == 'microsoft.storage/storageaccounts/blobservices'
                and isinstance(props, dict) and type(props.get('isVersioningEnabled')) is bool):
            payload['versioning_read_complete'] = True
            payload['blob_service'] = {'id': service_id, 'properties': {'isVersioningEnabled': props['isVersioningEnabled']}}
    containers = [c for c in reader.collections if c['type'] == 'storage_container'
                  and c['scope'].casefold() == account.casefold()]
    if len(containers) == 1 and containers[0]['status'] in ('collected', 'empty'):
        rows, seen = [], set()
        for raw in containers[0]['items']:
            rid = raw.get('id')
            if (not isinstance(rid, str) or not re.fullmatch(re.escape(account) + r'/blobServices/default/containers/[^/?#%\\\x00-\x20]+', rid, re.I)
                    or any(part in ('.', '..') for part in rid.split('/'))
                    or str(raw.get('type', '')).casefold() != 'microsoft.storage/storageaccounts/blobservices/containers'
                    or rid.casefold() in seen):
                return payload
            seen.add(rid.casefold())
            rows.append({'id': rid, 'blob_population_complete': False, 'blob_tags_complete': False,
                         'required_scope_authoritative': False,
                         'required_objects': {'collection_status': 'unavailable', 'items': []}})
        payload['containers'] = {'collection_status': 'collected' if rows else 'empty', 'items': rows}
    return payload


def _policy_absent(exc):
    """ARM answers 404 ManagementPolicyNotFound when an account has no lifecycle policy."""
    from .azure import _arm_error_code, _status_code
    return _status_code(exc) in (404, '404') and _arm_error_code(exc) == 'ManagementPolicyNotFound'


def _absent_policy(account):
    # No policy is a complete observation: the account has zero lifecycle rules.
    return {'id': account + '/managementPolicies/default', 'type': 'Microsoft.Storage/storageAccounts/managementPolicies',
            'properties': {'policy': {'rules': []}}, 'read_complete': True, 'policy_present': False}


def collect(reader, request, scopes, wanted, options):
    review = normalize(options)
    if review and review['scope'].casefold() not in {s.casefold() for s in scopes}:
        raise ValueError('lifecycle owner scope differs from selected scope')
    selected = NATIVE_TYPES.intersection(wanted)
    if not selected:
        return
    from .azure import AzureReadError
    # Both projections share one native singleton observation (including failure).
    # The shared scheduler executes jobs serially across kinds/scopes here.
    policies = {}
    def get_policy(account):
        key = account.casefold()
        if key not in policies:
            try:
                policies[key] = _native_policy(reader.call(request, ARM + account + '/managementPolicies/default?api-version=' + API_VERSION), account)
            except Exception as exc:
                policies[key] = _absent_policy(account) if _policy_absent(exc) else exc
        if isinstance(policies[key], Exception):
            raise policies[key]
        return policies[key]
    for scope in scopes:
        for kind in sorted(selected):
            def rows(scope=scope, kind=kind):
                parents = [c for c in reader.collections if c['type'] == 'storage_account' and c['scope'].casefold() == scope.casefold()]
                if len(parents) != 1 or parents[0]['status'] not in ('collected', 'empty'):
                    raise AzureReadError('lifecycle_parent_inventory_incomplete')
                seen = set()
                for parent in parents[0]['items']:
                    account = _account(parent.get('id'), scope)
                    if account.casefold() in seen:
                        raise ValueError('duplicate lifecycle parent account')
                    seen.add(account.casefold())
                    policy = get_policy(account)
                    target = next((a for a in review['accounts'] if a['account_id'].casefold() == account.casefold()), None) if review and review['scope'].casefold() == scope.casefold() else None
                    payload = _version_payload(reader, account, policy) if kind == VERSION_KIND else {
                        'management_policy': copy.deepcopy(policy), 'protected_scope_authoritative': False,
                        'version_snapshot_protection_resolved': False, 'overlap_resolved': False,
                        'protected_prefixes': {'collection_status': 'collected' if target and target['protected_prefixes'] else 'empty' if target else 'unavailable', 'items': copy.deepcopy(target['protected_prefixes']) if target else []},
                        'unresolved_authorities': list(_UNRESOLVED)}
                    provenance = {'schema_version': 1, 'read_only': True, 'complete': False, 'policy_approved': False,
                                  'captured_at': 'pending_native_snapshot_binding', 'source_operation': 'ManagementPolicies_Get',
                                  'native_source_id': policy['id'], 'api_version': API_VERSION, 'representation': 'configuration_metadata_not_deletion_outcome'}
                    if target and kind == KIND:
                        provenance['owner_review'] = {k: review[k] for k in ('scope', 'status', 'authorized_by', 'document_id', 'observed_at', 'expires_at')}
                    suffix = 'versionLifecycle' if kind == VERSION_KIND else 'storageLifecycle'
                    yield [{'id': account + '/complianceEvidence/' + suffix, 'parent_id': account, 'payload': payload, '_provenance': provenance}]
            reader.run([(kind, scope, 'Microsoft.Storage', rows)])


def snapshot_instant(collections, wanted, instant=None):
    if not NATIVE_TYPES.intersection(wanted):
        return instant
    instant = instant or datetime.now(timezone.utc).isoformat()
    clock = _time(instant)
    for collection in collections:
        if collection['type'] not in NATIVE_TYPES:
            continue
        for row in collection['items']:
            provenance = row['_provenance']
            provenance['captured_at'] = instant
            owner = provenance.get('owner_review')
            approved = bool(owner and _time(owner['observed_at']) <= clock <= _time(owner['expires_at']))
            provenance['policy_approved'] = approved
            if collection['type'] == KIND:
                row['payload']['protected_scope_authoritative'] = approved
    return instant
