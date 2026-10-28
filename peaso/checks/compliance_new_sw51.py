"""Signed GCP defensive compliance checks (sw51).

Snapshot policy inputs are explicit, project-bound metadata.sw51_policy values.
Absence checks require complete scoped inventories; no live API calls occur here.
"""
from __future__ import annotations

import json
import re
from collections import Counter
from dataclasses import replace
from datetime import datetime, timezone
from ipaddress import ip_network

from . import CHECKS, register, result, unknown
from .facts import Unavailable, complete_items, get, guard, list_of_objects, omitted, memoized

META = {'gcp_pci_bucket_56c6b1b7f813': {'kind': 'bucket',
                                 'category': 'exposure',
                                 'severity': 'high',
                                 'title': 'Cloud Storage bucket has no public write grant',
                                 'remediation': 'Remove public object-write IAM grants and active '
                                                'bucket/object ACL grants; enable '
                                                'uniformBucketLevelAccess where feasible.',
                                 'sha': '10bab721e5644eec6d4c39da00437c73e3fc0d7c6d31ca3d1a4c44ac81bc7e85'},
 'gcp_pci_bucket_7dc6cb8c2e05': {'kind': 'bucket',
                                 'category': 'exposure',
                                 'severity': 'high',
                                 'title': 'Non-excluded bucket is not publicly accessible',
                                 'remediation': 'Remove effective public IAM and bucket ACL grants from '
                                                'non-excluded buckets; document only approved '
                                                'exclusions.',
                                 'sha': '2de02460d76e52a0d846971b3741197fbf6db06cfb1702c8dd37869dcf85f610'},
 'gcp_c5_asset_change_audit': {'kind': 'asset',
                               'category': 'logging',
                               'severity': 'medium',
                               'title': 'Asset changes have audit events',
                               'remediation': 'Enable and retain Admin Activity audit logs for asset '
                                              'changes; reconcile each unlogged CAI snapshot change '
                                              'with its API event.',
                               'sha': '8199ab43d6d7067f32762b574d8c605ab3ffe7e5e6af73da7b30afafc9b1d958'},
 'gcp_c5_asset_inventory': {'kind': 'asset',
                            'category': 'asset_management',
                            'severity': 'medium',
                            'title': 'In-scope cloud asset inventory coverage',
                            'remediation': 'Expand Cloud Asset Inventory collection to the missing '
                                           'assetType and preserve name, assetType and updateTime '
                                           'metadata.',
                            'sha': 'b099f12db72aa6f8ad80289e37c20dc79fad13e94fa96507d034a2350bcea9fd'},
 'gcp_c5_asset_risk_label': {'kind': 'asset',
                             'category': 'asset_management',
                             'severity': 'medium',
                             'title': 'Cloud resource risk classification label',
                             'remediation': 'Set the approved risk classification label or tag on each '
                                            'in-scope asset using its service label settings.',
                             'sha': '088b31580ce910b3d2ec038d677c67409eff7d49a331bbb5efee4e5dabb39a6a'},
 'gcp_c5_region': {'kind': 'asset',
                   'category': 'data_residency',
                   'severity': 'medium',
                   'title': 'Resource location within approved region',
                   'remediation': 'Move or recreate resources in their contract-approved region; update '
                                  'bucket, SQL, GKE or KMS location settings through migration.',
                   'sha': 'ceec2649bfe1002405d9f3a77d4949fea30d9e879d782a2fed6211ab5ec8d56a'},
 'gcp_c5_key_versions': {'kind': 'kms_key',
                         'category': 'key_management',
                         'severity': 'medium',
                         'title': 'KMS key version lifecycle',
                         'remediation': 'Disable or destroy KMS key versions according to the approved '
                                        'lifecycle schedule; rotate expired ENABLED versions.',
                         'sha': 'b53d1e9dd33bc288b01bcdcf8d9f2d448ec38164aa546958776150276b9fdd2f'},
 'gcp_pci_kms_key_a3927a5f3b84': {'kind': 'kms_key',
                                  'category': 'least_privilege',
                                  'severity': 'medium',
                                  'title': 'KMS key has at most three distinct users',
                                  'remediation': 'Have the IAM and key owners review key-local and '
                                                 'inherited cryptographic-use grants, groups and '
                                                 'conditions before reducing access to three approved '
                                                 'principals.',
                                  'sha': 'b2c779d401c536c0b11ee40cf8fa76d430016ae95c73d3dc585d79b131854f1c'},
 'gcp_c5_cloud_armor_waf': {'kind': 'backend_service',
                            'category': 'network',
                            'severity': 'medium',
                            'title': 'Administration interface WAF policy',
                            'remediation': 'Attach a Cloud Armor securityPolicy to each in-scope admin '
                                           'backend and add the approved WAF expression/action rule.',
                            'sha': '89b8f646481fde32ae3c1c9c20e77cd4a0c72f7c7a1e7165523dca737a9ceeb5'},
 'gcp_cloudcdn_cache_policy': {'kind': 'backend_service',
                               'category': 'data_protection',
                               'severity': 'medium',
                               'title': 'Sensitive backend has an unapproved CDN cache policy',
                               'remediation': 'Disable CDN on sensitive backends or set an approved '
                                              'cdnPolicy.cacheMode, clientTtl and defaultTtl.',
                               'sha': 'da02e6a9437959d0be4643981b88dd16ed3bf8a7463aea5ef3f8a910765c9c16'},
 'gcp_pci_backend_service_2ce96d36d0bf': {'kind': 'backend_service',
                                          'category': 'encryption',
                                          'severity': 'medium',
                                          'title': 'Cloud CDN viewer TLS minimum is 1.2',
                                          'remediation': 'Attach an SSL policy with '
                                                         'minTlsVersion=TLS_1_2 or later to every HTTPS '
                                                         'proxy serving a CDN-enabled backend.',
                                          'sha': 'd69aad31c2e14a573184e5b14e5d41f93e9b2b1bf4cefe36e92ad5f02123b161'},
 'gcp_pci_backend_service_571fd0bfec67': {'kind': 'backend_service',
                                          'category': 'logging',
                                          'severity': 'medium',
                                          'title': 'Cloud Armor protected backend request logging',
                                          'remediation': 'Enable backendServices.logConfig.enable and '
                                                         'create the required matching Cloud Logging '
                                                         'sink destination/filter.',
                                          'sha': '776eb78ab55be00ba1663ee96e3f4e4fd80c03579d6a0aeca67617751dd10f94'},
 'gcp_backend_service_checks_armor_security_policy_contains_f48cc81ccae3': {'kind': 'security_policy',
                                                                            'category': 'network',
                                                                            'severity': 'medium',
                                                                            'title': 'Cloud Armor '
                                                                                     'policy has a '
                                                                                     'non-default rule',
                                                                            'remediation': 'Add a '
                                                                                           'non-default '
                                                                                           'Cloud Armor '
                                                                                           'security '
                                                                                           'policy rule '
                                                                                           'with an '
                                                                                           'explicit '
                                                                                           'match and '
                                                                                           'action '
                                                                                           'before '
                                                                                           'priority '
                                                                                           '2147483647.',
                                                                            'sha': '338ce668f5f5aa66e9b9448477cc2218b15fcc37aef6a249ac0d057280f110d0'},
 'gcp_cloud_armor_cidr_deny': {'kind': 'security_policy',
                               'category': 'network',
                               'severity': 'high',
                               'title': 'Load balancer allows callers outside approved CIDRs',
                               'remediation': 'Add a Cloud Armor DENY rule for sources outside '
                                              'approved_cidrs on each internet-facing backend security '
                                              'policy.',
                               'sha': 'bc4adfa7ae07e09c9f217caf0a1b535b18ee94e4793286dc20870155b2fc5012'},
 'gcp_cloud_armor_rate_limit': {'kind': 'security_policy',
                                'category': 'network',
                                'severity': 'high',
                                'title': 'Public backend lacks request rate limiting',
                                'remediation': 'Add a Cloud Armor throttle or rate-based-ban rule at '
                                               '2000 requests/300 seconds or less with banDurationSec '
                                               '>=60.',
                                'sha': '71b7c4b089afa7b4fe85d4d80f8c81c2866f965519736a31bdce818d7de8bf3f'}}


def signed(check_id, *dependencies, target='resource'):
    meta = META[check_id]
    def decorate(function):
        native = meta['category'] if meta['category'] in {'hardening', 'exposure', 'least_privilege', 'iam_graph', 'network'} else 'hardening'
        register(check_id, 'gcp', native, meta['kind'], meta['title'], meta['severity'], 'CM-6',
                 meta['remediation'], target=target,
                 dependencies=list(dependencies or (meta['kind'],)))(function)
        CHECKS[-1] = replace(CHECKS[-1], category=meta['category'])
        return function
    return decorate


def _scope(index):
    context = get(index, 'context', dict)
    if get(context, 'provider', str) != 'gcp':
        raise Unavailable('foreign provider')
    scope = get(context, 'scope', str)
    if not re.fullmatch(r'projects/[A-Za-z0-9_-]+', scope):
        raise Unavailable('project scope unavailable')
    return scope


def _validated_rows(index, kind):
    scope = _scope(index)
    envelopes = get(index, 'collections', dict).get(kind)
    if not isinstance(envelopes, list) or len(envelopes) != 1:
        raise Unavailable(kind + ' collection missing or ambiguous')
    envelope = envelopes[0]
    if get(envelope, 'type', str) != kind or get(envelope, 'scope', str) != scope:
        raise Unavailable(kind + ' foreign collection')
    if get(envelope, 'status', str) not in ('collected', 'empty') or envelope.get('coverage_status', 'collected') not in ('collected', 'empty'):
        raise Unavailable(kind + ' incomplete collection')
    rows = complete_items(index, kind)
    declared = list_of_objects(get(envelope, 'items', list))
    encode = lambda row: json.dumps(row, sort_keys=True, separators=(',', ':'), default=str)
    if Counter(map(encode, declared)) != Counter(map(encode, rows)) or (envelope['status'] == 'empty' and rows):
        raise Unavailable(kind + ' collection and index disagree')
    wrappers = get(index, kind, list)
    if len(wrappers) != len(rows):
        raise Unavailable(kind + ' wrapper count differs')
    seen = set()
    for wrapper in wrappers:
        if get(wrapper, 'type', str) != kind or get(wrapper, 'scope', str) != scope or wrapper.get('provider', 'gcp') != 'gcp':
            raise Unavailable(kind + ' foreign resource scope')
        row = get(wrapper, 'data', dict)
        if get(row, '_provenance.scope', str) != scope:
            raise Unavailable(kind + ' foreign native provenance')
        identity = next((get(row, key, str) for key in ('selfLink', 'name', 'id') if key in row), None)
        if not identity or identity in seen:
            raise Unavailable(kind + ' duplicate or missing identity')
        if identity.startswith('projects/') and not identity.startswith(scope + '/'):
            raise Unavailable(kind + ' foreign resource identity')
        seen.add(identity)
    return rows


def _rows(index, kind, item=None):
    rows = memoized(index, ('sw51_rows', kind), lambda: _validated_rows(index, kind))
    if item is not None and sum(row == item for row in rows) != 1:
        raise Unavailable(kind + ' subject absent or duplicated')
    return rows


def _policy(index, key, expected):
    scope = _scope(index)
    policy = get(get(get(index, 'context', dict), 'metadata', dict), 'sw51_policy', dict)
    if get(policy, 'status', str) != 'collected' or get(policy, 'scope', str) != scope:
        raise Unavailable('approved policy unavailable or foreign')
    return get(policy, key, expected)


def _strings(value):
    if not isinstance(value, list) or any(not isinstance(v, str) or not v for v in value) or len(value) != len(set(value)):
        raise Unavailable('malformed policy string list')
    return value


def _native_name(row):
    return get(row, 'name', str)


def _by(rows, path):
    result_map = {}
    for row in rows:
        key = get(row, path, str)
        if key in result_map:
            raise Unavailable('duplicate joined identity')
        result_map[key] = row
    return result_map


def _datetime(value):
    if not isinstance(value, str):
        raise Unavailable('malformed timestamp')
    try:
        parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
    except ValueError as exc:
        raise Unavailable('malformed timestamp') from exc
    if parsed.tzinfo is None:
        raise Unavailable('timestamp lacks timezone')
    return parsed.astimezone(timezone.utc)


def _read_time(index, kind):
    envelopes = get(get(index, 'collections', dict), kind, list)
    if len(envelopes) != 1:
        raise Unavailable('snapshot read time unavailable')
    return _datetime(get(envelopes[0], 'readTime', str))


def _bucket(item, index):
    _rows(index, 'bucket', item)
    name = _native_name(item)
    if not name or '/' in name:
        raise Unavailable('malformed bucket name')
    return name


def _public_iam(item, *, write_only=False):
    bindings = list_of_objects(get(item, 'iamPolicy.bindings', list))
    found = False
    for binding in bindings:
        members = _strings(get(binding, 'members', list))
        role = get(binding, 'role', str)
        if not role:
            raise Unavailable('missing IAM role')
        if 'condition' in binding:
            raise Unavailable('conditional IAM grant needs effective evaluation')
        if not write_only:
            found |= bool({'allUsers', 'allAuthenticatedUsers'} & set(members))
        elif {'allUsers', 'allAuthenticatedUsers'} & set(members):
            # Custom and inherited role permissions need an explicit resolved fact.
            if role in {'roles/storage.objectCreator', 'roles/storage.objectUser', 'roles/storage.objectAdmin', 'roles/storage.admin', 'roles/owner', 'roles/editor', 'roles/storage.legacyBucketWriter', 'roles/storage.legacyBucketOwner', 'roles/storage.legacyObjectOwner'}:
                found = True
            elif role not in {'roles/storage.objectViewer', 'roles/storage.legacyBucketReader', 'roles/storage.legacyObjectReader', 'roles/viewer'}:
                raise Unavailable('unresolved public IAM role permissions')
    return found


def _acl_public(rows, bucket, *, write_only=False, index=None):
    def classified():
        known = {_native_name(b) for b in _rows(index, 'bucket')} if index is not None else {bucket}
        readable, writable = set(), set()
        for row in rows:
            owner = get(row, 'bucket', str)
            if owner not in known:
                raise Unavailable('foreign ACL bucket')
            entity = get(row, 'entity', str)
            role = get(row, 'role', str)
            if role not in {'OWNER', 'WRITER', 'READER'}:
                raise Unavailable('unknown ACL role')
            if entity in {'allUsers', 'allAuthenticatedUsers'}:
                readable.add(owner)
                if role in {'OWNER', 'WRITER'}:
                    writable.add(owner)
        return readable, writable
    access, write = memoized(index, ('sw51_acl_public_buckets', id(rows)), classified) if index is not None else classified()
    return bucket in (write if write_only else access)


def _effective_bucket_public(index, bucket, field):
    row = _by(_rows(index, 'bucket_effective_iam'), 'name').get(bucket)
    if row is None or get(row, 'resolutionComplete', bool) is not True:
        raise Unavailable('effective bucket IAM resolution incomplete')
    return get(row, field, bool)


@signed('gcp_pci_bucket_7dc6cb8c2e05', 'bucket', 'bucket_acl', 'bucket_effective_iam')
def bucket_public_access(item, index):
    name = _bucket(item, index)
    excluded = _strings(_policy(index, 'excludedPublicBuckets', list))
    if name in excluded:
        return 'NOT_APPLICABLE', {'bucket': name, 'reason': 'approved exclusion'}
    public_iam = _public_iam(item)
    if public_iam:
        return result(True, bucket=name, source='IAM')
    effective_error = None
    try:
        effective = _effective_bucket_public(index, name, 'publicAccess')
    except Unavailable as exc:
        effective, effective_error = False, exc
    if effective:
        return result(True, bucket=name, source='effective IAM')
    uniform = get(item, 'iamConfiguration.uniformBucketLevelAccess.enabled', bool)
    if uniform:
        if effective_error:
            raise effective_error
        return result(False, bucket=name, source='IAM; uniform access disables ACLs')
    acls = _rows(index, 'bucket_acl')
    public_acl = _acl_public(acls, name, index=index)
    if public_acl:
        return result(True, bucket=name, source='bucket ACL')
    if effective_error:
        raise effective_error
    return result(public_acl, bucket=name, source='bucket ACL' if public_acl else 'IAM and bucket ACL')


@signed('gcp_pci_bucket_56c6b1b7f813', 'bucket', 'bucket_acl', 'object_acl', 'bucket_effective_iam')
def bucket_public_write(item, index):
    name = _bucket(item, index)
    public_iam = _public_iam(item, write_only=True)
    if public_iam:
        return result(True, bucket=name, source='known public object-write IAM role')
    effective_error = None
    try:
        effective = _effective_bucket_public(index, name, 'publicWrite')
    except Unavailable as exc:
        effective, effective_error = False, exc
    if effective:
        return result(True, bucket=name, source='effective IAM')
    uniform = get(item, 'iamConfiguration.uniformBucketLevelAccess.enabled', bool)
    if uniform:
        if effective_error:
            raise effective_error
        return result(False, bucket=name, source='IAM; uniform access disables ACLs')
    bucket_acls = _rows(index, 'bucket_acl')
    if _acl_public(bucket_acls, name, write_only=True, index=index):
        return result(True, bucket=name, source='active bucket ACL')
    object_acls = _rows(index, 'object_acl')
    if _acl_public(object_acls, name, write_only=True, index=index):
        return result(True, bucket=name, source='active ACL')
    if effective_error:
        raise effective_error
    return result(False, bucket=name, source='IAM and active ACLs')


@signed('gcp_c5_asset_inventory', 'asset', 'asset_service_inventory', target='scope')
def asset_inventory(item, index):
    assets = _rows(index, 'asset')
    services = _rows(index, 'asset_service_inventory')
    approved = _strings(_policy(index, 'approved_asset_types', list))
    if not approved:
        raise Unavailable('approved asset types empty')
    names = {}
    missing_metadata = []
    for asset in assets:
        name, typ = get(asset, 'name', str), get(asset, 'assetType', str)
        if typ in approved:
            if name in names:
                raise Unavailable('duplicate CAI asset')
            names[name] = asset
            if 'updateTime' not in asset:
                missing_metadata.append(name)
            else:
                _datetime(get(asset, 'updateTime', str))
    independent = []
    for row in services:
        service_name, service_type = get(row, 'name', str), get(row, 'assetType', str)
        if service_type in approved:
            independent.append((service_name, service_type))
    if len(independent) != len(set(independent)):
        raise Unavailable('duplicate independent service inventory')
    missing = [n for n, t in independent if n not in names]
    if missing or missing_metadata:
        return result(True, missing_service_assets=sorted(missing), missing_cai_metadata=sorted(missing_metadata))
    if not names and not independent:
        return 'NOT_APPLICABLE', {'reason': 'no approved in-scope assets'}
    return result(False, checked_assets=len(names))


@signed('gcp_c5_asset_risk_label', 'asset')
def asset_risk_label(item, index):
    _rows(index, 'asset', item)
    types = _strings(_policy(index, 'risk_asset_types', list))
    key = _policy(index, 'required_risk_label', str)
    approved = _strings(_policy(index, 'approved_risk_values', list))
    if not key or not approved or not types:
        raise Unavailable('risk label policy incomplete')
    typ = get(item, 'assetType', str)
    if typ not in types:
        return 'NOT_APPLICABLE', {'reason': 'asset type outside risk-label scope'}
    labels = get(item, 'resource.data.labels', dict)
    if any(not isinstance(k, str) or not isinstance(v, str) for k, v in labels.items()):
        raise Unavailable('malformed resource labels')
    return result(labels.get(key) not in approved, asset=get(item, 'name', str), label=key, value=labels.get(key))


@signed('gcp_c5_asset_change_audit', 'asset', 'asset_previous', 'asset_audit_log', target='scope')
def asset_change_audit(item, index):
    current = _rows(index, 'asset')
    previous = _rows(index, 'asset_previous')
    events = _rows(index, 'asset_audit_log')
    window = _policy(index, 'audit_window', dict)
    start, end = _datetime(get(window, 'start', str)), _datetime(get(window, 'end', str))
    if start >= end:
        raise Unavailable('invalid approved audit window')
    prior_read, current_read = _read_time(index, 'asset_previous'), _read_time(index, 'asset')
    if not start <= prior_read < current_read <= end:
        raise Unavailable('asset read times outside approved audit window')
    old = _by(previous, 'name')
    new = _by(current, 'name')
    changed = set()
    for name in old.keys() | new.keys():
        before, after = old.get(name), new.get(name)
        if before is not None:
            _datetime(get(before, 'updateTime', str))
        if after is not None:
            _datetime(get(after, 'updateTime', str))
        if before is None or after is None or before['updateTime'] != after['updateTime']:
            changed.add(name)
    if not changed:
        return 'NOT_APPLICABLE', {'reason': 'no observed asset changes'}
    matched = set()
    for event in events:
        name = get(event, 'protoPayload.resourceName', str)
        method = get(event, 'protoPayload.methodName', str)
        success = get(event, 'operationSucceeded', bool)
        log_name = get(event, 'logName', str)
        when = _datetime(get(event, 'timestamp', str))
        if name in changed and method and success and log_name.endswith('/logs/cloudaudit.googleapis.com%2Factivity') and start <= when <= end:
            matched.add(name)
    missing = changed - matched
    return result(bool(missing), changed_assets=sorted(changed), without_admin_activity=sorted(missing))


@signed('gcp_c5_region', 'asset', 'bucket', 'sql_instance', 'gke_cluster', 'kms_key')
def asset_region(item, index):
    _rows(index, 'asset', item)
    name, typ = get(item, 'name', str), get(item, 'assetType', str)
    mapping = _policy(index, 'asset_locations', dict)
    approved = _policy(index, 'approved_regions_by_asset', dict)
    if name not in approved:
        return 'NOT_APPLICABLE', {'asset': name, 'reason': 'no approved residency scope for asset'}
    regions = _strings(approved[name])
    if not regions:
        raise Unavailable('approved region set empty')
    entry = mapping.get(name)
    if not isinstance(entry, dict):
        raise Unavailable('approved asset location mapping unavailable')
    kind, resource_name = get(entry, 'kind', str), get(entry, 'resource_name', str)
    if kind not in {'bucket', 'sql_instance', 'gke_cluster', 'kms_key'}:
        raise Unavailable('unsupported location service')
    rows = _rows(index, kind)
    row = _by(rows, 'name').get(resource_name)
    if row is None:
        raise Unavailable('mapped service resource absent')
    if kind == 'bucket':
        location = get(row, 'location', str)
    elif kind == 'sql_instance':
        location = get(row, 'region', str)
    elif kind == 'gke_cluster':
        location = get(row, 'location', str)
    else:
        location = get(row, 'name', str).split('/locations/')[1].split('/')[0] if '/locations/' in row['name'] else ''
    if not location:
        raise Unavailable('resource location absent')
    resolved = _policy(index, 'location_region_mapping', dict)
    if location not in resolved and not re.fullmatch(r'[a-z]+(?:-[a-z0-9]+)+[0-9]', location):
        raise Unavailable('multi-region or zonal location mapping unavailable')
    effective = resolved.get(location, [location])
    effective = _strings(effective)
    if not effective:
        raise Unavailable('location mapping empty')
    return result(not set(effective).issubset(regions), asset=name, location=location, resolved_regions=effective)


@signed('gcp_c5_key_versions', 'kms_key', 'kms_key_version')
def key_versions(item, index):
    _rows(index, 'kms_key', item)
    name = get(item, 'name', str)
    policy = _policy(index, 'key_version_schedule', dict)
    schedule = policy.get(name)
    if not isinstance(schedule, dict):
        raise Unavailable('key version schedule unavailable')
    as_of = _datetime(get(get(index, 'context', dict), 'created_at', str))
    versions = [v for v in _rows(index, 'kms_key_version') if get(v, 'name', str).startswith(name + '/cryptoKeyVersions/')]
    if not versions:
        raise Unavailable('key version inventory empty or key has no versions')
    for v in versions:
        version_name = get(v, 'name', str)
        dates = schedule.get(version_name)
        if not isinstance(dates, dict):
            raise Unavailable('approved version dates unavailable')
        expiry = _datetime(get(dates, 'enabled_expiry', str))
        destroy_after = _datetime(get(dates, 'destroy_not_before', str))
        state = get(v, 'state', str)
        if state not in {'ENABLED', 'DISABLED', 'DESTROY_SCHEDULED', 'DESTROYED', 'IMPORT_FAILED', 'PENDING_IMPORT', 'PENDING_GENERATION'}:
            raise Unavailable('unrecognized key version state')
        if state == 'ENABLED' and as_of > expiry:
            return result(True, key=name, version=v['name'], reason='enabled after approved expiry')
        if state == 'DESTROYED':
            destroyed = _datetime(get(v, 'destroyTime', str))
            if destroyed < destroy_after:
                return result(True, key=name, version=v['name'], reason='destroyed before approved schedule')
    return result(False, key=name, checked_versions=len(versions))


@signed('gcp_pci_kms_key_a3927a5f3b84', 'kms_key', 'kms_effective_use')
def kms_effective_users(item, index):
    _rows(index, 'kms_key', item)
    name = get(item, 'name', str)
    joined = _by(_rows(index, 'kms_effective_use'), 'name').get(name)
    if joined is None or get(joined, 'resolutionComplete', bool) is not True:
        raise Unavailable('effective KMS use resolution incomplete')
    principals = _strings(get(joined, 'principals', list))
    return result(len(principals) > 3 or any(x in ('allUsers', 'allAuthenticatedUsers') for x in principals),
                  key=name, effective_principals=principals)


def _backend(item, index):
    _rows(index, 'backend_service', item)
    return get(item, 'selfLink', str)


def _url_backend_refs(url_map):
    if url_map.get('_representation') != 'full':
        raise Unavailable('URL map backend references unavailable')
    refs = set()
    def walk(value):
        if isinstance(value, dict):
            guard(value)
            for key, child in value.items():
                if key in {'service', 'defaultService', 'backendService'}:
                    if not isinstance(child, str) or not child:
                        raise Unavailable('malformed URL map backend reference')
                    refs.add(child)
                elif isinstance(child, (dict, list)):
                    walk(child)
        elif isinstance(value, list):
            for child in value:
                walk(child)
    walk(url_map)
    return refs


def _security_policy(item, index):
    _rows(index, 'security_policy', item)
    return get(item, 'selfLink', str)


def _policy_backends(item, index):
    ref = _security_policy(item, index)
    backends = _rows(index, 'backend_service')
    attached = []
    for backend in backends:
        if 'securityPolicy' in backend and get(backend, 'securityPolicy', str) == ref:
            attached.append(backend)
    return attached


def _rules(item):
    rules = list_of_objects(get(item, 'rules', list))
    priorities = set()
    for rule in rules:
        priority = get(rule, 'priority', int)
        if priority < 0 or priority > 2147483647 or priority in priorities:
            raise Unavailable('invalid or duplicate Cloud Armor rule priority')
        priorities.add(priority)
        get(rule, 'match', dict)
        get(rule, 'action', str)
    if 2147483647 not in priorities:
        raise Unavailable('default Cloud Armor rule unavailable')
    return rules


@signed('gcp_backend_service_checks_armor_security_policy_contains_f48cc81ccae3', 'security_policy', 'backend_service')
def armor_nondefault_rule(item, index):
    attached = _policy_backends(item, index)
    if not attached:
        return 'NOT_APPLICABLE', {'reason': 'no backend attaches policy'}
    rules = _rules(item)
    found = any(get(rule, 'priority', int) < 2147483647 and bool(get(rule, 'match', dict)) for rule in rules)
    return result(not found, policy=get(item, 'selfLink', str))


@signed('gcp_c5_cloud_armor_waf', 'backend_service', 'security_policy', 'url_map', 'target_https_proxy', 'forwarding_rule')
def admin_waf(item, index):
    name = _backend(item, index)
    mapping = _policy(index, 'admin_backend_mapping', dict)
    marker = get(mapping, name, dict)
    if get(marker, 'in_scope', bool) is not True or get(marker, 'internet_reachable', bool) is not True:
        return 'NOT_APPLICABLE', {'backend': name, 'reason': 'not an internet-reachable in-scope admin backend'}
    if get(marker, 'topology_verified', bool) is not True:
        raise Unavailable('admin backend topology mapping unverified')
    expression = _policy(index, 'approved_waf_expression', str)
    action = _policy(index, 'approved_waf_action', str)
    if not expression or action not in {'deny(403)', 'deny(404)', 'deny(502)', 'redirect'}:
        raise Unavailable('approved WAF rule unavailable')
    # Require complete route inventories before trusting the owner mapping.
    for kind in ('url_map', 'target_https_proxy', 'forwarding_rule'):
        _rows(index, kind)
    ref = item.get('securityPolicy')
    if ref is None:
        if '_representation' not in item or item['_representation'] != 'full':
            raise Unavailable('backend security policy field may be omitted')
        return result(True, backend=name, reason='no attached Cloud Armor policy')
    if not isinstance(ref, str) or not ref:
        raise Unavailable('malformed backend security policy reference')
    policy = _by(_rows(index, 'security_policy'), 'selfLink').get(ref)
    if policy is None:
        raise Unavailable('attached security policy absent')
    rules = _rules(policy)
    for rule in rules:
        if get(rule, 'priority', int) == 2147483647:
            continue
        if get(rule, 'disabled', bool):
            continue
        if get(rule, 'match.expr.expression', str) == expression and get(rule, 'action', str) == action:
            return result(False, backend=name, policy=ref)
    return result(True, backend=name, policy=ref, reason='approved enabled WAF rule absent')


def _public_policy(item, index):
    attached = _policy_backends(item, index)
    public = []
    for backend in attached:
        public_marker = get(backend, 'internetFacing', bool)
        if public_marker:
            public.append(backend)
    return public


@signed('gcp_cloud_armor_cidr_deny', 'security_policy', 'backend_service')
def armor_cidr_deny(item, index):
    public = _public_policy(item, index)
    if not public:
        return 'NOT_APPLICABLE', {'reason': 'no proven internet-facing attached backend'}
    approved = _strings(_policy(index, 'approved_cidrs', list))
    if not approved:
        raise Unavailable('approved CIDRs unavailable')
    try:
        canonical = [str(ip_network(cidr, strict=False)) for cidr in approved]
    except ValueError as exc:
        raise Unavailable('malformed approved CIDR') from exc
    # The policy supplies the exact reviewed CEL expression for this CIDR set.
    expected = _policy(index, 'approved_cidr_deny_expression', str)
    if not expected or get(_policy(index, 'cidr_expression_review', dict), 'cidrs', list) != canonical:
        raise Unavailable('approved CIDR expression review unavailable')
    rules = _rules(item)
    if get(item, 'cidrRulePrecedenceVerified', bool) is not True:
        raise Unavailable('Cloud Armor rule precedence not verified')
    found = any(get(rule, 'priority', int) < 2147483647 and get(rule, 'action', str).startswith('deny(')
                and get(rule, 'match.expr.expression', str) == expected and get(rule, 'disabled', bool) is False
                for rule in rules if 'expr' in rule.get('match', {}))
    return result(not found, policy=get(item, 'selfLink', str), internet_backends=len(public))


@signed('gcp_cloud_armor_rate_limit', 'security_policy', 'backend_service')
def armor_rate_limit(item, index):
    public = _public_policy(item, index)
    if not public:
        return 'NOT_APPLICABLE', {'reason': 'no proven internet-facing attached backend'}
    rules = _rules(item)
    if get(item, 'rateRulePrecedenceVerified', bool) is not True:
        raise Unavailable('rate-limit rule precedence unavailable')
    approved_key = _policy(index, 'rate_limit_enforce_on_key', str)
    approved_match = _policy(index, 'rate_limit_match_expression', str)
    if not approved_key or not approved_match:
        raise Unavailable('approved rate-limit match and client key unavailable')
    found = False
    for rule in rules:
        action = get(rule, 'action', str)
        if action not in {'throttle', 'rate_based_ban'} or get(rule, 'priority', int) == 2147483647:
            continue
        if get(rule, 'disabled', bool) or get(rule, 'match.expr.expression', str) != approved_match:
            continue
        options = get(rule, 'rateLimitOptions', dict)
        threshold = get(options, 'rateLimitThreshold', dict)
        count, interval = get(threshold, 'count', int), get(threshold, 'intervalSec', int)
        ban = get(options, 'banDurationSec', int)
        key = get(options, 'enforceOnKey', str)
        if count <= 0 or interval <= 0 or ban < 0:
            raise Unavailable('invalid rate-limit values')
        if key == approved_key and count <= 2000 and interval <= 300 and ban >= 60:
            found = True
    return result(not found, policy=get(item, 'selfLink', str), internet_backends=len(public))


@signed('gcp_cloudcdn_cache_policy', 'backend_service')
def cdn_cache_policy(item, index):
    name = _backend(item, index)
    sensitive = _policy(index, 'sensitive_backend_services', list)
    _strings(sensitive)
    if name not in sensitive:
        return 'NOT_APPLICABLE', {'backend': name, 'reason': 'not in approved sensitive-backend scope'}
    enabled = get(item, 'enableCDN', bool)
    if not enabled:
        return 'NOT_APPLICABLE', {'backend': name, 'reason': 'CDN disabled'}
    approved = _policy(index, 'approved_cache_policy', dict)
    modes = _strings(get(approved, 'cache_modes', list))
    max_client = get(approved, 'max_client_ttl', int)
    max_default = get(approved, 'max_default_ttl', int)
    if not modes or min(max_client, max_default) < 0:
        raise Unavailable('malformed approved cache policy')
    mode = get(item, 'cdnPolicy.cacheMode', str)
    client = get(item, 'cdnPolicy.clientTtl', int)
    default = get(item, 'cdnPolicy.defaultTtl', int)
    if min(client, default) < 0:
        raise Unavailable('malformed CDN TTL')
    return result(mode not in modes or client > max_client or default > max_default,
                  backend=name, cache_mode=mode, client_ttl=client, default_ttl=default)


@signed('gcp_pci_backend_service_2ce96d36d0bf', 'backend_service', 'url_map', 'target_https_proxy', 'ssl_policy')
def cdn_viewer_tls(item, index):
    name = _backend(item, index)
    enabled = get(item, 'enableCDN', bool)
    if not enabled:
        return 'NOT_APPLICABLE', {'backend': name, 'reason': 'CDN disabled'}
    maps = _rows(index, 'url_map')
    proxies = _rows(index, 'target_https_proxy')
    policies = _by(_rows(index, 'ssl_policy'), 'selfLink')
    serving_maps = []
    for row in maps:
        refs = _url_backend_refs(row)
        if name in refs:
            serving_maps.append(get(row, 'selfLink', str))
    if not serving_maps:
        raise Unavailable('serving URL map association absent')
    attached = [row for row in proxies if get(row, 'urlMap', str) in serving_maps]
    if not attached:
        raise Unavailable('serving HTTPS proxy absent')
    weak = []
    for proxy in attached:
        ref = get(proxy, 'sslPolicy', str)
        policy = policies.get(ref)
        if policy is None:
            raise Unavailable('attached SSL policy absent')
        version = get(policy, 'minTlsVersion', str)
        if version not in {'TLS_1_0', 'TLS_1_1', 'TLS_1_2', 'TLS_1_3'}:
            raise Unavailable('unrecognized TLS minimum')
        if version in {'TLS_1_0', 'TLS_1_1'}:
            weak.append(get(proxy, 'selfLink', str))
    return result(bool(weak), backend=name, weak_https_proxies=weak, serving_https_proxies=len(attached))


@signed('gcp_pci_backend_service_571fd0bfec67', 'backend_service', 'log_sink')
def armor_backend_logging(item, index):
    name = _backend(item, index)
    security_policy = item.get('securityPolicy')
    if security_policy is None:
        if item.get('_representation') != 'full':
            raise Unavailable('security policy attachment unavailable')
        return 'NOT_APPLICABLE', {'backend': name, 'reason': 'no Cloud Armor policy attached'}
    if not isinstance(security_policy, str) or not security_policy:
        raise Unavailable('malformed security policy reference')
    enabled = get(item, 'logConfig.enable', bool)
    if not enabled:
        return result(True, backend=name, reason='request logging disabled')
    requirement = _policy(index, 'required_armor_log_sink', dict)
    if get(requirement, 'required', bool):
        destination = get(requirement, 'destination', str)
        filter_text = get(requirement, 'filter', str)
        sinks = _rows(index, 'log_sink')
        matches = [s for s in sinks if get(s, 'destination', str) == destination and get(s, 'filter', str) == filter_text]
        if not matches:
            return result(True, backend=name, reason='required destination sink absent')
    return result(False, backend=name, logging_enabled=True)
