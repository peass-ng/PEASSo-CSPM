"""Native Data Protection, Files and NetApp inventories through the ARM reader.

Only management GET/LIST calls are issued. Parent rosters must be complete;
every child is joined by its exact ARM path. Blob auto-protection rules remain
unresolved until their complete rule semantics can be proven independently.
"""
from __future__ import annotations

import copy
import re

ARM = 'https://management.azure.com'
DP_VERSION = '2025-07-01'
STORAGE_VERSION = '2023-05-01'
NETAPP_VERSION = '2026-01-01'
NATIVE_TYPES = frozenset({'backup_vault', 'backup_instance', 'storage_file_share', 'netapp_account',
    'netapp_capacity_pool', 'netapp_volume', 'netapp_backup_policy', 'netapp_backup_vault'})


def required_types(wanted):
    result = set()
    if 'backup_instance' in wanted:
        result.add('backup_vault')
    if 'storage_file_share' in wanted:
        result.add('storage_account')
    if set(wanted) & {'netapp_capacity_pool', 'netapp_volume', 'netapp_backup_policy', 'netapp_backup_vault'}:
        result.add('netapp_account')
    if 'netapp_volume' in wanted:
        result.add('netapp_capacity_pool')
    return result


def _parent(reader, kind, scope):
    from .azure import AzureReadError
    rows = [c for c in reader.collections if c['type'] == kind and c['scope'].casefold() == scope.casefold()]
    if len(rows) != 1 or rows[0]['status'] not in ('collected', 'empty'):
        raise AzureReadError('native_backup_parent_incomplete')
    return rows[0]


def _identity(row, parent, suffix):
    rid = row.get('id')
    pattern = re.escape(parent) + '/' + suffix + r'/[^/?#\x00-\x20]+'
    if not isinstance(rid, str) or not re.fullmatch(pattern, rid, re.I):
        raise ValueError('foreign or malformed storage backup ARM identity')
    return rid


def _project(row, rid, operation, version):
    parts = re.split('/providers/', rid, flags=re.I)[-1].split('/')
    native_type = '/'.join([parts[0], *parts[1::2]])
    names=(rid.rsplit('/',1)[-1].casefold(),'/'.join(parts[2::2]).casefold())
    if 'name' in row and str(row['name']).casefold() not in names:
        raise ValueError('native backup resource name contradicts request identity')
    if 'type' in row and str(row['type']).casefold() != native_type.casefold():
        raise ValueError('native backup resource type contradicts request identity')
    props = row.get('properties')
    if not isinstance(props, dict):
        raise ValueError('storage backup properties missing')
    # All fields used to decide resource configuration are preserved. Free-form
    # tags, customer metadata, descriptions and service error messages are not.
    selected = {k: copy.deepcopy(props[k]) for k in (
        'provisioningState', 'currentProtectionState', 'dataSourceInfo', 'policyInfo',
        'dataProtection', 'enabled', 'accessTier', 'enabledProtocols', 'shareQuota',
    ) if k in props}
    if operation == 'Volumes_List':
        for key in ('subnetId', 'protocolTypes'):
            if key in props:
                selected[key] = copy.deepcopy(props[key])
        policy = props.get('exportPolicy')
        if isinstance(policy, dict):
            rules = policy.get('rules')
            selected['exportPolicy'] = {'rules': [
                {key: rule[key] for key in ('ruleIndex', 'allowedClients', 'nfsv3', 'nfsv41',
                                            'unixReadOnly', 'unixReadWrite', 'kerberos5ReadOnly',
                                            'kerberos5ReadWrite', 'kerberos5iReadOnly',
                                            'kerberos5iReadWrite', 'kerberos5pReadOnly',
                                            'kerberos5pReadWrite') if key in rule}
                if isinstance(rule, dict) else rule for rule in rules]
                if isinstance(rules, list) else rules}
        elif 'exportPolicy' in props:
            selected['exportPolicy'] = policy
    if isinstance(selected.get('dataSourceInfo'), dict):
        selected['dataSourceInfo'] = {k: v for k, v in selected['dataSourceInfo'].items()
            if k in ('resourceID', 'resourceType', 'datasourceType', 'objectType', 'resourceLocation')}
    if isinstance(selected.get('policyInfo'), dict):
        policy = selected['policyInfo']
        selected['policyInfo'] = {k: policy[k] for k in ('policyId', 'policyVersion') if k in policy}
        parameters = policy.get('policyParameters')
        if isinstance(parameters, dict) and 'backupDatasourceParametersList' in parameters:
            entries = parameters['backupDatasourceParametersList']
            selected['policyInfo']['policyParameters'] = {'backupDatasourceParametersList': [
                {k: entry[k] for k in ('objectType', 'containersList') if k in entry}
                if isinstance(entry, dict) else entry for entry in entries] if isinstance(entries, list) else entries}
    if isinstance(selected.get('dataProtection'), dict):
        protection = selected['dataProtection']
        backup = protection.get('backup')
        selected['dataProtection'] = ({'backup': {k: backup[k] for k in ('backupPolicyId', 'backupVaultId', 'policyEnforced') if k in backup}}
            if isinstance(backup, dict) else {'backup': backup} if 'backup' in protection else {})
    result = {'id': rid, 'name': rid.rsplit('/', 1)[-1], 'properties': selected,
              '_provenance': {'read_only': True, 'source_operation': operation,
                              'api_version': version, 'representation': 'full'}}
    if 'type' in row:
        result['type'] = row['type']
    return result


def _blob_selection(instance):
    """An explicit native container list proves selection, never a default."""
    params = instance.get('properties', {}).get('policyInfo', {}).get('policyParameters', {}).get('backupDatasourceParametersList')
    instance['_coverage'] = {'containerSelectionEvidence': {'status': 'not_collected'}}
    instance['containerSelectionEvidence'] = []
    if not isinstance(params, list) or not params:
        return
    if any(not isinstance(p, dict) or p.get('objectType') != 'BlobBackupDatasourceParameters' or
            not isinstance(p.get('containersList'), list) or
            any(not isinstance(name, str) or not re.fullmatch(r'(?:[a-z0-9][a-z0-9-]{1,61}[a-z0-9]|\$(?:root|web|logs))', name)
                for name in p['containersList']) for p in params):
        return
    if not any(p['containersList'] for p in params):
        return
    instance['containerSelectionEvidence'] = [{'backupInstanceId': instance['id'], 'mode': 'Explicit',
        '_provenance': copy.deepcopy(instance['_provenance'])}]
    instance['_coverage']['containerSelectionEvidence'] = {'status': 'collected'}


def collect(reader, request, scopes, wanted):
    requested = set(wanted)
    needed = requested | required_types(requested)
    if not needed & NATIVE_TYPES:
        return
    jobs = []
    for scope in scopes:
        for kind, resource_type, version in (
                ('backup_vault', 'Microsoft.DataProtection/backupVaults', DP_VERSION),
                ('netapp_account', 'Microsoft.NetApp/netAppAccounts', NETAPP_VERSION)):
            if kind not in needed:
                continue
            def fetch(scope=scope, kind=kind, resource_type=resource_type, version=version):
                seen = {}
                for page in reader.pages(request, ARM + scope + '/providers/' + resource_type + '?api-version=' + version):
                    projected = []
                    for raw in page:
                        rid = _identity(raw, scope, r'resourceGroups/[^/?#\x00-\x20]+/providers/' + re.escape(resource_type))
                        row = _project(raw, rid, resource_type + '_ListBySubscription', version)
                        if rid.casefold() in seen and seen[rid.casefold()] != row:
                            raise ValueError('conflicting native backup parent identity')
                        seen[rid.casefold()] = row
                        projected.append(row)
                    yield projected
            jobs.append((kind, scope, resource_type.split('/')[0], fetch))
    reader.run(jobs)

    def children(kind, parent_kind, suffix, version, operation):
        covered = {scope: [] for scope in scopes}
        jobs = []
        for scope in scopes:
            def fetch(scope=scope):
                source = _parent(reader, parent_kind, scope)
                failure, seen = None, {}
                for parent in source['items']:
                    pid = parent['id']
                    try:
                        for page in reader.pages(request, ARM + pid + '/' + suffix + '?api-version=' + version):
                            projected = []
                            for raw in page:
                                rid = _identity(raw, pid, re.escape(suffix))
                                row = _project(raw, rid, operation, version)
                                row['parent_id'] = pid
                                if kind == 'backup_instance':
                                    data_source = row['properties'].get('dataSourceInfo')
                                    source_id = data_source.get('resourceID') if isinstance(data_source, dict) else None
                                    if (not isinstance(source_id, str) or not re.fullmatch(re.escape(scope) +
                                            r'/resourceGroups/[^/?#\x00-\x20]+/providers/[^/?#\x00-\x20]+(?:/[^/?#\x00-\x20]+){2,}', source_id, re.I)):
                                        raise ValueError('foreign or missing backup data source identity')
                                    _blob_selection(row)
                                if rid.casefold() in seen and seen[rid.casefold()] != row:
                                    raise ValueError('conflicting native backup child identity')
                                seen[rid.casefold()] = row
                                projected.append(row)
                            yield projected
                        covered[scope].append(pid)
                    except Exception as exc:
                        if getattr(exc, 'code', '') in ('collection_cancelled', 'deadline_exceeded'):
                            raise
                        failure = exc
                if failure is not None:
                    raise failure
            jobs.append((kind, scope, 'Microsoft.Storage' if kind == 'storage_file_share' else
                         'Microsoft.DataProtection' if kind == 'backup_instance' else 'Microsoft.NetApp', fetch))
        reader.run(jobs)
        for scope in scopes:
            rows = [c for c in reader.collections if c['type'] == kind and c['scope'] == scope]
            if len(rows) == 1:
                rows[0]['covered_parent_ids'] = covered[scope]
                rows[0]['parent_inventory'] = parent_kind

    for kind, parent, suffix, version, operation in (
            ('backup_instance', 'backup_vault', 'backupInstances', DP_VERSION, 'BackupInstances_List'),
            ('storage_file_share', 'storage_account', 'fileServices/default/shares', STORAGE_VERSION, 'FileShares_List'),
            ('netapp_capacity_pool', 'netapp_account', 'capacityPools', NETAPP_VERSION, 'Pools_List'),
            ('netapp_backup_policy', 'netapp_account', 'backupPolicies', NETAPP_VERSION, 'BackupPolicies_List'),
            ('netapp_backup_vault', 'netapp_account', 'backupVaults', NETAPP_VERSION, 'BackupVaults_ListByNetAppAccount'),
            ('netapp_volume', 'netapp_capacity_pool', 'volumes', NETAPP_VERSION, 'Volumes_List')):
        if kind in needed:
            children(kind, parent, suffix, version, operation)
