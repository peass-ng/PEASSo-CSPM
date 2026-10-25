"""Read-only project inventories for the sw08/sw09 compliance evaluators.

Additional read permissions: cloudkms.cryptoKeyVersions.list,
logging.buckets.list, cloudsql.users.list, serviceusage.services.list,
certificatemanager.certificates.list, cloudasset.assets.searchAllResources,
compute.autoscalers.list and networksecurity.serverTlsPolicies.get.
Location discovery also needs the corresponding service locations.list.
HTTPS proxies reuse compute.targetHttpsProxies.list / regional list coverage
from the existing aggregated inventory; no proxy is fetched twice.
"""
from urllib.parse import quote
import re
from datetime import datetime, timedelta


def project_log_entry(row, scope, project_aliases=None):
    """Audit metadata only; omitted/redacted actors remain unclassified.

    No request/response/text/JSON payload or caller credentials survive. An
    observed row is not a claim about log retention or unobserved events.
    """
    from .gcp import ReadError
    log, insert = row.get('logName'), row.get('insertId')
    prefix = scope + '/logs/cloudaudit.googleapis.com%2F'
    if (not isinstance(log, str) or log not in (prefix + 'activity', prefix + 'data_access', prefix + 'policy')
            or not isinstance(insert, str) or not insert or len(insert) > 1024):
        raise ReadError('malformed', 'audit_metadata_identity_mismatch')
    payload = row.get('protoPayload')
    if not isinstance(payload, dict) or payload.get('@type') != 'type.googleapis.com/google.cloud.audit.AuditLog':
        raise ReadError('malformed', 'audit_metadata_payload_type_mismatch')
    resource = row.get('resource', {})
    if (not isinstance(resource, dict) or not isinstance(resource.get('labels', {}), dict)
            or not isinstance(resource.get('type'), str) or not resource['type'].strip()):
        raise ReadError('malformed', 'audit_metadata_resource_malformed')
    project = resource.get('labels', {}).get('project_id')
    if project is not None and project not in (project_aliases or {scope.split('/')[1]}):
        raise ReadError('malformed', 'audit_metadata_foreign_project')
    auth = payload.get('authenticationInfo')
    principal = auth.get('principalEmail') if isinstance(auth, dict) else None
    projected = {'name': log + '/entries/' + quote(insert, safe=''), 'logName': log, 'insertId': insert,
                 'resource': {'type': resource['type']},
                 'eventClass': 'authenticated_audit' if isinstance(principal, str) and principal.strip() else 'unclassified_audit',
                 'protoPayload': {key: data for key, data in payload.items() if key in ('@type', 'serviceName', 'methodName')},
                 'auditCoverage': {'absence_proves_no_event': False, 'retention_verified': False, 'representation': 'metadata'}}
    if 'timestamp' in row: projected['timestamp'] = row['timestamp']
    if isinstance(auth, dict):
        projected['protoPayload']['authenticationInfo'] = {key: data for key, data in auth.items() if key == 'principalEmail'}
    return projected


def event_jobs(collector, scope):
    if 'log_entry' not in collector.needed or not scope.startswith('projects/'):
        return []
    from .gcp import bound
    minutes = bound(collector.options, 'log_entry_minutes', 60, 1, 1440)
    end = datetime.fromisoformat(collector.read_time)
    start = end - timedelta(minutes=minutes)
    logs = [scope + '/logs/cloudaudit.googleapis.com%2F' + kind for kind in ('activity', 'data_access', 'policy')]
    expression = '(' + ' OR '.join('logName="' + log + '"' for log in logs) + ')'
    expression += f' AND timestamp>="{start.isoformat()}" AND timestamp<"{end.isoformat()}"'
    body = {'resourceNames': [scope], 'filter': expression, 'orderBy': 'timestamp desc', 'pageSize': min(collector.page_size, 1000)}
    def fetch():
        from .gcp import ReadError
        aliases = None
        for page, request_id in collector.pages('https://cloudresourcemanager.googleapis.com/v3/' + scope,
                scope, single=True, params={'fields': 'name,projectId'}):
            if len(page) != 1:
                raise ReadError('malformed', 'audit_project_binding_missing')
            project = page[0]
            name, project_id = project.get('name'), project.get('projectId')
            if (not isinstance(name, str) or not re.fullmatch(r'projects/[0-9]+', name)
                    or not isinstance(project_id, str) or not re.fullmatch(r'[a-z][a-z0-9-]+', project_id)
                    or scope.split('/')[1] not in (name.split('/')[1], project_id)):
                raise ReadError('malformed', 'audit_project_binding_mismatch')
            aliases = {name.split('/')[1], project_id}
            yield [], request_id
        if aliases is None:
            raise ReadError('malformed', 'audit_project_binding_missing')
        yield from collector.pages('https://logging.googleapis.com/v2/entries:list', scope,
            key='entries', method='POST', page_size_key=None, body=body,
            transform=lambda row: project_log_entry(row, scope, aliases))
    return [('log_entry', scope, 'logging', fetch)]


def complete_parent(collector, kind, scope):
    from .gcp import ReadError
    parent = collector.collections.get((kind, scope))
    if not parent or parent['coverage_status'] not in ('collected', 'empty'):
        raise ReadError('unavailable', kind + '_inventory_incomplete')
    return parent


def located(collector, scope, service, version, segment, key, option):
    """All selected/discovered locations, with failures retained as incomplete."""
    from .gcp import ReadError
    locations = collector.options.get(option, collector.options.get('regions'))
    if locations is None:
        locations = []
        for page, request_id in collector.pages(
                f'https://{service}.googleapis.com/{version}/{scope}/locations', scope, key='locations'):
            locations.extend(row.get('locationId') or row.get('name', '').rsplit('/', 1)[-1] for row in page)
            yield [], request_id
    if (not isinstance(locations, list) or not locations or len(locations) > 100 or
            any(not isinstance(x, str) or not re.fullmatch(r'[a-z0-9-]+', x) for x in locations)):
        raise ReadError('unavailable', 'location_coverage_unresolved')
    from .gcp_fanout import location_fanout

    def location_pages(location):
        prefix = f'{scope}/locations/{location}/{segment}/'
        def checked(item):
            if not isinstance(item.get('name'), str) or not item['name'].startswith(prefix):
                raise ReadError('malformed', 'location_resource_identity_mismatch')
            return {**item, '_representation': 'full'}
        return collector.pages(
            f'https://{service}.googleapis.com/{version}/{scope}/locations/{location}/{segment}',
            scope, key=key, transform=checked)
    failures = []
    for _location, pages, exc in location_fanout(collector, dict.fromkeys(locations), location_pages):
        yield from pages
        if exc is not None:
            if getattr(exc, 'request_id', None):
                yield [], exc.request_id
            failures.append(exc)
    if failures:
        raise failures[0]


def sql_instances(collector, scope, project):
    from .gcp import ReadError, wire_status
    binding = collector._data_project_binding(scope)
    project = binding['project_id']
    base = f'https://sqladmin.googleapis.com/sql/v1beta4/projects/{project}/instances'

    def hydrate(instance):
        collector._data_sql_identity(scope, instance)
        name = instance.get('name')
        if not isinstance(name, str) or not name:
            raise ReadError('malformed', 'sql_instance_identity_missing')
        seen_users = set()
        def project_user(row):
            username, host = row.get('name'), row.get('host', '')
            if not isinstance(username, str) or not username or not isinstance(host, str):
                raise ReadError('malformed', 'sql_user_identity_missing')
            # The API may omit these URL-bound fields. Explicit contradictory
            # values cannot be rewritten into the requested instance identity.
            for field, expected in (('instance', name), ('instanceId', name), ('userName', username)):
                if field in row and (not isinstance(row[field], str) or row[field] != expected):
                    raise ReadError('malformed', f'sql_user_{field}_mismatch')
            if 'project' in row and not collector._data_project_matches(scope, row['project']):
                raise ReadError('malformed', 'sql_user_project_mismatch')
            # Envelope identity de-duplicates rows. A repeated raw account,
            # even with different authentication or policy fields, cannot
            # certify a complete user inventory.
            identity = (username, host)
            if identity in seen_users:
                raise ReadError('malformed', 'sql_user_duplicate_identity')
            seen_users.add(identity)
            return {**row, 'userName': username, 'instanceId': name,
                    'name': f'{scope}/instances/{name}/users/{quote(username, safe="")}@{quote(host, safe="")}'}
        def validate_user_response(data):
            if ('kind' in data and data['kind'] != 'sql#usersList'
                    or 'items' not in data and data.get('kind') != 'sql#usersList'):
                raise ReadError('malformed', 'sql_users_response_shape_invalid')
        envelope = collector.envelope('sql_user', scope, 'sqladmin', lambda: collector.pages(
            f'{base}/{quote(name, safe="")}/users', scope, page_size_key=None, transform=project_user,
            response_validator=validate_user_response))
        detail = {'status': 'collected' if envelope['coverage_status'] in ('collected', 'empty') else envelope['coverage_status'],
                  'instance': name, 'items': [{**row, 'name': row['userName']} for row in envelope['items']],
                  'source_requests': envelope['source_requests']}
        if envelope.get('error'):
            detail['error'] = envelope['error']
        return {**instance, 'usersList': detail,
                '_coverage': {'usersList': {'status': detail['status'],
                    'collection_status': wire_status(detail['status']), 'source_requests': envelope['source_requests']}}}
    for page, request_id in collector.pages(base, scope, page_size_key='maxResults'):
        yield collector.parallel(hydrate, page), request_id


def normalize_os_inventory(data, scope, instance, expected_name):
    """Project the FULL OS Config package map without guessing unknown packages."""
    from .gcp import ReadError
    native_name = data.get('name')
    suffix = expected_name.split('/locations/', 1)[-1]
    if (not isinstance(native_name, str) or not re.fullmatch(r'projects/[A-Za-z0-9._:-]+/locations/' +
            re.escape(suffix), native_name) or not isinstance(data.get('updateTime'), str)):
        raise ReadError('malformed', 'os_inventory_identity_or_time_missing')
    source = data.get('items')
    if not isinstance(source, dict):
        raise ReadError('malformed', 'os_inventory_full_items_missing')
    packages = []
    for entry in source.values():
        if not isinstance(entry, dict):
            raise ReadError('malformed', 'os_inventory_item_malformed')
        if entry.get('type') not in ('INSTALLED_PACKAGE', 'AVAILABLE_PACKAGE'):
            raise ReadError('unavailable', 'os_inventory_item_type_unresolved')
        if entry.get('type') != 'INSTALLED_PACKAGE':
            continue
        installed = entry.get('installedPackage')
        if not isinstance(installed, dict):
            raise ReadError('malformed', 'os_inventory_installed_package_missing')
        candidates = [installed.get(key) for key in ('aptPackage', 'yumPackage', 'zypperPackage', 'googetPackage')
                      if key in installed]
        if len(candidates) != 1 or not isinstance(candidates[0], dict):
            raise ReadError('unavailable', 'os_inventory_package_type_unresolved')
        package = candidates[0]
        name, version = package.get('packageName'), package.get('version')
        if not isinstance(name, str) or not name or not isinstance(version, str) or not version:
            raise ReadError('malformed', 'os_inventory_package_identity_missing')
        projected = {'name': name, 'version': version}
        # An item observation time is not an installation time. Only a native
        # installTime can satisfy the patch-deployment evaluator.
        if isinstance(entry.get('installTime'), str):
            projected['installTime'] = entry['installTime']
        packages.append(projected)
    return {'name': native_name, 'instanceName': instance, 'updateTime': data['updateTime'],
            'items': {'installedPackages': packages}, '_representation': 'full'}


def dependent(collector):
    from .gcp import ReadError
    jobs = []
    for scope in collector.scopes:
        if not scope.startswith('projects/'):
            continue
        if 'dns_record' in collector.needed:
            from .gcp_history import dns_records
            jobs.append(('dns_record', scope, 'dns', lambda scope=scope: dns_records(collector, scope)))
        if 'sql_operation' in collector.needed:
            from .gcp_history import sql_operations
            jobs.append(('sql_operation', scope, 'sqladmin', lambda scope=scope: sql_operations(collector, scope)))
        if 'alert_policy' in collector.needed:
            def alert_policies(scope=scope):
                parent = complete_parent(collector, 'monitoring_alert_policy', scope)
                for request_id in parent['source_requests']:
                    yield [], request_id
                for row in parent['items']:
                    requests = row.get('_provenance', {}).get('source_requests', [])
                    if not requests:
                        raise ReadError('malformed', 'alert_policy_source_missing')
                    yield [{**row, '_representation': 'full'}], requests[0]
            jobs.append(('alert_policy', scope, 'monitoring', alert_policies))
        if 'sql_backup_run' in collector.needed:
            def backup_runs(scope=scope):
                parent = complete_parent(collector, 'sql_instance', scope)
                project = quote(scope.split('/', 1)[1], safe='')
                failures = []
                for instance in parent['items']:
                    name = instance.get('name')
                    if not isinstance(name, str) or not name or '/' in name:
                        raise ReadError('malformed', 'sql_instance_identity_missing')
                    def normalize(row, name=name):
                        backup_id = row.get('id')
                        if backup_id is None or not re.fullmatch(r'[0-9]+', str(backup_id)):
                            raise ReadError('malformed', 'sql_backup_run_identity_missing')
                        if row.get('instance') not in (None, name):
                            raise ReadError('malformed', 'sql_backup_run_parent_mismatch')
                        return {**row, 'name': f'{scope}/instances/{name}/backupRuns/{backup_id}',
                                'instanceName': name, '_representation': 'full'}
                    try:
                        yield from collector.pages(
                            f'https://sqladmin.googleapis.com/sql/v1beta4/projects/{project}/instances/{quote(name, safe="")}/backupRuns',
                            scope, page_size_key='maxResults', transform=normalize)
                    except ReadError as exc:
                        if getattr(exc, 'request_id', None):
                            yield [], exc.request_id
                        failures.append(exc)
                if failures:
                    raise failures[0]
            jobs.append(('sql_backup_run', scope, 'sqladmin', backup_runs))
        if 'os_inventory' in collector.needed:
            def os_inventories(scope=scope):
                parent = complete_parent(collector, 'instance', scope)
                seen, failures = set(), []
                for vm in parent['items']:
                    instance = vm.get('name')
                    zone = vm.get('zone') or vm.get('_aggregated_scope')
                    zone = zone.rsplit('/', 1)[-1] if isinstance(zone, str) else None
                    if (not isinstance(instance, str) or not re.fullmatch(r'[a-z][a-z0-9-]{0,62}', instance)
                            or not isinstance(zone, str) or not re.fullmatch(r'[a-z0-9-]+', zone)
                            or instance in seen):
                        raise ReadError('malformed', 'os_inventory_vm_join_unresolved')
                    seen.add(instance)
                    instance_id = str(vm.get('id') or instance)
                    if not re.fullmatch(r'[A-Za-z0-9-]+', instance_id):
                        raise ReadError('malformed', 'os_inventory_vm_id_unresolved')
                    expected = f'{scope}/locations/{zone}/instances/{instance_id}/inventory'
                    try:
                        yield from collector.pages(f'https://osconfig.googleapis.com/v1/{expected}', scope,
                            single=True, params={'view': 'FULL'},
                            transform=lambda row, instance=instance, expected=expected:
                                normalize_os_inventory(row, scope, instance, expected))
                    except ReadError as exc:
                        if getattr(exc, 'request_id', None):
                            yield [], exc.request_id
                        failures.append(exc)
                if failures:
                    raise failures[0]
            jobs.append(('os_inventory', scope, 'osconfig', os_inventories))
        if 'kms_key_version' in collector.needed:
            def versions(scope=scope):
                parent = complete_parent(collector, 'kms_key', scope)
                seen, failures = {}, []
                for item in parent['items']:
                    name = item.get('name')
                    if not isinstance(name, str) or not name.startswith(scope + '/locations/'):
                        raise ReadError('malformed', 'kms_parent_identity_missing')
                    def transform(row):
                        identity = row.get('name')
                        if not isinstance(identity, str) or not identity.startswith(name + '/cryptoKeyVersions/'):
                            raise ReadError('malformed', 'kms_version_parent_mismatch')
                        if identity in seen and seen[identity] != row:
                            raise ReadError('malformed', 'kms_version_conflict')
                        seen[identity] = row
                        return {**row, '_representation': 'full'}
                    try:
                        yield from collector.pages(f'https://cloudkms.googleapis.com/v1/{name}/cryptoKeyVersions',
                                                   scope, key='cryptoKeyVersions', transform=transform)
                    except ReadError as exc:
                        if getattr(exc, 'request_id', None):
                            yield [], exc.request_id
                        failures.append(exc)
                if failures:
                    raise failures[0]
            jobs.append(('kms_key_version', scope, 'cloudkms', versions))
        if 'sql_user' in collector.needed:
            def sql_users(scope=scope):
                failures = []
                for instance in complete_parent(collector, 'sql_instance', scope)['items']:
                    detail = instance.get('usersList', {})
                    for request_id in detail.get('source_requests', []):
                        yield [], request_id
                    rows = [{**row, 'name': f'{scope}/instances/{instance["name"]}/users/' +
                             quote(row['userName'], safe='') + '@' + quote(row.get('host', ''), safe='')}
                            for row in detail.get('items', [])]
                    for row in rows:
                        yield [row], row['_provenance']['source_requests'][0]
                    if detail.get('status') != 'collected':
                        failures.append(ReadError(detail.get('status', 'unavailable'),
                            detail.get('error', {}).get('code', 'sql_users_inventory_incomplete')))
                if failures:
                    raise failures[0]
            jobs.append(('sql_user', scope, 'sqladmin', sql_users))
        if 'target_https_proxy' in collector.needed:
            def proxies(scope=scope):
                parent = complete_parent(collector, 'target_proxy', scope)
                rows = [row for row in parent['items'] if row.get('_proxy_type') == 'targetHttpsProxies']
                for request_id in parent['source_requests']:
                    yield [], request_id
                for row in rows:
                    yield [{**row, '_representation': 'full'}], row['_provenance']['source_requests'][0]
            jobs.append(('target_https_proxy', scope, 'compute', proxies))
    collector.run_jobs(jobs)
    jobs = []
    if 'server_tls_policy' in collector.needed:
        for scope in collector.scopes:
            if not scope.startswith('projects/'):
                continue
            # Native network inventory enumerates policies even when no proxy
            # references them. Keep reference hydration for older callers only.
            if ('server_tls_policy', scope) in collector.collections:
                continue
            def policies(scope=scope):
                parent = complete_parent(collector, 'target_https_proxy', scope)
                references = {row.get('serverTlsPolicy') for row in parent['items'] if row.get('serverTlsPolicy')}
                failures = []
                for name in sorted(references):
                    if not isinstance(name, str) or not re.fullmatch(re.escape(scope) + r'/locations/[a-z0-9-]+/serverTlsPolicies/[\w.-]+', name):
                        raise ReadError('unavailable', 'tls_policy_owner_not_selected')
                    try:
                        def checked(row):
                            if row.get('name') != name:
                                raise ReadError('malformed', 'tls_policy_identity_mismatch')
                            return row
                        yield from collector.pages(f'https://networksecurity.googleapis.com/v1/{name}', scope,
                                                   single=True, transform=checked)
                    except ReadError as exc:
                        if getattr(exc, 'request_id', None):
                            yield [], exc.request_id
                        failures.append(exc)
                if failures:
                    raise failures[0]
            jobs.append(('server_tls_policy', scope, 'networksecurity', policies))
    collector.run_jobs(jobs)


def policy_metadata(options, scopes):
    """Preserve explicitly supplied project-bound owner decisions; infer none."""
    result = {}
    for key in ('compliance_policy', 'sw09_policy', 'sw51_policy', 'sw52', 'sw55_policy'):
        value = options.get(key)
        if value is None:
            continue
        if not isinstance(value, dict) or value.get('status') != 'collected' or value.get('scope') not in scopes:
            raise ValueError(key + ' must be collected and bound to a selected project')
        if key not in ('sw55_policy', 'compliance_policy') and not value['scope'].startswith('projects/'):
            raise ValueError(key + ' requires project scope')
        if key in ('sw51_policy', 'sw52', 'sw55_policy'):
            result[key] = value
            continue
        for field, entry in value.items():
            if key == 'sw09_policy' and field in ('topology_register', 'approved_iam_roster'):
                if not isinstance(entry, list) or any(not isinstance(row, dict) for row in entry):
                    raise ValueError(field + ' must be a list of approved records')
                continue
            if isinstance(entry, list) and (any(not isinstance(x, str) or not x for x in entry) or len(entry) != len(set(entry))):
                raise ValueError(key + '.' + field + ' must contain unique nonempty strings')
            if field in ('max_artifact_age',) and (type(entry) is not int or entry <= 0):
                raise ValueError(field + ' must be a positive integer')
        result[key] = value
    if 'MinRetentionTime' in options:
        value = options['MinRetentionTime']
        if type(value) is not int or value <= 0:
            raise ValueError('MinRetentionTime must be a positive integer')
        result['MinRetentionTime'] = value
    return result
