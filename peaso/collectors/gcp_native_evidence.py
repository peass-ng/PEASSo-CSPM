"""Bounded native SCC and Cloud SQL backup evidence, without workload payloads.

Requires securitycenter.findings.list, securitycenter.notificationConfigs.list
and the existing cloudsql.backupRuns.list/cloudsql.instances.list permissions.
SCC v1 is the global inventory; location-specific v2 findings are not inferred.
Backups with a multi-region location do not prove a separate failure region.
"""
import re
from urllib.parse import urlsplit


# These are independent service APIs, never a second Cloud Asset query. An
# approved type absent from this map makes coverage incomplete, rather than
# silently reducing the approved asset universe.
ASSET_INVENTORIES = {
    'compute.googleapis.com/Instance': 'instance',
    'compute.googleapis.com/Disk': 'disk',
    'compute.googleapis.com/Network': 'network',
    'compute.googleapis.com/Subnetwork': 'subnetwork',
    'compute.googleapis.com/Firewall': 'firewall',
    'compute.googleapis.com/Router': 'router',
    'compute.googleapis.com/BackendService': 'backend_service',
    'compute.googleapis.com/ForwardingRule': 'forwarding_rule',
    'compute.googleapis.com/Image': 'image',
    'compute.googleapis.com/Snapshot': 'snapshot',
    'storage.googleapis.com/Bucket': 'bucket',
    'sqladmin.googleapis.com/Instance': 'sql_instance',
    'run.googleapis.com/Service': 'cloudrun_service',
}
COMPUTE_PATHS = {
    'instance': r'zones/[^/]+/instances', 'disk': r'(?:zones|regions)/[^/]+/disks',
    'network': r'global/networks', 'subnetwork': r'regions/[^/]+/subnetworks',
    'firewall': r'global/firewalls', 'router': r'regions/[^/]+/routers',
    'backend_service': r'(?:global|regions/[^/]+)/backendServices',
    'forwarding_rule': r'(?:global|regions/[^/]+)/forwardingRules',
    'image': r'global/images', 'snapshot': r'global/snapshots',
}


def inventory_dependencies(options):
    policy = options.get('sw51_policy')
    types = policy.get('approved_asset_types') if isinstance(policy, dict) else None
    if not isinstance(types, list) or any(not isinstance(t, str) for t in types):
        return set()
    return {ASSET_INVENTORIES[t] for t in types if t in ASSET_INVENTORIES}


def _asset_name(row, asset_type, scope):
    from .gcp import ReadError
    kind = ASSET_INVENTORIES[asset_type]
    if asset_type.startswith('compute.googleapis.com/'):
        link = row.get('selfLink')
        parsed = urlsplit(link) if isinstance(link, str) else None
        prefix = '/compute/v1/' + scope + '/'
        name = row.get('name')
        if (parsed is None or parsed.scheme != 'https' or parsed.netloc not in
                ('www.googleapis.com', 'compute.googleapis.com') or parsed.query or parsed.fragment or
                not isinstance(name, str) or not re.fullmatch(r'[A-Za-z0-9_-]+', name) or
                not re.fullmatch(re.escape(prefix) + COMPUTE_PATHS[kind] + '/' + re.escape(name), parsed.path) or
                '/..' in parsed.path or '%' in parsed.path):
            raise ReadError('malformed', 'service_asset_compute_identity_unresolved')
        return '//compute.googleapis.com/' + parsed.path[len('/compute/v1/'):]
    name = row.get('name')
    if kind == 'bucket':
        if not isinstance(name, str) or not re.fullmatch(r'[a-z0-9][a-z0-9._-]{1,220}[a-z0-9]', name):
            raise ReadError('malformed', 'service_asset_bucket_identity_unresolved')
        return '//storage.googleapis.com/' + name
    if kind == 'sql_instance':
        if (not isinstance(name, str) or not re.fullmatch(r'[a-z][a-z0-9-]*', name) or
                row.get('project', scope.split('/')[1]) != scope.split('/')[1]):
            raise ReadError('malformed', 'service_asset_sql_identity_unresolved')
        return '//cloudsql.googleapis.com/' + scope + '/instances/' + name
    if kind == 'cloudrun_service':
        if not isinstance(name, str) or not re.fullmatch(re.escape(scope) + r'/locations/[^/]+/services/[^/]+', name):
            raise ReadError('malformed', 'service_asset_run_identity_unresolved')
        return '//run.googleapis.com/' + name
    raise ReadError('unsupported', 'service_asset_type_unsupported')


def _service_inventory_jobs(collector):
    from .gcp import ReadError
    from .gcp_compliance_wave import complete_parent
    if 'asset_service_inventory' not in collector.needed:
        return []
    jobs = []
    for scope in collector.scopes:
        if not scope.startswith('projects/'):
            continue

        def inventory(scope=scope):
            policy = collector.options.get('sw51_policy')
            types = policy.get('approved_asset_types') if isinstance(policy, dict) else None
            if (not isinstance(policy, dict) or policy.get('status') != 'collected' or policy.get('scope') != scope or
                    not isinstance(types, list) or not types or len(types) > 256 or
                    any(not isinstance(t, str) or not t for t in types) or len(set(types)) != len(types)):
                raise ReadError('unavailable', 'service_asset_approved_scope_unresolved')
            if set(types) - ASSET_INVENTORIES.keys():
                raise ReadError('unsupported', 'service_asset_approved_type_unsupported')
            seen = set()
            for asset_type in sorted(types):
                kind = ASSET_INVENTORIES[asset_type]
                parent = complete_parent(collector, kind, scope)
                for request_id in parent['source_requests']:
                    yield [], request_id
                for row in parent['items']:
                    name = _asset_name(row, asset_type, scope)
                    if name in seen:
                        raise ReadError('malformed', 'service_asset_identity_conflict')
                    seen.add(name)
                    requests = row.get('_provenance', {}).get('source_requests', [])
                    if not requests:
                        raise ReadError('malformed', 'service_asset_source_missing')
                    yield [{'name': name, 'assetType': asset_type, 'sourceInventory': kind,
                            'sourceNativeName': row.get('name')}], requests[0]
        jobs.append(('asset_service_inventory', scope, 'independent-service-apis', inventory))
    return jobs


def _timestamp(value):
    from datetime import datetime
    from .gcp import ReadError
    try:
        parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
        if parsed.tzinfo is None:
            raise ValueError('timezone absent')
    except (AttributeError, TypeError, ValueError) as exc:
        raise ReadError('malformed', 'native_evidence_timestamp_invalid') from exc
    return value


def scope_jobs(collector, scope):
    """SCC reads are organizational, exhaustive and never filtered by severity."""
    from .gcp import ReadError
    jobs = _approval_jobs(collector, scope)
    jobs.extend(_asset_history_jobs(collector, scope))
    if 'scc_export' in collector.needed:
        jobs.append(('scc_export', scope, 'securitycenter', lambda: _scc_exports(collector, scope)))
    if not re.fullmatch(r'organizations/[0-9]+', scope):
        return jobs
    for kind, suffix, key in (
            ('scc_finding', 'sources/-/findings', 'listFindingsResults'),
            ('scc_notification_config', 'notificationConfigs', 'notificationConfigs')):
        if kind not in collector.needed:
            continue

        def fetch(kind=kind, suffix=suffix, key=key):
            seen = {}

            def project(row):
                if kind == 'scc_finding':
                    row = row.get('finding')
                    if not isinstance(row, dict):
                        raise ReadError('malformed', 'scc_finding_wrapper_missing')
                    pattern = re.escape(scope) + r'/sources/[^/]+/findings/[^/]+'
                    if (row.get('state') not in ('ACTIVE', 'INACTIVE') or
                            row.get('severity') not in ('HIGH', 'CRITICAL', 'MEDIUM', 'LOW', 'UNSPECIFIED')):
                        raise ReadError('malformed', 'scc_finding_state_or_severity_invalid')
                    result = {k: row[k] for k in ('name', 'state', 'severity', 'createTime') if k in row}
                    _timestamp(result.get('createTime'))
                else:
                    pattern = re.escape(scope) + r'/notificationConfigs/[^/]+'
                    config, topic = row.get('streamingConfig'), row.get('pubsubTopic')
                    if (not isinstance(config, dict) or not isinstance(config.get('filter', ''), str) or
                            not re.fullmatch(r'projects/[A-Za-z0-9._:-]+/topics/[^/]+', topic or '')):
                        raise ReadError('malformed', 'scc_notification_destination_or_filter_invalid')
                    result = {'name': row.get('name'), 'filter': config.get('filter', ''), 'pubsubTopic': topic}
                name = result.get('name')
                if not isinstance(name, str) or not re.fullmatch(pattern, name):
                    raise ReadError('malformed', 'scc_resource_scope_mismatch')
                if name in seen and seen[name] != result:
                    raise ReadError('malformed', 'scc_resource_identity_conflict')
                seen[name] = result
                # Description, sourceProperties, externalUri and resource data
                # can contain customer information and are deliberately omitted.
                return result

            try:
                yield from collector.pages(f'https://securitycenter.googleapis.com/v1/{scope}/{suffix}',
                    scope, key=key, transform=project)
            except ReadError as exc:
                if exc.error.get('reason') == 'SERVICE_DISABLED':
                    # A disabled security API is not evidence of no findings.
                    error = ReadError('unavailable', 'scc_api_disabled', http_status=exc.error.get('http_status'))
                    error.request_id = getattr(exc, 'request_id', None)
                    raise error from exc
                raise

        jobs.append((kind, scope, 'securitycenter', fetch))
    return jobs


def _scc_exports(collector, scope):
    """Metadata-only v1/v2 finding export declarations at each selected scope."""
    from .gcp import ReadError
    locations = collector.options.get('scc_locations', ['global', 'us', 'eu', 'sa'])
    if (not isinstance(locations, list) or not locations or len(locations) > 4 or
            any(location not in {'global', 'us', 'eu', 'sa'} for location in locations)):
        raise ValueError('scc_locations must select global, us, eu or sa')
    seen = {}
    def projected(row, version, location, kind):
        name = row.get('name')
        match = re.fullmatch(r'(projects|folders|organizations)/([^/]+)/(?:locations/(global|us|eu|sa)/)?(notificationConfigs|bigQueryExports)/([^/]+)', name) if isinstance(name, str) else None
        if (not match or match[1] != scope.split('/')[0] or
                (match[2] != scope.split('/')[1] and (not scope.startswith('projects/') or
                 not collector._data_project_matches(scope, match[2]))) or
                match[3] != location or match[4] != kind):
            raise ReadError('malformed', 'scc_export_identity_mismatch')
        if kind == 'notificationConfigs':
            value = row.get('pubsubTopic')
            filter_value = (row.get('streamingConfig') or {}).get('filter')
            destination_kind = 'pubsub'
            if not isinstance(value, str) or not re.fullmatch(r'projects/[^/]+/topics/[^/]+', value):
                raise ReadError('malformed', 'scc_export_destination_invalid')
        else:
            value, filter_value, destination_kind = row.get('dataset'), row.get('filter'), 'bigquery'
            if not isinstance(value, str) or not re.fullmatch(r'projects/[^/]+/datasets/[^/]+', value):
                raise ReadError('malformed', 'scc_export_destination_invalid')
        if filter_value is not None and not isinstance(filter_value, str):
            raise ReadError('malformed', 'scc_export_filter_invalid')
        item = {'name': name, 'destination': value, 'destinationKind': destination_kind,
                'filter': filter_value or '', 'apiVersion': version, 'location': location or 'legacy'}
        if name in seen and seen[name] != item:
            raise ReadError('malformed', 'scc_export_identity_conflict')
        seen[name] = item
        return item
    endpoints = [('v1', None, 'notificationConfigs')]
    endpoints += [('v2', location, kind) for location in dict.fromkeys(locations)
                  for kind in ('notificationConfigs', 'bigQueryExports')]
    for version, location, kind in endpoints:
        parent = scope + ('/locations/' + location if location else '')
        yield from collector.pages(f'https://securitycenter.googleapis.com/{version}/{parent}/{kind}', scope,
            key=kind, page_size_key='pageSize',
            transform=lambda row, version=version, location=location, kind=kind:
                projected(row, version, location, kind))


def _approval_jobs(collector, scope):
    """Read all approval states and typed, project-bound Transparency logs."""
    from datetime import datetime, timedelta
    from urllib.parse import quote
    from .gcp import ReadError
    jobs = []
    if 'access_approval_request' in collector.needed:
        def approvals():
            seen = {}
            def project(row):
                name, resource = row.get('name'), row.get('requestedResourceName')
                match = re.fullmatch(r'projects/([^/]+)/approvalRequests/([^/]+)', name) \
                    if isinstance(name, str) and scope.startswith('projects/') else None
                if match and name != scope + '/approvalRequests/' + match[2]:
                    if not match[1].isdecimal():
                        raise ReadError('malformed', 'approval_request_identity_unresolved')
                    binding = collector._data_project_binding(scope, require_alias=True)
                    if match[1] != binding['project_number']:
                        raise ReadError('malformed', 'approval_request_identity_unresolved')
                    name = scope + '/approvalRequests/' + match[2]
                if (not isinstance(name, str) or not re.fullmatch(re.escape(scope) + r'/approvalRequests/[^/]+', name) or
                        not isinstance(resource, str) or not resource):
                    raise ReadError('malformed', 'approval_request_identity_unresolved')
                result = {k: row[k] for k in ('requestedResourceName', 'requestTime', 'requestedExpiration') if k in row}
                result['name'] = name
                _timestamp(result.get('requestTime')); _timestamp(result.get('requestedExpiration'))
                if 'approve' in row:
                    decision = row['approve']
                    if not isinstance(decision, dict):
                        raise ReadError('malformed', 'approval_decision_malformed')
                    result['approve'] = {k: decision[k] for k in
                        ('approveTime', 'expireTime', 'invalidateTime', 'autoApproved', 'policyApproved') if k in decision}
                    if any(type(decision[k]) is not bool for k in ('autoApproved', 'policyApproved') if k in decision):
                        raise ReadError('malformed', 'approval_decision_policy_flag_invalid')
                    _timestamp(result['approve'].get('approveTime'))
                    _timestamp(result['approve'].get('expireTime'))
                    if 'invalidateTime' in result['approve']:
                        _timestamp(result['approve']['invalidateTime'])
                if name in seen and seen[name] != result:
                    raise ReadError('malformed', 'approval_request_identity_conflict')
                seen[name] = result
                return {**result, '_representation': 'full'}
            yield from collector.pages(f'https://accessapproval.googleapis.com/v1/{scope}/approvalRequests',
                scope, key='approvalRequests', params={'filter': 'ALL'}, transform=project)
        jobs.append(('access_approval_request', scope, 'accessapproval', approvals))
    if 'provider_access_event' in collector.needed and scope.startswith('projects/'):
        def events():
            policy = collector.options.get('sw55_policy')
            window = policy.get('log_coverage') if isinstance(policy, dict) else None
            if (not isinstance(policy, dict) or policy.get('scope') != scope or policy.get('status') != 'collected' or
                    not isinstance(window, dict) or window.get('status') != 'collected'):
                raise ReadError('unavailable', 'provider_access_window_unresolved')
            start_text, end_text = _timestamp(window.get('start')), _timestamp(window.get('end'))
            start, end = (datetime.fromisoformat(v.replace('Z', '+00:00')) for v in (start_text, end_text))
            if not start < end <= datetime.fromisoformat(collector.read_time) or end - start > timedelta(days=31):
                raise ReadError('unavailable', 'provider_access_window_invalid_or_unbounded')
            start_text, end_text = start.isoformat(), end.isoformat()
            log = scope + '/logs/cloudaudit.googleapis.com%2Faccess_transparency'
            expression = f'logName="{log}" AND timestamp>="{start_text}" AND timestamp<"{end_text}"'
            body = {'resourceNames': [scope], 'filter': expression, 'orderBy': 'timestamp desc',
                    'pageSize': min(collector.page_size, 1000)}
            seen = {}
            for page, request_id in collector.pages('https://logging.googleapis.com/v2/entries:list', scope,
                    key='entries', method='POST', page_size_key=None, body=body):
                if not page:
                    yield [], request_id
                for row in page:
                    projected = []
                    payload, insert = row.get('jsonPayload'), row.get('insertId')
                    if (row.get('logName') != log or not isinstance(insert, str) or not insert or len(insert) > 1024 or
                            not isinstance(payload, dict) or
                            payload.get('@type') != 'type.googleapis.com/google.cloud.audit.TransparencyLog'):
                        raise ReadError('malformed', 'provider_access_log_identity_or_type_unverified')
                    at_text = _timestamp(row.get('timestamp'))
                    at = datetime.fromisoformat(at_text.replace('Z', '+00:00'))
                    if not start <= at < end:
                        raise ReadError('malformed', 'provider_access_log_outside_window')
                    accesses = payload.get('accesses')
                    approvals = payload.get('accessApprovals', [])
                    if (not isinstance(accesses, list) or not accesses or len(accesses) > 256 or
                            any(not isinstance(a, dict) for a in accesses) or not isinstance(approvals, list) or
                            any(not isinstance(a, str) or not re.fullmatch(re.escape(scope) + r'/approvalRequests/[^/]+', a)
                                for a in approvals) or len(approvals) != len(set(approvals))):
                        raise ReadError('malformed', 'provider_access_scope_or_approval_join_unresolved')
                    for ordinal, access in enumerate(accesses):
                        resource = access.get('resourceName')
                        match = re.fullmatch(r'//([a-z0-9.-]+\.googleapis\.com)/(.*)', resource or '')
                        if (match is None or not (match[2] == scope or match[2].startswith(scope + '/')) or
                                not isinstance(access.get('methodName'), str) or not access['methodName']):
                            raise ReadError('unavailable', 'provider_access_service_or_resource_unresolved')
                        item = {'name': log + '/entries/' + quote(insert, safe='') + '/accesses/' + str(ordinal),
                                'timestamp': at_text, 'serviceName': match[1], 'resourceName': match[2],
                                'principal': 'Google personnel (individual identity not disclosed)',
                                'principalIdentityDisclosed': False, 'provider_access': True,
                                'classificationSource': 'google.cloud.audit.TransparencyLog',
                                'approvalRequests': approvals}
                        if item['name'] in seen and seen[item['name']] != item:
                            raise ReadError('malformed', 'provider_access_log_identity_conflict')
                        seen[item['name']] = item
                        projected.append(item)
                    yield projected, request_id
        jobs.append(('provider_access_event', scope, 'logging', events))
    return jobs


def _audit_window(collector, scope):
    from datetime import datetime, timedelta
    from .gcp import ReadError
    policy = collector.options.get('sw51_policy')
    window = policy.get('audit_window') if isinstance(policy, dict) else None
    if (not isinstance(policy, dict) or policy.get('status') != 'collected' or policy.get('scope') != scope or
            not isinstance(window, dict)):
        raise ReadError('unavailable', 'asset_history_approved_window_unresolved')
    start, end = (datetime.fromisoformat(_timestamp(window.get(k)).replace('Z', '+00:00')) for k in ('start', 'end'))
    now = datetime.fromisoformat(collector.read_time)
    if not now - timedelta(days=35) <= start < end <= now:
        raise ReadError('unavailable', 'asset_history_window_outside_native_retention')
    return start, end


def asset_pages(collector, scope, kind, params):
    """Verify every returned CAI page acknowledges the exact as-of timestamp."""
    from datetime import datetime
    from .gcp import ReadError
    params = dict(params)
    strict = kind == 'asset_previous' or 'asset_previous' in collector.needed
    if strict:
        try:
            start, end = _audit_window(collector, scope)
            params['readTime'] = (start if kind == 'asset_previous' else end).isoformat()
        except ReadError:
            if kind == 'asset_previous':
                raise
            strict = False
    expected = datetime.fromisoformat(params['readTime'].replace('Z', '+00:00'))
    aliases = {scope.split('/')[1]}
    if strict:
        for page, request_id in collector.pages('https://cloudresourcemanager.googleapis.com/v3/' + scope,
                scope, single=True, params={'fields': 'name,projectId'}):
            binding = page[0]
            number, project_id = binding.get('name'), binding.get('projectId')
            if (not isinstance(number, str) or not re.fullmatch(r'projects/[0-9]+', number) or
                    not isinstance(project_id, str) or not re.fullmatch(r'[a-z][a-z0-9-]+', project_id) or
                    scope.split('/')[1] not in (number.split('/')[1], project_id)):
                raise ReadError('malformed', 'asset_history_project_binding_unresolved')
            aliases = {number.split('/')[1], project_id}
            collector.native_asset_bindings[scope] = {'aliases': aliases, 'project_id': project_id, 'request_id': request_id}
            yield [], request_id
    key = kind, scope
    def acknowledge(data):
        value = data.get('readTime')
        if value is None and not strict:
            collector.native_asset_times[key] = None
            return
        actual = datetime.fromisoformat(_timestamp(value).replace('Z', '+00:00'))
        if actual != expected:
            raise ReadError('malformed', 'asset_history_response_time_mismatch')
        if strict:
            for row in data.get('assets', []):
                name = row.get('name') if isinstance(row, dict) else None
                if not isinstance(name, str) or not name.startswith('//'):
                    raise ReadError('malformed', 'asset_history_resource_identity_unresolved')
                match = re.match(r'//[^/]+/projects/([^/]+)(?:/|$)', name)
                if match and match[1] not in aliases:
                    raise ReadError('malformed', 'asset_history_foreign_project')
        if key not in collector.native_asset_times or collector.native_asset_times[key] is not None:
            collector.native_asset_times[key] = value
    yield from collector.pages(f'https://cloudasset.googleapis.com/v1/{scope}/assets', scope,
        key='assets', params=params, response_validator=acknowledge)


def _asset_history_jobs(collector, scope):
    from datetime import datetime
    from urllib.parse import quote
    from .gcp import ReadError
    if not scope.startswith('projects/'):
        return []
    jobs = []
    if 'asset_previous' in collector.needed:
        def previous():
            params = {'contentType': 'RESOURCE', 'readTime': collector.read_time}
            types = collector.options.get('asset_types')
            if types:
                if not isinstance(types, list) or len(types) > 100 or any(not isinstance(t, str) for t in types):
                    raise ReadError('malformed', 'asset_history_type_selection_invalid')
                params['assetTypes'] = types
            yield from asset_pages(collector, scope, 'asset_previous', params)
        jobs.append(('asset_previous', scope, 'cloudasset', previous))
    if 'asset_audit_log' in collector.needed:
        def events():
            start, end = _audit_window(collector, scope)
            log = scope + '/logs/cloudaudit.googleapis.com%2Factivity'
            body = {'resourceNames': [scope], 'filter': f'logName="{log}" AND timestamp>="{start.isoformat()}" AND timestamp<="{end.isoformat()}"',
                    'orderBy': 'timestamp desc', 'pageSize': min(collector.page_size, 1000)}
            types = collector.options.get('asset_types')
            if (isinstance(types, list) and types and all(isinstance(t, str) and
                    re.fullmatch(r'[a-z0-9.-]+\.googleapis\.com/[A-Za-z0-9]+', t) for t in types)):
                # The CAI snapshots use this exact type selection. Unrelated
                # service logs cannot establish a change to those assets.
                services = sorted({('cloudsql.googleapis.com' if t.startswith('sqladmin.googleapis.com/')
                                    else t.split('/')[0]) for t in types})
                body['filter'] += ' AND (' + ' OR '.join('protoPayload.serviceName="' + s + '"' for s in services) + ')'
            seen = {}
            def project(row):
                payload, insert = row.get('protoPayload'), row.get('insertId')
                if (row.get('logName') != log or not isinstance(insert, str) or not insert or len(insert) > 1024 or
                        not isinstance(payload, dict) or payload.get('@type') != 'type.googleapis.com/google.cloud.audit.AuditLog'):
                    raise ReadError('malformed', 'asset_audit_native_type_or_identity_unresolved')
                service, resource, method = (payload.get(k) for k in ('serviceName', 'resourceName', 'methodName'))
                if (not isinstance(service, str) or not re.fullmatch(r'[a-z0-9.-]+\.googleapis\.com', service) or
                        not isinstance(resource, str) or not resource or not isinstance(method, str) or not method):
                    raise ReadError('unavailable', 'asset_audit_resource_join_unresolved')
                if resource.startswith('//'):
                    if not resource.startswith('//' + service + '/'):
                        raise ReadError('malformed', 'asset_audit_resource_service_mismatch')
                    full_name = resource
                elif service == 'storage.googleapis.com' and resource.startswith('projects/_/buckets/'):
                    full_name = '//' + service + '/' + resource[len('projects/_/buckets/'):]
                else:
                    full_name = '//' + service + '/' + resource
                at = datetime.fromisoformat(_timestamp(row.get('timestamp')).replace('Z', '+00:00'))
                if not start <= at <= end:
                    raise ReadError('malformed', 'asset_audit_event_outside_window')
                status = payload.get('status', {})
                if not isinstance(status, dict) or type(status.get('code', 0)) is not int:
                    raise ReadError('malformed', 'asset_audit_operation_status_unresolved')
                operation = row.get('operation')
                if operation is not None and (not isinstance(operation, dict) or
                        any(type(operation[k]) is not bool for k in ('first', 'last') if k in operation)):
                    raise ReadError('malformed', 'asset_audit_operation_completion_unresolved')
                succeeded = status.get('code', 0) == 0 and (operation is None or operation.get('last') is True)
                result = {'name': log + '/entries/' + quote(insert, safe=''), 'logName': log,
                          'timestamp': row['timestamp'], 'operationSucceeded': succeeded,
                          'protoPayload': {'serviceName': service, 'resourceName': full_name, 'methodName': method}}
                if result['name'] in seen and seen[result['name']] != result:
                    raise ReadError('malformed', 'asset_audit_event_identity_conflict')
                seen[result['name']] = result
                return result
            yield from collector.pages('https://logging.googleapis.com/v2/entries:list', scope,
                key='entries', method='POST', page_size_key=None, body=body, transform=project)
        jobs.append(('asset_audit_log', scope, 'logging', events))
    return jobs


def dependent(collector):
    """Project observed backup destinations only after complete parent reads."""
    from .gcp import ReadError
    from .gcp_compliance_wave import complete_parent
    for key, read_time in collector.native_asset_times.items():
        if read_time and key in collector.collections:
            collector.collections[key]['readTime'] = read_time
    _normalize_asset_audit_joins(collector)
    jobs = _service_inventory_jobs(collector)
    for scope in collector.scopes if 'backup_target' in collector.needed else ():
        if not scope.startswith('projects/'):
            continue

        def targets(scope=scope):
            instances = complete_parent(collector, 'sql_instance', scope)
            backups = complete_parent(collector, 'sql_backup_run', scope)
            names = {row.get('name') for row in instances['items']}
            for request_id in sorted(set(instances['source_requests'] + backups['source_requests'])):
                yield [], request_id
            for row in backups['items']:
                if row.get('instanceName') not in names:
                    raise ReadError('malformed', 'backup_target_instance_join_mismatch')
                if row.get('status') != 'SUCCESSFUL':
                    continue
                location = row.get('location')
                # Multi-regions (us/eu/asia) can include the source region; a
                # mere unequal string is not proof of geographic separation.
                if not isinstance(location, str) or not re.fullmatch(r'[a-z]+(?:-[a-z]+)+[0-9]+', location):
                    raise ReadError('unavailable', 'backup_failure_region_unresolved')
                _timestamp(row.get('endTime'))
                requests = row.get('_provenance', {}).get('source_requests', [])
                if not requests:
                    raise ReadError('malformed', 'backup_target_source_missing')
                yield [{'name': row['name'] + '/destination', 'sourceInstance': row['instanceName'],
                        'failureRegion': location, 'backupRun': row['name'], 'observedEndTime': row['endTime']}], requests[0]
        jobs.append(('backup_target', scope, 'sqladmin', targets))
    collector.run_jobs(jobs)


def _normalize_asset_audit_joins(collector):
    """Use Resource Manager's verified project ID/number equivalence only.

    Raw CAI names are retained. Audit resource references are projected to the
    one observed CAI spelling; the original reference and binding request remain
    attached. Conflicting CAI aliases are incomplete evidence, never two assets
    supposedly proven by the same guessed match.
    """
    for scope, binding in collector.native_asset_bindings.items():
        audit = collector.collections.get(('asset_audit_log', scope))
        parents = [collector.collections.get((kind, scope)) for kind in ('asset', 'asset_previous')]
        if (not audit or audit['coverage_status'] not in ('collected', 'empty') or
                any(not parent or parent['coverage_status'] not in ('collected', 'empty') for parent in parents)):
            continue
        def canonical(name):
            match = re.match(r'(//[^/]+/projects/)([^/]+)(/.*|$)', name)
            if match and match[2] in binding['aliases']:
                return match[1] + binding['project_id'] + match[3]
            return name
        observed = {}
        for parent in parents:
            for row in parent['items']:
                name = row.get('name')
                if isinstance(name, str):
                    observed.setdefault(canonical(name), set()).add(name)
        for row in audit['items']:
            original = row['protoPayload']['resourceName']
            matches = observed.get(canonical(original), set())
            if len(matches) > 1:
                audit['status'] = 'partial' if audit['items'] else 'unknown'
                audit['coverage_status'] = 'partial' if audit['items'] else 'unavailable'
                audit['error'] = {'kind': 'unavailable', 'code': 'asset_history_alias_identity_conflict'}
                break
            if len(matches) == 1 and original not in matches:
                row['sourceResourceName'] = original
                row['protoPayload']['resourceName'] = next(iter(matches))
                row['_provenance']['source_requests'] = sorted(set(row['_provenance']['source_requests'] + [binding['request_id']]))
                audit['source_requests'] = sorted(set(audit['source_requests'] + [binding['request_id']]))
