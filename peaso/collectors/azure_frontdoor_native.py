"""Scope-bound Front Door/CDN metadata, shared by the reviewed edge checks.

Conditional rule engines are retained as unresolved; origin ports never prove
an effective forwarding protocol. No keys, request samples or backend calls.
"""
from copy import deepcopy
from fnmatch import fnmatchcase
import re
from urllib.parse import urlencode, urlsplit

ARM = 'https://management.azure.com'
CDN_VERSION = '2025-04-15'
ORIGIN_GROUP_VERSION = '2026-07-01'
CLASSIC_VERSION = '2021-06-01'
DERIVED_TYPES = ('frontdoor_and_cdn_endpoint', 'afd_profile', 'afd_domain', 'afd_route', 'afd_security_policy')
PARENT_TYPES = {'cdn_profile', 'frontdoor'}


def metadata_projection(value):
    """Retain declared edge configuration; drop header values and free text."""
    result = {key: deepcopy(data) for key, data in value.items()
              if key in ('id', 'name', 'type', 'location', 'sku', 'identity', '_provenance')}
    if not value.get('type') and isinstance(value.get('id'), str):
        parts = re.split('/providers/', value['id'], flags=re.I)[-1].split('/')
        result['type'] = '/'.join([parts[0], *parts[1::2]])
        result.setdefault('_provenance', {})['type_source'] = 'native_resource_path'
    kind = str(result.get('type', '')).casefold().rsplit('/', 1)[-1]
    fields = {
        'frontdoors': ('frontendEndpoints', 'routingRules', 'backendPools', 'enabledState', 'provisioningState'),
        'profiles': ('provisioningState', 'originResponseTimeoutSeconds'),
        'frontendendpoints': ('hostName', 'customHttpsProvisioningState', 'customHttpsConfiguration', 'webApplicationFirewallPolicyLink'),
        'customdomains': ('hostName', 'customHttpsProvisioningState', 'customHttpsParameters', 'tlsSettings', 'domainValidationState', 'provisioningState', 'deploymentStatus'),
        'routes': ('supportedProtocols', 'forwardingProtocol', 'httpsRedirect', 'patternsToMatch', 'customDomains', 'linkToDefaultDomain', 'ruleSets', 'originGroup', 'originPath', 'enabledState', 'provisioningState', 'deploymentStatus'),
        'routingrules': ('acceptedProtocols', 'frontendEndpoints', 'enabledState', 'patternsToMatch', 'rulesEngine', 'routeConfiguration'),
        'afdendpoints': ('hostName', 'enabledState', 'provisioningState', 'deploymentStatus'),
        'endpoints': ('hostName', 'resourceState', 'enabledState', 'isHttpAllowed', 'isHttpsAllowed', 'provisioningState'),
        'origingroups': ('healthProbeSettings', 'authentication', 'provisioningState'),
        'origins': ('hostName', 'enabledState', 'sharedPrivateLinkResource', 'azureOrigin', 'provisioningState'),
        'securitypolicies': ('parameters', 'provisioningState', 'deploymentStatus'),
        'diagnosticsettingscategories': ('categoryType', 'categoryGroups'),
        'diagnosticsettings': ('logs', 'workspaceId', 'storageAccountId'),
        'backendpools': ('backends',),
    }.get(kind)
    props = value.get('properties')
    if not isinstance(props, dict) or fields is None:
        raise ValueError('unsupported native edge representation')
    result['properties'] = {key: deepcopy(props[key]) for key in fields if key in props}
    for field in (('frontendEndpoints', 'routingRules', 'backendPools') if kind == 'frontdoors' else ()):
        if field in result['properties']:
            children = result['properties'][field]
            if not isinstance(children, list):raise ValueError('invalid embedded edge metadata')
            projected, seen = [], {}
            for row in children:
                identity = _identity(row, result['id'], '/' + re.escape(field) + r'/[^/?#%\\\s]+')
                child = metadata_projection(row)
                key = identity.casefold()
                if key in seen:
                    if seen[key] != child:
                        raise ValueError('conflicting native embedded Front Door child identity')
                    continue
                seen[key] = child
                projected.append(child)
            result['properties'][field] = projected
    if kind == 'routingrules' and isinstance(result['properties'].get('routeConfiguration'), dict):
        config = result['properties']['routeConfiguration']
        result['properties']['routeConfiguration'] = {key: deepcopy(config[key]) for key in
            ('@odata.type', 'forwardingProtocol', 'redirectProtocol', 'backendPool') if key in config}
    if kind == 'origingroups' and isinstance(result['properties'].get('healthProbeSettings'), dict):
        result['properties']['healthProbeSettings'] = {key: data for key, data in result['properties']['healthProbeSettings'].items() if key == 'probeProtocol'}
    if kind == 'backendpools' and isinstance(result['properties'].get('backends'), list):
        result['properties']['backends'] = [{key: data for key, data in row.items() if key in ('address', 'enabledState')} if isinstance(row, dict) else row for row in result['properties']['backends']]
    if kind == 'endpoints':
        policy = props.get('deliveryPolicy')
        rules = policy.get('rules') if isinstance(policy, dict) else [] if policy is None else None
        result['properties']['_nativeDeliveryRules'] = ('present' if rules else 'empty') if isinstance(rules, list) else 'unknown'
    return result


def required_parents(wanted):
    result = set()
    if set(wanted).intersection(DERIVED_TYPES) or 'cdn_profile' in wanted:
        result.add('cdn_profile')
    if 'frontdoor_and_cdn_endpoint' in wanted:
        result.add('frontdoor')
    return result


def _identity(row, parent, pattern):
    if not isinstance(row, dict) or not isinstance(row.get('id'), str):
        raise ValueError('missing native edge identity')
    rid = row['id']
    if ('%' in rid or '\\' in rid or any(part in ('.', '..') for part in rid.split('/'))
            or not re.fullmatch(re.escape(parent) + pattern, rid, re.I)):
        raise ValueError('foreign native edge identity')
    parts = re.split('/providers/', rid, flags=re.I)
    components = parts[-1].split('/')
    expected = '/'.join([components[0], *components[1::2]])
    if row.get('type') is not None and (not isinstance(row.get('type'), str) or row['type'].casefold() != expected.casefold()):
        raise ValueError('native edge type and ID differ')
    if not isinstance(row.get('properties'), dict):
        raise ValueError('native edge properties missing')
    return rid


def _get(reader, request, row, parent, pattern, version):
    rid = _identity(row, parent, pattern)
    detail = reader.call(request, ARM + rid + '?api-version=' + version)
    _identity(detail, parent, pattern)
    if detail['id'].casefold() != rid.casefold():
        raise ValueError('native edge GET identity changed')
    # The shared reader also redacts sensitive metadata before storage.
    result = metadata_projection(detail)
    if result['type'].casefold().endswith('/diagnosticsettingscategories'):
        result['properties'].setdefault('categoryGroups', [])
    if result['type'].casefold().endswith('/diagnosticsettings'):
        result['properties'].setdefault('logs', [])
        for field in ('workspaceId', 'storageAccountId'):
            result['properties'].setdefault(field, None)
    result.setdefault('_provenance', {}).update(source_operation='get', read_only=True,
                                              api_version=version, representation='full')
    return result


def _children(reader, request, parent, path, version):
    rows, seen = [], set()
    pattern = '/' + re.escape(path) + r'/[^/?#\x00-\x1f]+'
    for page in reader.pages(request, ARM + parent + '/' + path + '?api-version=' + version):
        for item in page:
            # A list summary may omit properties; GET is the authoritative detail.
            if not isinstance(item, dict):
                raise ValueError('malformed edge list item')
            summary = {**item, 'properties': item.get('properties', {})}
            rid = _identity(summary, parent, pattern)
            if rid.casefold() in seen:
                raise ValueError('duplicate native edge child')
            if reader.budget.max_items is not None and len(rows) >= reader.budget.max_items:
                from .azure import AzureReadError
                raise AzureReadError('resource_limit')
            seen.add(rid.casefold())
            rows.append(_get(reader, request, summary, parent, pattern, version))
    return rows


def _embedded(parent, field, path):
    rows = parent['properties'].get(field)
    if not isinstance(rows, list):
        raise ValueError('classic edge embedded inventory unavailable')
    seen, result = set(), []
    for row in rows:
        rid = _identity(row, parent['id'], '/' + re.escape(path) + r'/[^/?#\x00-\x1f]+')
        if rid.casefold() in seen:
            raise ValueError('duplicate classic edge child')
        seen.add(rid.casefold())
        result.append(deepcopy(row))
    return result


def _covered(item, field, rows):
    item[field] = [{**row, 'parent_id': item['id']} for row in rows]
    item.setdefault('_coverage', {})[field] = {'status': 'collected' if rows else 'empty'}


def _unresolved(item, field, code):
    item[field] = []
    item.setdefault('_coverage', {})[field] = {'status': 'not_collected', 'error': {'code': code}}


def _routes(item, family, rows):
    effective = []
    endpoints = {entry['id'].casefold(): entry for entry in item.get('endpoints', [])
                 if isinstance(entry, dict) and isinstance(entry.get('id'), str)} if family == 'afd' else {}
    def route_state(row):
        state = row.get('properties', {}).get('enabledState')
        if family == 'classicFrontDoor' and state == 'Enabled':
            gate = item.get('properties', {}).get('enabledState')
            return 'Disabled' if gate == 'Disabled' else 'Enabled' if gate == 'Enabled' else None
        if family == 'afd' and state == 'Enabled':
            endpoint = endpoints.get(str(row.get('id', '')).rsplit('/', 2)[0].casefold())
            if endpoint is None:
                return None
            gate = endpoint.get('properties', {}).get('enabledState')
            return 'Disabled' if gate == 'Disabled' else 'Enabled' if gate == 'Enabled' else None
        return state
    enabled = [row for row in rows if route_state(row) == 'Enabled']
    # Multiple route/domain precedence needs an effective path partition. An
    # unsafe declaration hidden by a more-specific route must not become FAIL.
    if len(enabled) > 1:
        _unresolved(item, 'effectiveRoutes', 'multiple_routes_require_effective_path_partition');return
    for row in rows:
        props = row['properties']
        state = route_state(row)
        if state not in ('Enabled', 'Disabled'):
            _unresolved(item, 'effectiveRoutes', 'route_state_unavailable');return
        if state == 'Disabled':
            effective.append({'id': row['id'], 'type': row['type'], 'enabledState': state})
            continue
        if props.get('patternsToMatch') != ['/*']:
            _unresolved(item, 'effectiveRoutes', 'partial_path_coverage_requires_effective_path_partition');return
        bound_hosts, bound_domain_ids = [], []
        if family == 'afd':
            rules = props.get('ruleSets', [])
            if not isinstance(rules, list) or rules:
                _unresolved(item, 'effectiveRoutes', 'conditional_rule_sets_require_effective_path_evidence');return
            domains = props.get('customDomains', [])
            if (not isinstance(domains, list) or props.get('linkToDefaultDomain') not in ('Enabled', 'Disabled')
                    or props.get('linkToDefaultDomain') == 'Disabled' and not domains):
                _unresolved(item, 'effectiveRoutes', 'public_route_association_unavailable');return
            groups = {r['id'].casefold() for r in item.get('originGroups', [])}
            group_id = props.get('originGroup', {}).get('id') if isinstance(props.get('originGroup'), dict) else None
            if not isinstance(group_id, str) or group_id.casefold() not in groups:
                _unresolved(item, 'effectiveRoutes', 'route_origin_group_unresolved');return
            known_domains = {r['id'].casefold() for r in item.get('domains', [])}
            if any(not isinstance(ref, dict) or not isinstance(ref.get('id'), str) or ref['id'].casefold() not in known_domains for ref in domains):
                _unresolved(item, 'effectiveRoutes', 'route_custom_domain_unresolved');return
            if props['linkToDefaultDomain'] == 'Enabled':
                endpoint = endpoints.get(str(row['id']).rsplit('/', 2)[0].casefold())
                host = (endpoint.get('properties') or {}).get('hostName') if endpoint else None
                if not isinstance(host, str) or not host:
                    _unresolved(item, 'effectiveRoutes', 'route_default_hostname_unavailable');return
                bound_hosts.append(host)
                bound_domain_ids.append(endpoint['id'])
            domain_by_id = {entry['id'].casefold(): entry for entry in item.get('domains', [])}
            for ref in domains:
                if ref.get('isActive') is False:
                    continue
                host = (domain_by_id[ref['id'].casefold()].get('properties') or {}).get('hostName')
                if not isinstance(host, str) or not host:
                    _unresolved(item, 'effectiveRoutes', 'route_custom_hostname_unavailable');return
                bound_hosts.append(host)
                bound_domain_ids.append(ref['id'])
            protocols = props.get('supportedProtocols')
            forwarding = props.get('forwardingProtocol')
            redirect = props.get('httpsRedirect')
            if redirect not in ('Enabled', 'Disabled') or forwarding not in ('HttpOnly', 'HttpsOnly', 'MatchRequest'):
                _unresolved(item, 'effectiveRoutes', 'route_protocol_unavailable');return
            paths = []
            if isinstance(protocols, list) and 'Http' in protocols:
                paths.append({'acceptedProtocols': ['Http'], 'action': 'Redirect', 'redirectProtocol': 'HttpsOnly'} if redirect == 'Enabled' else
                             {'acceptedProtocols': ['Http'], 'action': 'Forward', 'forwardingProtocol': forwarding})
            if isinstance(protocols, list) and 'Https' in protocols:
                paths.append({'acceptedProtocols': ['Https'], 'action': 'Forward', 'forwardingProtocol': forwarding})
        else:
            if props.get('rulesEngine') is not None:
                _unresolved(item, 'effectiveRoutes', 'conditional_rule_engine_requires_effective_path_evidence');return
            refs = props.get('frontendEndpoints')
            known_domains = {r['id'].casefold() for r in item.get('domains', [])}
            if not isinstance(refs, list) or not refs or any(not isinstance(ref, dict) or str(ref.get('id', '')).casefold() not in known_domains for ref in refs):
                _unresolved(item, 'effectiveRoutes', 'classic_route_domain_association_unresolved');return
            domain_by_id = {entry['id'].casefold(): entry for entry in item.get('domains', [])}
            for ref in refs:
                host = (domain_by_id[ref['id'].casefold()].get('properties') or {}).get('hostName')
                if not isinstance(host, str) or not host:
                    _unresolved(item, 'effectiveRoutes', 'classic_route_hostname_unavailable');return
                bound_hosts.append(host)
                bound_domain_ids.append(ref['id'])
            protocols = props.get('acceptedProtocols')
            config = props.get('routeConfiguration', {})
            kind = config.get('@odata.type') if isinstance(config, dict) else None
            if kind == '#Microsoft.Azure.FrontDoor.Models.FrontdoorRedirectConfiguration':
                paths = [{'acceptedProtocols': protocols, 'action': 'Redirect', 'redirectProtocol': config.get('redirectProtocol')}]
            elif kind == '#Microsoft.Azure.FrontDoor.Models.FrontdoorForwardingConfiguration':
                pool = config.get('backendPool', {}).get('id') if isinstance(config.get('backendPool'), dict) else None
                pools = item['properties'].get('backendPools')
                if not isinstance(pools, list) or not isinstance(pool, str) or pool.casefold() not in {str(v.get('id', '')).casefold() for v in pools if isinstance(v, dict)}:
                    _unresolved(item, 'effectiveRoutes', 'classic_backend_pool_unresolved');return
                paths = [{'acceptedProtocols': protocols, 'action': 'Forward', 'forwardingProtocol': config.get('forwardingProtocol')}]
            else:
                _unresolved(item, 'effectiveRoutes', 'route_configuration_unavailable');return
        if (not isinstance(protocols, list) or not protocols or len(set(protocols)) != len(protocols)
                or any(p not in ('Http', 'Https') for p in protocols) or not props.get('patternsToMatch')):
            _unresolved(item, 'effectiveRoutes', 'route_paths_or_protocols_unavailable');return
        # Both products configure an explicit backend/origin group. They are
        # conservatively assessed as custom origins, regardless of DNS suffix.
        effective.append({'id': row['id'], 'type': row['type'], 'enabledState': state,
                          'customOrigin': any(path['action'] == 'Forward' for path in paths), 'paths': paths,
                          'boundHostNames': sorted(set(bound_hosts)),
                          'boundDomainIds': sorted(set(bound_domain_ids)),
                          'resolved': {field: True for field in ('routeAssociation', 'protocols', 'ruleSets', 'pathCoverage', 'originPolicy')}})
    _covered(item, 'effectiveRoutes', effective)


def _read_diagnostics(reader, request, item):
    for field, path in [('diagnosticCategories', 'diagnosticSettingsCategories'), ('diagnosticSettings', 'diagnosticSettings')]:
        try:
            rows = _children(reader, request, item['id'], 'providers/Microsoft.Insights/' + path, '2021-05-01-preview')
            _covered(item, field, rows)
        except Exception:
            _unresolved(item, field, 'diagnostic_inventory_incomplete')


def _classic_cdn_routes(item, endpoints):
    rows = []
    for endpoint in endpoints:
        props = endpoint['properties']
        if props.get('_nativeDeliveryRules') != 'empty':
            _unresolved(item, 'effectiveRoutes', 'classic_cdn_delivery_rules_require_effective_paths');return
        state = {'Running': 'Enabled', 'Stopped': 'Disabled'}.get(props.get('resourceState'))
        if state is None:
            _unresolved(item, 'effectiveRoutes', 'classic_cdn_runtime_state_unavailable');return
        if any(type(props.get(key)) is not bool for key in ('isHttpAllowed', 'isHttpsAllowed')):
            _unresolved(item, 'effectiveRoutes', 'classic_cdn_protocol_configuration_unavailable');return
        protocols = [name for name, key in [('Http', 'isHttpAllowed'), ('Https', 'isHttpsAllowed')] if props[key]]
        if not protocols and state == 'Enabled':
            _unresolved(item, 'effectiveRoutes', 'classic_cdn_no_declared_protocol');return
        host = props.get('hostName')
        if state == 'Enabled' and (not isinstance(host, str) or not host):
            _unresolved(item, 'effectiveRoutes', 'classic_cdn_hostname_unavailable');return
        rows.append({'id': endpoint['id'], 'type': endpoint['type'], 'enabledState': state,
                     'boundHostNames': [host] if state == 'Enabled' else [],
                     'boundDomainIds': [endpoint['id']] if state == 'Enabled' else [],
                     'paths': [{'acceptedProtocols': protocols, 'action': 'Forward'}],
                     'resolved': {**{key: True for key in ('routeAssociation', 'protocols', 'ruleSets', 'pathCoverage')},
                                  'originPolicy': False}})
    _covered(item, 'effectiveRoutes', rows)


def _blob_reader(reader, request, container, principal):
    """Use target-principal assignments, including transitive groups; not caller permissions."""
    uuid = r'[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}'
    if not isinstance(principal, str) or not re.fullmatch(uuid, principal):
        return {'status': 'not_collected'}
    prefix = ARM + container + '/providers/Microsoft.Authorization/'
    denies = [row for page in reader.pages(request, prefix + 'denyAssignments?' + urlencode({
        'api-version': '2022-04-01', '$filter': 'atScope()'})) for row in page]
    # Unknown deny membership/conditions must never become an allow proof.
    if denies:return {'status': 'not_collected', 'reason': 'deny_assignment_evaluation_required'}
    rows = [row for page in reader.pages(request, prefix + 'roleAssignments?' + urlencode({
        'api-version': '2022-04-01', '$filter': "atScope() and assignedTo('" + principal + "')"})) for row in page]
    allowed, conditional, seen = False, False, set()
    action = 'microsoft.storage/storageaccounts/blobservices/containers/blobs/read'
    for row in rows:
        if not isinstance(row, dict) or not isinstance(row.get('id'), str) or row['id'].casefold() in seen:
            raise ValueError('malformed or duplicate target role assignment')
        seen.add(row['id'].casefold())
        props = row.get('properties')
        if not isinstance(props, dict):raise ValueError('role assignment properties unavailable')
        scope = props.get('scope')
        if not isinstance(scope, str) or not (container.casefold() == scope.casefold() or
                container.casefold().startswith(scope.casefold().rstrip('/') + '/') or
                scope.casefold().startswith('/providers/microsoft.management/managementgroups/')):
            raise ValueError('foreign target role assignment scope')
        if not re.fullmatch(re.escape(scope.rstrip('/') + '/providers/Microsoft.Authorization/roleAssignments/') + uuid, row['id'], re.I):
            raise ValueError('target role assignment identity and scope differ')
        subject = props.get('principalId')
        if not isinstance(subject, str) or not re.fullmatch(uuid, subject) or (subject.casefold() != principal.casefold() and props.get('principalType') != 'Group'):
            raise ValueError('target assignment subject is not the selected identity or group')
        if props.get('condition'):
            conditional = True;continue
        rid = props.get('roleDefinitionId')
        if (not isinstance(rid, str) or '%' in rid or '\\' in rid or
                not re.fullmatch(r'/(?:subscriptions/[^/?#]+/|providers/Microsoft.Management/managementGroups/[^/?#]+/)?providers/Microsoft.Authorization/roleDefinitions/' + uuid, rid, re.I)):
            raise ValueError('invalid target role definition identity')
        definition = reader.call(request, ARM + rid + '?api-version=2022-04-01')
        if not isinstance(definition, dict) or str(definition.get('id', '')).casefold() != rid.casefold():
            raise ValueError('foreign target role definition')
        permissions = definition.get('properties', {}).get('permissions')
        if not isinstance(permissions, list):raise ValueError('role data permission inventory missing')
        for permission in permissions:
            if not isinstance(permission, dict):raise ValueError('malformed role permissions')
            include, exclude = permission.get('dataActions'), permission.get('notDataActions')
            if any(not isinstance(values, list) or any(not isinstance(v, str) for v in values) for values in (include, exclude)):
                raise ValueError('role data permission predicates unavailable')
            allowed |= any(fnmatchcase(action, p.casefold()) for p in include) and not any(fnmatchcase(action, p.casefold()) for p in exclude)
    if conditional and not allowed:return {'status': 'not_collected', 'reason': 'conditional_role_evaluation_required'}
    return {'status': 'collected', 'principalId': principal, 'dataReader': allowed,
            '_provenance': {'source_operation': 'roleAssignments.assignedTo+denyAssignments.atScope', 'read_only': True}}


def _blob_origins(reader, request, item):
    groups = {row['id'].casefold(): row for row in item.get('originGroups', [])}
    scope = '/' + '/'.join(item['id'].split('/')[1:3])
    accounts = None
    group_paths = {}
    for route in item.get('routes', []):
        props = route['properties']
        key = str(props.get('originGroup', {}).get('id')).casefold()
        group_paths.setdefault(key, set()).add(str(props.get('originPath')))
    for route in item.get('routes', []):
        props = route['properties'];group_id = props.get('originGroup', {}).get('id')
        group = groups.get(str(group_id).casefold())
        if group is None:continue
        origins = group.get('origins', [])
        if len(group_paths[str(group_id).casefold()]) > 1:
            # Evidence is attached to the shared group. Different route paths
            # require separate container grants and cannot share one result.
            route['originAuthenticationPrerequisites'] = {
                'status': 'not_collected', 'reason': 'shared_origin_group_distinct_paths'}
            for origin in origins:
                origin['blobContainerEvidence'] = {'status': 'not_collected'}
                origin.pop('blobRbacEvidence', None)
            continue
        rules = props.get('ruleSets', [])
        route['originAuthenticationPrerequisites'] = {
            'status': 'collected' if isinstance(rules, list) and not rules else 'not_collected',
            'forwardingHttpsOnly': props.get('forwardingProtocol') == 'HttpsOnly',
            'originGroupProbeHttps': group['properties'].get('healthProbeSettings', {}).get('probeProtocol') == 'Https',
            'noPrivateLink': all(not origin['properties'].get('sharedPrivateLinkResource') for origin in origins)}
        for origin in origins:
            origin['blobContainerEvidence'] = {'status': 'not_collected'}
            hostname = origin['properties'].get('hostName')
            if not isinstance(hostname, str) or not re.fullmatch(r'[a-z0-9]{3,24}\.blob\.core\.windows\.net', hostname, re.I):
                continue  # A custom DNS name is not proof of a non-Blob origin.
            path = props.get('originPath')
            if not isinstance(path, str) or not path.startswith('/') or any(c in path for c in ('%', '?', '#', '\\')):
                continue
            container_name = path.split('/')[1]
            if not re.fullmatch(r'(?:[a-z0-9][a-z0-9-]{1,61}[a-z0-9]|\$root)', container_name) or '--' in container_name:
                continue
            if accounts is None:
                accounts = []
                for page in reader.pages(request, ARM + scope + '/providers/Microsoft.Storage/storageAccounts?api-version=2023-05-01'):
                    for account in page:
                        _identity(account, scope, r'/resourceGroups/[^/?#]+/providers/Microsoft\.Storage/storageAccounts/[^/?#]+')
                        accounts.append(account)
            matches = [a for a in accounts if urlsplit(str(a['properties'].get('primaryEndpoints', {}).get('blob', ''))).hostname == hostname.casefold()]
            if len(matches) != 1:continue
            container = matches[0]['id'] + '/blobServices/default/containers/' + container_name
            detail = reader.call(request, ARM + container + '?api-version=2023-05-01')
            _identity(detail, matches[0]['id'], '/blobServices/default/containers/' + re.escape(container_name))
            origin['blobContainerEvidence'] = {'status': 'collected', 'isContainer': True,
                'requiredByPolicy': False, 'resource_id': container,
                '_provenance': {'source_operation': 'containers.get', 'read_only': True}}
            auth = group['properties'].get('authentication')
            if not isinstance(auth, dict):continue  # A full GET proves no configured origin authentication.
            if auth.get('type') == 'SystemAssignedIdentity':principal = item.get('identity', {}).get('principalId')
            elif auth.get('type') == 'UserAssignedIdentity':
                identity = auth.get('userAssignedIdentity', {}).get('id')
                values = item.get('identity', {}).get('userAssignedIdentities', {})
                principal = next((v.get('principalId') for key, v in values.items() if isinstance(identity, str) and key.casefold() == identity.casefold() and isinstance(v, dict)), None)
            else:continue
            origin['blobRbacEvidence'] = _blob_reader(reader, request, container, principal)


def _profile(reader, request, parent):
    item = deepcopy(parent)
    sku = item.get('sku', {}).get('name')
    if sku in ('Standard_AzureFrontDoor', 'Premium_AzureFrontDoor'):
        family = 'afd'
        domains = _children(reader, request, item['id'], 'customDomains', CDN_VERSION)
        for domain in domains:
            p = domain['properties']
            # HTTPS is automatic for AFD custom domains, but configuration alone
            # does not prove activation before validation and deployment finish.
            if (p.get('domainValidationState') == 'Approved' and p.get('provisioningState') == 'Succeeded'
                    and p.get('deploymentStatus') == 'Succeeded' and isinstance(p.get('tlsSettings'), dict)):
                domain['httpsState'] = 'Enabled'
        endpoints = _children(reader, request, item['id'], 'afdEndpoints', CDN_VERSION)
        _covered(item, 'endpoints', endpoints)
        routes = [route for endpoint in endpoints for route in _children(reader, request, endpoint['id'], 'routes', CDN_VERSION)]
        policies = _children(reader, request, item['id'], 'securityPolicies', CDN_VERSION)
        _covered(item, 'securityPolicies', policies)
        # Older versions omit authentication and tokenDestinationHeader. Their
        # absence cannot establish that authentication is missing or usable.
        groups = _children(reader, request, item['id'], 'originGroups', ORIGIN_GROUP_VERSION)
        for group in groups:
            group['origins'] = _children(reader, request, group['id'], 'origins', CDN_VERSION)
        _covered(item, 'domains', domains);_covered(item, 'customDomains', domains)
        _covered(item, 'routes', routes);_covered(item, 'originGroups', groups)
        try:
            _blob_origins(reader, request, item)
        except Exception:
            # Missing data-plane identity evidence cannot invalidate TLS/log
            # configuration inventories; the Blob evaluator remains UNKNOWN.
            for route in item.get('routes', []):
                route['originAuthenticationPrerequisites'] = {'status': 'not_collected'}
        _routes(item, family, routes)
        return item, {'afd_profile': [deepcopy(parent)], 'afd_domain': domains + endpoints,
                      'afd_route': routes, 'afd_security_policy': policies}
    if sku not in ('Standard_Microsoft', 'Standard_Akamai', 'Standard_Verizon', 'Premium_Verizon', 'Standard_ChinaCdn'):
        raise ValueError('unknown CDN generation')
    endpoints = _children(reader, request, item['id'], 'endpoints', CDN_VERSION)
    _covered(item, 'endpoints', endpoints)
    domains = [domain for endpoint in endpoints for domain in _children(reader, request, endpoint['id'], 'customDomains', CDN_VERSION)]
    _covered(item, 'domains', domains);_covered(item, 'customDomains', domains)
    # Listener protocol is known independently of the effective origin policy.
    _classic_cdn_routes(item, endpoints)
    return item, {}


def collect(reader, request, scopes, wanted):
    from .azure import AzureReadError
    if not set(wanted).intersection(set(DERIVED_TYPES) | {'cdn_profile'}):
        return
    projected = {scope: {kind: [] for kind in DERIVED_TYPES} for scope in scopes}
    failures = {scope: [] for scope in scopes}
    for scope in scopes:
        kinds = required_parents(wanted)
        for kind in kinds:
            sources = [c for c in reader.collections if c['type'] == kind and c['scope'].casefold() == scope.casefold()]
            if len(sources) != 1 or sources[0]['status'] not in ('collected', 'empty'):
                failures[scope].append('parent_inventory_incomplete')
                continue
            for parent in sources[0]['items']:
                try:
                    _identity(parent, scope, r'/resourceGroups/[^/?#]+/providers/' + re.escape('Microsoft.Network/frontDoors' if kind == 'frontdoor' else 'Microsoft.Cdn/profiles') + r'/[^/?#]+')
                    if kind == 'frontdoor':
                        item = deepcopy(parent);domains = _embedded(item, 'frontendEndpoints', 'frontendEndpoints');routes = _embedded(item, 'routingRules', 'routingRules')
                        _covered(item, 'domains', domains);_routes(item, 'classicFrontDoor', routes);facts = {}
                    else:
                        item, facts = _profile(reader, request, parent)
                        # Enrich the canonical profile without replacing its identity.
                        parent.update(deepcopy(item))
                    _read_diagnostics(reader, request, item)
                    projected[scope]['frontdoor_and_cdn_endpoint'].append(item)
                    for target, rows in facts.items():projected[scope][target].extend(rows)
                except Exception:
                    failures[scope].append('edge_child_inventory_incomplete')
    jobs = []
    for scope in scopes:
        for kind in set(wanted).intersection(DERIVED_TYPES):
            def fetch(scope=scope, kind=kind):
                yield projected[scope][kind]
                if failures[scope]:raise AzureReadError(failures[scope][0])
            jobs.append((kind, scope, 'Microsoft.Cdn', fetch))
    reader.run(jobs)
