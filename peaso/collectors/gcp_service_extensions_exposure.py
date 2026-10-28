"""Read Service Extensions routing references without plugin code or payloads."""

import re

from .gcp import ReadError
from .gcp_network_catalog import _location_validations


ROOT = 'https://networkservices.googleapis.com/v1'
BETA_ROOT = 'https://networkservices.googleapis.com/v1beta1'
SECURITY_ROOT = 'https://networksecurity.googleapis.com/v1'
CHAINS = 'name,forwardingRules,loadBalancingScheme,extensionChains(extensions(name,service,supportedEvents,forwardHeaders,failOpen))'
LISTS = (
    ('authzExtensions', 'authzExtension', 'name,service,loadBalancingScheme,forwardHeaders,failOpen'),
    ('lbTrafficExtensions', 'lbTrafficExtension', CHAINS),
    ('lbRouteExtensions', 'lbRouteExtension', CHAINS),
    ('lbEdgeExtensions', 'lbEdgeExtension', CHAINS),
)


def _project(row, kind):
    name = row.get('name')
    if not isinstance(name, str):
        raise ReadError('malformed', 'service_extension_name_missing')
    safe = {'name': name, 'resourceKind': kind}
    if kind == 'authzPolicy':
        safe['action'] = row.get('action')
        safe['policyProfile'] = row.get('policyProfile')
        target = row.get('target') or {}
        safe['targetResources'] = [x for x in target.get('resources', []) if isinstance(x, str)] if isinstance(target, dict) else []
        provider = row.get('customProvider') or {}
        extension = provider.get('authzExtension') or {} if isinstance(provider, dict) else {}
        safe['authzExtensions'] = [x for x in extension.get('resources', []) if isinstance(x, str)] if isinstance(extension, dict) else []
    elif kind == 'extensionBinding':
        safe['producerExtension'] = row.get('producerExtension')
        target = row.get('target') or {}
        if isinstance(target, dict):
            safe['targetResources'] = [x for x in target.get('resources', []) if isinstance(x, str)]
            bind_scope = target.get('scope') or {}
            safe['targetScope'] = bind_scope.get('parent') if isinstance(bind_scope, dict) else None
    elif kind == 'producerExtension':
        safe['phase'] = row.get('phase')
        settings = row.get('extensionSettings') or {}
        if isinstance(settings, dict):
            safe['service'] = settings.get('service')
            safe['supportedEvents'] = settings.get('supportedEvents')
    elif kind == 'authzExtension':
        safe.update({key: row.get(key) for key in ('service', 'loadBalancingScheme', 'failOpen')})
        safe['forwardHeaders'] = [x for x in row.get('forwardHeaders', []) if isinstance(x, str)] if isinstance(row.get('forwardHeaders'), list) else None
    else:
        safe['forwardingRules'] = [x for x in row.get('forwardingRules', []) if isinstance(x, str)] if isinstance(row.get('forwardingRules'), list) else []
        if kind == 'cdnEdgeExtension':
            target = row.get('target') or {}
            safe['targetResources'] = [x for x in target.get('resources', []) if isinstance(x, str)] if isinstance(target, dict) else []
        safe['loadBalancingScheme'] = row.get('loadBalancingScheme')
        safe['extensions'] = []
        for chain in row.get('extensionChains', []) if isinstance(row.get('extensionChains'), list) else []:
            if not isinstance(chain, dict):
                continue
            for extension in chain.get('extensions', []) if isinstance(chain.get('extensions'), list) else []:
                if not isinstance(extension, dict):
                    continue
                safe['extensions'].append({key: extension.get(key) for key in ('name', 'service', 'supportedEvents',
                    'forwardHeaders', 'failOpen') if key in extension})
    return safe


def _locations(collector, scope):
    selected = collector.options.get('regions')
    if selected is not None:
        yield list(dict.fromkeys(['global', *_location_validations(selected)])), None
        return
    found = ['global']
    for rows, receipt in collector.pages(f'{ROOT}/{scope}/locations', scope, key='locations',
            params={'fields': 'locations(name,locationId),nextPageToken,unreachable'}):
        for row in rows:
            name = row.get('locationId') or str(row.get('name', '')).rsplit('/', 1)[-1]
            if isinstance(name, str) and not re.search(r'-[a-z]$', name):
                found.append(name)
        yield [], receipt
    yield _location_validations(found), None


def collection_pages(collector, scope):
    for locations, location_receipt in _locations(collector, scope):
        if location_receipt:
            yield [], location_receipt
        for location in locations:
            parent = f'{scope}/locations/{location}'
            for segment, kind, fields in LISTS:
                mask = f'{segment}({fields}),nextPageToken,unreachable'
                for rows, receipt in collector.pages(f'{ROOT}/{parent}/{segment}', scope, key=segment,
                        params={'fields': mask}):
                    yield [_project(row, kind) for row in rows], receipt
            for rows, receipt in collector.pages(f'{SECURITY_ROOT}/{parent}/authzPolicies', scope,
                    key='authzPolicies', params={'fields': 'authzPolicies(name,action,policyProfile,target(resources),customProvider(authzExtension(resources))),nextPageToken,unreachable'}):
                yield [_project(row, 'authzPolicy') for row in rows], receipt
            for segment, kind, fields in (
                    ('cdnEdgeExtensions', 'cdnEdgeExtension',
                     'name,target(resources),extensionChains(extensions(name,service,supportedEvents,forwardHeaders,failOpen))'),
                    ('extensionBindings', 'extensionBinding',
                     'name,producerExtension,target(resources,scope(parent,resourceTypes)),failOpen'),
                    ('producerExtensions', 'producerExtension',
                     'name,phase,extensionSettings(service,supportedEvents)')):
                for rows, receipt in collector.pages(f'{BETA_ROOT}/{parent}/{segment}', scope, key=segment,
                        params={'fields': f'{segment}({fields}),nextPageToken,unreachable'}):
                    yield [_project(row, kind) for row in rows], receipt
            for plugins, receipt in collector.pages(f'{ROOT}/{parent}/wasmPlugins', scope,
                    key='wasmPlugins', params={'fields': 'wasmPlugins(name,mainVersionId,usedBy(name)),nextPageToken,unreachable'}):
                yield [], receipt
                for plugin in plugins:
                    name = plugin.get('name')
                    if not isinstance(name, str) or not name.startswith(parent + '/wasmPlugins/'):
                        raise ReadError('malformed', 'wasm_plugin_name_invalid')
                    safe = {'name': name, 'resourceKind': 'wasmPlugin',
                            'mainVersionId': plugin.get('mainVersionId'),
                            'usedBy': [x.get('name') for x in plugin.get('usedBy', [])
                                       if isinstance(x, dict) and isinstance(x.get('name'), str)],
                            'versions': []}
                    if safe['mainVersionId'] and safe['usedBy']:
                        for versions, version_receipt in collector.pages(f'{ROOT}/{name}/versions', scope,
                                key='wasmPluginVersions', params={'fields':
                                'wasmPluginVersions(name,imageUri,pluginConfigUri),nextPageToken,unreachable'}):
                            safe['versions'].extend({key: version[key] for key in ('name', 'imageUri', 'pluginConfigUri')
                                if isinstance(version.get(key), str)} for version in versions)
                            yield [], version_receipt
                    yield [safe], receipt
