"""Project only Model Armor configuration references; never read prompt content."""

from .gcp import ReadError
from .gcp_network_catalog import _location_validations


ROOT = 'https://modelarmor.googleapis.com/v1'


def collection_pages(collector, scope):
    selected = collector.options.get('regions')
    if selected is None:
        locations = ['global']
        for rows, receipt in collector.pages(f'{ROOT}/{scope}/locations', scope, key='locations',
                params={'fields': 'locations(name,locationId),nextPageToken,unreachable'}):
            for row in rows:
                name = row.get('locationId') or str(row.get('name', '')).rsplit('/', 1)[-1]
                if isinstance(name, str):
                    locations.append(name)
            yield [], receipt
    else:
        locations = ['global', *_location_validations(selected)]
    for location in dict.fromkeys(locations):
        parent = f'{scope}/locations/{location}'
        for rows, receipt in collector.pages(f'{ROOT}/{parent}/templates', scope, key='templates',
                params={'fields': 'templates(name,filterConfig(sdpSettings(advancedConfig(inspectTemplate,deidentifyTemplate))),templateMetadata(logSanitizeOperations)),nextPageToken,unreachable'}):
            safe = []
            for row in rows:
                name = row.get('name')
                if not isinstance(name, str):
                    raise ReadError('malformed', 'model_armor_template_name_missing')
                sdp = (row.get('filterConfig') or {}).get('sdpSettings') or {}
                advanced = sdp.get('advancedConfig') or {}
                metadata = row.get('templateMetadata') or {}
                safe.append({'name': name, 'resourceKind': 'template',
                    'inspectTemplate': advanced.get('inspectTemplate'),
                    'deidentifyTemplate': advanced.get('deidentifyTemplate'),
                    'logSanitizeOperations': metadata.get('logSanitizeOperations')})
            yield safe, receipt
        try:
            row, receipt = collector.read(f'{ROOT}/{parent}/floorSetting', scope,
                params={'fields': 'name,aiPlatformFloorSetting(enableCloudLogging),googleMcpServerFloorSetting(enableCloudLogging)'})
        except ReadError as exc:
            if exc.status in {'not_found', 'NOT_FOUND', '404'}:
                continue
            raise
        yield [{'name': row.get('name') or parent + '/floorSetting', 'resourceKind': 'floorSetting',
                'aiPlatformCloudLogging': (row.get('aiPlatformFloorSetting') or {}).get('enableCloudLogging'),
                'mcpCloudLogging': (row.get('googleMcpServerFloorSetting') or {}).get('enableCloudLogging')}], receipt
