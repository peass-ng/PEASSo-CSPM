"""Read GKE Multi-Cloud cluster endpoints and administrator subjects."""

from .gcp import ReadError
from .gcp_network_catalog import _location_validations


SERVICE = 'gkemulticloud.googleapis.com'
TYPES = {
    'attachedClusters': 'name,state,oidcConfig(issuerUrl),authorization(adminUsers,adminGroups)',
    'awsClusters': 'name,state,endpoint,authorization(adminUsers,adminGroups)',
    'azureClusters': 'name,state,endpoint,authorization(adminUsers,adminGroups)',
}


def collection_pages(collector, scope):
    selected = collector.options.get('regions')
    if selected is None:
        locations = []
        url = f'https://us-central1-{SERVICE}/v1/{scope}/locations'
        for rows, receipt in collector.pages(url, scope, key='locations',
                params={'fields': 'locations(name,locationId),nextPageToken,unreachable'}):
            for row in rows:
                location = row.get('locationId') or str(row.get('name', '')).rsplit('/', 1)[-1]
                if isinstance(location, str) and location != 'global':
                    locations.append(location)
            yield [], receipt
    else:
        locations = _location_validations(selected)
    for location in dict.fromkeys(locations):
        root = f'https://{location}-{SERVICE}/v1/{scope}/locations/{location}'
        for segment, fields in TYPES.items():
            for rows, receipt in collector.pages(root + '/' + segment, scope, key=segment,
                    params={'fields': f'{segment}({fields}),nextPageToken,unreachable'}):
                safe = []
                for row in rows:
                    name = row.get('name')
                    if not isinstance(name, str):
                        raise ReadError('malformed', 'multicloud_cluster_name_missing')
                    auth = row.get('authorization') or {}
                    safe.append({'name': name, 'resourceKind': segment, 'state': row.get('state'),
                        'endpoint': row.get('endpoint'),
                        'oidcIssuerUrl': (row.get('oidcConfig') or {}).get('issuerUrl'),
                        'adminUsers': [x.get('username') for x in auth.get('adminUsers', [])
                            if isinstance(x, dict) and isinstance(x.get('username'), str)],
                        'adminGroups': [x.get('group') for x in auth.get('adminGroups', [])
                            if isinstance(x, dict) and isinstance(x.get('group'), str)]})
                yield safe, receipt
