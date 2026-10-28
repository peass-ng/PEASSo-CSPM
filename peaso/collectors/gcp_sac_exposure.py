"""Read Secure Access Connect partner and gateway links without pairing keys."""

from .gcp_network_catalog import _location_validations


ROOT = 'https://networksecurity.googleapis.com/v1'


def collection_pages(collector, scope):
    selected = collector.options.get('regions')
    if selected is None:
        locations = []
        for rows, receipt in collector.pages(f'{ROOT}/{scope}/locations', scope, key='locations',
                params={'fields': 'locations(name,locationId),nextPageToken,unreachable'}):
            for row in rows:
                name = row.get('locationId') or str(row.get('name', '')).rsplit('/', 1)[-1]
                if isinstance(name, str) and name != 'global':
                    locations.append(name)
            yield [], receipt
    else:
        locations = _location_validations(selected)
    for rows, receipt in collector.pages(f'{ROOT}/{scope}/locations/global/sacRealms', scope,
            key='sacRealms', params={'fields': 'sacRealms(name,state,securityService),nextPageToken,unreachable'}):
        yield [{'name': row['name'], 'resourceKind': 'realm', 'state': row.get('state'),
                'securityService': row.get('securityService')} for row in rows
               if isinstance(row.get('name'), str)], receipt
    for location in dict.fromkeys(locations):
        for rows, receipt in collector.pages(f'{ROOT}/{scope}/locations/{location}/sacAttachments', scope,
                key='sacAttachments', params={'fields':
                'sacAttachments(name,state,sacRealm,nccGateway),nextPageToken,unreachable'}):
            yield [{'name': row['name'], 'resourceKind': 'attachment', 'state': row.get('state'),
                    'sacRealm': row.get('sacRealm'), 'nccGateway': row.get('nccGateway')}
                   for row in rows if isinstance(row.get('name'), str)], receipt
