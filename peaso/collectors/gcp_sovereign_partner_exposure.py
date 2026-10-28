"""Read Assured Workloads partner grants without workload content."""

from .gcp_network_catalog import _location_validations


PARTNER_LOCATIONS = ('europe-west1', 'europe-west4', 'europe-west9', 'europe-west3',
    'europe-west8', 'europe-west12', 'me-central2')
PERMISSIONS = ('dataLogsViewer', 'serviceAccessApprover', 'assuredWorkloadsMonitoring',
    'accessTransparencyLogsSupportCaseViewer')


def collection_pages(collector, scope):
    selected = collector.options.get('regions')
    locations = (location for location in _location_validations(selected)
                 if location in PARTNER_LOCATIONS) if selected is not None else PARTNER_LOCATIONS
    for location in locations:
        root = f'https://{location}-assuredworkloads.googleapis.com/v1/{scope}/locations/{location}/workloads'
        fields = 'workloads(name,partner,partnerPermissions(' + ','.join(PERMISSIONS) + ')),nextPageToken'
        for rows, receipt in collector.pages(root, scope, key='workloads', params={'fields': fields}):
            safe = []
            for row in rows:
                permissions = row.get('partnerPermissions') or {}
                if not isinstance(row.get('name'), str):
                    continue
                safe.append({'name': row['name'], 'partner': row.get('partner'),
                    'partnerPermissions': {key: permissions.get(key) is True for key in PERMISSIONS}})
            yield safe, receipt
