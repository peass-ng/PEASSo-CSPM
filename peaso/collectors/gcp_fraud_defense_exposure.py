"""Read Fraud Defense public key scope without retrieving legacy secrets."""

from .gcp import ReadError


ROOT = 'https://recaptchaenterprise.googleapis.com/v1'


def collection_pages(collector, scope):
    fields = ('keys(name,webSettings(allowAllDomains,allowedDomains),'
        'androidSettings(allowAllPackageNames),iosSettings(allowAllBundleIds),universalSettings),nextPageToken')
    for rows, receipt in collector.pages(f'{ROOT}/{scope}/keys', scope, key='keys',
            params={'fields': fields}):
        safe = [{'name': row.get('name'), 'resourceKind': 'key',
                'webAllowAllDomains': (row.get('webSettings') or {}).get('allowAllDomains'),
                'allowedDomains': (row.get('webSettings') or {}).get('allowedDomains'),
                'androidAllowAllPackageNames': (row.get('androidSettings') or {}).get('allowAllPackageNames'),
                'iosAllowAllBundleIds': (row.get('iosSettings') or {}).get('allowAllBundleIds'),
                'universal': row.get('universalSettings') is not None}
               for row in rows if isinstance(row.get('name'), str)]
        yield safe, receipt
        for item in safe:
            if not item['universal']:
                continue
            try:
                policy, policy_receipt = collector.read(f'{ROOT}/{item["name"]}/policy', scope,
                    params={'fields': 'allowAllDomains,allowedDomains'})
            except ReadError as exc:
                if exc.status in {'not_found', 'NOT_FOUND', '404'}:
                    continue
                raise
            yield [{'name': item['name'] + '/policy', 'resourceKind': 'policy',
                    'allowAllDomains': policy.get('allowAllDomains'),
                    'allowedDomains': policy.get('allowedDomains')}], policy_receipt
