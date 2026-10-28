"""Enabled SNS mobile push endpoints, without device tokens or app credentials."""

import re

KIND = 'sns_platform_endpoint'
SPECS = {KIND: ('sns', 'list_platform_applications', 'PlatformApplications')}
NATIVE_IDS = {KIND: 'EndpointArn'}
READ_ACTIONS = {('sns', 'list_platform_applications'),
                ('sns', 'list_endpoints_by_platform_application')}


def collect(requests, session, region, account):
    from .aws import ReadResult
    from .aws_network_inventory import MetadataSession

    partition = session.get_partition_for_region(region)
    projected = MetadataSession(session)
    applications = requests.pages(projected, 'sns', region,
                                  'list_platform_applications', 'PlatformApplications')
    if applications.status not in {'collected', 'empty'}:
        return applications
    rows, failures = [], []
    pattern = (rf'arn:{re.escape(partition)}:sns:{re.escape(region)}:{re.escape(account)}:'
               r'app/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)')
    for application in applications.items:
        arn = application.get('PlatformApplicationArn') if isinstance(application, dict) else None
        match = re.fullmatch(pattern, arn) if isinstance(arn, str) else None
        if match is None:
            failures.append('malformed')
            continue
        endpoints = requests.pages(projected, 'sns', region,
                                   'list_endpoints_by_platform_application', 'Endpoints',
                                   PlatformApplicationArn=arn)
        if endpoints.status not in {'collected', 'empty'}:
            failures.append(endpoints.status)
        for endpoint in endpoints.items:
            identity = endpoint.get('EndpointArn') if isinstance(endpoint, dict) else None
            enabled = endpoint.get('Enabled') if isinstance(endpoint, dict) else None
            if (not isinstance(identity, str) or not re.fullmatch(
                    rf'arn:{re.escape(partition)}:sns:{re.escape(region)}:{re.escape(account)}:'
                    rf'endpoint/{re.escape(match.group(1))}/{re.escape(match.group(2))}/'
                    r'[0-9a-fA-F-]{36}', identity) or type(enabled) is not bool):
                failures.append('malformed')
                continue
            rows.append({'EndpointArn': identity, 'PlatformApplicationArn': arn,
                         'Enabled': enabled})
    status = 'partial' if rows and failures else failures[0] if failures else 'collected' if rows else 'empty'
    return ReadResult(rows, status, {'code': 'sns_platform_endpoint_inventory_incomplete'} if failures else None)


FETCHERS = {KIND: collect}
