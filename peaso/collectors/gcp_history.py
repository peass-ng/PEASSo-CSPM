"""Bounded, read-only DNS and deployment history facts.

These inventories preserve native evidence. They do not infer that a build was
deployed to production, that a restore was validated, or that DNS is effective.
"""
from hashlib import sha256
import re
from urllib.parse import quote, urlsplit


def cloudbuild_locations(collector, scope):
    """Discover the service's regional inventory unless explicitly selected."""
    from .gcp import ReadError
    locations = collector.options.get('cloudbuild_locations')
    if locations is None:
        yield ['global'], None
        seen = {'global'}
        for page, request in collector.pages(f'https://cloudbuild.googleapis.com/v2/{scope}/locations',
                                             scope, key='locations'):
            found = []
            for row in page:
                location = row.get('locationId')
                if not isinstance(location, str) or not re.fullmatch(r'[a-z0-9-]+', location):
                    raise ReadError('malformed', 'cloudbuild_location_identity_invalid')
                if location not in seen:
                    seen.add(location)
                    found.append(location)
            if len(seen) > 101:
                raise ReadError('unavailable', 'cloudbuild_location_limit')
            yield found, request
        return
    if (not isinstance(locations, list) or len(locations) > 100 or
            any(not isinstance(x, str) or not re.fullmatch(r'[a-z0-9-]+', x) for x in locations)):
        raise ReadError('malformed', 'cloudbuild_locations_invalid')
    yield list(dict.fromkeys(['global', *locations])), None


def cloudbuild_builds(collector, scope):
    from .gcp import ReadError
    locations = []
    for found, request in cloudbuild_locations(collector, scope):
        locations.extend(found)
        if request:
            yield [], request
    from .gcp_fanout import location_fanout

    def location_pages(location):
        prefix = f'{scope}/locations/{location}/builds/'
        def project(row):
            ident = row.get('id')
            if not isinstance(ident, str) or not re.fullmatch(r'[A-Za-z0-9-]+', ident):
                raise ReadError('malformed', 'cloudbuild_build_id_missing')
            name = row.get('name', prefix + ident)
            project_id = scope.split('/')[1]
            alias = re.fullmatch(r'projects/([0-9]+)/locations/' + re.escape(location) + '/builds/' + re.escape(ident), name) if isinstance(name, str) else None
            if (row.get('projectId', project_id) != project_id or
                    name != prefix + ident and not (alias and row.get('projectId') == project_id)):
                raise ReadError('malformed', 'cloudbuild_build_scope_mismatch')
            kept = {key: row[key] for key in ('id', 'projectId', 'status', 'createTime', 'startTime', 'finishTime',
                    'buildTriggerId') if key in row}
            provenance = row.get('sourceProvenance', {})
            repo = provenance.get('resolvedRepoSource', {}) if isinstance(provenance, dict) else {}
            if isinstance(repo, dict) and 'commitSha' in repo:
                kept['sourceProvenance'] = {'resolvedRepoSource': {'commitSha': repo['commitSha']}}
            substitutions = row.get('substitutions', {})
            if isinstance(substitutions, dict) and 'COMMIT_SHA' in substitutions:
                kept['substitutions'] = {'COMMIT_SHA': substitutions['COMMIT_SHA']}
            if isinstance(row.get('ConfigurationSecretIndicators'), dict):
                kept['ConfigurationSecretIndicators'] = row['ConfigurationSecretIndicators']
            return {'name': name, **kept, '_representation': 'partial'}
        return collector.pages(f'https://cloudbuild.googleapis.com/v1/{scope}/locations/{location}/builds',
            scope, key='builds', params={'projectId': scope.split('/')[1]}, transform=project)
    failures = []
    for _location, pages, exc in location_fanout(collector, locations, location_pages):
        yield from pages
        if exc is not None:
            if getattr(exc, 'request_id', None):
                yield [], exc.request_id
            failures.append(exc)
    if failures:
        raise failures[0]


def sql_operations(collector, scope):
    from .gcp import ReadError
    from .gcp_compliance_wave import complete_parent
    project_id = scope.split('/')[1]
    def project(row):
        name = row.get('name')
        if not isinstance(name, str) or not re.fullmatch(r'[A-Za-z0-9-]+', name):
            raise ReadError('malformed', 'sql_operation_id_missing')
        if row.get('targetProject', project_id) != project_id:
            raise ReadError('malformed', 'sql_operation_project_mismatch')
        kept = {key: row[key] for key in ('status', 'operationType', 'targetId', 'targetProject',
                                         'insertTime', 'startTime', 'endTime') if key in row}
        error = row.get('error')
        if isinstance(error, dict):
            errors = error.get('errors')
            if not isinstance(errors, list) or any(not isinstance(e, dict) or not isinstance(e.get('code'), str) for e in errors):
                raise ReadError('malformed', 'sql_operation_errors_malformed')
            kept['error'] = {'errors': [{'code': e['code']} for e in errors]} if errors else {}
        elif error is not None:
            raise ReadError('malformed', 'sql_operation_errors_malformed')
        return {'name': f'{scope}/operations/{name}', **kept, '_representation': 'partial'}
    parent = complete_parent(collector, 'sql_instance', scope)
    for request in parent['source_requests']:
        yield [], request
    from .gcp_fanout import location_fanout

    def instance_pages(instance):
        # Identity errors stop the listing; read errors are kept per instance.
        name = instance.get('name')
        if not isinstance(name, str) or not re.fullmatch(r'[a-z][a-z0-9-]{0,97}', name):
            raise ReadError('malformed', 'sql_operation_instance_identity_invalid')
        try:
            for page in collector.pages(f'https://sqladmin.googleapis.com/sql/v1beta4/{scope}/operations',
                    scope, page_size_key='maxResults', params={'instance': name}, transform=project):
                yield page, None
        except ReadError as exc:
            yield None, exc
    failures = []
    for _instance, entries, error in location_fanout(collector, parent['items'], instance_pages):
        for page, exc in entries:
            if exc is None:
                yield page
                continue
            if getattr(exc, 'request_id', None):
                yield [], exc.request_id
            failures.append(exc)
        if error is not None:
            raise error
    if failures:
        raise failures[0]


def dns_records(collector, scope):
    from .gcp import ReadError
    from .gcp_compliance_wave import complete_parent
    zones = complete_parent(collector, 'dns_managed_zone', scope)
    for request in zones['source_requests']:
        yield [], request
    from .gcp_fanout import location_fanout

    def zone_pages(zone):
        # Zone identity errors stop the listing; rrset read errors are kept.
        name = zone.get('name')
        if not isinstance(name, str) or not re.fullmatch(r'[a-z][a-z0-9-]{0,62}', name):
            raise ReadError('malformed', 'dns_zone_identity_invalid')
        visibility = zone.get('visibility')
        if visibility == 'public':
            return
        if visibility != 'private':
            raise ReadError('unavailable', 'dns_zone_visibility_unresolved')
        policy = getattr(collector, 'psc_owner_policy', None)
        if policy and policy['scope'] == scope:
            domain = zone.get('dnsName')
            if not isinstance(domain, str) or not domain.endswith('.'):
                raise ReadError('unavailable', 'dns_zone_domain_unresolved')
            domain = domain.lower().rstrip('.')
            # Exact required record names can occur only in their containing
            # zones. An unrelated Service Directory-managed zone does not
            # provide static rrsets and must not hide this scoped inventory.
            if not any(host == domain or host.endswith('.' + domain)
                       for host in policy['required_google_api_hostnames']):
                return
        config = zone.get('privateVisibilityConfig')
        networks = config.get('networks') if isinstance(config, dict) else None
        if not isinstance(networks, list) or not networks:
            raise ReadError('unavailable', 'dns_private_networks_unresolved')
        urls = []
        for network in networks:
            url = network.get('networkUrl') if isinstance(network, dict) else None
            if not isinstance(url, str):
                raise ReadError('malformed', 'dns_network_identity_invalid')
            parsed = urlsplit(url)
            if (parsed.scheme != 'https' or parsed.hostname not in ('www.googleapis.com', 'compute.googleapis.com') or
                    parsed.query or parsed.fragment or parsed.username or parsed.port not in (None, 443) or
                    not re.fullmatch(r'/compute/v1/projects/[A-Za-z0-9._:-]+/global/networks/[a-z][a-z0-9-]{0,62}', parsed.path)):
                raise ReadError('malformed', 'dns_network_identity_invalid')
            urls.append(url)
        def project(row):
            host, record_type = row.get('name'), row.get('type')
            if (not isinstance(host, str) or not host.endswith('.') or len(host) > 254 or
                    not isinstance(record_type, str) or not re.fullmatch(r'[A-Z][A-Z0-9]*', record_type)):
                raise ReadError('malformed', 'dns_record_identity_invalid')
            # One record may be visible to several VPCs; its stable resource
            # identity includes both zone and network, rather than only hostname.
            return [{**row, 'managed_zone': name, 'network': network,
                'resource': f'//dns.googleapis.com/{scope}/managedZones/{name}/rrsets/{quote(host, safe="")}/{record_type}/networks/{sha256(network.encode()).hexdigest()}',
                '_representation': 'full'} for network in dict.fromkeys(urls)]
        try:
            for page, request in collector.pages(f'https://dns.googleapis.com/dns/v1/{scope}/managedZones/{name}/rrsets',
                    scope, key='rrsets', page_size_key='maxResults'):
                yield ([record for row in page for record in project(row)], request), None
        except ReadError as exc:
            yield None, exc
    failures = []
    for _zone, entries, error in location_fanout(collector, zones['items'], zone_pages):
        for page, exc in entries:
            if exc is None:
                yield page
                continue
            if getattr(exc, 'request_id', None):
                yield [], exc.request_id
            failures.append(exc)
        if error is not None:
            raise error
    if failures:
        raise failures[0]
