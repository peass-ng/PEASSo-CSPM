"""Read CA pools and their exact IAM policies for prospective self-grants."""

from __future__ import annotations

import re

from .gcp import ReadError
from .gcp_fanout import fanout_pages


def scope_jobs(collector, scope):
    if 'ca_pool' not in collector.needed or not scope.startswith('projects/'):
        return []

    def fetch():
        locations = set()
        for page, request_id in collector.pages(
                'https://privateca.googleapis.com/v1/' + scope + '/locations', scope,
                key='locations'):
            for row in page:
                name = row.get('name')
                location = row.get('locationId') or (name.rsplit('/', 1)[-1]
                                                     if isinstance(name, str) else None)
                if not isinstance(location, str) or not re.fullmatch(r'[a-z0-9-]+', location):
                    raise ReadError('malformed', 'privateca_location_invalid')
                if location != 'global':
                    locations.add(location)
            yield [], request_id
        seen = set()

        def location_pages(location):
            parent = scope + '/locations/' + location

            def keep(row, location=location):
                name = row.get('name')
                match = re.fullmatch(r'projects/([^/]+)/locations/' + re.escape(location) +
                                     r'/caPools/([A-Za-z0-9_-]+)', name) if isinstance(name, str) else None
                if not match:
                    raise ReadError('malformed', 'privateca_pool_identity_invalid')
                if match[1] != scope.split('/', 1)[1]:
                    binding = collector._data_project_binding(scope, require_alias=True)
                    if match[1] not in {binding['project_id'], binding['project_number']}:
                        raise ReadError('malformed', 'privateca_pool_foreign_project')
                canonical = parent + '/caPools/' + match[2]
                if canonical in seen:
                    raise ReadError('malformed', 'privateca_pool_duplicate')
                seen.add(canonical)
                return {'name': canonical, **{key: row[key] for key in ('tier', 'issuancePolicy') if key in row}}

            for pools, request_id in collector.pages(
                    'https://privateca.googleapis.com/v1/' + parent + '/caPools', scope,
                    key='caPools', transform=keep):
                yield [], request_id
                for pool in pools:
                    def policy(value):
                        bindings = value.get('bindings', [])
                        if not isinstance(bindings, list) or any(
                                not isinstance(binding, dict)
                                or not isinstance(binding.get('role'), str)
                                or not isinstance(binding.get('members'), list)
                                for binding in bindings):
                            raise ReadError('malformed', 'privateca_pool_policy_invalid')
                        return {key: value[key] for key in ('version', 'etag', 'bindings') if key in value}

                    for policies, policy_request in collector.pages(
                            'https://privateca.googleapis.com/v1/' + pool['name'] + ':getIamPolicy',
                            scope, single=True, transform=policy):
                        if len(policies) != 1:
                            raise ReadError('malformed', 'privateca_pool_policy_missing')
                        yield [{**pool, 'iamPolicy': policies[0],
                                '_coverage': {'iamPolicy': {'status': 'collected'}}}], policy_request

        yield from fanout_pages(collector, sorted(locations), location_pages)

    return [('ca_pool', scope, 'privateca', fetch)]


def collect(collector):
    collector.run_jobs([job for scope in collector.scopes for job in scope_jobs(collector, scope)])
