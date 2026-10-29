"""Collect exact Dataplex lakes and their policy for task execution paths."""

from __future__ import annotations

import re

from .gcp import ReadError
from .gcp_fanout import location_fanout
from .gcp_dataplex_locations import LAKE_NON_REGIONAL_LOCATIONS


HOST = 'https://dataplex.googleapis.com/v1/'
LOCATION = re.compile(r'projects/([^/]+)/locations/([a-z0-9-]+)')
LAKE = re.compile(r'projects/([^/]+)/locations/([a-z0-9-]+)/lakes/([a-z][a-z0-9-]*)')
STATES = {'STATE_UNSPECIFIED', 'ACTIVE', 'CREATING', 'DELETING', 'ACTION_REQUIRED'}


def _project(collector, scope, observed):
    project_id = scope.split('/', 1)[1]
    if observed == project_id:
        return
    binding = collector._data_project_binding(scope, require_alias=True)
    if observed not in {binding['project_id'], binding['project_number']}:
        raise ReadError('malformed', 'dataplex_foreign_project')


def _complete_page(data):
    if data.get('unreachableLocations'):
        raise ReadError('unavailable', 'dataplex_unreachable_locations')


def scope_jobs(collector, scope):
    if 'dataplex_privesc_lake' not in collector.needed or not scope.startswith('projects/'):
        return []

    def fetch():
        locations = set()
        for page, request_id in collector.pages(HOST + scope + '/locations', scope,
                                                key='locations'):
            yield [], request_id
            for location in page:
                name = location.get('name')
                match = LOCATION.fullmatch(name) if isinstance(name, str) else None
                if not match:
                    raise ReadError('malformed', 'dataplex_location_invalid')
                _project(collector, scope, match[1])
                if match[2] not in LAKE_NON_REGIONAL_LOCATIONS:
                    if match[2] in locations:
                        raise ReadError('malformed', 'dataplex_location_duplicate')
                    locations.add(match[2])
        seen = set()

        def region_pages(region):
            parent = scope + '/locations/' + region
            for page, request_id in collector.pages(HOST + parent + '/lakes', scope,
                                                    key='lakes', response_validator=_complete_page):
                yield page, request_id

        # Lake listings fan out per region; identity checks, duplicate checks
        # and policy reads replay in region order as before.
        for region, pages, error in location_fanout(collector, sorted(locations), region_pages):
            parent = scope + '/locations/' + region
            for page, request_id in pages:
                yield [], request_id
                # Lakes before the first invalid one are still kept.
                lakes, failure = [], None
                try:
                    for lake in page:
                        name = lake.get('name')
                        match = LAKE.fullmatch(name) if isinstance(name, str) else None
                        if not match or match[2] != region:
                            raise ReadError('malformed', 'dataplex_lake_identity_invalid')
                        _project(collector, scope, match[1])
                        canonical = parent + '/lakes/' + match[3]
                        if canonical in seen:
                            raise ReadError('malformed', 'dataplex_lake_duplicate')
                        seen.add(canonical)
                        state = lake.get('state')
                        if state not in STATES:
                            raise ReadError('malformed', 'dataplex_lake_state_invalid')
                        lakes.append({'name': canonical, 'state': state})
                except ReadError as exc:
                    failure = exc
                def policy(projected):
                    return collector.hydrate(
                        projected, 'iamPolicy', HOST + projected['name'] + ':getIamPolicy', scope,
                        params={'options.requestedPolicyVersion': 3})
                parallel = getattr(collector, 'parallel', None)
                for hydrated in (parallel(policy, lakes) if parallel else map(policy, lakes)):
                    yield [hydrated], request_id
                if failure is not None:
                    raise failure
            if error is not None:
                raise error

    return [('dataplex_privesc_lake', scope, 'dataplex', fetch)]


def collect(collector):
    collector.run_jobs([job for scope in collector.scopes for job in scope_jobs(collector, scope)])
