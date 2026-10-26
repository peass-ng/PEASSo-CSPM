"""Read Dataform creator grants and repository policies for bounded execution."""

from __future__ import annotations

import re

from .gcp import ReadError
from .gcp_fanout import fanout_pages


HOST = 'https://dataform.googleapis.com/v1/'
LOCATION = re.compile(r'projects/([^/]+)/locations/([a-z0-9-]+)')
REPOSITORY = re.compile(r'projects/([^/]+)/locations/([a-z0-9-]+)/repositories/([A-Za-z0-9_-]+)')


def _project(collector, scope, observed):
    project_id = scope.split('/', 1)[1]
    if observed == project_id:
        return project_id
    binding = collector._data_project_binding(scope, require_alias=True)
    if observed not in {binding['project_id'], binding['project_number']}:
        raise ReadError('malformed', 'dataform_foreign_project')
    return project_id


def _policy(value):
    bindings = value.get('bindings', [])
    if (not isinstance(bindings, list)
            or any(not isinstance(binding, dict)
                   or not isinstance(binding.get('role'), str)
                   or not isinstance(binding.get('members'), list)
                   for binding in bindings)):
        raise ReadError('malformed', 'dataform_repository_policy_invalid')
    return {key: value[key] for key in ('version', 'etag', 'bindings') if key in value}


def scope_jobs(collector, scope):
    if 'dataform_privesc_location' not in collector.needed or not scope.startswith('projects/'):
        return []

    def fetch():
        locations = set()
        for page, request_id in collector.pages(HOST + scope + '/locations', scope, key='locations'):
            for location in page:
                name = location.get('name')
                match = LOCATION.fullmatch(name) if isinstance(name, str) else None
                if not match or match[2] == 'global':
                    if match and match[2] == 'global':
                        continue
                    raise ReadError('malformed', 'dataform_location_invalid')
                _project(collector, scope, match[1])
                if match[2] in locations:
                    raise ReadError('malformed', 'dataform_location_duplicate')
                locations.add(match[2])
            yield [], request_id
        def location_pages(location):
            parent = scope + '/locations/' + location
            configs = []
            config_request_id = None
            for page, request_id in collector.pages(HOST + parent + '/config', scope, single=True):
                configs.extend(page)
                config_request_id = request_id
                yield [], request_id
            if len(configs) != 1:
                raise ReadError('malformed', 'dataform_config_missing')
            config = configs[0]
            name = config.get('name')
            match = re.fullmatch(r'projects/([^/]+)/locations/' + re.escape(location) + r'/config', name) \
                if isinstance(name, str) else None
            if not match:
                raise ReadError('malformed', 'dataform_config_identity_invalid')
            _project(collector, scope, match[1])
            creator = config.get('creatorRoleConfig')
            if creator is None:
                creator = {}
            if (not isinstance(creator, dict)
                    or ('disableGrant' in creator and type(creator['disableGrant']) is not bool)
                    or ('creatorRole' in creator and not isinstance(creator['creatorRole'], str))
                    or ('disableGrant' in creator and 'creatorRole' in creator)):
                raise ReadError('malformed', 'dataform_creator_role_invalid')
            repositories = []
            seen = set()
            for page, request_id in collector.pages(HOST + parent + '/repositories', scope,
                                                     key='repositories'):
                yield [], request_id
                for repository in page:
                    raw = repository.get('name')
                    match = REPOSITORY.fullmatch(raw) if isinstance(raw, str) else None
                    if not match or match[2] != location:
                        raise ReadError('malformed', 'dataform_repository_identity_invalid')
                    _project(collector, scope, match[1])
                    canonical = parent + '/repositories/' + match[3]
                    if canonical in seen:
                        raise ReadError('malformed', 'dataform_repository_duplicate')
                    seen.add(canonical)
                    policies = []
                    for policy_page, policy_request in collector.pages(
                            HOST + canonical + ':getIamPolicy', scope, single=True,
                            transform=_policy):
                        policies.extend(policy_page)
                        yield [], policy_request
                    if len(policies) != 1:
                        raise ReadError('malformed', 'dataform_repository_policy_missing')
                    repositories.append({
                        'name': canonical,
                        'serviceAccount': repository.get('serviceAccount'),
                        'teamFolder': repository.get('teamFolder'),
                        'iamPolicy': policies[0],
                    })
            private_workspace = config.get('enablePrivateWorkspace')
            if private_workspace is not None and type(private_workspace) is not bool:
                raise ReadError('malformed', 'dataform_workspace_mode_invalid')
            yield [{'name': parent, 'creatorRoleConfig': creator,
                    'enablePrivateWorkspace': private_workspace,
                    'repositories': repositories}], config_request_id

        yield from fanout_pages(collector, sorted(locations), location_pages)

    return [('dataform_privesc_location', scope, 'dataform', fetch)]


def collect(collector):
    collector.run_jobs([job for scope in collector.scopes for job in scope_jobs(collector, scope)])
