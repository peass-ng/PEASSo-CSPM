"""Read CA pools and their exact IAM policies for prospective self-grants."""

from __future__ import annotations

import re
from urllib.parse import urlsplit, urlunsplit

from .gcp import ReadError
from .gcp_fanout import fanout_pages


def _safe_url(value):
    if not isinstance(value, str):
        return None
    parsed = urlsplit(value)
    if parsed.scheme not in {'http', 'https'} or not parsed.hostname:
        return None
    try:
        port = parsed.port
    except ValueError:
        return None
    host = '[' + parsed.hostname + ']' if ':' in parsed.hostname else parsed.hostname
    return urlunsplit((parsed.scheme, host + (':' + str(port) if port else ''), '', '', ''))


def _safe_authority(row, name):
    safe = {'name': name, **{key: row[key] for key in ('state', 'keySpec', 'gcsBucket') if key in row}}
    for field, keys in (('accessUrls', ('caCertificateAccessUrl', 'crlAccessUrls')),
                        ('userDefinedAccessUrls', ('aiaIssuingCertificateUrls', 'crlAccessUrls'))):
        value = row.get(field)
        if not isinstance(value, dict):
            continue
        projected = {}
        for key in keys:
            item = value.get(key)
            if isinstance(item, list):
                projected[key] = [url for x in item if (url := _safe_url(x))]
            elif (url := _safe_url(item)):
                projected[key] = url
        safe[field] = projected
    return safe


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
                return {'name': canonical, **{key: row[key] for key in ('tier', 'issuancePolicy',
                    'publishingOptions') if key in row}}

            for pools, request_id in collector.pages(
                    'https://privateca.googleapis.com/v1/' + parent + '/caPools', scope,
                    key='caPools', transform=keep):
                yield [], request_id
                for pool in pools:
                    def child_name(row, parent_name, segment):
                        name = row.get('name')
                        prefix = parent_name + '/' + segment + '/'
                        if isinstance(name, str) and not name.startswith(prefix) and name.startswith('projects/'):
                            parts = name.split('/', 2)
                            binding = collector._data_project_binding(scope, require_alias=True)
                            if len(parts) == 3 and parts[1] in {binding['project_id'], binding['project_number']}:
                                name = 'projects/' + scope.split('/', 1)[1] + '/' + parts[2]
                        suffix = name.removeprefix(prefix) if isinstance(name, str) else ''
                        if (not isinstance(name, str) or not name.startswith(prefix) or
                                not re.fullmatch(r'[A-Za-z0-9_-]+', suffix)):
                            raise ReadError('malformed', 'privateca_child_identity_invalid')
                        return name

                    authorities = []
                    for rows, authority_request in collector.pages(
                            'https://privateca.googleapis.com/v1/' + pool['name'] + '/certificateAuthorities',
                            scope, key='certificateAuthorities', params={'fields':
                                'certificateAuthorities(name,state,keySpec(cloudKmsKeyVersion),gcsBucket,'
                                'accessUrls,userDefinedAccessUrls),nextPageToken'}):
                        yield [], authority_request
                        for row in rows:
                            authority_name = child_name(row, pool['name'], 'certificateAuthorities')
                            authority = _safe_authority(row, authority_name)
                            crls = []
                            for crl_rows, crl_request in collector.pages(
                                    'https://privateca.googleapis.com/v1/' + authority_name + '/certificateRevocationLists',
                                    scope, key='certificateRevocationLists', params={'fields':
                                        'certificateRevocationLists(name,state,accessUrl),nextPageToken'}):
                                yield [], crl_request
                                for crl in crl_rows:
                                    crl_name = child_name(crl, authority_name, 'certificateRevocationLists')
                                    for policies, crl_policy_request in collector.pages(
                                            'https://privateca.googleapis.com/v1/' + crl_name + ':getIamPolicy',
                                            scope, single=True, params={'options.requestedPolicyVersion': 3}):
                                        yield [], crl_policy_request
                                        if len(policies) != 1 or not isinstance(policies[0].get('bindings', []), list):
                                            raise ReadError('malformed', 'privateca_crl_policy_invalid')
                                        crls.append({'name': crl_name, 'state': crl.get('state'),
                                            'accessUrl': _safe_url(crl.get('accessUrl')),
                                            'iamPolicy': {key: policies[0][key] for key in
                                            ('version', 'bindings') if key in policies[0]}})
                            authority['certificateRevocationLists'] = crls
                            authorities.append(authority)
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
                        yield [{**pool, 'certificateAuthorities': authorities, 'iamPolicy': policies[0],
                                '_coverage': {'iamPolicy': {'status': 'collected'}}}], policy_request

        yield from fanout_pages(collector, sorted(locations), location_pages)

    return [('ca_pool', scope, 'privateca', fetch)]


def collect(collector):
    collector.run_jobs([job for scope in collector.scopes for job in scope_jobs(collector, scope)])
