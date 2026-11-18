"""Brief typed copy for native Job image evidence and its actual public DTO.

Public deduplication retains detector/path/layer and Job/container locations,
but drops the native image URI and declaration. Never reconstruct those fields.
"""
import re

from peaso.secret_scanning import merge_leaks
from .gcp_workload_image_source_association_20261020 import _immutable

CHECK_ID = 'gcp.review.cloudrun_job.declared_image_secret_indicators'
UNKNOWN = ('Evidence for the selected Cloud Run Job’s declared image is incomplete or unbound. '
           'Secret absence and the executed image were not established; credentials were not validated.')
LIMIT = 'Credentials and the executed image were not verified.'
PROJECT = r'[a-z][a-z0-9-]{4,28}[a-z0-9]'
LABEL = r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?'
JOB = r'projects/(' + PROJECT + r')/locations/[a-z][a-z0-9-]{0,62}/jobs/[a-z0-9](?:[a-z0-9-]{0,126}[a-z0-9])?'
DIGEST = r'sha256:[0-9a-f]{64}'
VERSIONS = {'kingfisher': '1.4.0', 'trufflehog': '3.92.5'}


def _match(pattern, value):
    return isinstance(value, str) and re.fullmatch(pattern, value) is not None


def _leaks(value, *, public, scope):
    if not isinstance(value, list) or len(value) > 256 or merge_leaks(value) != value:
        raise ValueError('malformed secret observations')
    count = 0
    for leak in value:
        for location in leak['locations']:
            count += 1
            allowed = {'path', 'line', 'layer', 'resource_id', 'scope'} if public else {'path', 'line', 'layer'}
            if (set(location) - allowed or not _match(DIGEST, location.get('layer'))
                    or not _match(r'image-config\.json|member-[1-9][0-9]{0,3}', location['path'])):
                raise ValueError('unbound image location')
            if public and (location.get('scope') != scope or not _match(
                    re.escape(scope) + JOB[JOB.index('/locations/'):] + '#container=' + LABEL,
                    location.get('resource_id'))):
                raise ValueError('unbound Job container')
    if count > 2000:
        raise ValueError('location bound')
    return value


def observation(finding):
    if (not isinstance(finding, dict) or finding.get('provider') != 'gcp'
            or finding.get('check_id') != CHECK_ID):
        return None
    status, e, scope = finding.get('status'), finding.get('evidence'), finding.get('scope')
    if status not in ('PASS', 'FAIL', 'UNKNOWN', 'DENIED'):
        return None
    if status in ('UNKNOWN', 'DENIED'):
        return UNKNOWN
    try:
        if (not isinstance(e, dict) or e.get('credential_validation') != 'not_attempted'
                or not _match('projects/' + PROJECT, scope)):
            return UNKNOWN
        public = 'secret_fingerprint' in finding or 'linked_check_ids' in finding
        leaks = _leaks(e.get('secret_leaks'), public=public, scope=scope)
        if public:
            fingerprint = finding.get('secret_fingerprint')
            if (status != 'FAIL' or finding.get('linked_check_ids') != [CHECK_ID]
                    or not _match('[0-9a-f]{64}', fingerprint)
                    or finding.get('resource_id') != 'secret:' + fingerprint
                    or len(leaks) != 1 or leaks[0]['fingerprint'] != fingerprint
                    or 'complete' in e and type(e['complete']) is not bool
                    or (e.get('complete') is False) != (e.get('coverage') == 'incomplete')):
                return UNKNOWN
            text = 'A likely secret was detected in image bytes linked to the selected Cloud Run Job declaration.'
        else:
            declaration = e.get('job_declaration')
            if (e.get('association_kind') != 'desired_digest_declaration'
                    or e.get('runtime_association_status') != 'UNKNOWN'
                    or 'observed_runtime_digest' not in e or e['observed_runtime_digest'] is not None
                    or e.get('deployed_bytes_proven') is not False or type(e.get('complete')) is not bool
                    or not isinstance(declaration, dict) or declaration.get('api_version') != 'run.googleapis.com/v2'
                    or declaration.get('kind') != 'Job' or declaration.get('project_id') != scope.split('/')[1]
                    or not _match(JOB, declaration.get('name')) or not declaration['name'].startswith(scope + '/')
                    or not _match(LABEL, declaration.get('container_name'))
                    or not _match(r'[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}', declaration.get('uid'))
                    or not _match(r'[1-9][0-9]{0,18}', declaration.get('generation'))
                    or not isinstance(declaration.get('etag'), str) or not 1 <= len(declaration['etag']) <= 256
                    or not _match(r'/template/template/containers/(?:[0-9]|1[0-5])/image', declaration.get('image_json_pointer'))
                    or _immutable(e.get('image_uri'))['project_id'] != scope.split('/')[1]):
                return UNKNOWN
            engines, layers, requests = e.get('config_engines'), e.get('layer_coverage'), e.get('source_requests')
            if (not isinstance(engines, list) or len(engines) != 2
                    or {r['engine'] for r in engines} != set(VERSIONS)
                    or any(set(r) != {'engine', 'version', 'status'} or VERSIONS[r['engine']] != r['version']
                           or r['status'] not in ('complete', 'unavailable') for r in engines)
                    or not isinstance(layers, list) or not 1 <= len(layers) <= 16
                    or any(not _match(DIGEST, r.get('digest')) or r.get('status') not in ('complete', 'unavailable') for r in layers)
                    or not isinstance(requests, list) or not 10 <= len(requests) <= 26
                    or len(set(requests)) != len(requests)
                    or any(not _match(r'request-[1-9][0-9]*', r) for r in requests)
                    or (status == 'FAIL') != bool(leaks)
                    or e['complete'] and (any(r['status'] != 'complete' for r in engines + layers))):
                return UNKNOWN
            if status == 'PASS':
                if not e['complete']:
                    return UNKNOWN
                return ('Both offline detectors found no supported secret in the immutable image declared by the selected Cloud Run Job container. '
                        'Credentials and the executed image were not verified.')
            text = 'A likely secret was detected in the immutable image declared by the selected Cloud Run Job container.'
        if e.get('complete') is False:
            text += ' Inspection is incomplete.'
        return text + ' ' + LIMIT
    except (KeyError, ValueError, TypeError, AttributeError, IndexError):
        return UNKNOWN
