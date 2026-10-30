"""New-only Job proposal: native REST-shaped fixtures and real local OCI scanners."""
from copy import deepcopy
import hashlib
import json
from urllib.parse import unquote

import pytest
import requests

from peaso import secret_scanning as scanning
from peaso.collectors import gcp_cloudrun_v2_job_declared_images_20261020 as proposal
from peaso.collectors import gcp_image_secret_indicators as native
from tests.test_gcp_image_secret_review_20261019 import (
    image, Session, transport, TOKEN, encoded, clean, real, isolate,  # noqa: F401
)

SCOPE = 'projects/review'
JOB = SCOPE + '/locations/us-central1/jobs/batch-job'
UID = '4c03895a-b5b4-4d6c-b8dd-f1979d8f044c'


def fixtures(value='production', *, second=None, layers=2):
    image_row, blobs = image(value, layers=layers)
    bare = image_row['uri'].removeprefix('https://')
    selector = {'api_version': 'run.googleapis.com/v2', 'kind': 'Job', 'project_id': 'review',
                'resource_name': JOB, 'resource_uid': UID, 'container_name': 'worker',
                'digest': image_row['digest'], 'repository': image_row['repository'],
                'immutable_reference': bare}
    job = {'name': JOB, 'uid': UID, 'etag': 'native-job-etag', 'generation': '8',
           'observedGeneration': '8', 'reconciling': False,
           'template': {'template': {'containers': [{'name': 'worker', 'image': bare}]}}}
    repository = {'name': image_row['repository'], 'format': 'DOCKER', 'mode': 'STANDARD_REPOSITORY',
                  'updateTime': '2026-10-20T09:00:00Z'}
    docker = {'name': unquote(image_row['name']), 'uri': bare, 'mediaType': native.OCI,
              'updateTime': '2026-10-20T09:01:00Z'}
    project = {'name': 'projects/123456789', 'projectId': 'review', 'state': 'ACTIVE'}
    selectors = [selector]
    bodies = dict(zip((r[0] for r in proposal._requests(selector, SCOPE)),
                      [job, project, repository, docker]))
    if second is not None:
        second_row, extra = image(second, layers=layers)
        # Distinct container names may intentionally declare the same immutable image.
        extra_selector = dict(selector, container_name='sidecar', digest=second_row['digest'],
                              immutable_reference=second_row['uri'].removeprefix('https://'))
        selectors.append(extra_selector)
        job['template']['template']['containers'].append(
            {'name': 'sidecar', 'image': extra_selector['immutable_reference']})
        docker_url = proposal._requests(extra_selector, SCOPE)[3][0]
        bodies[docker_url] = dict(docker, name=unquote(second_row['name']),
                                  uri=extra_selector['immutable_reference'])
        blobs.update(extra)
    return selectors, bodies, blobs


class MetadataSession:
    def __init__(self, bodies, *, alter=None, fault=None):
        self.bodies, self.alter, self.fault = bodies, alter, fault
        self.calls, self.closed, self.responses_closed = [], False, 0
        self.counts = {}

    def request(self, method, url, **kwargs):
        assert method == 'GET' and kwargs['stream'] is True and kwargs['allow_redirects'] is False
        assert kwargs['timeout'] <= 10 and kwargs['headers']['Accept-Encoding'] == 'identity'
        assert kwargs['headers']['Authorization'] == 'Bearer fixture-access-token'
        assert set(kwargs) == {'params', 'headers', 'stream', 'allow_redirects', 'timeout'}
        assert url in self.bodies, 'Unexpected native endpoint: ' + url
        self.calls.append((url, deepcopy(kwargs['params'])))
        count = self.counts[url] = self.counts.get(url, 0) + 1
        body = deepcopy(self.bodies[url])
        if self.alter:
            self.alter(url, body, count)
        raw = encoded(body)
        fault = self.fault(url, count) if self.fault else None
        if fault == 'duplicate':
            raw = raw[:-1] + b',"name":"duplicate"}'
        if fault in ('oversized', 'stream_oversized'):
            raw = b' ' * (proposal.MAX_METADATA_BODY + 1)
        owner = self
        prepared_url = requests.Request('GET', url, params=kwargs['params']).prepare().url

        class Response:
            status_code = 403 if fault == 'denied' else 206 if fault == 'partial_http' else 200
            history = []
            headers = {'Content-Length': str(len(raw)), 'Content-Type': 'application/json'}
            url = prepared_url

            def iter_content(self, chunk_size):
                output = raw[:-1] if fault == 'truncated' else raw
                for offset in range(0, len(output), 17):
                    yield output[offset:offset + 17]

            def close(self):
                owner.responses_closed += 1

        response = Response()
        if fault == 'redirect':
            response.url = 'https://foreign.invalid/metadata'
        if fault == 'encoding':
            response.headers['Content-Encoding'] = 'gzip'
        if fault == 'stream_oversized':
            response.headers.pop('Content-Length')
        return response

    def close(self):
        self.closed = True


def run(*, value='production', second=None, selectors=None, alter=None, fault=None,
        binary_options=None, native_transport=None, **options):
    selected, bodies, blobs = fixtures(value, second=second)
    metadata = MetadataSession(bodies, alter=alter, fault=fault)
    binary = Session(blobs, **(binary_options or {}))
    native_transport = native_transport or transport()
    result = proposal.collect_declared_images(native_transport, scope=SCOPE,
        selectors=selected if selectors is None else selectors, enabled=options.pop('enabled', True),
        metadata_session=metadata, image_session=binary, **options)
    return result, metadata, binary, native_transport


@pytest.mark.parametrize('value,status', [('production', 'PASS'), (TOKEN, 'FAIL')])
def test_real_native_get_to_declared_image_to_offline_dual_detectors(real, value, status, capsys, record_property):
    result, metadata, binary, wire = run(value=value)
    assert result['status'] == status and result['complete'] is True, result
    assert len(metadata.calls) == 8 and len(binary.calls) == 4
    assert metadata.closed and binary.closed and metadata.responses_closed == 8
    assert wire.calls == 12
    assert result['observed_runtime_digest'] is None and result['deployed_bytes_proven'] is False
    row = result['rows'][0]
    assert row['association_revalidated'] and row['declaration']['association_kind'] == 'desired_digest_declaration'
    source = row['declaration']['selected_artifact_image_hint']['source']
    assert source['uid'] == UID and source['image_json_pointer'] == '/template/template/containers/0/image'
    assert len(set(row['source_requests'])) == 12
    assert set(row['source_requests']) == {r['id'] for r in result['source_requests']}
    assert len(result['metadata_captures']) == 8
    records = {r['id']: r for r in result['source_requests']}
    for capture in result['metadata_captures']:
        record = records[capture['source_request']]
        assert record['http_attempts'] == 1 and record['status'] == 'collected'
        assert record['body_sha256'] == hashlib.sha256(encoded(capture['body'])).hexdigest()
    if status == 'FAIL':
        leak, = row['content']['leaks']
        assert {d['engine'] for d in leak['detectors']} == {'kingfisher', 'trufflehog'}
        assert len({loc['layer'] for loc in leak['locations']}) == 3
    assert TOKEN not in repr(result) + repr(scanning._RESULTS) + str(capsys.readouterr())
    assert 'fixture-access-token' not in repr(result)
    record_property('native_capture_witness', json.dumps(result, sort_keys=True))


@pytest.mark.parametrize('second,expected', [('production', 'PASS'), (TOKEN, 'FAIL')])
def test_real_named_multicontainer_selection(real, second, expected):
    result, metadata, binary, _ = run(second=second)
    assert result['status'] == expected and result['complete'] is True
    assert [r['selection']['container_name'] for r in result['rows']] == ['worker', 'sidecar']
    assert [r['declaration']['selected_artifact_image_hint']['source']['image_json_pointer']
            for r in result['rows']] == ['/template/template/containers/0/image', '/template/template/containers/1/image']
    assert len(binary.calls) == 8 and len(metadata.calls) == 16


@pytest.mark.parametrize('enabled', [False, None, 1, 'true'])
def test_defaultoff_and_exact_boolean_required(clean, enabled):
    result, metadata, binary, wire = run(enabled=enabled)
    assert result['status'] == 'UNKNOWN' and result['reason'] == 'disabled'
    assert not metadata.calls and not binary.calls and wire.calls == 0


def test_omitted_selector_is_not_discovery(clean):
    result, metadata, binary, _ = run(selectors=[])
    assert result['status'] == 'UNKNOWN' and not metadata.calls and not binary.calls
    assert metadata.closed and binary.closed


@pytest.mark.parametrize('field,value', [
    ('project_id', 'foreign'), ('resource_name', JOB.replace('/review/', '/foreign/')),
    ('kind', 'Execution'), ('api_version', 'run.googleapis.com/v1'), ('resource_uid', 'invalid'),
    ('container_name', ''), ('digest', 'sha256:' + 'f' * 64),
    ('repository', SCOPE + '/locations/us-central1/repositories/foreign'),
    ('immutable_reference', 'us-central1-docker.pkg.dev/review/images/app:latest'),
])
def test_invalid_independent_selectors_fail_before_io(clean, field, value):
    selectors, _, _ = fixtures()
    selectors[0][field] = value
    result, metadata, binary, wire = run(selectors=selectors)
    assert result['status'] == 'UNKNOWN' and not metadata.calls and not binary.calls and wire.calls == 0


@pytest.mark.parametrize('mode', ['uid', 'project', 'container', 'digest', 'repository', 'docker_name',
    'docker_uri', 'tag', 'duplicate_container', 'unnamed', 'reconciling', 'stale', 'partial',
    'synthetic', 'virtual', 'remote', 'index', 'secret_field'])
def test_native_metadata_identity_or_unsupported_contract_never_reaches_bytes(clean, mode):
    def alter(url, body, count):
        if '/jobs/' in url:
            containers = body['template']['template']['containers']
            if mode == 'uid': body['uid'] = '4c03895a-b5b4-4d6c-b8dd-f1979d8f044d'
            if mode == 'container': containers[0]['name'] = 'foreign'
            if mode == 'digest': containers[0]['image'] = containers[0]['image'].split('@')[0] + '@sha256:' + 'f' * 64
            if mode == 'tag': containers[0]['image'] = containers[0]['image'].split('@')[0] + ':latest'
            if mode == 'duplicate_container': containers.append(deepcopy(containers[0]))
            if mode == 'unnamed': containers[0]['name'] = ''
            if mode == 'reconciling': body['reconciling'] = True
            if mode == 'stale': body['observedGeneration'] = '7'
            if mode == 'partial': body['_coverage'] = {'template': {'status': 'unavailable'}}
            if mode == 'synthetic': body['status'] = {'imageDigest': 'invented'}
            if mode == 'secret_field': containers[0]['env'] = [{'value': TOKEN}]
        elif 'cloudresourcemanager' in url and mode == 'project': body['projectId'] = 'foreign'
        elif '/dockerImages/' in url:
            if mode == 'docker_name': body['name'] = body['name'].replace('/images/', '/foreign/')
            if mode == 'docker_uri': body['uri'] = body['uri'].replace('/review/', '/foreign/')
            if mode == 'index': body['mediaType'] = 'application/vnd.oci.image.index.v1+json'
        else:
            if mode == 'repository': body['name'] += '-foreign'
            if mode == 'virtual': body['mode'] = 'VIRTUAL_REPOSITORY'
            if mode == 'remote': body['mode'] = 'REMOTE_REPOSITORY'
    result, metadata, binary, _ = run(alter=alter)
    assert result['status'] == 'UNKNOWN' and not result['complete'] and not binary.calls
    assert TOKEN not in repr(result) and metadata.closed and binary.closed


@pytest.mark.parametrize('endpoint', ['jobs', 'cloudresourcemanager', 'repositories', 'dockerImages'])
@pytest.mark.parametrize('fault', ['denied', 'partial_http', 'truncated', 'oversized',
                                   'stream_oversized', 'duplicate', 'redirect', 'encoding'])
def test_all_metadata_gets_fail_closed_with_bounded_capture(clean, endpoint, fault):
    def match(url, count):
        if endpoint == 'repositories': return '/repositories/' in url and '/dockerImages/' not in url
        return endpoint in url
    result, metadata, binary, _ = run(fault=lambda url, count: fault if match(url, count) else None)
    assert result['status'] == 'UNKNOWN' and not result['complete'] and not binary.calls
    assert metadata.closed and binary.closed and metadata.responses_closed == len(metadata.calls)
    assert all(r['http_attempts'] == 1 for r in result['source_requests'])


@pytest.mark.parametrize('endpoint', ['jobs', 'project', 'repository', 'dockerimage'])
@pytest.mark.parametrize('denied', [False, True])
def test_fresh_revalidation_rejects_change_or_denial(clean, endpoint, denied):
    def matches(url):
        return {'jobs': '/jobs/' in url, 'project': 'cloudresourcemanager' in url,
                'repository': '/repositories/' in url and '/dockerImages/' not in url,
                'dockerimage': '/dockerImages/' in url}[endpoint]
    def alter(url, body, count):
        if count == 2 and matches(url):
            if endpoint == 'jobs': body['etag'] = 'changed'
            elif endpoint == 'project': body['name'] = 'projects/999999999'
            else: body['updateTime'] = '2026-10-20T09:03:00Z'
    result, metadata, binary, _ = run(alter=None if denied else alter,
        fault=lambda url, count: 'denied' if denied and count == 2 and matches(url) else None)
    assert result['status'] == 'UNKNOWN' and not result['complete']
    assert result['rows'][0]['association_revalidated'] is False
    assert len(binary.calls) == 4 and len(metadata.calls) >= 5
    assert metadata.closed and binary.closed


@pytest.mark.parametrize('binary_options', [{'status': 403}, {'truncated': True}, {'redirect': True}, {'challenge': True}])
def test_registry_denied_truncated_redirect_challenge_is_unknown(clean, binary_options):
    result, metadata, binary, _ = run(binary_options=binary_options)
    assert result['status'] == 'UNKNOWN' and result['rows'][0]['association_revalidated']
    assert not result['complete'] and metadata.closed and binary.closed


@pytest.mark.parametrize('failed_engine', ['_scan_kingfisher', '_scan_trufflehog'])
def test_real_other_engine_positive_survives_asymmetric_failure(real, monkeypatch, failed_engine):
    monkeypatch.setattr(scanning, failed_engine, lambda *args: (_ for _ in ()).throw(TimeoutError()))
    result, _, _, _ = run(value=TOKEN)
    assert result['status'] == 'FAIL' and result['complete'] is False
    assert result['rows'][0]['content']['leaks']
    content = result['rows'][0]['content']
    assert next(e for e in content['config_engines']
                if e['engine'] == failed_engine.removeprefix('_scan_'))['status'] == 'unavailable'
    assert all(row['status'] == 'unavailable' for row in content['layer_coverage'])
    assert TOKEN not in repr(result)


@pytest.mark.parametrize('failed_engine', ['_scan_kingfisher', '_scan_trufflehog'])
def test_asymmetric_clean_cannot_pass(clean, monkeypatch, failed_engine):
    monkeypatch.setattr(scanning, failed_engine, lambda *args: (_ for _ in ()).throw(TimeoutError()))
    result, _, _, _ = run()
    assert result['status'] == 'UNKNOWN' and not result['complete']


def test_known_positive_after_an_incomplete_first_container(real):
    # Explicitly deny the first digest, then allow the second selected container.
    selectors, _, _ = fixtures(second=TOKEN)
    denied_url = proposal._requests(selectors[0], SCOPE)[3][0]
    result, metadata, binary, _ = run(second=TOKEN,
        fault=lambda url, count: 'denied' if url == denied_url else None)
    assert [r['status'] for r in result['rows']] == ['UNKNOWN', 'FAIL']
    assert result['status'] == 'FAIL' and not result['complete']
    assert result['rows'][1]['content']['leaks'] and metadata.closed and binary.closed


def test_real_positive_retained_before_later_blob_failure(real, monkeypatch):
    original = Session.request
    def request(self, method, url, **kwargs):
        response = original(self, method, url, **kwargs)
        if len(self.calls) == 4:
            response.status_code = 403
        return response
    monkeypatch.setattr(Session, 'request', request)
    result, _, _, _ = run(value=TOKEN)
    assert result['status'] == 'FAIL' and not result['complete']
    assert result['rows'][0]['content']['leaks']


def test_positive_bytes_remain_evidence_when_changed_metadata_prevents_association(real):
    def alter(url, body, count):
        if '/jobs/' in url and count == 2:
            body['uid'] = '4c03895a-b5b4-4d6c-b8dd-f1979d8f044d'
    result, _, _, _ = run(value=TOKEN, alter=alter)
    assert result['status'] == 'UNKNOWN' and not result['complete']
    row = result['rows'][0]
    assert not row['association_revalidated']
    assert row['content']['byte_status'] == 'FAIL' and row['content']['leaks']
    assert result['observed_runtime_digest'] is None and not result['deployed_bytes_proven']


@pytest.mark.parametrize('field', ['uid', 'generation', 'digest', 'repository', 'image_name'])
def test_identity_change_during_capture_is_unknown(clean, field):
    def alter(url, body, count):
        if count != 2:
            return
        if '/jobs/' in url:
            if field == 'uid': body['uid'] = '4c03895a-b5b4-4d6c-b8dd-f1979d8f044d'
            if field == 'generation': body['generation'] = body['observedGeneration'] = '9'
            if field == 'digest':
                row = body['template']['template']['containers'][0]
                row['image'] = row['image'].split('@')[0] + '@sha256:' + 'f' * 64
        elif '/dockerImages/' in url and field == 'image_name': body['name'] += '-changed'
        elif '/repositories/' in url and field == 'repository': body['name'] += '-changed'
    result, _, binary, _ = run(alter=alter)
    assert result['status'] == 'UNKNOWN' and not result['complete'] and len(binary.calls) == 4


@pytest.mark.parametrize('bound,value', [('MAX_LAYERS', 1), ('MAX_IMAGE', 1),
                                       ('MAX_EXPANDED', 1), ('MAX_MEMBERS', 1)])
def test_native_image_layer_byte_expansion_and_member_bounds(clean, monkeypatch, bound, value):
    monkeypatch.setattr(native, bound, value)
    result, metadata, binary, _ = run()
    assert result['status'] == 'UNKNOWN' and not result['complete']
    assert metadata.closed and binary.closed


def test_native_manifest_digest_and_descriptor_integrity(clean):
    selectors, bodies, blobs = fixtures()
    manifest = next(k for k in blobs if '/manifests/' in k)
    blobs[manifest] += b'corrupted'
    metadata, binary = MetadataSession(bodies), Session(blobs)
    result = proposal.collect_declared_images(transport(), scope=SCOPE, selectors=selectors,
        enabled=True, metadata_session=metadata, image_session=binary)
    assert result['status'] == 'UNKNOWN' and not result['complete'] and len(binary.calls) == 1
    assert metadata.closed and binary.closed


@pytest.mark.parametrize('mode', ['duplicate', 'unknown_key', 'different_uid', 'too_many', 'cross_project'])
def test_closed_unique_bounded_selections(clean, mode):
    selectors, _, _ = fixtures()
    if mode == 'duplicate': selectors *= 2
    if mode == 'unknown_key': selectors[0]['runtime_digest'] = selectors[0]['digest']
    if mode == 'different_uid':
        selectors.append(dict(selectors[0], container_name='sidecar',
                              resource_uid='4c03895a-b5b4-4d6c-b8dd-f1979d8f044d'))
    if mode == 'too_many': selectors = [dict(selectors[0], container_name='worker-' + str(i)) for i in range(5)]
    if mode == 'cross_project':
        selectors[0]['immutable_reference'] = selectors[0]['immutable_reference'].replace('/review/', '/foreign/')
    result, metadata, binary, _ = run(selectors=selectors)
    assert result['status'] == 'UNKNOWN' and not metadata.calls and not binary.calls


def test_real_positive_after_incomplete_config_and_first_layer(real, monkeypatch):
    calls = {}
    def wrapper(name, original):
        def scan(payload, path, timeout):
            calls[name] = calls.get(name, 0) + 1
            if calls[name] <= 2: raise TimeoutError()
            return original(payload, path, timeout)
        return scan
    for name in ('_scan_kingfisher', '_scan_trufflehog'):
        monkeypatch.setattr(scanning, name, wrapper(name, getattr(scanning, name)))
    # No engine reports a positive until the final layer; earlier errors persist.
    result, _, binary, _ = run(value=TOKEN)
    assert result['status'] == 'FAIL' and not result['complete'] and min(calls.values()) >= 3
    assert len(binary.calls) == 4
    content = result['rows'][0]['content']
    assert [row['status'] for row in content['layer_coverage']] == ['unavailable', 'complete']
    assert content['config_engines'] and all(e['status'] == 'unavailable' for e in content['config_engines'])


@pytest.mark.parametrize('budget', [0, 2, 5, 10])
def test_shared_native_call_budget_and_cleanup(clean, budget):
    result, metadata, binary, wire = run(native_transport=transport(max_calls=budget))
    assert result['status'] == 'UNKNOWN' and wire.calls <= budget
    assert metadata.closed and binary.closed


def test_deadline_cancellation_and_metadata_call_cap(clean, monkeypatch):
    def cancelled(): raise TimeoutError('cancelled-sensitive-text')
    result, metadata, binary, _ = run(native_transport=transport(cancel=cancelled))
    assert result['status'] == 'UNKNOWN' and not metadata.calls and not binary.calls
    assert 'sensitive-text' not in repr(result) and metadata.closed and binary.closed
    monkeypatch.setattr(proposal, 'MAX_METADATA_CALLS', 2)
    result, metadata, binary, _ = run()
    assert result['status'] == 'UNKNOWN' and len(metadata.calls) == 2 and not binary.calls
    monkeypatch.setattr(proposal, 'MAX_SECONDS', -1)
    result, metadata, binary, _ = run()
    assert result['status'] == 'UNKNOWN' and not metadata.calls and not binary.calls


def test_source_request_ownership_excludes_other_native_work(clean):
    wire = transport()
    wire.evidence = [{'id': 'request-1', 'scope': 'projects/foreign'}]
    def alter(url, body, count):
        if len(wire.evidence) == 1:
            wire.evidence.append({'id': 'request-2', 'scope': 'projects/unrelated'})
    result, _, _, _ = run(alter=alter, native_transport=wire)
    assert result['status'] == 'PASS'
    owned = set(result['rows'][0]['source_requests'])
    assert not owned.intersection({'request-1', 'request-2'})
    assert owned == {r['id'] for r in result['source_requests']}


def test_cleanup_attempts_both_sessions_even_when_first_close_fails(clean, monkeypatch):
    def close(self):
        self.closed = True
        raise OSError('do-not-retain-close-details')
    monkeypatch.setattr(MetadataSession, 'close', close)
    result, metadata, binary, _ = run()
    assert result['status'] == 'UNKNOWN' and not result['complete']
    assert result['reason'] == 'session_cleanup_incomplete'
    assert metadata.closed and binary.closed and 'close-details' not in repr(result)


def test_metadata_total_bytes_and_registry_call_cap(clean, monkeypatch):
    monkeypatch.setattr(proposal, 'MAX_METADATA_BYTES', 1)
    result, metadata, binary, _ = run()
    assert result['status'] == 'UNKNOWN' and len(metadata.calls) == 1 and not binary.calls
    monkeypatch.setattr(proposal, 'MAX_METADATA_BYTES', 1048576)
    monkeypatch.setattr(native, 'MAX_CALLS', 1)
    result, metadata, binary, _ = run()
    assert result['status'] == 'UNKNOWN' and len(binary.calls) == 1
    assert metadata.closed and binary.closed
