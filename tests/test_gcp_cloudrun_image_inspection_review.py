"""Installed optional Cloud Run -> immutable images -> dual detector path."""
from copy import deepcopy
import json
from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from peaso.collectors import gcp
from peaso.collectors import gcp_cloudrun_image_inspection as bridge
from peaso.collectors import gcp_image_secret_indicators as projection
from peaso.collectors import gcp_image_stream_inspection_20261021 as stream
from peaso.engine import evaluate_snapshot
from peaso.server.validation import validate_connector
from tests.test_gcp_cloudrun_content_sources_review import fixture, SERVICE
from tests.test_gcp_image_secret_review_20261019 import (image, Session, SCOPE, REPO, PROJECTS,
    REPOSITORIES, TOKEN, clean, real, isolate)  # noqa: F401


def observed(monkeypatch, mode='complete', *, value='production', enabled=True, kinds=None):
    row, blobs = image(value)
    binary = Session(blobs)
    reader_type = stream.Reader
    monkeypatch.setattr(stream, 'Reader', lambda transport: reader_type(transport, session=binary))
    inputs = fixture()
    for body in list(inputs['service_reads'].values()) + list(inputs['revision_reads'].values()):
        body['metadata']['namespace'] = '123456789'
    for body in inputs['revision_reads'].values():
        body['status']['imageDigest'] = row['uri']
        body['spec']['containers'] = [{'image': row['uri'].removeprefix('https://')}]
    if mode == 'multicontainer':
        next(iter(inputs['revision_reads'].values()))['spec']['containers'] *= 2
    if mode == 'source_coverage':
        next(iter(inputs['service_reads'].values()))['_coverage'] = {'status': {'status': 'unavailable'}}
    calls, services = [], 0

    def request(method, url, **kwargs):
        nonlocal services
        assert method == 'GET'
        calls.append((url, deepcopy(kwargs)))
        status = 200
        if url == 'https://cloudresourcemanager.googleapis.com/v3/' + SCOPE:
            data = {**PROJECTS[0], 'state': 'ACTIVE'}
        elif url == 'https://compute.googleapis.com/compute/v1/' + SCOPE:
            data = {'name': 'review', 'commonInstanceMetadata': {'items': []}}
        elif url.endswith('/locations/us-central1/repositories'):
            data = {'repositories': deepcopy(REPOSITORIES)}
        elif url == 'https://artifactregistry.googleapis.com/v1/' + REPO + '/dockerImages':
            data = {'dockerImages': [{'name': row['name'], 'uri': row['uri'].removeprefix('https://')}]}
        elif url in inputs['service_reads']:
            services += 1
            data = deepcopy(inputs['service_reads'][url])
            if mode == 'service_denied': status = 403
            if mode == 'changed' and services > 1:
                data['metadata']['generation'] = 2
                data['status']['observedGeneration'] = 2
            if mode == 'recreated' and services > 1:
                data['metadata']['uid'] = 'different-native-service'
        elif url in inputs['revision_reads']:
            data = deepcopy(inputs['revision_reads'][url])
            if mode == 'tagged_revision_denied' and url.endswith('api-preview'): status = 403
        elif url.endswith(':getIamPolicy'):
            data = {'bindings': []}
        else:
            raise AssertionError('Unexpected native API: ' + url)
        return SimpleNamespace(status_code=status, headers={}, content=json.dumps(data).encode(), json=lambda: data)

    options = {'content_secret_scans': enabled, '_content_secret_scan_kinds': ['artifact_image'] if kinds is None else kinds,
               'selected_cloudrun_services': [SERVICE],
               'inventories': ['artifact_image', 'artifact_repository', 'project'],
               'artifactregistry_locations': ['us-central1'], 'include_inherited': False,
               'metrics_scopes': False, 'concurrency': 1, 'retries': 0}
    native = gcp.Transport(SimpleNamespace(headers=lambda: {'Authorization': 'Bearer fixture-access-token'},
                                          close=lambda: None), options)
    monkeypatch.setattr(native, '_session', lambda: SimpleNamespace(request=request, close=lambda: None))
    snapshot = gcp.GCPCollector({'provider': 'gcp', 'scopes': [SCOPE], 'options': options},
        requirements=['artifact_image', 'artifact_repository', 'project'], transport=native).collect()
    return snapshot, binary, calls


def test_all_traffic_and_tagged_images_are_inspected_and_bound_to_native_reads(monkeypatch, clean):
    snapshot, binary, calls = observed(monkeypatch)
    findings = evaluate_snapshot(snapshot, checks=[projection.CHECK_ID])['findings']
    assert len(findings) == 1 and findings[0]['status'] == 'PASS', findings
    paths = findings[0]['evidence']['cloudrun_deployment_paths']
    assert {p['revision'].rsplit('/', 1)[1] for p in paths} == {'api-old', 'api-new', 'api-preview'}
    assert len(binary.calls) == 4 and binary.closed  # One shared image read, not three copies.
    service_calls = [r for r in calls if r[0].endswith('/services/api')]
    assert len(service_calls) == 2  # Fresh HTTP revalidation despite native cache.
    row = next(e['items'][0] for e in snapshot['collections'] if e['type'] == 'artifact_image')
    proof = row[bridge.MARKER]
    assert proof['reads'][0]['source_request'] != proof['revalidation'][0]['source_request']


def test_real_offline_tools_merge_one_leak_across_active_revision_paths(monkeypatch, real):
    snapshot, _, _ = observed(monkeypatch, value=TOKEN)
    findings = evaluate_snapshot(snapshot, checks=[projection.CHECK_ID])['findings']
    assert len(findings) == 1 and findings[0]['status'] == 'FAIL', findings
    assert len(findings[0]['evidence']['secret_leaks']) == 1
    assert TOKEN not in repr(snapshot) + repr(findings)


def test_two_containers_with_the_same_immutable_image_share_a_complete_scan(monkeypatch, clean):
    snapshot, binary, _ = observed(monkeypatch, 'multicontainer')
    findings = evaluate_snapshot(snapshot, checks=[projection.CHECK_ID])['findings']
    assert len(findings) == 1 and findings[0]['status'] == 'PASS', findings
    paths = [path for path in findings[0]['evidence']['cloudrun_deployment_paths']
             if path['revision'].endswith('/api-old')]
    assert len(paths) == 2
    assert {path['container_index'] for path in paths} == {0, 1}
    assert all(path['association_kind'] == 'immutable_container_declaration'
               and path['runtime_image_proven'] is False for path in paths)
    assert len(binary.calls) == 4  # The same immutable image is read once.


@pytest.mark.parametrize('mode', ['service_denied', 'tagged_revision_denied', 'source_coverage', 'changed', 'recreated'])
def test_unresolved_active_paths_and_concurrent_changes_never_pass(monkeypatch, clean, mode):
    snapshot, binary, _ = observed(monkeypatch, mode)
    findings = evaluate_snapshot(snapshot, checks=[projection.CHECK_ID])['findings']
    assert findings and all(f['status'] == 'UNKNOWN' for f in findings), findings
    if mode not in ('changed', 'recreated'): assert not binary.calls


@pytest.mark.parametrize('enabled,kinds', [(False, ['artifact_image']), (True, [])])
def test_cloudrun_content_sources_are_off_without_exact_opt_in(monkeypatch, clean, enabled, kinds):
    snapshot, binary, calls = observed(monkeypatch, enabled=enabled, kinds=kinds)
    assert not binary.calls
    assert not any('-run.googleapis.com' in url for url, _ in calls)
    assert all(f['status'] == 'UNKNOWN' for f in evaluate_snapshot(snapshot,
        checks=[projection.CHECK_ID])['findings'])


@pytest.mark.parametrize('tamper', ['request', 'receipt_url', 'body', 'revalidation', 'selection', 'owner'])
def test_consumer_rejects_forged_source_proof(monkeypatch, clean, tamper):
    snapshot, _, _ = observed(monkeypatch)
    row = next(e['items'][0] for e in snapshot['collections'] if e['type'] == 'artifact_image')
    proof = row[bridge.MARKER]
    if tamper == 'request': proof['reads'][0]['source_request'] = 'not-a-source-request'
    if tamper == 'receipt_url':
        rid = proof['reads'][0]['source_request']
        next(r for r in snapshot['metadata']['source_requests'] if r['id'] == rid)['url'] += '-foreign'
    if tamper == 'body': proof['reads'][0]['body']['metadata']['generation'] = 7
    if tamper == 'revalidation': proof['revalidation'] = []
    if tamper == 'selection': proof['selected_artifact_images'] = []
    if tamper == 'owner': row['_provenance']['source_requests'] = []
    # Reseal the modified offline fixture so this tests the consumer's native
    # proof checks, rather than merely triggering the snapshot digest guard.
    from peaso.snapshot import make_snapshot
    snapshot = make_snapshot('gcp', snapshot['scopes'], snapshot['collections'],
        created_at=snapshot['created_at'], metadata=snapshot['metadata'])
    findings = evaluate_snapshot(snapshot, checks=[projection.CHECK_ID])['findings']
    assert findings and all(f['status'] == 'UNKNOWN' for f in findings), findings


def test_public_intake_validates_scopes_and_cannot_supply_private_plan():
    settings = SimpleNamespace(auth_mode='local')
    validate_connector('gcp', {}, {'selected_cloudrun_services': [SERVICE]}, settings, scopes=[SCOPE])
    for provider, scopes, values in [('aws', [SCOPE], [SERVICE]), ('gcp', [], [SERVICE]),
            ('gcp', [SCOPE], []), ('gcp', [SCOPE], [SERVICE.replace('/review/', '/foreign/')]),
            ('gcp', [SCOPE], [SERVICE, SERVICE])]:
        with pytest.raises(HTTPException):
            validate_connector(provider, {}, {'selected_cloudrun_services': values}, settings, scopes=scopes)
    with pytest.raises(HTTPException):
        validate_connector('gcp', {}, {'selected_cloudrun_services': [SERVICE],
            '_cloudrun_image_plan': {}}, SimpleNamespace(auth_mode='cognito'), scopes=[SCOPE])


def test_public_engine_derives_image_authorization_for_selected_run_services(monkeypatch):
    from peaso import engine, collectors
    from peaso.snapshot import make_snapshot
    seen = []
    def collect(connector, requirements):
        seen.append(deepcopy(connector))
        return make_snapshot('gcp', [SCOPE], [])
    monkeypatch.setattr(collectors, 'collect_live', collect)
    engine.collect_snapshot({'connector': {'provider': 'gcp', 'scopes': [SCOPE],
        'options': {'content_secret_scans': True, 'selected_cloudrun_services': [SERVICE]}},
        'checks': [projection.CHECK_ID]})
    assert seen[0]['options']['_content_secret_scan_kinds'] == ['artifact_image']
    assert seen[0]['options']['selected_cloudrun_services'] == [SERVICE]


def test_native_gcr_image_plans_share_the_verified_registry_identity_parser():
    from peaso.collectors import gcp_cloudrun_content_sources as planner
    data = fixture()
    digest = 'sha256:' + 'a' * 64
    uri = 'https://gcr.io/review/nested/api@' + digest
    repo = SCOPE + '/locations/us/repositories/gcr.io'
    for body in data['revision_reads'].values():
        body['status']['imageDigest'] = uri
        body['spec']['containers'] = [{'image': uri.removeprefix('https://')}]
    data['repositories'] = [{'name': repo, 'format': 'DOCKER'}]
    data['image_rows'] = [{'uri': uri, 'digest': digest, 'repository': repo,
        'name': repo + '/dockerImages/nested%2Fapi%40' + digest}]
    result = planner.plan_sources(**data)
    assert result['selected_artifact_images'] == [uri.removeprefix('https://')]
