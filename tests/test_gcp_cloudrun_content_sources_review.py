"""Pure fixtures; executable directly without pytest or session cleanup hooks."""
from copy import deepcopy
import importlib.util
from pathlib import Path

_PATH = Path(__file__).resolve().parents[1] / 'peaso/collectors/gcp_cloudrun_content_sources.py'
_SPEC = importlib.util.spec_from_file_location('cloudrun_planner_review', _PATH)
planner = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(planner)

SCOPE = 'projects/review'
SERVICE = SCOPE + '/locations/us-central1/services/api'
BASE = 'https://us-central1-run.googleapis.com/apis/serving.knative.dev/v1/namespaces/review'
REPO = SCOPE + '/locations/us-central1/repositories/apps'
IMAGE = 'us-central1-docker.pkg.dev/review/apps/nested/api'


def fixture():
    uri = 'https://' + IMAGE + '@sha256:' + 'a' * 64
    def body(name):
        return {'metadata': {'name': name, 'namespace': '1234', 'uid': 'native-' + name, 'generation': 1},
                'status': {'observedGeneration': 1, 'conditions': [{'type': 'Ready', 'status': 'True'}]}}
    service = body('api')
    service['status'].update(latestReadyRevisionName='api-unused', traffic=[
        {'revisionName': 'api-old', 'percent': 90},
        {'revisionName': 'api-new', 'percent': 10, 'latestRevision': True},
        {'revisionName': 'api-preview', 'tag': 'preview'},
        {'revisionName': 'api-inactive', 'percent': 0}])
    revisions = {}
    for name in ('api-old', 'api-new', 'api-preview'):
        revision = body(name)
        revision['metadata']['labels'] = {'serving.knative.dev/service': 'api'}
        revision['spec'] = {'containers': [{'image': IMAGE + ':mutable'}]}
        revision['status']['imageDigest'] = uri
        revisions[BASE + '/revisions/' + name] = revision
    return {'scope': SCOPE, 'services': [SERVICE],
            'projects': [{'projectId': 'review', 'name': 'projects/1234'}],
            'repositories': [{'name': REPO, 'format': 'DOCKER'}],
            'service_reads': {BASE + '/services/api': service}, 'revision_reads': revisions,
            'image_rows': [{'uri': uri, 'digest': 'sha256:' + 'a' * 64, 'repository': REPO,
                            'name': REPO + '/dockerImages/nested%2Fapi%40sha256%3A' + 'a' * 64}]}


def reject(data, code):
    try:
        planner.plan_sources(**data)
    except ValueError as exc:
        assert str(exc) == code, (str(exc), code)
    else:
        raise AssertionError('unsafe fixture accepted: ' + code)


def test_all_traffic_and_tagged_paths_not_latest_ready_only():
    data = fixture()
    original = deepcopy(data)
    result = planner.plan_sources(**data)
    assert {p['revision'].rsplit('/', 1)[1] for p in result['deployment_paths']} == {'api-old', 'api-new', 'api-preview'}
    assert result['deployment_paths'][-1]['tags'] == ['preview']
    assert len(result['selected_artifact_images']) == len(result['image_rows']) == 1
    assert result['complete'] is False and result['content_status'] == 'not_inspected'
    assert data == original
    result['image_rows'][0]['digest'] = 'changed'
    assert data == original


def test_metadata_request_stages_are_fixed_gets():
    data = fixture()
    first = planner.service_requests(SCOPE, [SERVICE])
    second = planner.revision_requests(SCOPE, [SERVICE], projects=data['projects'], service_reads=data['service_reads'])
    assert first == [{'method': 'GET', 'url': BASE + '/services/api', 'scope': SCOPE,
                      'params': {'fields': planner.SERVICE_FIELDS}}]
    assert len(second) == 3 and all(r['method'] == 'GET' and r['params']['fields'] == planner.REVISION_FIELDS for r in second)
    assert 'observedGeneration' in planner.REVISION_FIELDS


def test_service_selection_bounds_duplicates_and_foreign_paths():
    for selection, code in [([], 'bounded_explicit_services_required'),
                            ([SERVICE] * 5, 'bounded_explicit_services_required'),
                            ([SERVICE] * 2, 'duplicate_service_selection'),
                            ([SERVICE.replace('/review/', '/other/')], 'foreign_or_invalid_service_selection'),
                            ([SERVICE + '?x=y'], 'foreign_or_invalid_service_selection')]:
        data = fixture()
        data['services'] = selection
        reject(data, code)
    services = [SERVICE + str(i) for i in range(4)]
    assert len(planner.service_requests(SCOPE, services)) == 4


def test_native_project_alias_must_be_proven_unique():
    for projects in ([], [{'projectId': 'foreign', 'name': 'projects/1234'}],
                     [{'projectId': 'review', 'name': 'projects/1234'}] * 2):
        data = fixture()
        data['projects'] = projects
        reject(data, 'native_project_join_incomplete')


def test_wrong_regional_service_url_is_not_evidence():
    data = fixture()
    data['service_reads'] = {BASE.replace('us-central1-', 'europe-west1-') + '/services/api': next(iter(data['service_reads'].values()))}
    reject(data, 'native_response_missing')


def test_service_and_revision_reconciliation_and_ready_required():
    for kind in ('service_reads', 'revision_reads'):
        for field, value, code in [('observedGeneration', 0, 'native_reconciling'),
                                   ('observedGeneration', 2, 'native_reconciling'),
                                   ('observedGeneration', True, 'native_reconciling'),
                                   ('conditions', [{'type': 'Ready', 'status': 'Unknown'}], 'native_not_ready'),
                                   ('conditions', [{'type': 'Ready', 'status': 'True'}] * 2, 'native_not_ready')]:
            data = fixture()
            next(iter(data[kind].values()))['status'][field] = value
            reject(data, code)


def test_exact_service_revision_namespace_and_parent_relationship():
    for kind in ('service_reads', 'revision_reads'):
        for field, value in [('name', 'foreign'), ('namespace', '5678'), ('deletionTimestamp', '2026-01-01T00:00:00Z')]:
            data = fixture()
            next(iter(data[kind].values()))['metadata'][field] = value
            reject(data, 'native_identity_or_deletion_mismatch')
    data = fixture()
    next(iter(data['revision_reads'].values()))['metadata']['labels']['serving.knative.dev/service'] = 'api-other'
    reject(data, 'native_revision_service_mismatch')


def test_missing_tagged_revision_rejects_whole_plan():
    data = fixture()
    del data['revision_reads'][BASE + '/revisions/api-preview']
    reject(data, 'native_response_missing')


def test_traffic_bad_total_mutable_latest_and_malformed_fields():
    for traffic, code in [([], 'native_traffic_missing_or_bound'),
                          ([{'revisionName': 'api-old', 'percent': 99}], 'native_traffic_incomplete_or_bound'),
                          ([{'latestRevision': True, 'percent': 100}], 'native_traffic_revision_unresolved'),
                          ([{'revisionName': 'api-old', 'percent': True}], 'native_traffic_target_invalid'),
                          ([{'revisionName': 'api-old', 'percent': 100, 'tag': 1}], 'native_traffic_target_invalid'),
                          ([{'revisionName': 'api-old', 'percent': 100, 'tag': 'x'}, {'revisionName': 'api-new', 'tag': 'x'}], 'native_traffic_target_invalid')]:
        data = fixture()
        data['service_reads'][BASE + '/services/api']['status']['traffic'] = traffic
        reject(data, code)


def test_same_revision_multiple_routes_deduplicate_preserving_tags():
    data = fixture()
    data['service_reads'][BASE + '/services/api']['status']['traffic'] = [
        {'revisionName': 'api-old', 'percent': 100}, {'revisionName': 'api-old', 'tag': 'a'},
        {'revisionName': 'api-old', 'tag': 'b'}]
    paths = planner.plan_sources(**data)['deployment_paths']
    assert len(paths) == 1 and paths[0]['traffic_percent'] == 100 and paths[0]['tags'] == ['a', 'b']


def test_multicontainer_revisions_are_explicitly_unsupported():
    data = fixture()
    next(iter(data['revision_reads'].values()))['spec']['containers'].append({'image': IMAGE + ':sidecar'})
    reject(data, 'multi_container_or_missing_container_unsupported')


def test_status_requires_immutable_digest_no_mutable_clean_claim():
    for image, code in [(IMAGE + ':latest', 'immutable_artifact_image_required'),
                         (IMAGE.replace('/review/', '/other/') + '@sha256:' + 'a' * 64, 'foreign_or_unsafe_image'),
                         ('https://evil.example/x@sha256:' + 'a' * 64, 'immutable_artifact_image_required')]:
        data = fixture()
        next(iter(data['revision_reads'].values()))['status']['imageDigest'] = image
        reject(data, code)


def test_spec_must_bind_same_path_and_digest_when_pinned():
    for image, code in [(IMAGE + '@sha256:' + 'b' * 64, 'revision_spec_digest_mismatch'),
                         (IMAGE + '-other:latest', 'revision_spec_image_path_mismatch')]:
        data = fixture()
        next(iter(data['revision_reads'].values()))['spec']['containers'][0]['image'] = image
        reject(data, code)
    data = fixture()
    next(iter(data['revision_reads'].values()))['spec']['containers'][0]['image'] = IMAGE + '@sha256:' + 'a' * 64
    assert planner.plan_sources(**data)['status'] == 'planned'


def test_repository_and_native_docker_image_join_required():
    for key, value, code in [('repositories', [], 'native_repository_join_incomplete'),
                              ('repositories', [{'name': REPO, 'format': 'MAVEN'}], 'native_repository_join_incomplete'),
                              ('image_rows', [], 'native_docker_image_missing_or_duplicate')]:
        data = fixture()
        data[key] = value
        reject(data, code)
    for field, value in [('name', REPO + '/dockerImages/wrong'), ('digest', 'sha256:' + 'b' * 64), ('repository', REPO + '-other')]:
        data = fixture()
        data['image_rows'][0][field] = value
        reject(data, 'native_docker_image_binding_mismatch')
    data = fixture()
    data['image_rows'] *= 2
    reject(data, 'native_docker_image_missing_or_duplicate')


def test_generation_strings_and_id_namespace_are_native():
    data = fixture()
    for kind in ('service_reads', 'revision_reads'):
        for body in data[kind].values():
            body['metadata'].update(namespace='review', generation='1')
            body['status']['observedGeneration'] = '1'
    assert planner.plan_sources(**data)['status'] == 'planned'


def test_multiple_explicit_services_preserve_all_paths():
    data = fixture()
    other_service = SERVICE.replace('/api', '/worker')
    data['services'].append(other_service)
    service = deepcopy(data['service_reads'][BASE + '/services/api'])
    service['metadata']['name'] = 'worker'
    service['status']['traffic'] = [{'revisionName': 'worker-r1', 'percent': 100}]
    data['service_reads'][BASE + '/services/worker'] = service
    revision = deepcopy(data['revision_reads'][BASE + '/revisions/api-old'])
    revision['metadata'].update(name='worker-r1', labels={'serving.knative.dev/service': 'worker'})
    data['revision_reads'][BASE + '/revisions/worker-r1'] = revision
    result = planner.plan_sources(**data)
    assert len(result['deployment_paths']) == 4
    assert {p['service'] for p in result['deployment_paths']} == {SERVICE, other_service}
    assert len(result['image_rows']) == 1


def test_active_revision_total_bound_is_fail_closed():
    data = fixture()
    traffic = [{'revisionName': 'api-old', 'percent': 100}]
    traffic.extend({'revisionName': 'api-r' + str(i), 'tag': 'tag' + str(i)} for i in range(16))
    data['service_reads'][BASE + '/services/api']['status']['traffic'] = traffic
    reject(data, 'native_traffic_incomplete_or_bound')


def test_reader_unique_image_bound_is_fail_closed():
    data = fixture()
    data['revision_reads'] = {}
    data['image_rows'] = []
    traffic = []
    for i in range(5):
        revision = deepcopy(fixture()['revision_reads'][BASE + '/revisions/api-old'])
        name = 'api-r' + str(i)
        digest = 'sha256:' + str(i) * 64
        uri = 'https://' + IMAGE + '@' + digest
        revision['metadata']['name'] = name
        revision['status']['imageDigest'] = uri
        data['revision_reads'][BASE + '/revisions/' + name] = revision
        traffic.append({'revisionName': name, 'percent': 20})
        data['image_rows'].append({'uri': uri, 'digest': digest, 'repository': REPO,
                                  'name': REPO + '/dockerImages/nested/api@' + digest})
    data['service_reads'][BASE + '/services/api']['status']['traffic'] = traffic
    reject(data, 'selected_image_reader_bound')


def test_plans_satisfy_existing_selected_image_reader_pure_contracts():
    # Execute the actual reader validation function definitions without importing
    # its network/scanner dependencies or calling Reader/inspect_image.
    import ast
    import re
    from urllib.parse import unquote
    reader_path = _PATH.with_name('gcp_image_secret_indicators.py')
    tree = ast.parse(reader_path.read_text())
    definitions = [node for node in tree.body if isinstance(node, ast.FunctionDef)
                   and node.name in ('normalize_selected', 'bind_image')]
    parser_spec = importlib.util.spec_from_file_location('registry_uri_review', _PATH.with_name('gcp_registry_image_uri.py'))
    parser_module = importlib.util.module_from_spec(parser_spec)
    parser_spec.loader.exec_module(parser_module)
    namespace = {'re': re, 'unquote': unquote, 'MAX_IMAGES': planner.MAX_IMAGES,
                 '_digest_uri': lambda uri: planner._image(uri, SCOPE), 'parse_image_uri': parser_module.parse}
    exec(compile(ast.Module(body=definitions, type_ignores=[]), str(reader_path), 'exec'), namespace)
    data = fixture()
    result = planner.plan_sources(**data)
    assert namespace['normalize_selected'](result['selected_artifact_images'], SCOPE) == [r['uri'] for r in result['image_rows']]
    for row in result['image_rows']:
        assert namespace['bind_image'](row, SCOPE, data['repositories'], data['projects']) == (row['uri'], row['repository'], row['digest'])


if __name__ == '__main__':
    tests = [(name, value) for name, value in sorted(globals().items()) if name.startswith('test_') and callable(value)]
    for name, test in tests:
        test()
        print('PASS', name)
    print(f'{len(tests)} focused functions passed directly; pytest not invoked')
