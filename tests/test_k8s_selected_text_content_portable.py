import copy
import io
import inspect
import json
from pathlib import Path
import socket
import sys
from types import SimpleNamespace
from urllib.parse import urlsplit

import pytest
from kubernetes.client import ApiClient, Configuration
from peaso import secret_scanning
from peaso import checks
from peaso.collectors import k8s

from peaso.collectors import k8s_selected_text_content as source
from peaso.checks import k8s_selected_text_content_review as consumer
from peaso.checks import k8s_literal_secret_review_20261020 as base
TOKEN = 'ghp_' + '7mQ2zR9wL4cV8nK1sF6aH3jP5uD0xB2yE9rT'
HOST = 'https://text-k8s.invalid:6443'
CLUSTER = 'text-review'


@pytest.fixture(autouse=True)
def offline(monkeypatch):
    def block(*args, **kwargs):
        raise AssertionError('network and external authentication forbidden')
    for owner, names in ((socket, ('create_connection', 'getaddrinfo')),
                         (socket.socket, ('connect', 'connect_ex', 'sendto'))):
        for name in names:
            monkeypatch.setattr(owner, name, block)
    from kubernetes import config
    monkeypatch.setattr(config, 'load_kube_config', block)
    monkeypatch.setattr(config, 'load_incluster_config', block)
    secret_scanning._RESULTS.clear()
    yield
    secret_scanning._RESULTS.clear()


def target(kind):
    return {'cluster_id': CLUSTER, 'namespace': 'cluster' if kind == 'CustomResourceDefinition' else 'team-a',
            'kind': kind, 'name': 'example.test' if kind == 'CustomResourceDefinition' else 'selected'}


def document(kind, value):
    t = target(kind)
    meta = {'name': t['name'], 'uid': '1111-2222-3333', 'resourceVersion': '17',
            'annotations': {'note': 'ordinary'}}
    if kind != 'CustomResourceDefinition':
        meta['namespace'] = t['namespace']
    result = {'apiVersion': source.NATIVE_KINDS[kind][0], 'kind': kind, 'metadata': meta}
    if kind == 'Event':
        result['message'] = value
    elif kind == 'Ingress':
        result['spec'] = {'rules': [{'host': 'example.test', 'http': {'paths': [{'path': value}]}}]}
    elif kind == 'Gateway':
        result['spec'] = {'listeners': [{'name': 'web', 'hostname': value}]}
    else:
        result['spec'] = {'group': 'example.test', 'names': {'kind': 'Example', 'plural': 'examples'},
                          'versions': [{'name': 'v1', 'schema': {'openAPIV3Schema': {'description': value}}}]}
    return result


class Response:
    def __init__(self, document, status=200):
        self.body = json.dumps(document).encode()
        self.stream = io.BytesIO(self.body)
        self.status = status
        self.headers = {'Content-Type': 'application/json', 'Content-Length': str(len(self.body))}
        self.closed = self.released = False

    @property
    def data(self):
        raise AssertionError('unbounded response retention forbidden')

    def read(self, size):
        assert 0 < size <= 16384
        return self.stream.read(size)

    def close(self):
        self.closed = True

    def release_conn(self):
        self.released = True


def capture(monkeypatch, kind, *, positive=False, mutate=None, status=200, enabled=True):
    t = target(kind)
    doc = document(kind, TOKEN if positive else 'ordinary selected text')
    calls, responses, scans = [], [], []

    def detector(payload, path, timeout):
        scans.append(bytes(payload))
        return [(TOKEN, 'github-pat', 1)] if TOKEN.encode() in payload else []
    monkeypatch.setattr(secret_scanning, '_scan_kingfisher', detector)
    monkeypatch.setattr(secret_scanning, '_scan_trufflehog', detector)

    class Pool:
        def request(self, method, url, **kwargs):
            parsed = urlsplit(url)
            assert method == 'GET' and parsed.scheme == 'https' and parsed.netloc == 'text-k8s.invalid:6443'
            assert parsed.path == source._path(t) and not parsed.query
            assert kwargs['headers']['authorization'] == 'Bearer inert-auth-canary'
            assert kwargs['redirect'] is False and kwargs['retries'] is False
            assert kwargs['preload_content'] is False and kwargs['decode_content'] is False
            assert kwargs.get('body') is None
            calls.append(parsed.path)
            payload = copy.deepcopy(doc)
            if mutate:
                payload = mutate(payload, len(calls))
            response = Response(payload, status)
            responses.append(response)
            return response

    configuration = Configuration()
    configuration.host = HOST
    configuration.api_key = {'authorization': 'inert-auth-canary'}
    configuration.api_key_prefix = {'authorization': 'Bearer'}
    client = ApiClient(configuration)
    client.rest_client.pool_manager = Pool()
    api = k8s._wrap_client(client)
    opts = {'content_secret_scans': enabled, '_content_secret_scan_kinds': [source.KIND] if enabled else [],
            source.OPTION: [t], 'retries': 0}
    reader = k8s.K8sReader(opts)
    try:
        metadata, matches = source.collect(reader, api, opts, [t['namespace']], CLUSTER)
        scopes, collections, metadata = source.redact_output([t['namespace']], reader.collections, metadata, matches)
        own, = collections
        item = own['items'][0] if own['items'] else {}
        index = {'context': {'provider': 'k8s', 'scope': t['namespace'], 'metadata': metadata},
                 'collections': {source.KIND: [own]}}
        result = consumer.evaluate(item, index)
        assert TOKEN not in json.dumps({'metadata': metadata, 'collections': collections, 'result': result})
        assert all(response.closed and response.released for response in responses)
        return result, SimpleNamespace(calls=calls, scans=scans, item=item, index=index)
    finally:
        client.close()


@pytest.mark.parametrize('kind', list(source.NATIVE_KINDS))
@pytest.mark.parametrize('positive', [False, True])
def test_exact_selected_native_text(monkeypatch, kind, positive):
    (status, evidence), trace = capture(monkeypatch, kind, positive=positive)
    assert status == ('FAIL' if positive else 'PASS')
    assert len(trace.calls) == 2 and len(trace.scans) == 2
    assert evidence['complete'] is True


@pytest.mark.parametrize('mutation', [
    lambda doc, n: {**doc, 'kind': 'Pod'},
    lambda doc, n: {**doc, 'metadata': {**doc['metadata'], 'name': 'foreign'}},
    lambda doc, n: {**doc, 'metadata': {**doc['metadata'], 'resourceVersion': str(n)}},
    lambda doc, n: {**doc, 'items': []},
    lambda doc, n: {**doc, 'message': {'wrong': 'type'}},
])
def test_malformed_foreign_changed_incomplete(monkeypatch, mutation):
    result, trace = capture(monkeypatch, 'Event', mutate=mutation)
    assert result[0] == 'UNKNOWN'
    assert len(trace.calls) <= 2


def test_missing_or_disabled_never_pass(monkeypatch):
    result, trace = capture(monkeypatch, 'Event', status=404)
    assert result[0] == 'UNKNOWN' and len(trace.calls) == 1
    result, trace = capture(monkeypatch, 'Event', enabled=False)
    assert result[0] == 'UNKNOWN' and trace.calls == []


def test_missing_native_spec_does_not_turn_annotation_into_clean_result(monkeypatch):
    result, _ = capture(monkeypatch, 'Ingress', mutate=lambda doc, _: {key: value for key, value in doc.items() if key != 'spec'})
    assert result[0] == 'UNKNOWN'


def test_cluster_scoped_route_and_selector():
    t = target('CustomResourceDefinition')
    assert source._path(t) == '/apis/apiextensions.k8s.io/v1/customresourcedefinitions/example.test'
    wrong = {**t, 'namespace': 'team-a'}
    with pytest.raises(source.Incomplete):
        source._path(wrong)
    with pytest.raises(source.Incomplete):
        source.selected_targets({'content_secret_scans': True,
                                 '_content_secret_scan_kinds': [source.KIND],
                                 source.OPTION: [wrong]}, ['team-a'])


def test_selection_scope_and_eight_object_ceiling():
    targets = [{**target('Ingress'), 'name': 'selected-' + str(index)} for index in range(8)]
    options = {'content_secret_scans': True, '_content_secret_scan_kinds': [source.KIND], source.OPTION: targets}
    assert len(source.selected_targets(options, ['team-a'])) == 8
    with pytest.raises(source.Incomplete):
        source.selected_targets({**options, source.OPTION: targets + [{**target('Ingress'), 'name': 'selected-8'}]}, ['team-a'])
    with pytest.raises(source.Incomplete):
        source.selected_targets(options, ['foreign'])


def test_receipt_tamper_is_unknown(monkeypatch):
    (status, _), trace = capture(monkeypatch, 'Gateway')
    assert status == 'PASS'
    tampered = copy.deepcopy(trace.index)
    tampered['context']['metadata'][source.KIND + '_receipts'][0]['status'] = 204
    assert consumer.evaluate(trace.item, tampered)[0] == 'UNKNOWN'


def test_confirmed_hit_survives_later_resource_limit(monkeypatch):
    _, trace = capture(monkeypatch, 'Event', positive=True)
    partial = copy.deepcopy(trace.index)
    scope = partial['context']['scope']
    partial['context']['metadata'][source.KIND + '_selection'][scope].append(source.KIND + ':' + 'f' * 64)
    own = partial['collections'][source.KIND][0]
    own['status'] = 'partial'
    own['error'] = {'code': 'resource_limit'}
    status, evidence = consumer.evaluate(trace.item, partial)
    assert status == 'FAIL' and evidence['complete'] is False
    assert 'not fully read' in evidence['observed']




def test_selected_text_and_configmap_wrapper_coexist(monkeypatch):
    assert consumer._original is base._evaluate_legacy
    assert base.evaluate is not base._evaluate_legacy
    consumer.install()
    check, = [check for check in checks.CHECKS if check.id == source.CHECK]
    assert inspect.unwrap(check.evaluate) is consumer.evaluate
    for positive, expected in ((False, 'PASS'), (True, 'FAIL')):
        _, trace = capture(monkeypatch, 'Event', positive=positive)
        assert checks.evaluate_check(source.CHECK, trace.item, trace.index)[0] == expected
    _, trace = capture(monkeypatch, 'Event', status=404)
    assert checks.evaluate_check(source.CHECK, trace.item, trace.index)[0] == 'UNKNOWN'


def test_registered_native_cases_replay_without_secret_values():
    from peaso.checks.fixtures import CASES
    packaged = json.loads(Path(consumer.__file__).with_name(
        'k8s_selected_text_content_review_cases.json').read_text())[source.CHECK]
    assert CASES[source.CHECK] == packaged
    assert TOKEN not in json.dumps(packaged)
    for branch in ('pass', 'fail', 'unknown', 'missing'):
        expected = branch.upper() if branch != 'missing' else 'UNKNOWN'
        item, index = packaged[branch], packaged[branch + '_index']
        assert consumer.evaluate(item, index)[0] == expected
        assert checks.evaluate_check(source.CHECK, item, index)[0] == expected
