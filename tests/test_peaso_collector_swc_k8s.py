"""Provider-owned mocked Kubernetes collection and sw10 shape contracts."""
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import json
from types import SimpleNamespace

import pytest

from peaso.collectors import k8s
from peaso.checks import evaluate_check
from peaso.checks import compliance_new_sw10 as sw10

NOW = datetime.now(timezone.utc).isoformat()
POLICY = {
    'cluster_id': 'fixture', 'observed_at': NOW, 'max_age_seconds': 600, 'max_policy_items': 40,
    'approved_namespaces': ['apps'], 'approved_node_pool_selector': {'pool': 'safe'},
    'approved_node_selector': {'pool': 'safe'}, 'approved_label_selector': {'team': 'safe'},
    'approved_max_request_timeout': 60, 'oldestVersionSupported': 'v1.29.0',
    'system_namespaces': ['kube-system'], 'approved_min_event_qps': 0,
    'in_scope_service_names': ['edge'], 'required_external_traffic_policy': 'Local',
    'allowed_namespaces': ['apps', '*'], 'required_subject_kind': 'Group',
    'required_subject_name': 'incident-response', 'required_role_kind': 'ClusterRole',
    'required_role_name': 'system:view',
}


@pytest.fixture(autouse=True)
def current_test_evidence_time(monkeypatch):
    # Keep the declared 600-second policy meaningful even when this module
    # waits behind other files in the full parallel suite.
    fixed = datetime.fromisoformat(NOW)

    class EvidenceDateTime(datetime):
        @classmethod
        def now(cls, tz=None):
            return fixed.astimezone(tz) if tz else fixed.replace(tzinfo=None)

    monkeypatch.setattr(k8s, "datetime", EvidenceDateTime)
    monkeypatch.setitem(globals(), "datetime", EvidenceDateTime)


def node(i):
    return {'metadata': {'name': f'node-{i}', 'uid': f'n-{i}'}}


def pod(i, component='kube-proxy', args=None):
    return {'metadata': {'namespace': 'kube-system', 'name': f'proxy-{i}', 'uid': f'p-{i}'},
            'spec': {'nodeName': f'node-{i}', 'containers': [{'name': 'component', 'command': [component],
                     'args': ['--metrics-bind-address=127.0.0.1:10249'] if args is None else args}]}}


def manifest():
    return {'status': 'complete', 'cluster_id': 'fixture', 'observed_at': NOW,
            'max_age_seconds': 600, 'max_nodes': 10,
            'nodes': [{'name': f'node-{i}', 'uid': f'n-{i}', 'deployment': 'pod', 'host_managed': False,
                       'pod_namespace': 'kube-system', 'pod_name': f'proxy-{i}', 'pod_uid': f'p-{i}'} for i in (1, 2)]}


class API:
    server = 'https://fixture.invalid'
    api_client = SimpleNamespace(configuration=SimpleNamespace(host=server))

    def __init__(self, *, nodes=None, pods=None, pages=False, fail=None):
        self.rows = {'/api/v1/nodes': [node(1), node(2)] if nodes is None else nodes,
                     '/api/v1/pods': [pod(1), pod(2)] if pods is None else pods}
        self.pages, self.fail, self.calls = pages, fail, []

    def get_json(self, path, params=None):
        self.calls.append((path, deepcopy(params or {})))
        assert path in self.rows
        offset = int((params or {}).get('continue', '0'))
        if self.fail == (path, offset):
            raise k8s.K8sReadError('permission_denied', 403)
        rows = self.rows[path]
        more = self.pages and offset + 1 < len(rows)
        return {'metadata': {'resourceVersion': '7', 'continue': str(offset + 1) if more else ''},
                'items': deepcopy(rows[offset:offset + 1] if self.pages else rows)}


def run(api=None, *, supplied=True, scopes=None, options=None):
    opts = {'inventories': ['pod'], 'retries': 0, 'compliance_policy': deepcopy(POLICY)}
    if supplied:
        opts['metadata_evidence_coverage'] = {'kube_proxy_pod': manifest() if supplied is True else supplied}
    opts.update(options or {})
    api = api or API()
    snap = k8s.collect({'provider': 'k8s', 'auth': {'cluster_id': 'fixture'},
                        'scopes': scopes or ['*'], 'options': opts}, api=api)
    return snap, api


def collection(snap, kind):
    return next(c for c in snap['collections'] if c['type'] == kind)


def test_complete_paged_reads_reused_and_shape_matches_evaluator():
    snap, api = run(API(pages=True), options={'inventories': ['pod', 'node']})
    cov = snap['metadata']['kube_proxy_pod_coverage']
    assert cov['status'] == 'attested_complete' and cov['runtime_verified'] is False
    assert cov['node_count'] == 2
    assert len(snap['collections']) == 2
    for path in ('/api/v1/pods', '/api/v1/nodes'):
        calls = [params for p, params in api.calls if p == path]
        assert len(calls) == 2 and calls[1]['continue'] == '1'
    observed = collection(snap, 'pod')['items'][0]
    assert observed['provenance']['evidence'] == 'read-only list'
    assert observed['spec']['containers'][0]['_component_config']['flags'] == {'metrics-bind-address': '127.0.0.1:10249'}
    index = {'context': {'provider': 'k8s', 'scope': '*', 'created_at': snap['created_at'], 'metadata': snap['metadata']},
             'collections': {'pod': [collection(snap, 'pod')]},
             'pod': [{'type': 'pod', 'data': p, 'scope': '*'} for p in collection(snap, 'pod')['items']]}
    assert evaluate_check('k8s.cis.the_kube_proxy_metrics_service_is_bound_to_localhost', observed, index)[0] == 'PASS'
    for key in POLICY.keys() - {'cluster_id', 'observed_at', 'max_age_seconds', 'max_policy_items'}:
        expected = type(POLICY[key])
        assert sw10._policy(index, key, expected) == POLICY[key]


def test_empty_inventories_stay_empty_without_attestation():
    snap, _ = run(API(nodes=[], pods=[]))
    assert all(c['status'] == 'empty' and not c['items'] for c in snap['collections'])
    assert snap['metadata']['kube_proxy_pod_coverage']['status'] == 'unknown'


@pytest.mark.parametrize('kind', ['node', 'pod'])
@pytest.mark.parametrize('offset,status', [(0, 'denied'), (1, 'partial')])
def test_denied_first_or_later_page_preserves_envelope(kind, offset, status):
    snap, _ = run(API(pages=True, fail=(f'/api/v1/{kind}s', offset)))
    c = collection(snap, kind)
    assert c['status'] == status and len(c['items']) == offset
    assert c['error']['code'] == '403'
    assert snap['metadata']['kube_proxy_pod_coverage']['status'] == 'unknown'


@pytest.mark.parametrize('options', [{'max_pages': 1}, {'max_resources': 1}])
def test_budgets_never_attest_complete(options):
    snap, _ = run(API(pages=True), options=options)
    assert any(c['status'] == 'partial' for c in snap['collections'])
    assert snap['metadata']['kube_proxy_pod_coverage']['status'] == 'unknown'


def test_no_manifest_reuses_only_requested_inventory():
    snap, api = run(supplied=False)
    assert [p for p, _ in api.calls] == ['/api/v1/pods']
    assert snap['metadata']['kube_proxy_pod_coverage']['status'] == 'unknown'


@pytest.mark.parametrize('change', [
    {'cluster_id': 'foreign'}, {'status': 'partial'}, {'max_nodes': 1}, {'max_nodes': True},
    {'max_age_seconds': 0}, {'observed_at': 'bad'},
    {'observed_at': (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()},
    {'observed_at': (datetime.now(timezone.utc) + timedelta(days=1)).isoformat()},
])
def test_invalid_stale_future_or_foreign_manifest_unknown(change):
    supplied = manifest()
    supplied.update(change)
    snap, _ = run(supplied=supplied)
    assert snap['metadata']['kube_proxy_pod_coverage']['status'] == 'unknown'


@pytest.mark.parametrize('change', [{'host_managed': True}, {'deployment': 'host'}, {'uid': 'old'},
                                   {'pod_uid': 'old'}, {'pod_name': 'other'}])
def test_host_or_recreated_node_or_pod_not_attested(change):
    supplied = manifest()
    supplied['nodes'][0].update(change)
    snap, _ = run(supplied=supplied)
    assert snap['metadata']['kube_proxy_pod_coverage']['status'] == 'unknown'


def test_duplicate_or_missing_proxy_declaration_unknown():
    duplicate = pod(1)
    duplicate['metadata'].update(name='extra-proxy', uid='extra-pod')
    for pods in ([pod(1)], [pod(1), duplicate, pod(2)], [pod(1), pod(2, args=['--metrics-bind-address=a', '--metrics-bind-address=b'])]):
        snap, _ = run(API(pods=pods))
        assert snap['metadata']['kube_proxy_pod_coverage']['status'] == 'unknown'


def test_namespace_scoped_inventory_cannot_attest_cluster_coverage():
    api = API()
    api.rows['/api/v1/namespaces/kube-system/pods'] = api.rows.pop('/api/v1/pods')
    snap, _ = run(api, scopes=['kube-system'])
    assert snap['metadata']['kube_proxy_pod_coverage']['status'] == 'unknown'
    assert all(p != '/api/v1/pods' for p, _ in api.calls)


@pytest.mark.parametrize('literal', ['true', 'false'])
def test_apiserver_explicit_token_expiration_literal_and_redaction(literal):
    p = pod(1, 'kube-apiserver', ['--service-account-extend-token-expiration=' + literal,
                                '--request-timeout=30s', '--unknown=INERT-CREDENTIAL'])
    p['spec']['containers'][0]['env'] = [{'name': 'TOKEN', 'value': 'INERT-CREDENTIAL'}]
    snap, _ = run(API(pods=[p]), supplied=False)
    observed = collection(snap, 'pod')['items'][0]
    flags = observed['spec']['containers'][0]['_component_config']['flags']
    assert flags == {'service-account-extend-token-expiration': literal, 'request-timeout': '30s'}
    assert 'INERT-CREDENTIAL' not in json.dumps(snap)
    index = {'context': {'provider': 'k8s', 'scope': '*', 'metadata': snap['metadata'], 'created_at': snap['created_at']},
             'collections': {'pod': [collection(snap, 'pod')]}, 'pod': [{'type': 'pod', 'data': observed, 'scope': '*'}]}
    assert evaluate_check('k8s.cis.the_service_account_extend_token_expiration_parameter_is_set_to_false', observed, index)[0] == ('PASS' if literal == 'false' else 'FAIL')
    assert evaluate_check('k8s.cis.the_request_timeout_argument_is_set_as_appropriate', observed, index)[0] == 'PASS'


def test_apiserver_rejects_positional_boolean_token_expiration():
    p = pod(1, 'kube-apiserver', ['--service-account-extend-token-expiration', 'false'])
    snapshot, _ = run(API(pods=[p]), supplied=False)
    component = collection(snapshot, 'pod')['items'][0]['spec']['containers'][0]['_component_config']
    assert component == {'collection_status': 'malformed',
                         'error': {'code': 'component_boolean_positional_value'}}


def test_missing_flags_remain_absent():
    snap, _ = run(API(pods=[pod(1, 'kube-apiserver', [])]), supplied=False)
    assert collection(snap, 'pod')['items'][0]['spec']['containers'][0]['_component_config']['flags'] == {}


@pytest.mark.parametrize('key,value', [
    ('approved_max_request_timeout', 0), ('approved_max_request_timeout', True),
    ('approved_min_event_qps', -1), ('approved_min_event_qps', False),
    ('approved_namespaces', ['apps', 'apps']), ('approved_namespaces', []),
    ('approved_namespaces', [{}]), ('approved_node_selector', {}),
    ('approved_node_selector', {'bad key': 'x'}), ('approved_label_selector', {'team': []}),
    ('system_namespaces', []), ('allowed_namespaces', ['*', '*']),
    ('required_external_traffic_policy', 'invalid'), ('required_subject_kind', 'Role'),
    ('required_subject_name', ''), ('required_role_kind', 'User'),
    ('oldestVersionSupported', 'v1.29'), ('oldestVersionSupported', 'v1.29.0-01'),
    ('oldestVersionSupported', 'v1.29.0+build..x'),
    ('max_policy_items', 1), ('cluster_id', 'other'), ('max_age_seconds', None),
    ('observed_at', (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()),
])
def test_invalid_policy_rejects_entire_declaration(key, value):
    policy = deepcopy(POLICY)
    policy[key] = value
    snap, _ = run(options={'compliance_policy': policy})
    result = snap['metadata']['compliance_policy']
    assert result['status'] == 'unknown'
    assert not any(k in result for k in ('approved_namespaces', 'required_subject_name', 'oldestVersionSupported'))


@pytest.mark.parametrize('offset,status', [(0, 'unknown'), (1, 'partial')])
def test_unclassified_read_error_preserves_unknown_or_partial(offset, status):
    class Broken(API):
        def get_json(self, path, params=None):
            if path == '/api/v1/pods' and int((params or {}).get('continue', '0')) == offset:
                raise RuntimeError('INERT-PRIVATE-UPSTREAM-BODY')
            return super().get_json(path, params)
    snap, _ = run(Broken(pages=True))
    assert collection(snap, 'pod')['status'] == status
    assert snap['metadata']['kube_proxy_pod_coverage']['status'] == 'unknown'
    assert 'INERT-PRIVATE-UPSTREAM-BODY' not in json.dumps(snap)


@pytest.mark.parametrize('offset,status', [(0, 'malformed'), (1, 'partial')])
def test_malformed_page_preserves_incomplete_coverage(offset, status):
    class Malformed(API):
        def get_json(self, path, params=None):
            if path == '/api/v1/pods' and int((params or {}).get('continue', '0')) == offset:
                return {'metadata': {}, 'items': 'bad'}
            return super().get_json(path, params)
    snap, _ = run(Malformed(pages=True))
    assert collection(snap, 'pod')['status'] == status
    assert snap['metadata']['kube_proxy_pod_coverage']['status'] == 'unknown'


def test_transient_failure_uses_existing_retry_budget(monkeypatch):
    from peaso.collectors import azure
    delays = []
    monkeypatch.setattr(azure.time, 'sleep', delays.append)
    class Transient(API):
        failed = False
        def get_json(self, path, params=None):
            if path == '/api/v1/pods' and not self.failed:
                self.failed = True
                self.calls.append((path, deepcopy(params or {})))
                raise k8s.K8sReadError('unavailable', 503)
            return super().get_json(path, params)
    snap, api = run(Transient(), options={'retries': 1, 'concurrency': 1})
    assert snap['metadata']['kube_proxy_pod_coverage']['status'] == 'attested_complete'
    assert len([p for p, _ in api.calls if p == '/api/v1/pods']) == 2
    assert delays == [.2]


def test_existing_configmap_metadata_transport_and_reference_facts_are_reused():
    import io
    class Response(io.BytesIO):
        def release_conn(self):
            pass
    class MetadataAPI(API):
        def __init__(self):
            super().__init__(pods=[pod(1)])
            self.api_client = SimpleNamespace(configuration=SimpleNamespace(host=self.server), call_api=self.call_api)
            self.rows['/api/v1/pods'][0]['spec'].update(
                serviceAccountName='worker', volumes=[{'name': 'settings', 'configMap': {'name': 'settings', 'optional': False}}])
        def call_api(self, path, method, **kwargs):
            assert method == 'GET' and path == '/api/v1/configmaps'
            assert kwargs['header_params']['Accept'] == 'application/json;as=PartialObjectMetadataList;g=meta.k8s.io;v=v1'
            self.calls.append((path, dict(kwargs['query_params'])))
            return Response(json.dumps({'kind': 'PartialObjectMetadataList', 'metadata': {'resourceVersion': '8'},
                'items': [{'metadata': {'name': 'settings', 'namespace': 'kube-system', 'uid': 'cm1'}}]}).encode())
    snap, api = run(MetadataAPI(), supplied=False, options={'inventories': ['pod', 'configmap_metadata']})
    assert collection(snap, 'configmap_metadata')['status'] == 'collected'
    assert collection(snap, 'configmap_metadata')['items'][0]['provenance']['representation'] == 'PartialObjectMetadataList'
    spec = collection(snap, 'pod')['items'][0]['spec']
    assert spec['serviceAccountName'] == 'worker'
    assert spec['volumes'][0]['configMap'] == {'name': 'settings', 'optional': False}
    assert len([p for p, _ in api.calls if p == '/api/v1/configmaps']) == 1
    assert 'k8s_privesc_challenge_evidence' not in {c['type'] for c in snap['collections']}
