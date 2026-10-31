"""Default, hosted, scope and privacy gates for the selected Kubernetes log check."""
from copy import deepcopy
import json
import logging
import socket
from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from peaso import checks, engine, secret_scanning as scanning
from peaso.collectors import k8s
from peaso.collectors import k8s_selected_log_sample_secret_indicators as source
from peaso.server.validation import validate_connector
from tests import test_k8s_selected_log_sample_secret_review_20261020 as wire


@pytest.fixture(autouse=True)
def offline(monkeypatch):
    def blocked(*a, **kw): pytest.fail('network/DNS/default authentication forbidden')
    for name in ('connect', 'connect_ex', 'sendto'): monkeypatch.setattr(socket.socket, name, blocked)
    for name in ('getaddrinfo', 'gethostbyname', 'gethostbyname_ex', 'create_connection'): monkeypatch.setattr(socket, name, blocked)
    from kubernetes import config
    for name in ('load_kube_config', 'load_incluster_config', 'new_client_from_config'): monkeypatch.setattr(config, name, blocked)
    scanning._RESULTS.clear()
    yield
    scanning._RESULTS.clear()


def current(): return next(c for c in checks.CHECKS if c.id == source.CHECK)


def base_request(**options):
    return {'connector': {'provider': 'k8s', 'scopes': ['team-a'],
        'auth': {'method': 'token', 'server': wire.HOST, 'token': wire.AUTH, 'cluster_id': wire.CLUSTER},
        'options': options}, 'checks': [source.CHECK]}


def test_default_plan_excludes_new_content_kind_and_explicit_named_plan_includes_it():
    req = base_request(content_secret_scans=True, selected_k8s_log_samples=[wire.target()])
    assert engine.plan_collection(req) == [source.KIND]
    default = deepcopy(req); default.pop('checks')
    assert source.KIND not in engine.plan_collection(default)
    assert source.KIND not in k8s.ENDPOINTS


def test_spoofed_internal_kind_cannot_substitute_for_named_request(monkeypatch):
    snapshot, rows, trace = wire.capture(monkeypatch, named=False,
        options={'_content_secret_scan_kinds': [source.KIND]})
    assert not trace.calls and wire.verdict(rows) == {'UNKNOWN'}
    assert snapshot['metadata'][source.KIND + '_authorized'] is False


@pytest.mark.parametrize('bad', [[], [wire.target(namespace='foreign')], [{**wire.target(), 'previous': True}],
    [{**wire.target(), 'pod': '../exec'}], [wire.target()] * 2])
def test_engine_selector_rejection_precedes_api_creation(monkeypatch, bad):
    def blocked(*a, **kw): pytest.fail('invalid selectors must fail before API creation')
    monkeypatch.setattr(k8s, '_new_api', blocked)
    with pytest.raises(ValueError):
        engine.collect_snapshot(base_request(content_secret_scans=True, selected_k8s_log_samples=bad))


def test_selected_log_scope_wildcard_rejected_pre_auth(monkeypatch):
    req = base_request(content_secret_scans=True, selected_k8s_log_samples=[wire.target()])
    req['connector']['scopes'] = ['*']
    monkeypatch.setattr(k8s, '_new_api', lambda *a: pytest.fail('wildcard selector reached auth'))
    with pytest.raises(ValueError): engine.collect_snapshot(req)


def test_hosted_option_and_exact_namespace_validation(monkeypatch):
    # DNS is a finite declared fixture for the existing public-host policy;
    # no resolver or cloud endpoint is contacted.
    monkeypatch.setattr(socket, 'getaddrinfo', lambda *a, **kw: [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('8.8.8.8', 6443))])
    req = base_request(content_secret_scans=True, selected_k8s_log_samples=[wire.target()])
    validate_connector('k8s', req['connector']['auth'], req['connector']['options'],
        SimpleNamespace(auth_mode='cognito'), scopes=['team-a'])
    for provider, scopes, extra in [('k8s', ['*'], {}), ('azure', ['team-a'], {}),
            ('k8s', ['team-a'], {'_content_secret_scan_kinds': [source.KIND]})]:
        with pytest.raises(HTTPException) as error:
            validate_connector(provider, req['connector']['auth'], {**req['connector']['options'], **extra},
                SimpleNamespace(auth_mode='cognito'), scopes=scopes)
        assert error.value.status_code == 422


def test_hosted_production_selected_job_uses_only_inline_configured_identity(monkeypatch):
    snapshot, rows, trace = wire.capture(monkeypatch, options={'hosted': True})
    assert wire.verdict(rows) == {'PASS'} and len(trace.calls) == 3
    assert snapshot['metadata'][source.KIND + '_authorized'] is True


def test_scope_limit_does_not_read_omitted_namespace(monkeypatch):
    snapshot, rows, trace = wire.capture(monkeypatch,
        targets=[wire.target(), wire.target(namespace='team-b', pod='second')], options={'max_scopes': 1})
    assert len(trace.calls) == 3 and all('/team-a/' in r[2] for r in trace.calls)
    omitted, = [c for c in snapshot['collections'] if c['type'] == source.KIND and c['scope'] == 'team-b']
    assert omitted['status'] not in ('collected', 'empty') and not omitted['items']
    assert 'UNKNOWN' in wire.verdict(rows)


def test_no_ambient_access_capture_and_count_only_progress(monkeypatch):
    from peaso.ai import access
    monkeypatch.setattr(access, 'k8s', lambda *a, **kw: pytest.fail('private content must not capture access identities'))
    progress = []
    snapshot, rows, trace = wire.capture(monkeypatch, options={'_progress_callback': progress.append})
    assert wire.verdict(rows) == {'PASS'} and len(trace.calls) == 3
    assert progress and all(not r.get('scope') for r in progress)
    assert 'selected-pod' not in json.dumps(progress)


@pytest.mark.parametrize('denied', [False, True])
def test_later_real_sdk_metadata_body_debug_is_private_and_cache_is_scrubbed(monkeypatch, caplog, denied):
    caplog.set_level(logging.DEBUG, logger='kubernetes.client.rest')
    caplog.set_level(logging.DEBUG, logger='urllib3.connectionpool')
    obj = wire.pod(); obj['metadata']['labels'] = {'observed-canary': wire.TOKEN}
    obj['spec']['containers'][0]['env'][0]['value'] = wire.TOKEN
    listing = '/api/v1/namespaces/team-a/pods'
    payload = {'apiVersion': 'v1', 'kind': 'PodList', 'metadata': {'resourceVersion': '207'}, 'items': [obj]}
    if denied:
        payload = ({'apiVersion': 'v1', 'kind': 'Status', 'status': 'Failure', 'reason': 'Forbidden',
            'message': wire.TOKEN, 'code': 403}, 403)
    snapshot, rows, trace = wire.capture(monkeypatch, value=wire.TOKEN,
        options={'inventories': [source.KIND, 'pod']}, extra_documents={listing: payload})
    assert wire.verdict(rows) == {'FAIL'} and len(trace.calls) == 4
    assert any(c['type'] == 'pod' and c['status'] == ('denied' if denied else 'collected') for c in snapshot['collections'])
    # Debug logs, the scanner cache and denied error bodies never carry the value.
    assert wire.TOKEN not in caplog.text + json.dumps(list(scanning._RESULTS.values()))
    # A found value stays visible only where it was collected: the pod label.
    # The env literal remains redacted at collection.
    def located(value, path=()):
        if isinstance(value, dict):
            return [p for key, child in value.items() for p in located(child, path + (key,))]
        if isinstance(value, list):
            return [p for index, child in enumerate(value) for p in located(child, path + (index,))]
        return [path] if isinstance(value, str) and wire.TOKEN in value else []
    pod_items = [c for c in snapshot['collections'] if c['type'] == 'pod']
    expected = [] if denied else [('collections', snapshot['collections'].index(pod_items[0]), 'items', 0,
                                   'metadata', 'labels', 'observed-canary')]
    assert located(snapshot) == expected and wire.TOKEN not in json.dumps(rows)
    assert trace.api.api_client.last_response is None
    logging.getLogger('kubernetes.client.rest').debug('unrelated-after-worker-job')
    assert 'unrelated-after-worker-job' in caplog.text


@pytest.mark.parametrize('mode', ['foreign', 'follow', 'previous', 'exec', 'post', 'body', 'duplicate'])
def test_real_transport_exact_grants_preserve_all_other_safety(mode):
    calls = []
    class Pool:
        def request(self, *args, **kwargs): calls.append(args); pytest.fail('unsafe target reached transport')
    pool = k8s._BoundedPool(Pool(), wire.HOST)
    _, path, fields = source.request_spec(wire.target(), '2026-10-20T08:00:00Z')
    pool.selected_log_requests = frozenset({(path, tuple(sorted(fields.items())))})
    host, method, body = wire.HOST, 'GET', None
    if mode == 'foreign': host = 'https://foreign.invalid'
    elif mode == 'follow': fields['follow'] = 'true'
    elif mode == 'previous': fields['previous'] = 'true'
    elif mode == 'exec': path = path[:-3] + 'exec'
    elif mode == 'post': method = 'POST'
    elif mode == 'body': body = 'forbidden'
    url = host + path
    if mode == 'duplicate': url += '?follow=false'
    with pytest.raises(ValueError): pool.request(method, url, fields=fields, body=body)
    assert not calls


@pytest.mark.parametrize('denied', [False, True])
def test_literal_only_actual_sdk_debug_privacy(monkeypatch, caplog, capsys, denied):
    from kubernetes.client import ApiClient, Configuration
    from peaso.collectors import k8s_literal_secret_indicators as literal
    caplog.set_level(logging.DEBUG, logger='kubernetes.client.rest')
    caplog.set_level(logging.DEBUG, logger='urllib3.connectionpool')
    pool, native = wire.native_wire_pool(monkeypatch, denied=denied)
    def scanner(payload, path, timeout):
        return [(wire.TOKEN, 'github-pat', 1)] if wire.TOKEN.encode() in payload else []
    monkeypatch.setattr(scanning, '_scan_kingfisher', scanner)
    monkeypatch.setattr(scanning, '_scan_trufflehog', scanner)
    def api(auth):
        configuration = Configuration(); configuration.host = wire.HOST
        configuration.api_key = {'authorization': wire.AUTH}; configuration.api_key_prefix = {'authorization': 'Bearer'}
        sdk = ApiClient(configuration); sdk.rest_client.pool_manager = pool
        result = k8s._wrap_client(sdk); result.close = lambda: None
        native.api = result
        return result
    monkeypatch.setattr(k8s, '_new_api', api)
    req = base_request(content_secret_scans=True, selected_k8s_literal_resources=[{
        'cluster_id': wire.CLUSTER, 'namespace': 'team-a', 'kind': 'Pod', 'name': 'selected-pod'}])
    req['checks'] = [literal.CHECK]
    before = list(logging.getLogger('urllib3.connectionpool').filters)
    snapshot = engine.collect_snapshot(req)
    rows = engine.evaluate_snapshot(snapshot, checks=[literal.CHECK])['findings']
    assert wire.verdict(rows) == ({'UNKNOWN'} if denied else {'FAIL'})
    assert len(native.sent) == (1 if denied else 2)
    assert any(wire.AUTH.encode() in content for content in native.sent)
    assert source.KIND not in snapshot['metadata']['collection_plan']['requirements']
    streams = capsys.readouterr()
    assert all(value not in caplog.text + streams.out + streams.err for value in (wire.TOKEN, wire.AUTH, 'selected-pod'))
    assert wire.TOKEN not in json.dumps([snapshot, rows])
    assert native.api.api_client.last_response is None
    assert logging.getLogger('urllib3.connectionpool').filters == before
    logging.getLogger('urllib3.connectionpool').debug('unrelated-default-sdk-record-retained')
    assert 'unrelated-default-sdk-record-retained' in caplog.text
    pool.clear()


