"""Production SDK auth/origin gate -> actual collector -> public engine.

The retained predecessor used a local integration bridge; it has been removed.
Provider DTOs and verdict assertions remain independent of historical CASES.
"""
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import io
import json
import logging
from pathlib import Path
import socket
import threading
from types import SimpleNamespace
from urllib.parse import parse_qsl, urlencode, urlsplit

import pytest
from kubernetes.client import ApiClient, Configuration
from peaso import checks, engine, secret_scanning as scanning
from peaso.snapshot import seal
from peaso.collectors import k8s
from peaso.collectors import k8s_literal_secret_indicators as literals
from peaso.collectors import k8s_selected_log_sample_secret_indicators as source
from peaso.checks import k8s_selected_log_sample_secret_review_20261020 as consumer
from peaso.snapshot import make_snapshot, seal

HOST = 'https://review-log-k8s.invalid:6443'
CLUSTER = 'selected-review-cluster'
AUTH = 'inert-log-review-auth-canary'
TOKEN = 'ghp_' + '7mQ2zR9wL4cV8nK1sF6aH3jP5uD0xB2yE9rT'
PRODUCTION_TYPES = tuple(k8s.TYPES)
PRODUCTION_IDS = frozenset(c.id for c in checks.CHECKS)


def target(namespace='team-a', pod='selected-pod', container='main', cluster=CLUSTER):
    return {'cluster_id': cluster, 'namespace': namespace, 'pod': pod, 'container': container}


def pod(t=None, family='containers', terminated=False):
    t = t or target()
    status_field = {'containers': 'containerStatuses', 'initContainers': 'initContainerStatuses',
        'ephemeralContainers': 'ephemeralContainerStatuses'}[family]
    state = {'terminated': {'startedAt': '2026-01-02T00:00:00Z', 'finishedAt': '2026-01-03T00:00:00Z', 'exitCode': 0}} if terminated else {'running': {'startedAt': '2026-01-02T00:00:00Z'}}
    specification = {family: [{'name': t['container'], 'image': 'example.invalid/not-pulled',
        'env': [{'name': 'MODE', 'value': 'ready'}]}]}
    if family != 'containers':
        specification['containers'] = [{'name': 'unselected-regular', 'image': 'example.invalid/not-pulled'}]
    return {'apiVersion': 'v1', 'kind': 'Pod', 'metadata': {'namespace': t['namespace'], 'name': t['pod'],
        'uid': '7bc47700-1935-41a7-a928-9e49604eda26', 'resourceVersion': '207',
        'creationTimestamp': '2026-01-01T00:00:00Z', 'annotations': {'private-content': 'not retained'}},
        'spec': specification,
        'status': {'phase': 'Running', status_field: [{'name': t['container'], 'containerID': 'containerd://abcdef1234',
            'ready': True, 'image': 'example.invalid/not-pulled', 'imageID': 'containerd://sha256:abcdef1234',
            'restartCount': 0, 'state': state}]}}


class Response:
    def __init__(self, payload, status=200, log=False, headers=None):
        self.raw = json.dumps(payload).encode() if isinstance(payload, (dict, list)) else payload
        self.stream = io.BytesIO(self.raw)
        self.status, self.closed, self.released = status, False, False
        self.headers = {'Content-Type': 'text/plain; charset=utf-8' if log else 'application/json',
            'Content-Length': str(len(self.raw)), **(headers or {})}

    @property
    def data(self):
        pytest.fail('unbounded SDK raw response caching is forbidden')

    def read(self, size):
        assert 0 < size <= 16384
        return self.stream.read(size)

    def close(self): self.closed = True
    def release_conn(self): self.released = True


@pytest.fixture(autouse=True)
def offline(monkeypatch):
    def blocked(*args, **kwargs):
        pytest.fail('live network/DNS/auth is forbidden')
    for name in ('connect', 'connect_ex', 'sendto'):
        monkeypatch.setattr(socket.socket, name, blocked)
    for name in ('create_connection', 'getaddrinfo', 'gethostbyname', 'gethostbyname_ex'):
        monkeypatch.setattr(socket, name, blocked)
    from kubernetes import config
    monkeypatch.setattr(config, 'load_kube_config', blocked)
    monkeypatch.setattr(config, 'load_incluster_config', blocked)
    scanning._RESULTS.clear()
    import inspect
    registered, = [c for c in checks.CHECKS if c.id == source.CHECK]
    assert inspect.unwrap(registered.evaluate) is consumer.evaluate
    assert k8s.TYPES.count(source.KIND) == 1
    yield
    scanning._RESULTS.clear()


def capture(monkeypatch, *, targets=None, value='service ready', real=False, missing=None,
        mutate=None, fault=None, options=None, named=True, combined=False, cluster=CLUSTER,
        configure=None, bridge=True, scanners=None, extra_metadata=None, extra_documents=None):
    targets = targets or [target()]
    trace = SimpleNamespace(calls=[], responses=[], scans=[], readers=[], api=None)
    if not real:
        def detector(payload, path, timeout):
            trace.scans.append((len(payload), path, timeout))
            return [(TOKEN, 'github-pat', 1)] if TOKEN.encode() in payload else []
        monkeypatch.setattr(scanning, '_scan_kingfisher', detector)
        monkeypatch.setattr(scanning, '_scan_trufflehog', detector)
    if missing:
        def unavailable(*a, **kw): raise RuntimeError(TOKEN)
        for name in (('kingfisher', 'trufflehog') if missing == 'both' else (missing,)):
            monkeypatch.setattr(scanning, '_scan_' + name, unavailable)
    for name, function in (scanners or {}).items():
        monkeypatch.setattr(scanning, '_scan_' + name, function)
    if not bridge:
        # Model a missing runtime transport grant, preserving the predecessor's
        # closed-gate witness without replacing the production collector.
        monkeypatch.setattr(source, 'allowed_request', lambda *a: False)
    class Pool:
        def request(self, method, url, **kwargs):
            parsed = urlsplit(url)
            assert method == 'GET' and parsed.scheme == 'https' and parsed.netloc == 'review-log-k8s.invalid:6443'
            assert not parsed.query and not parsed.fragment and not parsed.username
            assert kwargs['headers']['authorization'] == 'Bearer ' + AUTH
            assert kwargs['redirect'] is False and kwargs['retries'] is False
            if extra_documents and parsed.path in extra_documents:
                assert kwargs.get('body') is None
                trace.calls.append((method, parsed.netloc, parsed.path, deepcopy(kwargs.get('fields'))))
                class MetadataResponse(Response):
                    reason = 'Forbidden'
                    @property
                    def data(self): return self.raw
                    def getheaders(self): return self.headers
                    def getheader(self, name, default=None): return self.headers.get(name, default)
                document = extra_documents[parsed.path]
                document, status = document if isinstance(document, tuple) else (document, 200)
                response = MetadataResponse(document, status=status)
                trace.responses.append(response)
                return response
            assert kwargs['headers']['Accept-Encoding'] == 'identity'
            assert kwargs['preload_content'] is False and kwargs['decode_content'] is False
            assert 0 < kwargs['timeout'] <= 10 and kwargs.get('body') is None
            is_log = parsed.path.endswith('/log')
            fields = kwargs.get('fields', {})
            candidates = [t for t in targets if parsed.path in source.request_spec(t, '2026-01-01T00:00:00Z')[:2]]
            t = next(t for t in candidates if not is_log or t['container'] == fields.get('container'))
            if is_log:
                assert fields == source.request_spec(t, fields['sinceTime'])[2]
                assert len(fields) == 8 and fields['tailLines'] == '100' and fields['limitBytes'] == '262144'
                assert fields['follow'] == 'false' and fields['previous'] == 'false'
            else:
                assert not fields
            ordinal = 1 + sum(c[2] == parsed.path for c in trace.calls)
            trace.calls.append((method, parsed.netloc, parsed.path, deepcopy(fields)))
            if fault:
                result = fault(t, is_log, ordinal, fields)
                if result is not None:
                    trace.responses.append(result)
                    return result
            if is_log:
                stamp = (datetime.fromisoformat(fields['sinceTime'].replace('Z', '+00:00')) + timedelta(minutes=30)).isoformat().replace('+00:00', 'Z')
                content = value(t, fields) if callable(value) else value
                raw = (stamp + ' ' + content + '\n').encode()
                result = Response(raw, log=True)
            else:
                document = pod(t)
                for other in candidates:
                    if other['container'] != t['container']:
                        document['spec']['containers'].append(pod(other)['spec']['containers'][0])
                        document['status']['containerStatuses'].append(pod(other)['status']['containerStatuses'][0])
                if combined:
                    document['spec']['containers'][0]['env'][0]['value'] = TOKEN
                if mutate:
                    mutate(document, t, ordinal)
                result = Response(document)
            trace.responses.append(result)
            return result
    def new_api(auth):
        conf = Configuration()
        conf.host = HOST
        conf.verify_ssl = True
        conf.api_key = {'authorization': AUTH}
        conf.api_key_prefix = {'authorization': 'Bearer'}
        client = ApiClient(conf)
        client.rest_client.pool_manager = Pool()
        api = k8s._wrap_client(client)
        api.close = lambda: None
        trace.api = api
        if configure:
            configure(api)
        return api
    monkeypatch.setattr(k8s, '_new_api', new_api)
    from peaso.collectors import k8s_selected_metadata_runtime_20261020 as metadata_runtime
    original_finalize = metadata_runtime.finalize
    def observed_finalize(scopes, collections, metadata, *ledgers):
        # Observation/privacy canaries only: the production collector performs
        # every read and creates every marker, receipt and scope binding.
        assert len(ledgers) == 6
        trace.ledgers = ledgers
        if combined:
            metadata['other_projection'] = {'name': TOKEN, TOKEN: 'safe',
                'encoded': __import__('base64').b64encode(TOKEN.encode()).decode()}
        metadata.update(extra_metadata or {})
        return original_finalize(scopes, collections, metadata, *ledgers)
    monkeypatch.setattr(metadata_runtime, 'finalize', observed_finalize)
    opts = {'content_secret_scans': True, source.OPTION: targets, 'retries': 0, **(options or {})}
    if combined:
        opts[literals.OPTION] = [{'cluster_id': t['cluster_id'], 'namespace': t['namespace'], 'kind': 'Pod', 'name': t['pod']} for t in targets]
    req = {'connector': {'provider': 'k8s', 'scopes': list(dict.fromkeys(t['namespace'] for t in targets)),
        'auth': {'method': 'token', 'server': HOST, 'token': AUTH, 'cluster_id': cluster}, 'options': opts},
        'checks': [source.CHECK] + ([literals.CHECK] if combined else [])}
    if not named:
        req['checks'] = ['k8s.rbac.role_no_wildcards']
        req['connector']['options']['inventories'] = [source.KIND]
    trace.request = req
    snapshot = engine.collect_snapshot(req)
    return snapshot, engine.evaluate_snapshot(snapshot, checks=[source.CHECK])['findings'], trace


def marker(snapshot, pos=0):
    own = next(c for c in snapshot['collections'] if c['type'] == source.KIND)
    return own['items'][pos][source.MARKER]


def verdict(rows): return {row['status'] for row in rows}


def pure(snapshot, pos=0):
    own = next(c for c in snapshot['collections'] if c['type'] == source.KIND)
    return consumer.evaluate(own['items'][pos], {'context': {'provider': 'k8s', 'scope': own['scope'],
        'metadata': snapshot['metadata'], 'created_at': snapshot['created_at']}, 'collections': {source.KIND: [own]}})


@pytest.mark.parametrize('hit', [False, True])
@pytest.mark.parametrize('real', [False, True])
def test_native_sample_public_engine_and_privacy(monkeypatch, hit, real):
    snapshot, rows, trace = capture(monkeypatch, value=TOKEN if hit else 'service ready', real=real)
    assert verdict(rows) == ({'FAIL'} if hit else {'PASS'}), rows
    status, evidence = pure(snapshot)
    assert status == rows[0]['status']
    assert evidence['complete'] is True and evidence['credential_validation'] == 'not_attempted'
    assert len(trace.calls) == 3 and marker(snapshot)['native_bound'] is True
    assert {(e['engine'], e['version'], e['status']) for e in evidence['parts'][0]['engines']} == {
        ('kingfisher', '1.4.0', 'complete'), ('trufflehog', '3.92.5', 'complete')}
    persisted = json.dumps([snapshot, rows, list(scanning._RESULTS.values())])
    assert all(v not in persisted for v in (TOKEN, AUTH, 'service ready', 'not retained', 'example.invalid/not-pulled', 'selected-pod', 'containerd://abcdef1234'))
    assert all(r.closed and r.released for r in trace.responses)
    assert trace.api.api_client.last_response is None
    assert trace.api.api_client.rest_client.pool_manager.literal_paths == frozenset()
    assert trace.api.api_client.rest_client.pool_manager.selected_log_requests == frozenset()
    assert not any(getattr(trace, 'ledgers', ()))  # no found value is queued for scrubbing
    if hit:
        leak, = evidence['secret_leaks']
        assert {d['engine'] for d in leak['detectors']} == {'kingfisher', 'trufflehog'}


@pytest.mark.parametrize('missing', ['kingfisher', 'trufflehog', 'both'])
@pytest.mark.parametrize('hit', [False, True])
def test_independent_detector_failure(monkeypatch, missing, hit):
    snapshot, rows, trace = capture(monkeypatch, value=TOKEN if hit else 'ready', missing=missing)
    expected = 'FAIL' if hit and missing != 'both' else 'UNKNOWN'
    assert verdict(rows) == ({'FAIL', 'UNKNOWN'} if expected == 'FAIL' else {'UNKNOWN'}), rows
    if expected == 'FAIL':
        failure, = [r for r in rows if r['status'] == 'FAIL']
        assert failure['evidence']['complete'] is False
        assert pure(snapshot)[0] == 'FAIL'
        assert {d['engine'] for l in failure['evidence']['secret_leaks'] for d in l['detectors']} == ({'kingfisher', 'trufflehog'} - {missing})
    assert TOKEN not in json.dumps([snapshot, rows]) and len(trace.calls) == 3


@pytest.mark.parametrize('step', ['before', 'log', 'after'])
@pytest.mark.parametrize('status', [206, 301, 401, 403, 404, 429, 500])
def test_denied_partial_error_status_never_clean(monkeypatch, step, status):
    def fault(t, log, ordinal, fields):
        if (step == 'log' and log) or (step == 'before' and not log and ordinal == 1) or (step == 'after' and not log and ordinal == 2):
            return Response(TOKEN.encode(), status, log=log)
    snapshot, rows, trace = capture(monkeypatch, value=TOKEN, fault=fault)
    assert verdict(rows) == {'UNKNOWN'} and marker(snapshot)['native_bound'] is False
    assert TOKEN not in json.dumps([snapshot, rows])
    assert len(trace.calls) == {'before': 1, 'log': 2, 'after': 3}[step]
    assert all(r.closed and r.released for r in trace.responses)


@pytest.mark.parametrize('field', ['namespace', 'name', 'uid', 'resourceVersion', 'apiVersion', 'kind',
    'missing_status', 'missing_container', 'duplicate_container', 'duplicate_status', 'restart_bool',
    'restart_negative', 'containerID', 'waiting', 'future_start', 'bad_creation', 'deleting', 'partial'])
def test_native_identity_and_status_guards(monkeypatch, field):
    def mutate(obj, t, ordinal):
        meta = obj['metadata']; entry = obj['status']['containerStatuses'][0]
        if field in ('namespace', 'name'): meta[field] = 'foreign'
        elif field == 'uid': meta[field] = 'not-a-uid'
        elif field == 'resourceVersion': meta[field] = ''
        elif field == 'apiVersion': obj[field] = 'apps/v1'
        elif field == 'kind': obj[field] = 'ConfigMap'
        elif field == 'missing_status': obj.pop('status')
        elif field == 'missing_container': obj['spec']['containers'][0]['name'] = 'sibling'
        elif field == 'duplicate_container': obj['spec']['containers'].append(deepcopy(obj['spec']['containers'][0]))
        elif field == 'duplicate_status': obj['status']['containerStatuses'].append(deepcopy(entry))
        elif field == 'restart_bool': entry['restartCount'] = False
        elif field == 'restart_negative': entry['restartCount'] = -1
        elif field == 'containerID': entry['containerID'] = 'opaque-unbound-id'
        elif field == 'waiting': entry['state'] = {'waiting': {'reason': 'Pending'}}
        elif field == 'future_start': entry['state']['running']['startedAt'] = '2099-01-01T00:00:00Z'
        elif field == 'bad_creation': meta['creationTimestamp'] = 'tomorrow'
        elif field == 'deleting': meta['deletionTimestamp'] = '2026-01-02T00:00:00Z'
        elif field == 'partial': obj['_partial'] = True
    snapshot, rows, trace = capture(monkeypatch, mutate=mutate)
    assert verdict(rows) == {'UNKNOWN'} and len(trace.calls) == 1


@pytest.mark.parametrize('field', ['uid', 'version', 'restart', 'container', 'started', 'context'])
def test_before_after_races_cannot_bind_a_hit(monkeypatch, field):
    def mutate(obj, t, ordinal):
        if ordinal != 2: return
        entry = obj['status']['containerStatuses'][0]
        if field == 'uid': obj['metadata']['uid'] = '8bc47700-1935-41a7-a928-9e49604eda26'
        elif field == 'version': obj['metadata']['resourceVersion'] = '208'
        elif field == 'restart': entry['restartCount'] += 1
        elif field == 'container': entry['containerID'] = 'containerd://new123'
        elif field == 'started': entry['state']['running']['startedAt'] = '2026-01-02T01:00:00Z'
    def fault(t, log, ordinal, fields):
        if field == 'context' and log:
            # A native current-log read cannot be associated with a later
            # changed authenticated context, even if the Pod DTO stays equal.
            trace_ref[0].api.api_client.configuration.api_key['authorization'] = 'changed-context'
        return None
    trace_ref = []
    if field == 'context':
        def configure(api): trace_ref.append(SimpleNamespace(api=api))
    else: configure = None
    snapshot, rows, trace = capture(monkeypatch, mutate=mutate, value=TOKEN, configure=configure, fault=fault)
    assert verdict(rows) == {'UNKNOWN'} and marker(snapshot)['native_bound'] is False
    assert TOKEN not in json.dumps(snapshot) and len(trace.calls) <= 3


@pytest.mark.parametrize('case', ['empty', 'no_newline', 'bad_utf8', 'binary', 'too_many_lines', 'no_stamp',
    'old', 'future', 'before_start', 'nano_future', 'at_limit', 'over_limit', 'length_mismatch', 'bad_length',
    'content_range', 'wrong_media', 'encoded', 'duplicate_json', 'wrong_json', 'body_type'])
def test_bounded_response_and_timestamp_guards(monkeypatch, case):
    def fault(t, log, ordinal, fields):
        if not log:
            if case == 'duplicate_json': return Response(b'{"kind":"Pod","kind":"Pod"}')
            if case == 'wrong_json': return Response(b'not JSON ' + TOKEN.encode())
            return None
        start = datetime.fromisoformat(fields['sinceTime'].replace('Z', '+00:00'))
        stamp = (start + timedelta(minutes=30)).isoformat().replace('+00:00', 'Z')
        raw = (stamp + ' ready\n').encode(); headers = {}
        if case == 'empty': raw = b''
        elif case == 'no_newline': raw = raw.rstrip(b'\n')
        elif case == 'bad_utf8': raw = stamp.encode() + b' \xff\n'
        elif case == 'binary': raw = stamp.encode() + b' a\x00b\n'
        elif case == 'too_many_lines': raw *= 101
        elif case == 'no_stamp': raw = b'no time prefix\n'
        elif case in ('old', 'future', 'before_start', 'nano_future'):
            bad = {'old': start - timedelta(seconds=1), 'future': start + timedelta(hours=1, seconds=1),
                'before_start': datetime(2026, 1, 1, tzinfo=timezone.utc), 'nano_future': start + timedelta(hours=1)}[case]
            bad_stamp = bad.isoformat(timespec='microseconds').replace('+00:00', 'Z')
            if case == 'nano_future': bad_stamp = bad_stamp[:-1] + '001Z'
            raw = (bad_stamp + ' ' + TOKEN + '\n').encode()
        elif case in ('at_limit', 'over_limit'): raw = b'x' * (source.MAX_LOG + (case == 'over_limit'))
        elif case == 'length_mismatch': headers['Content-Length'] = str(len(raw) + 1)
        elif case == 'bad_length': headers['Content-Length'] = '1e9'
        elif case == 'content_range': headers['Content-Range'] = 'bytes 0-20/100'
        elif case == 'wrong_media': headers['Content-Type'] = 'application/json'
        elif case == 'encoded': headers['Content-Encoding'] = 'gzip'
        response = Response(raw, log=True, headers=headers)
        if case == 'body_type': response.read = lambda _: 'decoded unsafe text'
        return response
    snapshot, rows, trace = capture(monkeypatch, fault=fault)
    assert verdict(rows) == {'UNKNOWN'} and TOKEN not in json.dumps(snapshot)
    assert all(r.closed and r.released for r in trace.responses)


@pytest.mark.parametrize('family', ['containers', 'initContainers', 'ephemeralContainers'])
def test_native_container_families(monkeypatch, family):
    def mutate(obj, t, ordinal):
        fresh = pod(t, family)
        obj.clear(); obj.update(fresh)
    _, rows, trace = capture(monkeypatch, mutate=mutate)
    assert verdict(rows) == {'PASS'} and len(trace.calls) == 3


def test_terminated_current_instance_and_timestamp_bounds(monkeypatch):
    fixed = (datetime.now(timezone.utc) - timedelta(minutes=5)).isoformat().replace('+00:00', 'Z')
    def mutate(obj, t, ordinal):
        entry = obj['status']['containerStatuses'][0]
        obj['status']['phase'] = 'Succeeded'
        entry['state'] = {'terminated': {'startedAt': '2026-01-02T00:00:00Z',
            'finishedAt': fixed, 'exitCode': 0}}
    _, rows, _ = capture(monkeypatch, mutate=mutate)
    assert verdict(rows) == {'PASS'}


@pytest.mark.parametrize('option', [False, 'unnamed'])
def test_explicit_double_gate_no_content_reads(monkeypatch, option):
    snapshot, rows, trace = capture(monkeypatch, options={'content_secret_scans': option is not False}, named=option != 'unnamed')
    assert not trace.calls and verdict(rows) == {'UNKNOWN'}


def test_production_transport_without_exact_grant_remains_closed(monkeypatch):
    _, rows, trace = capture(monkeypatch, bridge=False)
    assert verdict(rows) == {'UNKNOWN'} and len(trace.calls) == 1


@pytest.mark.parametrize('mode', ['cluster', 'origin', 'tls', 'auth'])
def test_cluster_and_authenticated_origin_binding(monkeypatch, mode):
    def configure(api):
        if mode == 'origin': api.api_client.configuration.host = 'https://foreign.invalid'
        if mode == 'tls': api.api_client.configuration.verify_ssl = False
        if mode == 'auth': api.api_client.configuration.api_key = {}
    _, rows, trace = capture(monkeypatch, cluster='foreign-cluster' if mode == 'cluster' else CLUSTER, configure=configure)
    assert verdict(rows) == {'UNKNOWN'} and not trace.calls


@pytest.mark.parametrize('case', ['zero', 'five', 'duplicate', 'wildcard_ns', 'foreign_ns', 'path', 'extra', 'cluster', 'container', 'pod_empty'])
def test_exact_selector_rejection_before_transport(case):
    values = [target()]; scopes = ['team-a']
    if case == 'zero': values = []
    elif case == 'five': values = [target(pod='pod-' + str(i)) for i in range(5)]
    elif case == 'duplicate': values *= 2
    elif case == 'wildcard_ns': scopes = ['*']
    elif case == 'foreign_ns': values[0]['namespace'] = 'foreign'
    elif case == 'path': values[0]['pod'] = 'pod/exec'
    elif case == 'extra': values[0]['previous'] = True
    elif case == 'cluster': values.append(target(pod='other', cluster='different'))
    elif case == 'container': values[0]['container'] = '*'
    elif case == 'pod_empty': values[0]['pod'] = ''
    with pytest.raises(ValueError):
        source.selected_targets({'content_secret_scans': True, '_content_secret_scan_kinds': [source.KIND], source.OPTION: values}, scopes)


def test_four_targets_same_value_and_cross_adapter_union(monkeypatch):
    targets = [target(pod='pod-' + str(i), namespace='team-' + ('a' if i < 2 else 'b')) for i in range(4)]
    snapshot, rows, trace = capture(monkeypatch, targets=targets, value=TOKEN)
    assert verdict(rows) == {'FAIL'} and len(rows) == 1 and len(trace.calls) == 12
    leaks = scanning.merge_leaks([l for row in rows for l in row['evidence']['secret_leaks']])
    assert len(leaks) == 1 and len(leaks[0]['locations']) == 4
    assert len({row['id'] for row in snapshot['collections'][0]['items']}) == 2


def test_literal_log_same_value_hmac_and_union_redaction(monkeypatch):
    snapshot, rows, trace = capture(monkeypatch, combined=True, value=TOKEN)
    all_rows = engine.evaluate_snapshot(snapshot, checks=[source.CHECK, literals.CHECK])['findings']
    assert verdict(all_rows) == {'FAIL'} and len(all_rows) == 1
    leaks = scanning.merge_leaks([l for row in all_rows for l in row['evidence']['secret_leaks']])
    assert len(leaks) == 1 and len(leaks[0]['locations']) == 2
    assert set(all_rows[0]['linked_check_ids']) == {source.CHECK, literals.CHECK}
    # Found values are never masked; positive scan outcomes are not cached.
    assert 'REDACTED' not in json.dumps([snapshot, all_rows]) and TOKEN not in json.dumps(list(scanning._RESULTS.values()))
    assert len(trace.calls) == 5 and not any(getattr(trace, 'ledgers', ()))  # no found value is queued for scrubbing


def test_identity_text_hits_are_redacted_and_exact_dedup(monkeypatch):
    snapshot, rows, _ = capture(monkeypatch, targets=[target(cluster=TOKEN)], cluster=TOKEN)
    assert verdict(rows) == {'FAIL'} and TOKEN in json.dumps([snapshot, rows])  # found values stay visible
    assert scanning._fingerprint(TOKEN) != scanning._fingerprint(TOKEN + ' ')


@pytest.mark.parametrize('limit', [1, 2])
def test_reader_call_budget(monkeypatch, limit):
    _, rows, trace = capture(monkeypatch, options={'max_calls': limit})
    assert verdict(rows) == {'UNKNOWN'} and len(trace.calls) == limit


def test_resource_budget_prevents_second_target_read(monkeypatch):
    _, rows, trace = capture(monkeypatch, targets=[target(), target(pod='second')], options={'max_resources': 1})
    assert len(trace.calls) == 3 and verdict(rows) == {'UNKNOWN'}  # A partial selection cannot prove absence.


def test_deadline_and_cancel_before_native_call(monkeypatch):
    _, rows, trace = capture(monkeypatch, options={'_cancel_check': lambda: True})
    assert verdict(rows) == {'UNKNOWN'} and not trace.calls


@pytest.mark.parametrize('field', ['schema', 'native_bound', 'complete', 'capture', 'uid', 'window', 'receipt', 'engine', 'leak_path', 'leak_line'])
def test_pure_consumer_rejects_tampered_projection(monkeypatch, field):
    snapshot, _, _ = capture(monkeypatch, value=TOKEN)
    tampered = deepcopy(snapshot); m = marker(tampered)
    if field == 'schema': m[field] = 'untrusted'
    elif field == 'native_bound': m[field] = False
    elif field == 'complete': m[field] = 1
    elif field == 'capture': m[field] = 'other'
    elif field == 'uid': m['uid_binding'] = 'native-uid'
    elif field == 'window': tampered['metadata'][source.KIND + '_window'][0] = '2026-01-01T00:00:00Z'
    elif field == 'receipt': tampered['metadata'][source.KIND + '_receipts'][0]['scope'] = 'foreign'
    elif field == 'engine': m['parts'][0]['engines'][0]['version'] = 'unreviewed'
    elif field == 'leak_path': m['leaks'][0]['locations'][0]['path'] = TOKEN
    elif field == 'leak_line': m['leaks'][0]['locations'][0]['line'] = 1000000
    rows = engine.evaluate_snapshot(seal(tampered), checks=[source.CHECK])['findings']
    assert verdict(rows) == {'UNKNOWN'}


@pytest.mark.parametrize('change', ['follow', 'previous', 'limit', 'duplicate', 'container', 'path', 'since', 'exec'])
def test_proposed_exact_query_allowlist(change):
    _, path, fields = source.request_spec(target(), '2026-10-20T08:00:00Z')
    grants = frozenset({(path, tuple(sorted(fields.items())))})
    assert source.allowed_request(path, urlencode(fields), grants)
    if change == 'follow': fields['follow'] = 'true'
    elif change == 'previous': fields['previous'] = 'true'
    elif change == 'limit': fields['limitBytes'] = '999999'
    elif change == 'container': fields['container'] = 'sibling'
    elif change == 'path': path = path.replace('team-a', 'foreign')
    elif change == 'since': fields['sinceTime'] = '2020-01-01T00:00:00Z'
    elif change == 'exec': path = path[:-3] + 'exec'
    query = urlencode(fields) + ('&follow=false' if change == 'duplicate' else '')
    assert not source.allowed_request(path, query, grants)


def test_two_selected_containers_in_one_pod(monkeypatch):
    snapshot, rows, trace = capture(monkeypatch, targets=[target(), target(container='sidecar')], value=TOKEN)
    assert verdict(rows) == {'FAIL'} and len(rows) == 1 and len(trace.calls) == 6
    assert len(rows[0]['evidence']['secret_leaks'][0]['locations']) == 2
    assert len({i['id'] for i in snapshot['collections'][0]['items']}) == 2


@pytest.mark.parametrize('hit', [False, True])
def test_other_selected_target_denial_cannot_clean_sample(monkeypatch, hit):
    def fault(t, log, ordinal, fields):
        if t['pod'] == 'denied' and not log:
            return Response(TOKEN.encode(), status=403)
    snapshot, rows, trace = capture(monkeypatch, targets=[target(), target(pod='denied')],
        value=TOKEN if hit else 'ready', fault=fault)
    assert verdict(rows) == ({'UNKNOWN', 'FAIL'} if hit else {'UNKNOWN'})
    if hit:
        failure, = [r for r in rows if r['status'] == 'FAIL']
        assert failure['evidence']['complete'] is False
    assert len(trace.calls) == 4 and TOKEN not in json.dumps(snapshot)


def test_union_redaction_across_disagreeing_detector_values(monkeypatch):
    second = 'ghp_' + '9nK2vF7mT4bR1sQ8wC3aH5jP6uD0xL2yE9zV'
    def king(raw, path, timeout): return [(TOKEN, 'rule-one', 1)]
    def truffle(raw, path, timeout): return [(second, 'rule-two', 1)]
    snapshot, rows, _ = capture(monkeypatch, value=TOKEN + ' ' + second,
        scanners={'kingfisher': king, 'trufflehog': truffle},
        extra_metadata={'union': {TOKEN: second, 'name': TOKEN + second}})
    assert verdict(rows) == {'FAIL'} and len(rows) == 2
    assert 'REDACTED' not in json.dumps([snapshot, rows])  # found values are never masked


def test_failed_detector_observed_values_redacted_without_trusting_hit(monkeypatch):
    def malformed(raw, path, timeout): return [(TOKEN, 'one', 1), ('', 'invalid', 2)]
    snapshot, rows, _ = capture(monkeypatch, value=TOKEN,
        scanners={'kingfisher': malformed, 'trufflehog': lambda *a: []},
        extra_metadata={'name': TOKEN})
    assert verdict(rows) == {'UNKNOWN'} and marker(snapshot)['leaks'] == []
    assert 'REDACTED' not in json.dumps([snapshot, rows])  # found values are never masked


def test_detected_value_in_current_container_identity_is_not_exported(monkeypatch):
    def mutate(obj, t, ordinal): obj['status']['containerStatuses'][0]['containerID'] = 'containerd://' + TOKEN
    snapshot, rows, _ = capture(monkeypatch, mutate=mutate)
    assert verdict(rows) == {'FAIL'} and TOKEN not in json.dumps([snapshot, rows])


def test_monotonic_deadline_during_log_stream(monkeypatch):
    clock = [0]
    monkeypatch.setattr(source, 'time', SimpleNamespace(monotonic=lambda: clock[0]))
    def fault(t, log, ordinal, fields):
        if log:
            response = Response(b'2026-10-20T00:00:00Z ready\n', log=True)
            native_read = response.read
            def bounded_read(size):
                result = native_read(size)
                clock[0] = source.MAX_SECONDS + 1
                return result
            response.read = bounded_read
            return response
    snapshot, rows, trace = capture(monkeypatch, fault=fault)
    assert verdict(rows) == {'UNKNOWN'} and len(trace.calls) == 2
    assert marker(snapshot)['reason'] == 'deadline_exceeded'
    assert all(r.closed and r.released for r in trace.responses)


def test_total_wire_budget(monkeypatch):
    monkeypatch.setattr(source, 'MAX_TOTAL', 10)
    snapshot, rows, trace = capture(monkeypatch)
    assert verdict(rows) == {'UNKNOWN'} and len(trace.calls) == 1
    assert marker(snapshot)['reason'] == 'native_byte_limit'


def test_timestamps_have_exact_nanosecond_boundaries():
    assert source.timestamp_ns('2026-10-20T09:00:00.000000001Z') == source.timestamp_ns('2026-10-20T09:00:00Z') + 1
    assert source.timestamp_ns('2026-10-20T10:00:00+01:00') == source.timestamp_ns('2026-10-20T09:00:00Z')
    for value in ('2026-10-20T09:00:00+00:60', '2026-10-20T09:00:00.1234567890Z', '2026-10-20T09:00:60Z'):
        with pytest.raises(source.Incomplete): source.timestamp_ns(value)


@pytest.mark.parametrize('bad', [[], ['*'], [['team-a']], ['team-a', 'team-a']])
def test_malformed_namespace_scopes_rejected(bad):
    with pytest.raises(ValueError):
        source.selected_targets({'content_secret_scans': True, source.OPTION: [target()]}, bad)


def native_wire_pool(monkeypatch, *, denied=False):
    """Actual urllib3/http.client framing; only TCP/TLS socket is replaced."""
    import urllib3
    from urllib3.connection import HTTPSConnection
    wire = SimpleNamespace(sent=[], received=[], connections=[])
    class WireSocket:
        def __init__(self): self.request = bytearray(); self.timeout = None
        def sendall(self, content): self.request.extend(content); wire.sent.append(bytes(content))
        def makefile(self, mode, *args, **kwargs):
            assert mode == 'rb'
            line = bytes(self.request).split(b'\r\n', 1)[0].decode()
            method, route, protocol = line.split(' ')
            assert method == 'GET' and protocol == 'HTTP/1.1'
            assert b'authorization: Bearer ' + AUTH.encode() in bytes(self.request)
            parsed = urlsplit(route)
            if parsed.path.endswith('/log'):
                fields = dict(parse_qsl(parsed.query))
                assert fields == source.request_spec(target(), fields['sinceTime'])[2]
                stamp = (datetime.fromisoformat(fields['sinceTime'].replace('Z', '+00:00')) + timedelta(minutes=30)).isoformat().replace('+00:00', 'Z')
                raw = (stamp + ' ' + TOKEN + '\n').encode(); media = 'text/plain'
            else:
                assert parsed.path == source.request_spec(target(), '2026-01-01T00:00:00Z')[0] and not parsed.query
                obj = pod(); obj['metadata']['annotations']['debug-canary'] = TOKEN
                obj['spec']['containers'][0]['env'][0]['value'] = TOKEN
                raw = json.dumps(obj).encode(); media = 'application/json'
            status = '403 Forbidden' if denied else '200 OK'
            if denied: raw = TOKEN.encode()
            response = ('HTTP/1.1 ' + status + '\r\nContent-Type: ' + media + '\r\nContent-Length: ' + str(len(raw)) + '\r\nConnection: close\r\n\r\n').encode() + raw
            wire.received.append(raw)
            return io.BytesIO(response)
        def settimeout(self, value): self.timeout = value
        def gettimeout(self): return self.timeout
        def close(self): pass
        def shutdown(self, *args): pass
    def connect(connection):
        assert connection.host == 'review-log-k8s.invalid'
        connection.sock = WireSocket()
        connection.is_verified = True
        connection.proxy_is_verified = True
        wire.connections.append(connection)
    monkeypatch.setattr(HTTPSConnection, 'connect', connect)
    return urllib3.PoolManager(), wire


@pytest.mark.parametrize('denied', [False, True])
def test_native_sdk_debug_auth_body_path_privacy(monkeypatch, caplog, capsys, denied):
    for name in ('kubernetes.client.rest', 'urllib3', 'urllib3.connectionpool'):
        caplog.set_level(logging.DEBUG, logger=name)
    pool, wire = native_wire_pool(monkeypatch, denied=denied)
    def configure(api): api.api_client.rest_client.pool_manager.pool = pool
    before_filters = {name: list(logging.getLogger(name).filters) for name in ('kubernetes.client.rest', 'urllib3.connectionpool')}
    snapshot, rows, trace = capture(monkeypatch, configure=configure)
    assert verdict(rows) == ({'UNKNOWN'} if denied else {'FAIL'})
    assert wire.sent and any(AUTH.encode() in sent for sent in wire.sent)
    assert any(TOKEN.encode() in received for received in wire.received)
    streams = capsys.readouterr()
    assert all(text not in caplog.text + streams.out + streams.err for text in (AUTH, TOKEN, 'selected-pod'))
    assert TOKEN not in json.dumps([snapshot, rows])
    assert trace.api.api_client.last_response is None
    assert all(logging.getLogger(name).filters == prior for name, prior in before_filters.items())
    logging.getLogger('urllib3.connectionpool').debug('unrelated-after-private-read')
    assert 'unrelated-after-private-read' in caplog.text
    pool.clear()


def test_actual_rest_preloaded_debug_is_a_leak_witness(monkeypatch, caplog):
    """Explains why the sampler never enters the SDK preloaded REST path."""
    caplog.set_level(logging.DEBUG, logger='kubernetes.client.rest')
    pool, wire = native_wire_pool(monkeypatch)
    conf = Configuration(); conf.host = HOST
    api = ApiClient(conf)
    api.rest_client.pool_manager = pool
    path = source.request_spec(target(), '2026-01-01T00:00:00Z')[0]
    response = api.rest_client.GET(HOST + path, headers={'authorization': 'Bearer ' + AUTH}, _preload_content=True)
    assert response.status == 200 and TOKEN in caplog.text
    assert any(AUTH.encode() in sent for sent in wire.sent)
    caplog.clear()
    pool.clear()


@pytest.mark.parametrize('mode', ['sdk', 'http', 'urllib3', 'pooled'])
def test_unsafe_wire_debug_fails_closed_without_global_toggles(monkeypatch, caplog, capsys, mode):
    import http.client
    from urllib3.connection import HTTPSConnection
    before = http.client.HTTPConnection.debuglevel
    def configure(api):
        if mode == 'sdk':
            # Preserve external state with monkeypatch; the production reader
            # itself must never disable caller logging or wire debug globally.
            for name in ('client', 'urllib3'):
                caplog.set_level(logging.getLogger(name).level, logger=name)
            monkeypatch.setattr(http.client.HTTPConnection, 'debuglevel', before)
            api.api_client.configuration.debug = True
        elif mode == 'http': monkeypatch.setattr(http.client.HTTPConnection, 'debuglevel', 1)
        elif mode == 'urllib3': monkeypatch.setattr(HTTPSConnection, 'debuglevel', 1)
        else:
            import urllib3
            manager = urllib3.PoolManager()
            existing = manager.connection_from_url(HOST)
            connection = HTTPSConnection('review-log-k8s.invalid')
            connection.debuglevel = 1
            existing.pool.get(); existing.pool.put(connection)
            api.api_client.rest_client.pool_manager.pool = manager
    snapshot, rows, trace = capture(monkeypatch, configure=configure)
    assert verdict(rows) == {'UNKNOWN'} and not trace.calls
    assert marker(snapshot)['reason'] == 'unsafe_native_wire_debug'
    streams = capsys.readouterr()
    assert AUTH not in caplog.text + streams.out + streams.err
    if mode in ('sdk', 'http'): assert http.client.HTTPConnection.debuglevel == 1
    elif mode == 'urllib3': assert HTTPSConnection.debuglevel == 1
    else: assert http.client.HTTPConnection.debuglevel == before


def test_scoped_sdk_filters_preserve_unrelated_and_other_thread_logs(caplog):
    logger = logging.getLogger('kubernetes.client.rest')
    caplog.set_level(logging.DEBUG, logger=logger.name)
    caplog.set_level(logging.DEBUG, logger='unrelated.component')
    prior = list(logger.filters)
    with pytest.raises(RuntimeError):
        with source.private_native_logs():
            logger.debug('private-content-must-be-hidden')
            logging.getLogger('unrelated.component').debug('same-thread-unrelated-preserved')
            worker = threading.Thread(target=lambda: logger.debug('other-thread-sdk-preserved'))
            worker.start(); worker.join(timeout=2)
            assert not worker.is_alive()
            raise RuntimeError('fixed failure')
    assert 'private-content-must-be-hidden' not in caplog.text
    assert 'same-thread-unrelated-preserved' in caplog.text and 'other-thread-sdk-preserved' in caplog.text
    assert logger.filters == prior
    logger.debug('filters-restored-on-exception')
    assert 'filters-restored-on-exception' in caplog.text


def test_overlapping_private_reads_restore_only_their_own_filters(caplog):
    logger = logging.getLogger('urllib3.connectionpool')
    caplog.set_level(logging.DEBUG, logger=logger.name)
    before = list(logger.filters)
    barrier = threading.Barrier(2)
    def private():
        with source.private_native_logs():
            barrier.wait(timeout=2)
            logger.debug('concurrent-private-record')
            barrier.wait(timeout=2)
    worker = threading.Thread(target=private)
    worker.start()
    with source.private_native_logs():
        barrier.wait(timeout=2)
        logger.debug('main-private-record')
        barrier.wait(timeout=2)
    worker.join(timeout=2)
    assert not worker.is_alive() and logger.filters == before
    assert 'concurrent-private-record' not in caplog.text and 'main-private-record' not in caplog.text


_NATIVE_FIXTURE = Path('peaso/checks/k8s_selected_log_sample_secret_review_20261020_native_fixtures.json')


@pytest.mark.parametrize('name', ['clean', 'hit', 'one_engine_hit', 'one_engine_no_hit', 'denied', 'partial', 'restart', 'disabled'])
def test_current_native_fixture_public_engine(name):
    receipt = json.loads(_NATIVE_FIXTURE.read_text())
    assert receipt['registration'] == 'unregistered_proposal_only'
    case, = [c for c in receipt['cases'] if c['name'] == name]
    snapshot = case['snapshot']
    status, evidence = pure(snapshot)
    assert status == case['consumer_status']
    rows = engine.evaluate_snapshot(snapshot, checks=[source.CHECK])['findings']
    assert sorted(verdict(rows)) == case['public_statuses']
    assert len(case['native_http_requests']) == len(case['native_http_responses'])
    if status != 'UNKNOWN':
        assert len(case['native_http_requests']) == 3
        assert [r['method'] for r in case['native_http_requests']] == ['GET'] * 3
        assert evidence['credential_validation'] == 'not_attempted'


def test_detected_namespace_is_hidden_and_scope_redaction_cannot_prove_clean(monkeypatch):
    sensitive = 'sensitive-canary'
    def detector(raw, path, timeout):
        return [(sensitive, 'identity-canary', 1)] if sensitive.encode() in raw else []
    snapshot, rows, _ = capture(monkeypatch, targets=[target(namespace=sensitive)],
        scanners={'kingfisher': detector, 'trufflehog': detector})
    # The existing union scrub marks changed native scope fields unavailable;
    # losing that scope proof must not be ignored to manufacture a clean result.
    assert verdict(rows) == {'FAIL'}  # found values stay visible; the scope is not scrubbed
    assert sensitive in json.dumps([snapshot, rows])
