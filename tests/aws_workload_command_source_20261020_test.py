"""Finite direct-file unittest proof; never import either shared registry.

Run: PYTHONPATH=. .venv/bin/python tests/aws_workload_command_source_20261020_test.py
This proves only the NEW unregistered files plus the existing offline helper.
It neither disables nor exercises the original package import/admission guard.
"""
from contextlib import ExitStack
from copy import deepcopy
import importlib.util
import io
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import boto3
from botocore.awsrequest import AWSResponse
from botocore.stub import Stubber
from peaso import secret_scanning as scanning

ROOT = Path(__file__).resolve().parents[1]
# Under pytest, tests/conftest.py loads the published registry before collection;
# a direct-file run loads neither. The proof itself must never load more of either.
REGISTRY_PREFIXES = ('peaso.collectors', 'peaso.checks')


def registry_modules():
    return {name for name in sys.modules if name.startswith(REGISTRY_PREFIXES)}


PRELOADED_REGISTRY_MODULES = registry_modules()


def load(name, relative):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


source = load('workload_command_proof_producer', 'peaso/collectors/aws_workload_command_source_20261020.py')
_SUCCESSOR_BINDING = []


def successor_reviewed_sources():
    """Production replaces the historical docs drift receipt with the packaged
    successor binding (runtime.install_source_successor). Verify that binding in
    a child process so this proof still never imports either shared registry."""
    if not _SUCCESSOR_BINDING:
        out = subprocess.run([sys.executable, '-B', '-c',
            'from peaso.collectors import aws_workload_command_runtime_20261020 as r; print(r.reviewed_sources())'],
            cwd=ROOT, env={**os.environ, 'PYTHONPATH': os.pathsep.join([str(ROOT)] + [p for p in [os.environ.get('PYTHONPATH')] if p])}, capture_output=True, text=True,
            timeout=900, check=True)
        _SUCCESSOR_BINDING.append(out.stdout.strip().splitlines()[-1])
    return _SUCCESSOR_BINDING[0]


source.reviewed_sources = successor_reviewed_sources
consumer = load('workload_command_proof_consumer', 'peaso/checks/aws_workload_command_source_20261020.py')
ACCOUNT, REGION = '123456789012', 'us-east-1'
SCOPE = ACCOUNT + '/' + REGION
TOKEN = 'ghp_' + '7mQ2zR9wL4cV8nK1sF6aH3jP5uD0xB2yE9rT'
CALLER = {'Account': ACCOUNT, 'UserId': 'AIDALOCALREVIEW',
          'Arn': 'arn:aws:iam::' + ACCOUNT + ':user/local-review'}


def target(service='ecs', name='AuditDefinition', revision=3, scope=SCOPE):
    account, region = scope.split('/')
    resource = 'task-definition' if service == 'ecs' else 'job-definition'
    return {'scope': scope, 'service': service,
            'definition_arn': f'arn:aws:{service}:{region}:{account}:{resource}/{name}:{revision}'}


def options(targets):
    return {'content_secret_scans': True, 'check_id': source.CHECK,
            'content_secret_scan_grants': [source.GRANT], source.OPTION: targets}


def metadata():
    return {'HTTPStatusCode': 200, 'RequestId': '11111111-1111-4111-8111-111111111111',
            'HTTPHeaders': {'discarded': TOKEN}}


def response(selected, command=None, entry=None):
    command = ['echo', 'ready'] if command is None else command
    entry = ['/bin/sh', '-c'] if entry is None else entry
    _, _, _, name, revision = source.parse(selected)
    if selected['service'] == 'ecs':
        return {'taskDefinition': {'taskDefinitionArn': selected['definition_arn'],
            'family': name, 'revision': revision, 'status': 'ACTIVE',
            'containerDefinitions': [{'name': 'app', 'entryPoint': entry, 'command': command,
                'image': TOKEN, 'environment': [{'name': 'TOKEN', 'value': TOKEN}],
                'secrets': [{'name': 'TOKEN', 'valueFrom': TOKEN}],
                'environmentFiles': [{'type': 's3', 'value': TOKEN}]}]}, 'ResponseMetadata': metadata()}
    return {'jobDefinitions': [{'jobDefinitionArn': selected['definition_arn'],
        'jobDefinitionName': name, 'revision': revision, 'status': 'ACTIVE', 'type': 'container',
        'containerProperties': {'command': command, 'image': TOKEN,
            'environment': [{'name': 'TOKEN', 'value': TOKEN}],
            'secrets': [{'name': 'TOKEN', 'valueFrom': TOKEN}]}}], 'ResponseMetadata': metadata()}


def definition(payload, service):
    return payload['taskDefinition'] if service == 'ecs' else payload['jobDefinitions'][0]


class Raw:
    def __init__(self, body):
        self.body, self.closed, self.read_bytes = io.BytesIO(body), False, 0

    def read(self, amt, decode_content=False):
        chunk = self.body.read(amt)
        self.read_bytes += len(chunk)
        return chunk

    def stream(self, amt=65536, decode_content=False):
        while chunk := self.body.read(amt):
            self.read_bytes += len(chunk)
            yield chunk

    def close(self):
        self.closed = True
        self.body.close()


class CommandProof(unittest.TestCase):
    def setUp(self):
        self.stack, self.attempts = ExitStack(), []
        def blocked(*args, **kwargs):
            self.attempts.append(True)
            raise AssertionError('live network forbidden')
        for name in ('create_connection', 'getaddrinfo', 'gethostbyname', 'gethostbyname_ex', 'gethostbyaddr', 'getnameinfo'):
            self.stack.enter_context(patch.object(socket, name, blocked))
        for name in ('connect', 'connect_ex', 'sendto'):
            self.stack.enter_context(patch.object(socket.socket, name, blocked))
        self.stack.enter_context(patch.dict(os.environ, {'AWS_EC2_METADATA_DISABLED': 'true',
            'AWS_CONFIG_FILE': '/nonexistent/workload-command-proof',
            'AWS_SHARED_CREDENTIALS_FILE': '/nonexistent/workload-command-proof'}))
        scanning._RESULTS.clear()
        scanning._trufflehog.cache_clear()

    def tearDown(self):
        self.stack.close()
        scanning._RESULTS.clear()
        scanning._trufflehog.cache_clear()
        self.assertFalse(self.attempts)

    def capture(self, specs, *, caller=None, auth_error=False, endpoint=False, after=None):
        """specs: (selected, response-or-None); None gives native AccessDenied."""
        selected = [item[0] for item in specs]
        plan = source.prepare(options(selected), list(dict.fromkeys(t['scope'] for t in selected)))
        sdk = boto3.Session(aws_access_key_id='offline-key', aws_secret_access_key='offline-secret', region_name=REGION)
        clients = {s: sdk.client(s, region_name=REGION, endpoint_url=f'https://{s}.{REGION}.amazonaws.com')
                   for s in ('sts', 'ecs', 'batch')}
        trace = SimpleNamespace(calls=[], auth=[])
        for service, client in clients.items():
            def before(params, model, context, _service=service, **kwargs):
                trace.calls.append((_service, model.name, deepcopy(params)))
            client.meta.events.register('before-parameter-build.*.*', before)
            if after and service != 'sts':
                client.meta.events.register('after-call.*.*', after)
        def client(service, **kwargs):
            self.assertEqual(kwargs['region_name'], REGION)
            self.assertEqual(kwargs['endpoint_url'], f'https://{service}.{REGION}.amazonaws.com')
            self.assertEqual(kwargs['config'].retries, {'total_max_attempts': 1})
            self.assertEqual(kwargs['config'].proxies, {})
            self.assertTrue(kwargs['config'].ignore_configured_endpoint_urls)
            self.assertIs(kwargs['verify'], True)
            self.assertEqual(kwargs['config'].signature_version, 'v4')
            self.assertTrue(0 < kwargs['config'].read_timeout <= 3)
            if endpoint:
                clients[service].meta._endpoint_url = 'https://untrusted.invalid'
            return clients[service]
        def factory(scope):
            trace.auth.append(scope)
            if auth_error:
                raise RuntimeError(TOKEN)
            return SimpleNamespace(client=client)
        with ExitStack() as stack:
            stubs = {s: stack.enter_context(Stubber(c)) for s, c in clients.items()}
            stubs['sts'].add_response('get_caller_identity', {**(caller or CALLER), 'ResponseMetadata': metadata()}, {})
            for t, payload in specs:
                service = t['service']
                method = 'describe_task_definition' if service == 'ecs' else 'describe_job_definitions'
                if payload is None:
                    stubs[service].add_client_error(method, service_error_code='AccessDeniedException',
                        service_message=TOKEN, http_status_code=403, expected_params=source.request_for(t))
                else:
                    stubs[service].add_response(method, payload, source.request_for(t))
            result = source.collect(plan, factory)
        return result, trace

    def statuses(self, collection):
        return [consumer.evaluate(row, collection)[0] for row in collection['items']]

    def test_01_real_dual_detectors_native_positive_clean_and_privacy(self):
        specs = []
        for service in ('ecs', 'batch'):
            for positive in (False, True):
                t = target(service, 'Definition' + str(positive))
                specs.append((t, response(t, ['echo', TOKEN] if positive else None)))
        result, trace = self.capture(specs)
        self.assertEqual(self.statuses(result), ['PASS', 'FAIL', 'PASS', 'FAIL'])
        self.assertEqual(trace.auth, [SCOPE])
        self.assertEqual(len(trace.calls), 5)
        self.assertEqual([call[2] for call in trace.calls[1:]], [source.request_for(t) for t, _ in specs])
        for row in (result['items'][1], result['items'][3]):
            self.assertEqual(len(row['leaks']), 1)
            self.assertEqual({d['engine'] for d in row['leaks'][0]['detectors']}, {'kingfisher', 'trufflehog'})
        self.assertEqual(result['items'][1]['leaks'][0]['fingerprint'], result['items'][3]['leaks'][0]['fingerprint'])
        status, combined = consumer.evaluate_collection(result)
        self.assertEqual(status, 'FAIL')
        self.assertEqual(len(combined['secret_leaks']), 1)
        self.assertEqual(len(combined['secret_leaks'][0]['locations']), 2)
        self.assertEqual(len(combined['secret_leaks'][0]['detectors']), 2)
        public = json.dumps(result) + json.dumps([consumer.evaluate(r, result) for r in result['items']])
        for value in (TOKEN, 'offline-key', 'local-review', 'AuditDefinition', 'valueFrom', 'environmentFiles'):
            self.assertNotIn(value, public)
        self.assertEqual(registry_modules(), PRELOADED_REGISTRY_MODULES)

    def test_02_explicit_empty_arrays_are_native_zero_not_missing(self):
        specs = [(target(s), response(target(s), [], [])) for s in ('ecs', 'batch')]
        result, _ = self.capture(specs)
        self.assertEqual(self.statuses(result), ['PASS', 'PASS'])
        self.assertTrue(all(scan['bytes'] == scan['literals'] == 0 for r in result['items'] for scan in r['scans']))
        self.assertTrue(all(len(scan['engines']) == 2 for r in result['items'] for scan in r['scans']))
        self.assertEqual(consumer.evaluate_collection(result)[0], 'PASS')

    def test_03_missing_fields_remain_unknown_and_valid_partial_positive_survives(self):
        for missing in ('entryPoint', 'command'):
            t = target()
            payload = response(t)
            payload['taskDefinition']['containerDefinitions'][0].pop(missing)
            result, _ = self.capture([(t, payload)])
            self.assertEqual(self.statuses(result), ['UNKNOWN'])
        t = target()
        payload = response(t, [TOKEN])
        payload['taskDefinition']['containerDefinitions'][0].pop('entryPoint')
        result, _ = self.capture([(t, payload)])
        self.assertEqual(self.statuses(result), ['FAIL'])
        self.assertFalse(consumer.evaluate(result['items'][0], result)[1]['complete'])
        t = target('batch')
        payload = response(t)
        payload['jobDefinitions'][0]['containerProperties'].pop('command')
        result, _ = self.capture([(t, payload)])
        self.assertEqual(self.statuses(result), ['UNKNOWN'])

    def test_04_exact_native_identity_revision_active_status_and_uniqueness(self):
        for service in ('ecs', 'batch'):
            edits = [lambda d: d.update(revision=4), lambda d: d.update(status='INACTIVE'),
                lambda d: d.pop('status'), lambda d: d.pop('revision'),
                lambda d: d.update({'taskDefinitionArn' if service == 'ecs' else 'jobDefinitionArn':
                    target(service, scope='999999999999/us-east-1')['definition_arn']}),
                lambda d: d.update({'taskDefinitionArn' if service == 'ecs' else 'jobDefinitionArn':
                    target(service, scope='123456789012/us-west-2')['definition_arn']}),
                lambda d: d.update({'family' if service == 'ecs' else 'jobDefinitionName': 'Other'})]
            for edit in edits:
                t, payload = target(service), response(target(service), [TOKEN])
                edit(definition(payload, service))
                if service == 'batch' and 'revision' not in definition(payload, service):
                    # Required model fields cannot be honestly fed to Stubber.
                    with self.assertRaises(ValueError):
                        source.literals(payload, t)
                    continue
                result, _ = self.capture([(t, payload)])
                self.assertEqual(self.statuses(result), ['UNKNOWN'])
                self.assertFalse(result['items'][0]['leaks'])
        for service in ('ecs', 'batch'):
            t, payload = target(service), response(target(service), [TOKEN])
            if service == 'ecs':
                payload['taskDefinition']['containerDefinitions'] *= 2
            else:
                payload['jobDefinitions'] *= 2
            result, _ = self.capture([(t, payload)])
            self.assertEqual(self.statuses(result), ['UNKNOWN'])

    def test_05_batch_variants_pagination_and_references_are_unknown(self):
        for edit in (lambda d: d.update(type='multinode'), lambda d: d.update(ecsProperties={'taskProperties': []}),
                     lambda d: d.update(eksProperties={}), lambda d: d.update(nodeProperties={'numNodes': 1, 'mainNode': 0, 'nodeRangeProperties': []}),
                     lambda d: d.update(containerOrchestrationType='EKS')):
            t, payload = target('batch'), response(target('batch'), [TOKEN])
            edit(payload['jobDefinitions'][0])
            result, _ = self.capture([(t, payload)])
            self.assertEqual(self.statuses(result), ['UNKNOWN'])
        t = target('batch')
        for command, expected in ((['Ref::TOKEN'], 'UNKNOWN'), (['echo', 'Ref::TOKEN'], 'UNKNOWN'),
                                  ([TOKEN, 'Ref::TOKEN'], 'FAIL')):
            result, _ = self.capture([(t, response(t, command))])
            self.assertEqual(self.statuses(result), [expected])
        payload = response(t, [TOKEN])
        payload['nextToken'] = TOKEN
        result, trace = self.capture([(t, payload)])
        self.assertEqual(self.statuses(result), ['UNKNOWN'])
        self.assertEqual(len(trace.calls), 2)

    def test_06_denied_auth_foreign_principal_and_endpoint_failure(self):
        t = target()
        for kwargs, payload in (({}, None), ({'auth_error': True}, response(t, [TOKEN])),
                ({'caller': {**CALLER, 'Account': '999999999999'}}, response(t, [TOKEN])),
                ({'caller': {**CALLER, 'Arn': 'arn:aws-cn:iam::' + ACCOUNT + ':user/foreign'}}, response(t, [TOKEN])),
                ({'endpoint': True}, response(t, [TOKEN]))):
            result, trace = self.capture([(t, payload)], **kwargs)
            self.assertEqual(self.statuses(result), ['UNKNOWN'])
            self.assertNotIn(TOKEN, json.dumps(result))
            if kwargs:
                self.assertFalse(any(call[0] != 'sts' for call in trace.calls))

    def test_07_real_partial_detector_and_later_native_failure_retain_positive(self):
        t1, t2 = target(), target('batch')
        with patch.dict(os.environ, {'PATH': '/nonexistent/workload-proof-engine'}):
            result, _ = self.capture([(t1, response(t1, [TOKEN])), (t2, response(t2))])
        self.assertEqual(self.statuses(result), ['FAIL', 'UNKNOWN'])
        scan = result['items'][0]['scans'][1]
        self.assertEqual(scan['engines'][0]['status'], 'complete')
        self.assertEqual(scan['engines'][1]['status'], 'unavailable')
        result, _ = self.capture([(t1, response(t1, [TOKEN])), (t2, None)])
        self.assertEqual(self.statuses(result), ['FAIL', 'UNKNOWN'])
        self.assertFalse(consumer.evaluate(result['items'][0], result)[1]['complete'])
        status, combined = consumer.evaluate_collection(result)
        self.assertEqual(status, 'FAIL')
        self.assertFalse(combined['complete'])

    def test_08_grants_bounds_and_tampered_plan_rejected_before_auth(self):
        edits = [lambda o: o.pop('check_id'), lambda o: o.update(content_secret_scans=False),
            lambda o: o.update(content_secret_scan_grants=[]), lambda o: o.update(content_secret_scan_grants=['other']),
            lambda o: o[source.OPTION].append(target()),
            lambda o: o.update({source.OPTION: [target(name='Def' + str(i)) for i in range(9)]}),
            lambda o: o[source.OPTION][0].update(definition_arn=target(revision=0)['definition_arn']),
            lambda o: o[source.OPTION][0].update(definition_arn=target()['definition_arn'].rsplit(':', 1)[0]),
            lambda o: o[source.OPTION][0].update(definition_arn=target(scope='999999999999/us-east-1')['definition_arn'])]
        for edit in edits:
            opts = options([target()])
            edit(opts)
            with self.assertRaises(ValueError):
                source.prepare(opts, [SCOPE])
        plan = source.prepare(options([target()]), [SCOPE])
        plan['body']['targets'][0]['definition_arn'] += '0'
        calls = []
        with self.assertRaises(ValueError):
            source.collect(plan, lambda scope: calls.append(scope))
        self.assertEqual(calls, [])
        with self.assertRaises(ValueError):
            source.prepare(options([target()]), [SCOPE, ACCOUNT + '/us-' + 'x' * 80 + '-1'])
        for state, deadline in (({'calls': 12, 'bytes': 0, 'wire_bytes': 0}, 1e20),
                                ({'calls': 0, 'bytes': 0, 'wire_bytes': 0}, 0)):
            with self.assertRaises(ValueError):
                source.native_call(None, 'ecs', REGION, 'DescribeTaskDefinition', {}, deadline, state)

    def test_09_native_malformed_and_content_byte_bounds(self):
        t = target()
        for payload in (response(t, ['x' * (source.MAX_CONTENT + 1)]), {'ResponseMetadata': metadata()},
                        {'taskDefinition': {}, 'ResponseMetadata': metadata()}):
            result, _ = self.capture([(t, payload)])
            self.assertEqual(self.statuses(result), ['UNKNOWN'])
        for bad in (None, 'echo', [None], [3], [['nested']], ['\x00'], ['\ud800']):
            # Stubber rejects non-native types; malformed decoder/event output is
            # separately checked by the same extraction routine, without a stub lie.
            payload = response(t)
            payload['taskDefinition']['containerDefinitions'][0]['command'] = bad
            try:
                sources, complete = source.literals(payload, t)
                self.assertFalse(complete)
            except UnicodeError:
                pass

    def test_10_preparser_transport_body_bounds_and_cleanup(self):
        for length, declared, encoding, expected in ((20, '20', None, True),
                (20, '21', None, False), (20, str(source.MAX_RESPONSE + 1), None, False),
                (source.MAX_RESPONSE + 1, None, None, False), (20, None, 'gzip', False)):
            raw = Raw(b'x' * length)
            headers = {}
            if declared is not None:
                headers['Content-Length'] = declared
            if encoding:
                headers['Content-Encoding'] = encoding
            response = AWSResponse('https://ecs.us-east-1.amazonaws.com/', 200, headers, raw)
            state = {'wire_bytes': 0}
            if expected:
                bounded = source.bounded_response(response, time.monotonic() + 3, state)
                self.assertEqual(bounded.content, b'x' * length)
            else:
                with self.assertRaises(ValueError):
                    source.bounded_response(response, time.monotonic() + 3, state)
            self.assertTrue(raw.closed)
        raw = Raw(b'x' * 20)
        with self.assertRaises(ValueError):
            source.bounded_response(AWSResponse('https://ecs.us-east-1.amazonaws.com/', 200, {}, raw),
                time.monotonic() + 3, {'wire_bytes': source.MAX_TOTAL - 10})
        self.assertTrue(raw.closed)

    def test_11_actual_signed_sdk_serialization_and_bounded_parser_without_network(self):
        for service in ('ecs', 'batch'):
            for change in ('none', 'body', 'url', 'target', 'retry'):
                if service == 'batch' and change == 'target':
                    continue
                t = target(service)
                sdk = boto3.Session(aws_access_key_id='offline-key', aws_secret_access_key='offline-secret', region_name=REGION)
                endpoint = f'https://{service}.{REGION}.amazonaws.com'
                client = sdk.client(service, region_name=REGION, endpoint_url=endpoint)
                http = client._endpoint.http_session
                original_send, original_close = http.send, client.close
                seen, raw_bodies, closed = [], [], []
                def send(request):
                    seen.append(request)
                    payload = response(t)
                    payload.pop('ResponseMetadata')
                    raw = Raw(json.dumps(payload).encode())
                    raw_bodies.append(raw)
                    return AWSResponse(request.url, 200, {'x-amzn-requestid': 'local-native-request'}, raw)
                http.send = send
                def close():
                    closed.append(True)
                    original_close()
                client.close = close
                event = 'before-send.' + client.meta.service_model.service_id.hyphenize() + '.' + (
                    'DescribeTaskDefinition' if service == 'ecs' else 'DescribeJobDefinitions')
                def mutate(request, **kwargs):
                    if change == 'body':
                        request.body = b'{}'
                    elif change == 'url':
                        request.url = 'https://untrusted.invalid/'
                    elif change == 'target':
                        request.headers['X-Amz-Target'] = 'AmazonEC2ContainerServiceV20141113.RunTask'
                    elif change == 'retry':
                        client.meta.events.emit(event, request=request)
                client.meta.events.register_last(event, mutate)
                session = SimpleNamespace(client=lambda *args, **kwargs: client)
                operation = 'DescribeTaskDefinition' if service == 'ecs' else 'DescribeJobDefinitions'
                if change == 'none':
                    native, receipt = source.native_call(session, service, REGION, operation, source.request_for(t),
                        time.monotonic() + 3, {'calls': 0, 'bytes': 0, 'wire_bytes': 0})
                    self.assertEqual(receipt['http_status'], 200)
                    self.assertEqual(len(seen), 1)
                    self.assertIn('Authorization', seen[0].headers)
                    self.assertTrue(raw_bodies[0].closed)
                else:
                    with self.assertRaises(ValueError):
                        source.native_call(session, service, REGION, operation, source.request_for(t),
                            time.monotonic() + 3, {'calls': 0, 'bytes': 0, 'wire_bytes': 0})
                    self.assertFalse(seen)
                self.assertEqual(closed, [True])
                self.assertEqual(http.send, send)  # Wrapper always restored.

    def test_12_consumer_rejects_malformed_foreign_duplicate_and_forged_completion(self):
        t = target()
        result, _ = self.capture([(t, response(t))])
        for edit in (lambda c: c['items'].append(deepcopy(c['items'][0])),
                lambda c: c['items'][0].update(scope='999999999999/us-east-1'),
                lambda c: c['items'][0].update(principal='bad'),
                lambda c: c['items'][0]['requests'][1].update(operation='RunTask'),
                lambda c: c['items'][0]['scans'][0]['engines'][0].update(status='unavailable'),
                lambda c: c['items'][0]['scans'][0].update(path=TOKEN),
                lambda c: c['items'][0]['scans'].pop(),
                lambda c: c.update(response_bytes=source.MAX_TOTAL + 1)):
            bad = deepcopy(result)
            edit(bad)
            self.assertEqual(consumer.evaluate(bad['items'][0], bad)[0], 'UNKNOWN')
        self.assertEqual(consumer.evaluate({}, {})[0], 'UNKNOWN')
        self.assertEqual(consumer.evaluate_collection({})[0], 'UNKNOWN')

    def test_13_later_byte_deadline_and_scanner_failures_preserve_positive(self):
        t1, t2, t3 = target(name='First'), target('batch', name='Second'), target('batch', name='Third')
        payloads = [response(t1, [TOKEN]), response(t2), response(t3)]
        # Two individually valid SDK objects push the third over the aggregate.
        for payload, t in zip(payloads, (t1, t2, t3)):
            definition(payload, t['service'])['tags'] = {'padding': 'x' * (1400 * 1024)}
        # ECS taskDefinition has no tags member; keep native tags at response root.
        payloads[0]['tags'] = [{'key': 'padding', 'value': definition(payloads[0], 'ecs').pop('tags')['padding']}]
        result, _ = self.capture(list(zip((t1, t2, t3), payloads)))
        self.assertEqual(self.statuses(result), ['FAIL', 'UNKNOWN', 'UNKNOWN'])
        self.assertLessEqual(result['response_bytes'], source.MAX_TOTAL)
        t = target()
        original = source.scan_content
        calls = []
        def fail_later(payload, path, **kwargs):
            calls.append(True)
            if len(calls) > 1:
                raise TimeoutError(TOKEN)
            return original(payload, path, **kwargs)
        with patch.object(source, 'scan_content', fail_later):
            result, _ = self.capture([(t, response(t, ['ready'], [TOKEN]))])
        self.assertEqual(self.statuses(result), ['FAIL'])
        self.assertNotIn(TOKEN, json.dumps(result))
        self.assertFalse(result['complete'])

    def test_14_literal_container_output_and_parser_bounds(self):
        t = target()
        for array in (['ok'] * 257, ['é' * (source.MAX_CONTENT // 2 + 1)]):
            payload = response(t, array)
            sources, complete = source.literals(payload, t)
            self.assertFalse(complete)
            self.assertLessEqual(sum(len(data) for _, data, _ in sources), source.MAX_CONTENT)
        payload = response(t)
        payload['taskDefinition']['containerDefinitions'] = [
            {'name': 'app' + str(i), 'entryPoint': [], 'command': []} for i in range(33)]
        with self.assertRaises(ValueError):
            source.literals(payload, t)
        for value in ({'bad': object()}, {'bad': float('nan')}, {'bad': 'x' * (source.MAX_RESPONSE + 1)}):
            with self.assertRaises(ValueError):
                source.response_size(value)
        self.assertEqual(consumer.CHECK, source.CHECK)
        self.assertEqual(consumer.KIND, source.KIND)
        self.assertEqual(consumer.SCHEMA, source.SCHEMA)

    def test_15_serialized_nested_argument_mutation_is_blocked(self):
        t = target('batch')
        sdk = boto3.Session(aws_access_key_id='offline-key', aws_secret_access_key='offline-secret', region_name=REGION)
        client = sdk.client('batch', region_name=REGION, endpoint_url=f'https://batch.{REGION}.amazonaws.com')
        seen = []
        client._endpoint.http_session.send = lambda request: seen.append(request)
        def mutate(params, **kwargs):
            params['jobDefinitions'][0] = target('batch', name='Foreign')['definition_arn']
        client.meta.events.register('before-parameter-build.batch.DescribeJobDefinitions', mutate)
        with self.assertRaises(ValueError):
            source.native_call(SimpleNamespace(client=lambda *a, **kw: client), 'batch', REGION,
                'DescribeJobDefinitions', source.request_for(t), time.monotonic() + 3,
                {'calls': 0, 'bytes': 0, 'wire_bytes': 0})
        self.assertFalse(seen)

    def test_16_deadlines_output_bounds_and_subprocess_cleanup(self):
        with self.assertRaisesRegex(ValueError, 'deadline'):
            source.native_call(None, 'ecs', REGION, 'DescribeTaskDefinition', source.request_for(target()), 0,
                {'calls': 0, 'bytes': 0, 'wire_bytes': 0})
        raw = Raw(b'discard')
        with self.assertRaisesRegex(ValueError, 'deadline'):
            source.bounded_response(AWSResponse('https://ecs.us-east-1.amazonaws.com/', 200, {}, raw), 0, {'wire_bytes': 0})
        self.assertTrue(raw.closed)
        self.assertEqual(raw.read_bytes, 0)
        with patch.object(source, 'MAX_SECONDS', 0):
            result, trace = self.capture([(target(), response(target()))])
        self.assertEqual(self.statuses(result), ['UNKNOWN'])
        self.assertEqual(trace.auth, [])
        processes, popen = [], scanning.subprocess.Popen
        def start(*args, **kwargs):
            process = popen(*args, **kwargs)
            processes.append(process)
            return process
        with patch.object(scanning.subprocess, 'Popen', start):
            with self.assertRaisesRegex(ValueError, 'output bound'):
                scanning._run([sys.executable, '-c', 'import sys;sys.stdout.buffer.write(b"x" * 4259840)'], b'', 3)
            with self.assertRaises(TimeoutError):
                scanning._run([sys.executable, '-c', 'import time;time.sleep(10)'], b'', .05)
        self.assertTrue(all(p.poll() is not None and p.stdin.closed and p.stdout.closed for p in processes))

    def test_17_real_overflowing_locations_keep_bounded_positive_prefix(self):
        t = target('batch')
        result, _ = self.capture([(t, response(t, ['\n'.join([TOKEN] * 513)]))])
        self.assertEqual(self.statuses(result), ['FAIL'])
        row = result['items'][0]
        self.assertFalse(row['complete'])
        self.assertLessEqual(sum(len(leak['locations']) for leak in row['leaks']), source.MAX_LOCATIONS)
        self.assertGreater(len(row['leaks']), 0)


if __name__ == '__main__':
    unittest.main(verbosity=2)
