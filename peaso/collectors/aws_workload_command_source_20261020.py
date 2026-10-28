"""Unregistered, exact revision ECS/Batch command-literal proposal.

No provider dispatcher imports this file. prepare() must precede all auth.
The supplied session factory is trusted and must provide only authorized sessions.
"""

from peaso.secret_evidence import scan_with_source, target_source
from copy import deepcopy
from datetime import date, datetime
import hashlib
import io
import json
import math
from pathlib import Path
import re
import time
from uuid import uuid4

from peaso.secret_scanning import _fingerprint, merge_leaks, scan_content

CHECK = 'aws.review.workload.selected_command_literal_secret_indicators'
KIND = 'aws_selected_workload_command_literals'
OPTION = 'selected_aws_workload_commands'
GRANT = 'aws-workload-selected-command-literals-v1'
SCHEMA = 'aws-workload-command-source-20261020-v1'
MAX_TARGETS, MAX_CALLS = 8, 12
MAX_SCOPES = 4  # Retained selected-content scope bound; metadata scopes are validated separately.
MAX_SELECTED_SCOPES = 4
MAX_RESPONSE, MAX_TOTAL = 2 * 1024 * 1024, 4 * 1024 * 1024
MAX_CONTENT, MAX_LITERALS, MAX_CONTAINERS = 256 * 1024, 256, 32
MAX_LEAKS, MAX_LOCATIONS, MAX_SECONDS = 128, 512, 90
SCOPE = re.compile(r'([0-9]{12})/([a-z]{2}(?:-[a-z0-9]+)+-[0-9]+)\Z')
METHODS = {'GetCallerIdentity': 'get_caller_identity',
           'DescribeTaskDefinition': 'describe_task_definition',
           'DescribeJobDefinitions': 'describe_job_definitions'}


def reviewed_sources():
    """Local review drift check, not authentication of hostile Python/snapshots."""
    root = Path(__file__).resolve().parents[2]
    receipt = json.loads((root / 'docs/check-review/aws-workload-command-source-20261020.json').read_text())
    for name, expected in receipt['source_hashes'].items():
        path = (root / name).resolve()
        if not path.is_relative_to(root) or hashlib.sha256(path.read_bytes()).hexdigest() != expected:
            raise ValueError('source_binding')
    return hashlib.sha256(json.dumps(receipt['source_hashes'], sort_keys=True).encode()).hexdigest()


def parse(target):
    if not isinstance(target, dict) or set(target) != {'scope', 'service', 'definition_arn'}:
        raise ValueError('invalid_selection')
    scope, service, arn = target['scope'], target['service'], target['definition_arn']
    match = SCOPE.fullmatch(scope) if isinstance(scope, str) and len(scope) <= 80 else None
    if not match or service not in ('ecs', 'batch') or not isinstance(arn, str) or len(arn) > 512:
        raise ValueError('invalid_selection')
    account, region = match.groups()
    partition = 'aws-cn' if region.startswith('cn-') else 'aws-us-gov' if region.startswith('us-gov-') else 'aws'
    resource = 'task-definition' if service == 'ecs' else 'job-definition'
    prefix = f'arn:{partition}:{service}:{region}:{account}:{resource}/'
    identity = re.fullmatch(r'([A-Za-z0-9_-]{1,' + ('255' if service == 'ecs' else '128') + r'}):([1-9][0-9]{0,9})', arn[len(prefix):])
    if '-iso' in region or not arn.startswith(prefix) or not identity:
        raise ValueError('invalid_selection')
    return account, region, partition, identity[1], int(identity[2])


def locator(target):
    return KIND + ':' + _fingerprint(json.dumps(target, sort_keys=True))


def request_for(target):
    return ({'taskDefinition': target['definition_arn']} if target['service'] == 'ecs'
            else {'jobDefinitions': [target['definition_arn']]})


def prepare(options, scopes):
    """Explicit check selection, independent content opt-in and named grant."""
    if (not isinstance(options, dict) or options.get('check_id') != CHECK
            or options.get('content_secret_scans') is not True
            or options.get('content_secret_scan_grants') != [GRANT]):
        raise ValueError('explicit_grant_required')
    targets = options.get(OPTION)
    if (not isinstance(scopes, list) or not scopes
            or any(not isinstance(s, str) or len(s) > 80 or not SCOPE.fullmatch(s) for s in scopes)
            or len(set(scopes)) != len(scopes) or not isinstance(targets, list)
            or not 1 <= len(targets) <= MAX_TARGETS):
        raise ValueError('invalid_selection')
    seen = set()
    selected_scopes = set()
    for target in targets:
        parse(target)
        ident = locator(target)
        if target['scope'] not in scopes or ident in seen:
            raise ValueError('invalid_selection')
        seen.add(ident)
        selected_scopes.add(target['scope'])
        if len(selected_scopes) > MAX_SELECTED_SCOPES:
            raise ValueError('invalid_selection')
    body = {'targets': deepcopy(targets), 'scopes': list(scopes), 'binding': reviewed_sources()}
    return {'body': body, 'seal': _fingerprint(json.dumps(body, sort_keys=True))}


def left(deadline):
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise ValueError('deadline')
    return remaining


def response_size(value):
    """Bound SDK objects before creating an additional full JSON copy."""
    stack, nodes = [(value, 0)], 0
    while stack:
        member, depth = stack.pop()
        nodes += 1
        if nodes > 65536 or depth > 32:
            raise ValueError('response_bound')
        if isinstance(member, str):
            if len(member) > MAX_RESPONSE:
                raise ValueError('response_bound')
        elif isinstance(member, dict):
            if len(member) > 65536 or any(not isinstance(k, str) for k in member):
                raise ValueError('response_shape')
            stack.extend((x, depth + 1) for pair in member.items() for x in pair)
        elif isinstance(member, list):
            if len(member) > 65536:
                raise ValueError('response_bound')
            stack.extend((x, depth + 1) for x in member)
        elif isinstance(member, (date, datetime)):
            pass
        elif member is not None and type(member) not in (bool, int, float):
            raise ValueError('response_shape')
        elif isinstance(member, float) and not math.isfinite(member):
            raise ValueError('response_shape')
    size = 0
    for chunk in json.JSONEncoder(ensure_ascii=False, allow_nan=False,
            default=lambda x: x.isoformat(), separators=(',', ':')).iterencode(value):
        size += len(chunk.encode('utf-8'))
        if size > MAX_RESPONSE:
            raise ValueError('response_bound')
    return size


class BoundedBody:
    """The SDK parser sees only a body already bounded by the transport wrapper."""
    def __init__(self, body):
        self.body = io.BytesIO(body)

    def stream(self, amt=65536, decode_content=False):
        while chunk := self.body.read(amt):
            yield chunk


def bounded_response(response, deadline, state):
    from botocore.awsrequest import AWSResponse
    raw = response.raw
    try:
        headers = {k.lower(): v for k, v in response.headers.items()}
        if headers.get('content-encoding', 'identity').lower() != 'identity':
            raise ValueError('response_encoding')
        declared = headers.get('content-length')
        if declared is not None and (not re.fullmatch(r'[0-9]{1,10}', declared)
                or int(declared) > min(MAX_RESPONSE, MAX_TOTAL - state['wire_bytes'])):
            raise ValueError('response_bound')
        body = bytearray()
        limit = min(MAX_RESPONSE, MAX_TOTAL - state['wire_bytes'])
        while True:
            left(deadline)
            if declared is not None and len(body) == int(declared):
                break
            remaining = limit - len(body)
            if remaining <= 0:
                # No over-budget sentinel read: an unframed body at the limit
                # cannot establish EOF and remains UNKNOWN.
                raise ValueError('response_bound')
            amount = min(65536, remaining, int(declared) - len(body) if declared is not None else remaining)
            chunk = raw.read(amount, decode_content=False)
            if not isinstance(chunk, bytes) or len(chunk) > amount:
                raise ValueError('response_shape')
            if not chunk:
                break
            state['wire_bytes'] += len(chunk)
            body.extend(chunk)
        if declared is not None and len(body) != int(declared):
            raise ValueError('response_length')
        left(deadline)
        return AWSResponse(response.url, response.status_code, response.headers, BoundedBody(bytes(body)))
    finally:
        raw.close()


def native_call(session, service, region, operation, args, deadline, state):
    """Exact serialized readonly request, one send, bounded pre-parser body."""
    from botocore.config import Config
    expected = {'sts': 'GetCallerIdentity', 'ecs': 'DescribeTaskDefinition', 'batch': 'DescribeJobDefinitions'}
    if expected.get(service) != operation or state['calls'] >= MAX_CALLS:
        raise ValueError('call_bound')
    if state['bytes'] >= MAX_TOTAL or state['wire_bytes'] >= MAX_TOTAL:
        raise ValueError('response_bound')
    expected_args = deepcopy(args)
    if service == 'sts':
        if expected_args != {}:
            raise ValueError('request_binding')
    else:
        key = 'taskDefinition' if service == 'ecs' else 'jobDefinitions'
        if not isinstance(expected_args, dict) or set(expected_args) != {key}:
            raise ValueError('request_binding')
        values = [expected_args[key]] if service == 'ecs' else expected_args[key]
        if not isinstance(values, list) or len(values) != 1 or not isinstance(values[0], str):
            raise ValueError('request_binding')
        parts = values[0].split(':', 5)
        if len(parts) != 6:
            raise ValueError('request_binding')
        parse({'service': service, 'scope': parts[4] + '/' + region, 'definition_arn': values[0]})
    timeout = min(3, left(deadline) / 3)
    suffix = 'amazonaws.com.cn' if region.startswith('cn-') else 'amazonaws.com'
    endpoint = f'https://{service}.{region}.{suffix}'
    url = endpoint + ('/v1/describejobdefinitions' if service == 'batch' else '/')
    client = session.client(service, region_name=region, endpoint_url=endpoint, verify=True,
        config=Config(connect_timeout=timeout, read_timeout=timeout, signature_version='v4',
            retries={'total_max_attempts': 1}, ignore_configured_endpoint_urls=True,
            use_fips_endpoint=False, use_dualstack_endpoint=False, proxies={}))
    event, guard, original_send = None, None, None
    try:
        if (client.meta.endpoint_url != endpoint or client.meta.region_name != region
                or client.meta.service_model.service_name != service
                or client.meta.method_to_api_mapping.get(METHODS[operation]) != operation):
            raise ValueError('endpoint_binding')
        model = client.meta.service_model.operation_model(operation)
        wire = client._convert_to_request_dict(args, model, endpoint_url=endpoint)
        if wire['method'] != 'POST' or wire['url'] != url:
            raise ValueError('request_binding')
        def validate(request):
            left(deadline)
            if request.method != 'POST' or request.url != url:
                raise ValueError('wire_binding')
            body = request.body.decode('utf-8') if isinstance(request.body, bytes) else request.body
            if service == 'sts':
                if body != 'Action=GetCallerIdentity&Version=2011-06-15':
                    raise ValueError('wire_binding')
            elif json.loads(body) != expected_args:
                raise ValueError('wire_binding')
            if service == 'ecs':
                target = request.headers.get('X-Amz-Target')
                target = target.decode() if isinstance(target, bytes) else target
                if target != client.meta.service_model.metadata['targetPrefix'] + '.' + operation:
                    raise ValueError('wire_binding')
        attempts = []
        def guard(request, **kwargs):
            attempts.append(True)
            if len(attempts) != 1:
                raise ValueError('retry_bound')
            validate(request)
        event = 'before-send.' + client.meta.service_model.service_id.hyphenize() + '.' + operation
        client.meta.events.register_first(event, guard)
        transport = client._endpoint.http_session
        original_send = transport.send
        sends = []
        def send(request):
            validate(request)  # Recheck after all event handlers, immediately before transport.
            sends.append(True)
            if len(sends) != 1:
                raise ValueError('retry_bound')
            return bounded_response(original_send(request), deadline, state)
        transport.send = send
        state['calls'] += 1
        response = getattr(client, METHODS[operation])(**args)
        left(deadline)
        size = response_size(response)
        if state['bytes'] + size > MAX_TOTAL:
            raise ValueError('response_bound')
        state['bytes'] += size
        metadata = response['ResponseMetadata']
        if (type(metadata['HTTPStatusCode']) is not int or metadata['HTTPStatusCode'] != 200
                or not isinstance(metadata['RequestId'], str) or not 1 <= len(metadata['RequestId']) <= 256):
            raise ValueError('native_receipt')
        return response, {'service': service, 'operation': operation, 'http_status': 200,
            'request': _fingerprint(json.dumps(expected_args, sort_keys=True)),
            'response': _fingerprint(metadata['RequestId']), 'bytes': size}
    finally:
        if original_send is not None:
            client._endpoint.http_session.send = original_send
        if event is not None:
            client.meta.events.unregister(event, guard)
        client.close()


def literals(response, target):
    """Bind the immutable native definition before extracting bounded arrays.

    Missing/malformed fields are incomplete. Other valid fields can still yield
    positive evidence; unsupported Batch Ref:: placeholders are never resolved.
    """
    _, _, _, name, revision = parse(target)
    service = target['service']
    if service == 'ecs':
        definition = response.get('taskDefinition')
        if (not isinstance(definition, dict) or definition.get('taskDefinitionArn') != target['definition_arn']
                or definition.get('family') != name):
            raise ValueError('native_identity')
        containers = definition.get('containerDefinitions')
        if not isinstance(containers, list) or not 1 <= len(containers) <= MAX_CONTAINERS:
            raise ValueError('container_shape')
        names = [c.get('name') if isinstance(c, dict) else None for c in containers]
        if any(not isinstance(n, str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,255}', n) for n in names) or len(set(names)) != len(names):
            raise ValueError('container_identity')
        fields = [(f'containerDefinitions[{i}].{field}', container, field)
                  for i, container in enumerate(containers) for field in ('entryPoint', 'command')]
    else:
        definitions = response.get('jobDefinitions')
        if response.get('nextToken') not in (None, '') or not isinstance(definitions, list) or len(definitions) != 1:
            raise ValueError('definition_cardinality')
        definition = definitions[0]
        if (not isinstance(definition, dict) or definition.get('jobDefinitionArn') != target['definition_arn']
                or definition.get('jobDefinitionName') != name or definition.get('type') != 'container'
                or definition.get('containerOrchestrationType', 'ECS') != 'ECS'
                or any(k in definition for k in ('ecsProperties', 'eksProperties', 'nodeProperties'))
                or not isinstance(definition.get('containerProperties'), dict)):
            raise ValueError('native_variant')
        fields = [('containerProperties.command', definition['containerProperties'], 'command')]
    if type(definition.get('revision')) is not int or definition['revision'] != revision or definition.get('status') != 'ACTIVE':
        raise ValueError('native_revision_status')
    sources, complete, total, count = [], True, 0, 0
    for field, container, key in fields:
        array = container.get(key)
        if not isinstance(array, list) or len(array) > MAX_LITERALS:
            complete = False
            continue
        data = []
        for value in array:
            if (not isinstance(value, str) or len(value) > MAX_CONTENT or '\x00' in value
                    or service == 'batch' and value.startswith('Ref::')):
                complete = False
                continue
            encoded = value.encode('utf-8')
            total += len(encoded) + 1
            count += 1
            if total > MAX_CONTENT or count > MAX_LITERALS:
                complete = False
                break
            data.append(encoded)
        # Explicit [] is evidence of zero returned literals; omitted is not.
        if not array or data:
            sources.append((field, b'\n'.join(data), len(data)))
    return sources, complete


def collect(plan, session_factory):
    """No auth until the selected, granted, sealed plan is revalidated."""
    binding = reviewed_sources()
    if (not isinstance(plan, dict) or set(plan) != {'body', 'seal'}
            or plan['seal'] != _fingerprint(json.dumps(plan['body'], sort_keys=True))
            or plan['body']['binding'] != binding):
        raise ValueError('plan_binding')
    body = plan['body']
    if prepare({'check_id': CHECK, 'content_secret_scans': True,
            'content_secret_scan_grants': [GRANT], OPTION: body['targets']}, body['scopes']) != plan:
        raise ValueError('plan_binding')
    deadline, capture = time.monotonic() + MAX_SECONDS, 'command-capture:' + uuid4().hex
    state = {'calls': 0, 'bytes': 0, 'wire_bytes': 0}
    result = {'schema': SCHEMA, 'kind': KIND, 'authorized': True, 'binding': binding,
        'capture': capture, 'selection': {locator(t): {'scope': t['scope'], 'service': t['service'],
            'request': _fingerprint(json.dumps(request_for(t), sort_keys=True))} for t in body['targets']},
        'items': [], 'calls': 0, 'response_bytes': 0, 'wire_bytes': 0, 'complete': False}
    principals = {}
    for scope in dict.fromkeys(t['scope'] for t in body['targets']):
        selected = [t for t in body['targets'] if t['scope'] == scope]
        session, principal, identity_receipt = None, None, None
        try:
            left(deadline)
            session = session_factory(scope)
            account, region, partition, _, _ = parse(selected[0])
            caller, identity_receipt = native_call(session, 'sts', region, 'GetCallerIdentity', {}, deadline, state)
            if (caller.get('Account') != account or not isinstance(caller.get('UserId'), str) or not caller['UserId']
                    or not isinstance(caller.get('Arn'), str)
                    or not re.fullmatch('arn:' + partition + r':(?:iam|sts)::' + account + r':(?:user|role|assumed-role|federated-user)/[^\s]+|arn:' + partition + ':iam::' + account + ':root', caller['Arn'])):
                raise ValueError('caller_identity')
            principal = _fingerprint(json.dumps({k: caller[k] for k in ('Account', 'Arn', 'UserId')}, sort_keys=True))
            if account in principals and principals[account] != principal:
                raise ValueError('principal_changed')
            principals[account] = principal
        except Exception:
            session = None
        for target in selected:
            row = {'id': locator(target), 'scope': scope, 'service': target['service'], 'binding': binding,
                'capture': capture, 'principal': None, 'requests': [], 'native_bound': False,
                'native_complete': False, 'complete': False, 'scans': [], 'leaks': [],
                'verification': 'not_attempted'}
            result['items'].append(row)
            if session is None:
                continue
            response, sources, payload = None, None, None
            try:
                row['principal'], row['requests'] = principal, [identity_receipt]
                operation = 'DescribeTaskDefinition' if target['service'] == 'ecs' else 'DescribeJobDefinitions'
                response, receipt = native_call(session, target['service'], region, operation, request_for(target), deadline, state)
                row['requests'].append(receipt)
                sources, row['native_complete'] = literals(response, target)
                row['native_bound'] = True
                for field, payload, count in sources:
                    path = row['id'] + ':' + _fingerprint(field)
                    outcome = scan_with_source(scan_content, payload, path, timeout=min(15, left(deadline) / 3), source=target_source(target, resource_id=target['definition_arn'], scope=scope, path=field, location_kind='configuration'), native=response)
                    scan = {'path': path, 'field': field, 'bytes': len(payload), 'literals': count,
                        'engines': outcome['engines'], 'complete': outcome['complete']}
                    # Keep a bounded positive prefix if later fields/detectors fail.
                    leaks = merge_leaks(row['leaks'] + outcome['leaks'])
                    if len(leaks) > MAX_LEAKS or sum(len(x['locations']) for x in leaks) > MAX_LOCATIONS:
                        # Preserve bounded positive evidence, including the first
                        # field, when detector findings exceed publication limits.
                        bounded, remaining_locations = [], MAX_LOCATIONS
                        for leak in leaks[:MAX_LEAKS]:
                            kept = deepcopy(leak)
                            kept['locations'] = kept['locations'][:remaining_locations]
                            if not kept['locations']:
                                break
                            remaining_locations -= len(kept['locations'])
                            bounded.append(kept)
                        row['scans'].append(scan)
                        row['leaks'] = bounded
                        row['native_complete'] = False
                        break
                    row['scans'].append(scan)
                    row['leaks'] = leaks
                    left(deadline)
                row['complete'] = (row['native_complete'] and len(row['scans']) == len(sources)
                    and bool(sources) and all(s['complete'] for s in row['scans']))
            except Exception:
                # Never publish provider exceptions, raw commands or scanner output.
                row['complete'] = False
            finally:
                response = sources = payload = None
    result.update(calls=state['calls'], response_bytes=state['bytes'], wire_bytes=state['wire_bytes'],
                  complete=all(r['complete'] for r in result['items']))
    if reviewed_sources() != binding:
        raise ValueError('source_binding')
    return result
