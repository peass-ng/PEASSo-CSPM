"""Unregistered exact-selected inline CodeBuild buildspec proposal.

Only prepare() accepts selectors; it runs before the supplied auth factory.
SDK allocation precedes byte bounds. No build, source retrieval or validation.
"""

from peaso.secret_evidence import scan_with_source, target_source
from copy import deepcopy
import json
import re
import time
from uuid import uuid4

from peaso.secret_scanning import scan_content, merge_leaks, _fingerprint
from .aws_selected_configuration_secret_indicators import response_size

KIND = 'codebuild_selected_inline_buildspec'
CHECK = 'aws.review.codebuild.selected_inline_buildspec_secret_indicators'
OPTION = 'selected_aws_codebuild_inline_buildspecs'
GRANT = 'aws-codebuild-selected-inline-buildspec-v1'
SCHEMA = 'aws-codebuild-inline-buildspec-20261020-v1'
FIELD = 'projects[0].source.buildspec'
MAX_TARGETS = 8
MAX_SCOPES = 4
MAX_CALLS = 12
MAX_RESPONSE = 2 * 1024 * 1024
MAX_TOTAL = 4 * 1024 * 1024
MAX_CONTENT = 256 * 1024
MAX_LEAKS = 128
MAX_LOCATIONS = 512
MAX_SECONDS = 90
SCOPE = re.compile(r'([0-9]{12})/([a-z]{2}(?:-[a-z0-9]+)+-[0-9]+)\Z')
SOURCE_TYPES = ('CODECOMMIT', 'CODEPIPELINE', 'GITHUB', 'GITLAB', 'GITLAB_SELF_MANAGED',
                'S3', 'BITBUCKET', 'GITHUB_ENTERPRISE', 'NO_SOURCE')


# Opaque collection binding tag; plans and captures must carry the same value.
SOURCE_BINDING = '4767dc5e9980129046649479fe0222afa9fbef3c60cac5ef8dade9928e9447d7'


def reviewed_sources():
    """Return the binding tag shared by plans and captures of this reader."""
    return SOURCE_BINDING


def parse(target):
    if not isinstance(target, dict) or set(target) != {'scope', 'project_arn'}:
        raise ValueError('invalid_selection')
    scope, arn = target['scope'], target['project_arn']
    match = SCOPE.fullmatch(scope) if isinstance(scope, str) else None
    if not match or not isinstance(arn, str) or len(arn) > 512:
        raise ValueError('invalid_selection')
    account, region = match.groups()
    partition = 'aws-cn' if region.startswith('cn-') else 'aws-us-gov' if region.startswith('us-gov-') else 'aws'
    prefix = f'arn:{partition}:codebuild:{region}:{account}:project/'
    if '-iso' in region or not arn.startswith(prefix) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]{1,254}', arn[len(prefix):]):
        raise ValueError('invalid_selection')
    return account, region, partition, arn[len(prefix):]


def locator(target):
    return KIND + ':' + _fingerprint(json.dumps(target, sort_keys=True, separators=(',', ':')))


def prepare(options, scopes):
    """Credential-free explicit check, content opt-in AND named grant gate."""
    if not isinstance(options, dict):
        raise ValueError('invalid_selection')
    if (options.get('content_secret_scans') is not True or options.get('check_id') != CHECK
            or options.get('content_secret_scan_grants') != [GRANT]):
        raise ValueError('explicit_grant_required')
    targets = options.get(OPTION)
    if (not isinstance(scopes, list) or not 1 <= len(scopes) <= MAX_SCOPES
            or any(not isinstance(s, str) or not SCOPE.fullmatch(s) for s in scopes)
            or len(set(scopes)) != len(scopes) or not isinstance(targets, list)
            or not 1 <= len(targets) <= MAX_TARGETS):
        raise ValueError('invalid_selection')
    seen = set()
    for target in targets:
        parse(target)
        key = locator(target)
        if target['scope'] not in scopes or key in seen:
            raise ValueError('invalid_selection')
        seen.add(key)
    body = {'targets': deepcopy(targets), 'scopes': list(scopes), 'binding': reviewed_sources()}
    return {'body': body, 'seal': _fingerprint(json.dumps(body, sort_keys=True))}


def left(deadline):
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise ValueError('deadline')
    return remaining


def native_call(session, service, region, operation, args, deadline, state):
    """One SDK operation, no retries, fixed endpoint and exact serialized body."""
    from botocore.config import Config
    if state['calls'] >= MAX_CALLS:
        raise ValueError('call_bound')
    timeout = min(3, left(deadline) / 3)
    suffix = 'amazonaws.com.cn' if region.startswith('cn-') else 'amazonaws.com'
    endpoint = f'https://{service}.{region}.{suffix}'
    client = session.client(service, region_name=region, endpoint_url=endpoint,
        config=Config(connect_timeout=timeout, read_timeout=timeout,
            retries={'total_max_attempts': 1}, ignore_configured_endpoint_urls=True,
            use_fips_endpoint=False, use_dualstack_endpoint=False, proxies={}))
    if (client.meta.endpoint_url != endpoint or client.meta.region_name != region
            or client.meta.service_model.service_name != service):
        raise ValueError('endpoint_binding')
    model = client.meta.service_model.operation_model(operation)
    if client.meta.method_to_api_mapping.get(operation_to_method(operation)) != operation:
        raise ValueError('operation_binding')
    wire = client._convert_to_request_dict(args, model, endpoint_url=endpoint)
    if wire['method'] != 'POST' or wire['url'] != endpoint + '/':
        raise ValueError('request_binding')
    sends = []
    def guard(request, **kwargs):
        left(deadline)
        sends.append(True)
        if len(sends) != 1 or request.method != 'POST' or request.url != endpoint + '/':
            raise ValueError('wire_binding')
        body = request.body.decode() if isinstance(request.body, bytes) else request.body
        if service == 'codebuild' and json.loads(body) != args:
            raise ValueError('wire_binding')
        if service == 'codebuild':
            target = request.headers.get('X-Amz-Target')
            target = target.decode() if isinstance(target, bytes) else target
            if target != client.meta.service_model.metadata['targetPrefix'] + '.' + operation:
                raise ValueError('wire_binding')
        if service == 'sts' and body != 'Action=GetCallerIdentity&Version=2011-06-15':
            raise ValueError('wire_binding')
    event = 'before-send.' + client.meta.service_model.service_id.hyphenize() + '.' + operation
    client.meta.events.register_first(event, guard)
    try:
        state['calls'] += 1
        response = getattr(client, operation_to_method(operation))(**args)
        left(deadline)
        size = response_size(response)
        if size > MAX_RESPONSE or state['bytes'] + size > MAX_TOTAL:
            raise ValueError('response_bound')
        state['bytes'] += size
        meta = response['ResponseMetadata']
        if type(meta['HTTPStatusCode']) is not int or meta['HTTPStatusCode'] != 200 or not isinstance(meta['RequestId'], str) or not meta['RequestId']:
            raise ValueError('native_receipt')
        receipt = {'service': service, 'operation': operation, 'http_status': 200,
                   'request': _fingerprint(json.dumps(args, sort_keys=True)),
                   'response': _fingerprint(meta['RequestId']), 'bytes': size}
        return response, receipt
    finally:
        client.meta.events.unregister(event, guard)
        client.close()


def operation_to_method(operation):
    return {'GetCallerIdentity': 'get_caller_identity', 'BatchGetProjects': 'batch_get_projects'}[operation]


def inline_bytes(response, target):
    """Conservatively recognize inline syntax; never fetch a path/reference."""
    projects = response.get('projects')
    if (response.get('projectsNotFound', []) != [] or not isinstance(projects, list)
            or len(projects) != 1 or not isinstance(projects[0], dict)):
        raise ValueError('project_cardinality')
    project = projects[0]
    if project.get('arn') != target['project_arn'] or project.get('name') != parse(target)[3]:
        raise ValueError('project_identity')
    source = project.get('source')
    if not isinstance(source, dict) or source.get('type') not in SOURCE_TYPES:
        raise ValueError('source_shape')
    text = source.get('buildspec')
    if not isinstance(text, str) or not text or len(text) > MAX_CONTENT:
        raise ValueError('not_inline')
    data = text.encode('utf-8')
    if len(data) > MAX_CONTENT or '\x00' in text:
        raise ValueError('content_bound')
    # A relative filename, S3 URI or ARN is never content, even with a token.
    # No YAML loading/alias expansion is needed to scan the original bytes.
    header = re.match(r'\A(?:\ufeff)?(?:[ \t]*(?:#[^\n]*)?\r?\n)*(?:---[ \t]*\r?\n)?version:[ \t]*[\"\']?0\.[12][\"\']?[ \t]*(?:#[^\n]*)?\r?\n', text)
    if header is None:
        raise ValueError('not_inline')
    return data


def collect(plan, session_factory):
    """Auth is reached only for a reviewed, sealed prepare() plan.

    Factory(scope) returns a pinned authorized SDK session. The producer reads
    GetCallerIdentity itself and never retains session, credential or raw data.
    """
    binding = reviewed_sources()
    if (not isinstance(plan, dict) or set(plan) != {'body', 'seal'}
            or plan['seal'] != _fingerprint(json.dumps(plan['body'], sort_keys=True))
            or plan['body']['binding'] != binding):
        raise ValueError('plan_binding')
    body = plan['body']
    # Revalidate bounds before auth even when a process-local seal is present.
    fresh = prepare({'content_secret_scans': True, 'check_id': CHECK,
        'content_secret_scan_grants': [GRANT], OPTION: body['targets']}, body['scopes'])
    if fresh != plan:
        raise ValueError('plan_binding')
    deadline = time.monotonic() + MAX_SECONDS
    capture = 'buildspec-capture:' + uuid4().hex
    state = {'calls': 0, 'bytes': 0}
    result = {'schema': SCHEMA, 'kind': KIND, 'authorized': True, 'binding': binding,
              'capture': capture, 'selection': {locator(t): {'scope': t['scope'],
                  'request': _fingerprint(json.dumps({'names': [t['project_arn']]}, sort_keys=True))}
                  for t in body['targets']},
              'items': [], 'calls': 0, 'response_bytes': 0, 'complete': False}
    principals = {}
    for scope in dict.fromkeys(t['scope'] for t in body['targets']):
        selected = [t for t in body['targets'] if t['scope'] == scope]
        try:
            left(deadline)
            session = session_factory(scope)
            account, region, partition, _ = parse(selected[0])
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
            row = {'id': locator(target), 'scope': scope, 'capture': capture, 'binding': binding,
                   'field': FIELD, 'native_complete': False, 'complete': False,
                   'principal': None, 'requests': [], 'bytes': 0, 'engines': [], 'leaks': [],
                   'verification': 'not_attempted', 'reason': 'unavailable'}
            result['items'].append(row)
            if session is None:
                continue
            try:
                row['principal'] = principal
                row['requests'] = [identity_receipt]
                response, receipt = native_call(session, 'codebuild', region, 'BatchGetProjects',
                    {'names': [target['project_arn']]}, deadline, state)
                row['requests'].append(receipt)
                payload = inline_bytes(response, target)
                row['native_complete'] = True
                row['bytes'] = len(payload)
                outcome = scan_with_source(scan_content, payload, row['id'] + '.source.buildspec', timeout=min(15, left(deadline) / 3), source=target_source(target, resource_id=target['project_arn'], scope=scope, path='source.buildspec'))
                # Each engine has its own timeout; reserve time for both.
                leaks = merge_leaks(outcome['leaks'])
                if len(leaks) > MAX_LEAKS or sum(len(x['locations']) for x in leaks) > MAX_LOCATIONS:
                    raise ValueError('finding_bound')
                row.update(engines=outcome['engines'], leaks=leaks, complete=outcome['complete'],
                           reason='inspected' if outcome['complete'] else 'detector_incomplete')
                if time.monotonic() >= deadline:
                    row.update(complete=False, reason='detector_incomplete')
            except Exception:
                # Exception/provider text can contain credentials and paths.
                row['complete'] = False
    result.update(calls=state['calls'], response_bytes=state['bytes'],
                  complete=all(r['complete'] for r in result['items']))
    if reviewed_sources() != binding:
        raise ValueError('source_binding')
    return result
