"""Opt-in bounded content inspection with opaque paths and redacted observations.

GetFile cannot limit network response size: the 1MiB limit is inspected bytes,
not transferred bytes (AWS may return up to 6MiB). No payload is cached.
Offline Kingfisher and TruffleHog detection is limited to the selected bounded content.
"""
from __future__ import annotations
from peaso.secret_evidence import scan_with_source
import copy
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from contextlib import nullcontext
from contextvars import ContextVar
import json
import re
import threading
from .aws_user_data_secret_indicators import project

PROFILE = 'aws-code-log-content-indicators-v1'
PROJECTION_OPERATIONS = {('codecommit', op) for op in ('get_repository', 'get_branch', 'get_folder', 'get_file')} | {('logs', 'filter_log_events')}
READ_ACTIONS = PROJECTION_OPERATIONS | {('codecommit', 'list_repositories')}
SPECS = {'codecommit_repository': ('codecommit', 'list_repositories', 'repositories')}
NATIVE_IDS = {'codecommit_repository': 'repositoryName'}
MAX_BYTES, MAX_FILES, MAX_FOLDERS, MAX_MESSAGES = 1048576, 128, 128, 100
CATEGORIES = {'private_key', 'cloud_credential', 'password_assignment', 'secret'}
_LOG_SCANNER_GATE = ContextVar('aws_log_scanner_gate', default=None)


def _text(value, maximum=2048):
    return isinstance(value, str) and 0 < len(value) <= maximum and '\x00' not in value


def validate_request(service, operation, arguments, *, region=None, request_context=None):
    from .aws import ReadFailure
    valid = (service, operation) in PROJECTION_OPERATIONS and _text(region, 64) and isinstance(arguments, dict)
    allowed = {'get_repository': {'repositoryName'}, 'get_branch': {'repositoryName', 'branchName'},
               'get_folder': {'repositoryName', 'commitSpecifier', 'folderPath'},
               'get_file': {'repositoryName', 'commitSpecifier', 'filePath'},
               'filter_log_events': {'logGroupName', 'startTime', 'endTime', 'limit', 'nextToken'}}
    valid = valid and set(arguments) <= allowed.get(operation, set())
    if operation in ('get_file', 'filter_log_events'):
        valid = valid and isinstance(request_context, dict) and set(request_context) == {'remaining_bytes'} and type(request_context['remaining_bytes']) is int and 0 <= request_context['remaining_bytes'] <= MAX_BYTES
    elif request_context is not None:
        valid = False
    if service == 'codecommit':
        valid = valid and _text(arguments.get('repositoryName'), 100) and re.fullmatch(r'[\w.-]+', arguments['repositoryName']) is not None
        if operation == 'get_branch':
            valid = valid and _text(arguments.get('branchName'), 256)
        if operation in ('get_folder', 'get_file'):
            valid = valid and isinstance(arguments.get('commitSpecifier'), str) and re.fullmatch('[0-9a-f]{40}', arguments['commitSpecifier']) is not None
            path = arguments.get('filePath' if operation == 'get_file' else 'folderPath')
            valid = valid and _text(path) and path.startswith('/') and '..' not in path.split('/')
    elif service == 'logs':
        start, end, limit = (arguments.get(k) for k in ('startTime', 'endTime', 'limit'))
        valid = valid and _text(arguments.get('logGroupName'), 512) and type(start) is int and type(end) is int and 0 <= start < end and end-start <= 86400000 and type(limit) is int and 1 <= limit <= MAX_MESSAGES
        if 'nextToken' in arguments:
            valid = valid and _text(arguments['nextToken'], 1024)
    if not valid:
        raise ReadFailure('malformed', 'content_profile_arguments_invalid')


def opaque_arguments(arguments):
    """Process-HMAC request identity; exact native arguments stay ephemeral."""
    from peaso.secret_scanning import _fingerprint
    return {'request_locator': 'codecommit-request:' + _fingerprint(
        'codecommit-request-v1:' + json.dumps(arguments, sort_keys=True, ensure_ascii=True, separators=(',', ':')))}


def path_locator(region, repository, commit, path):
    """Bind opaque exact path bytes to the repository, Region and commit."""
    from peaso.secret_scanning import _fingerprint
    return '/codecommit-path/' + _fingerprint('codecommit-path-v1:' + json.dumps(
        [region, repository, commit, path], ensure_ascii=True, separators=(',', ':')))


def request_binding(service, operation, region, arguments, context):
    return {'service': service, 'operation': operation, 'region': region,
        'arguments': opaque_arguments(arguments) if service == 'codecommit' else copy.deepcopy(arguments),
        'context': copy.deepcopy(context)}


def _completed_scan(requests, key, scan=None):
    """Bounded redacted replay only; never retain route maps or provider text."""
    if not hasattr(requests, '_lock'):
        return None
    with requests._lock:
        cache = getattr(requests, '_codecommit_completed_scans', None)
        if cache is None:
            cache = requests._codecommit_completed_scans = {}
        if scan is None:
            return copy.deepcopy(cache.get(key))
        if scan['complete'] is True and len(json.dumps(scan, ensure_ascii=True).encode()) <= 2097152:
            if len(cache) >= 4 and key not in cache:
                cache.pop(next(iter(cache)))
            cache[key] = copy.deepcopy(scan)
    return None


def _categories(text):
    return project(text, '')['MatchedCategories']


def project_response(response, service, operation, arguments, *, request_context=None, region=None, routing=None):
    """No raw content, response metadata or arbitrary exception text leaves here."""
    from .aws import ReadFailure
    validate_request(service, operation, arguments, region=region, request_context=request_context)
    if not isinstance(response, dict):
        raise ReadFailure('malformed', 'content_response_shape')
    if routing is not None and (service != 'codecommit' or operation != 'get_folder'
            or not isinstance(routing, dict) or set(routing) != {'files', 'folders'}
            or any(not isinstance(v, list) or v for v in routing.values())):
        raise ReadFailure('malformed', 'content_route_sink_invalid')
    binding = request_binding(service, operation, region, arguments, request_context)
    try:
        if operation == 'get_repository':
            row = response['repositoryMetadata']
            value = {k: row[k] for k in ('repositoryName', 'Arn', 'accountId', 'defaultBranch')}
            if 'repositoryId' in row:
                value['repositoryId'] = row['repositoryId']
            if any(not _text(v) for v in value.values()) or value['repositoryName'] != arguments['repositoryName']:
                raise ValueError()
        elif operation == 'get_branch':
            value = {k: response['branch'][k] for k in ('branchName', 'commitId')}
            if value['branchName'] != arguments['branchName'] or re.fullmatch('[0-9a-f]{40}', value['commitId']) is None:
                raise ValueError()
        elif operation == 'get_folder':
            if response['commitId'] != arguments['commitSpecifier'] or response['folderPath'] != arguments['folderPath']:
                raise ValueError()
            value = {'files': [], 'folders': []}
            ephemeral = {'files': [], 'folders': []}
            for source, target in (('files', 'files'), ('subFolders', 'folders')):
                rows = response.get(source, [])
                if not isinstance(rows, list) or len(rows) > 10000:
                    raise ValueError()
                for row in rows:
                    path = row['absolutePath']
                    if not _text(path) or not path.startswith('/') or '..' in path.split('/') or path == arguments['folderPath'] or path.rsplit('/', 1)[0] != arguments['folderPath'].rstrip('/'):
                        raise ValueError()
                    value[target].append(path_locator(region, arguments['repositoryName'], arguments['commitSpecifier'], path))
                    ephemeral[target].append(path)
            value['unsupported_entries'] = bool(response.get('symbolicLinks') or response.get('subModules'))
            if routing is not None:
                routing.update(ephemeral)
        elif operation == 'get_file':
            if response['commitId'] != arguments['commitSpecifier'] or response['filePath'] != arguments['filePath']:
                raise ValueError()
            payload = response['fileContent']
            if not isinstance(payload, bytes) or type(response['fileSize']) is not int or len(payload) != response['fileSize']:
                raise ValueError()
            value = {'size': len(payload), 'inspected_bytes': len(payload) if len(payload) <= request_context['remaining_bytes'] else 0, 'categories': [], 'readable': len(payload) <= request_context['remaining_bytes']}
            if value['readable']:
                try:
                    text = payload.decode('utf-8')
                    if any(ord(char) < 32 and char not in '\t\r\n' for char in text):
                        raise UnicodeError()
                    from peaso.secret_scanning import scan_content
                    outcome = scan_with_source(scan_content, payload, path_locator(region, arguments['repositoryName'],
                        arguments['commitSpecifier'], arguments['filePath']), source={'path': arguments['filePath'], 'source': json.dumps({k: arguments[k] for k in ('repositoryName', 'commitSpecifier')}), 'scope': region})
                    value.update(leaks=outcome['leaks'], scanner_complete=outcome['complete'])
                    value['categories'] = sorted(set(_categories(text)) | ({'secret'} if outcome['leaks'] else set()))
                except UnicodeError:
                    value['readable'] = False
        else:
            events = response['events']
            if not isinstance(events, list) or len(events) > arguments['limit']:
                raise ValueError()
            value = {'events': [], 'nextToken': response.get('nextToken')}
            if value['nextToken'] is not None and not _text(value['nextToken'], 1024):
                raise ValueError()
            remaining = request_context['remaining_bytes']
            from peaso.secret_scanning import prepared_content_batch, scan_content
            pending = []
            def flush():
                nonlocal pending
                if not pending:
                    return
                batch, pending = pending, []
                # Preparation stages only already-admitted message bytes in
                # volatile tmpfs. Each original event still enters the normal
                # scanner with its own thread-local source context.
                gate = _LOG_SCANNER_GATE.get()
                with gate if gate is not None else nullcontext(), prepared_content_batch(
                        [(payload, 'log-message') for _, message, payload, _ in batch], timeout=60):
                    for timestamp, message, payload, row in batch:
                        outcome = scan_with_source(scan_content, payload, 'log-message', source={
                            'path': arguments['logGroupName'], 'scope': region,
                            'source': json.dumps({**{k: arguments[k] for k in ('logGroupName', 'logStreamName')
                                                       if k in arguments},
                                                  **{k: row[k] for k in ('timestamp', 'eventId', 'logStreamName')
                                                     if k in row}}),
                            'location_kind': 'log'})
                        value['events'].append({'timestamp': timestamp, 'size': len(payload),
                            'readable': True, 'leaks': outcome['leaks'],
                            'scanner_complete': outcome['complete'],
                            'categories': sorted(set(_categories(message)) |
                                                 ({'secret'} if outcome['leaks'] else set()))})
            for row in events:
                timestamp, message = row['timestamp'], row['message']
                if type(timestamp) is not int or not arguments['startTime'] <= timestamp < arguments['endTime'] or not isinstance(message, str):
                    raise ValueError()
                payload = message.encode('utf-8')
                size = len(payload)
                readable = size <= remaining
                if readable:
                    pending.append((timestamp, message, payload, row))
                    remaining -= size
                    if len(pending) == MAX_MESSAGES:
                        flush()
                else:
                    flush()
                    value['events'].append({'timestamp': timestamp, 'size': size, 'readable': False,
                        'leaks': [], 'scanner_complete': False, 'categories': []})
            flush()
        return {'binding': binding, 'value': value}
    except (KeyError, TypeError, ValueError, UnicodeError):
        raise ReadFailure('malformed', 'content_response_invalid') from None


def _call(requests, session, region, service, operation, *, remaining_bytes=None, routing=None, **arguments):
    context = {'remaining_bytes': remaining_bytes} if remaining_bytes is not None else None
    validate_request(service, operation, arguments, region=region, request_context=context)
    route_args = {'_codecommit_routes': routing} if routing is not None else {}
    value = requests.call(session, service, region, operation, _metadata_profile=PROFILE, _projection_context=context, **route_args, **arguments)
    expected = request_binding(service, operation, region, arguments, context)
    if not isinstance(value, dict) or value.get('binding') != expected or not isinstance(value.get('value'), dict):
        raise ValueError('content_projection_binding_invalid')
    if routing is not None:
        for field in ('files', 'folders'):
            if value['value'].get(field) != [path_locator(region, arguments['repositoryName'],
                    arguments['commitSpecifier'], path) for path in routing[field]]:
                raise ValueError('content_projection_route_binding_invalid')
    return value['value']


def _base(item, region, scope):
    return {'profile': PROFILE, 'collection_status': 'not_collected', 'scope': scope, 'region': region, 'complete': False,
            'records': [], 'file_requests': 0, 'inspected_bytes': 0, 'errors': [], 'identity': item.get('Arn') or item.get('arn')}


def _failure(scan, exc):
    from .aws import _failure as failure
    info = failure(exc)
    # Never retain arbitrary exception messages, request IDs or SDK response data.
    status = 'malformed' if isinstance(exc, (ValueError, TypeError, KeyError)) else info.status
    scan['errors'].append({'status': status, 'code': 'content_read_incomplete'})
    scan['collection_status'] = 'partial' if scan['records'] else status
    return scan


def scan_repository(requests, session, region, item):
    scan = _base(item, region, 'bounded_default_commit_files')
    if getattr(requests, 'content_secret_scans', False) is not True:
        return scan
    try:
        name = item['repositoryName']
        repo = _call(requests, session, region, 'codecommit', 'get_repository', repositoryName=name)
        arn = repo['Arn']
        if re.fullmatch(r'arn:[a-z0-9-]+:codecommit:' + re.escape(region) + r':\d{12}:' + re.escape(name), arn) is None or repo['accountId'] != arn.split(':')[4] or item.get('Arn', arn) != arn:
            raise ValueError()
        if 'repositoryId' in item and item['repositoryId'] != repo.get('repositoryId'):
            raise ValueError()
        scan.update(identity=arn, repository=name, account_id=repo['accountId'], branch=repo['defaultBranch'])
        branch = _call(requests, session, region, 'codecommit', 'get_branch', repositoryName=name, branchName=scan['branch'])
        commit = scan['commit'] = branch['commitId']
        replay_key = opaque_arguments({'region': region, 'repository': arn, 'branch': scan['branch'], 'commit': commit})['request_locator']
        completed = _completed_scan(requests, replay_key)
        if completed is not None:
            return completed
        pending, seen, paths, incomplete = ['/'], set(), set(), False
        while pending and len(seen) < MAX_FOLDERS:
            folder = pending.pop(0)
            if folder in seen:
                raise ValueError()
            seen.add(folder)
            routing = {'files': [], 'folders': []}
            try:
                row = _call(requests, session, region, 'codecommit', 'get_folder', routing=routing,
                    repositoryName=name, commitSpecifier=commit, folderPath=folder)
                files, folders = routing['files'], routing['folders']
            finally:
                routing.clear()
            incomplete |= row['unsupported_entries']
            pending.extend(folders)
            for path in files:
                if path in paths:
                    raise ValueError()
                paths.add(path)
                if scan['file_requests'] >= MAX_FILES or scan['inspected_bytes'] >= MAX_BYTES:
                    incomplete = True
                    continue
                try:
                    scan['file_requests'] += 1
                    content = _call(requests, session, region, 'codecommit', 'get_file', repositoryName=name, commitSpecifier=commit, filePath=path, remaining_bytes=MAX_BYTES-scan['inspected_bytes'])
                    readable = content['readable'] and scan['inspected_bytes'] + content['size'] <= MAX_BYTES
                    scan['inspected_bytes'] += content['inspected_bytes']
                    scan['records'].append({'path': path_locator(region, name, commit, path), 'size': content['size'], 'inspected_bytes': content['inspected_bytes'], 'readable': readable, 'categories': content['categories'] if readable else [], 'leaks': content.get('leaks', []), 'scanner_complete': content.get('scanner_complete', False)})
                    incomplete |= not readable or not content.get('scanner_complete', False)
                except Exception as exc:
                    _failure(scan, exc)
                    incomplete = True
        scan['complete'] = not (pending or incomplete or scan['errors'])
        scan['collection_status'] = 'collected' if scan['complete'] else 'partial'
        _completed_scan(requests, replay_key, scan)
        return scan
    except Exception as exc:
        return _failure(scan, exc)


def scan_logs(requests, session, region, item):
    scan = _base(item, region, 'bounded_log_window')
    if getattr(requests, 'content_secret_scans', False) is not True:
        return scan
    try:
        name = item['logGroupName']
        arn = item.get('arn') or item.get('logGroupArn')
        if not isinstance(arn, str) or re.fullmatch(r'arn:[a-z0-9-]+:logs:' + re.escape(region) + r':\d{12}:log-group:' + re.escape(name) + r'(?::\*)?', arn) is None:
            raise ValueError()
        end = int(requests.observed_at.timestamp() * 1000)
        if 'repositoryId' in item and item['repositoryId'] != repo.get('repositoryId'):
            raise ValueError()
        scan.update(identity=arn, group=name, account_id=arn.split(':')[4], start=end-86400000, end=end)
        token, seen = None, set()
        for _ in range(min(getattr(requests, 'max_pages', None) or 10, 10)):
            args = {'logGroupName': name, 'startTime': scan['start'], 'endTime': end, 'limit': MAX_MESSAGES-len(scan['records'])}
            if token is not None:
                args['nextToken'] = token
            row = _call(requests, session, region, 'logs', 'filter_log_events', remaining_bytes=MAX_BYTES-scan['inspected_bytes'], **args)
            for event in row['events']:
                readable = event['readable'] and scan['inspected_bytes'] + event['size'] <= MAX_BYTES
                if readable:
                    scan['inspected_bytes'] += event['size']
                scan['records'].append({'timestamp': event['timestamp'], 'size': event['size'], 'inspected_bytes': event['size'] if readable else 0, 'readable': readable, 'categories': event['categories'] if readable else [], 'leaks': event.get('leaks', []), 'scanner_complete': event.get('scanner_complete', False)})
            from peaso.progress import PHASES, emit_progress
            emit_progress(getattr(requests, 'progress_callback', None),
                phase='scanning_content' if 'scanning_content' in PHASES else 'collecting',
                provider='aws', completed=len(scan['records']), total=None, dynamic_total=True)
            token = row['nextToken']
            if token is None:
                scan['complete'] = all(r['readable'] and r.get('scanner_complete', False) for r in scan['records'])
                break
            if token in seen or len(scan['records']) >= MAX_MESSAGES:
                break
            seen.add(token)
        scan['collection_status'] = 'collected' if scan['complete'] else 'partial'
        return scan
    except Exception as exc:
        return _failure(scan, exc)


LOG_GROUP_WORKERS = 2


def _enricher(scanner, *, parallel_logs=False):
    def enrich(requests, session, region, items):
        output = copy.deepcopy(items)
        # A global call/item cap must retain input-order admission. Each log
        # group otherwise owns its own page, byte, and message budgets. Keep
        # only two scans in flight: a group can stage up to MAX_BYTES of log
        # text and start its own bounded detector process.
        parallel = (parallel_logs and len(output) > 1
                    and getattr(requests, 'content_secret_scans', False) is True
                    and getattr(requests, 'max_calls', None) is None
                    and getattr(requests, 'max_items', None) is None
                    and getattr(requests, 'deadline', None) is None
                    and getattr(requests, 'workers', 1) > 1)
        if parallel:
            # Keep detector preparation and its subprocess at one per scan,
            # while allowing the two independent AWS read chains to overlap.
            gate = threading.Lock()
            def run(item):
                token = _LOG_SCANNER_GATE.set(gate)
                try:
                    return scanner(requests, session, region, item)
                finally:
                    _LOG_SCANNER_GATE.reset(token)
            with ThreadPoolExecutor(max_workers=LOG_GROUP_WORKERS, thread_name_prefix='aws-log-content') as pool:
                pending = deque()
                for item in output:
                    pending.append((item, pool.submit(run, item)))
                    if len(pending) == LOG_GROUP_WORKERS:
                        settled, future = pending.popleft()
                        settled['ContentSecretIndicators'] = future.result()
                while pending:
                    settled, future = pending.popleft()
                    settled['ContentSecretIndicators'] = future.result()
            return output
        for item in output:
            item['ContentSecretIndicators'] = scanner(requests, session, region, item)
        return output
    return enrich


ENRICHERS = {'codecommit_repository': _enricher(scan_repository), 'log_group': _enricher(scan_logs, parallel_logs=True)}
