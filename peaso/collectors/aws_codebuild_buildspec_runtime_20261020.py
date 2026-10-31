"""Default-off engine grant and native adapter for the sealed inline producer."""
from copy import deepcopy
from types import FunctionType
import json
import time
import threading
from peaso.secret_scanning import scan_content, _fingerprint
from . import aws_codebuild_buildspec_source_20261020 as source
from . import aws_selected_configuration_secret_indicators as configuration

KIND, CHECK, OPTION = source.KIND, source.CHECK, source.OPTION
GRANT = '_aws_codebuild_inline_engine_grant'
MARKER = 'CodeBuildInlineBuildspecCapture'
CAPTURES = KIND + '_captures'
STATE = '_codebuild_inline_runtime'
SPECS = {KIND: ('codebuild', 'batch_get_projects', None)}
NATIVE_IDS = {KIND: 'id'}
_TOKEN = object()


class _Grant:
    __slots__ = ('token', 'scopes', 'selection')

    def __init__(self, scopes, targets):
        self.token = _TOKEN
        self.scopes = tuple(scopes)
        self.selection = _fingerprint(json.dumps(targets, sort_keys=True))

    def __deepcopy__(self, memo):
        return self


def targets(options, scopes, named=(), provider='aws'):
    """Validate selectors without importing admission, credentials or SDKs."""
    if OPTION not in options and not (options.get('content_secret_scans') is True and CHECK in named):
        return []
    try:
        rows = options.get(OPTION)
        if (provider != 'aws' or not isinstance(scopes, list) or not 1 <= len(scopes) <= source.MAX_SCOPES
                or any(not isinstance(s, str) or not source.SCOPE.fullmatch(s) for s in scopes)
                or len(set(scopes)) != len(scopes) or not isinstance(rows, list)
                or not 1 <= len(rows) <= source.MAX_TARGETS):
            raise ValueError()
        seen = set()
        for row in rows:
            source.parse(row)
            if row['scope'] not in scopes or source.locator(row) in seen:
                raise ValueError()
            seen.add(source.locator(row))
        return deepcopy(rows)
    except (ValueError, TypeError, KeyError, AttributeError):
        raise ValueError('Selected CodeBuild buildspecs require 1-8 exact project ARNs in 1-4 selected account/region scopes') from None


def issue_engine_grant(options, scopes, named=()):
    options.pop(GRANT, None)
    rows = targets(options, scopes, named)
    if options.get('content_secret_scans') is True and CHECK in named:
        options[GRANT] = _Grant(scopes, rows)


def authorize_collector(options, scopes):
    token = options.pop(GRANT, None)
    rows = targets(options, scopes)
    granted = (type(token) is _Grant and token.token is _TOKEN and token.scopes == tuple(scopes)
        and token.selection == _fingerprint(json.dumps(rows, sort_keys=True))
        and options.get('content_secret_scans') is True)
    incoming = options.get('_content_secret_scan_kinds')
    if isinstance(incoming, list):
        options['_content_secret_scan_kinds'] = [k for k in incoming if k != KIND or granted]
    return granted and KIND in options.get('_content_secret_scan_kinds', [])


def runtime_binding():
    return source.reviewed_sources()


def prepare(options, scopes):
    rows = targets(options, scopes, [CHECK])
    body = {'targets': rows, 'scopes': list(scopes), 'binding': runtime_binding()}
    return {'body': body, 'seal': _fingerprint(json.dumps(body, sort_keys=True))}


def disabled_snapshot(scopes):
    from peaso.snapshot import make_snapshot
    return make_snapshot('aws', list(scopes), [{'type': KIND, 'scope': s, 'service': 'codebuild',
        'status': 'not_collected', 'items': [], 'error': {'code': 'explicit_named_content_grant_required'}}
        for s in scopes], metadata={'collection': 'read-only', CAPTURES: {}})


def initialize(requests, permitted):
    setattr(requests, STATE, {'permitted': permitted, 'captures': {}, 'deadline': time.monotonic() + source.MAX_SECONDS,
        'native_calls': 0, 'response_bytes': 0, 'lock': threading.Lock()})


def native_call(requests, pinned_session, scope, session, service, region, operation, args, deadline, state):
    from .aws import ReadFailure
    requests.check_deadline()
    if session is not pinned_session or region != scope.split('/')[1]:
        raise ValueError('session_scope_binding')
    runtime_state = getattr(requests, STATE)
    with runtime_state['lock']:
        if runtime_state['native_calls'] >= source.MAX_CALLS:
            raise ValueError('codebuild_call_bound')
        runtime_state['native_calls'] += 1
    with requests._lock:
        if requests.max_calls is not None and requests.calls >= requests.max_calls:
            raise ReadFailure('not_collected', 'call_limit')
        requests.calls += 1
    if requests.deadline is not None:
        deadline = min(deadline, requests.deadline)
    deadline = min(deadline, runtime_state['deadline'])
    from .aws_content_sdk_logging import private_sdk_logs
    with private_sdk_logs():
        result = source.native_call(session, service, region, operation, args, deadline, state)
    requests.check_deadline()
    with runtime_state['lock']:
        if runtime_state['response_bytes'] + result[1]['bytes'] > source.MAX_TOTAL:
            raise ValueError('codebuild_response_bound')
        runtime_state['response_bytes'] += result[1]['bytes']
    return result


def collect_selected(requests, session, region, caller, options, scopes):
    from .aws import ReadResult
    state = getattr(requests, STATE)
    if not state['permitted']:
        return ReadResult([], 'not_collected', {'code': 'explicit_named_content_grant_required'})
    scope = caller['Account'] + '/' + region
    selected = [t for t in targets(options, scopes) if t['scope'] == scope]
    if not selected:
        return ReadResult([], 'not_collected', {'code': 'no_selected_project_in_scope'})
    requests.check_deadline()
    if time.monotonic() >= state['deadline']:
        return ReadResult([], 'timeout', {'code': 'codebuild_content_deadline'})
    def scanner(payload, path, *, timeout):
        requests.check_deadline()
        outcome = scan_content(payload, path, timeout=min(timeout, source.left(state['deadline'])),
            _redact_values=lambda values: configuration.remember_matches(requests, values))
        return outcome
    def call(*args):
        return native_call(requests, session, scope, *args)
    namespace = dict(vars(source), reviewed_sources=runtime_binding, prepare=prepare,
                     scan_content=scanner, native_call=call)
    capture = FunctionType(source.collect.__code__, namespace, source.collect.__name__,
                           source.collect.__defaults__, source.collect.__closure__)
    plan = prepare({'content_secret_scans': True, OPTION: selected}, [scope])
    produced = capture(plan, lambda requested: session if requested == scope else None)
    expected_principal = _fingerprint(json.dumps({k: caller[k] for k in ('Account', 'Arn', 'UserId')}, sort_keys=True))
    if any(row['principal'] is not None and row['principal'] != expected_principal for row in produced['items']):
        return ReadResult([], 'unknown', {'code': 'codebuild_caller_changed'})
    with requests._lock:
        state['captures'][scope] = deepcopy({k: v for k, v in produced.items() if k != 'items'})
    rows = [{'id': native['id'], MARKER: native,
        '_provenance': {'scope': scope, 'capture': produced['capture'], 'selection_locator': native['id']}}
        for native in produced['items']]
    return ReadResult(rows, 'collected' if produced['complete'] else 'partial')


def retain_union(requests):
    """Keep shared HMAC descriptors until every output/cache surface is scrubbed."""
    if getattr(requests, STATE, {}).get('permitted'):
        configuration.remember_matches(requests, getattr(requests, 's3_source_redactions', set()))


def finalize(requests, collections, metadata, options):
    state = getattr(requests, STATE, {})
    if not state.get('permitted'):
        options.pop(OPTION, None)
        return collections, metadata
    metadata[CAPTURES] = deepcopy(state['captures'])
    descriptors = requests.configuration_content_redactions
    windows = 0
    def scrub(value):
        nonlocal windows
        if isinstance(value, str):
            matches = []
            for length, fingerprints in descriptors.items():
                for start in range(max(0, len(value) - length + 1)):
                    windows += 1
                    if windows > configuration.MAX_REDACTION_WINDOWS:
                        return 'codebuild-private:' + _fingerprint(value)
                    if _fingerprint(value[start:start + length]) in fingerprints:
                        matches.append((start, start + length))
            if not matches:
                return value
            out, offset = [], 0
            for start, end in sorted(matches):
                if start >= offset:
                    out.extend((value[offset:start], '[redacted]'))
                offset = max(offset, end)
            return ''.join(out) + value[offset:]
        if isinstance(value, (list, tuple)):
            return [scrub(v) for v in value]
        if isinstance(value, dict):
            result = {}
            for key, child in value.items():
                safe_key = scrub(list(key)) if isinstance(key, tuple) else scrub(key)
                if isinstance(safe_key, list):
                    safe_key = tuple(safe_key)
                if safe_key in result:
                    safe_key = 'codebuild-key:' + _fingerprint(repr(key))
                result[safe_key] = scrub(child)
            return result
        return value
    try:
        options.pop(OPTION, None)
        options.pop(GRANT, None)
        if requests.configuration_content_redaction_overflow:
            with requests._lock:
                requests._cache.clear()
            options.clear()
            return [{**{k: v for k, v in c.items() if k != 'items'}, 'items': [], 'status': 'unknown',
                'error': {'code': 'content_union_redaction_incomplete'}} for c in collections], {'collection': 'read-only'}
        with requests._lock:
            for key, future in list(requests._cache.items()):
                if future.done() and future.exception() is None:
                    current = future.result()
                    safe = scrub(current)
                    if isinstance(current, dict):
                        current.clear(); current.update(safe)
                    elif isinstance(current, list):
                        current[:] = safe
                elif future.done() and future.exception() is not None:
                    failure = future.exception()
                    if hasattr(failure, 'code') and scrub(failure.code) != failure.code:
                        failure.code = 'detected_secret_withheld'; failure.args = (failure.code,)
                if scrub(key) != key:
                    requests._cache.pop(key, None)
            # Native client/session objects are never returned; keys can carry
            # an operator label or endpoint and are no longer needed after reads.
            requests._clients.clear(); requests._sessions.clear()
        safe_options = scrub(options)
        options.clear(); options.update(safe_options)
        return scrub(collections), scrub(metadata)
    finally:
        state.clear()
        descriptors.clear()
        getattr(requests, 's3_source_redactions', set()).clear()

