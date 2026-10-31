"""Engine-issued, default-off adapter around the unchanged native command reader."""
from copy import deepcopy
import json
from . import aws_workload_command_source_20261020 as source

CHECK, KIND, OPTION = source.CHECK, source.KIND, source.OPTION
GRANT = '_aws_workload_command_engine_grant'
MARKER = 'SelectedWorkloadCommandCapture'
CAPTURE = KIND + '_capture'
_TOKEN = object()


class _Grant:
    __slots__ = ('token', 'scopes', 'targets')

    def __init__(self, scopes, targets):
        self.token, self.scopes, self.targets = _TOKEN, tuple(scopes), deepcopy(targets)

    def __deepcopy__(self, memo):
        return self


def targets(options, scopes, named=(), provider='aws'):
    if OPTION not in options and not (options.get('content_secret_scans') is True and CHECK in named):
        return []
    rows = options.get(OPTION)
    if (provider != 'aws' or not isinstance(scopes, list) or not scopes
            or len(set(scopes)) != len(scopes)
            or any(not isinstance(s, str) or len(s) > 80 or not source.SCOPE.fullmatch(s) for s in scopes)
            or not isinstance(rows, list) or not 1 <= len(rows) <= source.MAX_TARGETS):
        raise ValueError('invalid_selected_workload_commands')
    seen = set()
    for row in rows:
        source.parse(row)
        ident = source.locator(row)
        if row['scope'] not in scopes or ident in seen:
            raise ValueError('invalid_selected_workload_commands')
        seen.add(ident)
    if len({row['scope'] for row in rows}) > source.MAX_SELECTED_SCOPES:
        raise ValueError('invalid_selected_workload_commands')
    return deepcopy(rows)


def issue_engine_grant(options, scopes, named=()):
    options.pop(GRANT, None)
    rows = targets(options, scopes, named)
    if options.get('content_secret_scans') is True and CHECK in named:
        options[GRANT] = _Grant(scopes, rows)


def authorize_collector(options, scopes):
    token = options.pop(GRANT, None)
    rows = targets(options, scopes)
    incoming = options.get('_content_secret_scan_kinds')
    permitted = (type(token) is _Grant and token.token is _TOKEN and token.scopes == tuple(scopes)
        and token.targets == rows and options.get('content_secret_scans') is True
        and isinstance(incoming, list) and KIND in incoming)
    if isinstance(incoming, list):
        options['_content_secret_scan_kinds'] = [k for k in incoming if k != KIND]
    if not permitted:
        return None
    return source.prepare({'check_id': CHECK, 'content_secret_scans': True,
        'content_secret_scan_grants': [source.GRANT], OPTION: rows}, scopes)


def disabled_snapshot(scopes):
    from peaso.snapshot import make_snapshot
    return make_snapshot('aws', list(scopes), [{'type': KIND, 'scope': s, 'service': 'workload',
        'status': 'not_collected', 'items': [], 'error': {'code': 'explicit_named_content_grant_required'}}
        for s in scopes], metadata={'collection': 'read-only'})


def collect_selected(plan, contexts, requests):
    """Use only normal, pinned, authorized account contexts; never discover one."""
    if plan is None:
        return None
    sessions = {}
    for session, caller in contexts:
        if caller['Account'] in sessions:
            raise ValueError('ambiguous_workload_account_context')
        sessions[caller['Account']] = (session, deepcopy(caller))

    class ScopedSession:
        def __init__(self, session, region):
            self.session, self.region = session, region

        def client(self, service, **kwargs):
            requests.check_deadline()
            if service not in ('sts', 'ecs', 'batch') or kwargs.get('region_name') != self.region:
                raise ValueError('workload_session_scope_binding')
            with requests._lock:
                if requests.max_calls is not None and requests.calls >= requests.max_calls:
                    raise ValueError('workload_call_limit')
                requests.calls += 1
            return self.session.client(service, **kwargs)

    def factory(scope):
        account, region = scope.split('/')
        if scope not in plan['body']['scopes'] or account not in sessions:
            raise ValueError('workload_account_context_unavailable')
        return ScopedSession(sessions[account][0], region)

    from .aws_content_sdk_logging import private_sdk_logs
    with private_sdk_logs():
        capture = source.collect(plan, factory)
    # The reader independently repeats native STS binding. Reject context drift.
    from peaso.secret_scanning import _fingerprint
    for row in capture['items']:
        account = row['scope'].split('/')[0]
        if row['native_bound'] and account in sessions:
            caller = sessions[account][1]
            expected = (_fingerprint(json.dumps({k: caller[k] for k in ('Account', 'Arn', 'UserId')}, sort_keys=True))
                if all(isinstance(caller.get(k), str) and caller[k] for k in ('Account', 'Arn', 'UserId')) else None)
            if expected is None or row['principal'] != expected:
                row.update(native_bound=False, native_complete=False, complete=False, scans=[], leaks=[])
                capture['complete'] = False
    return capture


def publish(capture, plan, collections, metadata, options):
    options.pop(OPTION, None)
    options.pop(GRANT, None)
    if plan is None:
        return collections, metadata
    from peaso.checks.aws_workload_command_source_20261020 import evaluate_collection
    status, evidence = evaluate_collection(capture)
    scope = plan['body']['targets'][0]['scope']
    leaks = evidence.get('secret_leaks', [])
    ids = ['leak:' + leak['fingerprint'] for leak in leaks] if leaks else ['summary']
    rows = [{'id': KIND + ':' + ident, MARKER: ident} for ident in ids]
    # The full bounded native capture is ordinary snapshot data, saved once.
    metadata[CAPTURE] = {'scope': scope, 'scopes': list(plan['body']['scopes']), 'native': capture}
    collections = [c for c in collections if c['type'] != KIND]
    collections.append({'type': KIND, 'scope': scope, 'service': 'workload',
        'status': 'collected' if capture['complete'] else 'partial', 'items': rows})
    return collections, metadata

