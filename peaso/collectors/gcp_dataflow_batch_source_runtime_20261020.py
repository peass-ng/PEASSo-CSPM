"""Two explicit engine-granted source readers; native captures remain unmodified."""
from copy import deepcopy
from types import FunctionType
import json
import logging
from peaso.secret_scanning import _fingerprint, redact_matches, scan_content
from . import gcp_dataflow_referenced_source_20261020 as dataflow
from . import gcp_batch_referenced_source_20261020 as batch
from . import gcp_workbench_source_runtime_20261020 as workbench
from . import gcp_dataproc_source_runtime_20261020 as dataproc

PROFILES = {
    'dataflow': dict(source=dataflow, check=dataflow.CHECK, kind='dataflow_selected_package_source', marker='DataflowReferencedSourceCapture'),
    'batch': dict(source=batch, check=batch.CHECK, kind=batch.KIND, marker='BatchReferencedSourceCapture'),
}
KINDS = frozenset(p['kind'] for p in PROFILES.values())
CHECKS = tuple(p['check'] for p in PROFILES.values())
OPTIONS = frozenset(p['source'].OPTION for p in PROFILES.values())
GRANT = '_dataflow_batch_source_engine_grants'
NAMED = '_dataflow_batch_source_named_checks'
STATE = '_dataflow_batch_source_runtime'
_SEAL = object()


class _Grant:
    __slots__ = ('seal', 'profile', 'scopes', 'selection')

    def __init__(self, profile, scopes, targets):
        self.seal, self.profile, self.scopes = _SEAL, profile, tuple(scopes)
        self.selection = _fingerprint(json.dumps(targets, sort_keys=True))


def preflight(options, scopes, named=(), provider='gcp'):
    selected = {}
    for profile, p in PROFILES.items():
        source = p['source']
        if source.OPTION not in options and p['check'] not in named:
            selected[profile] = []
            continue
        try:
            if provider != 'gcp':
                raise ValueError('provider')
            targets = (source.selection(scopes, options, [p['check']] if p['check'] in named else [])[0]
                       if profile == 'dataflow' else source.selected_targets(options, scopes))
            if p['check'] in named and options.get('content_secret_scans') is True and not targets:
                raise ValueError('missing selection')
            selected[profile] = targets
        except (ValueError, TypeError, UnicodeError, source.Incomplete):
            raise ValueError('Selected Dataflow/Batch sources require 1-4 exact owned native resource/reference/bucket/object/generation targets') from None
    return selected


def issue_engine_grants(options, scopes, named=()):
    options.pop(GRANT, None)
    options[NAMED] = []
    targets = preflight(options, scopes, named)
    if options.get('content_secret_scans') is True and any(p['check'] in named for p in PROFILES.values()):
        options[GRANT] = {profile: _Grant(profile, scopes, targets[profile]) for profile, p in PROFILES.items() if p['check'] in named}


def authorize_collector(options, scopes):
    tokens = options.pop(GRANT, {})
    targets = preflight(options, scopes)
    permitted = set()
    for profile, p in PROFILES.items():
        token = tokens.get(profile) if type(tokens) is dict else None
        if (type(token) is _Grant and token.seal is _SEAL and token.profile == profile
                and token.scopes == tuple(scopes) and options.get('content_secret_scans') is True
                and token.selection == _fingerprint(json.dumps(targets[profile], sort_keys=True))):
            permitted.add(p['kind'])
    options[NAMED] = [p['check'] for p in PROFILES.values() if p['kind'] in permitted]
    incoming = options.get('_content_secret_scan_kinds')
    incoming = incoming if isinstance(incoming, list) else []
    options['_content_secret_scan_kinds'] = [k for k in incoming if k not in KINDS or k in permitted]
    return frozenset(permitted) & frozenset(options['_content_secret_scan_kinds'])


def _dataflow_capture(transport, scopes, options, values):
    """Exact sealed parser code with a private union-aware scanner binding."""
    def scanner(raw, path, timeout):
        return scan_content(raw, path, timeout=timeout, _redact_values=values.update)
    namespace = dict(vars(dataflow), scan_content=scanner)
    inspect_payload = FunctionType(dataflow.inspect_payload.__code__, namespace, dataflow.inspect_payload.__name__, dataflow.inspect_payload.__defaults__, dataflow.inspect_payload.__closure__)
    namespace['inspect_payload'] = inspect_payload
    capture = FunctionType(dataflow.capture.__code__, namespace, dataflow.capture.__name__, dataflow.capture.__defaults__, dataflow.capture.__closure__)
    return capture(transport, scopes, options, [dataflow.CHECK])


def _state(transport):
    with transport.lock:
        if not hasattr(transport, STATE):
            setattr(transport, STATE, dict(captures={}, items={}, redactions=set()))
        return getattr(transport, STATE)


def collection_pages(collector, scope, profile):
    p = PROFILES[profile]; source = p['source']
    targets = [t for t in preflight(collector.options, collector.scopes)[profile] if source.parse(t) == scope]
    if not targets:
        return
    state = _state(collector.transport)
    # Refuse private wire diagnostics before acquiring a token or opening a session.
    unsafe = any(logging.getLogger(n).getEffectiveLevel() <= logging.DEBUG for n in ('urllib3', 'urllib3.connectionpool', 'requests'))
    if unsafe:
        from .gcp import ReadError
        raise ReadError('unavailable', 'unsafe_http_diagnostics')
    options = {**collector.options, source.OPTION: targets}
    capture = (_dataflow_capture(collector.transport, [scope], options, state['redactions']) if profile == 'dataflow'
               else source.collect(collector.transport, options, [scope], named=[p['check']]))
    with collector.transport.lock:
        state['captures'][(profile, scope)] = deepcopy({k: v for k, v in capture.items() if k != 'items'})
    for native in capture['items']:
        ident = native['identity'] if profile == 'dataflow' else native['name']
        refs = native['requests'] if profile == 'dataflow' else native[batch.MARKER]['source_requests']
        row = dict(name=ident, **{p['marker']: deepcopy(native)},
                   _provenance=dict(scope=scope, capture=capture['capture'], source_requests=refs),
                   _coverage={p['marker']: dict(status='collected', source_requests=refs)})
        with collector.transport.lock:
            state['items'][ident] = deepcopy(row)
        for ref in refs[:-1]:
            yield [], ref
        yield row and [row], refs[-1] if refs else 'local:selected-source-unavailable'


def jobs(collector, scope):
    return [(p['kind'], scope, profile, lambda profile=profile: collection_pages(collector, scope, profile))
            for profile, p in PROFILES.items() if p['kind'] in collector.needed and p['check'] in collector.options.get(NAMED, [])]


def preserve_capture(item, raw, transport):
    produced = getattr(transport, STATE, {}).get('items', {}).get(raw.get('name'))
    if produced is not None and raw == produced:
        item['_provenance']['capture'] = produced['_provenance']['capture']


def _redact(value, values):
    """Extend the shared string-key scrub to retained tuple dictionary keys."""
    if isinstance(value, dict):
        output = {}
        for key, item in value.items():
            safe = redact_matches(list(key) if isinstance(key, tuple) else key, values)
            if isinstance(key, tuple):
                safe = ('redacted-collection', _fingerprint(json.dumps(key))) if safe != list(key) else key
            output[safe] = _redact(item, values)
        return output
    if isinstance(value, (list, tuple)):
        return [_redact(v, values) for v in value]
    return redact_matches(value, values)


def final_snapshot(collector, snapshot):
    transport = collector.transport
    state = getattr(transport, STATE, {})
    values = (set(state.get('redactions', ())) | set(getattr(transport, '_batch_source_redactions', ()))
              | set(workbench.source.redaction_values(transport)) | set(dataproc.source.redaction_values(transport)))
    try:
        snapshot = deepcopy(snapshot)
        metadata = snapshot.setdefault('metadata', {})
        for profile, p in PROFILES.items():
            metadata[p['kind'] + '_captures'] = {scope: deepcopy(capture) for (name, scope), capture in state.get('captures', {}).items() if name == profile}
        for options in (collector.options, transport.options, metadata.get('options', {})):
            for key in (*OPTIONS, GRANT, NAMED):
                options.pop(key, None)
        for owner, fields in ((collector, ('options', 'collections')), (transport, ('options', 'cache', 'evidence'))):
            for field in fields:
                setattr(owner, field, _redact(getattr(owner, field), values))
        for name in ('_workbench_source_state', '_dataproc_source_state'):
            pending = getattr(transport, name, None)
            if pending is not None:
                pending['redactions'].update(values)
        from peaso.snapshot import seal
        return seal(_redact(snapshot, values))
    finally:
        clear_pending(transport)
        values.clear()


def clear_pending(transport):
    state = getattr(transport, STATE, None)
    if state is not None:
        state['redactions'].clear(); state['items'].clear(); state['captures'].clear()
        delattr(transport, STATE)
    values = getattr(transport, '_batch_source_redactions', None)
    if values is not None:
        values.clear(); delattr(transport, '_batch_source_redactions')
