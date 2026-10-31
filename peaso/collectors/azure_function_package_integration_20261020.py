"""Default-off native package capture with a final, whole-collector union scrub."""
import base64
from contextlib import contextmanager
from contextvars import ContextVar
from copy import deepcopy
from uuid import uuid4

from peaso import azure_function_package_index_20261020 as index_owner
from peaso.snapshot import seal
from . import azure_function_package_runtime_20261020 as predecessor
from . import azure_function_package_source_20261020 as source
from . import azure_function_package_portable_20261020 as exporter

CHECK, KIND, OPTION = predecessor.CHECK, predecessor.KIND, predecessor.OPTION
GRANT = '_azure_function_package_engine_grant'
_TOKEN = object()
_SHARED = ContextVar('azure_package_shared_account', default=False)


class _Grant:
    __slots__ = ('token', 'scopes', 'targets', 'union', 'expected')

    def __init__(self, scopes, targets):
        self.token, self.scopes, self.targets = _TOKEN, tuple(scopes), deepcopy(targets)
        self.union, self.expected = predecessor._Union(), None

    def __deepcopy__(self, memo):
        return self


@contextmanager
def owner_context(*, shared_service_account=False):
    """Trusted execution policy, deliberately absent from serialized options."""
    if type(shared_service_account) is not bool:
        raise ValueError('invalid_package_owner_context')
    token = _SHARED.set(shared_service_account)
    try:
        yield
    finally:
        _SHARED.reset(token)


def preflight(options, scopes, named_checks, *, provider='azure'):
    if provider != 'azure' and (OPTION in options or CHECK in named_checks):
        raise ValueError('package_selection_requires_azure')
    if provider != 'azure':
        return []
    targets = source.preflight(options, scopes, named_checks, shared_service_account=_SHARED.get())
    if (OPTION in options or targets) and any(s != s.lower() for s in scopes):
        raise ValueError('package_scopes_require_canonical_identity')
    return targets


def issue_engine_grant(options, scopes, named_checks):
    options.pop(GRANT, None)
    targets = preflight(options, scopes, named_checks)
    if targets:
        options[GRANT] = _Grant(scopes, targets)
        return options[GRANT]


def authorize(options, scopes):
    grant = options.pop(GRANT, None)
    valid = (type(grant) is _Grant and grant.token is _TOKEN and grant.scopes == tuple(scopes)
             and grant.targets == source.preflight(options, scopes, [CHECK], shared_service_account=_SHARED.get())
             and options.get('content_secret_scans') is True)
    # Private kind selectors and serialized grant-like data never authorize.
    if '_content_secret_scan_kinds' in options or valid:
        options['_content_secret_scan_kinds'] = [k for k in options.get('_content_secret_scan_kinds', []) if k != KIND]
    if valid:
        options['_content_secret_scan_kinds'].append(KIND)
        grant.token = None
    else:
        source.preflight(options, scopes, [], shared_service_account=_SHARED.get())
    return grant if valid else None


def collect(reader, transport, grant, scopes, *, customer_context_id, credential_context_id):
    """Use unchanged native capture/export, sharing the owner's read budget."""
    if grant is None:
        return
    reader.check_cancelled()
    union = grant.union
    reader.package_source_union = union
    grant.union = union
    reader.package_source_grant = grant
    isolated = predecessor._reader(union)
    # Native standalone isolation remains real; the actual scheduler now debits
    # the same owner budget/lock and observes its cancellation/deadline hooks.
    isolated.budget, isolated.lock = reader.budget, reader.lock
    isolated.cancel_check, isolated.deadline = reader.cancel_check, reader.deadline
    isolated.retries = 0
    state = {'authority': None}
    with source.private_native_logs():
        token = source.storage._token(transport, source.storage.ARM, state)
        claims = source.storage._json(base64.urlsafe_b64decode(token.split('.')[1] + '=' * ((-len(token.split('.')[1])) % 4)))
        del token
        expected = exporter.build_expected_context(grant.targets, scopes,
            capture='package-capture:' + uuid4().hex, customer_context_id=customer_context_id,
            credential_context_id=credential_context_id, tenant_id=claims['tid'], principal_id=claims['oid'])
        del claims
        expected.pop('capture')
        native = predecessor._NATIVE_COLLECT(isolated, transport, scopes,
            {'content_secret_scans': True, OPTION: grant.targets}, [CHECK],
            customer_context_id=customer_context_id, credential_context_id=credential_context_id)
        if not source.authentic(native):
            raise ValueError('package_native_capture_rejected')
        expected['capture'] = native['capture']
        snapshot = exporter.export_native_projection(native, expected_index_context=expected)
    reader.package_source_snapshot, reader.package_source_expected = snapshot, expected
    grant.expected = deepcopy(expected)


def retain_union(reader):
    union = getattr(reader, 'package_source_union', None)
    if union is None:
        return
    for name, values in tuple(vars(reader).items()):
        if name.endswith('_redactions') and isinstance(values, set):
            union.remember(values)
        if name.endswith('_overflow') and values is True:
            union.overflow = True


def _scrub(union, value):
    """Scrub JSON surfaces and runtime tuple keys without serializing hooks."""
    nodes = chars = windows = 0

    def visit(item, depth=0):
        nonlocal nodes, chars, windows
        nodes += 1
        if nodes > 65536 or depth > 32:
            raise ValueError('package_union_bound')
        if isinstance(item, str):
            chars += len(item.encode())
            windows += sum(max(0, len(item) - length + 1) for length in union.descriptors)
            if chars > source.storage.MAX_REDACTION_BYTES or windows > predecessor.MAX_WINDOWS:
                raise ValueError('package_union_bound')
            return union.scrub(item)
        if isinstance(item, dict):
            out = {}
            for key, child in item.items():
                safe_key = visit(key, depth + 1)
                if safe_key in out:
                    raise ValueError('package_union_key_collision')
                out[safe_key] = visit(child, depth + 1)
            return out
        if isinstance(item, (tuple, list, set)):
            return type(item)(visit(v, depth + 1) for v in item)
        if item is None or type(item) in (int, float, bool):
            return union.scrub(item)
        return item
    if union.overflow:
        raise ValueError('package_union_overflow')
    return visit(value)


def finish(reader, snapshot, options, transport, cache, cache_locks):
    """Run the actual prior finalizer, then scrub and release the whole union."""
    from . import azure_function_settings_runtime_hooks_20261020 as legacy
    retain_union(reader)
    try:
        snapshot = legacy.final_snapshot(reader, snapshot)
        return finalize(reader, snapshot, options, transport, cache, cache_locks)
    except Exception:
        options.clear(); cache.clear(); cache_locks.clear()
        if hasattr(transport, 'tokens'):
            transport.tokens.clear()
        union = getattr(reader, 'package_source_union', None)
        if union is not None:
            union.clear()
        for name, value in tuple(vars(reader).items()):
            if isinstance(value, (dict, list, set)):
                value.clear()
        reader.package_source_union = reader.package_source_snapshot = reader.package_source_expected = None
        raise ValueError('package_union_redaction_incomplete') from None


def finalize(reader, snapshot, options, transport, cache, cache_locks):
    """Called after every existing finalizer; owns every retained mixed surface."""
    union = getattr(reader, 'package_source_union', None)
    if union is None:
        return snapshot
    expected = getattr(reader, 'package_source_expected', None)
    try:
        package = getattr(reader, 'package_source_snapshot', None)
        options.pop(OPTION, None)
        options.pop(GRANT, None)
        if package is not None:
            safe_package = union.scrub(package)
            safe_package['snapshot_id'] = predecessor.contract.digest({k: v for k, v in safe_package.items() if k != 'snapshot_id'})
            predecessor.contract.validate_snapshot(safe_package, expected)
            snapshot['collections'].extend(safe_package['collections'])
            snapshot['metadata'].update(safe_package['metadata'])
            snapshot['metadata'][index_owner.EXPORT] = {k: safe_package[k] for k in ('created_at', 'snapshot_id')}
        surfaces = _scrub(union, {'snapshot': snapshot, 'options': options,
            'reader': {name: value for name, value in vars(reader).items() if isinstance(value, (dict, list, set, tuple))},
            'cache': cache, 'cache_locks': cache_locks})
        safe = surfaces['snapshot']
        options.clear(); options.update(surfaces['options'])
        for name, value in surfaces['reader'].items():
            setattr(reader, name, value)
        if expected is not None:
            index_owner.retain_expected_context(expected)
        return seal(safe)
    except Exception:
        if expected is not None:
            index_owner.forget_expected_context(expected['capture'])
        options.clear()
        reader.collections.clear()
        raise ValueError('package_union_redaction_incomplete') from None
    finally:
        cache.clear(); cache_locks.clear()
        if hasattr(transport, 'tokens'):
            transport.tokens.clear()
        for name, value in tuple(vars(reader).items()):
            if name.endswith('_redactions') and isinstance(value, set):
                value.clear()
        reader.package_source_snapshot = reader.package_source_expected = None
        if getattr(reader, 'package_source_grant', None) is None:
            union.clear()
        reader.package_source_union = None


def collect_pipeline(connector, requirements, request):
    """Finish actual native dispatch plus later bulk overlays before cleanup."""
    from peaso import engine
    from peaso.collectors import collect_live
    options = connector['options']
    grant = options.get(GRANT)
    if type(grant) is not _Grant or grant.token is not _TOKEN:
        raise ValueError('package_pipeline_grant_required')
    supplied = request.get('connector', request).get('options', {})
    try:
        snapshot = engine.validate(collect_live(connector, requirements))
        if grant.union is None:
            raise ValueError('package_pipeline_capture_missing')
        # Bulk evidence may have added options after Azure's native finalizer.
        # The same union remains live until this last export boundary.
        for current in (options, supplied):
            current.pop(OPTION, None); current.pop(GRANT, None)
        safe = _scrub(grant.union, {'snapshot': snapshot, 'options': options, 'supplied': supplied})
        options.clear(); options.update(safe['options'])
        supplied.clear(); supplied.update(safe['supplied'])
        snapshot = safe['snapshot']
        engine.emit_progress(phase='collecting', provider='azure', completed=len(snapshot['collections']),
            total=len(snapshot['collections']), resources=sum(len(c['items']) for c in snapshot['collections']), dynamic_total=False)
        snapshot['metadata']['collection_plan'] = {
            'mode': 'collect_all' if options.get('collect_all') else 'explicit_inventories' if 'inventories' in options
                else 'full_default' if engine._full_selection('azure', *engine._selection('azure', request.get('categories'), request.get('checks'), request.get('frameworks'))) else 'dependencies',
            'requirements': requirements, 'categories': request.get('categories') or list(engine.CATEGORIES),
            'checks': request.get('checks') or 'all_selected', 'frameworks': request.get('frameworks') or 'all_selected'}
        return engine.validate(seal(snapshot))
    except Exception:
        options.clear(); supplied.clear()
        if grant.expected is not None:
            index_owner.forget_expected_context(grant.expected['capture'])
        raise ValueError('package_pipeline_export_rejected') from None
    finally:
        if grant.union is not None:
            grant.union.clear()
        grant.union = grant.expected = None
        grant.targets.clear()
