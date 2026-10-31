"""Unregistered owner entrypoints for selected configured package capture.

Prepare before auth; keep expected_context separately; release output only after
finalize_union has scrubbed every owner-supplied export/cache surface. This module
does not install hooks, authorize hosted requests, or claim registry admission.
"""
from copy import deepcopy
import math
import os
import threading
from uuid import uuid4
from weakref import WeakKeyDictionary

from peaso import azure_function_package_portable_20261020 as contract
from peaso.secret_scanning import _fingerprint
from . import azure_function_package_source_20261020 as source
from . import azure_function_package_portable_20261020 as exporter
from . import azure_selected_storage_secret_indicators as storage

CHECK, OPTION, KIND = source.CHECK, source.OPTION, contract.KIND
DECLARATION = {'id': CHECK, 'kind': KIND, 'provider': 'azure', 'severity': 'high',
    'finding_type': 'secrets', 'ui_group': 'Secrets', 'requirements': [],
    'dependencies': [KIND], 'allow_incomplete_failure': True,
    'title': 'Selected configured deployment package source has no detected secrets',
    'remediation': 'Remove exposed literals, rotate confirmed exposed credentials, and rebuild with managed identities or supported secret references.'}
MAX_WINDOWS = 2000000
_NATIVE_COLLECT = source.collect
_LOCK = threading.Lock()
_PLANS, _PENDING = WeakKeyDictionary(), WeakKeyDictionary()


class Invalid(ValueError):
    """Fixed private-data-free runtime error."""


class _Handle:
    __slots__ = ('__weakref__',)

    def __copy__(self):
        raise Invalid('opaque_runtime_handle')

    def __deepcopy__(self, memo):
        raise Invalid('opaque_runtime_handle')

    def __reduce__(self):
        raise Invalid('opaque_runtime_handle')


def prepare(options, scopes, named_checks, *, customer_context_id,
            credential_context_id, tenant_id, principal_id,
            shared_service_account=False, provider='azure'):
    """Credential-free, exact public named selection; no request-supplied grant.

    Identity and shared-account arguments belong to the trusted owner, never
    request options. No framework, wildcard, private kind or supplied plan grants
    authority. Disabled supplied selectors still receive native validation.
    """
    if provider != 'azure' or not isinstance(options, dict):
        raise Invalid('invalid_runtime_selection')
    if any(k in options for k in ('grant', 'plan', '_azure_function_package_runtime_plan')):
        raise Invalid('user_supplied_runtime_grant')
    try:
        targets = source.preflight(options, scopes, named_checks,
                                   shared_service_account=shared_service_account)
        if not targets:
            return None
        expected = exporter.build_expected_context(targets, scopes,
            capture='package-capture:' + uuid4().hex,
            customer_context_id=customer_context_id, credential_context_id=credential_context_id,
            tenant_id=tenant_id, principal_id=principal_id)
        # This provisional UUID validates the context builder only; it is never
        # asserted as a native capture. The actual UUID remains source-owned.
        expected.pop('capture')
        state = {'targets': targets, 'selection_context': expected, 'pid': os.getpid()}
    except (ValueError, TypeError, KeyError, AttributeError):
        raise Invalid('invalid_runtime_selection_or_binding') from None
    plan = _Handle()
    with _LOCK:
        _PLANS[plan] = state
    return plan


def selection_context(plan):
    """Retain independent selection/identity before collect; no capture invented."""
    with _LOCK:
        state = _PLANS.get(plan) if type(plan) is _Handle else None
        if state is None or state['pid'] != os.getpid():
            raise Invalid('invalid_or_consumed_runtime_plan')
        return deepcopy(state['selection_context'])


def captured_context(pending, *, expected_selection_context):
    """Bind native capture only to independently retained pre-auth plan context.

    Capture comes from the authentic return of this controlled invocation, never
    supplied options or portable JSON. Retain this result separately from the
    snapshot for later index admission, including across process boundaries.
    """
    with _LOCK:
        state = _PENDING.get(pending) if type(pending) is _Handle else None
        if state is None or state['pid'] != os.getpid() or expected_selection_context != {
                k: v for k, v in state['expected'].items() if k != 'capture'}:
            raise Invalid('independent_selection_context_required')
        return deepcopy(state['expected'])


class _Union:
    def __init__(self):
        self.descriptors, self.overflow = {}, False
        self.count = self.size = 0

    def remember(self, values):
        try:
            if self.overflow or len(values) > storage.MAX_REDACTION_VALUES:
                raise ValueError()
            for value in values:
                if not isinstance(value, str) or not value or len(value.encode()) > storage.MAX_REDACTION_VALUE_BYTES:
                    raise ValueError()
                fingerprints = self.descriptors.setdefault(len(value), set())
                before = len(fingerprints)
                fingerprints.add(_fingerprint(value))
                if len(fingerprints) != before:
                    self.count += 1
                    self.size += len(value.encode())
                if self.count > storage.MAX_REDACTION_VALUES or self.size > storage.MAX_REDACTION_TOTAL:
                    raise ValueError()
        except (ValueError, TypeError, UnicodeError):
            self.overflow = True
            self.descriptors.clear()

    def scrub(self, value):
        if self.overflow:
            raise Invalid('content_union_redaction_incomplete')
        nodes = chars = windows = 0

        def visit(item, depth=0):
            nonlocal nodes, chars, windows
            nodes += 1
            if nodes > 65536 or depth > 32:
                raise Invalid('content_union_redaction_incomplete')
            if isinstance(item, str):
                chars += len(item.encode())
                if chars > storage.MAX_REDACTION_BYTES:
                    raise Invalid('content_union_redaction_incomplete')
                ranges = []
                for length, fingerprints in self.descriptors.items():
                    count = max(0, len(item) - length + 1)
                    windows += count
                    if windows > MAX_WINDOWS:
                        raise Invalid('content_union_redaction_incomplete')
                    for start in range(count):
                        if _fingerprint(item[start:start + length]) in fingerprints:
                            ranges.append((start, start + length))
                out, offset = [], 0
                # Merge overlapping spans so no suffix of a matched value leaks.
                for start, end in sorted(ranges):
                    if start >= offset:
                        out.extend((item[offset:start], '[redacted]'))
                    offset = max(offset, end)
                return ''.join(out) + item[offset:]
            if isinstance(item, (list, tuple)):
                if len(item) > 65536:
                    raise Invalid('content_union_redaction_incomplete')
                return [visit(v, depth + 1) for v in item]
            if isinstance(item, dict):
                if len(item) > 65536 or any(not isinstance(k, str) for k in item):
                    raise Invalid('content_union_redaction_incomplete')
                out = {}
                for key, child in item.items():
                    safe = visit(key, depth + 1)
                    if safe in out:
                        raise Invalid('content_union_redaction_incomplete')
                    out[safe] = visit(child, depth + 1)
                return out
            if item is None or type(item) in (bool, int) or type(item) is float and math.isfinite(item):
                return item
            raise Invalid('content_union_redaction_incomplete')
        return visit(value)

    def clear(self):
        self.descriptors.clear()


def _reader(union):
    # Keep the real scheduler and its native retry/deadline behavior. The only
    # specialization retains HMAC descriptors when the native ephemeral set is
    # populated; native cleanup still destroys all matched plaintext.
    from .azure import _Reader

    class Matches(set):
        def update(self, values):
            union.remember(values)
            super().update(values)

    class IsolatedReader(_Reader):
        def __setattr__(self, key, value):
            if key == 'storage_source_secret_redactions':
                value = Matches(value)
            if key == 'storage_source_secret_overflow' and value is True:
                union.overflow = True
            super().__setattr__(key, value)
    return IsolatedReader({'retries': 0})


def collect(plan, authenticate):
    """Consume a prepared plan once, then invoke the owner auth factory.

    Original collect callable and all original HTTP, ZIP and scanner helpers run
    unchanged. Its own generated capture is retained only after the original
    seal validates, and the exporter checks all independently planned bindings.
    No dynamic function execution, module monkeypatching or re-signing occurs.
    """
    with _LOCK:
        state = _PLANS.pop(plan, None) if type(plan) is _Handle else None
    if state is None or state['pid'] != os.getpid():
        raise Invalid('invalid_or_consumed_runtime_plan')
    union = _Union()
    try:
        if not callable(authenticate):
            raise Invalid('runtime_source_binding_changed')
        selection = state['selection_context']
        reader = _reader(union)
        native = _NATIVE_COLLECT(reader, authenticate(), selection['scopes'],
            {'content_secret_scans': True, OPTION: state['targets']}, [CHECK],
            customer_context_id=selection['customer_context_id'],
            credential_context_id=selection['credential_context_id'])
        if not source.authentic(native):
            raise Invalid('native_capture_not_authentic')
        expected = dict(selection, capture=native['capture'])
        snapshot = exporter.export_native_projection(native, expected_index_context=expected)
        pending = _Handle()
        with _LOCK:
            _PENDING[pending] = {'snapshot': snapshot, 'expected': expected, 'union': union, 'pid': os.getpid()}
        return pending
    except Exception:
        union.clear()
        raise Invalid('runtime_capture_rejected') from None


def retain_union(pending, matched_values):
    """Owner contributes other selected-content detectors' transient matches."""
    with _LOCK:
        state = _PENDING.get(pending) if type(pending) is _Handle else None
        if state is None or state['pid'] != os.getpid():
            raise Invalid('invalid_or_consumed_runtime_capture')
        state['union'].remember(matched_values)


def finalize_union(pending, *, surfaces):
    """Release sanitized copies exactly once; fail closed on any redaction bound.

    surfaces is the complete JSON-ready owner union: collections, metadata,
    options, errors, cached responses and pending writes. Nothing may be emitted
    or cached earlier. Caller replaces all originals with returned copies; this
    function neither edits shared hooks nor mutates the supplied surfaces.
    """
    with _LOCK:
        state = _PENDING.pop(pending, None) if type(pending) is _Handle else None
    if state is None or state['pid'] != os.getpid():
        raise Invalid('invalid_or_consumed_runtime_capture')
    try:
        # Raw selected site/blob names are runtime inputs, not export metadata.
        if not isinstance(surfaces, dict):
            raise Invalid('content_union_redaction_incomplete')
        surfaces = dict(surfaces)
        if 'options' in surfaces:
            if not isinstance(surfaces['options'], dict):
                raise Invalid('content_union_redaction_incomplete')
            surfaces['options'] = {k: v for k, v in surfaces['options'].items() if k != OPTION}
        safe = state['union'].scrub({'package_snapshot': state['snapshot'], 'surfaces': surfaces})
        # Scrubbing must never repair or silently invalidate package assertions.
        snapshot = safe['package_snapshot']
        snapshot['snapshot_id'] = contract.digest({k: v for k, v in snapshot.items() if k != 'snapshot_id'})
        contract.validate_snapshot(snapshot, state['expected'])
        return safe
    except Exception:
        raise Invalid('content_union_redaction_incomplete') from None
    finally:
        state['union'].clear()


def discard(handle):
    """Explicit cleanup on owner cancellation; never emit a partial private union."""
    with _LOCK:
        if type(handle) is _Handle:
            _PLANS.pop(handle, None)
            state = _PENDING.pop(handle, None)
            if state:
                state['union'].clear()
