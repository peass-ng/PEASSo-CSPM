"""Native-field successors for five existing annotation criteria.

No CASES or Check metadata is changed. Existing safe/checked, provider-managed
applicability and Claude native-field wrappers are cloned with fresh closure
cells; only the innermost criterion is replaced.
"""
from copy import deepcopy
from dataclasses import replace
import types

IDS = (
    'k8s.claude.ingress.no_nginx_snippets',
    'k8s.claude.ingress.no_nginx_snippet_alias',
    'k8s.claude.ingress.no_nginx_snippet_lua',
    'k8s.claude.podsecuritypolicy.default_seccomp_profile',
    'k8s.claude.podsecuritypolicy.security_services_hardening',
)
MARK = '_k8s_annotation_native_admission_20261020'
_PREDECESSORS = {}


def _bindings(function):
    return dict(zip(function.__code__.co_freevars, (c.cell_contents for c in function.__closure__ or ())))


def _layers(check):
    safe = check.evaluate; values = _bindings(safe)
    if (set(values) != {'checked', 'id', 'kind', 'provider', 'target'}
            or any(values[k] != getattr(check, k) for k in ('id', 'kind', 'provider', 'target'))):
        raise RuntimeError('Annotation registry wrapper binding changed')
    checked = values['checked']; guard = _bindings(checked)
    if set(guard) != {'function'}:
        raise RuntimeError('Annotation checked wrapper changed')
    native_guard = guard['function']; native = _bindings(native_guard)
    if set(native) != {'function'} or getattr(safe, '__wrapped__', None) is not native_guard:
        raise RuntimeError('Annotation native-field wrapper changed')
    return safe, checked, native_guard, native['function']


def _cell(value):
    return (lambda: value).__closure__[0]


def _clone(function, leaf, successor, memo):
    if function is leaf:
        return successor
    if function in memo:
        return memo[function]
    values = []
    for cell in function.__closure__ or ():
        value = cell.cell_contents
        values.append(_clone(value, leaf, successor, memo) if isinstance(value, types.FunctionType) else value)
    clone = types.FunctionType(function.__code__, function.__globals__, function.__name__,
        function.__defaults__, tuple(_cell(v) for v in values) if function.__closure__ else None)
    memo[function] = clone
    clone.__kwdefaults__ = deepcopy(function.__kwdefaults__)
    clone.__annotations__ = dict(function.__annotations__)
    clone.__module__, clone.__qualname__, clone.__doc__ = function.__module__, function.__qualname__, function.__doc__
    clone.__dict__.update(function.__dict__)
    if hasattr(function, '__wrapped__'):
        wrapped = function.__wrapped__
        if wrapped not in memo:
            raise RuntimeError('Annotation wrapper lineage is not shared with execution')
        clone.__wrapped__ = memo[wrapped]
    return clone


def _successor(check, candidate):
    leaf = _layers(check)[-1]
    evaluate = _clone(check.evaluate, leaf, candidate.evaluate_for(check.id), {})
    setattr(evaluate, MARK, check.id)
    return replace(check, evaluate=evaluate)


def install():
    """Swap the innermost criterion of each of the five checks for its native-field successor."""
    from . import CHECKS
    from . import k8s_annotation_indicators_review_20261020 as candidate
    selected = {}
    for cid in IDS:
        matches = [c for c in CHECKS if c.id == cid]
        if len(matches) != 1:
            raise RuntimeError('Annotation predecessor absent or duplicated')
        selected[cid] = matches[0]
    updates = {cid: _successor(check, candidate) for cid, check in selected.items()
               if getattr(check.evaluate, MARK, None) is None}
    CHECKS[:] = [updates.get(c.id, c) for c in CHECKS]
    _PREDECESSORS.update({cid: selected[cid] for cid in updates})
