"""Shared helper: follow wrapped check callables to their bound functions."""
import inspect


def _bound_functions(value, seen=None):
    """Follow actual wrappers/closed dispatch maps without executing a predicate."""
    seen = set() if seen is None else seen
    if inspect.isfunction(value):
        value = inspect.unwrap(value)
    if id(value) in seen:
        return
    seen.add(id(value))
    if inspect.isfunction(value):
        yield value
        for part in (*(value.__defaults__ or ()), *(value.__kwdefaults__ or {}).values()):
            yield from _bound_functions(part, seen)
        for cell in value.__closure__ or ():
            try:
                part = cell.cell_contents
            except ValueError:
                continue
            yield from _bound_functions(part, seen)
    elif isinstance(value, dict):
        for part in value.values():
            yield from _bound_functions(part, seen)
    elif isinstance(value, (list, tuple)):
        for part in value:
            yield from _bound_functions(part, seen)
