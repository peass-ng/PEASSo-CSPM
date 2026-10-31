"""Test helper for copying native CASES while keeping opaque trust witnesses."""
from copy import deepcopy


def snapshot_cases(value):
    """Copy all mutable content while retaining the actual opaque trust witness.

    _Admitted intentionally uses object identity. deepcopy creates an unequal
    witness, so comparing it with a live registry is invalid. Its identity is
    retained; every ordinary nested container is still copied.
    """
    from peaso.azure_function_package_index_20261020 import _Admitted
    memo, seen = {}, set()
    def visit(item):
        if id(item) in seen:
            return
        seen.add(id(item))
        if type(item) is _Admitted:
            memo[id(item)] = item
        elif isinstance(item, dict):
            for key, child in item.items():
                visit(key); visit(child)
        elif isinstance(item, (list, tuple, set, frozenset)):
            for child in item:
                visit(child)
    visit(value)
    return deepcopy(value, memo)
