"""Forkserver preload for a long-lived worker: import and prove the engine once.

Only the forkserver of ``Worker.run`` imports this module, before it serves any
job. Every job child is then forked from a process that already ran the
pinned-source proof of ``peaso.checks`` over the same immutable bytes, so the
child skips the import instead of repeating it. The forkserver never receives
a request, credential or snapshot, so a forked child starts from the same
job-free state a freshly spawned interpreter would.

A failed import or proof must not leave half-proven state to inherit: every
``peaso`` submodule and the compile/parse caches are dropped again, so each child
imports ``peaso.checks`` itself and fails closed exactly as a spawned child.
"""
import ast
import builtins
import gc
import sys


def _forget_peaso():
    cache = sys.modules.get("peaso.compile_cache")
    if cache is not None:
        builtins.compile = cache._ORIGINAL_COMPILE
        ast.parse = cache._ORIGINAL_PARSE
    for name in [name for name in sys.modules if name.startswith("peaso.") and name != __name__]:
        del sys.modules[name]


def warm():
    try:
        import peaso.checks  # noqa: F401
        import peaso.engine  # noqa: F401
        import peaso.worker  # noqa: F401
    except Exception:  # noqa: BLE001 - each child re-imports and reports the failure
        _forget_peaso()
        return False
    # Keep the imported objects out of the collector so forked children do not
    # copy every page the cyclic GC would otherwise touch.
    gc.freeze()
    return True


WARM = warm()
