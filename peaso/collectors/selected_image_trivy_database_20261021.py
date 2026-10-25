"""Trusted Trivy database lease for explicitly selected image CVE reads."""
import subprocess

from peaso.trivy_database_20261021 import DatabaseUnavailable, database_lease


def acquire(stack, *, enabled, cancel, diagnostics=None):
    """Enter one collector-owned lease; return None when DB provisioning fails.

    The caller owns ``stack`` through all offline scans. Neither cache paths nor
    executables come from request options; tests may replace database_lease here.
    """
    if enabled is not True:
        return None
    cancel()
    try:
        kwargs = {} if diagnostics is None else {"diagnostics": diagnostics}
        cache = stack.enter_context(database_lease(enabled=True, **kwargs))
    except (DatabaseUnavailable, OSError, subprocess.SubprocessError):
        return None
    cancel()
    return cache
