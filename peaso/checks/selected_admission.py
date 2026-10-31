"""Register selected-content review checks together with their packaged native cases."""
from copy import deepcopy
import json
from pathlib import Path


def load_cases(name):
    """Return the packaged native fixture cases stored next to this module."""
    return json.loads(Path(__file__).with_name(name).read_text())


def install(provider, declarations, cases, *, severity=None, allow_incomplete_failure=True,
            remediation=None):
    """Register each ``(metadata, evaluate)`` pair once and publish its native cases."""
    from . import CHECKS, register
    from .fixtures import CASES
    for metadata, function in declarations:
        ident = metadata['id']
        if not any(check.id == ident for check in CHECKS):
            hint = remediation(metadata) if remediation else metadata['remediation']
            register(ident, provider, metadata['category'], metadata['kind'], metadata['title'],
                     severity or metadata['severity'], 'security_configuration', hint,
                     dependencies=metadata['dependencies'],
                     allow_incomplete_failure=allow_incomplete_failure)(function)
        if ident in cases:
            CASES[ident] = deepcopy(cases[ident])
