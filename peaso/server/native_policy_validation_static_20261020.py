"""API-only native review roster without executing the checks package.

The roster is read from the same manifest file that the native registrar
consumes. There is no native import fallback.
"""
from functools import lru_cache
import json
from pathlib import Path
from types import MappingProxyType
from typing import Mapping

MANIFEST_PATH = Path(__file__).resolve().parents[1] / 'checks' / 'bulk_pending.json'
MAX_MANIFEST_BYTES = 256 * 1024


def _pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            raise ValueError('duplicate native review manifest key')
        result[key] = value
    return result


@lru_cache(maxsize=1)
def module_ids() -> Mapping[str, frozenset[str]]:
    """Read package data by path: importing its package would install all checks."""
    try:
        with MANIFEST_PATH.open('rb') as stream:
            raw = stream.read(MAX_MANIFEST_BYTES + 1)
        if len(raw) > MAX_MANIFEST_BYTES:
            raise ValueError('native review manifest budget')
        manifest = json.loads(raw, object_pairs_hook=_pairs)
        if (type(manifest) is not dict or manifest.get('schema_version') != 1
                or type(manifest.get('checks')) is not dict
                or type(manifest.get('modules')) is not dict):
            raise ValueError('native review manifest schema differs')
        roster: dict[str, set[str]] = {name: set() for name in manifest['modules']}
        for cid, contract in manifest['checks'].items():
            if (type(cid) is not str or not cid or type(contract) is not dict
                    or type(contract.get('source_module')) is not str
                    or contract['source_module'] not in roster):
                raise ValueError('native review manifest contract differs')
            roster[contract['source_module']].add(cid)
        return MappingProxyType({name: frozenset(ids) for name, ids in roster.items()})
    except (OSError, UnicodeError, TypeError, KeyError) as error:
        raise ValueError('native review manifest unavailable') from error


def check_review_map(value, module, *, individually_scoped=False):
    # Keep the predecessor's validation order, bounds, scope rules and errors.
    from .native_policy_validation import bounded, _scoped
    bounded(value)
    allowed = module_ids().get(module, frozenset())
    if set(value) - allowed or any(not isinstance(entry, dict) for entry in value.values()):
        raise ValueError('unsupported native check review identity')
    if individually_scoped:
        for review in value.values():
            _scoped(review, set(review), r'/(?:subscriptions/[A-Za-z0-9._-]{1,128}|tenants/[0-9a-fA-F-]{36})')


def install():
    """Rebind the API process only; preserve the pinned predecessor on disk."""
    from . import native_policy_validation
    native_policy_validation._check_review_map = check_review_map
