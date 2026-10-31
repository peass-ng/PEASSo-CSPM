"""Historical metadata cannot add runnable aliases or hide unrelated removals."""
import pytest
from peaso.checks import CHECKS
from scripts.peaso_compliance_compile import REVIEWED_NATIVE_ALIASES_20261021
from tests.release_successor_history import registered_before_bulk


def test_historical_alias_projection_keeps_live_registry_unchanged_and_cannot_execute():
    before = tuple(CHECKS)
    historical = registered_before_bulk(CHECKS)
    retired = set(REVIEWED_NATIVE_ALIASES_20261021) - {check.id for check in CHECKS}
    aliases = [check for check in historical if check.id in retired]
    assert aliases and len(aliases) == len(retired)
    for check in aliases:
        with pytest.raises(AssertionError, match='not a runnable current predicate'):
            check.evaluate({}, {})
    assert tuple(CHECKS) == before


def test_historical_projection_rejects_unreviewed_registry_removal():
    historical = registered_before_bulk(CHECKS)
    ident = next(check.id for check in historical if check.id not in REVIEWED_NATIVE_ALIASES_20261021)
    with pytest.raises(AssertionError, match='Unreviewed historical registry removal'):
        registered_before_bulk([check for check in CHECKS if check.id != ident])
