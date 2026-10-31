"""Historical local runtime and its current admitted native successor."""

import pytest

from tests import test_azure_function_package_source_20261020 as native


@pytest.fixture(autouse=True)
def offline(monkeypatch):
    yield from native.offline.__wrapped__(monkeypatch)


@pytest.mark.parametrize('hit,partial,status', [(False, False, 'PASS'), (True, False, 'FAIL'),
    (False, True, 'UNKNOWN'), (True, True, 'FAIL')])
def test_current_admitted_native_both_scanners_same_evidence(monkeypatch, hit, partial, status):
    from tests import test_azure_function_package_integrated_20261020 as current
    current.test_actual_engine_native_and_both_detectors(monkeypatch, hit, partial, status)


@pytest.mark.parametrize('operation', native.source.OPERATIONS)
def test_current_admitted_native_denied_is_unknown(monkeypatch, operation):
    from tests import test_azure_function_package_integrated_20261020 as current
    current.test_actual_engine_denied_native_is_unknown(monkeypatch, operation)


def test_current_admitted_saved_positive_negative_and_unknown():
    from peaso.checks import azure_function_package_integration_admission_20261020 as admission
    from peaso.checks import azure_function_package_integrated_consumer_20261020 as consumer
    from peaso.checks import CHECKS
    cases = admission.native_cases()
    registered, = [check for check in CHECKS if check.id == consumer.DECLARATION['id']]
    statuses = set()
    for case in cases:
        item, index = admission.native_case(case)
        status, evidence = registered.evaluate(item, index)
        assert status == case['expected_status']
        statuses.add(status)
    assert {'PASS', 'FAIL', 'UNKNOWN'} <= statuses
