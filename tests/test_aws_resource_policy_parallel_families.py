"""Resource-policy families run concurrently yet merge exactly as the serial loop."""
import threading
import time

import pytest

from peaso.collectors import aws
from peaso.collectors import aws_resource_policy_families as families
from tests.test_aws_resource_policy_coverage import ACCOUNT, REGION, SESSION, Requests as ShapeRequests


class Requests(ShapeRequests):
    """SDK-shaped fake with the concurrency surface used by ``run_all``."""

    def __init__(self, workers, *, denied=(), broken=()):
        super().__init__()
        self.workers, self.max_calls = workers, None
        self._lock = threading.RLock()
        self.denied, self.broken = set(denied), set(broken)
        self.active = self.peak = 0

    def _enter(self, service):
        with self._lock:
            self.active += 1
            self.peak = max(self.peak, self.active)
        time.sleep(0.002)
        with self._lock:
            self.active -= 1
        if service in self.broken:
            raise RuntimeError('provider adapter failed')

    def pages(self, session, service, region, operation, path, **parameters):
        self._enter(service)
        if service in self.denied:
            with self._lock:
                self.calls.append((service, region, operation, parameters))
            return aws.ReadResult([], 'denied', {'code': 'AccessDeniedException'})
        with self._lock:
            return super().pages(session, service, region, operation, path, **parameters)

    def detail(self, session, service, region, operation, absent=(), **parameters):
        self._enter(service)
        with self._lock:
            return super().detail(session, service, region, operation, absent=absent, **parameters)


def _read(requests):
    read = families.collect(requests, SESSION, REGION, ACCOUNT)
    return read.items, read.status, read.error


def test_concurrent_families_merge_in_recipe_order():
    serial, parallel = Requests(1, denied={'kms', 'efs'}), Requests(8, denied={'kms', 'efs'})
    expected, observed = _read(serial), _read(parallel)
    assert serial.peak == 1 and parallel.peak > 1
    assert observed == expected
    assert expected[1] == 'partial'
    # Failures keep recipe order, so the first failure stays the first one read.
    assert [f['family'] for f in observed[2]['families']] == [f['family'] for f in expected[2]['families']]
    assert sorted(serial.calls, key=repr) == sorted(parallel.calls, key=repr)


def test_merged_rows_keep_family_order_for_a_shared_resource():
    shared = 'arn:aws:fixture:%s:%s:resource/shared' % (REGION, ACCOUNT)
    first = families.Recipe('first', 'logs', (families.step('describe_resource_policies', 'resourcePolicies'),),
                            None, {}, '$policyDocument', shared)
    second = families.Recipe('second', 'xray', (families.step('list_resource_policies', 'ResourcePolicies'),),
                             None, {}, '$PolicyDocument', shared)
    rows = [families.collect(Requests(workers), SESSION, REGION, ACCOUNT, [first, second]).items for workers in (1, 8)]
    assert rows[0] == rows[1]
    assert rows[1][0]['_provenance']['families'] == ['first', 'second']
    assert rows[1][0]['_provenance']['source_operations'] == ['logs:describe_resource_policies', 'xray:list_resource_policies']


def test_an_unexpected_failure_still_propagates():
    with pytest.raises(RuntimeError):
        families.collect(Requests(8, broken={'secretsmanager'}), SESSION, REGION, ACCOUNT)
