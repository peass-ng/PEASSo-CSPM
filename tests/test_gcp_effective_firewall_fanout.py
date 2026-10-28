"""Regional firewall reads overlap without changing serial evidence/error order."""
import copy
import threading
import time


from peaso.collectors import gcp

SCOPE = 'projects/p-one'
NETWORK = 'https://www.googleapis.com/compute/v1/' + SCOPE + '/global/networks/default'


def execute(*, workers, failure=None, cap=None, delay=0.015):
    class Transport:
        def __init__(self):
            self.lock = threading.Lock()
            self.active = self.peak = 0
            self.seen = []
        def request(self, method, url, **kwargs):
            region = url.split('/regions/')[1].split('/')[0]
            with self.lock:
                self.active += 1
                self.peak = max(self.peak, self.active)
                self.seen.append(region)
            try:
                time.sleep(delay)
                if region == failure:
                    error = gcp.ReadError('denied', '403', http_status=403)
                    error.request_id = region
                    raise error
                return {'firewalls': [], 'firewallPolicys': [{'name': region}]}, region
            finally:
                with self.lock:
                    self.active -= 1
    transport = Transport()
    options = {'concurrency': workers, 'compute_resource_iam': False}
    if cap is not None:
        options['max_resources'] = cap
    collector = gcp.GCPCollector({'provider': 'gcp', 'scopes': [SCOPE], 'options': options},
                                  ['effective_firewall'], transport=transport)
    collector.read_time = '2026-10-28T00:00:00Z'
    collector.collections[('network', SCOPE)] = {'status': 'collected', 'items': [{'selfLink': NETWORK}]}
    collector.collections[('subnetwork', SCOPE)] = {'status': 'collected', 'items': [
        {'selfLink': 'https://www.googleapis.com/compute/v1/' + SCOPE + '/regions/r' + str(i) + '/subnetworks/s',
         'network': NETWORK} for i in range(8)]}
    try:
        run_jobs = collector.run_jobs
        collector.run_jobs = lambda jobs: run_jobs([job for job in jobs if job[0] == 'effective_firewall'])
        collector.dependent_jobs()
        return copy.deepcopy(collector.collections[('effective_firewall', SCOPE)]), transport
    finally:
        collector.hydration_pool.shutdown()
        if collector.location_pool is not None:
            collector.location_pool.shutdown()


def test_full_inventory_overlaps_but_preserves_every_serial_fact():
    before, _ = execute(workers=1)
    after, transport = execute(workers=4)
    assert after == before
    assert len(after['items']) == 8
    assert 1 < transport.peak <= 8
    assert sorted(transport.seen) == ['r' + str(i) for i in range(8)]


def test_first_failure_keeps_the_same_serial_prefix_and_status():
    before, _ = execute(workers=1, failure='r3')
    after, _ = execute(workers=4, failure='r3')
    assert after == before
    assert after['status'] == 'partial'
    assert len(after['items']) == 3


def test_explicit_resource_cap_keeps_serial_reads():
    _, transport = execute(workers=4, cap=3)
    assert transport.peak == 1
