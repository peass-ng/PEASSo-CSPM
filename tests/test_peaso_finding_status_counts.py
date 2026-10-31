"""One mask per identity retains the API's distinct status/group counts."""
import random

import pytest

from tests.synthetic.benchmark_peaso_finding_pages import LiteralStatusCounts
from peaso.finding_status_counts import FindingStatusCounts


def test_all_status_combinations_and_unknown_states_match_original():
    randomizer = random.Random(2783)
    optimized, original = FindingStatusCounts(), LiteralStatusCounts()
    statuses = ['FAIL', 'PASS', 'UNKNOWN', 'MANUAL', 'DENIED', 'NOT_APPLICABLE', 'EMPTY',
        'CUSTOM', '', 'fail', 'UNKNOWN,MANUAL']
    for _ in range(1000):
        status = randomizer.choice(statuses)
        identity = f'id-{randomizer.randrange(75)}'
        optimized.add(status, identity)
        original.add(status, identity)
        assert optimized.result() == original.result()
        assert optimized.total == original.total


def test_group_keys_and_overlapping_statuses_keep_union_semantics():
    optimized, original = FindingStatusCounts(), LiteralStatusCounts()
    identities = [('aws', 'check', ''), ('aws', 'check', 'fingerprint'), ('gcp', 'check', ''), None, 0, False]
    for identity in identities:
        for status in ['UNKNOWN', 'MANUAL', 'EMPTY', 'NOT_APPLICABLE', 'FAIL', 'PASS', 'DENIED', 'CUSTOM']:
            optimized.add(status, identity)
            original.add(status, identity)
            assert optimized.result() == original.result()
            assert optimized.total == original.total


@pytest.mark.parametrize('identity', [[], {}, ['id'], {'id': 'native'}])
def test_unhashable_archived_keys_keep_original_error(identity):
    for counter in (FindingStatusCounts(), LiteralStatusCounts()):
        with pytest.raises(TypeError, match='unhashable type'):
            counter.add('FAIL', identity)
        assert counter.total == 0
        assert all(value == 0 for value in counter.result().values())


def test_result_mutation_and_fresh_requests_do_not_change_other_counts():
    first = FindingStatusCounts()
    first.add('FAIL', 'id')
    changed = first.result()
    changed['FAIL'] = 100
    assert first.result()['FAIL'] == 1
    second = FindingStatusCounts()
    second.add('PASS', 'id')
    assert second.result()['FAIL'] == 0 and second.result()['PASS'] == 1
    assert first.result()['FAIL'] == 1 and first.result()['PASS'] == 0
