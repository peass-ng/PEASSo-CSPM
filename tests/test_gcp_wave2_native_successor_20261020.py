"""Real native current/archived Functions witnesses for the bounded successor."""
from copy import deepcopy
import inspect
import json

import pytest

from peaso.checks import CHECKS
from peaso.checks import gcp_function_secret_partial_page_20261020 as current
from peaso.checks import gcp_function_secret_partial_positive_candidate_20261020 as candidate
from peaso.checks import gcp_function_secret_review_20261019 as predecessor
from peaso.collectors import gcp_function_secret_indicators as legacy
from peaso.collectors import gcp_function_secret_pairs_20261020 as paired

# Reviewed successor bodies outside proposal_boundary, and the whole reviewed outside text.
from tests.gcp_function_partial_positive_native_20261020 import TOKEN, collect_native, index_for, raw
from tests.gcp_wave2_historical_native_20261020 import collect_historical_native


@pytest.mark.parametrize('positive', [True, False])
@pytest.mark.parametrize('partial', [True, False])
def test_same_native_source_preserves_current_positive_and_absence_guards(monkeypatch, positive, partial):
    source = raw({'SETTING': TOKEN if positive else 'production'}, {'BUILD': 'release'})
    old_env, old_receipt, _ = collect_historical_native(monkeypatch, source, unavailable_second=partial)
    new_env, new_receipt, _ = collect_native(monkeypatch, source, unavailable_second=partial)
    old, = old_env['items']
    new, = new_env['items']
    assert old[legacy.MARKER]['schema'] == legacy.SCHEMA
    assert new[paired.MARKER]['schema'] == paired.SCHEMA
    registered, = [c for c in CHECKS if c.id == predecessor.CHECK_ID]
    assert inspect.unwrap(registered.evaluate) is current.evaluate
    expected = 'FAIL' if positive else 'UNKNOWN' if partial else 'PASS'
    assert candidate.evaluate(old, index_for(old, old_env))[0] == expected
    before = deepcopy(new)
    status, evidence = registered.evaluate(new, index_for(new, new_env))
    assert status == expected and new == before
    if partial:
        assert predecessor.evaluate(old, index_for(old, old_env))[0] == 'UNKNOWN'
    else:
        assert predecessor.evaluate(old, index_for(old, old_env))[0] == status
    if positive:
        assert evidence['complete'] is (not partial)
        assert {d['engine'] for leak in evidence['secret_leaks'] for d in leak['detectors']} == (
            {'kingfisher'} if partial else {'kingfisher', 'trufflehog'})
    # 75087001 made the current collector's ``function`` inventory depend on
    # ``cloudfunctions_location`` (the privilege model needs the project's
    # Functions regions): one location listing joins the current capture's
    # list and getIamPolicy reads; the historical capture keeps its two.
    locations = ['GET', 'https://cloudfunctions.googleapis.com/v2/projects/review/locations']
    for receipt, listings in ((old_receipt, 0), (new_receipt, 1)):
        assert receipt['raw_source_unchanged'] and receipt['secret_absent_from_retained_output']
        calls = receipt['http_calls']
        assert receipt['ordinary_inventory_status'] == 'collected' and calls.count(locations) == listings
        assert len([call for call in calls if call != locations]) == 2
    assert TOKEN not in json.dumps([old, new, evidence, old_receipt, new_receipt])
