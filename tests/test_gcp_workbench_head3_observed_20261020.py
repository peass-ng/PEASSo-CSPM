"""Brief copy consumes actual normal-engine Workbench setting evidence."""
from copy import deepcopy
import json
from pathlib import Path

import pytest

from peaso.checks.gcp_workbench_head3_observed_20261020 import observation


CAPTURE = Path('tests/fixtures/gcp-workbench-head3-brief-native-20261020.json')
SAMPLES = [pytest.param(f, id=r['case'] + '-' + f['check_id'].rsplit('.', 1)[-1])
           for r in json.loads(CAPTURE.read_text())['records'] for f in r['findings']]


@pytest.mark.parametrize('cid', [p.values[0]['check_id'] for p in SAMPLES[:3]])
@pytest.mark.parametrize('fault', ['provider', 'status', 'truth', 'setting', 'instance', 'scope'])
def test_copy_rejects_unbound_or_contradictory_setting_facts(cid, fault):
    f = next(deepcopy(p.values[0]) for p in SAMPLES
             if p.values[0]['check_id'] == cid and p.values[0]['status'] == 'PASS')
    assert observation(f)
    if fault == 'provider':
        f['provider'] = 'azure'
    elif fault == 'status':
        f['status'] = 'FAIL'
    elif fault == 'truth':
        f['evidence']['schedule_declared' if cid.endswith('schedule_declared') else 'disabled'] = 'true'
    elif fault == 'setting':
        f['evidence']['setting'] = 'unrelated.setting'
    elif fault == 'instance':
        f['evidence']['instance'] = 'foreign'
    else:
        f['scope'] = 'projects/other'
    assert observation(f) is None
