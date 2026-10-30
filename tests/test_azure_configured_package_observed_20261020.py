"""Brief copy follows the captured per-member detector facts, not saved prose."""
from copy import deepcopy
import json
from pathlib import Path
import pytest

from peaso.checks.azure_configured_package_observed_20261020 import observation, CHECK

ROWS = json.loads(Path('tests/fixtures/azure-configured-package-evidence-review-20261020.json').read_text())[CHECK]


@pytest.mark.parametrize('fault', ['provider', 'status', 'coverage', 'credential_validation', 'runtime_bytes', 'detector', 'path', 'global_leak', 'raw_member'])
def test_partial_copy_rejects_contradictory_or_unattributed_hits(fault):
    f = deepcopy(next(f for f in ROWS if f['capture_branch'] == 'partial_positive'))
    assert observation(f) and 'incomplete' in observation(f)
    e = f['evidence']
    if fault == 'provider': f['provider'] = 'gcp'
    elif fault == 'status': f['status'] = 'PASS'
    elif fault == 'coverage': e['coverage'] = 'all_running_files'
    elif fault == 'credential_validation': e['credential_validation'] = 'verified'
    elif fault == 'runtime_bytes': e['runtime_bytes'] = 'verified'
    elif fault == 'detector': e['parts'][-1]['engines'][0]['status'] = 'unavailable'
    elif fault == 'path': e['parts'][-1]['path'] = 'unbound'
    elif fault == 'global_leak': e['secret_leaks'] = []
    else: e['parts'][-1]['source_text'] = 'never-render'
    assert observation(f) is None
