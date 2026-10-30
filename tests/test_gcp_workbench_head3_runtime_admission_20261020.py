"""Focused real registry/normal-engine Workbench admission and fault proof."""
from copy import deepcopy
import json
import re

import pytest

import peaso.checks as registry
from peaso.checks import fixtures
from peaso.checks import gcp_workbench_head3_admission_20261020 as admission
from peaso.collectors import gcp
from peaso.collectors import gcp_workbench_head3_projection_20261020 as projection
from peaso.engine import evaluate_snapshot
from peaso.engine import evaluate_snapshot, plan_collection
from peaso.checks import CHECKS

IDS = admission.CHECK_IDS
SCOPE = 'projects/review'
NAME = SCOPE + '/locations/us-central1-a/instances/notebook'
KEYS = dict(zip(IDS, ('notebook-disable-terminal', 'notebook-disable-downloads', projection.KEY)))


@pytest.fixture(scope='module', autouse=True)
def actual_transactional_bundle():
    # The same real transactional installer is exercised before the shared
    # init hook lands; a separate fresh-process node proves that actual hook.
    admission.install_bundle()


class NativeHTTP:
    def __init__(self, rows, *, denied=False, unreachable=False):
        self.rows, self.denied, self.unreachable = rows, denied, unreachable
        self.calls = []

    def request(self, method, url, **kwargs):
        self.calls.append((method, url))
        policy = re.fullmatch(r'https://notebooks.googleapis.com/v2/(projects/[^/]+)/locations/[^/]+/instances/[^/]+:getIamPolicy', url)
        if policy:
            assert method == 'GET' and policy[1] in self.rows
            return {'bindings': [], 'version': 3}, 'wb-policy-' + policy[1].split('/')[1]
        match = re.fullmatch(r'https://notebooks.googleapis.com/v2/(projects/[^/]+)/locations/-/instances', url)
        assert method == 'GET' and match and match[1] in self.rows
        if self.denied:
            error = gcp.ReadError('denied', 'api_error', http_status=403)
            error.request_id = 'wb-' + match[1].split('/')[1]
            raise error
        result = {'instances': deepcopy(self.rows[match[1]])}
        if self.unreachable:
            result['unreachable'] = [match[1] + '/locations/us-west1-a']
        return result, 'wb-' + match[1].split('/')[1]


def row(name=NAME, *, state='ACTIVE', metadata=None):
    if metadata is None:
        metadata = {KEYS[IDS[0]]: 'true', KEYS[IDS[1]]: 'true', KEYS[IDS[2]]: '00 19 * * MON'}
    return {'name': name, 'state': state, 'gceSetup': {'metadata': metadata}}


def collect(rows, **transport_options):
    transport = NativeHTTP(rows, **transport_options)
    connector = {'provider': 'gcp', 'scopes': list(rows), 'options': {
        'inventories': ['workbench_instance'], 'include_inherited': False,
        'metrics_scopes': False, 'concurrency': 1}}
    snapshot = gcp.GCPCollector(connector, requirements=['workbench_instance'], transport=transport).collect()
    assert sum(url.endswith('/instances') for _, url in transport.calls) == len(rows)
    return snapshot, transport


def findings(snapshot, ids=IDS):
    result = evaluate_snapshot(snapshot, checks=list(ids))
    assert {finding['check_id'] for finding in result['findings']} == set(ids)
    return result['findings']


@pytest.mark.parametrize('cid', IDS)
@pytest.mark.parametrize('case,expected', [
    ('pass', 'PASS'), ('fail', 'FAIL'), ('redacted', 'UNKNOWN'),
    ('malformed', 'UNKNOWN'), ('unsupported', 'UNKNOWN'), ('omitted', 'FAIL'),
    ('deleted', 'NOT_APPLICABLE'), ('cross_project', 'UNKNOWN'),
    ('unrecognized_state', 'UNKNOWN'), ('denied_leaf', 'UNKNOWN'),
])
def test_normal_engine_native_row(cid, case, expected):
    native = row()
    key = KEYS[cid]
    if case == 'fail':
        native['gceSetup']['metadata'][key] = '' if key == projection.KEY else 'false'
    elif case == 'redacted':
        native['gceSetup']['metadata'][key] = None
    elif case == 'malformed':
        native['gceSetup']['metadata'][key] = True
    elif case == 'unsupported':
        native['gceSetup']['metadata'][key] = 'unsupported-expression'
    elif case == 'omitted':
        native['gceSetup']['metadata'].pop(key)
    elif case == 'deleted':
        native['state'] = 'DELETED'
    elif case == 'cross_project':
        native['name'] = NAME.replace('/review/', '/other/')
    elif case == 'unrecognized_state':
        native['state'] = 'FUTURE_STATE'
    elif case == 'denied_leaf':
        native['gceSetup']['metadata']['_coverage'] = {key: {'status': 'denied'}}
    snapshot, transport = collect({SCOPE: [native]})
    output = findings(snapshot, [cid])
    assert {finding['status'] for finding in output} == {expected}, output
    assert sum(url.endswith('/instances') for _, url in transport.calls) == 1
    assert 'unsupported-expression' not in json.dumps([f['evidence'] for f in output])


@pytest.mark.parametrize('option', ['denied', 'unreachable'])
def test_unavailable_native_reads_never_become_clean_findings(option):
    snapshot, _ = collect({SCOPE: [row()]}, **{option: True})
    output = findings(snapshot)
    # Normal engine retains its existing explicit DENIED inventory status.
    assert {finding['status'] for finding in output} <= {'UNKNOWN', 'DENIED'}


def test_multi_asset_multi_project_and_saved_json_replay_use_only_existing_list(tmp_path):
    rows = {}
    for scope in ('projects/alpha1', 'projects/bravo1'):
        good = row(scope + '/locations/us-central1-a/instances/good')
        bad = row(scope + '/locations/us-central1-a/instances/bad', metadata={
            KEYS[IDS[0]]: 'false', KEYS[IDS[1]]: 'false', KEYS[IDS[2]]: ''})
        rows[scope] = [good, bad]
    snapshot, transport = collect(rows)
    original = findings(snapshot)
    assert len(original) == 12
    assert sum(f['status'] == 'PASS' for f in original) == 6
    assert sum(f['status'] == 'FAIL' for f in original) == 6
    path = tmp_path / 'saved-native.json'
    path.write_text(json.dumps(snapshot))
    replay = findings(json.loads(path.read_text()))
    assert replay == original
    assert sum(url.endswith('/instances') for _, url in transport.calls) == 2


@pytest.mark.parametrize('mode', ['registry_append', 'cases_write'])
def test_real_transaction_rolls_back_after_partial_registry_or_cases_failure(monkeypatch, mode):
    """Faults act on copied mutable registries using the actual register code."""
    baseline = [check for check in registry.CHECKS if check.id not in IDS]
    base_cases = {cid: value for cid, value in fixtures.CASES.items() if cid not in IDS}

    class FailingChecks(list):
        def append(self, value):
            super().append(value)
            if value.id == IDS[1] and mode == 'registry_append':
                raise OSError('injected registry append failure')

    class FailingCases(dict):
        def __setitem__(self, key, value):
            super().__setitem__(key, value)
            if key == IDS[1] and mode == 'cases_write':
                raise OSError('injected CASES write failure')

    copied_checks, copied_cases = FailingChecks(baseline), FailingCases(base_cases)
    monkeypatch.setattr(registry, 'CHECKS', copied_checks)
    monkeypatch.setattr(fixtures, 'CASES', copied_cases)
    with pytest.raises(OSError):
        admission.install_bundle()
    assert len(copied_checks) == len(baseline)
    assert all(left is right for left, right in zip(copied_checks, baseline))
    assert copied_cases.keys() == base_cases.keys()
    assert all(copied_cases[cid] is value for cid, value in base_cases.items())


@pytest.mark.parametrize('status', ['PASS', 'FAIL', 'UNKNOWN'])
def test_coherent_init_normal_snapshot(status):
    assert sum(check.id in IDS for check in registry.CHECKS) == 3
    metadata = {
        KEYS[IDS[0]]: 'true' if status == 'PASS' else 'false' if status == 'FAIL' else None,
        KEYS[IDS[1]]: 'true' if status == 'PASS' else 'false' if status == 'FAIL' else None,
        KEYS[IDS[2]]: '00 19 * * MON' if status == 'PASS' else '' if status == 'FAIL' else None,
    }
    rows = [row(metadata=metadata)]
    if status == 'PASS':
        rows.append(row(NAME + '-deleted', state='DELETED'))
    snapshot, transport = collect({SCOPE: rows})
    output = findings(snapshot)
    assert sum(finding['status'] == status for finding in output) == 3
    assert sum(finding['status'] == 'NOT_APPLICABLE' for finding in output) == (3 if status == 'PASS' else 0)
    assert sum(url.endswith('/instances') for _, url in transport.calls) == 1
