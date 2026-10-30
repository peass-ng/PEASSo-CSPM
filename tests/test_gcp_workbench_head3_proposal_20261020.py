"""Native proposal predicates, scalar projection and ordinary fakeHTTP path.

No registration or upstream/cloud code execution. Collector schedule acceptance
is a separate node until its owner installs the explicit successor patch.
"""
from copy import deepcopy
import inspect
import json
from pathlib import Path

import pytest

from peaso.checks import gcp_workbench_head3_proposal_20261020 as candidate
from peaso.collectors import gcp_workbench_head3_projection_20261020 as projection
from peaso.collectors.gcp import GCPCollector, ReadError
from peaso.engine import _index
from peaso.snapshot import resources

CASES_PATH = Path('peaso/checks/gcp_workbench_head3_native_cases_20261020.json')
CASES = json.loads(CASES_PATH.read_text())['cases']
SCOPE = 'projects/review'
NAME = SCOPE + '/locations/us-central1-a/instances/notebook'
URL = 'https://notebooks.googleapis.com/v2/' + SCOPE + '/locations/-/instances'


@pytest.mark.parametrize('case', CASES, ids=lambda case: case['id'])
def test_actual_native_predicate(case):
    item, index = deepcopy(case['item']), deepcopy(case['index'])
    before = deepcopy((item, index))
    status, evidence = candidate.EVALUATORS[case['check_id']](item, index)
    assert status == case['expected'], (case['id'], status, evidence)
    assert (item, index) == before
    assert 'observed' in evidence and len(evidence['observed'].split('. ')) <= 3
    if status in ('PASS', 'FAIL'):
        assert evidence['instance'] == NAME
        assert '00 19' not in json.dumps(evidence)


@pytest.mark.parametrize('value', [
    '', '00 19 * * MON', '0 0 1 * *', '59 23 31 12 7', '0 0 * JAN-MAR MON,FRI',
    '*/15 0-23/2 1,15 * 0-6', '0 0 * jan-mar mon-fri', '0 0 * * SUN',
])
def test_supported_cron_subset(value):
    assert projection.supported_schedule(value) == value
    scrubbed = {'preserved': None, projection.KEY: None}
    actual = projection.project_upgrade_schedule({projection.KEY: value}, scrubbed)
    assert actual[projection.KEY] == value and scrubbed[projection.KEY] is None


@pytest.mark.parametrize('value', [
    None, True, 7, [], {}, ' ', '\t', '0 0 * * *\n', '@weekly', '0 0 * * * command',
    '60 0 * * *', '0 24 * * *', '0 0 0 * *', '0 0 32 * *', '0 0 * 0 *',
    '0 0 * 13 *', '0 0 * * 8', '*/0 * * * *', '0-59/61 * * * *',
    '5-1 * * * *', '0 0 * * FRI-MON', '0 0 * FOO MON', '0 0 * * MONDAY',
    '0 0 * * 1/2', '0,,1 0 * * *', '0/2 0 * * *', '0 0 * * * #secret',
    '0 0 * * *;echo untrusted', 'CRON_TZ=UTC 0 0 * * *', '0 0 * * ?','0 0 L * *',
    '0 0 * * 1#2', '0 0 * * ~', '0 0 * * МON', '0 0 * * MON' + ' ' * 129,
])
def test_unsupported_schedule_is_masked_with_unknown_coverage(value):
    assert projection.supported_schedule(value) is None
    output = projection.project_upgrade_schedule({projection.KEY: value}, {'other': None})
    assert projection.KEY in output and output[projection.KEY] is None
    assert output['_coverage'][projection.KEY]['status'] == 'unknown'
    assert 'untrusted' not in json.dumps(output) and 'secret' not in json.dumps(output)


@pytest.mark.parametrize('marker', [None, 'collected', {}, {'status': 'denied'},
                                  {'status': 'partial'}, {'status': 'empty'}])
def test_projection_does_not_upgrade_unavailable_native_coverage(marker):
    raw = {projection.KEY: '00 19 * * MON', '_coverage': {projection.KEY: marker}}
    output = projection.project_upgrade_schedule(raw, {projection.KEY: None, '_coverage': deepcopy(raw['_coverage'])})
    assert output[projection.KEY] is None
    assert output['_coverage'][projection.KEY]['status'] == 'unknown'


def test_projection_keeps_absence_and_explicit_empty_distinct_from_invalid():
    assert projection.project_upgrade_schedule({}, {}) == {}
    assert projection.project_upgrade_schedule({projection.KEY: ''}, {}) == {projection.KEY: ''}
    assert projection.project_upgrade_schedule({projection.KEY: 'anything'}, {})[projection.KEY] is None


class NativeHTTP:
    def __init__(self, row, mode='collected'):
        self.row = row
        self.mode = mode
        self.calls = []

    def request(self, method, url, **kwargs):
        self.calls.append((method, url, kwargs))
        if url == 'https://notebooks.googleapis.com/v2/' + self.row['name'] + ':getIamPolicy':
            # 75087001 hydrates each listed instance's IAM policy.
            assert method == 'GET' and kwargs['params'] == {'options.requestedPolicyVersion': 3}
            return {'bindings': []}, 'wb-iam-1'
        assert method == 'GET' and url == URL
        if self.mode == 'denied':
            error = ReadError('denied', 'api_error', http_status=403)
            error.request_id = 'wb-read-1'
            raise error
        response = {'instances': [deepcopy(self.row)]}
        if self.mode == 'unreachable':
            response['unreachable'] = ['projects/review/locations/us-west1-a']
        return response, 'wb-read-1'


def ordinary_capture(metadata, *, mode='collected', state='ACTIVE', name=NAME):
    transport = NativeHTTP({'name': name, 'state': state, 'gceSetup': {'metadata': metadata}}, mode)
    connector = {'provider': 'gcp', 'scopes': [SCOPE], 'options': {
        'inventories': ['workbench_instance'], 'include_inherited': False,
        'concurrency': 1, 'metrics_scopes': False}}
    snapshot = GCPCollector(connector, requirements=['workbench_instance'], transport=transport).collect()
    iam = 'https://notebooks.googleapis.com/v2/' + name + ':getIamPolicy'
    assert [call[1] for call in transport.calls] == [URL] + ([iam] if mode != 'denied' else [])
    index = _index(snapshot, resources(snapshot))
    index['context'] = {'provider': 'gcp', 'scope': SCOPE}
    collection, = [c for c in snapshot['collections'] if c['type'] == 'workbench_instance']
    item = collection['items'][0] if collection['items'] else {}
    return item, index, snapshot


@pytest.mark.parametrize('suffix,key', [
    ('terminal_access_disabled', 'notebook-disable-terminal'),
    ('file_download_disabled', 'notebook-disable-downloads'),
])
@pytest.mark.parametrize('value,expected', [('true', 'PASS'), ('false', 'FAIL'), (None, 'UNKNOWN'), (True, 'UNKNOWN')])
def test_actual_ordinary_boolean_projection(suffix, key, value, expected):
    item, index, snapshot = ordinary_capture({key: value})
    assert candidate.EVALUATORS[candidate.PREFIX + suffix](item, index)[0] == expected
    assert item['_provenance']['representation'] == 'full'


@pytest.mark.parametrize('mode', ['denied', 'unreachable'])
@pytest.mark.parametrize('suffix', ['terminal_access_disabled', 'file_download_disabled', 'auto_upgrade_schedule_declared'])
def test_actual_ordinary_incomplete_reads_are_unknown(mode, suffix):
    item, index, snapshot = ordinary_capture({'notebook-disable-terminal': 'true',
        'notebook-disable-downloads': 'true', projection.KEY: '00 19 * * MON'}, mode=mode)
    assert candidate.EVALUATORS[candidate.PREFIX + suffix](item, index)[0] == 'UNKNOWN'


@pytest.mark.parametrize('value,expected', [('00 19 * * MON', 'PASS'), ('', 'FAIL'),
                                         ('arbitrary-private-text', 'UNKNOWN'), (None, 'UNKNOWN')])
def test_actual_ordinary_schedule_after_owner_patch(value, expected):
    """Separate admission node: must stay red until the owner installs its patch."""
    item, index, snapshot = ordinary_capture({projection.KEY: value})
    actual, evidence = candidate.auto_upgrade_schedule_declared(item, index)
    assert actual == expected, (actual, expected, evidence)
    if expected == 'UNKNOWN':
        assert item['gceSetup']['metadata']['_coverage'][projection.KEY]['status'] == 'unknown'


def test_declarations_match_admitted_successor_and_proposal_stays_unregistered():
    from peaso.checks import CHECKS
    declarations = json.loads(Path('peaso/checks/gcp_workbench_head3_declarations_20261020.json').read_text())['declarations']
    assert {row['id'] for row in declarations} == candidate.EVALUATORS.keys()
    assert all(row['kind'] == 'workbench_instance' and len(row['remediation']) == 2 for row in declarations)
    assert [row['severity'] for row in declarations] == ['medium', 'medium', 'low']
    # The pure proposal never registers itself. Its separately reviewed native
    # successor now owns these exact IDs in the ordinary runtime registry.
    from peaso.checks import gcp_workbench_head3_admission_20261020 as admission
    current = {check.id: check for check in CHECKS}
    assert candidate.EVALUATORS.keys() == admission.EVALUATORS.keys()
    for cid, evaluator in admission.EVALUATORS.items():
        assert inspect.unwrap(current[cid].evaluate) is evaluator
        assert current[cid].kind == 'workbench_instance'
        assert current[cid].dependencies == ['workbench_instance']
    assert 'register(' not in inspect.getsource(candidate)
