"""GCP joins retain recorded scope, health, source order and native path rules."""
from collections import defaultdict
import copy
from unittest.mock import patch

import pytest

from tests.synthetic.benchmark_peaso_gcp_lb_workloads import FormerGcpWorkloads, run_stage, synthetic_snapshot
from peaso.analysis import cloud_workload_index as indexed
from peaso.principal_exposure import project
from peaso.snapshot import resources, seal, validate


def outcome(function):
    try:
        return 'value', function()
    except (KeyError, TypeError, AttributeError) as error:
        return 'error', type(error)


@pytest.mark.parametrize('relation', ['gcp_backend_path', 'gcp_running_instance_path'])
@pytest.mark.parametrize('scope', ['projects/a', 'projects/b', None, [], {}])
@pytest.mark.parametrize('path', ['projects/a/instances/one', None, 'absent'])
@pytest.mark.parametrize('malformed', [False, True])
def test_scoped_candidates_match_literal_joins_with_malformed_rows(relation, scope, path, malformed):
    rows = [{'scope': recorded_scope, 'data': {'selfLink': link, 'status': status}}
            for recorded_scope in ('projects/a', 'projects/b', None, [])
            for link in ('https://www.googleapis.com/compute/v1/projects/a/instances/one',
                         'projects/a/instances/one', None, {})
            for status in ('RUNNING', 'TERMINATED')]
    rows.append(rows[0])
    if malformed:
        rows += [{'scope': 'projects/b', 'data': None}, {'data': {'status': 'TERMINATED'}}]
    owner = indexed.CloudWorkloadIndex(defaultdict(list, test=rows))

    def match(source):
        return [r for r in source if r['scope'] == scope
                and (relation == 'gcp_backend_path' or r['data'].get('status') == 'RUNNING')
                and indexed.compute_path(r['data'].get('selfLink')) in {path}]

    assert outcome(lambda: match(owner.candidates('test', relation, [(scope, path)]))) == outcome(lambda: match(rows))


@pytest.mark.parametrize('scenario', ['healthy', 'unhealthy', 'health_denied', 'health_top_level_denied',
    'stopped', 'missing_backend', 'missing_instance', 'protected', 'iap', 'other_scope',
    'duplicate_backend', 'duplicate_backend_reverse', 'partial_link', 'capacity'])
def test_complete_network_and_principal_workflow_equals_former_joins(scenario):
    snapshot = synthetic_snapshot(6)
    facts = {c['type']: c['items'] for c in snapshot['collections']}
    backend = facts['backend_service'][0]
    health = backend['BackendHealth']
    if scenario == 'unhealthy':
        health['groups'][0]['healthStatus'][0]['healthState'] = 'UNHEALTHY'
    elif scenario == 'health_denied':
        health['groups'][0]['collection_status'] = 'denied'
    elif scenario == 'health_top_level_denied':
        # Preserve the native evaluator's group-level completeness predicate.
        health['collection_status'] = 'denied'
    elif scenario == 'stopped':
        facts['instance'][0]['status'] = 'TERMINATED'
    elif scenario == 'missing_backend':
        facts['backend_service'].pop(0)
    elif scenario == 'missing_instance':
        facts['instance'].pop(0)
    elif scenario == 'protected':
        backend['securityPolicy'] = 'projects/benchmark/global/securityPolicies/protected'
    elif scenario == 'iap':
        backend['iap'] = {'enabled': True}
    elif scenario == 'other_scope':
        other_backend = copy.deepcopy(backend)
        other_backend['BackendHealth']['groups'][0]['healthStatus'][0]['healthState'] = 'UNHEALTHY'
        other_instance = copy.deepcopy(facts['instance'][0])
        other_instance['serviceAccounts'] = [{'email': 'foreign@other.iam.gserviceaccount.com'}]
        snapshot['scopes'].append('projects/other')
        snapshot['collections'].extend({'scope': 'projects/other', 'type': kind, 'status': 'collected', 'items': [row]}
            for kind, row in (('backend_service', other_backend), ('instance', other_instance)))
    elif scenario.startswith('duplicate_backend'):
        duplicate = copy.deepcopy(backend)
        duplicate['name'] = 'zz-last-backend'
        duplicate['selfLink'] = duplicate['selfLink'].replace('www.googleapis.com', 'compute.googleapis.com')
        duplicate['BackendHealth']['groups'][0]['source_requests'] = ['last-health-request']
        facts['backend_service'].append(duplicate)
    elif scenario == 'partial_link':
        facts['instance'][0]['selfLink'] = facts['instance'][0]['selfLink'].split('/compute/v1/')[1]
    snapshot = validate(seal(snapshot))
    before, rows = copy.deepcopy(snapshot), resources(snapshot)
    if scenario == 'duplicate_backend_reverse':
        rows.reverse()
    with patch.object(indexed, 'CloudWorkloadIndex', FormerGcpWorkloads):
        expected = run_stage(snapshot, rows)
    with patch.object(indexed, 'MAX_KEYS', 1 if scenario == 'capacity' else indexed.MAX_KEYS):
        actual = run_stage(snapshot, rows)
    assert actual == expected
    assert snapshot == before
    key = 'serviceAccount:web-0@benchmark.iam.gserviceaccount.com'
    if scenario in ('healthy', 'health_top_level_denied', 'iap', 'other_scope', 'duplicate_backend', 'duplicate_backend_reverse', 'capacity'):
        signal = actual['principals'][key]['exposures'][0]
        assert signal['state'] == 'declared'
        assert signal['backend_evidence']['health_state'] == 'HEALTHY'
        if scenario.startswith('duplicate_backend'):
            matching = [r for r in rows if r['type'] == 'backend_service'
                and r['data']['selfLink'].endswith('/global/backendServices/web-0')]
            assert len(matching) == 2
            assert signal['backend_evidence']['source_requests'] == matching[-1]['data']['BackendHealth']['groups'][0]['source_requests']
    else:
        assert key not in actual['principals']
    assert 'serviceAccount:foreign@other.iam.gserviceaccount.com' not in actual['principals']


def test_unrelated_malformed_backend_health_is_not_evaluated():
    snapshot = synthetic_snapshot(3)
    backends = next(c for c in snapshot['collections'] if c['type'] == 'backend_service')
    backends['items'].append({'name': 'unrelated', 'selfLink': 'https://www.googleapis.com/compute/v1/projects/benchmark/global/backendServices/unrelated',
                             'BackendHealth': 'invalid'})
    snapshot = validate(seal(snapshot))
    rows = resources(snapshot)
    with patch.object(indexed, 'CloudWorkloadIndex', FormerGcpWorkloads):
        expected = project(snapshot, rows)
    assert project(snapshot, rows) == expected
    assert len(expected) == 3


def test_whole_privilege_pipeline_preserves_backend_exposure_annotations():
    from peaso.privesc import analyze

    snapshot = synthetic_snapshot(4)
    scope = snapshot['scopes'][0]
    accounts = [{'email': f'web-{i}@benchmark.iam.gserviceaccount.com', 'name': f'projects/benchmark/serviceAccounts/web-{i}'} for i in range(4)]
    policy = {'bindings': [{'role': 'roles/owner', 'members': ['serviceAccount:' + row['email'] for row in accounts]}]}
    snapshot['collections'].extend({'scope': scope, 'type': kind, 'status': 'collected', 'items': items}
                                   for kind, items in (('service_account', accounts), ('iam_policy', [policy])))
    snapshot = validate(seal(snapshot))
    before = copy.deepcopy(snapshot)
    with patch.object(indexed, 'CloudWorkloadIndex', FormerGcpWorkloads):
        expected = analyze(snapshot)
    actual = analyze(snapshot)
    expected['stats'].pop('timing_seconds')
    actual['stats'].pop('timing_seconds')
    assert actual == expected
    assert snapshot == before
    assert actual['graph']['nodes']
    assert any(n.get('exposures') for n in actual['graph']['nodes'])
