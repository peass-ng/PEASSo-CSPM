"""An API bootstrap failure retains native degradation and incomplete content coverage."""
import json
import socket
from urllib.error import HTTPError

import pytest

from peaso.collectors import k8s
from peaso.snapshot import validate

KIND = 'k8s_selected_literals'


def connector(automatic=True):
    return {'provider': 'k8s', 'scopes': ['*'],
            'auth': {'cluster_id': 'owned-fixture', 'method': 'token',
                     'server': 'https://cluster.invalid', 'token': 'test-only'},
            'options': {'content_secret_scans': automatic,
                        '_content_secret_scan_kinds': [KIND] if automatic else [],
                        'concurrency': 4}}


@pytest.mark.parametrize(('failure', 'expected_status', 'expected_code'), [
    (OSError('private-canary-token'), 'unknown', 'read_failed'),
    (ValueError('private-canary-token'), 'malformed', 'read_failed'),
    (HTTPError('https://sensitive.invalid', 403, 'private-canary-token', {}, None), 'denied', '403'),
])
def test_automatic_content_preserves_bootstrap_failure_without_secondary_attribute_error(
        monkeypatch, failure, expected_status, expected_code):
    factories = []

    def unavailable(auth):
        factories.append(True)
        raise failure

    def network_prohibited(*args, **kwargs):
        pytest.fail('bootstrap regression must not contact a provider')

    monkeypatch.setattr(k8s, '_new_api', unavailable)
    monkeypatch.setattr(socket.socket, 'connect', network_prohibited)
    result = k8s.collect(connector(), requirements=['pod', KIND])
    validate(result)
    assert factories == [True]
    assert result['metadata']['calls'] == 0
    rows = result['collections']
    assert {row['type'] for row in rows} == {
        'pod', KIND, 'deployment', 'daemonset', 'statefulset', 'replicaset',
        'job', 'cronjob', 'replicationcontroller', 'podtemplate',
    }
    assert all(row['status'] == expected_status and row['items'] == [] for row in rows)
    assert all(row['error'] == {'kind': type(failure).__name__, 'code': expected_code} for row in rows)
    coverage = result['metadata']['automatic_workload_environment_coverage'][KIND]
    assert coverage == {'discovered': 0, 'planned': 0, 'inspected': 0, 'targets': [],
                        'complete': False, 'reason': 'source_inventory_unavailable'}
    assert result['metadata']['automatic_workload_environment_batches'] == {KIND: []}
    rendered = json.dumps(result)
    assert 'private-canary-token' not in rendered and 'sensitive.invalid' not in rendered


def test_non_automatic_bootstrap_failure_keeps_existing_metadata_shape(monkeypatch):
    def unavailable(auth):
        raise OSError('startup unavailable')
    monkeypatch.setattr(k8s, '_new_api', unavailable)
    result = k8s.collect(connector(False), requirements=['pod'])
    validate(result)
    assert result['collections'][0]['status'] == 'unknown'
    assert 'automatic_workload_environment_coverage' not in result['metadata']
    assert 'automatic_workload_environment_batches' not in result['metadata']
