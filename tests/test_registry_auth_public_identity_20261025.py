"""Registry credentials must not erase the image association they authorize."""
import json

import pytest

from peaso.auth.secrets import credential_values, redact
from peaso.image_findings import build_report
from peaso.image_findings_storage import safe_observations
from peaso.selected_image_observations_20261021 import metadata_for_report
from test_selected_image_observations_20261021 import case


@pytest.mark.parametrize('kind', ['k8s_selected_registry_image_vulnerabilities',
    'gke_selected_pod_image_vulnerabilities', 'azure_selected_aks_pod_image_vulnerabilities'])
@pytest.mark.parametrize('status', ['FAIL', 'PASS'])
@pytest.mark.parametrize('method', ['basic', 'bearer'])
def test_real_redaction_preserves_selected_image_projection(kind, status, method):
    snapshot, evaluated, _ = case(kind, status)
    credentials = {'host': 'registry.example', 'repository': 'app', 'method': method}
    credentials.update({'username': 'private-user', 'password': 'private-password'}
        if method == 'basic' else {'token': 'private-token'})
    private = ['private-user', 'private-password'] if method == 'basic' else ['private-token']
    auth = {'registry_auth': [credentials], 'token': 'private-cluster-token'}
    snapshot['collections'][0]['items'][0]['literal_runtime_value'] = ' '.join(private + ['private-cluster-token'])
    values = tuple(credential_values(auth))
    assert set(values) == set(private + ['private-cluster-token'])
    public = redact(snapshot, values)
    assert all(secret not in json.dumps(public) for secret in values)
    observations = metadata_for_report(public, evaluated)['observations']
    report = build_report(safe_observations(observations), selected=True)
    assert report['invalid_observations'] == 0
    assert report['invalid_vulnerabilities'] == 0
    assert len(report['rows']) == (1 if status == 'FAIL' else 0)
    assert report['complete'] is True


def test_repeated_flat_auth_documents_do_not_drop_later_credentials():
    entries = [{'host': 'registry.example', 'repository': 'app', 'method': 'bearer',
                'token': 'private-token-' + str(i)} for i in range(64)]
    assert set(credential_values({'registry_auth': entries})) == {e['token'] for e in entries}


@pytest.mark.parametrize('change', [
    {'method': 'unknown'}, {'method': []}, {'extra': 'other-private'},
    {'host': 'https://registry.example'}, {'repository': '../app'},
    {'repository': 'app//part'}, {'token': ['nested-private']},
])
def test_unknown_registry_documents_keep_conservative_extraction(change):
    entry = {'host': 'registry.example', 'repository': 'app', 'method': 'bearer', 'token': 'private-token'}
    entry.update(change)
    values = tuple(credential_values({'registry_auth': [entry]}))
    assert entry['host'] in values and entry['repository'] in values
    assert ('nested-private' if isinstance(entry['token'], list) else entry['token']) in values


def test_public_identity_equal_to_actual_password_is_still_redacted():
    entry = {'host': 'registry.example', 'repository': 'app', 'method': 'basic',
             'username': 'private-user', 'password': 'registry.example'}
    public = redact({'image': 'registry.example/app@sha256:' + 'a' * 64},
                    tuple(credential_values({'registry_auth': [entry]})))
    assert 'registry.example' not in public['image']


def test_registry_documents_keep_original_structure_bound():
    entries = [{'host': 'registry.example', 'repository': 'app', 'method': 'bearer',
                'token': 'private-token-' + str(i)} for i in range(20_001)]
    with pytest.raises(ValueError, match='structure exceeds limits'):
        list(credential_values({'registry_auth': entries}))


def test_registry_cycles_remain_bounded():
    entries = []
    entries.append(entries)
    assert list(credential_values({'registry_auth': entries})) == []
