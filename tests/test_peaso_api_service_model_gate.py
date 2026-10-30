"""Focused build-only SDK model closure checks for the reviewed source epoch."""
from pathlib import Path
import shutil

import pytest

from scripts import peaso_api_service_model_gate as gate


ROOT = Path(__file__).resolve().parents[1]


def test_reviewed_source_and_literal_api_clients():
    files = gate.reviewed_python(ROOT)
    calls = gate.direct_clients(ROOT)
    assert len(files) == gate.REVIEWED_PYTHON_COUNT
    assert len(calls) == 29
    assert {service for _, _, service in calls} <= gate.API_SERVICES
    assert gate.review_source(ROOT)['source_diff'] == {'added': [], 'removed': [], 'changed': []}




@pytest.mark.parametrize('call,reason', [
    ('session.client(service_name)', 'dynamic API SDK client'),
    ('session.client("sagemaker")', 'unlisted API SDK service'),
])
def test_dynamic_and_unlisted_clients_fail_closed(tmp_path, monkeypatch, call, reason):
    server = tmp_path / 'peaso' / 'server'
    collector = tmp_path / 'peaso' / 'collectors'
    server.mkdir(parents=True)
    collector.mkdir(parents=True)
    (collector / 'aws.py').write_text('def _session(auth, region):\n    return None\n')
    (server / 'app.py').write_text(f'def route(session, service_name):\n    return {call}\n')
    monkeypatch.setattr(gate, 'API_SOURCE_DIRECTORIES', ('peaso/server',))
    monkeypatch.setattr(gate, 'API_SOURCE_FILES', ())
    with pytest.raises(RuntimeError, match=reason):
        gate.direct_clients(tmp_path)


def _fake_models(tmp_path):
    (tmp_path / f'botocore-{gate.REQUIRED_BOTOCORE_VERSION}.dist-info').mkdir()
    (tmp_path / f'botocore-{gate.REQUIRED_BOTOCORE_VERSION}.dist-info' / 'METADATA').write_text(
        f'Name: botocore\nVersion: {gate.REQUIRED_BOTOCORE_VERSION}\n')
    data = tmp_path / 'botocore' / 'data'
    data.mkdir(parents=True)
    (data / 'endpoints.json').write_text('shared endpoint data')
    for service in gate.API_SERVICES:
        model = data / service / '2000-01-01'
        model.mkdir(parents=True)
        (model / 'service-2.json.gz').write_bytes(b'retained model')
    return data


def test_missing_retained_model_fails_without_deletion(tmp_path, monkeypatch):
    data = _fake_models(tmp_path)
    shutil.rmtree(data / 'sts')
    extra = data / 'unlisted' / '2000-01-01'
    extra.mkdir(parents=True)
    (extra / 'service-2.json.gz').write_bytes(b'other model')
    monkeypatch.setattr(gate, 'reviewed_python', lambda root: {})
    monkeypatch.setattr(gate, 'direct_clients', lambda root: [])
    with pytest.raises(RuntimeError, match='model tree incomplete'):
        gate.prune_api_service_models(tmp_path)
    assert (extra / 'service-2.json.gz').read_bytes() == b'other model'
    assert (data / 'endpoints.json').read_text() == 'shared endpoint data'


def test_prune_removes_only_unlisted_service_trees(tmp_path, monkeypatch):
    data = _fake_models(tmp_path)
    extra = data / 'unlisted' / '2000-01-01'
    extra.mkdir(parents=True)
    (extra / 'service-2.json.gz').write_bytes(b'other model')
    monkeypatch.setattr(gate, 'reviewed_python', lambda root: {})
    monkeypatch.setattr(gate, 'direct_clients', lambda root: [])
    result = gate.prune_api_service_models(tmp_path)
    assert result['removed_model_paths'] == ['botocore/data/unlisted/2000-01-01/service-2.json.gz']
    assert not extra.exists()
    assert (data / 'sts' / '2000-01-01' / 'service-2.json.gz').read_bytes() == b'retained model'
    assert (data / 'endpoints.json').read_text() == 'shared endpoint data'


@pytest.mark.parametrize('linked', ['root', 'botocore', 'data'])
def test_model_tree_symlinks_fail_before_any_deletion(tmp_path, monkeypatch, linked):
    real = tmp_path / 'real'
    real.mkdir()
    data = _fake_models(real)
    extra = data / 'unlisted'
    extra.mkdir()
    marker = extra / 'model.json'
    marker.write_bytes(b'must remain unchanged')
    if linked == 'root':
        stage = tmp_path / 'stage'
        stage.symlink_to(real, target_is_directory=True)
    elif linked == 'botocore':
        stage = tmp_path / 'stage'
        stage.mkdir()
        shutil.copytree(real / f'botocore-{gate.REQUIRED_BOTOCORE_VERSION}.dist-info',
                        stage / f'botocore-{gate.REQUIRED_BOTOCORE_VERSION}.dist-info')
        (stage / 'botocore').symlink_to(real / 'botocore', target_is_directory=True)
    else:
        stage = real
        moved = tmp_path / 'external-models'
        data.rename(moved)
        data.symlink_to(moved, target_is_directory=True)
        marker = moved / 'unlisted/model.json'
    monkeypatch.setattr(gate, 'reviewed_python', lambda root: {})
    monkeypatch.setattr(gate, 'direct_clients', lambda root: [])
    with pytest.raises(RuntimeError, match='model tree contains a symlink'):
        gate.prune_api_service_models(stage)
    assert marker.read_bytes() == b'must remain unchanged'
