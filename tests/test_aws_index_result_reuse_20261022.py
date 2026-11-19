"""Offline runner-count and authority regressions for selected ECR indexes."""
import json
from pathlib import Path
from types import SimpleNamespace
from datetime import datetime, timedelta, timezone

import pytest

from peaso import container_image_archive_20261020 as archive
from peaso import oci_index_20261021 as oci
from peaso import trivy_container_runner_20261020 as trivy
from peaso.collectors import aws_image_vulnerability_native_20261021 as native
from tests.test_aws_image_vulnerability_runtime_20261021 import (
    ACCOUNT, REGION, SCOPE, image, scan_runner, wire)


@pytest.fixture
def db_cache(tmp_path):
    root = tmp_path / 'database'
    db = root / 'db'
    db.mkdir(parents=True)
    (db / 'trivy.db').write_bytes(b'synthetic-offline-database')
    now = datetime.now(timezone.utc)
    (db / 'metadata.json').write_bytes(wire({'Version': 2,
        'UpdatedAt': (now - timedelta(hours=1)).isoformat(),
        'NextUpdate': (now + timedelta(hours=23)).isoformat(),
        'DownloadedAt': now.isoformat()}))
    return root


def _index(manifest, child_digest):
    raw = wire({'schemaVersion': 2, 'mediaType': oci.OCI_INDEX,
        'manifests': [{'mediaType': archive.OCI, 'digest': child_digest,
                       'size': len(manifest), 'platform': {'os': 'linux', 'architecture': 'amd64'}}]})
    return archive.sha(raw), raw


def _two_platforms(image):
    config = wire({**json.loads(image.config), 'architecture': 'arm64'})
    manifest = wire({**json.loads(image.manifest), 'config': {
        **json.loads(image.manifest)['config'], 'digest': archive.sha(config), 'size': len(config)}})
    arm = SimpleNamespace(config=config, layer=image.layer, manifest=manifest, digest=archive.sha(manifest))
    raw = wire({'schemaVersion': 2, 'mediaType': oci.OCI_INDEX, 'manifests': [
        {'mediaType': archive.OCI, 'digest': item.digest, 'size': len(item.manifest),
         'platform': {'os': 'linux', 'architecture': arch}}
        for item, arch in ((image, 'amd64'), (arm, 'arm64'))]})
    return archive.sha(raw), raw, arm


def _targets(parent, other=None, *, four=False):
    repo = 'fixture/image'
    targets = [
        {'scope': SCOPE, 'repository_name': repo, 'image_digest': parent,
         'task_definition_arn': f'arn:aws:ecs:{REGION}:{ACCOUNT}:task-definition/one:1',
         'container_name': 'app'},
        {'scope': SCOPE, 'repository_name': repo, 'image_digest': other or parent,
         'job_definition_arn': f'arn:aws:batch:{REGION}:{ACCOUNT}:job-definition/two:1',
         'batch_profile': 'container'},
    ]
    if four:
        targets.extend([
            {**targets[0], 'task_definition_arn':
                f'arn:aws:ecs:{REGION}:{ACCOUNT}:task-definition/three:1'},
            {**targets[1], 'job_definition_arn':
                f'arn:aws:batch:{REGION}:{ACCOUNT}:job-definition/four:1'},
        ])
    return targets


def _reader(monkeypatch, image, parents, *, changed_binding=False, denied=False, second_hook=None, other=None):
    images = {item.digest: item for item in (image, other) if item is not None}
    payloads = {archive.sha(raw): raw for item in images.values() for raw in (item.config, item.layer)}
    class Reader:
        def start_target(self):
            self.target_calls = 0
        counts = {'caller': 0, 'binding': 0, 'parent': 0, 'child': 0}
        def __init__(self, requests, session, account, region, *, target_count=1):
            assert (account, region, target_count) in ((ACCOUNT, REGION, 2), (ACCOUNT, REGION, 4))
            self.account, self.region, self.ledger = account, region, []
            self.second_binding_calls = 0
        def check(self):
            pass
        def caller(self):
            self.counts['caller'] += 1
            self.ledger.append({'operation': 'sts:get_caller_identity', 'status': 'collected'})
        def workload_binding(self, target):
            self.counts['binding'] += 1
            if 'job_definition_arn' in target:
                self.second_binding_calls += 1
                if second_hook:
                    second_hook(self.second_binding_calls)
            arn = target.get('task_definition_arn') or target.get('job_definition_arn')
            binding = {'asset_arn': arn, 'image_uri':
                f'{ACCOUNT}.dkr.ecr.{REGION}.amazonaws.com/{target["repository_name"]}@{target["image_digest"]}'}
            if changed_binding and 'job_definition_arn' in target and self.second_binding_calls > 1:
                binding['image_uri'] += '-changed'
            self.ledger.append({'operation': ('ecs:describe_task_definition' if 'task_definition_arn' in target
                else 'batch:describe_job_definitions'), 'status': 'collected'})
            return binding
        def reference(self, target):
            self.active_target = target
            binding = self.workload_binding(target)
            return target['repository_name'], target['image_digest'], binding['image_uri'], binding
        def manifest(self, repo, digest, *, allow_index=False):
            assert repo == 'fixture/image'
            if digest in parents:
                assert allow_index
                self.counts['parent'] += 1
                raw = parents[digest]
            else:
                assert not allow_index and digest in images
                self.counts['child'] += 1
                if denied and 'job_definition_arn' in self.active_target:
                    raise ValueError('denied')
                raw = images[digest].manifest
            self.ledger.append({'operation': 'ecr:batch_get_image', 'status': 'collected',
                                'digest': digest, 'bytes': len(raw)})
            return raw, json.loads(raw)
        def blob(self, repo, descriptor, *, path=None, image_digest=None):
            assert repo == 'fixture/image' and image_digest in images
            raw = payloads[descriptor['digest']]
            self.ledger.append({'operation': 'ecr:signed_layer_download', 'status': 'collected',
                                'digest': descriptor['digest'], 'bytes': len(raw)})
            if path is not None:
                Path(path).write_bytes(raw)
                return path
            return raw
        def close(self):
            return True
    monkeypatch.setattr(native, 'Reader', Reader)
    return Reader


@pytest.mark.parametrize('positive', [False, True])
def test_shared_index_child_runner_once_with_fresh_asset_evidence(image, monkeypatch, tmp_path, db_cache, positive):
    parent, raw = _index(image.manifest, image.digest)
    reader = _reader(monkeypatch, image, {parent: raw})
    calls = []
    run = scan_runner(positive=positive)
    def counting(*args, **kwargs):
        calls.append(args[0]['manifest_digest'])
        result = run(*args, **kwargs)
        result['database'] = trivy.database_state(db_cache)
        return result
    result = native.collect_native(object(), object(), ACCOUNT, REGION, _targets(parent),
                                   enabled=True, runner=counting, db_cache=db_cache, scratch_parent=tmp_path)
    assert calls == [image.digest]  # Baseline was two child Trivy runner calls.
    assert result['complete'] and result['status'] == ('FAIL' if positive else 'PASS')
    assert [row['image_scan_reused'] for row in result['rows']] == [False, True]
    assert [row['status'] for row in result['rows']] == [('FAIL' if positive else 'PASS')] * 2
    assert all(len(row['child_observations'][0]['scan']['findings']) == int(positive)
               for row in result['rows'])
    assert len({row['child_observations'][0]['asset_id'] for row in result['rows']}) == 2
    assert all(any(entry['operation'] == 'ecr:batch_get_image' for entry in row['source_ledger'])
               for row in result['rows'])
    assert reader.counts['binding'] >= 5 and reader.counts['parent'] >= 3
    assert list(tmp_path.iterdir()) == [db_cache]


def test_two_platform_index_preserves_each_child_finding(image, monkeypatch, tmp_path, db_cache):
    parent, raw, arm = _two_platforms(image)
    _reader(monkeypatch, image, {parent: raw}, other=arm)
    calls = []
    run = scan_runner()
    def counting(*args, **kwargs):
        calls.append(args[0]['manifest_digest'])
        result = run(*args, **kwargs)
        result['database'] = trivy.database_state(db_cache)
        return result
    result = native.collect_native(object(), object(), ACCOUNT, REGION, _targets(parent, four=True),
                                   enabled=True, runner=counting, db_cache=db_cache, scratch_parent=tmp_path)
    assert result['complete'] and calls == [image.digest, arm.digest]  # Baseline: eight.
    assert len(result['rows']) == 4 and len(result['observations']) == 8
    assert all(len(row['child_observations']) == 2 for row in result['rows'])
    assert all({obs['scan']['image']['manifest_digest'] for obs in row['child_observations']}
               == {image.digest, arm.digest} for row in result['rows'])
    assert all(all(obs['scan']['findings'] for obs in row['child_observations'])
               for row in result['rows'])


def test_changed_parent_digest_runs_again(image, monkeypatch, tmp_path, db_cache):
    parent, raw = _index(image.manifest, image.digest)
    changed = wire({**json.loads(raw), 'annotations': {'revision': 'two'}})
    other = archive.sha(changed)
    _reader(monkeypatch, image, {parent: raw, other: changed})
    calls = []
    run = scan_runner()
    def counting(*args, **kwargs):
        calls.append(args[0]['manifest_digest'])
        result = run(*args, **kwargs)
        result['database'] = trivy.database_state(db_cache)
        return result
    result = native.collect_native(object(), object(), ACCOUNT, REGION, _targets(parent, other),
                                   enabled=True, runner=counting, db_cache=db_cache, scratch_parent=tmp_path)
    assert result['complete'] and calls == [image.digest, image.digest]
    assert not result['rows'][1]['image_scan_reused']


def test_changed_binding_blocks_reuse_and_preserves_first_finding(image, monkeypatch, tmp_path, db_cache):
    parent, raw = _index(image.manifest, image.digest)
    _reader(monkeypatch, image, {parent: raw}, changed_binding=True)
    calls = []
    run = scan_runner()
    def counting(*args, **kwargs):
        calls.append(args[0]['manifest_digest'])
        result = run(*args, **kwargs)
        result['database'] = trivy.database_state(db_cache)
        return result
    result = native.collect_native(object(), object(), ACCOUNT, REGION, _targets(parent),
                                   enabled=True, runner=counting, db_cache=db_cache, scratch_parent=tmp_path)
    assert calls == [image.digest] and not result['complete']
    assert result['rows'][0]['status'] == 'FAIL'
    assert result['rows'][1]['status'] == 'UNKNOWN'


def test_database_lease_change_requires_new_scan(image, monkeypatch, tmp_path):
    parent, raw = _index(image.manifest, image.digest)
    epoch = [1]
    def lease(_):
        return {'fresh': True, 'schema_version': 2, 'updated_at': str(epoch[0]),
                'next_update': 'next', 'downloaded_at': 'downloaded',
                'db_stat_identity': [epoch[0], 2, 3, 4], 'metadata_sha256': str(epoch[0])}
    monkeypatch.setattr(trivy, 'database_state', lease)
    def bump(count):
        if count == 1:
            epoch[0] = 2
    _reader(monkeypatch, image, {parent: raw}, second_hook=bump)
    calls = []
    run = scan_runner()
    def counting(*args, **kwargs):
        calls.append(args[0]['manifest_digest'])
        result = run(*args, **kwargs)
        result['database'] = lease(None)
        return result
    result = native.collect_native(object(), object(), ACCOUNT, REGION, _targets(parent),
        enabled=True, runner=counting, db_cache='/synthetic/lease', scratch_parent=tmp_path)
    assert result['complete'] and calls == [image.digest, image.digest]
    assert not result['rows'][1]['image_scan_reused']


@pytest.mark.parametrize('failure', ['denied', 'incomplete'])
def test_denial_or_incomplete_scan_never_reused_as_clean(image, monkeypatch, tmp_path, db_cache, failure):
    parent, raw = _index(image.manifest, image.digest)
    _reader(monkeypatch, image, {parent: raw}, denied=failure == 'denied')
    calls = []
    run = scan_runner(positive=False)
    def counting(*args, **kwargs):
        calls.append(args[0]['manifest_digest'])
        result = run(*args, **kwargs)
        result['database'] = trivy.database_state(db_cache)
        if failure == 'incomplete' and len(calls) == 1:
            result.update(status='UNKNOWN', complete=False, scan_complete=False,
                          coverage_status='UNKNOWN')
        return result
    result = native.collect_native(object(), object(), ACCOUNT, REGION, _targets(parent),
                                   enabled=True, runner=counting, db_cache=db_cache, scratch_parent=tmp_path)
    if failure == 'denied':
        assert calls == [image.digest] and not result['complete']
        assert result['rows'][1]['status'] == 'UNKNOWN'
    else:
        assert calls == [image.digest, image.digest]
        assert not result['rows'][0]['complete'] and result['rows'][1]['complete']
        assert not result['rows'][1]['image_scan_reused']
