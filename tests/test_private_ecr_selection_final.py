"""Portable integration tests for the composed selected private ECR path."""
from copy import deepcopy
from hashlib import sha256
import pytest

from peaso.aws_image_selection_20261021 import CHECK, ENABLE, OPTION
from peaso.collectors import aws_image_vulnerability_runtime_20261021 as runtime
from peaso.collectors import aws_workload_image_secret_native_20261021 as secrets
from peaso.image_findings_storage import safe_observations
from peaso.selected_image_observations_20261021 import metadata_for_report

ACCOUNT = '123456789012'
REGION = 'us-east-1'
SCOPE = ACCOUNT + '/' + REGION
REPO = 'demo/image'
ASSET = f'arn:aws:ecs:{REGION}:{ACCOUNT}:task-definition/demo:7'
DIGEST = lambda value: 'sha256:' + sha256(value.encode()).hexdigest()
PARENT = DIGEST('parent')
CHILD_A, CHILD_B = DIGEST('child-a'), DIGEST('child-b')
CONFIG_A, CONFIG_B = DIGEST('config-a'), DIGEST('config-b')
TARGET = {'scope': SCOPE, 'task_definition_arn': ASSET, 'container_name': 'app',
    'repository_name': REPO, 'image_digest': PARENT}
PREFIX = f'{ACCOUNT}.dkr.ecr.{REGION}.amazonaws.com/{REPO}@'


def observation(digest, config, finding=False):
    vulns = ([{'vulnerability_id': 'CVE-2025-12345', 'severity': 'HIGH',
        'package_types': ['apk'], 'package': 'demo', 'version': '1.0',
        'fixed_in': ['1.1'], 'fix_status': 'fixed', 'classes': ['os-pkgs'],
        'image_digest': digest}] if finding else [])
    return {'provider': 'aws', 'scope': SCOPE, 'asset_id': ASSET,
        'asset_kind': 'ecs_task_definition', 'scan': {'image': {'provider': 'aws',
            'scope': SCOPE, 'immutable_reference': PREFIX + digest,
            'manifest_digest': digest, 'config_digest': config},
            'status': 'FAIL' if finding else 'PASS', 'complete': True,
            'scan_complete': True, 'coverage_status': 'COMPLETE',
            'database': {'fresh': True}, 'findings': vulns}}


def row(*, positive=False, partial=False):
    descriptors = [{'digest': CHILD_A, 'size': 300,
        'mediaType': 'application/vnd.oci.image.manifest.v1+json',
        'platform': {'os': 'linux', 'architecture': 'amd64'},
        'config_digest': CONFIG_A}]
    scans = [observation(CHILD_A, CONFIG_A, positive)]
    if not partial:
        descriptors.append({'digest': CHILD_B, 'size': 320,
            'mediaType': 'application/vnd.oci.image.manifest.v1+json',
            'platform': {'os': 'linux', 'architecture': 'arm64'},
            'config_digest': CONFIG_B})
        scans.append(observation(CHILD_B, CONFIG_B))
    return {'selection': deepcopy(TARGET), 'status': 'FAIL' if positive else
        'UNKNOWN' if partial else 'PASS', 'complete': not partial,
        'index_graph': {'parent_digest': PARENT,
            'media_type': 'application/vnd.oci.image.index.v1+json',
            'children': descriptors, 'complete': not partial},
        'parent_binding_stable': True,
        'workload_binding': {'image_uri': PREFIX + PARENT},
        'association': 'ecs_declared_image', 'child_observations': scans,
        'observation': None}


def attached(value):
    metadata = {}
    runtime.attach_metadata(metadata, [{'type': runtime.KIND, 'scope': SCOPE,
        'items': [{'ImageVulnerabilityReview': value}]}], [TARGET])
    return metadata['image_vulnerability_scan']['observations']


def test_two_child_scans_reach_existing_images_artifact():
    output = attached(row())
    assert [r['scan']['image']['manifest_digest'] for r in output] == [CHILD_A, CHILD_B]
    assert all(r['scan']['status'] == 'PASS' for r in output)
    image_metadata = metadata_for_report({'provider': 'aws', 'metadata': {
        'image_vulnerability_scan': {'selected': True, 'observations': output}},
        'collections': []}, {'provider': 'aws', 'findings': []})
    assert len(safe_observations(image_metadata['observations'])) == 2


def test_partial_high_finding_survives_with_coverage_gap():
    output = attached(row(positive=True, partial=True))
    assert len(output) == 2 and output[0]['scan']['status'] == 'FAIL' and output[1] is None


def test_foreign_child_and_stale_parent_never_publish_scans():
    foreign = row(positive=True)
    foreign['child_observations'][0]['scan']['image']['manifest_digest'] = DIGEST('foreign')
    assert attached(foreign) == [None]
    stale = row(positive=True)
    stale['parent_binding_stable'] = False
    assert attached(stale) == [None]


def test_leaf_projection_and_default_off_named_grants():
    leaf = {'selection': deepcopy(TARGET), 'observation': observation(CHILD_A, CONFIG_A)}
    assert attached(leaf) == [leaf['observation']]
    options = {}
    runtime.issue_engine_grant(options, [SCOPE], [])
    assert runtime.authorize_collector(options, [SCOPE]) == []
    secrets.issue_engine_grant(options, [SCOPE], [])
    assert secrets.authorize_collector(options, [SCOPE]) == []
    selected = {ENABLE: True, OPTION: [TARGET]}
    runtime.issue_engine_grant(selected, [SCOPE], [CHECK])
    assert runtime.authorize_collector(selected, [SCOPE]) == [TARGET]


def test_named_ecs_batch_secret_selection_has_no_implicit_lambda_or_registry_grant():
    batch = {'scope': SCOPE,
        'job_definition_arn': f'arn:aws:batch:{REGION}:{ACCOUNT}:job-definition/demo:3',
        'batch_profile': 'container', 'repository_name': REPO, 'image_digest': PARENT}
    options = {'content_secret_scans': True,
        secrets.OPTION: [deepcopy(TARGET), batch]}
    secrets.issue_engine_grant(options, [SCOPE], [secrets.CHECK])
    assert secrets.authorize_collector(options, [SCOPE]) == [TARGET, batch]
    assert secrets.GRANT not in options
    assert runtime.authorize_collector(options, [SCOPE]) == []


def test_selected_repository_parent_request_omits_leaf_filter():
    from datetime import datetime, timezone
    from types import SimpleNamespace
    from peaso.collectors import aws_package_content_indicators as content
    class Requests:
        content_secret_scans = True
        def __init__(self):
            self.calls = []
        def detail(self, session, service, region, operation, **kwargs):
            self.calls.append((service, operation, kwargs))
            if service == 'sts':
                return {'collection_status': 'collected', 'Account': ACCOUNT,
                    'Arn': f'arn:aws:sts::{ACCOUNT}:assumed-role/test/runner'}
            assert service == 'ecr' and operation == 'batch_get_image'
            assert kwargs['imageIds'] == [{'imageDigest': PARENT}]
            assert 'acceptedMediaTypes' not in kwargs
            return {'collection_status': 'collected', 'ImageDigest': PARENT}
        def pages(self, session, service, region, operation, member, **kwargs):
            assert (service, operation, member) == ('ecr', 'describe_images', 'imageDetails')
            return SimpleNamespace(status='collected', items=[{'imageDigest': PARENT,
                'imagePushedAt': datetime(2026, 1, 1, tzinfo=timezone.utc),
                'registryId': ACCOUNT, 'repositoryName': REPO}])
    requests = Requests()
    item = {'repositoryArn': f'arn:aws:ecr:{REGION}:{ACCOUNT}:repository/{REPO}',
        'repositoryName': REPO, 'registryId': ACCOUNT}
    result = content.enrich('ecr_repository', requests, object(), REGION, [item])
    assert result[0]['PackageContentSource']['SelectedImageDigest'] == PARENT
    assert len(requests.calls) == 2


def test_direct_selected_index_native_consumer_and_partial(monkeypatch):
    from peaso import oci_index_20261021 as index
    from peaso.collectors import aws_image_vulnerability_native_20261021 as native
    from peaso.checks import aws_image_vulnerabilities_20261021 as check
    import json
    from types import SimpleNamespace
    leaf_media = 'application/vnd.oci.image.manifest.v1+json'
    child = lambda digest, config: json.dumps({'schemaVersion': 2,
        'mediaType': leaf_media, 'config': {'digest': config,
        'size': 8, 'mediaType': 'application/vnd.oci.image.config.v1+json'},
        'layers': [{'digest': DIGEST('layer'), 'size': 9,
            'mediaType': 'application/vnd.oci.image.layer.v1.tar+gzip'}]},
        sort_keys=True, separators=(',', ':')).encode()
    raw_a, raw_b = child(CHILD_A, CONFIG_A), child(CHILD_B, CONFIG_B)
    digest_a = 'sha256:' + sha256(raw_a).hexdigest()
    digest_b = 'sha256:' + sha256(raw_b).hexdigest()
    parent_raw = json.dumps({'schemaVersion': 2, 'mediaType': index.OCI_INDEX,
        'manifests': [{'digest': d, 'size': len(raw), 'mediaType': leaf_media,
            'platform': {'os': 'linux', 'architecture': arch}}
            for d, raw, arch in ((digest_a, raw_a, 'amd64'), (digest_b, raw_b, 'arm64'))]},
        sort_keys=True, separators=(',', ':')).encode()
    parent_digest = 'sha256:' + sha256(parent_raw).hexdigest()
    direct = {'scope': SCOPE, 'repository_name': REPO, 'image_digest': parent_digest}
    class Reader:
        denied = False
        clean = False
        def __init__(self, requests, session, account, region, *, target_count=1):
            assert (account, region) == (ACCOUNT, REGION)
            self.account, self.region, self.ledger = account, region, []
        def check(self):
            pass
        def caller(self):
            self.ledger.append({'operation': 'sts:get_caller_identity',
                'status': 'collected', 'account': ACCOUNT})
        def reference(self, selected):
            assert selected == direct
            return REPO, parent_digest, PREFIX + parent_digest, None
        def manifest(self, repo, digest, *, allow_index=False):
            assert repo == REPO
            if digest == parent_digest:
                assert allow_index
                raw = parent_raw
            else:
                assert not allow_index
                if self.denied and digest == digest_b:
                    self.ledger.append({'operation': 'ecr:batch_get_image', 'status': 'collected'})
                    raise ValueError('denied')
                raw = {digest_a: raw_a, digest_b: raw_b}[digest]
            self.ledger.append({'operation': 'ecr:batch_get_image', 'status': 'collected',
                'digest': digest, 'bytes': len(raw)})
            return raw, json.loads(raw)
        def close(self):
            return True
    def leaf_scan(reader, selected, repo, digest, reference, binding, manifest,
                  document, cache, runner, cli, scratch, *, platform=None):
        assert selected == direct and binding is None and platform['os'] == 'linux'
        conf = document['config']['digest']
        obs = observation(digest, conf, finding=digest == digest_a and not Reader.clean)
        obs['asset_id'] = f'arn:aws:ecr:{REGION}:{ACCOUNT}:repository/{REPO}@{parent_digest}'
        obs['asset_kind'] = 'ecr_image'
        return obs['scan']['image'], obs['scan']
    monkeypatch.setattr(native, 'Reader', Reader)
    monkeypatch.setattr(native, '_scan_bound', leaf_scan)
    def capture(denied, *, clean=False):
        Reader.denied = denied
        Reader.clean = clean
        result = native.collect_native(SimpleNamespace(), object(), ACCOUNT, REGION, [direct], enabled=True)
        row = result['rows'][0]
        item = {'id': 'ecr-image:' + runtime._hash(direct), 'ImageVulnerabilityReview': row}
        envelope = {'context': {'provider': 'aws', 'scope': SCOPE, 'metadata': {OPTION: [direct]}},
            'collections': {runtime.KIND: [{'scope': SCOPE,
                'status': 'partial' if denied else 'collected', 'items': [item]}]}}
        return row, check.evaluate(item, envelope), attached_direct(row, direct)
    def attached_direct(value, selected):
        metadata = {}
        runtime.attach_metadata(metadata, [{'type': runtime.KIND, 'scope': SCOPE,
            'items': [{'ImageVulnerabilityReview': value}]}], [selected])
        return metadata['image_vulnerability_scan']['observations']
    complete, (status, evidence), images = capture(False)
    assert status == 'FAIL' and len(images) == 2
    assert images[0]['scan']['image']['manifest_digest'] == digest_a
    clean, (status, evidence), images = capture(False, clean=True)
    assert status == 'PASS' and len(images) == 2 and all(image['scan']['status'] == 'PASS' for image in images)
    partial, (status, evidence), images = capture(True)
    assert status == 'FAIL' and images[0]['scan']['status'] == 'FAIL' and images[-1] is None
    partial_clean, (status, evidence), images = capture(True, clean=True)
    assert status == 'UNKNOWN' and images[-1] is None


def test_lambda_index_remains_unselected_and_foreign_scope_rejected(monkeypatch):
    from peaso.collectors import aws_image_vulnerability_native_20261021 as native
    from types import SimpleNamespace
    function = f'arn:aws:lambda:{REGION}:{ACCOUNT}:function:demo'
    target = {'scope': SCOPE, 'function_arn': function}
    class Reader:
        def __init__(self, requests, session, account, region, *, target_count=1):
            self.ledger = []
        def caller(self):
            pass
        def reference(self, selected):
            return REPO, PARENT, PREFIX + PARENT, {'function_arn': function,
                'revision': 'revision', 'image_uri': PREFIX + PARENT}
        def manifest(self, repo, digest, *, allow_index=False):
            assert allow_index is False
            raise ValueError('Lambda index is not a leaf image')
        def close(self):
            return True
    monkeypatch.setattr(native, 'Reader', Reader)
    result = native.collect_native(SimpleNamespace(), object(), ACCOUNT, REGION, [target], enabled=True)
    assert result['status'] == 'UNKNOWN' and result['rows'][0]['status'] == 'UNKNOWN'
    foreign = {'scope': '000000000000/' + REGION, 'repository_name': REPO, 'image_digest': PARENT}
    with pytest.raises(ValueError):
        native.collect_native(SimpleNamespace(), object(), ACCOUNT, REGION, [foreign], enabled=True)
