"""Encrypted source joins with the real offline detectors and private detail API."""
import importlib.util
import json
import os
from pathlib import Path
import sys
import time

import pytest

ROOT = Path(__file__).resolve().parents[1]
HERE = ROOT
from peaso import secret_evidence
from peaso.secret_scanning import scan_content

TOKEN = 'ghp_' + '7mQ2zR9wL4cV8nK1sF6aH3jP5uD0xB2yE9rT'
SCOPE = 'projects/example-project'
CHECK = 'gcp.review.cloudrun_worker_pool.selected_revision_image_secret_indicators'


def finding(leaks, resource, scope=SCOPE, check=CHECK):
    return {'check_id': check, 'status': 'FAIL', 'resource_id': resource,
            'native_resource_id': resource, 'scope': scope, 'evidence': {'secret_leaks': leaks}}


def detail_roundtrip(sink, cipher, leaks, resource, scope=SCOPE, check=CHECK):
    document = sink.document()
    assert TOKEN not in json.dumps(document)
    matched = secret_evidence.details(finding(leaks, resource, scope, check), document, cipher,
                                      tenant='offline', scan_id='selected')
    assert matched['status'] == 'available' and any(row['value'] == TOKEN for row in matched['matches'])
    foreign = secret_evidence.details(finding(leaks, resource + '-foreign', scope, check), document, cipher,
                                      tenant='offline', scan_id='selected')
    wrong_scope = secret_evidence.details(finding(leaks, resource, 'projects/foreign-project', check), document, cipher,
                                          tenant='offline', scan_id='selected')
    assert foreign['status'] == wrong_scope['status'] == 'unavailable'


@pytest.mark.parametrize('resource,caller,expression', [
    ('projects/example-project/locations/us-central1/workerPools/pool/revisions/rev#container=0',
     'gcp_workerpool_image_native_20261021.py', "target['revision_name'] + '#container=' + str(target['container_index'])"),
    ('appengine-flex-image:' + 'a' * 64,
     'gcp_appengine_flex_image_native_20261021.py', 'identity(target)'),
])
def test_image_config_real_detectors_join_selected_finding(monkeypatch, resource, caller, expression):
    from peaso.collectors import gcp_image_stream_inspection_20261021 as helper
    uri = 'https://us-central1-docker.pkg.dev/example-project/owned/image'
    manifest_digest = 'sha256:' + 'a' * 64
    config_digest = 'sha256:' + 'b' * 64
    layer_digest = 'sha256:' + 'c' * 64
    config = json.dumps({'os': 'linux', 'architecture': 'amd64',
        'rootfs': {'type': 'layers', 'diff_ids': ['sha256:' + 'd' * 64]},
        'config': {'Env': ['TOKEN=' + TOKEN]}}).encode()
    manifest = json.dumps({'schemaVersion': 2, 'mediaType': helper.native.OCI,
        'config': {'digest': config_digest, 'size': len(config),
                   'mediaType': sorted(helper.native.CONFIG_TYPES)[0]},
        'layers': [{'digest': layer_digest, 'size': 1,
                    'mediaType': sorted(helper.native.TAR_TYPES)[0]}]}).encode()
    monkeypatch.setattr(helper.native, 'bind_image', lambda *args: (uri, 'owned-repo', manifest_digest))
    monkeypatch.setattr(helper, 'visit_files', lambda *args, **kw: {
        'expanded_bytes': 0, 'members': 0, 'links_skipped': 0})

    class Reader:
        end = time.monotonic() + 90
        def check(self): pass
        def get(self, url, category, digest, *args):
            return manifest if category == 'manifests' else config
        def get_layer(self, url, descriptor, path):
            path.write_bytes(b'x')

    cipher = secret_evidence.EphemeralCipher()
    with secret_evidence.capture(cipher, tenant='offline', scan_id='selected') as sink:
        result = helper.inspect_image({}, SCOPE, [], [], Reader(), capture_resource_id=resource)
    assert result['leaks'] and result['complete']
    assert {'kingfisher', 'trufflehog'} <= {d['engine'] for leak in result['leaks'] for d in leak['detectors']}
    assert TOKEN not in json.dumps(result)
    detail_roundtrip(sink, cipher, result['leaks'], resource)


def test_gke_scanner_rebinds_private_source_to_gcp_item_and_project():
    from peaso.collectors import gcp_gke_selected_pod_image_20261021 as gke
    namespace = {'identity': gke.identity, '_gcp_capture_scanner': gke._gcp_capture_scanner}
    target = {'cluster_id': SCOPE + '/locations/us-central1/clusters/owned',
              'namespace': 'default', 'pod': 'owned', 'image': 'registry.example/repo@sha256:' + 'a' * 64}
    resource = namespace['identity'](target)
    leaks = []
    def actual_scanner(raw, path, source, check, collected, parts, **kwargs):
        outcome = secret_evidence.scan_with_source(scan_content, raw, path,
                    source=source, timeout=15)
        collected.extend(outcome['leaks'])
        parts.append(outcome['engines'])
    scanner = namespace['_gcp_capture_scanner'](target, actual_scanner)
    cipher = secret_evidence.EphemeralCipher()
    with secret_evidence.capture(cipher, tenant='offline', scan_id='selected') as sink:
        scanner(('TOKEN=' + TOKEN).encode(), 'image-config.json',
                {'resource_id': 'k8s-image-opaque', 'scope': target['cluster_id'],
                 'layer': 'sha256:' + 'b' * 64}, lambda: None, leaks, [])
    assert leaks
    detail_roundtrip(sink, cipher, leaks, resource,
                     check='gcp.review.gke.selected_pod_image_secret_indicators')


def test_developerconnect_existing_native_source_joins_without_change():
    from peaso.collectors import gcp_developerconnect_file_native_20261021 as native
    target = {'provider': 'github', 'link_name': SCOPE + '/locations/us-central1/connections/owned/gitRepositoryLinks/owned',
              'link_uid': 'owned', 'clone_uri': 'https://github.com/owned/repo.git',
              'commit_sha': 'a' * 40, 'blob_sha': 'b' * 40, 'path': 'src/settings.py'}
    resource = native.resource_id(target)
    cipher = secret_evidence.EphemeralCipher()
    with secret_evidence.capture(cipher, tenant='offline', scan_id='selected') as sink:
        result = native.scan(target, SCOPE, ('TOKEN=' + TOKEN).encode())
    assert result['leaks'] and TOKEN not in json.dumps(result)
    detail_roundtrip(sink, cipher, result['leaks'], resource,
                     check=native.CHECK_ID)
