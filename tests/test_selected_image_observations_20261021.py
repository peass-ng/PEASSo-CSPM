"""New selected image sources reach the existing image artifact without native imports."""
from copy import deepcopy
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

from peaso.image_findings import build_report
from peaso.image_findings_storage import safe_observations
from peaso.image_findings_storage import attach_to_manifest
from peaso.selected_image_observations_20261021 import SOURCES, metadata_for_report
from peaso.snapshot import digest
from peaso.storage.artifacts import FileArtifacts

DIGEST = 'sha256:' + 'a' * 64


def case(kind, status='FAIL'):
    provider, cid, marker_path, scan_path = SOURCES[kind]
    scope = {'aws': '123456789012/us-east-1', 'azure': '/subscriptions/sub',
             'gcp': 'projects/project1', 'k8s': 'apps'}[provider]
    pod = kind in ('k8s_selected_registry_image_vulnerabilities',
                   'azure_selected_aks_pod_image_vulnerabilities', 'gke_selected_pod_image_vulnerabilities')
    original_scope = ({'azure': scope + '/resourceGroups/rg/providers/Microsoft.ContainerService/managedClusters/c',
                       'gcp': scope + '/locations/us-central1/clusters/c',
                       'k8s': 'cluster1'}[provider] if pod else scope)
    image = {'provider': 'k8s' if pod else provider, 'scope': original_scope,
             'immutable_reference': 'registry.example/app@' + DIGEST,
             'manifest_digest': DIGEST, 'config_digest': 'sha256:' + 'b' * 64}
    vulnerability = {'vulnerability_id': 'CVE-2026-12345', 'severity': 'HIGH',
        'package_types': ['debian'], 'package': 'openssl', 'version': '1.0',
        'fixed_in': ['1.1'], 'fix_status': 'fixed', 'classes': ['os-pkgs'], 'image_digest': DIGEST}
    scan = {'image': image, 'status': status, 'complete': status != 'UNKNOWN',
            'scan_complete': status != 'UNKNOWN',
            'coverage_status': 'UNKNOWN' if status == 'UNKNOWN' else 'COMPLETE',
            'database': {'fresh': True}, 'findings': [vulnerability] if status == 'FAIL' else []}
    if kind.startswith('appengine_'):
        scan['database_fresh'] = scan.pop('database')['fresh']
    item = {'id': 'asset1'}
    cursor = item
    for key in marker_path + scan_path[:-1]:
        cursor = cursor.setdefault(key, {})
    cursor[scan_path[-1]] = scan
    if kind == 'acr_selected_image_vulnerabilities':
        registry = scope + '/resourceGroups/rg/providers/Microsoft.ContainerRegistry/registries/registry1'
        repository = 'app'
        scan['image']['immutable_reference'] = 'registry1.azurecr.io/' + repository + '@' + DIGEST
        marker = item['AcrSelectedImageVulnerabilities']
        marker['status'] = status
        marker['selection'] = {'registry_id': registry, 'repository': repository, 'digest': DIGEST}
        marker['observation'].update(provider='azure', scope=scope,
            asset_id=registry + '/repositories/' + repository + '@' + DIGEST,
            asset_kind='acr_image')
    snapshot = {'provider': provider, 'metadata': {}, 'collections': [
        {'type': kind, 'scope': scope, 'status': 'collected', 'items': [item]}]}
    report = {'findings': [{'check_id': cid, 'provider': provider, 'scope': scope,
        'resource_id': digest([provider, scope, kind, 'asset1']), 'status': status}]}
    return snapshot, report, scan


@pytest.mark.parametrize('kind', list(SOURCES))
@pytest.mark.parametrize('status', ['PASS', 'FAIL', 'UNKNOWN'])
def test_source_to_safe_image_artifact(kind, status):
    snapshot, report, _ = case(kind, status)
    before = deepcopy((snapshot, report))
    metadata = metadata_for_report(snapshot, report)
    rows = safe_observations(metadata['observations'])
    result = build_report(rows, selected=True)
    assert (snapshot, report) == before
    if status == 'FAIL':
        assert len(result['rows']) == 1
        assert result['rows'][0]['vulnerability_id'] == 'CVE-2026-12345'
        assert result['rows'][0]['image_digest'] == DIGEST
        assert result['rows'][0]['affected_assets'][0]['resource_id'] == report['findings'][0]['resource_id']
    elif status == 'PASS':
        assert result['complete'] is True and result['rows'] == []
    else:
        assert result['complete'] is False and result['rows'] == []


@pytest.mark.parametrize('kind', list(SOURCES))
def test_absent_evaluated_check_cannot_project_scan(kind):
    snapshot, report, _ = case(kind)
    report['findings'] = []
    result = metadata_for_report(snapshot, report)
    assert result == ({'selected': True, 'observations': [None]}
                      if kind == 'acr_selected_image_vulnerabilities' else None)
    if kind == 'acr_selected_image_vulnerabilities':
        presented = build_report(safe_observations(result['observations']), selected=True)
        assert presented['complete'] is False and presented['rows'] == []


@pytest.mark.parametrize('kind', list(SOURCES))
def test_foreign_scan_and_contradictory_status_are_gaps(kind):
    snapshot, report, scan = case(kind)
    scan['image']['provider'] = 'foreign'
    assert metadata_for_report(snapshot, report)['observations'] == [None]
    snapshot, report, scan = case(kind)
    scan['status'] = 'PASS'
    projected = metadata_for_report(snapshot, report)
    if kind in ('k8s_selected_registry_image_vulnerabilities',
                'azure_selected_aks_pod_image_vulnerabilities',
                'gke_selected_pod_image_vulnerabilities'):
        # A trusted evaluated FAIL and independently valid typed positives
        # survive a contradictory clean summary, with unknown coverage.
        result = build_report(projected['observations'], selected=True)
        assert len(result['rows']) == 1 and result['coverage'] == 'UNKNOWN'
        assert result['rows'][0]['vulnerability_id'] == scan['findings'][0]['vulnerability_id']
    else:
        assert projected['observations'] == [None]


def test_existing_observations_survive_and_missing_selected_assets_leave_gap():
    kind = 'ecr_public_selected_image_content'
    snapshot, report, _ = case(kind)
    snapshot['metadata']['image_vulnerability_scan'] = {'selected': True, 'observations': [None]}
    assert len(metadata_for_report(snapshot, report)['observations']) == 2
    snapshot['collections'] = []
    assert metadata_for_report(snapshot, report)['observations'] == [None, None]


def test_same_image_advisory_across_assets_is_one_table_row():
    snapshot, report, _ = case('k8s_selected_registry_image_vulnerabilities')
    extra = deepcopy(snapshot['collections'][0]['items'][0])
    extra['id'] = 'asset2'
    snapshot['collections'][0]['items'].append(extra)
    extra_finding = dict(report['findings'][0], resource_id=digest([
        'k8s', 'apps', 'k8s_selected_registry_image_vulnerabilities', 'asset2']))
    report['findings'].append(extra_finding)
    metadata = metadata_for_report(snapshot, report)
    result = build_report(safe_observations(metadata['observations']), selected=True)
    assert len(result['rows']) == 1
    assert {a['resource_id'] for a in result['rows'][0]['affected_assets']} == {
        report['findings'][0]['resource_id'], extra_finding['resource_id']}


def test_native_resource_hash_and_provider_required_for_projection():
    snapshot, report, _ = case('ecr_public_selected_image_content')
    report['findings'][0]['resource_id'] = 'asset1'  # Native ID is not the evaluated ID.
    assert metadata_for_report(snapshot, report)['observations'] == [None]
    report['findings'][0]['resource_id'] = digest([
        'aws', '123456789012/us-east-1', 'ecr_public_selected_image_content', 'asset1'])
    report['findings'][0]['provider'] = 'gcp'
    assert metadata_for_report(snapshot, report) is None
    report['findings'][0]['provider'] = 'aws'
    assert len(metadata_for_report(snapshot, report)['observations']) == 1


@pytest.mark.parametrize('kind,foreign_scope', [
    ('azure_selected_aks_pod_image_vulnerabilities',
     '/subscriptions/foreign/resourceGroups/rg/providers/Microsoft.ContainerService/managedClusters/c'),
    ('gke_selected_pod_image_vulnerabilities',
     'projects/foreign/locations/us-central1/clusters/c'),
])
def test_foreign_cluster_scope_cannot_be_projected(kind, foreign_scope):
    snapshot, report, scan = case(kind)
    scan['image']['scope'] = foreign_scope
    assert metadata_for_report(snapshot, report)['observations'] == [None]


def test_raw_scanner_status_survives_later_ai_verdict_and_duplicates_are_gaps():
    snapshot, report, _ = case('ecr_public_selected_image_content')
    report['findings'][0].update(scanner_status='FAIL', status='UNKNOWN')
    assert build_report(safe_observations(metadata_for_report(snapshot, report)['observations']),
        selected=True)['rows']
    report['findings'].append(dict(report['findings'][0]))
    assert metadata_for_report(snapshot, report)['observations'] == [None]


def test_index_children_keep_child_digest_and_partial_positive():
    kind = 'ecr_public_selected_image_content'
    snapshot, report, scan = case(kind)
    marker = snapshot['collections'][0]['items'][0]['ECRPublicImageContent']
    first, second = 'sha256:' + 'c' * 64, 'sha256:' + 'd' * 64
    marker['selection'] = {'scope': snapshot['collections'][0]['scope'],
        'registry_alias': 'owned', 'repository_name': 'demo', 'image_digest': DIGEST}
    marker['graph'] = {'parent_digest': DIGEST, 'complete': False, 'children': [
        {'digest': first, 'config_digest': 'sha256:' + 'e' * 64},
        {'digest': second, 'config_digest': 'sha256:' + 'f' * 64}]}
    child = deepcopy(scan)
    child['image'] = dict(child['image'], immutable_reference='public.ecr.aws/owned/demo@' + first,
        manifest_digest=first, config_digest='sha256:' + 'e' * 64)
    child['findings'][0]['image_digest'] = first
    child.update(complete=False, scan_complete=False, coverage_status='UNKNOWN', database={'fresh': False})
    marker['child_vulnerability_scans'] = [child]
    observations = metadata_for_report(snapshot, report)['observations']
    assert len(observations) == 2 and observations[1] is None
    artifact = build_report(safe_observations(observations), selected=True)
    assert artifact['rows'][0]['image_digest'] == first
    assert artifact['coverage'] == 'UNKNOWN'
    child['image']['immutable_reference'] = 'public.ecr.aws/foreign/demo@' + first
    assert metadata_for_report(snapshot, report)['observations'] == [None]


def test_pod_index_child_uses_parent_reference_and_child_digest():
    snapshot, report, scan = case('k8s_selected_registry_image_vulnerabilities')
    marker = snapshot['collections'][0]['items'][0]['SelectedRegistryImage']
    child_digest = 'sha256:' + 'c' * 64
    marker.update(manifest_digest=DIGEST, status_image_id='registry.example/app@' + DIGEST,
        graph={'parent_digest': DIGEST, 'complete': True, 'children': [
            {'digest': child_digest, 'config_digest': 'sha256:' + 'd' * 64}]})
    child = deepcopy(scan)
    child['image'].update(immutable_reference='registry.example/app@' + child_digest,
        manifest_digest=child_digest, config_digest='sha256:' + 'd' * 64)
    child['findings'][0]['image_digest'] = child_digest
    marker['child_vulnerability_scans'] = [child]
    rows = build_report(safe_observations(metadata_for_report(snapshot, report)['observations']),
        selected=True)['rows']
    assert len(rows) == 1 and rows[0]['image_digest'] == child_digest
    marker['graph']['parent_digest'] = 'sha256:' + 'e' * 64
    assert metadata_for_report(snapshot, report)['observations'] == [None]


@pytest.mark.parametrize('kind,marker_name', [
    ('azure_selected_aks_pod_image_vulnerabilities', 'SelectedAksImage'),
    ('gke_selected_pod_image_vulnerabilities', 'SelectedGkePodImage'),
])
def test_cloud_pod_index_child_keeps_exact_cloud_scope(kind, marker_name):
    snapshot, report, scan = case(kind)
    holder = snapshot['collections'][0]['items'][0][marker_name]['image']
    child_digest = 'sha256:' + 'c' * 64
    holder.update(manifest_digest=DIGEST, status_image_id='registry.example/app@' + DIGEST,
        graph={'parent_digest': DIGEST, 'complete': True, 'children': [
            {'digest': child_digest, 'config_digest': 'sha256:' + 'd' * 64}]})
    child = deepcopy(scan)
    child['image'].update(immutable_reference='registry.example/app@' + child_digest,
        manifest_digest=child_digest, config_digest='sha256:' + 'd' * 64)
    child['findings'][0]['image_digest'] = child_digest
    holder['child_vulnerability_scans'] = [child]
    rows = build_report(safe_observations(metadata_for_report(snapshot, report)['observations']),
        selected=True)['rows']
    assert len(rows) == 1 and rows[0]['image_digest'] == child_digest
    assert rows[0]['scope'] == snapshot['collections'][0]['scope']


def test_native_shaped_scanner_to_tenant_artifact_and_table(tmp_path):
    snapshot, report, scan = case('ecr_public_selected_image_content')
    scan.update(schema='trivy-native-immutable-image-vulnerabilities-20261020-v1',
        cli_version='0.68.1', scanners=['vuln'], package_types=['os', 'library'],
        severities=['HIGH', 'CRITICAL'], scanned_classes=['os-pkgs'],
        production_freshness_certified=False, runtime_image_proven=False,
        diagnostics=[], reason=None, os_end_of_support=False,
        stderr='sensitive-native-diagnostic')
    metadata = metadata_for_report(snapshot, report)
    artifacts = FileArtifacts(tmp_path / 'artifacts')
    manifest = attach_to_manifest({}, artifacts, 'owner', 'a' * 32, metadata)
    reference = manifest['image_vulnerability_scan']['artifact']
    stored = artifacts.get('owner', reference)
    assert 'sensitive-native-diagnostic' not in json.dumps(stored)
    with pytest.raises(ValueError):
        artifacts.get('foreign', reference)
    rows = build_report(stored['observations'], selected=True)['rows']
    assert len(rows) == 1 and rows[0]['affected_assets'][0]['resource_id'] == report['findings'][0]['resource_id']


def test_existing_ecr_native_case_uses_evaluated_resource_identity():
    import peaso
    from peaso.snapshot import resource_id
    cases = Path(os.environ.get('PEASO_SELECTED_CASES_DIR',
        Path(peaso.__file__).resolve().parent / 'checks'))
    fixture = json.loads((cases / 'aws_ecr_public_image_review_20261021_cases.json').read_text())
    check = 'aws.review.ecr_public.selected_image_high_vulnerabilities'
    native = fixture[check]['fail_index']
    collection = native['collections']['ecr_public_selected_image_content'][0]
    scope, item = collection['scope'], collection['items'][0]
    rid = digest(['aws', scope, collection['type'],
        resource_id('aws', collection['type'], scope, item)])
    snapshot = {'provider': 'aws', 'metadata': native['context']['metadata'],
        'collections': [collection]}
    report = {'provider': 'aws', 'findings': [{'provider': 'aws', 'check_id': check,
        'scope': scope, 'resource_id': rid, 'status': 'FAIL'}]}
    before = deepcopy((snapshot, report))
    metadata = metadata_for_report(snapshot, report)
    assert (snapshot, report) == before
    result = build_report(safe_observations(metadata['observations']), selected=True)
    assert len(result['rows']) == 1
    assert result['rows'][0]['affected_assets'][0]['resource_id'] == rid


def test_cold_presentation_import_does_not_load_native_or_analysis():
    import peaso
    import peaso.selected_image_observations_20261021 as module
    root = str(Path(peaso.__file__).resolve().parent.parent)
    candidate = str(Path(module.__file__).resolve().parent)
    code = '''import builtins,sys
sys.path.insert(0, %r)
import peaso
peaso.__path__.insert(0, %r)
old=builtins.__import__
def blocked(name,*args,**kwargs):
    if name.startswith(('peaso.collectors','peaso.checks','peaso.analysis')):
        raise AssertionError(name)
    return old(name,*args,**kwargs)
builtins.__import__=blocked
import peaso.selected_image_observations_20261021
assert not any(k.startswith(('peaso.collectors','peaso.checks','peaso.analysis')) for k in sys.modules)
''' % (root, candidate)
    done = subprocess.run([sys.executable, '-I', '-c', code], capture_output=True, text=True)
    assert done.returncode == 0, done.stderr
