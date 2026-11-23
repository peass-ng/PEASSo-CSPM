from copy import deepcopy
from types import SimpleNamespace
import importlib.abc
import json
import sys

from fastapi import FastAPI, Header, HTTPException
from fastapi.testclient import TestClient
import pytest
from peaso.storage.artifacts import job_prefix

from peaso.server.image_findings_routes import install_routes, SCHEMA, page_report, MAX_PAGE_BYTES
from peaso.image_findings import build_report
from tests.test_peaso_image_findings_20261021 import BASE

SCAN = 'a' * 32
REF = job_prefix('workspace-a', SCAN) + 'detail-' + 'b' * 32 + '.json'


def client(metadata='default', payload=None):
    calls = []
    app = FastAPI()
    def identity(authorization: str | None = Header(default=None)):
        if authorization is None:
            raise HTTPException(401, 'Sign in required')
        return SimpleNamespace(tenant_id=authorization)
    def owned_bundle(tenant, ident):
        calls.append(('job', tenant, ident))
        if tenant != 'workspace-a' or ident != SCAN:
            raise HTTPException(404, 'Scan not found')
        chosen = {'selected': True, 'artifact': REF} if metadata == 'default' else metadata
        return {}, {} if chosen is None else {'image_vulnerability_scan': chosen}
    class Artifacts:
        def get(self, tenant, reference):
            calls.append(('artifact', tenant, reference))
            assert tenant == 'workspace-a' and reference == REF
            return (payload if payload is not None else
                    {'schema': SCHEMA, 'scan_id': SCAN, 'observations': [BASE]})
    install_routes(app, identity=identity, owned_bundle=owned_bundle, artifacts=Artifacts())
    return TestClient(app), calls


def test_owned_scan_finding_and_assets():
    c, calls = client()
    result = c.get(f'/api/scans/{SCAN}/image-findings', headers={'Authorization': 'workspace-a'})
    assert result.status_code == 200
    body = result.json()
    assert body['coverage'] == 'COMPLETE' and body['total'] == 1
    assert body['rows'][0]['affected_asset_count'] == 1
    ident = body['rows'][0]['id']
    assets = c.get(f'/api/scans/{SCAN}/image-findings/{ident}/assets', headers={'Authorization': 'workspace-a'})
    assert assets.status_code == 200
    assert assets.json()['items'][0]['resource_id'] == BASE['asset_id']
    assert all(row[1] == 'workspace-a' for row in calls)


def test_no_auth_or_other_workspace_never_reads_image_artifact():
    c, calls = client()
    assert c.get(f'/api/scans/{SCAN}/image-findings').status_code == 401
    assert calls == []
    assert c.get(f'/api/scans/{SCAN}/image-findings', headers={'Authorization': 'workspace-b'}).status_code == 404
    assert not any(row[0] == 'artifact' for row in calls)


@pytest.mark.parametrize('reference', [
    job_prefix('workspace-b', SCAN) + 'detail-' + 'b' * 32 + '.json',
    job_prefix('workspace-a', 'c' * 32) + 'detail-' + 'b' * 32 + '.json',
    job_prefix('workspace-a', SCAN) + '../../private.json',
])
def test_wrong_tenant_scan_or_path_is_not_read(reference):
    c, calls = client({'selected': True, 'artifact': reference})
    assert c.get(f'/api/scans/{SCAN}/image-findings', headers={'Authorization': 'workspace-a'}).status_code == 409
    assert not any(row[0] == 'artifact' for row in calls)


@pytest.mark.parametrize('payload', [
    {'schema': SCHEMA, 'scan_id': 'c' * 32, 'observations': [BASE]},
    {'schema': 'other', 'scan_id': SCAN, 'observations': [BASE]},
])
def test_artifact_body_must_belong_to_this_scan(payload):
    c, _ = client(payload=payload)
    assert c.get(f'/api/scans/{SCAN}/image-findings', headers={'Authorization': 'workspace-a'}).status_code == 409


def test_legacy_scan_has_not_scanned_state():
    c, calls = client(None)
    body = c.get(f'/api/scans/{SCAN}/image-findings', headers={'Authorization': 'workspace-a'}).json()
    assert body['coverage'] == 'NOT_SCANNED' and not body['complete']
    assert not any(row[0] == 'artifact' for row in calls)


def test_selection_without_results_never_claims_clean():
    c, _ = client(payload={'schema': SCHEMA, 'scan_id': SCAN, 'observations': []})
    body = c.get(f'/api/scans/{SCAN}/image-findings', headers={'Authorization': 'workspace-a'}).json()
    assert body['coverage'] == 'UNKNOWN' and not body['complete']


def test_query_limits_enforced_before_loading():
    c, calls = client()
    for suffix in ('?offset=-1', '?limit=0', '?limit=101'):
        assert c.get(f'/api/scans/{SCAN}/image-findings{suffix}', headers={'Authorization': 'workspace-a'}).status_code == 422
    assert not calls


def test_unknown_finding_assets_are_not_disclosed():
    c, _ = client()
    assert c.get(f'/api/scans/{SCAN}/image-findings/foreign/assets', headers={'Authorization': 'workspace-a'}).status_code == 404


def test_finding_pagination_and_asset_preview_are_explicit():
    observations = []
    for i in range(12):
        o = deepcopy(BASE)
        o['asset_id'] += f'-{i}'
        observations.append(o)
    c, _ = client(payload={'schema': SCHEMA, 'scan_id': SCAN, 'observations': observations})
    page = c.get(f'/api/scans/{SCAN}/image-findings', headers={'Authorization': 'workspace-a'}).json()
    row = page['rows'][0]
    assert row['affected_asset_count'] == 12 and len(row['affected_assets']) == 10 and row['assets_truncated']
    assets = c.get(f'/api/scans/{SCAN}/image-findings/{row["id"]}/assets?limit=5', headers={'Authorization': 'workspace-a'}).json()
    assert assets['total'] == 12 and len(assets['items']) == 5 and assets['next_offset'] == 5
    export = c.get(f'/api/scans/{SCAN}/image-findings?include_assets=true', headers={'Authorization': 'workspace-a'})
    [full] = export.json()['rows']
    assert full['id'] == row['id'] and full['affected_asset_count'] == 12
    assert len(full['affected_assets']) == 12 and not full['assets_truncated']


def test_page_response_bounded_without_silent_missing_rows():
    observations = []
    for i in range(150):
        o = deepcopy(BASE)
        o['scan']['findings'][0]['vulnerability_id'] = f'CVE-2026-{10000+i}'
        observations.append(o)
    report = build_report(observations, selected=True)
    first, second = page_report(report, 0, 100), page_report(report, 100, 100)
    assert first['next_offset'] == 100 and second['next_offset'] is None
    assert len(first['rows']) + len(second['rows']) == first['total'] == 150
    assert len(json.dumps(first).encode()) < MAX_PAGE_BYTES


def test_full_assets_page_respects_byte_limit_and_can_fall_back_to_preview(monkeypatch):
    import peaso.server.image_findings_routes as routes
    report = {'rows': [dict(id=str(i), vulnerability_id='CVE-2026-1234', provider='aws',
                           scope='123/us-east-1', image_digest='image',
                           affected_assets=[{'resource_id': 'x' * 100} for _ in range(count)])
                       for i, count in enumerate((18, 18, 72))]}
    monkeypatch.setattr(routes, 'MAX_PAGE_BYTES', 4000)
    first = page_report(report, 0, 100, include_assets=True)
    second = page_report(report, first['next_offset'], 100, include_assets=True)
    assert first['next_offset'] == 1 and not first['rows'][0]['assets_truncated']
    assert second['next_offset'] is None
    assert not second['rows'][0]['assets_truncated']
    assert second['rows'][1]['assets_truncated'] and second['rows'][1]['affected_asset_count'] == 72
    assert all(len(json.dumps(page).encode()) < 4000 for page in (first, second))


def test_routes_need_no_native_registry_engine_or_analysis_imports():
    import os
    import subprocess
    code = """import importlib.abc, sys
from tests.test_peaso_image_routes_20261021 import client, SCAN
class Block(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname in ('peaso.checks', 'peaso.engine', 'peaso.analysis'):
            raise AssertionError('native boot forbidden')
assert not any(name in sys.modules for name in ('peaso.checks', 'peaso.engine', 'peaso.analysis'))
sys.meta_path.insert(0, Block())
c, _ = client()
r = c.get('/api/scans/' + SCAN + '/image-findings', headers={'Authorization':'workspace-a'})
assert r.status_code == 200, r.text
"""
    result = subprocess.run([sys.executable, '-c', code], cwd=str(__import__('pathlib').Path(__file__).parent),
        env={**os.environ, 'PYTHONPATH': os.pathsep.join(sys.path), 'PYTHONDONTWRITEBYTECODE':'1'},
        capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr


def test_sidebar_totals_count_distinct_cves_and_images_before_pagination():
    report = {'rows': [dict(id=str(n), vulnerability_id='CVE-2026-1000' if n < 2 else 'CVE-2026-1001',
                           provider='aws', scope='123/us-east-1', image_digest='image-' + str(n % 2),
                           affected_assets=[]) for n in range(3)]}
    first = page_report(report, 0, 1)
    assert first['total'] == 3
    assert first['vulnerability_count'] == 2
    assert first['image_count'] == 2
    assert len(first['rows']) == 1
