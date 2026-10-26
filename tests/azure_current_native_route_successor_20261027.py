"""Admit current Azure read routes beside sealed 2026-10-20 native tests.

The dated test and review bytes stay exact. Only the additional, read-only
route requested by the current collector is supplied; the original fake still
handles every reviewed route and all verdict assertions.
"""
from __future__ import annotations

from copy import deepcopy
import hashlib
import io
import json
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import pytest


ROOT = Path(__file__).resolve().parents[1]
SEALED = {
    'test_azure_application_compute_2_native_review_20261020.py': (
        'c8d3e7743ea35a58ae696d25060ca27c2a372d50a7dc4b31a3b8c612ad745e38',
        'docs/check-review/azure-application-compute-2-native-review-20261020.json',
        '45b25d2087ce77a7e3ee04bfae6ed730427517a26c40ea4a0176c3703c3d4baa',
    ),
    'test_azure_database_crypto_backup_2_native_review_20261020.py': (
        '0fde706645565bbbb5d49a139a627b38acbb8459b76f9a03f122e896c678dc51',
        'docs/check-review/azure-database-crypto-backup-2-native-review-20261020.json',
        'b5c3191167742b2b389c9889885b3b5f29c57fc54c8438f2f4ca3c47cbcf137b',
    ),
}


def _sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


@pytest.fixture(autouse=True)
def _current_azure_native_auxiliary_routes(request):
    module = request.module
    name = Path(getattr(module, '__file__', '')).name
    if name not in SEALED:
        return
    test_sha, review_path, review_sha = SEALED[name]
    assert Path(module.__file__).resolve() == ROOT / 'tests' / name
    assert _sha(ROOT / 'tests' / name) == test_sha
    assert _sha(ROOT / review_path) == review_sha
    monkeypatch = request.getfixturevalue('monkeypatch')

    if name == 'test_azure_application_compute_2_native_review_20261020.py':
        original = module.NativeHTTP.request
        route = module.SLOT + '/basicPublishingCredentialsPolicies/scm'
        diagnostics = module.SLOT + '/providers/Microsoft.Insights/diagnosticSettings'

        def request_current(self, url, *, body=None, audience=module.azure.ARM):
            parsed = urlsplit(url)
            if self.cid == 'azure.claude2.web_app_slot_https_only' and parsed.path in (route, diagnostics):
                assert parsed.scheme == 'https' and parsed.netloc == 'management.azure.com'
                assert body is None and audience == module.azure.ARM
                assert parse_qs(parsed.query) == {'api-version': [
                    '2023-12-01' if parsed.path == route else '2021-05-01-preview']}
                self.calls.append({'method': 'GET', 'url': url, 'body': None})
                if parsed.path == diagnostics:
                    return {'value': []}
                site_policy = self.children[module.SITE + '/basicPublishingCredentialsPolicies/scm']
                slot_policy = deepcopy(site_policy)
                slot_policy['id'] = route
                slot_policy['name'] = 'scm'
                slot_policy['type'] = 'Microsoft.Web/sites/slots/basicPublishingCredentialsPolicies'
                return slot_policy
            return original(self, url, body=body, audience=audience)

        monkeypatch.setattr(module.NativeHTTP, 'request', request_current)
        return

    original = module.NativeHTTP._open

    def open_current(self, request, timeout):
        parsed = urlsplit(request.full_url)
        route = self.d['rid'] + '/azureADOnlyAuthentications'
        current_app_inventory = {module.SCOPE + '/providers/Microsoft.App/' + segment
                                 for segment in ('jobs', 'managedEnvironments', 'containerApps')}
        if parsed.path in current_app_inventory and parse_qs(parsed.query) == {'api-version': ['2025-07-01']}:
            assert parsed.scheme == 'https' and parsed.netloc == 'management.azure.com'
            assert request.get_method() == 'GET' and request.data is None and timeout == 20
            self.calls.append({'method': 'GET', 'host': parsed.netloc, 'path': parsed.path,
                               'query': {'api-version': ['2025-07-01']}})
            return io.BytesIO(b'{"value": []}')
        if (self.d['parentkind'] == 'sql_server'
                and self.mode in {'positive', 'negative', 'missing', 'malformed',
                                  'parent_partial', 'child_partial'}
                and parsed.path == route):
            assert parsed.scheme == 'https' and parsed.netloc == 'management.azure.com'
            assert request.get_method() == 'GET' and request.data is None and timeout == 20
            query = parse_qs(parsed.query)
            assert query == {'api-version': ['2023-08-01']}
            self.calls.append({'method': 'GET', 'host': parsed.netloc, 'path': route, 'query': query})
            admins = self.d.get('admins')
            rows = []
            if isinstance(admins, list) and admins and isinstance(admins[0], dict):
                properties = admins[0].get('properties')
                value = properties.get('azureADOnlyAuthentication') if isinstance(properties, dict) else None
                rows = [{'id': route + '/Default', 'name': 'Default',
                         'type': 'Microsoft.Sql/servers/azureADOnlyAuthentications',
                         'properties': {'azureADOnlyAuthentication': value}}]
            return io.BytesIO(json.dumps({'value': rows}).encode())
        return original(self, request, timeout)

    monkeypatch.setattr(module.NativeHTTP, '_open', open_current)
