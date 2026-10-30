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
        '5929c09d6c94d627b7df2db8e50a2cee3ef9580f1c30da4c4e3c981f01d4d0a2',
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

        slot_singletons = {module.SLOT + '/config/authsettingsV2': ('config/authsettingsV2', '2025-05-01'),
                           module.SLOT + '/config/web': ('config/web', '2023-12-01')}
        functions = module.SITE + '/functions'
        scale_set = module.ENDPOINTS['vm_scale_set'][2]
        scale_set_children = (scale_set + '/networkInterfaces', scale_set + '/publicipaddresses')

        def request_current(self, url, *, body=None, audience=module.azure.ARM):
            parsed = urlsplit(url)
            # Current read-only child LISTs: Function HTTP trigger envelopes for a
            # function-kind site and VMSS instance NIC/public IP inventories. The
            # sealed fixtures declare no functions and no scale-set instances.
            if ((parsed.path == functions and self.kind == 'app_service'
                 and 'functionapp' in str(self.obj.get('kind', '')).split(','))
                    or (parsed.path in scale_set_children and self.kind == 'vm_scale_set')):
                assert parsed.scheme == 'https' and parsed.netloc == 'management.azure.com'
                assert body is None and audience == module.azure.ARM
                assert parse_qs(parsed.query) == {'api-version': [
                    '2025-05-01' if parsed.path == functions else '2018-10-01']}
                self.calls.append({'method': 'GET', 'url': url, 'body': None})
                return {'value': []}
            if self.cid == 'azure.claude2.web_app_slot_https_only' and parsed.path in slot_singletons:
                # Current slot singleton GETs mirror the reviewed parent-site DTO.
                suffix, version = slot_singletons[parsed.path]
                assert parsed.scheme == 'https' and parsed.netloc == 'management.azure.com'
                assert body is None and audience == module.azure.ARM
                assert parse_qs(parsed.query) == {'api-version': [version]}
                self.calls.append({'method': 'GET', 'url': url, 'body': None})
                slot_config = deepcopy(self.children[module.SITE + '/' + suffix])
                slot_config['id'] = parsed.path
                slot_config['type'] = 'Microsoft.Web/sites/slots/config'
                return slot_config
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
