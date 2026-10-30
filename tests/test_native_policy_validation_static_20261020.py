"""Trusted native parity, immutable predecessor and actual hosted cold routes."""
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest
from peaso.server import native_policy_validation_static_20261020 as successor

ROOT = Path(__file__).resolve().parents[1]
PREDECESSOR_SHA256 = 'c84159d8cc96b092aeea28db399c31a6c7b09bff90502e9b3e76cb2bb79791bd'


def result(function, value, module, scoped=False):
    try:
        function(value, module, individually_scoped=scoped)
    except Exception as error:
        return [type(error).__name__, str(error)]
    return None


def cases(roster):
    # Every finite manifest ID against every module detects both accidental
    # unions and accidental subsets; only the exact source_module may accept.
    all_ids = sorted(set().union(*roster.values()))
    for module in sorted(roster):
        for cid in all_ids + ['unreviewed.invalid', 'azure.storage.https_only']:
            yield [{cid: {}}, module, False]
        cid = sorted(roster[module])[0]
        for value in (None, False, True, 0, 1, '', 'x', [], {}, [1], {cid: None}, {cid: []}, {cid: 1},
                      {cid: {'nested': [None, True, 1, 0.5, 'normative']}}, {cid: {'x': 'y' * 8193}},
                      {cid: {'x': '\x00'}}, {cid: {'x': [1] * 257}},
                      {cid: {'x' * 257: 'bad-key'}}, {cid: {str(i): 0 for i in range(257)}}):
            yield [value, module, False]
        for scope in ('/subscriptions/customer', '/tenants/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee',
                      '/subscriptions/' + 'x' * 128, '/subscriptions/' + 'x' * 129, '*', '', None, 0):
            for status in ('collected', 'missing', None, True):
                yield [{cid: {'status': status, 'scope': scope}}, module, True]
        for value in ({cid: {}}, {cid: {'scope': '/subscriptions/customer'}},
                      {cid: {'status': 'collected'}}, {cid: []}):
            yield [value, module, True]
        nested = {}
        for _ in range(16):
            nested = {'x': nested}
        yield [{cid: nested}, module, False]
    yield [{'unreviewed.invalid': {}}, 'unknown-module', False]




@pytest.mark.parametrize('mode', ['missing', 'corrupt', 'oversized'])
def test_roster_fails_closed_without_native_fallback(tmp_path, monkeypatch, mode):
    path = tmp_path / 'bulk_pending.json'
    if mode == 'corrupt':
        path.write_text('{}')
    elif mode == 'oversized':
        path.write_bytes(b' ' * (successor.MAX_MANIFEST_BYTES + 1))
    successor.module_ids.cache_clear()
    monkeypatch.setattr(successor, 'MANIFEST_PATH', path)
    try:
        with pytest.raises(ValueError):
            successor.module_ids()
    finally:
        successor.module_ids.cache_clear()


def test_real_hosted_post_patch_all_ids_without_native_registry_imports():
    proof = subprocess.run([sys.executable, str(Path(__file__).with_name('probe_connector_static_20261020.py'))],
                           cwd=ROOT, capture_output=True, text=True, timeout=180,
                           env=dict(os.environ, PYTHONDONTWRITEBYTECODE='1'))
    assert proof.returncode == 0, proof.stderr
    evidence = json.loads(proof.stdout)
    assert evidence['native_modules_loaded'] == []
    assert evidence['network_attempts'] == 0
    assert evidence['auth_mode'] == 'cognito'
    assert evidence['exact_owner_fixture']
    assert evidence['owner_check_review_map_calls'] == 2


def test_native_registrar_still_admits_every_manifest_id_after_api_rebinding():
    code = '''
import json, tempfile
from pathlib import Path
from peaso.auth import Identity
from peaso.server.app import create_app
from peaso.server.config import Settings
class OfflineIdentity:
    def authenticate(self, authorization):
        return Identity('same-process-native-admission', True)
with tempfile.TemporaryDirectory(prefix='peaso-api-native-parity-') as temporary:
    directory = Path(temporary)
    create_app(Settings(state_dir=directory/'state', identity_dir=directory/'identity',
                        auth_mode='cognito'), authenticator=OfflineIdentity())
    from peaso.checks import CHECKS
    from peaso.checks.bulk_pending import MANIFEST
    from peaso.server import native_policy_validation
    from peaso.server.native_policy_validation_static_20261020 import check_review_map
    assert native_policy_validation._check_review_map is check_review_map
    assert set(MANIFEST['checks']) <= {check.id for check in CHECKS}
    print(json.dumps({'registered_checks': len(CHECKS), 'bulk_checks': len(MANIFEST['checks'])}))
'''
    native = subprocess.run([sys.executable, '-c', code], cwd=ROOT, capture_output=True, text=True,
                            timeout=180, env=dict(os.environ, PYTHONDONTWRITEBYTECODE='1',
                                                  PEASO_STORAGE='sqlite', AWS_EC2_METADATA_DISABLED='true'))
    assert native.returncode == 0, native.stderr
