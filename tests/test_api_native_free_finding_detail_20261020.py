"""Authenticated archived finding views stay presentation-only on cold start."""
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
PROBE = r'''
import copy, importlib.abc, json, sys, tempfile
from pathlib import Path

class RejectNative(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname in ('peaso.checks', 'peaso.engine', 'peaso.analysis', 'peaso.collectors', 'peaso.check_services') or fullname.startswith(('peaso.checks.', 'peaso.analysis.', 'peaso.collectors.')):
            raise AssertionError('presentation initialized native runtime: ' + fullname)
sys.meta_path.insert(0, RejectNative())

from fastapi import HTTPException
from fastapi.testclient import TestClient
from peaso.auth import Identity
from peaso.server.app import create_app
from peaso.server.config import Settings
from peaso.server.materialized_catalog import description_for
from peaso.storage import SQLiteStore, FileArtifacts

class Auth:
    def authenticate(self, authorization):
        if authorization in ('Bearer alice', 'Bearer bob'):
            return Identity(authorization[7:])
        raise HTTPException(401, 'Invalid authentication')

with tempfile.TemporaryDirectory(prefix='peaso-detail-proof-') as temporary:
    root = Path(temporary)
    settings = Settings(state_dir=root/'state', identity_dir=root/'identity',
                        local_token='isolated-detail-proof-token-0123456789')
    store = SQLiteStore(settings.state_dir)
    artifacts = FileArtifacts(root/'artifacts')
    app = create_app(settings, store=store, artifacts=artifacts, authenticator=Auth())
    cases = [
        ('aws.iam.root_mfa', 'aws', {'AccountMFAEnabled': 0}),
        ('aws.claude_a.iam.root_console_has_mfa', 'aws', {'password_present': 0, 'mfa_enabled': 0}),
        ('aws.a.iam.root_summary_no_keys', 'aws', {'account_access_keys_present': 0}),
        ('gcp.ports.compute_instance_ip_forwarding_disabled', 'gcp', {'canIpForward': True}),
        ('analysis.internet_exposure', 'aws', {'exposure_kind': 'network', 'exposed_ports': [443]}),
        ('analysis.federated_trust', 'aws', {'federated_trusts': [{
            'issuer': 'token.actions.githubusercontent.com',
            'federated_principal': 'arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com',
            'conditions': {'StringEquals': {'token.actions.githubusercontent.com:aud': 'sts.amazonaws.com'}},
            'problems': [{'code': 'no_sub_condition'}],
        }]}),
    ]
    findings = []
    for index, (cid, provider, evidence) in enumerate(cases):
        finding = dict(id='f'+str(index), check_id=cid, provider=provider, scope='123456789012/us-east-1',
            category='exposure' if cid.startswith('analysis.') else 'hardening',
            service='iam', resource_id='fixture-'+str(index), severity='high', title='Fixture',
            frameworks=[], status='FAIL', evidence=evidence, remediation='Archived remediation')
        metadata = description_for(cid)
        if metadata:
            finding.update({key: copy.deepcopy(metadata[key]) for key in
                ('description','evaluated','pass_when','fail_when','not_applicable_when') if key in metadata})
        findings.append(finding)
    original = copy.deepcopy(findings)
    connector = store.add_connector('alice', {'provider': 'aws'}, 'encrypted')
    job = store.enqueue('alice', {'connector_id': connector['id']})
    report = dict(schema_version='1.0', snapshot_id='fixture', provider='aws', scopes=[],
                  findings=findings, coverage=[], resources=[], graphs={}, stats={},
                  remediation_templates={row['check_id']: {'cli': [{'code': 'inspect <ACCOUNT_ID>'}]} for row in findings})
    reference = artifacts.put('alice', job['id'], 'report', report)
    with store.transaction() as db:
        db.execute("UPDATE jobs SET status='completed',report=? WHERE id=?", (reference, job['id']))
    with TestClient(app, base_url='http://127.0.0.1:8000') as client:
        client.headers['Authorization'] = 'Bearer alice'
        # This must be the first cold request: a previous graph/native import
        # used to hide check_services -> analysis -> collectors -> azure's cycle.
        prefix = '/api/scans/'+job['id']
        response = client.get(prefix+'/findings?aggregation=check&categories=hardening')
        assert response.status_code == 200, response.text
        grouped = response.json()
        assert grouped['total'] == 4
        root_group = next(item for item in grouped['items'] if item['check_id'] == 'aws.iam.root_mfa')
        assert root_group['service'] == 'iam'
        assert root_group['affected_regions'] == []
        assert root_group['affected_scopes'] == []
        assert root_group['observed_scopes'] == ['123456789012/global']
        response = client.get(prefix+'/finding-groups/'+root_group['id'])
        assert response.status_code == 200, response.text
        assert response.json()['evidence'] == findings[0]['evidence']
        assert response.json()['members'][0]['id'] == findings[0]['id']
        for suffix in ('/findings?categories=hardening', '/summary?aggregation=check',
                       '/report?aggregation=check'):
            response = client.get(prefix+suffix)
            assert response.status_code == 200, (suffix, response.text)
        for expected in findings:
            response = client.get('/api/scans/'+job['id']+'/findings/'+expected['id'])
            assert response.status_code == 200, response.text
            actual = response.json()
            assert actual['id'] == expected['id']
            assert actual['status'] == expected['status']
            assert actual['evidence'] == expected['evidence']
            if expected['check_id'] == 'analysis.federated_trust':
                assert 'does not restrict which token subjects' in actual['evidence_summary']
            if expected['provider'] == 'aws':
                assert actual['remediation_details']['cli'][0]['code'] == 'inspect 123456789012'
        client.headers['Authorization'] = 'Bearer bob'
        assert client.get('/api/scans/'+job['id']+'/findings/f0').status_code == 404
        assert client.get(prefix+'/findings?aggregation=check').status_code == 404
        assert client.get(prefix+'/finding-groups/'+root_group['id']).status_code == 404
    assert findings == original
assert not [name for name in sys.modules if name in ('peaso.checks', 'peaso.engine', 'peaso.analysis', 'peaso.collectors', 'peaso.check_services') or name.startswith(('peaso.checks.', 'peaso.analysis.', 'peaso.collectors.'))]
print('native-free authenticated detail, evidence conservation and tenant isolation passed')
'''


def test_cold_authenticated_detail_does_not_initialize_native_checks():
    result = subprocess.run([sys.executable, '-c', PROBE], cwd=ROOT,
                            capture_output=True, text=True, timeout=60)
    assert result.returncode == 0, result.stdout + result.stderr

