"""A detector-found secret reaches the owning tenant's finding detail in clear text.

The value travels: collector detector -> encrypted private store -> authorized
detail API. Other tenants get 404, the private store holds only ciphertext and
the scanner's own connector credential stays redacted.
"""
import json
import multiprocessing
import secrets

from fastapi import HTTPException
from fastapi.testclient import TestClient

from peaso import secret_scanning as scanning
from peaso.auth import Identity
from peaso.secret_evidence import private_reference, source_context
from peaso.server import create_app
from peaso.server.config import Settings

ARN = 'arn:aws:lambda:us-east-1:123456789012:function:fixture'
SCOPE = '123456789012/us-east-1'


class Identities:
    def authenticate(self, authorization):
        if authorization == 'Bearer alice':
            return Identity('alice')
        if authorization == 'Bearer bob':
            return Identity('bob')
        raise HTTPException(401)


def test_detector_secret_is_clear_text_for_owner_only(tmp_path, monkeypatch):
    secret = 'synthetic-detector-value-' + secrets.token_hex(8)
    credential = 'synthetic-connector-credential-' + secrets.token_hex(8)
    settings = Settings(state_dir=tmp_path / 'state', identity_dir=tmp_path / 'identity')
    app = create_app(settings, authenticator=Identities())
    store, artifacts = app.state.store, app.state.artifacts
    connector = store.add_connector('alice', {'provider': 'aws', 'name': 'fixture'}, 'not-needed')
    job = store.enqueue('alice', {'connector_id': connector['id']})
    ident = job['id']

    # Hermetic detector: one engine reports the value, the other runs clean.
    monkeypatch.setattr(scanning, '_scan_kingfisher', lambda payload, path, timeout:
                        [(secret, 'synthetic', 1)] if secret.encode() in payload else [])
    monkeypatch.setattr(scanning, '_scan_trufflehog', lambda payload, path, timeout: scanning._DetectorMatches())

    def collect(_):
        from peaso.snapshot import make_snapshot
        with source_context(resource_id=ARN, scope=SCOPE, path='code/app.env'):
            outcome = scanning.scan_content(b'API_KEY=' + secret.encode() + b'\n', 'code/app.env')
        return make_snapshot('aws', [SCOPE], [{
            'type': 'lambda_function', 'scope': SCOPE, 'status': 'collected',
            'items': [{'Arn': ARN, 'FunctionName': 'fixture', 'note': credential,
                       'secret_leaks': outcome['leaks']}]}])

    monkeypatch.setattr('peaso.engine.collect_snapshot', collect)
    from peaso.worker import _process
    request = {'artifact_config': {'mode': 'file', 'root': str(artifacts.root)}, 'tenant_id': 'alice', 'scan_id': ident,
               'connector': {'provider': 'aws', 'auth': {'access_key_id': 'AKIAFIXTURE', 'secret_access_key': credential},
                             'input_mode': 'offline_snapshot'},
               'ai_enabled': False, 'ai_context': {'identity_dir': str(settings.identity_dir)}}
    context = multiprocessing.get_context('fork')
    parent, child = context.Pipe(duplex=False)
    process = context.Process(target=_process, args=('collector', request, child))
    try:
        process.start()
        child.close()
        while True:
            # Metrics and checkpoints precede the final (success, reference) reply.
            assert parent.poll(30)
            message = parent.recv()
            if isinstance(message, tuple) and isinstance(message[0], bool):
                break
        success, reference, *rest = message
        assert success, rest
    finally:
        process.join(timeout=3)
        if process.is_alive():
            process.kill()
            process.join()
        parent.close()

    snapshot = artifacts.get('alice', reference)
    item = next(row for rows in snapshot['collections'] for row in rows.get('items', []))
    # The scanner's own credential never reaches published output.
    assert credential not in json.dumps(snapshot)
    leaks = item['secret_leaks']
    fingerprint = leaks[0]['fingerprint']
    # Encrypted at rest: the private store file holds only ciphertext.
    private_file = artifacts.root / private_reference('alice', ident)
    assert secret.encode() not in private_file.read_bytes()
    assert credential.encode() not in private_file.read_bytes()

    row = store.claim('collector', tenant='alice', ident=ident)
    assert store.finish(ident, row['owner'], 'collected', reference)
    row = store.claim('analyzer', tenant='alice', ident=ident)
    found = {'id': 'secret-' + fingerprint, 'check_id': 'fixture.detected_secret', 'provider': 'aws',
             'status': 'FAIL', 'finding_type': 'secrets', 'scope': SCOPE, 'resource_id': ARN,
             'native_resource_id': ARN, 'secret_fingerprint': fingerprint, 'category': 'hardening',
             'severity': 'high', 'title': 'Detected secret', 'frameworks': [],
             'evidence': {'secret_leaks': leaks}}
    report = {'provider': 'aws', 'schema_version': '1.0', 'snapshot_id': 'fixture', 'stats': {}, 'graphs': {},
              'resources': [], 'coverage': [], 'ai': {'status': 'not_requested'}, 'findings': [found]}
    assert store.finish(ident, row['owner'], 'completed', artifacts.put('alice', ident, 'report', report))

    with TestClient(app, base_url='http://127.0.0.1:8000', headers={'Authorization': 'Bearer alice'}) as client:
        detail = client.get(f'/api/scans/{ident}/findings/secret-{fingerprint}')
        assert detail.status_code == 200, detail.text
        private = detail.json()['secret_evidence']
        assert private['status'] == 'available'
        # The real value, not a mask, alias or fingerprint.
        assert [match['value'] for match in private['matches']] == [secret]
        assert private['matches'][0]['locations'][0]['resource_id'] == ARN
        assert detail.headers['cache-control'] == 'private, no-store'
        assert credential not in detail.text
        client.headers['Authorization'] = 'Bearer bob'
        assert client.get(f'/api/scans/{ident}/findings/secret-{fingerprint}').status_code == 404
