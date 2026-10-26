"""Owned details and fresh CLI exports; no live credentials or network."""
import copy
import json
import multiprocessing

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient
from peaso.auth import CredentialCipher, Identity
from peaso.secret_evidence import capture, named_environment, private_reference
from peaso.server import create_app
from peaso.server.config import Settings
from peaso.storage import FileArtifacts
from tests.test_private_secret_evidence import VALUE, ARN, finding


class Identities:
    def authenticate(self, authorization):
        if authorization == 'Bearer alice': return Identity('alice')
        if authorization == 'Bearer key': return Identity('alice', auth_kind='api_key')
        if authorization == 'Bearer bob': return Identity('bob')
        raise HTTPException(401)


@pytest.fixture
def owned(tmp_path):
    settings = Settings(state_dir=tmp_path / 'state', identity_dir=tmp_path / 'identity')
    app = create_app(settings, authenticator=Identities())
    store, artifacts = app.state.store, app.state.artifacts
    connector = store.add_connector('alice', {'provider': 'aws', 'name': 'fixture'}, 'not-needed')
    job = store.enqueue('alice', {'connector_id': connector['id']})
    row = store.claim('collector', tenant='alice', ident=job['id'])
    assert store.finish(job['id'], row['owner'], 'collected', artifacts.put('alice', job['id'], 'snapshot', {}))
    row = store.claim('analyzer', tenant='alice', ident=job['id'])
    report = {'provider': 'aws', 'schema_version': '1.0', 'snapshot_id': 'fixture', 'stats': {}, 'graphs': {},
              'resources': [], 'coverage': [], 'ai': {'status': 'not_requested'},
              'findings': [finding(category='hardening', severity='high', title='Secret setting', frameworks=[])]}
    ref = artifacts.put('alice', job['id'], 'report', report)
    assert store.finish(job['id'], row['owner'], 'completed', ref)
    cipher = CredentialCipher(settings.identity_dir)
    with capture(cipher, tenant='alice', scan_id=job['id']) as sink:
        named_environment({'Variables': {'DB_PASSWORD': VALUE}}, provider='aws', resource_id=ARN)
    artifacts.put_secret_evidence('alice', job['id'], sink.document())
    with TestClient(app, base_url='http://127.0.0.1:8000', headers={'Authorization': 'Bearer alice'}) as client:
        yield client, job['id'], report, settings


def test_authorized_detail_only_full_values_and_no_log_or_public_artifact(owned, caplog):
    client, ident, report, settings = owned
    url = f'/api/scans/{ident}'
    detail = client.get(url + '/findings/secret-legacy')
    assert detail.status_code == 200, detail.text
    assert detail.json()['secret_evidence']['matches'][0]['value'] == VALUE
    assert detail.headers['cache-control'] == 'private, no-store'
    assert detail.headers['pragma'] == 'no-cache'
    for suffix in ('/findings', '/report', '/ai', '/summary'):
        reply = client.get(url + suffix)
        assert reply.status_code == 200, (suffix, reply.text)
        assert VALUE not in reply.text
    assert VALUE not in caplog.text
    for path in settings.state_dir.rglob('*'):
        if path.is_file(): assert VALUE.encode() not in path.read_bytes(), str(path)
    client.headers['Authorization'] = 'Bearer key'
    keyed = client.get(url + '/findings/secret-legacy')
    assert keyed.status_code == 200
    assert keyed.json()['secret_evidence']['matches'][0]['value'] == VALUE
    assert VALUE not in client.get(url + '/findings').text
    client.headers['Authorization'] = 'Bearer bob'
    assert client.get(url + '/findings/secret-legacy').status_code == 404
    assert client.get(url + '/findings').status_code == 404


def test_historic_detail_honestly_unavailable_and_metadata_only_never_invents(owned):
    client, ident, report, settings = owned
    app = client.app
    ref = private_reference('alice', ident)
    (app.state.artifacts.root / ref).unlink()
    detail = client.get(f'/api/scans/{ident}/findings/secret-legacy').json()
    assert detail['secret_evidence']['status'] == 'unavailable'
    assert 'fresh scan' in detail['secret_evidence']['message']
    assert detail['secret_evidence']['matches'] == []


def test_large_public_detail_envelope_keeps_raw_values_out_of_download(owned, monkeypatch):
    client, ident, report, _ = owned
    artifacts = client.app.state.artifacts
    safe = report['findings'][0]
    detail_ref = artifacts.put('alice', ident, 'detail', safe)
    new = copy.deepcopy(report)
    new['findings'][0]['_detail_reference'] = detail_ref
    row = client.app.state.store.job('alice', ident)
    new_ref = artifacts.put('alice', ident, 'report', new)
    client.app.state.store.replace_completed_report('alice', ident, row['report'], new_ref)
    monkeypatch.setattr(artifacts, 'presign', lambda *args: 'https://artifact.invalid/public-detail', raising=False)
    reply = client.get(f'/api/scans/{ident}/findings/secret-legacy')
    assert reply.status_code == 200, reply.text
    assert reply.json()['secret_evidence']['matches'][0]['value'] == VALUE
    assert reply.json()['download_url'].startswith('https://')
    assert VALUE not in json.dumps(artifacts.get('alice', detail_ref))


def test_worker_private_persistence_and_ai_input_exclusion(tmp_path, monkeypatch):
    from peaso.worker import _process
    from peaso.snapshot import make_snapshot
    from peaso.ai.pipeline import findings_document
    artifacts = FileArtifacts(tmp_path / 'artifacts')
    identity_dir = tmp_path / 'identity'
    ident = 'a' * 32
    def collect(_):
        named_environment({'Variables': {'DB_PASSWORD': VALUE}}, provider='aws', resource_id=ARN)
        return make_snapshot('aws', ['123456789012/us-east-1'], [
            {'type': 'lambda_function', 'scope': '123456789012/us-east-1', 'status': 'collected',
             'items': [{'Arn': ARN, 'FunctionName': 'fixture', 'note': VALUE, 'labels': {VALUE: VALUE}, 'EnvironmentVariableNames': {'collection_status': 'collected', 'names': ['DB_PASSWORD']}}]}])
    monkeypatch.setattr('peaso.engine.collect_snapshot', collect)
    context = multiprocessing.get_context('fork'); parent, child = context.Pipe(duplex=False)
    request = {'artifact_config': {'mode': 'file', 'root': str(artifacts.root)}, 'tenant_id': 'alice', 'scan_id': ident,
               'connector': {'provider': 'aws', 'auth': {}, 'input_mode': 'offline_snapshot'}, 'ai_enabled': False, 'ai_context': {'identity_dir': str(identity_dir)}}
    process = context.Process(target=_process, args=('collector', request, child))
    try:
        process.start(); child.close()
        while True:
            # Metrics and checkpoints precede the final (success, reference) reply.
            assert parent.poll(15)
            message = parent.recv()
            if isinstance(message, tuple) and isinstance(message[0], bool):
                break
        success, reference, *rest = message; assert success, rest
        snapshot = artifacts.get('alice', reference)
        # Found values stay as collected in the snapshot; the private store adds the match record.
        assert VALUE in json.dumps(snapshot)
        private_file = artifacts.root / private_reference('alice', ident)
        assert VALUE.encode() not in private_file.read_bytes()  # encrypted at rest
        from peaso.secret_evidence import load_details
        detail = load_details(artifacts, CredentialCipher(identity_dir), 'alice', ident, finding())
        assert detail['matches'][0]['value'] == VALUE
        safe_finding = finding(category='hardening')
        assert VALUE not in json.dumps(findings_document({'provider': 'aws'}, [safe_finding]))
        from peaso.ai.pipeline import private_json
        raw_path = tmp_path / 'ai-input.json'
        private_json(raw_path, {'items': [dict(safe_finding, secret_evidence=detail)]})
        assert VALUE not in raw_path.read_text()
        assert 'secret-evidence' not in json.dumps(snapshot)
    finally:
        process.join(timeout=3)
        if process.is_alive(): process.kill(); process.join()
        parent.close()


def test_cli_owned_json_is_explicit_private_0600_and_generic_outputs_stay_redacted(tmp_path, monkeypatch, capsys):
    from peaso import cli
    from peaso.snapshot import make_snapshot
    check = 'aws.htbp.lambda.env_var_names_not_credentials'
    def collect(_):
        named_environment({'Variables': {'DB_PASSWORD': VALUE}}, provider='aws', resource_id=ARN)
        return make_snapshot('aws', ['123456789012/us-east-1'], [{'type': 'lambda_function',
            'scope': '123456789012/us-east-1', 'status': 'collected', 'items': [{'Arn': ARN,
                'FunctionName': 'fixture', 'note': VALUE,
                'EnvironmentVariableNames': {'collection_status': 'collected', 'names': ['DB_PASSWORD']}}]}])
    monkeypatch.setattr(cli, 'collect_snapshot', collect)
    owned_file, snapshot_file = tmp_path / 'private.json', tmp_path / 'snapshot.json'
    args = ['scan', '--provider', 'aws', '--quiet', '--checks', check, '--include-secret-values', '--output', str(owned_file), '--snapshot-output', str(snapshot_file)]
    assert cli.main(args) == 0
    result = json.loads(owned_file.read_text())
    observed = next(row for row in result['findings'] if row['check_id'] == check)
    assert observed['status'] == 'FAIL'
    assert observed['observations'][0]['secret_evidence']['matches'][0]['value'] == VALUE
    assert owned_file.stat().st_mode & 0o777 == 0o600
    # The snapshot keeps the found value as collected; only the private file carries the match record.
    assert VALUE in snapshot_file.read_text()
    assert VALUE not in str(capsys.readouterr())
    cli._write(result, None, 'json')
    assert VALUE not in str(capsys.readouterr())
    assert cli.main(['scan', '--provider', 'aws', '--quiet', '--checks', check]) == 0
    assert VALUE not in str(capsys.readouterr())
    for tail in ([], ['--format', 'markdown', '--output', str(owned_file)]):
        with pytest.raises(SystemExit) as rejected:
            cli.main(['scan', '--provider', 'aws', '--include-secret-values', *tail])
        assert rejected.value.code == 2


def test_published_reports_and_ai_files_strip_private_details(owned, tmp_path):
    from peaso.storage.reports import publish_report
    from peaso.ai.pipeline import private_json
    client, ident, report, _ = owned
    dirty = copy.deepcopy(report)
    dirty['findings'][0]['secret_evidence'] = {'status': 'available', 'matches': [{'value': VALUE}]}
    dirty['findings'][0]['evidence']['nested'] = {'secret_evidence': {'value': VALUE}}
    artifacts = client.app.state.artifacts
    manifest_ref = publish_report(artifacts, 'alice', ident, dirty)
    manifest = artifacts.get('alice', manifest_ref)
    assert VALUE not in json.dumps(manifest)
    assert VALUE not in json.dumps(artifacts.get('alice', manifest['report_json']))
    assert VALUE not in artifacts.get_text('alice', manifest['report_markdown'])
    path = tmp_path / 'ai.json'
    private_json(path, dirty)
    assert VALUE not in path.read_text()
    assert VALUE in json.dumps(dirty)  # API detail memory is not mutated.


@pytest.mark.parametrize('encoded', [False, True])
def test_owned_cli_json_retains_complete_pair_and_components_under_one_public_fingerprint(tmp_path, capsys, encoded):
    import base64
    from peaso import cli, secret_evidence as evidence, secret_scanning as scanning
    access, secret = 'AKIA' + '7MQ2ZR9WL4CV8NK1', '7mQ2zR9wL4cV8nK1sF6aH3jP5uD0xB2yE9rT1vW8'
    fp = scanning._fingerprint(access)
    payload = (access + '\n' + secret).encode()
    if encoded:
        payload = base64.b64encode(payload)
    with capture(evidence.EphemeralCipher()) as sink:
        with evidence.source_context(resource_id=ARN, path='/app/config.env'):
            evidence.remember_full_match(access, access + ':' + secret, payload=payload, path='/app/config.env', engine='trufflehog', rule='AWS')
            evidence.remember(access, fp, path='/app/config.env', line=None if encoded else 1, engine='trufflehog', rule='AWS', observed_bytes=not encoded)
    report = {'provider': 'aws', 'findings': [finding(fp, category='hardening', severity='high', frameworks=[])]}
    private = evidence.export_report(report, sink)
    path = tmp_path / 'owned-pair.json'
    cli._write(private, path, 'json', include_private=True)
    exported = json.loads(path.read_text())['findings'][0]
    assert exported['secret_fingerprint'] == fp
    assert {m['value'] for m in exported['secret_evidence']['matches']} == ({access, access + ':' + secret} if encoded else {access, secret, access + ':' + secret})
    if encoded:
        for match in exported['secret_evidence']['matches']:
            assert match['locations'][0]['path'] is None
            assert match['locations'][0]['line'] is None
            assert match['locations'][0]['detector_input_path'] == '/app/config.env'
    else:
        component = next(m for m in exported['secret_evidence']['matches'] if m['value'] == secret)
        assert component['locations'][0]['path'] == '/app/config.env'
        assert component['locations'][0]['line'] == 2
    assert path.stat().st_mode & 0o777 == 0o600
    cli._write(private, None, 'json')
    public = capsys.readouterr().out
    assert access not in public and secret not in public


def test_grouped_legacy_detail_shows_full_values_without_putting_them_in_member_summaries(owned):
    from peaso.finding_groups import group_id
    client, ident, report, _ = owned
    cid = report['findings'][0]['check_id']
    url = f'/api/scans/{ident}/finding-groups/{group_id("aws", cid)}'
    reply = client.get(url)
    assert reply.status_code == 200, reply.text
    assert reply.json()['secret_evidence']['matches'][0]['value'] == VALUE
    assert VALUE not in json.dumps(reply.json()['members'])
    assert reply.headers['cache-control'] == 'private, no-store'
    for suffix in ('findings?aggregation=check', 'summary?aggregation=check', 'report?aggregation=check'):
        public = client.get(f'/api/scans/{ident}/' + suffix)
        assert public.status_code == 200, (suffix, public.text)
        assert VALUE not in public.text
    client.headers['Authorization'] = 'Bearer bob'
    assert client.get(url).status_code == 404


@pytest.mark.parametrize('download_envelope', [False, True])
def test_authorized_fingerprint_detail_filters_other_resource_and_related_locations(owned, monkeypatch, download_envelope):
    from peaso import secret_evidence as evidence, secret_scanning as scanning
    client, ident, report, settings = owned
    fp = scanning._fingerprint(VALUE)
    check = report['findings'][0]['check_id']
    other = ARN.replace('123456789012', '999999999999')
    cipher = CredentialCipher(settings.identity_dir)
    with capture(cipher, tenant='alice', scan_id=ident) as sink:
        for resource, scope in ((ARN, '123456789012/us-east-1'), (other, '999999999999/us-east-1')):
            with evidence.source_context(resource_id=resource, scope=scope, check_ids={check}):
                evidence.remember_full_match(VALUE, VALUE + ':detector-pair', payload=VALUE.encode(), path='/app/shared.env', engine='trufflehog', rule='composite')
                evidence.remember(VALUE, fp, path='/app/shared.env', public_path='/app/shared.env', line=1, engine='trufflehog', rule='composite')
    client.app.state.artifacts.put_secret_evidence('alice', ident, sink.document())
    new = copy.deepcopy(report)
    full = finding(fp, category='hardening', severity='high', title='Secret setting', frameworks=[],
        resource_id='secret:' + fp, native_resource_id=None, linked_check_ids=[check], evidence={'secret_leaks': [
        {'fingerprint': fp, 'detectors': [{'engine': 'trufflehog', 'rule': 'composite'}], 'locations': [
            {'resource_id': ARN, 'scope': '123456789012/us-east-1', 'path': '/app/shared.env', 'line': 1}]}]})
    if download_envelope:
        from peaso.storage.reports import finding_summary
        artifacts = client.app.state.artifacts
        public_ref = artifacts.put('alice', ident, 'detail', full)
        new['findings'] = [dict(finding_summary(full), _detail_reference=public_ref)]
        monkeypatch.setattr(artifacts, 'presign', lambda *args: 'https://artifact.invalid/public-detail', raising=False)
    else:
        new['findings'] = [full]
    row = client.app.state.store.job('alice', ident)
    ref = client.app.state.artifacts.put('alice', ident, 'report', new)
    client.app.state.store.replace_completed_report('alice', ident, row['report'], ref)
    response = client.get(f'/api/scans/{ident}/findings/secret-{fp}')
    assert response.status_code == 200, response.text
    detail = response.json()['secret_evidence']
    assert {match['value'] for match in detail['matches']} == {VALUE, VALUE + ':detector-pair'}
    for match in detail['matches']:
        assert {loc['resource_id'] for loc in match['locations']} == {ARN}
        assert {loc['scope'] for loc in match['locations']} == {'123456789012/us-east-1'}
    derived = next(match for match in detail['matches'] if match['value'].endswith(':detector-pair'))
    assert derived['locations'][0]['path'] is None
    assert derived['locations'][0]['detector_input_path'] == '/app/shared.env'
    assert other not in response.text
    assert VALUE not in client.get(f'/api/scans/{ident}/findings').text
    if download_envelope:
        assert response.json()['download_url'].startswith('https://')
        assert VALUE not in json.dumps(client.app.state.artifacts.get('alice', public_ref))
    client.headers['Authorization'] = 'Bearer bob'
    assert client.get(f'/api/scans/{ident}/findings/secret-{fp}').status_code == 404


@pytest.mark.parametrize('conflict', ['scope', 'resource'])
def test_authorized_individual_and_group_withhold_canonical_origin_conflicts(owned, conflict):
    from peaso import secret_evidence as evidence, secret_scanning as scanning
    from peaso.finding_groups import group_id
    client, ident, report, settings = owned
    check = report['findings'][0]['check_id']
    fp = scanning._fingerprint(VALUE)
    cipher = CredentialCipher(settings.identity_dir)
    scope = '123456789012/us-east-1'
    with capture(cipher, tenant='alice', scan_id=ident) as sink:
        with evidence.source_context(resource_id=ARN, scope=scope, check_ids={check}):
            evidence.remember(VALUE, fp, path='config.env', line=1, engine='trufflehog', rule='synthetic')
    artifacts = client.app.state.artifacts
    artifacts.put_secret_evidence('alice', ident, sink.document())
    public = finding(fp, category='hardening', severity='high', title='Secret setting', frameworks=[], evidence={'secret_leaks': [
        {'fingerprint': fp, 'locations': [{'resource_id': ARN, 'scope': scope, 'path': 'config.env', 'line': 1}]}]})
    if conflict == 'scope':
        public['scope'] = '123456789012/us-west-2'
    else:
        public['resource_id'] = public['native_resource_id'] = ARN + '-other'
    new = dict(report, findings=[public])
    row = client.app.state.store.job('alice', ident)
    ref = artifacts.put('alice', ident, 'report', new)
    client.app.state.store.replace_completed_report('alice', ident, row['report'], ref)
    for suffix in ('findings/secret-' + fp, 'finding-groups/' + group_id('aws', check)):
        response = client.get(f'/api/scans/{ident}/' + suffix)
        assert response.status_code == 200, response.text
        private = response.json()['secret_evidence']
        assert private['status'] == 'unavailable'
        assert private['complete'] is False
        assert private['matches'] == []
        assert VALUE not in response.text


def test_canonical_snapshot_binding_cannot_relabel_an_explicit_conflicting_scope():
    from peaso import secret_evidence as evidence, secret_scanning as scanning
    from peaso.snapshot import make_snapshot
    fp = scanning._fingerprint(VALUE)
    other_scope = '123456789012/us-west-2'
    canonical = {'fingerprint': fp, 'detectors': [{'engine': 'trufflehog', 'rule': 'synthetic'}],
        'locations': [{'path': 'input.env', 'line': 1}]}
    snapshot = make_snapshot('aws', [other_scope], [{'type': 'lambda_function', 'scope': other_scope, 'status': 'collected',
        'items': [{'Arn': ARN, 'ContentScan': {'leaks': [canonical]}}]}])
    with capture(evidence.EphemeralCipher(), tenant='alice', scan_id='a' * 32) as sink:
        with evidence.source_context(resource_id=ARN, scope='123456789012/us-east-1'):
            evidence.remember(VALUE, fp, path='input.env', public_path='input.env', line=1, engine='trufflehog', rule='synthetic')
    sink.public_snapshot(snapshot)
    row = sink.cipher.decrypt(sink.records[fp])
    assert row['locations'][0]['scope'] == '123456789012/us-east-1'
    assert '_canonical_scope' not in row['locations'][0]
    observed = finding(fp, scope=other_scope, evidence={'secret_leaks': [canonical]})
    result = evidence.details(observed, sink.document(), sink.cipher, tenant='alice', scan_id='a' * 32)
    assert result['status'] == 'unavailable'
    assert result['matches'] == []


def test_authorized_decoded_detail_has_full_pair_and_input_without_literal_path_claim(owned):
    import base64
    from peaso import secret_evidence as evidence, secret_scanning as scanning
    client, ident, report, settings = owned
    primary, component = 'AKIA' + '7MQ2ZR9WL4CV8NK1', '7mQ2zR9wL4cV8nK1sF6aH3jP5uD0xB2yE9rT1vW8'
    fp = scanning._fingerprint(primary)
    cipher = CredentialCipher(settings.identity_dir)
    path = '/app/' + component + '.env'
    payload = base64.b64encode((primary + '\n' + component).encode())
    with capture(cipher, tenant='alice', scan_id=ident) as sink:
        with evidence.source_context(resource_id=ARN, scope='123456789012/us-east-1'):
            evidence.remember_full_match(primary, primary + ':' + component, payload=payload, path=path, engine='trufflehog', rule='AWS')
            evidence.remember(primary, fp, path=path, public_path='/app/REDACTED.env', engine='trufflehog', rule='AWS', observed_bytes=False)
    client.app.state.artifacts.put_secret_evidence('alice', ident, sink.document())
    new = copy.deepcopy(report)
    new['findings'] = [finding(fp, category='hardening', severity='high', title='Secret setting', frameworks=[], evidence={
        'secret_leaks': [{'fingerprint': fp, 'detectors': [{'engine': 'trufflehog', 'rule': 'AWS'}], 'locations': [
            {'resource_id': ARN, 'scope': '123456789012/us-east-1', 'path': '/app/REDACTED.env'}]}]})]
    row = client.app.state.store.job('alice', ident)
    ref = client.app.state.artifacts.put('alice', ident, 'report', new)
    client.app.state.store.replace_completed_report('alice', ident, row['report'], ref)
    response = client.get(f'/api/scans/{ident}/findings/secret-{fp}')
    assert response.status_code == 200, response.text
    matches = response.json()['secret_evidence']['matches']
    assert {match['value'] for match in matches} == {primary, primary + ':' + component}
    for match in matches:
        assert match['locations'][0]['path'] is None
        assert match['locations'][0]['line'] is None
        assert match['locations'][0]['detector_input_path'] == path
    assert component not in client.get(f'/api/scans/{ident}/findings').text
    client.headers['Authorization'] = 'Bearer bob'
    assert client.get(f'/api/scans/{ident}/findings/secret-{fp}').status_code == 404


def test_decoded_privacy_scrub_covers_other_snapshot_metadata_without_inventing_native_witness():
    import base64
    from peaso import secret_evidence as evidence, secret_scanning as scanning
    from peaso.snapshot import make_snapshot
    primary, component = 'AKIA' + '7MQ2ZR9WL4CV8NK1', '7mQ2zR9wL4cV8nK1sF6aH3jP5uD0xB2yE9rT1vW8'
    payload = base64.b64encode((primary + '\n' + component).encode())
    with capture(evidence.EphemeralCipher()) as sink:
        with evidence.source_context(resource_id=ARN, scope='123456789012/us-east-1'):
            evidence.remember_full_match(primary, primary + ':' + component, payload=payload, path='encoded.env', engine='trufflehog', rule='AWS')
            evidence.remember(primary, scanning._fingerprint(primary), path='encoded.env', engine='trufflehog', rule='AWS', observed_bytes=False)
            # The actual scanner passes its complete privacy union to this
            # explicit hook, independently of which values have literal origins.
            evidence.remember_redactions({primary, component, primary + ':' + component})
    snapshot = make_snapshot('aws', ['123456789012/us-east-1'], [{'type': 'lambda_function',
        'scope': '123456789012/us-east-1', 'status': 'collected', 'items': [{'Arn': ARN, 'note': component, 'labels': {component: component}}]}])
    public = sink.public_snapshot(snapshot)
    # Found values stay visible in other snapshot fields; no witness is invented for them.
    assert public['collections'][0]['items'][0]['labels'] == {component: component}
    assert scanning._fingerprint(component) not in sink.records
    assert 'redactions' not in sink.document()
    assert component not in json.dumps(sink.document())
