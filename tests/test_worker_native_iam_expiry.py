"""Collector-owned IAM report expiry must preserve facts and stay resumable."""
import copy
import json
import threading
from types import SimpleNamespace

import pytest
from botocore.exceptions import ClientError

from peaso.collectors.aws_iam_report_native import service_reports
from peaso.collectors.resume import partition
from peaso.snapshot import make_snapshot, seal
from peaso.worker import Worker, _expired_snapshot, _retryable_expired_snapshot

ACCOUNT = '123456789012'
REGION = ACCOUNT + '/us-east-1'
GLOBAL = ACCOUNT + '/global'


def native_report(code, kind='role'):
    """Exercise the normal native producer, not a hand-created status shape."""
    arn = 'arn:aws:iam::' + ACCOUNT + ':' + kind + '/SyntheticReadonly'
    class Requests:
        _lock = threading.RLock()
        iam_service_access_reports_requested = True
        service_last_accessed_wait = 1
        service_last_accessed_workers = 1
        iam_usage_scan = True
        def check_deadline(self):
            pass
        def call(self, session, service, region, operation, **kwargs):
            if (service, operation) == ('sts', 'get_caller_identity'):
                return {'Account': ACCOUNT, 'Arn': 'arn:aws:sts::' + ACCOUNT + ':assumed-role/Reader/scan'}
            assert (service, operation) == ('iam', 'generate_service_last_accessed_details')
            raise ClientError({'Error': {'Code': code, 'Message': 'synthetic provider message'}}, operation)
    rows, state = service_reports(Requests(), SimpleNamespace(get_partition_for_region=lambda _: 'aws'), 'us-east-1', [arn])[arn]
    assert rows is None and state['error']['code'] == code
    return {'type': 'iam_' + kind, 'scope': GLOBAL, 'service': 'iam', 'status': 'collected',
            'items': [{'Arn': arn, 'ServicesLastAccessedStatus': state}]}


def saved_snapshot(code='ExpiredToken', kind='role'):
    return make_snapshot('aws', [REGION, GLOBAL], [
        {'type': 'bucket', 'scope': REGION, 'service': 's3', 'status': 'collected', 'items': [{
            'Name': 'retained-encrypted-bucket', 'Encryption': {'ServerSideEncryptionConfiguration': {'Rules': [{
                'ApplyServerSideEncryptionByDefault': {'SSEAlgorithm': 'AES256'}}]}}}]}, native_report(code, kind)])


@pytest.mark.parametrize('kind', ['user', 'group', 'role', 'policy'])
@pytest.mark.parametrize('code', ['ExpiredToken', 'ExpiredTokenException', 'RequestExpired'])
def test_real_native_report_expiry_keeps_facts_and_only_retries_iam(kind, code):
    snapshot = saved_snapshot(code, kind)
    before = copy.deepcopy(snapshot)
    assert _expired_snapshot(snapshot)
    current = seal(_retryable_expired_snapshot(snapshot))
    assert snapshot == before, 'classification must not alter original sealed evidence'
    assert current['collections'][0] == before['collections'][0]
    iam = current['collections'][1]
    assert iam['status'] == 'partial' and iam['error']['code'] == code
    assert iam['items'] == before['collections'][1]['items']
    remaining, reused = partition({'provider': 'aws', 'scopes': [REGION], 'auth': {}, 'options': {}}, ['bucket', 'iam_' + kind], current)
    assert remaining == ['iam_' + kind]
    assert [row['type'] for row in reused] == ['bucket']


@pytest.mark.parametrize('code', ['AccessDenied', 'AccessDeniedException', 'InvalidClientTokenId', 'ReportExpired'])
def test_native_authorization_or_report_availability_does_not_expire_credentials(code):
    snapshot = saved_snapshot(code)
    assert not _expired_snapshot(snapshot)
    assert _retryable_expired_snapshot(snapshot) is snapshot


@pytest.mark.parametrize('mutation', ['provider', 'service', 'type', 'scope', 'arn', 'principal_arn', 'operation', 'completed', 'policy_json', 'message_only', 'non_aws_code'])
def test_only_exact_collector_owned_iam_report_error_is_classified(mutation):
    snapshot = saved_snapshot()
    envelope = snapshot['collections'][1]
    item = envelope['items'][0]
    state = item['ServicesLastAccessedStatus']
    if mutation == 'provider': snapshot['provider'] = 'gcp'
    elif mutation == 'service': envelope['service'] = 'lambda'
    elif mutation == 'type': envelope['type'] = 'lambda_function'
    elif mutation == 'scope': envelope['scope'] = '999999999999/global'
    elif mutation == 'arn': item['Arn'] = 'unbound'
    elif mutation == 'principal_arn': state['principal_arn'] = 'arn:aws:iam::' + ACCOUNT + ':role/Other'
    elif mutation == 'operation': state['operation'] = 'application:Error'
    elif mutation == 'completed': state['collection_status'] = 'collected'
    elif mutation == 'policy_json':
        item['RolePolicyList'] = [{'PolicyDocument': {'ServicesLastAccessedStatus': item.pop('ServicesLastAccessedStatus')}}]
    elif mutation == 'message_only': state['error'] = {'code': 'AccessDenied', 'message': 'ExpiredToken'}
    elif mutation == 'non_aws_code': state['error']['code'] = 'invalid_grant'
    assert not _expired_snapshot(snapshot)
    assert _retryable_expired_snapshot(snapshot) is snapshot


def test_existing_envelope_expiry_additional_errors_and_ordinary_denial():
    for error, expected in [({'code': 'ExpiredToken'}, True), ({'code': 'partial', 'additional_errors': [{'code': 'ExpiredTokenException'}]}, True), ({'code': 'AccessDenied'}, False)]:
        assert _expired_snapshot({'provider': 'aws', 'collections': [{'type': 'bucket', 'scope': REGION, 'status': 'denied', 'items': [], 'error': error}]}) is expected


@pytest.mark.parametrize('code,expected', [('ExpiredToken', 'credentials_expired'), ('AccessDenied', 'collected')])
def test_actual_worker_preserves_checkpoint_and_snapshot_with_correct_terminal_state(tmp_path, code, expected):
    from peaso.auth import CredentialCipher
    from peaso.server.config import Settings
    from peaso.storage.artifacts import FileArtifacts
    from peaso.storage.sqlite import SQLiteStore
    settings = Settings(state_dir=tmp_path/'state', identity_dir=tmp_path/'identity')
    store = SQLiteStore(settings.state_dir)
    artifacts = FileArtifacts(settings.state_dir/'artifacts')
    snapshot = saved_snapshot(code)
    encrypted = CredentialCipher(settings.identity_dir).encrypt({'auth': {}, 'options': {'snapshot': snapshot}})
    connector = store.add_connector('owner', {'provider': 'aws', 'scopes': snapshot['scopes'], 'input_mode': 'offline_snapshot'}, encrypted)
    job = store.enqueue('owner', {'connector_id': connector['id'], 'categories': ['hardening'], 'checks': ['aws.s3.default_encryption'], 'ai_enabled': False}, limit=10)
    assert store.admit('owner', job['id'])
    assert Worker('collector', settings, store=store, artifacts=artifacts).run_once('owner', job['id'])
    row = store.job('owner', job['id'])
    assert row['status'] == expected, row
    assert row['snapshot'] and row['partial_report']
    saved = artifacts.get('owner', row['snapshot'])
    assert saved['collections'][0]['items'] == snapshot['collections'][0]['items']
    manifest = artifacts.get('owner', row['partial_report'])
    report = artifacts.get('owner', manifest['report_json'])
    assert any(f['check_id'] == 'aws.s3.default_encryption' and f['status'] == 'PASS' for f in report['findings'])
    if code == 'ExpiredToken':
        assert row['error_code'] == 'credentials_expired'
        remaining, reused = partition({'provider': 'aws', 'scopes': [REGION], 'auth': {}, 'options': {}}, ['bucket', 'iam_role'], saved)
        assert remaining == ['iam_role']
        assert [r['type'] for r in reused] == ['bucket']
