"""S3 Express One Zone is absent from some S3 Regions; that is not a failed read."""
import socket

import pytest

boto3 = pytest.importorskip('boto3')
from botocore.exceptions import EndpointConnectionError
from botocore.stub import Stubber

from peaso.collectors import aws

ACCOUNT, REGION = '123456789012', 'ap-northeast-3'


def collect(monkeypatch, resolvable):
    def getaddrinfo(host, port, *args, **kwargs):
        if host in resolvable:
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('192.0.2.1', port))]
        raise socket.gaierror(socket.EAI_NONAME, 'nodename nor servname provided')
    monkeypatch.setattr(socket, 'getaddrinfo', getaddrinfo)
    session = boto3.Session(aws_access_key_id='INERT', aws_secret_access_key='INERT', region_name=REGION)
    sts = session.client('sts', region_name=REGION)
    s3 = session.client('s3', region_name=REGION)

    class NoExpressEndpoint:
        def __getattr__(self, name):
            return getattr(s3, name)

        def list_directory_buckets(self, **kwargs):
            raise EndpointConnectionError(endpoint_url=f'https://s3express-control.{REGION}.amazonaws.com/')

    monkeypatch.setattr(aws, '_session', lambda auth, region: (session, 'fixture'))
    monkeypatch.setattr(aws.Requests, 'client',
                        lambda self, _session, service, region: sts if service == 'sts' else NoExpressEndpoint())
    with Stubber(sts) as stub:
        stub.add_response('get_caller_identity', {'Account': ACCOUNT,
            'Arn': f'arn:aws:iam::{ACCOUNT}:user/reviewer', 'UserId': 'AIDAREVIEWER'}, {})
        snapshot = aws.collect({'provider': 'aws', 'scopes': [ACCOUNT], 'auth': {'profile': 'fixture'},
            'options': {'regions': [REGION], 'retry_attempts': 1, 'service_concurrency': 1, 'scope_concurrency': 1}},
            ['s3_directory_bucket'])
    row, = [c for c in snapshot['collections'] if c['type'] == 's3_directory_bucket']
    return snapshot, row


def lifecycle_status(snapshot):
    from peaso.engine import evaluate_snapshot
    check = 'aws.claude_a.s3.directory_bucket_lifecycle'
    return {f['status'] for f in evaluate_snapshot(snapshot, checks=[check])['findings'] if f['check_id'] == check}


def test_region_without_s3_express_endpoint_is_unsupported(monkeypatch):
    snapshot, row = collect(monkeypatch, {f's3.{REGION}.amazonaws.com'})
    assert row['status'] == 'not_collected' and row['error']['code'] == 'unsupported_region_service'
    assert lifecycle_status(snapshot) == {'NOT_APPLICABLE'}


def test_unresolvable_dns_everywhere_stays_a_failed_read(monkeypatch):
    snapshot, row = collect(monkeypatch, set())
    assert row['error']['code'] != 'unsupported_region_service'
    assert lifecycle_status(snapshot) == {'UNKNOWN'}
