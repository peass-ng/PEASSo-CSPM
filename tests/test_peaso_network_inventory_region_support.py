"""A service with no endpoint in a Region is unsupported there, not a failed inventory."""
import pytest

boto3 = pytest.importorskip('boto3')
from botocore.exceptions import EndpointConnectionError
from botocore.stub import Stubber

from peaso.collectors import aws

ACCOUNT = '123456789012'


def collect(monkeypatch, region):
    session = boto3.Session(aws_access_key_id='INERT', aws_secret_access_key='INERT', region_name=region)
    sts = session.client('sts', region_name=region)

    ml = session.client('machinelearning', region_name=region)

    class NoEndpoint:
        def __getattr__(self, name):
            return getattr(ml, name)

        def describe_ml_models(self, **kwargs):
            raise EndpointConnectionError(endpoint_url=f'https://machinelearning.{region}.amazonaws.com/')

    monkeypatch.setattr(aws, '_session', lambda auth, region: (session, 'fixture'))
    monkeypatch.setattr(aws.Requests, 'client',
                        lambda self, _session, service, region: sts if service == 'sts' else NoEndpoint())
    with Stubber(sts) as stub:
        stub.add_response('get_caller_identity', {'Account': ACCOUNT,
            'Arn': f'arn:aws:iam::{ACCOUNT}:user/reviewer', 'UserId': 'AIDAREVIEWER'}, {})
        snapshot = aws.collect({'provider': 'aws', 'scopes': [ACCOUNT], 'auth': {'profile': 'fixture'},
            'options': {'regions': [region], 'retry_attempts': 1, 'service_concurrency': 1, 'scope_concurrency': 1}},
            ['machinelearning_model'])
    row, = [c for c in snapshot['collections'] if c['type'] == 'machinelearning_model']
    return row


def test_network_inventory_in_region_without_service_endpoint_is_unsupported(monkeypatch):
    region = next(r for r in boto3.Session().get_available_regions('ec2')
                  if r not in boto3.Session().get_available_regions('machinelearning'))
    row = collect(monkeypatch, region)
    assert row['status'] == 'not_collected' and row['error']['code'] == 'unsupported_region_service'


def test_unreachable_endpoint_in_supported_region_stays_a_failed_read(monkeypatch):
    region = boto3.Session().get_available_regions('machinelearning')[0]
    row = collect(monkeypatch, region)
    assert row['status'] != 'collected'
    assert (row.get('error') or {}).get('code') != 'unsupported_region_service'
