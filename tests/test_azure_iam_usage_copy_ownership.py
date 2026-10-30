"""The IAM usage tail retains defensive input isolation and returns owned items."""
from copy import deepcopy
from urllib.error import HTTPError

import pytest

from peaso.collectors import azure, azure_iam_usage_extension as usage
from peaso.snapshot import make_snapshot, seal, validate

SCOPE = '/subscriptions/11111111-1111-1111-1111-111111111111'


def source():
    return make_snapshot('azure', [SCOPE], [{
        'type': 'role_definition', 'scope': SCOPE, 'status': 'collected',
        'items': [{'id': 'role', 'nested': {'values': ['native']}}],
    }], metadata={'nested': {'values': ['metadata']}}, created_at='2026-10-29T00:00:00Z')


def event():
    return {'eventDataId': 'event', 'caller': 'reader@example.test',
            'eventTimestamp': '2026-10-29T00:00:00Z', 'resourceId': SCOPE,
            'authorization': {'action': 'Microsoft.Compute/virtualMachines/read'},
            'status': {'value': 'Succeeded'}}


@pytest.mark.parametrize('frozen', [False, True])
@pytest.mark.parametrize('late_failure', [False, True])
def test_returned_snapshot_is_independent_and_preserves_prefix_on_failure(monkeypatch, frozen, late_failure):
    value = validate(source(), read_only=True) if frozen else source()
    before = deepcopy(value)
    instances = []

    class Transport:
        def __init__(self, auth):
            self.calls = 0
            self.closed = False
            instances.append(self)

        def request(self, url):
            self.calls += 1
            if self.calls == 2:
                raise HTTPError(url, 403, 'fixture denial', {}, None)
            return {'value': [event()], **({'nextLink': url + '&page=2'} if late_failure else {})}

        def close(self):
            self.closed = True

    monkeypatch.setattr(azure, 'AzureTransport', Transport)
    result = usage.enrich_snapshot(value, {'auth': {}})
    assert value == before
    assert validate(result) == result
    assert result['collections'][0] == before['collections'][0]
    tail = result['collections'][-1]
    assert tail['status'] == ('partial' if late_failure else 'collected')
    assert len(tail['items']) == 1
    assert tail['queryWindow']['days'] == 90
    assert tail['queryWindow']['absenceProvesUnused'] is False
    assert instances[0].closed
    assert instances[0].calls == (2 if late_failure else 1)
    assert type(result['collections'][0]['items']) is list
    assert type(result['collections'][0]['items'][0]) is dict
    result['collections'][0]['items'][0]['nested']['values'].append('changed result')
    assert value == before
    value['metadata']['nested']['values'].append('changed input')
    assert result['metadata']['nested']['values'] == ['metadata']


def test_input_collections_are_copied_before_provider_read(monkeypatch):
    value = source()

    class Transport:
        def __init__(self, auth):
            pass

        def request(self, url):
            value['collections'][0]['items'][0]['nested']['values'].append('changed during read')
            return {'value': []}

        def close(self):
            pass

    monkeypatch.setattr(azure, 'AzureTransport', Transport)
    result = usage.enrich_snapshot(value, {'auth': {}})
    assert result['collections'][0]['items'][0]['nested']['values'] == ['native']
    assert value['collections'][0]['items'][0]['nested']['values'] == ['native', 'changed during read']


def test_hosted_credential_denial_retains_ownership_without_opening_transport(monkeypatch):
    value = source()
    before = deepcopy(value)

    def forbidden(*args, **kwargs):
        pytest.fail('No transport for invalid hosted credential material')

    monkeypatch.setattr(azure, 'AzureTransport', forbidden)
    result = usage.enrich_snapshot(value, {'auth': {'token_file': 'not-opened'}, 'options': {'hosted': True}})
    assert result['collections'][-1]['status'] == 'denied'
    assert result['collections'][-1]['error']['code'] == 'hosted_credentials_required'
    assert validate(result) == result
    result['collections'][0]['items'][0]['nested']['values'].append('changed result')
    assert value == before


def test_existing_usage_snapshot_returns_without_copy_or_transport(monkeypatch):
    value = source()
    value['collections'].append({'type': 'iam_usage_activity', 'scope': SCOPE,
                                 'status': 'empty', 'items': []})
    value = seal(value)

    def forbidden(*args, **kwargs):
        pytest.fail('Existing IAM usage must not refetch')

    monkeypatch.setattr(azure, 'AzureTransport', forbidden)
    assert usage.enrich_snapshot(value, {'auth': {}}) is value
