"""Cross-region service state reuse preserves native unavailability evidence."""
import json
from types import SimpleNamespace

import pytest

from peaso.collectors import gcp

SCOPE = 'projects/peaso-test'
HOST = 'cloudkms.googleapis.com'


def transport(monkeypatch, *, consumer=SCOPE, service=HOST, reason='SERVICE_DISABLED', status=403):
    calls = []
    payload = {'error': {'details': [{'reason': reason, 'metadata': {'consumer': consumer, 'service': service}}]}}
    response = SimpleNamespace(status_code=status, headers={}, content=json.dumps(payload).encode(), json=lambda: payload)
    session = SimpleNamespace(request=lambda *a, **kw: calls.append(a[1]) or response, close=lambda: None)
    value = gcp.Transport(SimpleNamespace(headers=lambda: {}, close=lambda: None), {'retries': 0})
    monkeypatch.setattr(value, '_session', lambda: session)
    return value, calls


def read(value, location, scope=SCOPE):
    with pytest.raises(gcp.ReadError) as caught:
        value.request('GET', f'https://{HOST}/v1/{scope}/locations/{location}/keyRings', scope=scope)
    return caught.value


def test_disabled_service_reused_across_regions_with_original_receipt(monkeypatch):
    value, calls = transport(monkeypatch)
    first = read(value, 'us-central1')
    second = read(value, 'europe-west1')
    assert len(calls) == value.calls == 1
    assert first is not second and first.error == second.error
    assert first.status == second.status == 'unavailable'
    assert value.evidence[1]['source_request_id'] == value.evidence[0]['id']
    assert value.evidence[1]['cache_basis'] == 'native_consumer_service_disabled'
    assert value.evidence[1]['http_attempts'] == 0
    assert value.evidence[1]['url'].endswith('/europe-west1/keyRings')
    assert second.request_id == value.evidence[1]['id']
    assert 'http_status' not in value.evidence[1]  # No invented HTTP response.


@pytest.mark.parametrize('options', [
    {'consumer': 'projects/quota-project'},
    {'consumer': 'projects/123456'},
    {'consumer': None},
    {'service': 'another.googleapis.com'},
    {'reason': 'IAM_PERMISSION_DENIED'},
    {'reason': 'RATE_LIMIT_EXCEEDED', 'status': 429},
    {'status': 500},
])
def test_unbound_or_transient_failure_does_not_disable_other_reads(monkeypatch, options):
    value, calls = transport(monkeypatch, **options)
    read(value, 'us-central1')
    read(value, 'europe-west1')
    assert len(calls) == value.calls == 2
    assert not value.disabled_services


def test_state_does_not_cross_projects_or_transports(monkeypatch):
    value, calls = transport(monkeypatch)
    read(value, 'us-central1')
    read(value, 'europe-west1', scope='projects/other')
    assert len(calls) == 2
    other, other_calls = transport(monkeypatch)
    read(other, 'europe-west1')
    assert len(other_calls) == 1


def test_cancelled_follower_still_checks_cancellation(monkeypatch):
    value, calls = transport(monkeypatch)
    read(value, 'us-central1')
    value.options['_cancel_check'] = lambda: True
    with pytest.raises(gcp.ReadError) as caught:
        value.request('GET', f'https://{HOST}/v1/{SCOPE}/locations/europe-west1/keyRings', scope=SCOPE)
    assert caught.value.error['code'] == 'cancelled'
    assert len(calls) == 1
