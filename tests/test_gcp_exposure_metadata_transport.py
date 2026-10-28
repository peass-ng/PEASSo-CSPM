"""Exercise planned exposure reads through the real transport admission layer."""
from types import SimpleNamespace

import pytest

from peaso.collectors import gcp

SCOPE = 'projects/peaso-test'


@pytest.fixture
def transport(monkeypatch):
    calls = []
    def request(method, url, **kwargs):
        calls.append((method, url, kwargs))
        return SimpleNamespace(status_code=200, headers={}, content=b'{}', json=lambda: {})
    value = gcp.Transport(SimpleNamespace(headers=lambda: {}, close=lambda: None), {'retries': 0})
    monkeypatch.setattr(value, '_session', lambda: SimpleNamespace(request=request, close=lambda: None))
    return value, calls


ROUTES = [
    ('https://cloudtasks.googleapis.com/v2/' + SCOPE + '/locations', None),
    ('https://cloudtasks.googleapis.com/v2/' + SCOPE + '/locations/us-central1/queues', None),
    ('https://cloudtasks.googleapis.com/v2/' + SCOPE + '/locations/us-central1/queues/q/tasks', {'responseView': 'BASIC'}),
    ('https://dialogflow.googleapis.com/v2/' + SCOPE + '/agent:search', None),
    ('https://dialogflow.googleapis.com/v2/' + SCOPE + '/agent/fulfillment', None),
    ('https://dialogflow.googleapis.com/v2/' + SCOPE + '/agent/environments', None),
    ('https://recaptchaenterprise.googleapis.com/v1/' + SCOPE + '/keys', None),
    ('https://recaptchaenterprise.googleapis.com/v1/' + SCOPE + '/keys/key-id/policy', None),
    ('https://us-central1-gkemulticloud.googleapis.com/v1/' + SCOPE + '/locations', None),
    *[('https://us-central1-gkemulticloud.googleapis.com/v1/' + SCOPE + '/locations/us-central1/' + kind, None)
      for kind in ('attachedClusters', 'awsClusters', 'azureClusters')],
]


@pytest.mark.parametrize('url,params', ROUTES)
def test_planned_metadata_read_reaches_native_transport(transport, url, params):
    value, calls = transport
    data, receipt = value.request('GET', url, scope=SCOPE, params=params)
    assert data == {} and len(calls) == 1
    assert value.evidence[0]['id'] == receipt
    assert value.evidence[0]['http_status'] == 200


@pytest.mark.parametrize('url,params', ROUTES)
def test_metadata_admission_cannot_cross_scope_or_write(transport, url, params):
    value, calls = transport
    for method, scope, body in [('GET', 'projects/foreign', None), ('GET', SCOPE, {}),
                                ('POST', SCOPE, None), ('DELETE', SCOPE, None)]:
        with pytest.raises(gcp.ReadError, match='unsafe_api_endpoint'):
            value.request(method, url, scope=scope, params=params, body=body)
    assert not calls


@pytest.mark.parametrize('url,params', [
    ('https://cloudtasks.googleapis.com/v2/' + SCOPE + '/locations/us-central1/queues/q/tasks', {'responseView': 'FULL'}),
    ('https://cloudtasks.googleapis.com/v2/' + SCOPE + '/locations/us-central1/queues/q/tasks/t', {'responseView': 'BASIC'}),
    ('https://recaptchaenterprise.googleapis.com/v1/' + SCOPE + '/keys/k:retrieveLegacySecretKey', None),
    ('https://dialogflow.googleapis.com/v2/' + SCOPE + '/agent:export', None),
    ('https://us-central1-gkemulticloud.googleapis.com/v1/' + SCOPE + '/locations/europe-west1/awsClusters', None),
    ('https://us-central1-gkemulticloud.googleapis.com/v1/' + SCOPE + '/locations/us-central1:generateAttachedClusterInstallManifest', None),
    ('https://cloudtasks.googleapis.com/v2/' + SCOPE + '/locations#fragment', None),
    ('https://cloudtasks.googleapis.com.evil.test/v2/' + SCOPE + '/locations', None),
])
def test_unselected_content_credentials_and_foreign_routes_stay_blocked(transport, url, params):
    value, calls = transport
    with pytest.raises(gcp.ReadError, match='unsafe_api_endpoint'):
        value.request('GET', url, scope=SCOPE, params=params)
    assert not calls


@pytest.mark.parametrize('url', [
    'https://modelarmor.googleapis.com/v1/' + SCOPE + '/locations/global/floorSetting',
    'https://modelarmor.us-central1.rep.googleapis.com/v1/' + SCOPE + '/locations',
    'https://modelarmor.eu.rep.googleapis.com/v1/' + SCOPE + '/locations/eu/templates',
])
def test_model_armor_uses_global_floor_and_regional_metadata_only(transport, url):
    value, calls = transport
    value.request('GET', url, scope=SCOPE)
    assert len(calls) == 1
    with pytest.raises(gcp.ReadError):
        value.request('GET', url, scope='projects/foreign')
    with pytest.raises(gcp.ReadError):
        value.request('POST', url, scope=SCOPE)
    assert len(calls) == 1


def test_model_armor_collection_reads_global_floor_once_and_templates_in_native_region():
    from peaso.collectors.gcp_model_armor_exposure import collection_pages
    calls = []
    class Collector:
        options = {}
        def read(self, url, scope, **kwargs):
            calls.append(url)
            assert '/locations/global/floorSetting' in url
            return {'name': SCOPE + '/locations/global/floorSetting',
                    'aiPlatformFloorSetting': {'enableCloudLogging': True}}, 'floor'
        def pages(self, url, scope, **kwargs):
            calls.append(url)
            if url.endswith('/locations'):
                yield [{'locationId': 'global'}, {'locationId': 'eu'}, {'locationId': 'us-central1'}], 'locations'
            else:
                region = url.split('modelarmor.')[1].split('.')[0]
                assert '/locations/' + region + '/templates' in url
                yield [{'name': SCOPE + '/locations/' + region + '/templates/t'}], region
    pages = list(collection_pages(Collector(), SCOPE))
    assert len(calls) == len(pages) == 4
    assert calls[0].startswith('https://modelarmor.googleapis.com/')
    assert calls[1].startswith('https://modelarmor.us-central1.rep.googleapis.com/')
    assert [item['resourceKind'] for rows, _ in pages for item in rows] == ['floorSetting', 'template', 'template']


@pytest.mark.parametrize('url', [
    'https://modelarmor.googleapis.com/v1/' + SCOPE + '/locations/global/templates',
    'https://modelarmor.global.rep.googleapis.com/v1/' + SCOPE + '/locations/global/templates',
    'https://modelarmor.eu.rep.googleapis.com/v1/' + SCOPE + '/locations/us/templates',
    'https://modelarmor.eu.rep.googleapis.com/v1/' + SCOPE + '/locations/eu/templates/t:sanitizeUserPrompt',
])
def test_model_armor_cannot_admit_global_templates_foreign_regions_or_content(transport, url):
    value, calls = transport
    with pytest.raises(gcp.ReadError, match='unsafe_api_endpoint'):
        value.request('GET', url, scope=SCOPE)
    assert not calls
