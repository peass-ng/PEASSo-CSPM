"""No compliant verdict from missing or invalid DNSSEC default key specs."""
from copy import deepcopy

import pytest

from peaso.engine import evaluate_snapshot
from tests.test_peaso_collectors_gcp import snapshot
from tests.test_gcp_firewall_port_native_matrix_review_20261020 import forbid_provider_network

CASES = [
    ('rsasha1', 'FAIL'), ('rsasha256', 'PASS'), ('rsasha512', 'PASS'),
    ('ecdsap256sha256', 'PASS'), ('ecdsap384sha384', 'PASS'),
    ('empty_specs', 'UNKNOWN'), ('other_key_only', 'UNKNOWN'),
    ('bad_key_type', 'UNKNOWN'), ('bad_algorithm', 'UNKNOWN'),
    ('missing_algorithm', 'UNKNOWN'), ('denied_algorithm', 'UNKNOWN'),
    ('invalid_visibility', 'UNKNOWN'), ('private', 'NOT_APPLICABLE'),
    ('dnssec_off', 'NOT_APPLICABLE'),
]
ZONE_IAM_URL = 'https://dns.googleapis.com/dns/v1/projects/p-one/managedZones/review:getIamPolicy'


@pytest.mark.parametrize('flavor', ['claude', 'ports'])
@pytest.mark.parametrize('key_type,slug', [('keySigning', 'ksk'), ('zoneSigning', 'zsk')])
@pytest.mark.parametrize('scenario,expected', CASES)
def test_native_dnssec_default_key_evidence(key_type, slug, scenario, expected, flavor):
    spec = {'keyType': key_type, 'algorithm': scenario if expected == 'PASS' or scenario == 'rsasha1' else 'rsasha256'}
    zone = {'kind': 'dns#managedZone', 'name': 'review', 'dnsName': 'example.invalid.',
            'id': '10001', 'visibility': 'public',
            'dnssecConfig': {'state': 'on', 'defaultKeySpecs': [spec]}}
    if scenario == 'empty_specs': zone['dnssecConfig']['defaultKeySpecs'] = []
    elif scenario == 'other_key_only': spec['keyType'] = 'zoneSigning' if key_type == 'keySigning' else 'keySigning'
    elif scenario == 'bad_key_type': spec['keyType'] = 'unrecognized'
    elif scenario == 'bad_algorithm': spec['algorithm'] = 'unrecognized'
    elif scenario == 'missing_algorithm': spec.pop('algorithm')
    elif scenario == 'invalid_visibility': zone['visibility'] = 'unrecognized'
    elif scenario == 'private': zone['visibility'] = 'private'
    elif scenario == 'dnssec_off': zone['dnssecConfig']['state'] = 'off'
    original = deepcopy(zone)

    def resolve(request):
        if request['url'] == ZONE_IAM_URL:
            # 16bb81e0 hydrates each managed zone's IAM policy with one POST.
            assert request['method'] == 'POST'
            return {'version': 3, 'bindings': []}
        assert request['method'] == 'GET'
        assert request['url'] == 'https://dns.googleapis.com/dns/v1/projects/p-one/managedZones'
        return {'kind': 'dns#managedZonesListResponse', 'managedZones': [zone]}

    collected, transport = snapshot(['dns_managed_zone'], resolve)
    assert zone == original and [r['url'] for r in transport.requests] == [
        'https://dns.googleapis.com/dns/v1/projects/p-one/managedZones', ZONE_IAM_URL]
    if scenario == 'denied_algorithm':
        collected['collections'][0]['items'][0]['dnssecConfig']['defaultKeySpecs'][0]['_coverage'] = {'algorithm': {'status': 'denied'}}
        collected.pop('snapshot_id', None)
    before = deepcopy(collected)
    cid = f'gcp.claude.dns_zone.{slug}_not_rsasha1' if flavor == 'claude' else (
        'gcp.ports.dns_managed_zone_' + ('key' if slug == 'ksk' else 'zone') + '_signing_not_using_rsasha1')
    if flavor == 'ports' and scenario == 'dnssec_off': expected = 'PASS'
    rows = evaluate_snapshot(collected, checks=[cid])['findings']
    assert collected == before and len(rows) == 1
    assert rows[0]['status'] == expected, rows[0]


@pytest.mark.parametrize('flavor', ['claude', 'ports'])
@pytest.mark.parametrize('visibility,state,expected', [
    ('public', 'on', 'PASS'), ('public', 'off', 'FAIL'),
    ('public', 'transfer', 'FAIL'), ('public', 'unrecognized', 'UNKNOWN'),
    ('private', 'on', 'NOT_APPLICABLE'), ('unrecognized', 'on', 'UNKNOWN'),
])
def test_native_dnssec_enabled_visibility_and_state(visibility, state, expected, flavor):
    zone = {'kind': 'dns#managedZone', 'name': 'review', 'id': '10001',
            'visibility': visibility, 'dnssecConfig': {'state': state}}

    def resolve(request):
        if request['url'] == ZONE_IAM_URL:
            # 16bb81e0 hydrates each managed zone's IAM policy with one POST.
            assert request['method'] == 'POST'
            return {'version': 3, 'bindings': []}
        assert request['method'] == 'GET'
        assert request['url'] == 'https://dns.googleapis.com/dns/v1/projects/p-one/managedZones'
        return {'kind': 'dns#managedZonesListResponse', 'managedZones': [zone]}

    collected, transport = snapshot(['dns_managed_zone'], resolve)
    before = deepcopy(collected)
    cid = 'gcp.claude.dns_zone.dnssec_enabled' if flavor == 'claude' else 'gcp.ports.dns_managed_zone_dnssec_enabled'
    if flavor == 'ports' and state == 'transfer' and visibility == 'public': expected = 'PASS'
    rows = evaluate_snapshot(collected, checks=[cid])['findings']
    assert collected == before and [r['url'] for r in transport.requests] == [
        'https://dns.googleapis.com/dns/v1/projects/p-one/managedZones', ZONE_IAM_URL]
    assert len(rows) == 1 and rows[0]['status'] == expected
