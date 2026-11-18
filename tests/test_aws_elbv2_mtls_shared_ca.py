"""ALB mTLS listeners must not trust a CDN's shared origin-pull CA."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from test_peaso_aws_bulk_inventory import sdk, ACCOUNT  # noqa: F401  (pytest fixture)
from peaso.collectors import aws, aws_elbv2_mtls_trust_store as collector
from peaso.checks import CHECKS
from peaso.checks.aws_finding_priority import contextual_severity
from peaso.snapshot import make_snapshot
from tests.archived_check_contract import evaluate_snapshot

CHECK = 'aws.htbp.elbv2.mtls_no_shared_cdn_origin_ca'
REGION = 'eu-west-1'
SCOPE = ACCOUNT + '/' + REGION
LB = f'arn:aws:elasticloadbalancing:{REGION}:{ACCOUNT}:loadbalancer/app/web/abcd'
LISTENER = f'arn:aws:elasticloadbalancing:{REGION}:{ACCOUNT}:listener/app/web/abcd/efgh'
STORE = f'arn:aws:elasticloadbalancing:{REGION}:{ACCOUNT}:truststore/origin/1234'
BUNDLE_URL = f'https://prod-{REGION}-truststore.s3.{REGION}.amazonaws.com/bundle.pem?X-Amz-Signature=abc'
CLOUDFLARE_PEM = (Path(__file__).parent / 'fixtures' / 'cloudflare_origin_pull_ca.pem').read_bytes()


def private_ca_pem():
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'Throwaway Origin CA'),
                      x509.NameAttribute(NameOID.ORGANIZATION_NAME, 'Example Ltd')])
    now = datetime.now(timezone.utc)
    certificate = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
                   .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(days=1))
                   .not_valid_after(now + timedelta(days=30))
                   .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
                   .sign(key, hashes.SHA256()))
    return certificate.public_bytes(serialization.Encoding.PEM)


def collect(sdk, monkeypatch, mode, pem=b'', scheme='internet-facing'):
    session, add = sdk
    elb = add('elbv2')
    elb.add_response('describe_load_balancers', {'LoadBalancers': [{
        'LoadBalancerArn': LB, 'LoadBalancerName': 'web', 'DNSName': 'web-1.eu-west-1.elb.amazonaws.com',
        'Scheme': scheme, 'Type': 'application'}]}, {})
    mutual = {'Mode': mode, **({'TrustStoreArn': STORE} if mode == 'verify' else {})}
    elb.add_response('describe_listeners', {'Listeners': [{'ListenerArn': LISTENER, 'LoadBalancerArn': LB,
        'Protocol': 'HTTPS', 'Port': 443, 'MutualAuthentication': mutual}]}, {'LoadBalancerArn': LB})
    if mode == 'verify':
        elb.add_response('describe_trust_stores', {'TrustStores': [{'Name': 'origin', 'TrustStoreArn': STORE}]},
                         {'TrustStoreArns': [STORE]})
        if pem is None:
            elb.add_client_error('get_trust_store_ca_certificates_bundle', 'AccessDenied', http_status_code=403,
                                 expected_params={'TrustStoreArn': STORE})
        else:
            elb.add_response('get_trust_store_ca_certificates_bundle', {'Location': BUNDLE_URL}, {'TrustStoreArn': STORE})
    fetched = []
    monkeypatch.setattr(collector, 'download', lambda requests, url, region: fetched.append(url) or pem)
    read = collector.listeners(aws.Requests({'retry_attempts': 1}), session, REGION, ACCOUNT)
    elb.assert_no_pending_responses()
    return read, fetched


def decide(read):
    snapshot = make_snapshot('aws', [SCOPE], [{'type': collector.KIND, 'scope': SCOPE, 'status': read.status,
                                               'items': read.items}])
    [finding] = evaluate_snapshot(snapshot, checks=[CHECK])['findings']
    # Findings are emitted compact; the severity a report shows is the check's, adjusted per finding.
    [check] = [c for c in CHECKS if c.id == CHECK]
    return {**finding, 'severity': contextual_severity(finding, check.severity)}


def test_verify_listener_trusting_cloudflare_shared_ca_fails(sdk, monkeypatch):
    read, fetched = collect(sdk, monkeypatch, 'verify', CLOUDFLARE_PEM + private_ca_pem())
    assert fetched == [BUNDLE_URL]
    finding = decide(read)
    assert finding['status'] == 'FAIL'
    assert finding['severity'] == 'medium'
    [match] = finding['evidence']['shared_cdn_cas']
    assert match['provider'] == 'Cloudflare' and 'origin-pull.cloudflare.net' in match['subject']
    assert finding['evidence']['trust_store_name'] == 'origin'
    assert finding['evidence']['internet_facing'] is True


def test_internal_load_balancer_finding_is_low(sdk, monkeypatch):
    read, _ = collect(sdk, monkeypatch, 'verify', CLOUDFLARE_PEM, scheme='internal')
    finding = decide(read)
    assert finding['status'] == 'FAIL' and finding['severity'] == 'low'


def test_verify_listener_with_only_a_private_ca_passes(sdk, monkeypatch):
    read, _ = collect(sdk, monkeypatch, 'verify', private_ca_pem())
    assert decide(read)['status'] == 'PASS'


@pytest.mark.parametrize('mode', ['passthrough', 'off'])
def test_listener_without_client_certificate_verification_is_not_applicable(sdk, monkeypatch, mode):
    read, fetched = collect(sdk, monkeypatch, mode)
    assert fetched == []
    assert decide(read)['status'] == 'NOT_APPLICABLE'


def test_denied_bundle_read_is_unknown_and_names_the_action(sdk, monkeypatch):
    read, fetched = collect(sdk, monkeypatch, 'verify', None)
    assert fetched == []
    finding = decide(read)
    assert finding['status'] == 'UNKNOWN'
    assert 'elasticloadbalancing:GetTrustStoreCaCertificatesBundle' in str(finding['evidence'])


def test_unreadable_bundle_download_is_unknown_not_pass(sdk, monkeypatch):
    def unavailable(requests, url, region):
        raise aws.ReadFailure('not_collected', 'trust_store_bundle_download_unavailable')
    session, add = sdk
    elb = add('elbv2')
    elb.add_response('describe_load_balancers', {'LoadBalancers': [{'LoadBalancerArn': LB, 'Scheme': 'internet-facing',
                                                                    'Type': 'application'}]}, {})
    elb.add_response('describe_listeners', {'Listeners': [{'ListenerArn': LISTENER, 'LoadBalancerArn': LB,
        'Protocol': 'HTTPS', 'MutualAuthentication': {'Mode': 'verify', 'TrustStoreArn': STORE}}]}, {'LoadBalancerArn': LB})
    elb.add_response('describe_trust_stores', {'TrustStores': []}, {'TrustStoreArns': [STORE]})
    elb.add_response('get_trust_store_ca_certificates_bundle', {'Location': BUNDLE_URL}, {'TrustStoreArn': STORE})
    monkeypatch.setattr(collector, 'download', unavailable)
    read = collector.listeners(aws.Requests({}), session, REGION, ACCOUNT)
    assert decide(read)['status'] == 'UNKNOWN'


@pytest.mark.parametrize('url', ['http://b.s3.eu-west-1.amazonaws.com/x', 'https://evil.example.com/x',
                                 'https://b.s3.eu-west-1.amazonaws.com.evil.com/x', 'https://169.254.169.254/x'])
def test_bundle_fetch_only_targets_aws_s3_over_https(url):
    with pytest.raises(ValueError):
        collector.validate_url(url, REGION)
    collector.validate_url(BUNDLE_URL, REGION)
