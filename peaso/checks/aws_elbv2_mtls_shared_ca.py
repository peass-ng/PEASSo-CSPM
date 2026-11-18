"""ALB mTLS trust stores must not trust a CDN's shared origin-pull CA.

An ALB HTTPS listener in mTLS ``verify`` mode admits any client certificate
that chains to a CA in its trust store. Some CDNs present one client
certificate, issued by one CA, for every customer's origin pulls (Cloudflare's
default Authenticated Origin Pulls certificate). If the trust store holds that
CA, any account on the same CDN can point its own zone at the ALB and reach the
origin through the mTLS check, bypassing the owner's CDN WAF, Access policies
and rate limits.

The CA list is data: add an entry to ``SHARED_ORIGIN_PULL_CAS`` to cover
another CDN. A CA matches by SHA-256 fingerprint, or by its exact subject
attributes so a reissued shared CA is still caught.
"""
from __future__ import annotations

from . import result, unknown
from .facts import Unavailable, get, optional
from .fixtures import CASES
from .hacktricks_bp_common import ht_register

CHECK_ID = 'aws.htbp.elbv2.mtls_no_shared_cdn_origin_ca'
KIND = 'elbv2_mtls_listener'
TITLE = 'ALB mTLS trust store does not trust a CDN shared origin-pull CA'
REMEDIATION = (
    'Remove the shared CDN origin-pull CA from the ALB trust store. With Cloudflare, enable zone-level or per-hostname '
    'Authenticated Origin Pulls with your own CA and put only that CA in the trust store. Also allow only the CDN IP '
    'ranges in the load balancer security group, and have the application verify a per-customer CDN identity token '
    '(for example the Cloudflare Access JWT, Cf-Access-Jwt-Assertion).')
BUNDLE_ACTION = 'elasticloadbalancing:GetTrustStoreCaCertificatesBundle'

# Multi-tenant CDN CAs whose client certificate is shared by every customer.
SHARED_ORIGIN_PULL_CAS = (
    {'provider': 'Cloudflare', 'name': 'Authenticated Origin Pulls shared CA (global)',
     'sha256': {'9A:1A:C2:B4:BE:15:F9:F2:7E:EE:20:A7:34:CB:A4:E9:89:8F:61:00:1B:3B:D7:C8:4B:69:B5:6A:3E:25:A2:B9'},
     'subject': {'CN': 'origin-pull.cloudflare.net', 'O': 'CloudFlare, Inc.'}},
)


def shared_ca(certificate):
    """The SHARED_ORIGIN_PULL_CAS entry the certificate is, or None."""
    fingerprint = str(certificate.get('sha256', '')).upper()
    for entry in SHARED_ORIGIN_PULL_CAS:
        if fingerprint in entry['sha256']:
            return entry
        names = {'CN': certificate.get('subject_cn'), 'O': certificate.get('subject_o')}
        if all(names[key] == value for key, value in entry['subject'].items()):
            return entry
    return None


@ht_register(CHECK_ID, 'aws', 'network', KIND, TITLE, 'medium', 'SC-7', REMEDIATION,
             pages=['pentesting-cloud/aws-security/aws-unauthenticated-enum-access/aws-edge-origin-bypass/README.md',
                    'pentesting-cloud/aws-security/aws-unauthenticated-enum-access/aws-elb-unauthenticated-access/README.md'])
def mtls_shared_cdn_ca(item, index):
    listener = get(item, 'ListenerArn', str)
    mutual = get(item, 'MutualAuthentication', dict)
    mode = optional(mutual, 'Mode', 'off', str)
    evidence = {'listener_arn': listener, 'load_balancer_dns_name': item.get('DNSName'), 'scheme': item.get('Scheme'),
                'internet_facing': item.get('InternetFacing') is True, 'mtls_mode': mode}
    if mode != 'verify':
        return 'NOT_APPLICABLE', evidence
    evidence['trust_store_arn'] = get(mutual, 'TrustStoreArn', str)
    evidence['trust_store_name'] = item.get('TrustStoreName')
    # Read directly: an unread bundle carries its own status, code and IAM action.
    bundle = item.get('TrustStoreBundle')
    if not isinstance(bundle, dict):
        raise Unavailable('trust store CA bundle not collected')
    if bundle.get('collection_status') != 'collected':
        code = (bundle.get('error') or {}).get('code') if isinstance(bundle.get('error'), dict) else None
        action = bundle.get('iam_action') or BUNDLE_ACTION
        if bundle.get('collection_status') == 'denied':
            return unknown(f'trust store CA bundle read denied: grant {action}', denied_action=action,
                           error_code=code, **evidence)
        return unknown(f'trust store CA bundle unreadable ({code or "unknown error"}); needs {action}',
                       error_code=code, **evidence)
    certificates = get(bundle, 'certificates', list)
    if not certificates or any(not isinstance(c, dict) or not isinstance(c.get('sha256'), str) for c in certificates):
        raise Unavailable('trust store CA bundle has no readable certificates')
    matches = []
    for certificate in certificates:
        entry = shared_ca(certificate)
        if entry is not None:
            matches.append({'provider': entry['provider'], 'ca': entry['name'],
                            'subject': certificate.get('subject'), 'sha256': certificate['sha256']})
    return result(bool(matches), shared_cdn_cas=matches, trust_store_ca_count=len(certificates), **evidence)


_LISTENER = {'ListenerArn': 'arn:aws:elasticloadbalancing:eu-west-1:111111111111:listener/app/web/abc/def',
             'DNSName': 'web-1.eu-west-1.elb.amazonaws.com', 'Scheme': 'internet-facing', 'InternetFacing': True,
             'TrustStoreName': 'origin'}
_STORE = 'arn:aws:elasticloadbalancing:eu-west-1:111111111111:truststore/origin/abc'
_VERIFY = {'Mode': 'verify', 'TrustStoreArn': _STORE}
CASES[CHECK_ID] = {
    'pass': {**_LISTENER, 'MutualAuthentication': _VERIFY, 'TrustStoreBundle': {'collection_status': 'collected',
             'certificates': [{'subject': 'CN=Example Private Origin CA', 'subject_cn': 'Example Private Origin CA',
                               'subject_o': 'Example', 'sha256': '00:11'}]}},
    'fail': {**_LISTENER, 'MutualAuthentication': _VERIFY, 'TrustStoreBundle': {'collection_status': 'collected',
             'certificates': [{'subject': 'CN=origin-pull.cloudflare.net,O=CloudFlare\\, Inc.',
                               'subject_cn': 'origin-pull.cloudflare.net', 'subject_o': 'CloudFlare, Inc.',
                               'sha256': next(iter(SHARED_ORIGIN_PULL_CAS[0]['sha256']))}]}},
    'missing': {**_LISTENER, 'MutualAuthentication': _VERIFY},
    'malformed': {**_LISTENER, 'MutualAuthentication': _VERIFY, 'TrustStoreBundle': {'collection_status': 'collected',
                  'certificates': 'not-a-list'}},
}


def install():
    """Registration happens on import; kept for the package's explicit install list."""
    return CHECK_ID
