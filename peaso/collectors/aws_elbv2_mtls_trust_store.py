"""CA certificates trusted by ALB HTTPS listeners that verify client certificates.

An ALB listener in mTLS ``verify`` mode accepts any client certificate that
chains to a CA in its ELBv2 trust store. This module records, per ALB HTTPS
listener, its mutual-authentication mode and, for ``verify`` listeners, the
subject, issuer and SHA-256 fingerprint of every CA in the trust store bundle.

GetTrustStoreCaCertificatesBundle returns a short-lived presigned S3 URL. The
bundle is fetched once per trust store and scan with a bounded, redirect-free
HTTPS GET to an AWS S3 host only; the PEM text is parsed in memory and only the
certificate identities are kept. A bundle that cannot be read is recorded with
its status, error code and the IAM action it needs, never as an empty trust store.
"""
from __future__ import annotations

import re
import threading
import time
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, ProxyHandler, build_opener

KIND = 'elbv2_mtls_listener'
BUNDLE_ACTION = 'elasticloadbalancing:GetTrustStoreCaCertificatesBundle'
DESCRIBE_TRUST_STORES_ACTION = 'elasticloadbalancing:DescribeTrustStores'
# ELBv2 trust stores hold at most a few hundred CAs; the PEM bundle is small.
BUNDLE_LIMIT = 4 * 1024 * 1024
MAX_CERTIFICATES = 1000
SPECS = {KIND: ('elbv2', 'describe_listeners', None)}
NATIVE_IDS = {KIND: 'ListenerArn'}
READ_ACTIONS = {('elbv2', 'describe_load_balancers'), ('elbv2', 'describe_listeners'),
                ('elbv2', 'describe_trust_stores'), ('elbv2', 'get_trust_store_ca_certificates_bundle')}
_TRUST_STORE = re.compile(r'arn:(?P<partition>aws(?:-[a-z0-9-]+)?):elasticloadbalancing:(?P<region>[a-z0-9-]+):'
                          r'(?P<account>[0-9]{12}):truststore/(?P<name>[A-Za-z0-9-]{1,32})/[A-Za-z0-9]+')


def _result(rows=(), status=None, code=None):
    from .aws import ReadResult
    rows = list(rows)
    return ReadResult(rows, status or ('collected' if rows else 'empty'), {'code': code} if code else None)


def _arn(value, partition, account, region, resource):
    return isinstance(value, str) and bool(re.fullmatch(
        'arn:' + re.escape(partition) + ':elasticloadbalancing:' + re.escape(region) + ':'
        + re.escape(account) + ':' + resource + '/.+', value))


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def validate_url(url, region):
    """Only an HTTPS AWS S3 host (virtual-host or path style), never an arbitrary host."""
    if not isinstance(url, str) or len(url) > 32768 or any(ord(c) <= 32 or ord(c) >= 127 for c in url):
        raise ValueError('invalid bundle URL')
    parsed = urlsplit(url)
    suffix = r'amazonaws\.com\.cn' if region.startswith('cn-') else r'amazonaws\.com'
    host = (r'(?:[a-z0-9][a-z0-9.-]*\.)?s3(?:[.-]dualstack)?(?:[.-]' + re.escape(region) + r')?\.' + suffix)
    if (parsed.scheme != 'https' or parsed.username is not None or parsed.password is not None
            or parsed.port is not None or parsed.fragment or not re.fullmatch(host, parsed.hostname or '')
            or not parsed.path.startswith('/')):
        raise ValueError('bundle URL outside AWS S3')
    return url


def download(requests, url, region, cap=BUNDLE_LIMIT):
    """One bounded GET under the scan call budget and deadline; no URL or error text leaks."""
    from .aws import ReadFailure
    try:
        validate_url(url, region)
        with requests._lock:
            requests.check_deadline()
            if requests.max_calls is not None and requests.calls >= requests.max_calls:
                raise ReadFailure('not_collected', 'call_limit')
            requests.calls += 1
        end = min(time.monotonic() + 10, requests.deadline if requests.deadline is not None else float('inf'))
        opener = build_opener(ProxyHandler({}), _NoRedirect())
        with opener.open(url, timeout=min(5, requests.timeout, max(0.001, end - time.monotonic()))) as response:
            if response.status != 200 or response.headers.get('Content-Encoding', 'identity') != 'identity':
                raise ValueError('unexpected HTTP response')
            length = response.headers.get('Content-Length')
            if length is not None and (not length.isdecimal() or int(length) > cap):
                raise ValueError('invalid HTTP length')
            body = bytearray()
            while True:
                requests.check_deadline()
                if time.monotonic() >= end:
                    raise ValueError('download deadline')
                chunk = response.read(min(65536, cap + 1 - len(body)))
                if not chunk:
                    break
                body.extend(chunk)
                if len(body) > cap:
                    raise ValueError('bundle too large')
            if length is not None and len(body) != int(length):
                raise ValueError('truncated bundle')
            return bytes(body)
    except ReadFailure as failure:
        if failure.code in ('collection_cancelled', 'intentional_scan_deadline', 'call_limit'):
            raise
        raise ReadFailure('not_collected', 'trust_store_bundle_download_unavailable') from None
    except Exception:
        raise ReadFailure('not_collected', 'trust_store_bundle_download_unavailable') from None


def _name(name):
    from cryptography.x509.oid import NameOID
    def first(oid):
        values = name.get_attributes_for_oid(oid)
        return str(values[0].value) if values else ''
    return {'string': name.rfc4514_string(), 'CN': first(NameOID.COMMON_NAME),
            'O': first(NameOID.ORGANIZATION_NAME), 'OU': first(NameOID.ORGANIZATIONAL_UNIT_NAME)}


def certificates(pem):
    """Subject, issuer and SHA-256 fingerprint of each PEM certificate, in bundle order."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    loaded = x509.load_pem_x509_certificates(pem)
    if len(loaded) > MAX_CERTIFICATES:
        raise ValueError('too many certificates')
    rows = []
    for certificate in loaded:
        subject, issuer = _name(certificate.subject), _name(certificate.issuer)
        rows.append({'subject': subject['string'], 'subject_cn': subject['CN'], 'subject_o': subject['O'],
                     'subject_ou': subject['OU'], 'issuer': issuer['string'],
                     'sha256': certificate.fingerprint(hashes.SHA256()).hex(':').upper()})
    return rows


def _state(requests):
    with requests._lock:
        state = getattr(requests, '_elbv2_trust_store_bundles', None)
        if state is None:
            state = requests._elbv2_trust_store_bundles = ({}, threading.Lock())
        return state


def _unread(status, code, action):
    return {'collection_status': status, 'error': {'code': code}, 'iam_action': action}


def bundle(requests, session, region, arn):
    """The trust store's CA identities, read once per trust store and scan."""
    cache, lock = _state(requests)
    key = (id(session), region, arn)
    with lock:
        if key in cache:
            return cache[key]
    response = requests.detail(session, 'elbv2', region, 'get_trust_store_ca_certificates_bundle', TrustStoreArn=arn)
    status = response.get('collection_status')
    location = response.get('Location')
    if status != 'collected':
        code = (response.get('error') or {}).get('code') or 'trust_store_bundle_unavailable'
        value = _unread(status or 'not_collected', code, BUNDLE_ACTION)
    elif not isinstance(location, str) or not location:
        value = _unread('malformed', 'trust_store_bundle_location_missing', BUNDLE_ACTION)
    else:
        from .aws import ReadFailure
        try:
            pem = download(requests, location, region)
            try:
                rows = certificates(pem)
            except Exception:
                rows = None
            value = (_unread('malformed', 'trust_store_bundle_unparseable', BUNDLE_ACTION) if not rows else
                     {'collection_status': 'collected', 'certificates': rows,
                      'source_operation': 'GetTrustStoreCaCertificatesBundle'})
        except ReadFailure as failure:
            if failure.code in ('collection_cancelled', 'intentional_scan_deadline'):
                raise
            value = _unread(failure.status, failure.code, BUNDLE_ACTION)
    with lock:
        return cache.setdefault(key, value)


def _trust_store_name(requests, session, region, arn):
    response = requests.detail(session, 'elbv2', region, 'describe_trust_stores', TrustStoreArns=[arn])
    stores = response.get('TrustStores') if response.get('collection_status') == 'collected' else None
    for store in stores if isinstance(stores, list) else ():
        if isinstance(store, dict) and store.get('TrustStoreArn') == arn and isinstance(store.get('Name'), str):
            return store['Name']
    match = _TRUST_STORE.fullmatch(arn)
    return match['name'] if match else None


def listeners(requests, session, region, account):
    partition = session.get_partition_for_region(region)
    rows, seen = [], set()

    def failure(read):
        return _result(rows, 'partial' if rows else read.status,
                       (read.error or {}).get('code', 'elbv2_mtls_inventory_incomplete'))
    try:
        lbs = requests.pages(session, 'elbv2', region, 'describe_load_balancers', 'LoadBalancers')
        if lbs.status not in ('collected', 'empty'):
            return failure(lbs)
        for lb in lbs.items:
            if not isinstance(lb, dict) or lb.get('Type') != 'application':
                continue
            arn = lb.get('LoadBalancerArn')
            if not _arn(arn, partition, account, region, 'loadbalancer') or lb.get('Scheme') not in ('internet-facing', 'internal'):
                raise ValueError('elbv2_mtls_load_balancer_identity_invalid')
            read = requests.pages(session, 'elbv2', region, 'describe_listeners', 'Listeners', LoadBalancerArn=arn)
            if read.status not in ('collected', 'empty'):
                return failure(read)
            for listener in read.items:
                if not isinstance(listener, dict) or listener.get('Protocol') != 'HTTPS':
                    continue
                identity = listener.get('ListenerArn')
                if not _arn(identity, partition, account, region, 'listener') or listener.get('LoadBalancerArn') != arn:
                    raise ValueError('elbv2_mtls_listener_parent_join_invalid')
                if identity in seen:
                    raise ValueError('elbv2_mtls_listener_duplicate_identity')
                seen.add(identity)
                mutual = listener.get('MutualAuthentication')
                mutual = mutual if isinstance(mutual, dict) else {}
                mode = mutual.get('Mode') or 'off'
                store = mutual.get('TrustStoreArn')
                row = {'ListenerArn': identity, 'LoadBalancerArn': arn, 'LoadBalancerName': lb.get('LoadBalancerName'),
                       'DNSName': lb.get('DNSName'), 'Scheme': lb['Scheme'],
                       'InternetFacing': lb['Scheme'] == 'internet-facing', 'Protocol': 'HTTPS',
                       'Port': listener.get('Port'),
                       'MutualAuthentication': {'Mode': mode, 'TrustStoreArn': store},
                       '_provenance': {'source_operation': 'DescribeLoadBalancers+DescribeListeners'
                                       + ('+GetTrustStoreCaCertificatesBundle' if mode == 'verify' else ''),
                                       'read_only': True,
                                       'semantics': 'configured trust store CAs; no client certificate was presented'}}
                if mode == 'verify':
                    if not _arn(store, partition, account, region, 'truststore'):
                        row['TrustStoreBundle'] = _unread('malformed', 'trust_store_arn_missing', BUNDLE_ACTION)
                    else:
                        row['TrustStoreName'] = _trust_store_name(requests, session, region, store)
                        row['TrustStoreBundle'] = bundle(requests, session, region, store)
                rows.append(row)
    except (ValueError, TypeError, KeyError, AttributeError) as exc:
        code = str(exc) if isinstance(exc, ValueError) and str(exc).startswith('elbv2_mtls_') else 'elbv2_mtls_response_malformed'
        return _result(rows, 'partial' if rows else 'malformed', code)
    return _result(rows)


FETCHERS = {KIND: listeners}
