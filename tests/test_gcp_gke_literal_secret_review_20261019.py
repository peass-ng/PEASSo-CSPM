"""Native GCP cluster production -> pinned read-only Kubernetes mock -> checks.

Shared pinned scanner/dedup patterns attributed to Function/Logging/additional
literal reviews. No sockets, cloud calls, helpers or credential verification.
"""
import base64
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from importlib.metadata import version
import io
import json
import ssl
import socket
from types import SimpleNamespace
from uuid import uuid5, NAMESPACE_URL
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from google.oauth2.credentials import Credentials as OAuthCredentials
from peaso import secret_scanning as scanning
from peaso.secret_findings import deduplicate_secret_findings
from peaso.collectors import gcp
from peaso.collectors import gcp_gke_literal_secret_indicators as native
from peaso.checks import gcp_gke_literal_secret_review_20261019 as check

SCOPE = 'projects/review'
CLUSTER = SCOPE + '/locations/us-central1-a/clusters/cluster-a'
IP = '34.123.45.67'
TOKEN = 'ghp_' + '7mQ2zR9wL4cV8nK1sF6aH3jP5uD0xB2yE9rT'
AUTH = 'ya29.SYNTHETIC_GOOGLE_BEARER_NEVER_STORE'
CANARY = 'UNTRUSTED_METADATA_NEVER_STORE'


@pytest.fixture(scope='module')
def ca():
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'Synthetic GKE review CA')])
    cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(key.public_key())
        .serial_number(x509.random_serial_number()).not_valid_before(datetime.now(timezone.utc) - timedelta(days=1))
        .not_valid_after(datetime(2099, 1, 1, tzinfo=timezone.utc))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True).sign(key, hashes.SHA256()))
    return SimpleNamespace(encoded=base64.b64encode(cert.public_bytes(serialization.Encoding.PEM)).decode(),
                           der=cert.public_bytes(serialization.Encoding.DER), cert=cert)


def cluster_row(ca):
    # Native Cluster.name is SHORT; not a synthetic resource-scoped name.
    return {'name': 'cluster-a', 'location': 'us-central1-a', 'status': 'RUNNING', 'endpoint': IP,
        'selfLink': 'https://container.googleapis.com/v1/projects/review/zones/us-central1-a/clusters/cluster-a',
        'masterAuth': {'clusterCaCertificate': ca.encoded, 'clientKey': CANARY}}


def metadata(kind, name, ns='team'):
    return {'name': name, 'namespace': ns, 'uid': str(uuid5(NAMESPACE_URL, kind + '/' + ns + '/' + name)),
            'resourceVersion': '101', 'annotations': {'last-applied': CANARY}, 'managedFields': [{'fieldsV1': CANARY}]}


def configmap(value='public', name='settings', ns='team'):
    return {'apiVersion': 'v1', 'kind': 'ConfigMap', 'metadata': metadata('ConfigMap', name, ns),
        'data': {'setting': value}, 'binaryData': {'text': base64.b64encode(('setting=' + value).encode()).decode()}}


def pod(value='public', name='worker', ns='team'):
    return {'apiVersion': 'v1', 'kind': 'Pod', 'metadata': metadata('Pod', name, ns),
        'spec': {'containers': [{'name': 'main', 'env': [{'name': 'MODE', 'value': value},
            {'name': 'MANAGED', 'valueFrom': {'secretKeyRef': {'name': 'managed-secret', 'key': 'password', 'optional': False}}}],
            'envFrom': [{'secretRef': {'name': 'managed-env'}}], 'args': ['--setting=' + value], 'command': ['echo', value]}],
            'volumes': [{'name': 'service-account-token', 'projected': {'sources': [{'serviceAccountToken': {'path': CANARY}}]}}]}}


def listing(kind, rows, token='', rv='100'):
    return {'apiVersion': 'v1', 'kind': kind + 'List', 'metadata': {'resourceVersion': rv, 'continue': token}, 'items': rows}


class GoogleResponse:
    status_code = 200
    def __init__(self, data): self.data = data
    def json(self): return deepcopy(self.data)
    def close(self): pass


class KubeResponse:
    def __init__(self, data, status=200, headers=None):
        encoded = data if isinstance(data, bytes) else json.dumps(data).encode()
        self.body = io.BytesIO(encoded)
        self.status = status
        self.headers = {'Content-Length': str(len(encoded))} if headers is None else headers
        self.chunked = self.headers.get('Transfer-Encoding') == 'chunked'
        self.closed = False
    def getheader(self, key, default=None):
        return next((value for name, value in self.headers.items() if name.lower() == key.lower()), default)
    def read(self, size): return self.body.read(size)
    def close(self): self.closed = True


@pytest.fixture(autouse=True)
def clear_results(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("unmocked socket access", pytrace=False)
    for name in ("connect", "connect_ex"):
        monkeypatch.setattr(socket.socket, name, forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    scanning._RESULTS.clear()
    yield
    scanning._RESULTS.clear()


@pytest.fixture
def clean(monkeypatch):
    monkeypatch.setattr(scanning, '_scan_kingfisher', lambda *a: [])
    monkeypatch.setattr(scanning, '_scan_trufflehog', lambda *a: [])


@pytest.fixture
def harness(monkeypatch, ca):
    def run(*, maps=None, pods=None, kube_pages=None, clusters=None, options=None, scopes=None,
            auth_mode='sdk', google_extra=None, status=200, mutate_source=None, connection_error=None, after_response=None):
        opts = {'inventories': [native.KIND], 'retries': 0, 'content_secret_scans': True,
            '_content_secret_scan_kinds': [native.KIND], 'selected_gke_clusters': [CLUSTER],
            'selected_gke_namespaces': {CLUSTER: ['team']}, **(options or {})}
        sdk = OAuthCredentials(AUTH, scopes=[native.CLOUD_SCOPE], granted_scopes=None,
                               expiry=datetime.now(timezone.utc).replace(tzinfo=None) + timedelta(hours=1))
        credentials = gcp.Credentials({'token': AUTH})
        transport = gcp.Transport(credentials, opts)
        google_calls = []
        cluster_data = {'clusters': [cluster_row(ca)] if clusters is None else clusters, **(google_extra or {})}
        def google_request(method, url, **kwargs):
            assert method == 'GET' and url == 'https://container.googleapis.com/v1/' + SCOPE + '/locations/-/clusters'
            google_calls.append({'method': method, 'url': url})
            return GoogleResponse(cluster_data)
        monkeypatch.setattr(transport, '_session', lambda: SimpleNamespace(request=google_request))
        collector = gcp.GCPCollector({'auth': {}, 'options': opts, 'scopes': [SCOPE] if scopes is None else scopes},
            [native.KIND], transport=transport)
        if SCOPE not in collector.scopes: collector.scopes.append(SCOPE)  # Simulated discovered project only.
        source_jobs = [j for j in collector.scope_jobs(SCOPE) if j[0] == 'gke_cluster']
        source = collector.envelope(*source_jobs[0])
        collector.collections[('gke_cluster', SCOPE)] = source
        if mutate_source is not None: mutate_source(source, transport)
        # Control-plane collection used actual Credentials; bridge reuses only its existing token.
        if auth_mode != 'pasted':
            credentials.direct_token = None
            credentials.credential = sdk
        if auth_mode == 'gcloud':
            credentials.credential = None
            credentials.gcloud = SimpleNamespace(token=AUTH, expires=native.time.monotonic() + 100,
                headers=lambda: pytest.fail('gcloud helper invoked'))
        if auth_mode == 'missing': credentials.credential = None
        if auth_mode == 'expired': sdk.expiry = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(minutes=1)
        if kube_pages is None:
            kube_pages = []
            if opts.get('selected_gke_namespaces') is None:
                kube_pages.append(listing('Namespace', [{'apiVersion': 'v1', 'kind': 'Namespace', 'metadata': {'name': 'team'}}]))
            kube_pages += [listing('ConfigMap', [configmap()] if maps is None else maps), listing('Pod', [pod()] if pods is None else pods)]
        responses = [p if isinstance(p, (KubeResponse, native.http.client.HTTPResponse)) else KubeResponse(p, status) for p in kube_pages]
        kube_calls, contexts = [], []
        class Connection:
            def __init__(self, host, port, context, timeout):
                if connection_error is not None: raise connection_error
                expected = next(row for row in cluster_data['clusters'] if row.get('endpoint') == host)
                assert port == 443 and 0 < timeout <= 1
                assert context.verify_mode == ssl.CERT_REQUIRED and context.check_hostname is True
                assert context.minimum_version >= ssl.TLSVersion.TLSv1_2
                expected_ca = x509.load_pem_x509_certificate(base64.b64decode(expected['masterAuth']['clusterCaCertificate'])).public_bytes(serialization.Encoding.DER)
                assert context.get_ca_certs(binary_form=True) == [expected_ca]
                contexts.append(context)
                self.index = None
            def request(self, method, path, headers):
                assert method == 'GET' and headers == {'Authorization': 'Bearer ' + AUTH,
                    'Accept': 'application/json', 'Accept-Encoding': 'identity'}
                assert '/secrets' not in path and '/exec' not in path and '/logs' not in path
                self.index = len(kube_calls)
                kube_calls.append({'method': method, 'path': path})
            def getresponse(self):
                if after_response is not None: after_response()
                return responses[self.index]
            def close(self): pass
        monkeypatch.setattr(native.http.client, 'HTTPSConnection', Connection)
        collector.dependent_jobs()
        envelope = collector.collections[(native.KIND, SCOPE)]
        index = {'context': {'provider': 'gcp', 'scope': SCOPE, 'metadata': {
            **native.selection_metadata(collector), 'source_requests': deepcopy(transport.evidence)}},
            'collections': {native.KIND: [envelope], 'gke_cluster': [source]}}
        items = envelope['items']
        verdicts = [check.evaluate(item, index) for item in items]
        return SimpleNamespace(items=items, item=items[0] if items else {}, index=index, source=source,
            envelope=envelope, verdicts=verdicts, result=verdicts[0] if verdicts else check.evaluate({}, index),
            transport=transport, google_calls=google_calls, kube_calls=kube_calls, responses=responses, contexts=contexts)
    return run


def test_actual_pinned_pair_both_native_types_dedup_privacy_and_no_reference_dereference(harness, capsys):
    assert version('kingfisher-secret-scanner') == scanning.KINGFISHER_VERSION
    assert scanning._trufflehog()
    result = harness(maps=[configmap(TOKEN)], pods=[pod(TOKEN)])
    assert [r[0] for r in result.verdicts] == ['FAIL', 'FAIL']
    findings = []
    for item, (status, evidence) in zip(result.items, result.verdicts):
        assert len(evidence['secret_leaks']) == 1
        assert {d['engine'] for d in evidence['secret_leaks'][0]['detectors']} == {'kingfisher', 'trufflehog'}
        findings.append({'provider': 'gcp', 'check_id': check.CHECK_ID, 'scope': SCOPE,
            'resource_id': item['name'], 'status': status, 'evidence': evidence})
    dedup = deduplicate_secret_findings(findings)
    assert len(dedup) == 1
    assert len(dedup[0]['evidence']['secret_leaks'][0]['locations']) >= 5
    pod_item = next(item for item in result.items if item['nativeKind'] == 'Pod')
    assert any(r.get('valueFrom', {}).get('secretKeyRef', {}).get('name') == 'managed-secret' for r in pod_item['references'])
    assert len(result.kube_calls) == 2 and len(result.google_calls) == 1
    saved = json.dumps([result.envelope, result.verdicts, result.transport.evidence, dedup]) + repr(result.transport.cache) + repr(scanning._RESULTS) + str(capsys.readouterr())
    assert all(v not in saved for v in (TOKEN, AUTH, CANARY, base64.b64encode(('setting=' + TOKEN).encode()).decode()))
    assert all(r.closed for r in result.responses)


def test_actual_pinned_negative_is_only_returned_supported_configuration(harness):
    result = harness()
    assert [r[0] for r in result.verdicts] == ['PASS', 'PASS']
    assert 'returned supported workload configuration' in result.result[1]['observed']
    assert result.source['items'][0]['name'] == 'cluster-a'
    assert not result.source['items'][0]['name'].startswith('projects/')


@pytest.mark.parametrize('mode', ['pasted', 'gcloud', 'sdk'])
def test_existing_token_with_no_scope_metadata_can_be_authorized_by_native_api(harness, clean, mode):
    result = harness(auth_mode=mode)
    assert result.result[0] == 'PASS' and len(result.kube_calls) == 2


@pytest.mark.parametrize('status', [401, 403])
def test_iam_cluster_metadata_does_not_establish_kubernetes_rbac(harness, status):
    result = harness(kube_pages=[{'kind': 'Status', 'message': TOKEN}], status=status, auth_mode='pasted')
    assert result.source['status'] == 'collected'
    assert result.result[0] == 'UNKNOWN' and result.envelope['status'] == 'denied'
    assert len(result.kube_calls) == 1
    assert TOKEN not in json.dumps([result.envelope, result.transport.evidence])


@pytest.mark.parametrize('options', [{'content_secret_scans': False},
    {'_content_secret_scan_kinds': []}, {'selected_gke_clusters': []}, {'gke_endpoint': 'https://evil.invalid'},
    {'selected_gke_namespaces': {CLUSTER: ['*']}}, {'selected_gke_namespaces': {CLUSTER: []}}])
def test_default_disabled_or_unbound_selection_zero_bridge_calls(harness, options):
    result = harness(kube_pages=[], options=options)
    assert result.result[0] == 'UNKNOWN' and not result.kube_calls


def test_discovery_of_project_does_not_authorize_content(harness):
    result = harness(kube_pages=[], scopes=['organizations/123'], options={'all_projects': True})
    assert result.result[0] == 'UNKNOWN' and not result.kube_calls


@pytest.mark.parametrize('mode', ['missing', 'expired'])
def test_missing_or_expired_existing_token_does_not_invoke_helpers(harness, mode):
    result = harness(auth_mode=mode, kube_pages=[])
    assert result.result[0] == 'UNKNOWN' and not result.kube_calls


@pytest.mark.parametrize('case', ['full_name', 'selflink', 'location', 'project', 'duplicate', 'private_ip', 'hostname', 'url', 'ca_missing', 'ca_invalid', 'partial', 'source_receipt'])
def test_native_cluster_ca_endpoint_and_subject_proof_required_before_bearer_use(harness, ca, case):
    rows = [cluster_row(ca)]
    extra = {}
    mutate = None
    if case == 'full_name': rows[0]['name'] = CLUSTER
    if case == 'selflink': del rows[0]['selfLink']
    if case == 'location': rows[0]['location'] = 'europe-west1'
    if case == 'project': rows[0]['selfLink'] = rows[0]['selfLink'].replace('/review/', '/other/')
    if case == 'duplicate':
        # Source collector normally coalesces identical identities; conflicting location fact is also unproved.
        def mutate(source, transport): source['items'].append(deepcopy(source['items'][0]))
    if case == 'private_ip': rows[0]['endpoint'] = '10.0.0.1'
    if case == 'hostname': rows[0]['endpoint'] = 'attacker.invalid'
    if case == 'url': rows[0]['endpoint'] = 'https://34.123.45.67/other'
    if case == 'ca_missing': del rows[0]['masterAuth']['clusterCaCertificate']
    if case == 'ca_invalid': rows[0]['masterAuth']['clusterCaCertificate'] = base64.b64encode(b'not a certificate').decode()
    if case == 'partial': extra['missingZones'] = ['us-central1-a']
    if case == 'source_receipt':
        def mutate(source, transport): transport.evidence[0]['http_status'] = 403
    result = harness(clusters=rows, google_extra=extra, kube_pages=[], mutate_source=mutate)
    assert result.result[0] == 'UNKNOWN' and not result.kube_calls


def test_bounded_native_namespace_discovery_then_exact_namespaced_lists(harness, clean):
    result = harness(options={'selected_gke_namespaces': None})
    assert result.result[0] == 'PASS'
    assert [c['path'].split('?')[0] for c in result.kube_calls] == [
        '/api/v1/namespaces', '/api/v1/namespaces/team/configmaps', '/api/v1/namespaces/team/pods']
    assert result.item['namespaceAuthorization']['mode'] == 'discovered'


def test_namespace_list_denied_does_not_guess_default_or_read_workloads(harness):
    result = harness(options={'selected_gke_namespaces': None}, kube_pages=[{'kind': 'Status', 'message': TOKEN}], status=403)
    assert result.result[0] == 'UNKNOWN' and len(result.kube_calls) == 1


@pytest.mark.parametrize('case', ['binary', 'base64', 'overlap', 'value', 'map', 'foreign', 'uid', 'partial_metadata'])
def test_configmap_native_content_omission_and_unsupported_shapes(harness, clean, case):
    row = configmap()
    if case == 'binary': row['binaryData']['text'] = base64.b64encode(b'\xff\xfe').decode()
    if case == 'base64': row['binaryData']['text'] = 'not base64!'
    if case == 'overlap': row['binaryData']['setting'] = base64.b64encode(b'text').decode()
    if case == 'value': row['data']['setting'] = 'x' * (native.MAX_VALUE_BYTES + 1)
    if case == 'map': row['data'] = []
    if case == 'foreign': row['metadata']['namespace'] = 'other'
    if case == 'uid': row['metadata']['uid'] = 'ambiguous'
    if case == 'partial_metadata': row['kind'] = 'PartialObjectMetadata'
    result = harness(maps=[row], pods=[])
    assert result.result[0] == 'UNKNOWN'


def test_omitted_configmap_maps_are_empty_only_on_bound_complete_native_object(harness, clean):
    row = configmap(); del row['data']; del row['binaryData']
    result = harness(maps=[row], pods=[])
    assert result.result[0] == 'PASS'
    assert len(result.item[native.MARKER]['surfaces']) == 2


def test_pod_all_container_classes_and_managed_secret_references(harness, clean):
    row = pod()
    row['spec']['initContainers'] = [{'name': 'init', 'env': [{'name': 'FROM_FIELD', 'valueFrom': {'fieldRef': {'fieldPath': 'metadata.name'}}}]}]
    row['spec']['ephemeralContainers'] = [{'name': 'debug', 'args': ['--public'], 'command': ['echo']}]
    result = harness(maps=[], pods=[row])
    assert result.result[0] == 'PASS'
    assert len(result.item[native.MARKER]['surfaces']) == 9
    assert any(r['path'] == 'initContainers/1/env' for r in result.item['references'])
    assert all('/ephemeralcontainers' not in c['path'] for c in result.kube_calls)


@pytest.mark.parametrize('case', ['union', 'duplicate_env', 'missing_containers', 'args', 'reference', 'envfrom', 'partial'])
def test_pod_literal_and_reference_shapes_fail_closed(harness, clean, case):
    row = pod(); c = row['spec']['containers'][0]
    if case == 'union': c['env'][0]['valueFrom'] = {'secretKeyRef': {'name': 's', 'key': 'k'}}
    if case == 'duplicate_env': c['env'].append(deepcopy(c['env'][0]))
    if case == 'missing_containers': del row['spec']['containers']
    if case == 'args': c['args'] = 'not an array'
    if case == 'reference': c['env'][1]['valueFrom']['secretKeyRef']['value'] = TOKEN
    if case == 'envfrom': c['envFrom'][0]['configMapRef'] = {'name': 'also'}
    if case == 'partial': row['_coverage'] = {'spec': {'status': 'partial'}}
    result = harness(maps=[], pods=[row])
    assert result.result[0] == 'UNKNOWN'
    assert TOKEN not in json.dumps([result.envelope, result.transport.evidence])


@pytest.mark.parametrize('case', ['redirect', 'short', 'gzip', 'unframed', 'too_large', 'invalid_json', 'unexpected_kind'])
def test_native_https_framing_redirect_and_error_content_never_certify(harness, clean, case):
    body = listing('ConfigMap', [configmap()])
    response = KubeResponse(body)
    if case == 'redirect': response = KubeResponse({'message': TOKEN}, 302, {'Location': 'https://evil.invalid/'})
    if case == 'short': response.headers['Content-Length'] = str(int(response.headers['Content-Length']) + 1)
    if case == 'gzip': response.headers['Content-Encoding'] = 'gzip'
    if case == 'unframed': response.headers = {}
    if case == 'too_large': response.headers['Content-Length'] = str(native.MAX_HTTP_BYTES + 1)
    if case == 'invalid_json': response = KubeResponse(b'{"items":[' + TOKEN.encode())
    if case == 'unexpected_kind': response = KubeResponse(listing('Secret', []))
    result = harness(kube_pages=[response])
    assert result.result[0] == 'UNKNOWN' and len(result.kube_calls) == 1
    assert TOKEN not in json.dumps([result.envelope, result.transport.evidence])


def test_reader_allowlist_cannot_get_secret_values_or_pod_subresources(harness, clean, monkeypatch):
    original = native.Reader.pages
    paths = ['/api/v1/namespaces/team/secrets', '/api/v1/namespaces/team/pods/a/log',
             '/api/v1/namespaces/team/pods/a/exec', '/api/v1/namespaces/team/pods/a/attach',
             '/api/v1/namespaces/team/pods/a/portforward', '/apis/certificates.k8s.io/v1/certificatesigningrequests']
    def prohibited(self, path):
        for forbidden in paths:
            with pytest.raises(gcp.ReadError, match='gke_literal_path_prohibited'):
                self.read(forbidden, {'limit': native.PAGE_SIZE})
        yield from original(self, path)
    monkeypatch.setattr(native.Reader, 'pages', prohibited)
    result = harness()
    assert result.result[0] == 'PASS' and len(result.kube_calls) == 2


@pytest.mark.parametrize('engine', ['kingfisher', 'trufflehog'])
def test_either_tool_failure_even_positive_other_engine_unknown(harness, monkeypatch, engine):
    monkeypatch.setattr(scanning, '_scan_kingfisher', lambda *a: [(TOKEN, 'synthetic', 1)])
    monkeypatch.setattr(scanning, '_scan_trufflehog', lambda *a: [(TOKEN, 'synthetic', 1)])
    def fail(*args): raise RuntimeError(TOKEN)
    monkeypatch.setattr(scanning, '_scan_' + engine, fail)
    result = harness(maps=[configmap(TOKEN)], pods=[])
    assert result.result[0] == 'UNKNOWN'
    assert TOKEN not in json.dumps([result.envelope, result.transport.evidence])


def test_shared_collector_rejects_non_boolean_content_option_before_reads(harness):
    with pytest.raises(ValueError, match='content_secret_scans must be a boolean'):
        harness(kube_pages=[], options={'content_secret_scans': 'true'})


def test_pagination_continuation_is_transient_and_list_version_consistent(harness, clean):
    result = harness(kube_pages=[listing('ConfigMap', [configmap(name='first')], token='PRIVATE_CURSOR'),
        listing('ConfigMap', [configmap(name='second')]), listing('Pod', [])])
    assert [r[0] for r in result.verdicts] == ['PASS', 'PASS']
    assert 'continue=PRIVATE_CURSOR' in result.kube_calls[1]['path']
    assert 'PRIVATE_CURSOR' not in json.dumps([result.envelope, result.transport.evidence])


@pytest.mark.parametrize('case', ['pages', 'repeat', 'version', 'duplicate', 'remaining', 'namespace_limit'])
def test_pagination_and_namespace_completeness_fail_closed(harness, clean, case):
    opts = None
    first = listing('ConfigMap', [configmap()], token='next')
    if case == 'pages': pages = [listing('ConfigMap', [], token=str(i)) for i in range(3)]
    if case == 'repeat': pages = [listing('ConfigMap', [], token='next')] * 2
    if case == 'version': pages = [first, listing('ConfigMap', [configmap(name='second')], rv='999')]
    if case == 'duplicate': pages = [first, listing('ConfigMap', [configmap()])]
    if case == 'remaining':
        page = listing('ConfigMap', []); page['metadata']['remainingItemCount'] = 1; pages = [page]
    if case == 'namespace_limit':
        opts = {'selected_gke_namespaces': None}
        pages = [listing('Namespace', [{'apiVersion': 'v1', 'kind': 'Namespace', 'metadata': {'name': 'team' + str(i)}} for i in range(native.MAX_NAMESPACES + 1)])]
    result = harness(kube_pages=pages, options=opts)
    assert result.result[0] == 'UNKNOWN'
    assert len(result.kube_calls) <= 3


def test_actual_same_value_dedup_across_selected_clusters_namespaces_and_surfaces(harness, ca):
    second = cluster_row(ca)
    second['name'] = 'cluster-b'; second['endpoint'] = '34.123.45.68'
    second['selfLink'] = second['selfLink'].replace('/cluster-a', '/cluster-b')
    selected_b = CLUSTER.replace('/cluster-a', '/cluster-b')
    pages = []
    for ns in ('team', 'other', 'team'):
        row = configmap(TOKEN, ns=ns)
        pages.extend([listing('ConfigMap', [row]), listing('Pod', [])])
    result = harness(clusters=[cluster_row(ca), second], kube_pages=pages, options={
        'selected_gke_clusters': [CLUSTER, selected_b],
        'selected_gke_namespaces': {CLUSTER: ['team', 'other'], selected_b: ['team']}})
    assert [r[0] for r in result.verdicts] == ['FAIL'] * 3
    findings = [{'provider': 'gcp', 'check_id': check.CHECK_ID, 'scope': SCOPE,
        'resource_id': item['name'], 'status': 'FAIL', 'evidence': outcome[1]}
        for item, outcome in zip(result.items, result.verdicts)]
    dedup = deduplicate_secret_findings(findings)
    assert len(dedup) == 1
    locations = dedup[0]['evidence']['secret_leaks'][0]['locations']
    assert len({loc['resource_id'] for loc in locations}) == 3
    assert len(result.kube_calls) == 6


@pytest.mark.parametrize('bound', ['MAX_CALLS', 'MAX_RESOURCES', 'MAX_READ_BYTES', 'MAX_SCAN_BYTES', 'MAX_SECONDS'])
def test_global_bridge_budget_shares_counters_and_never_becomes_clean(harness, clean, monkeypatch, bound):
    monkeypatch.setattr(native, bound, 0 if bound in ('MAX_RESOURCES', 'MAX_SECONDS') else 1)
    result = harness()
    assert result.result[0] == 'UNKNOWN'
    assert result.transport.calls == len(result.google_calls) + len(result.kube_calls)


def test_native_call_budget_and_cancellation_are_shared(harness, clean):
    from threading import Event
    event = Event()
    result = harness(options={'cancel_event': event}, after_response=event.set)
    assert result.result[0] == 'UNKNOWN' and len(result.kube_calls) == 1
    result = harness(options={'max_calls': 1}, kube_pages=[])
    assert result.result[0] == 'UNKNOWN' and not result.kube_calls


def test_unreachable_private_or_tls_failure_has_no_raw_error_evidence(harness):
    result = harness(kube_pages=[], connection_error=ssl.SSLCertVerificationError(TOKEN))
    assert result.result[0] == 'UNKNOWN' and not result.kube_calls
    assert TOKEN not in json.dumps([result.envelope, result.transport.evidence])


@pytest.mark.parametrize('case', ['provider', 'partial', 'duplicate', 'plan', 'cluster_ca', 'cluster_endpoint', 'namespace', 'receipt', 'engines', 'paths'])
def test_consumer_requires_cluster_namespace_native_reads_and_complete_pair(harness, clean, case):
    result = harness(maps=[configmap()], pods=[])
    assert result.result[0] == 'PASS'
    if case == 'provider': result.index['context']['provider'] = 'aws'
    if case == 'partial': result.envelope['status'] = 'partial'
    if case == 'duplicate': result.envelope['items'].append(deepcopy(result.item))
    if case == 'plan': result.index['context']['metadata']['gke_literal_selection']['status'] = 'disabled'
    if case == 'cluster_ca': result.item['clusterCaSha256'] = '0' * 64
    if case == 'cluster_endpoint': result.item['clusterEndpoint'] = '8.8.8.8'
    if case == 'namespace': result.item['namespaceAuthorization']['names'] = ['other']
    if case == 'receipt': result.index['context']['metadata']['source_requests'][-1]['http_status'] = 403
    if case == 'engines': result.item[native.MARKER]['surfaces'][0]['engines'].pop()
    if case == 'paths': result.item[native.MARKER]['surfaces'][0]['path'] = TOKEN
    assert check.evaluate(result.item, result.index)[0] == 'UNKNOWN'


def test_source_validator_catches_conflicting_native_rows_before_collector_coalescing(harness, ca):
    first, second = cluster_row(ca), cluster_row(ca)
    second['endpoint'] = '34.123.45.68'
    result = harness(clusters=[first, second], kube_pages=[])
    assert result.source['status'] != 'collected'
    assert result.result[0] == 'UNKNOWN' and not result.kube_calls


@pytest.mark.parametrize('terminated,expected', [(True, 'PASS'), (False, 'UNKNOWN')])
def test_real_http_client_chunk_integrity_after_valid_native_json(harness, clean, terminated, expected):
    body = json.dumps(listing('ConfigMap', [configmap()])).encode()
    wire = (b'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n' +
            format(len(body), 'x').encode() + b'\r\n' + body + b'\r\n' +
            (b'0\r\n\r\n' if terminated else b''))
    response = native.http.client.HTTPResponse(SimpleNamespace(makefile=lambda *a: io.BytesIO(wire)), method='GET')
    response.begin()
    result = harness(kube_pages=[response, listing('Pod', [])])
    assert result.result[0] == expected


def test_empty_native_workload_lists_do_not_invent_a_clean_resource(harness, clean):
    result = harness(maps=[], pods=[])
    assert not result.items and result.result[0] == 'UNKNOWN'


def test_native_ip_endpoint_disabled_and_multicast_are_not_contacted(harness, ca):
    for change in ({'endpoint': '224.0.0.1'}, {'controlPlaneEndpointsConfig': {'ipEndpointsConfig': {'enabled': False}}}):
        row = cluster_row(ca); row.update(change)
        result = harness(clusters=[row], kube_pages=[])
        assert result.result[0] == 'UNKNOWN' and not result.kube_calls


def test_conditional_email_scope_proposal_is_only_for_a_named_explicit_gke_plan():
    options = {'content_secret_scans': True, '_content_secret_scan_kinds': [native.KIND],
        'selected_gke_clusters': [CLUSTER], 'selected_gke_namespaces': {CLUSTER: ['team']}}
    collector = SimpleNamespace(options=options, requested_scopes=[SCOPE], needed={native.KIND})
    assert native.auth_requested(collector) is True
    for change in ({'content_secret_scans': False}, {'_content_secret_scan_kinds': []}, {'selected_gke_clusters': []}):
        collector.options = {**options, **change}
        assert native.auth_requested(collector) is False
    collector.options = options; collector.requested_scopes = ['organizations/123']
    assert native.auth_requested(collector) is False


@pytest.mark.parametrize('encoding', ['plaintext', 'base64'])
def test_detected_value_recurring_in_reference_metadata_stays_visible(harness, encoding):
    # Found secrets are intentionally shown in clear text to the tenant
    # (secret_scanning.redact_matches keeps metadata unchanged), so a detected
    # value reused as an env name stays visible in the reference metadata.
    row = pod(TOKEN)
    value = TOKEN if encoding == 'plaintext' else base64.b64encode(TOKEN.encode()).decode().rstrip('=')
    row['spec']['containers'][0]['env'][1]['name'] = value
    result = harness(maps=[], pods=[row])
    item = result.item
    assert item[native.MARKER]['complete'] and item[native.MARKER]['leaks']
    assert 'references' not in item.get('_coverage', {})
    assert item['references'][0]['envName'] == value
    print('PROBE', result.result[0])
    assert AUTH not in json.dumps([item, result.index, result.verdicts, result.transport.evidence])


def test_install_loads_native_fixture_cases_and_is_idempotent(monkeypatch):
    import peaso.checks as registry
    from peaso.checks import fixtures
    monkeypatch.setattr(registry, 'CHECKS', [c for c in registry.CHECKS if c.id != check.CHECK_ID])
    monkeypatch.setattr(fixtures, 'CASES', {k: v for k, v in fixtures.CASES.items() if k != check.CHECK_ID})
    check.install()
    check.install()
    assert sum(c.id == check.CHECK_ID for c in registry.CHECKS) == 1
    cases = fixtures.CASES[check.CHECK_ID]
    from peaso.checks.facts import MemoIndex
    for label in ('pass', 'fail', 'unknown'):
        assert check.evaluate(cases[label], MemoIndex(cases[label + '_index']))[0] == label.upper()
