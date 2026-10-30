"""Memory-only SDK/HTTP stubs exercise real request cache and pure consumers."""
from copy import deepcopy
from datetime import datetime, timezone
import base64
import gzip
import hashlib
import io
import json
import stat
import tarfile
import threading
from types import SimpleNamespace
import zipfile
import pytest
from peaso.collectors import aws, aws_package_content_indicators as p
from peaso.checks import aws_package_content_review_20261019 as c
from datetime import datetime, timezone, timedelta

ACCOUNT, REGION = '123456789012', 'us-east-1'
SECRET = 'SyntheticOnly9342!Credential'
URL = f'https://awslambda-example.s3.{REGION}.amazonaws.com/package?X-Amz-Signature=NEVERCACHEME'
KINDS = list(c.SURFACES)
FUNCTIONS = dict(zip(KINDS, (c.function_code, c.layer_content, c.image_layers)))


@pytest.fixture(autouse=True)
def isolated_detector_dependencies(monkeypatch, request):
    """Parser/SDK unit cases do not require optional native tool installations."""
    from peaso import secret_scanning
    secret_scanning._RESULTS.clear()
    if request.node.name == 'test_real_dual_scanners_ecr_and_lambda_sdk_to_one_report_finding':
        import shutil
        pytest.importorskip('kingfisher_sdk')
        if not shutil.which('trufflehog'):
            pytest.skip('requires the optional pinned TruffleHog binary')
    else:
        monkeypatch.setattr(secret_scanning, '_scan_kingfisher', lambda *args: [])
        monkeypatch.setattr(secret_scanning, '_scan_trufflehog', lambda *args: [])
    yield
    secret_scanning._RESULTS.clear()


def zip_bytes(files=None, compression=zipfile.ZIP_DEFLATED):
    out = io.BytesIO()
    with zipfile.ZipFile(out, 'w', compression=compression) as archive:
        for name, value in (files or [('config.py', 'ready=true')]): archive.writestr(name, value)
    return out.getvalue()


def tar_bytes(files=None):
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode='w', format=tarfile.USTAR_FORMAT) as archive:
        for name, value in (files or [('config.py', b'ready=true')]):
            if isinstance(value, str): value = value.encode()
            info = tarfile.TarInfo(name); info.size = len(value)
            archive.addfile(info, io.BytesIO(value))
    return out.getvalue()


def digest(raw): return 'sha256:' + hashlib.sha256(raw).hexdigest()
def arn(service, name): return f'arn:aws:{service}:{REGION}:{ACCOUNT}:{name}'
def index(kind, item):
    scope = ACCOUNT + '/' + REGION
    return {'context': {'provider': 'aws', 'Account': ACCOUNT, 'scope': scope},
            'collections': {kind: [{'type': kind, 'scope': scope, 'status': 'collected', 'items': [item]}]}}


class Response:
    def __init__(self, data, *, headers=None, status=200, url=URL, cancel=None):
        self.source = io.BytesIO(data); self.status = status; self.url = url
        self.headers = {} if headers is None else headers
        self.cancel = cancel
    def geturl(self): return self.url
    def read(self, count):
        data = self.source.read(count)
        if self.cancel is not None: self.cancel.set()
        return data
    def __enter__(self): return self
    def __exit__(self, *args): return None


def http(monkeypatch, payloads):
    calls = []
    def open_(url, timeout):
        calls.append((url, timeout))
        payload = payloads[url]
        if isinstance(payload, Exception): raise payload
        return payload() if callable(payload) else Response(payload, url=url)
    monkeypatch.setattr(p, 'build_opener', lambda *a: SimpleNamespace(open=open_))
    return calls


def sdk(monkeypatch, kind, detected=True, *, enabled=True):
    text = "PASSWORD='" + SECRET + "'" if detected else 'ready=true'
    content = zip_bytes([('config.py', text)])
    calls, payloads = [], {URL: content}
    if kind == 'lambda_function':
        item = {'FunctionArn': arn('lambda', 'function:example'), 'FunctionName': 'example', 'Version': '$LATEST'}
        response = {'Configuration': {**item, 'PackageType': 'Zip', 'CodeSize': len(content), 'CodeSha256': base64.b64encode(hashlib.sha256(content).digest()).decode(), 'Environment': {'Variables': {'SECRET': SECRET}}}, 'Code': {'RepositoryType': 'S3', 'Location': URL}, 'Unknown': SECRET}
        operations = {'get_function': response}
    elif kind == 'lambda_layer_version':
        item = {'LayerVersionArn': arn('lambda', 'layer:example:1'), 'LayerArn': arn('lambda', 'layer:example'), 'LayerName': 'example', 'Version': 1}
        response = {**item, 'Content': {'Location': URL, 'CodeSize': len(content), 'CodeSha256': base64.b64encode(hashlib.sha256(content).digest()).decode()}, 'Description': SECRET}
        operations = {'get_layer_version': response}
    else:
        item = {'repositoryArn': arn('ecr', 'repository/example'), 'repositoryName': 'example', 'registryId': ACCOUNT}
        layer = gzip.compress(tar_bytes([('config.py', text)]))
        config = json.dumps({'architecture': 'amd64', 'os': 'linux',
            'rootfs': {'type': 'layers', 'diff_ids': [digest(tar_bytes([('config.py', text)]))]},
            'config': {'Env': ['STAGE=prod']}, 'history': [{'created_by': 'COPY safe'}]}).encode()
        ld, cd = digest(layer), digest(config)
        manifest = json.dumps({'schemaVersion': 2, 'mediaType': p.OCI,
            'config': {'mediaType': 'application/vnd.oci.image.config.v1+json', 'digest': cd, 'size': len(config)},
            'layers': [{'mediaType': 'application/vnd.oci.image.layer.v1.tar+gzip', 'digest': ld, 'size': len(layer)}]})
        image_digest = digest(manifest.encode())
        response = {'images': [{'registryId': ACCOUNT, 'repositoryName': 'example', 'imageId': {'imageDigest': image_digest}, 'imageManifest': manifest, 'imageManifestMediaType': p.OCI}], 'failures': []}
        payloads = {URL + '-config': config, URL + '-layer': layer}
        def location(**kw):
            which = '-config' if kw['layerDigest'] == cd else '-layer'
            return {'layerDigest': kw['layerDigest'], 'downloadUrl': URL + which}
        operations = {'batch_get_image': response, 'get_download_url_for_layer': location,
            'describe_images': {'imageDetails': [{'registryId': ACCOUNT, 'repositoryName': 'example', 'imageDigest': image_digest, 'imagePushedAt': datetime(2026, 10, 19, tzinfo=timezone.utc)}]}}
    def client(service, **kwargs):
        class Client:
            def __getattr__(self, operation):
                def invoke(**kw):
                    calls.append((service, operation, deepcopy(kw)))
                    if operation == 'get_caller_identity': return {'Account': ACCOUNT, 'Arn': f'arn:aws:sts::{ACCOUNT}:assumed-role/a/b', 'UserId': 'test'}
                    value = operations[operation]
                    return deepcopy(value(**kw) if callable(value) else value)
                return invoke
            def can_paginate(self, operation): return False
        return Client()
    session = SimpleNamespace(client=client)
    requests = aws.Requests({'content_secret_scans': enabled, 'retry_attempts': 1})
    # Root owns READ_ACTIONS integration; synthetic tests exercise real dispatcher.
    monkeypatch.setattr(aws, 'READ_ACTIONS', aws.READ_ACTIONS | p.READ_ACTIONS)
    downloads = http(monkeypatch, payloads)
    return requests, session, item, operations, calls, downloads, payloads


@pytest.mark.parametrize('kind', KINDS)
@pytest.mark.parametrize('detected', [True, False])
def test_sdk_http_future_consumer_chain(monkeypatch, kind, detected):
    requests, session, item, operations, calls, downloads, payloads = sdk(monkeypatch, kind, detected)
    result = p.ENRICHERS[kind](requests, session, REGION, [item])[0]
    status, evidence = FUNCTIONS[kind](result, index(kind, result))
    assert status == ('FAIL' if detected else 'PASS')
    assert len(evidence['observed']) <= 150
    cache = json.dumps([f.result() for f in requests._cache.values()], default=str)
    for value in (SECRET, 'NEVERCACHEME', URL, 'imageManifest', 'CodeSha256', 'downloadUrl', 'Location'):
        assert value not in cache
    assert downloads
    before = len(calls), len(downloads)
    again = p.ENRICHERS[kind](requests, session, REGION, [item])[0]
    assert again == result
    assert (len(calls), len(downloads)) == before
    assert all('_metadata_profile' not in args for _, _, args in calls)


def test_real_dual_scanners_ecr_and_lambda_sdk_to_one_report_finding(monkeypatch):
    """Synthetic contents, real detectors, mocked AWS/HTTP and real report path."""
    from peaso import engine
    from peaso.snapshot import make_snapshot
    from peaso.secret_scanning import _RESULTS
    token = 'ghp_' + '7mQ2zR9wL4cV8nK1sF6aH3jP5uD0xB2yE9rT'
    monkeypatch.setitem(globals(), 'SECRET', token)
    _RESULTS.clear()
    collections, selected = [], []
    for kind in KINDS:
        requests, session, item, _, calls, downloads, _ = sdk(monkeypatch, kind)
        enriched = p.ENRICHERS[kind](requests, session, REGION, [item])[0]
        status, evidence = FUNCTIONS[kind](enriched, index(kind, enriched))
        assert status == 'FAIL' and evidence['source_complete'] is True
        assert len(evidence['secret_leaks']) == 1
        assert {d['engine'] for d in evidence['secret_leaks'][0]['detectors']} == {'kingfisher', 'trufflehog'}
        cached = json.dumps([f.result() for f in requests._cache.values()], default=str)
        assert token not in cached
        assert calls and downloads
        collections.append({'type': kind, 'scope': ACCOUNT + '/' + REGION,
                            'status': 'collected', 'items': [enriched]})
        selected.append(next(d['id'] for d in c.DECLARATIONS if d['kind'] == kind))
    report = engine.evaluate_snapshot(make_snapshot('aws', [ACCOUNT + '/' + REGION], collections), checks=selected)
    failed = [f for f in report['findings'] if f['status'] == 'FAIL']
    assert len(failed) == 1 and report['stats']['by_status']['FAIL'] == 1
    assert sorted(failed[0]['linked_check_ids']) == sorted(selected)
    assert len(failed[0]['evidence']['secret_leaks'][0]['locations']) == 3
    assert token not in json.dumps(report)


@pytest.mark.parametrize('kind', KINDS)
def test_optout_no_sdk_or_download(monkeypatch, kind):
    requests, session, item, _, calls, downloads, _ = sdk(monkeypatch, kind, enabled=False)
    result = p.ENRICHERS[kind](requests, session, REGION, [item])[0]
    assert FUNCTIONS[kind](result, index(kind, result))[0] == 'UNKNOWN'
    assert calls == downloads == []


@pytest.mark.parametrize('value', [None, 0, 1, 'true', [], {}])
def test_option_strict_boolean(value):
    with pytest.raises(ValueError): aws.Requests({'content_secret_scans': value})


@pytest.mark.parametrize('kind', KINDS)
def test_foreign_native_no_target_content_api(monkeypatch, kind):
    requests, session, item, _, calls, downloads, _ = sdk(monkeypatch, kind)
    field = c.SURFACES[kind][0]
    item[field] = item[field].replace(ACCOUNT, '999999999999')
    result = p.ENRICHERS[kind](requests, session, REGION, [item])[0]
    assert FUNCTIONS[kind](result, index(kind, result))[0] == 'UNKNOWN'
    assert [op for _, op, _ in calls] == ['get_caller_identity']
    assert not downloads


@pytest.mark.parametrize('kind', KINDS)
@pytest.mark.parametrize('mutation', ['denied', 'malformed', 'foreign_response', 'integrity'])
def test_unusable_response_unknown_redacted_exception(monkeypatch, kind, mutation):
    requests, session, item, ops, calls, downloads, payloads = sdk(monkeypatch, kind)
    operation = {'lambda_function': 'get_function', 'lambda_layer_version': 'get_layer_version', 'ecr_repository': 'batch_get_image'}[kind]
    if mutation == 'denied':
        def denied(**kw):
            from botocore.exceptions import ClientError
            raise ClientError({'Error': {'Code': 'AccessDeniedException', 'Message': URL + SECRET}}, operation)
        ops[operation] = denied
    elif mutation == 'malformed': ops[operation] = {'Location': URL, 'Secret': SECRET}
    elif mutation == 'integrity':
        for key in payloads: payloads[key] += b'corruption'
    elif kind == 'lambda_function': ops[operation]['Configuration']['FunctionArn'] += ':foreign'
    elif kind == 'lambda_layer_version': ops[operation]['Version'] = 2
    else: ops[operation]['images'][0]['registryId'] = '999999999999'
    result = p.ENRICHERS[kind](requests, session, REGION, [item])[0]
    assert FUNCTIONS[kind](result, index(kind, result))[0] == 'UNKNOWN'
    assert SECRET not in json.dumps(result)
    for future in requests._cache.values():
        if future.exception() is not None:
            assert future.exception().__traceback__ is None
            assert URL not in str(future.exception())
        else: assert SECRET not in json.dumps(future.result(), default=str)


@pytest.mark.parametrize('kind', KINDS)
@pytest.mark.parametrize('mutation', ['no_context', 'partial_inventory', 'missing_source', 'wrong_account', 'wrong_region', 'forged_presence', 'bad_category', 'incomplete'])
def test_consumer_requires_full_bound_evidence(kind, mutation):
    item, ix = c._fixture(kind, False)
    marker = item['PackageContentSource']['PackageSecretIndicators']
    if mutation == 'no_context': ix['context'] = {}
    elif mutation == 'partial_inventory': ix['collections'][kind][0]['status'] = 'partial'
    elif mutation == 'missing_source': item.pop('PackageContentSource')
    elif mutation == 'wrong_account': marker['AccountId'] = '999999999999'
    elif mutation == 'wrong_region': marker['Region'] = 'eu-west-1'
    elif mutation == 'forged_presence': marker['HighConfidenceSecretPresent'] = True
    elif mutation == 'bad_category': marker.update(HighConfidenceSecretPresent=True, References=[{'File': 'config.py', 'Categories': ['secret literal']}])
    else: marker.update(NativeResponseComplete=False, collection_status='partial', Reason='image_content_incomplete')
    assert FUNCTIONS[kind](item, ix)[0] == 'UNKNOWN'


def test_partial_positive_fails_but_partial_negative_unknown():
    for present in (True, False):
        item, ix = c._fixture('ecr_repository', present)
        item['PackageContentSource']['PackageSecretIndicators'].update(NativeResponseComplete=False, collection_status='partial', Reason='image_content_incomplete')
        assert c.image_layers(item, ix)[0] == ('FAIL' if present else 'UNKNOWN')


@pytest.mark.parametrize('url', [
    'http://bucket.s3.us-east-1.amazonaws.com/a?x=y', 'https://user@bucket.s3.us-east-1.amazonaws.com/a?x=y',
    'https://bucket.s3.us-east-1.amazonaws.com:443/a?x=y', 'https://bucket.s3.us-east-1.amazonaws.com.evil.test/a?x=y',
    'https://bucket.s3.eu-west-1.amazonaws.com/a?x=y', 'https://s3.amazonaws.com/a?x=y',
    'https://bucket.s3.us-east-1.amazonaws.com/a?x=y#fragment', 'https://127.0.0.1/a?x=y',
    'https://bucket.s3.us-east-1.amazonaws.com/a\n?x=y', 'https://bucket.s3.us-east-1.amazonaws.com/a',
])
def test_url_rejected_before_network(url):
    with pytest.raises(ValueError): p.validate_url(url, REGION)


@pytest.mark.parametrize('kwargs', [
    {'headers': {'Content-Length': '999999999'}}, {'headers': {'Content-Length': '100'}},
    {'headers': {'Content-Encoding': 'gzip'}}, {'status': 302}, {'url': 'https://evil.test/'},
])
def test_http_metadata_fail_closed(monkeypatch, kwargs):
    http(monkeypatch, {URL: lambda: Response(b'abc', **kwargs)})
    with pytest.raises(aws.ReadFailure): p.download(aws.Requests({}), URL, REGION, 10)


def test_actual_stream_cap_and_cancellation(monkeypatch):
    http(monkeypatch, {URL: b'A' * 100})
    with pytest.raises(aws.ReadFailure): p.download(aws.Requests({}), URL, REGION, 10)
    cancel = threading.Event()
    http(monkeypatch, {URL: lambda: Response(b'abc', cancel=cancel)})
    with pytest.raises(aws.ReadFailure): p.download(aws.Requests({'cancel_event': cancel}), URL, REGION, 10)


@pytest.mark.parametrize('name', ['../secret', '/secret', 'a/../secret', 'a\\secret', 'a//secret', './secret', 'C:/secret', 'a\x00b'])
def test_zip_and_tar_traversal_rejected(name):
    request = aws.Requests({})
    # Zip library itself truncates NUL names, so test validator explicitly.
    with pytest.raises(ValueError): p._path(name)
    if '\x00' not in name:
        with pytest.raises(Exception): p.scan_zip(zip_bytes([(name, SECRET)]), request)
        with pytest.raises(Exception): p.scan_tar(tar_bytes([(name, SECRET)]), 'application/vnd.oci.image.layer.v1.tar', request)


def test_zip_bomb_duplicate_symlink_unsupported_and_truncated():
    request = aws.Requests({})
    raws = [zip_bytes([('bomb', 'A' * 1000000)]), zip_bytes([('a', 'safe'), ('a', SECRET)]), zip_bytes()[:-10], zip_bytes() + b'junk', zip_bytes(compression=zipfile.ZIP_BZIP2)]
    out = io.BytesIO()
    with zipfile.ZipFile(out, 'w') as archive:
        info = zipfile.ZipInfo('link'); info.create_system = 3; info.external_attr = (stat.S_IFLNK | 0o777) << 16
        archive.writestr(info, 'target')
    raws.append(out.getvalue())
    for raw in raws:
        with pytest.raises(Exception): p.scan_zip(raw, request)


def test_tar_duplicate_symlink_and_concatenated_gzip_rejected():
    request = aws.Requests({})
    raw = tar_bytes([('a', b'safe'), ('a', SECRET)])
    with pytest.raises(ValueError): p.scan_tar(raw, 'application/vnd.oci.image.layer.v1.tar', request)
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode='w') as archive:
        info = tarfile.TarInfo('link'); info.type = tarfile.SYMTYPE; info.linkname = 'target'; archive.addfile(info)
    with pytest.raises(ValueError): p.scan_tar(out.getvalue(), 'application/vnd.oci.image.layer.v1.tar', request)
    raw = gzip.compress(tar_bytes()) + gzip.compress(tar_bytes())
    with pytest.raises(ValueError): p.scan_tar(raw, 'application/vnd.oci.image.layer.v1.tar+gzip', request)


@pytest.mark.parametrize('kind', KINDS)
def test_cancelled_enricher_has_no_content_reads(monkeypatch, kind):
    requests, session, item, _, calls, downloads, _ = sdk(monkeypatch, kind)
    event = threading.Event(); event.set(); requests.cancel_event = event
    result = p.ENRICHERS[kind](requests, session, REGION, [item])[0]
    assert FUNCTIONS[kind](result, index(kind, result))[0] == 'UNKNOWN'
    assert not calls and not downloads


def test_fixture_cases_pass_and_fail_by_presence():
    for kind in KINDS:
        for present in (True, False):
            item, ix = c._fixture(kind, present)
            assert FUNCTIONS[kind](item, ix)[0] == ('FAIL' if present else 'PASS')


@pytest.mark.parametrize('kind', KINDS)
def test_loaded_pipeline_includes_projection_and_no_raw_future(monkeypatch, kind):
    requests, session, item, _, calls, downloads, _ = sdk(monkeypatch, kind)
    assert p.READ_ACTIONS <= aws.READ_ACTIONS
    # Exercise the centrally composed pipeline, preserving earlier enrichers.
    # Earlier optional evidence calls may be denied by this intentionally narrow SDK.
    result = aws.ENRICHERS[kind](requests, session, REGION, [item])[0]
    assert FUNCTIONS[kind](result, index(kind, result))[0] == 'FAIL'
    assert downloads
    for future in requests._cache.values():
        if future.exception() is None:
            assert SECRET not in json.dumps(future.result(), default=str)
            assert 'NEVERCACHEME' not in json.dumps(future.result(), default=str)


@pytest.mark.parametrize('kind', KINDS)
def test_loaded_pipeline_optout_no_content_operations(monkeypatch, kind):
    requests, session, item, _, calls, downloads, _ = sdk(monkeypatch, kind, enabled=False)
    result = aws.ENRICHERS[kind](requests, session, REGION, [item])[0]
    assert FUNCTIONS[kind](result, index(kind, result))[0] == 'UNKNOWN'
    assert not any((service, op) in p.PROJECTION_OPERATIONS for service, op, _ in calls)
    assert not downloads


@pytest.mark.parametrize('kind', ['lambda_function', 'lambda_layer_version'])
def test_lambda_direct_requests_default_off_and_unprofiled_guard(monkeypatch, kind):
    requests, session, item, _, calls, downloads, _ = sdk(monkeypatch, kind, enabled=False)
    operation = 'get_function' if kind == 'lambda_function' else 'get_layer_version'
    args = {'FunctionName': item['FunctionArn'], 'Qualifier': item['Version']} if kind == 'lambda_function' else {'LayerName': item['LayerArn'], 'VersionNumber': item['Version']}
    for profile in (None, p.PROFILE):
        result = requests.detail(session, 'lambda', REGION, operation, _metadata_profile=profile, **args)
        assert result['collection_status'] == 'not_collected'
    assert not calls and not downloads


@pytest.mark.parametrize('kind', KINDS)
def test_caller_authority_missing_or_foreign_never_reads_content(monkeypatch, kind):
    requests, session, item, _, calls, downloads, _ = sdk(monkeypatch, kind)
    old = session.client
    def client(service, **kwargs):
        if service == 'sts': return SimpleNamespace(get_caller_identity=lambda **kw: {'Account': '999999999999', 'Arn': 'arn:aws:sts::999999999999:assumed-role/a/b'})
        return old(service, **kwargs)
    session.client = client
    result = p.ENRICHERS[kind](requests, session, REGION, [item])[0]
    assert FUNCTIONS[kind](result, index(kind, result))[0] == 'UNKNOWN'
    assert not calls and not downloads


@pytest.mark.parametrize('mode', ['empty', 'denied', 'missing_timestamp', 'naive_timestamp', 'foreign', 'duplicate', 'latest_tie', 'partial'])
def test_ecr_complete_latest_digest_selection_required(monkeypatch, mode):
    requests, session, item, ops, calls, downloads, _ = sdk(monkeypatch, 'ecr_repository')
    rows = ops['describe_images']['imageDetails']
    if mode == 'empty': rows.clear()
    elif mode == 'missing_timestamp': rows[0].pop('imagePushedAt')
    elif mode == 'naive_timestamp': rows[0]['imagePushedAt'] = datetime(2026, 10, 19)
    elif mode == 'foreign': rows[0]['registryId'] = '999999999999'
    elif mode == 'duplicate': rows.append(deepcopy(rows[0]))
    elif mode == 'latest_tie': rows.append({**rows[0], 'imageDigest': 'sha256:' + '9' * 64})
    elif mode == 'partial':
        requests.max_pages = 1
        ops['describe_images']['nextToken'] = 'more'
    else:
        def denied(**kw): raise aws.ReadFailure('access_denied', 'denied')
        ops['describe_images'] = denied
    result = p.ENRICHERS['ecr_repository'](requests, session, REGION, [item])[0]
    assert c.image_layers(result, index('ecr_repository', result))[0] == 'UNKNOWN'
    assert not any(op == 'batch_get_image' for _, op, _ in calls)
    assert not downloads


def _replace_manifest(ops, document):
    image = ops['batch_get_image']['images'][0]
    raw = json.dumps(document)
    image.update(imageManifest=raw, imageManifestMediaType=document.get('mediaType'))
    dg = digest(raw.encode()); image['imageId']['imageDigest'] = dg
    ops['describe_images']['imageDetails'][0]['imageDigest'] = dg


@pytest.mark.parametrize('conflict', [None, 'account', 'digest', 'manifest', 'media', 'failure'])
def test_installed_secret_projection_two_tag_aliases(monkeypatch, conflict):
    requests, session, item, ops, calls, downloads, _ = sdk(monkeypatch, 'ecr_repository', False)
    image = ops['batch_get_image']['images'][0]
    image['imageId']['imageTag'] = 'stable'
    alias = deepcopy(image)
    alias['imageId']['imageTag'] = 'release'
    if conflict == 'account': alias['registryId'] = '999999999999'
    elif conflict == 'digest': alias['imageId']['imageDigest'] = 'sha256:' + '9' * 64
    elif conflict == 'manifest': alias['imageManifest'] += ' '
    elif conflict == 'media': alias['imageManifestMediaType'] = p.DOCKER
    elif conflict == 'failure': ops['batch_get_image']['failures'] = [{'failureCode': 'ImageNotFound'}]
    ops['batch_get_image']['images'].append(alias)
    result = p.ENRICHERS['ecr_repository'](requests, session, REGION, [item])[0]
    status = c.image_layers(result, index('ecr_repository', result))[0]
    assert status == ('PASS' if conflict is None else 'UNKNOWN')
    assert bool(downloads) is (conflict is None)


@pytest.mark.parametrize('mode', ['multiarch', 'external', 'foreign_download_digest', 'unsupported_compression', 'malformed_json', 'duplicate_json'])
def test_ecr_unsupported_source_never_passes(monkeypatch, mode):
    requests, session, item, ops, calls, downloads, _ = sdk(monkeypatch, 'ecr_repository', False)
    document = json.loads(ops['batch_get_image']['images'][0]['imageManifest'])
    if mode == 'multiarch': document = {'schemaVersion': 2, 'mediaType': 'application/vnd.oci.image.index.v1+json', 'manifests': []}
    elif mode == 'external': document['layers'][0]['urls'] = ['https://evil.test/']
    elif mode == 'unsupported_compression': document['layers'][0]['mediaType'] = 'application/vnd.oci.image.layer.v1.tar+zstd'
    elif mode == 'foreign_download_digest':
        ops['get_download_url_for_layer'] = lambda **kw: {'layerDigest': 'sha256:' + '9' * 64, 'downloadUrl': URL}
    if mode in ('malformed_json', 'duplicate_json'):
        raw = '{' if mode == 'malformed_json' else '{"schemaVersion":2,"schemaVersion":2}'
        dg = digest(raw.encode())
        ops['batch_get_image']['images'][0].update(imageManifest=raw, imageId={'imageDigest': dg})
        ops['describe_images']['imageDetails'][0]['imageDigest'] = dg
    else: _replace_manifest(ops, document)
    result = p.ENRICHERS['ecr_repository'](requests, session, REGION, [item])[0]
    assert c.image_layers(result, index('ecr_repository', result))[0] == 'UNKNOWN'
    assert not any('evil.test' in url for url, _ in downloads)


def append_bad_layer(ops, payloads):
    raw = bytearray(tar_bytes([('corrupt.py', 'ready=true')]))
    raw[0] ^= 1
    broken = bytes(raw)
    compressed = gzip.compress(broken)
    payloads[URL + '-later'] = compressed
    config = json.loads(payloads[URL + '-config'])
    config['rootfs']['diff_ids'].append(digest(broken))
    config_raw = json.dumps(config).encode()
    payloads[URL + '-config'] = config_raw
    document = json.loads(ops['batch_get_image']['images'][0]['imageManifest'])
    document['config'].update(size=len(config_raw), digest=digest(config_raw))
    document['layers'].append({'mediaType': 'application/vnd.oci.image.layer.v1.tar+gzip',
                               'digest': digest(compressed), 'size': len(compressed)})
    _replace_manifest(ops, document)
    old = ops['get_download_url_for_layer']
    def location(**kw):
        layer = kw['layerDigest']
        if layer == digest(config_raw): url = URL + '-config'
        elif layer == digest(compressed): url = URL + '-later'
        else: return old(**kw)
        return {'layerDigest': layer, 'downloadUrl': url}
    ops['get_download_url_for_layer'] = location


def test_real_partial_ecr_positive_survives_later_bad_layer(monkeypatch):
    requests, session, item, ops, calls, downloads, payloads = sdk(monkeypatch, 'ecr_repository', True)
    append_bad_layer(ops, payloads)
    result = p.ENRICHERS['ecr_repository'](requests, session, REGION, [item])[0]
    assert c.image_layers(result, index('ecr_repository', result))[0] == 'FAIL'
    assert result['PackageContentSource']['PackageSecretIndicators']['NativeResponseComplete'] is False
    assert SECRET not in json.dumps(result)


@pytest.mark.parametrize('surface', ['env', 'history', 'private_key', 'cloud_credential'])
def test_config_and_byte_faithful_selected_detector_sources(monkeypatch, surface):
    requests, session, item, ops, calls, downloads, payloads = sdk(monkeypatch, 'ecr_repository', False)
    config = {'config': {'Env': []}, 'history': []}
    if surface == 'env': config['config']['Env'] = ['DB_PASSWORD=' + SECRET]
    elif surface == 'history': config['history'] = [{'created_by': "RUN password='" + SECRET + "'"}]
    elif surface == 'private_key': config['history'] = [{'created_by': '-----BEGIN PRIVATE KEY-----'}]
    else: config['history'] = [{'created_by': 'AWS_ACCESS_KEY_ID=AKIA' + 'A' * 16 + '\naws_secret_access_key=' + 'z' * 40}]
    raw = json.dumps(config).encode(); payloads[URL + '-config'] = raw
    document = json.loads(ops['batch_get_image']['images'][0]['imageManifest'])
    document['config'].update(size=len(raw), digest=digest(raw))
    _replace_manifest(ops, document)
    # SDK stub identifies config by original digest; update exact binding.
    old = ops['get_download_url_for_layer']
    ops['get_download_url_for_layer'] = lambda **kw: {'layerDigest': kw['layerDigest'], 'downloadUrl': URL + '-config'} if kw['layerDigest'] == digest(raw) else old(**kw)
    result = p.ENRICHERS['ecr_repository'](requests, session, REGION, [item])[0]
    assert c.image_layers(result, index('ecr_repository', result))[0] == 'FAIL'
    assert SECRET not in json.dumps(result)


@pytest.mark.parametrize('mode', ['members', 'expanded', 'actual_zip_bytes', 'layer_bytes', 'image_actual_bytes'])
def test_bounds_enforced_with_small_synthetic_budgets(monkeypatch, mode):
    if mode in ('members', 'expanded', 'actual_zip_bytes'):
        request = aws.Requests({})
        if mode == 'members': monkeypatch.setattr(p, 'MEMBER_LIMIT', 1); raw = zip_bytes([('a', 'safe'), ('b', 'safe')])
        elif mode == 'expanded': monkeypatch.setattr(p, 'EXPANDED_LIMIT', 3); raw = zip_bytes()
        else: monkeypatch.setattr(p, 'ZIP_LIMIT', 3); raw = zip_bytes()
        with pytest.raises(ValueError): p.scan_zip(raw, request)
    else:
        requests, session, item, _, _, downloads, _ = sdk(monkeypatch, 'ecr_repository', False)
        if mode == 'layer_bytes': monkeypatch.setattr(p, 'ECR_LAYER_LIMIT', 3)
        else: monkeypatch.setattr(p, 'ECR_IMAGE_LIMIT', 3)
        result = p.ENRICHERS['ecr_repository'](requests, session, REGION, [item])[0]
        assert c.image_layers(result, index('ecr_repository', result))[0] == 'UNKNOWN'
        assert not downloads


def test_stream_budget_counts_failed_bytes_and_deadline(monkeypatch):
    requests = aws.Requests({})
    budget = [4]
    http(monkeypatch, {URL: b'0123456789'})
    with pytest.raises(aws.ReadFailure): p.download(requests, URL, REGION, 100, budget=budget)
    assert budget == [0]
    calls = http(monkeypatch, {URL: b'0123456789'})
    with pytest.raises(aws.ReadFailure): p.download(requests, URL, REGION, 100, budget=budget)
    assert not calls
    requests.deadline = 0
    calls = http(monkeypatch, {URL: b'x'})
    with pytest.raises(aws.ReadFailure): p.download(requests, URL, REGION, 10)
    assert not calls


def test_archive_member_bounds_gzip_bomb_and_sparse_rejection(monkeypatch):
    requests = aws.Requests({})
    monkeypatch.setattr(p, 'EXPANDED_LIMIT', 20000)
    with pytest.raises(ValueError): p.scan_tar(gzip.compress(b'A' * 100000), 'application/vnd.oci.image.layer.v1.tar+gzip', requests)
    raw = tar_bytes([('one', b'a'), ('two', b'b')])
    monkeypatch.setattr(p, 'MEMBER_LIMIT', 1)
    with pytest.raises(ValueError): p.scan_tar(raw, 'application/vnd.oci.image.layer.v1.tar', requests)
    info = tarfile.TarInfo('sparse'); info.type = tarfile.GNUTYPE_SPARSE
    sparse = info.tobuf() + bytes(10240)
    with pytest.raises(ValueError): p.scan_tar(sparse, 'application/vnd.oci.image.layer.v1.tar', requests)


def test_request_download_call_budget_no_network(monkeypatch):
    requests = aws.Requests({'max_calls': 1}); requests.calls = 1
    calls = http(monkeypatch, {URL: b'safe'})
    with pytest.raises(aws.ReadFailure): p.download(requests, URL, REGION, 10)
    assert not calls


@pytest.mark.parametrize('context', [None, {}, (), ('invalid',), ('invalid', None)])
def test_malformed_context_cannot_retain_raw_response(context):
    with pytest.raises(aws.ReadFailure) as exc:
        p.project_response({'downloadUrl': URL, 'secret': SECRET}, 'ecr', 'get_download_url_for_layer', {}, request_context=context, region=REGION)
    assert SECRET not in str(exc.value) and URL not in str(exc.value)


def test_zip_central_directory_member_bound_before_zipfile_allocation(monkeypatch):
    raw = bytearray(zip_bytes())
    end = raw.rfind(b'PK\x05\x06')
    raw[end + 8:end + 12] = (5001).to_bytes(2, 'little') * 2
    monkeypatch.setattr(p.zipfile, 'ZipFile', lambda *a, **kw: pytest.fail('must reject directory count before allocation'))
    with pytest.raises(ValueError): p.scan_zip(bytes(raw), aws.Requests({}))


def test_compressed_image_layers_global_expansion_limit_partial_unknown(monkeypatch):
    requests, session, item, ops, calls, downloads, payloads = sdk(monkeypatch, 'ecr_repository', False)
    # Each blob is individually under 64 MiB but the image aggregate is smaller here.
    monkeypatch.setattr(p, 'ECR_EXPANDED_LIMIT', 10240)
    result = p.ENRICHERS['ecr_repository'](requests, session, REGION, [item])[0]
    assert c.image_layers(result, index('ecr_repository', result))[0] == 'UNKNOWN'
    assert result['PackageContentSource']['PackageSecretIndicators']['NativeResponseComplete'] is False




def test_bound_tar_preserves_proven_positive_before_later_bad_header(monkeypatch):
    requests, session, item, ops, _, _, payloads = sdk(monkeypatch, 'ecr_repository')
    append_bad_layer(ops, payloads)
    result = p.ENRICHERS['ecr_repository'](requests, session, REGION, [item])[0]
    assert c.image_layers(result, index('ecr_repository', result))[0] == 'FAIL'
    assert result['PackageContentSource']['PackageSecretIndicators']['NativeResponseComplete'] is False
    assert SECRET not in json.dumps(result)
