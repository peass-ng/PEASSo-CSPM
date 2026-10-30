"""Native Functions metadata -> trusted projection -> audited GCS archive pipeline.

Archive construction/stream fixtures are attributed to the selected archive
review; no HTTP/archive logic is copied into production. Installed shared hooks
are exercised by actual GCPCollector/Transport, without injection or source rewriting.
"""
from copy import deepcopy
from importlib.metadata import version
import json
import time
from pathlib import Path
import runpy
import socket
from types import SimpleNamespace
from urllib.parse import quote

import pytest

from peaso import secret_scanning as scanning
from peaso.collectors import gcp
from peaso.collectors import gcp_function_secret_indicators as environment
from peaso.collectors import gcp_function_source_secret_indicators as native
from peaso.collectors import gcp_selected_archive_secret_indicators as archives
from peaso.collectors import gcp_selected_object_secret_indicators as objects
from peaso.checks import gcp_function_source_secret_review_20261019 as check
from peaso.secret_findings import deduplicate_secret_findings

ARCHIVE = runpy.run_path(str(Path(__file__).with_name('test_gcp_selected_archive_secret_review_20261019.py')))
SCOPE, BUCKET, TOKEN = ARCHIVE['SCOPE'], ARCHIVE['BUCKET'], ARCHIVE['TOKEN']
NAME = SCOPE + '/locations/us-central1/functions/review'
AUTH = 'synthetic-native-function-bearer-never-store'
OBJECT = 'private/' + TOKEN + '/source.tar.gz'


def function(name=NAME, object_name=OBJECT, generation='1234'):
    return {'name': name, 'environment': 'GEN_2', 'state': 'ACTIVE', 'updateTime': '2026-10-18T10:00:00Z',
        'description': TOKEN, 'labels': {'sensitive': TOKEN},
        'buildConfig': {'runtime': 'python312', 'environmentVariables': {},
            'source': {'storageSource': {'bucket': BUCKET, 'object': object_name}},
            'sourceProvenance': {'resolvedStorageSource': {'bucket': BUCKET, 'object': object_name, 'generation': generation}}},
        'serviceConfig': {'environmentVariables': {}, 'secretEnvironmentVariables': [
            {'key': 'MANAGED', 'projectId': 'review', 'secret': 'reference-only', 'version': 'latest'}]}}


@pytest.fixture(autouse=True)
def offline(monkeypatch):
    def forbidden(*a, **kw): pytest.fail('unmocked socket access', pytrace=False)
    monkeypatch.setattr(socket.socket, 'connect', forbidden)
    monkeypatch.setattr(socket.socket, 'connect_ex', forbidden)
    monkeypatch.setattr(socket, 'create_connection', forbidden)
    monkeypatch.setattr(socket, 'getaddrinfo', forbidden)
    scanning._RESULTS.clear()
    yield
    scanning._RESULTS.clear()


@pytest.fixture
def clean(monkeypatch):
    monkeypatch.setattr(scanning, '_scan_kingfisher', lambda *a: [])
    monkeypatch.setattr(scanning, '_scan_trufflehog', lambda *a: [])


def pipeline(monkeypatch, *, rows=None, payload=None, format_name='tar.gz', options=None,
             function_extra=None, function_pages=None, media_status=200, mutate=None, responses=None, scope=SCOPE):
    rows = [function()] if rows is None else rows
    options = {'inventories': ['project', 'bucket', 'function', native.KIND], 'concurrency': 1, 'retries': 0,
        'include_inherited': False, 'metrics_scopes': False, 'content_secret_scans': True,
        '_content_secret_scan_kinds': [native.KIND], **(options or {})}
    credentials = gcp.Credentials({'token': AUTH})
    transport = gcp.Transport(credentials, options)
    calls, streams = [], []
    pending_pages = deepcopy(function_pages) if function_pages is not None else None
    payload = ARCHIVE['archive'](format_name, {'settings.env': b'STAGE=production\n'}) if payload is None else payload
    class Metadata:
        status_code = 200
        headers = {}
        def __init__(self, data):
            self.data = data
            self.content = json.dumps(data).encode()
        def json(self): return deepcopy(self.data)
    def request(method, url, **kwargs):
        calls.append({'method': method, 'url': url, 'params': deepcopy(kwargs.get('params'))})
        assert method == 'GET'
        assert '/secrets/' not in url and ':generate' not in url
        if url == 'https://cloudresourcemanager.googleapis.com/v3/' + scope:
            return Metadata({'name': 'projects/10001', 'projectId': 'review', 'state': 'ACTIVE'})
        if url == 'https://compute.googleapis.com/compute/v1/' + scope:
            return Metadata({'name': 'review', 'id': '10001'})
        if url == 'https://storage.googleapis.com/storage/v1/b':
            return Metadata({'items': [{'name': BUCKET, 'projectNumber': '10001'}]})
        if url == 'https://storage.googleapis.com/storage/v1/b/' + BUCKET + '/iam':
            return Metadata({'version': 1, 'bindings': []})
        if url == 'https://cloudfunctions.googleapis.com/v2/' + scope + '/locations/-/functions':
            page = pending_pages.pop(0) if pending_pages is not None else {'functions': rows, **(function_extra or {})}
            reply = Metadata(page[0] if isinstance(page, tuple) else page)
            if isinstance(page, tuple): reply.status_code = page[1]
            return reply
        if url.endswith(':getIamPolicy'):
            return Metadata({'version': 3, 'bindings': []})
        assert url.startswith('https://storage.googleapis.com/storage/v1/b/' + BUCKET + '/o/')
        assert kwargs['stream'] is True and kwargs['allow_redirects'] is False
        assert kwargs['headers']['Accept-Encoding'] == 'identity'
        target_row = next(r for r in rows if url.endswith('/o/' + quote(r['buildConfig']['sourceProvenance']['resolvedStorageSource']['object'], safe='')))
        resolved = target_row['buildConfig']['sourceProvenance']['resolvedStorageSource']
        assert kwargs['params']['generation'] == kwargs['params']['ifGenerationMatch'] == resolved['generation']
        target = {'project_scope': scope, **resolved, 'format': format_name}
        reply = ARCHIVE['replies'](payload, target)[int(kwargs['params'].get('alt') == 'media')]
        if responses is not None: reply = responses(reply, kwargs['params'].get('alt') == 'media')
        if kwargs['params'].get('alt') == 'media': reply.status_code = media_status
        streams.append(reply)
        return reply
    monkeypatch.setattr(transport, '_session', lambda: SimpleNamespace(request=request))
    collector = gcp.GCPCollector({'provider': 'gcp', 'scopes': [scope], 'options': options},
        requirements=['project', 'bucket', 'function', native.KIND], transport=transport)
    collector.run_jobs(collector.scope_jobs(scope))
    if mutate is not None: mutate(collector, transport)
    collector.dependent_jobs()
    envelope = collector.collections[(native.KIND, scope)]
    context = {'context': {'provider': 'gcp', 'scope': scope, 'metadata': {
        **native.selection_metadata(collector), 'source_requests': deepcopy(transport.evidence)}}, 'collections': {}}
    for (kind, _), env in collector.collections.items(): context['collections'].setdefault(kind, []).append(env)
    items = envelope['items']
    return SimpleNamespace(collector=collector, transport=transport, calls=calls, streams=streams,
        item=items[0] if items else {}, items=items, index=context, envelope=envelope,
        verdicts=[check.evaluate(r, context) for r in items], result=check.evaluate(items[0] if items else {}, context))


def test_real_pinned_dual_pair_positive_dedup_owners_privacy(monkeypatch, capsys):
    assert version('kingfisher-secret-scanner') == scanning.KINGFISHER_VERSION
    assert scanning._trufflehog()
    payload = ARCHIVE['archive']('tar.gz', {'secrets.env': ('TOKEN=' + TOKEN + '\n').encode(),
                                           'duplicate.env': ('TOKEN=' + TOKEN + '\n').encode()})
    result = pipeline(monkeypatch, rows=[function(), function(NAME + '-second')], payload=payload)
    assert [v[0] for v in result.verdicts] == ['FAIL', 'FAIL']
    assert sum((c['params'] or {}).get('alt') == 'media' for c in result.calls) == 1
    findings = []
    for row, (status, evidence) in zip(result.items, result.verdicts):
        leak, = evidence['secret_leaks']
        assert {d['engine'] for d in leak['detectors']} == {'kingfisher', 'trufflehog'}
        assert len(leak['locations']) == 2
        assert evidence['function'] == row['name'] and evidence['deployed_code_assessed'] is False
        findings.append({'provider': 'gcp', 'check_id': check.CHECK_ID, 'scope': SCOPE,
                         'resource_id': row['name'], 'status': status, 'evidence': evidence})
    assert len(deduplicate_secret_findings(findings)) == 1
    assert not hasattr(result.transport, '_function_source_pending')
    retained = json.dumps([result.index, result.items, result.verdicts]) + repr(result.transport.cache) + repr(scanning._RESULTS) + str(capsys.readouterr())
    assert all(value not in retained for value in (TOKEN, AUTH, OBJECT, 'settings.env', 'secrets.env'))
    assert all(r.closed for r in result.streams)
    assert native.KIND not in result.collector.options.get('selected_gcs_archives', [])
    assert result.collector.options['_content_secret_scan_kinds'] == [native.KIND]


@pytest.mark.parametrize('format_name', ['zip', 'tar', 'tar.gz'])
def test_real_pinned_negative_bounded_archive_claim(monkeypatch, format_name):
    row = function(object_name='private/source.' + format_name)
    result = pipeline(monkeypatch, rows=[row], format_name=format_name)
    assert result.result[0] == 'PASS'
    assert 'Deployed images' in result.result[1]['observed']
    assert len(result.streams) == 2


@pytest.mark.parametrize('options', [{'content_secret_scans': False}, {'_content_secret_scan_kinds': []},
    {'_content_secret_scan_kinds': ['function']}, {'_content_secret_scan_kinds': [archives.KIND]}])
def test_default_zero_content_calls(monkeypatch, options):
    result = pipeline(monkeypatch, options=options)
    assert result.result[0] == 'UNKNOWN' and result.streams == []
    assert not hasattr(result.transport, '_function_source_pending')


@pytest.mark.parametrize('case', ['missing_provenance','missing_source','missing_generation','zero_generation',
    'latest','integer_generation','overflow','different_object','different_bucket','different_generation',
    'repository','signed_url','wrong_project','wrong_location','gen1','deploying','missing_parent',
    'partial_parent','unsupported_format','bad_time','date_only','provider_marker','duplicate_function','too_many','partial_list'])
def test_unsafe_source_never_reads_archive(monkeypatch, clean, case):
    row = function()
    build = row['buildConfig']
    resolved = build['sourceProvenance']['resolvedStorageSource']
    if case == 'missing_provenance': build.pop('sourceProvenance')
    if case == 'missing_source': build.pop('source')
    if case == 'missing_generation': resolved.pop('generation')
    if case == 'zero_generation': resolved['generation'] = '0'
    if case == 'latest': resolved['generation'] = 'latest'
    if case == 'integer_generation': resolved['generation'] = 1234
    if case == 'overflow': resolved['generation'] = '9223372036854775808'
    if case == 'different_object': resolved['object'] = 'other.tar.gz'
    if case == 'different_bucket': resolved['bucket'] = 'other-bucket'
    if case == 'different_generation': build['source']['storageSource']['generation'] = '999'
    if case == 'repository': build['source'] = {'repoSource': {'repoName': 'repo'}}
    if case == 'signed_url': resolved['sourceUploadUrl'] = 'https://example.invalid/' + TOKEN
    if case == 'wrong_project': row['name'] = 'projects/foreign/locations/us-central1/functions/review'
    if case == 'wrong_location': row['name'] = SCOPE + '/locations//functions/review'
    if case == 'gen1': row['environment'] = 'GEN_1'
    if case == 'deploying': row['state'] = 'DEPLOY_IN_PROGRESS'
    if case == 'missing_parent': row.pop('buildConfig')
    if case == 'partial_parent': build['_coverage'] = {'source': {'status': 'partial'}}
    if case == 'unsupported_format':
        build['source']['storageSource']['object'] = resolved['object'] = 'source.7z'
    if case == 'bad_time': row['updateTime'] = 'not-a-time'
    if case == 'date_only': row['updateTime'] = '2026-10-18Z'
    if case == 'provider_marker':
        row[native.REFERENCE] = {'schema': native.SCHEMA, 'status': 'bound'}
        build.pop('sourceProvenance')
    rows = [row, deepcopy(row)] if case == 'duplicate_function' else [row]
    if case == 'too_many': rows = [function(NAME + str(i)) for i in range(native.MAX_FUNCTIONS + 1)]
    extra = {'unreachable': ['us-west1']} if case == 'partial_list' else None
    result = pipeline(monkeypatch, rows=rows, function_extra=extra)
    assert result.result[0] == 'UNKNOWN' and result.streams == []
    assert TOKEN not in json.dumps(result.envelope)


@pytest.mark.parametrize('case', ['foreign_bucket','partial_bucket','partial_project','partial_function','no_pending',
    'changed_reference','deadline','cancel','shared_calls','shared_bytes','transport_calls'])
def test_native_dependencies_and_shared_bounds(monkeypatch, clean, case):
    def mutate(collector, transport):
        if case == 'foreign_bucket': collector.collections[('bucket', SCOPE)]['items'][0]['projectNumber'] = '10002'
        if case == 'partial_bucket': collector.collections[('bucket', SCOPE)]['coverage_status'] = 'partial'
        if case == 'partial_project': collector.collections[('project', SCOPE)]['coverage_status'] = 'partial'
        if case == 'partial_function': collector.collections[('function', SCOPE)]['coverage_status'] = 'partial'
        if case == 'no_pending': delattr(transport, '_function_source_pending')
        if case == 'changed_reference': collector.collections[('function', SCOPE)]['items'][0][native.REFERENCE]['generation'] = '9000'
        if case == 'deadline': transport._function_source_pending['started'] -= 31
        if case == 'cancel': monkeypatch.setattr(transport, 'check_cancelled', lambda: (_ for _ in ()).throw(RuntimeError(TOKEN)))
        if case in ('shared_calls', 'shared_bytes'):
            import threading, time
            transport._selected_object_secret_state = {'started': time.monotonic(), 'bytes': objects.MAX_TOTAL_BYTES if case == 'shared_bytes' else 0,
                'calls': objects.MAX_CALLS if case == 'shared_calls' else 0, 'lock': threading.Lock(), 'items': {}}
        if case == 'transport_calls': transport.max_calls = transport.calls
    result = pipeline(monkeypatch, mutate=mutate)
    assert result.result[0] == 'UNKNOWN'
    assert not hasattr(result.transport, '_function_source_pending')
    assert TOKEN not in json.dumps(result.envelope)


@pytest.mark.parametrize('status', [301, 302, 401, 403, 404, 500])
def test_media_denied_or_redirect_unknown_and_no_fallback(monkeypatch, clean, status):
    result = pipeline(monkeypatch, media_status=status)
    assert result.result[0] == 'UNKNOWN' and len(result.streams) == 2
    assert all(s.closed for s in result.streams)
    assert TOKEN not in json.dumps(result.envelope)


@pytest.mark.parametrize('case', ['wrong_generation','truncated','wrong_mime','encoding','malformed_metadata','oversize','binary','nested','traversal','empty'])
def test_native_media_and_archive_completeness(monkeypatch, clean, case):
    payload = None
    if case == 'binary': payload = ARCHIVE['archive']('tar.gz', {'bytes.txt': b'\xff\x00'})
    if case == 'nested': payload = ARCHIVE['archive']('tar.gz', {'nested.zip': ARCHIVE['archive']()})
    if case == 'traversal': payload = ARCHIVE['archive']('tar.gz', {'../escape.txt': b'public'})
    if case == 'empty': payload = ARCHIVE['archive']('tar.gz', {})
    def response(reply, media):
        if case == 'wrong_generation' and media: reply.headers['X-Goog-Generation'] = '999'
        if case == 'truncated' and media: reply.headers['Content-Length'] = str(int(reply.headers['Content-Length']) + 1)
        if case == 'wrong_mime' and media: reply.headers['Content-Type'] = 'text/plain'
        if case == 'encoding' and media: reply.headers['Content-Encoding'] = 'gzip'
        if case == 'malformed_metadata' and not media: return ARCHIVE['Response'](b'{bad')
        if case == 'oversize' and not media: reply.headers['Content-Length'] = str(objects.MAX_METADATA_BYTES + 1)
        return reply
    result = pipeline(monkeypatch, payload=payload, responses=response)
    assert result.result[0] == 'UNKNOWN'
    assert all(s.closed for s in result.streams)


@pytest.mark.parametrize('engine', ['_scan_kingfisher', '_scan_trufflehog'])
def test_tool_failure_cannot_prove_absence(monkeypatch, engine):
    monkeypatch.setattr(scanning, engine, lambda *a: (_ for _ in ()).throw(RuntimeError(TOKEN)))
    result = pipeline(monkeypatch)
    assert result.result[0] == 'UNKNOWN' and TOKEN not in json.dumps(result.envelope)


@pytest.mark.parametrize('case', ['source_receipt','media_receipt','authorization','source_marker','archive_id','object_id',
    'source_scope','source_partial','duplicate_source','foreign_owner','false_complete','field_coverage','project_number','media_operation'])
def test_consumer_rejects_contradictions(monkeypatch, clean, case):
    result = pipeline(monkeypatch)
    assert result.result[0] == 'PASS'
    item, index = result.item, result.index
    if case == 'source_receipt': item[native.MARKER]['source_requests'] = ['missing']
    if case == 'media_receipt': item[native.MARKER]['archive_source_requests'] = ['missing','other']
    if case == 'authorization': index['context']['metadata']['function_source_archive_authorized'] = False
    if case == 'source_marker': index['collections']['function'][0]['items'][0][native.REFERENCE]['generation'] = '999'
    if case == 'archive_id': item[native.REFERENCE]['archive_id'] = 'gcs-selected-archive:' + '0' * 64
    if case == 'object_id': item[native.REFERENCE]['object_id'] = 'gcs-selected-object:' + '0' * 64
    if case == 'source_scope': index['collections']['function'][0]['scope'] = 'projects/foreign'
    if case == 'source_partial': index['collections']['function'][0]['status'] = 'partial'
    if case == 'duplicate_source': index['collections']['function'][0]['items'].append(deepcopy(index['collections']['function'][0]['items'][0]))
    if case == 'foreign_owner': item['name'] = 'projects/foreign/locations/us-central1/functions/review'
    if case == 'false_complete': item[native.MARKER]['complete'] = False
    if case == 'field_coverage': item['_coverage'][native.MARKER]['status'] = 'unknown'
    if case == 'project_number': index['collections']['bucket'][0]['items'][0]['projectNumber'] = '10002'
    if case == 'media_operation':
        ref = item[native.MARKER]['archive_source_requests'][0]
        next(r for r in index['context']['metadata']['source_requests'] if r['id'] == ref)['operation'] = 'not-media'
    assert check.evaluate(item, index)[0] == 'UNKNOWN'


def test_native_pagination_consumes_both_pages_preserving_owners(monkeypatch, clean):
    first, second = function(), function(NAME + '-second')
    result = pipeline(monkeypatch, rows=[first, second], function_pages=[
        {'functions': [first], 'nextPageToken': 'opaque-native-cursor'}, {'functions': [second]}])
    assert [v[0] for v in result.verdicts] == ['PASS', 'PASS']
    assert len(result.streams) == 2
    native_calls = [c for c in result.calls if c['url'].endswith('/locations/-/functions')]
    assert len(native_calls) == 2 and native_calls[1]['params']['pageToken'] == 'opaque-native-cursor'
    assert 'opaque-native-cursor' not in json.dumps(result.index)


def test_later_partial_page_invalidates_content_access(monkeypatch, clean):
    first, second = function(), function(NAME + '-second')
    result = pipeline(monkeypatch, rows=[first, second], function_pages=[
        {'functions': [first], 'nextPageToken': 'cursor'}, {'functions': [second], 'unreachable': ['us-west1']}])
    assert result.result[0] == 'UNKNOWN' and result.streams == []
    assert not hasattr(result.transport, '_function_source_pending')


def test_empty_function_collection_does_not_create_passing_resource(monkeypatch, clean):
    result = pipeline(monkeypatch, rows=[])
    assert result.items == [] and result.result[0] == 'UNKNOWN' and not result.streams


def test_teardown_discards_private_target_plan(monkeypatch):
    options = {'content_secret_scans': True, '_content_secret_scan_kinds': [native.KIND]}
    transport = gcp.Transport(gcp.Credentials({'token': AUTH}), options)
    result = native.capture_response(transport, {'functions': [function()]}, method='GET',
        url='https://cloudfunctions.googleapis.com/v2/' + SCOPE + '/locations/-/functions', scope=SCOPE)
    assert native.REFERENCE in result['functions'][0]
    assert TOKEN not in json.dumps(result)
    assert getattr(transport, '_function_source_pending')['rows']
    transport.close()
    native.clear_pending(transport)
    assert not hasattr(transport, '_function_source_pending')


@pytest.mark.parametrize('dependency', ['project', 'bucket'])
def test_consumer_requires_ownership_native_receipts(monkeypatch, clean, dependency):
    result = pipeline(monkeypatch)
    result.index['collections'][dependency][0]['source_requests'] = []
    assert check.evaluate(result.item, result.index)[0] == 'UNKNOWN'


def test_native_upload_placeholder_generation_requires_resolved_positive_generation(monkeypatch, clean):
    row = function()
    row['buildConfig']['source']['storageSource']['generation'] = '0'
    result = pipeline(monkeypatch, rows=[row])
    assert result.result[0] == 'PASS'
    assert result.item[native.REFERENCE]['generation'] == '1234'


@pytest.mark.parametrize('field,value', [('state', 'DEPLOY_IN_PROGRESS'), ('environment', 'GEN_1'),
                                        ('updateTime', '2026-10-17T10:00:00Z')])
def test_consumer_requires_unchanged_native_function_observation(monkeypatch, clean, field, value):
    result = pipeline(monkeypatch)
    result.index['collections']['function'][0]['items'][0][field] = value
    assert check.evaluate(result.item, result.index)[0] == 'UNKNOWN'


def test_install_native_cases_is_idempotent(monkeypatch):
    import peaso.checks as registry
    from peaso.checks import fixtures
    from peaso.checks.facts import MemoIndex
    monkeypatch.setattr(registry, 'CHECKS', [c for c in registry.CHECKS if c.id != check.CHECK_ID])
    monkeypatch.setattr(fixtures, 'CASES', {k: v for k, v in fixtures.CASES.items() if k != check.CHECK_ID})
    check.install()
    check.install()
    assert sum(c.id == check.CHECK_ID for c in registry.CHECKS) == 1
    cases = fixtures.CASES[check.CHECK_ID]
    for label in ('pass', 'fail', 'unknown'):
        assert check.evaluate(cases[label], MemoIndex(cases[label + '_index']))[0] == label.upper()


def admitted_environment_check():
    """Exercise the installed paired consumer on real native source captures."""
    import inspect
    from peaso.checks import CHECKS
    from peaso.checks import gcp_function_secret_partial_page_20261020 as admitted
    registered, = [c for c in CHECKS if c.id == 'gcp.review.function.literal_environment_secret_indicators']
    assert inspect.unwrap(registered.evaluate) is admitted.evaluate
    return registered


def assert_native_environment_positive(row, index, registered):
    from peaso.checks import gcp_function_secret_review_20261019 as predecessor
    from peaso.collectors import gcp_function_secret_pairs_20261020 as paired
    # The immutable v1 consumer cannot interpret the admitted paired v2 projection.
    assert predecessor.evaluate(row, index)[0] == 'UNKNOWN'
    assert row[paired.MARKER]['schema'] == paired.SCHEMA
    status, evidence = registered.evaluate(row, index)
    assert status == 'FAIL' and evidence['complete'] is True
    assert {d['engine'] for leak in evidence['secret_leaks'] for d in leak['detectors']} == {'kingfisher', 'trufflehog'}
    refs = set(row['_provenance']['source_requests'])
    reads = [r for r in index['context']['metadata']['source_requests'] if r['id'] in refs]
    assert any(r['status'] == 'collected' and r['http_status'] == 200
               and r['url'].endswith('/locations/-/functions') for r in reads)


def test_both_named_environment_and_source_checks_compose_on_native_metadata(monkeypatch):
    environment_check = admitted_environment_check()
    row = function()
    row['serviceConfig']['environmentVariables'] = {'CREDENTIAL': TOKEN}
    payload = ARCHIVE['archive']('tar.gz', {'source.env': ('TOKEN=' + TOKEN + '\n').encode()})
    result = pipeline(monkeypatch, rows=[row], payload=payload,
                      options={'_content_secret_scan_kinds': ['function', native.KIND]})
    function_row = result.index['collections']['function'][0]['items'][0]
    assert function_row['buildConfig']['_coverage'] == {field: {'status': 'unknown',
        'reason': 'function_source_reference_not_retained'} for field in ('source', 'sourceProvenance')}
    from peaso.checks.facts import get, Unavailable
    with pytest.raises(Unavailable): get(function_row, 'buildConfig.source', dict)
    assert_native_environment_positive(function_row, result.index, environment_check)
    assert result.result[0] == 'FAIL'
    assert TOKEN not in json.dumps(result.index) + repr(result.transport.cache)


@pytest.mark.parametrize('multi_page', [False, True])
def test_source_limit_keeps_ordinary_native_inventory_and_environment_results(monkeypatch, multi_page):
    environment_check = admitted_environment_check()
    # This covers the source-count limit, not the 30s page scan-time bound that
    # 11 two-engine scans can exceed on a loaded CI runner. A slower monotonic
    # clock keeps that bound out of reach without editing reviewed sources.
    real_monotonic = time.monotonic
    monkeypatch.setattr(time, 'monotonic', lambda: real_monotonic() / 10)
    rows = [function(NAME + str(i)) for i in range(native.MAX_FUNCTIONS + 1)]
    for row in rows: row['serviceConfig']['environmentVariables'] = {'CREDENTIAL': TOKEN}
    pages = [{'functions': rows[:6], 'nextPageToken': 'cursor'}, {'functions': rows[6:]}] if multi_page else None
    result = pipeline(monkeypatch, rows=rows, function_pages=pages,
                      options={'_content_secret_scan_kinds': ['function', native.KIND]})
    source = result.index['collections']['function'][0]
    assert source['status'] == 'collected' and len(source['items']) == native.MAX_FUNCTIONS + 1
    for row in source['items']:
        assert_native_environment_positive(row, result.index, environment_check)
    assert result.result[0] == 'UNKNOWN' and not result.streams
    assert TOKEN not in json.dumps(result.index) + repr(result.transport.cache)
    assert not hasattr(result.transport, '_function_source_pending')


def test_later_native_function_denial_discards_earlier_plan_without_content_reads(monkeypatch, clean):
    result = pipeline(monkeypatch, function_pages=[{'functions': [function()], 'nextPageToken': 'cursor'},
        ({'error': {'message': TOKEN}}, 403)])
    assert result.result[0] == 'UNKNOWN' and not result.streams
    assert result.index['collections']['function'][0]['status'] == 'partial'
    assert not hasattr(result.transport, '_function_source_pending')
    assert TOKEN not in json.dumps(result.index) + repr(result.transport.cache)


@pytest.mark.parametrize('surface,field,reason', [('buildConfig', 'environmentVariables', 'partial'),
    ('serviceConfig', 'source', 'function_source_reference_not_retained'),
    ('buildConfig', 'source', 'unrelated_reason')])
def test_environment_coverage_allowance_remains_narrow(surface, field, reason):
    source = {'_coverage': {field: {'status': 'unknown', 'reason': reason}}}
    # Root owns this narrowly proposed helper; required/env/other-parent coverage stays forbidden.
    assert environment._coverage_ok(source, source_fields=(surface == 'buildConfig')) is False
