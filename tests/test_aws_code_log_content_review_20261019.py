"""Offline synthetic SDK, boundary redaction and pure runtime tests."""
import copy
import json
import pytest
from peaso.collectors import aws_code_log_content_indicators as c
from peaso.checks import aws_code_log_content_review_20261019 as checks

REGION, ACCOUNT, COMMIT = 'us-east-1', '123456789012', 'a'*40
REPO = {'repositoryName': 'demo', 'Arn': f'arn:aws:codecommit:{REGION}:{ACCOUNT}:demo'}
GROUP = {'logGroupName': 'demo', 'arn': f'arn:aws:logs:{REGION}:{ACCOUNT}:log-group:demo:*'}
SECRET = '-----BEGIN PRIVATE KEY-----\nSYNTHETIC_PRIVATE_MATERIAL'


@pytest.fixture(autouse=True)
def isolated_detector_dependencies(monkeypatch, request):
    """SDK/redaction unit cases are separate from real optional-tool acceptance."""
    from peaso import secret_scanning
    secret_scanning._RESULTS.clear()
    if request.node.name.startswith('test_real_dual_scanners_sdk_content'):
        import shutil
        pytest.importorskip('kingfisher_sdk')
        if not shutil.which('trufflehog'):
            pytest.skip('requires the optional pinned TruffleHog binary')
    else:
        monkeypatch.setattr(secret_scanning, '_scan_kingfisher', lambda *args: [])
        monkeypatch.setattr(secret_scanning, '_scan_trufflehog', lambda *args: [])
    yield
    secret_scanning._RESULTS.clear()


def fixture(mode, positive=False):
    case = checks.RUNTIME_CASES[checks.IDS[mode]]
    return copy.deepcopy((case['fail'], case['fail_index']) if positive else (case['pass'], case['pass_index']))


@pytest.fixture
def sdk(monkeypatch):
    import boto3
    from botocore.stub import Stubber
    from peaso.collectors import aws
    session = boto3.Session(aws_access_key_id='test', aws_secret_access_key='test', region_name=REGION)
    clients = {svc: session.client(svc, region_name=REGION) for svc in ('codecommit', 'logs')}
    stubs = {svc: Stubber(client) for svc, client in clients.items()}
    for stub in stubs.values():
        stub.activate()
    routes = []
    def client(self, _session, service, region):
        routes.append((service, region))
        assert region == REGION
        return clients[service]
    monkeypatch.setattr(aws.Requests, 'client', client)
    requests = aws.Requests({'retry_attempts': 1, 'content_secret_scans': True})
    yield requests, session, stubs, routes
    for stub in stubs.values():
        stub.assert_no_pending_responses()
        stub.deactivate()


def prime_repo(stub, paths=('/config.py',), content=SECRET):
    stub.add_response('get_repository', {'repositoryMetadata': {'repositoryName': 'demo', 'Arn': REPO['Arn'], 'accountId': ACCOUNT, 'defaultBranch': 'main'}}, {'repositoryName': 'demo'})
    stub.add_response('get_branch', {'branch': {'branchName': 'main', 'commitId': COMMIT}}, {'repositoryName': 'demo', 'branchName': 'main'})
    stub.add_response('get_folder', {'commitId': COMMIT, 'folderPath': '/', 'files': [{'absolutePath': path} for path in paths]}, {'repositoryName': 'demo', 'commitSpecifier': COMMIT, 'folderPath': '/'})
    for path in paths:
        stub.add_response('get_file', {'commitId': COMMIT, 'blobId': 'b'*40, 'filePath': path, 'fileMode': 'NORMAL', 'fileSize': len(content.encode()), 'fileContent': content.encode()}, {'repositoryName': 'demo', 'commitSpecifier': COMMIT, 'filePath': path})


def log_args(requests, token=None, limit=100):
    end = int(requests.observed_at.timestamp()*1000)
    return {'logGroupName': 'demo', 'startTime': end-86400000, 'endTime': end, 'limit': limit, **({'nextToken': token} if token else {})}


def cache_values(requests):
    return json.dumps([future.result() for future in requests._cache.values() if future.done() and future.exception() is None])


@pytest.mark.parametrize('mode', ['repository', 'logs'])
def test_pure_runtime(mode):
    for positive in (False, True):
        item, index = fixture(mode, positive)
        status, evidence = getattr(checks, mode)(item, index)
        assert status == ('FAIL' if positive else 'PASS')
        assert len(evidence['observed']) <= 150
        assert SECRET not in json.dumps(evidence)


@pytest.mark.parametrize('mode', ['repository', 'logs'])
@pytest.mark.parametrize('positive', [False, True])
def test_partial_scope(mode, positive):
    item, index = fixture(mode, positive)
    item['ContentSecretIndicators'].update(collection_status='partial', complete=False, errors=[{'status': 'access_denied'}])
    assert getattr(checks, mode)(item, index)[0] == ('FAIL' if positive else 'UNKNOWN')


@pytest.mark.parametrize('mode', ['repository', 'logs'])
@pytest.mark.parametrize('mutation', ['account', 'region', 'identity', 'disabled', 'malformed'])
def test_foreign_missing_malformed(mode, mutation):
    item, index = fixture(mode, True)
    sample = item['ContentSecretIndicators']
    if mutation == 'account': sample['account_id'] = '999999999999'
    if mutation == 'region': sample['region'] = 'eu-west-1'
    if mutation == 'identity': sample['identity'] += '-foreign'
    if mutation == 'disabled': sample['collection_status'] = 'not_collected'
    if mutation == 'malformed': sample['records'][0]['categories'] = ['UNKNOWN']
    assert getattr(checks, mode)(item, index)[0] == 'UNKNOWN'


@pytest.mark.parametrize('option', [None, False, 1, 'true'])
def test_optout_no_requests(option, monkeypatch):
    from peaso.collectors.aws import Requests
    if option not in (None, False) or type(option) is int:
        with pytest.raises(ValueError):
            Requests({'content_secret_scans': option})
        return
    requests = Requests({} if option is None else {'content_secret_scans': option})
    monkeypatch.setattr(requests, 'call', lambda *a, **kw: pytest.fail('disabled content request'))
    assert c.scan_repository(requests, None, REGION, REPO)['collection_status'] == 'not_collected'
    assert c.scan_logs(requests, None, REGION, GROUP)['collection_status'] == 'not_collected'


def test_repository_sdk_cache_redacted(sdk):
    requests, session, stubs, routes = sdk
    prime_repo(stubs['codecommit'])
    first = c.scan_repository(requests, session, REGION, REPO)
    second = c.scan_repository(requests, session, REGION, REPO)
    assert first == second and first['complete']
    assert [{k: v for k, v in row.items() if k not in ('leaks', 'scanner_complete')} for row in first['records']] == [{'path': c.path_locator(REGION, REPO['repositoryName'], COMMIT, '/config.py'), 'size': len(SECRET), 'inspected_bytes': len(SECRET), 'readable': True, 'categories': ['private_key']}]
    assert first['records'][0]['scanner_complete'] is True
    assert first['records'][0]['leaks'] == []
    assert requests.calls == 4 and requests.cache_hits == 2
    cached = cache_values(requests)
    assert SECRET not in cached and 'SYNTHETIC_PRIVATE_MATERIAL' not in cached and 'fileContent' not in cached


@pytest.mark.parametrize('mode', ['repository', 'logs'])
def test_real_dual_scanners_sdk_content(sdk, mode):
    requests, session, stubs, _ = sdk
    token = 'ghp_' + '7mQ2zR9wL4cV8nK1sF6aH3jP5uD0xB2yE9rT'
    if mode == 'repository':
        prime_repo(stubs['codecommit'], content='token='+token)
        sample = c.scan_repository(requests, session, REGION, REPO)
    else:
        stamp = log_args(requests)['startTime'] + 1
        stubs['logs'].add_response('filter_log_events', {'events': [
            {'timestamp': stamp, 'message': 'token='+token}]}, log_args(requests))
        sample = c.scan_logs(requests, session, REGION, GROUP)
    item, index = fixture(mode)
    item['ContentSecretIndicators'] = sample
    status, evidence = getattr(checks, mode)(item, index)
    assert status == 'FAIL' and sample['complete']
    assert len(evidence['secret_leaks']) == 1
    assert {d['engine'] for d in evidence['secret_leaks'][0]['detectors']} == {'kingfisher', 'trufflehog'}
    assert token not in cache_values(requests) + json.dumps(evidence)


def test_log_pagination_cache_redacted(sdk):
    requests, session, stubs, routes = sdk
    timestamp = log_args(requests)['startTime']+1
    stubs['logs'].add_response('filter_log_events', {'events': [], 'nextToken': 'next'}, log_args(requests))
    stubs['logs'].add_response('filter_log_events', {'events': [{'timestamp': timestamp, 'message': SECRET}]}, log_args(requests, 'next'))
    first = c.scan_logs(requests, session, REGION, GROUP)
    second = c.scan_logs(requests, session, REGION, GROUP)
    assert first == second and first['complete'] and first['records'][0]['categories'] == ['private_key']
    assert requests.calls == 2 and requests.cache_hits == 2
    assert SECRET not in cache_values(requests) and 'SYNTHETIC_PRIVATE_MATERIAL' not in cache_values(requests)


@pytest.mark.parametrize('mode', ['repository', 'logs'])
def test_denied(sdk, mode):
    requests, session, stubs, routes = sdk
    service, operation, args = ('codecommit', 'get_repository', {'repositoryName': 'demo'}) if mode == 'repository' else ('logs', 'filter_log_events', log_args(requests))
    stubs[service].add_client_error(operation, service_error_code='AccessDeniedException', service_message=SECRET, expected_params=args)
    sample = (c.scan_repository if mode == 'repository' else c.scan_logs)(requests, session, REGION, REPO if mode == 'repository' else GROUP)
    assert sample['collection_status'] != 'collected' and not sample['complete']
    assert SECRET not in json.dumps(sample)


def test_empty_log_window(sdk):
    requests, session, stubs, routes = sdk
    stubs['logs'].add_response('filter_log_events', {'events': []}, log_args(requests))
    sample = c.scan_logs(requests, session, REGION, GROUP)
    assert sample['complete'] and sample['records'] == []


def test_empty_repository(sdk):
    requests, session, stubs, routes = sdk
    prime_repo(stubs['codecommit'], ())
    assert c.scan_repository(requests, session, REGION, REPO)['complete']


def test_log_repeated_token_partial(sdk):
    requests, session, stubs, routes = sdk
    stubs['logs'].add_response('filter_log_events', {'events': [], 'nextToken': 'next'}, log_args(requests))
    stubs['logs'].add_response('filter_log_events', {'events': [], 'nextToken': 'next'}, log_args(requests, 'next'))
    sample = c.scan_logs(requests, session, REGION, GROUP)
    assert not sample['complete'] and sample['collection_status'] == 'partial'


def test_log_message_cap_partial(sdk):
    requests, session, stubs, routes = sdk
    stamp = log_args(requests)['startTime']+1
    stubs['logs'].add_response('filter_log_events', {'events': [{'timestamp': stamp, 'message': SECRET}]*100, 'nextToken': 'next'}, log_args(requests))
    sample = c.scan_logs(requests, session, REGION, GROUP)
    assert len(sample['records']) == 100 and not sample['complete']
    item, index = fixture('logs')
    item['ContentSecretIndicators'] = sample
    assert checks.logs(item, index)[0] == 'FAIL'


@pytest.mark.parametrize('mode', ['file', 'logs'])
def test_projection_byte_bound(mode):
    arguments = {'repositoryName': 'demo', 'commitSpecifier': COMMIT, 'filePath': '/config.py'} if mode == 'file' else {'logGroupName': 'demo', 'startTime': 1, 'endTime': 100, 'limit': 100}
    response = {'commitId': COMMIT, 'filePath': '/config.py', 'fileSize': len(SECRET), 'fileContent': SECRET.encode()} if mode == 'file' else {'events': [{'timestamp': 2, 'message': SECRET}]*2}
    value = c.project_response(response, 'codecommit' if mode == 'file' else 'logs', 'get_file' if mode == 'file' else 'filter_log_events', arguments, region=REGION, request_context={'remaining_bytes': len(SECRET) if mode == 'logs' else 0})['value']
    if mode == 'file':
        assert value['readable'] is False and value['categories'] == []
    else:
        assert value['events'][0]['categories'] == ['private_key'] and value['events'][1]['categories'] == []


@pytest.mark.parametrize('bad', [{'commitId': 'b'*40}, {'filePath': '/foreign'}, {'fileSize': 99}, {'fileContent': 'wrongtype'}])
def test_malformed_projection(bad):
    from peaso.collectors.aws import ReadFailure
    response = {'commitId': COMMIT, 'filePath': '/config.py', 'fileSize': len(SECRET), 'fileContent': SECRET.encode(), **bad}
    with pytest.raises(ReadFailure):
        c.project_response(response, 'codecommit', 'get_file', {'repositoryName': 'demo', 'commitSpecifier': COMMIT, 'filePath': '/config.py'}, region=REGION, request_context={'remaining_bytes': 1048576})


def test_default_requests_guard(sdk):
    requests, session, stubs, routes = sdk
    from peaso.collectors.aws import ReadFailure
    with pytest.raises(ReadFailure):
        requests.call(session, 'logs', REGION, 'filter_log_events', **log_args(requests))
    with pytest.raises(ReadFailure):
        requests.call(session, 'codecommit', REGION, 'get_file', repositoryName='demo', commitSpecifier=COMMIT, filePath='/config.py')
    assert routes == []


def test_log_group_rejects_repository_identity_without_reader_call(sdk):
    requests, session, _, routes = sdk
    sample = c.scan_logs(requests, session, REGION, {**GROUP, 'repositoryId': 'foreign'})
    assert sample['collection_status'] == 'malformed'
    assert sample['errors'] == [{'status': 'malformed', 'code': 'content_read_incomplete'}]
    assert routes == []


@pytest.mark.parametrize('mode', ['repository', 'logs'])
@pytest.mark.parametrize('state', ['denied', 'not_collected', 'empty', 'malformed', 'partial'])
def test_collection_membership_is_required(mode, state):
    item, index = fixture(mode)
    index['collections'][checks.KINDS[mode]][0]['status'] = state
    assert getattr(checks, mode)(item, index)[0] == 'UNKNOWN'


def test_positive_then_denied_log_page(sdk):
    requests, session, stubs, _ = sdk
    stamp = log_args(requests)['startTime']+1
    stubs['logs'].add_response('filter_log_events', {'events': [{'timestamp': stamp, 'message': SECRET}], 'nextToken': 'next'}, log_args(requests))
    stubs['logs'].add_client_error('filter_log_events', service_error_code='AccessDeniedException', expected_params=log_args(requests, 'next', 99))
    sample = c.scan_logs(requests, session, REGION, GROUP)
    assert sample['collection_status'] == 'partial' and not sample['complete']
    item, index = fixture('logs')
    item['ContentSecretIndicators'] = sample
    assert checks.logs(item, index)[0] == 'FAIL'


def test_sdk_foreign_file_projection_does_not_cache_payload(sdk):
    requests, session, stubs, _ = sdk
    args = {'repositoryName': 'demo', 'commitSpecifier': COMMIT, 'filePath': '/config.py'}
    stubs['codecommit'].add_response('get_file', {'commitId': 'b'*40, 'blobId': 'b'*40, 'filePath': '/config.py', 'fileMode': 'NORMAL', 'fileSize': len(SECRET), 'fileContent': SECRET.encode()}, args)
    from peaso.collectors.aws import ReadFailure
    with pytest.raises(ReadFailure):
        c._call(requests, session, REGION, 'codecommit', 'get_file', remaining_bytes=1048576, **args)
    for future in requests._cache.values():
        error = future.exception()
        assert error is not None and error.__traceback__ is None
        assert SECRET not in str(error)


def test_profile_context_is_part_of_cache_key(sdk):
    requests, session, stubs, _ = sdk
    args = {'repositoryName': 'demo', 'commitSpecifier': COMMIT, 'filePath': '/config.py'}
    response = {'commitId': COMMIT, 'blobId': 'b'*40, 'filePath': '/config.py', 'fileMode': 'NORMAL', 'fileSize': len(SECRET), 'fileContent': SECRET.encode()}
    for _ in range(2):
        stubs['codecommit'].add_response('get_file', response, args)
    assert c._call(requests, session, REGION, 'codecommit', 'get_file', remaining_bytes=1048576, **args)['categories'] == ['private_key']
    assert c._call(requests, session, REGION, 'codecommit', 'get_file', remaining_bytes=0, **args)['categories'] == []
    assert requests.calls == 2


@pytest.mark.parametrize('enabled', [False, True])
def test_guard_rejects_missing_context_before_sdk(sdk, enabled):
    requests, session, stubs, routes = sdk
    requests.content_secret_scans = enabled
    from peaso.collectors.aws import ReadFailure
    with pytest.raises(ReadFailure):
        requests.call(session, 'logs', REGION, 'filter_log_events', _metadata_profile=c.PROFILE, **log_args(requests))
    assert routes == []


def test_subfolder_and_unsupported_metadata(sdk):
    requests, session, stubs, routes = sdk
    stub = stubs['codecommit']
    stub.add_response('get_repository', {'repositoryMetadata': {'repositoryName': 'demo', 'Arn': REPO['Arn'], 'accountId': ACCOUNT, 'defaultBranch': 'main'}}, {'repositoryName': 'demo'})
    stub.add_response('get_branch', {'branch': {'branchName': 'main', 'commitId': COMMIT}}, {'repositoryName': 'demo', 'branchName': 'main'})
    stub.add_response('get_folder', {'commitId': COMMIT, 'folderPath': '/', 'subFolders': [{'absolutePath': '/src'}]}, {'repositoryName': 'demo', 'commitSpecifier': COMMIT, 'folderPath': '/'})
    stub.add_response('get_folder', {'commitId': COMMIT, 'folderPath': '/src', 'symbolicLinks': [{'absolutePath': '/src/link'}]}, {'repositoryName': 'demo', 'commitSpecifier': COMMIT, 'folderPath': '/src'})
    sample = c.scan_repository(requests, session, REGION, REPO)
    assert sample['collection_status'] == 'partial' and not sample['complete']


def test_repository_file_cap(sdk, monkeypatch):
    requests, session, stubs, routes = sdk
    monkeypatch.setattr(c, 'MAX_FILES', 1)
    stub = stubs['codecommit']
    stub.add_response('get_repository', {'repositoryMetadata': {'repositoryName': 'demo', 'Arn': REPO['Arn'], 'accountId': ACCOUNT, 'defaultBranch': 'main'}}, {'repositoryName': 'demo'})
    stub.add_response('get_branch', {'branch': {'branchName': 'main', 'commitId': COMMIT}}, {'repositoryName': 'demo', 'branchName': 'main'})
    stub.add_response('get_folder', {'commitId': COMMIT, 'folderPath': '/', 'files': [{'absolutePath': '/first'}, {'absolutePath': '/second'}]}, {'repositoryName': 'demo', 'commitSpecifier': COMMIT, 'folderPath': '/'})
    stub.add_response('get_file', {'commitId': COMMIT, 'blobId': 'b'*40, 'filePath': '/first', 'fileMode': 'NORMAL', 'fileSize': 0, 'fileContent': b''}, {'repositoryName': 'demo', 'commitSpecifier': COMMIT, 'filePath': '/first'})
    sample = c.scan_repository(requests, session, REGION, REPO)
    assert sample['file_requests'] == 1 and not sample['complete']


@pytest.mark.parametrize('mode', ['repository', 'logs'])
@pytest.mark.parametrize('positive', [False, True])
def test_real_snapshot_engine(mode, positive, monkeypatch):
    from peaso import engine
    from peaso.checks import Check
    from peaso.snapshot import make_snapshot
    item, index = fixture(mode, positive)
    declaration = next(d for d in checks.DECLARATIONS if d['id'] == checks.IDS[mode])
    native = Check(declaration['id'], 'aws', declaration['category'], declaration['kind'], declaration['title'],
                   declaration['severity'], declaration['control'], declaration['remediation'], getattr(checks, mode),
                   'resource', tuple(declaration['dependencies']), True)
    monkeypatch.setattr(engine, '_registry', lambda: [native])
    snapshot = make_snapshot('aws', [ACCOUNT+'/'+REGION], sum(index['collections'].values(), []), created_at='2026-10-19T00:00:00Z')
    findings = [f for f in engine.evaluate_snapshot(snapshot, categories=['hardening'], checks=[checks.IDS[mode]])['findings'] if f['check_id'] == checks.IDS[mode]]
    assert len(findings) == 1 and findings[0]['status'] == ('FAIL' if positive else 'PASS')


@pytest.mark.parametrize('mode', ['repository', 'logs'])
def test_missing_record_size_unknown(mode):
    item, index = fixture(mode)
    del item['ContentSecretIndicators']['records'][0]['size']
    assert getattr(checks, mode)(item, index)[0] == 'UNKNOWN'


def test_repository_aggregate_byte_cap(sdk):
    requests, session, stubs, _ = sdk
    content = 'x' * 600000 + SECRET
    prime_repo(stubs['codecommit'], ('/first', '/second'), content)
    sample = c.scan_repository(requests, session, REGION, REPO)
    assert sample['inspected_bytes'] == len(content)
    assert sample['records'][0]['categories'] == ['private_key']
    assert not sample['records'][1]['readable'] and sample['records'][1]['categories'] == []
    assert not sample['complete'] and sample['collection_status'] == 'partial'
    assert content not in cache_values(requests)


def test_binary_decode_consumes_inspection_budget():
    response = {'commitId': COMMIT, 'filePath': '/binary', 'fileSize': 3, 'fileContent': b'\xff\x00\xff'}
    value = c.project_response(response, 'codecommit', 'get_file', {'repositoryName': 'demo', 'commitSpecifier': COMMIT, 'filePath': '/binary'}, region=REGION, request_context={'remaining_bytes': 3})['value']
    assert not value['readable'] and value['inspected_bytes'] == 3 and value['categories'] == []


def test_loaded_collector_contract():
    from peaso.collectors import aws
    assert c.READ_ACTIONS <= aws.READ_ACTIONS
    assert aws.SPECS['codecommit_repository'] == c.SPECS['codecommit_repository']
    assert aws._NATIVE_IDS['codecommit_repository'] == 'repositoryName'
    assert all(kind in aws.ENRICHERS for kind in ('codecommit_repository', 'log_group'))
