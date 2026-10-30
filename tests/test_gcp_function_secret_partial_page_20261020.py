"""Native retained first-page observations remain decisive after a later failure."""
from copy import deepcopy
from importlib.metadata import version
import json
from types import SimpleNamespace

import pytest

from peaso import secret_scanning as scanning
from peaso.collectors import gcp
from peaso.checks import evaluate_check
from peaso.checks import gcp_function_secret_paired_review_20261020 as base
from peaso.engine import evaluate_snapshot
from tests.gcp_function_partial_positive_native_20261020 import NAME, SCOPE, TOKEN, URL, raw


def collect_pages(monkeypatch, positive=True, unavailable_second=False):
    assert version('kingfisher-secret-scanner') == scanning.KINGFISHER_VERSION
    scanning._RESULTS.clear()
    scanning._trufflehog.cache_clear()
    if unavailable_second:
        which = scanning.shutil.which
        monkeypatch.setattr(scanning.shutil, 'which',
            lambda command: None if command == 'trufflehog' else which(command))
    source = raw({'SETTING': TOKEN if positive else 'production'}, {'BUILD': 'release'})
    calls = []
    class Response:
        def __init__(self, body, status=200): self.body, self.status_code = body, status
        def json(self): return deepcopy(self.body)
    def request(method, url, **kwargs):
        calls.append({'method': method, 'url': url, 'params': kwargs.get('params')})
        assert method == 'GET'
        if url == URL:
            if kwargs.get('params', {}).get('pageToken'):
                return Response({'error': {'message': TOKEN}}, 503)
            return Response({'functions': [deepcopy(source)], 'nextPageToken': 'page-two'})
        if url == 'https://cloudfunctions.googleapis.com/v2/' + SCOPE + '/locations':
            # 75087001: ``function`` depends on the project's Functions regions.
            return Response({'locations': [{'name': SCOPE + '/locations/us-central1', 'locationId': 'us-central1'}]})
        assert url == 'https://cloudfunctions.googleapis.com/v2/' + NAME + ':getIamPolicy'
        return Response({'bindings': []})
    transport = gcp.Transport(SimpleNamespace(headers=lambda: {}, close=lambda: None),
        {'content_secret_scans': True, '_content_secret_scan_kinds': ['function'], 'retries': 0})
    monkeypatch.setattr(transport, '_session', lambda: SimpleNamespace(request=request, close=lambda: None))
    collector = gcp.GCPCollector({'provider': 'gcp', 'scopes': [SCOPE], 'options': {
        'inventories': ['function'], 'metrics_scopes': False, 'include_inherited': False,
        'concurrency': 1}}, requirements=['function'], transport=transport)
    snapshot = collector.collect()
    envelope, = [row for row in snapshot['collections'] if row['type'] == 'function']
    assert envelope['status'] == 'partial'
    row, = envelope['items']
    assert row['FunctionSecretIndicators']['complete'] is (not unavailable_second)
    assert bool(row['FunctionSecretIndicators']['leaks']) is positive
    assert len(calls) == 4  # locations listing, two function pages, one getIamPolicy
    assert TOKEN not in json.dumps([snapshot, transport.evidence,
        [entry.get('data') for entry in transport.cache.values()]]) + repr(scanning._RESULTS)
    index = {'context': {'provider': 'gcp', 'scope': SCOPE, 'metadata': snapshot['metadata']},
             'collections': {'function': [envelope]}}
    return snapshot, row, index, calls


@pytest.fixture(scope='module')
def positive_page():
    with pytest.MonkeyPatch.context() as patch:
        return collect_pages(patch)


def test_base_paired_evaluator_still_rejects_the_global_partial_envelope(positive_page):
    _, row, index, _ = positive_page
    assert base._evaluate(row, index)[0] == 'UNKNOWN'


def test_registered_known_native_later_page_positive_requirement(positive_page):
    snapshot, row, index, _ = positive_page
    assert evaluate_check(base.CHECK_ID, row, index)[0] == 'FAIL'
    findings = evaluate_snapshot(snapshot, checks=[base.CHECK_ID])['findings']
    positives = [finding for finding in findings if finding['status'] == 'FAIL']
    assert len(positives) == 1
    evidence = positives[0]['evidence']
    assert evidence['complete'] is False and evidence['incomplete'] is True
    assert evidence['function_secret_pairs']
    assert any(finding['status'] == 'UNKNOWN' for finding in findings)
    assert json.loads(json.dumps(positives))[0]['evidence']['function_secret_pairs'] == evidence['function_secret_pairs']


def test_clean_first_page_with_later_failure_never_becomes_pass(monkeypatch):
    snapshot, row, index, _ = collect_pages(monkeypatch, positive=False)
    assert evaluate_check(base.CHECK_ID, row, index)[0] == 'UNKNOWN'
    assert all(finding['status'] == 'UNKNOWN'
               for finding in evaluate_snapshot(snapshot, checks=[base.CHECK_ID])['findings'])


@pytest.mark.parametrize('case', [
    'missing_provenance', 'foreign_provenance', 'missing_native_reference', 'missing_metadata',
    'foreign_collector', 'duplicate_request_id', 'foreign_request_url', 'masked_request',
    'non_get_request', 'denied_request', 'malformed_http_status', 'request_body',
    'duplicate_envelope', 'foreign_envelope', 'denied_envelope', 'foreign_item',
    'malformed_surface', 'unavailable_engine_hit',
])
def test_partial_positive_requires_intact_bound_successful_native_source(positive_page, case):
    _, row, index, _ = deepcopy(positive_page)
    assert evaluate_check(base.CHECK_ID, row, index)[0] == 'FAIL'
    envelope = index['collections']['function'][0]
    metadata = index['context']['metadata']
    read = next(record for record in metadata['source_requests']
                if record.get('url') == URL and record.get('status') == 'collected')
    if case == 'missing_provenance': del row['_provenance']
    elif case == 'foreign_provenance': row['_provenance']['scope'] = 'projects/foreign'
    elif case == 'missing_native_reference': row['_provenance']['source_requests'] = ['not-the-read']
    elif case == 'missing_metadata': index['context']['metadata'] = {}
    elif case == 'foreign_collector': metadata['collector'] = 'foreign'
    elif case == 'duplicate_request_id': metadata['source_requests'].append(deepcopy(read))
    elif case == 'foreign_request_url': read['url'] = URL.replace('cloudfunctions.googleapis.com', 'foreign.invalid')
    elif case == 'masked_request': read['query'] = {'fields': 'functions.name'}
    elif case == 'non_get_request': read['method'] = 'POST'
    elif case == 'denied_request': read['status'], read['http_status'] = 'denied', 403
    elif case == 'malformed_http_status': read['http_status'] = True
    elif case == 'request_body': read['request'] = {'body': 'unexpected'}
    elif case == 'duplicate_envelope': index['collections']['function'].append(deepcopy(envelope))
    elif case == 'foreign_envelope': envelope['scope'] = 'projects/foreign'
    elif case == 'denied_envelope': envelope['status'] = 'denied'
    elif case == 'foreign_item': row['name'] = NAME.replace('/review/', '/foreign/')
    elif case == 'malformed_surface': row['FunctionSecretIndicators']['surfaces'][0]['engines'] = []
    elif case == 'unavailable_engine_hit':
        marker = row['FunctionSecretIndicators']
        marker['complete'], marker['status'] = False, 'incomplete'
        marker['surfaces'][0]['complete'] = False
        marker['surfaces'][0]['engines'][1]['status'] = 'unavailable'
    assert evaluate_check(base.CHECK_ID, row, index)[0] == 'UNKNOWN', case


def test_partial_page_pair_persistence_filters_fingerprint_and_validates_read(positive_page):
    from peaso.gcp_function_secret_page_persistence_20261020 import retain_function_secret_pairs
    from peaso.secret_findings import deduplicate_secret_findings
    _, row, index, _ = positive_page
    status, evidence = evaluate_check(base.CHECK_ID, row, index)
    source = {'provider': 'gcp', 'check_id': base.CHECK_ID, 'scope': SCOPE,
        'resource_id': NAME, 'native_resource_id': NAME, 'status': status,
        'frameworks': [], 'evidence': evidence}
    final = deduplicate_secret_findings([source])
    persisted, = retain_function_secret_pairs([source], final)
    assert persisted['evidence']['incomplete'] is True
    pairs = persisted['evidence']['function_secret_pairs']
    assert all(pair['source_request']['status'] == 'collected' and pair['source_request']['http_status'] == 200
               and pair['inventory_complete'] is False for pair in pairs)
    assert all(leak['fingerprint'] == persisted['secret_fingerprint'] for pair in pairs for leak in pair['secret_leaks'])
    bad = deepcopy(source)
    bad['evidence']['function_secret_native_read']['url'] = URL.replace('cloudfunctions.googleapis.com', 'foreign.invalid')
    assert 'function_secret_pairs' not in retain_function_secret_pairs([bad], final)[0]['evidence']
    assert TOKEN not in json.dumps(persisted)




def test_partial_page_and_partial_detector_coverage_combine_without_losing_hit(monkeypatch):
    snapshot, row, index, _ = collect_pages(monkeypatch, unavailable_second=True)
    status, evidence = evaluate_check(base.CHECK_ID, row, index)
    assert status == 'FAIL'
    assert evidence['function_secret_scan_complete'] is False
    assert evidence['complete'] is False and evidence['incomplete'] is True
    finding, = [finding for finding in evaluate_snapshot(snapshot, checks=[base.CHECK_ID])['findings']
                if finding['status'] == 'FAIL']
    assert finding['evidence']['incomplete'] is True
    assert {detector['engine'] for pair in finding['evidence']['function_secret_pairs']
            for leak in pair['secret_leaks'] for detector in leak['detectors']} == {'kingfisher'}


