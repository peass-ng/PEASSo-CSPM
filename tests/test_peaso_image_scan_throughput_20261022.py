"""Synthetic TAR source conservation across bounded detector preparation."""
import io
import json
import tarfile
import threading
import time
from contextvars import ContextVar
from types import SimpleNamespace

import pytest

from peaso import secret_scanning as scanning
from peaso import secret_scanning_batch as batch
from peaso import secret_evidence as evidence
from peaso import secret_scan_clean
from peaso.collectors import aws_package_content_indicators as package
from peaso.collectors import aws_code_log_content_indicators as code_log
from peaso.collectors import gcp_image_secret_indicators as gcp_image


TOKEN_A = 'ghp_' + '7mQ2zR9wL4cV8nK1sF6aH3jP5uD0xB2yE9rT'
TOKEN_B = 'ghp_' + '2Yt9Ec5Zp0Ru6Wq1Aa8Kd3Vx7Mn4Bs5Hj9Lf'
MEDIA = 'application/vnd.oci.image.layer.v1.tar'


def archive(files):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode='w', format=tarfile.USTAR_FORMAT) as tar:
        for name, content in files:
            header = tarfile.TarInfo(name)
            header.size = len(content)
            tar.addfile(header, io.BytesIO(content))
    return output.getvalue()


class Requests:
    def __init__(self):
        self.events = []
        self.progress_callback = self.events.append

    def check_deadline(self):
        pass


@pytest.fixture(autouse=True)
def clear_cache():
    # Both process memos hold detector outcomes from earlier mocked runs.
    scanning._RESULTS.clear(); secret_scan_clean._CLEAN.clear()
    yield
    scanning._RESULTS.clear(); secret_scan_clean._CLEAN.clear()


def test_tar_batches_exact_files_and_keeps_both_engine_positives(monkeypatch):
    files = [(f'dir/file-{i}.txt', f'line one\nfile={i}\n'.encode()) for i in range(40)]
    files[3] = (files[3][0], b'line one\nking=' + TOKEN_A.encode() + b'\n')
    files[35] = (files[35][0], b'line one\nhog=' + TOKEN_B.encode() + b'\n')
    groups, threads = [], []

    def prepare(items, timeout):
        groups.append([path for _, path in items])
        return {(payload, path): (json.dumps({'Raw': TOKEN_B, 'RawV2': TOKEN_B,
                    'DetectorName': 'Github', 'Verified': False}).encode()
                    if TOKEN_B.encode() in payload else b'') for payload, path in items}

    def kingfisher(payload, path, timeout):
        threads.append(threading.get_ident())
        return [(TOKEN_A, 'synthetic', 2)] if TOKEN_A.encode() in payload else []

    monkeypatch.setattr(batch, '_prepare_trufflehog_batch', prepare)
    monkeypatch.setattr(scanning, '_scan_kingfisher', kingfisher)
    monkeypatch.setattr(scanning, '_run', lambda *a: pytest.fail('serial scanner started'))
    requests = Requests()
    refs, expanded, members = package.scan_tar(archive(files), MEDIA, requests)
    assert [len(group) for group in groups] == [40]
    assert [name for group in groups for name in group] == [name for name, _ in files]
    assert len(threads) == 40 and all(thread != threading.get_ident() for thread in threads)
    assert members == 40 and expanded > 0
    assert {(ref['File'], leak['detectors'][0]['engine'], leak['locations'][0]['line'])
            for ref in refs for leak in ref['Leaks']} == {
                (files[3][0], 'kingfisher', 2), (files[35][0], 'trufflehog', 2)}
    assert [event['completed'] for event in requests.events] == [40]
    assert all(event['provider'] == 'aws' and event['phase'] in
               {'collecting', 'scanning_images'} and event['dynamic_total'] is True
               and event['total'] is None and set(event) ==
               {'phase', 'provider', 'completed', 'total', 'dynamic_total'}
               for event in requests.events)
    assert batch._PREPARED_BATCH.get() is None


def test_tar_late_invalid_member_preserves_scanned_positive(monkeypatch):
    files = [('first', b'king=' + TOKEN_A.encode()), ('first', b'duplicate')]
    monkeypatch.setattr(batch, '_prepare_trufflehog_batch',
                        lambda items, timeout: {(payload, path): b'' for payload, path in items})
    monkeypatch.setattr(scanning, '_scan_kingfisher',
                        lambda payload, path, timeout: [(TOKEN_A, 'synthetic', 1)]
                        if TOKEN_A.encode() in payload else [])
    monkeypatch.setattr(scanning, '_scan_trufflehog', lambda *args: [])
    with pytest.raises(package.PartialArchive) as error:
        package.scan_tar(archive(files), MEDIA, Requests())
    assert len(error.value.refs) == 1
    assert error.value.refs[0]['File'] == 'first'
    assert error.value.refs[0]['Leaks'][0]['detectors'][0]['engine'] == 'kingfisher'


def test_tar_detector_failure_is_incomplete_with_other_positive(monkeypatch):
    files = [('first', b'king=' + TOKEN_A.encode()), ('second', b'clean')]
    monkeypatch.setattr(batch, '_prepare_trufflehog_batch',
                        lambda items, timeout: {(payload, path): b'' for payload, path in items})
    monkeypatch.setattr(scanning, '_scan_kingfisher',
                        lambda payload, path, timeout: [(TOKEN_A, 'synthetic', 1)]
                        if TOKEN_A.encode() in payload else [])
    monkeypatch.setattr(scanning, '_scan_trufflehog',
                        lambda *args: (_ for _ in ()).throw(RuntimeError('synthetic scanner failure')))
    with pytest.raises(package.PartialArchive) as error:
        package.scan_tar(archive(files), MEDIA, Requests())
    assert len(error.value.refs) == 1
    assert error.value.refs[0]['Leaks'][0]['detectors'][0]['engine'] == 'kingfisher'


def test_gcp_image_deadline_forwards_only_count_progress():
    events = []
    reader = SimpleNamespace(transport=SimpleNamespace(progress_callback=events.append))
    package._scan_progress(gcp_image.Deadline(reader), 17, 'image')
    assert len(events) == 1
    assert events[0]['provider'] == 'gcp'
    assert events[0]['completed'] == 17
    assert 'resources' not in events[0]
    assert 'scope' not in events[0]


def test_tar_batch_private_evidence_retains_exact_layer_and_asset(monkeypatch):
    resource = 'arn:aws:ecr:us-east-1:123456789012:repository/owned@sha256:' + 'a' * 64
    layer = 'sha256:' + 'b' * 64
    check = 'aws.review.ecr_repository.package_content_secret_indicators'
    payload = b'line one\ntoken=' + TOKEN_A.encode() + b'\n'
    files = [('safe/first', payload), ('safe/second', b'clean=true\n')]
    monkeypatch.setattr(batch, '_prepare_trufflehog_batch',
                        lambda items, timeout: {(raw, name):
                            json.dumps({'Raw': TOKEN_A, 'RawV2': TOKEN_A,
                                        'DetectorName': 'Github', 'Verified': False}).encode()
                            if TOKEN_A.encode() in raw else b'' for raw, name in items})
    monkeypatch.setattr(scanning, '_scan_kingfisher',
                        lambda raw, name, timeout: [(TOKEN_A, 'synthetic', 2)]
                        if TOKEN_A.encode() in raw else [])
    monkeypatch.setattr(scanning, '_run', lambda *a: pytest.fail('serial scanner started'))
    cipher = evidence.EphemeralCipher()
    with evidence.capture(cipher, tenant='offline', scan_id='a' * 32) as sink:
        with evidence.source_context(resource_id=resource, scope='123456789012/us-east-1',
                                     image_digest='sha256:' + 'c' * 64, layer=layer,
                                     check_ids={check}):
            refs, _, _ = package.scan_tar(archive(files), MEDIA, Requests())
    assert len(refs) == 1 and refs[0]['File'] == 'safe/first'
    sealed = sink.document()
    assert TOKEN_A not in json.dumps(sealed) and TOKEN_A not in json.dumps(refs)
    finding = {'check_id': check, 'status': 'FAIL', 'resource_id': resource,
               'native_resource_id': resource, 'scope': '123456789012/us-east-1',
               'evidence': {'secret_leaks': refs[0]['Leaks']}}
    detail = evidence.details(finding, sealed, cipher, tenant='offline', scan_id='a' * 32)
    assert detail['status'] == 'available'
    assert {entry['value'] for entry in detail['matches']} == {TOKEN_A}
    assert {entry['locations'][0]['layer'] for entry in detail['matches']} == {layer}
    assert {entry['locations'][0]['path'] for entry in detail['matches']} == {'safe/first'}


def test_ecr_layer_fetch_bounds_workers_and_preserves_threadlocal_bindings(tmp_path):
    resource = 'arn:aws:ecr:us-east-1:123456789012:repository/owned@sha256:' + 'a' * 64
    digest = 'sha256:' + 'a' * 64
    descriptors = [('sha256:' + str(i) * 64, 64) for i in range(4)]
    barrier = threading.Barrier(2)
    marker = ContextVar('synthetic_layer_context')
    token = marker.set('owning-scan')
    state = threading.local()
    lock = threading.Lock()

    class FakeRequests:
        def __init__(self):
            self.active = self.maximum = 0
            self.calls = []

        def check_deadline(self):
            pass

        def detail(self, session, service, region, operation, **arguments):
            index = next(i for i, (ld, _) in enumerate(descriptors)
                         if ld == arguments['layerDigest'])
            ld, size = descriptors[index]
            assert marker.get() == 'owning-scan'
            assert state.active[:2] == (ld, size) and state.budget == [size]
            assert evidence._source.fields['resource_id'] == resource
            assert evidence._source.fields['layer'] == ld
            assert service == 'ecr' and operation == 'get_download_url_for_layer'
            assert arguments['_cache_refresh'] is True
            with lock:
                self.active += 1
                self.maximum = max(self.maximum, self.active)
                self.calls.append(index)
            try:
                if index < 2:
                    barrier.wait(timeout=2)
                time.sleep(.02)
                state.active[2].write_bytes(b'x' * size)
            finally:
                with lock:
                    self.active -= 1
            return {'collection_status': 'collected', 'LayerDigest': ld,
                    'RegistryId': '123456789012', 'RepositoryName': 'owned',
                    'CompressedBytes': size}

    requests = FakeRequests()
    cipher = evidence.EphemeralCipher()
    try:
        with evidence.capture(cipher, tenant='offline', scan_id='a' * 32):
            paths = package._download_image_layers(requests, object(), 'us-east-1',
                '123456789012', 'owned', digest, resource, descriptors, tmp_path, state)
    finally:
        marker.reset(token)
    assert [path.name for path in paths] == [f'blob-{i:04}' for i in range(4)]
    assert requests.maximum == 2 and requests.active == 0
    assert sorted(requests.calls) == [0, 1, 2, 3]


def test_ecr_layer_fetch_rejects_unwritten_blob(tmp_path):
    state = threading.local()

    class Requests:
        def check_deadline(self):
            pass

        def detail(self, *args, **kwargs):
            return {'collection_status': 'collected', 'LayerDigest': kwargs['layerDigest'],
                    'RegistryId': '123456789012', 'RepositoryName': 'owned',
                    'CompressedBytes': 64}

    with pytest.raises(ValueError, match='layer incomplete'):
        package._download_image_layers(Requests(), object(), 'us-east-1',
            '123456789012', 'owned', 'sha256:' + 'a' * 64, 'owned-image',
            [('sha256:' + 'b' * 64, 64)], tmp_path, state)


def test_log_page_batches_messages_and_retains_each_event_source(monkeypatch):
    events = [{'timestamp': 100 + i, 'eventId': f'event-{i}',
               'logStreamName': 'owned-stream',
               'message': ('token=' + TOKEN_A if i in (3, 70) else f'clean event {i}')}
              for i in range(100)]
    groups = []

    def prepare(items, timeout):
        groups.append(list(items))
        return {(payload, path): (json.dumps({'Raw': TOKEN_A, 'RawV2': TOKEN_A,
                    'DetectorName': 'Github', 'Verified': False}).encode()
                    if TOKEN_A.encode() in payload else b'') for payload, path in items}

    def kingfisher(payload, path, timeout):
        if TOKEN_A.encode() not in payload:
            return []
        return [(TOKEN_A, 'synthetic', 1)]

    monkeypatch.setattr(batch, '_prepare_trufflehog_batch', prepare)
    monkeypatch.setattr(scanning, '_scan_kingfisher', kingfisher)
    monkeypatch.setattr(scanning, '_run', lambda *a: pytest.fail('serial scanner started'))
    arguments = {'logGroupName': 'owned-group', 'startTime': 100,
                 'endTime': 200, 'limit': 100}
    cipher = evidence.EphemeralCipher()
    with evidence.capture(cipher, tenant='offline', scan_id='a' * 32) as sink:
        with evidence.source_context(resource_id='owned-log-group', scope='us-east-1'):
            result = code_log.project_response({'events': events}, 'logs',
                'filter_log_events', arguments, region='us-east-1',
                request_context={'remaining_bytes': code_log.MAX_BYTES})['value']
    assert [len(group) for group in groups] == [100]
    assert all(path == 'log-message' for group in groups for _, path in group)
    assert [row['timestamp'] for row in result['events']] == list(range(100, 200))
    assert all(row['scanner_complete'] for row in result['events'])
    assert [i for i, row in enumerate(result['events']) if row['leaks']] == [3, 70]
    assert all({d['engine'] for leak in result['events'][i]['leaks']
                for d in leak['detectors']} == {'kingfisher', 'trufflehog'}
               for i in (3, 70))
    # Private capture runs on the caller; the Kingfisher worker deliberately
    # has no thread-local source context. Inspect actual persisted locations.
    contexts = cipher.decrypt(sink.records[scanning._fingerprint(TOKEN_A)])['locations']
    assert [json.loads(context['source'])['eventId'] for context in contexts] == [
        'event-3', 'event-70']
    assert all(context['path'] == 'owned-group' and
               context['resource_id'] == 'owned-log-group' for context in contexts)
    assert TOKEN_A not in json.dumps(result) and TOKEN_A not in json.dumps(sink.document())


@pytest.mark.parametrize('serial_fails', [False, True])
def test_log_batch_preparation_failure_keeps_event_coverage_and_positive(
        monkeypatch, serial_fails):
    monkeypatch.setattr(batch, '_prepare_trufflehog_batch',
                        lambda *args: (_ for _ in ()).throw(TimeoutError('synthetic batch timeout')))
    monkeypatch.setattr(scanning, '_trufflehog', lambda: '/synthetic/trufflehog')
    monkeypatch.setattr(scanning, '_scan_kingfisher',
                        lambda payload, path, timeout: [(TOKEN_A, 'synthetic', 1)]
                        if TOKEN_A.encode() in payload else [])
    calls = []

    def run(argv, payload, timeout):
        calls.append(payload)
        if serial_fails and TOKEN_A.encode() in payload:
            raise TimeoutError('synthetic serial timeout')
        return (json.dumps({'Raw': TOKEN_A, 'RawV2': TOKEN_A,
                'DetectorName': 'Github', 'Verified': False}).encode()
                if TOKEN_A.encode() in payload else b'')

    monkeypatch.setattr(scanning, '_run', run)
    messages = [{'timestamp': 101, 'message': 'token=' + TOKEN_A},
                {'timestamp': 102, 'message': 'clean event'}]
    result = code_log.project_response({'events': messages}, 'logs',
        'filter_log_events', {'logGroupName': 'owned', 'startTime': 100,
                              'endTime': 200, 'limit': 2}, region='us-east-1',
        request_context={'remaining_bytes': code_log.MAX_BYTES})['value']['events']
    assert len(calls) == 2 and all(row['readable'] for row in result)
    assert result[0]['leaks'] and result[1]['leaks'] == []
    assert result[0]['scanner_complete'] is (not serial_fails)
    assert result[1]['scanner_complete'] is True
    assert {d['engine'] for leak in result[0]['leaks']
            for d in leak['detectors']} == ({'kingfisher'} if serial_fails else
                                            {'kingfisher', 'trufflehog'})


def test_log_message_budget_keeps_unreadable_gap_and_later_coverage(monkeypatch):
    seen = []
    monkeypatch.setattr(scanning, '_scan_kingfisher',
                        lambda payload, path, timeout: seen.append(payload) or [])
    monkeypatch.setattr(scanning, '_scan_trufflehog', lambda *args: [])
    messages = [{'timestamp': 101, 'message': 'one'},
                {'timestamp': 102, 'message': 'oversized'},
                {'timestamp': 103, 'message': 'two'}]
    result = code_log.project_response({'events': messages}, 'logs',
        'filter_log_events', {'logGroupName': 'owned', 'startTime': 100,
                              'endTime': 200, 'limit': 3}, region='us-east-1',
        request_context={'remaining_bytes': 6})['value']['events']
    assert [row['readable'] for row in result] == [True, False, True]
    assert [row['scanner_complete'] for row in result] == [True, False, True]
    assert [row['size'] for row in result] == [3, 9, 3]
    assert seen == [b'one', b'two']
