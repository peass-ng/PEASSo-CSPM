"""Bounded ECR repository lanes keep the serial enricher's exact rows and reads."""
from collections import Counter
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import gzip
import json
import random
import threading
import time
from types import SimpleNamespace

import pytest

from peaso.collectors import aws, aws_package_content_indicators as package
from peaso.collectors import aws_ecr_repository_lanes_20261029 as lanes_module
from peaso.collectors import aws_image_capture_20261022 as capture
from peaso.secret_scanning_adaptive import AdaptiveTH
from tests.test_aws_package_content_review_20261019 import (
    ACCOUNT, REGION, URL, FUNCTIONS, arn, digest, http, index, tar_bytes)

KIND = 'ecr_repository'
WHEN = datetime(2026, 10, 19, tzinfo=timezone.utc)


@pytest.fixture(autouse=True)
def offline_detectors(monkeypatch):
    from peaso import secret_scanning
    secret_scanning._RESULTS.clear()
    monkeypatch.setattr(secret_scanning, '_scan_kingfisher', lambda *args: [])
    monkeypatch.setattr(secret_scanning, '_scan_trufflehog', lambda *args: [])
    yield
    secret_scanning._RESULTS.clear()


def _image(repo, text, payloads, *, layers=1):
    tars = [tar_bytes([(f'app/{repo}-{n}.py', text if n == 0 else f'ready={n}')]) for n in range(layers)]
    blobs = [gzip.compress(raw, mtime=0) for raw in tars]
    config = json.dumps({'architecture': 'amd64', 'os': 'linux',
        'rootfs': {'type': 'layers', 'diff_ids': [digest(raw) for raw in tars]},
        'config': {'Env': ['STAGE=' + repo]}, 'history': [{'created_by': 'COPY ' + repo}]}).encode()
    cd = digest(config)
    payloads[URL + '-' + cd] = config
    descriptors = []
    for blob in blobs:
        payloads[URL + '-' + digest(blob)] = blob
        descriptors.append({'mediaType': 'application/vnd.oci.image.layer.v1.tar+gzip',
                            'digest': digest(blob), 'size': len(blob)})
    manifest = json.dumps({'schemaVersion': 2, 'mediaType': package.OCI,
        'config': {'mediaType': 'application/vnd.oci.image.config.v1+json', 'digest': cd, 'size': len(config)},
        'layers': descriptors})
    return digest(manifest.encode()), manifest, len(config) + sum(map(len, blobs))


def _registry(monkeypatch, *, delay=0.0):
    """Eight repositories: findings, clean, multi-image, unsized, foreign, empty."""
    payloads, images, inventories, items = {}, {}, {}, []
    specs = [
        ('alpha', "PASSWORD='SyntheticOnly9342!Credential'", 1, True),
        ('bravo', 'ready=true', 2, True),
        ('charlie', "PASSWORD='SyntheticOnly5521!Credential'", 3, True),
        ('delta', 'ready=false', 1, False),           # no size: runs alone
        ('echo', "PASSWORD='SyntheticOnly7713!Credential'", 2, True),
        ('foxtrot', 'ready=maybe', 1, True),
    ]
    for offset, (repo, text, layers, sized) in enumerate(specs):
        rows = []
        for age in (2, 0) if repo in ('bravo', 'echo') else (0,):
            body = text if age == 0 else 'stale=' + repo
            image_digest, manifest, size = _image(repo + str(age), body, payloads, layers=layers)
            images[(repo, image_digest)] = manifest
            row = {'registryId': ACCOUNT, 'repositoryName': repo, 'imageDigest': image_digest,
                   'imagePushedAt': WHEN + timedelta(minutes=offset) - timedelta(days=age),
                   'imageManifestMediaType': package.OCI}
            if sized:
                row['imageSizeInBytes'] = size
            rows.append(row)
        inventories[repo] = rows
        items.append({'repositoryArn': arn('ecr', 'repository/' + repo), 'repositoryName': repo,
                      'registryId': ACCOUNT})
    items.insert(3, {'repositoryArn': arn('ecr', 'repository/golf').replace(ACCOUNT, '999999999999'),
                     'repositoryName': 'golf', 'registryId': '999999999999'})
    inventories['hotel'] = []
    items.append({'repositoryArn': arn('ecr', 'repository/hotel'), 'repositoryName': 'hotel',
                  'registryId': ACCOUNT})
    calls, lock, lanes_seen = [], threading.Lock(), set()

    def operation(name, kw):
        if name == 'get_caller_identity':
            return {'Account': ACCOUNT, 'Arn': f'arn:aws:sts::{ACCOUNT}:assumed-role/a/b', 'UserId': 'test'}
        if name == 'describe_images':
            return {'imageDetails': inventories[kw['repositoryName']]}
        if name == 'batch_get_image':
            repo, image_digest = kw['repositoryName'], kw['imageIds'][0]['imageDigest']
            return {'images': [{'registryId': ACCOUNT, 'repositoryName': repo,
                                'imageId': {'imageDigest': image_digest},
                                'imageManifest': images[(repo, image_digest)],
                                'imageManifestMediaType': package.OCI}], 'failures': []}
        if name == 'get_download_url_for_layer':
            return {'layerDigest': kw['layerDigest'], 'downloadUrl': URL + '-' + kw['layerDigest']}
        raise AssertionError(name)

    def client(service, **kwargs):
        class Client:
            def __getattr__(self, name):
                def invoke(**kw):
                    with lock:
                        calls.append((service, name, json.dumps(kw, sort_keys=True, default=str)))
                        if name == 'batch_get_image':
                            lanes_seen.add(threading.current_thread().name)
                    if delay:
                        time.sleep(delay * random.random())
                    return deepcopy(operation(name, kw))
                return invoke
            def can_paginate(self, name): return False
        return Client()
    session = SimpleNamespace(client=client)
    requests = aws.Requests({'content_secret_scans': True, 'retry_attempts': 1})
    monkeypatch.setattr(aws, 'READ_ACTIONS', aws.READ_ACTIONS | package.READ_ACTIONS)
    downloads = http(monkeypatch, payloads)
    requests.lanes_seen = lanes_seen
    return requests, session, items, calls, downloads


def _serial():
    return aws._explicit_content_enricher(KIND, package.ENRICHERS[KIND])


def _run(monkeypatch, enricher, *, delay=0.0):
    from peaso import secret_evidence
    requests, session, items, calls, downloads = _registry(monkeypatch, delay=delay)
    with secret_evidence.capture(secret_evidence.EphemeralCipher()) as sink:
        with capture.capture_scope(requests):
            rows = enricher(requests, session, REGION, deepcopy(items))
        private = {}
        for fingerprint in sink.records:
            record = sink.load(fingerprint)
            private[record['value']] = (sorted(json.dumps(location, sort_keys=True, default=str)
                                               for location in record['locations']),
                                        record['detectors'], record['check_ids'])
    requests.private_evidence = private
    return requests, items, rows, calls, downloads


def _statuses(rows):
    return [FUNCTIONS[KIND](row, index(KIND, row))[0] for row in rows]




@pytest.mark.parametrize('delay', [0.0, 0.01])
def test_lanes_rows_order_and_api_reads_match_serial(monkeypatch, delay):
    first, items, serial, serial_calls, serial_downloads = _run(monkeypatch, _serial(), delay=delay)
    widths = []
    original = lanes_module.ThreadPoolExecutor
    def pool(*args, **kwargs):
        widths.append(kwargs['max_workers'])
        return original(*args, **kwargs)
    monkeypatch.setattr(lanes_module, 'ThreadPoolExecutor', pool)
    requests, _, parallel, calls, downloads = _run(monkeypatch, lanes_module.lanes(KIND, _serial()), delay=delay)
    assert widths == [lanes_module.LANES]
    assert len(first.lanes_seen) == 1 and len(requests.lanes_seen) > 1
    assert all(name.startswith('peaso-ecr-repo') for name in requests.lanes_seen)
    assert parallel == serial
    # Clear-text values remain in the owner's private evidence, identically.
    assert len(requests.private_evidence) == 3
    assert requests.private_evidence == first.private_evidence
    assert [row['repositoryName'] for row in parallel] == [item['repositoryName'] for item in items]
    assert _statuses(parallel) == ['FAIL', 'PASS', 'FAIL', 'UNKNOWN', 'PASS', 'FAIL', 'PASS', 'UNKNOWN']
    assert Counter(calls) == Counter(serial_calls)
    assert Counter(url for url, _ in downloads) == Counter(url for url, _ in serial_downloads)
    # Clear-text values stay with the owner's private evidence, never in cache.
    cache = json.dumps([f.result() for f in requests._cache.values() if f.exception() is None], default=str)
    assert 'SyntheticOnly' not in cache and 'X-Amz-Signature' not in cache


def _fake(monkeypatch, *, bounds, capacity=1 << 40, sleep=.05, fail=()):
    lock = threading.Lock()
    state = {'active': 0, 'peak': 0, 'overlap': set()}
    running = set()

    def enricher(requests, session, region, items):
        (item,) = items
        with lock:
            state['active'] += 1
            state['peak'] = max(state['peak'], state['active'])
            running.add(item['n'])
            if len(running) > 1:
                state['overlap'].update(running)
        try:
            time.sleep(sleep * (1 + item['n'] % 3))
            if item['n'] in fail:
                raise RuntimeError('lane %d' % item['n'])
            return [{**item, 'done': True}]
        finally:
            with lock:
                state['active'] -= 1
                running.discard(item['n'])
    store = SimpleNamespace(lock=threading.Lock(), capacity=capacity, reserved=0, entries={})
    requests = SimpleNamespace(_lock=threading.Lock(), workers=32, max_calls=None,
                               content_secret_scans=True, _ecr_image_capture=store)
    monkeypatch.setattr(package, '_own_account', lambda *args: ACCOUNT)
    monkeypatch.setattr(lanes_module, '_upper_bound', lambda r, s, g, a, item: bounds[item['n']])
    return requests, lanes_module.lanes(KIND, enricher), state


def test_concurrency_is_bounded_to_three_lanes(monkeypatch):
    requests, enrich, state = _fake(monkeypatch, bounds=[10] * 9)
    items = [{'n': n} for n in range(9)]
    assert enrich(requests, None, REGION, items) == [{'n': n, 'done': True} for n in range(9)]
    assert state['peak'] == lanes_module.LANES


def test_capture_headroom_or_unknown_size_runs_repository_alone(monkeypatch):
    requests, enrich, state = _fake(monkeypatch, bounds=[600] * 5, capacity=1000)
    assert len(enrich(requests, None, REGION, [{'n': n} for n in range(5)])) == 5
    assert state['peak'] == 1
    requests, enrich, state = _fake(monkeypatch, bounds=[10, 10, None, 10, 10, 10])
    assert len(enrich(requests, None, REGION, [{'n': n} for n in range(6)])) == 6
    assert 2 not in state['overlap'] and state['peak'] == 3


def test_first_failure_in_input_order_is_raised(monkeypatch):
    requests, enrich, _ = _fake(monkeypatch, bounds=[10] * 6, fail={4, 1})
    with pytest.raises(RuntimeError, match='lane 1'):
        enrich(requests, None, REGION, [{'n': n} for n in range(6)])


@pytest.mark.parametrize('change', ['disabled', 'not_selected', 'no_capture', 'bounded_calls', 'single'])
def test_serial_fallbacks(monkeypatch, change):
    requests, enrich, state = _fake(monkeypatch, bounds=[10] * 4)
    items = [{'n': n} for n in range(4)]
    seen = []
    def serial(requests, session, region, rows):
        seen.append(len(rows))
        return rows
    enrich = lanes_module.lanes(KIND, serial)
    if change == 'disabled': requests.content_secret_scans = False
    elif change == 'not_selected': requests.content_secret_scan_kinds = frozenset({'lambda_function'})
    elif change == 'no_capture': requests._ecr_image_capture = None
    elif change == 'bounded_calls': requests.max_calls = 10
    else: items = items[:1]
    assert enrich(requests, None, REGION, items) == items
    assert seen == [len(items)]


def _adaptive(capacity=None, sleep=.15):
    lock, intervals, active = threading.Lock(), [], [0, 0]
    def prepare(items, timeout):
        start = time.monotonic()
        with lock:
            active[0] += 1; active[1] = max(active[1], active[0])
        time.sleep(sleep)
        with lock:
            active[0] -= 1
            intervals.append((start, time.monotonic()))
        return {item: b'' for item in items}
    policy = AdaptiveTH(prepare, lambda error: False)
    policy.large_capacity = capacity
    return policy, intervals, active


def _consume_all(policy, count=6):
    items = [(('value-%04d' % i).encode(), 'f/%d' % i) for i in range(1025)]
    def consume():
        with policy.prepared_groups(items, deadline=time.monotonic() + 600) as groups:
            return sum(len(group) for group, _ in groups)
    threads, results = [], []
    for _ in range(count):
        thread = threading.Thread(target=lambda: results.append(consume()))
        thread.start(); threads.append(thread)
    for thread in threads:
        thread.join(30)
    assert results == [1025] * count
    return sum(len(item[0]) for item in items)


def test_large_trufflehog_probe_first_alone_then_three_lanes():
    policy, intervals, active = _adaptive()
    _consume_all(policy)
    intervals.sort()
    first = intervals[0]
    assert all(start >= first[1] for start, _ in intervals[1:])
    assert active[1] == 3 and policy.metrics['large_attempts'] == 6
    assert policy.large_active == policy.large_bytes == 0


def test_large_trufflehog_lanes_respect_volatile_staging_capacity():
    need = sum(len(('value-%04d' % i).encode()) for i in range(1025))
    policy, _, active = _adaptive(capacity=2 * need + 1024 * 1024)
    _consume_all(policy)
    assert active[1] == 2 and policy.metrics['large_attempts'] == 6
