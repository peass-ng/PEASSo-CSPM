"""Slow ECR layer streams under a shared link: progress keeps them alive.

Live scans of a repository image and the container-image Lambdas built from
it download several 100+ MB layers at once. Each layer used to have a fixed
wall-clock limit, so a stream still delivering bytes was cut off and the
image (and every Lambda using it) was reported as an unreadable archive.
"""
import threading
import time

from peaso.collectors import aws_image_capture_20261022 as capture
from peaso.collectors import aws_image_vulnerability_native_20261021 as native
from peaso.collectors import aws_package_content_indicators as p
from peaso.checks import aws_package_content_review_20261019 as c
from tests.test_aws_package_content_review_20261019 import (
    URL, Response, index, image_function, lambda_result,
    isolated_detector_dependencies)  # noqa: F401 (autouse: offline detectors)


class Clock(threading.local):
    """Each download thread's view of time; layer reads take simulated seconds.

    Thread-local, so the slow layer stream does not age the config blob that
    downloads next to it.
    """
    offset = 0.0
    longest = 0.0

    def monotonic(self):
        return time.monotonic() + self.offset

    def advance(self, seconds):
        self.offset += seconds
        type(self).longest = max(type(self).longest, self.offset)


class Trickle(Response):
    """A layer stream on a shared link: a few bytes per (simulated) 40 s read."""
    def __init__(self, data, url, clock, stall):
        super().__init__(data, url=url)
        self.clock, self.stall = clock, stall

    def read(self, count):
        stalled = self.stall and self.source.tell() >= len(self.source.getvalue()) // 2
        self.clock.advance(200 if stalled else 40)
        return self.source.read(min(count, 4))


def _scan(monkeypatch, *, stall):
    requests, session, item, repository, ops, calls, downloads, _ = image_function(monkeypatch, True)
    Clock.longest = 0.0
    layer_url, clock, payloads = URL + '-layer', Clock(), {}
    # Same blobs the review fixture serves; only the layer stream is slow.
    original = p.build_opener().open
    for suffix in ('-config', '-layer'):
        payloads[URL + suffix] = original(URL + suffix, 1).source.getvalue()
    def opener(*args):
        class Opener:
            def open(self, request, timeout):
                url = request if isinstance(request, str) else request.full_url
                body = payloads[url]
                return Trickle(body, url, clock, stall) if url == layer_url else Response(body, url=url)
        return Opener()
    monkeypatch.setattr(p, 'build_opener', opener)
    monkeypatch.setattr(native, 'time', clock)
    with capture.capture_scope(requests):
        ecr = p.ENRICHERS['ecr_repository'](requests, session, 'us-east-1', [repository])[0]
        fn, (fn_status, _) = lambda_result(requests, session, item)
    return ecr, fn, fn_status, clock


def test_layer_still_delivering_bytes_is_scanned_for_ecr_and_lambda(monkeypatch):
    ecr, fn, fn_status, clock = _scan(monkeypatch, stall=False)
    indicators = ecr['PackageContentSource']['PackageSecretIndicators']
    assert indicators['NativeResponseComplete'] is True, indicators.get('Reason')
    assert c.image_layers(ecr, index('ecr_repository', ecr))[0] == 'FAIL'
    assert fn_status == 'FAIL'
    # Far longer than five minutes in total, yet bytes never stopped arriving.
    assert clock.longest > 1000


def test_stalled_layer_is_a_download_failure_not_an_unreadable_archive(monkeypatch):
    ecr, fn, fn_status, _ = _scan(monkeypatch, stall=True)
    for result in (ecr, fn):
        reason = result['PackageContentSource']['PackageSecretIndicators']['Reason']
        assert reason == 'image_content_incomplete: layer_download_unavailable'
    assert fn_status == 'UNKNOWN'
