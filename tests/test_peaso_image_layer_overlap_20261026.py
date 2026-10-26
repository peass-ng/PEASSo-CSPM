import threading

import pytest

from peaso.image_layer_overlap_20261026 import download_then_validate


def _download(values, events=None, fail_at=None):
    def download(put):
        for index, value in enumerate(values):
            if fail_at == index:
                raise ValueError('image_layer_download_failed')
            if events is not None:
                events[index].wait(5)
            put(index, value)
        return list(values)
    return download


def _collect(seen):
    def validate(get):
        seen.append([get(index) for index in range(3)])
    return validate


def test_layers_are_validated_once_in_order_and_returned():
    seen, stages = [], []
    layers = download_then_validate(_download(['a', 'b', 'c']), _collect(seen), 3, lambda: None,
                                    validating=lambda: stages.append('validation'))
    assert layers == ['a', 'b', 'c'] and seen == [['a', 'b', 'c']] and stages == ['validation']


def test_validation_starts_before_later_layers_finish():
    gates = [threading.Event() for _ in range(3)]
    gates[0].set()
    order = []

    def validate(get):
        for index in range(3):
            order.append(('validate', get(index)))
            if index + 1 < 3:
                gates[index + 1].set()
    download_then_validate(_download(['a', 'b', 'c'], gates), validate, 3, lambda: None)
    assert order == [('validate', 'a'), ('validate', 'b'), ('validate', 'c')]


def test_download_error_wins_and_validation_stage_is_not_entered():
    stages = []

    def validate(get):
        get(0)
        raise ValueError('archive_validation_failed')
    with pytest.raises(ValueError, match='image_layer_download_failed'):
        download_then_validate(_download(['a', 'b', 'c'], fail_at=2), validate, 3, lambda: None,
                               validating=lambda: stages.append('validation'))
    assert stages == []


def test_validation_error_is_reported_after_every_download_joined():
    finished, stages = [], []

    def download(put):
        for index, value in enumerate('abc'):
            put(index, value)
        finished.append(True)
        return list('abc')

    def validate(get):
        get(0)
        raise ValueError('archive_validation_failed')
    with pytest.raises(ValueError, match='archive_validation_failed'):
        download_then_validate(download, validate, 3, lambda: None,
                               validating=lambda: stages.append(bool(finished)))
    assert stages == [True]


def test_unreported_or_different_layers_are_validated_serially():
    seen = []
    assert download_then_validate(lambda put: list('abc'), _collect(seen), 3, lambda: None) == list('abc')
    assert seen == [list('abc')]

    seen.clear()

    def stale(put):
        for index in range(3):
            put(index, 'old')
        return list('abc')
    download_then_validate(stale, _collect(seen), 3, lambda: None)
    assert seen == [['old'] * 3, list('abc')]


def test_cancellation_while_waiting_reaches_the_validator():
    release = threading.Event()

    def download(put):
        release.wait(5)
        raise ValueError('image_layer_download_cancelled')

    def check():
        release.set()
        raise ValueError('cancelled')
    with pytest.raises(ValueError, match='image_layer_download_cancelled'):
        download_then_validate(download, _collect([]), 3, check)


from tests.test_aws_image_layer_pipeline import expected_ledger, fixture  # noqa: E402,F401


@pytest.mark.parametrize('serial', [False, True])
def test_ecr_layers_feed_validation_with_unchanged_download_evidence(fixture, serial):
    from peaso.collectors.aws_image_layer_overlap_20261026 import download_and_validate
    f = fixture
    if serial:
        f.requests.max_calls = 100
    seen, stages = [], []

    def validate(ready):
        seen.append([ready(index).read_bytes() for index in range(len(f.descs))])
    paths = download_and_validate(f.reader, 'fixture', f.descs, f.root, 'sha256:' + 'a' * 64,
                                  validate, validating=lambda: stages.append('validation'))
    assert [p.read_bytes() for p in paths] == f.bodies and seen == [f.bodies]
    assert stages == ['validation'] and f.reader.ledger == expected_ledger(f)
    assert 'layer_ready' not in vars(f.reader) and f.state['transfers'] == 0


def test_ecr_download_failure_wins_over_partial_validation(fixture, monkeypatch):
    from peaso.collectors import aws_image_vulnerability_native_20261021 as native
    from peaso.collectors.aws_image_layer_overlap_20261026 import download_and_validate
    f, stages = fixture, []

    def download(requests, url, region, digest, size, path, **kwargs):
        if digest == f.descs[-1]['digest']:
            raise ValueError('image_layer_download_failed')
        return f.download(requests, url, region, digest, size, path, **kwargs)
    monkeypatch.setattr(native, 'download_blob_path', download)

    def validate(ready):
        ready(0)
        raise ValueError('archive_validation_failed')
    with pytest.raises(ValueError, match='image_layer_download_failed'):
        download_and_validate(f.reader, 'fixture', f.descs, f.root, 'sha256:' + 'a' * 64,
                              validate, validating=lambda: stages.append('validation'))
    assert stages == [] and 'layer_ready' not in vars(f.reader)
