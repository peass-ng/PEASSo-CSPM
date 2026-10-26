"""The AWS credential preflight overlaps the registry import without hiding errors."""
import threading

import pytest

from peaso import worker


def _connector(**extra):
    return {'provider': 'aws', 'auth': {'method': 'profile', 'profile': 'selected'}, **extra}


def test_preflight_runs_concurrently_with_work(monkeypatch):
    started, release = threading.Event(), threading.Event()
    seen = []

    def verify(connector):
        started.set()
        assert release.wait(5)
        seen.append(('verify', threading.current_thread() is not threading.main_thread()))

    def work():
        assert started.wait(5)
        seen.append(('work', threading.current_thread() is threading.main_thread()))
        release.set()
        return 'imported'

    monkeypatch.setattr(worker, '_verify_aws_credentials', verify)
    assert worker._verify_aws_credentials_while(_connector(), work) == 'imported'
    assert sorted(seen) == [('verify', True), ('work', True)]


def test_credential_failure_is_raised_after_work(monkeypatch):
    def verify(connector):
        raise worker.CredentialExpired('AWS connector authentication failed before collection')

    monkeypatch.setattr(worker, '_verify_aws_credentials', verify)
    calls = []
    with pytest.raises(worker.CredentialExpired):
        worker._verify_aws_credentials_while(_connector(), lambda: calls.append(1))
    assert calls == [1]


def test_work_failure_waits_for_preflight(monkeypatch):
    done = []
    monkeypatch.setattr(worker, '_verify_aws_credentials', lambda connector: done.append(1))

    def work():
        raise ImportError('broken registry')

    with pytest.raises(ImportError):
        worker._verify_aws_credentials_while(_connector(), work)
    assert done == [1]


@pytest.mark.parametrize('connector', [{'provider': 'gcp'}, _connector(input_mode='offline_snapshot'),
                                       _connector(input_mode='demo')])
def test_non_live_aws_runs_inline(monkeypatch, connector):
    order = []
    monkeypatch.setattr(worker, '_verify_aws_credentials', lambda c: order.append(('verify', threading.current_thread() is threading.main_thread())))
    worker._verify_aws_credentials_while(connector, lambda: order.append(('work', True)))
    assert order == [('verify', True), ('work', True)]
