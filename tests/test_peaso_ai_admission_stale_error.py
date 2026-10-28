"""Workflow admission rechecks current AI access instead of trusting old errors."""

from types import SimpleNamespace

import pytest

from peaso.ai import auth, providers
from peaso.ai.crypto import AICipher
from peaso.storage.runtime import WorkflowDispatcher


class Store:
    def __init__(self):
        self.state = {}
        self.admitted = False

    def ai_state(self, user, key):
        return self.state.get((user, key))

    def set_ai_state(self, user, key, value, previous):
        identity = user, key
        if self.state.get(identity) != previous:
            return False
        if value is None:
            self.state.pop(identity, None)
        else:
            self.state[identity] = value
        return True

    def admit(self, tenant, job_id):
        self.admitted = True
        return True

    def job(self, tenant, job_id):
        return {'id': job_id, 'status': 'queued'}


class Client:
    def __init__(self):
        self.started = []

    def start_execution(self, **kwargs):
        self.started.append(kwargs)


@pytest.fixture
def admission(tmp_path, monkeypatch):
    store = Store()
    cipher = AICipher(tmp_path / 'identity')
    settings = SimpleNamespace(identity_dir=tmp_path / 'identity', auth_mode='local')
    monkeypatch.setattr('peaso.server.config.Settings', lambda: settings)
    monkeypatch.setattr('peaso.storage.runtime.stores', lambda _: (store, None))
    monkeypatch.setattr('peaso.ai.isolation.available', lambda: True)
    profile = {'provider': 'openai', 'model': 'OPENAI_BEST_QUALITY',
               'thinking': 'high', 'credential': 'valid-fixture-token', 'validated': True}
    store.set_ai_state('alice', providers.STATE_KEY, cipher.encrypt(profile), None)
    previous_error = cipher.encrypt({'message': 'Previous inference failed.', 'at': 1})
    store.set_ai_state('alice', providers.ERROR_KEY, previous_error, None)
    client = Client()
    dispatcher = WorkflowDispatcher(arn='fixture-workflow', client=client, store=store)
    return store, cipher, previous_error, dispatcher, client


def test_stale_error_clears_only_after_fresh_successful_validation(admission, monkeypatch):
    store, cipher, previous_error, dispatcher, client = admission
    calls = []

    def validate(access):
        calls.append(access.public())
        assert access.credential == 'valid-fixture-token'
        return access

    monkeypatch.setattr(providers, 'validate_access', validate)
    assert dispatcher.dispatch('alice', {'id': 'queued', 'ai_enabled': True}) is True
    assert calls == [{'provider': 'openai', 'model': 'OPENAI_BEST_QUALITY', 'thinking': 'high'}]
    assert previous_error and store.ai_state('alice', providers.ERROR_KEY) is None
    assert store.admitted and len(client.started) == 1


def test_currently_invalid_access_blocks_dispatch_and_retains_new_error(admission, monkeypatch):
    store, cipher, previous_error, dispatcher, client = admission

    def invalid(_access):
        raise providers.ConfigurationError('Current inference access is invalid.')

    monkeypatch.setattr(providers, 'validate_access', invalid)
    assert dispatcher.dispatch('alice', {'id': 'queued', 'ai_enabled': True}) is False
    assert not store.admitted and not client.started
    current_error = store.ai_state('alice', providers.ERROR_KEY)
    assert current_error != previous_error
    assert cipher.decrypt(current_error)['message'] == 'Current inference access is invalid.'


def test_new_error_during_validation_cannot_be_erased(admission, monkeypatch):
    store, cipher, previous_error, dispatcher, client = admission

    def concurrent(access):
        store.set_ai_state('alice', providers.ERROR_KEY,
                           cipher.encrypt({'message': 'New concurrent failure.', 'at': 2}), previous_error)
        return access

    monkeypatch.setattr(providers, 'validate_access', concurrent)
    assert dispatcher.dispatch('alice', {'id': 'queued', 'ai_enabled': True}) is False
    assert not store.admitted and not client.started
    assert cipher.decrypt(store.ai_state('alice', providers.ERROR_KEY))['message'] == 'New concurrent failure.'
