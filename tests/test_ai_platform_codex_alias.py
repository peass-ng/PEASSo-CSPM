"""The hosted platform account runs Codex on the shared OpenAI model tier."""
import time

from peaso.ai import providers
from peaso.ai._vendor.chack import model_aliases


def test_platform_token_resolves_openai_alias_and_ignores_stale_codex_alias(monkeypatch):
    monkeypatch.setattr(model_aliases, '_REMOTE_MODEL_CACHE', {
        'OPENAI_BEST_QUALITY': 'gpt-6-sol',
        'CODEX_BEST_QUALITY': 'gpt-5.6-sol',
    })
    monkeypatch.setattr(model_aliases, '_REMOTE_CACHE_LOADED_AT', time.time())
    access = providers.model_access('fixture-platform-token')
    assert access.public()['provider'] == 'codex'
    assert access.public()['model'] == 'gpt-6-sol'
