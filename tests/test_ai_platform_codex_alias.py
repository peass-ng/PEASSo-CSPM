"""The hosted platform account must use the central Codex model alias."""
import time

from peaso.ai import providers
from peaso.ai._vendor.chack import model_aliases


def test_platform_token_uses_codex_alias_when_openai_alias_differs(monkeypatch):
    monkeypatch.setattr(model_aliases, '_REMOTE_MODEL_CACHE', {
        'OPENAI_BEST_QUALITY': 'gpt-6-sol',
        'CODEX_BEST_QUALITY': 'gpt-5.6-sol',
    })
    monkeypatch.setattr(model_aliases, '_REMOTE_CACHE_LOADED_AT', time.time())
    access = providers.model_access('fixture-platform-token')
    assert access.public() == {
        'provider': 'codex', 'model': 'gpt-5.6-sol', 'thinking': 'high',
    }
