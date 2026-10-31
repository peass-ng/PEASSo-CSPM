from __future__ import annotations

import logging
import os
import time
from typing import Any, Dict, Optional

import requests

# Local fallback only. Runtime resolution prefers the central model-alias Lambda.
OPENAI_BEST_QUALITY = "gpt-6-sol"
OPENAI_CHEAP_BUT_QUALITY = "gpt-6-sol"
OPENAI_BEST_CHEAPEST = "gpt-6-luna"
# Deprecated: Codex runs the OpenAI tiers. Kept only so configs that still
# name these aliases get the same models.
CODEX_BEST_QUALITY = OPENAI_BEST_QUALITY
CODEX_BEST_CHEAPEST = OPENAI_BEST_CHEAPEST
ANTHROPIC_BEST_QUALITY = "claude-opus-5-5"
ANTHROPIC_CHEAP_BUT_QUALITY = "claude-sonnet-5-5"
ANTHROPIC_BEST_CHEAPEST = "claude-haiku-5-5"
OPENROUTER_BEST_QUALITY = f"openrouter/openai/{OPENAI_BEST_QUALITY}"
OPENROUTER_CHEAP_BUT_QUALITY = "openrouter/google/gemini-3.8-flash"
OPENROUTER_BEST_CHEAPEST = "openrouter/deepseek/deepseek-v4.1-flash"
COPILOT_BEST_QUALITY = "claude-sonnet-4.6"
COPILOT_CHEAP_BUT_QUALITY = "gpt-5.4-mini"
COPILOT_BEST_CHEAPEST = "gpt-5-mini"
OPENAI_DEFAULT_BACKEND = "codex"
ANTHROPIC_DEFAULT_BACKEND = "claude"
OPENROUTER_DEFAULT_BACKEND = "openrouter"
COPILOT_DEFAULT_BACKEND = "copilot"

_ALIAS_EQUIVALENTS_BY_PROVIDER: Dict[str, Dict[str, str]] = {
    "openai": {
        "BEST_QUALITY": "OPENAI_BEST_QUALITY",
        "CHEAP_BUT_QUALITY": "OPENAI_CHEAP_BUT_QUALITY",
        "BEST_CHEAPEST": "OPENAI_BEST_CHEAPEST",
    },
    "codex": {
        "BEST_QUALITY": "OPENAI_BEST_QUALITY",
        "CHEAP_BUT_QUALITY": "OPENAI_CHEAP_BUT_QUALITY",
        "BEST_CHEAPEST": "OPENAI_BEST_CHEAPEST",
    },
    "claude": {
        "BEST_QUALITY": "ANTHROPIC_BEST_QUALITY",
        "CHEAP_BUT_QUALITY": "ANTHROPIC_CHEAP_BUT_QUALITY",
        "BEST_CHEAPEST": "ANTHROPIC_BEST_CHEAPEST",
    },
    "claude-code": {
        "BEST_QUALITY": "ANTHROPIC_BEST_QUALITY",
        "CHEAP_BUT_QUALITY": "ANTHROPIC_CHEAP_BUT_QUALITY",
        "BEST_CHEAPEST": "ANTHROPIC_BEST_CHEAPEST",
    },
    "claude_code": {
        "BEST_QUALITY": "ANTHROPIC_BEST_QUALITY",
        "CHEAP_BUT_QUALITY": "ANTHROPIC_CHEAP_BUT_QUALITY",
        "BEST_CHEAPEST": "ANTHROPIC_BEST_CHEAPEST",
    },
    "anthropic": {
        "BEST_QUALITY": "ANTHROPIC_BEST_QUALITY",
        "CHEAP_BUT_QUALITY": "ANTHROPIC_CHEAP_BUT_QUALITY",
        "BEST_CHEAPEST": "ANTHROPIC_BEST_CHEAPEST",
    },
    "openrouter": {
        "BEST_QUALITY": "OPENROUTER_BEST_QUALITY",
        "CHEAP_BUT_QUALITY": "OPENROUTER_CHEAP_BUT_QUALITY",
        "BEST_CHEAPEST": "OPENROUTER_BEST_CHEAPEST",
    },
    "copilot": {
        "BEST_QUALITY": "COPILOT_BEST_QUALITY",
        "CHEAP_BUT_QUALITY": "COPILOT_CHEAP_BUT_QUALITY",
        "BEST_CHEAPEST": "COPILOT_BEST_CHEAPEST",
    },
    "copilot-cli": {
        "BEST_QUALITY": "COPILOT_BEST_QUALITY",
        "CHEAP_BUT_QUALITY": "COPILOT_CHEAP_BUT_QUALITY",
        "BEST_CHEAPEST": "COPILOT_BEST_CHEAPEST",
    },
    "copilot_cli": {
        "BEST_QUALITY": "COPILOT_BEST_QUALITY",
        "CHEAP_BUT_QUALITY": "COPILOT_CHEAP_BUT_QUALITY",
        "BEST_CHEAPEST": "COPILOT_BEST_CHEAPEST",
    },
    "gh-copilot": {
        "BEST_QUALITY": "COPILOT_BEST_QUALITY",
        "CHEAP_BUT_QUALITY": "COPILOT_CHEAP_BUT_QUALITY",
        "BEST_CHEAPEST": "COPILOT_BEST_CHEAPEST",
    },
    "gh_copilot": {
        "BEST_QUALITY": "COPILOT_BEST_QUALITY",
        "CHEAP_BUT_QUALITY": "COPILOT_CHEAP_BUT_QUALITY",
        "BEST_CHEAPEST": "COPILOT_BEST_CHEAPEST",
    },
}
_ALIAS_EQUIVALENTS_BY_KEY_TYPE: Dict[str, Dict[str, str]] = {
    "openai": {
        "BEST_QUALITY": "OPENAI_BEST_QUALITY",
        "CHEAP_BUT_QUALITY": "OPENAI_CHEAP_BUT_QUALITY",
        "BEST_CHEAPEST": "OPENAI_BEST_CHEAPEST",
    },
    "anthropic": {
        "BEST_QUALITY": "ANTHROPIC_BEST_QUALITY",
        "CHEAP_BUT_QUALITY": "ANTHROPIC_CHEAP_BUT_QUALITY",
        "BEST_CHEAPEST": "ANTHROPIC_BEST_CHEAPEST",
    },
    "openrouter": {
        "BEST_QUALITY": "OPENROUTER_BEST_QUALITY",
        "CHEAP_BUT_QUALITY": "OPENROUTER_CHEAP_BUT_QUALITY",
        "BEST_CHEAPEST": "OPENROUTER_BEST_CHEAPEST",
    },
    "copilot": {
        "BEST_QUALITY": "COPILOT_BEST_QUALITY",
        "CHEAP_BUT_QUALITY": "COPILOT_CHEAP_BUT_QUALITY",
        "BEST_CHEAPEST": "COPILOT_BEST_CHEAPEST",
    },
}
_OPENAI_ALIAS_EQUIVALENTS: Dict[str, str] = {
    "BEST_QUALITY": "OPENAI_BEST_QUALITY",
    "CHEAP_BUT_QUALITY": "OPENAI_CHEAP_BUT_QUALITY",
    "BEST_CHEAPEST": "OPENAI_BEST_CHEAPEST",
}


MODEL_ALIASES: Dict[str, str] = {
    "OPENAI_BEST_QUALITY": OPENAI_BEST_QUALITY,
    "CODEX_BEST_QUALITY": CODEX_BEST_QUALITY,
    "CODEX_BEST_CHEAPEST": CODEX_BEST_CHEAPEST,
    "OPENAI_CHEAP_BUT_QUALITY": OPENAI_CHEAP_BUT_QUALITY,
    "OPENAI_BEST_CHEAPEST": OPENAI_BEST_CHEAPEST,
    "ANTHROPIC_BEST_QUALITY": ANTHROPIC_BEST_QUALITY,
    "ANTHROPIC_CHEAP_BUT_QUALITY": ANTHROPIC_CHEAP_BUT_QUALITY,
    "ANTHROPIC_BEST_CHEAPEST": ANTHROPIC_BEST_CHEAPEST,
    "OPENROUTER_BEST_QUALITY": OPENROUTER_BEST_QUALITY,
    "OPENROUTER_CHEAP_BUT_QUALITY": OPENROUTER_CHEAP_BUT_QUALITY,
    "OPENROUTER_BEST_CHEAPEST": OPENROUTER_BEST_CHEAPEST,
    "COPILOT_BEST_QUALITY": COPILOT_BEST_QUALITY,
    "COPILOT_CHEAP_BUT_QUALITY": COPILOT_CHEAP_BUT_QUALITY,
    "COPILOT_BEST_CHEAPEST": COPILOT_BEST_CHEAPEST,
}
BACKEND_ALIASES: Dict[str, str] = {
    "OPENAI_DEFAULT_BACKEND": OPENAI_DEFAULT_BACKEND,
    "ANTHROPIC_DEFAULT_BACKEND": ANTHROPIC_DEFAULT_BACKEND,
    "OPENROUTER_DEFAULT_BACKEND": OPENROUTER_DEFAULT_BACKEND,
    "COPILOT_DEFAULT_BACKEND": COPILOT_DEFAULT_BACKEND,
}


# How hard each tier alias thinks. Offline fallback only: the central Lambda's
# ``thinking_efforts`` block wins, so a tier's effort changes without a rebuild.
THINKING_EFFORTS: Dict[str, str] = {
    "OPENAI_BEST_QUALITY": "high",
    "OPENAI_CHEAP_BUT_QUALITY": "medium",
    "OPENAI_BEST_CHEAPEST": "high",
    "CODEX_BEST_QUALITY": "high",
    "CODEX_BEST_CHEAPEST": "high",
    "ANTHROPIC_BEST_QUALITY": "high",
    "ANTHROPIC_CHEAP_BUT_QUALITY": "medium",
    "ANTHROPIC_BEST_CHEAPEST": "high",
    "OPENROUTER_BEST_QUALITY": "high",
    "OPENROUTER_CHEAP_BUT_QUALITY": "medium",
    "OPENROUTER_BEST_CHEAPEST": "high",
    "COPILOT_BEST_QUALITY": "high",
    "COPILOT_CHEAP_BUT_QUALITY": "medium",
    "COPILOT_BEST_CHEAPEST": "high",
}


def get_default_model_aliases() -> Dict[str, str]:
    return dict(MODEL_ALIASES)


def get_default_backend_aliases() -> Dict[str, str]:
    return dict(BACKEND_ALIASES)


def get_public_model_aliases() -> Dict[str, str]:
    return {
        key: value
        for key, value in MODEL_ALIASES.items()
        if key.startswith(("OPENAI_", "CODEX_", "ANTHROPIC_", "OPENROUTER_"))
    }


def get_public_backend_aliases() -> Dict[str, str]:
    return dict(BACKEND_ALIASES)

_LOGGER = logging.getLogger("chack.model_aliases")
_REMOTE_CACHE_SECONDS = int(os.environ.get("CHACK_MODEL_ALIASES_CACHE_SECONDS", "300") or "300")
_REMOTE_URL = os.environ.get("CHACK_MODEL_ALIASES_LAMBDA_URL", "").strip()
_DEFAULT_REMOTE_URL = "https://6lj6nwv3krblocoano5k33zzna0uqebx.lambda-url.us-east-1.on.aws/"
if not _REMOTE_URL:
    _REMOTE_URL = _DEFAULT_REMOTE_URL
_REMOTE_MODEL_CACHE: Optional[Dict[str, str]] = None
_REMOTE_BACKEND_CACHE: Optional[Dict[str, str]] = None
_REMOTE_EFFORT_CACHE: Optional[Dict[str, str]] = None
_REMOTE_CACHE_LOADED_AT: float = 0.0
_GENERIC_MODEL_ALIASES = frozenset({"BEST_QUALITY", "CHEAP_BUT_QUALITY", "BEST_CHEAPEST"})


def _load_remote_aliases() -> Optional[dict[str, Dict[str, str]]]:
    if not _REMOTE_URL:
        return None
    try:
        response = requests.get(_REMOTE_URL, timeout=5)
        response.raise_for_status()
        payload = response.json()
    except requests.RequestException as exc:
        _LOGGER.warning("Failed to fetch model aliases from %s: %s", _REMOTE_URL, exc)
        return None
    except ValueError as exc:
        _LOGGER.warning("Invalid JSON from %s: %s", _REMOTE_URL, exc)
        return None

    if not isinstance(payload, dict):
        _LOGGER.warning("Unexpected aliases payload from %s: %r", _REMOTE_URL, payload)
        return None

    def _normalize_alias_block(raw_block: Any) -> Dict[str, str]:
        aliases: Dict[str, str] = {}
        if not isinstance(raw_block, dict):
            return aliases
        for key, value in raw_block.items():
            if not key or not isinstance(key, str):
                continue
            if not value or not isinstance(value, str):
                continue
            aliases[key.strip()] = value.strip()
        return aliases

    model_aliases = _normalize_alias_block(payload.get("model_aliases", payload))
    backend_aliases = _normalize_alias_block(payload.get("backend_aliases", {}))
    thinking_efforts = _normalize_alias_block(payload.get("thinking_efforts", {}))
    return {
        "model_aliases": model_aliases,
        "backend_aliases": backend_aliases,
        "thinking_efforts": thinking_efforts,
    }


def _refresh_remote_alias_caches() -> None:
    global _REMOTE_MODEL_CACHE, _REMOTE_BACKEND_CACHE, _REMOTE_EFFORT_CACHE, _REMOTE_CACHE_LOADED_AT
    if not _REMOTE_URL:
        return
    now = time.time()
    if _REMOTE_MODEL_CACHE is None or (now - _REMOTE_CACHE_LOADED_AT) > _REMOTE_CACHE_SECONDS:
        remote = _load_remote_aliases()
        if remote:
            _REMOTE_MODEL_CACHE = remote.get("model_aliases") or None
            _REMOTE_BACKEND_CACHE = remote.get("backend_aliases") or None
            _REMOTE_EFFORT_CACHE = remote.get("thinking_efforts") or None
            _REMOTE_CACHE_LOADED_AT = now
        else:
            _REMOTE_CACHE_LOADED_AT = now


def _get_model_aliases() -> Dict[str, str]:
    """Return effective aliases, with the central Lambda taking precedence.

    Local constants are deliberately only an offline fallback. This ordering is
    operations-critical: changing an alias in the central Lambda must affect
    every chack-agent consumer after its cache expires, without requiring a
    package rebuild.
    """
    _refresh_remote_alias_caches()
    merged = dict(MODEL_ALIASES)
    merged.update(_REMOTE_MODEL_CACHE or {})
    return merged


def _get_backend_aliases() -> Dict[str, str]:
    _refresh_remote_alias_caches()
    merged = dict(BACKEND_ALIASES)
    merged.update(_REMOTE_BACKEND_CACHE or {})
    return merged


def _get_thinking_efforts() -> Dict[str, str]:
    _refresh_remote_alias_caches()
    merged = dict(THINKING_EFFORTS)
    merged.update(_REMOTE_EFFORT_CACHE or {})
    return merged


# Codex runs the OpenAI tiers, so the deprecated Codex aliases are read as the
# OpenAI ones whatever an alias server still publishes under the old names.
_DEPRECATED_ALIASES: Dict[str, str] = {
    "CODEX_BEST_QUALITY": "OPENAI_BEST_QUALITY",
    "CODEX_BEST_CHEAPEST": "OPENAI_BEST_CHEAPEST",
}


def _adapt_alias_for_runtime(name: str, *, provider: str = "") -> str:
    key = str(name or "").strip()
    if not key:
        return name
    key = _DEPRECATED_ALIASES.get(key, key)
    model_provider = str(provider or "").strip().lower()
    provider_aliases = _ALIAS_EQUIVALENTS_BY_PROVIDER.get(model_provider)
    if provider_aliases:
        return provider_aliases.get(key, key)
    return key


def _adapt_alias_for_key_type(name: str, *, key_type: str = "") -> str:
    key = str(name or "").strip()
    if not key:
        return name
    resolved = _ALIAS_EQUIVALENTS_BY_KEY_TYPE.get(str(key_type or "").strip().lower(), {})
    if resolved:
        return resolved.get(key, key)
    return _OPENAI_ALIAS_EQUIVALENTS.get(key, key)


def _is_openrouter_model_name(value: str) -> bool:
    return str(value or "").strip().startswith("openrouter/")


def _validate_resolved_model_name(*, requested_name: str, resolved_name: str, provider: str = "", key_type: str = "") -> str:
    normalized_provider = str(provider or "").strip().lower()
    normalized_key_type = str(key_type or "").strip().lower()
    if normalized_provider == "openrouter" or normalized_key_type == "openrouter":
        if not _is_openrouter_model_name(resolved_name):
            raise ValueError(
                f"Model alias {requested_name!r} resolved to {resolved_name!r}, but openrouter models must use a full 'openrouter/<vendor>/<model>' path"
            )
    return resolved_name


def _log_backend_resolution(*, requested_name: str, key_type: str, resolved_backend: str) -> None:
    _LOGGER.info(
        "Resolved backend alias %r using %s credentials -> %s",
        requested_name,
        key_type,
        resolved_backend,
    )


def _log_model_resolution(*, requested_name: str, provider: str = "", key_type: str = "", resolved_name: str) -> None:
    source = f"provider={provider}" if provider else f"credentials={key_type}"
    _LOGGER.info(
        "Resolved model alias %r using %s -> %s",
        requested_name,
        source,
        resolved_name,
    )


def _has_value(value: Any) -> bool:
    return bool(str(value or "").strip())


def _select_api_key_type(
    *,
    openai_api_key: str = "",
    codex_access_token: str = "",
    claude_access_token: str = "",
    anthropic_api_key: str = "",
    openrouter_api_key: str = "",
    credentials: Any = None,
    prefer_codex_access_token: bool = False,
) -> str:
    resolved_codex_access = str(
        codex_access_token
        or getattr(credentials, "codex_access_token", "")
        or os.environ.get("CODEX_ACCESS_TOKEN", "")
    ).strip()
    resolved_openai = str(openai_api_key or getattr(credentials, "openai_api_key", "") or os.environ.get("OPENAI_API_KEY", "")).strip()
    resolved_claude_access = str(
        claude_access_token
        or getattr(credentials, "claude_access_token", "")
        or getattr(credentials, "claude_code_oauth_token", "")
        or os.environ.get("CLAUDE_CODE_OAUTH_TOKEN", "")
        or os.environ.get("CLAUDE_ACCESS_TOKEN", "")
    ).strip()
    resolved_anthropic = str(
        anthropic_api_key
        or getattr(credentials, "anthropic_api_key", "")
        or getattr(credentials, "claude_api_key", "")
        or os.environ.get("ANTHROPIC_API_KEY", "")
        or os.environ.get("CLAUDE_API_KEY", "")
    ).strip()
    resolved_openrouter = str(
        openrouter_api_key
        or getattr(credentials, "openrouter_api_key", "")
        or os.environ.get("OPENROUTER_API_KEY", "")
    ).strip()

    if prefer_codex_access_token and resolved_codex_access:
        return "openai"
    if resolved_openai:
        return "openai"
    if resolved_claude_access or resolved_anthropic:
        return "anthropic"
    if resolved_openrouter:
        return "openrouter"
    return ""


def resolve_backend_alias(
    name: str,
    *,
    openai_api_key: str = "",
    codex_access_token: str = "",
    claude_access_token: str = "",
    anthropic_api_key: str = "",
    openrouter_api_key: str = "",
    credentials: Any = None,
) -> str:
    raw_name = str(name or "").strip()
    if not raw_name:
        return raw_name

    effective_name = raw_name
    if raw_name == "DEFAULT_BACKEND":
        key_type = _select_api_key_type(
            openai_api_key=openai_api_key,
            codex_access_token=codex_access_token,
            claude_access_token=claude_access_token,
            anthropic_api_key=anthropic_api_key,
            openrouter_api_key=openrouter_api_key,
            credentials=credentials,
            prefer_codex_access_token=True,
        )
        if key_type == "openai":
            effective_name = "OPENAI_DEFAULT_BACKEND"
        elif key_type == "anthropic":
            effective_name = "ANTHROPIC_DEFAULT_BACKEND"
        elif key_type == "openrouter":
            effective_name = "OPENROUTER_DEFAULT_BACKEND"
        else:
            raise ValueError(
                "DEFAULT_BACKEND requires one of CODEX_ACCESS_TOKEN, OPENAI_API_KEY, "
                "CLAUDE_CODE_OAUTH_TOKEN/CLAUDE_ACCESS_TOKEN, "
                "ANTHROPIC_API_KEY/CLAUDE_API_KEY, or OPENROUTER_API_KEY"
            )

    aliases = _get_backend_aliases()
    resolved_backend = aliases.get(effective_name, raw_name)
    if raw_name == "DEFAULT_BACKEND":
        _log_backend_resolution(
            requested_name=raw_name,
            key_type=key_type,
            resolved_backend=resolved_backend,
        )
    return resolved_backend


def resolve_model_alias(
    name: str,
    *,
    provider: str = "",
    openai_api_key: str = "",
    anthropic_api_key: str = "",
    openrouter_api_key: str = "",
    credentials: Any = None,
) -> str:
    if not name:
        return name
    raw_name = str(name or "").strip()
    normalized_provider = str(provider or "").strip().lower()
    key = _adapt_alias_for_runtime(raw_name, provider=normalized_provider)
    if not key:
        return name
    key_type = ""
    if not normalized_provider:
        key_type = _select_api_key_type(
            openai_api_key=openai_api_key,
            anthropic_api_key=anthropic_api_key,
            openrouter_api_key=openrouter_api_key,
            credentials=credentials,
        )
        if raw_name in _GENERIC_MODEL_ALIASES and not key_type:
            raise ValueError(
                f"Model alias {raw_name!r} requires one of OPENAI_API_KEY, ANTHROPIC_API_KEY/CLAUDE_API_KEY, or OPENROUTER_API_KEY"
            )
        key = _adapt_alias_for_key_type(
            key,
            key_type=key_type,
        )
    aliases = _get_model_aliases()
    if key in aliases:
        resolved_name = aliases[key]
        resolved_name = _validate_resolved_model_name(
            requested_name=raw_name,
            resolved_name=resolved_name,
            provider=normalized_provider,
            key_type=key_type,
        )
        if raw_name in _GENERIC_MODEL_ALIASES:
            _log_model_resolution(
                requested_name=raw_name,
                provider=normalized_provider,
                key_type=key_type,
                resolved_name=resolved_name,
            )
        return resolved_name
    if key.startswith("OPENAI_"):
        fallback = key[len("OPENAI_") :]
        if fallback in aliases:
            resolved_name = aliases[fallback]
            resolved_name = _validate_resolved_model_name(
                requested_name=raw_name,
                resolved_name=resolved_name,
                provider=normalized_provider,
                key_type=key_type,
            )
            if raw_name in _GENERIC_MODEL_ALIASES:
                _log_model_resolution(
                    requested_name=raw_name,
                    provider=normalized_provider,
                    key_type=key_type,
                    resolved_name=resolved_name,
                )
            return resolved_name
    else:
        fallback = f"OPENAI_{key}"
        if fallback in aliases:
            resolved_name = aliases[fallback]
            resolved_name = _validate_resolved_model_name(
                requested_name=raw_name,
                resolved_name=resolved_name,
                provider=normalized_provider,
                key_type=key_type,
            )
            if raw_name in _GENERIC_MODEL_ALIASES:
                _log_model_resolution(
                    requested_name=raw_name,
                    provider=normalized_provider,
                    key_type=key_type,
                    resolved_name=resolved_name,
                )
            return resolved_name
    return name


def resolve_thinking_effort_alias(
    name: str,
    *,
    provider: str = "",
    openai_api_key: str = "",
    anthropic_api_key: str = "",
    openrouter_api_key: str = "",
    credentials: Any = None,
) -> str:
    """Thinking effort the central Lambda assigns to model alias ``name``.

    ``name`` is looked up exactly like ``resolve_model_alias`` looks up the
    model, so the generic ``BEST_QUALITY`` follows the provider's own tier.
    Returns "" when ``name`` is a concrete model or a tier without an effort,
    or when the published value is not a known level.
    """
    from .thinking_effort import normalize_thinking_effort

    raw_name = str(name or "").strip()
    if not raw_name:
        return ""
    normalized_provider = str(provider or "").strip().lower()
    key = _adapt_alias_for_runtime(raw_name, provider=normalized_provider)
    if not normalized_provider:
        key_type = _select_api_key_type(
            openai_api_key=openai_api_key,
            anthropic_api_key=anthropic_api_key,
            openrouter_api_key=openrouter_api_key,
            credentials=credentials,
        )
        key = _adapt_alias_for_key_type(key, key_type=key_type)
    for effort in (_get_thinking_efforts().get(key, ""), THINKING_EFFORTS.get(key, "")):
        if not effort:
            continue
        try:
            return normalize_thinking_effort(effort)
        except ValueError:
            _LOGGER.warning("Ignoring unknown thinking effort %r published for %s", effort, key)
    return ""
