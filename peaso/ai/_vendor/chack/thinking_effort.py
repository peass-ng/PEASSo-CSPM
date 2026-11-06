from __future__ import annotations

import logging
import os
import re
from collections.abc import Collection
from typing import Any

import yaml


_LOGGER = logging.getLogger("chack.thinking_effort")


DEFAULT_THINKING_EFFORT = "high"
# Ordered weakest -> strongest so error messages read like the provider docs.
THINKING_EFFORT_ORDER = ("none", "minimal", "low", "medium", "high", "xhigh", "max")
THINKING_EFFORT_LEVELS = frozenset(THINKING_EFFORT_ORDER)

_ALIASES = {
    "off": "none",
    "disabled": "none",
    "extra_high": "xhigh",
    "extra-high": "xhigh",
    "extra high": "xhigh",
    "very_high": "xhigh",
    "very-high": "xhigh",
    "very high": "xhigh",
}


def normalize_thinking_effort(value: Any) -> str:
    """Return the canonical cross-backend effort name or raise ValueError."""
    raw = str(value or "").strip().lower()
    normalized = _ALIASES.get(raw, raw) or DEFAULT_THINKING_EFFORT
    if normalized not in THINKING_EFFORT_LEVELS:
        allowed = ", ".join(sorted(THINKING_EFFORT_LEVELS))
        raise ValueError(
            f"Unsupported thinking_effort value {value!r}. Expected one of: {allowed}"
        )
    return normalized


def openai_thinking_effort(value: Any) -> str:
    """Send the configured level to the Responses API unchanged.

    ``reasoning.effort`` takes the whole vocabulary and rejects what the chosen
    model does not implement, which ``validate_thinking_effort`` already catches
    at config load. Clamping here would only demote levels the model does
    support, so ``max`` on GPT-5.6 stays ``max``.
    """
    return normalize_thinking_effort(value)


def codex_thinking_effort(value: Any) -> str:
    """Send the configured level to Codex's ``model_reasoning_effort``.

    The Codex CLI forwards this config value to the Responses API verbatim
    instead of checking it against an enum, so the level the yaml asks for is
    the level the model receives.
    """
    return normalize_thinking_effort(value)


def copilot_thinking_effort(value: Any) -> str:
    """Send the configured level to Copilot CLI's ``--reasoning-effort``.

    ``copilot --help`` documents the full none/minimal/low/medium/high/xhigh/max
    choice list, so every configured level survives the hand-off.
    """
    return normalize_thinking_effort(value)


def _claude_cli_effort(effort: str, supported: set[str]) -> str:
    if effort in {"none", "minimal"}:
        return "low"
    if effort == "xhigh":
        if "xhigh" in supported:
            return "xhigh"
        return "max" if "max" in supported else "high"
    if effort == "max" and "max" not in supported:
        return "xhigh" if "xhigh" in supported else "high"
    return effort


def claude_thinking_effort(
    value: Any,
    supported_levels: Collection[str] | None = None,
) -> str:
    """Map to the levels supported by the installed Claude Code CLI.

    Claude Code takes ``--effort`` from a fixed choice list and rejects anything
    else, and the list grew over releases: older builds stop at ``max`` while
    newer ones also accept ``xhigh``. The caller passes the levels discovered
    from ``claude --help`` so both generations work. This is the one backend
    that can still run below the configured level, so say so when it happens.
    """
    effort = normalize_thinking_effort(value)
    supported = set(supported_levels or {"low", "medium", "high", "max"})
    resolved = _claude_cli_effort(effort, supported)
    if resolved != effort:
        _LOGGER.warning(
            "The installed Claude Code CLI does not accept --effort %s, "
            "running at %s instead; upgrade the CLI to use the configured level.",
            effort,
            resolved,
        )
    return resolved


OPENCODE_SDK_OPENAI = "@ai-sdk/openai"
OPENCODE_SDK_OPENAI_COMPATIBLE = "@ai-sdk/openai-compatible"
OPENCODE_SDK_ANTHROPIC = "@ai-sdk/anthropic"
OPENCODE_SDK_OPENROUTER = "@openrouter/ai-sdk-provider"

# OpenRouter's ``reasoning.effort`` stops at ``xhigh``.
_OPENROUTER_EFFORT_CAP = {"max": "xhigh"}


def opencode_thinking_effort(value: Any, sdk: str) -> dict[str, Any]:
    """Model ``options`` that carry the effort through opencode's provider SDK.

    opencode passes a model's ``options`` to the AI SDK provider named by the
    provider's ``npm`` package, so the effort has to be spelled the way that
    package expects:

    * ``@ai-sdk/openai`` (Responses API) and ``@ai-sdk/openai-compatible``
      (Chat Completions) take ``reasoningEffort`` and forward every level
      unchanged, as the Codex and OpenAI backends do.
    * ``@ai-sdk/anthropic`` takes adaptive thinking plus ``effort``, whose
      levels are low..max; ``none`` turns thinking off and ``minimal`` becomes
      ``low``.
    * ``@openrouter/ai-sdk-provider`` takes ``reasoning.effort``, which tops
      out at ``xhigh``.
    """
    effort = normalize_thinking_effort(value)
    if sdk == OPENCODE_SDK_ANTHROPIC:
        if effort == "none":
            return {"thinking": {"type": "disabled"}}
        return {
            "thinking": {"type": "adaptive"},
            "effort": "low" if effort == "minimal" else effort,
        }
    if sdk == OPENCODE_SDK_OPENROUTER:
        return {"reasoning": {"effort": _OPENROUTER_EFFORT_CAP.get(effort, effort)}}
    return {"reasoningEffort": effort}


def _gemini_model_name(model_name: Any) -> str:
    return str(model_name or "").strip().lower().rsplit("/", 1)[-1]


def gemini_thinking_config(value: Any, model_name: Any = "") -> dict[str, Any]:
    """Build a model-family-safe Gemini CLI ``thinkingConfig``.

    Gemini 3 uses ``thinkingLevel`` and Gemini 2.5 uses ``thinkingBudget``.
    Sending both is not portable, so select exactly one based on the configured
    model. Unknown/future models use the level-based API used by current Gemini.
    """
    effort = normalize_thinking_effort(value)
    model = _gemini_model_name(model_name)

    if not model.startswith("gemini-2.5"):
        # Gemini 3 Pro only supports LOW/HIGH, while Flash and newer Pro
        # variants also expose MINIMAL and/or MEDIUM. Clamp unsupported common
        # levels instead of letting the provider reject the request.
        if "gemini-3-pro" in model and "gemini-3.1-pro" not in model:
            level = "LOW" if effort in {"none", "minimal", "low"} else "HIGH"
        elif "flash-lite-image" in model:
            level = "MINIMAL" if effort in {"none", "minimal", "low"} else "HIGH"
        else:
            level = {
                "none": "MINIMAL",
                "minimal": "MINIMAL",
                "low": "LOW",
                "medium": "MEDIUM",
                "high": "HIGH",
                "xhigh": "HIGH",
                "max": "HIGH",
            }[effort]
        return {"includeThoughts": True, "thinkingLevel": level}

    is_pro = "-pro" in model
    budget = {
        # Gemini 2.5 Pro cannot disable thinking and has a minimum of 128.
        "none": 128 if is_pro else 0,
        "minimal": 128 if is_pro else 512,
        "low": 2048,
        "medium": 8192,
        "high": 16384,
        # Flash/Flash-Lite cap at 24576; Pro permits 32768.
        "xhigh": 32768 if is_pro else 24576,
        "max": 32768 if is_pro else 24576,
    }[effort]
    return {"includeThoughts": True, "thinkingBudget": budget}


# ---------------------------------------------------------------------------
# Per-model validation
#
# The vocabulary above is the union of every provider's levels, so a value that
# normalizes fine can still be meaningless for the model a config selects (for
# example ``xhigh`` on Claude Sonnet 4.6, which only goes up to ``max``).
#
# The levels each model accepts come from ``config/thinking_effort.yaml``, which
# the Update OpenRouter Pricing workflow regenerates daily from OpenRouter's
# published ``reasoning.supported_efforts``. The family rules further down are
# only a fallback for models that file does not list: Gemini 2.5, whose thinking
# is budget-based rather than effort-based, and spellings OpenRouter does not
# carry. Anything neither source knows returns ``None`` and is not validated, so
# a brand new model works before either list catches up.
# ---------------------------------------------------------------------------

_PUBLISHED_EFFORTS_FILE = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "config", "thinking_effort.yaml"
)
# A trailing release date or revision (claude-opus-4-5-20251101, ...-v1) is not
# part of how the published table names a model.
_MODEL_REVISION_RE = re.compile(r"-(?:v\d+|\d{6,})$")

_published_efforts_cache: dict[str, frozenset[str]] | None = None


def _load_published_efforts() -> dict[str, frozenset[str]]:
    try:
        with open(_PUBLISHED_EFFORTS_FILE, "r", encoding="utf-8") as handle:
            raw = yaml.safe_load(handle) or {}
    except (OSError, yaml.YAMLError) as exc:
        _LOGGER.warning("Could not read %s: %s", _PUBLISHED_EFFORTS_FILE, exc)
        return {}
    models = raw.get("models") if isinstance(raw, dict) else None
    if not isinstance(models, dict):
        return {}
    table: dict[str, frozenset[str]] = {}
    for model, levels in models.items():
        if not isinstance(levels, list):
            continue
        known = frozenset(
            str(level).strip().lower() for level in levels
        ) & THINKING_EFFORT_LEVELS
        if known:
            table[str(model).strip().lower()] = known
    return table


def published_thinking_efforts() -> dict[str, frozenset[str]]:
    """The generated model -> levels table, read once and cached."""
    global _published_efforts_cache
    if _published_efforts_cache is None:
        _published_efforts_cache = _load_published_efforts()
    return _published_efforts_cache


# Models with no reasoning control at all still accept ``high``: every provider
# defines it as "behave exactly as if the parameter was never sent", which is
# what the repo-wide default means.
_NO_EFFORT_CONTROL = frozenset({"high"})

_ANTHROPIC_FULL = frozenset({"low", "medium", "high", "xhigh", "max"})
_ANTHROPIC_NO_XHIGH = frozenset({"low", "medium", "high", "max"})
_ANTHROPIC_NO_MAX = frozenset({"low", "medium", "high"})

_OPENAI_MINIMAL = frozenset({"minimal", "low", "medium", "high"})
_OPENAI_NONE = frozenset({"none", "low", "medium", "high"})
_OPENAI_XHIGH = frozenset({"none", "low", "medium", "high", "xhigh"})
_OPENAI_MAX = frozenset({"none", "low", "medium", "high", "xhigh", "max"})
_OPENAI_O_SERIES = frozenset({"low", "medium", "high"})

# Gemini 2.5 takes a token budget, so every level maps to a distinct budget.
# Only Pro is excluded from ``none``: it cannot turn thinking off.
_GEMINI_25_PRO = frozenset({"minimal", "low", "medium", "high", "xhigh", "max"})
_GEMINI_25_FLASH = THINKING_EFFORT_LEVELS
# Gemini 3 takes a thinkingLevel enum, which tops out at HIGH.
_GEMINI_3_PRO = frozenset({"low", "high"})
_GEMINI_31_PRO = frozenset({"low", "medium", "high"})
_GEMINI_3_FLASH = frozenset({"minimal", "low", "medium", "high"})

_VENDOR_PREFIX_RE = re.compile(
    r"^(?:[a-z]{2,6}\.)?(?:anthropic|google|openai|meta|mistralai)\."
)
_CLAUDE_RE = re.compile(r"^claude-(opus|sonnet|haiku|fable|mythos)-(\d+)(?:[.-](\d+))?")
_CLAUDE_LEGACY_RE = re.compile(r"^claude-(?:instant|\d)")
_GPT_RE = re.compile(r"^gpt-(\d+)(?:[.-](\d+))?")
_O_SERIES_RE = re.compile(r"^o[1-9]\d*(?:[.-]|$)")
_GEMINI_RE = re.compile(r"^gemini-(\d+)(?:[.-](\d+))?-(pro|flash-lite|flash)")


def _model_key(model_name: Any) -> str:
    """Reduce a configured model name to a bare, comparable model id.

    Handles the shapes this repo can produce: OpenRouter ``openrouter/<vendor>/
    <model>`` paths, Bedrock/Vertex ``us.anthropic.<model>-v1:0`` ids, and the
    dotted Copilot spellings (``claude-sonnet-4.6``). Version separators are
    folded to ``-`` last, so every spelling of one model lands on one key.
    """
    raw = str(model_name or "").strip().lower()
    if not raw:
        return ""
    raw = raw.split(":", 1)[0]
    if raw.startswith("openrouter/"):
        raw = raw[len("openrouter/") :]
    if "/" in raw:
        raw = raw.rsplit("/", 1)[-1]
    return _VENDOR_PREFIX_RE.sub("", raw).strip().replace(".", "-")


def _anthropic_levels(key: str) -> frozenset[str] | None:
    if not key.startswith("claude"):
        return None
    if key.startswith("claude-mythos-preview"):
        return _ANTHROPIC_NO_XHIGH
    match = _CLAUDE_RE.match(key)
    if not match:
        # claude-3-5-sonnet and older never had an effort parameter.
        return _NO_EFFORT_CONTROL if _CLAUDE_LEGACY_RE.match(key) else None
    family = match.group(1)
    version = (int(match.group(2)), int(match.group(3) or 0))
    if family in {"fable", "mythos"}:
        return _ANTHROPIC_FULL if version >= (5, 0) else None
    if family == "haiku":
        # No Haiku exposes effort yet; leave later ones to a future update.
        return _NO_EFFORT_CONTROL if version < (5, 0) else None
    if family == "opus":
        if version >= (4, 7):
            return _ANTHROPIC_FULL
        if version == (4, 6):
            return _ANTHROPIC_NO_XHIGH
        if version == (4, 5):
            return _ANTHROPIC_NO_MAX
        return _NO_EFFORT_CONTROL
    if family == "sonnet":
        if version >= (5, 0):
            return _ANTHROPIC_FULL
        if version == (4, 6):
            return _ANTHROPIC_NO_XHIGH
        return _NO_EFFORT_CONTROL
    return None


def _openai_levels(key: str) -> frozenset[str] | None:
    if _O_SERIES_RE.match(key):
        return _OPENAI_O_SERIES
    match = _GPT_RE.match(key)
    if not match:
        return None
    major = int(match.group(1))
    minor = int(match.group(2) or 0)
    if major < 5:
        return _NO_EFFORT_CONTROL
    if major > 5:
        return None
    if minor >= 6:
        return _OPENAI_MAX
    if minor >= 2:
        return _OPENAI_XHIGH
    if minor == 1:
        return _OPENAI_NONE
    # GPT-5.0 is the only family that kept ``minimal`` instead of ``none``.
    return _OPENAI_MINIMAL


def _gemini_levels(key: str) -> frozenset[str] | None:
    match = _GEMINI_RE.match(key)
    if not match:
        return None
    version = (int(match.group(1)), int(match.group(2) or 0))
    tier = match.group(3)
    if version < (2, 5):
        return _NO_EFFORT_CONTROL
    if version < (3, 0):
        return _GEMINI_25_PRO if tier == "pro" else _GEMINI_25_FLASH
    if version >= (4, 0):
        return None
    if tier == "pro":
        return _GEMINI_3_PRO if version == (3, 0) else _GEMINI_31_PRO
    return _GEMINI_3_FLASH


def supported_thinking_efforts(model_name: Any) -> frozenset[str] | None:
    """Return the effort levels ``model_name`` accepts, or None if unknown.

    The generated table wins over the family rules: it is refreshed daily, so it
    knows about models released after this code was written.
    """
    key = _model_key(model_name)
    if not key:
        return None
    published = published_thinking_efforts()
    for candidate in (key, _MODEL_REVISION_RE.sub("", key)):
        levels = published.get(candidate)
        if levels:
            return levels
    for resolver in (_anthropic_levels, _openai_levels, _gemini_levels):
        levels = resolver(key)
        if levels is not None:
            return levels
    return None


_stepped_down_models: set[str] = set()


def validate_thinking_effort(
    value: Any,
    *,
    model: Any = "",
    setting: str = "thinking_effort",
) -> str:
    """Resolve ``value`` against the levels the selected model accepts.

    Returns the level to actually use. An explicitly chosen level that the model
    does not implement raises, because silently running at some other level is
    what this whole check exists to prevent. The one exception is the default
    ``high``: a handful of models do not offer it, and refusing to start over a
    level the user never chose would be hostile, so that steps down to the
    strongest level the model does offer and says so.
    """
    effort = normalize_thinking_effort(value)
    supported = supported_thinking_efforts(model)
    if supported is None or effort in supported:
        return effort
    model_label = str(model or "").strip()
    if effort == DEFAULT_THINKING_EFFORT:
        nearest = max(supported, key=THINKING_EFFORT_ORDER.index)
        # Every role that inherits the primary model hits this, so say it once.
        if model_label.lower() not in _stepped_down_models:
            _stepped_down_models.add(model_label.lower())
            _LOGGER.warning(
                "Model %s does not offer the default %s thinking effort; "
                "using %s instead. Set %s explicitly to choose another level.",
                model_label,
                DEFAULT_THINKING_EFFORT,
                nearest,
                setting,
            )
        return nearest
    if supported == _NO_EFFORT_CONTROL:
        raise ValueError(
            f"{setting}={effort!r} is not valid for model {model_label!r}: this model "
            f"has no configurable thinking effort, so only the default "
            f"{DEFAULT_THINKING_EFFORT!r} applies."
        )
    allowed = ", ".join(
        level for level in THINKING_EFFORT_ORDER if level in supported
    )
    raise ValueError(
        f"{setting}={effort!r} is not supported by model {model_label!r}. "
        f"Supported values for this model: {allowed}"
    )
