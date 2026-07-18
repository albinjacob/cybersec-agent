"""
LLM wrapper shared by all agents.

Design: every agent calls `reason(system_prompt, user_prompt)` instead of
hitting an API directly. This function:

  1. Uses whatever provider/key/model is set via `configure(...)` (BYOK from
     the Gradio UI), if any.
  2. Else auto-detects from environment variables, in order: ANTHROPIC_API_KEY,
     then OPENAI_API_KEY, then OPENROUTER_API_KEY.
  3. Else falls back to a deterministic, rule-based "mock reasoner" so the
     whole pipeline still runs end-to-end with no key and no network.

BYOK: `configure(provider, api_key, model)` lets the UI override the
environment-derived defaults per session, e.g. a judge pastes their own
OpenRouter key and picks a model from the live OpenRouter catalog
(`list_openrouter_models()`) without touching any agent code.
"""

import os
import json
import time

from dotenv import load_dotenv
load_dotenv()

ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY")
OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY")
OPENROUTER_API_KEY = os.environ.get("OPENROUTER_API_KEY")
MODEL_MODE = None  # set on first call, for reporting
LAST_FALLBACK_REASON = None  # human-readable reason for the most recent mock fallback, if any


def get_last_fallback_reason():
    """Call right after reason() when its mode == 'mock' to get why it fell back."""
    return LAST_FALLBACK_REASON

DEFAULT_MODELS = {
    "anthropic": "claude-sonnet-5",
    "openai": "gpt-4o-mini",
    "openrouter": "openai/gpt-4o-mini",
}

# BYOK overrides set via configure(); None means "fall back to env auto-detect"
_RUNTIME = {"provider": None, "api_key": None, "model": None}

_openrouter_models_cache = {"data": None, "fetched_at": 0}


def configure(provider=None, api_key=None, model=None):
    """
    Set BYOK overrides from the UI. provider is one of
    "anthropic" / "openai" / "openrouter" / "auto" (or None, same as "auto").
    Passing provider="auto" (or None) clears overrides and reverts to
    environment-variable auto-detection.
    """
    if not provider or provider == "auto":
        _RUNTIME["provider"] = None
        _RUNTIME["api_key"] = None
        _RUNTIME["model"] = None
        return
    _RUNTIME["provider"] = provider
    _RUNTIME["api_key"] = api_key or None
    _RUNTIME["model"] = model or None


def list_openrouter_models(force_refresh=False):
    """
    Fetch the live OpenRouter model catalog (public endpoint, no key needed).
    Cached in-process for 10 minutes. Returns a list of model id strings,
    e.g. "anthropic/claude-sonnet-5", "openai/gpt-4o-mini", sorted alphabetically.
    Falls back to a short hardcoded list if the request fails (e.g. offline).
    """
    now = time.time()
    if not force_refresh and _openrouter_models_cache["data"] and now - _openrouter_models_cache["fetched_at"] < 600:
        return _openrouter_models_cache["data"]

    fallback = [
        "anthropic/claude-sonnet-5",
        "anthropic/claude-opus-4.8",
        "anthropic/claude-haiku-4.5",
        "openai/gpt-4o",
        "openai/gpt-4o-mini",
        "google/gemini-2.5-pro",
        "meta-llama/llama-3.3-70b-instruct",
        "mistralai/mistral-large",
        "deepseek/deepseek-chat",
    ]
    try:
        import requests
        resp = requests.get("https://openrouter.ai/api/v1/models", timeout=10)
        resp.raise_for_status()
        ids = sorted(m["id"] for m in resp.json().get("data", []) if m.get("id"))
        if ids:
            _openrouter_models_cache["data"] = ids
            _openrouter_models_cache["fetched_at"] = now
            return ids
    except Exception:
        pass
    return fallback


def _call_anthropic(system_prompt: str, user_prompt: str, api_key: str, model: str) -> str:
    import requests
    resp = requests.post(
        "https://api.anthropic.com/v1/messages",
        headers={
            "x-api-key": api_key,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        },
        json={
            "model": model,
            "max_tokens": 1024,
            "system": system_prompt,
            "messages": [{"role": "user", "content": user_prompt}],
        },
        timeout=30,
    )
    resp.raise_for_status()
    data = resp.json()
    return "".join(block.get("text", "") for block in data.get("content", []))


def _call_openai(system_prompt: str, user_prompt: str, api_key: str, model: str) -> str:
    import requests
    resp = requests.post(
        "https://api.openai.com/v1/chat/completions",
        headers={
            "Authorization": f"Bearer {api_key}",
            "content-type": "application/json",
        },
        json={
            "model": model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
        },
        timeout=30,
    )
    resp.raise_for_status()
    data = resp.json()
    return data["choices"][0]["message"]["content"]


def _call_openrouter(system_prompt: str, user_prompt: str, api_key: str, model: str) -> str:
    import requests
    resp = requests.post(
        "https://openrouter.ai/api/v1/chat/completions",
        headers={
            "Authorization": f"Bearer {api_key}",
            "content-type": "application/json",
        },
        json={
            "model": model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
        },
        timeout=30,
    )
    resp.raise_for_status()
    data = resp.json()
    return data["choices"][0]["message"]["content"]


_CALLERS = {
    "anthropic": _call_anthropic,
    "openai": _call_openai,
    "openrouter": _call_openrouter,
}


def reason(system_prompt: str, user_prompt: str, mock_fn=None):
    """
    Returns (text, mode) where mode is 'live-anthropic', 'live-openai',
    'live-openrouter', or 'mock'.
    `mock_fn` is a zero-arg callable each agent supplies to produce a
    deterministic, structured fallback answer specific to that agent's task.
    On a 'mock' result, call get_last_fallback_reason() for a human-readable
    reason why (no key configured, or the specific error the API returned).
    """
    global MODEL_MODE, LAST_FALLBACK_REASON
    LAST_FALLBACK_REASON = None

    # 1. Explicit BYOK override from the UI takes priority, and does NOT fall
    #    through to other providers on failure (a user selecting a bad key
    #    should see that fail, not silently get another provider's answer).
    if _RUNTIME["provider"]:
        provider = _RUNTIME["provider"]
        api_key = _RUNTIME["api_key"] or {
            "anthropic": ANTHROPIC_API_KEY,
            "openai": OPENAI_API_KEY,
            "openrouter": OPENROUTER_API_KEY,
        }.get(provider)
        model = _RUNTIME["model"] or DEFAULT_MODELS.get(provider)
        if api_key:
            try:
                text = _CALLERS[provider](system_prompt, user_prompt, api_key, model)
                MODEL_MODE = f"live-{provider}"
                return text, MODEL_MODE
            except Exception as e:
                LAST_FALLBACK_REASON = f"{provider} ({model}) call failed: {e}"
        else:
            LAST_FALLBACK_REASON = f"No API key provided for {provider}"
        MODEL_MODE = "mock"
        if mock_fn is not None:
            return mock_fn(), "mock"
        return "[no reasoning available - BYOK provider failed and no mock_fn provided]", "mock"

    # 2. Auto-detect from environment variables, in priority order.
    attempted = False
    last_error = None
    for provider, key in (
        ("anthropic", ANTHROPIC_API_KEY),
        ("openai", OPENAI_API_KEY),
        ("openrouter", OPENROUTER_API_KEY),
    ):
        if not key:
            continue
        attempted = True
        try:
            text = _CALLERS[provider](system_prompt, user_prompt, key, DEFAULT_MODELS[provider])
            MODEL_MODE = f"live-{provider}"
            return text, MODEL_MODE
        except Exception as e:
            last_error = f"{provider} ({DEFAULT_MODELS[provider]}) call failed: {e}"
            continue  # fall through to next provider

    # 3. Mock fallback.
    MODEL_MODE = "mock"
    LAST_FALLBACK_REASON = last_error if attempted else (
        "No ANTHROPIC_API_KEY / OPENAI_API_KEY / OPENROUTER_API_KEY configured"
    )
    if mock_fn is not None:
        return mock_fn(), "mock"
    return "[no reasoning available - no API key and no mock_fn provided]", "mock"
