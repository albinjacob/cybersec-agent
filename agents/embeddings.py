"""
Embeddings wrapper for Policy Checker's RAG retrieval.

Design mirrors agents/llm.py: configure(provider, api_key, model) sets a BYOK
override from the UI; auto-detects from the environment otherwise. Three
providers:

  - "local": sentence-transformers running fully offline on CPU, no API key,
    no separate server process (unlike Ollama, it's a plain Python library -
    model weights download once from Hugging Face Hub, then everything runs
    in-process). This is the default when nothing else is configured, since
    it works with zero setup - the same reasoning agents/llm.py falls back
    to a deterministic mock reasoner rather than requiring a key. It's also
    the heaviest to install (pulls in PyTorch), so it's the wrong choice for
    a lean cloud deploy - see "openrouter" below.
  - "openai": OpenAI's real embeddings API (text-embedding-3-small/large).
  - "openrouter": the same OpenAI-compatible embeddings request, routed
    through OpenRouter's unified endpoint. Lets a deploy that already has
    OPENROUTER_API_KEY configured for LLM reasoning (agents/llm.py) get real
    semantic embeddings too, with no extra key and no PyTorch install -
    the natural choice for a resource-constrained host like Render's free
    tier, where "local" risks an out-of-memory crash and no OPENAI_API_KEY
    may be set.

Unlike agents/llm.py there is no "mock" tier here - "local" already runs at
zero cost and zero configuration, so it doubles as the always-available
default rather than a last-resort fallback. embed() raises on failure
(missing dependency, bad key, network error); the caller
(agents/policy_checker.py) decides what to do next - its own fallback is
the original TF-IDF path, not a second embeddings tier.
"""

import os

DEFAULT_MODELS = {
    "local": "all-MiniLM-L6-v2",
    "openai": "text-embedding-3-small",
    "openrouter": "openai/text-embedding-3-small",
}

OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY")
OPENROUTER_API_KEY = os.environ.get("OPENROUTER_API_KEY")

# BYOK overrides set via configure(); None means "auto" (see current_provider_and_model)
_RUNTIME = {"provider": None, "api_key": None, "model": None}

_local_model_cache = {}  # model name -> loaded SentenceTransformer instance, cached in-process


def configure(provider=None, api_key=None, model=None):
    """
    Set BYOK overrides from the UI. provider is one of
    "local" / "openai" / "openrouter" / "auto" (or None, same as "auto").
    Passing provider="auto" (or None) clears overrides and reverts to
    environment-based auto-detection.
    """
    if not provider or provider == "auto":
        _RUNTIME["provider"] = None
        _RUNTIME["api_key"] = None
        _RUNTIME["model"] = None
        return
    _RUNTIME["provider"] = provider
    _RUNTIME["api_key"] = api_key or None
    _RUNTIME["model"] = model or None


def current_provider_and_model():
    """What embed() will actually use right now, without calling it - used by
    the UI to show current status and to validate a cache against the live
    config before trusting it. Auto-detect priority mirrors agents/llm.py:
    a native provider (OpenAI) before the OpenRouter proxy, before the
    always-available local fallback."""
    if _RUNTIME["provider"]:
        return _RUNTIME["provider"], _RUNTIME["model"] or DEFAULT_MODELS.get(_RUNTIME["provider"])
    if OPENAI_API_KEY:
        return "openai", DEFAULT_MODELS["openai"]
    if OPENROUTER_API_KEY:
        return "openrouter", DEFAULT_MODELS["openrouter"]
    return "local", DEFAULT_MODELS["local"]


def _get_local_model(model_name):
    if model_name not in _local_model_cache:
        from sentence_transformers import SentenceTransformer
        _local_model_cache[model_name] = SentenceTransformer(model_name)
    return _local_model_cache[model_name]


def _embed_local(texts, model_name):
    model = _get_local_model(model_name)
    vectors = model.encode(list(texts), show_progress_bar=False, convert_to_numpy=True)
    return [v.tolist() for v in vectors]


def _embed_openai(texts, api_key, model_name):
    import requests
    resp = requests.post(
        "https://api.openai.com/v1/embeddings",
        headers={"Authorization": f"Bearer {api_key}", "content-type": "application/json"},
        json={"model": model_name, "input": list(texts)},
        timeout=60,
    )
    resp.raise_for_status()
    data = resp.json()["data"]
    ordered = sorted(data, key=lambda d: d["index"])  # API preserves order, but be explicit
    return [d["embedding"] for d in ordered]


def _embed_openrouter(texts, api_key, model_name):
    # Same OpenAI-compatible shape as _embed_openai, routed through
    # OpenRouter's unified endpoint - lets a deploy with only an
    # OPENROUTER_API_KEY (the key already used for LLM reasoning) get real
    # embeddings without a separate OpenAI key or the heavy local model.
    import requests
    resp = requests.post(
        "https://openrouter.ai/api/v1/embeddings",
        headers={"Authorization": f"Bearer {api_key}", "content-type": "application/json"},
        json={"model": model_name, "input": list(texts)},
        timeout=60,
    )
    resp.raise_for_status()
    data = resp.json()["data"]
    ordered = sorted(data, key=lambda d: d.get("index", 0))
    return [d["embedding"] for d in ordered]


_API_EMBEDDERS = {
    "openai": (_embed_openai, lambda: OPENAI_API_KEY, "No OpenAI API key configured for embeddings"),
    "openrouter": (_embed_openrouter, lambda: OPENROUTER_API_KEY, "No OpenRouter API key configured for embeddings"),
}


def embed(texts):
    """
    Embed a list of strings (or a single string). Returns
    (vectors, provider, model) - vectors is a list of float lists, one per
    input text, same order as the input. Raises on failure; callers decide
    their own fallback.
    """
    single = isinstance(texts, str)
    text_list = [texts] if single else list(texts)

    provider, model = current_provider_and_model()
    if provider in _API_EMBEDDERS:
        caller, env_key_fn, missing_msg = _API_EMBEDDERS[provider]
        api_key = _RUNTIME["api_key"] or env_key_fn()
        if not api_key:
            raise RuntimeError(missing_msg)
        vectors = caller(text_list, api_key, model)
    else:
        vectors = _embed_local(text_list, model)

    return vectors, provider, model
