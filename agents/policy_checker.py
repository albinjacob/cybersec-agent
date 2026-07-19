"""
Policy Checker Agent
--------------------
RAG over a policy corpus - the full NIST SP 800-53 Rev 5 control catalog
(data/knowledgebase/nist_800_53_catalog.json, ~1,014 controls + enhancements, sourced by
scripts/fetch_nist_catalog.py) plus a condensed ISO 27001/SOC2 excerpt
(data/testing/quick_demo/policy_excerpt.md) - using real semantic embeddings
(agents/embeddings.py: local sentence-transformers by default, or a hosted
API via BYOK). For each finding, retrieves the most relevant policy
control(s) and flags them as compliance gaps.

Embeddings are precomputed and cached to disk (data/knowledgebase/policy_index_meta.json +
data/knowledgebase/policy_index_vectors.npy) rather than recomputed every run - NIST
revises 800-53 roughly once every several years, so re-embedding ~1,000
chunks on every pipeline execution would be pure waste. The cache is
rebuilt only via the UI's "Rebuild Index" button (agents/policy_checker.py's
rebuild_index()), and the loader validates the cache against the currently
configured embedding provider/model before trusting it - a mismatch (or no
cache at all) falls back to the original TF-IDF path over the small
excerpt, with `embedding_mode`/`embedding_fallback_reason` on the returned
dict recording which path ran and why, same pattern as scan_mode/feed_mode.
"""

import hashlib
import json
import logging
import os
import re
from datetime import datetime, timezone

import numpy as np
import requests
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

from . import embeddings
from .llm import UNTRUSTED_DATA_NOTE, fence_untrusted, reason

log = logging.getLogger(__name__)

NIST_CATALOG_PATH = "data/knowledgebase/nist_800_53_catalog.json"
DEFAULT_POLICY_PATH = "data/testing/quick_demo/policy_excerpt.md"

# One cache pair PER embedding provider, not one shared pair - a dev machine
# (typically "local", no key) and a deployment (typically "openrouter", one
# shared key) are expected to run with genuinely different active providers
# at the same time. A single shared cache file could only ever match one of
# them, permanently flagging the other as "rebuild needed". Keying the
# filename by provider lets both live in the repo simultaneously, each valid
# for its own environment.
CACHE_META_PATH_TMPL = "data/knowledgebase/policy_index_meta.{provider}.json"
CACHE_VECTORS_PATH_TMPL = "data/knowledgebase/policy_index_vectors.{provider}.npy"


def _cache_paths(provider):
    return CACHE_META_PATH_TMPL.format(provider=provider), CACHE_VECTORS_PATH_TMPL.format(provider=provider)

# Real embedding cosine similarities run higher than TF-IDF's for genuinely
# related text, so the "is this a real match" bar is raised accordingly.
# Empirically calibrated against this corpus: unrelated text tops out
# around 0.17, genuine (if imperfectly worded) matches start around 0.24.
EMBEDDING_MIN_SCORE = 0.25
TFIDF_MIN_SCORE = 0.05


def load_policy_chunks(path: str):
    with open(path, encoding="utf-8", errors="replace") as f:
        content = f.read()
    # split on markdown headers (## ...) - each header + body is one chunk
    parts = re.split(r"(?=^## )", content, flags=re.MULTILINE)
    chunks = [p.strip() for p in parts if p.strip() and not p.strip().startswith("# Mini Policy")]
    return chunks


class PolicyIndex:
    """TF-IDF fallback - used when no embedding index is cached/compatible."""

    def __init__(self, chunks):
        self.chunks = chunks
        self.vectorizer = TfidfVectorizer(stop_words="english")
        self.matrix = self.vectorizer.fit_transform(chunks)

    def retrieve(self, query: str, top_k: int = 1, min_score: float = TFIDF_MIN_SCORE):
        q_vec = self.vectorizer.transform([query])
        sims = cosine_similarity(q_vec, self.matrix)[0]
        ranked = sorted(range(len(sims)), key=lambda i: -sims[i])
        results = []
        for i in ranked[:top_k]:
            if sims[i] >= min_score:
                # third element mirrors EmbeddingPolicyIndex's (chunk, score,
                # source) shape so run() doesn't have to branch on index type
                results.append((self.chunks[i], float(sims[i]), "policy_excerpt"))
        return results


class EmbeddingPolicyIndex:
    """Real semantic search over the cached vectors - same retrieve()
    interface/return shape as PolicyIndex so run() barely needs to branch.

    `extra_chunks` lets a caller append chunks that aren't in the prebuilt
    cache - specifically a policy document the user uploaded this run. Those
    get embedded on the fly (a handful of chunks, cheap) and stacked onto the
    cached matrix, so the user's own controls compete with NIST's on equal
    footing instead of being silently ignored."""

    def __init__(self, meta, vectors, extra_chunks=None):
        self.chunks = list(meta["chunks"])
        self.vectors = vectors
        if extra_chunks:
            extra_vectors, _, _ = embeddings.embed([c["text"] for c in extra_chunks])
            self.chunks += list(extra_chunks)
            self.vectors = np.vstack([vectors, np.array(extra_vectors, dtype=np.float32)])

    def retrieve(self, query: str, top_k: int = 1, min_score: float = EMBEDDING_MIN_SCORE):
        query_vec, _, _ = embeddings.embed(query)
        sims = cosine_similarity(np.array(query_vec), self.vectors)[0]
        ranked = sorted(range(len(sims)), key=lambda i: -sims[i])
        results = []
        for i in ranked[:top_k]:
            if sims[i] >= min_score:
                results.append((self.chunks[i]["text"], float(sims[i]), self.chunks[i].get("source")))
        return results


def _build_nist_chunks():
    if not os.path.exists(NIST_CATALOG_PATH):
        return []
    with open(NIST_CATALOG_PATH, encoding="utf-8") as f:
        catalog = json.load(f)
    chunks = []
    for c in catalog:
        title = f"NIST SP 800-53 - {c['control_id']}: {c['title']}"
        chunks.append({
            "id": f"nist-{c['control_id'].lower()}",
            "source": "nist_800_53",
            "title": title,
            "text": f"## {title}\n{c['statement']}",
        })
    return chunks


def _build_excerpt_chunks(path=DEFAULT_POLICY_PATH, source="policy_excerpt", id_prefix="excerpt"):
    chunks = []
    for i, raw in enumerate(load_policy_chunks(path)):
        title = raw.splitlines()[0].replace("## ", "").strip() or f"Clause {i + 1}"
        chunks.append({"id": f"{id_prefix}-{i}", "source": source, "title": title, "text": raw})
    return chunks


def build_all_chunks():
    """The full corpus this agent searches: comprehensive NIST 800-53 plus
    the condensed ISO 27001/SOC2 excerpt (ISO's real text is copyrighted,
    so it stays paraphrased/condensed rather than a full catalog for now)."""
    return _build_nist_chunks() + _build_excerpt_chunks()


def _corpus_hash(chunks):
    combined = "".join(c["text"] for c in chunks)
    return hashlib.sha256(combined.encode("utf-8")).hexdigest()


def rebuild_index():
    """Re-embeds the full policy corpus with whatever embedding
    provider/model is currently configured (agents/embeddings.py) and
    writes the result to its provider-specific cache file on disk.
    Deliberately manual/rare - triggered by the UI's Rebuild Index button,
    never called automatically during a pipeline run."""
    chunks = build_all_chunks()
    texts = [c["text"] for c in chunks]
    vectors, provider, model = embeddings.embed(texts)

    meta = {
        "corpus_hash": _corpus_hash(chunks),
        "embedding_provider": provider,
        "embedding_model": model,
        "built_at": datetime.now(timezone.utc).isoformat(),
        "chunk_count": len(chunks),
        "chunks": [{"id": c["id"], "source": c["source"], "title": c["title"], "text": c["text"]} for c in chunks],
    }
    meta_path, vectors_path = _cache_paths(provider)
    with open(meta_path, "w", encoding="utf-8") as f:
        json.dump(meta, f, indent=2)
    np.save(vectors_path, np.array(vectors, dtype=np.float32))
    return meta


def _load_cached_index(provider):
    """Returns (meta, vectors) for THIS provider's cache file, or
    (None, None) if missing/unreadable - each provider has its own cache
    pair, so a dev machine on "local" and a deployment on "openrouter" each
    read their own valid, never-mismatched file."""
    meta_path, vectors_path = _cache_paths(provider)
    if not (os.path.exists(meta_path) and os.path.exists(vectors_path)):
        return None, None
    try:
        with open(meta_path, encoding="utf-8") as f:
            meta = json.load(f)
        vectors = np.load(vectors_path)
        return meta, vectors
    except Exception:
        return None, None


def index_status():
    """For the UI's Policy Index admin panel: what's cached right now for
    the CURRENTLY configured provider, and whether it's stale/incompatible
    with the currently configured model."""
    current_provider, current_model = embeddings.current_provider_and_model()
    meta, _ = _load_cached_index(current_provider)
    if meta is None:
        return {
            "exists": False,
            "current_provider": current_provider,
            "current_model": current_model,
        }
    current_hash = _corpus_hash(build_all_chunks())
    return {
        "exists": True,
        "chunk_count": meta["chunk_count"],
        "embedding_provider": meta["embedding_provider"],
        "embedding_model": meta["embedding_model"],
        "built_at": meta["built_at"],
        "corpus_stale": meta["corpus_hash"] != current_hash,
        # Provider can never mismatch now (the cache file IS the provider's own),
        # but the model name within that provider still can (e.g. a future model
        # upgrade for the same provider) - keep the check for that case.
        "model_mismatch": meta["embedding_model"] != current_model,
        "current_provider": current_provider,
        "current_model": current_model,
    }


def _is_user_supplied_policy(policy_path):
    """True when the caller passed a policy doc that ISN'T our bundled excerpt
    (which is already baked into the cached index)."""
    if not policy_path or not os.path.exists(policy_path):
        return False
    try:
        return os.path.abspath(policy_path) != os.path.abspath(DEFAULT_POLICY_PATH)
    except Exception:
        return False


def _local_embeddings_available():
    """Cheap check for whether sentence-transformers is actually importable -
    it's an optional dependency (large, offline-only), so a cache built with
    provider="local" can be config-valid but still unusable in an environment
    that never installed it (e.g. a lean deploy)."""
    try:
        import sentence_transformers  # noqa: F401
        return True
    except ImportError:
        return False


def _get_index(policy_path):
    """Returns (index, embedding_mode, fallback_reason)."""
    current_provider, current_model = embeddings.current_provider_and_model()
    meta, vectors = _load_cached_index(current_provider)
    if meta is not None and vectors is not None:
        if meta["embedding_model"] == current_model:
            if current_provider == "local" and not _local_embeddings_available():
                return (
                    PolicyIndex(load_policy_chunks(policy_path)), "tfidf-fallback",
                    "sentence-transformers not installed - using keyword-based matching "
                    "over the small excerpt instead.",
                )
            # A user-uploaded policy isn't in the prebuilt cache; embed it now
            # and search it alongside NIST rather than ignoring it.
            extra = None
            if _is_user_supplied_policy(policy_path):
                extra = _build_excerpt_chunks(policy_path, source="user_policy", id_prefix="user")
            return EmbeddingPolicyIndex(meta, vectors, extra_chunks=extra), "embeddings", None
        reason_text = (
            f"Cached {current_provider} index was built with model {meta['embedding_model']}, "
            f"but {current_model} is configured now - rebuild the index to use it."
        )
    else:
        reason_text = (
            f"No embedding index built yet for provider '{current_provider}' - using keyword-based "
            "matching over the small excerpt instead."
        )

    return PolicyIndex(load_policy_chunks(policy_path)), "tfidf-fallback", reason_text


def _mock_summary(gaps):
    if not gaps:
        return "No clear compliance gaps identified against the loaded policy excerpts."
    lines = ["Policy Checker Agent - compliance gaps:"]
    for g in gaps:
        header = g["policy_chunk"].splitlines()[0].replace("## ", "")
        lines.append(f"- Finding: {g['finding']}\n  -> Maps to: {header} (similarity {g['score']:.2f})")
    return "\n".join(lines)


def _retrieve_all(index, all_findings, min_score):
    gaps = []
    for f in all_findings:
        query = f.get("detail", "")
        results = index.retrieve(query, top_k=1, min_score=min_score)
        for chunk, score, source in results:
            gaps.append({
                "finding": query,
                "policy_chunk": chunk,
                "score": score,
                "source": source,
            })
    return gaps


def run(policy_path: str, all_findings, llm_config: dict | None = None):
    # embeddings.embed() raises on failure (missing dependency, bad key,
    # network error) by design - this is the safety net that turns that into
    # a graceful TF-IDF fallback instead of crashing the whole pipeline node.
    # Covers both index construction (_get_index() may itself call embed() to
    # embed a user-supplied policy doc) and per-query retrieval. Deliberately
    # NARROW: only the failure classes embed() genuinely produces (missing
    # key/dependency, network/API errors). A genuine bug in retrieval code
    # should crash loudly into the app-level handler, not masquerade as
    # "embedding failed".
    try:
        index, embedding_mode, embedding_fallback_reason = _get_index(policy_path)
        min_score = EMBEDDING_MIN_SCORE if embedding_mode == "embeddings" else TFIDF_MIN_SCORE
        gaps = _retrieve_all(index, all_findings, min_score)
    except (RuntimeError, ImportError, OSError, requests.RequestException) as e:
        embedding_mode = "tfidf-fallback"
        embedding_fallback_reason = f"Embedding failed ({e}) - falling back to keyword search."
        log.warning("Policy retrieval fell back to TF-IDF: %s", e)
        index = PolicyIndex(load_policy_chunks(policy_path))
        gaps = _retrieve_all(index, all_findings, TFIDF_MIN_SCORE)

    system_prompt = (
        "You are a compliance analyst. Given security findings mapped to policy "
        "clauses (NIST 800-53 / ISO 27001 / SOC2), summarize which controls are "
        "not being met and what evidence would be needed to close each gap."
        + UNTRUSTED_DATA_NOTE
    )
    # Selected fields only: the full policy_chunk text (up to a whole NIST
    # control statement per gap) is the single biggest token sink in the
    # pipeline - the control's title line + match score carries what the
    # narrative needs.
    compact = [{"finding": g["finding"],
                "control": g["policy_chunk"].splitlines()[0].replace("## ", ""),
                "score": round(g["score"], 2)} for g in gaps]
    user_prompt = fence_untrusted(json.dumps(compact, indent=1), tag="mapped_gaps")
    summary, mode, reasoning_fallback_reason = reason(system_prompt, user_prompt,
                                                      mock_fn=lambda: _mock_summary(gaps),
                                                      config=llm_config)
    # Only meaningful when embeddings actually ran - a tfidf-fallback run didn't
    # use this provider at all, so recording it there would misrepresent what
    # actually happened this request.
    embedding_provider, embedding_model = (
        embeddings.current_provider_and_model() if embedding_mode == "embeddings" else (None, None)
    )
    return {
        "agent": "policy_checker",
        "gaps": gaps,
        "summary": summary,
        "reasoning_mode": mode,
        "reasoning_fallback_reason": reasoning_fallback_reason,
        "embedding_mode": embedding_mode,
        "embedding_fallback_reason": embedding_fallback_reason,
        "embedding_provider": embedding_provider,
        "embedding_model": embedding_model,
    }
