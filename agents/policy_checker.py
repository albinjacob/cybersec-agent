"""
Policy Checker Agent
--------------------
RAG over a policy corpus - the full NIST SP 800-53 Rev 5 control catalog
(data/nist_800_53_catalog.json, ~1,014 controls + enhancements, sourced by
scripts/fetch_nist_catalog.py) plus a condensed ISO 27001/SOC2 excerpt
(data/policy_excerpt.md) - using real semantic embeddings
(agents/embeddings.py: local sentence-transformers by default, or a hosted
API via BYOK). For each finding, retrieves the most relevant policy
control(s) and flags them as compliance gaps.

Embeddings are precomputed and cached to disk (data/policy_index_meta.json +
data/policy_index_vectors.npy) rather than recomputed every run - NIST
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
import os
import re
from datetime import datetime, timezone

import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

from . import embeddings
from .llm import reason, get_last_fallback_reason

NIST_CATALOG_PATH = "data/nist_800_53_catalog.json"
CACHE_META_PATH = "data/policy_index_meta.json"
CACHE_VECTORS_PATH = "data/policy_index_vectors.npy"
DEFAULT_POLICY_PATH = "data/policy_excerpt.md"

# Real embedding cosine similarities run higher than TF-IDF's for genuinely
# related text, so the "is this a real match" bar is raised accordingly.
# Empirically calibrated against this corpus: unrelated text tops out
# around 0.17, genuine (if imperfectly worded) matches start around 0.24.
EMBEDDING_MIN_SCORE = 0.25
TFIDF_MIN_SCORE = 0.05


def load_policy_chunks(path: str):
    with open(path) as f:
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
    writes the result to disk. Deliberately manual/rare - triggered by the
    UI's Rebuild Index button, never called automatically during a
    pipeline run."""
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
    with open(CACHE_META_PATH, "w", encoding="utf-8") as f:
        json.dump(meta, f, indent=2)
    np.save(CACHE_VECTORS_PATH, np.array(vectors, dtype=np.float32))
    return meta


def _load_cached_index():
    """Returns (meta, vectors) or (None, None) if missing/unreadable."""
    if not (os.path.exists(CACHE_META_PATH) and os.path.exists(CACHE_VECTORS_PATH)):
        return None, None
    try:
        with open(CACHE_META_PATH, encoding="utf-8") as f:
            meta = json.load(f)
        vectors = np.load(CACHE_VECTORS_PATH)
        return meta, vectors
    except Exception:
        return None, None


def index_status():
    """For the UI's Policy Index admin panel: what's cached right now, and
    whether it's stale/incompatible with the currently configured model."""
    meta, _ = _load_cached_index()
    current_provider, current_model = embeddings.current_provider_and_model()
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
        "model_mismatch": (meta["embedding_provider"], meta["embedding_model"]) != (current_provider, current_model),
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


def _get_index(policy_path):
    """Returns (index, embedding_mode, fallback_reason)."""
    meta, vectors = _load_cached_index()
    if meta is not None and vectors is not None:
        current_provider, current_model = embeddings.current_provider_and_model()
        if (meta["embedding_provider"], meta["embedding_model"]) == (current_provider, current_model):
            # A user-uploaded policy isn't in the prebuilt cache; embed it now
            # and search it alongside NIST rather than ignoring it.
            extra = None
            if _is_user_supplied_policy(policy_path):
                extra = _build_excerpt_chunks(policy_path, source="user_policy", id_prefix="user")
            return EmbeddingPolicyIndex(meta, vectors, extra_chunks=extra), "embeddings", None
        reason_text = (
            f"Cached index was built with {meta['embedding_provider']}/{meta['embedding_model']}, "
            f"but {current_provider}/{current_model} is configured now - rebuild the index to use it."
        )
    else:
        reason_text = "No embedding index built yet - using keyword-based matching over the small excerpt instead."

    return PolicyIndex(load_policy_chunks(policy_path)), "tfidf-fallback", reason_text


def _mock_summary(gaps):
    if not gaps:
        return "No clear compliance gaps identified against the loaded policy excerpts."
    lines = ["Policy Checker Agent - compliance gaps:"]
    for g in gaps:
        header = g["policy_chunk"].splitlines()[0].replace("## ", "")
        lines.append(f"- Finding: {g['finding']}\n  -> Maps to: {header} (similarity {g['score']:.2f})")
    return "\n".join(lines)


def run(policy_path: str, all_findings):
    index, embedding_mode, embedding_fallback_reason = _get_index(policy_path)
    min_score = EMBEDDING_MIN_SCORE if embedding_mode == "embeddings" else TFIDF_MIN_SCORE

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

    system_prompt = (
        "You are a compliance analyst. Given security findings mapped to policy "
        "clauses (NIST 800-53 / ISO 27001 / SOC2), summarize which controls are "
        "not being met and what evidence would be needed to close each gap."
    )
    user_prompt = f"Mapped gaps:\n{gaps}"
    summary, mode = reason(system_prompt, user_prompt, mock_fn=lambda: _mock_summary(gaps))
    return {
        "agent": "policy_checker",
        "gaps": gaps,
        "summary": summary,
        "reasoning_mode": mode,
        "reasoning_fallback_reason": get_last_fallback_reason() if mode == "mock" else None,
        "embedding_mode": embedding_mode,
        "embedding_fallback_reason": embedding_fallback_reason,
    }
