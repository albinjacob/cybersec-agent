# Architecture & Design Decisions

Why the codebase is shaped the way it is. For what the system does, see
[`README.md`](../README.md); for hackathon context, see
[`BACKGROUND.md`](BACKGROUND.md).

## Detection is deterministic; the LLM only narrates

Every agent extracts its findings with rule-based logic (regex, static
analysis, real Trivy/NVD queries) *before* any LLM call. The LLM's only job
is turning structured findings into readable prose. This means:

- Findings can never be hallucinated — a "CRITICAL SSH brute-force" finding
  exists because 3+ failed logins from one IP were actually counted, not
  because a model said so.
- `report_builder.py` computes `risk_level` from the structured findings,
  never from LLM prose, so the executive summary can't drift from the data.
- Every finding card's "What this means" / "Recommended Action" text comes
  from a hardcoded `KNOWLEDGE_BASE` dict in `ui_render.py`, not the LLM, so
  guidance is identical regardless of which model is configured.

## Real LangGraph, genuine parallel fan-out

`orchestrator.py` uses `langgraph.graph.StateGraph`, not a hand-rolled
stand-in. Log Monitor and Vulnerability Scanner run in parallel from START
(independent inputs), join at Threat Intelligence, then run sequentially
through Incident Response → Policy Checker → Notify.

## Every subsystem reports live-vs-fallback, with a real reason

Four independent subsystems (LLM reasoning, Trivy scanning, NVD threat
intel, RAG embeddings) each carry a `*_mode` field plus a `*_fallback_reason`
string that's `None` unless that mode degraded. A fallback is never a quiet
badge — it's a loud banner with the actual error (e.g. an HTTP status), both
per-agent and aggregated on the Overview page. This is the single idea most
worth preserving if the codebase changes further: it lets a judge see at a
glance what's actually live versus degraded, and it means a flaky NVD
timeout during a demo degrades visibly and gracefully instead of crashing.

## Model Council for CRITICAL findings only

Incident Response gets a second, independent model's opinion plus a judge
call that reconciles the two, but only for CRITICAL-severity findings
(capped, to bound cost) — this is a defensible signal only where it
matters, not a blanket 3x-cost multiplier on every finding.

## No vector database

The NIST 800-53 corpus (~1,000 chunks, ~2MB of cached vectors) is orders of
magnitude below the scale where an ANN index (Pinecone/Weaviate/Qdrant)
matters. Plain in-memory cosine similarity (scikit-learn) is sufficient and
is what's actually running. Embeddings are precomputed and cached per
embedding-provider, rebuilt only via a manual "Rebuild Index" button — the
corpus doesn't change at runtime, so re-embedding on every pipeline run
would be pure waste.

## BYOK, no baked-in keys

No API keys ship in the app. LLM reasoning and RAG embeddings each have
their own settings section (different things — LLM affects narrative
reasoning everywhere, embeddings affect only Policy Checker retrieval) but
share the same `configure()`/mock-fallback pattern. Every agent runs
end-to-end with zero configuration by falling back to deterministic mock
reasoning / TF-IDF retrieval.

## Notify is a terminal action stage, not a 6th reasoning agent

`agents/notify.py` dispatches a Slack webhook message when a finding meets
a configured severity threshold. It has no LLM reasoning of its own — it's
plumbing, not an agent — which is why the UI and report treat it as an
"action stage" distinct from the five reasoning agents.

## Evals are a first-class page, not an afterthought

An agentic pipeline with LLM calls at every node needs a repeatable way to
catch a regression from a prompt tweak or model swap. The Evaluations page
scores retrieval precision/recall (deterministic) and reasoning
faithfulness (LLM-as-judge) against a fixed set of golden test cases, with
run history persisted to Supabase (or a local file if unconfigured).

## Presentation is split from orchestration

`ui_render.py` is pure presentation (data in, HTML out, zero Gradio
imports); `app.py` owns only Gradio layout, wiring, and the streaming
handler; `orchestrator.py` is pure pipeline wiring. Agents know nothing
about Gradio. All dynamic HTML (findings evidence, LLM output, uploaded
file content) is escaped before interpolation — user-controlled log/report
content is treated as untrusted throughout.

## `data/` is organized by purpose, not by file type

- `data/testing/quick_demo/` — the 4 bundled files the pipeline falls back
  to when an upload slot is left blank.
- `data/testing/test_fixtures/` — a 50-file set spanning real sub-formats
  (multiple log styles, IaC formats, dependency ecosystems, policy docs)
  for manually exercising every code path the UI claims to support.
- `data/knowledgebase/` — reference/runtime data the app depends on
  independent of any demo or test flow (CVE fallback dataset, NIST 800-53
  catalog, embedding cache — the last two regenerated on demand, not
  committed as source data).
