# Hackathon Context — Cyber Security AI Agent

Condensed handoff notes so a fresh Claude Code session (or a teammate) can
pick this up cold, without needing the original chat history. Read this
first, then `README.md` in this same folder for the full technical detail.

## Program background

This project comes out of an 11-day AI Engineering Accelerator covering:
Day 1 Prompt Engineering + Chat Completion (OpenAI standard), Day 2 n8n,
Day 3 building an app with n8n + Google AI Studio (webhook-driven front
end → AI agent → back to front end), Day 4 Hugging Face/Gradio/local
models (Gradio taught explicitly as the go-to Python front end for ML/agent
demos), Day 5 RAG basics with LanceDB/LlamaIndex, Day 6 building & debugging
with AI ("Atlas"), Day 7 building a full RAG app (with a Gradio front end
built on top of it — same pattern used here), Day 8 Codex + Evals (also
covered a heavier Next.js/React/Tailwind/ShadCN stack via Claude Code, for
context on the "other" front-end option), Day 9 Claude Code + MCP, plus
separate LangChain/LangGraph + LangSmith modules on multi-agent
orchestration.

The hackathon offers 6 project topics (multi-agent DevOps incident suite,
multimodal design analysis, AI financial coach, multi-agent deep
researcher, **Cyber Security AI Agent**, browser automation agent). This
project targets **Cyber Security AI Agent**.

## The chosen topic, verbatim intent

> An AI-powered cybersecurity system made of multiple agents that can
> monitor logs, find security issues, and suggest fixes automatically:
> Log Monitor Agent, Threat Intelligence Agent, Vulnerability Scanner
> Agent, Incident Response Agent, Policy Checker Agent (against
> ISO/NIST/SOC2). Shows how RAG and AI agents work together for real-time
> threat detection, analysis, and response.

## What's been built (in a Cowork cloud sandbox with zero internet access)

A fully working, end-to-end prototype — `python3 main.py` runs it right
now, no setup. Five agents wired through a hand-rolled orchestrator
(`orchestrator.py`) that mirrors LangGraph's `StateGraph` API on purpose,
producing one markdown report (`report_builder.py`).

Because the build environment had **no PyPI, no apt/Ubuntu mirrors, and no
outbound access to api.anthropic.com/api.openai.com**, several pieces are
deliberately real-logic-but-offline stand-ins rather than the live
integrations the topic ultimately wants:

- **Agent reasoning** — deterministic rule-based summaries by default;
  `agents/llm.py` already calls the real Anthropic/OpenAI API first and
  only falls back to mock on failure/missing key. Export
  `ANTHROPIC_API_KEY` on a networked machine and it goes live with zero
  code changes.
- **Orchestration** — `orchestrator.py`'s `SimpleGraph` stands in for
  `langgraph.graph.StateGraph`. Structured so swapping in real LangGraph
  is close to a find-and-replace (see docstring at top of that file).
- **Threat intel feed** — `data/cve_dataset.json`, 10 hand-picked
  CVE/pattern records, instead of a live NVD API query.
- **Vulnerability scanner** — custom static checks over `Dockerfile` /
  `requirements.txt` in `vuln_scanner.py`, instead of shelling out to a
  real Trivy install (`trivy image ... --format json`).
- **Policy RAG** — TF-IDF + cosine similarity (scikit-learn, offline) over
  a 9-clause condensed policy excerpt (`data/policy_excerpt.md`), instead
  of real embeddings over the full NIST 800-53 / ISO 27001 / SOC2
  corpora.
- **Notifications** — since built: `agents/notify.py` is a terminal LangGraph
  node (not a 6th reasoning agent) that dispatches a Slack webhook message
  when a finding at or above a configured severity is present, with a
  labeled `skipped` fallback when nothing is configured. Email/JIRA
  integration remains out of scope.

Every agent's output JSON carries a `reasoning_mode` field
(`"mock"` / `"live-anthropic"` / `"live-openai"`) so it's always visible
which parts are live.

## UI decision

Chose **Gradio** over the n8n+Google AI Studio pattern (Day 2–3) and the
heavier Next.js/React/Tailwind/Claude-Code-scaffolded stack (Day 8),
specifically because Gradio was taught twice for exactly this shape of
problem — a Python ML/agent pipeline needing a demoable web UI (Day 4 and
Day 7, both explicitly building Gradio front ends over Python pipelines).
`app.py` is a thin Gradio Blocks skin over the existing `orchestrator.py` —
a "Quick Demo" tab (one click, bundled sample data) and an "Analyze Your
Own Files" tab (upload log/Dockerfile/requirements/policy, all optional
with sample-data fallback), severity badge counters, one accordion per
agent, and the full markdown report at the bottom.

(Historical note: Gradio couldn't be installed in the original no-PyPI cloud
sandbox, so a static `output/ui_preview.html` mockup stood in for the real UI.
That mockup — and the `generate_preview.py` that produced it — have since been
removed now that `app.py` runs for real.)

## The 15-hour build plan (from README.md, repeated here for quick reference)

Hour 0–1: get a real API key working + confirm `reasoning_mode` flips to
live. Hour 1–4: swap in real Trivy for the vulnerability scanner (highest
payoff single change). Hour 4–7: real or semi-real NVD threat intel.
Hour 7–10: wider policy corpus + real embeddings for RAG. Hour 10–12:
Slack/JIRA notifications. Hour 12–14: get the actual Gradio UI running
(`pip install gradio && python3 app.py`). Hour 14–15: rehearse, save a
known-good `output/report.md` as a backup in case live APIs flake during
the demo.

## What to ask Claude Code to do first

A good opening prompt in this folder:

> Read HACKATHON_CONTEXT.md and README.md. This was built in a
> network-isolated sandbox with mocked LLM reasoning, a hand-rolled
> LangGraph stand-in, a static CVE dataset, and no real Trivy — all
> clearly marked with swap points. You have real internet here. Wire in
> my ANTHROPIC_API_KEY, install real LangGraph and Trivy, and get
> `app.py` (Gradio) actually running so I can click through it.
