# Cyber Security AI Agent

A multi-agent cybersecurity system that **monitors logs, finds security issues, suggests
fixes, and can act on them** — five specialized AI agents plus a terminal notification/action
stage, orchestrated as a real [LangGraph](https://github.com/langchain-ai/langgraph) pipeline,
producing one traceable, prioritized report. Built for the "Cyber Security AI Agent" hackathon topic.

```bash
python -m pip install -r requirements.txt
python app.py        # → Gradio web UI  (recommended for the demo)
# or
python main.py       # → CLI, writes output/report.md + output/state.json
```

No API key is required to run it — every agent degrades gracefully to an offline path
and clearly labels which path it used. Paste a key in the UI (**BYOK**, see below) to run
the reasoning live.

---

## What it does — the 60-second story

The bundled sample data tells a concrete story: **an attacker is brute-forcing SSH and
scanning ports (`data/testing/quick_demo/sample_auth.log`), and a vulnerable container image is about to ship
(`data/testing/quick_demo/Dockerfile` + `data/testing/quick_demo/requirements.txt`).** Run the pipeline and watch five agents
catch it, correlate CVEs, map the gaps to NIST controls, and hand back an action plan.

```
sample_auth.log ──► Log Monitor Agent ─────┐
                                            ├─► Threat Intelligence Agent ─┐
Dockerfile + requirements.txt ─► Vuln Scanner Agent ┘                     │
                                                                          ├─► Incident Response Agent ─┐
policy_excerpt.md / NIST catalog ► Policy Checker Agent ──────────────────┘                            ├─► Notify (action) ─► Report
                                                                                                        ┘
```

Log Monitor and Vulnerability Scanner run first on independent inputs. Threat Intelligence
joins on both. Incident Response and Policy Checker both consume the combined findings. Notify
runs last as a terminal **action** stage — not a 6th reasoning agent — dispatching a Slack/email
alert when a finding at or above a configured severity is present. `report_builder.py` stitches
every stage's output into one markdown report.

## The five agents (+ one action stage)

| Agent | Job |
|---|---|
| **Log Monitor** | Parses auth logs for brute-force, recon, and port-scan signals |
| **Threat Intelligence** | Looks up the surfaced CVEs / patterns against a live threat feed |
| **Vulnerability Scanner** | Scans the Dockerfile + dependencies for misconfig and known CVEs |
| **Incident Response** | Turns findings into a prioritized, actionable remediation plan |
| **Policy Checker** | Maps gaps to NIST 800-53 / ISO / SOC2 controls via semantic RAG |
| **Notify** *(action stage, not an LLM agent)* | Dispatches a Slack message / email when a finding meets the configured severity threshold |

## Model Council + judge (CRITICAL findings only)

For CRITICAL-severity findings specifically, Incident Response gets a second, independent
model's opinion (a genuinely different model under whatever provider/key is configured) plus a
third **judge** call that reconciles the two into one final recommendation and flags whether they
agreed. Shown as a "🏛️ Model Council" block on the Incident Response page and in the markdown
report. Needs a live key configured (BYOK) to run at all - with no key, it's skipped
(`council mode: skipped-mock`), same as every other reasoning path in this app.

## Evaluation Dashboard (self-improvement)

Evaluation isn't optional for an agentic AI system - every LLM call can be wrong or inconsistent,
and without a fixed, repeatable test suite there's no way to catch a regression from a prompt
tweak, a model swap, or a retrieval change before a user does. A dedicated page (left nav:
**Evaluations**) scores this app's own retrieval accuracy and reasoning quality against a fixed
set of hand-written, known-answer test cases (`evals/golden_cases.py`) - click **Run Evals** to
see it live:

- **Retrieval Precision@1 / Recall@3** - deterministic, no LLM involved, always available: checks
  whether Policy Checker's real semantic search retrieves the *correct* NIST 800-53 control family
  for each golden finding.
- **Reasoning Faithfulness** - an [LLM-as-a-judge](https://en.wikipedia.org/wiki/LLM-as-a-judge)
  score (1-5) on whether an agent's summary only states facts present in its input, repeated 3x
  per case to report a consistency signal alongside the mean. Needs a live key configured; with no
  key it reports `mode: mock` rather than a fabricated score.

Every score tile explains in plain English *why that metric matters here*, and every golden case
can be expanded to see exactly what was retrieved/judged and why - built for someone with no prior
evals background to read.

**Run history** persists across sessions via a free-tier **Supabase** Postgres table when
configured, falling back to a local file (this-session-only) otherwise:

```sql
create table eval_runs (
    id bigint generated always as identity primary key,
    created_at timestamptz not null default now(),
    record jsonb not null
);
```

Set `SUPABASE_URL` (the project URL) and `SUPABASE_SECRET_KEY` (the service_role-equivalent key) as env vars
to enable it - both are optional; the dashboard works with local-only history if they're absent.

## Real integrations, with graceful fallback

Every external integration is genuinely wired up **and** has an offline fallback so a live
demo never hard-fails on flaky wifi or a missing binary. Each agent's output records which
path actually ran, so a judge can see at a glance what's live:

| Piece | Live path | Fallback (labeled in output) |
|---|---|---|
| Agent reasoning | Anthropic / OpenAI / OpenRouter via BYOK key | Deterministic rule-based summary — `reasoning_mode: mock` |
| Orchestration | Real LangGraph `StateGraph` (`orchestrator.py`) | — (always live) |
| Vulnerability scan | Real **Trivy** (`trivy config` + `trivy fs --scanners vuln`) against its live DB | Static regex/dataset checks — `scan_mode: static-fallback` |
| Threat intel | Live **NVD REST API v2.0** (public, no key) | Bundled `cve_dataset.json` — `local-fallback` |
| Policy RAG | Real semantic embeddings over the **full NIST 800-53 catalog** (~1,014 controls, cached vectors) | TF-IDF over a condensed excerpt |
| Notifications | Real **Slack webhook** dispatch for findings at/above a configured severity | Labeled `skipped` — pipeline still completes with no channel configured |

## Bring Your Own Key (BYOK)

No keys are baked into the app. The UI's right-hand **Settings** panel has a password-type
API-key field (Anthropic / OpenAI / OpenRouter) applied per session — paste your own key to
run reasoning live and watch `reasoning_mode` flip to `live-anthropic`. Leave it blank and
everything still runs on the offline paths above.

The same Settings panel has a **Notifications** section (Slack webhook URL and which severities
should trigger an alert). Nothing there is required — leave it blank and the Notify stage just
reports `skipped` and the run still completes.

## Repo layout

```
cybersec-agent/
├── app.py               # Gradio web UI (thin skin over the pipeline)
├── main.py              # CLI entry point
├── orchestrator.py      # LangGraph StateGraph wiring the 5 agents + Notify
├── report_builder.py    # aggregates agent outputs into markdown
├── ui_render.py          # presentation layer for the Gradio UI (no gradio imports)
├── requirements.txt     # app dependencies  (NOT data/testing/quick_demo/requirements.txt)
├── agents/              # the five agents + notify (action stage) + shared llm/embeddings helpers
├── data/
│   ├── testing/quick_demo/     # bundled sample inputs (incl. an intentionally vulnerable requirements.txt)
│   ├── testing/test_fixtures/  # 50-file set for manually testing "Analyze Your Own Files"
│   └── knowledgebase/          # CVE dataset, NIST 800-53 catalog, policy embedding cache
├── output/              # report.md (kept as a demo backup) — regenerated each run
├── scripts/             # one-off data-prep (fetch/flatten the NIST 800-53 catalog)
└── docs/                # project background + architecture decisions
```

## Optional: enable live scanning

- **Trivy** (for real vulnerability scanning): install from
  [aquasecurity/trivy](https://github.com/aquasecurity/trivy) — the scanner auto-detects it
  on `PATH` and falls back to static checks if it's absent. On Render (or any host without
  Trivy preinstalled), `scripts/render_build.sh` installs it automatically as part of the
  build — either deploy via the included `render.yaml` (Blueprint), or paste
  `bash scripts/render_build.sh` into an existing service's **Build Command** in the Render
  dashboard.
- **Live LLM reasoning**: paste an API key in the UI (BYOK).
- **NVD threat intel** works out of the box (public API, no key), falling back to the bundled
  dataset if unreachable.
- **Notifications**: paste a Slack webhook URL in the UI, or set `SLACK_WEBHOOK_URL` as an env
  var. Optional `NOTIFY_SEVERITIES` (default `CRITICAL`) controls which severities trigger it.

For hackathon context, see [`docs/BACKGROUND.md`](docs/BACKGROUND.md); for
the reasoning behind the architecture, see [`docs/DECISIONS.md`](docs/DECISIONS.md).
