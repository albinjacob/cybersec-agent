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
scanning ports (`data/sample_auth.log`), and a vulnerable container image is about to ship
(`data/Dockerfile` + `data/requirements.txt`).** Run the pipeline and watch five agents
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
| Notifications | Real **Slack webhook** + **Gmail SMTP** dispatch for findings at/above a configured severity | Labeled `skipped` — pipeline still completes with no channel configured |

## Bring Your Own Key (BYOK)

No keys are baked into the app. The UI's right-hand **Settings** panel has a password-type
API-key field (Anthropic / OpenAI / OpenRouter) applied per session — paste your own key to
run reasoning live and watch `reasoning_mode` flip to `live-anthropic`. Leave it blank and
everything still runs on the offline paths above.

The same Settings panel has a **Notifications** section (Slack webhook URL, Gmail address +
app password, a recipient list, and which severities should trigger an alert). Nothing there is
required — leave it blank and the Notify stage just reports `skipped` and the run still completes.

## Repo layout

```
cybersec-agent/
├── app.py               # Gradio web UI (thin skin over the pipeline)
├── main.py              # CLI entry point
├── orchestrator.py      # LangGraph StateGraph wiring the 5 agents + Notify
├── report_builder.py    # aggregates agent outputs into markdown
├── ui_render.py          # presentation layer for the Gradio UI (no gradio imports)
├── requirements.txt     # app dependencies  (NOT data/requirements.txt)
├── agents/              # the five agents + notify (action stage) + shared llm/embeddings helpers
├── data/                # sample inputs + threat feed + NIST catalog + policy index
│   └── requirements.txt #   ⚠ intentionally vulnerable SAMPLE the scanner analyzes
├── output/              # report.md (kept as a demo backup) — regenerated each run
├── scripts/             # one-off data-prep (fetch/flatten the NIST 800-53 catalog)
└── docs/                # deeper build history & handoff notes
```

## Optional: enable live scanning

- **Trivy** (for real vulnerability scanning): install from
  [aquasecurity/trivy](https://github.com/aquasecurity/trivy) — the scanner auto-detects it
  on `PATH` and falls back to static checks if it's absent.
- **Live LLM reasoning**: paste an API key in the UI (BYOK).
- **NVD threat intel** works out of the box (public API, no key), falling back to the bundled
  dataset if unreachable.
- **Notifications**: paste a Slack webhook URL and/or a Gmail address + [app
  password](https://myaccount.google.com/apppasswords) (not your account password) in the UI, or
  set `SLACK_WEBHOOK_URL`, `SMTP_USER`, `SMTP_PASS`, `ALERT_EMAIL_TO` (comma-separated) as env
  vars. Optional `NOTIFY_SEVERITIES` (default `CRITICAL`) controls which severities trigger it.

For the full build narrative and design decisions, see [`docs/`](docs/).
