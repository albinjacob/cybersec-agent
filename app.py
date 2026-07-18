"""
Gradio front end for the Cyber Security AI Agent pipeline.

Layout: a top app bar (brand + live subsystem status chips + BYOK button), a
left sidebar navigating between an Overview dashboard, one page per agent,
and a Full Report page. A right sidebar holds BYOK settings for LLM
reasoning, Policy RAG embeddings, and the Slack notification stage.

The Overview page is the ONLY place the pipeline is launched - it owns both
"Run Quick Demo" (bundled sample data) and "Analyze Your Own Files" (with an
explicit panel documenting what each input accepts and, importantly, what it
does NOT). Agent pages are pure result views: live tracker, severity filter,
and findings as collapsible color-coded cards. This mirrors reality - any run
executes the whole graph, so five per-agent upload forms were five copies of
one thing that also implied agents ran independently.

Pipeline runs STREAM live: run handlers are generators fed by LangGraph's
.stream() (orchestrator.stream_pipeline), so the DAG tracker lights up node
by node - Log Monitor and Vulnerability Scanner visibly run in parallel -
and each agent's page populates the moment its agent completes rather than
after the whole ~60s run.

All HTML rendering lives in ui_render.py (pure presentation, no Gradio);
this module owns layout, wiring, and the streaming run handler.

Because Threat Intelligence, Incident Response, and Policy Checker all
consume Log Monitor's and/or Vulnerability Scanner's output, no agent can
run in true isolation - running from ANY page always executes the full
graph, then populates every agent's page, so browsing between agents after
one run never re-triggers the (paid, live) LLM calls.

Run with:
    python3 app.py
"""

import os
import time

import gradio as gr

from orchestrator import stream_pipeline
from report_builder import build_report
from agents import llm, embeddings, notify, policy_checker, vuln_scanner
from evals.run_evals import run_all as run_all_evals
from evals.storage import load_history as load_eval_history, save_run as save_eval_run
from ui_render import (
    ACCENT,
    ADMIN_ACCENT,
    AGENTS,
    AGENT_DISPLAY_PLACEHOLDER,
    APP_VERSION,
    CUSTOM_CSS,
    EVAL_RUN_PLACEHOLDER,
    FILE_LABELS,
    FILTERABLE_AGENTS,
    PIPELINE_ORDER,
    PIPELINE_PREDECESSORS,
    dashboard_html,
    deploy_key_hint_html,
    eval_case_cards_html,
    eval_history_html,
    eval_score_tiles_html,
    eval_storage_status_html,
    file_help_html,
    framework_primer_html,
    glossary_term,
    icon_html,
    nav_section_label_html,
    pipeline_tracker_html,
    subsystem_chip_state,
    render_agent_display,
    self_improvement_primer_html,
    topbar_health_html,
)

# Explicit on both ends, not host-specific magic: local dev sets MODE=development
# in .env (see .env.example); a deployment sets MODE=production itself, in
# whichever host's dashboard it happens to be this month (Render, Railway, a
# VPS - doesn't matter, this isn't tied to one host's auto-injected env var).
# Absence of MODE anywhere defaults to "not deployed" - the safer failure mode,
# since it just means a host that forgot to set it gets quieter local-style
# behavior rather than incorrectly showing deploy-only messaging.
# Used only for the soft "paste a key" nudge below; never for choosing the
# embedding provider itself (that's already driven by whether OPENROUTER_API_KEY
# is set, uniformly across dev machines and deployments - see agents/embeddings.py).
IS_DEPLOYED = os.environ.get("MODE", "development").strip().lower() == "production"

# ------------------------------------------------------------- BYOK settings

# No "Auto" radio for reasoning: this app is shared with hackathon reviewers who are all
# expected to bring their own OpenRouter key, and this deployment never sets a server-side
# env key on Render - so "Auto" always resolved to mock in production, and worse, selecting
# it while a key was pasted silently discarded that key (agents/llm.py's configure() clears
# _RUNTIME for provider="auto"). Provider is now implied by whether a key was pasted; backend
# env-var auto-detect in agents/llm.py is unchanged for main.py's CLI path.

# Anthropic/OpenAI were never real embedding options in this app; only Offline (local,
# sentence-transformers) and OpenRouter remain. "Auto" is dropped here for the same reason as
# reasoning above - it's driven purely by a server-side OPENROUTER_API_KEY that's never set in
# this deployment model, so it was provably identical to "Offline embeddings" and just added a
# redundant label. "Local" was renamed to "Offline embeddings" - it runs identically on a
# deployed server, not just a developer's own machine, and the old name invited that misreading.
EMBEDDING_PROVIDER_LABELS = {
    "Offline embeddings (no key)": "local",
    "OpenRouter": "openrouter",
}
LOCAL_EMBEDDING_MODELS = ["all-MiniLM-L6-v2"]
OPENROUTER_EMBEDDING_MODELS = ["openai/text-embedding-3-small", "openai/text-embedding-3-large"]

REPORT_PATH = os.path.join("output", "report.md")

NARRATIVE_PLACEHOLDER = "Run the agent above to see the AI's narrative summary here."


def embedding_models_for_provider(provider_label):
    provider = EMBEDDING_PROVIDER_LABELS[provider_label]
    if provider == "local":
        return gr.update(choices=LOCAL_EMBEDDING_MODELS, value=LOCAL_EMBEDDING_MODELS[0], interactive=True)
    if provider == "openrouter":
        return gr.update(choices=OPENROUTER_EMBEDDING_MODELS, value=OPENROUTER_EMBEDDING_MODELS[0], interactive=True)
    return gr.update(choices=[], value=None, interactive=False)


def policy_index_status_html():
    status = policy_checker.index_status()
    if not status["exists"]:
        provider = status["current_provider"]
        # A paid API provider means "Rebuild Index" makes ~1,000 real embedding
        # calls on whatever key is configured - said plainly here, right where
        # the button is, rather than letting a user click it without knowing
        # a cost is about to be incurred. Local has no such cost to flag.
        cost_note = (
            f' This is a one-time (or rare) operation - it will make ~1,000 real embedding API calls '
            f'to <b>{provider}</b> using the key configured above.'
            if provider in ("openai", "openrouter") else
            ' This runs fully offline at no cost.'
        )
        return (
            '<div style="padding:10px 14px; border-radius:8px; background:var(--background-fill-secondary); '
            'font-size:13px;">No embedding index built yet for provider '
            f'<code>{provider}/{status["current_model"]}</code> - Policy Checker is using keyword-based '
            f'matching over the small excerpt instead. Click <b>Rebuild Index</b> below to build one from '
            f'the full NIST SP 800-53 catalog.{cost_note}</div>'
        )
    warning = ""
    if status["model_mismatch"]:
        warning = (
            f'<div style="margin-top:6px;">⚠️ Cache was built with model <code>{status["embedding_model"]}</code>, '
            f'but <code>{status["current_model"]}</code> is configured now for {status["current_provider"]} - '
            'click Rebuild Index below to use it.</div>'
        )
    elif status["corpus_stale"]:
        warning = '<div style="margin-top:6px;">⚠️ Source corpus has changed since this index was built - rebuild recommended.</div>'
    built_at = status["built_at"][:19].replace("T", " ")
    return (
        '<div style="padding:10px 14px; border-radius:8px; background:var(--background-fill-secondary); '
        'font-size:13px;">'
        f'<b>{status["chunk_count"]}</b> chunks indexed with <code>{status["embedding_provider"]}/'
        f'{status["embedding_model"]}</code> &middot; built {built_at} UTC'
        f'{warning}'
        '</div>'
    )


def preflight():
    """What can be TRUTHFULLY determined before running anything, so the top-bar
    chips answer "is this set up correctly?" instead of showing a meaningless
    dash. Each value is (text, tone); a key mapped to None means "genuinely
    unknowable without running" (the chip then says "checked on run").

    Everything here is a cheap local check - env var, file glob, cached JSON.
    Deliberately NO network calls: NVD reachability is the one thing we can't
    know, and probing it on every page load would be slow and could itself
    time out, which is exactly the flakiness the fallback exists for.
    """
    # LLM: which provider would actually be used (mirrors reason()'s order)
    provider = None
    if llm._RUNTIME.get("provider"):
        provider = llm._RUNTIME["provider"]
    elif llm.ANTHROPIC_API_KEY:
        provider = "anthropic"
    elif llm.OPENAI_API_KEY:
        provider = "openai"
    elif llm.OPENROUTER_API_KEY:
        provider = "openrouter"
    llm_pre = (provider, "ok") if provider else ("no key → mock", "warn")

    scanner_pre = ("Trivy", "ok") if vuln_scanner._find_trivy() else ("not installed", "warn")

    try:
        st = policy_checker.index_status()
        if not st["exists"]:
            policy_pre = ("not indexed", "warn")
        elif st.get("model_mismatch") or st.get("corpus_stale"):
            policy_pre = ("rebuild needed", "warn")
        else:
            # 3rd element is tooltip-only detail (embedding provider/model) - kept
            # out of the value itself so the compact topbar chip stays terse.
            policy_pre = (f'{st["chunk_count"]:,} controls', "ok",
                          f'{st["current_provider"]}/{st["current_model"]}')
    except Exception:
        policy_pre = ("unavailable", "warn")

    return {
        "llm": llm_pre,
        "scanner": scanner_pre,
        "threat_feed": None,   # only knowable by actually calling NVD
        "policy_rag": policy_pre,
    }


def policy_chip_update(state=None):
    """(topbar_health minus llm/policy_rag) is rendered separately as plain
    HTML; this is the Policy chip specifically, as a gr.Button update - reused
    by every place the embedding index's status can change (a settings tweak,
    a rebuild, or a pipeline run completing), so the topbar is never stale
    relative to what Compliance Check's own panel already shows."""
    label, tone, _tip = subsystem_chip_state("policy_rag", state, preflight())
    return gr.update(value=label, elem_classes=["chip-btn", tone])


def ai_chip_update(state=None):
    """Same idea as policy_chip_update, for the AI chip - only recomputed
    per pipeline run (LLM reasoning's mode is only known once `llm.configure()`
    runs inside a run handler, unlike embeddings which apply live on change)."""
    label, tone, _tip = subsystem_chip_state("llm", state, preflight())
    return gr.update(value=label, elem_classes=["chip-btn", tone])


def apply_embedding_settings(provider_label, api_key, model, state):
    embeddings.configure(provider=EMBEDDING_PROVIDER_LABELS.get(provider_label, "local"), api_key=api_key, model=model)
    return (
        policy_index_status_html(),
        topbar_health_html(state, preflight(), exclude=("llm", "policy_rag")),
        policy_chip_update(state),
    )


def rebuild_policy_index(provider_label, api_key, model, state):
    embeddings.configure(provider=EMBEDDING_PROVIDER_LABELS.get(provider_label, "local"), api_key=api_key, model=model)
    policy_checker.rebuild_index()
    return (
        policy_index_status_html(),
        topbar_health_html(state, preflight(), exclude=("llm", "policy_rag")),
        policy_chip_update(state),
    )

# ---------------------------------------------------- notification settings


def notify_status_html(slack_webhook, severities):
    """Config-at-a-glance for the sidebar - never shows the secret value
    itself, only whether the channel is configured."""
    slack_state = "configured" if slack_webhook else "not set"
    sevs = ", ".join(notify.parse_list(severities)) or "none"
    return (
        '<div style="padding:10px 14px; border-radius:8px; background:var(--background-fill-secondary); '
        f'font-size:13px;">Slack: <b>{slack_state}</b><br>'
        f'Alerts on: <b>{sevs}</b></div>'
    )


def apply_notification_settings(slack_webhook, severities):
    notify.configure(slack_webhook=slack_webhook, severities=severities)
    return notify_status_html(slack_webhook, severities)

# --------------------------------------------------- streaming run handler


def _node_statuses(done_nodes, running):
    """Status per DAG node, derived from the fixed topology: a node is
    'running' once every predecessor has completed."""
    statuses = {}
    for node in PIPELINE_ORDER:
        if node in done_nodes:
            statuses[node] = "done"
        elif running and all(p in done_nodes for p in PIPELINE_PREDECESSORS[node]):
            statuses[node] = "running"
        elif running:
            statuses[node] = "pending"
        else:
            statuses[node] = "idle"
    return statuses


def _running_display_placeholder(key, statuses):
    meta_title = next(a["title"] for a in AGENTS if a["key"] == key)
    if statuses.get(key) == "running":
        return (f'<div class="empty-state"><div class="empty-icon">{icon_html("threat_intel", size=30)}</div>'
                f'<div class="subdued-text"><b>{meta_title}</b> is running now - results will '
                'appear here the moment it completes.</div></div>')
    return (f'<div class="empty-state"><div class="empty-icon">{icon_html("report", size=30)}</div>'
            f'<div class="subdued-text"><b>{meta_title}</b> is queued, waiting on upstream agents.</div></div>')


DEMO_BTN_LABEL = "Run Quick Demo"
ANALYZE_BTN_LABEL = "Run Analysis"
RUNNING_BTN_LABEL = "Running…"


def _button_updates(phase, active):
    """Both run buttons are disabled for the duration of a run (they'd both
    kick off the same graph), and the one that was actually clicked flips to
    "Running…" so the click visibly registers - otherwise the button sits
    there looking untouched for ~100s."""
    if phase == "final":
        return (gr.update(value=DEMO_BTN_LABEL, interactive=True),
                gr.update(value=ANALYZE_BTN_LABEL, interactive=True))
    demo = (gr.update(value=RUNNING_BTN_LABEL, interactive=False) if active == "demo"
            else gr.update(interactive=False))
    analyze = (gr.update(value=RUNNING_BTN_LABEL, interactive=False) if active == "analyze"
               else gr.update(interactive=False))
    return demo, analyze


def _stream_snapshot(state, statuses, durations, phase, report_md=None, error=None, active=None, elapsed=None):
    """One yield's worth of UI updates, in STREAM_OUTPUTS order:
    [topbar_health, ai_chip_btn, policy_chip_btn, overview_dashboard, overview_tracker,
     per agent: (tracker, display, narrative),
     per agent: (agent_progress, agent_followup),
     report_out, report_download, pipeline_state, demo_btn, analyze_btn,
     overview_progress].
    Non-final phases use gr.update() no-ops where nothing changed."""
    state = state or {}
    running = phase != "final"
    caption = None
    if phase == "final" and durations:
        caption = f"Completed in {sum(durations.values()):.1f}s of agent time"
    elif phase in ("start", "progress") and not error and elapsed is not None:
        # An unbounded "running"/"queued" wait with no time signal is exactly
        # where an impatient user gives up - a real Quick Demo run measured at
        # ~85-105s of wall time, with nothing telling the user that. Bound it:
        # how many of 6 stages (5 analysis agents + the action stage) are
        # done, how long it's been, and the rough total.
        done_n = len(durations)
        caption = f"{done_n} of 6 stages done - {elapsed:.0f}s elapsed (usually ~90s total)"
    tracker = pipeline_tracker_html(statuses, durations, state, error=error, caption=caption)

    # preflight still matters mid-run: subsystems that haven't reported yet keep
    # showing their readiness rather than reverting to a dash
    out = [topbar_health_html(state, preflight(), exclude=("llm", "policy_rag")),
           ai_chip_update(state),
           policy_chip_update(state),
           dashboard_html(state, running=running and not error), tracker]
    for a in AGENTS:
        key = a["key"]
        out.append(tracker)
        if key in state:
            out.append(render_agent_display(key, state))
            out.append(state[key]["summary"])
        elif phase == "start" or error:
            out.append(_running_display_placeholder(key, statuses) if not error else AGENT_DISPLAY_PLACEHOLDER)
            out.append(NARRATIVE_PLACEHOLDER)
        else:
            out.append(_running_display_placeholder(key, statuses))
            out.append(gr.update())

    # Reveal every agent page's tracker/filter and narrative/next-button the
    # moment ANY run starts - same "reveal on first yield, stay visible after"
    # rule as overview_progress, applied uniformly rather than waiting for
    # each individual agent's own node to finish (a user browsing to an
    # agent page mid-run should see its tracker live, not still hidden).
    for _a in AGENTS:
        out.append(gr.update(visible=True))
        out.append(gr.update(visible=True))

    if report_md is not None:
        out.append(report_md)
        out.append(gr.update(value=REPORT_PATH, interactive=True))
    elif phase == "start":
        out.append("_Report will be generated when the pipeline completes..._")
        out.append(gr.update(interactive=False))
    else:
        out.append(gr.update())
        out.append(gr.update())

    out.append(dict(state) if state else None)
    out.extend(_button_updates(phase, active))
    # Reveal the tracker/KPI block on the very first yield of a run and leave
    # it visible thereafter - once a run has happened, showing its progress
    # and results is no longer noise.
    out.append(gr.update(visible=True))
    return tuple(out)


def run_and_render_stream(log_file, dockerfile, requirements_file, policy_file,
                           api_key, model, active="analyze"):
    """Generator event handler: streams the LangGraph run so the tracker and
    each agent's page update live as nodes complete."""
    # Provider is implied by whether a key was pasted - no separate radio to fall out of sync
    # with the key field (see the "remove Auto" addendum for the footgun this replaced).
    llm.configure(provider="openrouter" if api_key else "auto", api_key=api_key, model=model)
    log_path = log_file.name if log_file else "data/sample_auth.log"
    dockerfile_path = dockerfile.name if dockerfile else "data/Dockerfile"
    req_path = requirements_file.name if requirements_file else "data/requirements.txt"
    policy_path = policy_file.name if policy_file else "data/policy_excerpt.md"

    t0 = time.time()
    done_at = {}
    durations = {}
    state = {}

    yield _stream_snapshot(None, _node_statuses(done_at, running=True), durations,
                            phase="start", active=active, elapsed=0.0)

    try:
        for node, acc_state in stream_pipeline(log_path, dockerfile_path, req_path, policy_path):
            now = time.time()
            started = max([t0] + [done_at[p] for p in PIPELINE_PREDECESSORS[node] if p in done_at])
            done_at[node] = now
            durations[node] = now - started
            state = acc_state
            yield _stream_snapshot(state, _node_statuses(done_at, running=True), durations,
                                    phase="progress", active=active, elapsed=now - t0)
    except Exception as e:
        # phase="final" here too, so the buttons re-enable rather than
        # stranding the user with a dead "Running…" button after a crash
        yield _stream_snapshot(state, _node_statuses(done_at, running=False), durations,
                                phase="final", error=str(e), active=active)
        return

    report = build_report(state)
    os.makedirs("output", exist_ok=True)
    with open(REPORT_PATH, "w", encoding="utf-8") as f:
        f.write(report)

    yield _stream_snapshot(state, _node_statuses(done_at, running=False), durations,
                            phase="final", report_md=report, active=active)


def run_quick_demo_stream(api_key, model):
    yield from run_and_render_stream(None, None, None, None, api_key, model, active="demo")


def run_evals_and_render():
    """Generator so the button visibly registers the click before the ~10-30s
    scoring run (which makes several live LLM calls when a key is configured)."""
    yield (
        gr.update(value="Running…", interactive=False),
        '<div class="subdued-text" style="margin:8px 0;">Running evals now - this can take up '
        'to ~30s with a live key configured...</div>',
        gr.update(), gr.update(), gr.update(), gr.update(),
    )
    record = run_all_evals()
    storage_mode = save_eval_run(record)
    history, history_mode = load_eval_history()
    yield (
        gr.update(value="▶ Run Evals", interactive=True),
        "",
        eval_storage_status_html(storage_mode),
        eval_score_tiles_html(record),
        eval_case_cards_html(record),
        eval_history_html(history, history_mode),
    )


def make_severity_filter_fn(key):
    def _fn(filter_value, state):
        if not state or key not in state:
            return gr.update()
        return render_agent_display(key, state, severity_filter=filter_value)
    return _fn

# --------------------------------------------------------------------- app


with gr.Blocks(title="CyberSec AI Agent") as demo:
    # holds the last run's full state dict so severity filters can re-render
    # cards without re-running the (paid) pipeline
    pipeline_state = gr.State(None)

    # ---- right sidebar: BYOK settings (LLM + embeddings) ----
    with gr.Sidebar(position="right", open=False, width=320, label="Settings") as settings_sidebar:
        gr.Markdown(
            "### ⚙️ Model Settings\n"
            "Paste your OpenRouter key for live reasoning across all 5 agents. Leave blank to run "
            "offline (mock)."
        )
        api_key_input = gr.Textbox(
            label="OpenRouter API Key (optional)", type="password",
            placeholder="Leave blank to run offline (mock)",
        )
        model_dropdown = gr.Dropdown(
            choices=[], value=None, label="Model", interactive=False, allow_custom_value=True,
            filterable=True,
        )

        gr.Markdown("---")
        gr.Markdown(
            "### 🔎 Policy RAG Embeddings\n"
            "Controls semantic search for the Policy Checker agent only - separate from the reasoning "
            "model above, which affects all 5 agents. Defaults to offline embeddings; no API "
            "key needed unless you pick OpenRouter."
        )
        with gr.Group():
            embed_provider_radio = gr.Radio(
                choices=list(EMBEDDING_PROVIDER_LABELS.keys()),
                value="Offline embeddings (no key)",
                label="Embedding Provider",
                elem_classes=["compact-radio"],
            )
            gr.HTML(
                f'<div style="font-size:11px; color:var(--body-text-color-subdued); margin-top:-4px;">'
                f'{glossary_term("Offline embeddings", "ⓘ what runs locally?")}</div>'
            )
            embed_api_key_input = gr.Textbox(
                label="API Key (optional, only needed for OpenRouter)", type="password",
                placeholder="Leave blank for offline embeddings",
            )
            embed_model_dropdown = gr.Dropdown(
                choices=[], value=None, label="Embedding Model", interactive=False, allow_custom_value=True,
            )
        embed_provider_radio.change(
            fn=embedding_models_for_provider, inputs=embed_provider_radio, outputs=embed_model_dropdown
        )

        gr.Markdown("---")
        gr.Markdown(
            "### 📣 Notifications\n"
            "Dispatches a Slack message when a finding at or above the selected severities is "
            "detected - this is the pipeline's terminal **action** stage, not another reasoning "
            "agent. Leave both blank to skip it entirely."
        )
        severity_checkboxes = gr.CheckboxGroup(
            choices=["CRITICAL", "HIGH", "MEDIUM", "LOW"], value=["CRITICAL"],
            label="Alert on severities",
        )
        slack_webhook_input = gr.Textbox(
            label="Slack webhook URL (optional)", type="password",
            placeholder="https://hooks.slack.com/services/...",
        )
        notify_status = gr.HTML(value=notify_status_html(None, ["CRITICAL"]))

    settings_inputs = [api_key_input, model_dropdown]
    embedding_settings_inputs = [embed_provider_radio, embed_api_key_input, embed_model_dropdown]
    notification_settings_inputs = [slack_webhook_input, severity_checkboxes]

    # ---- top app bar: brand | live status chips | settings ----
    with gr.Row(elem_id="app-topbar"):
        # Subtitle says what the product DOES. It used to list the stack
        # (LangGraph · Trivy · NVD · semantic RAG), which the status chips to
        # its right now report live and per-run - so the static list was both
        # redundant and less truthful than the chips beside it.
        gr.HTML(
            f'<div><div class="brand-title">{icon_html("shield", size=18)} CyberSec AI Agent'
            f'<span class="version-badge">v{APP_VERSION}</span></div>'
            '<div class="brand-sub subdued-text">Automated log, vulnerability &amp; '
            'compliance analysis</div></div>'
        )
        # AI/Scan/CVE/Policy live together as one visual chip cluster, so they
        # need a nested Row with a tight custom gap - left as one flat Row,
        # each of these three becomes its own top-level child of "app-topbar"
        # and picks up Gradio's normal (much larger) inter-component spacing,
        # which is what produced the ugly gaps between them.
        with gr.Row(elem_id="chip-cluster"):
            # AI is the first chip, also rendered as a real button - clicking
            # it opens the same Settings sidebar "Configure Models" does. Not
            # a replacement for that button (Settings also covers Embeddings
            # and Notifications, unrelated to "AI"), just a second, obvious
            # way in for the one setting this chip actually reflects.
            _ai_label, _ai_tone, _ai_tip = subsystem_chip_state("llm", preflight=preflight())
            ai_chip_btn = gr.Button(_ai_label, size="sm", scale=0,
                                     elem_classes=["chip-btn", _ai_tone])
            # Live subsystem health, always visible on every page - same data
            # as the Overview chips (shared _subsystem_health), abbreviated.
            topbar_health = gr.HTML(value=topbar_health_html(preflight=preflight(), exclude=("llm", "policy_rag")),
                                     elem_id="topbar-health-slot")
            # Policy is the other chip rendered as a REAL button, not HTML
            # like Scan/CVE - clicking it jumps straight to Compliance Check
            # (where Rebuild Index lives), instead of making a user hunt
            # through the left nav for the one page that can fix a
            # "not indexed"/"rebuild needed" chip.
            _policy_label, _policy_tone, _policy_tip = subsystem_chip_state("policy_rag", preflight=preflight())
            policy_chip_btn = gr.Button(_policy_label, size="sm", scale=0,
                                         elem_classes=["chip-btn", _policy_tone])
        # Deliberately NOT "Settings": Gradio renders its own footer "Settings"
        # (its theme/API panel), and two differently-scoped buttons sharing one
        # label is what made this confusing. "Configure Models" names what the
        # panel actually does - it sets the reasoning LLM *and* the embedding
        # model - and can't be mistaken for Gradio's.
        # Label is text-only; the gear glyph is drawn by CSS (::before). A 12px
        # emoji baked into the label was unreadable and couldn't be sized
        # independently of the text - CSS owns the icon so it can be sized and
        # inherits currentColor (monochrome, matches the label, no emoji font).
        open_settings_btn = gr.Button("Configure Models", size="sm", scale=0,
                                       elem_id="settings-toggle-btn")
    open_settings_btn.click(fn=lambda: gr.Sidebar(open=True), outputs=settings_sidebar)
    ai_chip_btn.click(fn=lambda: gr.Sidebar(open=True), outputs=settings_sidebar)

    # Soft nudge, deployed instances only, shown/hidden per browser session via
    # demo.load() (not baked in at server-start, since whether a key is
    # configured can change while the server keeps running).
    deploy_key_hint = gr.HTML(value="")

    # ---- left sidebar: navigation ----
    # Two visually distinct groups - not real access control (no logins exist
    # in this app), just an honest label on which pages a regular user runs
    # day-to-day vs. which are a developer/reviewer's own inspection tools.
    with gr.Sidebar(position="left", open=True, width=250, label="Navigate"):
        gr.HTML(value=nav_section_label_html("Workspace", ACCENT))
        nav_buttons = {"overview": gr.Button(
            "Overview", size="sm", elem_classes=["nav-btn", "icon-home"]
        )}
        for a in AGENTS:
            # `nav_label` for user-friendly names (e.g. "Activity Scan" instead of "Log Monitor")
            # while keeping internal agent names (key) unchanged for hackathon requirements.
            nav_buttons[a["key"]] = gr.Button(
                f'{a["num"]}. {a["nav_label"]}', size="sm",
                elem_classes=["nav-btn", f'icon-{a["key"]}'],
            )
        nav_buttons["report"] = gr.Button(
            "Full Report", size="sm", elem_classes=["nav-btn", "icon-report"]
        )
        gr.HTML(value=nav_section_label_html(
            "Admin / Reviewer", ADMIN_ACCENT,
            subtitle="No login gates this - just a visual grouping.",
        ))
        nav_buttons["self_improvement"] = gr.Button(
            "Evaluations", size="sm", elem_classes=["nav-btn", "icon-shield", "nav-btn-admin"]
        )

    pages = {}
    card_buttons = {}
    agent_tracker = {}
    agent_display = {}
    agent_output = {}
    agent_filter = {}
    next_action_buttons = {}
    agent_progress = {}
    agent_followup = {}

    IDLE_TRACKER = pipeline_tracker_html(
        caption="Pipeline idle - start a run from the Overview page to watch it execute live."
    )

    # ---- overview page: the ONLY place the pipeline is launched ----
    # Any run executes the whole graph regardless of which page starts it, so
    # the old per-agent upload forms were five copies of one thing and implied
    # agents could run independently. One launch point, five result views.
    # Reading order top-to-bottom tells a story: what this IS (agent cards) ->
    # how to run it (tabs) -> what's happening (tracker) -> what came out
    # (KPI tiles + status). Results used to sit above the button that produces
    # them, which read backwards.
    with gr.Column(visible=True) as pages["overview"]:
        gr.Markdown("## Security Operations Overview")

        gr.Markdown("### Agents in this pipeline")
        # Grid (not Gradio's flex Row): with 5 cards the flex row wraps onto
        # two lines and `equal_height` only equalises *within* a line, so the
        # cards came out 177/154/132px. See #agent-card-grid in CUSTOM_CSS.
        with gr.Row(elem_id="agent-card-grid"):
            for a in AGENTS:
                with gr.Column(elem_classes=["agent-card", f"ac-{a['key']}"]):
                    gr.Markdown(
                        f"### {icon_html(a['key'], size=18)} {a['num']}. {a['title']}\n{a['card_blurb']}",
                        sanitize_html=False,
                    )
                    # CTA names the ARTIFACT, not the agent: the card header
                    # already says the agent's name, so "View Log Monitor Agent →"
                    # under "1. Log Monitor Agent" was the same words twice and
                    # said nothing about what you'd actually see.
                    card_buttons[a["key"]] = gr.Button(a["cta"], size="sm")

        with gr.Tab("Quick Demo"):
            gr.Markdown(
                "One click, no files needed - runs the bundled sample data (a real SSH "
                "brute-force + port scan + recon log, a vulnerable Dockerfile, and an "
                "outdated requirements.txt) through all 5 agents. Takes about 90 seconds - "
                "the tracker below shows live progress, agent by agent."
            )
            demo_btn = gr.Button(DEMO_BTN_LABEL, variant="primary",
                                  elem_id="run-demo-btn", elem_classes="action-btn")

        with gr.Tab("Analyze Your Own Files"):
            gr.Markdown(
                "**Every field is optional** - anything you leave blank falls back to the "
                "bundled sample for that input, so you can try one file at a time."
            )
            gr.HTML(value=file_help_html())
            file_comps = {}
            with gr.Row():
                file_comps["log"] = gr.File(label=FILE_LABELS["log"])
                file_comps["dockerfile"] = gr.File(label=FILE_LABELS["dockerfile"])
            with gr.Row():
                file_comps["requirements"] = gr.File(label=FILE_LABELS["requirements"])
                file_comps["policy"] = gr.File(label=FILE_LABELS["policy"])
            analyze_btn = gr.Button(ANALYZE_BTN_LABEL, variant="primary",
                                     elem_id="run-analyze-btn", elem_classes="action-btn")

        # Progress sits directly under the controls that start it, and results
        # under progress - so the page reads in the order things happen.
        # Hidden until a run actually starts: an idle tracker (5 grey "idle"
        # nodes) and 4 dashed KPI tiles are pure noise to a first-time visitor
        # who hasn't clicked anything yet - they describe a run that doesn't
        # exist. `overview_progress` toggles to visible in the first stream
        # yield (see _stream_snapshot) and then stays visible for the rest of
        # the session, same as every other run-triggered update.
        with gr.Column(visible=False) as overview_progress:
            overview_tracker = gr.HTML(value=IDLE_TRACKER)
            overview_dashboard = gr.HTML(value=dashboard_html())

    # ---- one page per agent: pure results, no run controls ----
    for a in AGENTS:
        key = a["key"]
        with gr.Column(visible=False) as pages[key]:
            # Page heading: friendly name (nav_label) + technical transparency (agent title)
            agent_title = a["title"]
            gr.Markdown(
                f"## {icon_html(a['key'], size=20)} {a['nav_label']} (powered by {agent_title})\n{a['page_blurb']}",
                sanitize_html=False, elem_classes="page-heading",
            )
            if key == "policy_checker":
                # The one page whose whole vocabulary (NIST/ISO/SOC 2, control
                # IDs) is meaningless to a first-timer. Stated outright rather
                # than tucked in a tooltip - tooltips don't exist on a projector.
                # Always visible: it's orientation, not a run result.
                gr.HTML(value=framework_primer_html())
            # Tracker + severity filter describe a run that doesn't exist yet
            # pre-run (5 idle nodes, a filter with nothing to filter) - same
            # noise the Overview tracker/KPI fix already addressed, just
            # missed on the per-agent pages. Hidden until a run starts, same
            # reveal-on-first-yield mechanism as overview_progress.
            with gr.Column(visible=False) as agent_progress[key]:
                agent_tracker[key] = gr.HTML(value=IDLE_TRACKER)
                if key in FILTERABLE_AGENTS:
                    agent_filter[key] = gr.Radio(
                        choices=["All", "Critical", "High", "Medium", "Low"], value="All",
                        label="Filter by severity", elem_classes="severity-filter",
                    )
            # The one thing that SHOULD be visible pre-run: either the
            # placeholder telling the user how to start one, or (post-run)
            # the real findings.
            agent_display[key] = gr.HTML(value=AGENT_DISPLAY_PLACEHOLDER)
            # Narrative + next-step button are equally premature pre-run -
            # there's no narrative to read and no "next" page with real
            # content yet either. Same hidden-until-run treatment.
            with gr.Column(visible=False) as agent_followup[key]:
                with gr.Accordion("🤖 AI Narrative Summary", open=False):
                    agent_output[key] = gr.Textbox(show_label=False, lines=8, value=NARRATIVE_PLACEHOLDER)
                # Every result page ends with exactly one next move, mirroring
                # the real DAG (log_monitor/vuln_scanner -> threat_intel ->
                # incident_response -> policy_checker -> report) rather than
                # an arbitrary "go to Action Plan" everywhere - findings as
                # raw as these deserve a next step that's actually downstream
                # of them, not a repeat of the Overview triage message.
                next_action_buttons[key] = gr.Button(
                    a["next_label"], variant="secondary", elem_classes="action-btn"
                )
            if key == "policy_checker":
                # Independent of run state - rebuilding the embedding index is
                # an admin action a user might want before ever running the
                # pipeline, not a "result" gated on having one.
                with gr.Accordion("⚙️ Policy Index", open=False):
                    gr.Markdown(
                        "Rebuilds the semantic search index over the full NIST SP 800-53 catalog + policy "
                        "excerpt using the embedding provider/model configured in the right sidebar. "
                        "This is a one-time (or rare) operation - it does NOT run automatically on every "
                        "pipeline execution, since the underlying corpus barely ever changes. A policy "
                        "doc you upload is embedded per-run and doesn't need a rebuild."
                    )
                    policy_index_status = gr.HTML(value=policy_index_status_html())
                    rebuild_index_btn = gr.Button("🔄 Rebuild Index", variant="secondary",
                                                   elem_classes="action-btn")

    # ---- full report page ----
    with gr.Column(visible=False) as pages["report"]:
        with gr.Row():
            gr.Markdown(f"## {icon_html('report', size=20)} Full Report", sanitize_html=False)
            report_download = gr.DownloadButton(
                "⬇️ Download report.md", value=REPORT_PATH, size="sm", scale=0, interactive=False
            )
        report_out = gr.Markdown(value="_Run the pipeline from the Overview page to generate the report._")

    # ---- self-improvement dashboard: evals, not a standalone CLI artifact ----
    # Deliberately its own top-level page (not a hidden dev tool) - a hackathon
    # reviewer should be able to click "Run Evals" and see this app grade its
    # own retrieval accuracy and reasoning quality, the same way they can click
    # "Run Quick Demo" and see the pipeline itself.
    with gr.Column(visible=False) as pages["self_improvement"]:
        gr.Markdown(f"## {icon_html('shield', size=20)} Evaluation Dashboard", sanitize_html=False)
        gr.HTML(value='<p class="subdued-text" style="margin-top:-8px;">Self-improvement: how this app '
                       'measures and improves its own accuracy over time.</p>')
        gr.HTML(value=self_improvement_primer_html())
        _initial_history, _initial_history_mode = load_eval_history()
        # Persistence banner sits ABOVE the button, deliberately - whether history
        # survives a redeploy is a property of the deployment's configuration, not
        # of any one run, so a reviewer should see it before clicking anything.
        eval_storage_status = gr.HTML(value=eval_storage_status_html(_initial_history_mode))
        eval_run_btn = gr.Button("▶ Run Evals", variant="primary", elem_classes="action-btn")
        eval_progress = gr.HTML(value="")
        eval_tiles = gr.HTML(value=EVAL_RUN_PLACEHOLDER)
        eval_cases = gr.HTML(value="")
        gr.Markdown("### Run history")
        eval_history = gr.HTML(value=eval_history_html(_initial_history, _initial_history_mode))

    # ---- wiring: one fixed output order shared by every run button ----
    # MUST exactly match _stream_snapshot()'s yield order.
    STREAM_OUTPUTS = [topbar_health, ai_chip_btn, policy_chip_btn, overview_dashboard, overview_tracker]
    for a in AGENTS:
        key = a["key"]
        STREAM_OUTPUTS.extend([agent_tracker[key], agent_display[key], agent_output[key]])
    for a in AGENTS:
        key = a["key"]
        STREAM_OUTPUTS.extend([agent_progress[key], agent_followup[key]])
    STREAM_OUTPUTS.extend([report_out, report_download, pipeline_state, demo_btn, analyze_btn])
    STREAM_OUTPUTS.append(overview_progress)

    # Two launch points, both on Overview, both streaming into every page.
    demo_btn.click(fn=run_quick_demo_stream, inputs=settings_inputs, outputs=STREAM_OUTPUTS)
    analyze_btn.click(
        fn=run_and_render_stream,
        inputs=[file_comps["log"], file_comps["dockerfile"],
                file_comps["requirements"], file_comps["policy"]] + settings_inputs,
        outputs=STREAM_OUTPUTS,
    )

    for key, radio in agent_filter.items():
        radio.change(fn=make_severity_filter_fn(key), inputs=[radio, pipeline_state],
                     outputs=agent_display[key])

    # Both handlers also refresh the topbar's Policy chip - previously only
    # the Compliance Check page's own status text updated, so the topbar chip
    # could sit on a stale "not indexed"/"rebuild needed" reading even right
    # after a rebuild fixed it.
    policy_status_outputs = [policy_index_status, topbar_health, policy_chip_btn]
    for comp in embedding_settings_inputs:
        comp.change(fn=apply_embedding_settings, inputs=embedding_settings_inputs + [pipeline_state],
                    outputs=policy_status_outputs)
    rebuild_index_btn.click(fn=rebuild_policy_index, inputs=embedding_settings_inputs + [pipeline_state],
                             outputs=policy_status_outputs)

    for comp in notification_settings_inputs:
        comp.change(fn=apply_notification_settings, inputs=notification_settings_inputs, outputs=notify_status)

    demo.load(fn=lambda: deploy_key_hint_html(IS_DEPLOYED, llm.current_provider()), outputs=deploy_key_hint)

    def _initial_model_choices():
        models = llm.list_openrouter_models()
        default = "openai/gpt-4o-mini" if "openai/gpt-4o-mini" in models else models[0]
        return gr.update(choices=models, value=default, interactive=True)

    demo.load(fn=_initial_model_choices, outputs=model_dropdown)

    eval_run_btn.click(
        fn=run_evals_and_render,
        outputs=[eval_run_btn, eval_progress, eval_storage_status, eval_tiles, eval_cases, eval_history],
    )

    # ---- page navigation ----
    PAGE_KEYS = ["overview"] + [a["key"] for a in AGENTS] + ["report", "self_improvement"]
    PAGE_LIST = [pages[k] for k in PAGE_KEYS]

    def make_nav_fn(target):
        def _fn():
            return [gr.update(visible=(k == target)) for k in PAGE_KEYS]
        return _fn

    for key, btn in nav_buttons.items():
        btn.click(fn=make_nav_fn(key), outputs=PAGE_LIST)
    for key, btn in card_buttons.items():
        btn.click(fn=make_nav_fn(key), outputs=PAGE_LIST)
    # Topbar Policy chip: same navigate-on-click pattern as the nav/card
    # buttons above - jumps to Compliance Check, where Rebuild Index lives,
    # instead of leaving a "not indexed" chip that a user has to go hunting
    # through the left nav to act on.
    policy_chip_btn.click(fn=make_nav_fn("policy_checker"), outputs=PAGE_LIST)
    # Next-action buttons navigate to a DIFFERENT page than the one they live
    # on (unlike nav/card buttons, which navigate to their own key) - each
    # agent's "next_key" points at its real downstream consumer in the DAG.
    for a in AGENTS:
        next_action_buttons[a["key"]].click(fn=make_nav_fn(a["next_key"]), outputs=PAGE_LIST)


THEME = gr.themes.Base(
    primary_hue="cyan",
    secondary_hue="blue",
    neutral_hue="slate",
    font=[gr.themes.GoogleFont("IBM Plex Sans"), "ui-sans-serif", "system-ui", "sans-serif"],
    font_mono=[gr.themes.GoogleFont("IBM Plex Mono"), "ui-monospace", "Consolas", "monospace"],
)

if __name__ == "__main__":
    demo.launch(
        theme=THEME, css=CUSTOM_CSS, footer_links=["gradio", "settings"],
        server_name="0.0.0.0", server_port=int(os.environ.get("PORT", 7860)),
    )
