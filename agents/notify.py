"""
Notification / Action Stage
----------------------------
The pipeline's terminal action: dispatches a Slack alert when a finding at or
above the configured severity threshold is present. This is deliberately NOT
a reasoning agent - it does fixed routing/formatting over data the other
agents already produced, so it never calls `llm.reason()` and is drawn in the
UI as a distinct "action" stage rather than a 6th agent.

BYOK: `configure(...)` lets the UI set a Slack webhook and which severities
trigger an alert, mirroring the override/env-fallback pattern in
`agents/llm.py`. With nothing configured, `run()` still completes and reports
a labeled "skipped" mode - the pipeline never hard-fails because
notifications aren't set up.
"""

import os

from dotenv import load_dotenv
load_dotenv()

SLACK_WEBHOOK_URL = os.environ.get("SLACK_WEBHOOK_URL")
NOTIFY_SEVERITIES = os.environ.get("NOTIFY_SEVERITIES")  # comma-separated, e.g. "CRITICAL,HIGH"

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}

# BYOK overrides set via configure(); None/[] means "fall back to env"
_RUNTIME = {
    "slack_webhook": None,
    "severities": None,
}


def parse_list(value):
    """Accepts a list, or a comma/newline-separated string; returns a
    de-duplicated list of stripped, non-empty entries, order preserved."""
    if not value:
        return []
    if isinstance(value, str):
        parts = [p.strip() for p in value.replace("\n", ",").split(",")]
    else:
        parts = [str(p).strip() for p in value]
    seen = set()
    out = []
    for p in parts:
        if p and p not in seen:
            seen.add(p)
            out.append(p)
    return out


def configure(slack_webhook=None, severities=None):
    """
    Set BYOK overrides from the UI. `severities` accepts a list/set or a
    comma-separated string of severity names; normalized to uppercase.
    Passing an empty/None value for a field clears that override (falls back
    to the matching env var).
    """
    _RUNTIME["slack_webhook"] = slack_webhook or None
    sev_list = parse_list(severities)
    _RUNTIME["severities"] = {s.upper() for s in sev_list} if sev_list else None


def _active_slack_webhook():
    return _RUNTIME["slack_webhook"] or SLACK_WEBHOOK_URL


def _active_severities():
    if _RUNTIME["severities"]:
        return _RUNTIME["severities"]
    env_sevs = parse_list(NOTIFY_SEVERITIES)
    return {s.upper() for s in env_sevs} if env_sevs else {"CRITICAL"}


def _triggering_findings(log_findings, vuln_findings, severities):
    findings = [f for f in log_findings + vuln_findings if f.get("severity") in severities]
    findings.sort(key=lambda f: SEVERITY_ORDER.get(f.get("severity"), 4))
    return findings


def _remediation_steps_for(finding, plan):
    """Look up the incident-response plan item matching this finding, by the
    same finding_key each plan item was built from (type for log findings,
    id for vuln findings) - so the alert body reuses IR's steps instead of
    re-deriving them."""
    key = finding.get("type") or finding.get("id")
    for item in plan:
        if item.get("finding_key") == key and item.get("issue") == finding.get("detail"):
            return item.get("steps", [])
    return []


def _format_message(findings, plan, risk_level):
    lines = [f"[{risk_level}] CyberSec AI Agent detected {len(findings)} alert-worthy finding(s):"]
    for f in findings:
        detail = f.get("detail", "")
        origin = f.get("source_ip") or f.get("evidence") or f.get("package") or ""
        origin_suffix = f" ({origin})" if origin else ""
        lines.append(f"\n- [{f.get('severity')}] {detail}{origin_suffix}")
        steps = _remediation_steps_for(f, plan)
        for step in steps[:2]:
            lines.append(f"    -> {step}")
    return "\n".join(lines)


def _send_slack(webhook, text):
    # The field promises "Slack webhook", so hold it to that: an arbitrary
    # user-supplied URL POSTed from the server is a server-side request
    # forgery primitive (internal endpoints, cloud metadata services) with
    # the findings payload attached. The failure surfaces through the same
    # per-channel "failed" status any other send error does.
    from urllib.parse import urlparse
    parsed = urlparse(webhook)
    if parsed.scheme != "https" or parsed.hostname != "hooks.slack.com":
        raise ValueError("Webhook rejected: must be an https://hooks.slack.com/... URL")
    import requests
    resp = requests.post(webhook, json={"text": text}, timeout=8)
    resp.raise_for_status()


def run(state):
    log_findings = state["log_monitor"]["findings"]
    vuln_findings = state["vuln_scanner"]["findings"]
    plan = state["incident_response"]["plan"]

    # Per-run config carried in the graph state wins over the session-global
    # configure() override - module state is shared by every browser session
    # in the process, so one user's webhook must never receive another user's
    # alerts (same reasoning as llm.reason()'s per-request config).
    run_cfg = state.get("notify_config") or {}
    severities = run_cfg.get("severities") or _active_severities()
    findings = _triggering_findings(log_findings, vuln_findings, severities)

    base = {
        "agent": "notify",
        "severities": sorted(severities, key=lambda s: SEVERITY_ORDER.get(s, 4)),
    }

    if not findings:
        return {
            **base,
            "mode": "no-alert",
            "channels": [],
            "sent_count": 0,
            "summary": f"No findings at or above the configured severities ({', '.join(base['severities'])}) - nothing to dispatch.",
        }

    worst = findings[0]["severity"]
    webhook = run_cfg.get("slack_webhook") or _active_slack_webhook()

    if not webhook:
        return {
            **base,
            "mode": "skipped",
            "channels": [{"channel": "slack", "status": "not-configured", "detail": "No Slack webhook URL configured"}],
            "sent_count": 0,
            "summary": f"{len(findings)} finding(s) at {worst}+ would trigger an alert, "
                       f"but no Slack webhook is configured - skipped.",
        }

    text = _format_message(findings, plan, worst)
    channels = []
    sent_count = 0

    try:
        _send_slack(webhook, text)
        channels.append({"channel": "slack", "status": "sent", "detail": "Delivered to configured webhook"})
        sent_count += 1
    except Exception as e:
        channels.append({"channel": "slack", "status": "failed", "detail": str(e)})

    mode = "sent" if sent_count else "offline-fallback"
    summary = (
        f"Dispatched {len(findings)} {worst}+ finding(s) via {sent_count} channel(s)."
        if sent_count else
        f"{len(findings)} {worst}+ finding(s) matched, but every configured channel failed to send."
    )

    return {
        **base,
        "mode": mode,
        "channels": channels,
        "sent_count": sent_count,
        "summary": summary,
    }
