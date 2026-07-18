"""
Notification / Action Stage
----------------------------
The pipeline's terminal action: dispatches an alert (Slack + email) when a
finding at or above the configured severity threshold is present. This is
deliberately NOT a reasoning agent - it does fixed routing/formatting over
data the other agents already produced, so it never calls `llm.reason()` and
is drawn in the UI as a distinct "action" stage rather than a 6th agent.

BYOK: `configure(...)` lets the UI set a Slack webhook, Gmail SMTP
credentials, a recipient list, and which severities trigger an alert, mirroring
the override/env-fallback pattern in `agents/llm.py`. With nothing configured,
`run()` still completes and reports a labeled "skipped" mode - the pipeline
never hard-fails because notifications aren't set up.
"""

import os
import smtplib
from email.message import EmailMessage

from dotenv import load_dotenv
load_dotenv()

SLACK_WEBHOOK_URL = os.environ.get("SLACK_WEBHOOK_URL")
SMTP_USER = os.environ.get("SMTP_USER")
SMTP_PASS = os.environ.get("SMTP_PASS")
ALERT_EMAIL_TO = os.environ.get("ALERT_EMAIL_TO")  # comma-separated
NOTIFY_SEVERITIES = os.environ.get("NOTIFY_SEVERITIES")  # comma-separated, e.g. "CRITICAL,HIGH"

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}

# BYOK overrides set via configure(); None/[] means "fall back to env"
_RUNTIME = {
    "slack_webhook": None,
    "smtp_user": None,
    "smtp_pass": None,
    "recipients": [],
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


def configure(slack_webhook=None, smtp_user=None, smtp_pass=None, recipients=None, severities=None):
    """
    Set BYOK overrides from the UI. `recipients` accepts a list or a
    comma/newline-separated string. `severities` accepts a list/set or a
    comma-separated string of severity names; normalized to uppercase.
    Passing an empty/None value for a field clears that override (falls back
    to the matching env var).
    """
    _RUNTIME["slack_webhook"] = slack_webhook or None
    _RUNTIME["smtp_user"] = smtp_user or None
    _RUNTIME["smtp_pass"] = smtp_pass or None
    _RUNTIME["recipients"] = parse_list(recipients)
    sev_list = parse_list(severities)
    _RUNTIME["severities"] = {s.upper() for s in sev_list} if sev_list else None


def _active_slack_webhook():
    return _RUNTIME["slack_webhook"] or SLACK_WEBHOOK_URL


def _active_smtp_creds():
    return _RUNTIME["smtp_user"] or SMTP_USER, _RUNTIME["smtp_pass"] or SMTP_PASS


def _active_recipients():
    return _RUNTIME["recipients"] or parse_list(ALERT_EMAIL_TO)


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
    import requests
    resp = requests.post(webhook, json={"text": text}, timeout=8)
    resp.raise_for_status()


def _send_email(user, password, recipients, subject, body):
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = user
    msg["To"] = ", ".join(recipients)
    msg.set_content(body)
    with smtplib.SMTP_SSL("smtp.gmail.com", 465, timeout=10) as server:
        server.login(user, password)
        server.send_message(msg)


def run(state):
    log_findings = state["log_monitor"]["findings"]
    vuln_findings = state["vuln_scanner"]["findings"]
    plan = state["incident_response"]["plan"]

    severities = _active_severities()
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
            "recipients_count": 0,
            "summary": f"No findings at or above the configured severities ({', '.join(base['severities'])}) - nothing to dispatch.",
        }

    worst = findings[0]["severity"]
    webhook = _active_slack_webhook()
    smtp_user, smtp_pass = _active_smtp_creds()
    recipients = _active_recipients()

    channels = []
    if not webhook:
        channels.append({"channel": "slack", "status": "not-configured", "detail": "No Slack webhook URL configured"})
    if not (smtp_user and smtp_pass and recipients):
        channels.append({"channel": "email", "status": "not-configured", "detail": "Gmail credentials or recipients not configured"})

    if not webhook and not (smtp_user and smtp_pass and recipients):
        return {
            **base,
            "mode": "skipped",
            "channels": channels,
            "sent_count": 0,
            "recipients_count": 0,
            "summary": f"{len(findings)} finding(s) at {worst}+ would trigger an alert, "
                       f"but no Slack webhook or Gmail credentials are configured - skipped.",
        }

    text = _format_message(findings, plan, worst)
    sent_count = 0

    if webhook:
        try:
            _send_slack(webhook, text)
            channels.append({"channel": "slack", "status": "sent", "detail": "Delivered to configured webhook"})
            sent_count += 1
        except Exception as e:
            channels.append({"channel": "slack", "status": "failed", "detail": str(e)})

    if smtp_user and smtp_pass and recipients:
        try:
            _send_email(smtp_user, smtp_pass, recipients,
                        subject=f"[CyberSec AI Agent] {worst} risk detected ({len(findings)} finding(s))",
                        body=text)
            channels.append({"channel": "email", "status": "sent", "detail": f"Delivered to {len(recipients)} recipient(s)"})
            sent_count += 1
        except Exception as e:
            channels.append({"channel": "email", "status": "failed", "detail": str(e)})

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
        "recipients_count": len(recipients),
        "summary": summary,
    }
