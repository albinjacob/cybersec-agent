"""
Report Builder
--------------
Aggregates all agent outputs into a single markdown report - the "traceable,
actionable output" the hackathon topic calls for.
"""

from datetime import datetime


def build_report(state) -> str:
    lm = state["log_monitor"]
    ti = state["threat_intel"]
    vs = state["vuln_scanner"]
    ir = state["incident_response"]
    pc = state["policy_checker"]
    notify = state.get("notify")

    n_critical = sum(1 for f in lm["findings"] + vs["findings"] if f["severity"] == "CRITICAL")
    n_high = sum(1 for f in lm["findings"] + vs["findings"] if f["severity"] == "HIGH")
    n_medium = sum(1 for f in lm["findings"] + vs["findings"] if f["severity"] == "MEDIUM")
    n_low = sum(1 for f in lm["findings"] + vs["findings"] if f["severity"] == "LOW")

    modes = {a["agent"]: a["reasoning_mode"] for a in [lm, ti, vs, ir, pc]}

    # Executive verdict: worst severity present drives the headline, so a reader
    # gets the overall posture before any section detail.
    if n_critical:
        risk_level = "CRITICAL"
    elif n_high:
        risk_level = "ELEVATED"
    elif n_medium:
        risk_level = "MODERATE"
    elif n_low:
        risk_level = "LOW"
    else:
        risk_level = "ALL CLEAR"
    total = n_critical + n_high + n_medium + n_low

    lines = []
    lines.append("# Cybersecurity AI Agent - Incident & Compliance Report")
    lines.append(f"_Generated {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}_")
    lines.append("")
    lines.append("## Executive Summary")
    lines.append(f"**Overall risk: {risk_level}** — {total} issue(s) detected across logs and dependencies "
                 f"({n_critical} critical, {n_high} high, {n_medium} medium, {n_low} low).")
    if n_critical or n_high:
        lines.append("Start with **section 4 (Incident Response — Action Plan)** for prioritized remediation, "
                     "then **section 5 (Policy Checker)** for the affected compliance controls.")
    if notify and notify.get("mode") == "sent":
        lines.append(f"📣 {notify['sent_count']} alert(s) dispatched to Slack for the findings above.")
    lines.append(f"_Reasoning mode per agent: {modes}_")
    lines.append("")
    lines.append("---")
    lines.append("## 1. Log Monitor Agent")
    lines.append(lm["summary"])
    lines.append("")
    lines.append("## 2. Threat Intelligence Agent")
    lines.append(ti["summary"])
    lines.append("")
    lines.append("## 3. Vulnerability Scanner Agent")
    lines.append(vs["summary"])
    lines.append("")
    lines.append("## 4. Incident Response Agent - Action Plan")
    lines.append(ir["summary"])
    for item in ir.get("plan", []):
        c = item.get("council")
        if c and c.get("mode") == "live":
            tag = "AGREE" if c["agreement"] else "DISAGREE"
            lines.append(f"\n> 🏛️ **Model Council** ({tag}) on \"{item['issue']}\": {c['judge_verdict']}")
    lines.append("")
    lines.append("## 5. Policy Checker Agent - Compliance Gaps")
    lines.append(pc["summary"])
    lines.append("")
    lines.append("---")
    lines.append("_This report was produced by a 5-agent pipeline (Log Monitor -> Vulnerability Scanner -> "
                  "Threat Intelligence -> Incident Response -> Policy Checker) plus a terminal Notify action "
                  "stage, orchestrated as a LangGraph directed graph. See README.md for which integrations "
                  "ran live vs. fell back._")
    return "\n".join(lines)
