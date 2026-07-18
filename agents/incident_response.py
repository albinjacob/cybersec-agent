"""
Incident Response Agent
-----------------------
Takes the combined findings from Log Monitor, Threat Intel, and Vulnerability
Scanner, and produces a prioritized, step-by-step remediation plan.
"""

from . import council
from .llm import reason, get_last_fallback_reason

PLAYBOOKS = {
    "ssh_bruteforce": [
        "Block source IP at the firewall/WAF immediately.",
        "Force password reset + enforce key-based auth with MFA for the targeted accounts.",
        "Enable fail2ban or equivalent rate-limiting on sshd.",
        "Review auth logs for any successful login from the same source in the surrounding 24h window.",
    ],
    "privileged_password_login": [
        "Disable password authentication for privileged accounts; require SSH keys + MFA.",
        "Rotate credentials for the affected account.",
        "Audit sudoers / group membership for the account for unexpected grants.",
    ],
    "port_scan": [
        "Confirm firewall default-deny is enforced on all non-required ports.",
        "Add the scanning source IP to a watchlist / threat-intel blocklist.",
        "Verify no scanned service (e.g. Redis 6379, MongoDB 27017) is unintentionally exposed to the internet.",
    ],
    "recon_probe": [
        "Verify the probed paths (.env, wp-admin, etc.) don't exist or are not reachable.",
        "Add WAF rules to block path-traversal and common CMS-probe signatures.",
        "Confirm no secrets are committed or reachable at web-exposed paths.",
    ],
    "insecure_permission_change": [
        "Revert world-writable permissions; set least-privilege ownership on the affected path.",
        "Audit for any files dropped/modified while permissions were open.",
        "Add a config-drift monitor/alert for permission changes on sensitive paths.",
    ],
    "container-runs-as-root": [
        "Add a non-root USER directive to the Dockerfile and rebuild.",
        "Re-deploy with the updated image; verify running processes are non-root via `docker exec ... whoami`.",
    ],
    "outdated-base-image-tag": [
        "Pin base image to the latest patched tag (or a minimal distro like python:3.12-slim).",
        "Add automated base-image update scanning (e.g. Renovate/Dependabot) to CI.",
    ],
    "unpinned-apt-packages": [
        "Pin apt package versions or use a lockfile/multi-stage build for reproducibility.",
    ],
    "dependency_cve": [
        "Upgrade the flagged package to the patched version referenced in the CVE.",
        "Re-run the vulnerability scan post-upgrade to confirm remediation.",
        "Add dependency scanning as a CI gate (e.g. pip-audit, Trivy) to prevent regressions.",
    ],
}

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


def build_plan(log_findings, vuln_findings):
    plan = []
    for f in log_findings:
        steps = PLAYBOOKS.get(f["type"], ["Investigate and remediate per standard IR procedure."])
        plan.append({
            "issue": f["detail"],
            "severity": f["severity"],
            "source_agent": "log_monitor",
            "steps": steps,
            "finding_key": f["type"],
        })
    for f in vuln_findings:
        key = f["id"] if f["id"] in PLAYBOOKS else ("dependency_cve" if f["source"] == "dependency_scan" else None)
        steps = PLAYBOOKS.get(key, ["Investigate and remediate per standard IR procedure."])
        plan.append({
            "issue": f["detail"],
            "severity": f["severity"],
            "source_agent": "vuln_scanner",
            "steps": steps,
            "finding_key": f["id"],
        })
    plan.sort(key=lambda x: SEVERITY_ORDER.get(x["severity"], 4))
    return plan


def _attach_council(plan):
    """Second-opinion + judge review for CRITICAL items only - the added
    latency/cost of a 3-call council is bounded to the findings that actually
    warrant it. Non-CRITICAL items get council=None; unaffected otherwise."""
    for item in plan:
        if item["severity"] == "CRITICAL":
            item["council"] = council.run_council(item["issue"], item["steps"])
        else:
            item["council"] = None
    return plan


def _mock_summary(plan):
    lines = ["Incident Response Agent - prioritized action plan:"]
    for i, item in enumerate(plan, 1):
        lines.append(f"\n{i}. [{item['severity']}] {item['issue']}  (from {item['source_agent']})")
        for step in item["steps"]:
            lines.append(f"   - {step}")
    return "\n".join(lines)


def run(log_findings, vuln_findings):
    plan = build_plan(log_findings, vuln_findings)
    plan = _attach_council(plan)
    system_prompt = (
        "You are an incident response lead. Given a prioritized list of issues "
        "and remediation steps, write a clear, executive-readable action plan, "
        "grouping related issues and calling out anything time-critical."
    )
    user_prompt = f"Plan items:\n{plan}"
    summary, mode = reason(system_prompt, user_prompt, mock_fn=lambda: _mock_summary(plan))
    return {
        "agent": "incident_response",
        "plan": plan,
        "summary": summary,
        "reasoning_mode": mode,
        "reasoning_fallback_reason": get_last_fallback_reason() if mode == "mock" else None,
    }
