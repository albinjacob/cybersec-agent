"""
Golden test cases for the evals framework - hand-written, no LLM involved in
authoring them, so they're a fixed, trustworthy yardstick.

RETRIEVAL_CASES check the Policy Checker RAG: does a given finding retrieve a
control from the right NIST 800-53 family? `expected_prefixes` is a list of
acceptable control-id prefixes (a finding can legitimately map to more than
one reasonable family).

REASONING_CASES check LLM-as-judge-scored summary quality: a small finding set
plus the rubric the judge should apply.
"""

RETRIEVAL_CASES = [
    dict(
        finding_text="4 failed SSH logins from 203.0.113.7 targeting privileged accounts ['root', 'admin']",
        expected_prefixes=["AC-7", "IA-2", "IA-5"],
        note="SSH brute force should map to access-control lockout or authenticator management",
    ),
    dict(
        finding_text="Password-based (not key-based) login for privileged user 'root' from 203.0.113.7",
        expected_prefixes=["IA-2", "IA-5", "AC-2"],
        note="Privileged password login should map to authenticator/account management",
    ),
    dict(
        finding_text="Port scan from 198.51.100.4 against ports [22, 3389, 6379, 27017]",
        expected_prefixes=["SC-7", "SI-4", "AC-4"],
        note="Port scan should map to boundary protection or system monitoring",
    ),
    dict(
        finding_text="Reconnaissance probe against '/.env' (status 404)",
        expected_prefixes=["SC-7", "SI-4", "RA-5"],
        note="Recon probe should map to boundary protection, monitoring, or vulnerability scanning",
    ),
    dict(
        finding_text="User 'www-data' set world-writable permissions (chmod 777) on a web-accessible path",
        expected_prefixes=["CM-6", "AC-6"],
        note="Insecure permission change should map to configuration settings or least privilege",
    ),
    dict(
        finding_text="No USER directive found - container will run as root by default, violating "
                      "least-privilege configuration management practices.",
        expected_prefixes=["CM-6", "AC-6"],
        note="Container running as root should map to configuration settings or least privilege",
    ),
    dict(
        finding_text="requests==2.6.0: known remote code execution vulnerability in HTTP header parsing",
        expected_prefixes=["SI-2", "RA-5"],
        note="A dependency CVE should map to flaw remediation or vulnerability scanning",
    ),
    dict(
        finding_text="Base image pinned to a specific old minor version (e.g. python:3.9) rather than a "
                      "maintained/patched tag - increases exposure to base-layer CVEs.",
        expected_prefixes=["SI-2", "CM-8"],
        note="Outdated base image should map to flaw remediation or component inventory",
    ),
]

REASONING_CASES = [
    dict(
        name="ssh_bruteforce_only",
        findings=[
            {"type": "ssh_bruteforce", "severity": "CRITICAL",
             "detail": "6 failed SSH logins from 203.0.113.7 targeting privileged accounts ['root']"},
        ],
        rubric=(
            "Must mention blocking/rate-limiting the source IP and moving to key-based auth or MFA. "
            "Must NOT invent a CVE ID, a specific product name, or a company name not present above."
        ),
    ),
    dict(
        name="port_scan_and_dependency_cve",
        findings=[
            {"type": "port_scan", "severity": "HIGH",
             "detail": "Port scan from 198.51.100.4 against ports [22, 6379, 27017]"},
            {"id": "CVE-2021-44228", "severity": "CRITICAL", "source": "dependency_scan",
             "detail": "log4j-core==2.14.1: remote code execution via JNDI lookup"},
        ],
        rubric=(
            "Must treat the CVE-2021-44228 finding as more urgent than the port scan. Must NOT invent "
            "a different CVE ID or claim the port scan alone is a code-execution vulnerability."
        ),
    ),
    dict(
        name="container_root_only",
        findings=[
            {"id": "container-runs-as-root", "severity": "HIGH", "source": "dockerfile_scan",
             "detail": "No USER directive found - container will run as root by default."},
        ],
        rubric=(
            "Must recommend adding a non-root USER directive. Must NOT claim this finding involves "
            "a network exposure or a specific CVE, since none was given."
        ),
    ),
    dict(
        name="no_findings",
        findings=[],
        rubric=(
            "Must state that no issues were found. Must NOT invent a finding, severity, or "
            "recommendation that implies something was detected."
        ),
    ),
    dict(
        name="mixed_low_medium",
        findings=[
            {"type": "recon_probe", "severity": "MEDIUM",
             "detail": "Reconnaissance probe against '/wp-admin' (status 404)"},
            {"id": "unpinned-apt-packages", "severity": "LOW", "source": "dockerfile_scan",
             "detail": "apt-get install used without version pins - build is non-reproducible."},
        ],
        rubric=(
            "Must correctly describe both findings as low urgency relative to a CRITICAL. Must NOT "
            "escalate either finding to CRITICAL/HIGH severity language."
        ),
    ),
]
