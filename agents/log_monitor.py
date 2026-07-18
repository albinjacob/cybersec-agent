"""
Log Monitor Agent
------------------
Reads system/network/web logs and detects unusual activity: SSH brute force,
privilege escalation, port scanning, and web recon patterns. Rule-based
detection (regex + simple stateful counting) does the heavy lifting for
precision; the LLM call (or mock) is used to turn raw hits into a narrative
summary an analyst can read quickly.
"""

import re
from collections import defaultdict
from .llm import reason, get_last_fallback_reason

FAILED_SSH_RE = re.compile(r"Failed password for (\w+) from ([\d.]+) port (\d+)")
ACCEPTED_SSH_RE = re.compile(r"Accepted (password|publickey) for (\w+) from ([\d.]+)")
UFW_BLOCK_RE = re.compile(r"\[UFW BLOCK\].*SRC=([\d.]+) DST=([\d.]+).*DPT=(\d+)")
SUDO_RE = re.compile(r"sudo\[\d+\]:\s+(\w+) : .*USER=root ; COMMAND=(.+)")
NGINX_RECON_RE = re.compile(
    r'"(GET|POST) (.+?) HTTP/1\.\d" (\d+)'
)
RECON_PATH_HINTS = ["../", "wp-admin", ".env", "phpmyadmin", "/etc/passwd"]


def parse_log(path: str):
    findings = []
    failed_counts = defaultdict(list)
    scan_ports = defaultdict(set)

    with open(path) as f:
        lines = f.readlines()

    for line in lines:
        m = FAILED_SSH_RE.search(line)
        if m:
            user, ip, port = m.groups()
            failed_counts[ip].append((user, line.strip()))
            continue

        m = ACCEPTED_SSH_RE.search(line)
        if m:
            method, user, ip = m.groups()
            if method == "password" and user in ("root", "admin"):
                findings.append({
                    "type": "privileged_password_login",
                    "severity": "HIGH",
                    "detail": f"Password-based (not key-based) login for privileged user '{user}' from {ip}",
                    "evidence": line.strip(),
                })
            continue

        m = UFW_BLOCK_RE.search(line)
        if m:
            src, dst, port = m.groups()
            scan_ports[src].add(port)
            continue

        m = SUDO_RE.search(line)
        if m:
            user, cmd = m.groups()
            if "chmod 777" in cmd:
                findings.append({
                    "type": "insecure_permission_change",
                    "severity": "MEDIUM",
                    "detail": f"User '{user}' set world-writable permissions (chmod 777) on a web-accessible path",
                    "evidence": line.strip(),
                })
            continue

        m = NGINX_RECON_RE.search(line)
        if m:
            _, path_hit, status = m.groups()
            if any(hint in path_hit for hint in RECON_PATH_HINTS):
                findings.append({
                    "type": "recon_probe",
                    "severity": "MEDIUM",
                    "detail": f"Reconnaissance probe against '{path_hit}' (status {status})",
                    "evidence": line.strip(),
                })

    # Brute force: >=3 failed attempts from same IP against privileged accounts
    for ip, attempts in failed_counts.items():
        if len(attempts) >= 3:
            users = sorted(set(u for u, _ in attempts))
            findings.append({
                "type": "ssh_bruteforce",
                "severity": "CRITICAL",
                "detail": f"{len(attempts)} failed SSH logins from {ip} targeting privileged accounts {users}",
                "evidence": attempts[-1][1],
                "source_ip": ip,
            })

    # Port scan: same source hitting >=3 distinct ports blocked by firewall
    for ip, ports in scan_ports.items():
        if len(ports) >= 3:
            findings.append({
                "type": "port_scan",
                "severity": "HIGH",
                "detail": f"Port scan from {ip} against ports {sorted(ports, key=int)}",
                "evidence": f"UFW blocked {len(ports)} distinct ports from {ip}",
                "source_ip": ip,
            })

    return findings


def _mock_summary(findings):
    if not findings:
        return "No suspicious activity detected in the supplied log window."
    lines = ["Log Monitor Agent - detected activity summary:"]
    for f in sorted(findings, key=lambda x: {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}[x["severity"]]):
        lines.append(f"- [{f['severity']}] {f['type']}: {f['detail']}")
    return "\n".join(lines)


def run(log_path: str):
    findings = parse_log(log_path)
    system_prompt = (
        "You are a SOC log analyst. Given structured findings extracted from a "
        "server log, write a concise, prioritized narrative summary for an incident "
        "responder, ordered by severity."
    )
    user_prompt = f"Findings:\n{findings}"
    summary, mode = reason(system_prompt, user_prompt, mock_fn=lambda: _mock_summary(findings))
    return {
        "agent": "log_monitor",
        "findings": findings,
        "summary": summary,
        "reasoning_mode": mode,
        "reasoning_fallback_reason": get_last_fallback_reason() if mode == "mock" else None,
    }
