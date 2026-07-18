"""
Vulnerability Scanner Agent
---------------------------
Shells out to Trivy (https://github.com/aquasecurity/trivy) for real
scanning: `trivy config` for Dockerfile misconfigurations (root user,
missing HEALTHCHECK, etc.) and `trivy fs --scanners vuln` for dependency
CVEs in requirements.txt, against Trivy's live vulnerability database.

Falls back to the original static regex/local-dataset checks if the trivy
binary can't be located or the scan fails for any reason, so the pipeline
never hard-fails on a missing tool or a flaky first-run DB download. Either
way the return shape (`findings: [...]`, `dependency_names: [...]`) is
unchanged, so nothing downstream (Threat Intel, Incident Response, Policy
Checker, the UI) needs to know which path ran - `scan_mode` on the returned
dict records which one did ("trivy" or "static-fallback").
"""

import glob
import json
import os
import re
import shutil
import subprocess
import sys

from .llm import reason, get_last_fallback_reason
from .threat_intel import load_local_feed

SEVERITY_NORMALIZE = {
    "CRITICAL": "CRITICAL", "HIGH": "HIGH", "MEDIUM": "MEDIUM", "LOW": "LOW",
    "UNKNOWN": "LOW",
}

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _find_trivy():
    exe = shutil.which("trivy")
    if exe:
        return exe
    # scripts/render_build.sh installs trivy into ./bin (relative to the repo
    # root) rather than a system PATH location - a native-runtime build/start
    # command isn't guaranteed to share write access to system directories,
    # but the project's own checkout persists from build into the running
    # service.
    local_bin = os.path.join(_REPO_ROOT, "bin", "trivy")
    if os.path.isfile(local_bin) and os.access(local_bin, os.X_OK):
        return local_bin
    if sys.platform != "win32":
        return None
    # Windows-only: a just-installed winget package isn't always on PATH for
    # the current process without a fresh shell, so also check its known
    # install location.
    candidates = glob.glob(os.path.expandvars(
        r"%LOCALAPPDATA%\Microsoft\WinGet\Packages\AquaSecurity.Trivy_*\trivy.exe"
    ))
    return candidates[0] if candidates else None


def _run_trivy_json(args, timeout):
    """Returns (parsed_json, error_reason) - exactly one of the two is None."""
    trivy_bin = _find_trivy()
    if not trivy_bin:
        locations = ["PATH", "./bin"] + (["the winget install location"] if sys.platform == "win32" else [])
        return None, f"trivy binary not found (checked {', '.join(locations)})"
    try:
        result = subprocess.run(
            [trivy_bin, *args, "--format", "json", "--quiet"],
            capture_output=True, text=True, timeout=timeout, encoding="utf-8",
        )
        if result.returncode != 0:
            stderr = (result.stderr or "").strip().splitlines()[-1:] or [""]
            return None, f"trivy exited with code {result.returncode}: {stderr[0][:200]}"
        return json.loads(result.stdout), None
    except subprocess.TimeoutExpired:
        return None, f"trivy scan timed out after {timeout}s"
    except Exception as e:
        return None, f"trivy scan failed: {e}"


def _trivy_scan_dockerfile(dockerfile_path: str):
    """Returns (findings, error_reason) - exactly one of the two is None."""
    data, error = _run_trivy_json(["config", os.path.dirname(dockerfile_path) or "."], timeout=60)
    if data is None:
        return None, error
    findings = []
    for result in data.get("Results", []):
        for m in result.get("Misconfigurations") or []:
            if m.get("Status") != "FAIL":
                continue
            findings.append({
                "id": m["ID"],
                "severity": SEVERITY_NORMALIZE.get(m.get("Severity", "LOW"), "LOW"),
                "detail": f'{m.get("Title", m["ID"])}: {m.get("Message", "")}'.strip(": "),
                "source": "dockerfile_trivy",
            })
    return findings, None


def _trivy_scan_dependencies(requirements_path: str):
    """Returns (findings, error_reason) - exactly one of the two is None."""
    data, error = _run_trivy_json(
        ["fs", os.path.dirname(requirements_path) or ".", "--scanners", "vuln"], timeout=180
    )
    if data is None:
        return None, error
    findings = []
    for result in data.get("Results", []):
        for v in result.get("Vulnerabilities") or []:
            findings.append({
                "id": v["VulnerabilityID"],
                "severity": SEVERITY_NORMALIZE.get(v.get("Severity", "LOW"), "LOW"),
                "detail": f'{v.get("PkgName")}=={v.get("InstalledVersion")}: {v.get("Title", "")}',
                "source": "dependency_scan",
                "package": v.get("PkgName"),
                "version": v.get("InstalledVersion"),
            })
    return findings, None


# --- static fallback: the original hand-rolled checks, used only if trivy
# isn't available or its scan fails for any reason ---

DOCKERFILE_CHECKS = [
    {
        "pattern": re.compile(r"^\s*FROM\s+\S+:\d+\.\d+\s*$", re.MULTILINE),
        "condition": "match",
        "id": "outdated-base-image-tag",
        "severity": "MEDIUM",
        "detail": "Base image pinned to a specific old minor version (e.g. python:3.9) rather than a maintained/patched tag - increases exposure to base-layer CVEs.",
    },
    {
        "pattern": re.compile(r"^\s*USER\s+\S+", re.MULTILINE),
        "condition": "missing",
        "id": "container-runs-as-root",
        "severity": "HIGH",
        "detail": "No USER directive found - container will run as root by default, violating least-privilege configuration management practices.",
    },
    {
        "pattern": re.compile(r"apt-get\s+install(?!.*=)", re.MULTILINE),
        "condition": "match",
        "id": "unpinned-apt-packages",
        "severity": "LOW",
        "detail": "apt-get install used without version pins - build is non-reproducible and may silently pull vulnerable package versions.",
    },
]


def _static_scan_dockerfile(path: str):
    with open(path) as f:
        content = f.read()
    findings = []
    for check in DOCKERFILE_CHECKS:
        matched = bool(check["pattern"].search(content))
        triggered = matched if check["condition"] == "match" else not matched
        if triggered:
            findings.append({
                "id": check["id"],
                "severity": check["severity"],
                "detail": check["detail"],
                "source": "dockerfile_static_check",
            })
    return findings


def _static_scan_dependencies(req_path: str, deps):
    dataset = load_local_feed()
    findings = []
    for name, version in deps:
        pinned = f"{name}=={version}"
        for entry in dataset:
            affected = [a.lower() for a in entry.get("affected", [])]
            if pinned in affected or name in affected:
                findings.append({
                    "id": entry["cve_id"],
                    "severity": entry["severity"],
                    "detail": f"{name}=={version}: {entry['summary']}",
                    "source": "dependency_scan",
                    "package": name,
                    "version": version,
                })
    return findings


def parse_requirements(path: str):
    deps = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            m = re.match(r"([A-Za-z0-9_\-]+)\s*==\s*([\w.]+)", line)
            if m:
                deps.append((m.group(1).lower(), m.group(2)))
    return deps


def _mock_summary(findings):
    if not findings:
        return "No known vulnerabilities or misconfigurations found."
    lines = ["Vulnerability Scanner Agent - scan results:"]
    for f in sorted(findings, key=lambda x: {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}.get(x["severity"], 4)):
        lines.append(f"- [{f['severity']}] {f['id']}: {f['detail']}")
    return "\n".join(lines)


def run(dockerfile_path: str, requirements_path: str):
    deps = parse_requirements(requirements_path)
    dep_names = [d[0] for d in deps]

    docker_findings, docker_error = _trivy_scan_dockerfile(dockerfile_path)
    dep_findings, dep_error = _trivy_scan_dependencies(requirements_path)

    if docker_findings is not None and dep_findings is not None:
        scan_mode = "trivy"
        scan_fallback_reason = None
    else:
        docker_findings = _static_scan_dockerfile(dockerfile_path)
        dep_findings = _static_scan_dependencies(requirements_path, deps)
        scan_mode = "static-fallback"
        scan_fallback_reason = docker_error or dep_error

    all_findings = docker_findings + dep_findings

    system_prompt = (
        "You are an application security engineer reviewing static scan "
        "output (container config + dependency CVEs). Summarize the most "
        "important findings and their real-world exploitability, ordered "
        "by severity."
    )
    user_prompt = f"Findings:\n{all_findings}"
    summary, mode = reason(system_prompt, user_prompt, mock_fn=lambda: _mock_summary(all_findings))
    return {
        "agent": "vuln_scanner",
        "findings": all_findings,
        "dependency_names": dep_names,
        "summary": summary,
        "reasoning_mode": mode,
        "reasoning_fallback_reason": get_last_fallback_reason() if mode == "mock" else None,
        "scan_mode": scan_mode,
        "scan_fallback_reason": scan_fallback_reason,
    }
