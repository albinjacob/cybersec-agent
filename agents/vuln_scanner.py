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

import contextlib
import glob
import json
import logging
import os
import re
import shutil
import subprocess
import sys
import tempfile

from .llm import UNTRUSTED_DATA_NOTE, fence_untrusted, reason
from .threat_intel import load_local_feed

log = logging.getLogger(__name__)

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


@contextlib.contextmanager
def _isolated_scan_dir(path, dest_name=None):
    """Copy ONE file into a fresh private temp dir and yield that dir. Trivy's
    config/fs scans take a directory, and scanning dirname(uploaded_file)
    would ingest whatever else that directory happens to hold - on a shared
    host, potentially another session's uploads, whose contents would then
    surface in this requester's findings.

    dest_name overrides the copy's filename (see _canonical_dependency_name -
    Trivy's fs vuln scanner identifies package manager files by exact
    filename, not content, so an upload saved under any other name would
    silently produce zero findings otherwise)."""
    scan_dir = tempfile.mkdtemp(prefix="trivy_scan_")
    try:
        shutil.copy2(path, os.path.join(scan_dir, dest_name or os.path.basename(path)))
        yield scan_dir
    finally:
        shutil.rmtree(scan_dir, ignore_errors=True)


# Trivy's `trivy fs --scanners vuln` recognizes package-manager files by exact
# filename (confirmed empirically: an identical file scans as 0 vulnerabilities
# under a renamed basename vs. its canonical name), unlike `trivy config`,
# which detects Dockerfile/Kubernetes/Terraform/CloudFormation content
# regardless of filename. A user-uploaded file rarely keeps the exact
# canonical name (Gradio preserves whatever the user's local file was called,
# e.g. "backend-requirements.txt" or "requirements_prod.txt"), so without this
# mapping the scan would silently report "no known vulnerabilities" instead of
# "this file wasn't recognized".
_LOCKFILE_NAME_HINTS = {
    "yarn": "yarn.lock",
    "gemfile": "Gemfile.lock",
    "cargo": "Cargo.lock",
}
_LOCKFILE_CONTENT_SNIFFS = [
    ("yarn lockfile", "yarn.lock"),
    ("gem\n  remote:", "Gemfile.lock"),
    ("[[package]]", "Cargo.lock"),
]


def _canonical_dependency_name(path):
    """Best-effort mapping from an arbitrary uploaded filename to the exact
    filename Trivy's dependency scanner expects for that ecosystem. Falls back
    to the original basename if the extension/content isn't recognized (the
    scan then behaves exactly as it did before this fix - static fallback
    still applies if Trivy finds nothing to scan)."""
    basename = os.path.basename(path)
    ext = os.path.splitext(basename)[1].lower()
    if ext == ".txt":
        return "requirements.txt"
    if ext == ".json":
        return "package-lock.json"
    if ext == ".mod":
        return "go.mod"
    if ext == ".xml":
        return "pom.xml"
    if ext == ".lock":
        lower = basename.lower()
        for hint, canonical in _LOCKFILE_NAME_HINTS.items():
            if hint in lower:
                return canonical
        try:
            with open(path, encoding="utf-8", errors="replace") as f:
                head = f.read(2048).lower()
        except OSError:
            head = ""
        for sniff, canonical in _LOCKFILE_CONTENT_SNIFFS:
            if sniff in head:
                return canonical
    return basename


def _trivy_scan_dockerfile(dockerfile_path: str):
    """Returns (findings, error_reason) - exactly one of the two is None."""
    with _isolated_scan_dir(dockerfile_path) as scan_dir:
        data, error = _run_trivy_json(["config", scan_dir], timeout=60)
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
    dest_name = _canonical_dependency_name(requirements_path)
    with _isolated_scan_dir(requirements_path, dest_name=dest_name) as scan_dir:
        data, error = _run_trivy_json(["fs", scan_dir, "--scanners", "vuln"], timeout=180)
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
    with open(path, encoding="utf-8", errors="replace") as f:
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
    with open(path, encoding="utf-8", errors="replace") as f:
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


def run(dockerfile_path: str, requirements_path: str, llm_config: dict | None = None):
    deps = parse_requirements(requirements_path)
    dep_names = [d[0] for d in deps]

    docker_findings, docker_error = _trivy_scan_dockerfile(dockerfile_path)
    dep_findings, dep_error = _trivy_scan_dependencies(requirements_path)

    if docker_findings is not None and dep_findings is not None:
        scan_mode = "trivy"
        scan_fallback_reason = None
    else:
        scan_fallback_reason = docker_error or dep_error
        log.warning("Trivy scan fell back to static checks: %s", scan_fallback_reason)
        docker_findings = _static_scan_dockerfile(dockerfile_path)
        dep_findings = _static_scan_dependencies(requirements_path, deps)
        scan_mode = "static-fallback"

    all_findings = docker_findings + dep_findings

    system_prompt = (
        "You are an application security engineer reviewing static scan "
        "output (container config + dependency CVEs). Summarize the most "
        "important findings and their real-world exploitability, ordered "
        "by severity." + UNTRUSTED_DATA_NOTE
    )
    compact = [{"id": f["id"], "severity": f["severity"], "detail": f["detail"]} for f in all_findings]
    user_prompt = fence_untrusted(json.dumps(compact, indent=1))
    summary, mode, fallback_reason = reason(system_prompt, user_prompt,
                                            mock_fn=lambda: _mock_summary(all_findings),
                                            config=llm_config)
    return {
        "agent": "vuln_scanner",
        "findings": all_findings,
        "dependency_names": dep_names,
        "summary": summary,
        "reasoning_mode": mode,
        "reasoning_fallback_reason": fallback_reason,
        "scan_mode": scan_mode,
        "scan_fallback_reason": scan_fallback_reason,
    }
