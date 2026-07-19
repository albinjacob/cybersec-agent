"""
Threat Intelligence Agent
-------------------------
Given log-monitor findings and dependency names from the vuln scanner, looks
up relevant CVEs / known attack patterns and summarizes exposure.

Queries the live NVD REST API v2.0
(https://services.nvd.nist.gov/rest/json/cves/2.0 - public, no API key
required) for each derived keyword. Falls back automatically to the
bundled data/knowledgebase/cve_dataset.json if the API is unreachable, times out, or hits
the unauthenticated rate limit (5 requests/30s), so a live demo never
breaks on a flaky connection. `feed_mode` on the returned dict records which
path actually ran ("live-nvd" or "local-fallback").
"""

import json
import logging

from .llm import UNTRUSTED_DATA_NOTE, fence_untrusted, reason

log = logging.getLogger(__name__)

DATASET_PATH = "data/knowledgebase/cve_dataset.json"
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_TIMEOUT = 8
NVD_RESULTS_PER_KEYWORD = 3
NVD_MAX_KEYWORDS = 5  # matches the unauthenticated 5-req/30s NVD rate limit


def load_local_feed(path: str = DATASET_PATH):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def _severity_from_metrics(metrics):
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key)
        if entries:
            sev = entries[0].get("cvssData", {}).get("baseSeverity") or entries[0].get("baseSeverity")
            if sev:
                return sev.upper()
    return "MEDIUM"


def _nvd_lookup_keyword(keyword):
    import requests
    resp = requests.get(
        NVD_API_URL,
        params={"keywordSearch": keyword, "resultsPerPage": NVD_RESULTS_PER_KEYWORD},
        timeout=NVD_TIMEOUT,
    )
    resp.raise_for_status()
    hits = []
    for item in resp.json().get("vulnerabilities", []):
        cve = item["cve"]
        descriptions = cve.get("descriptions", [])
        summary = next((d["value"] for d in descriptions if d.get("lang") == "en"),
                        descriptions[0]["value"] if descriptions else "")
        hits.append({
            "cve_id": cve["id"],
            "severity": _severity_from_metrics(cve.get("metrics", {})),
            "summary": summary,
            "affected": [keyword],
            "keywords": [keyword],
        })
    return hits


def lookup_live(keywords):
    """Query NVD live for up to NVD_MAX_KEYWORDS keywords.
    Returns (results, error_reason) - exactly one of the two is None. Any
    failure (network, timeout, rate limit) returns (None, reason) so the
    caller falls back to the local dataset instead of a partial result."""
    results = []
    try:
        for kw in keywords[:NVD_MAX_KEYWORDS]:
            results.extend(_nvd_lookup_keyword(kw))
    except Exception as e:
        return None, f"NVD API call failed: {e}"
    return results, None


def lookup_local(keywords, dataset):
    keywords_lower = [k.lower() for k in keywords]
    hits = []
    for entry in dataset:
        entry_kw = [k.lower() for k in entry.get("keywords", [])]
        entry_affected = [a.lower() for a in entry.get("affected", [])]
        if any(k in entry_kw or k in entry_affected for k in keywords_lower) or \
           any(any(k in kw for kw in entry_kw) for k in keywords_lower):
            hits.append(entry)
    return hits


def _mock_summary(matches):
    if not matches:
        return "No known CVEs/threat patterns matched current findings against the local feed."
    lines = ["Threat Intelligence Agent - exposure summary:"]
    for m in sorted(matches, key=lambda x: {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}.get(x["severity"], 4)):
        lines.append(f"- [{m['severity']}] {m['cve_id']}: {m['summary']}")
    return "\n".join(lines)


def run(log_findings, dependency_names=None, llm_config: dict | None = None):
    dep_keywords = [d.lower() for d in (dependency_names or [])]
    log_keywords = set()
    for f in log_findings:
        log_keywords.add(f["type"].replace("_", " "))
        if f["type"] == "ssh_bruteforce":
            log_keywords.update(["ssh brute force", "failed password", "root login"])
        if f["type"] == "recon_probe":
            log_keywords.update(["wp-admin", ".env", "path traversal", "recon"])

    # Precise package names first: NVD's keyword search is a loose text
    # match, so exact dependency names ("pyyaml", "django") surface far more
    # targeted CVEs than broad multi-word phrases ("root login"), which tend
    # to match old, low-relevance results. Since only NVD_MAX_KEYWORDS get
    # queried live, put the high-signal ones first.
    keyword_list = dep_keywords + [k for k in log_keywords if k not in dep_keywords]

    live_matches, live_error = lookup_live(keyword_list)
    if live_matches is not None:
        matches, feed_mode, feed_fallback_reason = live_matches, "live-nvd", None
    else:
        log.warning("NVD lookup fell back to the local dataset: %s", live_error)
        matches = lookup_local(keyword_list, load_local_feed())
        feed_mode, feed_fallback_reason = "local-fallback", live_error

    # de-dupe by cve_id
    seen = set()
    unique_matches = []
    for m in matches:
        if m["cve_id"] not in seen:
            seen.add(m["cve_id"])
            unique_matches.append(m)

    system_prompt = (
        "You are a threat intelligence analyst. Given matched CVE/threat-pattern "
        "records, summarize the organization's real exposure and which findings "
        "each CVE relates to, ordered by severity." + UNTRUSTED_DATA_NOTE
    )
    compact = [{"cve_id": m["cve_id"], "severity": m["severity"], "summary": m["summary"]}
               for m in unique_matches]
    user_prompt = fence_untrusted(json.dumps(compact, indent=1), tag="cve_matches")
    summary, mode, fallback_reason = reason(system_prompt, user_prompt,
                                            mock_fn=lambda: _mock_summary(unique_matches),
                                            config=llm_config)
    return {
        "agent": "threat_intel",
        "matches": unique_matches,
        "summary": summary,
        "reasoning_mode": mode,
        "reasoning_fallback_reason": fallback_reason,
        "feed_mode": feed_mode,
        "feed_fallback_reason": feed_fallback_reason,
    }
