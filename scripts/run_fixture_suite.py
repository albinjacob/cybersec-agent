"""
Batch-runs every file in data/testing/test_fixtures/ through the real pipeline
and writes one consolidated pass/fail report, instead of uploading each file
one at a time through the Gradio UI.

Findings are deterministic (regex / real Trivy / real NVD) - see
docs/DECISIONS.md ("the LLM only narrates") - so pass/fail is judged purely on
structured findings, unaffected by which reasoning mode ran.

Usage:
    python scripts/run_fixture_suite.py                    # development mode (default)
    python scripts/run_fixture_suite.py --mode production  # requires OPENROUTER_API_KEY
"""

import argparse
import os
import sys
import traceback

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from orchestrator import run_pipeline  # noqa: E402

FIXTURES_ROOT = "data/testing/test_fixtures"
QUICK_DEMO = "data/testing/quick_demo"
DEFAULTS = {
    "log": f"{QUICK_DEMO}/sample_auth.log",
    "infra": f"{QUICK_DEMO}/Dockerfile",
    "dependencies": f"{QUICK_DEMO}/requirements.txt",
    "policy": f"{QUICK_DEMO}/policy_excerpt.md",
}
SLOT_ARG = {"log": "log_path", "infra": "dockerfile_path",
            "dependencies": "requirements_path", "policy": "policy_path"}

# --- Expectations, transcribed from data/testing/test_fixtures/README.md ---
# log/infra/dependencies entries are checked against structured findings;
# "info" fixtures have no fixed pass/fail (retrieval quality, or a case the
# README documents as "not necessarily zero findings") - reported for manual
# read-through instead.

LOG_FIXTURES = [
    ("auth_clean.log", {"must_not": ["ssh_bruteforce", "privileged_password_login",
                                      "insecure_permission_change", "recon_probe", "port_scan"]}),
    ("auth_multi_severity.log", {"must_have": ["ssh_bruteforce", "privileged_password_login",
                                                "insecure_permission_change"]}),
    ("auth_boundary_2fails.log", {"must_not": ["ssh_bruteforce"]}),
    ("auth_nonascii.log", {"info": "must parse without crashing"}),
    ("ufw_clean.log", {"must_not": ["port_scan"]}),
    ("ufw_portscan_multi.log", {"must_have": ["port_scan"]}),
    ("ufw_boundary_2ports.log", {"must_not": ["port_scan"]}),
    ("ufw_multi_ip_scan.log", {"must_have": ["port_scan"], "min_type_counts": {"port_scan": 2}}),
    ("nginx_clean.log", {"must_not": ["recon_probe"]}),
    ("nginx_recon_heavy.log", {"must_have": ["recon_probe"], "min_type_counts": {"recon_probe": 2}}),
    ("nginx_single_probe_boundary.log", {"must_have": ["recon_probe"], "min_type_counts": {"recon_probe": 1}}),
    ("apache_clean.log", {"must_not": ["recon_probe"]}),
    ("apache_recon_scanner.log", {"must_have": ["recon_probe"]}),
]

INFRA_FIXTURES = [
    ("Dockerfile.hardened", {"max_count": 0}),
    ("Dockerfile.vulnerable", {"must_have_id_substr": ["0002", "0026"]}),
    ("Dockerfile.multistage_edge_case", {"must_have_id_substr": ["0026"], "must_not_id_substr": ["0002"]}),
    ("k8s_pod_hardened.yaml", {"max_count": 0}),
    ("k8s_pod_privileged_hostnetwork.yaml", {"must_have_id_substr": ["0001"], "min_count": 10}),
    ("k8s_deployment_no_resource_limits.yaml", {"min_count": 1}),
    ("k8s_secrets_in_env.yaml", {"info": "Trivy has no dedicated secret-in-env check; other "
                                          "findings on this minimal manifest are expected"}),
    ("k8s_deployment_hardened_full.yaml", {"max_count": 0}),
    ("helm_rendered_hardened.yaml", {"max_count": 0}),
    ("helm_rendered_vulnerable.yaml", {"min_count": 10}),
    ("terraform_hardened.tf", {"info": "expected: some low/medium findings unrelated to the targeted checks"}),
    ("terraform_vulnerable_open_sg_s3.tf", {"min_count": 8, "must_have_severity": ["HIGH", "CRITICAL"]}),
    ("cloudformation_hardened.yaml", {"info": "expected: same shared low/medium findings as terraform_hardened"}),
    ("cloudformation_vulnerable_open_sg_s3.yaml", {"min_count": 5, "must_have_severity": ["HIGH", "CRITICAL"]}),
]

DEP_FIXTURES = [
    ("requirements_clean.txt", {"must_not_id": ["CVE-2020-14343", "CVE-2018-6188", "CVE-2018-7537"]}),
    ("requirements_vulnerable.txt", {"must_have_id": ["CVE-2020-14343"]}),
    ("requirements_unpinned.txt", {"expect_dependency_names_empty": True}),
    ("requirements_mixed.txt", {"must_have_id": ["CVE-2020-14343"]}),
    ("package-lock_clean.json", {"must_not_id": ["CVE-2020-8203", "CVE-2020-7598"]}),
    ("package-lock_vulnerable.json", {"must_have_id": ["CVE-2020-8203", "CVE-2020-7598"]}),
    ("yarn_clean.lock", {"must_not_id": ["CVE-2020-8203"]}),
    ("yarn_vulnerable.lock", {"must_have_id": ["CVE-2020-8203"]}),
    ("go_clean.mod", {"must_not_id": ["CVE-2020-26160", "CVE-2022-32149"]}),
    ("go_vulnerable.mod", {"must_have_id": ["CVE-2020-26160", "CVE-2022-32149"]}),
    ("pom_clean.xml", {"must_not_id": ["CVE-2021-44228"]}),
    ("pom_vulnerable.xml", {"must_have_id": ["CVE-2021-44228"]}),
    ("Gemfile_clean.lock", {"must_not_id": ["CVE-2018-14404", "CVE-2019-5418"]}),
    ("Gemfile_vulnerable.lock", {"must_have_id": ["CVE-2018-14404", "CVE-2019-5418"]}),
    ("Cargo_clean.lock", {"must_not_id": ["CVE-2020-26235"]}),
    ("Cargo_vulnerable.lock", {"must_have_id": ["CVE-2020-26235"]}),
]

POLICY_FIXTURES = [
    ("policy_custom_topic.md", {}),
    ("policy_overlapping_nist.md", {}),
    ("policy_malformed_no_headings.md", {}),
    ("policy_short_single_clause.md", {}),
    ("policy_comprehensive_iso_soc2_style.md", {}),
    ("policy_empty_or_whitespace.md", {}),
    ("policy_multi_match_conflict.md", {}),
]


def _judge_log(findings, expect):
    types = [f["type"] for f in findings]
    if "info" in expect:
        return "INFO", expect["info"]
    fails = []
    for t in expect.get("must_have", []):
        if t not in types:
            fails.append(f"missing type '{t}'")
    for t in expect.get("must_not", []):
        if t in types:
            fails.append(f"unexpected type '{t}'")
    for t, n in expect.get("min_type_counts", {}).items():
        actual = types.count(t)
        if actual < n:
            fails.append(f"expected >= {n} '{t}', got {actual}")
    verdict = "PASS" if not fails else "FAIL"
    return verdict, f"types={types}" + (f" ({'; '.join(fails)})" if fails else "")


def _judge_scan(findings, expect, dependency_names=None):
    if "info" in expect:
        return "INFO", f"{expect['info']} (actual: {len(findings)} findings)"
    if expect.get("expect_dependency_names_empty"):
        ok = dependency_names is not None and len(dependency_names) == 0
        return ("PASS" if ok else "FAIL"), f"dependency_names={dependency_names}"
    ids = [f["id"] for f in findings]
    severities = [f["severity"] for f in findings]
    fails = []
    if "max_count" in expect and len(findings) > expect["max_count"]:
        fails.append(f"expected <= {expect['max_count']} findings, got {len(findings)}: {ids}")
    if "min_count" in expect and len(findings) < expect["min_count"]:
        fails.append(f"expected >= {expect['min_count']} findings, got {len(findings)}")
    for sub in expect.get("must_have_id_substr", []):
        if not any(sub in i for i in ids):
            fails.append(f"missing id containing '{sub}'")
    for sub in expect.get("must_not_id_substr", []):
        if any(sub in i for i in ids):
            fails.append(f"unexpected id containing '{sub}'")
    # At least one of the cited CVEs, not all - Trivy's vulnerability DB is
    # live and keeps advancing after these fixtures were researched, and an
    # individual CVE ID can get reclassified/merged (e.g. into a GHSA
    # advisory) over time. Requiring just one still-firing hit proves the
    # ecosystem's ecosystem is genuinely scanned without being brittle
    # against that natural drift.
    wanted_cves = expect.get("must_have_id", [])
    if wanted_cves and not any(cve in ids for cve in wanted_cves):
        fails.append(f"none of {wanted_cves} present")
    for cve in expect.get("must_not_id", []):
        if cve in ids:
            fails.append(f"unexpected {cve} present")
    for sev in expect.get("must_have_severity", []):
        if sev in severities:
            break
    else:
        if expect.get("must_have_severity"):
            fails.append(f"expected one of severities {expect['must_have_severity']}, got {sorted(set(severities))}")
    verdict = "PASS" if not fails else "FAIL"
    detail = f"{len(findings)} findings: {ids}" if ids else "0 findings"
    if fails:
        detail += f" ({'; '.join(fails)})"
    return verdict, detail


def run_fixture(category, filename, expect, mode, llm_config):
    path = f"{FIXTURES_ROOT}/{category}/{filename}"
    paths = {slot: DEFAULTS[slot] for slot in DEFAULTS}
    paths[category] = path

    try:
        state = run_pipeline(paths["log"], paths["infra"], paths["dependencies"], paths["policy"],
                              llm_config=llm_config)
    except Exception as e:
        return "FAIL", f"CRASHED: {e}\n{traceback.format_exc(limit=3)}"

    if category == "log":
        return _judge_log(state["log_monitor"]["findings"], expect)
    if category in ("infra", "dependencies"):
        vs = state["vuln_scanner"]
        # vuln_scanner combines docker-config findings AND dependency-CVE findings from
        # BOTH slots into one list (the "infra" fixture leaves requirements_path at its
        # quick_demo default, and vice versa) - filter to the half this fixture actually
        # targets, using each finding's own "source" field, or the expectation would be
        # polluted by the *other* slot's default findings.
        dockerfile_sources = ("dockerfile_trivy", "dockerfile_static_check")
        dep_sources = ("dependency_scan",)
        wanted_sources = dockerfile_sources if category == "infra" else dep_sources
        relevant = [f for f in vs["findings"] if f.get("source") in wanted_sources]
        return _judge_scan(relevant, expect, dependency_names=vs.get("dependency_names"))
    if category == "policy":
        gaps = state["policy_checker"].get("mapped_gaps") or state["policy_checker"].get("gaps") or []
        return "INFO", f"{len(gaps)} policy gap(s) mapped (manual read-through, no fixed expectation)"
    raise ValueError(category)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=["development", "production"], default="development")
    parser.add_argument("--out", default="output/fixture_test_report.md")
    args = parser.parse_args()

    llm_config = None
    if args.mode == "development":
        for key in ("ANTHROPIC_API_KEY", "OPENAI_API_KEY", "OPENROUTER_API_KEY"):
            os.environ.pop(key, None)
    else:
        api_key = os.environ.get("OPENROUTER_API_KEY")
        if not api_key:
            print("ERROR: --mode production requires OPENROUTER_API_KEY to be set "
                  "(the app's own BYOK path only supports OpenRouter - see app.py).",
                  file=sys.stderr)
            sys.exit(1)
        llm_config = {"provider": "openrouter", "api_key": api_key}

    sections = [
        ("log", LOG_FIXTURES),
        ("infra", INFRA_FIXTURES),
        ("dependencies", DEP_FIXTURES),
        ("policy", POLICY_FIXTURES),
    ]

    results = []
    for category, fixtures in sections:
        for filename, expect in fixtures:
            verdict, detail = run_fixture(category, filename, expect, args.mode, llm_config)
            results.append((category, filename, verdict, detail))
            print(f"[{verdict:4}] {category}/{filename} - {detail[:120]}")

    n_pass = sum(1 for r in results if r[2] == "PASS")
    n_fail = sum(1 for r in results if r[2] == "FAIL")
    n_info = sum(1 for r in results if r[2] == "INFO")

    lines = [
        "# Fixture Test Report",
        "",
        f"Mode: `{args.mode}`  |  Total: {len(results)}  |  "
        f"PASS: {n_pass}  FAIL: {n_fail}  INFO: {n_info}",
        "",
    ]
    for category, _ in sections:
        lines.append(f"## `{category}/`")
        lines.append("")
        lines.append("| File | Verdict | Detail |")
        lines.append("|---|---|---|")
        for cat, filename, verdict, detail in results:
            if cat != category:
                continue
            safe_detail = detail.split("\n")[0].replace("|", "\\|")
            lines.append(f"| `{filename}` | {verdict} | {safe_detail} |")
        lines.append("")

    failures = [r for r in results if r[2] == "FAIL"]
    if failures:
        lines.append("## Failures in detail")
        lines.append("")
        for category, filename, verdict, detail in failures:
            lines.append(f"### `{category}/{filename}`")
            lines.append("")
            lines.append("```")
            lines.append(detail)
            lines.append("```")
            lines.append("")

    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

    print(f"\n{n_pass} passed, {n_fail} failed, {n_info} info-only. Report: {args.out}")
    sys.exit(1 if n_fail else 0)


if __name__ == "__main__":
    main()
