"""
Pure presentation layer for the Gradio app: every function here takes plain
Python data (the pipeline state dict, status maps) and returns HTML strings.
No Gradio imports - app.py owns layout/wiring, this module owns rendering.

Cards are built directly from each agent's structured data (findings /
matches / plan / gaps - computed by rule-based parsing BEFORE the LLM ever
sees them) rather than by parsing the LLM's free-text narrative summary,
which is far more robust to formatting drift across models/providers.
"""

import html
import os
import re
import urllib.parse


def _esc(value):
    """HTML-escape any dynamic value before interpolation into markup.

    Everything rendered on these pages that didn't originate in this file is
    untrusted: log lines a user uploaded, CVE text from live NVD, Trivy
    messages, package names from a requirements.txt, and every LLM response.
    Unescaped, any of those can carry markup/script into gr.HTML - a log line
    is all it takes. Escape at the interpolation site, never earlier, so the
    underlying data stays clean for prompts/reports/JSON."""
    return html.escape(str(value), quote=True)

# ---------------------------------------------------------------- constants

VERSION_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "VERSION")


def read_version(path: str = VERSION_PATH) -> str:
    """App version ("X.Y") from the VERSION file, bumped by
    scripts/bump_version.py. Falls back to "0.1" if the file is missing or
    malformed - a version badge is never worth crashing the app over."""
    try:
        with open(path, encoding="utf-8") as f:
            major, minor = f.read().strip().split(".")
        return f"{int(major)}.{int(minor)}"
    except Exception:
        return "0.1"


APP_VERSION = read_version()

SEVERITY_COLORS = {
    "CRITICAL": "#dc2626",
    "HIGH": "#ea580c",
    "MEDIUM": "#ca8a04",
    "LOW": "#65a30d",
}
SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
NEUTRAL_COLOR = "#6366f1"
ACCENT = "#06b6d4"   # cyan - matches the app theme's primary hue
OK_GREEN = "#16a34a"
WARN_AMBER = "#f59e0b"
IDLE_GREY = "#94a3b8"  # "no data yet" - deliberately NOT a severity colour
# Purple reads as "role", not "status" - distinct from ACCENT (the app's own
# brand hue), the severity palette, and NEUTRAL_COLOR (already used for
# compliance-framework badges elsewhere) so it can't be misread as any of those.
ADMIN_ACCENT = "#a855f7"

TYPE_ICONS = {
    "ssh_bruteforce": "🔓",
    "privileged_password_login": "🔑",
    "port_scan": "📡",
    "recon_probe": "🕵️",
    "insecure_permission_change": "📂",
}

# Order matches report_builder.py's section numbering (1-5).
AGENTS = [
    dict(
        key="log_monitor", num=1, icon="📋", title="Log Monitor Agent", short="Log Monitor Agent",
        nav_label="Activity Scan",
        cta="View incidents →",
        card_blurb="Scans authentication and system logs for brute-force logins, "
                    "reconnaissance probes, and suspicious privilege changes.",
        page_blurb="Parses raw auth/system logs, correlates failed-then-successful "
                    "logins, port scans, and web recon probes into severity-ranked incidents.",
        inputs=("log",),
        next_key="threat_intel", next_label="Next: Threat Lookup for CVE matches →",
    ),
    dict(
        key="threat_intel", num=2, icon="🛰️", title="Threat Intelligence Agent", short="Threat Intelligence Agent",
        nav_label="Threat Lookup",
        cta="View CVE matches →",
        card_blurb="Cross-references Log Monitor and Vulnerability Scanner findings "
                    "against the live NVD CVE feed to explain real exploitability.",
        page_blurb="Correlates findings from the Log Monitor and Vulnerability Scanner "
                    "agents against live NVD CVE records and attack patterns, explaining "
                    "how they could be chained together.",
        inputs=("log", "dockerfile", "requirements"),
        next_key="incident_response", next_label="Next: Action Plan for what to do →",
    ),
    dict(
        key="vuln_scanner", num=3, icon="🛠️", title="Vulnerability Scanner Agent", short="Vulnerability Scanner Agent",
        nav_label="Dependency Audit",
        cta="View findings →",
        card_blurb="Audits your Dockerfile and requirements.txt with Trivy for known "
                    "CVEs and container hardening gaps.",
        page_blurb="Runs Trivy against pinned dependency versions and your Dockerfile, "
                    "surfacing known CVEs, root-user execution, unpinned packages, and "
                    "other hardening gaps.",
        inputs=("dockerfile", "requirements"),
        next_key="threat_intel", next_label="Next: Threat Lookup for CVE matches →",
    ),
    dict(
        key="incident_response", num=4, icon="🚨", title="Incident Response Agent", short="Incident Response Agent",
        nav_label="Action Plan",
        cta="View action plan →",
        card_blurb="Turns every finding into a prioritized, time-boxed remediation plan.",
        page_blurb="Synthesizes every upstream finding into a concrete action plan, "
                    "split into Immediate / Critical-High / Medium / Low priority tiers "
                    "with a leadership summary.",
        inputs=("log", "dockerfile", "requirements"),
        next_key="policy_checker", next_label="Next: Compliance Check for control mapping →",
    ),
    dict(
        key="policy_checker", num=5, icon="📜", title="Policy Checker Agent", short="Policy Checker Agent",
        nav_label="Compliance Check",
        cta="View control gaps →",
        card_blurb="Maps every finding to specific NIST SP 800-53 / ISO 27001 / SOC 2 "
                    "controls via semantic search, with the evidence needed to close each gap.",
        page_blurb="Matches each finding against the full NIST SP 800-53 Rev 5 catalog "
                    "(1,000+ controls) plus condensed ISO 27001 / SOC 2 excerpts, by meaning "
                    "rather than keywords - so it catches a control even when the wording differs.",
        inputs=("log", "dockerfile", "requirements", "policy"),
        next_key="report", next_label="Next: View Full Report →",
    ),
]
AGENT_META = {a["key"]: a for a in AGENTS}
# The terminal action stage is deliberately NOT in AGENTS - it does fixed
# routing over data the five analysis agents already produced (no LLM call),
# so it gets no detail page / nav entry / severity filter, and the tracker
# renders it as a distinct "action" node rather than a 6th agent.
AGENT_META["notify"] = dict(key="notify", icon="📣", short="Notify", title="Notification / Action Stage")

# ---------------------------------------------------------------- icon system
# Replaces multi-colour emoji (📋🛰️🛠️🚨📜🏠📄⚡📁🛡️) in primary nav/branding
# surfaces with one consistent, monochrome, currentColor-adaptive vector set.
# Emoji render inconsistently across OS/browser and can't be recoloured to
# match the IBM Plex / cyan-slate theme - a bigger "vibe-coded AI defaults"
# tell than the fonts ever were. Hand-drawn minimal outline/solid icons
# (no external icon-font dependency) - each is a shape fragment (no <svg>
# wrapper), so it can be dropped into either an inline <svg> (for gr.HTML /
# sanitize_html=False gr.Markdown contexts) or a CSS mask-image (for plain-text
# Button/Tab labels, which can't hold HTML at all).
_ICON_SHAPES = {
    # stroke-style (outline) icons: (inner_svg_markup, is_filled)
    "home": ('<path d="M4 11.5 12 4l8 7.5"/><path d="M6 10v9h5v-5h2v5h5v-9"/>', False),
    "log_monitor": ('<path d="M7 3h7l4 4v14H7z"/><path d="M14 3v4h4"/>'
                     '<path d="M9.5 9h2.5M9.5 12h6M9.5 15h6"/>', False),
    "threat_intel": ('<circle cx="12" cy="12" r="8"/><circle cx="12" cy="12" r="4.2"/>'
                      '<circle cx="12" cy="12" r="1" fill="currentColor" stroke="none"/>'
                      '<path d="M12 2.5v2.3M21.5 12h-2.3M12 21.5v-2.3M2.5 12h2.3"/>', False),
    "vuln_scanner": ('<path d="M12 3.2 19 6v5.7c0 5-3 8.3-7 9.6-4-1.3-7-4.6-7-9.6V6z"/>'
                      '<path d="M9 12l2 2 4-4.3"/>', False),
    "incident_response": ('<path d="M12 4 21.3 20H2.7z"/><path d="M12 10v4.3"/>'
                           '<circle cx="12" cy="17.2" r="0.9" fill="currentColor" stroke="none"/>', False),
    "policy_checker": ('<rect x="6" y="4.5" width="12" height="16" rx="1.5"/>'
                        '<rect x="9" y="3" width="6" height="3" rx="1"/>'
                        '<path d="M9 12.3l2 2 4-4.3"/>', False),
    "report": ('<path d="M7 3h7l4 4v14H7z"/><path d="M14 3v4h4"/>', False),
    "shield": ('<path d="M12 3.2 19 6v5.7c0 5-3 8.3-7 9.6-4-1.3-7-4.6-7-9.6V6z"/>', False),
    # solid-style icons
    "zap": ('<polygon points="13,2 5,14 11,14 10,22 19,10 13,10"/>', True),
    "folder": ('<path d="M3 6.5h6.2l1.8 2H21v11.5H3z"/>', True),
}


def icon_html(name: str, size: int = 16, extra_style: str = "") -> str:
    """Inline SVG for gr.HTML / sanitize_html=False gr.Markdown contexts.
    Always monochrome via currentColor, so it inherits whatever text colour
    surrounds it (including dark-mode / hover recolouring) with zero CSS."""
    shape, filled = _ICON_SHAPES[name]
    if filled:
        attrs = 'fill="currentColor" stroke="none"'
    else:
        attrs = 'fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"'
    return (f'<svg viewBox="0 0 24 24" width="{size}" height="{size}" {attrs} '
            f'style="vertical-align:-3px;flex-shrink:0;{extra_style}">{shape}</svg>')


def nav_section_label_html(text, color, subtitle=None):
    """Small uppercase divider label for the left nav sidebar, splitting
    "what a regular user runs" from "what a developer/reviewer inspects" -
    purely a visual/organisational grouping (this app has no role-based
    login), so the wording says that plainly rather than implying an access
    control that doesn't exist."""
    sub = f'<div style="font-size:10px; font-weight:400; letter-spacing:0; margin-top:1px; opacity:0.8;">{subtitle}</div>' if subtitle else ""
    return (
        f'<div style="margin:14px 0 4px 4px; padding-top:10px; border-top:1px solid var(--border-color-primary);">'
        f'<div style="font-size:10.5px; font-weight:700; letter-spacing:0.08em; text-transform:uppercase; color:{color};">{text}</div>'
        f'{sub}'
        '</div>'
    )


def _icon_data_uri(name: str) -> str:
    """Same shape, serialised as a standalone SVG document for CSS
    mask-image - lets a plain-text Gradio Button/Tab label (which can't hold
    HTML) still carry a real vector icon via a ::before pseudo-element."""
    shape, filled = _ICON_SHAPES[name]
    attrs = 'fill="black"' if filled else 'fill="none" stroke="black" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"'
    svg = f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" {attrs}>{shape}</svg>'
    return "data:image/svg+xml," + urllib.parse.quote(svg)


def _icon_mask_css() -> str:
    """CSS generated from _ICON_SHAPES, one .icon-{name} class per icon -
    mirrors how _agent_accent_css() used to generate per-agent CSS from the
    AGENTS list before it was removed. Add a shape to _ICON_SHAPES and it's
    usable as elem_classes=[..., "icon-{name}"] on any Button/Tab with no
    further wiring."""
    rules = []
    for name in _ICON_SHAPES:
        uri = _icon_data_uri(name)
        rules.append(
            f'.icon-{name} {{ position: relative; padding-left: 30px !important; }}\n'
            f'.icon-{name}::before {{\n'
            f'  content: ""; position: absolute; left: 12px; top: 50%;\n'
            f'  width: 15px; height: 15px; transform: translateY(-50%);\n'
            f'  background-color: currentColor;\n'
            f'  -webkit-mask: url(\'{uri}\') center / contain no-repeat;\n'
            f'  mask: url(\'{uri}\') center / contain no-repeat;\n'
            f'}}'
        )
    return "\n".join(rules)


# Labels reflect what the pipeline ACTUALLY accepts, verified by testing the
# real parsers - not aspirational. The log field is genuinely narrow (regex
# patterns for sshd/sudo/UFW/nginx only); the other two are far broader than
# their old "Dockerfile"/"requirements.txt" labels implied, because Trivy
# handles many config formats and lockfile ecosystems.
FILE_LABELS = {
    "log": "Linux auth / access log",
    "dockerfile": "Infra config (Dockerfile, K8s, Terraform…)",
    "requirements": "Dependency manifest / lockfile",
    "policy": "Your policy document (optional)",
}

# (supported, not_supported, what_it_detects) per input - drives the
# "What can I upload?" panel. Everything here was verified empirically:
# docker/kubectl/JSON logs really do yield zero findings, and `trivy config`
# really does score Kubernetes YAML (19 findings on a test pod spec).
FILE_HELP = {
    "log": dict(
        icon="📜",
        title="Linux auth / access log",
        supported=["<code>/var/log/auth.log</code> — sshd &amp; sudo lines",
                    "UFW firewall blocks (<code>[UFW BLOCK] … DPT=</code>)",
                    "nginx / apache access logs (<code>\"GET /path HTTP/1.1\" 404</code>)"],
        unsupported=["<code>docker logs</code> / <code>kubectl</code> output",
                      "JSON or structured app logs, traces, kubelet logs",
                      "Windows Event Log exports"],
        detects="SSH brute force (needs <b>3+ failed logins from one IP</b>), privileged "
                "password logins, port scans, and recon probes (<code>.env</code>, "
                "<code>wp-admin</code>, path traversal). Normal traffic correctly yields nothing.",
    ),
    "dockerfile": dict(
        icon="🐳",
        title="Infrastructure config",
        supported=["<code>Dockerfile</code>", "Kubernetes manifests (<code>.yaml</code>)",
                    "Terraform (<code>.tf</code>)", "CloudFormation (<code>.yaml</code>/<code>.json</code>)"],
        unsupported=["<code>docker-compose.yml</code> — Trivy has no native parser for it "
                      "(tracked upstream, unresolved)",
                      "Raw Helm charts — a single template file can't be recognized without the "
                      "full chart directory. <b>Workaround:</b> run <code>helm template mychart "
                      "&gt; rendered.yaml</code> locally and upload that instead — it scans as a "
                      "plain Kubernetes manifest"],
        detects="Scanned by <b>Trivy</b> for misconfigurations — running as root, missing "
                "HEALTHCHECK, privileged containers, unpinned packages, dropped capabilities. "
                "A single Terraform/CloudFormation file can't resolve remote state, and "
                "CloudFormation silently skips templates using some advanced intrinsic functions "
                "— zero findings there isn't necessarily a clean bill of health.",
    ),
    "requirements": dict(
        icon="📦",
        title="Dependency manifest",
        supported=["<code>requirements.txt</code> (Python)",
                    "<code>package-lock.json</code>, <code>yarn.lock</code> (Node)",
                    "<code>go.mod</code> (Go)", "<code>pom.xml</code>, <code>Gemfile.lock</code>, <code>Cargo.lock</code>"],
        unsupported=["<code>go.sum</code> alone — Trivy needs the paired <code>go.mod</code> to "
                      "even determine the module/Go version; upload <code>go.mod</code> instead"],
        detects="Scanned by <b>Trivy</b> against its CVE database for known-vulnerable "
                "package versions. Unpinned/loose ranges are skipped — pinned versions work best.",
    ),
    "policy": dict(
        icon="📋",
        title="Your policy document",
        supported=["Markdown with a <code>## Heading</code> per control/clause"],
        unsupported=[],
        detects="Embedded on the fly and searched <b>alongside the built-in NIST SP 800-53 "
                "catalog</b> (1,014 controls). Your clauses compete with NIST's — the best "
                "semantic match wins. Leave blank to use NIST + the bundled ISO 27001 / SOC 2 excerpt.",
    ),
}


def file_help_html():
    """The 'What can I upload?' panel. Deliberately states what does NOT work:
    the log parsers are regex-based and silently return zero findings for
    docker/kubectl/JSON logs, which would otherwise look like a broken app."""
    blocks = []
    for kind in ("log", "dockerfile", "requirements", "policy"):
        h = FILE_HELP[kind]
        ok = "".join(f'<li>{s}</li>' for s in h["supported"])
        no = ""
        if h["unsupported"]:
            no_items = "".join(f'<li>{s}</li>' for s in h["unsupported"])
            no = (f'<div class="fh-no"><b>✗ Not supported</b>'
                  f'<ul>{no_items}</ul></div>')
        blocks.append(
            f'<div class="fh-card">'
            f'<div class="fh-title">{h["icon"]} {h["title"]}</div>'
            f'<div class="fh-ok"><b>✓ Accepts</b><ul>{ok}</ul></div>'
            f'{no}'
            f'<div class="fh-detects">{h["detects"]}</div>'
            f'</div>'
        )
    return f'<div class="fh-grid">{"".join(blocks)}</div>'

AGENT_DISPLAY_PLACEHOLDER = (
    # This renders on the per-agent result pages, not Overview - "above" was
    # a lie here, since Run Quick Demo/Analyze Your Own Files live on a
    # different page entirely. A first click out of curiosity (an agent
    # card's CTA, before ever running anything) landed on this exact string
    # with instructions that didn't match what was in front of the user.
    # Point at the one control that's actually present on every page: the
    # left-nav Overview link.
    f'<div class="empty-state"><div class="empty-icon">{icon_html("shield", size=30)}</div>'
    '<div class="subdued-text">Not run yet - go to <b>Overview</b> (left nav) and click '
    '<b>Run Quick Demo</b> or <b>Analyze Your Own Files</b>. Results will appear here '
    'automatically once it finishes.</div></div>'
)

# The LangGraph DAG topology, mirrored from orchestrator.py - used by the
# live tracker to know which node is "running" (all predecessors done).
PIPELINE_PREDECESSORS = {
    "log_monitor": [],
    "vuln_scanner": [],
    "threat_intel": ["log_monitor", "vuln_scanner"],
    "incident_response": ["threat_intel"],
    "policy_checker": ["incident_response"],
    "notify": ["policy_checker"],
}
PIPELINE_ORDER = ["log_monitor", "vuln_scanner", "threat_intel", "incident_response", "policy_checker", "notify"]

CVE_ID_RE = re.compile(r"^CVE-\d{4}-\d+")

# Plain-English glossary for the jargon this app unavoidably surfaces.
# Deterministic and hand-written (same philosophy as KNOWLEDGE_BASE) - never
# LLM-generated, so the explanation is identical on every run.
#
# `url` is None where linking would ACTIVELY HURT a first-timer rather than
# help: ISO 27001's normative text is paywalled (~CHF 124) and SOC 2's criteria
# sit behind the AICPA, so a "learn more" link there just leads to a dead end or
# a purchase page. A link that disappoints is worse than no link.
#
# Canonical spellings match what's baked into the policy corpus itself
# (data/knowledgebase/policy_index_meta.json titles): "NIST SP 800-53", "SOC 2", not
# "NIST 800-53"/"SOC2" - one standard, one name, everywhere.
GLOSSARY = {
    "NIST SP 800-53": dict(
        gloss="A free catalog of ~1,000 security controls from the US National Institute of "
              "Standards and Technology. Mandatory for US federal systems and widely used "
              "elsewhere as a security baseline.",
        url="https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final",
    ),
    "ISO 27001": dict(
        gloss="The international standard for managing information security. Organisations get "
              "certified against it to prove their security programme is sound - often required "
              "to win enterprise contracts.",
        url=None,   # normative text is paywalled - a link would lead to a purchase page
    ),
    "SOC 2": dict(
        gloss="A US audit report proving a service provider handles customer data safely. "
              "Commonly demanded by enterprise customers before they'll buy your SaaS.",
        url=None,   # criteria sit behind the AICPA
    ),
    "CVE": dict(
        gloss="Common Vulnerabilities and Exposures - a public ID for a known software flaw "
              "(e.g. CVE-2021-44228). If your dependency has one, the exploit is public too.",
        url="https://www.cve.org/",
    ),
    "NVD": dict(
        gloss="The US National Vulnerability Database - the public feed of CVE records, "
              "including severity scores. This app queries it live.",
        url="https://nvd.nist.gov/",
    ),
    "Trivy": dict(
        gloss="An open-source security scanner (by Aqua Security) that checks container images, "
              "config files and dependency lockfiles against known vulnerabilities.",
        url="https://github.com/aquasecurity/trivy",
    ),
    "Golden case": dict(
        gloss="A hand-written test case with a known-correct answer, e.g. 'this exact finding "
              "should map to control AC-7'. Used the same way a unit test's expected output is - "
              "as a fixed yardstick, not something the AI graded itself.",
        url=None,
    ),
    "Precision@1": dict(
        gloss="Of the single best-matching result the system retrieved, was it actually correct? "
              "100% means the top result was right every time; lower means it's often pointing at "
              "the wrong control.",
        url=None,
    ),
    "Recall@3": dict(
        gloss="Looking at the top 3 results (not just the very best one), was the correct answer "
              "in there somewhere? Usually higher than Precision@1, since it gives the system more "
              "chances to include the right answer.",
        url=None,
    ),
    "LLM-as-a-judge": dict(
        gloss="Instead of a human grading an AI's answer, a second AI call does it - given a "
              "rubric, it scores the first answer and explains why. Cheaper and faster than human "
              "review, though it can inherit the same kinds of mistakes an AI can make.",
        url=None,
    ),
    "Faithfulness": dict(
        gloss="Did the summary only state facts that were actually present in the input findings, "
              "or did it invent something (a CVE, a detail, a severity) that wasn't there? A "
              "faithful answer can still be incomplete - this only checks it isn't making things up.",
        url=None,
    ),
    "Consistency": dict(
        gloss="The same question is asked multiple times and the scores are compared. If they "
              "swing wildly run to run, the answer isn't reliable even when it's sometimes good - "
              "shown here as how much the score varies, not just its average.",
        url=None,
    ),
    "Offline embeddings": dict(
        gloss="Runs a small open-source model (sentence-transformers, all-MiniLM-L6-v2) directly "
              "on the server - no external API call, no key, no per-request cost. Slightly lower "
              "semantic quality than OpenRouter's larger hosted models, but real semantic search "
              "over the full catalog, not a keyword-only fallback.",
        url="https://www.sbert.net/",
    ),
}


def glossary_term(term, display=None):
    """Render a jargon term with a dotted underline + native tooltip.

    Uses <abbr title>, so the explanation is available on hover/focus and to
    screen readers without spending any layout on it. This is the SECONDARY
    layer: tooltips are invisible on a projector and on touch, so anything a
    first-timer genuinely must read is stated outright instead (see
    framework_primer_html), and this just rewards curiosity.
    """
    entry = GLOSSARY.get(term)
    label = display or term
    if not entry:
        return label
    tip = entry["gloss"]
    if entry.get("url"):
        tip += "  (click to read more)"
        return (f'<a class="gloss" href="{entry["url"]}" target="_blank" rel="noopener" '
                f'title="{tip}">{label}</a>')
    return f'<abbr class="gloss" title="{tip}">{label}</abbr>'


def framework_primer_html():
    """One always-visible, no-interaction line explaining the compliance
    frameworks, shown on the Policy Checker page. Deliberately NOT a tooltip:
    this is the one thing a first-timer must understand to read the page at
    all, and it has to survive being demoed on a projector where nobody can
    hover."""
    return (
        '<div class="primer">'
        '<b>🎓 New to these?</b> They\'re catalogs of security controls that auditors check you '
        f'against — {glossary_term("NIST SP 800-53")} (free US government baseline, ~1,000 '
        f'controls), {glossary_term("ISO 27001")} (the international standard), and '
        f'{glossary_term("SOC 2")} (US audit criteria for service providers). '
        'Each card below is one control your findings appear to violate, and what evidence '
        'would close the gap.'
        '</div>'
    )

# ------------------------------------------------------------ knowledge base
# Plain-English explanations + recommended actions for the fixed, known set of
# finding types/check-ids this pipeline produces. Deterministic on purpose (not
# LLM-generated per card) so every run - regardless of which model answered -
# shows the same reliable guidance. CVE ids aren't listed individually here;
# they fall back to a generic explanation + a real NVD "Learn More" link.
KNOWLEDGE_BASE = {
    # log_monitor finding types
    "ssh_bruteforce": dict(
        explain="Someone is repeatedly guessing passwords to break into privileged accounts like "
                "admin or root. If they succeed, they gain full control of this system.",
        action="Block the attacking IP immediately, and require key-based login with multi-factor "
               "authentication for admin/root accounts instead of passwords.",
    ),
    "privileged_password_login": dict(
        explain="An admin or root account signed in using just a password instead of a more secure "
                "method. Passwords can be guessed, stolen, or leaked - this is exactly the weak point "
                "brute-force attacks exploit.",
        action="Disable password login for privileged accounts, require SSH keys plus MFA, and "
               "rotate this account's credentials.",
    ),
    "port_scan": dict(
        explain="Someone is systematically checking which services (databases, remote desktop, web "
                "servers) are reachable on this machine - the reconnaissance step that usually comes "
                "before a real attack.",
        action="Confirm no unnecessary services are exposed to the internet, and add the scanning "
               "IP to a blocklist.",
    ),
    "recon_probe": dict(
        explain="An automated tool is probing for common web weaknesses - exposed configuration "
                "files, default admin panels - hoping to find an easy way in.",
        action="Verify these paths return nothing sensitive, and add firewall/WAF rules to block "
               "known probe patterns.",
    ),
    "insecure_permission_change": dict(
        explain="A file or folder was made writable by anyone on the system. This is a common way "
                "attackers plant a hidden backdoor after breaking in.",
        action="Revert to least-privilege permissions, and check whether anything was added to "
               "that location while it was exposed.",
    ),
    # vuln_scanner Dockerfile check ids
    "container-runs-as-root": dict(
        explain="Your application runs with full administrator (root) privileges inside its "
                "container. If an attacker exploits any bug in the app, they instantly get root "
                "access to the whole container.",
        action="Add a USER directive to your Dockerfile so the app runs as a regular, unprivileged "
               "user, then rebuild and redeploy.",
    ),
    "outdated-base-image-tag": dict(
        explain="Your container is built on an old, no-longer-patched version of its base system. "
                "Security fixes released since then don't apply to you.",
        action="Rebuild using a current, actively maintained base image tag (or a minimal/slim variant).",
    ),
    "unpinned-apt-packages": dict(
        explain="Your build installs system packages without pinning exact versions, so every "
                "build could silently pull in a different - possibly vulnerable - version without "
                "anyone noticing.",
        action="Pin package versions or use a lockfile/multi-stage build so builds are reproducible "
               "and auditable.",
    ),
}


def knowledge_for(key, package=None):
    """Returns (explain, action, learn_more_url) for a finding type/check-id/CVE id."""
    if key in KNOWLEDGE_BASE:
        entry = KNOWLEDGE_BASE[key]
        return entry["explain"], entry["action"], None

    if key and CVE_ID_RE.match(key):
        pkg_txt = f" in <b>{package}</b>" if package else ""
        explain = (f"This is a publicly documented security flaw{pkg_txt}. Because it's public, "
                   "attackers can look up exactly how to exploit it without any special research.")
        action = "Upgrade the affected package to a patched version, then re-scan to confirm the fix."
        learn_more = f"https://nvd.nist.gov/vuln/detail/{key}"
        return explain, action, learn_more

    # Non-CVE check id (e.g. a Trivy Dockerfile rule like "DS-0002") we don't
    # have a specific entry for - a neutral best-practice framing fits better
    # here than the CVE-flavored copy above.
    explain = "This is a known security best-practice violation flagged by an automated scanner."
    action = "Review the finding above and remediate per the scanner's guidance, then re-scan to confirm."
    return explain, action, None


def _explainer_html(explain, action=None, learn_more=None):
    learn_html = ""
    if learn_more:
        learn_html = (f' &middot; <a href="{learn_more}" target="_blank" rel="noopener" '
                      f'style="color:inherit; text-decoration:underline;">🔗 Learn More</a>')

    action_html = ""
    if action:
        action_html = f'<div style="margin-top:4px;"><b>✅ Recommended Action:</b> {action}{learn_html}</div>'
    elif learn_html:
        action_html = f'<div style="margin-top:4px;">{learn_html}</div>'

    return (
        '<div style="margin-top:10px; padding-top:10px; border-top:1px dashed var(--border-color-primary); '
        'font-size:12.5px;">'
        f'<div><b>💡 What this means:</b> {explain}</div>'
        f'{action_html}'
        '</div>'
    )

# ----------------------------------------------------------- badges/warnings


def severity_badge_html(findings):
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    tiles = ""
    for sev, count in counts.items():
        color = SEVERITY_COLORS[sev]
        tiles += f"""
        <div style="flex:1; text-align:center; padding:16px; border-radius:12px;
                     background:{color}1a; border:1px solid {color}55; margin:4px;">
            <div style="font-size:28px; font-weight:700; color:{color};">{count}</div>
            <div style="font-size:12px; letter-spacing:0.05em; color:{color}; text-transform:uppercase;">{sev}</div>
        </div>"""
    return f'<div style="display:flex; gap:8px;">{tiles}</div>'


def single_reasoning_badge_html(mode):
    color = OK_GREEN if mode.startswith("live-") else "#6b7280"
    return (f'<div style="display:inline-block; padding:4px 10px; border-radius:8px; '
            f'background:{color}1a; border:1px solid {color}55; color:{color}; '
            f'font-size:12px; font-weight:600; letter-spacing:0.03em;">REASONING: {mode.upper()}</div>')


def agent_fallback_warnings(key, state):
    """(label, reason) pairs for whatever fell back on THIS agent's run. Empty
    list means everything ran on its real/live path."""
    s = state.get(key)
    if not s:
        return []
    warnings = []
    # notify is not a reasoning agent - it has its own mode vocabulary
    # (sent/skipped/no-alert/offline-fallback), not reasoning_mode.
    if key == "notify":
        if s.get("mode") == "skipped":
            warnings.append(("Notifications", "Alert-worthy findings present, but no Slack channel is configured"))
        elif s.get("mode") == "offline-fallback":
            failed = [c["detail"] for c in s.get("channels", []) if c.get("status") == "failed"]
            warnings.append(("Notifications", "; ".join(failed) or "All configured channels failed to send"))
        return warnings
    if s["reasoning_mode"] == "mock":
        warnings.append(("AI reasoning", s.get("reasoning_fallback_reason")
                          or "No LLM provider configured or all providers failed"))
    if key == "vuln_scanner" and s.get("scan_mode") == "static-fallback":
        warnings.append(("Vulnerability scan", s.get("scan_fallback_reason") or "Trivy unavailable"))
    if key == "threat_intel" and s.get("feed_mode") == "local-fallback":
        warnings.append(("Threat feed", s.get("feed_fallback_reason") or "NVD API unavailable"))
    if key == "policy_checker" and s.get("embedding_mode") == "tfidf-fallback":
        warnings.append(("Semantic policy search", s.get("embedding_fallback_reason")
                          or "No embedding index built"))
    return warnings


def fallback_warning_html(warnings):
    """Loud, explicit warning banner - deliberately more prominent than the
    quiet colored mode badges, since a silent fallback is easy to miss."""
    if not warnings:
        return ""
    # reason strings can embed upstream API error text (response bodies, model
    # names) - untrusted like everything else that crosses a network boundary
    items = "".join(f'<li style="margin-bottom:2px;"><b>{_esc(label)}:</b> {_esc(reason)}</li>' for label, reason in warnings)
    return (
        f'<div style="background:{WARN_AMBER}1a; border:1px solid {WARN_AMBER}; border-left:4px solid {WARN_AMBER}; '
        'border-radius:8px; padding:12px 16px; margin-bottom:12px;">'
        '<div style="font-weight:700;">⚠️ Running in fallback mode - results may be less complete</div>'
        f'<ul style="margin:6px 0 0 18px; padding:0; font-size:13px;">{items}</ul>'
        '</div>'
    )

# ------------------------------------------------------------- finding cards


def _card_html(icon, title, badge_text, color, body_html, extra_html="", open_default=False):
    # title/badge are always plain text at every call site (finding ids, CVE
    # ids, issue text, policy headers - several of them attacker-influenced),
    # so they're escaped centrally here; body_html/extra_html are caller-built
    # markup and each caller escapes its own dynamic values.
    open_attr = " open" if open_default else ""
    return f"""
    <details class="finding-card" style="border-left:4px solid {color}; background:{color}12;"{open_attr}>
      <summary>
        <span class="fc-title">{icon} {_esc(title)}</span>
        <span class="fc-badge" style="background:{color};">{_esc(badge_text)}</span>
      </summary>
      <div class="fc-body">
        <div style="font-size:13.5px; line-height:1.55;">{body_html}</div>
        {extra_html}
      </div>
    </details>"""


def _cards_wrap(card_htmls, empty_msg):
    if not card_htmls:
        return f'<div class="subdued-text" style="font-style:italic; padding:8px 0;">{empty_msg}</div>'
    return "".join(card_htmls)


def render_log_monitor_cards(findings):
    items = sorted(findings, key=lambda f: SEVERITY_ORDER.get(f["severity"], 4))
    high_count = sum(1 for f in items if f["severity"] == "HIGH")
    cards = []
    for f in items:
        icon = TYPE_ICONS.get(f["type"], "⚠️")
        title = f["type"].replace("_", " ").title()
        color = SEVERITY_COLORS[f["severity"]]
        extra = ""
        if f.get("evidence"):
            extra = (f'<div class="subdued-text" style="margin-top:8px; font-family:var(--font-mono, monospace); '
                      f'font-size:11.5px; background:var(--background-fill-secondary); padding:6px 10px; '
                      f'border-radius:6px; overflow-x:auto;">{_esc(f["evidence"])}</div>')
        explain, action, learn_more = knowledge_for(f["type"])
        extra += _explainer_html(explain, action, learn_more)
        # CRITICAL always open; HIGH open only if <5 total HIGH; MEDIUM/LOW closed
        should_open = f["severity"] == "CRITICAL" or (f["severity"] == "HIGH" and high_count < 5)
        cards.append(_card_html(icon, title, f["severity"], color, _esc(f["detail"]), extra,
                                 open_default=should_open))
    return _cards_wrap(cards, "No suspicious activity detected in the supplied log.")


def render_vuln_scanner_cards(findings):
    items = sorted(findings, key=lambda f: SEVERITY_ORDER.get(f["severity"], 4))
    high_count = sum(1 for f in items if f["severity"] == "HIGH")
    cards = []
    for f in items:
        color = SEVERITY_COLORS[f["severity"]]
        icon = "📦" if f.get("source") == "dependency_scan" else "🐳"
        extra = ""
        if f.get("package"):
            extra = f'<div style="margin-top:6px;"><code style="font-size:11.5px;">{_esc(f["package"])}=={_esc(f.get("version", ""))}</code></div>'
        explain, action, learn_more = knowledge_for(f["id"], package=f.get("package"))
        extra += _explainer_html(explain, action, learn_more)
        # CRITICAL always open; HIGH open only if <5 total HIGH; MEDIUM/LOW closed
        should_open = f["severity"] == "CRITICAL" or (f["severity"] == "HIGH" and high_count < 5)
        cards.append(_card_html(icon, f["id"], f["severity"], color, _esc(f["detail"]), extra,
                                 open_default=should_open))
    return _cards_wrap(cards, "No known vulnerabilities or misconfigurations found.")


def render_threat_intel_cards(matches):
    items = sorted(matches, key=lambda m: SEVERITY_ORDER.get(m["severity"], 4))
    high_count = sum(1 for m in items if m["severity"] == "HIGH")
    cards = []
    for m in items:
        color = SEVERITY_COLORS[m["severity"]]
        chips = "".join(
            f'<span style="display:inline-block; background:var(--background-fill-secondary); '
            f'padding:2px 8px; border-radius:6px; font-size:11px; margin:4px 4px 0 0;">{_esc(a)}</span>'
            for a in m.get("affected", [])
        )
        extra = f'<div>{chips}</div>' if chips else ""
        affected = m.get("affected") or []
        explain, action, learn_more = knowledge_for(m["cve_id"], package=affected[0] if affected else None)
        extra += _explainer_html(explain, action, learn_more)
        # CRITICAL always open; HIGH open only if <5 total HIGH; MEDIUM/LOW closed
        should_open = m["severity"] == "CRITICAL" or (m["severity"] == "HIGH" and high_count < 5)
        cards.append(_card_html("🛰️", m["cve_id"], m["severity"], color, _esc(m["summary"]), extra,
                                 open_default=should_open))
    return _cards_wrap(cards, "No known CVEs/threat patterns matched current findings.")


def _council_block_html(council):
    """Model Council sub-block for a CRITICAL card: two independent model
    opinions plus a judge's reconciled verdict, with an agree/disagree chip
    (green = agree, amber = disagree - same palette as the rest of the app's
    ok/warn states)."""
    if not council or council.get("mode") != "live":
        return ""
    # agreement is "agree" / "disagree" / "unparseable" (council._parse_agreement) -
    # a judge reply that didn't lead with either word gets a neutral chip, not a
    # silently-wrong DISAGREE.
    tone_color, tone_label = {
        "agree": (OK_GREEN, "AGREE"),
        "disagree": (WARN_AMBER, "DISAGREE"),
    }.get(council["agreement"], (IDLE_GREY, "NO CLEAR VERDICT"))
    return (
        '<div style="margin-top:12px; padding-top:10px; border-top:1px dashed var(--border-color-primary);">'
        '<div style="font-weight:700; font-size:12.5px; margin-bottom:6px;">🏛️ Model Council '
        '<span style="font-weight:400; font-size:11px;" class="subdued-text">- a second model reviews '
        'this finding independently, then a judge reconciles both opinions</span></div>'
        '<div style="display:flex; gap:10px; flex-wrap:wrap;">'
        f'<div style="flex:1; min-width:220px; font-size:12px; background:var(--background-fill-secondary); '
        f'border-radius:8px; padding:8px 10px;"><b>Opinion A</b> <span class="subdued-text">({_esc(council["model_a"])})</span>'
        f'<div style="margin-top:4px;">{_esc(council["opinion_a"])}</div></div>'
        f'<div style="flex:1; min-width:220px; font-size:12px; background:var(--background-fill-secondary); '
        f'border-radius:8px; padding:8px 10px;"><b>Opinion B</b> <span class="subdued-text">({_esc(council["model_b"])})</span>'
        f'<div style="margin-top:4px;">{_esc(council["opinion_b"])}</div></div>'
        '</div>'
        f'<div style="margin-top:8px; padding:8px 10px; border-radius:8px; background:{tone_color}1a; '
        f'border:1px solid {tone_color}55;">'
        f'<span style="font-size:11px; font-weight:700; color:{tone_color}; letter-spacing:0.03em;">{tone_label}</span>'
        f'<div style="margin-top:4px; font-size:12.5px;"><b>Judge\'s verdict:</b> {_esc(council["judge_verdict"])}</div>'
        '</div>'
        '</div>'
    )


def render_incident_response_cards(plan):
    items = sorted(plan, key=lambda p: SEVERITY_ORDER.get(p["severity"], 4))
    high_count = sum(1 for p in items if p["severity"] == "HIGH")
    priority_label = {"CRITICAL": "IMMEDIATE", "HIGH": "HIGH", "MEDIUM": "MEDIUM", "LOW": "LOW"}
    cards = []
    for p in items:
        color = SEVERITY_COLORS[p["severity"]]
        steps_html = "".join(f'<li style="margin-bottom:4px;">{_esc(s)}</li>' for s in p["steps"])
        # steps ARE the recommended action here, so only show the plain-English "what this means"
        # line, not a second, redundant action line.
        explain, _action, _learn_more = knowledge_for(p.get("finding_key"))
        extra = (f'<div style="margin-top:8px; font-size:12.5px;"><b>💡 What this means:</b> {explain}</div>'
                 f'<ul style="margin:10px 0 4px 0; padding-left:20px; font-size:13px;">{steps_html}</ul>'
                 f'<div class="subdued-text" style="margin-top:4px; font-size:11px;">via '
                 f'{p["source_agent"].replace("_", " ").title()}</div>'
                 f'{_council_block_html(p.get("council"))}')
        # CRITICAL always open; HIGH open only if <5 total HIGH; MEDIUM/LOW closed
        should_open = p["severity"] == "CRITICAL" or (p["severity"] == "HIGH" and high_count < 5)
        cards.append(_card_html("🚨", p["issue"], priority_label.get(p["severity"], p["severity"]),
                                 color, "", extra, open_default=should_open))
    return _cards_wrap(cards, "No action items identified.")


# (label, colour, glossary key) - the glossary key drives the chip's tooltip so
# "NIST SP 800-53" is explained right where a first-timer meets it. Labels use
# the canonical spellings that the corpus itself uses.
POLICY_SOURCE_LABELS = {
    "nist_800_53": ("NIST SP 800-53", NEUTRAL_COLOR, "NIST SP 800-53"),
    "policy_excerpt": ("ISO 27001 / SOC 2", NEUTRAL_COLOR, "ISO 27001"),
    "user_policy": ("Your policy", "#0891b2", None),
}


def render_policy_checker_cards(gaps):
    items = sorted(gaps, key=lambda g: -g["score"])
    cards = []
    for i, g in enumerate(items):
        header = g["policy_chunk"].splitlines()[0].replace("## ", "")
        pct = round(g["score"] * 100)
        # Show which corpus this matched - especially so an uploaded policy is
        # visibly being used, rather than the user having to take it on faith.
        src_label, src_color, gloss_key = POLICY_SOURCE_LABELS.get(g.get("source"), (None, None, None))
        src_chip = ""
        if src_label:
            tip = GLOSSARY.get(gloss_key, {}).get("gloss", "") if gloss_key else ""
            title_attr = f' title="{tip}"' if tip else ""
            src_chip = (f'<span{title_attr} style="display:inline-block; margin-left:8px; font-size:10px; '
                        f'font-weight:700; padding:2px 7px; border-radius:999px; cursor:{"help" if tip else "default"}; '
                        f'background:{src_color}1f; color:{src_color}; border:1px solid {src_color}55;">'
                        f'{src_label}</span>')
        body = f'<b>Finding:</b> {_esc(g["finding"])}{src_chip}'
        extra = _explainer_html(
            "This finding isn't backed by evidence that the matched control is actually enforced.",
            action="Address the underlying finding above, then gather evidence (config exports, "
                   "screenshots, audit logs, tickets) proving this control is enforced, and attach "
                   "it to your compliance record.",
        )
        cards.append(_card_html("📜", header, f"{pct}% MATCH", NEUTRAL_COLOR, body, extra,
                                 open_default=i == 0))
    return _cards_wrap(cards, "No compliance gaps identified against the loaded policy corpus.")


AGENT_CARD_RENDERERS = {
    "log_monitor": ("findings", render_log_monitor_cards),
    "threat_intel": ("matches", render_threat_intel_cards),
    "vuln_scanner": ("findings", render_vuln_scanner_cards),
    "incident_response": ("plan", render_incident_response_cards),
    "policy_checker": ("gaps", render_policy_checker_cards),
}

# Agents whose items carry a "severity" field (policy gaps use match % instead).
FILTERABLE_AGENTS = {"log_monitor", "vuln_scanner", "threat_intel", "incident_response"}


def render_agent_display(key, state, severity_filter="All"):
    """One combined HTML block per agent page: fallback warning, reasoning
    badge, severity counts (log_monitor/vuln_scanner only), then the findings
    cards - single component so a run shows one loading indicator per page."""
    parts = [fallback_warning_html(agent_fallback_warnings(key, state))]
    parts.append(single_reasoning_badge_html(state[key]["reasoning_mode"]))
    if key in ("log_monitor", "vuln_scanner"):
        parts.append(f'<div style="margin-top:10px;">{severity_badge_html(state[key]["findings"])}</div>')
    data_key, renderer = AGENT_CARD_RENDERERS[key]
    items = state[key][data_key]
    if key in FILTERABLE_AGENTS and severity_filter and severity_filter != "All":
        items = [x for x in items if x.get("severity") == severity_filter.upper()]
    parts.append(f'<div style="margin-top:14px;">{renderer(items)}</div>')
    return "".join(parts)

# --------------------------------------------------------- pipeline tracker


def _tracker_node_html(key, status, duration, has_fallback):
    """A node's state must be readable at a glance from across a room (this
    gets demoed on a projector), so state drives the node's FILL, not just a
    1px border: grey=idle/queued, cyan=running, green=done, amber=done but
    something fell back."""
    meta = AGENT_META[key]
    if status == "done":
        status_html = f'<span class="pl-status done">✓ {duration:.1f}s</span>'
    elif status == "running":
        status_html = '<span class="pl-status running"><span class="pl-dot"></span> running</span>'
    elif status == "pending":
        status_html = '<span class="pl-status pending">queued</span>'
    else:  # idle (never run)
        status_html = '<span class="pl-status idle">idle</span>'

    # a completed-but-degraded node is amber, not green - green must only ever
    # mean "ran on its real/live path"
    warn_cls = " warn" if (has_fallback and status == "done") else ""
    warn = (' <span class="pl-warn" title="This stage ran in fallback mode - see the warning below">⚠</span>'
            if has_fallback else "")
    return (f'<div class="pl-node {status}{warn_cls}">'
            f'<div class="pl-name">{meta["icon"]} {meta["short"]}{warn}</div>'
            f'{status_html}</div>')


def pipeline_tracker_html(node_statuses=None, durations=None, state=None, error=None, caption=None):
    """The live LangGraph DAG: [Log Monitor ∥ Vuln Scanner] → Threat Intel →
    Incident Response → Policy Checker → Notify, with per-node status + timing.
    Notify is a terminal action stage (dispatches Slack alerts), not a
    6th reasoning agent - drawn with a distinct "action" tag and hand-off
    arrow so that distinction is visible, not just implied."""
    node_statuses = node_statuses or {k: "idle" for k in PIPELINE_ORDER}
    durations = durations or {}
    state = state or {}

    def node(key):
        return _tracker_node_html(
            key, node_statuses.get(key, "idle"), durations.get(key, 0.0),
            has_fallback=bool(agent_fallback_warnings(key, state)),
        )

    arrow = '<div class="pl-arrow">›</div>'
    # The first two agents run concurrently on independent inputs and fan in to
    # Threat Intelligence - drawing that as an explicit branch (rather than a
    # flat left-to-right list) is what shows this is a real orchestration graph,
    # not five prompts fired in sequence. The bracket + "parallel" tag makes the
    # fan-in legible at a glance.
    branch = (
        '<div class="pl-branch">'
        f'<div class="pl-parallel">{node("log_monitor")}{node("vuln_scanner")}</div>'
        '<div class="pl-branch-tag" title="These two agents run concurrently on '
        'independent inputs, then fan in to Threat Intelligence">parallel</div>'
        '</div>'
    )
    # Notify does fixed routing/dispatch over data the five agents already
    # produced - no LLM call. A distinct hand-off arrow + "action" tag (mirrors
    # the "parallel" tag's visual language, recolored) keeps it legible as a
    # different kind of node rather than a 6th reasoning agent.
    action_arrow = (
        '<div class="pl-arrow pl-arrow-act" title="Hands off from analysis to the '
        'action stage">⇥</div>'
    )
    action = (
        '<div class="pl-branch pl-action">'
        '<div class="pl-branch-tag pl-action-tag" title="Deterministic dispatch, not an LLM '
        'reasoning step - sends a Slack alert for findings at or above the configured '
        'severity">action</div>'
        f'{node("notify")}'
        '</div>'
    )
    track = (
        '<div class="pl-track">'
        f'{branch}'
        f'{arrow}{node("threat_intel")}{arrow}{node("incident_response")}{arrow}{node("policy_checker")}'
        f'{action_arrow}{action}'
        '</div>'
    )
    header = (
        '<div class="pl-header">'
        '<span class="pl-title">Agent pipeline '
        '<span class="pl-title-sub">· 5 analysis agents → action</span></span>'
        '<span class="pl-tag" title="Orchestrated as a real LangGraph directed graph; '
        'each node lights up as it runs">LangGraph DAG · live</span>'
        '</div>'
    )
    caption_html = f'<div class="pl-caption subdued-text">{caption}</div>' if caption else ""
    error_html = ""
    if error:
        error_html = (f'<div style="margin-top:8px; color:{SEVERITY_COLORS["CRITICAL"]}; '
                      f'font-size:13px;"><b>Pipeline error:</b> {_esc(error)}</div>')
    # A pulsing teal glow on the outer box (not a color already spoken for -
    # green means done, amber means degraded) makes "a run is actively in
    # progress" legible at a glance without looking like an alert.
    active_cls = " active" if "running" in node_statuses.values() else ""
    return f'<div class="pl-wrap{active_cls}">{header}{track}{caption_html}{error_html}</div>'

# -------------------------------------------------------- overview dashboard


def _finding_tally(state):
    """Shared by the KPI tiles and the completion message so the two can never
    disagree: returns None until both finding-producing agents have reported,
    otherwise a {severity: count} dict."""
    lm, vs = state.get("log_monitor"), state.get("vuln_scanner")
    if not (lm and vs):
        return None
    tally = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in lm["findings"] + vs["findings"]:
        tally[f["severity"]] = tally.get(f["severity"], 0) + 1
    return tally


def _kpi_tiles_html(state):
    """Severity counts. Colour here MEANS "we measured this" - so until both
    finding-producing agents have reported, the tiles stay grey rather than
    showing a red "—" for CRITICAL, which read as a severity signal when it
    actually meant "no data yet"."""
    tally = _finding_tally(state)
    known = tally is not None
    counts = tally or {"CRITICAL": "–", "HIGH": "–", "MEDIUM": "–", "LOW": "–"}

    tiles = ""
    for sev, count in counts.items():
        color = SEVERITY_COLORS[sev] if known else IDLE_GREY
        cls = "kpi-tile" if known else "kpi-tile idle"
        tiles += (f'<div class="{cls}" style="border-color:{color}55; background:{color}12;">'
                  f'<div class="kpi-num" style="color:{color};">{count}</div>'
                  f'<div class="kpi-label" style="color:{color};">{sev}</div></div>')
    return f'<div class="kpi-row">{tiles}</div>'


def _health_chip(label, value, tone, title="", ring=False, compact=False):
    """tone: ok (green) / warn (amber) / idle (gray).
    `ring` = a hollow dot, meaning "configured but not yet proven this run" -
    a filled dot is only used for something we actually observed happen."""
    cls = "chip compact" if compact else "chip"
    dot = "chip-dot ring" if ring else "chip-dot"
    t = f' title="{title}"' if title else ""
    return (f'<span class="{cls} {tone}"{t}><span class="{dot}"></span>'
            f'<b>{label}</b>&nbsp;{value}</span>')


# Labels match the fallback banner's wording for the same subsystems, so one
# subsystem is never called two different things in two places.
SUBSYSTEM_LABELS = {
    "llm": "AI reasoning",
    "scanner": "Vuln scan",
    "threat_feed": "Threat feed",
    "policy_rag": "Policy search",
}
# Top-bar variant. The full labels above total ~620px of chips for a ~505px
# slot, so they wrapped to two rows and made the bar look broken. The bar shares
# space with a brand and a button, so it gets terse labels; the full name and
# meaning live in each chip's tooltip.
SUBSYSTEM_LABELS_COMPACT = {
    "llm": "AI",
    "scanner": "Scan",
    "threat_feed": "CVE",
    "policy_rag": "Policy",
}


def _subsystem_health(state, preflight=None):
    """Single source of truth for subsystem status.

    Two distinct questions, depending on whether a run has happened:
      - BEFORE a run  -> "is this set up correctly?" (readiness, from
        `preflight`: is a key configured, is Trivy installed, is the policy
        index built). Shown with a RING dot - configured, but unproven.
      - AFTER a run    -> "did it actually run for real?" (from the same
        *_mode transparency flags the fallback banners read). FILLED dot.

    Returns [(key, full_value, compact_value, tone, ring, tooltip)] - the KEY,
    not a label, so each caller picks its own label width (SUBSYSTEM_LABELS for
    the roomy dashboard, SUBSYSTEM_LABELS_COMPACT for the cramped top bar).
    Previously this returned a bare "—" for everything pre-run, which told a
    user nothing while looking like data.
    """
    preflight = preflight or {}
    rows = []

    def ready_row(key, observed):
        """observed: (full, short, tone) once we've actually run, else None."""
        label = SUBSYSTEM_LABELS[key]
        if observed:
            full, short, tone = observed
            return (key, full, short, tone, False, f"{label}: {full} (observed this run)")
        pre = preflight.get(key)
        if pre is None:
            return (key, "checked on run", "on run", "idle", True,
                    f"{label}: can't be known until you run - it needs a live network call")
        # A 3rd, optional element is tooltip-only detail (e.g. which embedding
        # provider is configured) - kept out of `value` so the compact topbar
        # chip stays terse; only the tooltip gets the extra specificity.
        value, tone, *extra = pre
        detail = f" ({extra[0]})" if extra and extra[0] else ""
        return (key, value, value, tone, True, f"{label}: {value}{detail} (configured, not yet exercised)")

    # LLM - one provider per run, so any completed agent's mode is representative.
    # notify has no reasoning_mode (it's not an LLM-reasoning stage), so it's
    # excluded here even though it's in PIPELINE_ORDER.
    modes = [state[k]["reasoning_mode"] for k in PIPELINE_ORDER if k != "notify" and k in state]
    observed = None
    if modes:
        observed = ((f"{modes[-1].replace('live-', '')} · live", modes[-1].replace("live-", ""), "ok")
                    if modes[-1].startswith("live-") else ("mock fallback", "mock", "warn"))
    rows.append(ready_row("llm", observed))

    vs = state.get("vuln_scanner")
    observed = None
    if vs:
        observed = (("Trivy · live", "Trivy", "ok") if vs.get("scan_mode") == "trivy"
                    else ("static fallback", "static", "warn"))
    rows.append(ready_row("scanner", observed))

    ti = state.get("threat_intel")
    observed = None
    if ti:
        observed = (("NVD · live", "NVD", "ok") if ti.get("feed_mode") == "live-nvd"
                    else ("local fallback", "local", "warn"))
    rows.append(ready_row("threat_feed", observed))

    pc = state.get("policy_checker")
    observed = None
    if pc:
        if pc.get("embedding_mode") == "embeddings":
            detail = (f" ({pc['embedding_provider']}/{pc['embedding_model']})"
                      if pc.get("embedding_provider") else "")
            observed = (f"semantic · live{detail}", "semantic", "ok")
        else:
            observed = ("TF-IDF fallback", "TF-IDF", "warn")
    rows.append(ready_row("policy_rag", observed))

    return rows


def topbar_health_html(state=None, preflight=None, exclude=None):
    """Compact status chips for the top app bar - the single place subsystem
    health is shown, so it's visible from every page rather than only the
    Overview. Uses the `short` values ("Trivy" not "Trivy · live") to fit
    beside the brand; the dot carries the meaning (ring = configured/ready,
    filled = observed this run) and each chip has a tooltip spelling it out.

    `exclude`, if given, is a subsystem key or collection of keys to drop from
    the rendered HTML - used to pull "llm" and "policy_rag" out so app.py can
    render them as real, clickable gr.Buttons (see subsystem_chip_state())
    instead of inert HTML, without duplicating them here too."""
    state = state or {}
    exclude_keys = {exclude} if isinstance(exclude, str) else set(exclude or ())
    chips = [_health_chip(SUBSYSTEM_LABELS_COMPACT[key], short, tone, title=tip, ring=ring, compact=True)
             for key, _full, short, tone, ring, tip in _subsystem_health(state, preflight)
             if key not in exclude_keys]
    return '<div class="health-chips topbar-health">' + "".join(chips) + "</div>"


def subsystem_chip_state(key, state=None, preflight=None):
    """One subsystem's row from _subsystem_health, as plain data (not HTML) -
    app.py renders the AI and Policy topbar chips as real gr.Buttons (AI opens
    Settings, Policy navigates to Compliance Check) instead of inert HTML, and
    a Button needs a label string + a tone to pick a CSS class, not an HTML
    fragment. The "○"/"●" prefix mirrors the ring/filled dot the other (HTML)
    chips use, so the meaning ("configured" vs "observed this run") isn't lost
    just because these two chips are a different component type."""
    state = state or {}
    label = SUBSYSTEM_LABELS_COMPACT[key]
    for row_key, _full, short, tone, ring, tip in _subsystem_health(state, preflight):
        if row_key == key:
            dot = "○" if ring else "●"
            return f"{dot} {label} {short}", tone, tip
    return f"○ {label} —", "idle", ""


def _priority_status_line(tally, final):
    """Shared by the interim (mid-run) and final (all-5-done) status lines so
    the wording only ever diverges in the one place it needs to: whether the
    verdict is settled yet. `tally` is a real {severity: count} dict (never
    None/placeholder dashes) - callers only invoke this once _finding_tally()
    has actually reported."""
    critical, high = tally.get("CRITICAL", 0), tally.get("HIGH", 0)
    worst_sev, worst_n = ("CRITICAL", critical) if critical else ("HIGH", high)
    plural = "s" if worst_n != 1 else ""
    if critical or high:
        if final:
            text = (f'⚠️ {worst_n} {worst_sev} finding{plural} - start with <b>4. Action Plan</b> '
                     '(left nav) for what to do right now, or open any agent below for the details behind it.')
        else:
            # Deliberately NOT "⚠️ ... start with Action Plan" - that page
            # hasn't run yet, so pointing at it here would be a broken
            # promise. Italic + "so far" marks this as provisional, so the
            # KPI tiles (live as soon as 2 of 5 agents report) are never
            # sitting above blank text while 3 agents are still running.
            text = (f'{worst_n} {worst_sev} finding{plural} so far - still correlating threat intel, '
                     'action plan, and policy matches…')
    elif final:
        text = ('✅ Analysis complete, nothing CRITICAL or HIGH - open any agent (cards below '
                 'or left nav) for its findings, or the Full Report page for the complete document.')
    else:
        text = 'No CRITICAL/HIGH findings so far - still correlating threat intel, action plan, and policy matches…'
    style = "" if final else "font-style:italic;"
    return f'<div class="subdued-text" style="font-size:13px; margin-top:6px; {style}">{text}</div>'


def _risk_verdict_html(tally):
    """The single "so what" headline that leads the Overview once a run
    finishes. A time-poor reviewer (or a grading agent) should get the overall
    posture in one glance before reading any KPI tile or agent card - the level
    word is picked by the worst severity present, so the colour and label always
    agree with the numbers below. Callers only invoke this once a run is
    complete, so `tally` is a real {severity: count} dict."""
    critical = tally.get("CRITICAL", 0)
    high = tally.get("HIGH", 0)
    medium = tally.get("MEDIUM", 0)
    low = tally.get("LOW", 0)
    total = critical + high + medium + low

    if critical:
        level, color = "CRITICAL RISK", SEVERITY_COLORS["CRITICAL"]
    elif high:
        level, color = "ELEVATED RISK", SEVERITY_COLORS["HIGH"]
    elif medium:
        level, color = "MODERATE RISK", SEVERITY_COLORS["MEDIUM"]
    elif low:
        level, color = "LOW RISK", SEVERITY_COLORS["LOW"]
    else:
        level, color = "ALL CLEAR", "#16a34a"

    noun = "issue" if total == 1 else "issues"
    summary = (f"{total} {noun} detected across logs &amp; dependencies"
               if total else "No security issues in the analyzed logs or dependencies")
    return (
        f'<div class="risk-verdict" style="border-color:{color}66; background:{color}12;">'
        f'<span class="rv-badge" style="background:{color};">{level}</span>'
        f'<span class="rv-summary">{summary}</span>'
        f'</div>'
    )


def dashboard_html(state=None, running=False):
    """Overview page dashboard: an executive risk verdict (once a run finishes)
    over severity KPI tiles, an aggregated fallback banner, and a one-line
    next-step status."""
    state = state or {}

    all_warnings = []
    for a in AGENTS:
        all_warnings.extend(agent_fallback_warnings(a["key"], state))
    banner = fallback_warning_html(all_warnings)

    tally = _finding_tally(state)
    all_done = len([k for k in PIPELINE_ORDER if k in state]) == len(PIPELINE_ORDER)

    verdict = _risk_verdict_html(tally or {}) if all_done else ""

    if all_done:
        # A flat "open any agent" treated 7 CRITICAL findings and 0 findings as
        # equally worth exploring - five pages presented with equal weight when
        # the data itself is never actually balanced. Name the worst bucket and
        # point at ONE next click (Action Plan, since that's where "what do I do"
        # lives) rather than enumerating every page as an equal option.
        status_line = _priority_status_line(tally or {}, final=True)
    elif running:
        # KPI tiles go live as soon as log_monitor + vuln_scanner both report
        # (2 of 5 agents) - real, coloured numbers next to blank text for the
        # remaining ~60-70s looked like the page had stalled. Show a
        # provisional read the moment there's real data to show one; stay
        # silent only while the tiles themselves are still grey dashes (the
        # button + tracker already say "running", no need for a third copy).
        status_line = _priority_status_line(tally, final=False) if tally is not None else ""
    else:
        status_line = ('<div class="subdued-text" style="font-size:13px; margin-top:6px;">'
                       'No analysis run yet - hit <b>Run Quick Demo</b> above to see the whole '
                       'pipeline work on bundled sample data.</div>')

    # NOTE: no health chips here - they live in the top app bar, where they're
    # visible from every page. Rendering them here too put two identical chip
    # rows ~40px apart on this page.
    # The verdict leads (the "so what"), then the KPI tiles (the breakdown),
    # then the status line (the next click). Empty string when a run isn't done.
    return banner + verdict + _kpi_tiles_html(state) + status_line

# ------------------------------------------------------- self-improvement page

EVAL_RUN_PLACEHOLDER = (
    f'<div class="empty-state"><div class="empty-icon">{icon_html("shield", size=30)}</div>'
    '<div class="subdued-text">No evals have been run yet this session - click '
    '<b>Run Evals</b> above to score this app\'s own retrieval accuracy and reasoning '
    'quality against a fixed set of known-answer test cases.</div></div>'
)


def self_improvement_primer_html():
    """Always-visible explainer, same treatment as framework_primer_html - a
    first-timer needs this in plain sight, not behind a hover tooltip, since
    demos happen on a projector where nobody can hover."""
    return (
        '<div class="primer">'
        '<b>🎓 What is Evaluation, and why does this page exist?</b> Every AI agent above can be '
        'wrong, or give a different answer to the same question on different runs. '
        '<b>Evaluation is not optional for an agentic AI system</b> - without a fixed, repeatable '
        'test suite, there is no way to catch a regression from a prompt tweak, a model swap, or a '
        'retrieval change before a user does. This page runs that evaluation automatically, '
        f'using {glossary_term("Golden case", "fixed, known-answer test cases")} instead of '
        'trusting the agents\' output on faith - the same idea as a test suite catching a code '
        'regression. For a security tool specifically, a wrong compliance-control match or a '
        'hallucinated CVE has real consequences, so measuring it matters more than in most software.'
        '</div>'
    )


def _eval_tile(value_html, label, caption, color):
    return (
        f'<div style="flex:1; min-width:150px; text-align:center; padding:14px 10px; '
        f'border-radius:12px; background:{color}12; border:1px solid {color}55;">'
        f'<div style="font-size:26px; font-weight:750; color:{color};">{value_html}</div>'
        f'<div style="font-size:11px; letter-spacing:0.05em; color:{color}; text-transform:uppercase; '
        f'font-weight:600;">{label}</div>'
        f'<div class="subdued-text" style="font-size:11px; margin-top:6px; line-height:1.4;">{caption}</div>'
        '</div>'
    )


def eval_score_tiles_html(record):
    """The headline numbers, each with a plain-English 'why this matters here'
    caption rather than a bare metric name - so a reader who's never heard of
    precision/recall can still act on the score."""
    if not record:
        return EVAL_RUN_PLACEHOLDER
    retrieval = record["retrieval"]
    reasoning = record["reasoning"]

    precision_pct = round(retrieval["precision_at_1"] * 100)
    recall_pct = round(retrieval["recall_at_3"] * 100)
    precision_color = OK_GREEN if precision_pct >= 70 else WARN_AMBER
    recall_color = OK_GREEN if recall_pct >= 70 else WARN_AMBER

    tiles = [
        _eval_tile(
            f'{precision_pct}%', glossary_term("Precision@1"),
            "Low precision means Policy Checker is pointing you at the wrong compliance control - "
            "you'd waste time gathering evidence for something that isn't actually the gap. "
            f'(mode: <code>{retrieval["embedding_mode"]}</code>)',
            precision_color,
        ),
        _eval_tile(
            f'{recall_pct}%', glossary_term("Recall@3"),
            "A softer check: was the right control anywhere in the top 3 matches shown, even if "
            "not first.",
            recall_color,
        ),
    ]

    if reasoning["reasoning_mode"] == "mock":
        tiles.append(_eval_tile(
            "n/a", "Reasoning Quality",
            "No API key configured this run, so there's no live model output for a judge to "
            f'grade - {glossary_term("LLM-as-a-judge", "LLM-as-a-judge")} scoring needs a real '
            "answer to assess. Configure a key in Settings and re-run to measure this.",
            IDLE_GREY,
        ))
    else:
        faith = reasoning["faithfulness_mean"]
        parse_failures = reasoning.get("parse_failures", 0)
        faith_color = OK_GREEN if (faith >= 4 and not parse_failures) else WARN_AMBER
        caption = (
            "Low faithfulness means an agent's summary is stating things not actually present in "
            f'the findings it was given - a hallucination risk. Judged by {reasoning["reasoning_mode"]}.'
        )
        if parse_failures:
            caption += (
                f' ⚠️ {parse_failures} judge repl{"y" if parse_failures == 1 else "ies"} could not be '
                'parsed against the scoring rubric and were excluded - treat this mean with caution.'
            )
        tiles.append(_eval_tile(f'{faith:.1f} / 5', glossary_term("Faithfulness"), caption, faith_color))

    return f'<div style="display:flex; gap:10px; flex-wrap:wrap;">{"".join(tiles)}</div>'


def _eval_retrieval_case_card(case):
    color = OK_GREEN if case["top1_hit"] else (WARN_AMBER if case["any_hit"] else SEVERITY_COLORS["HIGH"])
    badge = "TOP-1 MATCH" if case["top1_hit"] else ("IN TOP-3" if case["any_hit"] else "MISS")
    body = (
        f'<div><b>Finding:</b> {_esc(case["finding_text"])}</div>'
        f'<div style="margin-top:4px;"><b>Expected control family:</b> {_esc(", ".join(case["expected"]))}</div>'
        f'<div style="margin-top:4px;"><b>Actually retrieved:</b> {_esc(", ".join(case["retrieved"])) or "(nothing above the match threshold)"}</div>'
        f'<div class="subdued-text" style="margin-top:6px; font-size:11.5px;">{_esc(case["note"])}</div>'
    )
    return _card_html("🎯", "Retrieval case", badge, color, body)


def _eval_reasoning_case_card(case):
    faith = case["faithfulness_mean"]
    is_mock = case["reasoning_mode"] == "mock"
    # In mock mode, faithfulness_mean is a hardcoded neutral placeholder (no
    # live model ever judged the summary) - showing it as "3.0/5" would read
    # as a real score. Label it plainly instead, matching how the top-level
    # tile and run-history table already report "n/a" for this case.
    badge = "not judged (mock)" if is_mock else f'{faith:.1f}/5 faithfulness'
    color = IDLE_GREY if is_mock else (OK_GREEN if faith >= 4 else WARN_AMBER)
    consistency_note = (
        "not applicable - no live model configured, so nothing was actually judged this run"
        if is_mock else
        ("perfectly consistent across repeats" if case["faithfulness_stddev"] == 0
         else f'varied by ±{case["faithfulness_stddev"]:.1f} across repeats - {glossary_term("Consistency", "see why this matters")}')
    )
    body = (
        f'<div><b>Rubric:</b> {_esc(case["rubric"])}</div>'
        f'<div style="margin-top:6px;"><b>Sample summary graded:</b> {_esc(case["sample_summary"])}</div>'
        f'<div style="margin-top:6px;"><b>Judge\'s reasoning:</b> {_esc(case["judge_reason"])}</div>'
        f'<div class="subdued-text" style="margin-top:6px; font-size:11.5px;">{consistency_note}</div>'
    )
    return _card_html("⚖️", case["name"].replace("_", " ").title(),
                       badge, color, body)


def eval_case_cards_html(record):
    """Per-case drill-down so a reader can verify the grading themselves
    instead of trusting a bare number - same transparency instinct as showing
    raw findings before an LLM's narrative elsewhere in this app."""
    if not record:
        return ""
    retrieval_cards = [_eval_retrieval_case_card(c) for c in record["retrieval"]["cases"]]
    reasoning_cards = [_eval_reasoning_case_card(c) for c in record["reasoning"]["cases"]]
    return (
        '<div style="margin-top:20px;"><h4>Retrieval cases</h4>'
        f'{"".join(retrieval_cards)}</div>'
        '<div style="margin-top:20px;"><h4>Reasoning quality cases</h4>'
        f'{"".join(reasoning_cards)}</div>'
    )


def deploy_key_hint_html(is_deployed, has_key):
    """Soft, dismissible-in-spirit nudge shown only on a deployed instance
    (RENDER env var present) when nobody has pasted an LLM key yet this
    session. Deliberately NOT shown for local runs (a dev machine has its own
    env-var/BYOK story already) and deliberately soft wording, not a blocking
    banner - this app is designed to run meaningfully with zero keys (mock
    reasoning + local/TF-IDF retrieval), so this should read as a tip to get
    the full live experience, not a requirement.

    has_key reflects the API key textbox's current value directly, not
    llm.current_provider() - that only updates once configure() runs inside
    a pipeline call, so it stayed stale (still showing this hint) for a
    user who pasted a key but hadn't clicked Run yet."""
    if not is_deployed or has_key:
        return ""
    return (
        '<div style="display:flex; align-items:center; gap:10px; padding:8px 14px; '
        f'border-radius:8px; background:{ACCENT}12; border:1px solid {ACCENT}55; margin:0 0 12px 0;">'
        f'<span style="font-size:15px;">💡</span>'
        '<div style="font-size:12.5px;">Running without a key right now - reasoning is on the '
        'deterministic mock path. Paste an <b>OpenRouter</b> key in <b>Configure Models</b> (top right) '
        'for live AI reasoning and full semantic policy search.</div>'
        '</div>'
    )


def eval_storage_status_html(storage_mode):
    """Prominent, always-visible banner on whether eval run history is
    genuinely persistent (Supabase) or will be lost on the next restart/
    redeploy (local file). Deliberately placed near the Run Evals button,
    not buried under the results below - this is a property of the current
    deployment's configuration, not of any single run, so it should be
    visible before a reviewer even clicks anything."""
    is_live = storage_mode == "supabase-live"
    color = OK_GREEN if is_live else WARN_AMBER
    icon = "🗄️" if is_live else "💾"
    label = "Persistent history - Supabase connected" if is_live else "Session-only history - no Supabase configured"
    detail = (
        "Run history is stored in Supabase and will survive a server restart or redeploy."
        if is_live else
        "SUPABASE_URL / SUPABASE_SECRET_KEY aren't configured (or Supabase couldn't be reached), "
        "so history is being kept in a local file instead - it will NOT survive a redeploy."
    )
    return (
        f'<div style="display:flex; align-items:center; gap:10px; padding:9px 14px; '
        f'border-radius:8px; background:{color}12; border:1px solid {color}55; margin:10px 0;">'
        f'<span style="font-size:16px;">{icon}</span>'
        f'<div><div style="font-weight:700; font-size:12.5px; color:{color};">{label}</div>'
        f'<div class="subdued-text" style="font-size:11.5px; margin-top:2px;">{detail}</div></div>'
        '</div>'
    )


def eval_history_html(history, storage_mode):
    """Run-history table. The storage_mode banner itself lives at the top of
    the page (eval_storage_status_html) - not repeated here to avoid saying
    the same thing twice on one page."""
    if not history:
        return '<div class="subdued-text" style="margin-top:4px;">No runs recorded yet.</div>'

    rows = ""
    for rec in history:
        ts = rec["timestamp"][:19].replace("T", " ")
        precision = round(rec["retrieval"]["precision_at_1"] * 100)
        mode = rec["reasoning"]["reasoning_mode"]
        faith = ("n/a" if mode == "mock" else f'{rec["reasoning"]["faithfulness_mean"]:.1f}/5')
        rows += (
            f'<tr><td style="padding:6px 10px;">{ts} UTC</td>'
            f'<td style="padding:6px 10px;">{precision}%</td>'
            f'<td style="padding:6px 10px;">{faith}</td>'
            f'<td style="padding:6px 10px;"><code>{mode}</code></td></tr>'
        )
    table = (
        '<div style="overflow-x:auto; margin-top:12px;">'
        '<table style="width:100%; border-collapse:collapse; font-size:12.5px;">'
        '<thead><tr style="text-align:left; border-bottom:1px solid var(--border-color-primary);">'
        '<th style="padding:6px 10px;">Run (UTC)</th><th style="padding:6px 10px;">Retrieval Precision@1</th>'
        '<th style="padding:6px 10px;">Reasoning Faithfulness</th><th style="padding:6px 10px;">Reasoning mode</th>'
        '</tr></thead><tbody>'
        f'{rows}</tbody></table></div>'
    )
    return table

# -------------------------------------------------------------------- theme


CUSTOM_CSS = """
/* ---------- top bar ---------- */
#app-topbar {
    align-items: center;
    border-bottom: 1px solid var(--border-color-primary);
    padding: 2px 0 10px 0;
    margin-bottom: 10px;
    flex-wrap: wrap;
    row-gap: 8px;
}
/* Gradio nests each Row child as .block > .html-container > .prose, and the
   padding that broke alignment lives on the INNER .html-container (10px 12px),
   not the .block - so styling .block alone changed nothing. On top of that,
   prose margins left the chips' box 53px tall around a 23px chip row, so the
   chips floated near its top. Net effect: align-items:center correctly centred
   the BOXES (~55) while the eye saw content at 47/42/55.
   Fix = strip the inner padding and margins so every box hugs its content;
   then centring aligns what's actually visible. Verify by comparing the
   centreY of .brand-title / .chip / #settings-toggle-btn - they must match. */
#app-topbar > .block {
    padding: 0 !important;
    margin: 0 !important;
    border: none !important;
    background: transparent !important;
    min-width: 0;
    align-self: center;
}
#app-topbar .html-container { padding: 0 !important; margin: 0 !important; }
#app-topbar .prose { margin: 0 !important; }
#app-topbar .prose > * { margin: 0 !important; }
#app-topbar .topbar-health { margin: 0 !important; }
/* AI/Scan/CVE/Policy need to read as ONE chip cluster, not four separately-
   spaced components - #chip-cluster is a nested Row (see app.py) so its three
   children (ai_chip_btn, the Scan+CVE HTML, policy_chip_btn) get their own
   tight gap instead of Gradio's normal (much larger) inter-component spacing,
   and none of them stretch to fill space, which is what left visible gaps
   between the chip groups. */
#chip-cluster {
    flex: 0 1 auto !important;
    flex-wrap: nowrap !important;
    gap: 6px !important;
    align-items: center;
}
/* Gradio's own block wrapper sets width:100% internally - flex:0 0 auto alone
   doesn't override that (flex-basis:auto still resolves through an explicit
   width), so it claimed the whole row and wrapped the other two chips onto
   separate lines. width:auto is the actual fix; flex is kept for intent. */
#chip-cluster > .block { flex: 0 0 auto !important; width: auto !important; }
/* #chip-cluster itself is a Gradio .row, not .block - the rule above (and
   #app-topbar > .block) never touches it, so it still inherits Gradio's
   default .row width:100%, which wins over its own flex-grow:0 and forces
   it (and everything after it) onto its own full-width line. */
#app-topbar > #chip-cluster { width: auto !important; }
.brand-title { font-size: 17px; font-weight: 700; letter-spacing: -0.01em; }
/* The shield SVG shares the brand-title's left edge but Gradio's base
   stylesheet sets `svg { display: block }` globally, which drops it onto
   its own line despite the icon's own inline vertical-align. Scope it back
   to inline here rather than fighting the global rule everywhere else.
   Tinted with the theme's own primary hue (cyan) rather than inventing a
   new accent color - this app has no other decorative color, only the
   semantic OK_GREEN/WARN_AMBER status colors, which this must not collide with. */
.brand-title svg { display: inline; color: var(--primary-600); }
.brand-sub { font-size: 11.5px; margin-top: 1px; }
/* Version sits with the brand but must never compete with it - small, muted,
   monospace so digits don't reflow as it grows (v0.9 -> v0.10). */
.version-badge {
    font-family: var(--font-mono, monospace);
    font-size: 10.5px;
    font-weight: 600;
    margin-left: 8px;
    padding: 2px 7px;
    border-radius: 999px;
    background: #94a3b81f;
    color: #64748b;
    border: 1px solid #94a3b840;
    vertical-align: middle;
}
.dark .version-badge { color: #94a3b8; }

/* Gradio's `secondary` variant is a pale slate-200 FILL (#e2e8f0) with black
   text - against a white bar that reads as a DISABLED control, not an
   available one. This is a secondary action next to the primary "Run Quick
   Demo", so it should be OUTLINED: clearly interactive, visibly subordinate.
   Explicit height/line-height so it shares one optical line with the chips
   instead of relying on Gradio's default button box. */
#settings-toggle-btn {
    position: relative;
    background: transparent !important;
    border: 1px solid var(--border-color-primary) !important;
    color: var(--body-text-color) !important;
    font-size: 12.5px !important;
    font-weight: 600 !important;
    height: 30px !important;
    min-height: 30px !important;
    line-height: 1 !important;
    padding: 0 12px !important;
    border-radius: 8px !important;
    display: inline-flex !important;
    align-items: center;
    justify-content: center;
    gap: 6px;
    white-space: nowrap;
    transition: border-color 0.15s ease, background-color 0.15s ease, color 0.15s ease;
}
/* U+2699 in TEXT presentation (no emoji variation selector), so it renders as
   a glyph inheriting currentColor rather than a fixed-palette colour emoji -
   sized independently of the label, and it recolours on hover with the text. */
#settings-toggle-btn::before {
    content: "\\2699";
    font-size: 15px;
    line-height: 1;
    opacity: 0.85;
}
#settings-toggle-btn:hover {
    border-color: #06b6d4 !important;
    background: #06b6d414 !important;
    color: #0e7490 !important;
}
#settings-toggle-btn:hover::before { opacity: 1; }
.dark #settings-toggle-btn:hover { color: #22d3ee !important; }
#settings-toggle-btn:hover::after {
    content: "Choose the reasoning LLM & embedding model - or bring your own key";
    position: absolute;
    top: 100%;
    right: 0;
    margin-top: 6px;
    background: #111827;
    color: #fff;
    padding: 6px 10px;
    border-radius: 6px;
    font-size: 12px;
    white-space: nowrap;
    z-index: 9999;
    pointer-events: none;
}

/* Gradio's own --body-text-color-subdued is a fixed light gray (#bbbbc2) in
   BOTH light and dark mode, so it's invisible on white backgrounds. Gradio
   toggles dark mode via a ".dark" class (no prefers-color-scheme media
   queries), so mirror that here with per-mode colors. */
.subdued-text { color: #6b7280; }
.dark .subdued-text, :root .dark .subdued-text { color: #bbbbc2; }

/* ---------- nav sidebar ----------
   Every row is forced to a single line of identical height: labels are short
   by design (see app.py), but this guarantees the rhythm holds even if a
   future label grows - it truncates rather than wrapping and shoving the
   list out of alignment. */
.nav-btn {
    justify-content: flex-start !important;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
    min-height: 34px;
    text-align: left;
    transition: background-color 0.15s ease, border-color 0.15s ease, transform 0.1s ease;
}
.nav-btn:hover { border-color: #06b6d488; transform: translateX(2px); }

/* Admin/reviewer-facing nav items (currently just Evaluations) get a purple
   left-edge stripe so they read as a distinct group from the regular-user
   pages above, without implying real access control this app doesn't have. */
.nav-btn-admin { border-left: 3px solid #a855f7 !important; }
.nav-btn-admin:hover { border-color: #a855f788; }

/* ---------- overview agent cards ----------
   Gradio's Row is a wrapping flexbox, and `equal_height` only equalises
   cards *within one line* - with 5 cards it wrapped to two lines and gave
   177/154/132px. Overriding to a real grid with `grid-auto-rows: 1fr` makes
   every row track the same height, so all cards match no matter how they
   wrap. Each card is then a full-height flex column with the button pushed
   down by `margin-top:auto`, so buttons land on one baseline regardless of
   how long each blurb is. */
#agent-card-grid {
    display: grid !important;
    grid-template-columns: repeat(auto-fit, minmax(185px, 1fr));
    grid-auto-rows: 1fr;
    gap: 14px;
    margin-bottom: 8px;
    flex-wrap: nowrap !important;
}
#agent-card-grid > * { min-width: 0; }
.agent-card {
    border: 1px solid var(--border-color-primary);
    border-top: 3px solid var(--border-color-primary);
    border-radius: 12px;
    padding: 14px !important;
    height: 100%;
    display: flex !important;
    flex-direction: column;
    transition: transform 0.15s ease, box-shadow 0.15s ease, border-color 0.15s ease;
}
.agent-card:hover { transform: translateY(-3px); }
.agent-card > *:last-child { margin-top: auto; }

/* ---------- executive risk verdict ---------- */
/* The "so what" headline that leads the Overview once a run completes. Reads
   as one bold statement from across a room (this gets demoed on a projector),
   sitting above the KPI breakdown - the colour is the worst severity present. */
.risk-verdict {
    display: flex; align-items: center; gap: 14px; flex-wrap: wrap;
    border: 1px solid; border-radius: 12px;
    padding: 14px 18px; margin: 24px 0 4px 0;
}
.rv-badge {
    color: #fff; font-size: 15px; font-weight: 800; letter-spacing: 0.04em;
    padding: 6px 14px; border-radius: 999px; white-space: nowrap;
}
.rv-summary { font-size: 15px; font-weight: 600; }

/* ---------- KPI tiles + health chips ---------- */
/* 24px above: separates "what happened" (KPI) from "how it ran" (tracker,
   directly above) as two distinct reading beats rather than one dense block.
   When the verdict banner is present it owns that top gap, so the tiles tuck
   closer beneath it. */
.risk-verdict + .kpi-row { margin-top: 12px; }
.kpi-row { display: flex; gap: 10px; margin: 24px 0 16px 0; }
.kpi-tile {
    flex: 1; text-align: center; padding: 14px 8px;
    border: 1px solid; border-radius: 12px;
}
.kpi-num { font-size: 30px; font-weight: 750; line-height: 1.1; }
.kpi-label { font-size: 11px; letter-spacing: 0.06em; font-weight: 600; }
/* no data yet - visibly inert, so a grey "—" reads as "not measured"
   rather than a severity reading of zero/unknown */
.kpi-tile.idle { opacity: 0.55; }
.kpi-tile.idle .kpi-num { font-weight: 600; }

.health-chips { display: flex; flex-wrap: wrap; gap: 8px; margin: 2px 0; }
.chip {
    display: inline-flex; align-items: center; gap: 6px;
    font-size: 12px; padding: 4px 12px; border-radius: 999px;
    border: 1px solid var(--border-color-primary);
}
.chip-dot { width: 7px; height: 7px; border-radius: 50%; display: inline-block; }
.chip.ok    { border-color: #16a34a55; } .chip.ok .chip-dot    { background: #16a34a; }
.chip.warn  { border-color: #f59e0b88; } .chip.warn .chip-dot  { background: #f59e0b; }
.chip.idle .chip-dot { background: #94a3b8; }
/* Hollow dot = configured but not yet exercised this run. A FILLED dot is
   reserved for something we actually observed happen - same discipline as the
   tracker, where green only ever means "ran on its real path". */
.chip-dot.ring { background: transparent !important; border: 1.5px solid currentColor; }
.chip.ok .chip-dot.ring   { color: #16a34a; }
.chip.warn .chip-dot.ring { color: #f59e0b; }
.chip.idle .chip-dot.ring { color: #94a3b8; }
.chip { cursor: default; }

/* compact variant for the top bar - abbreviated values, tighter padding.
   The top bar is now the ONLY place these render, so they must never be
   hidden: on narrow widths they wrap onto a second line instead of
   disappearing, which would leave no health signal anywhere. */
.chip.compact { font-size: 11px; padding: 3px 9px; gap: 5px; }
/* align-content:center so that IF these ever wrap to a second row, the block
   still centres against the brand and button instead of hanging off the top
   (which is exactly how the two-row overflow read as "broken alignment"). */
.topbar-health {
    justify-content: flex-end;
    align-content: center;
    align-items: center;
    gap: 6px;
    flex-wrap: wrap;
}
@media (max-width: 1000px) { .topbar-health { justify-content: flex-start; } }

/* AI and Policy chips are real gr.Buttons (not HTML like Scan/CVE), so they
   can navigate/open Settings on click. At REST they're styled to look
   IDENTICAL to their HTML siblings (.chip.compact) - same border-only tone,
   no fill, neutral label text - so nothing marks them as "different" just
   sitting there; a permanent color/fill difference isn't a real signal
   anyway once every chip happens to share the same tone. Clickability is
   revealed ONLY on hover (tone tint + a small lift), the same restrained
   language .nav-btn:hover already uses elsewhere in this app. !important
   overrides Gradio's own button sizing/background defaults. */
.chip-btn {
    font-size: 11px !important; font-weight: 600 !important;
    padding: 3px 9px !important; min-height: unset !important; height: auto !important;
    min-width: unset !important; width: auto !important;
    border-radius: 999px !important; box-shadow: none !important;
    white-space: nowrap; background: transparent !important;
    color: var(--body-text-color) !important;
    /* Gradio's secondary button has border-width:0 by default - setting only
       border-color (as this rule used to) is invisible without also forcing
       a real width/style, which is why these looked borderless next to
       Scan/CVE's 1px HTML-chip border. */
    border-width: 1px !important; border-style: solid !important;
    transition: background-color 0.15s ease, transform 0.1s ease;
}
.chip-btn.ok   { border-color: #16a34a55 !important; }
.chip-btn.warn { border-color: #f59e0b88 !important; }
.chip-btn.idle { border-color: #94a3b855 !important; }
.chip-btn.ok:hover   { background: #16a34a12 !important; transform: translateY(-1px); }
.chip-btn.warn:hover { background: #f59e0b12 !important; transform: translateY(-1px); }
.chip-btn.idle:hover { background: #94a3b812 !important; transform: translateY(-1px); }

/* Settings sidebar's Provider/Embedding Provider radios rendered noticeably
   roomier than the rest of this app's compact controls (Gradio's own default:
   ~6px/12px padding, 14px font). Tightened here via a plain `label` tag
   selector scoped under our own .compact-radio class - robust across Gradio
   versions, since it doesn't depend on Gradio's internal svelte-* hash
   classes (confirmed live: those exist but aren't a stable target). */
.compact-radio label { padding: 3px 10px !important; font-size: 12px !important; }
.compact-radio .wrap { gap: 4px !important; }

/* ---------- pipeline tracker ---------- */
.pl-wrap {
    border: 1px solid var(--border-color-primary); border-radius: 12px;
    padding: 14px 16px; margin: 16px 0 24px 0;
    background: var(--background-fill-secondary);
}
/* Teal, not green/amber - those already mean done/degraded. A pulsing glow
   (not a hard blink) on the whole box says "a run is actively in progress"
   without reading as an alert. Settles the instant nothing is running. */
.pl-wrap.active { animation: pl-box-glow 1.8s ease-in-out infinite; }
@keyframes pl-box-glow {
    0%, 100% { box-shadow: 0 0 0 1px #0d948833; border-color: #0d948866; }
    50% { box-shadow: 0 0 0 6px #0d948833; border-color: #0d9488; }
}
.dark .pl-wrap.active { animation: pl-box-glow-dark 1.8s ease-in-out infinite; }
@keyframes pl-box-glow-dark {
    0%, 100% { box-shadow: 0 0 0 1px #2dd4bf33; border-color: #2dd4bf66; }
    50% { box-shadow: 0 0 0 6px #2dd4bf33; border-color: #2dd4bf; }
}
/* header: names the block as the live orchestration graph, so a viewer reads
   the nodes below as a DAG rather than a generic progress bar. */
.pl-header {
    display: flex; align-items: center; justify-content: space-between;
    gap: 10px; flex-wrap: wrap; margin-bottom: 12px;
}
.pl-title { font-size: 12px; font-weight: 700; letter-spacing: 0.03em; text-transform: uppercase; color: #64748b; }
.pl-title-sub { font-size: 10.5px; font-weight: 500; text-transform: none; letter-spacing: normal; color: #94a3b8; }
.dark .pl-title-sub { color: #64748b; }
.pl-tag {
    font-size: 10.5px; font-weight: 700; letter-spacing: 0.02em;
    color: #6366f1; background: #6366f114; border: 1px solid #6366f13a;
    padding: 2px 9px; border-radius: 999px; white-space: nowrap;
}
.dark .pl-title { color: #94a3b8; }
.dark .pl-tag { color: #a5b4fc; background: #6366f11f; border-color: #6366f14d; }
.pl-track { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }
/* the parallel fan-in: two stacked nodes sharing a right-hand bracket + a
   vertical "parallel" tag, so the branch topology is explicit rather than
   implied by mere vertical stacking. */
.pl-branch { display: flex; align-items: stretch; gap: 7px; }
.pl-parallel { display: flex; flex-direction: column; gap: 8px; }
.pl-branch-tag {
    display: flex; align-items: center; justify-content: center;
    writing-mode: vertical-rl; text-orientation: mixed;
    font-size: 9px; font-weight: 700; letter-spacing: 0.1em; text-transform: uppercase;
    color: #94a3b8; border-left: 2px solid #cbd5e1;
    border-top-right-radius: 4px; border-bottom-right-radius: 4px; padding: 0 1px 0 4px;
}
.dark .pl-branch-tag { border-left-color: #475569; }
/* action tag: recolored + mirrored (border-right, sits left of the node) so
   it reads as a different kind of hand-off, not another "parallel" grouping */
.pl-action-tag {
    color: #6366f1; border-left: none; border-right: 2px solid #6366f1a5;
    border-top-right-radius: 0; border-bottom-right-radius: 0;
    border-top-left-radius: 4px; border-bottom-left-radius: 4px;
    padding: 0 4px 0 1px;
}
.dark .pl-action-tag { border-right-color: #818cf899; color: #a5b4fc; }
.pl-arrow-act { color: #6366f1; font-weight: 600; font-size: 15px; }
.dark .pl-arrow-act { color: #a5b4fc; }
.pl-node {
    /* Radius hierarchy: 12px is reserved for primary containers (agent-card,
       kpi-tile, pl-wrap) - a repeated dense-data row like this one gets a
       sharper 6px so it doesn't compete on equal footing with the surface
       that holds it. Uniform 10-12px everywhere was the "vibe-coded" tell:
       nothing read as more/less important than anything else. */
    border: 1px solid var(--border-color-primary); border-radius: 6px;
    padding: 8px 12px; min-width: 132px;
    background: var(--background-fill-primary);
    transition: border-color 0.2s ease, box-shadow 0.2s ease;
}
.pl-node .pl-name { font-size: 12.5px; font-weight: 650; white-space: nowrap; }
.pl-status { font-size: 11px; display: inline-flex; align-items: center; gap: 5px; margin-top: 2px; }
.pl-status.done { color: #15803d; font-weight: 700; }
.pl-status.pending, .pl-status.idle { color: #94a3b8; }
.pl-status.running { color: #0e7490; font-weight: 700; }

/* State drives the node FILL, not just the border - a 1px green outline was
   too subtle to read at a glance (and invisible on a projector). */
.pl-node.idle, .pl-node.pending { background: #94a3b814; border-color: #94a3b855; }
.pl-node.running {
    background: #06b6d422; border-color: #06b6d4;
    box-shadow: 0 0 0 3px #06b6d426;
}
.pl-node.done { background: #16a34a26; border-color: #16a34a; }
/* completed but degraded - green must only ever mean "ran on its real path" */
.pl-node.done.warn { background: #f59e0b26; border-color: #f59e0b; }
.pl-node.done.warn .pl-status.done { color: #b45309; }

.dark .pl-status.done { color: #4ade80; }
.dark .pl-status.running { color: #22d3ee; }
.dark .pl-node.done.warn .pl-status.done { color: #fbbf24; }
.pl-dot {
    width: 7px; height: 7px; border-radius: 50%; background: #06b6d4;
    display: inline-block; animation: pl-pulse 1s ease-in-out infinite;
}
@keyframes pl-pulse { 0%, 100% { opacity: 1; } 50% { opacity: 0.25; } }
.pl-arrow { font-size: 20px; color: #9ca3af; font-weight: 300; }
.pl-warn { color: #f59e0b; }
.pl-caption { font-size: 12px; margin-top: 8px; }

/* ---------- collapsible finding cards ---------- */
.finding-card {
    /* Sharper radius (see .pl-node) - this is a repeated dense-data row,
       not a primary container; more vertical breathing room between stacked
       cards than the old 10px, so a long findings list doesn't read as one
       fused block. */
    border-radius: 6px; margin-bottom: 16px; overflow: hidden;
    transition: box-shadow 0.15s ease;
}
.finding-card:hover { box-shadow: 0 3px 10px rgba(0, 0, 0, 0.07); }
.finding-card summary {
    display: flex; justify-content: space-between; align-items: center; gap: 12px;
    padding: 12px 16px; cursor: pointer; list-style: none;
}
.finding-card summary::-webkit-details-marker { display: none; }
.finding-card summary::after {
    content: "›"; font-size: 18px; color: #9ca3af;
    transform: rotate(90deg); transition: transform 0.15s ease;
    flex-shrink: 0; margin-left: 4px;
}
.finding-card[open] summary::after { transform: rotate(-90deg); }
.fc-title { font-weight: 700; font-size: 14px; }
.fc-badge {
    flex-shrink: 0; color: #fff; font-size: 10.5px; font-weight: 700;
    padding: 3px 10px; border-radius: 999px; letter-spacing: 0.04em;
    white-space: nowrap; margin-left: auto;
}
.fc-body { padding: 0 16px 14px 16px; }

/* ---------- severity filter chips ---------- */
.severity-filter label {
    border-radius: 999px !important;
}

/* ---------- glossary terms + framework primer ----------
   A dotted underline is the long-standing convention for "there's a definition
   here" - without it a bare title= tooltip is undiscoverable, since nobody
   hovers text that looks inert. help cursor reinforces it. */
.gloss {
    text-decoration: none;
    border-bottom: 1px dotted currentColor;
    cursor: help;
    font-weight: 600;
    color: inherit;
}
a.gloss { cursor: pointer; }
a.gloss:hover, abbr.gloss:hover { border-bottom-style: solid; color: #0e7490; }
.dark a.gloss:hover, .dark abbr.gloss:hover { color: #22d3ee; }

.primer {
    border: 1px solid var(--border-color-primary);
    border-left: 3px solid #6366f1;
    background: #6366f10f;
    border-radius: 8px;
    padding: 10px 14px;
    margin: 4px 0 20px 0;
    font-size: 12.5px;
    line-height: 1.6;
}

/* ---------- empty states ---------- */
.empty-state { text-align: center; padding: 28px 12px; }
.empty-icon { font-size: 30px; margin-bottom: 6px; opacity: 0.5; }
/* Gradio's base stylesheet sets `svg { display: block }` globally, which
   defeats .empty-state's text-align:center (that only centers inline
   content) - the shield renders as its own left-aligned block instead of
   centered, floating oddly in the empty space. Same root cause as the
   earlier icon-zap/icon-folder tab bug. */
.empty-icon svg { display: inline-block; }

/* ---------- "what can I upload?" help panel ---------- */
.fh-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(230px, 1fr));
    gap: 10px;
    margin: 8px 0 20px 0;
}
.fh-card {
    border: 1px solid var(--border-color-primary);
    border-radius: 8px;
    padding: 12px 14px;
    background: var(--background-fill-secondary);
    font-size: 12.5px;
}
.fh-title { font-weight: 700; font-size: 13.5px; margin-bottom: 8px; }
.fh-card ul { margin: 3px 0 0 16px; padding: 0; }
.fh-card li { margin-bottom: 2px; }
.fh-card code { font-size: 11px; padding: 1px 4px; border-radius: 4px; }
.fh-ok b { color: #16a34a; }
.fh-no { margin-top: 7px; }
.fh-no b { color: #dc2626; }
.fh-detects {
    margin-top: 9px; padding-top: 8px;
    border-top: 1px dashed var(--border-color-primary);
    font-size: 12px;
}

/* ---------- action buttons ----------
   Gradio buttons stretch to fill their container, so a standalone action
   button spans the whole page and reads like a banner rather than a button.
   This is a CLASS, not a per-id rule: the previous `#run-demo-btn` one-off
   capped Quick Demo and silently left "Run Analysis" and "Rebuild Index"
   full-width. Any new standalone button should get `action-btn`. */
.action-btn { max-width: 260px; }

/* ---------- type scale ----------
   Page content used a near-flat scale: h2 22px/600, h3 same weight as body
   text at 14-16px, blurbs indistinguishable from headings in weight. Nothing
   told the eye where to look first pre-run (before the 30px KPI numbers
   exist). Widen the scale: a real page-level heading, and secondary/blurb
   text pushed down rather than left at body size. */
.gradio-container .prose h2 {
    font-size: 26px !important;
    font-weight: 700 !important;
    letter-spacing: -0.015em;
    margin: 4px 0 20px 0 !important;
}
.gradio-container .prose h3 {
    font-size: 16px !important;
    font-weight: 700 !important;
    margin: 4px 0 10px 0 !important;
}
/* Card/page blurbs are the paragraph directly following an h3/h2 inside
   these two contexts - sized down so the heading above it reads as the
   clear first stop, not a same-weight sibling. Colour matches .subdued-text
   rather than Gradio's own --body-text-color-subdued, which is broken
   (fixed light-gray in both light AND dark mode - see that class's comment). */
.agent-card .prose p, .page-heading .prose p {
    font-size: 12.5px !important;
    line-height: 1.55 !important;
    color: #6b7280;
}
.dark .agent-card .prose p, .dark .page-heading .prose p { color: #bbbbc2; }
""" + "\n" + _icon_mask_css()


# Per-agent accents removed - severity colors only for clearer visual signal
# (Fix #4: eliminate vibe-coded AI defaults, prioritize severity as the primary signal)
