"""
Unit tests for the deterministic core - the regex/parsing/normalization layer
that everything else (LLM summaries, councils, evals, alerts) builds on. The
evals framework measures model quality; this file covers the plumbing.

Run with: python -m pytest tests/
"""

import os
import sys
import textwrap

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agents import notify
from agents.council import _parse_agreement
from agents.log_monitor import parse_log
from agents.vuln_scanner import SEVERITY_NORMALIZE, parse_requirements
from evals.run_evals import SCORE_RE, _matches_expected


# --------------------------------------------------------------- log monitor

def _write(tmp_path, name, content):
    p = tmp_path / name
    p.write_text(textwrap.dedent(content), encoding="utf-8")
    return str(p)


def test_parse_log_detects_ssh_bruteforce(tmp_path):
    lines = "\n".join(
        f"Jan 10 10:0{i}:00 host sshd[100]: Failed password for root from 203.0.113.9 port 4400{i}"
        for i in range(3)
    )
    findings = parse_log(_write(tmp_path, "auth.log", lines))
    brute = [f for f in findings if f["type"] == "ssh_bruteforce"]
    assert len(brute) == 1
    assert brute[0]["severity"] == "CRITICAL"
    assert brute[0]["source_ip"] == "203.0.113.9"


def test_parse_log_two_failures_is_not_bruteforce(tmp_path):
    lines = "\n".join(
        f"Jan 10 10:0{i}:00 host sshd[100]: Failed password for root from 203.0.113.9 port 4400{i}"
        for i in range(2)
    )
    findings = parse_log(_write(tmp_path, "auth.log", lines))
    assert not [f for f in findings if f["type"] == "ssh_bruteforce"]


def test_parse_log_privileged_password_login(tmp_path):
    line = "Jan 10 10:00:00 host sshd[100]: Accepted password for root from 198.51.100.7 port 22 ssh2"
    findings = parse_log(_write(tmp_path, "auth.log", line))
    assert any(f["type"] == "privileged_password_login" for f in findings)


def test_parse_log_keybased_login_is_clean(tmp_path):
    line = "Jan 10 10:00:00 host sshd[100]: Accepted publickey for root from 198.51.100.7 port 22 ssh2"
    assert parse_log(_write(tmp_path, "auth.log", line)) == []


def test_parse_log_port_scan_needs_three_distinct_ports(tmp_path):
    lines = "\n".join(
        f"Jan 10 kernel: [UFW BLOCK] IN=eth0 SRC=192.0.2.4 DST=10.0.0.5 DPT={port}"
        for port in (6379, 27017, 5432)
    )
    findings = parse_log(_write(tmp_path, "auth.log", lines))
    scans = [f for f in findings if f["type"] == "port_scan"]
    assert len(scans) == 1 and scans[0]["source_ip"] == "192.0.2.4"


def test_parse_log_survives_non_utf8_bytes(tmp_path):
    p = tmp_path / "auth.log"
    p.write_bytes(b"Jan 10 host sshd[1]: Failed password for root from 203.0.113.9 port 1\xff\n")
    parse_log(str(p))  # must not raise UnicodeDecodeError


def test_parse_log_html_in_log_is_treated_as_data(tmp_path):
    # An uploaded log line carrying markup must parse as plain data - the
    # rendering layer (ui_render._esc) is responsible for neutralizing it.
    line = 'Jan 10 host sudo[9]: eve : TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=chmod 777 /var/www/<script>x</script>'
    findings = parse_log(_write(tmp_path, "auth.log", line))
    assert any(f["type"] == "insecure_permission_change" for f in findings)


# -------------------------------------------------------------- vuln scanner

def test_parse_requirements_pins_only(tmp_path):
    content = """\
        # comment
        Flask==2.0.1
        requests >= 2.0
        PyYAML == 5.3.1

        not a requirement line
    """
    deps = parse_requirements(_write(tmp_path, "requirements.txt", content))
    assert ("flask", "2.0.1") in deps
    assert ("pyyaml", "5.3.1") in deps
    assert all(name != "requests" for name, _ in deps)  # unpinned -> skipped


def test_severity_normalize_maps_unknown_to_low():
    assert SEVERITY_NORMALIZE["UNKNOWN"] == "LOW"
    assert SEVERITY_NORMALIZE["CRITICAL"] == "CRITICAL"


# ------------------------------------------------------------------- council

def test_parse_agreement_plain_words():
    assert _parse_agreement("AGREE\nDo the thing.") == "agree"
    assert _parse_agreement("DISAGREE\nReviewer B is wrong.") == "disagree"


def test_parse_agreement_tolerates_markdown_decoration():
    assert _parse_agreement("**AGREE** - both reviewers align.") == "agree"
    assert _parse_agreement("  \n> DISAGREE: they differ on step 1") == "disagree"


def test_parse_agreement_unparseable_is_explicit():
    assert _parse_agreement("Both reviewers make good points.") == "unparseable"
    assert _parse_agreement("") == "unparseable"
    assert _parse_agreement(None) == "unparseable"


def test_parse_agreement_disagree_not_misread_as_agree():
    # "DISAGREEMENT" is neither exact verdict word - it must fall to the
    # explicit neutral state, and must never be misread as "agree"
    assert _parse_agreement("DISAGREEMENT is putting it mildly.") == "unparseable"


# --------------------------------------------------------------------- evals

def test_matches_expected_accepts_family_and_enhancements():
    assert _matches_expected("AC-6", ["AC-6"])
    assert _matches_expected("AC-6.10", ["AC-6"])
    assert not _matches_expected("AC-61", ["AC-6"])  # prefix alone is not a family match
    assert not _matches_expected("SI-4", ["AC-6"])


def test_judge_score_regex_parses_expected_format():
    m = SCORE_RE.search("FAITHFULNESS: 4\nRELEVANCE: 5\nREASON: solid.")
    assert m and (m.group(1), m.group(2)) == ("4", "5")


def test_judge_score_regex_rejects_prose():
    assert SCORE_RE.search("I would rate this summary highly overall.") is None


# -------------------------------------------------------------------- notify

def test_parse_list_accepts_string_and_list():
    assert notify.parse_list("CRITICAL, HIGH") == ["CRITICAL", "HIGH"]
    assert notify.parse_list(["HIGH", "HIGH", "LOW"]) == ["HIGH", "LOW"]
    assert notify.parse_list("CRITICAL\nHIGH") == ["CRITICAL", "HIGH"]
    assert notify.parse_list(None) == []


def test_send_slack_rejects_non_slack_urls():
    import pytest
    with pytest.raises(ValueError):
        notify._send_slack("https://internal.example/metadata", "text")
    with pytest.raises(ValueError):
        notify._send_slack("http://hooks.slack.com/services/x", "text")  # http, not https
