"""
One-time (or rarely-run) data-prep script: fetches the official NIST SP
800-53 Rev 5 control catalog (OSCAL JSON format, public, no auth) and
flattens it into data/knowledgebase/nist_800_53_catalog.json - a simple list of
{control_id, family, family_title, title, statement} chunks that
agents/policy_checker.py embeds and searches against.

This is NOT run at pipeline runtime - NIST revises 800-53 roughly once every
several years (Rev 4 -> 2013, Rev 5 -> 2020, Rev 5.1 -> 2023), so re-fetching
the catalog on every app run would be pointless. Re-run this script by hand
only when NIST ships a new revision. The separate "Rebuild Index" button in
the app re-embeds the existing data/knowledgebase/nist_800_53_catalog.json file - it does
not re-fetch from NIST.

Usage:
    python3 scripts/fetch_nist_catalog.py
"""

import json
import re

CATALOG_URL = (
    "https://raw.githubusercontent.com/usnistgov/oscal-content/main/"
    "nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_catalog.json"
)
OUTPUT_PATH = "data/knowledgebase/nist_800_53_catalog.json"

PARAM_PLACEHOLDER_RE = re.compile(r"\{\{\s*insert:\s*param,\s*[\w.-]+\s*\}\}")


def _clean_prose(text: str) -> str:
    return PARAM_PLACEHOLDER_RE.sub("[organization-defined parameter]", text).strip()


def _extract_statement(control: dict) -> str:
    statement_part = next((p for p in control.get("parts", []) if p.get("name") == "statement"), None)
    if not statement_part:
        return ""
    texts = []

    def collect(part):
        if part.get("prose"):
            texts.append(part["prose"])
        for sub_part in part.get("parts", []):
            collect(sub_part)

    collect(statement_part)
    return _clean_prose(" ".join(texts))


def _is_withdrawn(control: dict) -> bool:
    return any(p.get("name") == "status" and p.get("value") == "withdrawn" for p in control.get("props", []))


def _flatten_control(control: dict, family_id: str, family_title: str, chunks: list):
    if not _is_withdrawn(control):
        chunks.append({
            "control_id": control["id"].upper(),
            "family": family_id.upper(),
            "family_title": family_title,
            "title": control.get("title", ""),
            "statement": _extract_statement(control),
        })
    # Control enhancements are nested recursively under their base control.
    for enhancement in control.get("controls", []):
        _flatten_control(enhancement, family_id, family_title, chunks)


def build_catalog():
    import requests
    print(f"Fetching {CATALOG_URL} ...")
    resp = requests.get(CATALOG_URL, timeout=60)
    resp.raise_for_status()
    catalog = resp.json()["catalog"]

    chunks = []
    for group in catalog.get("groups", []):
        for control in group.get("controls", []):
            _flatten_control(control, group["id"], group.get("title", ""), chunks)

    with open(OUTPUT_PATH, "w", encoding="utf-8") as f:
        json.dump(chunks, f, indent=2)

    print(f"Wrote {len(chunks)} controls/enhancements to {OUTPUT_PATH}")
    return chunks


if __name__ == "__main__":
    build_catalog()
