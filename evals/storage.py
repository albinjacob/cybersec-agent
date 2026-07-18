"""
Evals run-history storage - same live/fallback contract every other agent in
this app already uses (Trivy/NVD/embeddings all degrade gracefully with a
labeled fallback; this does too).

If SUPABASE_URL/SUPABASE_KEY are configured, run history is stored in a
Supabase Postgres table - real persistence across sessions and Render
redeploys. Otherwise it falls back to a local JSONL file, which only
survives for the lifetime of the current running instance.

One-time Supabase setup (free tier): create a project, then in the SQL
editor run:

    create table eval_runs (
        id bigint generated always as identity primary key,
        created_at timestamptz not null default now(),
        record jsonb not null
    );

Then set SUPABASE_URL and SUPABASE_SECRET_KEY (the service_role-equivalent key from the
project's API settings - full read/write, bypasses RLS) as env vars. This app has no
browser-side Supabase calls, so the publishable/anon key and JWKS URL (meant for
client-exposed code and end-user JWT verification, respectively) have no role here.
"""

import json
import os
from pathlib import Path

SUPABASE_URL = os.environ.get("SUPABASE_URL")
SUPABASE_KEY = os.environ.get("SUPABASE_SECRET_KEY")

LOCAL_HISTORY_PATH = Path(__file__).parent / "results" / "history.jsonl"


def _supabase_configured():
    return bool(SUPABASE_URL and SUPABASE_KEY)


def save_run(record):
    """Persists one eval run record. Returns the storage_mode actually used."""
    if _supabase_configured():
        try:
            import requests
            resp = requests.post(
                f"{SUPABASE_URL.rstrip('/')}/rest/v1/eval_runs",
                headers={
                    "apikey": SUPABASE_KEY,
                    "Authorization": f"Bearer {SUPABASE_KEY}",
                    "Content-Type": "application/json",
                    "Prefer": "return=minimal",
                },
                json={"record": record},
                timeout=10,
            )
            resp.raise_for_status()
            return "supabase-live"
        except Exception:
            pass  # fall through to local storage so a run is never lost
    _append_local(record)
    return "local-fallback"


def _append_local(record):
    LOCAL_HISTORY_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(LOCAL_HISTORY_PATH, "a", encoding="utf-8") as f:
        f.write(json.dumps(record) + "\n")


def load_history(limit=20):
    """Returns (records, storage_mode) - most recent run first."""
    if _supabase_configured():
        try:
            import requests
            resp = requests.get(
                f"{SUPABASE_URL.rstrip('/')}/rest/v1/eval_runs",
                headers={
                    "apikey": SUPABASE_KEY,
                    "Authorization": f"Bearer {SUPABASE_KEY}",
                },
                params={"select": "record", "order": "created_at.desc", "limit": str(limit)},
                timeout=10,
            )
            resp.raise_for_status()
            rows = resp.json()
            return [r["record"] for r in rows], "supabase-live"
        except Exception:
            pass  # fall through to local history
    return _load_local(limit), "local-fallback"


def _load_local(limit):
    if not LOCAL_HISTORY_PATH.exists():
        return []
    with open(LOCAL_HISTORY_PATH, encoding="utf-8") as f:
        records = [json.loads(line) for line in f if line.strip()]
    return list(reversed(records))[:limit]
