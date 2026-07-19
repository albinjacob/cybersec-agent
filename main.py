"""
Entry point - runs the full Cyber Security AI Agent pipeline against the
bundled sample data and writes a report to output/report.md.

Usage:
    python3 main.py
    python3 main.py --log path/to/log --dockerfile path/to/Dockerfile \
                     --requirements path/to/requirements.txt --policy path/to/policy.md
"""

import argparse
import json
import os
import sys
from orchestrator import run_pipeline
from report_builder import build_report

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--log", default="data/testing/quick_demo/sample_auth.log")
    parser.add_argument("--dockerfile", default="data/testing/quick_demo/Dockerfile")
    parser.add_argument("--requirements", default="data/testing/quick_demo/requirements.txt")
    parser.add_argument("--policy", default="data/testing/quick_demo/policy_excerpt.md")
    parser.add_argument("--out", default="output/report.md")
    parser.add_argument("--json-out", default="output/state.json")
    args = parser.parse_args()

    state = run_pipeline(args.log, args.dockerfile, args.requirements, args.policy)
    report = build_report(state)

    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as f:
        f.write(report)

    with open(args.json_out, "w", encoding="utf-8") as f:
        json.dump(state, f, indent=2, default=str)

    print(report)
    print(f"\n\n[written to {args.out} and {args.json_out}]")


if __name__ == "__main__":
    main()
