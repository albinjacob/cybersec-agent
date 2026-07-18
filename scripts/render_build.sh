#!/usr/bin/env bash
# Render build command: installs Python deps, then installs the real Trivy
# binary so the Vulnerability Scanner agent runs its live path instead of
# falling back to static checks.
#
# Installs into ./bin (relative to the repo root) rather than /usr/local/bin -
# native-runtime build/start commands aren't guaranteed to share write access
# to system directories, but the project's own checkout is guaranteed to
# persist from build into the running service (agents/vuln_scanner.py's
# _find_trivy() checks this same relative path). Idempotent - safe to run on
# every deploy.
set -euo pipefail

pip install -r requirements.txt

mkdir -p bin
if [ ! -x bin/trivy ]; then
  curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh \
    | sh -s -- -b ./bin
fi

./bin/trivy --version
