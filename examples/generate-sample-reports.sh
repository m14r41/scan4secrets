#!/usr/bin/env bash
# Generate the published sample reports from the examples/sample-app fixture.
# Used by the docs-deploy workflow (so the live site always has fresh reports
# matching the current code) and by anyone who wants to reproduce them locally.
#
# Output: website/static/reports/sast-sample-app.{html,json,jsonl,csv,sarif,xlsx,pdf}
# The reports are git-ignored on purpose (their JSON/CSV bodies echo the scanned
# lines); they are generated at deploy time, never committed.
set -euo pipefail
cd "$(dirname "$0")/.."

# Prefer the repo shim (main.py) so we always run THIS checkout's code — a stale
# globally-installed scan4secrets may predate flags like --misconfig. Fall back to
# the installed console script only if main.py is absent.
if [ -f main.py ]; then
  RUN="${PYTHON:-python} main.py"
else
  RUN="scan4secrets"
fi

mkdir -p website/static/reports
$RUN --path examples/sample-app --misconfig \
  --report html json jsonl csv sarif excel pdf \
  --output website/static/reports/sast-sample-app

echo "Sample reports written to website/static/reports/sast-sample-app.*"
