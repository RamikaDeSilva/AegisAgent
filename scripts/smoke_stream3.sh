#!/usr/bin/env bash
# Brain x Stream 3 smoke test.
#
# Runs the full 8-node live graph against real GitHub / Greptile / Nia /
# AllScale APIs while Stream 2 (sqlmap, nuclei) stays mocked. This proves
# Brain's contracts with the implemented Context stream work end-to-end,
# without depending on the WIP Muscle stream.
#
# Requirements:
#   - .env populated with GITHUB_TOKEN, GREPTILE_API_KEY, NIA_API_KEY,
#     ALLSCALE_API_KEY, OPENAI_API_KEY (BOUNTY_WALLET / BOUNTY_AMOUNT optional)
#   - The provided PR URL must be one your GITHUB_TOKEN can comment on
#
# Usage:
#   scripts/smoke_stream3.sh <github_pr_url>
#
# Example:
#   scripts/smoke_stream3.sh https://github.com/yourname/playground/pull/3

set -euo pipefail

if [ "$#" -lt 1 ]; then
  echo "Usage: $0 <github_pr_url>" >&2
  exit 1
fi

PR_URL="$1"

cat <<EOF
Smoke-testing Brain x Stream 3 against ${PR_URL}
Stream 2 scanners are mocked; everything else hits real sponsor APIs.
Watch the PR thread: a "AegisAgent is analyzing..." comment should appear,
then update with the simplified vulnerability report.

EOF

# Run from the repository root regardless of where the user invoked the script.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${REPO_ROOT}"

python3 main.py --pr "${PR_URL}" --mock-scanners
