"""
AegisAgent CLI entry point.

Usage:
    python main.py --pr <github_pr_url>   # Live run against a real GitHub PR
    python main.py --mock                 # Local dev loop: skip GitHub/Greptile, use fixture state
"""

from __future__ import annotations

import argparse
import asyncio

from dotenv import load_dotenv

from core.agent import MOCK_PR_SCAN_STATE, AegisAgent, PRScanState
from core.deps import build_live_deps, build_mock_deps

load_dotenv()


async def _run(pr_url: str | None, mock: bool) -> PRScanState:
    """Build the right deps and invoke the agent."""
    deps = build_mock_deps() if mock else build_live_deps()
    agent = AegisAgent(deps=deps)
    if mock:
        return await agent.process_pull_request(mock_state=MOCK_PR_SCAN_STATE)
    return await agent.process_pull_request(pr_url=pr_url)


def run_pr_agent(pr_url: str | None, mock: bool = False) -> PRScanState:
    """
    Orchestrate a full AegisAgent scan for a given Pull Request.

    In live mode (--pr), the agent:
      1. Posts a pending-status comment to the PR immediately.
      2. Fetches the PR diff via github_client.
      3. Asks Greptile whether the diff touches database code.
      4. If DB-impacted, asks Nia for WAF bypass strategies.
      5. Runs sqlmap and nuclei in parallel with a 60 s kill switch.
      6. Triggers an AllScale bounty payout if a vulnerability is confirmed.
      7. Uses the LLM to simplify the raw scan output.
      8. Edits the pending comment in-place with the final simplified report.

    In mock mode (--mock), steps 1–4 are skipped; the agent loads
    MOCK_PR_SCAN_STATE from core.agent and starts at step 5, enabling
    rapid prompt iteration without consuming GitHub or Greptile rate limits.

    Args:
        pr_url: The full GitHub Pull Request URL (e.g.
            "https://github.com/owner/repo/pull/42"). None when mock=True.
        mock: If True, bypass network calls and inject MOCK_PR_SCAN_STATE.

    Returns:
        The final PRScanState after all nodes have run.
    """
    return asyncio.run(_run(pr_url, mock))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="AegisAgent — autonomous AI Red-Team agent for PR analysis.",
    )

    mode_group = parser.add_mutually_exclusive_group(required=True)
    mode_group.add_argument(
        "--pr",
        metavar="URL",
        type=str,
        help="GitHub Pull Request URL to analyze (live mode).",
    )
    mode_group.add_argument(
        "--mock",
        action="store_true",
        help=(
            "Skip GitHub and Greptile API calls; load MOCK_PR_SCAN_STATE from "
            "core/agent.py and start at step 5 (tools + LLM simplify). "
            "Use this for rapid prompt iteration during development."
        ),
    )

    args = parser.parse_args()
    run_pr_agent(pr_url=args.pr, mock=args.mock)
