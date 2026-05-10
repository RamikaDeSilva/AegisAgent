"""
Smoke-test for all four Stream 3 integration clients.

Run with:
    python3 test_clients.py

Prerequisites:
  - .env file populated (copy .env.example and fill in keys)
  - python3 -m pip install -r requirements.txt
  - Set PR_URL and REPO_NAME below to a real GitHub PR you have access to
"""

import asyncio
import logging

from dotenv import load_dotenv

load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(name)s — %(message)s",
)
logger = logging.getLogger("test_clients")

# ---------------------------------------------------------------------------
# Configure these before running
# ---------------------------------------------------------------------------

PR_URL = "https://github.com/RamikaDeSilva/AegisAgent/pull/1"
REPO_NAME = "RamikaDeSilva/AegisAgent"

# ---------------------------------------------------------------------------


async def main() -> None:
    from integrations.github_client import (
        get_pr_diff,
        post_pending_status,
        update_pr_comment,
        post_pr_comment,
    )
    from integrations.greptile_client import analyze_diff_for_db_impact
    from integrations.nia_client import get_waf_bypasses
    from integrations.allscale_client import trigger_bounty_payout

    print("\n=== github_client ===")

    comment_id = await post_pending_status(PR_URL)
    print(f"  post_pending_status  → comment_id={comment_id!r}")
    if comment_id == 0:
        print("  WARNING: comment_id is 0 — check GITHUB_TOKEN and PR_URL")

    diff = await get_pr_diff(PR_URL)
    print(f"  get_pr_diff          → {len(diff)} chars")
    if not diff:
        print("  WARNING: empty diff — check GITHUB_TOKEN and PR_URL")

    if comment_id:
        ok = await update_pr_comment(
            comment_id,
            "🛡️ **AegisAgent smoke-test** — this comment was edited in-place by `update_pr_comment`.",
        )
        print(f"  update_pr_comment    → {ok}")

    print("\n=== greptile_client ===")
    is_db = await analyze_diff_for_db_impact(REPO_NAME, diff or "mock diff for test")
    print(f"  analyze_diff_for_db_impact → {is_db}")

    print("\n=== nia_client ===")
    bypasses = await get_waf_bypasses("python-fastapi-postgres")
    print(f"  get_waf_bypasses           → {bypasses}")

    print("\n=== allscale_client ===")
    paid = await trigger_bounty_payout("0xDEADBEEF000000000000000000000000DEADBEEF", 0.01)
    print(f"  trigger_bounty_payout      → {paid}")

    print("\nDone.")


if __name__ == "__main__":
    asyncio.run(main())
