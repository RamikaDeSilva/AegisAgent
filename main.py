"""
AegisAgent CLI entry point.

Usage:
    python main.py --pr <github_pr_url>                  # Live: real Stream 2 + Stream 3
    python main.py --pr <github_pr_url> --mock-scanners  # Real Stream 3, mocked Stream 2 (use while Muscle is WIP)
    python main.py --mock                                # Strict isolation, default scenario (vuln)
    python main.py --mock --scenario <name>              # Strict isolation, named scenario
    python main.py --print-graph                         # Print the LangGraph Mermaid diagram and exit

Available --scenario names:
    vuln          DB-impacting PR; injection found; bounty paid (default)
    clean         DB-impacting PR; scans clean; no bounty
    timeout       Scanners hit the 60s kill switch
    error         Scanners fail to start
    no_db_impact  Greptile rules out DB impact; agent exits early (LIVE 8-node graph)
"""

from __future__ import annotations

import argparse
import asyncio
import sys

from dotenv import load_dotenv

from core.agent import AegisAgent, PRScanState
from core.deps import build_live_deps, build_mock_deps, build_partial_deps
from core.scenarios import SCENARIOS, get_scenario

load_dotenv()


async def _run_scenario(scenario_name: str) -> PRScanState:
    """Resolve a scenario by name and invoke the agent against it."""
    scenario = get_scenario(scenario_name)
    deps = scenario.deps_factory()
    agent = AegisAgent(deps=deps)
    if scenario.mock_state is not None:
        return await agent.process_pull_request(mock_state=scenario.mock_state)
    return await agent.process_pull_request(pr_url=scenario.pr_url)


async def _run_live(pr_url: str, mock_scanners: bool) -> PRScanState:
    """Run the agent against a real PR URL.

    When ``mock_scanners`` is True the Muscle stream is replaced with inline
    stubs so Brain can be exercised end-to-end against the implemented
    Stream 3 even before the Muscle stream lands.
    """
    deps = build_partial_deps() if mock_scanners else build_live_deps()
    agent = AegisAgent(deps=deps)
    return await agent.process_pull_request(pr_url=pr_url)


def run_pr_agent(
    pr_url: str | None,
    mock: bool = False,
    scenario: str = "vuln",
    mock_scanners: bool = False,
) -> PRScanState:
    """
    Orchestrate a full AegisAgent scan for a given Pull Request.

    Live mode (``--pr``) runs the 8-step flow:
      1. Posts a pending-status comment to the PR immediately.
      2. Fetches the PR diff via github_client.
      3. Asks Greptile whether the diff touches database code.
      4. If DB-impacted, asks Nia for WAF bypass strategies.
      5. Runs sqlmap and nuclei in parallel with a 60 s kill switch.
      6. Triggers an AllScale bounty payout if a vulnerability is confirmed.
      7. Uses the LLM to simplify the raw scan output.
      8. Edits the pending comment in-place with the final simplified report.

    With ``--mock-scanners``, step 5 runs against in-process scanner stubs
    (no sqlmap / nuclei binaries needed), but every other step hits the
    real Stream 3 integrations. Use this while Stream 2 is WIP.

    Mock mode (``--mock [--scenario NAME]``) runs against fully-stubbed
    Streams 2 and 3 — no network calls outside the LLM. Used for prompt
    iteration and as the strict-isolation pre-merge gate.

    Args:
        pr_url: Full GitHub Pull Request URL. Required in live mode.
        mock: If True, use the named scenario (defaults to ``vuln``).
        scenario: Which scenario from ``SCENARIOS`` to run (mock mode only).
        mock_scanners: Replace Stream 2 with inline stubs (live mode only).

    Returns:
        The final PRScanState after the agent has run.
    """
    if mock:
        return asyncio.run(_run_scenario(scenario))
    if pr_url is None:
        raise ValueError("Live mode requires --pr <url>")
    return asyncio.run(_run_live(pr_url, mock_scanners))


def _build_arg_parser() -> argparse.ArgumentParser:
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
            "Run against fully-stubbed Streams 2 and 3. Use --scenario to "
            "pick which code path to exercise."
        ),
    )
    mode_group.add_argument(
        "--print-graph",
        action="store_true",
        help=(
            "Print a Mermaid diagram of the agent's live 8-node graph "
            "and exit. Pipe to a file or paste into any Mermaid renderer."
        ),
    )

    parser.add_argument(
        "--scenario",
        type=str,
        default="vuln",
        choices=sorted(SCENARIOS.keys()),
        help=(
            "Which mock scenario to run (only valid with --mock). "
            "Default: vuln."
        ),
    )
    parser.add_argument(
        "--mock-scanners",
        action="store_true",
        help=(
            "Replace Stream 2 (sqlmap, nuclei) with in-process stubs while "
            "still using real Stream 3 integrations. Only valid with --pr. "
            "Use this while the Muscle stream is WIP."
        ),
    )

    return parser


def _validate_args(args: argparse.Namespace) -> None:
    """Reject nonsensical flag combinations with a clean argparse error."""
    if args.mock_scanners and not args.pr:
        sys.exit("error: --mock-scanners only makes sense with --pr <url>")
    if args.scenario != "vuln" and not args.mock:
        sys.exit("error: --scenario only makes sense with --mock")


def _print_graph() -> None:
    """Print the live graph as Mermaid and exit.

    Builds a quiet AegisAgent with mock deps so we never touch the network or
    teammate code just to render a diagram.
    """
    agent = AegisAgent(deps=build_mock_deps(quiet=True), log=False)
    print(agent._live_graph.get_graph().draw_mermaid())


if __name__ == "__main__":
    parser = _build_arg_parser()
    args = parser.parse_args()
    _validate_args(args)
    if args.print_graph:
        _print_graph()
        sys.exit(0)
    run_pr_agent(
        pr_url=args.pr,
        mock=args.mock,
        scenario=args.scenario,
        mock_scanners=args.mock_scanners,
    )
