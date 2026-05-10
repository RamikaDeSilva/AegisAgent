"""
Brain stream — pytest suite.

Owned by: Stream 1 (Brain). Do NOT edit if you are on Muscle or Context.

Coverage map:
    * Pure helpers   : _parse_repo_name, _aggregate_status, _extract_text
    * Node methods   : every _node_* on AegisAgent
    * Conditional   : _route_after_classify
    * Compiled graphs: _mock_graph (3 nodes), _live_graph (8 nodes, both branches)
    * LLM prompt    : simplify_vulnerability_report for success/timeout/error

All tests run with ``_FakeLLM`` (no OPENAI_API_KEY required) and inline
async stubs (no tools.* / integrations.* imports). The contract import test
at the bottom proves the Stream 2/3 module surface still resolves.
"""

from __future__ import annotations

from unittest.mock import AsyncMock

import pytest

from core.agent import (
    MOCK_PR_SCAN_STATE,
    AegisAgent,
    PRScanState,
    _aggregate_status,
    _extract_text,
    _parse_repo_name,
)
from core.deps import BrainDeps, _FakeLLM, build_mock_deps


# =============================================================================
# Test helpers
# =============================================================================


def _make_deps(**overrides) -> BrainDeps:
    """Build a quiet BrainDeps with optional callable overrides.

    Starts from build_mock_deps(quiet=True) and replaces any named callable
    with the value passed in ``overrides`` (typically an AsyncMock).
    """
    deps = build_mock_deps(quiet=True)
    for key, value in overrides.items():
        setattr(deps, key, value)
    return deps


def _make_agent(deps: BrainDeps | None = None) -> AegisAgent:
    """Build an AegisAgent with logging suppressed so pytest output stays clean."""
    return AegisAgent(deps=deps if deps is not None else _make_deps(), log=False)


def _state(**fields) -> PRScanState:
    """PRScanState builder with sensible defaults for testing nodes."""
    base = {
        "pr_url": "https://github.com/acme/api/pull/42",
        "repo_name": "acme/api",
        "diff_text": "diff --git a b\n+SELECT * FROM x",
        "tech_stack": "python-fastapi-postgres",
        "target_url": "http://localhost/q?",
        "waf_bypasses": ["space2comment"],
        "pending_comment_id": 1,
        "bounty_wallet": "0xWALLET",
        "bounty_amount": 100.0,
    }
    base.update(fields)
    return PRScanState(**base)


# =============================================================================
# Pure helpers
# =============================================================================


class TestParseRepoName:
    def test_standard_url(self):
        assert _parse_repo_name("https://github.com/acme/api/pull/99") == "acme/api"

    def test_trailing_slash(self):
        assert _parse_repo_name("https://github.com/acme/api/pull/99/") == "acme/api"

    def test_too_short_url_returns_empty(self):
        assert _parse_repo_name("https://github.com") == ""


class TestAggregateStatus:
    @pytest.mark.parametrize(
        "sqlmap,nuclei,expected",
        [
            ({"status": "success"}, {"status": "success"}, "success"),
            ({"status": "success"}, {"status": "timeout"}, "success"),
            ({"status": "success"}, {"status": "error"}, "success"),
            ({"status": "timeout"}, {"status": "success"}, "success"),
            ({"status": "timeout"}, {"status": "timeout"}, "timeout"),
            ({"status": "timeout"}, {"status": "error"}, "timeout"),
            ({"status": "error"}, {"status": "success"}, "success"),
            ({"status": "error"}, {"status": "timeout"}, "timeout"),
            ({"status": "error"}, {"status": "error"}, "error"),
        ],
    )
    def test_combinations(self, sqlmap, nuclei, expected):
        assert _aggregate_status(sqlmap, nuclei) == expected

    def test_missing_dicts_treated_as_error(self):
        assert _aggregate_status(None, None) == "error"


class TestExtractText:
    def test_string_content(self):
        msg = type("Msg", (), {"content": "hello"})()
        assert _extract_text(msg) == "hello"

    def test_list_of_strings(self):
        msg = type("Msg", (), {"content": ["foo", "bar"]})()
        assert _extract_text(msg) == "foo\nbar"

    def test_list_of_dicts_with_text(self):
        msg = type("Msg", (), {"content": [{"text": "alpha"}, {"text": "beta"}]})()
        assert _extract_text(msg) == "alpha\nbeta"

    def test_falls_back_to_str(self):
        assert _extract_text(42) == "42"


# =============================================================================
# Node methods
# =============================================================================


class TestNodes:
    async def test_post_pending_returns_comment_id_and_repo(self):
        post_stub = AsyncMock(return_value=999)
        agent = _make_agent(_make_deps(post_pending_status=post_stub))

        result = await agent._node_post_pending(
            _state(pr_url="https://github.com/foo/bar/pull/7")
        )

        post_stub.assert_awaited_once_with("https://github.com/foo/bar/pull/7")
        assert result == {"pending_comment_id": 999, "repo_name": "foo/bar"}

    async def test_fetch_diff_writes_diff_text(self):
        diff_stub = AsyncMock(return_value="<the diff>")
        agent = _make_agent(_make_deps(get_pr_diff=diff_stub))

        result = await agent._node_fetch_diff(_state())

        diff_stub.assert_awaited_once()
        assert result == {"diff_text": "<the diff>"}

    async def test_classify_db_writes_bool(self):
        classify_stub = AsyncMock(return_value=True)
        agent = _make_agent(
            _make_deps(analyze_diff_for_db_impact=classify_stub)
        )

        result = await agent._node_classify_db(
            _state(repo_name="foo/bar", diff_text="hi")
        )

        classify_stub.assert_awaited_once_with("foo/bar", "hi")
        assert result == {"db_impacted": True}

    async def test_early_exit_calls_update_comment_with_no_impact_message(self):
        update_stub = AsyncMock(return_value=True)
        agent = _make_agent(_make_deps(update_pr_comment=update_stub))

        result = await agent._node_early_exit_no_db(
            _state(pending_comment_id=42)
        )

        update_stub.assert_awaited_once()
        comment_id, body = update_stub.await_args.args
        assert comment_id == 42
        assert "No database-impacting" in body
        assert "No database-impacting" in result["simplified_report"]

    async def test_early_exit_skips_update_when_no_comment_id(self):
        update_stub = AsyncMock(return_value=True)
        agent = _make_agent(_make_deps(update_pr_comment=update_stub))

        await agent._node_early_exit_no_db(_state(pending_comment_id=None))

        update_stub.assert_not_awaited()

    async def test_fetch_waf_writes_bypass_list(self):
        waf_stub = AsyncMock(return_value=["space2comment", "between"])
        agent = _make_agent(_make_deps(get_waf_bypasses=waf_stub))

        result = await agent._node_fetch_waf(
            _state(tech_stack="python-fastapi-postgres")
        )

        waf_stub.assert_awaited_once_with("python-fastapi-postgres")
        assert result == {"waf_bypasses": ["space2comment", "between"]}

    async def test_run_scans_calls_both_in_parallel(self):
        sqlmap_stub = AsyncMock(return_value={"status": "success", "findings": []})
        nuclei_stub = AsyncMock(return_value={"status": "success", "findings": []})
        agent = _make_agent(
            _make_deps(run_sqlmap=sqlmap_stub, run_nuclei=nuclei_stub)
        )

        result = await agent._node_run_scans(
            _state(
                target_url="http://t/?q=",
                waf_bypasses=["space2comment", "between"],
            )
        )

        sqlmap_stub.assert_awaited_once_with("http://t/?q=", "space2comment,between")
        nuclei_stub.assert_awaited_once_with("http://t/?q=")
        assert result["sqlmap_result"]["status"] == "success"
        assert result["nuclei_result"]["status"] == "success"

    async def test_run_scans_passes_none_tamper_when_no_bypasses(self):
        sqlmap_stub = AsyncMock(return_value={"status": "success", "findings": []})
        nuclei_stub = AsyncMock(return_value={"status": "success", "findings": []})
        agent = _make_agent(
            _make_deps(run_sqlmap=sqlmap_stub, run_nuclei=nuclei_stub)
        )

        target = "http://target/?q="
        await agent._node_run_scans(_state(target_url=target, waf_bypasses=[]))

        sqlmap_stub.assert_awaited_once_with(target, None)


class TestBountyNode:
    async def test_paid_when_findings_and_wallet(self):
        payout_stub = AsyncMock(return_value=True)
        agent = _make_agent(_make_deps(trigger_bounty_payout=payout_stub))

        state = _state(
            sqlmap_result={"status": "success", "findings": [{"parameter": "q"}]},
            bounty_wallet="0xABC",
            bounty_amount=250.0,
        )
        result = await agent._node_bounty(state)

        payout_stub.assert_awaited_once_with("0xABC", 250.0)
        assert result == {"bounty_paid": True}

    async def test_not_paid_when_no_wallet(self):
        payout_stub = AsyncMock(return_value=True)
        agent = _make_agent(_make_deps(trigger_bounty_payout=payout_stub))

        state = _state(
            sqlmap_result={"status": "success", "findings": [{"parameter": "q"}]},
            bounty_wallet=None,
        )
        result = await agent._node_bounty(state)

        payout_stub.assert_not_awaited()
        assert result == {"bounty_paid": False}

    async def test_not_paid_when_no_findings(self):
        payout_stub = AsyncMock(return_value=True)
        agent = _make_agent(_make_deps(trigger_bounty_payout=payout_stub))

        state = _state(
            sqlmap_result={"status": "success", "findings": []},
            bounty_wallet="0xABC",
        )
        result = await agent._node_bounty(state)

        payout_stub.assert_not_awaited()
        assert result == {"bounty_paid": False}

    async def test_not_paid_when_sqlmap_timed_out(self):
        payout_stub = AsyncMock(return_value=True)
        agent = _make_agent(_make_deps(trigger_bounty_payout=payout_stub))

        state = _state(
            sqlmap_result={"status": "timeout", "findings": []},
            bounty_wallet="0xABC",
        )
        result = await agent._node_bounty(state)

        payout_stub.assert_not_awaited()
        assert result == {"bounty_paid": False}


class TestSimplifyAndPostNode:
    async def test_calls_update_with_summary(self):
        update_stub = AsyncMock(return_value=True)
        agent = _make_agent(_make_deps(update_pr_comment=update_stub))

        state = _state(
            sqlmap_result={"status": "success", "findings": [{"parameter": "q"}]},
            nuclei_result={"status": "success", "findings": []},
        )
        result = await agent._node_simplify_and_post(state)

        update_stub.assert_awaited_once()
        comment_id, body = update_stub.await_args.args
        assert comment_id == state.pending_comment_id
        assert isinstance(body, str) and len(body) > 0
        assert result["simplified_report"] == body


# =============================================================================
# Conditional router
# =============================================================================


class TestRouter:
    def test_db_impacted_true_routes_to_waf(self):
        agent = _make_agent()
        assert agent._route_after_classify(_state(db_impacted=True)) == "fetch_waf"

    def test_db_impacted_false_routes_to_early_exit(self):
        agent = _make_agent()
        assert (
            agent._route_after_classify(_state(db_impacted=False))
            == "early_exit_no_db"
        )


# =============================================================================
# End-to-end graphs
# =============================================================================


class TestMockGraph:
    async def test_runs_through_mock_state(self):
        agent = _make_agent()

        result = await agent.process_pull_request(mock_state=MOCK_PR_SCAN_STATE)

        assert result.sqlmap_result is not None
        assert result.nuclei_result is not None
        assert result.simplified_report is not None
        assert result.bounty_paid is True


class TestLiveGraph:
    async def test_full_flow_when_db_impacted(self):
        update_stub = AsyncMock(return_value=True)
        agent = _make_agent(_make_deps(update_pr_comment=update_stub))

        result = await agent.process_pull_request(
            pr_url="https://github.com/acme/api/pull/77"
        )

        assert result.repo_name == "acme/api"
        assert result.pending_comment_id == 1
        assert result.diff_text is not None
        assert result.db_impacted is True
        assert result.waf_bypasses == ["space2comment", "between"]
        assert result.sqlmap_result is not None
        assert result.nuclei_result is not None
        assert result.simplified_report is not None
        update_stub.assert_awaited_once()

    async def test_early_exit_when_not_db_impacted(self):
        deps = build_mock_deps(db_impacted=False, quiet=True)
        update_stub = AsyncMock(return_value=True)
        deps.update_pr_comment = update_stub
        agent = AegisAgent(deps=deps, log=False)

        result = await agent.process_pull_request(
            pr_url="https://github.com/acme/api/pull/88"
        )

        assert result.db_impacted is False
        assert result.sqlmap_result is None  # scans never ran
        assert result.nuclei_result is None
        update_stub.assert_awaited_once()
        _, body = update_stub.await_args.args
        assert "No database-impacting" in body


# =============================================================================
# simplify_vulnerability_report status branches
# =============================================================================


class TestSimplifyVulnerabilityReport:
    async def test_success_branch_returns_string(self):
        agent = _make_agent()
        out = await agent.simplify_vulnerability_report(
            {
                "status": "success",
                "sqlmap": {"status": "success", "findings": [{"parameter": "q"}]},
                "nuclei": {"status": "success", "findings": []},
                "pr_url": "https://github.com/x/y/pull/1",
                "bounty_paid": True,
                "diff_excerpt": "...",
            }
        )
        assert isinstance(out, str)
        assert len(out) > 0

    async def test_timeout_branch_returns_string(self):
        agent = _make_agent()
        out = await agent.simplify_vulnerability_report(
            {
                "status": "timeout",
                "sqlmap": {"status": "timeout"},
                "nuclei": {"status": "timeout"},
                "pr_url": "https://github.com/x/y/pull/1",
                "bounty_paid": False,
                "diff_excerpt": "...",
            }
        )
        assert isinstance(out, str)
        assert len(out) > 0

    async def test_error_branch_returns_string(self):
        agent = _make_agent()
        out = await agent.simplify_vulnerability_report(
            {
                "status": "error",
                "sqlmap": {"status": "error"},
                "nuclei": {"status": "error"},
                "pr_url": "https://github.com/x/y/pull/1",
                "bounty_paid": False,
                "diff_excerpt": "...",
            }
        )
        assert isinstance(out, str)
        assert len(out) > 0

    async def test_uses_fake_llm_when_no_api_key(self, monkeypatch):
        monkeypatch.delenv("OPENAI_API_KEY", raising=False)
        agent = _make_agent()
        assert isinstance(agent.deps.llm, _FakeLLM)
        out = await agent.simplify_vulnerability_report(
            {"status": "success", "sqlmap": {}, "nuclei": {}, "diff_excerpt": ""}
        )
        assert "fake-LLM fallback" in out


# =============================================================================
# Contract smoke-import (drift detector for Stream 2 / Stream 3)
# =============================================================================


class TestGraphRendering:
    """Make sure the --print-graph CLI path can produce a Mermaid diagram."""

    def test_live_graph_renders_mermaid(self):
        agent = _make_agent()
        diagram = agent._live_graph.get_graph().draw_mermaid()
        assert isinstance(diagram, str)
        assert len(diagram) > 0
        assert "graph" in diagram.lower() or "flowchart" in diagram.lower()
        # Sanity: every live-graph node should appear somewhere in the output.
        for node in (
            "post_pending",
            "fetch_diff",
            "classify_db",
            "early_exit_no_db",
            "fetch_waf",
            "run_scans",
            "bounty_payout",
            "simplify_and_post",
        ):
            assert node in diagram, f"node {node!r} missing from Mermaid"


class TestContractImports:
    """Catches surprise renames from teammates without coupling Brain to them."""

    def test_stream_2_callables_resolve(self):
        from tools.sqlmap_runner import run_sqlmap
        from tools.nuclei_runner import run_nuclei

        assert callable(run_sqlmap)
        assert callable(run_nuclei)

    def test_stream_3_callables_resolve(self, monkeypatch):
        # integrations.greptile_client instantiates an AsyncOpenAI client at
        # module-import time. The conftest fixture unsets OPENAI_API_KEY for
        # hermetic Brain tests, so we set a placeholder here just to let the
        # import succeed. No network call is ever made.
        monkeypatch.setenv("OPENAI_API_KEY", "sk-test-placeholder")
        import sys

        for mod in list(sys.modules):
            if mod.startswith("integrations."):
                del sys.modules[mod]

        from integrations.github_client import (
            get_pr_diff,
            post_pending_status,
            update_pr_comment,
        )
        from integrations.greptile_client import analyze_diff_for_db_impact
        from integrations.nia_client import get_waf_bypasses
        from integrations.allscale_client import trigger_bounty_payout

        for fn in (
            get_pr_diff,
            post_pending_status,
            update_pr_comment,
            analyze_diff_for_db_impact,
            get_waf_bypasses,
            trigger_bounty_payout,
        ):
            assert callable(fn)
