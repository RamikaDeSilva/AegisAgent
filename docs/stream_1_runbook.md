# Stream 1 — Brain Runbook

Operational guide for the Brain stream. Pairs with the contract spec in
[stream_1_brain.md](stream_1_brain.md): that doc says *what* Brain owes the
other streams, this one says *how* you actually drive it day-to-day.

Owner: Stream 1 (Brain). Safe to read in any stream; only Brain should edit.

---

## Quick start

```bash
# Strict isolation (no Stream 2 / Stream 3 imports). Default scenario = vuln.
python main.py --mock

# Strict isolation, named scenario.
python main.py --mock --scenario timeout

# Real Stream 3, mocked Stream 2 (use while Stream 2 is WIP).
python main.py --pr https://github.com/owner/repo/pull/42 --mock-scanners
# or, equivalently, the wrapper:
scripts/smoke_stream3.sh https://github.com/owner/repo/pull/42

# Fully live (requires Stream 2 to be done).
python main.py --pr https://github.com/owner/repo/pull/42

# Visualise the live 8-node graph.
python main.py --print-graph

# Automated regression suite.
pytest
```

---

## Three deps modes

All three live in [core/deps.py](../core/deps.py). The agent never imports
from `tools.*` or `integrations.*` directly — only via the `BrainDeps`
container the factory below produces.

| Factory | Stream 2 | Stream 3 | LLM | When to use |
|---|---|---|---|---|
| `build_live_deps()` | real | real | real ChatOpenAI | Production / fully live runs (`--pr`) |
| `build_mock_deps(...)` | inline stubs | inline stubs | real ChatOpenAI (or `_FakeLLM` if no key) | Strict-isolation `--mock` runs and the pytest suite |
| `build_partial_deps(...)` | inline stubs | real | real ChatOpenAI | `--pr ... --mock-scanners` smoke test while Stream 2 is WIP |

`build_mock_deps()` accepts `sqlmap_result=`, `nuclei_result=`,
`db_impacted=`, and `quiet=` overrides — that is what the scenario
fixtures in [core/scenarios.py](../core/scenarios.py) use to bend the
agent down each code path.

---

## Scenario reference

Selectable via `--scenario NAME`. All five live in
[core/scenarios.py](../core/scenarios.py).

| Name | Graph | What it exercises |
|---|---|---|
| `vuln` (default) | mock (3 nodes) | Happy path: sqlmap finds an injection, bounty fires, summary describes the vuln |
| `clean` | mock (3 nodes) | DB-impacting PR but scans turn up nothing — bounty skipped, summary says "all clear" |
| `timeout` | mock (3 nodes) | Both scanners hit the 60 s kill switch — drives the timeout branch in `simplify_vulnerability_report` |
| `error` | mock (3 nodes) | Scanners fail to start — drives the error branch in `simplify_vulnerability_report` |
| `no_db_impact` | **live (8 nodes)** | Greptile says the diff is unrelated to the DB — exercises `post_pending`, `fetch_diff`, `classify_db`, and the conditional edge to `early_exit_no_db` |

---

## Smoke testing Brain × Stream 3

When Stream 3 is implemented but Stream 2 is still WIP, the most useful
test you can run is the partial-deps smoke test:

```bash
scripts/smoke_stream3.sh https://github.com/yourname/playground/pull/3
```

This walks the full 8-node live graph against real GitHub, Greptile, Nia,
and AllScale, with sqlmap / nuclei stubbed. After it exits cleanly, check:

1. The PR thread received the placeholder comment, then it was edited in
   place to contain the LLM-simplified report (matches the UX contract
   from [stream_1_brain.md](stream_1_brain.md)).
2. The terminal logs show `→ post_pending`, `→ fetch_diff`,
   `→ classify_db`, and (if DB-impacted) `→ fetch_waf` and
   `→ run_scans` — proving Brain wired itself end-to-end.

Required `.env` entries: `GITHUB_TOKEN`, `GREPTILE_API_KEY`,
`NIA_API_KEY`, `ALLSCALE_API_KEY`, `OPENAI_API_KEY`. Optional:
`BOUNTY_WALLET`, `BOUNTY_AMOUNT`.

---

## Iterating on the LLM prompt

The point of `--mock` is prompt iteration — there is no faster loop.

1. Set `OPENAI_API_KEY` in `.env`.
2. Edit `_SIMPLIFY_SYSTEM_PROMPT` and the per-status `instruction` blocks
   in [core/agent.py](../core/agent.py) (`AegisAgent.simplify_vulnerability_report`).
3. Run `python main.py --mock --scenario vuln` and read the output.
4. Switch scenario to `timeout`, `error`, `clean` to verify the alternate
   branches still read well. The summary appears between the
   `update_pr_comment` rule lines.
5. To change the canned scan inputs that the LLM sees, edit the
   `_TIMEOUT_RESULT` / `_ERROR_RESULT` / `_CLEAN_SQLMAP_RESULT` dicts in
   [core/scenarios.py](../core/scenarios.py) or the
   `MOCK_PR_SCAN_STATE` fixture in [core/agent.py](../core/agent.py).

If `OPENAI_API_KEY` is missing, the agent falls back to `_FakeLLM` —
useful for verifying graph wiring on a fresh clone, useless for prompt
iteration. The runbook nags you about this at the comment-output level.

---

## Visualising the graph

```bash
python main.py --print-graph                  # to stdout
python main.py --print-graph > graph.mermaid  # to a file
```

Paste the output into the Mermaid live editor (mermaid.live) or any
Markdown renderer that supports Mermaid blocks. The diagram is generated
fresh from `agent._live_graph.get_graph().draw_mermaid()` so it cannot
drift away from the actual wiring.

---

## Pre-merge gate

Before pushing any change to a Brain-owned file, run both:

```bash
pytest
python -c "from tools.sqlmap_runner import run_sqlmap; \
from tools.nuclei_runner import run_nuclei; \
from integrations.github_client import get_pr_diff, post_pending_status, update_pr_comment; \
from integrations.greptile_client import analyze_diff_for_db_impact; \
from integrations.nia_client import get_waf_bypasses; \
from integrations.allscale_client import trigger_bounty_payout; print('contracts OK')"
```

The first proves Brain itself is internally consistent. The second proves
no teammate has silently renamed something the deps factory imports — if
that one fails, **chat with the affected stream owner, do not edit their
file**.

---

## File ownership recap

Brain owns: [core/agent.py](../core/agent.py),
[core/deps.py](../core/deps.py), [core/scenarios.py](../core/scenarios.py),
[main.py](../main.py), [tests/](../tests/),
[scripts/smoke_stream3.sh](../scripts/smoke_stream3.sh),
[docs/stream_1_brain.md](stream_1_brain.md), and this runbook.

Brain must not edit: [tools/](../tools/), [integrations/](../integrations/).
Coordinate via this runbook and the contract spec instead.
