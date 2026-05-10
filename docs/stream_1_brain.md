# Stream 1 — The Brain (Agent Orchestration)

## Scope

You own the LangChain/LangGraph orchestration layer and the LLM prompt logic.

## Files You May Edit

| File            | Purpose                                      |
|-----------------|----------------------------------------------|
| `core/agent.py` | `PRScanState` model, `AegisAgent` class, `MOCK_PR_SCAN_STATE` fixture |
| `main.py`       | CLI entry point, `run_pr_agent` function      |

## Files You Must NOT Edit

- `tools/` — owned by the Muscle stream
- `integrations/` — owned by the Context stream

If you need a tool or integration to behave differently, open a conversation
with the relevant stream owner. Never edit their files directly.

---

## Your Job

1. **LangChain/LangGraph orchestration** — wire `AegisAgent.process_pull_request`
   as a graph of nodes. Each node reads from and writes to a `PRScanState`
   instance (defined in `core/agent.py`). Never pass raw dicts between nodes.

2. **LLM simplification** — implement `AegisAgent.simplify_vulnerability_report`
   to translate the raw `sqlmap`/`nuclei` dict output into a concise, human-
   readable developer summary. This is what gets posted to the PR.

---

## Shared State: PRScanState

`PRScanState` (Pydantic `BaseModel`, defined in `core/agent.py`) is the single
object that flows through every node in the graph. All fields are optional
(except `pr_url`) with sensible defaults so partial state is always valid.

```python
class PRScanState(BaseModel):
    pr_url: str
    repo_name: str | None = None
    diff_text: str | None = None
    db_impacted: bool | None = None   # populated by Greptile node
    tech_stack: str | None = None
    waf_bypasses: list[str] = []      # populated by Nia node
    target_url: str | None = None
    sqlmap_result: dict | None = None
    nuclei_result: dict | None = None
    simplified_report: str | None = None
    pending_comment_id: int | None = None  # returned by post_pending_status
    bounty_paid: bool = False
```

You own this model. You may add fields freely — but only you may edit it.

---

## Orchestration Contract (7-Step Flow)

```
1. post_pending_status(pr_url)          → store comment_id in state
2. get_pr_diff(pr_url)                  → store diff_text in state
3. analyze_diff_for_db_impact(...)      → store db_impacted in state
   └─ if False: update_pr_comment("No DB impact found.") and exit
4. get_waf_bypasses(tech_stack)         → store waf_bypasses in state
5. run_sqlmap(target_url, ...)          → store sqlmap_result in state
   run_nuclei(target_url)               → store nuclei_result in state
6. trigger_bounty_payout(...)           → store bounty_paid in state
7. simplify_vulnerability_report(...)   → store simplified_report in state
   update_pr_comment(comment_id, simplified_report)
```

---

## Local Development: The --mock Flag

**Always use `--mock` when iterating on LLM prompts.** Do not hit the live
GitHub or Greptile APIs during development — you will burn rate limits and
waste time on network latency.

```bash
python main.py --mock
```

When `--mock` is passed, `main.py` imports `MOCK_PR_SCAN_STATE` from
`core/agent.py` and calls `process_pull_request(mock_state=MOCK_PR_SCAN_STATE)`.
The orchestrator must detect a non-None `mock_state`, skip steps 1–3, and
jump straight to step 5 (tools + LLM simplify + comment).

### MOCK_PR_SCAN_STATE

This fixture lives in `core/agent.py` and is **Brain-owned**. Edit it freely
to test different scenarios (e.g., different tech stacks, different WAF
bypass lists, different raw sqlmap output). Never hard-code test data in
`main.py` — keep it here.

```python
MOCK_PR_SCAN_STATE = PRScanState(
    pr_url="https://github.com/acme/api/pull/99",
    repo_name="acme/api",
    diff_text="...",   # contains a vulnerable raw SQL query
    db_impacted=True,
    tech_stack="python-fastapi-postgres",
    target_url="http://localhost:3000/rest/products/search?q=",
    waf_bypasses=["space2comment", "between"],
)
```

---

## Definition of Done

- [ ] `PRScanState` is fully typed and all nodes read/write only via this model.
- [ ] `process_pull_request` implements the 7-step flow above.
- [ ] `simplify_vulnerability_report` produces a Markdown summary readable by
      a developer who has never seen sqlmap output before.
- [ ] `--mock` mode completes end-to-end without any network calls.
- [ ] No hardcoded API keys in any file (use `python-dotenv` + `.env`).
