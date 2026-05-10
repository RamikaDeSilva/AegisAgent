# AegisAgent

Autonomous AI Red-Team agent that analyzes GitHub Pull Requests for database
vulnerabilities. Competes in three sponsor tracks:

- **Greptile** — diff classification (does this PR touch DB code?)
- **Nia** — WAF bypass intelligence (how do we get past the firewall?)
- **AllScale** — automated bounty payouts (pay out when a vuln is confirmed)

---

## How It Works

```
PR Created
 → Agent fetches diff              (integrations/github_client.py)
 → Greptile classifies: DB touched? (integrations/classifier_client.py)
 → If yes: Nia returns WAF bypass strategies (integrations/nia_client.py)
 → sqlmap / nuclei scan the endpoint   (tools/)
 → LLM simplifies raw scan output      (core/agent.py)
 → AllScale triggers bounty payout     (integrations/allscale_client.py)
 → Agent edits the pending PR comment with final results (integrations/github_client.py)
```

---

## Project Structure

```
AegisAgent/
├── core/
│   └── agent.py            # Brain stream — PRScanState, AegisAgent orchestrator
├── integrations/
│   ├── github_client.py    # PR diff fetch, pending comment post/edit
│   ├── classifier_client.py # DB-impact classification (Greptile track)
│   ├── nia_client.py       # WAF bypass list via Nia API
│   └── allscale_client.py  # Bounty payout trigger via AllScale API
├── tools/
│   ├── sqlmap_runner.py    # Muscle stream — async sqlmap wrapper
│   └── nuclei_runner.py    # Muscle stream — async nuclei wrapper
├── docs/
│   ├── stream_1_brain.md   # Brain stream contracts
│   ├── stream_2_muscle.md  # Muscle stream contracts
│   └── stream_3_context.md # Context stream contracts
├── main.py                 # CLI entry point
├── test_clients.py         # Smoke-test for all four integration clients
├── requirements.txt
└── .env.example
```

---

## Setup

### 1. Install dependencies

```bash
python3 -m pip install -r requirements.txt
```

### 2. Configure environment variables

```bash
cp .env.example .env
```

Edit `.env` and fill in your keys:

| Variable | Where to get it |
|---|---|
| `GITHUB_TOKEN` | GitHub → Settings → Developer Settings → Personal Access Tokens. Needs `repo` scope. |
| `GREPTILE_API_KEY` | [app.greptile.com](https://app.greptile.com) → API Keys |
| `NIA_API_KEY` | Nia sponsor dashboard |
| `ALLSCALE_API_KEY` | AllScale sponsor dashboard |
| `OPENAI_API_KEY` | [platform.openai.com/api-keys](https://platform.openai.com/api-keys) |

---

## Running

### Mock mode (local dev — no API calls to GitHub or Greptile)

```bash
python3 main.py --mock
```

Injects `MOCK_PR_SCAN_STATE` from `core/agent.py` and skips directly to the
tool-execution + LLM-simplify steps. Use this for all prompt iteration.

### Live mode

```bash
python3 main.py --pr https://github.com/owner/repo/pull/42
```

Runs the full pipeline against a real PR.

---

## Smoke-testing the integration clients

Edit `test_clients.py` and set `PR_URL` / `REPO_NAME` to a real GitHub PR you
own, then run:

```bash
python3 test_clients.py
```

Expected output (all keys configured correctly):

```
=== github_client ===
  post_pending_status  → comment_id=<non-zero int>
  get_pr_diff          → <N> chars
  update_pr_comment    → True

=== classifier_client ===
  analyze_diff_for_db_impact → True/False

=== nia_client ===
  get_waf_bypasses           → ['space2comment', ...]

=== allscale_client ===
  trigger_bounty_payout      → True
```

If a value comes back as `0`, `False`, or `[]` unexpectedly, check the `ERROR`
log lines above it — `logger.exception` captures the full traceback.

---

## Stream Ownership

| Stream | Files | Must NOT touch |
|---|---|---|
| Brain | `core/agent.py`, `main.py` | `tools/`, `integrations/` |
| Muscle | `tools/` | `core/`, `integrations/`, `main.py` |
| Context | `integrations/` | `core/`, `tools/`, `main.py` |

See `docs/` for the full API contracts between streams.

---

## Key Design Decisions

- **Pure `httpx.AsyncClient`** for all GitHub and sponsor API calls — no
  blocking I/O, no thread pool wrappers.
- **Tenacity retries** on every outbound HTTP call: up to 3 attempts with
  exponential backoff for `429`, `502`, `503`, timeouts, and network errors.
- **Structured logging** (`logger.exception`) in every error path so failures
  surface with full tracebacks instead of silent `False` returns.
- **Strict YES/NO prompt** to Greptile — prevents false positives from
  keyword-scanning free-text LLM responses.
- **Module-level comment cache** in `github_client.py` — bridges the gap
  between `post_pending_status` (which has the PR URL) and
  `update_pr_comment` (which only receives a comment ID), without requiring
  extra env vars.
