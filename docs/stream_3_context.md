# Stream 3 — The Context (Sponsor & Platform APIs)

## Scope

You own every outbound API call: GitHub PR operations and all three sponsor
track integrations (Greptile, Nia, AllScale).

## Files You May Edit

| File                               | Purpose                                   |
|------------------------------------|-------------------------------------------|
| `integrations/github_client.py`    | PR diff fetch, comment post/edit          |
| `integrations/greptile_client.py`  | DB-impact classification via Greptile API |
| `integrations/nia_client.py`       | WAF bypass list via Nia API               |
| `integrations/allscale_client.py`  | Bounty payout trigger via AllScale API    |
| `integrations/__init__.py`         | Package init (keep empty)                 |

## Files You Must NOT Edit

- `core/` — owned by the Brain stream
- `tools/` — owned by the Muscle stream
- `main.py` — owned by the Brain stream

---

## Your Job

Implement all external API clients as async functions. Read API keys from
environment variables via `python-dotenv` — never hardcode credentials.

---

## Public Interface Contracts

The Brain stream calls your functions with these exact signatures. Do not
change signatures without coordinating with the Brain owner.

### `integrations/github_client.py`

```python
async def get_pr_diff(pr_url: str) -> str:
    """Return the raw unified diff text for the given PR URL."""

async def post_pending_status(pr_url: str) -> int:
    """
    Post an immediate placeholder comment to the PR and return its comment ID.

    The comment body MUST be exactly:
        "🛡️ AegisAgent is analyzing this PR for database impact..."

    The returned comment ID is stored in PRScanState.pending_comment_id
    and used by update_pr_comment to edit the comment in-place later.
    """

async def update_pr_comment(comment_id: int, comment_body: str) -> bool:
    """
    Edit an existing PR comment (identified by comment_id) with new body text.

    Called at the end of the orchestration flow to replace the pending-status
    message with the final LLM-simplified vulnerability report. This keeps the
    PR thread clean: one evolving comment, not a wall of bot noise.
    """

async def post_pr_comment(pr_url: str, comment_body: str) -> bool:
    """
    Post a net-new comment on the PR (fallback for follow-up scans).

    Prefer update_pr_comment for the primary result. Use this only when
    posting a genuinely new piece of information (e.g., a re-scan result).
    """
```

### UX Contract (Critical)

- `post_pending_status` MUST post the exact string:
  `"🛡️ AegisAgent is analyzing this PR for database impact..."`
- `update_pr_comment` MUST edit (not create) the comment with the given ID.
- Result: one comment on the PR that evolves from "analyzing..." to the
  final report. Judges and developers see a clean, responsive bot.

### `integrations/greptile_client.py`

```python
async def analyze_diff_for_db_impact(repo_name: str, diff_text: str) -> bool:
    """
    Return True if the diff touches database code (raw SQL, ORM queries,
    migrations, etc.), False otherwise.

    Uses the Greptile API. Reads GREPTILE_API_KEY from the environment.
    """
```

### `integrations/nia_client.py`

```python
async def get_waf_bypasses(tech_stack: str) -> list[str]:
    """
    Return a list of sqlmap tamper script names suited to the given tech stack
    (e.g. ["space2comment", "between", "randomcase"]).

    Uses the Nia API. Reads NIA_API_KEY from the environment.
    """
```

### `integrations/allscale_client.py`

```python
async def trigger_bounty_payout(wallet_address: str, amount: float) -> bool:
    """
    Trigger a bounty payout to the given wallet address for the given amount.
    Return True on success, False on failure.

    Uses the AllScale API. Reads ALLSCALE_API_KEY from the environment.
    """
```

---

## Implementation Notes

- Use `httpx.AsyncClient` for HTTP calls to sponsor APIs.
- Use `PyGithub` (`github.Github`) or `httpx` for GitHub API calls — both
  are in `requirements.txt`. PyGithub is simpler for comment editing.
- Load all API keys with `os.getenv(...)` after `load_dotenv()`.
- All functions must be `async def` — no blocking I/O.

---

## Definition of Done

- [ ] `post_pending_status` posts the exact UX-contract string and returns
      a valid GitHub comment ID (`int`).
- [ ] `update_pr_comment` edits the existing comment (not creates a new one).
- [ ] `get_pr_diff` returns a non-empty string for a real PR URL.
- [ ] All sponsor clients read their API keys from environment variables.
- [ ] No hardcoded credentials anywhere.
- [ ] All functions are async; no calls to `requests` or `subprocess`.
- [ ] `integrations/__init__.py` remains empty.
