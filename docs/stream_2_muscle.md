# Stream 2 — The Muscle (Execution Wrappers)

## Scope

You own all subprocess execution: wrapping `sqlmap` and `nuclei` as safe,
async, timeout-enforced Python functions.

## Files You May Edit


| File                     | Purpose                       |
| ------------------------ | ----------------------------- |
| `tools/sqlmap_runner.py` | Async wrapper around `sqlmap` |
| `tools/nuclei_runner.py` | Async wrapper around `nuclei` |
| `tools/__init__.py`      | Package init (keep empty)     |


## Files You Must NOT Edit

- `core/` — owned by the Brain stream
- `integrations/` — owned by the Context stream
- `main.py` — owned by the Brain stream

---

## Responsibility Split

Each tool has a hard-scoped lane. They must never scan for the same thing.

### `sqlmap` owns — SQL Injection (exclusively)

- Error-based, blind, time-based, and UNION-based SQLi detection
- Deep payload mutation across all injectable parameters
- WAF bypass via tamper scripts (sourced from `PRScanState.waf_bypasses`)
- Database fingerprinting (DB engine and version)
- Exploitation-grade confirmation — not just "maybe vulnerable"

`sqlmap` does **NOT** scan for CVEs, misconfigs, XSS, SSRF, or any
non-SQLi vulnerability class. That is nuclei's domain.

### `nuclei` owns — Broad Vulnerability Surface (everything except SQLi)

- CVE detection (known vulnerabilities in frameworks/libraries)
- Misconfiguration detection (exposed `.git`, debug endpoints, default creds)
- Exposure detection (admin panels, API keys in responses, directory listing)
- XSS, SSRF, open redirect detection
- HTTP header security checks

`nuclei` must **always** pass `-exclude-tags sqli` so it never runs its own
SQL injection templates. sqlmap covers that lane with far greater depth.

---

## Your Job

Build safe, async `asyncio.create_subprocess_exec` wrappers around `sqlmap`
and `nuclei`. Each wrapper must:

1. Spawn the subprocess asynchronously.
2. Enforce a hard timeout via `asyncio.wait_for` — 60 s for `sqlmap`, 120 s for `nuclei`.
3. On timeout (60 s for sqlmap, 120 s for nuclei): terminate the process, log the result,
  and return a structured error dict — never raise an exception.
4. On success: parse stdout and return a structured dict.
5. Log all meaningful events using `rich` (imported from `rich`).

---

## Public Interface Contract

The Brain stream calls your functions with these exact signatures. Do not  
change the signatures without coordinating with the Brain owner.

```python
async def run_sqlmap(
    target_url: str,
    tamper_script: str | None = None,
    post_data: str | None = None,
    cookie: str | None = None,
    headers: dict[str, str] | None = None,
) -> dict:
    ...

async def run_nuclei(target_url: str) -> dict:
    ...
```

- `post_data` — optional POST body string (e.g. `"id=1&name=foo"`); maps to `--data`
- `cookie` — optional cookie string (e.g. `"session=abc123"`); maps to `--cookie`
- `headers` — optional dict of extra HTTP headers; each entry maps to `-H "Key: Value"`

### Subprocess flags

**sqlmap:**

```
sqlmap -u <url> --batch --level=3 --risk=2 --technique=BEUSTQ
       [--tamper <script>]
       [--data <post_data>]
       [--cookie <cookie>]
       [-H "Key: Value" ...]
```

- `--batch` — non-interactive, no prompts
- `--level=3 --risk=2` — broad coverage, not destructive
- `--technique=BEUSTQ` — all 6 SQLi techniques (Boolean, Error, Union, Stacked, Time, Query)
- `--tamper <script>` — injected only when `tamper_script` is not `None`
- `--data <post_data>` — injected only when `post_data` is not `None`; switches sqlmap to POST mode
- `--cookie <cookie>` — injected only when `cookie` is not `None`
- `-H "Key: Value"` — one flag per entry in `headers`; injected only when `headers` is not `None`

**nuclei:**

```
nuclei -u <url> -exclude-tags sqli -json
```

- `-exclude-tags sqli` — hard exclusion; never duplicates sqlmap's work
- `-json` — structured output, easier to parse into `findings`

No `-tags` whitelist is applied. nuclei runs its full template library so that
categories like `auth`, `default-logins`, `ssl`, `dns`, `network`, and
`fuzzing` are not silently skipped.

---

### Return dict schema (success)

```python
{
    "status": "success",
    "target": target_url,
    "stdout": "<raw tool output>",
    "stderr": "",
    "findings": [...],   # see per-tool shapes below
}
```

**sqlmap `findings` entry:**

```python
{"type": "sqli", "technique": "<B|E|U|S|T|Q>", "parameter": "<param>", "db": "<dbms>"}
```

**nuclei `findings` entry:**

```python
{"type": "<first tag from template>", "template_id": "<id>", "severity": "<info|low|medium|high|critical>", "name": "<template name>"}
```

### Return dict schema (timeout — MANDATORY)

```python
{
    "status": "timeout",
    "target": target_url,
    "stdout": "",
    "stderr": "killed after 60s",   # "killed after 120s" for nuclei
}
```

### Return dict schema (error)

```python
{
    "status": "error",
    "target": target_url,
    "stdout": "",
    "stderr": "<error message>",
}
```

The Brain stream reads `result["status"]` to decide next steps. It will
**never** try/except around your functions — you must handle all failure modes
internally and always return one of the three dicts above.

---

## Mandatory Kill Switch

Every subprocess invocation MUST be wrapped in `asyncio.wait_for`:

```python
import asyncio
from rich.console import Console

console = Console()

async def run_sqlmap(
    target_url: str,
    tamper_script: str | None = None,
    post_data: str | None = None,
    cookie: str | None = None,
    headers: dict[str, str] | None = None,
) -> dict:
    cmd = [
        "sqlmap", "-u", target_url,
        "--batch", "--level=3", "--risk=2", "--technique=BEUSTQ",
    ]
    if tamper_script:
        cmd += ["--tamper", tamper_script]
    if post_data:
        cmd += ["--data", post_data]
    if cookie:
        cmd += ["--cookie", cookie]
    if headers:
        for key, value in headers.items():
            cmd += ["-H", f"{key}: {value}"]

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
    except Exception as exc:
        return {"status": "error", "target": target_url, "stdout": "", "stderr": str(exc)}

    try:
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=60)
        return {"status": "success", "target": target_url,
                "stdout": stdout.decode(), "stderr": stderr.decode(), "findings": [...]}
    except asyncio.TimeoutError:
        proc.terminate()
        try:
            await asyncio.wait_for(proc.wait(), timeout=2)
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
        console.log(f"[yellow]sqlmap timed out on {target_url} — scan inconclusive[/yellow]")
        return {"status": "timeout", "target": target_url, "stdout": "", "stderr": "killed after 60s"}
    except Exception as exc:
        return {"status": "error", "target": target_url, "stdout": "", "stderr": str(exc)}
```

Apply the same pattern to `run_nuclei` using the nuclei flags above. Do not
skip this — a hanging scan will block the GitHub Action indefinitely.

---

## Definition of Done

- Both `run_sqlmap` and `run_nuclei` are fully async (no `subprocess.run`).
- `sqlmap` uses `asyncio.wait_for(timeout=60)`; `nuclei` uses `asyncio.wait_for(timeout=120)`.
- `asyncio.create_subprocess_exec` spawn failures are caught and returned as `{"status": "error", ...}`.
- On `TimeoutError`: process is terminated/killed, `rich` logs the event,
and `{"status": "timeout", ...}` is returned.
- All three return-dict shapes (`success`, `timeout`, `error`) are handled.
- No exceptions bubble up to the Brain stream under any circumstances.
- `sqlmap` is invoked with `--level=3 --risk=2 --technique=BEUSTQ`.
- `run_sqlmap` accepts `post_data`, `cookie`, `headers` (all optional); maps to `--data`, `--cookie`, `-H`.
- `nuclei` is invoked with `-exclude-tags sqli` on every call — no exceptions.
- `nuclei` is invoked with `-json` and no `-tags` whitelist.
- `findings` entries follow the per-tool typed shapes defined above.
- `tools/__init__.py` remains empty (imports are done explicitly by Brain).

