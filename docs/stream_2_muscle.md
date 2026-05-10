# Stream 2 — The Muscle (Execution Wrappers)

## Scope

You own all subprocess execution: wrapping `sqlmap` and `nuclei` as safe,
async, timeout-enforced Python functions.

## Files You May Edit

| File                    | Purpose                          |
|-------------------------|----------------------------------|
| `tools/sqlmap_runner.py`  | Async wrapper around `sqlmap`  |
| `tools/nuclei_runner.py`  | Async wrapper around `nuclei`  |
| `tools/__init__.py`       | Package init (keep empty)      |

## Files You Must NOT Edit

- `core/` — owned by the Brain stream
- `integrations/` — owned by the Context stream
- `main.py` — owned by the Brain stream

---

## Your Job

Build safe, async `asyncio.create_subprocess_exec` wrappers around `sqlmap`
and `nuclei`. Each wrapper must:

1. Spawn the subprocess asynchronously.
2. Enforce a hard 60-second timeout via `asyncio.wait_for`.
3. On timeout: terminate the process, log the result, and return a structured
   error dict — never raise an exception.
4. On success: parse stdout and return a structured dict.
5. Log all meaningful events using `rich` (imported from `rich`).

---

## Public Interface Contract

The Brain stream calls your functions with these exact signatures. Do not
change the signatures without coordinating with the Brain owner.

```python
async def run_sqlmap(target_url: str, tamper_script: str | None = None) -> dict:
    ...

async def run_nuclei(target_url: str) -> dict:
    ...
```

### Return dict schema (success)

```python
{
    "status": "success",
    "target": target_url,
    "stdout": "<raw sqlmap/nuclei output>",
    "stderr": "",
    "findings": [],   # populated when you parse real output
}
```

### Return dict schema (timeout — MANDATORY)

```python
{
    "status": "timeout",
    "target": target_url,
    "stdout": "",
    "stderr": "killed after 60s",
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

async def run_sqlmap(target_url: str, tamper_script: str | None = None) -> dict:
    proc = await asyncio.create_subprocess_exec(
        "sqlmap", "-u", target_url, "--batch",
        *(["--tamper", tamper_script] if tamper_script else []),
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=60)
        return {"status": "success", "target": target_url,
                "stdout": stdout.decode(), "stderr": stderr.decode(), "findings": []}
    except asyncio.TimeoutError:
        proc.terminate()
        try:
            await asyncio.wait_for(proc.wait(), timeout=2)
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
        console.log(f"[yellow]sqlmap timed out on {target_url} — scan inconclusive[/yellow]")
        return {"status": "timeout", "target": target_url, "stdout": "", "stderr": "killed after 60s"}
```

Apply the same pattern to `run_nuclei`. Do not skip this — a hanging sqlmap
will block the GitHub Action indefinitely.

---

## Definition of Done

- [ ] Both `run_sqlmap` and `run_nuclei` are fully async (no `subprocess.run`).
- [ ] Both use `asyncio.wait_for(timeout=60)` on every invocation.
- [ ] On `TimeoutError`: process is terminated/killed, `rich` logs the event,
      and `{"status": "timeout", ...}` is returned.
- [ ] All three return-dict shapes (`success`, `timeout`, `error`) are handled.
- [ ] No exceptions bubble up to the Brain stream under any circumstances.
- [ ] `tools/__init__.py` remains empty (imports are done explicitly by Brain).
