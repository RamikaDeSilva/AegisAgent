import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from tools.sqlmap_runner import run_sqlmap

URL = "http://target/search?q=1"

SQLMAP_FINDING_OUTPUT = """\
[INFO] testing connection to the target URL
Parameter: q (GET)
    Type: Boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: q=1 AND 1=1
back-end DBMS: MySQL >= 5.0
"""


def make_proc(stdout=b"", stderr=b"", timeout=False):
    proc = MagicMock()
    if timeout:
        async def _communicate():
            raise asyncio.TimeoutError()
        proc.communicate = _communicate
    else:
        proc.communicate = AsyncMock(return_value=(stdout, stderr))
    proc.wait = AsyncMock(return_value=0)
    proc.terminate = MagicMock()
    proc.kill = MagicMock()
    return proc


@pytest.mark.asyncio
async def test_success_get_only():
    proc = make_proc(stdout=SQLMAP_FINDING_OUTPUT.encode())
    with patch("tools.sqlmap_runner.asyncio.create_subprocess_exec", AsyncMock(return_value=proc)):
        result = await run_sqlmap(URL)
    assert result["status"] == "success"
    assert result["target"] == URL
    assert isinstance(result["findings"], list)
    assert len(result["findings"]) > 0
    f = result["findings"][0]
    assert f["type"] == "sqli"
    assert f["technique"] == "B"
    assert f["parameter"] == "q"
    assert f["db"] == "MySQL >= 5.0"


@pytest.mark.asyncio
async def test_post_cookie_headers_flags_injected():
    proc = make_proc(stdout=b"")
    captured = {}

    async def fake_exec(*args, **kwargs):
        captured["args"] = list(args)
        return proc

    with patch("tools.sqlmap_runner.asyncio.create_subprocess_exec", fake_exec):
        await run_sqlmap(URL, post_data="id=1", cookie="s=abc", headers={"X-Foo": "bar"})

    cmd = captured["args"]
    assert "--data" in cmd
    assert "id=1" in cmd
    assert "--cookie" in cmd
    assert "s=abc" in cmd
    assert "-H" in cmd
    assert "X-Foo: bar" in cmd


@pytest.mark.asyncio
async def test_tamper_script_injected():
    proc = make_proc(stdout=b"")
    captured = {}

    async def fake_exec(*args, **kwargs):
        captured["args"] = list(args)
        return proc

    with patch("tools.sqlmap_runner.asyncio.create_subprocess_exec", fake_exec):
        await run_sqlmap(URL, tamper_script="space2comment")

    cmd = captured["args"]
    assert "--tamper" in cmd
    idx = cmd.index("--tamper")
    assert cmd[idx + 1] == "space2comment"


@pytest.mark.asyncio
async def test_timeout_path():
    proc = make_proc(timeout=True)
    with patch("tools.sqlmap_runner.asyncio.create_subprocess_exec", AsyncMock(return_value=proc)):
        result = await run_sqlmap(URL)
    assert result == {
        "status": "timeout",
        "target": URL,
        "stdout": "",
        "stderr": "killed after 1800s",
    }
    proc.terminate.assert_called_once()


@pytest.mark.asyncio
async def test_spawn_error():
    with patch(
        "tools.sqlmap_runner.asyncio.create_subprocess_exec",
        AsyncMock(side_effect=FileNotFoundError("sqlmap not found")),
    ):
        result = await run_sqlmap(URL)
    assert result["status"] == "error"
    assert "sqlmap not found" in result["stderr"]


@pytest.mark.asyncio
async def test_no_findings_when_clean_output():
    proc = make_proc(stdout=b"[INFO] no injectable parameters found")
    with patch("tools.sqlmap_runner.asyncio.create_subprocess_exec", AsyncMock(return_value=proc)):
        result = await run_sqlmap(URL)
    assert result["status"] == "success"
    assert result["findings"] == []
