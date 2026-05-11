import asyncio
import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from tools.nuclei_runner import run_nuclei

URL = "http://target/"

NUCLEI_LINE_1 = json.dumps({
    "template-id": "CVE-2021-44228",
    "info": {
        "name": "Log4Shell RCE",
        "severity": "critical",
        "tags": ["cve", "rce"],
    },
})

NUCLEI_LINE_2 = json.dumps({
    "template-id": "exposed-git-config",
    "info": {
        "name": "Exposed Git Config",
        "severity": "medium",
        "tags": ["exposure"],
    },
})


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


@pytest.fixture(autouse=True)
def mock_nuclei_which():
    with patch("tools.nuclei_runner.shutil.which", return_value="/usr/local/bin/nuclei"):
        yield


@pytest.mark.asyncio
async def test_success_findings_parsed():
    stdout = (NUCLEI_LINE_1 + "\n" + NUCLEI_LINE_2 + "\n").encode()
    proc = make_proc(stdout=stdout)
    with patch("tools.nuclei_runner.asyncio.create_subprocess_exec", AsyncMock(return_value=proc)):
        result = await run_nuclei(URL)
    assert result["status"] == "success"
    assert len(result["findings"]) == 2
    for f in result["findings"]:
        assert "type" in f
        assert "template_id" in f
        assert "severity" in f
        assert "name" in f
    assert result["findings"][0]["type"] == "cve"
    assert result["findings"][0]["template_id"] == "CVE-2021-44228"
    assert result["findings"][1]["type"] == "exposure"


@pytest.mark.asyncio
async def test_sqli_excluded_no_tags_whitelist():
    proc = make_proc(stdout=b"")
    captured = {}

    async def fake_exec(*args, **kwargs):
        captured["args"] = list(args)
        return proc

    with patch("tools.nuclei_runner.asyncio.create_subprocess_exec", fake_exec):
        await run_nuclei(URL)

    cmd = captured["args"]
    assert "-exclude-tags" in cmd
    idx = cmd.index("-exclude-tags")
    assert cmd[idx + 1] == "sqli"
    assert "-tags" not in cmd


@pytest.mark.asyncio
async def test_timeout_path():
    proc = make_proc(timeout=True)
    with patch("tools.nuclei_runner.asyncio.create_subprocess_exec", AsyncMock(return_value=proc)):
        result = await run_nuclei(URL)
    assert result["status"] == "timeout"
    assert result["stderr"] == "killed after 120s"
    proc.terminate.assert_called_once()


@pytest.mark.asyncio
async def test_spawn_error():
    with patch(
        "tools.nuclei_runner.asyncio.create_subprocess_exec",
        AsyncMock(side_effect=FileNotFoundError("nuclei not found")),
    ):
        result = await run_nuclei(URL)
    assert result["status"] == "error"
    assert "nuclei not found" in result["stderr"]


@pytest.mark.asyncio
async def test_binary_not_on_path():
    with patch("tools.nuclei_runner.shutil.which", return_value=None):
        result = await run_nuclei(URL)
    assert result["status"] == "error"
    assert "nuclei not found on PATH" in result["stderr"]


@pytest.mark.asyncio
async def test_malformed_json_lines_ignored():
    stdout = (
        "not valid json\n"
        + NUCLEI_LINE_1 + "\n"
        + "{broken\n"
        + NUCLEI_LINE_2 + "\n"
    ).encode()
    proc = make_proc(stdout=stdout)
    with patch("tools.nuclei_runner.asyncio.create_subprocess_exec", AsyncMock(return_value=proc)):
        result = await run_nuclei(URL)
    assert result["status"] == "success"
    assert len(result["findings"]) == 2
