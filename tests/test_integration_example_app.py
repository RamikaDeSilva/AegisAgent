"""
Integration tests — spin up the real example app and confirm both scanners
detect the intentional vulnerabilities.

These tests require sqlmap and nuclei to be installed on PATH. Each test is
skipped automatically when the required binary is absent, so CI stays green on
environments that only have the unit-test dependencies.

Run locally (after `pip install flask` and installing sqlmap/nuclei):

    pytest tests/test_integration_example_app.py -v -s
"""

from __future__ import annotations

import asyncio
import shutil
import threading
import time

import pytest
import requests

from tools.nuclei_runner import run_nuclei
from tools.sqlmap_runner import run_sqlmap

# ---------------------------------------------------------------------------
# Fixture — live Flask server on port 5001
# ---------------------------------------------------------------------------

BASE_URL = "http://localhost:5001"


@pytest.fixture(scope="module")
def live_app():
    """Start example/app.py in a background daemon thread for the test module."""
    import sys
    import os

    # Make sure the example package is importable
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "example_app",
        os.path.join(os.path.dirname(__file__), "../example/app.py"),
    )
    mod = importlib.util.module_from_spec(spec)  # type: ignore[arg-type]
    spec.loader.exec_module(mod)  # type: ignore[union-attr]

    flask_app = mod.app

    thread = threading.Thread(
        target=lambda: flask_app.run(host="127.0.0.1", port=5001, use_reloader=False),
        daemon=True,
    )
    thread.start()

    # Wait until the server is accepting connections (up to 5 s)
    deadline = time.time() + 5
    while time.time() < deadline:
        try:
            requests.get(BASE_URL, timeout=1)
            break
        except Exception:
            time.sleep(0.1)
    else:
        pytest.fail("example/app.py did not start within 5 seconds")

    yield BASE_URL


# ---------------------------------------------------------------------------
# sqlmap integration test
# ---------------------------------------------------------------------------

@pytest.mark.skipif(
    shutil.which("sqlmap") is None,
    reason="sqlmap not on PATH — skipping live scan",
)
def test_sqlmap_finds_sqli_on_example_app(live_app):
    """sqlmap must detect SQLi on /user?id=1 (Boolean-based at minimum)."""
    target = f"{live_app}/user?id=1"
    result = asyncio.run(run_sqlmap(target))

    assert result["status"] == "success", (
        f"sqlmap returned non-success: {result.get('stderr', '')}"
    )
    assert len(result["findings"]) > 0, (
        "sqlmap found no injectable parameters — "
        "check that the seed URL is correct and the app is reachable"
    )
    finding = result["findings"][0]
    assert finding["type"] == "sqli"
    assert finding["parameter"] == "id"


# ---------------------------------------------------------------------------
# nuclei integration test
# ---------------------------------------------------------------------------

@pytest.mark.skipif(
    shutil.which("nuclei") is None,
    reason="nuclei not on PATH — skipping live scan",
)
def test_nuclei_finds_debug_exposure_on_example_app(live_app):
    """nuclei must flag the unauthenticated /debug endpoint exposure."""
    result = asyncio.run(run_nuclei(live_app))

    assert result["status"] == "success", (
        f"nuclei returned non-success: {result.get('stderr', '')}"
    )
    assert len(result["findings"]) > 0, (
        "nuclei found no issues — check that templates are up to date "
        "and the app's /debug endpoint is reachable"
    )
    severities = {f["severity"] for f in result["findings"]}
    high_or_above = {"medium", "high", "critical"}
    assert severities & high_or_above, (
        f"Expected at least one medium/high/critical finding, got: {severities}"
    )
