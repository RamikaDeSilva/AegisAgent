"""
Test-suite global fixtures.

Owned by: Stream 1 (Brain).

Ensures every test runs against the deterministic ``_FakeLLM`` rather than
the real ChatOpenAI, regardless of whether the developer has an
OPENAI_API_KEY set in their environment. This keeps the suite hermetic
and keeps CI free of accidental OpenAI billing.

Per-test overrides (e.g. the explicit ``test_uses_fake_llm_when_no_api_key``)
remain free to delete the variable themselves; ``raising=False`` makes the
double-delete idempotent.
"""

from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def _force_fake_llm(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
