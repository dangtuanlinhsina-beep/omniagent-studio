"""Pytest configuration for the API test-suite.

Two kinds of tests live here:

* **Logic/security tests** (``static_logic_checks.py``, ``security_test.py``)
  — pure Python, always runnable, no browser required.
* **End-to-end sandbox tests** (``e2e_stream_test.py``) — need a real
  Chromium launched exactly like ``infra/sandbox-browser``.  Under ``pytest``
  they receive the session-scoped ``proc`` fixture below, which *skips* them
  when Playwright's Chromium is not installed (CI without browser deps) and is
  still runnable as a standalone script (``python e2e_stream_test.py``).
"""

from __future__ import annotations

import os
import subprocess
import sys
from collections.abc import Iterator

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))


def _chromium_available() -> bool:
    """``True`` when Playwright's Chromium binary is present on this machine."""
    try:
        from playwright.sync_api import sync_playwright

        with sync_playwright() as playwright_obj:
            path = playwright_obj.chromium.executable_path
        return bool(path) and os.path.exists(path)
    except Exception:  # noqa: BLE001 - playwright missing/broken => skip e2e
        return False


@pytest.fixture(scope="session")
def proc() -> Iterator[subprocess.Popen[bytes]]:
    """A live sandbox Chromium (CDP on 127.0.0.1:9333), or a skip."""
    if not _chromium_available():
        pytest.skip("Playwright Chromium is not installed — skipping e2e sandbox tests")

    import e2e_stream_test  # local import: needs sys.path from above

    process = e2e_stream_test.launch_sandbox_chrome()
    try:
        yield process
    finally:
        process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:  # pragma: no cover - defensive
            process.kill()
