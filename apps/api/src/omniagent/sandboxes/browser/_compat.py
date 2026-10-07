"""Playwright import-compat shims.

``playwright-python`` does not export every error class from its public
``playwright.async_api`` namespace in all versions (e.g. ``TargetClosedError``
lives in ``playwright._impl._errors``). This module resolves the names once so
the rest of the codebase can import them unconditionally.
"""

from __future__ import annotations

from playwright.async_api import Error as PlaywrightError
from playwright.async_api import TimeoutError as PlaywrightTimeoutError

try:  # public export (available in newer playwright-python releases)
    from playwright.async_api import TargetClosedError  # type: ignore[attr-defined]
except ImportError:  # pragma: no cover - version dependent
    try:  # internal location (stable since 1.37; subclass of Error)
        from playwright._impl._errors import TargetClosedError
    except ImportError:
        # Ultimate fallback: TargetClosedError is always a subclass of Error,
        # so catching Error is semantically safe (just less specific).
        TargetClosedError = PlaywrightError

__all__ = ["PlaywrightError", "PlaywrightTimeoutError", "TargetClosedError"]
