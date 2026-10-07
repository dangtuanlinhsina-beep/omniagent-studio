"""Browser sandbox subsystem: CDP screencast streaming + human takeover.

Public surface:
    * :class:`ScreencastStreamer` — attach to a sandbox browser and stream
      ``SCREEN_FRAME`` envelopes onto an asyncio queue.
    * :func:`dispatch_mouse_event` / :func:`dispatch_keyboard_event` —
      human-takeover input injection over a live ``CDPSession``.
    * :class:`SandboxRegistry` — graph_id -> CDP endpoint resolution.
    * :class:`Settings` / :func:`get_settings` — configuration.
"""

from .config import Settings, get_settings
from .human_takeover import dispatch_keyboard_event, dispatch_mouse_event
from .registry import SandboxRegistry, get_sandbox_registry
from .streamer import BrowserSandboxUnavailable, ScreencastStreamer

__all__ = [
    "BrowserSandboxUnavailable",
    "SandboxRegistry",
    "ScreencastStreamer",
    "Settings",
    "dispatch_keyboard_event",
    "dispatch_mouse_event",
    "get_sandbox_registry",
    "get_settings",
]
