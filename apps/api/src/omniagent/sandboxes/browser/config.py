"""Central configuration for the browser-sandbox subsystem.

All values are overridable through environment variables prefixed with
``OMNIAGENT_`` (e.g. ``OMNIAGENT_BROWSER_SANDBOX_CDP_URL``) or a local
``.env`` file.
"""

from __future__ import annotations

from functools import lru_cache
from typing import Literal

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Runtime settings for sandbox discovery, screencast and WS security."""

    model_config = SettingsConfigDict(
        env_prefix="OMNIAGENT_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # ------------------------------------------------------------------
    # Sandbox discovery
    # ------------------------------------------------------------------
    #: Static CDP endpoint shared by every graph (single-sandbox dev mode).
    browser_sandbox_cdp_url: str | None = None
    #: Per-graph endpoint template, e.g.
    #: ``http://browser-{graph_id}.sandbox.svc.cluster.local:9222`` or
    #: ``http://{graph_id}-browser:9222`` for docker-compose networks.
    browser_sandbox_cdp_url_template: str | None = None
    #: If no endpoint can be resolved, launch a local Playwright Chromium
    #: (development fallback — disable in production).
    browser_sandbox_launch_local_fallback: bool = True
    browser_sandbox_local_headless: bool = True

    # ------------------------------------------------------------------
    # Screencast (Page.startScreencast)
    # ------------------------------------------------------------------
    browser_screencast_format: Literal["jpeg", "png"] = "jpeg"
    #: JPEG quality 0-100. Ignored when format is "png".
    browser_screencast_quality: int = Field(70, ge=0, le=100)
    browser_screencast_max_width: int = Field(1280, ge=320, le=3840)
    browser_screencast_max_height: int = Field(720, ge=240, le=2160)
    browser_screencast_every_nth_frame: int = Field(1, ge=1, le=10)

    # ------------------------------------------------------------------
    # Streaming robustness / CDP
    # ------------------------------------------------------------------
    #: Bounded frame queue; oldest frames are dropped when the WebSocket
    #: consumer falls behind (low-latency policy for live video).
    browser_frame_queue_size: int = Field(32, ge=1, le=1024)
    #: Hard timeout (seconds) for every ``CDPSession.send`` call.
    browser_cdp_command_timeout: float = Field(10.0, gt=0.0)
    #: Playwright connect timeout in milliseconds.
    browser_connect_timeout_ms: float = Field(15_000.0, gt=0.0)
    browser_reconnect_base_delay: float = Field(0.5, gt=0.0)
    browser_reconnect_max_delay: float = Field(10.0, gt=0.0)
    #: ``None`` = retry forever (with capped exponential backoff + jitter).
    browser_max_reconnect_attempts: int | None = Field(None, ge=1)

    # ------------------------------------------------------------------
    # Viewport used when the API launches its own fallback browser
    # ------------------------------------------------------------------
    browser_viewport_width: int = Field(1280, ge=320, le=3840)
    browser_viewport_height: int = Field(720, ge=240, le=2160)

    # ------------------------------------------------------------------
    # WebSocket API security / behaviour
    # ------------------------------------------------------------------
    #: When set, clients must authenticate with ``?token=`` or
    #: ``Authorization: Bearer <token>`` (header form recommended — query
    #: strings end up in access logs).
    api_ws_auth_token: str | None = None
    #: graph_id must match this pattern before being interpolated anywhere.
    api_graph_id_pattern: str = r"^[A-Za-z0-9_-]{1,64}$"
    #: When true, MOUSE_EVENT/KEYBOARD_EVENT are rejected until the client
    #: explicitly enables human takeover via SET_TAKEOVER.
    browser_input_requires_takeover: bool = True


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return the process-wide cached settings instance."""
    return Settings()
