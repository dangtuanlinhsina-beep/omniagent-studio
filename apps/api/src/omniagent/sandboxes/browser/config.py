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
    #: Legacy static shared token (only used when JWT auth is NOT
    #: configured). Clients present it via ``?token=`` or
    #: ``Authorization: Bearer <token>``. Connections authenticated this way
    #: have full control rights (no role information available).
    api_ws_auth_token: str | None = None
    #: graph_id must match this pattern before being interpolated anywhere.
    api_graph_id_pattern: str = r"^[A-Za-z0-9_-]{1,64}$"
    #: When true, MOUSE_EVENT/KEYBOARD_EVENT are rejected until the client
    #: explicitly enables human takeover via SET_TAKEOVER.
    browser_input_requires_takeover: bool = True

    # ------------------------------------------------------------------
    # JWT authentication (security/auth.py)
    # ------------------------------------------------------------------
    #: HS256 shared secret — OmniAgent-minted tokens and legacy Supabase.
    security_jwt_secret: str | None = None
    #: Expected ``iss`` (e.g. https://xyz.clerk.accounts.dev or
    #: https://<ref>.supabase.co/auth/v1). Enforced when set; also used to
    #: derive the JWKS URL when security_jwks_url is unset.
    security_jwt_issuer: str | None = None
    #: Expected ``aud``; only enforced when set.
    security_jwt_audience: str | None = None
    #: Explicit JWKS endpoint for RS256/ES256 verification (Clerk/Supabase
    #: asymmetric). Defaults to {issuer}/.well-known/jwks.json.
    security_jwks_url: str | None = None
    security_jwks_cache_ttl_seconds: float = Field(300.0, gt=0.0)
    security_jwks_fetch_timeout_seconds: float = Field(10.0, gt=0.0)
    #: Allowed clock skew for exp/nbf checks.
    security_jwt_leeway_seconds: int = Field(10, ge=0, le=300)
    #: Reject tokens without a workspace identifier.
    security_require_workspace_id: bool = True
    #: Role assumed when the token carries no recognisable app role
    #: (deny-by-default). Must be one of VIEWER/OPERATOR/ADMIN.
    security_default_role: str = "VIEWER"
    #: Optional dot-path overrides for claim extraction, e.g.
    #: ``app_metadata.role`` or ``https://omniagent.io/claims.role``.
    security_user_id_claim: str | None = None
    security_workspace_id_claim: str | None = None
    security_role_claim: str | None = None

    # ------------------------------------------------------------------
    # Per-connection rate limiting (anti spam/DoS)
    # ------------------------------------------------------------------
    #: Max input packets (MOUSE_EVENT/KEYBOARD_EVENT) per second.
    security_rate_limit_input_per_second: float = Field(60.0, gt=0.0)
    #: Burst capacity of the input bucket; defaults to one second of rate.
    security_rate_limit_input_burst: float | None = Field(None, gt=0.0)
    #: Coarse guard over ALL inbound client messages per second.
    security_rate_limit_messages_per_second: float = Field(240.0, gt=0.0)
    security_rate_limit_message_burst: float | None = Field(None, gt=0.0)
    #: Rejections tolerated before the socket is closed with code 4429.
    security_rate_limit_max_strikes: int = Field(100, ge=1)


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return the process-wide cached settings instance."""
    return Settings()
